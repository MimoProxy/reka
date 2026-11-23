package rulesdata

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/router"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"go4.org/netipx"
)

type unsupportedSRSCondition string

func (c unsupportedSRSCondition) Error() string { return "unsupported SRS condition " + string(c) }

type unsupportedSRSVersion uint8

func (v unsupportedSRSVersion) Error() string {
	return fmt.Sprintf("unsupported SRS version %d (supported %d–%d)", v, C.RuleSetVersion1, C.RuleSetVersionCurrent)
}

// SRSCompatibilityCode reports a field or version without exposing rule values.
func SRSCompatibilityCode(err error) string {
	var condition unsupportedSRSCondition
	if errors.As(err, &condition) {
		return "unsupported_srs_condition_" + string(condition)
	}
	var version unsupportedSRSVersion
	if errors.As(err, &version) {
		return "unsupported_srs_version_" + strconv.Itoa(int(version))
	}
	return ""
}

func walkSRS(behavior string, data []byte, visit func(router.RuleSpec) error, account func(int) error) error {
	switch behavior {
	case "", "classical", "domain", "ipcidr", "geosite", "geoip":
	default:
		return fmt.Errorf("SRS does not support %q behavior", behavior)
	}
	compact, entries, err := inspectSRS(behavior, data)
	if err != nil {
		return fmt.Errorf("invalid SRS: %w", err)
	}
	if account != nil {
		if err := account(entries); err != nil {
			return err
		}
	}
	decoded, err := srs.Read(bytes.NewReader(data), false)
	if err != nil {
		return fmt.Errorf("invalid SRS: %w", err)
	}
	converter := srsConverter{compact: compact}
	for i, rule := range decoded.Options.Rules {
		spec, err := converter.rule(rule)
		if err == nil {
			err = visit(spec)
		}
		if err != nil {
			return fmt.Errorf("SRS rule %d: %w", i, err)
		}
	}
	return nil
}

type srsConverter struct {
	compact []srsCompact
	index   int
}

func (c *srsConverter) rule(rule option.HeadlessRule) (router.RuleSpec, error) {
	c.index++
	if rule.Type == C.RuleTypeLogical {
		logical := rule.LogicalOptions
		children := make([]router.RuleSpec, 0, len(logical.Rules))
		for i, child := range logical.Rules {
			spec, err := c.rule(child)
			if err != nil {
				return spec, fmt.Errorf("operand %d: %w", i, err)
			}
			children = append(children, spec)
		}
		kind := router.KindAnd
		if logical.Mode == C.LogicalTypeOr {
			kind = router.KindOr
		}
		return invertSRS(combineSRS(kind, children), logical.Invert), nil
	}
	var compact srsCompact
	if len(c.compact) > 0 && c.compact[0].rule == c.index {
		compact = c.compact[0]
		c.compact = c.compact[1:]
	}
	return defaultSRSRule(rule.DefaultOptions, compact)
}

func defaultSRSRule(rule option.DefaultHeadlessRule, compact srsCompact) (router.RuleSpec, error) {
	var conditions, destinations []router.RuleSpec
	// Sing ORs the destination address items and each group of ports.
	// Each other item and each resulting group must match.
	conditions = appendSRSValues(conditions, router.KindNetwork, rule.Network)
	conditions = appendSRSValues(conditions, router.KindProcessName, rule.ProcessName)
	conditions = appendSRSValues(conditions, router.KindProcessPath, rule.ProcessPath)
	conditions = appendSRSValues(conditions, router.KindProcessPathRegex, rule.ProcessPathRegex)
	if rule.SourceIPSet != nil {
		source, err := srsIPCondition(router.KindSrcIPCIDR, rule.SourceIPSet, compact.source)
		if err != nil {
			return source, fmt.Errorf("source_ip_cidr: %w", err)
		}
		conditions = append(conditions, source)
	}
	dstPorts, err := srsPorts(rule.Port, rule.PortRange)
	if err != nil {
		return router.RuleSpec{}, fmt.Errorf("port_range: %w", err)
	}
	srcPorts, err := srsPorts(rule.SourcePort, rule.SourcePortRange)
	if err != nil {
		return router.RuleSpec{}, fmt.Errorf("source_port_range: %w", err)
	}
	conditions = appendSRSValues(conditions, router.KindSrcPort, srcPorts)
	conditions = appendSRSValues(conditions, router.KindDstPort, dstPorts)
	if rule.DomainMatcher != nil {
		destinations = append(destinations, router.DomainMatcherCondition(rule.DomainMatcher, compact.domainEdges))
	}
	destinations = appendSRSValues(destinations, router.KindDomainKeyword, rule.DomainKeyword)
	destinations = appendSRSValues(destinations, router.KindDomainRegex, rule.DomainRegex)
	if rule.IPSet != nil {
		destination, err := srsIPCondition(router.KindIPCIDR, rule.IPSet, compact.destination)
		if err != nil {
			return destination, fmt.Errorf("ip_cidr: %w", err)
		}
		destinations = append(destinations, destination)
	}
	if len(destinations) > 0 {
		conditions = append(conditions, combineSRS(router.KindOr, destinations))
	}
	return invertSRS(combineSRS(router.KindAnd, conditions), rule.Invert), nil
}

func srsIPCondition(kind router.Kind, set *netipx.IPSet, stats srsIPStats) (router.RuleSpec, error) {
	if stats.mapped {
		// Native CIDR conditions unmap IPv4-mapped prefixes and addresses.
		var builder netipx.IPSetBuilder
		for _, addresses := range set.Ranges() {
			from, to := addresses.From(), addresses.To()
			if from.Is4In6() && to.Is4In6() {
				addresses = netipx.IPRangeFrom(from.Unmap(), to.Unmap())
			}
			builder.AddRange(addresses)
		}
		var err error
		if set, err = builder.IPSet(); err != nil {
			return router.RuleSpec{}, err
		}
	}
	return router.IPSetCondition(kind, set, stats.ranges), nil
}

func appendSRSValues(conditions []router.RuleSpec, kind router.Kind, values []string) []router.RuleSpec {
	if len(values) == 0 {
		return conditions
	}
	return append(conditions, router.RuleSpec{Kind: kind, Values: values})
}

func combineSRS(kind router.Kind, children []router.RuleSpec) router.RuleSpec {
	if len(children) == 1 {
		return children[0]
	}
	return router.RuleSpec{Kind: kind, Children: children}
}

func invertSRS(spec router.RuleSpec, invert bool) router.RuleSpec {
	if !invert {
		return spec
	}
	return router.RuleSpec{Kind: router.KindNot, Children: []router.RuleSpec{spec}}
}

func srsPorts(ports []uint16, ranges []string) ([]string, error) {
	if len(ports)+len(ranges) == 0 {
		return nil, nil
	}
	values := make([]string, 0, len(ports)+len(ranges))
	for _, port := range ports {
		values = append(values, strconv.FormatUint(uint64(port), 10))
	}
	for _, ports := range ranges {
		lo, hi, ok := strings.Cut(ports, ":")
		if !ok {
			return nil, fmt.Errorf("invalid range %q", ports)
		}
		if lo == "" {
			lo = "0"
		}
		if hi == "" {
			hi = "65535"
		}
		values = append(values, lo+"-"+hi)
	}
	return values, nil
}
