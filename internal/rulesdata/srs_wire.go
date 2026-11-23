package rulesdata

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/netip"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
)

// Item numbers follow sing-box/common/srs. Only supported items are scanned.
const (
	srsQueryType byte = iota
	srsNetwork
	srsDomain
	srsDomainKeyword
	srsDomainRegex
	srsSourceIPCIDR
	srsIPCIDR
	srsSourcePort
	srsSourcePortRange
	srsPort
	srsPortRange
	srsProcessName
	srsProcessPath
	srsPackageName
	srsWiFiSSID
	srsWiFiBSSID
	srsAdGuardDomain
	srsProcessPathRegex
	srsNetworkType
	srsNetworkIsExpensive
	srsNetworkIsConstrained
	srsNetworkInterfaceAddress
	srsDefaultInterfaceAddress
	srsPackageNameRegex
	srsFinal byte = 0xff
)

var srsItemName = [...]string{
	srsQueryType: "query_type", srsNetwork: "network", srsDomain: "domain/domain_suffix",
	srsDomainKeyword: "domain_keyword", srsDomainRegex: "domain_regex", srsSourceIPCIDR: "source_ip_cidr",
	srsIPCIDR: "ip_cidr", srsSourcePort: "source_port", srsSourcePortRange: "source_port_range",
	srsPort: "port", srsPortRange: "port_range", srsProcessName: "process_name", srsProcessPath: "process_path",
	srsPackageName: "package_name", srsWiFiSSID: "wifi_ssid", srsWiFiBSSID: "wifi_bssid",
	srsAdGuardDomain: "adguard_domain", srsProcessPathRegex: "process_path_regex", srsNetworkType: "network_type",
	srsNetworkIsExpensive: "network_is_expensive", srsNetworkIsConstrained: "network_is_constrained",
	srsNetworkInterfaceAddress: "network_interface_address", srsDefaultInterfaceAddress: "default_interface_address",
	srsPackageNameRegex: "package_name_regex",
}

var (
	errSRSEntries = errors.New("too many SRS entries")
	errSRSMatcher = errors.New("invalid SRS domain matcher")
)

type srsCompact struct {
	rule, domainEdges   int
	source, destination srsIPStats
}

type srsIPStats struct {
	ranges int
	mapped bool
}

type srsWire struct {
	*bufio.Reader
	behavior      string
	rules, values int
	compact       []srsCompact
}

// Check framing, budgets and compact structures before sing allocates them.
// A streaming pass also checks the zlib checksum, which srs.Read may not read.
func inspectSRS(behavior string, data []byte) ([]srsCompact, int, error) {
	if len(data) < 4 || !bytes.Equal(data[:3], srs.MagicBytes[:]) {
		return nil, 0, errors.New("invalid SRS magic or header")
	}
	if version := data[3]; version < C.RuleSetVersion1 || version > C.RuleSetVersionCurrent {
		return nil, 0, unsupportedSRSVersion(version)
	}
	raw := bytes.NewReader(data[4:])
	z, err := zlib.NewReader(raw)
	if err != nil {
		return nil, 0, err
	}
	defer z.Close()
	limited := &io.LimitedReader{R: z, N: MaxExpanded + 1}
	r := srsWire{Reader: bufio.NewReader(limited), behavior: behavior}
	count, err := r.count(MaxEntries)
	if err != nil {
		return nil, 0, err
	}
	for i := range count {
		if err := r.rule(0); err != nil {
			if limited.N == 0 {
				return nil, 0, errors.New("expanded SRS exceeds size limit")
			}
			return nil, 0, fmt.Errorf("rule %d: %w", i, err)
		}
	}
	_, err = r.ReadByte()
	if limited.N == 0 {
		return nil, 0, errors.New("expanded SRS exceeds size limit")
	}
	if err == nil || raw.Len() != 0 && err == io.EOF {
		return nil, 0, errors.New("trailing SRS data")
	}
	if err != io.EOF {
		return nil, 0, err
	}
	return r.compact, r.rules + r.values, nil
}

func (r *srsWire) count(limit int) (int, error) {
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return 0, err
	}
	if n > uint64(limit) {
		return 0, errSRSEntries
	}
	if n == 0 {
		return 0, errors.New("empty SRS rule or condition")
	}
	return int(n), nil
}

func (r *srsWire) addValues(n int) error {
	r.values += n
	if r.values > MaxEntries {
		return errSRSEntries
	}
	return nil
}

func (r *srsWire) rule(depth int) error {
	if depth > 32 {
		return errors.New("condition nesting exceeds 32")
	}
	r.rules++
	if r.rules > MaxEntries {
		return errSRSEntries
	}
	kind, err := r.ReadByte()
	if err != nil {
		return err
	}
	switch kind {
	case 0:
		if err := r.items(); err != nil {
			return err
		}
	case 1:
		mode, err := r.ReadByte()
		if err != nil {
			return err
		}
		if mode > 1 {
			return fmt.Errorf("unknown SRS logical mode %d", mode)
		}
		count, err := r.count(MaxEntries - r.rules)
		if err != nil {
			return err
		}
		for i := range count {
			if err := r.rule(depth + 1); err != nil {
				return fmt.Errorf("operand %d: %w", i, err)
			}
		}
	default:
		return fmt.Errorf("unknown SRS rule type %d", kind)
	}
	invert, err := r.ReadByte()
	if err == nil && invert > 1 {
		return errors.New("invalid SRS invert flag")
	}
	return err
}

func (r *srsWire) items() error {
	var seen uint32
	compact := srsCompact{rule: r.rules}
	for {
		kind, err := r.ReadByte()
		if err != nil {
			return err
		}
		if kind == srsFinal {
			break
		}
		if int(kind) >= len(srsItemName) {
			return fmt.Errorf("unknown SRS condition %d", kind)
		}
		name := srsItemName[kind]
		if seen&(1<<kind) != 0 {
			return fmt.Errorf("duplicate SRS condition %s", name)
		}
		seen |= 1 << kind
		switch kind {
		case srsQueryType, srsPackageName, srsPackageNameRegex, srsWiFiSSID, srsWiFiBSSID, srsAdGuardDomain,
			srsNetworkType, srsNetworkIsExpensive, srsNetworkIsConstrained, srsNetworkInterfaceAddress, srsDefaultInterfaceAddress:
			return unsupportedSRSCondition(name)
		}
		switch r.behavior {
		case "domain", "geosite":
			if kind != srsDomain && kind != srsDomainKeyword && kind != srsDomainRegex {
				return fmt.Errorf("SRS condition %s is incompatible with %s behavior", name, r.behavior)
			}
		case "ipcidr", "geoip":
			if kind != srsIPCIDR {
				return fmt.Errorf("SRS condition %s is incompatible with %s behavior", name, r.behavior)
			}
		}
		switch kind {
		case srsDomain:
			compact.domainEdges, err = r.matcher()
		case srsSourceIPCIDR:
			compact.source, err = r.ipSet()
		case srsIPCIDR:
			compact.destination, err = r.ipSet()
		default:
			err = r.list(kind == srsSourcePort || kind == srsPort)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if seen == 0 {
		return errors.New("empty SRS rule")
	}
	if compact.domainEdges != 0 || compact.source.ranges != 0 || compact.destination.ranges != 0 {
		r.compact = append(r.compact, compact)
	}
	return nil
}

func (r *srsWire) list(ports bool) error {
	count, err := r.count(MaxEntries - r.values)
	if err != nil {
		return err
	}
	r.values += count
	if ports {
		_, err := r.Discard(2 * count)
		return err
	}
	for range count {
		size, err := binary.ReadUvarint(r)
		if err != nil {
			return err
		}
		if size > MaxExpanded {
			return errors.New("SRS value exceeds expanded size limit")
		}
		if _, err := r.Discard(int(size)); err != nil {
			return err
		}
	}
	return nil
}

func (r *srsWire) matcher() (int, error) {
	version, err := r.ReadByte()
	if err != nil || version != 0 {
		return 0, errSRSMatcher
	}
	leaves, err := r.count(MaxExpanded / 8)
	if err != nil {
		return 0, err
	}
	var word [8]byte
	var lastLeaf int
	for i := range leaves {
		if _, err := io.ReadFull(r, word[:]); err != nil {
			return 0, err
		}
		value := binary.BigEndian.Uint64(word[:])
		if i == 0 && value&1 != 0 {
			return 0, errSRSMatcher
		}
		if value != 0 {
			lastLeaf = i*64 + bits.Len64(value) - 1
		}
		if err := r.addValues(bits.OnesCount64(value)); err != nil {
			return 0, err
		}
	}
	words, err := r.count(MaxExpanded / 8)
	if err != nil {
		return 0, err
	}
	// The breadth-first bitmap ends when there are no pending nodes.
	pending, edges := 1, 0
	for i := range words {
		if _, err := io.ReadFull(r, word[:]); err != nil {
			return 0, err
		}
		value := binary.BigEndian.Uint64(word[:])
		for bit := 0; bit < 64; bit++ {
			if value&1 == 0 {
				edges++
				pending++
			} else {
				pending--
			}
			value >>= 1
			if pending == 0 {
				if i != words-1 || value != 0 {
					return 0, errSRSMatcher
				}
				break
			}
		}
		if edges > MaxExpanded {
			return 0, errSRSMatcher
		}
	}
	labels, err := binary.ReadUvarint(r)
	if err != nil {
		return 0, err
	}
	if pending != 0 || lastLeaf == 0 || lastLeaf > edges || leaves != (edges+64)/64 || labels != uint64(edges) {
		return 0, errSRSMatcher
	}
	_, err = r.Discard(edges)
	return edges, err
}

func (r *srsWire) ipSet() (srsIPStats, error) {
	var stats srsIPStats
	version, err := r.ReadByte()
	if err != nil || version != 1 {
		return stats, errors.New("invalid SRS IP set version")
	}
	var size [8]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return stats, err
	}
	count := binary.BigEndian.Uint64(size[:])
	if count > uint64(MaxEntries-r.values) {
		return stats, errSRSEntries
	}
	if count == 0 {
		return stats, errors.New("empty SRS IP set")
	}
	var previous netip.Addr
	for range count {
		from, err := r.address()
		if err != nil {
			return stats, err
		}
		to, err := r.address()
		if err != nil {
			return stats, err
		}
		if from.BitLen() != to.BitLen() || to.Less(from) || !previous.Less(from) {
			return stats, errors.New("invalid or unordered SRS IP range")
		}
		stats.mapped = stats.mapped || from.Is4In6() && to.Is4In6()
		previous = to
	}
	stats.ranges = int(count)
	r.values += stats.ranges
	return stats, nil
}

func (r *srsWire) address() (netip.Addr, error) {
	size, err := binary.ReadUvarint(r)
	if err != nil {
		return netip.Addr{}, err
	}
	if size != 4 && size != 16 {
		return netip.Addr{}, errors.New("invalid SRS IP address length")
	}
	addr, err := r.Peek(int(size))
	if err != nil {
		return netip.Addr{}, err
	}
	result, _ := netip.AddrFromSlice(addr)
	_, _ = r.Discard(int(size))
	return result, nil
}
