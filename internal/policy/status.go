package policy

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

type statusRange [2]uint16
type expectedStatusKey struct{}

func ParseExpectedStatus(value string) ([]statusRange, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "*" {
		return nil, nil
	}
	parts := strings.Split(strings.ReplaceAll(value, ",", "/"), "/")
	if len(parts) > 28 || len(value) > 4096 {
		return nil, fmt.Errorf("too many expected HTTP status ranges")
	}
	var ranges []statusRange
	for _, part := range parts {
		if part == "" {
			continue
		}
		pair := strings.Split(strings.TrimSpace(part), "-")
		if len(pair) > 2 {
			return nil, fmt.Errorf("invalid HTTP status range")
		}
		parse := func(s string) (uint16, error) {
			n, err := strconv.ParseUint(strings.Trim(s, "[ ]"), 10, 16)
			return uint16(n), err
		}
		low, err := parse(pair[0])
		if err != nil {
			return nil, fmt.Errorf("invalid expected HTTP status")
		}
		high := low
		if len(pair) == 2 {
			high, err = parse(pair[1])
			if err != nil {
				return nil, fmt.Errorf("invalid expected HTTP status")
			}
		}
		if low > high {
			low, high = high, low
		}
		ranges = append(ranges, statusRange{low, high})
	}
	return ranges, nil
}
func ExpectedStatusAllows(ctx context.Context, code int) bool {
	value, _ := ctx.Value(expectedStatusKey{}).(string)
	// Native profiles keep their existing default; Clash imports explicitly
	// store "*", matching its reference default of any HTTP response.
	if value == "" {
		return code >= 200 && code < 400
	}
	ranges, err := ParseExpectedStatus(value)
	if err != nil || code < 0 || code > 65535 {
		return false
	}
	if len(ranges) == 0 {
		return true
	}
	for _, r := range ranges {
		if code >= int(r[0]) && code <= int(r[1]) {
			return true
		}
	}
	return false
}
