package model

import (
	"fmt"
	"strconv"
	"strings"
)

// PortHops converts Clash comma-separated ports and closed ranges to the
// backend's explicit start:end ranges. It never expands the range in memory.
func PortHops(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	if len(parts) > 1024 {
		return nil, fmt.Errorf("too many port ranges")
	}
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		bounds := strings.Split(strings.Trim(part, "[] "), "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid port range")
		}
		first, e := strconv.Atoi(strings.Trim(bounds[0], "[] "))
		if e != nil || first < 1 || first > 65535 {
			return nil, fmt.Errorf("invalid port range")
		}
		last := first
		if len(bounds) == 2 {
			last, e = strconv.Atoi(strings.Trim(bounds[1], "[] "))
			if e != nil || last < 1 || last > 65535 {
				return nil, fmt.Errorf("invalid port range")
			}
		}
		if first > last {
			first, last = last, first
		}
		result = append(result, fmt.Sprintf("%d:%d", first, last))
	}
	return result, nil
}

// HopSeconds implements the pinned Clash default and minimum interval.
func HopSeconds(value string) (int, int, error) {
	if value == "" {
		return 30, 30, nil
	}
	parts := strings.Split(strings.Trim(value, "[] "), "-")
	if len(parts) > 2 {
		return 0, 0, fmt.Errorf("invalid hop interval")
	}
	first, e := strconv.Atoi(strings.Trim(parts[0], "[] "))
	if e != nil || first < 0 || first > 86400 {
		return 0, 0, fmt.Errorf("invalid hop interval")
	}
	last := first
	if len(parts) == 2 {
		last, e = strconv.Atoi(strings.Trim(parts[1], "[] "))
		if e != nil || last < 0 || last > 86400 {
			return 0, 0, fmt.Errorf("invalid hop interval")
		}
	}
	if first > last {
		first, last = last, first
	}
	if first == 0 {
		first = 30
	} else if first < 5 {
		first = 5
	}
	if last < first {
		last = first
	}
	return first, last, nil
}
