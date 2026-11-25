// Package cron parses Surge-compatible cron expressions.
package cron

import (
	"fmt"
	"math/bits"
	"slices"
	"strconv"
	"strings"
	"time"
)

// searchYears bounds the search to two maximum gaps between Gregorian leap days (Reka).
const searchYears = 16

// Schedule matches local wall-clock times.
type Schedule struct {
	second, minute, hour, day, month, weekday field
	dayAny, weekdayAny                        bool
}

type field uint64

func (f field) has(value int) bool {
	return f&(1<<value) != 0
}

func (f field) next(value int) int {
	return bits.TrailingZeros64(uint64(f) & (^uint64(0) << value))
}

type fieldSpec struct {
	name      string
	low, high int
	names     []string
	question  bool
}

// Parse accepts five fields, or six fields with a leading seconds field.
func Parse(expression string) (Schedule, error) {
	values := strings.Fields(expression)
	switch len(values) {
	case 5:
		values = append([]string{"0"}, values...)
	case 6:
	default:
		return Schedule{}, fmt.Errorf("expected five or six cron fields")
	}
	specs := [...]fieldSpec{
		{name: "second", low: 0, high: 59},
		{name: "minute", low: 0, high: 59},
		{name: "hour", low: 0, high: 23},
		{name: "day", low: 1, high: 31, question: true},
		{name: "month", low: 1, high: 12, names: []string{"JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"}},
		{name: "weekday", low: 0, high: 7, names: []string{"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}, question: true},
	}
	var s Schedule
	fields := []*field{&s.second, &s.minute, &s.hour, &s.day, &s.month, &s.weekday}
	for i, spec := range specs {
		mask, err := spec.parse(values[i])
		if err != nil {
			return Schedule{}, fmt.Errorf("invalid %s field: %w", spec.name, err)
		}
		*fields[i] = mask
	}
	// Vixie cron numbers Sunday both 0 and 7.
	if s.weekday.has(7) {
		s.weekday |= 1
	}
	s.dayAny = unrestricted(values[3])
	s.weekdayAny = unrestricted(values[5])
	return s, nil
}

func unrestricted(value string) bool {
	return value == "*" || value == "?"
}

func (spec fieldSpec) parse(text string) (field, error) {
	var mask field
	for item := range strings.SplitSeq(text, ",") {
		base, interval, stepped := strings.Cut(item, "/")
		step := 1
		if stepped {
			var ok bool
			step, ok = decimal(interval)
			if !ok || step == 0 {
				return 0, fmt.Errorf("invalid step %q", interval)
			}
		}
		low, high := spec.low, spec.high
		switch base {
		case "*":
		case "?":
			if !spec.question || text != "?" {
				return 0, fmt.Errorf("invalid wildcard %q", item)
			}
		default:
			start, end, ranged := strings.Cut(base, "-")
			var ok bool
			low, ok = spec.value(start)
			if !ok {
				return 0, fmt.Errorf("invalid value %q", start)
			}
			switch {
			case ranged:
				high, ok = spec.value(end)
				if !ok || high < low {
					return 0, fmt.Errorf("invalid range %q", base)
				}
			case !stepped:
				high = low
			}
		}
		for value := low; ; value += step {
			mask |= 1 << value
			if step > high-value {
				break
			}
		}
	}
	return mask, nil
}

func (spec fieldSpec) value(text string) (int, bool) {
	if i := slices.Index(spec.names, strings.ToUpper(text)); i >= 0 {
		return spec.low + i, true
	}
	value, ok := decimal(text)
	return value, ok && value >= spec.low && value <= spec.high
}

func decimal(text string) (int, bool) {
	for i := range len(text) {
		if text[i] < '0' || text[i] > '9' {
			return 0, false
		}
	}
	value, err := strconv.Atoi(text)
	return value, err == nil
}

// Next returns the first occurrence strictly after after in its time zone.
// It returns a zero time when no occurrence is found.
func (s Schedule) Next(after time.Time) time.Time {
	cursor := after.Truncate(time.Second).Add(time.Second)
	limit := cursor.UTC().AddDate(searchYears, 0, 0)
	for cursor.Before(limit) {
		_, offset := cursor.Zone()
		start, end := cursor.ZoneBounds()
		if !end.IsZero() && !end.After(cursor) {
			// Future POSIX bounds may end a day early in a leap year.
			end = time.Date(cursor.UTC().Year()+1, 1, 1, 0, 0, 0, 0, time.UTC).In(cursor.Location())
		}
		ceiling := limit
		if !end.IsZero() && end.Before(ceiling) {
			ceiling = end
		}
		floor := cursor
		if !start.IsZero() {
			_, previousOffset := start.Add(-time.Second).Zone()
			if previousOffset > offset {
				// The previous offset already offered these wall-clock times.
				repeatedUntil := start.Add(time.Duration(previousOffset-offset) * time.Second)
				if repeatedUntil.After(floor) {
					floor = repeatedUntil
				}
			}
		}
		shift := time.Duration(offset) * time.Second
		// Search the wall clock within this constant-offset interval.
		if next := s.nextWallTime(floor.Add(shift).UTC(), ceiling.Add(shift).UTC()); !next.IsZero() {
			return next.Add(-shift).In(cursor.Location())
		}
		cursor = ceiling.In(cursor.Location())
	}
	return time.Time{}
}

func (s Schedule) nextWallTime(start, end time.Time) time.Time {
	if !start.Before(end) {
		return time.Time{}
	}
	day := start.Truncate(24 * time.Hour)
	for ; day.Before(end); day = day.AddDate(0, 0, 1) {
		if !s.month.has(int(day.Month())) || !s.matchesDay(day) {
			continue
		}
		hour, minute, second := 0, 0, 0
		if start.After(day) {
			hour, minute, second = start.Clock()
		}
		if offset, ok := s.nextTimeOfDay(hour, minute, second); ok {
			if candidate := day.Add(offset); candidate.Before(end) {
				return candidate
			}
		}
	}
	return time.Time{}
}

func (s Schedule) matchesDay(day time.Time) bool {
	dom, dow := s.day.has(day.Day()), s.weekday.has(int(day.Weekday()))
	if !s.dayAny && !s.weekdayAny {
		return dom || dow
	}
	return dom && dow
}

func (s Schedule) nextTimeOfDay(hour, minute, second int) (time.Duration, bool) {
	for h := s.hour.next(hour); h < 24; h = s.hour.next(h + 1) {
		firstMinute := 0
		if h == hour {
			firstMinute = minute
		}
		for m := s.minute.next(firstMinute); m < 60; m = s.minute.next(m + 1) {
			firstSecond := 0
			if h == hour && m == minute {
				firstSecond = second
			}
			if sec := s.second.next(firstSecond); sec < 60 {
				return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(sec)*time.Second, true
			}
		}
	}
	return 0, false
}
