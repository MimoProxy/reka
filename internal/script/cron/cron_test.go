package cron

import (
	"testing"
	"time"
)

func TestNext(t *testing.T) {
	for _, tc := range []struct {
		name, expression, after, want string
	}{
		{"minute schedule", "0 10 * * *", "2026-11-25T09:59:59.999Z", "2026-11-25T10:00:00Z"},
		{"strictly after", "0 10 * * *", "2026-11-25T10:00:00Z", "2026-11-26T10:00:00Z"},
		{"leading zeroes", "00 09 * * *", "2026-11-25T08:59:00Z", "2026-11-25T09:00:00Z"},
		{"list with stepped minutes", "*/30 0,1,7-23 * * *", "2026-11-25T01:30:20Z", "2026-11-25T07:00:00Z"},
		{"seconds with step starting at a value", "0/5 * 6-23 * * *", "2026-11-25T06:00:05.05Z", "2026-11-25T06:00:10Z"},
		{"stepped ranges", "5-15/5 10-14/2 6-23/2 * * *", "2026-11-25T06:10:15Z", "2026-11-25T06:12:05Z"},
		{"week and month names", "12 8 ? jAn,mAr MoN-FrI/2", "2026-01-05T08:12:00Z", "2026-01-07T08:12:00Z"},
		{"Sunday zero", "0 1 ? * 0", "2026-11-25T00:00:00Z", "2026-11-29T01:00:00Z"},
		{"Sunday seven", "0 1 ? * 7", "2026-11-25T00:00:00Z", "2026-11-29T01:00:00Z"},
		{"Sunday name", "0 1 * * SuN", "2026-11-25T00:00:00Z", "2026-11-29T01:00:00Z"},
		{"weekday matches first", "0 8 1 * FRI", "2026-11-25T00:00:00Z", "2026-11-27T08:00:00Z"},
		{"month day matches first", "0 8 1 * FRI", "2026-11-28T00:00:00Z", "2026-12-01T08:00:00Z"},
		{"question weekday", "0 8 1 * ?", "2026-11-28T00:00:00Z", "2026-12-01T08:00:00Z"},
		{"weekday matches without valid month day", "0 8 30 FEB SUN", "2026-01-28T00:00:00Z", "2026-02-01T08:00:00Z"},
		{"no matching date", "0 8 30 FEB *", "2026-01-28T00:00:00Z", ""},
		{"unrestricted day fields", "0 8 ? * ?", "2026-01-28T07:00:00Z", "2026-01-28T08:00:00Z"},
		{"leap day across non-leap century", "0 8 29 FEB *", "2096-02-29T08:00:00Z", "2104-02-29T08:00:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Parse(tc.expression)
			if err != nil {
				t.Fatal(err)
			}
			after := parseTime(t, tc.after)
			var want time.Time
			if tc.want != "" {
				want = parseTime(t, tc.want)
			}
			if got := s.Next(after); !got.Equal(want) {
				t.Fatalf("Next(%s) = %s, want %s", after, got, want)
			}
		})
	}
}

func TestParseInvalid(t *testing.T) {
	for _, expr := range []string{
		"", "* * * *", "* * * * * * *", "60 * * * * *", "60 * * * *", "* 24 * * *",
		"* * 0 * *", "* * 32 * *", "* * * 0 *", "* * * 13 *", "* * * * 8",
		",5 * * * *", "5,,10 * * * *", "5, * * * *", "*/0 * * * *", "*/-5 * * * *",
		"1/ * * * *", "15-10 * * * *", "10- * * * *", "1-2-3 * * * *", "+1 * * * *",
		"? * * * *", "* * * ? *", "* * ?/2 * *", "* * ?,5 * *", "* * * NOT *", "* * * * SUNDAY",
	} {
		t.Run(expr, func(t *testing.T) {
			if _, err := Parse(expr); err == nil {
				t.Fatalf("Parse(%q) succeeded", expr)
			}
		})
	}
}

func TestNextDaylightSavingTime(t *testing.T) {
	location, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, expression, after, want string
	}{
		{"skips nonexistent time", "30 2 * * *", "2024-03-10T00:00:00-05:00", "2024-03-11T02:30:00-04:00"},
		{"continues after spring gap", "30 2,3 * * *", "2024-03-10T01:30:00-05:00", "2024-03-10T03:30:00-04:00"},
		{"first occurrence in fall fold", "30 1 * * *", "2024-11-03T00:00:00-04:00", "2024-11-03T01:30:00-04:00"},
		{"skips duplicate in fall fold", "30 1 * * *", "2024-11-03T01:30:00-04:00", "2024-11-04T01:30:00-05:00"},
		{"continues after fall fold", "30 1,2 * * *", "2024-11-03T01:15:00-05:00", "2024-11-03T02:30:00-05:00"},
		{"future leap year end", "0 2 31 DEC *", "2044-12-30T00:00:00-05:00", "2044-12-31T02:00:00-05:00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Parse(tc.expression)
			if err != nil {
				t.Fatal(err)
			}
			after := parseTime(t, tc.after).In(location)
			want := parseTime(t, tc.want)
			if got := s.Next(after); !got.Equal(want) || got.Location() != location {
				t.Fatalf("Next(%s) = %s, want %s in %s", after, got, want, location)
			}
		})
	}
}

func parseTime(t *testing.T, text string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
