package main

import (
	"testing"
	"time"
)

func TestParseEtime(t *testing.T) {
	cases := map[string]time.Duration{
		"45":          0,
		"59":          0,
		"01:30":       90 * time.Second,
		"01:24:47":    time.Hour + 24*time.Minute + 47*time.Second,
		"1-02:03:04":  26*time.Hour + 3*time.Minute + 4*time.Second,
		"12-00:00:00": 12 * 24 * time.Hour,
		"not-a-time":  0,
		"-1:00":       0,
	}
	for in, want := range cases {
		d, ok := parseEtime(in)
		if want == 0 && !ok {
			continue
		}
		if want == 0 && ok {
			t.Errorf("parseEtime(%q) unexpectedly ok: %v", in, d)
			continue
		}
		if !ok || d != want {
			t.Errorf("parseEtime(%q) = %v, %v; want %v", in, d, ok, want)
		}
	}
}

func TestMapProcStatus(t *testing.T) {
	cases := map[string]string{
		"R":   "running",
		"S":   "sleeping",
		"Ssl": "sleeping",
		"I":   "sleeping",
		"D":   "uninterruptible",
		"Z":   "zombie",
		"T":   "stopped",
		"t":   "stopped",
		"X":   "dead",
		"":    "unknown",
		"Q":   "unknown",
	}
	for in, want := range cases {
		if got := mapProcStatus(in); got != want {
			t.Errorf("mapProcStatus(%q) = %q, want %q", in, got, want)
		}
	}
}
