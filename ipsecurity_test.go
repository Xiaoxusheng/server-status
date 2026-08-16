package main

import (
	"testing"
	"time"
)

func TestParseBlockDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"10m": 10 * time.Minute,
		"1h":  time.Hour,
		"6h":  6 * time.Hour,
		"24h": 24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
		"30d": 30 * 24 * time.Hour,
		"45m": 45 * time.Minute,
	}
	for in, want := range cases {
		d, ok := parseBlockDuration(in)
		if !ok || d != want {
			t.Errorf("parseBlockDuration(%q) = %v, %v; want %v", in, d, ok, want)
		}
	}
	if _, ok := parseBlockDuration("forever"); ok {
		t.Error("invalid duration should fail")
	}
}

func TestIsWhitelisted(t *testing.T) {
	ipSec.mu.Lock()
	ipSec.whitelist = []IPWhitelistEntry{
		{ID: "w1", IPOrCIDR: "192.168.1.0/24", Note: "家庭局域网"},
		{ID: "w2", IPOrCIDR: "10.0.0.8", Note: "单机"},
	}
	ipSec.mu.Unlock()

	cases := map[string]bool{
		"192.168.1.14": true,
		"192.168.1.99": true,
		"10.0.0.8":     true,
		"10.0.0.9":     false,
		"8.8.8.8":      false,
	}
	for ip, want := range cases {
		if got := isWhitelisted(ip); got != want {
			t.Errorf("isWhitelisted(%q) = %v, want %v", ip, got, want)
		}
	}

	ipSec.mu.Lock()
	ipSec.whitelist = nil
	ipSec.mu.Unlock()
}
