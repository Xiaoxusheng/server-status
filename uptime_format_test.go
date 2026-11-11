package main

import (
	"testing"
	"time"
)

func TestFormatUptimeCN(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0秒"},
		{59 * time.Second, "59秒"},
		{90 * time.Second, "1分30秒"},
		{352*time.Hour + 32*time.Minute + 59*time.Second, "14天16小时32分59秒"},
		{24 * time.Hour, "1天0小时0分0秒"},
		{365 * 24 * time.Hour, "1年0天0小时0分0秒"},
		{400*24*time.Hour + 3*time.Hour + 5*time.Minute + 7*time.Second, "1年35天3小时5分7秒"},
		{-5 * time.Second, "0秒"},
	}
	for _, c := range cases {
		if got := formatUptimeCN(c.d); got != c.want {
			t.Errorf("formatUptimeCN(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}
