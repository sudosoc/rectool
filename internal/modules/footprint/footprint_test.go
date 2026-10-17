package footprint

import (
	"strings"
	"testing"
)

func TestEmailMatcher(t *testing.T) {
	m := emailMatcher("john.doe@example.com")
	cases := []struct {
		text string
		ok   bool
		min  float64
	}{
		{"contact: john.doe@example.com today", true, 0.9},
		{"mail me: John.Doe [at] example [dot] com please", true, 0.8},
		{"john.doe(at)example.com", true, 0.8},
		{"xjohn.doe@example.com", false, 0},
		{"john.doe@example.com.evil.net", false, 0},
		{"jane@example.com", false, 0},
	}
	for _, c := range cases {
		_, conf, ok := m.find(c.text)
		if ok != c.ok || (ok && conf < c.min) {
			t.Errorf("%q: ok=%v conf=%v", c.text, ok, conf)
		}
	}
}

func TestParsePhone(t *testing.T) {
	pi := parsePhone("+15551234567")
	if pi.cc != "1" || pi.national != "5551234567" || pi.country == "" {
		t.Fatalf("%+v", pi)
	}
	if v := strings.Join(pi.variants(), "|"); !strings.Contains(v, "(555) 123-4567") {
		t.Fatalf("variants %s", v)
	}
	if pi := parsePhone("+442071838750"); pi.cc != "44" || pi.national != "2071838750" {
		t.Fatalf("%+v", pi)
	}
	if pi := parsePhone("5551234567"); pi.cc != "" {
		t.Fatal("no '+' must not guess a country")
	}
}

func TestPhoneMatcher(t *testing.T) {
	m := parsePhone("+15551234567").matcher()
	for _, ok := range []string{"call +1 (555) 123-4567 now", "tel: 555.123.4567.", "+1-555-123-4567"} {
		if _, _, found := m.find(ok); !found {
			t.Errorf("should match %q", ok)
		}
	}
	for _, bad := range []string{"id 95551234567890", "5551234568", "15551234"} {
		if _, _, found := m.find(bad); found {
			t.Errorf("should not match %q", bad)
		}
	}
	if _, conf, _ := m.find("call +1 555 123 4567"); conf < 0.8 {
		t.Errorf("international form conf %v", conf)
	}
	if _, conf, _ := m.find("call 555 123 4567"); conf > 0.7 {
		t.Errorf("national form should score lower, got %v", conf)
	}
}

func TestPublicHost(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://example.com/a": true, "http://127.0.0.1/": false, "http://10.0.0.5/x": false,
		"http://169.254.169.254/latest": false, "http://localhost:8080": false,
		"ftp://example.com": false, "http://[::1]/": false, "http://8.8.8.8/": true,
	} {
		if got := publicHost(raw); got != want {
			t.Errorf("%s: got %v want %v", raw, got, want)
		}
	}
}
