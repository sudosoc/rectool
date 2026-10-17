package syswrap

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sudosoc/rectool/internal/models"
)

func TestInputsRejectInjection(t *testing.T) {
	in := inputsFrom(models.Target{Username: "--output=/etc/x", Email: "a@evil.com; rm -rf /", Phone: "+1555123456"})
	if in.Username != "" || in.Email != "" || in.Domain != "" {
		t.Fatalf("unsafe values accepted: %+v", in)
	}
	if in.Phone == "" {
		t.Fatal("valid phone rejected")
	}
	in = inputsFrom(models.Target{Email: "Bob@Example.COM"})
	if in.Domain != "example.com" {
		t.Fatalf("domain = %q", in.Domain)
	}
}

func TestParseWhois(t *testing.T) {
	out := "Registrar: Example Registrar, Inc.\nCreation Date: 2001-01-01T00:00:00Z\nName Server: NS1.EXAMPLE.COM\nName Server: ns2.example.com\nName Server: ns1.example.com\nRegistrant Email: REDACTED FOR PRIVACY\n"
	f := parseWhois(Inputs{Domain: "example.com"}, nil, out)
	if len(f) != 1 || f[0].Details["name_servers"] != "NS1.EXAMPLE.COM, ns2.example.com" || f[0].Details["registrar"] == "" {
		t.Fatalf("%+v", f)
	}
	if _, has := f[0].Details["registrant_email"]; has {
		t.Fatal("redacted value kept")
	}
}

func TestParseHarvester(t *testing.T) {
	out := "[*] Emails found: 1\n----------------------\nadmin@example.com\n\n[*] Hosts found: 2\n---------------------\nwww.example.com:93.184.216.34\nmail.example.com\n"
	f := parseHarvester(Inputs{Domain: "example.com"}, nil, out)
	if len(f) != 3 || f[0].Details["email"] != "admin@example.com" || f[1].URL != "www.example.com" || f[1].Details["ip"] != "93.184.216.34" {
		t.Fatalf("%+v", f)
	}
}

func TestParseSherlockAndDig(t *testing.T) {
	f := parseSherlock(Inputs{Username: "bob"}, nil, "[*] Checking\n[+] GitHub: https://github.com/bob\n")
	if len(f) != 1 || f[0].Source != "GitHub" || f[0].URL != "https://github.com/bob" {
		t.Fatalf("%+v", f)
	}
	d := parseDig(Inputs{Domain: "x.org"}, []string{"+short", "MX", "x.org"}, "10 mail.x.org.\n")
	if len(d) != 1 || d[0].Details["type"] != "MX" {
		t.Fatalf("%+v", d)
	}
}

func TestCustomTool(t *testing.T) {
	sp := CustomSpec{Name: "demo", Binary: "demo", Args: []string{"-u", "{username}"}, Pattern: `^\[\+\]\s+(?P<title>\S+)\s+(?P<url>https?://\S+)$`}
	tool, err := sp.build()
	if err != nil {
		t.Fatal(err)
	}
	if tool.applicable(Inputs{}) || !tool.applicable(Inputs{Username: "u"}) {
		t.Fatal("requirements not derived from placeholders")
	}
	if got := tool.Args(Inputs{Username: "bob"})[0]; got[1] != "bob" {
		t.Fatalf("args %v", got)
	}
	f := tool.Parse(Inputs{}, nil, "[+] Site https://s.example/bob\nnoise")
	if len(f) != 1 || f[0].Source != "Site" || f[0].URL != "https://s.example/bob" {
		t.Fatalf("%+v", f)
	}
}

func TestRunCmdAndTimeout(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not in PATH")
	}
	out, err := runCmd(context.Background(), goBin, []string{"version"}, 30*time.Second, 1<<16)
	if err != nil || !strings.HasPrefix(out, "go version") {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if _, err := runCmd(context.Background(), goBin, []string{"version"}, time.Nanosecond, 1<<16); err == nil {
		t.Fatal("expected timeout error")
	}
}
