// Package browser renders a public web page with the operator's own installed
// Chrome / Chromium / Edge in headless mode and returns the resulting DOM.
//
// It exists because some sites (LinkedIn) refuse Go's HTTP client by its TLS
// fingerprint but serve their logged-out public page to a real browser. This
// IS a real browser, launched with its default settings: no stealth flags, no
// fingerprint tricks, no cookies, no login. If the site answers with a sign-in
// wall or CAPTCHA, the page is reported as blocked and nothing more is tried.
package browser

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ErrBlocked means the site showed a sign-in wall, CAPTCHA or error page.
var ErrBlocked = errors.New("the site served a sign-in wall or CAPTCHA instead of the public page")

// ErrNoBrowser means no Chrome / Chromium / Edge was found.
var ErrNoBrowser = errors.New("no Chrome, Chromium or Edge found (install one or set RECTOOL_BROWSER=/path/to/browser)")

// Find locates an installed Chromium-family browser.
func Find() (string, error) {
	if p := os.Getenv("RECTOOL_BROWSER"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	for _, n := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "microsoft-edge", "microsoft-edge-stable", "msedge"} {
		if p, err := exec.LookPath(n); err == nil {
			return p, nil
		}
	}
	var cands []string
	switch runtime.GOOS {
	case "windows":
		for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LocalAppData")} {
			if root == "" {
				continue
			}
			cands = append(cands,
				filepath.Join(root, "Google", "Chrome", "Application", "chrome.exe"),
				filepath.Join(root, "Microsoft", "Edge", "Application", "msedge.exe"))
		}
	case "darwin":
		cands = []string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Chromium.app/Contents/MacOS/Chromium"}
	}
	for _, p := range cands {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", ErrNoBrowser
}

// DumpDOM loads rawURL in a fresh, empty browser profile and returns the
// rendered HTML.
func DumpDOM(ctx context.Context, bin, rawURL string) (string, error) {
	if !strings.HasPrefix(rawURL, "https://") {
		return "", errors.New("browser: only https URLs are rendered")
	}
	profile, err := os.MkdirTemp("", "rectool-browser-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(profile)
	ctx, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	args := []string{"--headless=new", "--dump-dom", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
		"--user-data-dir=" + profile, "--virtual-time-budget=9000", rawURL}
	out, err := exec.CommandContext(ctx, bin, args...).Output()
	if err != nil && len(out) == 0 {
		return "", err
	}
	dom := string(out)
	if Blocked(dom) {
		return dom, ErrBlocked
	}
	return dom, nil
}

// Blocked reports whether a rendered page is a sign-in wall, CAPTCHA or
// challenge rather than the content asked for.
func Blocked(dom string) bool {
	l := strings.ToLower(dom)
	if strings.Contains(l, `"@type":"person"`) || strings.Contains(l, `"@type": "person"`) {
		return false // real profile data present
	}
	for _, m := range []string{"authwall", "captcha", "checkpoint/challenge", "join linkedin", "sign in to view", "/uas/login", "unusual traffic", "are you a human"} {
		if strings.Contains(l, m) {
			return true
		}
	}
	return len(strings.TrimSpace(dom)) < 200
}
