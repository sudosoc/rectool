package footprint

import (
	"context"
	"html"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/sudosoc/rectool/internal/httpx"
)

var (
	scriptRe = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	styleRe  = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	tagRe    = regexp.MustCompile(`(?s)<[^>]*>`)
	spaceRe  = regexp.MustCompile(`\s+`)
)

// publicHost reports whether raw is an http(s) URL to a host we are willing to
// fetch. Search results are untrusted, so loopback, private, link-local and
// internal names are refused (basic SSRF guard).
func publicHost(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	h := strings.ToLower(u.Hostname())
	if h == "" || h == "localhost" || strings.HasSuffix(h, ".local") ||
		strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".localhost") {
		return false
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
	}
	return true
}

// pageText downloads a result page and returns its visible text, or "" when
// the page is unsuitable (non-HTML/text, error status, unsafe host).
func pageText(ctx context.Context, c *httpx.Client, raw string) string {
	if !publicHost(raw) {
		return ""
	}
	resp, err := c.Do(ctx, httpx.Request{URL: raw})
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	if ct := strings.ToLower(resp.Header.Get("Content-Type")); ct != "" &&
		!strings.Contains(ct, "text/") && !strings.Contains(ct, "xml") && !strings.Contains(ct, "json") {
		return ""
	}
	s := string(resp.Body)
	s = scriptRe.ReplaceAllString(s, " ")
	s = styleRe.ReplaceAllString(s, " ")
	s = tagRe.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return spaceRe.ReplaceAllString(s, " ")
}

// matcher finds one identifier (in any of its variants) inside page text.
// If reject > 0, a match is discarded when that capture group participated
// (used to refuse "john@example.com.evil.net"-style continuations, which RE2
// cannot express as a look-ahead).
type matcher struct {
	re     *regexp.Regexp
	conf   func(match string) float64
	reject int
}

// find returns a short context window around the first acceptable match.
func (m matcher) find(text string) (ctxSnippet string, conf float64, ok bool) {
	for _, loc := range m.re.FindAllStringSubmatchIndex(text, -1) {
		if m.reject > 0 && loc[2*m.reject] >= 0 {
			continue
		}
		lo, hi := max(0, loc[0]-70), min(len(text), loc[1]+70)
		return strings.TrimSpace(text[lo:hi]), m.conf(text[loc[0]:loc[1]]), true
	}
	return "", 0, false
}
