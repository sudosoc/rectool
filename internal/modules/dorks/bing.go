package dorks

import (
	"encoding/base64"
	"html"
	"net/url"
	"regexp"
	"strings"
)

// ---- Bing (plain HTML, works without JS) ------------------------------

type bing struct{}

func (bing) name() string { return "bing" }
func (bing) searchURL(q string) string {
	return "https://www.bing.com/search?setlang=en&mkt=en-US&cc=us&count=30&q=" + url.QueryEscape(q)
}

var bingResRe = regexp.MustCompile(`(?s)<h2[^>]*><a[^>]+href="([^"]+)"[^>]*>(.*?)</a></h2>(?:.{0,600}?<p[^>]*>(.*?)</p>)?`)

func (bing) parse(status int, body []byte) ([]result, error) {
	s := string(body)
	if status == 429 || strings.Contains(s, "captcha") && !strings.Contains(s, "b_algo") {
		return nil, errBlocked
	}
	var out []result
	for _, m := range bingResRe.FindAllStringSubmatch(s, -1) {
		link := unwrapBing(html.UnescapeString(m[1]))
		if !strings.HasPrefix(link, "http") || strings.HasSuffix(host(link), "bing.com") {
			continue
		}
		out = append(out, result{Title: cleanText(m[2]), URL: link, Snippet: cleanText(m[3])})
	}
	return out, nil
}

// unwrapBing decodes Bing's click-tracking redirect (…/ck/a?…&u=a1<base64url>).
func unwrapBing(link string) string {
	u, err := url.Parse(link)
	if err != nil || !strings.HasSuffix(u.Hostname(), "bing.com") {
		return link
	}
	v := u.Query().Get("u")
	if !strings.HasPrefix(v, "a1") {
		return link
	}
	dec, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(v[2:], "="))
	if err != nil {
		return link
	}
	return string(dec)
}
