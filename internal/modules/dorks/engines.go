package dorks

import (
	"errors"
	"html"
	"net/url"
	"regexp"
	"strings"
)

// errBlocked means the engine served a bot-challenge / consent / JS wall.
// The module never tries to solve or bypass these; it stops using the engine.
var errBlocked = errors.New("engine blocked the request")

type result = Result

type searchEngine interface {
	name() string
	searchURL(q string) string
	parse(status int, body []byte) ([]result, error)
}

var tagRe = regexp.MustCompile(`<[^>]*>`)

func cleanText(s string) string {
	return strings.Join(strings.Fields(html.UnescapeString(tagRe.ReplaceAllString(s, ""))), " ")
}

func host(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// ---- Google ----------------------------------------------------------

type google struct{}

func (google) name() string { return "google" }
func (google) searchURL(q string) string {
	return "https://www.google.com/search?hl=en&num=20&pws=0&q=" + url.QueryEscape(q)
}

var googleResRe = regexp.MustCompile(`(?s)<a[^>]+href="([^"]+)"[^>]*>\s*(?:<br>)?\s*<h3[^>]*>(.*?)</h3>`)

func (google) parse(status int, body []byte) ([]result, error) {
	s := string(body)
	if status == 429 || strings.Contains(s, "/sorry/") || strings.Contains(s, "unusual traffic") ||
		strings.Contains(s, "enablejs") || strings.Contains(s, "consent.google.com") {
		return nil, errBlocked
	}
	var out []result
	for _, m := range googleResRe.FindAllStringSubmatch(s, -1) {
		link := html.UnescapeString(m[1])
		if strings.HasPrefix(link, "/url?") {
			q, err := url.ParseQuery(link[len("/url?"):])
			if err != nil || q.Get("q") == "" {
				continue
			}
			link = q.Get("q")
		}
		if !strings.HasPrefix(link, "http") || strings.Contains(host(link), "google.") {
			continue
		}
		out = append(out, result{Title: cleanText(m[2]), URL: link})
	}
	return out, nil
}

// ---- DuckDuckGo (HTML endpoint, no JS required) ----------------------

type duckduckgo struct{}

func (duckduckgo) name() string { return "duckduckgo" }
func (duckduckgo) searchURL(q string) string {
	return "https://html.duckduckgo.com/html/?kl=wt-wt&q=" + url.QueryEscape(q)
}

var ddgSnipRe = regexp.MustCompile(`(?s)class="result__snippet"[^>]*>(.*?)</a>`)

var ddgResRe = regexp.MustCompile(`(?s)<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>`)

func (duckduckgo) parse(status int, body []byte) ([]result, error) {
	s := string(body)
	if status == 202 || status == 429 || strings.Contains(s, "anomaly-modal") {
		return nil, errBlocked
	}
	var out []result
	snips := ddgSnipRe.FindAllStringSubmatch(s, -1)
	for i, m := range ddgResRe.FindAllStringSubmatch(s, -1) {
		link := html.UnescapeString(m[1])
		if strings.HasPrefix(link, "//") {
			link = "https:" + link
		}
		if u, err := url.Parse(link); err == nil && strings.HasSuffix(u.Hostname(), "duckduckgo.com") {
			if t := u.Query().Get("uddg"); t != "" {
				link = t // unwrap redirect
			} else {
				continue
			}
		}
		if !strings.HasPrefix(link, "http") {
			continue
		}
		r := result{Title: cleanText(m[2]), URL: link}
		if i < len(snips) {
			r.Snippet = cleanText(snips[i][1])
		}
		out = append(out, r)
	}
	return out, nil
}

func engineByName(n string) searchEngine {
	switch strings.ToLower(n) {
	case "brave":
		return brave{}
	case "google":
		return google{}
	case "bing":
		return bing{}
	case "duckduckgo", "ddg":
		return duckduckgo{}
	}
	return nil
}

// ---- Brave Search (server-rendered HTML; honours quotes and site:) ----------

type brave struct{}

func (brave) name() string { return "brave" }
func (brave) searchURL(q string) string {
	return "https://search.brave.com/search?source=web&q=" + url.QueryEscape(q)
}

var (
	braveLinkRe  = regexp.MustCompile(`<a href="(https?://[^"]+)"`)
	braveTitleRe = regexp.MustCompile(`class="title[^"]*"[^>]*title="([^"]*)"`)
	braveSnipRe  = regexp.MustCompile(`(?s)class="generic-snippet[^"]*"[^>]*>\s*<div class="content[^"]*"[^>]*>(.*?)</div>`)
)

func (brave) parse(status int, body []byte) ([]result, error) {
	s := string(body)
	if status == 429 || (status != 200 && status != 0) {
		return nil, errBlocked
	}
	blocks := strings.Split(s, `data-type="web"`)
	if len(blocks) < 2 {
		if strings.Contains(strings.ToLower(s), "captcha") {
			return nil, errBlocked
		}
		return nil, nil
	}
	var out []result
	for _, b := range blocks[1:] {
		if i := strings.Index(b, `data-type=`); i >= 0 {
			b = b[:i]
		}
		lm := braveLinkRe.FindStringSubmatch(b)
		if lm == nil {
			continue
		}
		r := result{URL: html.UnescapeString(lm[1])}
		if tm := braveTitleRe.FindStringSubmatch(b); tm != nil {
			r.Title = cleanText(tm[1])
		}
		if sm := braveSnipRe.FindStringSubmatch(b); sm != nil {
			r.Snippet = cleanText(sm[1])
		}
		out = append(out, r)
	}
	return out, nil
}
