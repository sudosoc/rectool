// Package mentions finds press and web-news articles that name the person
// (GDELT's open news index, no key). A name is not an identity, so every
// article is checked against what the operator supplied: ones whose headline
// also mentions the company, place or other detail are flagged as context
// matches, the rest are listed as unverified.
package mentions

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/identity"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

type Scanner struct{}

var _ scanner.Scanner = (*Scanner)(nil)

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "mentions" }
func (s *Scanner) Description() string {
	return "news and press articles that name the person, checked against your other details"
}
func (s *Scanner) CanRun(t models.Target) bool { return len(strings.Fields(t.FullName)) >= 2 }

type article struct {
	URL      string `json:"url"`
	Title    string `json:"title"`
	SeenDate string `json:"seendate"`
	Domain   string `json:"domain"`
	Language string `json:"language"`
	Country  string `json:"sourcecountry"`
}

func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	names := []string{t.FullName}
	names = append(names, identity.LatinVariants(t.FullName, 1)...)
	var all []article
	seen := map[string]bool{}
	for i, n := range names {
		if i > 0 { // GDELT asks for at most one request per five seconds
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5500 * time.Millisecond):
			}
		}
		arts, status := fetch(ctx, d.HTTP, n)
		for try := 0; status == 429 && try < 3; try++ { // GDELT shares its limit per IP: wait and retry
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(7 * time.Second):
			}
			arts, status = fetch(ctx, d.HTTP, n)
		}
		if status != 200 {
			emit(models.Finding{Source: "GDELT news index", Category: "mentions", Status: models.StatusError,
				Details: map[string]string{"error": fmt.Sprintf("HTTP %d: the news index is rate-limiting or unavailable; try again in a minute", status)}})
			break
		}
		for _, a := range arts {
			if !seen[a.URL] {
				seen[a.URL] = true
				all = append(all, a)
			}
		}
	}
	if len(all) == 0 {
		return nil
	}
	hints := contextWords(t)
	type scored struct {
		a     article
		match []string
	}
	var rows []scored
	for _, a := range all {
		low := strings.Join(identity.Words(a.Title), " ")
		// the headline must name the person (all words) to be listed at all
		ok := true
		for _, w := range identity.Words(t.FullName) {
			if !strings.Contains(low, w) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		var hit []string
		for _, h := range hints {
			if strings.Contains(low, h) {
				hit = append(hit, h)
			}
		}
		rows = append(rows, scored{a, hit})
	}
	if len(rows) == 0 {
		return nil
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if (len(rows[i].match) > 0) != (len(rows[j].match) > 0) {
			return len(rows[i].match) > 0
		}
		return rows[i].a.SeenDate > rows[j].a.SeenDate
	})
	ctxN := 0
	var lines []string
	first, last := "", ""
	for i, r := range rows {
		date := isoDate(r.a.SeenDate)
		if first == "" || date < first {
			first = date
		}
		if date > last {
			last = date
		}
		if len(r.match) > 0 {
			ctxN++
		}
		if i < 15 {
			tag := ""
			if len(r.match) > 0 {
				tag = " ✔ context: " + strings.Join(r.match, ", ")
			}
			lines = append(lines, fmt.Sprintf("%s · %s · %s%s — %s", date, r.a.Domain, r.a.Country, tag, clip(r.a.Title, 110)))
		}
	}
	det := map[string]string{"articles naming the person": fmt.Sprint(len(rows)), "also matching your other details": fmt.Sprint(ctxN),
		"first mention": first, "latest mention": last, "newest first (✔ = headline also has one of your details)": strings.Join(lines, "; "),
		"note": "headlines only, from roughly the last year; any person with this name matches. Only the ✔ lines have supporting context"}
	conf := 0.35
	if ctxN > 0 {
		conf = 0.6
	}
	emit(models.Finding{Source: "Press mentions (GDELT)", Category: "mentions", Status: models.StatusUncertain, Confidence: conf,
		URL: "https://api.gdeltproject.org/api/v2/doc/doc?mode=artlist&query=" + url.QueryEscape(`"`+t.FullName+`"`), Details: det})
	return nil
}

func contextWords(t models.Target) []string {
	var out []string
	add := func(s string) {
		for _, w := range identity.Words(s) {
			if len(w) >= 4 {
				out = append(out, w)
			}
		}
	}
	add(t.Company)
	add(t.Location)
	if i := strings.Index(t.Email, "@"); i > 0 {
		if dom := strings.SplitN(t.Email[i+1:], ".", 2)[0]; len(dom) >= 4 && !commonMail[dom] {
			out = append(out, dom)
		}
	}
	return out
}

var commonMail = map[string]bool{"gmail": true, "yahoo": true, "hotmail": true, "outlook": true, "icloud": true, "proton": true, "protonmail": true, "live": true}

func fetch(ctx context.Context, c *httpx.Client, name string) ([]article, int) {
	u := "https://api.gdeltproject.org/api/v2/doc/doc?mode=artlist&format=json&maxrecords=75&sort=datedesc&timespan=12months&query=" + url.QueryEscape(`"`+name+`"`)
	resp, err := c.Do(ctx, httpx.Request{URL: u, Timeout: 40 * time.Second, MaxBody: 4 << 20})
	if err != nil {
		return nil, 0
	}
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode
	}
	var r struct {
		Articles []article `json:"articles"`
	}
	if json.Unmarshal(resp.Body, &r) != nil {
		// GDELT answers 200 with a plain-text rate-limit notice
		return nil, 429
	}
	return r.Articles, 200
}

func isoDate(s string) string { // 20260115T093000Z
	if len(s) >= 8 {
		return s[:4] + "-" + s[4:6] + "-" + s[6:8]
	}
	return s
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
