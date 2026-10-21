// Package sitefiles reads the small public files and feeds a website serves
// about itself and its people: humans.txt (credits), ads.txt (advertising
// accounts and thus owner links), WordPress author lists, and RSS/Atom feeds.
// Everything is a normal GET of a URL the site publishes.
package sitefiles

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

type Scanner struct{}

var _ scanner.Scanner = (*Scanner)(nil)

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "sitefiles" }
func (s *Scanner) Description() string {
	return "people and accounts a site publishes about itself: humans.txt, ads.txt, WordPress authors, feed authors"
}
func (s *Scanner) CanRun(t models.Target) bool { return strings.TrimSpace(t.Domain) != "" }

func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	base := "https://" + strings.TrimSpace(t.Domain)
	jobs := []func(){
		func() { humans(ctx, d.HTTP, base, emit) },
		func() { adsTxt(ctx, d.HTTP, base, emit) },
		func() { wpUsers(ctx, d.HTTP, base, emit) },
		func() { feeds(ctx, d.HTTP, base, emit) },
	}
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		j := j
		if err := d.Pool.Submit(ctx, func() { defer wg.Done(); j() }); err != nil {
			wg.Done()
			break
		}
	}
	wg.Wait()
	return ctx.Err()
}

func get(ctx context.Context, c *httpx.Client, u string, max int64) (*httpx.Response, bool) {
	resp, err := c.Do(ctx, httpx.Request{URL: u, Timeout: 20 * time.Second, MaxBody: max})
	if err != nil || resp.StatusCode != 200 {
		return nil, false
	}
	return resp, true
}

var (
	emailRe  = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	htmlOpen = regexp.MustCompile(`(?is)<(!doctype|html|head|body)`)
)

// humans reads humans.txt: a credits file naming the people who built the site.
func humans(ctx context.Context, c *httpx.Client, base string, emit func(models.Finding)) {
	resp, ok := get(ctx, c, base+"/humans.txt", 200<<10)
	if !ok || htmlOpen.Match(resp.Body) {
		return
	}
	text := string(resp.Body)
	var ents []models.Entity
	seen := map[string]bool{}
	for _, e := range emailRe.FindAllString(text, 20) {
		if !seen[strings.ToLower(e)] {
			seen[strings.ToLower(e)] = true
			ents = append(ents, models.Entity{Type: models.EntEmail, Value: strings.ToLower(e)})
		}
	}
	var lines []string
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l != "" && len(lines) < 25 {
			lines = append(lines, l)
		}
	}
	emit(models.Finding{Source: "humans.txt", Category: "site-people", URL: base + "/humans.txt", Status: models.StatusFound, Confidence: 0.8,
		Details: map[string]string{"credits": strings.Join(lines, " | "), "note": "written by the site's own team: names, roles, contact addresses"}, Entities: ents})
}

// adsTxt lists the advertising accounts the site authorises. The publisher
// IDs identify the business behind the site and link its sister sites.
func adsTxt(ctx context.Context, c *httpx.Client, base string, emit func(models.Finding)) {
	resp, ok := get(ctx, c, base+"/ads.txt", 400<<10)
	if !ok || htmlOpen.Match(resp.Body) {
		return
	}
	nets := map[string]map[string]bool{}
	owner := []string{}
	for _, l := range strings.Split(string(resp.Body), "\n") {
		if i := strings.Index(l, "#"); i >= 0 {
			l = l[:i]
		}
		l = strings.TrimSpace(l)
		if strings.HasPrefix(strings.ToLower(l), "ownerdomain=") || strings.HasPrefix(strings.ToLower(l), "managerdomain=") || strings.HasPrefix(strings.ToLower(l), "contact=") {
			owner = append(owner, l)
			continue
		}
		f := strings.Split(l, ",")
		if len(f) < 3 {
			continue
		}
		dom, id := strings.ToLower(strings.TrimSpace(f[0])), strings.TrimSpace(f[1])
		if dom == "" || id == "" {
			continue
		}
		if nets[dom] == nil {
			nets[dom] = map[string]bool{}
		}
		nets[dom][id] = true
	}
	if len(nets) == 0 && len(owner) == 0 {
		return
	}
	var parts []string
	for dom, ids := range nets {
		var l []string
		for id := range ids {
			l = append(l, id)
		}
		sort.Strings(l)
		if len(l) > 3 {
			l = append(l[:3], fmt.Sprintf("+%d", len(l)-3))
		}
		parts = append(parts, dom+": "+strings.Join(l, ", "))
	}
	sort.Strings(parts)
	if len(parts) > 15 {
		parts = parts[:15]
	}
	det := map[string]string{"ad networks": fmt.Sprint(len(nets)), "publisher accounts": strings.Join(parts, " | "),
		"note": "the same publisher ID on another site means the same business or owner; search the ID to find sister sites"}
	if len(owner) > 0 {
		det["declared owner / contact"] = strings.Join(owner, "; ")
	}
	emit(models.Finding{Source: "ads.txt", Category: "site-people", URL: base + "/ads.txt", Status: models.StatusFound, Confidence: 0.7, Details: det})
}

// wpUsers reads the public WordPress REST author list (the same data every
// byline links to): display names, profile links and descriptions.
func wpUsers(ctx context.Context, c *httpx.Client, base string, emit func(models.Finding)) {
	resp, ok := get(ctx, c, base+"/wp-json/wp/v2/users?per_page=50", 1<<20)
	if !ok {
		return
	}
	var users []struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
		Link string `json:"link"`
		URL  string `json:"url"`
		Desc string `json:"description"`
	}
	if json.Unmarshal(resp.Body, &users) != nil || len(users) == 0 {
		return
	}
	var lines []string
	var ents []models.Entity
	for _, u := range users {
		line := html.UnescapeString(u.Name)
		if u.Desc != "" {
			line += " — " + clip(strings.Join(strings.Fields(html.UnescapeString(u.Desc)), " "), 100)
		}
		lines = append(lines, line)
		if strings.Contains(strings.TrimSpace(u.Name), " ") {
			ents = append(ents, models.Entity{Type: models.EntName, Value: html.UnescapeString(u.Name)})
		}
		if u.Slug != "" && len(u.Slug) >= 3 {
			ents = append(ents, models.Entity{Type: models.EntUsername, Value: u.Slug})
		}
	}
	emit(models.Finding{Source: "WordPress authors", Category: "site-people", URL: base + "/wp-json/wp/v2/users", Status: models.StatusFound, Confidence: 0.75,
		Details: map[string]string{"authors": fmt.Sprint(len(users)), "who": strings.Join(lines, " | "),
			"note": "the site's public author list; a slug is also the author's WordPress login name"}, Entities: ents})
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

var feedLink = regexp.MustCompile(`(?i)<link[^>]+type=["']application/(?:rss|atom)\+xml["'][^>]*>`)
var hrefAttr = regexp.MustCompile(`(?i)href=["']([^"']+)["']`)

// feeds finds the RSS / Atom feed from the home page and lists the authors.
func feeds(ctx context.Context, c *httpx.Client, base string, emit func(models.Finding)) {
	home, ok := get(ctx, c, base+"/", 2<<20)
	if !ok {
		return
	}
	var link string
	if m := feedLink.FindString(string(home.Body)); m != "" {
		if h := hrefAttr.FindStringSubmatch(m); h != nil {
			link = h[1]
		}
	}
	if link == "" {
		link = "/feed"
	}
	bu, _ := url.Parse(base + "/")
	ref, err := url.Parse(html.UnescapeString(link))
	if err != nil {
		return
	}
	fu := bu.ResolveReference(ref).String()
	resp, ok := get(ctx, c, fu, 2<<20)
	if !ok {
		return
	}
	var rss struct {
		Channel struct {
			Title string `xml:"title"`
			Items []struct {
				Creator string `xml:"creator"`
				Author  string `xml:"author"`
			} `xml:"item"`
		} `xml:"channel"`
	}
	var atom struct {
		Title   string `xml:"title"`
		Entries []struct {
			Author struct {
				Name  string `xml:"name"`
				Email string `xml:"email"`
			} `xml:"author"`
		} `xml:"entry"`
	}
	authors := map[string]int{}
	title := ""
	if xml.Unmarshal(resp.Body, &rss) == nil && len(rss.Channel.Items) > 0 {
		title = rss.Channel.Title
		for _, it := range rss.Channel.Items {
			if n := strings.TrimSpace(firstNon(it.Creator, it.Author)); n != "" {
				authors[n]++
			}
		}
	} else if xml.Unmarshal(resp.Body, &atom) == nil && len(atom.Entries) > 0 {
		title = atom.Title
		for _, e := range atom.Entries {
			if n := strings.TrimSpace(e.Author.Name); n != "" {
				authors[n]++
			}
		}
	}
	if len(authors) == 0 {
		return
	}
	var names []string
	var ents []models.Entity
	for n, k := range authors {
		names = append(names, fmt.Sprintf("%s (%d post)", n, k))
		if strings.Contains(n, " ") && !strings.Contains(n, "@") {
			ents = append(ents, models.Entity{Type: models.EntName, Value: n})
		}
	}
	sort.Strings(names)
	emit(models.Finding{Source: "Feed authors", Category: "site-people", URL: fu, Status: models.StatusFound, Confidence: 0.65,
		Details: map[string]string{"feed": title, "authors in recent posts": strings.Join(names, "; ")}, Entities: ents})
}

func firstNon(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
