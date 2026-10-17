// Package company researches an organisation name: likely web domains
// (verified against the live site), Wikipedia/Wikidata entries and the
// GitHub organisation, and hands the discovered domains and e-mail addresses
// to the engine as follow-up leads.
package company

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sudosoc/rectool/internal/extract"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/intel"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/probe"
	"github.com/sudosoc/rectool/internal/scanner"
)

// Scanner is the company module.
type Scanner struct{}

var _ scanner.Scanner = (*Scanner)(nil)

// New builds the module.
func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "company" }
func (s *Scanner) Description() string {
	return "organisation: likely websites, Wikipedia/Wikidata, GitHub org"
}
func (s *Scanner) CanRun(t models.Target) bool { return t.Company != "" }

var legalSuffix = map[string]bool{"inc": true, "llc": true, "ltd": true, "limited": true, "corp": true,
	"corporation": true, "co": true, "company": true, "gmbh": true, "sa": true, "plc": true, "ag": true,
	"bv": true, "srl": true, "pty": true, "llp": true, "lp": true, "the": true, "and": false}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// slugs returns candidate host labels for a company name.
func slugs(name string) []string {
	var words []string
	for _, w := range strings.Fields(strings.ToLower(name)) {
		w = nonAlnum.ReplaceAllString(w, "")
		if w != "" && !legalSuffix[w] {
			words = append(words, w)
		}
	}
	if len(words) == 0 {
		return nil
	}
	out := []string{strings.Join(words, "")}
	if len(words) > 1 {
		out = append(out, strings.Join(words, "-"))
	}
	return out
}

func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	name := t.Company
	type job func()
	var jobs []job

	// Candidate websites are buffered: guessed domains routinely include
	// parked or look-alike sites whose pages merely mention the name, so only
	// the single best match may become a followed lead.
	var (
		cmu   sync.Mutex
		cands []models.Finding
	)
	collect := func(f models.Finding) {
		cmu.Lock()
		cands = append(cands, f)
		cmu.Unlock()
	}
	tokens := nameTokens(name)
	for _, slug := range slugs(name) {
		for _, tld := range tldOrder {
			host := slug + "." + tld
			jobs = append(jobs, func() { candidateSite(ctx, d.HTTP, host, tokens, collect) })
		}
	}
	jobs = append(jobs,
		func() { wikipedia(ctx, d.HTTP, name, emit) },
		func() { wikidata(ctx, d.HTTP, name, emit) },
		func() { gleif(ctx, d.HTTP, name, tokens, emit) },
	)
	for _, slug := range slugs(name) {
		jobs = append(jobs, func() { githubOrg(ctx, d.HTTP, slug, emit) })
	}

	var (
		wg   sync.WaitGroup
		done atomic.Int64
	)
	for _, j := range jobs {
		wg.Add(1)
		err := d.Pool.Submit(ctx, func() {
			defer wg.Done()
			j()
			if d.Progress != nil {
				d.Progress(s.Name(), int(done.Add(1)), len(jobs))
			}
		})
		if err != nil {
			wg.Done()
			break
		}
	}
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	for _, f := range pickBest(cands, t.Domain) {
		emit(f)
	}
	return nil
}

var tldOrder = []string{"com", "org", "io", "net", "co", "ai", "app", "dev", "eu"}

func tldRank(host string) int {
	for i, t := range tldOrder {
		if strings.HasSuffix(host, "."+t) {
			return i
		}
	}
	return len(tldOrder)
}

// pickBest keeps every candidate in the report but lets at most one verified
// website (the operator's own domain if it is among them, else the most
// "official-looking" TLD) carry a strong, followed domain entity.
func pickBest(cands []models.Finding, known string) []models.Finding {
	isStrong := func(f models.Finding) bool { return len(f.Entities) > 0 && f.Entities[0].Strong }
	best, bestKnown := -1, false
	for i, f := range cands {
		if !isStrong(f) {
			continue
		}
		host := f.Entities[0].Value
		isKnown := known != "" && (host == known || strings.HasSuffix(known, "."+host))
		switch {
		case best < 0:
			best, bestKnown = i, isKnown
		case isKnown && !bestKnown:
			best, bestKnown = i, true
		case isKnown == bestKnown && tldRank(host) < tldRank(cands[best].Entities[0].Value):
			best = i
		}
	}
	for i := range cands {
		if isStrong(cands[i]) && i != best {
			cands[i].Entities[0].Strong = false
			cands[i].Confidence = 0.5
			cands[i].Details["verification"] += "; another candidate domain was preferred — this one may be parked or a look-alike"
		}
	}
	sort.SliceStable(cands, func(a, b int) bool { return cands[a].Source < cands[b].Source })
	return cands
}

func nameTokens(name string) []string {
	var out []string
	for _, w := range strings.Fields(strings.ToLower(name)) {
		w = nonAlnum.ReplaceAllString(w, "")
		if len(w) >= 3 && !legalSuffix[w] {
			out = append(out, w)
		}
	}
	return out
}

func fnd(source, category, link string, conf float64, d map[string]string, ents ...models.Entity) models.Finding {
	return models.Finding{Source: source, Category: category, URL: link,
		Status: models.StatusFound, Confidence: conf, Details: d, Entities: ents}
}

func put(d map[string]string, k, v string) {
	if v = strings.TrimSpace(v); v != "" {
		d[k] = v
	}
}

func getJSON(ctx context.Context, c *httpx.Client, u string, out any) bool {
	resp, err := c.Do(ctx, httpx.Request{URL: u, Timeout: 15 * time.Second, Headers: map[string]string{"Accept": "application/json"}})
	if err != nil || resp.StatusCode != 200 {
		return false
	}
	return json.Unmarshal(resp.Body, out) == nil
}

// candidateSite checks whether a guessed domain exists and really belongs to
// the company (its title/description/site name mentions the name).
func candidateSite(ctx context.Context, c *httpx.Client, host string, tokens []string, emit func(models.Finding)) {
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	ips, err := net.DefaultResolver.LookupHost(lctx, host)
	cancel()
	if err != nil || len(ips) == 0 {
		return
	}
	w, err := probe.FetchWeb(ctx, c, host)
	if err != nil {
		return
	}
	hay := strings.ToLower(w.Meta.Title + " " + w.Meta.Description + " " + w.Meta.OGSiteName)
	match := len(tokens) > 0
	for _, tk := range tokens {
		if !strings.Contains(hay, tk) {
			match = false
		}
	}
	d := map[string]string{"final URL": w.FinalURL, "status": strconv.Itoa(w.Status)}
	put(d, "title", w.Meta.Title)
	put(d, "description", w.Meta.Description)
	conf := 0.3
	if match {
		conf = 0.75
		d["verification"] = "company name appears in the page title/description"
	} else {
		d["verification"] = "domain exists but the page does not mention the company name (could be unrelated)"
	}
	if emails := extract.Emails(w.Body); len(emails) > 0 {
		d["emails on page"] = strings.Join(emails, ", ")
	}
	var ents []models.Entity
	if dom, ok := intel.NormalizeDomain(host); ok {
		ents = append(ents, models.Entity{Type: models.EntDomain, Value: dom, Strong: match})
	}
	emit(fnd("Possible website: "+host, "website", w.FinalURL, conf, d, ents...))
}

func wikipedia(ctx context.Context, c *httpx.Client, name string, emit func(models.Finding)) {
	var r struct {
		Type        string `json:"type"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Extract     string `json:"extract"`
		ContentURLs struct {
			Desktop struct {
				Page string `json:"page"`
			} `json:"desktop"`
		} `json:"content_urls"`
	}
	title := strings.ReplaceAll(strings.TrimSpace(name), " ", "_")
	if !getJSON(ctx, c, "https://en.wikipedia.org/api/rest_v1/page/summary/"+url.PathEscape(title), &r) ||
		r.Type == "disambiguation" || r.Extract == "" {
		return
	}
	d := map[string]string{}
	put(d, "title", r.Title)
	put(d, "description", r.Description)
	ex := r.Extract
	if len(ex) > 500 {
		ex = ex[:500] + "…"
	}
	put(d, "summary", ex)
	emit(fnd("Wikipedia article", "reference", r.ContentURLs.Desktop.Page, 0.6, d))
}

func wikidata(ctx context.Context, c *httpx.Client, name string, emit func(models.Finding)) {
	var r struct {
		Search []struct {
			ID          string `json:"id"`
			Label       string `json:"label"`
			Description string `json:"description"`
		} `json:"search"`
	}
	if !getJSON(ctx, c, "https://www.wikidata.org/w/api.php?action=wbsearchentities&language=en&format=json&limit=5&search="+url.QueryEscape(name), &r) ||
		len(r.Search) == 0 {
		return
	}
	var items []string
	for _, s := range r.Search {
		items = append(items, s.Label+" — "+s.Description+" ("+s.ID+")")
	}
	sort.Strings(items)
	emit(fnd("Wikidata entities", "reference", "https://www.wikidata.org/wiki/"+r.Search[0].ID, 0.4,
		map[string]string{"matches": strings.Join(items, " | "), "note": "name matches only; verify it is the same organisation"}))
}

func githubOrg(ctx context.Context, c *httpx.Client, slug string, emit func(models.Finding)) {
	var r struct {
		Login       string `json:"login"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Blog        string `json:"blog"`
		Location    string `json:"location"`
		Email       string `json:"email"`
		Twitter     string `json:"twitter_username"`
		HTMLURL     string `json:"html_url"`
		PublicRepos int    `json:"public_repos"`
		Followers   int    `json:"followers"`
		CreatedAt   string `json:"created_at"`
	}
	if !getJSON(ctx, c, "https://api.github.com/orgs/"+url.PathEscape(slug), &r) || r.Login == "" {
		return
	}
	d := map[string]string{"public repos": strconv.Itoa(r.PublicRepos), "followers": strconv.Itoa(r.Followers)}
	put(d, "name", r.Name)
	put(d, "description", r.Description)
	put(d, "website", r.Blog)
	put(d, "location", r.Location)
	put(d, "public email", r.Email)
	put(d, "twitter", r.Twitter)
	put(d, "created", r.CreatedAt)
	var ents []models.Entity
	if dom, ok := intel.NormalizeDomain(r.Blog); ok {
		ents = append(ents, models.Entity{Type: models.EntDomain, Value: dom, Strong: true})
	}
	if strings.Contains(r.Email, "@") {
		ents = append(ents, models.Entity{Type: models.EntEmail, Value: strings.ToLower(r.Email), Strong: true})
	}
	emit(fnd("GitHub organisation", "profile", r.HTMLURL, 0.6, d, ents...))
}
