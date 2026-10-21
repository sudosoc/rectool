// Package people finds *candidate profiles* of a person and returns them as
// structured Records for identity resolution: LinkedIn's public profile view,
// ORCID, Wikidata, OpenAlex, GitHub, personal CV documents.
//
// A name is ambiguous. Nothing here decides which "Jane Roe" the operator
// means: every candidate is returned as its own record, and the identity
// package keeps different people apart and ranks them against what the
// operator supplied (location, employer, e-mail, …).
package people

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/identity"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/modules/dorks"
	"github.com/sudosoc/rectool/internal/scanner"
)

// Config tunes the module.
type Config struct {
	Searcher *dorks.Searcher // shared scraper, used by the CV finder; optional
	Browser  bool            // fall back to the local headless browser when LinkedIn refuses the HTTP client
}

// Scanner is the people module.
type Scanner struct{ cfg Config }

var _ scanner.Scanner = (*Scanner)(nil)

// New builds the module.
func New(cfg Config) *Scanner { return &Scanner{cfg: cfg} }

func (s *Scanner) Name() string { return "people" }
func (s *Scanner) Description() string {
	return "candidate profiles for a name: LinkedIn public view, ORCID, Wikidata, OpenAlex, GitHub, CVs"
}

func hasLinkedIn(t models.Target) bool {
	for _, l := range t.Links {
		if strings.Contains(strings.ToLower(l), "linkedin.com/") {
			return true
		}
	}
	return false
}

func (s *Scanner) CanRun(t models.Target) bool {
	return len(strings.Fields(t.FullName)) >= 2 || hasLinkedIn(t) || strings.TrimSpace(t.Username) != "" || len(t.Links) > 0 || strings.TrimSpace(t.Notes) != ""
}

type job struct {
	name string
	run  func(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding))
}

func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	jobs := []job{
		{"linkedin", func(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
			linkedIn(ctx, c, t, emit, s.cfg.Browser)
		}},
		{"orcid", orcid},
		{"wikidata", wikidata},
		{"openalex", openAlex},
		{"github", githubPeople},
		{"notes", pastedProfile},
		{"crossref", crossref},
		{"wikipedia", wikipediaPerson},
		{"archiveorg", archiveOrg},
		{"arxiv", arxiv},
		{"europepmc", europePMC},
		{"inspire", inspire},
		{"frcompanies", franceCompanies},
		{"musicbrainz", musicBrainz},
		{"bluesky", blueskySearch},
		{"mastodon", mastodonSearch},
		{"stackoverflow", stackExchange},
		{"huggingface", huggingFace},
		{"webfinger", webfinger},
		{"archive", archived},
	}
	if s.cfg.Searcher != nil {
		search := s.cfg.Searcher
		jobs = append(jobs, job{"cv", func(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
			cvFinder(ctx, c, search, t, emit)
		}})
	}
	// Other spellings of the name (Mohamed / Muhammad, Arabic / Latin) get the
	// registry lookups too; identity resolution knows they are the same name.
	type run struct {
		job
		t models.Target
	}
	var runs []run
	for _, j := range jobs {
		runs = append(runs, run{j, t})
	}
	for _, v := range identity.LatinVariants(t.FullName, 2) {
		tv := t
		tv.FullName = v
		for _, j := range jobs {
			switch j.name {
			case "orcid", "wikidata", "openalex", "crossref", "wikipedia", "stackoverflow", "huggingface", "bluesky", "mastodon", "arxiv", "europepmc", "inspire", "frcompanies", "musicbrainz":
				runs = append(runs, run{j, tv})
			}
		}
	}
	var (
		wg   sync.WaitGroup
		done atomic.Int64
	)
	for _, r := range runs {
		wg.Add(1)
		j, t := r.job, r.t
		if err := d.Pool.Submit(ctx, func() {
			defer wg.Done()
			j.run(ctx, d.HTTP, t, emit)
			if d.Progress != nil {
				d.Progress(s.Name(), int(done.Add(1)), len(runs))
			}
		}); err != nil {
			wg.Done()
			break
		}
	}
	wg.Wait()
	return ctx.Err()
}

// ------------------------------------------------------------------ helpers

func getJSON(ctx context.Context, c *httpx.Client, u string, hdr map[string]string, out any) bool {
	if hdr == nil {
		hdr = map[string]string{}
	}
	if hdr["Accept"] == "" {
		hdr["Accept"] = "application/json"
	}
	resp, err := c.Do(ctx, httpx.Request{URL: u, Timeout: 25 * time.Second, Headers: hdr})
	if err != nil || resp.StatusCode != 200 {
		return false
	}
	return json.Unmarshal(resp.Body, out) == nil
}

func esc(s string) string { return url.QueryEscape(s) }

func nameMatches(a, b string) bool { return identity.MatchNames(a, b) == identity.NameStrong }

// trusted reports whether a candidate record already agrees with what the
// operator supplied strongly enough that its leads (e-mail, website, handles)
// may be followed automatically. Everything else is shown but not followed
// until identity resolution picks that person.
func trusted(rec models.Record, t models.Target) bool {
	if t.FullName != "" && identity.MatchNames(t.FullName, rec.Name) != identity.NameStrong {
		return false
	}
	res := identity.Resolve([]identity.Input{{Rec: rec}}, identity.FromTarget(t))
	if len(res.Identities) == 0 {
		return false
	}
	m := res.Identities[0].Matched
	for _, k := range m {
		if k != "name" && k != "name (partial)" {
			return true
		}
	}
	return false
}

// finding turns a Record into a finding with a readable detail summary, and
// entities for its contact points (strong only when the record is trusted).
func finding(source, category string, conf float64, rec models.Record, t models.Target) models.Finding {
	d := map[string]string{}
	set := func(k, v string) {
		if v = strings.TrimSpace(v); v != "" {
			d[k] = v
		}
	}
	set("name", rec.Name)
	set("headline", rec.Headline)
	set("current roles", strings.Join(rec.Roles, "; "))
	set("employers", strings.Join(rec.Employers, "; "))
	set("location", rec.Location)
	set("education", strings.Join(rec.Education, "; "))
	set("interests", strings.Join(rec.Interests, ", "))
	set("emails", strings.Join(rec.Emails, ", "))
	set("phones", strings.Join(rec.Phones, ", "))
	set("websites", strings.Join(rec.Websites, ", "))
	set("about", clip(rec.Bio, 400))
	set("avatar", rec.Photo)
	for k, v := range rec.IDs {
		set(k+" id", v)
	}
	var ents []models.Entity
	strong := trusted(rec, t)
	for _, e := range rec.Emails {
		ents = append(ents, models.Entity{Type: models.EntEmail, Value: e, Strong: strong})
	}
	for _, p := range rec.Phones {
		ents = append(ents, models.Entity{Type: models.EntPhone, Value: p})
	}
	for _, w := range rec.Websites {
		if dom := domainOf(w); dom != "" {
			ents = append(ents, models.Entity{Type: models.EntDomain, Value: dom, Strong: strong})
		}
	}
	if rec.Name != "" {
		ents = append(ents, models.Entity{Type: models.EntName, Value: rec.Name})
	}
	if rec.Location != "" {
		ents = append(ents, models.Entity{Type: models.EntLocation, Value: rec.Location})
	}
	for _, e := range rec.Employers {
		ents = append(ents, models.Entity{Type: models.EntOrg, Value: e})
	}
	r := rec
	return models.Finding{Source: source, Category: category, URL: rec.URL, Status: models.StatusFound,
		Confidence: conf, Details: d, Entities: ents, Record: &r}
}

func domainOf(raw string) string {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	h := strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
	switch h {
	case "", "twitter.com", "x.com", "github.com", "linkedin.com", "facebook.com", "instagram.com", "youtube.com", "medium.com", "gitlab.com", "orcid.org", "scholar.google.com", "researchgate.net":
		return ""
	}
	if !strings.Contains(h, ".") {
		return ""
	}
	return h
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func errFinding(source string, msg string) models.Finding {
	return models.Finding{Source: source, Category: "identity", Status: models.StatusError, Details: map[string]string{"error": msg}}
}
