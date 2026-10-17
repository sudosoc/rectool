// Package dorks implements the search-engine dorking module: it generates
// operator-based queries from the target's identifiers, scrapes the result
// pages (no API keys) and reports the hits as leads.
package dorks

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

// Config tunes the module.
type Config struct {
	Searcher *Searcher     // shared scraper; built from Engines/Delay when nil
	Engines  []string      // used only when Searcher is nil
	Delay    time.Duration // used only when Searcher is nil
	MaxDorks int           // cap on generated queries (default 30)
}

// Scanner is the dorking module.
type Scanner struct {
	cfg    Config
	search *Searcher
}

var _ scanner.Scanner = (*Scanner)(nil)

// New validates the config and builds the module.
func New(cfg Config) (*Scanner, error) {
	if cfg.MaxDorks <= 0 {
		cfg.MaxDorks = 30
	}
	if cfg.Searcher == nil {
		s, err := NewSearcher(cfg.Engines, cfg.Delay)
		if err != nil {
			return nil, err
		}
		cfg.Searcher = s
	}
	return &Scanner{cfg: cfg, search: cfg.Searcher}, nil
}

func (s *Scanner) Name() string        { return "dorks" }
func (s *Scanner) Description() string { return "search-engine dorking from name/email/username/phone" }
func (s *Scanner) CanRun(t models.Target) bool {
	return !t.IsEmpty()
}

// Scan runs each dork on the shared pool; the Searcher's rate limiting keeps
// the request cadence slow regardless of pool size.
func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	dorks := Generate(t)
	if len(dorks) > s.cfg.MaxDorks {
		dorks = dorks[:s.cfg.MaxDorks]
	}

	var (
		wg   sync.WaitGroup
		done atomic.Int64
		seen sync.Map // result URL -> struct{}
	)
	for _, dk := range dorks {
		wg.Add(1)
		err := d.Pool.Submit(ctx, func() {
			defer wg.Done()
			s.run(ctx, d.HTTP, dk, &seen, emit)
			if d.Progress != nil {
				d.Progress(s.Name(), int(done.Add(1)), len(dorks))
			}
		})
		if err != nil {
			wg.Done()
			break
		}
	}
	wg.Wait()
	return ctx.Err()
}

func (s *Scanner) run(ctx context.Context, c *httpx.Client, dk Dork, seen *sync.Map, emit func(models.Finding)) {
	results, engine, err := s.search.Search(ctx, c, dk.Query)
	if err != nil {
		if ctx.Err() == nil {
			emit(models.Finding{Source: dk.Query, Category: dk.Category, Status: models.StatusError,
				Details: map[string]string{"error": err.Error()}})
		}
		return
	}
	for rank, r := range results {
		if !matchesSite(dk.Query, r.URL) || !relevant(dk.Query, r) {
			continue // engine ignored an operator / served unrelated pages
		}
		if _, dup := seen.LoadOrStore(r.URL, struct{}{}); dup {
			continue
		}
		emit(models.Finding{
			Source:     dk.Query,
			Category:   dk.Category,
			URL:        r.URL,
			Status:     models.StatusFound,
			Confidence: 0.4, // a search hit is a lead, not proof of identity
			Details: map[string]string{
				"title": r.Title, "engine": engine, "rank": strconv.Itoa(rank + 1), "host": host(r.URL),
			},
		})
	}
}

var siteOpRe = regexp.MustCompile(`(?:^|[\s(])site:([A-Za-z0-9.-]+)`)

// matchesSite enforces positive site: operators client-side, because some
// engines silently ignore operators and return unrelated pages. A query with
// several site: terms (OR-ed) matches if the URL's host fits any of them.
func matchesSite(query, rawURL string) bool {
	ms := siteOpRe.FindAllStringSubmatch(query, -1)
	if len(ms) == 0 {
		return true
	}
	h := host(rawURL)
	for _, m := range ms {
		if h == m[1] || strings.HasSuffix(h, "."+m[1]) {
			return true
		}
	}
	return false
}

var quotedRe = regexp.MustCompile(`"([^"]{3,})"`)

// relevant drops results that do not mention the dork's first quoted phrase
// anywhere in title, URL or snippet. Engines facing a scraper often return
// generic filler pages; this keeps the report to plausible leads. Queries
// without a quoted phrase are not filtered.
func relevant(query string, r result) bool {
	m := quotedRe.FindStringSubmatch(query)
	if m == nil {
		return true
	}
	hay := strings.ToLower(r.Title + " " + r.URL + " " + r.Snippet)
	for _, tok := range strings.FieldsFunc(strings.ToLower(m[1]), func(c rune) bool { return c == ' ' }) {
		if !strings.Contains(hay, tok) {
			return false
		}
	}
	return true
}
