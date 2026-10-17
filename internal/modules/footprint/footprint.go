// Package footprint maps the public digital footprint of an email address or
// phone number using only public, unauthenticated sources: DNS, Gravatar's
// public avatar endpoint, and search-engine scraping whose hits are verified
// by fetching each page and confirming the identifier really appears on it.
//
// It deliberately does not query or download breach/credential databases.
package footprint

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/modules/dorks"
	"github.com/sudosoc/rectool/internal/scanner"
)

// Config tunes the module.
type Config struct {
	Searcher   *dorks.Searcher // shared scraper (recommended); a default is built when nil
	MaxResults int             // search hits examined per query (default 8)
}

// Scanner is the digital-footprint module.
type Scanner struct {
	cfg    Config
	search *dorks.Searcher
}

var _ scanner.Scanner = (*Scanner)(nil)

// New builds the module.
func New(cfg Config) (*Scanner, error) {
	if cfg.MaxResults <= 0 {
		cfg.MaxResults = 8
	}
	if cfg.Searcher == nil {
		s, err := dorks.NewSearcher(nil, 0)
		if err != nil {
			return nil, err
		}
		cfg.Searcher = s
	}
	return &Scanner{cfg: cfg, search: cfg.Searcher}, nil
}

func (s *Scanner) Name() string { return "footprint" }
func (s *Scanner) Description() string {
	return "email/phone public footprint: MX, Gravatar, verified web mentions"
}
func (s *Scanner) CanRun(t models.Target) bool { return t.Email != "" || t.Phone != "" }

// Scan queues every check on the shared pool.
func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	var jobs []func()
	seen := &sync.Map{} // result URL -> struct{}

	if e := t.Email; strings.Contains(e, "@") {
		jobs = append(jobs,
			func() { emit(emailMX(ctx, e)) },
			func() { gravatar(ctx, d.HTTP, e, emit) },
			func() { infostealer(ctx, d.HTTP, e, emit) },
			func() { githubByEmail(ctx, d.HTTP, e, emit) })
		m := emailMatcher(e)
		for _, q := range emailQueries(e) {
			jobs = append(jobs, func() { s.mentions(ctx, d.HTTP, "email", q, m, seen, emit) })
		}
	}
	if t.Phone != "" {
		pi := parsePhone(t.Phone)
		m := pi.matcher()
		vs := pi.variants()
		if len(vs) > 3 {
			vs = vs[:3]
		}
		for _, v := range vs {
			jobs = append(jobs, func() { s.mentions(ctx, d.HTTP, "phone", `"`+v+`"`, m, seen, emit) })
		}
	}

	var (
		wg   sync.WaitGroup
		done atomic.Int64
	)
	for _, job := range jobs {
		wg.Add(1)
		err := d.Pool.Submit(ctx, func() {
			defer wg.Done()
			job()
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
	return ctx.Err()
}

// mentions searches for query, fetches each hit, and emits only pages whose
// text really contains the identifier. This is what separates a verified
// public mention from a search engine's guess.
func (s *Scanner) mentions(ctx context.Context, c *httpx.Client, kind, query string, m matcher, seen *sync.Map, emit func(models.Finding)) {
	results, engine, err := s.search.Search(ctx, c, query)
	if err != nil {
		if ctx.Err() == nil {
			emit(models.Finding{Source: "mention search: " + query, Category: kind + "-mention",
				Status: models.StatusError, Details: map[string]string{"error": err.Error()}})
		}
		return
	}
	if len(results) > s.cfg.MaxResults {
		results = results[:s.cfg.MaxResults]
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for rank, r := range results {
		if _, dup := seen.LoadOrStore(r.URL, struct{}{}); dup {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			text := pageText(ctx, c, r.URL)
			if text == "" {
				return
			}
			snippet, conf, ok := m.find(text)
			if !ok {
				return
			}
			emit(models.Finding{
				Source: "mention (" + kind + ")", Category: kind + "-mention", URL: r.URL,
				Status: models.StatusFound, Confidence: conf,
				Details: map[string]string{
					"title": r.Title, "context": snippet, "query": query,
					"engine": engine, "rank": strconv.Itoa(rank + 1),
				},
			})
		}()
	}
	wg.Wait()
}
