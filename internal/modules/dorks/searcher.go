package dorks

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
)

// Result is one scraped search hit.
type Result struct{ Title, URL, Snippet string }

// Searcher scrapes search engines with per-engine rate limiting and remembers
// which engines have shown a bot wall. One Searcher is meant to be shared by
// every module so their combined request rate to an engine stays polite.
type Searcher struct {
	engines []searchEngine
	limit   map[string]*limiter
	blocked map[string]*atomic.Bool
}

// NewSearcher builds a Searcher. engines are tried in order per query
// (default brave, bing, duckduckgo, google); delay is the minimum gap between
// requests to one engine (default 3s).
func NewSearcher(engines []string, delay time.Duration) (*Searcher, error) {
	if len(engines) == 0 {
		engines = []string{"brave", "bing", "duckduckgo", "google"}
	}
	if delay <= 0 {
		delay = 3 * time.Second
	}
	s := &Searcher{limit: map[string]*limiter{}, blocked: map[string]*atomic.Bool{}}
	for _, n := range engines {
		e := engineByName(n)
		if e == nil {
			return nil, fmt.Errorf("unknown search engine %q (brave, bing, duckduckgo, google)", n)
		}
		s.engines = append(s.engines, e)
		s.limit[e.name()] = &limiter{gap: delay}
		s.blocked[e.name()] = new(atomic.Bool)
	}
	return s, nil
}

// Search runs query on the first engine that answers, returning the results
// and the engine's name. Engines that serve a bot challenge are disabled for
// the rest of the run; no attempt is made to solve or bypass the challenge.
func (s *Searcher) Search(ctx context.Context, c *httpx.Client, query string) ([]Result, string, error) {
	var lastErr string
	for _, e := range s.engines {
		if s.blocked[e.name()].Load() {
			lastErr = e.name() + " blocked"
			continue
		}
		if err := s.limit[e.name()].wait(ctx); err != nil {
			return nil, "", err
		}
		resp, err := c.Do(ctx, httpx.Request{URL: e.searchURL(query)})
		if err != nil {
			if ctx.Err() != nil {
				return nil, "", ctx.Err()
			}
			lastErr = e.name() + ": " + err.Error()
			continue
		}
		results, err := e.parse(resp.StatusCode, resp.Body)
		if err != nil {
			s.blocked[e.name()].Store(true)
			lastErr = e.name() + " blocked (bot challenge)"
			continue
		}
		return results, e.name(), nil
	}
	return nil, "", fmt.Errorf("%s", lastErr)
}

// limiter hands out request slots at least gap apart (plus jitter) without
// holding a lock while sleeping.
type limiter struct {
	mu   sync.Mutex
	next time.Time
	gap  time.Duration
}

func (l *limiter) wait(ctx context.Context) error {
	l.mu.Lock()
	at := time.Now()
	if l.next.After(at) {
		at = l.next
	}
	l.next = at.Add(l.gap + time.Duration(rand.Int64N(int64(l.gap/2)+1)))
	l.mu.Unlock()

	t := time.NewTimer(time.Until(at))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
