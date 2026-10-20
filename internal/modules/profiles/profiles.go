// Package profiles goes beyond "does this username exist": for platforms that
// publish structured public profile data it fetches the real name, location,
// bio, linked accounts, websites and e-mail addresses, and reports every
// cross-link as an entity the engine can follow.
package profiles

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/intel"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

// Scanner is the profile-enrichment module.
type Scanner struct{}

var _ scanner.Scanner = (*Scanner)(nil)

// New builds the module.
func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "profiles" }
func (s *Scanner) Description() string {
	return "deep profile data for a username: GitHub, Keybase, GitLab, npm, Mastodon, Stack Overflow, …"
}
func (s *Scanner) CanRun(t models.Target) bool { return len(t.Usernames()) > 0 }

type enricher struct {
	name string
	run  func(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding))
}

var enrichers = []enricher{
	{"github", githubProfile},
	{"github-commits", githubCommits},
	{"keybase", keybase},
	{"gitlab", gitlab},
	{"npm", npm},
	{"hackernews", hackerNews},
	{"devto", devTo},
	{"dockerhub", dockerHub},
	{"mastodon", mastodon},
	{"stackoverflow", stackOverflow},
	{"lichess", lichess},
	{"chesscom", chessCom},
	{"reddit", reddit},
}

func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	users := t.Usernames()
	if len(users) > 3 {
		users = users[:3]
	}
	total := len(users) * len(enrichers)

	// Findings are buffered per username so they can be cross-checked (and
	// attributed) against each other before anything is reported.
	var (
		wg   sync.WaitGroup
		done atomic.Int64
		mu   sync.Mutex
		buf  = map[string][]models.Finding{}
	)
	for _, u := range users {
		for _, e := range enrichers {
			wg.Add(1)
			err := d.Pool.Submit(ctx, func() {
				defer wg.Done()
				e.run(ctx, d.HTTP, u, func(f models.Finding) {
					if f.Details == nil {
						f.Details = map[string]string{}
					}
					f.Details["handle"] = u // lets identity resolution tie the profile to the handle that found it
					mu.Lock()
					buf[u] = append(buf[u], f)
					mu.Unlock()
				})
				if d.Progress != nil {
					d.Progress(s.Name(), int(done.Add(1)), total)
				}
			})
			if err != nil {
				wg.Done()
				break
			}
		}
	}
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	for _, u := range users {
		fs := buf[u]
		sort.SliceStable(fs, func(i, j int) bool { return fs[i].Source < fs[j].Source })
		for _, f := range attribute(u, fs, t) {
			emit(f)
		}
	}
	return nil
}

// ---- helpers ---------------------------------------------------------------

func getJSON(ctx context.Context, c *httpx.Client, u string, out any) bool {
	resp, err := c.Do(ctx, httpx.Request{URL: u, Timeout: 15 * time.Second,
		Headers: map[string]string{"Accept": "application/json"}})
	if err != nil || resp.StatusCode != 200 {
		return false
	}
	return json.Unmarshal(resp.Body, &out) == nil
}

func put(d map[string]string, k, v string) {
	if v = strings.TrimSpace(v); v != "" {
		d[k] = v
	}
}

func profile(source, link string, conf float64, d map[string]string, ents ...models.Entity) models.Finding {
	return models.Finding{Source: source, Category: "profile", URL: link, Status: models.StatusFound,
		Confidence: conf, Details: d, Entities: ents}
}

func emailEnt(e string, strong bool) (models.Entity, bool) {
	e = strings.ToLower(strings.TrimSpace(e))
	if !strings.Contains(e, "@") || strings.Contains(e, "noreply") || strings.Contains(e, "no-reply") {
		return models.Entity{}, false
	}
	return models.Entity{Type: models.EntEmail, Value: e, Strong: strong}, true
}

// siteEnt turns a website URL or bare domain into a domain entity.
func siteEnt(s string, strong bool) (models.Entity, bool) {
	if s = strings.TrimSpace(s); s == "" {
		return models.Entity{}, false
	}
	d, ok := intel.NormalizeDomain(s)
	if !ok || isPlatformDomain(d) {
		return models.Entity{}, false
	}
	return models.Entity{Type: models.EntDomain, Value: d, Strong: strong}, true
}

// isPlatformDomain filters links that only point at another social network.
func isPlatformDomain(d string) bool {
	for _, p := range []string{"twitter.com", "x.com", "github.com", "linkedin.com", "facebook.com", "instagram.com",
		"youtube.com", "youtu.be", "t.me", "reddit.com", "medium.com", "gitlab.com", "keybase.io", "mastodon.social"} {
		if d == p || strings.HasSuffix(d, "."+p) {
			return true
		}
	}
	return false
}

func userEnt(u string, strong bool) (models.Entity, bool) {
	u = strings.TrimPrefix(strings.TrimSpace(u), "@")
	if len(u) < 3 || strings.ContainsAny(u, " /") {
		return models.Entity{}, false
	}
	return models.Entity{Type: models.EntUsername, Value: u, Strong: strong}, true
}

func esc(s string) string { return url.PathEscape(s) }
