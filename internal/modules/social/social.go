// Package social implements the username-enumeration module: it probes a
// large list of platforms concurrently and decides, from the HTTP status
// code and page content, whether the account exists.
package social

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sudosoc/rectool/internal/extract"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

// Config tunes the module.
type Config struct {
	SitesFile  string   // custom site list (WMN format); empty = embedded defaults
	Categories []string // restrict to these site categories; empty = all
	Verify     bool     // re-probe each hit with a random canary username to reject false positives
	// DisabledFile lists sites a self-test found unreliable; they are skipped.
	// Empty means use every site.
	DisabledFile string
}

// Scanner is the social-media username module.
type Scanner struct {
	cfg   Config
	sites []Site
}

var _ scanner.Scanner = (*Scanner)(nil)

// New loads the site list and returns a ready module.
func New(cfg Config) (*Scanner, error) {
	sites, err := LoadSites(cfg.SitesFile)
	if err != nil {
		return nil, err
	}
	if off := LoadDisabled(cfg.DisabledFile); len(off) > 0 {
		kept := sites[:0]
		for _, st := range sites {
			if !off[st.Name] {
				kept = append(kept, st)
			}
		}
		sites = kept
	}
	if len(cfg.Categories) > 0 {
		want := map[string]bool{}
		for _, c := range cfg.Categories {
			want[strings.ToLower(strings.TrimSpace(c))] = true
		}
		filtered := sites[:0]
		for _, s := range sites {
			cat := strings.ToLower(s.Cat)
			if want[cat] || (want["nsfw"] && isNSFW(cat)) {
				filtered = append(filtered, s)
			}
		}
		sites = filtered
	} else {
		// Adult sites are opt-in (-categories nsfw): they add noise and are
		// rarely what an investigation needs.
		filtered := sites[:0]
		for _, s := range sites {
			if !isNSFW(strings.ToLower(s.Cat)) {
				filtered = append(filtered, s)
			}
		}
		sites = filtered
	}
	return &Scanner{cfg: cfg, sites: sites}, nil
}

// SiteCount returns how many platforms are loaded.
func (s *Scanner) SiteCount() int { return len(s.sites) }

func (s *Scanner) Name() string                { return "social" }
func (s *Scanner) Description() string         { return "username presence across social/dev/media platforms" }
func (s *Scanner) CanRun(t models.Target) bool { return len(t.Usernames()) > 0 }

// Scan fans one task per (username, site) pair out over the shared pool.
func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	users := t.Usernames()
	total := len(users) * len(s.sites)

	var (
		wg      sync.WaitGroup
		done    atomic.Int64
		retryMu sync.Mutex
		retry   []retryJob
	)
	report := func() {
		n := int(done.Add(1))
		if d.Progress != nil {
			d.Progress(s.Name(), n, total)
		}
	}

submit:
	for _, user := range users {
		for i := range s.sites {
			site := &s.sites[i]
			wg.Add(1)
			err := d.Pool.Submit(ctx, func() {
				defer wg.Done()
				defer report()
				if s.check(ctx, d.HTTP, site, user, emit, false) {
					retryMu.Lock()
					retry = append(retry, retryJob{site, user})
					retryMu.Unlock()
				}
			})
			if err != nil { // context cancelled: task was not queued
				wg.Done()
				break submit
			}
		}
	}
	wg.Wait()

	// Second pass: connection-level failures (timeouts, DNS) on a busy or
	// congested link are usually transient. Retry just those, gently, and only
	// report an error if they fail again.
	if len(retry) > 0 && ctx.Err() == nil {
		sem := make(chan struct{}, 12)
		for _, j := range retry {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer func() { <-sem; wg.Done() }()
				s.check(ctx, d.HTTP, j.site, j.user, emit, true)
			}()
		}
		wg.Wait()
	}
	return ctx.Err()
}

type retryJob struct {
	site *Site
	user string
}

type verdict int

const (
	vAbsent verdict = iota
	vPresent
	vBlocked // rate-limited / WAF / captcha: result untrustworthy
	vUnknown // response matched neither the "exists" nor the "missing" signature
)

// check probes one site for one username and emits the outcome. When final is
// false, a connection-level failure is not reported: check returns true so the
// caller can retry it later.
func (s *Scanner) check(ctx context.Context, c *httpx.Client, site *Site, user string, emit func(models.Finding), final bool) (retry bool) {
	if ctx.Err() != nil || !site.applicable(user) {
		return false
	}
	base := models.Finding{Source: site.Name, Category: site.Cat, URL: site.prettyURL(user)}

	v, resp, err := probe(ctx, c, site, user)
	if err != nil {
		if ctx.Err() != nil {
			return false
		}
		if !final {
			return true
		}
		f := base
		f.Status = models.StatusError
		f.Details = map[string]string{"error": err.Error()}
		emit(f)
		return false
	}

	switch v {
	case vPresent:
		conf := 0.6 // status code alone
		if site.EString != "" {
			conf = 0.9 // positive content marker as well
		}
		if s.cfg.Verify {
			canary := randomCanary()
			cv, _, cerr := probe(ctx, c, site, canary)
			switch {
			case ctx.Err() != nil:
				return false
			case cerr == nil && cv == vPresent:
				// The site says a random string exists too: signature is useless here.
				f := base
				f.Status = models.StatusNotFound
				f.Details = map[string]string{"reason": "canary username also matched (false positive)"}
				emit(f)
				return false
			case cerr == nil && cv == vAbsent:
				conf = minF(conf+0.05, 0.95)
			}
		}
		f := base
		f.Status = models.StatusFound
		f.Confidence = conf
		f.Details = map[string]string{"username": user, "http_status": strconv.Itoa(resp.StatusCode)}
		// Profile pages usually carry Open Graph metadata: the display name,
		// bio and avatar are useful for matching the account to the subject.
		if m := extract.ParseMeta(string(resp.Body)); m.Title != "" || m.Description != "" {
			if t := firstNonEmpty(m.OGTitle, m.Title); t != "" && !strings.EqualFold(t, site.Name) {
				f.Details["page title"] = clip(t, 140)
			}
			if m.Description != "" {
				f.Details["description"] = clip(m.Description, 220)
			}
			if m.OGImage != "" {
				f.Details["avatar"] = clip(m.OGImage, 300)
			}
		}
		emit(f)
	case vBlocked:
		f := base
		f.Status = models.StatusError
		f.Details = map[string]string{"error": "blocked or rate-limited", "http_status": strconv.Itoa(resp.StatusCode)}
		emit(f)
	case vUnknown:
		f := base
		f.Status = models.StatusUncertain
		f.Confidence = 0.3
		f.Details = map[string]string{"username": user, "http_status": strconv.Itoa(resp.StatusCode), "note": "response matched no known signature"}
		// Only surfaced when the status is a success code; other statuses are noise.
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			emit(f)
		}
	default:
		f := base
		f.Status = models.StatusNotFound
		emit(f)
	}
	return false
}

// probe sends the request for one (site, username) and classifies the reply.
func probe(ctx context.Context, c *httpx.Client, site *Site, user string) (verdict, *httpx.Response, error) {
	enc := url.PathEscape(user)
	req := httpx.Request{
		Method:     "GET",
		URL:        site.checkURL(enc),
		Headers:    site.Headers,
		NoRedirect: false,
	}
	if site.PostBody != "" {
		req.Method = "POST"
		req.Body = strings.ReplaceAll(site.PostBody, accountToken, user)
	}
	resp, err := c.Do(ctx, req)
	if err != nil {
		return vUnknown, nil, err
	}
	return classify(site, resp), resp, nil
}

// classify applies the site's signatures to a response.
func classify(site *Site, r *httpx.Response) verdict {
	body := string(r.Body)
	code := r.StatusCode

	// "Missing" signature wins: many sites return 200 with a "not found" page.
	if site.MString != "" && strings.Contains(body, site.MString) {
		return vAbsent
	}
	if site.MCode != 0 && code == site.MCode && site.MString == "" {
		return vAbsent
	}
	if code == site.ECode && (site.EString == "" || strings.Contains(body, site.EString)) {
		return vPresent
	}

	switch code {
	case 403, 407, 429, 503:
		return vBlocked
	case 404, 410:
		return vAbsent
	}
	// Status matched "exists" but the content marker did not: the page is a
	// generic/soft-404 shell rather than a profile.
	if code == site.ECode {
		return vAbsent
	}
	return vUnknown
}

func randomCanary() string {
	b := make([]byte, 7)
	_, _ = rand.Read(b)
	return "zq" + hex.EncodeToString(b) // 16 chars, letters+digits, valid in subdomains
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func isNSFW(cat string) bool { return strings.Contains(cat, "nsfw") }
