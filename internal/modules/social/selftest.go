package social

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/sudosoc/rectool/internal/httpx"
)

// Health is the self-test verdict for one site.
type Health struct {
	Site   string `json:"site"`
	Status string `json:"status"` // ok | broken | noisy | untested
	Detail string `json:"detail,omitempty"`
}

// Health statuses.
const (
	HealthOK       = "ok"       // a known account is detected and a random one is not
	HealthBroken   = "broken"   // a known account was NOT detected: signature stale, site changed, or we are blocked
	HealthNoisy    = "noisy"    // a random account is "found": the signature cannot tell accounts apart
	HealthBlocked  = "blocked"  // rate-limited / WAF / network error from here: tells us nothing about the signature
	HealthUntested = "untested" // the site lists no known account
)

// SelfTest checks every site against its known account and against a random
// one. Sites that fail would produce false negatives (broken) or false
// positives (noisy) in real scans, so they can be disabled.
func SelfTest(ctx context.Context, c *httpx.Client, sites []Site, conc int, progress func(done, total int)) []Health {
	if conc <= 0 {
		conc = 32
	}
	out := make([]Health, len(sites))
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for i := range sites {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			out[i] = testSite(ctx, c, &sites[i])
			if progress != nil {
				mu.Lock()
				done++
				d := done
				mu.Unlock()
				progress(d, len(sites))
			}
		}()
	}
	wg.Wait()
	return out
}

func pickKnown(site *Site) string {
	for _, k := range site.Known {
		if k != "" && !strings.ContainsAny(k, " /") {
			return k
		}
	}
	if len(site.Known) > 0 {
		return site.Known[0]
	}
	return ""
}

func testSite(ctx context.Context, c *httpx.Client, site *Site) Health {
	h := Health{Site: site.Name}
	known := pickKnown(site)
	if known == "" {
		h.Status = HealthUntested
		return h
	}
	v, _, err := probe(ctx, c, site, known)
	switch {
	case err != nil:
		h.Status, h.Detail = HealthBlocked, "request failed: "+err.Error()
		return h
	case v == vBlocked:
		h.Status, h.Detail = HealthBlocked, "blocked or rate-limited from this network"
		return h
	case v != vPresent:
		h.Status, h.Detail = HealthBroken, "known account not detected (signature is stale)"
		return h
	}
	cv, _, cerr := probe(ctx, c, site, randomCanary())
	if cerr == nil && cv == vPresent {
		h.Status, h.Detail = HealthNoisy, "a random username is also reported as existing"
		return h
	}
	h.Status = HealthOK
	return h
}

// LoadDisabled reads the list of site names disabled by a previous self-test.
func LoadDisabled(path string) map[string]bool {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var names []string
	if json.Unmarshal(b, &names) != nil {
		return nil
	}
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// SaveDisabled writes the disabled-site list (sorted) to path.
func SaveDisabled(path string, names []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	sort.Strings(names)
	b, _ := json.MarshalIndent(names, "", "  ")
	return os.WriteFile(path, b, 0o644)
}

// Sites returns the loaded site definitions (after category / disabled filtering).
func (s *Scanner) Sites() []Site { return s.sites }
