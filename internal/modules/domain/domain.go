// Package domain investigates a domain name from every public angle that
// needs no account: DNS and e-mail configuration, registration (RDAP),
// subdomains (certificate transparency and passive DNS), the website itself
// (technology, headers, contacts, social links, robots/sitemap/security.txt),
// the TLS certificate, archived URLs, and stealer-log exposure counts.
package domain

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

// Config tunes the module.
type Config struct {
	Wayback bool // query the Internet Archive for historical URLs (slow; default on)
}

// Scanner is the domain module.
type Scanner struct{ cfg Config }

var _ scanner.Scanner = (*Scanner)(nil)

// New builds the module.
func New(cfg Config) *Scanner { return &Scanner{cfg: cfg} }

func (s *Scanner) Name() string { return "domain" }
func (s *Scanner) Description() string {
	return "DNS, RDAP/WHOIS, subdomains, website tech & contacts, TLS, archive, exposure"
}
func (s *Scanner) CanRun(t models.Target) bool { return t.Domain != "" }

type job struct {
	name string
	run  func(ctx context.Context, c *httpx.Client, d string, emit func(models.Finding))
}

// Scan runs every sub-check as an independent task on the shared pool.
func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	jobs := []job{
		{"dns", dnsJob},
		{"rdap", rdapJob},
		{"subdomains", subdomainsJob},
		{"website", webJob},
		{"tls", tlsJob},
		{"exposure", exposureJob},
	}
	if s.cfg.Wayback {
		jobs = append(jobs, job{"wayback", waybackJob})
	}

	var (
		wg   sync.WaitGroup
		done atomic.Int64
	)
	for _, j := range jobs {
		wg.Add(1)
		err := d.Pool.Submit(ctx, func() {
			defer wg.Done()
			j.run(ctx, d.HTTP, t.Domain, emit)
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

// ---- helpers shared by the sub-checks --------------------------------------

func fnd(source, category, url string, conf float64, d map[string]string, ents ...models.Entity) models.Finding {
	return models.Finding{Source: source, Category: category, URL: url,
		Status: models.StatusFound, Confidence: conf, Details: d, Entities: ents}
}

func errFinding(source, category string, err error) models.Finding {
	return models.Finding{Source: source, Category: category, Status: models.StatusError,
		Details: map[string]string{"error": err.Error()}}
}

// put sets d[k]=v when v is non-empty.
func put(d map[string]string, k, v string) {
	if strings.TrimSpace(v) != "" {
		d[k] = v
	}
}

// list joins up to max items.
func list(items []string, max int) string {
	if len(items) > max {
		return strings.Join(items[:max], ", ") + " … (+" + itoa(len(items)-max) + " more)"
	}
	return strings.Join(items, ", ")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// sameSite reports whether host is domain or one of its subdomains.
func sameSite(host, domain string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == domain || strings.HasSuffix(host, "."+domain)
}
