package domain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/probe"
)

var interestingSub = []string{"admin", "dev", "stage", "staging", "test", "uat", "qa", "vpn", "mail", "webmail",
	"api", "jenkins", "gitlab", "git", "ci", "internal", "intranet", "beta", "sso", "auth", "login", "portal",
	"jira", "confluence", "grafana", "kibana", "monitor", "backup", "old", "legacy", "sandbox", "demo", "db",
	"sql", "phpmyadmin", "ftp", "sftp", "remote", "rdp", "citrix", "owa", "exchange", "panel", "cpanel", "dashboard"}

// subSource fetches names from one passive source. Failures are silent: each
// source is best-effort and the union is what matters.
type subSource struct {
	name string
	run  func(ctx context.Context, c *httpx.Client, domain string) []string
}

var subSources = []subSource{
	{"crt.sh", func(ctx context.Context, c *httpx.Client, d string) []string {
		resp, err := c.Do(ctx, httpx.Request{URL: "https://crt.sh/?q=%25." + d + "&output=json", Timeout: 40 * time.Second})
		if err != nil || resp.StatusCode != 200 {
			return nil
		}
		var rows []struct {
			NameValue string `json:"name_value"`
		}
		if json.Unmarshal(resp.Body, &rows) != nil {
			return nil
		}
		var out []string
		for _, r := range rows {
			out = append(out, strings.Split(r.NameValue, "\n")...)
		}
		return out
	}},
	{"certspotter", func(ctx context.Context, c *httpx.Client, d string) []string {
		resp, err := c.Do(ctx, httpx.Request{
			URL:     "https://api.certspotter.com/v1/issuances?domain=" + d + "&include_subdomains=true&expand=dns_names",
			Timeout: 25 * time.Second, Headers: map[string]string{"Accept": "application/json"}})
		if err != nil || resp.StatusCode != 200 {
			return nil
		}
		var rows []struct {
			DNSNames []string `json:"dns_names"`
		}
		if json.Unmarshal(resp.Body, &rows) != nil {
			return nil
		}
		var out []string
		for _, r := range rows {
			out = append(out, r.DNSNames...)
		}
		return out
	}},
	{"hackertarget", func(ctx context.Context, c *httpx.Client, d string) []string {
		resp, err := c.Do(ctx, httpx.Request{URL: "https://api.hackertarget.com/hostsearch/?q=" + d, Timeout: 25 * time.Second})
		if err != nil || resp.StatusCode != 200 {
			return nil
		}
		var out []string
		for _, line := range strings.Split(string(resp.Body), "\n") {
			if host, _, ok := strings.Cut(line, ","); ok {
				out = append(out, host)
			}
		}
		return out
	}},
	{"tls-certificate", func(ctx context.Context, _ *httpx.Client, d string) []string {
		cert, err := probe.FetchCert(ctx, d, 443)
		if err != nil {
			return nil
		}
		return cert.SANs
	}},
}

func subdomainsJob(ctx context.Context, c *httpx.Client, domain string, emit func(models.Finding)) {
	// 1. gather from every source concurrently
	var (
		mu     sync.Mutex
		found  = map[string]map[string]bool{} // name -> sources
		perSrc = map[string]int{}
		wg     sync.WaitGroup
	)
	for _, src := range subSources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			names := src.run(ctx, c, domain)
			mu.Lock()
			defer mu.Unlock()
			for _, n := range names {
				n = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(n, "*.")))
				if n == "" || n == domain || !sameSite(n, domain) || strings.ContainsAny(n, " *@/") {
					continue
				}
				if found[n] == nil {
					found[n] = map[string]bool{}
					perSrc[src.name]++
				}
				found[n][src.name] = true
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}

	names := make([]string, 0, len(found))
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)
	const maxResolve = 400
	if len(names) > maxResolve {
		names = names[:maxResolve]
	}

	// 2. wildcard DNS detection, then resolve everything
	rb := make([]byte, 6)
	_, _ = rand.Read(rb)
	wild := map[string]bool{}
	if ips, err := net.DefaultResolver.LookupHost(ctx, "zz"+hex.EncodeToString(rb)+"."+domain); err == nil {
		for _, ip := range ips {
			wild[ip] = true
		}
	}

	type res struct {
		name string
		ips  []string
	}
	results := make([]res, len(names))
	sem := make(chan struct{}, 24)
	for i, n := range names {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			ips, _ := net.DefaultResolver.LookupHost(lctx, n)
			sort.Strings(ips)
			results[i] = res{n, ips}
		}()
	}
	wg.Wait()

	var live, dead []string
	for _, r := range results {
		if len(r.ips) == 0 {
			dead = append(dead, r.name)
			continue
		}
		onlyWild := len(wild) > 0
		for _, ip := range r.ips {
			if !wild[ip] {
				onlyWild = false
			}
		}
		if onlyWild {
			dead = append(dead, r.name+" (wildcard)")
			continue
		}
		live = append(live, r.name)
	}

	sum := map[string]string{
		"discovered": itoa(len(found)), "resolving": itoa(len(live)), "not resolving": itoa(len(dead)),
	}
	var srcs []string
	for s, n := range perSrc {
		srcs = append(srcs, s+"="+itoa(n))
	}
	sort.Strings(srcs)
	put(sum, "per source (new names)", strings.Join(srcs, ", "))
	if len(wild) > 0 {
		sum["wildcard DNS"] = "yes — unresolvable-looking names may still answer; results filtered"
	}
	put(sum, "live subdomains", list(live, 60))
	put(sum, "dangling / dead (possible takeover candidates)", list(dead, 25))
	if len(found) == 0 {
		sum["note"] = "no passive source returned names (crt.sh and others are rate-limited or offline at times)"
	}
	emit(fnd("Subdomain enumeration", "subdomain", "", 0.85, sum))
	takeoverCandidates(ctx, domain, dead, emit)

	// 3. one finding per live subdomain (capped) so they show up individually
	byName := map[string]res{}
	for _, r := range results {
		byName[r.name] = r
	}
	for i, n := range live {
		if i >= 150 {
			break
		}
		r := byName[n]
		d := map[string]string{"ips": strings.Join(r.ips, ", ")}
		var srcNames []string
		for s := range found[n] {
			srcNames = append(srcNames, s)
		}
		sort.Strings(srcNames)
		d["found by"] = strings.Join(srcNames, ", ")
		conf := 0.8
		label := strings.TrimSuffix(n, "."+domain)
		for _, k := range interestingSub {
			if label == k || strings.HasPrefix(label, k+"-") || strings.HasPrefix(label, k+".") || strings.HasSuffix(label, "."+k) || strings.HasSuffix(label, "-"+k) {
				d["interesting"] = "name suggests " + k + " service"
				break
			}
		}
		emit(fnd(n, "subdomain", "https://"+n, conf, d))
	}
}
