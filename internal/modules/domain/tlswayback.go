package domain

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/probe"
)

func tlsJob(ctx context.Context, _ *httpx.Client, domain string, emit func(models.Finding)) {
	cert, err := probe.FetchCert(ctx, domain, 443)
	if err != nil {
		if cert, err = probe.FetchCert(ctx, "www."+domain, 443); err != nil {
			return // no HTTPS: the website check already reports that
		}
	}
	d := map[string]string{
		"subject": cert.Subject, "issuer": cert.Issuer, "valid from": cert.NotBefore.Format("2006-01-02"),
		"valid until": cert.NotAfter.Format("2006-01-02"), "serial": cert.Serial,
		"signature": cert.SigAlg, "TLS version": cert.TLSVersion,
	}
	put(d, "SANs", list(cert.SANs, 40))
	switch days := int(time.Until(cert.NotAfter).Hours() / 24); {
	case days < 0:
		d["status"] = "EXPIRED " + itoa(-days) + " days ago"
	case days < 21:
		d["status"] = "expires in " + itoa(days) + " days"
	default:
		d["status"] = "valid, " + itoa(days) + " days left"
	}
	if cert.SelfSigned {
		d["note"] = "self-signed certificate"
	}
	emit(fnd("TLS certificate", "tls", "", 0.95, d))
}

var archiveInteresting = regexp.MustCompile(`(?i)(\.(sql|bak|backup|old|zip|tar|gz|7z|rar|env|ini|conf|config|log|pem|key|git|svn|swp|dump|xml|json|yml|yaml|csv|xls|xlsx|doc|docx|pdf|ppt|pptx|txt)(\?|$)|/(admin|login|wp-admin|phpmyadmin|backup|dump|config|private|internal|api|swagger|graphql|debug|test|staging|\.git|\.svn|\.env|phpinfo|server-status|console|upload)(/|\?|$|\.))`)

func waybackJob(ctx context.Context, c *httpx.Client, domain string, emit func(models.Finding)) {
	resp, err := c.Do(ctx, httpx.Request{
		URL: "https://web.archive.org/cdx/search/cdx?url=*." + domain + "/*&output=json&fl=original,timestamp,statuscode" +
			"&collapse=urlkey&filter=statuscode:200&limit=4000",
		Timeout: 60 * time.Second,
	})
	if err != nil {
		if ctx.Err() == nil {
			emit(errFinding("Internet Archive", "archive", err))
		}
		return
	}
	if resp.StatusCode != 200 {
		emit(errFinding("Internet Archive", "archive", &httpErr{resp.StatusCode}))
		return
	}
	var rows [][]string
	if json.Unmarshal(resp.Body, &rows) != nil || len(rows) < 2 {
		return
	}
	rows = rows[1:] // header

	hosts := map[string]int{}
	exts := map[string]int{}
	type hit struct{ url, ts string }
	var hits []hit
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		u, err := url.Parse(r[0])
		if err != nil {
			continue
		}
		hosts[strings.ToLower(u.Hostname())]++
		if i := strings.LastIndexByte(u.Path, '.'); i >= 0 && len(u.Path)-i <= 6 {
			exts[strings.ToLower(u.Path[i:])]++
		}
		if archiveInteresting.MatchString(r[0]) {
			hits = append(hits, hit{r[0], r[1]})
		}
	}
	var hl []string
	for h := range hosts {
		hl = append(hl, h)
	}
	sort.Slice(hl, func(i, j int) bool { return hosts[hl[i]] > hosts[hl[j]] })
	var el []string
	for e, n := range exts {
		el = append(el, e+"="+itoa(n))
	}
	sort.Strings(el)

	sum := map[string]string{"archived URLs examined": itoa(len(rows)), "interesting": itoa(len(hits))}
	put(sum, "hosts seen in archive", list(hl, 40))
	put(sum, "file types", list(el, 30))
	emit(fnd("Internet Archive (historical URLs)", "archive", "https://web.archive.org/web/*/"+domain+"/*", 0.8, sum))

	for i, h := range hits {
		if i >= 60 {
			break
		}
		emit(fnd(h.url, "archive", "https://web.archive.org/web/"+h.ts+"/"+h.url, 0.6,
			map[string]string{"archived": h.ts, "why": "sensitive-looking path or file type"}))
	}
}

type httpErr struct{ code int }

func (e *httpErr) Error() string {
	return "HTTP " + itoa(e.code) + " (service temporarily unavailable?)"
}

func exposureJob(ctx context.Context, c *httpx.Client, domain string, emit func(models.Finding)) {
	resp, err := c.Do(ctx, httpx.Request{
		URL:     "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=" + url.QueryEscape(domain),
		Timeout: 25 * time.Second, Headers: map[string]string{"Accept": "application/json"},
	})
	if err != nil || resp.StatusCode != 200 {
		return
	}
	var r struct {
		Total         int `json:"total"`
		TotalStealers int `json:"totalStealers"`
		Employees     int `json:"employees"`
		Users         int `json:"users"`
		ThirdParties  int `json:"third_parties"`
		Data          struct {
			EmployeesURLs []struct {
				URL        string `json:"url"`
				Occurrence int    `json:"occurrence"`
			} `json:"employees_urls"`
		} `json:"data"`
	}
	if json.Unmarshal(resp.Body, &r) != nil || r.Total == 0 {
		return
	}
	d := map[string]string{
		"compromised credentials (stealer logs)": itoa(r.Total), "employees": itoa(r.Employees),
		"customers/users": itoa(r.Users), "third parties": itoa(r.ThirdParties),
		"note": "counts only, from Hudson Rock's public stealer-log index; no credentials are retrieved",
	}
	var urls []string
	for i, u := range r.Data.EmployeesURLs {
		if i >= 10 {
			break
		}
		urls = append(urls, u.URL+" ("+itoa(u.Occurrence)+")")
	}
	put(d, "employee-credential URLs (top)", strings.Join(urls, ", "))
	emit(fnd("Infostealer exposure (domain)", "exposure", "", 0.8, d))
}
