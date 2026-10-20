// Package records queries public record systems that few people think to
// search: SEC EDGAR filings (a person who is an officer, director or major
// shareholder of a listed company appears in filings by name) and urlscan.io's
// public scan archive (what a domain or IP served, from where, and when).
package records

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/identity"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

type Scanner struct{}

var _ scanner.Scanner = (*Scanner)(nil)

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "records" }
func (s *Scanner) Description() string {
	return "SEC EDGAR filings that name the person, and urlscan.io history of a domain or IP"
}
func (s *Scanner) CanRun(t models.Target) bool {
	return len(strings.Fields(t.FullName)) >= 2 || t.Domain != "" || t.IP != ""
}

var hdr = map[string]string{"User-Agent": "rectool research (+https://github.com/sudosoc/rectool)", "Accept": "application/json"}

func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	var jobs []func()
	if len(strings.Fields(t.FullName)) >= 2 {
		jobs = append(jobs, func() { edgar(ctx, d.HTTP, t.FullName, emit) })
	}
	if t.Domain != "" {
		jobs = append(jobs, func() { urlscan(ctx, d.HTTP, "page.domain:"+t.Domain, "domain "+t.Domain, emit) })
	}
	if t.IP != "" {
		jobs = append(jobs, func() { urlscan(ctx, d.HTTP, "page.ip:\""+t.IP+"\"", "IP "+t.IP, emit) })
	}
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		j := j
		if err := d.Pool.Submit(ctx, func() { defer wg.Done(); j() }); err != nil {
			wg.Done()
			break
		}
	}
	wg.Wait()
	return ctx.Err()
}

func edgar(ctx context.Context, c *httpx.Client, name string, emit func(models.Finding)) {
	// The SEC refuses anonymous automated clients: its fair-access policy asks
	// every client to identify itself with a contact address, which is the
	// operator's to give.
	contact := strings.TrimSpace(os.Getenv("RECTOOL_CONTACT"))
	if !strings.Contains(contact, "@") {
		emit(models.Finding{Source: "SEC EDGAR filings", Category: "registry", Status: models.StatusError, Details: map[string]string{
			"error": "skipped: the SEC requires clients to identify themselves. Set your contact e-mail with -contact you@example.com or RECTOOL_CONTACT, and it is sent only to sec.gov in the User-Agent header"}})
		return
	}
	h := map[string]string{"User-Agent": "rectool/1.0 " + contact, "Accept": "application/json"}
	resp, err := c.Do(ctx, httpx.Request{URL: "https://efts.sec.gov/LATEST/search-index?q=" + url.QueryEscape(`"`+name+`"`), Timeout: 30 * time.Second, Headers: h})
	if err != nil || resp.StatusCode != 200 {
		return
	}
	var r struct {
		Hits struct {
			Total struct{ Value int } `json:"total"`
			Hits  []struct {
				Source struct {
					Display []string `json:"display_names"`
					Form    string   `json:"form"`
					Date    string   `json:"file_date"`
					ADSH    string   `json:"adsh"`
				} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if json.Unmarshal(resp.Body, &r) != nil || len(r.Hits.Hits) == 0 {
		return
	}
	people := map[string]bool{}
	companies := map[string]int{}
	forms := map[string]int{}
	first, last := "", ""
	for _, h := range r.Hits.Hits {
		matched := false
		for _, dn := range h.Source.Display {
			n := cleanDisplay(dn)
			if identity.MatchNames(n, name) == identity.NameStrong {
				people[n] = true
				matched = true
			}
		}
		if !matched {
			continue
		}
		for _, dn := range h.Source.Display {
			if n := cleanDisplay(dn); identity.MatchNames(n, name) != identity.NameStrong {
				companies[n]++
			}
		}
		forms[h.Source.Form]++
		if first == "" || h.Source.Date < first {
			first = h.Source.Date
		}
		if h.Source.Date > last {
			last = h.Source.Date
		}
	}
	if len(forms) == 0 {
		return
	}
	var cl []string
	var ents []models.Entity
	for _, k := range sortedByCount(companies, 8) {
		cl = append(cl, k)
		ents = append(ents, models.Entity{Type: models.EntOrg, Value: k})
	}
	var pl []string
	for p := range people {
		pl = append(pl, p)
	}
	sort.Strings(pl)
	emit(models.Finding{Source: "SEC EDGAR filings", Category: "registry", Status: models.StatusUncertain, Confidence: 0.55,
		URL: "https://efts.sec.gov/LATEST/search-index?q=" + url.QueryEscape(`"`+name+`"`),
		Details: map[string]string{"names as filed": strings.Join(pl, "; "), "filings naming this person": fmt.Sprint(r.Hits.Total.Value),
			"companies in the same filings": strings.Join(cl, "; "), "form types": topForms(forms), "first filing": first, "latest filing": last,
			"note": "insiders of US-listed companies file under their name; any person with this name matches, so check the company against your subject"},
		Entities: ents})
}

func cleanDisplay(s string) string {
	if i := strings.Index(s, "(CIK"); i > 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(strings.ReplaceAll(s, "  ", " "))
	if i := strings.Index(s, "  "); i > 0 {
		s = s[:i]
	}
	return strings.Trim(s, " ,")
}

func sortedByCount(m map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	var l []kv
	for k, v := range m {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].v != l[j].v {
			return l[i].v > l[j].v
		}
		return l[i].k < l[j].k
	})
	var out []string
	for i, x := range l {
		if i >= n {
			break
		}
		out = append(out, x.k)
	}
	return out
}

func topForms(m map[string]int) string {
	var out []string
	for _, k := range sortedByCount(m, 8) {
		out = append(out, fmt.Sprintf("%s ×%d", k, m[k]))
	}
	return strings.Join(out, ", ")
}

// urlscan summarises past public scans of a domain or IP.
func urlscan(ctx context.Context, c *httpx.Client, query, label string, emit func(models.Finding)) {
	resp, err := c.Do(ctx, httpx.Request{URL: "https://urlscan.io/api/v1/search/?size=100&q=" + url.QueryEscape(query), Timeout: 30 * time.Second, Headers: hdr})
	if err != nil || resp.StatusCode != 200 {
		return
	}
	var r struct {
		Total   int `json:"total"`
		Results []struct {
			Task struct {
				Time string `json:"time"`
			} `json:"task"`
			Page struct {
				Domain  string `json:"domain"`
				IP      string `json:"ip"`
				Server  string `json:"server"`
				Country string `json:"country"`
				City    string `json:"city"`
				ASN     string `json:"asn"`
				ASNName string `json:"asnname"`
			} `json:"page"`
		} `json:"results"`
	}
	if json.Unmarshal(resp.Body, &r) != nil || len(r.Results) == 0 {
		return
	}
	ips, doms, servers, countries, asns := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	first, last := "", ""
	for _, x := range r.Results {
		if x.Page.IP != "" {
			ips[x.Page.IP]++
		}
		if x.Page.Domain != "" {
			doms[x.Page.Domain]++
		}
		if x.Page.Server != "" {
			servers[x.Page.Server]++
		}
		if x.Page.Country != "" {
			countries[x.Page.Country]++
		}
		if x.Page.ASN != "" {
			asns[x.Page.ASN+" "+x.Page.ASNName]++
		}
		if tm := x.Task.Time; len(tm) >= 10 {
			if first == "" || tm[:10] < first {
				first = tm[:10]
			}
			if tm[:10] > last {
				last = tm[:10]
			}
		}
	}
	d := map[string]string{"scans": fmt.Sprint(r.Total), "first scan": first, "last scan": last}
	var ents []models.Entity
	if v := sortedByCount(ips, 10); len(v) > 0 {
		d["IP addresses seen"] = strings.Join(v, ", ")
		for _, ip := range v {
			ents = append(ents, models.Entity{Type: models.EntIP, Value: ip})
		}
	}
	if v := sortedByCount(doms, 25); len(v) > 1 || (len(v) == 1 && strings.HasPrefix(query, "page.ip")) {
		d["domains seen"] = strings.Join(v, ", ")
		for _, dom := range v {
			ents = append(ents, models.Entity{Type: models.EntDomain, Value: dom})
		}
	}
	if v := sortedByCount(servers, 6); len(v) > 0 {
		d["web servers"] = strings.Join(v, ", ")
	}
	if v := sortedByCount(countries, 6); len(v) > 0 {
		d["hosted in"] = strings.Join(v, ", ")
	}
	if v := sortedByCount(asns, 6); len(v) > 0 {
		d["networks"] = strings.Join(v, "; ")
	}
	d["note"] = "from urlscan.io's public scan archive: shows hosting changes over time, not current state"
	emit(models.Finding{Source: "urlscan.io history: " + label, Category: "history", Status: models.StatusFound, Confidence: 0.7,
		URL: "https://urlscan.io/search/#" + url.PathEscape(query), Details: d, Entities: ents})
}
