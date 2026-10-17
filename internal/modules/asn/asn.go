// Package asn maps an autonomous-system number to its owner, announced
// prefixes, peers and registration contacts (RIPEstat + RDAP, no keys).
package asn

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/rdap"
	"github.com/sudosoc/rectool/internal/scanner"
)

// Scanner is the ASN module.
type Scanner struct{}

var _ scanner.Scanner = (*Scanner)(nil)

// New builds the module.
func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "asn" }
func (s *Scanner) Description() string {
	return "AS owner, announced prefixes, peers, registration contacts"
}
func (s *Scanner) CanRun(t models.Target) bool { return t.ASN != "" }

func ripe(ctx context.Context, c *httpx.Client, endpoint, asn string, out any) bool {
	resp, err := c.Do(ctx, httpx.Request{
		URL:     "https://stat.ripe.net/data/" + endpoint + "/data.json?resource=" + url.QueryEscape(asn),
		Timeout: 30 * time.Second, Headers: map[string]string{"Accept": "application/json"}})
	if err != nil || resp.StatusCode != 200 {
		return false
	}
	return json.Unmarshal(resp.Body, out) == nil
}

func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	asn := t.ASN
	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		if err := d.Pool.Submit(ctx, func() { defer wg.Done(); f() }); err != nil {
			wg.Done()
		}
	}

	run(func() {
		var r struct {
			Data struct {
				Holder    string `json:"holder"`
				Announced bool   `json:"announced"`
				Block     struct {
					Desc string `json:"desc"`
					Name string `json:"name"`
				} `json:"block"`
			} `json:"data"`
		}
		if !ripe(ctx, d.HTTP, "as-overview", asn, &r) || r.Data.Holder == "" {
			return
		}
		det := map[string]string{"holder": r.Data.Holder, "announced in BGP": strconv.FormatBool(r.Data.Announced)}
		if r.Data.Block.Name != "" {
			det["allocation block"] = r.Data.Block.Name + " — " + r.Data.Block.Desc
		}
		emit(models.Finding{Source: asn + " overview", Category: "network", URL: "https://bgp.he.net/" + asn,
			Status: models.StatusFound, Confidence: 0.95, Details: det})
	})

	run(func() {
		var r struct {
			Data struct {
				Prefixes []struct {
					Prefix string `json:"prefix"`
				} `json:"prefixes"`
			} `json:"data"`
		}
		if !ripe(ctx, d.HTTP, "announced-prefixes", asn, &r) || len(r.Data.Prefixes) == 0 {
			return
		}
		var v4, v6 []string
		for _, p := range r.Data.Prefixes {
			if strings.Contains(p.Prefix, ":") {
				v6 = append(v6, p.Prefix)
			} else {
				v4 = append(v4, p.Prefix)
			}
		}
		sort.Strings(v4)
		sort.Strings(v6)
		show := func(l []string) string {
			if len(l) > 40 {
				return strings.Join(l[:40], ", ") + " … (+" + strconv.Itoa(len(l)-40) + " more)"
			}
			return strings.Join(l, ", ")
		}
		det := map[string]string{"IPv4 prefixes": strconv.Itoa(len(v4)), "IPv6 prefixes": strconv.Itoa(len(v6))}
		if len(v4) > 0 {
			det["IPv4"] = show(v4)
		}
		if len(v6) > 0 {
			det["IPv6"] = show(v6)
		}
		emit(models.Finding{Source: asn + " announced prefixes", Category: "network", Status: models.StatusFound,
			Confidence: 0.9, Details: det})
	})

	run(func() {
		var r struct {
			Data struct {
				Neighbours []struct {
					ASN  int    `json:"asn"`
					Type string `json:"type"`
				} `json:"neighbours"`
			} `json:"data"`
		}
		if !ripe(ctx, d.HTTP, "asn-neighbours", asn, &r) || len(r.Data.Neighbours) == 0 {
			return
		}
		var left, right []string
		for _, n := range r.Data.Neighbours {
			if n.Type == "left" {
				left = append(left, "AS"+strconv.Itoa(n.ASN))
			} else {
				right = append(right, "AS"+strconv.Itoa(n.ASN))
			}
		}
		cut := func(l []string) string {
			if len(l) > 25 {
				return strings.Join(l[:25], ", ") + " …"
			}
			return strings.Join(l, ", ")
		}
		emit(models.Finding{Source: asn + " BGP neighbours", Category: "network", Status: models.StatusFound, Confidence: 0.85,
			Details: map[string]string{"upstream-side (left)": cut(left), "downstream-side (right)": cut(right),
				"count": strconv.Itoa(len(r.Data.Neighbours))}})
	})

	run(func() {
		n, err := rdap.LookupASN(ctx, d.HTTP, asn)
		if err != nil {
			return
		}
		det := map[string]string{}
		put := func(k, v string) {
			if v = strings.TrimSpace(v); v != "" {
				det[k] = v
			}
		}
		put("name", n.Name)
		put("country", n.Country)
		put("handle", n.Handle)
		put("registered", n.Created)
		put("last changed", n.Updated)
		put("remarks", n.Remarks)
		var ents []models.Entity
		seen := map[string]bool{}
		for _, ct := range n.Contacts {
			role := strings.Join(ct.Roles, "/")
			label := strings.Join(nonEmpty(ct.Name, ct.Org, ct.Email, ct.Phone), " · ")
			if label != "" {
				det[role] = label
			}
			if strings.Contains(ct.Email, "@") && !seen[ct.Email] {
				seen[ct.Email] = true
				ents = append(ents, models.Entity{Type: models.EntEmail, Value: ct.Email})
			}
		}
		emit(models.Finding{Source: asn + " registration (RDAP)", Category: "whois", URL: "https://rdap.org/autnum/" + strings.TrimPrefix(asn, "AS"),
			Status: models.StatusFound, Confidence: 0.9, Details: det, Entities: ents})
	})

	wg.Wait()
	return ctx.Err()
}

func nonEmpty(s ...string) []string {
	var out []string
	for _, v := range s {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
