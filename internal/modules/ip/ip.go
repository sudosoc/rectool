// Package ip investigates an IP address from public sources only: reverse
// DNS, ASN (Team Cymru over DNS), RDAP registration, geolocation, passively
// indexed open ports / CVEs (Shodan InternetDB), co-hosted domains, and the
// TLS certificate / web banner the address presents on 443/80.
//
// It never scans ports itself.
package ip

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/intel"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/probe"
	"github.com/sudosoc/rectool/internal/rdap"
	"github.com/sudosoc/rectool/internal/scanner"
)

// Scanner is the IP module.
type Scanner struct{}

var _ scanner.Scanner = (*Scanner)(nil)

// New builds the module.
func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "ip" }
func (s *Scanner) Description() string {
	return "rDNS, ASN, RDAP, geolocation, open ports/CVEs (passive), co-hosted domains, TLS banner"
}
func (s *Scanner) CanRun(t models.Target) bool { return t.IP != "" }

type job func(ctx context.Context, c *httpx.Client, a netip.Addr, emit func(models.Finding))

func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	a, ok := intel.NormalizeIP(t.IP)
	if !ok {
		return nil
	}
	jobs := []job{ptrJob, asnJob}
	if intel.PublicIP(a) {
		jobs = append(jobs, rdapJob, geoJob, internetDBJob, greyNoiseJob, reverseIPJob, bannerJob)
	} else {
		emit(fnd(a.String(), "ip", "", 0.9, map[string]string{
			"note": "private / loopback / link-local address: only local DNS checks are possible"}))
	}

	var (
		wg   sync.WaitGroup
		done atomic.Int64
	)
	for _, j := range jobs {
		wg.Add(1)
		err := d.Pool.Submit(ctx, func() {
			defer wg.Done()
			j(ctx, d.HTTP, a, emit)
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

func fnd(source, category, url string, conf float64, d map[string]string, ents ...models.Entity) models.Finding {
	return models.Finding{Source: source, Category: category, URL: url,
		Status: models.StatusFound, Confidence: conf, Details: d, Entities: ents}
}

func errFinding(source, category string, err error) models.Finding {
	return models.Finding{Source: source, Category: category, Status: models.StatusError,
		Details: map[string]string{"error": err.Error()}}
}

func put(d map[string]string, k, v string) {
	if strings.TrimSpace(v) != "" {
		d[k] = v
	}
}

func ptrJob(ctx context.Context, _ *httpx.Client, a netip.Addr, emit func(models.Finding)) {
	lctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	names, _ := net.DefaultResolver.LookupAddr(lctx, a.String())
	if len(names) == 0 {
		return
	}
	var ents []models.Entity
	for i, n := range names {
		names[i] = strings.TrimSuffix(n, ".")
		if d, ok := intel.NormalizeDomain(names[i]); ok {
			ents = append(ents, models.Entity{Type: models.EntDomain, Value: d})
		}
	}
	emit(fnd("Reverse DNS (PTR)", "dns", "", 0.9, map[string]string{"hostnames": strings.Join(names, ", ")}, ents...))
}

// asnJob uses Team Cymru's DNS-based IP→ASN mapping (no HTTP, no key).
func asnJob(ctx context.Context, _ *httpx.Client, a netip.Addr, emit func(models.Finding)) {
	zone := "origin.asn.cymru.com"
	if a.Is6() {
		zone = "origin6.asn.cymru.com"
	}
	lctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	txt, err := net.DefaultResolver.LookupTXT(lctx, intel.ReverseDNSName(a)+"."+zone)
	if err != nil || len(txt) == 0 {
		return
	}
	f := strings.Split(txt[0], "|")
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	if len(f) < 3 {
		return
	}
	asn := strings.Fields(f[0])[0]
	d := map[string]string{"ASN": "AS" + asn, "prefix": f[1], "country": f[2]}
	if len(f) >= 4 {
		put(d, "registry", f[3])
	}
	if len(f) >= 5 {
		put(d, "allocated", f[4])
	}
	if nt, err := net.DefaultResolver.LookupTXT(lctx, "AS"+asn+".asn.cymru.com"); err == nil && len(nt) > 0 {
		if p := strings.Split(nt[0], "|"); len(p) >= 5 {
			put(d, "AS name", strings.TrimSpace(p[4]))
		}
	}
	emit(fnd("ASN (Team Cymru)", "network", "https://bgp.he.net/AS"+asn, 0.95, d))
}

func rdapJob(ctx context.Context, c *httpx.Client, a netip.Addr, emit func(models.Finding)) {
	n, err := rdap.LookupIP(ctx, c, a.String())
	if err != nil {
		if ctx.Err() == nil {
			emit(errFinding("IP registration (RDAP)", "whois", err))
		}
		return
	}
	d := map[string]string{}
	put(d, "network name", n.Name)
	put(d, "handle", n.Handle)
	put(d, "type", n.Type)
	put(d, "country", n.Country)
	put(d, "range", strings.TrimSpace(n.Start+" – "+n.End))
	put(d, "CIDR", strings.Join(n.CIDRs, ", "))
	put(d, "parent", n.Parent)
	put(d, "registered", n.Created)
	put(d, "last changed", n.Updated)
	put(d, "remarks", n.Remarks)
	var ents []models.Entity
	seen := map[string]bool{}
	for _, ct := range n.Contacts {
		role := strings.Join(ct.Roles, "/")
		label := strings.Join(nonEmpty(ct.Name, ct.Org, ct.Email, ct.Phone), " · ")
		if label != "" {
			if old := d[role]; old != "" {
				label = old + " | " + label
			}
			d[role] = label
		}
		if strings.Contains(ct.Email, "@") && !seen[ct.Email] {
			seen[ct.Email] = true
			// abuse/noc mailboxes belong to the network operator, not the subject
			ents = append(ents, models.Entity{Type: models.EntEmail, Value: ct.Email})
		}
	}
	emit(fnd("IP registration (RDAP)", "whois", "https://rdap.org/ip/"+a.String(), 0.9, d, ents...))
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

func getJSON(ctx context.Context, c *httpx.Client, url string, timeout time.Duration, out any) bool {
	resp, err := c.Do(ctx, httpx.Request{URL: url, Timeout: timeout, Headers: map[string]string{"Accept": "application/json"}})
	if err != nil || resp.StatusCode != 200 {
		return false
	}
	return json.Unmarshal(resp.Body, out) == nil
}

func geoJob(ctx context.Context, c *httpx.Client, a netip.Addr, emit func(models.Finding)) {
	var r struct {
		Success    bool    `json:"success"`
		Type       string  `json:"type"`
		Continent  string  `json:"continent"`
		Country    string  `json:"country"`
		Region     string  `json:"region"`
		City       string  `json:"city"`
		Postal     string  `json:"postal"`
		Lat        float64 `json:"latitude"`
		Lon        float64 `json:"longitude"`
		Connection struct {
			ASN    int    `json:"asn"`
			Org    string `json:"org"`
			ISP    string `json:"isp"`
			Domain string `json:"domain"`
		} `json:"connection"`
		Timezone struct {
			ID string `json:"id"`
		} `json:"timezone"`
	}
	if !getJSON(ctx, c, "https://ipwho.is/"+a.String(), 15*time.Second, &r) || !r.Success {
		return
	}
	d := map[string]string{}
	put(d, "country", r.Country)
	put(d, "region", r.Region)
	put(d, "city", r.City)
	put(d, "postal", r.Postal)
	put(d, "coordinates", strconv.FormatFloat(r.Lat, 'f', 4, 64)+", "+strconv.FormatFloat(r.Lon, 'f', 4, 64))
	put(d, "timezone", r.Timezone.ID)
	put(d, "organisation", r.Connection.Org)
	put(d, "ISP", r.Connection.ISP)
	put(d, "ISP domain", r.Connection.Domain)
	d["note"] = "IP geolocation is approximate (usually city-level, often the ISP's location)"
	var ents []models.Entity
	if dom, ok := intel.NormalizeDomain(r.Connection.Domain); ok {
		ents = append(ents, models.Entity{Type: models.EntDomain, Value: dom})
	}
	emit(fnd("Geolocation", "geo", "", 0.6, d, ents...))
}

// internetDBJob reads Shodan's free InternetDB: ports and CVEs that Shodan has
// already observed. We do not touch the target.
func internetDBJob(ctx context.Context, c *httpx.Client, a netip.Addr, emit func(models.Finding)) {
	var r struct {
		Ports     []int    `json:"ports"`
		Hostnames []string `json:"hostnames"`
		CPEs      []string `json:"cpes"`
		Tags      []string `json:"tags"`
		Vulns     []string `json:"vulns"`
	}
	if !getJSON(ctx, c, "https://internetdb.shodan.io/"+a.String(), 15*time.Second, &r) {
		return
	}
	if len(r.Ports)+len(r.Hostnames)+len(r.CPEs)+len(r.Tags)+len(r.Vulns) == 0 {
		return
	}
	d := map[string]string{"note": "passively indexed by Shodan InternetDB; not scanned by rectool"}
	var ps []string
	for _, p := range r.Ports {
		ps = append(ps, strconv.Itoa(p))
	}
	put(d, "open ports", strings.Join(ps, ", "))
	put(d, "hostnames", strings.Join(r.Hostnames, ", "))
	put(d, "software (CPE)", strings.Join(r.CPEs, ", "))
	put(d, "tags", strings.Join(r.Tags, ", "))
	put(d, "known vulnerabilities", strings.Join(r.Vulns, ", "))
	var ents []models.Entity
	for _, h := range r.Hostnames {
		if dom, ok := intel.NormalizeDomain(h); ok {
			ents = append(ents, models.Entity{Type: models.EntDomain, Value: dom})
		}
	}
	conf := 0.8
	emit(fnd("Open ports & CVEs (Shodan InternetDB)", "exposure", "https://www.shodan.io/host/"+a.String(), conf, d, ents...))
}

func reverseIPJob(ctx context.Context, c *httpx.Client, a netip.Addr, emit func(models.Finding)) {
	resp, err := c.Do(ctx, httpx.Request{URL: "https://api.hackertarget.com/reverseiplookup/?q=" + a.String(), Timeout: 25 * time.Second})
	if err != nil || resp.StatusCode != 200 {
		return
	}
	body := strings.TrimSpace(string(resp.Body))
	if body == "" || strings.HasPrefix(body, "error") || strings.Contains(body, "API count exceeded") || strings.HasPrefix(body, "No DNS") {
		return
	}
	var hosts []string
	for _, h := range strings.Fields(body) {
		if strings.Contains(h, ".") && !strings.HasSuffix(h, ".arpa") {
			hosts = append(hosts, strings.ToLower(h))
		}
	}
	if len(hosts) == 0 {
		return
	}
	sort.Strings(hosts)
	shown := hosts
	if len(shown) > 80 {
		shown = shown[:80]
	}
	var ents []models.Entity
	for _, h := range shown[:min(len(shown), 25)] {
		if dom, ok := intel.NormalizeDomain(h); ok {
			ents = append(ents, models.Entity{Type: models.EntDomain, Value: dom})
		}
	}
	emit(fnd("Co-hosted domains (reverse IP)", "network", "", 0.6, map[string]string{
		"count": strconv.Itoa(len(hosts)), "domains": strings.Join(shown, ", "),
		"note": "shared hosting puts unrelated sites on one IP; treat as leads"}, ents...))
}

func bannerJob(ctx context.Context, c *httpx.Client, a netip.Addr, emit func(models.Finding)) {
	host := a.String()
	if cert, err := probe.FetchCert(ctx, host, 443); err == nil {
		d := map[string]string{"subject": cert.Subject, "issuer": cert.Issuer,
			"valid until": cert.NotAfter.Format("2006-01-02")}
		put(d, "names in certificate", strings.Join(cert.SANs, ", "))
		var ents []models.Entity
		if dom, ok := intel.NormalizeDomain(cert.Subject); ok {
			ents = append(ents, models.Entity{Type: models.EntDomain, Value: dom, Strong: true})
		}
		emit(fnd("TLS certificate on :443", "tls", "", 0.85, d, ents...))
	}
	if w, err := probe.FetchWeb(ctx, c, host); err == nil {
		d := map[string]string{"status": strconv.Itoa(w.Status), "final URL": w.FinalURL}
		put(d, "title", w.Meta.Title)
		put(d, "server", w.Header.Get("Server"))
		emit(fnd("Web service on the IP", "web", w.FinalURL, 0.8, d))
	}
}
