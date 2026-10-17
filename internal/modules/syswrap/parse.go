package syswrap

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/sudosoc/rectool/internal/models"
)

const maxItems = 500

func finding(source, category, url string, conf float64, d map[string]string) models.Finding {
	return models.Finding{Source: source, Category: category, URL: url,
		Status: models.StatusFound, Confidence: conf, Details: d}
}

// parseWhois pulls the intelligence-bearing "Key: value" lines out of whois
// output and merges repeated keys (name servers) into comma lists.
func parseWhois(in Inputs, _ []string, out string) []models.Finding {
	want := map[string]string{
		"registrar": "registrar", "registrant name": "registrant_name",
		"registrant organization": "registrant_org", "registrant email": "registrant_email",
		"registrant country": "registrant_country", "creation date": "created",
		"registry expiry date": "expires", "updated date": "updated",
		"name server": "name_servers", "registrar abuse contact email": "abuse_email",
		"admin email": "admin_email", "tech email": "tech_email", "dnssec": "dnssec",
	}
	d := map[string]string{}
	seen := map[string]map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, known := want[strings.ToLower(strings.TrimSpace(k))]
		v = strings.TrimSpace(v)
		if !known || v == "" || strings.Contains(strings.ToLower(v), "redacted") {
			continue
		}
		if seen[key] == nil {
			seen[key] = map[string]bool{}
		}
		lv := strings.ToLower(v)
		if seen[key][lv] {
			continue
		}
		seen[key][lv] = true
		if old, exists := d[key]; exists {
			d[key] = old + ", " + v
		} else {
			d[key] = v
		}
	}
	if len(d) == 0 {
		return nil
	}
	d["domain"] = in.Domain
	return []models.Finding{finding("whois "+in.Domain, "domain", "", 0.9, d)}
}

// parseDig turns `dig +short <type> <domain>` into one finding per record type.
func parseDig(in Inputs, args []string, out string) []models.Finding {
	var recs []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, ";") {
			recs = append(recs, l)
		}
	}
	if len(recs) == 0 {
		return nil
	}
	typ := "?"
	for _, a := range args {
		switch a {
		case "MX", "TXT", "NS", "A", "AAAA":
			typ = a
		}
	}
	if len(recs) > maxItems {
		recs = recs[:maxItems]
	}
	return []models.Finding{finding("dig "+typ+" "+in.Domain, "dns", "", 0.95,
		map[string]string{"type": typ, "records": strings.Join(recs, " | ")})}
}

var harvestHeadRe = regexp.MustCompile(`(?i)^\[\*\]\s+(Emails|Hosts|IPs|URLs|ASNS|Interesting Urls|Linkedin Links|Twitter Handles?)\b.*found`)

// parseHarvester reads theHarvester's console report: sections introduced by
// "[*] <Kind> found: N", a dashed rule, then one item per line until a blank
// line or the next "[*]" header.
func parseHarvester(in Inputs, _ []string, out string) []models.Finding {
	var res []models.Finding
	kind := ""
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if m := harvestHeadRe.FindStringSubmatch(line); m != nil {
			kind = strings.ToLower(m[1])
			continue
		}
		if line == "" || strings.HasPrefix(line, "[*]") {
			kind = ""
			continue
		}
		if kind == "" || strings.Trim(line, "-") == "" || len(res) >= maxItems {
			continue
		}
		item, ip, _ := strings.Cut(line, ":") // hosts print as "host:1.2.3.4"
		d := map[string]string{"type": kind, "domain": in.Domain}
		if ip != "" && kind == "hosts" {
			d["ip"] = ip
		}
		f := finding("theHarvester", kind, "", 0.7, d)
		if kind == "emails" {
			d["email"] = item
		} else {
			f.URL = item
		}
		res = append(res, f)
	}
	return res
}

var sherlockRe = regexp.MustCompile(`^\[\+\]\s+(.+?):\s+(https?://\S+)\s*$`)

// parseSherlock reads "[+] Site: URL" lines from `sherlock --print-found`.
func parseSherlock(in Inputs, _ []string, out string) []models.Finding {
	var res []models.Finding
	for _, l := range strings.Split(out, "\n") {
		if m := sherlockRe.FindStringSubmatch(strings.TrimSpace(l)); m != nil && len(res) < maxItems {
			res = append(res, finding(m[1], "social", m[2], 0.7,
				map[string]string{"username": in.Username, "via": "sherlock"}))
		}
	}
	return res
}

// parseSubfinder reads one subdomain per line.
func parseSubfinder(in Inputs, _ []string, out string) []models.Finding {
	var hosts []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.ToLower(strings.TrimSpace(l)); l != "" && strings.HasSuffix(l, in.Domain) && len(hosts) < maxItems {
			hosts = append(hosts, l)
		}
	}
	if len(hosts) == 0 {
		return nil
	}
	shown := hosts
	if len(shown) > 100 {
		shown = shown[:100]
	}
	return []models.Finding{finding("subfinder "+in.Domain, "subdomain", "", 0.8,
		map[string]string{"count": strconv.Itoa(len(hosts)), "subdomains": strings.Join(shown, ", ")})}
}

// parseWhatweb keeps WhatWeb's one-line fingerprint of the site.
func parseWhatweb(in Inputs, _ []string, out string) []models.Finding {
	line := strings.TrimSpace(strings.SplitN(strings.TrimSpace(out), "\n", 2)[0])
	if line == "" {
		return nil
	}
	if len(line) > 900 {
		line = line[:900] + "…"
	}
	return []models.Finding{finding("whatweb "+in.Domain, "tech", "", 0.7, map[string]string{"fingerprint": line})}
}

// parseFoundLines reads "[+] Site: URL" lines (Sherlock/Maigret style).
func parseFoundLines(via string) func(Inputs, []string, string) []models.Finding {
	return func(in Inputs, _ []string, out string) []models.Finding {
		var res []models.Finding
		for _, l := range strings.Split(out, "\n") {
			if m := sherlockRe.FindStringSubmatch(strings.TrimSpace(l)); m != nil && len(res) < maxItems {
				res = append(res, finding(m[1], "social", m[2], 0.7,
					map[string]string{"username": in.Username, "via": via}))
			}
		}
		return res
	}
}

var holeheRe = regexp.MustCompile(`^\[\+\]\s+([A-Za-z0-9.\-]+\.[a-z]{2,})`)

// parseHolehe lists the sites where an e-mail address has an account.
func parseHolehe(in Inputs, _ []string, out string) []models.Finding {
	var sites []string
	for _, l := range strings.Split(out, "\n") {
		if m := holeheRe.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			sites = append(sites, m[1])
		}
	}
	if len(sites) == 0 {
		return nil
	}
	return []models.Finding{finding("holehe: accounts registered with "+in.Email, "email-account", "", 0.75,
		map[string]string{"count": strconv.Itoa(len(sites)), "sites": strings.Join(sites, ", ")})}
}

// parseRawSummary keeps the first lines of a tool's report verbatim.
func parseRawSummary(name, category string) func(Inputs, []string, string) []models.Finding {
	return func(in Inputs, _ []string, out string) []models.Finding {
		out = strings.TrimSpace(out)
		if out == "" {
			return nil
		}
		if len(out) > 1500 {
			out = out[:1500] + "…"
		}
		return []models.Finding{finding(name, category, "", 0.6, map[string]string{"output": out})}
	}
}
