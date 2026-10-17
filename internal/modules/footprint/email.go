package footprint

import (
	"context"
	"crypto/md5" //nolint:gosec // Gravatar identifies accounts by MD5 of the address; not a security use
	"encoding/hex"
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/intel"
	"github.com/sudosoc/rectool/internal/models"
)

func setOf(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}

// emailMX reports the domain's mail exchangers and provider class. A domain
// with no MX records cannot receive mail, which weakens the address as a lead.
func emailMX(ctx context.Context, email string) models.Finding {
	_, domain, _ := strings.Cut(email, "@")
	f := models.Finding{Source: "MX " + domain, Category: "email-domain", Details: map[string]string{"domain": domain}}

	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	mxs, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil || len(mxs) == 0 {
		f.Status, f.Confidence = models.StatusUncertain, 0.5
		f.Details["mx"] = "none found"
		return f
	}
	sort.Slice(mxs, func(i, j int) bool { return mxs[i].Pref < mxs[j].Pref })
	hosts := make([]string, 0, len(mxs))
	for _, m := range mxs {
		hosts = append(hosts, strings.TrimSuffix(m.Host, "."))
	}
	f.Status, f.Confidence = models.StatusFound, 0.95
	f.Details["mx"] = strings.Join(hosts, ", ")
	switch {
	case intel.IsDisposable(domain):
		f.Details["class"] = "disposable"
	case intel.IsFreeMail(domain):
		f.Details["class"] = "free-provider"
	default:
		f.Details["class"] = "custom-domain"
	}
	return f
}

// gravatar checks whether the address is registered with Gravatar, which
// proves an account exists for exactly this email (hash match), and reads the
// public profile (name, location, linked accounts and sites) when there is one.
func gravatar(ctx context.Context, c *httpx.Client, email string, emit func(models.Finding)) {
	sum := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(email)))) //nolint:gosec
	h := hex.EncodeToString(sum[:])

	var prof struct {
		Entry []struct {
			DisplayName       string `json:"displayName"`
			PreferredUsername string `json:"preferredUsername"`
			AboutMe           string `json:"aboutMe"`
			CurrentLocation   string `json:"currentLocation"`
			ProfileURL        string `json:"profileUrl"`
			ThumbnailURL      string `json:"thumbnailUrl"`
			Name              struct {
				Formatted string `json:"formatted"`
			} `json:"name"`
			URLs []struct {
				Value string `json:"value"`
				Title string `json:"title"`
			} `json:"urls"`
			Accounts []struct {
				Domain   string `json:"domain"`
				Username string `json:"username"`
				URL      string `json:"url"`
				Verified string `json:"verified"`
			} `json:"accounts"`
		} `json:"entry"`
	}
	if resp, err := c.Do(ctx, httpx.Request{URL: "https://gravatar.com/" + h + ".json", Timeout: 15 * time.Second,
		Headers: map[string]string{"Accept": "application/json"}}); err == nil && resp.StatusCode == 200 &&
		json.Unmarshal(resp.Body, &prof) == nil && len(prof.Entry) > 0 {
		e := prof.Entry[0]
		d := map[string]string{"md5": h}
		put := func(k, v string) {
			if v = strings.TrimSpace(v); v != "" {
				d[k] = v
			}
		}
		put("display name", e.DisplayName)
		put("full name", e.Name.Formatted)
		put("username", e.PreferredUsername)
		put("location", e.CurrentLocation)
		put("about", e.AboutMe)
		var ents []models.Entity
		for _, n := range []string{e.DisplayName, e.Name.Formatted} {
			if strings.Contains(n, " ") {
				ents = append(ents, models.Entity{Type: models.EntName, Value: n})
			}
		}
		if len(e.PreferredUsername) >= 3 {
			ents = append(ents, models.Entity{Type: models.EntUsername, Value: e.PreferredUsername, Strong: true})
		}
		var acc, sites []string
		for _, a := range e.Accounts {
			acc = append(acc, a.Domain+": "+a.Username)
			if len(a.Username) >= 3 {
				ents = append(ents, models.Entity{Type: models.EntUsername, Value: a.Username, Strong: a.Verified == "true"})
			}
		}
		for _, u := range e.URLs {
			sites = append(sites, u.Value)
			if dom, ok := intel.NormalizeDomain(u.Value); ok && !strings.Contains(dom, "gravatar.com") {
				ents = append(ents, models.Entity{Type: models.EntDomain, Value: dom, Strong: true})
			}
		}
		put("linked accounts", strings.Join(acc, ", "))
		put("websites", strings.Join(sites, ", "))
		if e.ThumbnailURL != "" {
			put("avatar", e.ThumbnailURL+"?s=512")
		} else {
			put("avatar", "https://www.gravatar.com/avatar/"+h+"?s=512&d=404")
		}
		emit(models.Finding{Source: "Gravatar profile", Category: "email-account", URL: "https://gravatar.com/" + h,
			Status: models.StatusFound, Confidence: 0.95, Details: d, Entities: ents})
		return
	}
	resp, err := c.Do(ctx, httpx.Request{URL: "https://www.gravatar.com/avatar/" + h + "?d=404&s=64"})
	if err != nil || resp.StatusCode != 200 {
		return
	}
	emit(models.Finding{
		Source: "Gravatar", Category: "email-account", URL: "https://gravatar.com/" + h,
		Status: models.StatusFound, Confidence: 0.95,
		Details: map[string]string{"note": "an avatar is registered for this exact email", "md5": h,
			"avatar": "https://www.gravatar.com/avatar/" + h + "?s=512&d=404"},
	})
}

// infostealer asks Hudson Rock's free public index whether the address shows up
// in infostealer-malware logs. Only the existence, dates and counts are
// reported: no credentials, device names or IP addresses.
func infostealer(ctx context.Context, c *httpx.Client, email string, emit func(models.Finding)) {
	resp, err := c.Do(ctx, httpx.Request{
		URL:     "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=" + url.QueryEscape(email),
		Timeout: 25 * time.Second, Headers: map[string]string{"Accept": "application/json"},
	})
	if err != nil || resp.StatusCode != 200 {
		return
	}
	var r struct {
		Stealers []struct {
			Date      string `json:"date_compromised"`
			OS        string `json:"operating_system"`
			Corporate int    `json:"total_corporate_services"`
			User      int    `json:"total_user_services"`
		} `json:"stealers"`
	}
	if json.Unmarshal(resp.Body, &r) != nil || len(r.Stealers) == 0 {
		return
	}
	var dates []string
	corp, usr := 0, 0
	for _, s := range r.Stealers {
		if len(s.Date) >= 10 {
			dates = append(dates, s.Date[:10])
		}
		corp += s.Corporate
		usr += s.User
	}
	sort.Strings(dates)
	d := map[string]string{
		"infected devices":                     strconv.Itoa(len(r.Stealers)),
		"corporate services with saved logins": strconv.Itoa(corp),
		"personal services with saved logins":  strconv.Itoa(usr),
		"note":                                 "this address appears in infostealer-malware logs: assume its passwords are compromised and change them. Only counts and dates are shown.",
	}
	if len(dates) > 0 {
		d["compromise dates"] = dates[0] + " … " + dates[len(dates)-1]
	}
	emit(models.Finding{Source: "Infostealer exposure (Hudson Rock)", Category: "exposure",
		URL: "https://www.hudsonrock.com/free-tools", Status: models.StatusFound, Confidence: 0.85, Details: d})
}

// emailQueries are the search phrasings for an address: exact plus the
// "human obfuscated" forms people use to dodge scrapers.
func emailQueries(email string) []string {
	local, domain, _ := strings.Cut(email, "@")
	return []string{
		`"` + email + `"`,
		`"` + local + ` [at] ` + strings.ReplaceAll(domain, ".", " [dot] ") + `"`,
		`"` + local + ` (at) ` + strings.ReplaceAll(domain, ".", " (dot) ") + `"`,
		`"` + local + ` at ` + strings.ReplaceAll(domain, ".", " dot ") + `"`,
	}
}

// emailMatcher matches the address in plain or obfuscated form:
// john@example.com, john [at] example [dot] com, john(at)example.com, ...
func emailMatcher(email string) matcher {
	local, domain, _ := strings.Cut(email, "@")
	const sep = `\s*[\[\(\{<]?\s*%s\s*[\]\)\}>]?\s*`
	at := strings.Replace(sep, "%s", `(?:at|@)`, 1)
	dot := strings.Replace(sep, "%s", `(?:dot|\.)`, 1)

	labels := strings.Split(domain, ".")
	for i, l := range labels {
		labels[i] = regexp.QuoteMeta(l)
	}
	pat := `(?i)(?:^|[^A-Za-z0-9._%+-])` + regexp.QuoteMeta(local) + at + strings.Join(labels, dot) + `(\.?[A-Za-z0-9-])?`
	return matcher{
		reject: 1,
		re:     regexp.MustCompile(pat),
		conf: func(m string) float64 {
			if strings.Contains(m, "@") {
				return 0.9
			}
			return 0.8 // obfuscated form: still a deliberate publication of the address
		},
	}
}
