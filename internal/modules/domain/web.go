package domain

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/extract"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/probe"
)

var contactPage = regexp.MustCompile(`(?i)/(contact|contact-us|contactus|about|about-us|team|impressum|legal|imprint|kontakt|company)(/|\.html?|\.php)?$`)

var interestingPath = regexp.MustCompile(`(?i)(admin|login|backup|private|secret|staging|internal|\.git|config|upload|api|dashboard|wp-admin|phpmyadmin|cgi-bin|install|test|old|tmp|dev)`)

func fetch(ctx context.Context, c *httpx.Client, u string, timeout time.Duration) (*httpx.Response, bool) {
	resp, err := c.Do(ctx, httpx.Request{URL: u, Timeout: timeout})
	if err != nil || resp.StatusCode != 200 {
		return resp, false
	}
	return resp, true
}

func webJob(ctx context.Context, c *httpx.Client, domain string, emit func(models.Finding)) {
	w, err := probe.FetchWeb(ctx, c, domain)
	if err != nil {
		// Many domains only serve www.
		if w, err = probe.FetchWeb(ctx, c, "www."+domain); err != nil {
			if ctx.Err() == nil {
				emit(errFinding("Website", "web", err))
			}
			return
		}
	}

	host := domain
	if u, err := url.Parse(w.FinalURL); err == nil && u.Host != "" {
		host = u.Hostname()
	}
	site := map[string]string{"requested": w.URL, "final URL": w.FinalURL, "status": itoa(w.Status)}
	put(site, "title", w.Meta.Title)
	put(site, "description", w.Meta.Description)
	put(site, "og:site_name", w.Meta.OGSiteName)
	put(site, "author", w.Meta.Author)
	put(site, "keywords", w.Meta.Keywords)
	put(site, "canonical", w.Meta.Canonical)
	put(site, "server", w.Header.Get("Server"))
	emit(fnd("Website", "web", w.FinalURL, 0.95, site))

	if tech := extract.Tech(w.Header, w.Body); len(tech) > 0 {
		emit(fnd("Technology stack", "tech", "", 0.7, map[string]string{"detected": strings.Join(tech, ", ")}))
	}

	https := strings.HasPrefix(w.FinalURL, "https://")
	present, missing := probe.SecurityHeaders(w.Header, https)
	sec := map[string]string{}
	put(sec, "present", strings.Join(present, ", "))
	put(sec, "missing", strings.Join(missing, ", "))
	if !https {
		sec["transport"] = "site does not redirect to HTTPS"
	}
	if len(sec) > 0 {
		emit(fnd("Security headers", "security", "", 0.9, sec))
	}

	if cookies := cookieSummary(w.Header); cookies != "" {
		emit(fnd("Cookies set on first request", "web", "", 0.8, map[string]string{"cookies": cookies}))
	}

	if ids := extract.TrackingIDs(w.Body); len(ids) > 0 {
		d := map[string]string{"note": "the same tracking ID on another site suggests the same owner"}
		for k, v := range ids {
			d[k] = strings.Join(v, ", ")
		}
		emit(fnd("Analytics / tracking IDs", "tracking", "", 0.85, d))
	}

	// ---- gather text from the home page and a few contact-style pages ----
	pages := map[string]string{w.FinalURL: w.Body}
	links := extract.Links(w.Body, w.FinalURL)
	extra := 0
	for _, l := range links {
		u, err := url.Parse(l)
		if err != nil || !sameSite(u.Hostname(), domain) || !contactPage.MatchString(u.Path) || extra >= 3 {
			continue
		}
		if _, dup := pages[l]; dup {
			continue
		}
		if r, ok := fetch(ctx, c, l, 10*time.Second); ok {
			pages[l] = string(r.Body)
			extra++
			links = append(links, extract.Links(string(r.Body), l)...)
		}
	}

	emails := map[string]string{} // email -> page
	phones := map[string]string{}
	for p, body := range pages {
		for _, e := range extract.Emails(body) {
			emails[e] = p
		}
		for _, ph := range extract.Phones(body) {
			phones[ph] = p
		}
	}
	if len(emails) > 0 || len(phones) > 0 {
		d := map[string]string{"pages scanned": itoa(len(pages))}
		var ents []models.Entity
		var el, pl []string
		for e := range emails {
			el = append(el, e)
			at := strings.LastIndexByte(e, '@')
			ents = append(ents, models.Entity{Type: models.EntEmail, Value: e, Strong: at > 0 && sameSite(e[at+1:], domain)})
		}
		for p := range phones {
			pl = append(pl, p)
			ents = append(ents, models.Entity{Type: models.EntPhone, Value: p})
		}
		sort.Strings(el)
		sort.Strings(pl)
		put(d, "emails", strings.Join(el, ", "))
		put(d, "phones", strings.Join(pl, ", "))
		emit(fnd("Contact details on the website", "contact", w.FinalURL, 0.85, d, ents...))
	}

	for _, p := range extract.Social(links) {
		// On a social platform's own site, every navigation link would match.
		if pu, err := url.Parse(p.URL); err == nil && sameSite(pu.Hostname(), domain) {
			continue
		}
		d := map[string]string{"platform": p.Platform, "handle": p.Handle}
		emit(fnd(p.Platform+": "+p.Handle, "social-links", p.URL, 0.8, d,
			models.Entity{Type: models.EntUsername, Value: p.Handle}))
	}

	// ---- well-known files ------------------------------------------------
	base := "https://" + host
	if !https {
		base = "http://" + host
	}
	if r, ok := fetch(ctx, c, base+"/robots.txt", 8*time.Second); ok && !strings.Contains(strings.ToLower(string(r.Body[:min(len(r.Body), 200)])), "<html") {
		var dis, maps []string
		for _, line := range strings.Split(string(r.Body), "\n") {
			line = strings.TrimSpace(line)
			low := strings.ToLower(line)
			switch {
			case strings.HasPrefix(low, "disallow:"):
				p := strings.TrimSpace(line[len("disallow:"):])
				if p != "" && p != "/" && interestingPath.MatchString(p) {
					dis = append(dis, p)
				}
			case strings.HasPrefix(low, "sitemap:"):
				maps = append(maps, strings.TrimSpace(line[len("sitemap:"):]))
			}
		}
		d := map[string]string{}
		put(d, "interesting Disallow paths", list(dis, 30))
		put(d, "sitemaps", strings.Join(maps, ", "))
		if len(d) > 0 {
			emit(fnd("robots.txt", "web", base+"/robots.txt", 0.8, d))
		}
	}
	for _, p := range []string{"/.well-known/security.txt", "/security.txt"} {
		r, ok := fetch(ctx, c, base+p, 8*time.Second)
		if !ok || strings.Contains(strings.ToLower(string(r.Body[:min(len(r.Body), 200)])), "<html") {
			continue
		}
		d := map[string]string{}
		var ents []models.Entity
		for _, line := range strings.Split(string(r.Body), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
			if !ok {
				continue
			}
			k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
			switch k {
			case "contact", "policy", "expires", "encryption", "acknowledgments", "preferred-languages":
				if old := d[k]; old != "" {
					d[k] = old + ", " + v
				} else {
					d[k] = v
				}
				if k == "contact" && strings.HasPrefix(strings.ToLower(v), "mailto:") {
					ents = append(ents, models.Entity{Type: models.EntEmail, Value: strings.ToLower(strings.TrimPrefix(v[7:], "//")), Strong: true})
				}
			}
		}
		if len(d) > 0 {
			emit(fnd("security.txt", "contact", base+p, 0.9, d, ents...))
		}
		break
	}
	if r, ok := fetch(ctx, c, base+"/humans.txt", 8*time.Second); ok && !strings.Contains(strings.ToLower(string(r.Body[:min(len(r.Body), 200)])), "<html") {
		txt := strings.TrimSpace(string(r.Body))
		if len(txt) > 600 {
			txt = txt[:600] + "…"
		}
		if txt != "" {
			emit(fnd("humans.txt", "contact", base+"/humans.txt", 0.6, map[string]string{"content": txt}))
		}
	}
}

func cookieSummary(h http.Header) string {
	var out []string
	for _, c := range (&http.Response{Header: h}).Cookies() {
		flags := []string{}
		if !c.Secure {
			flags = append(flags, "no-Secure")
		}
		if !c.HttpOnly {
			flags = append(flags, "no-HttpOnly")
		}
		s := c.Name
		if len(flags) > 0 {
			s += " (" + strings.Join(flags, ",") + ")"
		}
		out = append(out, s)
	}
	return strings.Join(out, "; ")
}
