package people

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/extract"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/identity"
	"github.com/sudosoc/rectool/internal/jsonld"
	"github.com/sudosoc/rectool/internal/models"
)

// linkedIn reads the *logged-out public view* of LinkedIn profiles: the same
// page anyone sees in a private browser window, which embeds schema.org
// Person data (headline, current and past employers, schools, location,
// photo, about). It reads at most a handful of specific profile URLs, slowly,
// and stops at the first sign of blocking: no login, no CAPTCHA solving, no
// evasion. LinkedIn's terms restrict automated access, so use it only where
// you are entitled to; when LinkedIn refuses, the report lists a manual link.
//
// Profile URLs come from links the operator pasted, plus a few vanity-slug
// guesses derived from the name ("first-last", "firstlast"). A guess is
// accepted only if the page's name matches, so a stranger's profile at the
// same slug is rejected.
func linkedIn(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
	type target struct {
		url      string
		explicit bool
	}
	var todo []target
	seen := map[string]bool{}
	for _, l := range t.Links {
		if k := liKey(l); k != "" && !seen[k] {
			seen[k] = true
			todo = append(todo, target{"https://www.linkedin.com/in/" + k + "/", true})
		}
	}
	if w := identity.Words(t.FullName); len(w) >= 2 {
		f, l := w[0], w[len(w)-1]
		for _, slug := range []string{f + "-" + l, f + l} {
			if !seen[slug] {
				seen[slug] = true
				todo = append(todo, target{"https://www.linkedin.com/in/" + slug + "/", false})
			}
		}
	}

	blocked := 0
	for i, tg := range todo {
		if ctx.Err() != nil {
			return
		}
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(1500 * time.Millisecond):
			}
		}
		resp, err := c.Do(ctx, httpx.Request{URL: tg.url, Timeout: 20 * time.Second, MaxBody: 3 << 20,
			Headers: map[string]string{"Accept-Language": "en-US,en;q=0.9"}})
		if err != nil {
			continue
		}
		switch resp.StatusCode {
		case 200:
			blocked = 0
		case 999, 429, 403:
			blocked++
			if tg.explicit || blocked == 1 {
				emit(errFinding("LinkedIn public profile", "LinkedIn blocks automated access (HTTP "+itoa(resp.StatusCode)+", "+tg.url+"). rectool does not evade this: open the profile yourself and paste its text into the Notes box, or use the manual link"))
			}
			if blocked >= 2 {
				return // never hammer a service that is saying no
			}
			continue
		default:
			continue
		}
		body := string(resp.Body)
		persons := jsonld.Persons(body)
		if len(persons) == 0 {
			continue
		}
		p := persons[0]
		if !tg.explicit && !nameMatches(p.Name, t.FullName) {
			continue // a guessed slug that belongs to someone else
		}
		rec := linkedInRecord(p, extract.ParseMeta(body), resp.FinalURL, tg.url)
		emit(finding("LinkedIn public profile", "identity", 0.9, rec, t))
	}
}

func linkedInRecord(p jsonld.Person, meta extract.Meta, finalURL, asked string) models.Record {
	u := finalURL
	if i := strings.IndexAny(u, "?#"); i > 0 {
		u = u[:i]
	}
	if !strings.Contains(u, "linkedin.com/in/") {
		u = asked
	}
	rec := models.Record{Platform: "LinkedIn", URL: u, Self: true, Name: p.Name, Roles: p.JobTitles, Location: p.Location,
		Photo: p.Image, Bio: p.Description, Interests: p.KnowsAbout, IDs: map[string]string{}}
	if rec.Name == "" {
		rec.Name = strings.TrimSpace(strings.SplitN(strings.TrimSuffix(meta.Title, " | LinkedIn"), " - ", 2)[0])
	}
	if parts := strings.SplitN(strings.TrimSuffix(meta.Title, " | LinkedIn"), " - ", 2); len(parts) == 2 {
		rec.Headline = strings.TrimSpace(parts[1])
	}
	for _, o := range p.WorksFor {
		rec.Employers = appendUniq(rec.Employers, o.Name)
		if rec.Location == "" && o.Location != "" {
			rec.Location = o.Location
		}
	}
	for _, o := range p.Alumni {
		if o.School {
			rec.Education = appendUniq(rec.Education, o.Name)
		} else {
			rec.Employers = appendUniq(rec.Employers, o.Name) // past employer
		}
	}
	for _, l := range p.Languages {
		rec.Interests = appendUniq(rec.Interests, "speaks "+l)
	}
	for _, s := range p.SameAs {
		if !strings.Contains(s, "linkedin.com") {
			rec.Websites = appendUniq(rec.Websites, s)
		}
	}
	if k := liKey(u); k != "" {
		rec.IDs["linkedin"] = k
	}
	return rec
}

// liKey extracts the vanity slug from a LinkedIn profile URL.
func liKey(raw string) string {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.HasSuffix(strings.ToLower(u.Hostname()), "linkedin.com") {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "in" && parts[1] != "" {
		return strings.ToLower(parts[1])
	}
	return ""
}

func appendUniq(s []string, v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return s
	}
	for _, x := range s {
		if strings.EqualFold(x, v) {
			return s
		}
	}
	return append(s, v)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
