package domain

import (
	"context"
	"net/url"
	"strings"

	"github.com/sudosoc/rectool/internal/cvparse"
	"github.com/sudosoc/rectool/internal/doc"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/jsonld"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/probe"
)

// personData reads a personal or portfolio site as a *profile of the person
// who owns it*: schema.org Person data embedded in the page (name, job title,
// employers, schools, location, contact points, linked profiles, photo) and any
// CV / resume the site links to. Both are the person's own statements.
func personData(ctx context.Context, c *httpx.Client, w *probe.Web, links []string, emit func(models.Finding)) {
	var siteName string
	for _, p := range jsonld.Persons(w.Body) {
		rec := models.Record{Platform: "Website", URL: w.FinalURL, Self: true, Name: p.Name, Location: p.Location,
			Photo: p.Image, Bio: p.Description, Emails: p.Emails, Phones: p.Phones, Interests: p.KnowsAbout}
		if len(p.JobTitles) > 0 {
			rec.Headline = p.JobTitles[0]
			rec.Roles = p.JobTitles
		}
		for _, o := range p.WorksFor {
			rec.Employers = append(rec.Employers, o.Name)
		}
		for _, o := range p.Alumni {
			if o.School {
				rec.Education = append(rec.Education, o.Name)
			} else {
				rec.Employers = append(rec.Employers, o.Name)
			}
		}
		rec.Websites = p.SameAs // links to the person's profiles elsewhere: strong cross-references
		if rec.Name == "" {
			continue
		}
		siteName = rec.Name
		d := map[string]string{"name": rec.Name}
		put(d, "headline", rec.Headline)
		put(d, "employers", strings.Join(rec.Employers, "; "))
		put(d, "education", strings.Join(rec.Education, "; "))
		put(d, "location", rec.Location)
		put(d, "emails", strings.Join(rec.Emails, ", "))
		put(d, "profiles linked from the site", strings.Join(rec.Websites, ", "))
		put(d, "about", truncate(rec.Bio, 400))
		put(d, "avatar", rec.Photo)
		r := rec
		emit(models.Finding{Source: "Person data published on the website", Category: "identity", URL: w.FinalURL,
			Status: models.StatusFound, Confidence: 0.85, Details: d, Record: &r})
	}

	// CV / resume documents the site links to
	seen := 0
	for _, l := range links {
		u, err := url.Parse(l)
		if err != nil || seen >= 2 {
			continue
		}
		low := strings.ToLower(u.Path)
		if !strings.HasSuffix(low, ".pdf") || !(strings.Contains(low, "cv") || strings.Contains(low, "resume") || strings.Contains(low, "curriculum")) {
			continue
		}
		text, err := doc.FetchText(ctx, c, l)
		if err != nil {
			continue
		}
		seen++
		cv := cvparse.Parse(text)
		name := cv.Name
		if name == "" {
			name = siteName
		}
		rec := models.Record{Platform: "CV", URL: l, Self: true, Name: name, Emails: cv.Emails, Phones: cv.Phones,
			Location: cv.Location, Employers: cv.Employers, Education: cv.Education, Bio: cv.Summary,
			Interests: append(append([]string{}, cv.Interests...), cv.Skills...), Websites: cv.Links}
		d := map[string]string{"document": l}
		put(d, "name", rec.Name)
		put(d, "location", rec.Location)
		put(d, "employers", strings.Join(rec.Employers, "; "))
		put(d, "education", strings.Join(rec.Education, "; "))
		put(d, "skills & interests", strings.Join(rec.Interests, ", "))
		put(d, "emails", strings.Join(rec.Emails, ", "))
		put(d, "phones", strings.Join(rec.Phones, ", "))
		r := rec
		emit(models.Finding{Source: "CV / resume on the website", Category: "identity", URL: l,
			Status: models.StatusFound, Confidence: 0.85, Details: d, Record: &r})
	}
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
