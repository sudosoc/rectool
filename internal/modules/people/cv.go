package people

import (
	"context"
	"net/url"
	"strings"

	"github.com/sudosoc/rectool/internal/cvparse"
	"github.com/sudosoc/rectool/internal/doc"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/identity"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/modules/dorks"
)

// cvFinder searches the web for the person's CV / resume, downloads the few
// best PDF hits and extracts their contents. A document is kept only if it
// really contains the person's full name; how strongly it matches the
// operator's other identifiers (e-mail, phone, employer, location, handle) is
// recorded, and identity resolution then decides whether it belongs to the
// person being investigated.
func cvFinder(ctx context.Context, c *httpx.Client, s *dorks.Searcher, t models.Target, emit func(models.Finding)) {
	if len(strings.Fields(t.FullName)) < 2 {
		return
	}
	queries := []string{`"` + t.FullName + `" (CV OR resume OR "curriculum vitae") filetype:pdf`}
	if t.Location != "" {
		queries = append(queries, `"`+t.FullName+`" "`+t.Location+`" (CV OR resume) filetype:pdf`)
	}
	if t.Company != "" {
		queries = append(queries, `"`+t.FullName+`" "`+t.Company+`" (CV OR resume) filetype:pdf`)
	}
	var urls []string
	seen := map[string]bool{}
	var lastErr error
	for _, q := range queries {
		res, _, err := s.Search(ctx, c, q)
		if err != nil {
			lastErr = err
			continue
		}
		for _, r := range res {
			u, perr := url.Parse(r.URL)
			if perr != nil || seen[r.URL] || !strings.HasSuffix(strings.ToLower(u.Path), ".pdf") {
				continue
			}
			seen[r.URL] = true
			urls = append(urls, r.URL)
		}
	}
	if len(urls) == 0 {
		if lastErr != nil && ctx.Err() == nil {
			emit(errFinding("CV / resume search", "no search engine answered: "+lastErr.Error()))
		}
		return
	}
	if len(urls) > 4 {
		urls = urls[:4]
	}
	for _, u := range urls {
		if ctx.Err() != nil {
			return
		}
		text, err := doc.FetchText(ctx, c, u)
		if err != nil {
			continue
		}
		rec, matched, ok := cvRecord(text, u, t)
		if !ok {
			continue
		}
		conf := 0.35
		note := "only the name matches: this CV may belong to a different person with the same name"
		if len(matched) > 0 {
			conf = 0.85
			note = "also matches the supplied " + strings.Join(matched, ", ")
		}
		f := finding("CV / resume document", "identity", conf, rec, t)
		f.Details["verification"] = note
		f.Details["document"] = u
		emit(f)
	}
}

// cvRecord parses a CV's text and checks it belongs to the named person.
func cvRecord(text, u string, t models.Target) (models.Record, []string, bool) {
	cv := cvparse.Parse(text)
	// The name must be the document's *owner*, not merely mentioned somewhere
	// (a colleague's CV can thank or cite the person). The header name decides;
	// when the parser cannot find one, the name must open the document.
	if cv.Name != "" {
		if identity.MatchNames(cv.Name, t.FullName) != identity.NameStrong {
			return models.Record{}, nil, false
		}
	} else if !nameOpens(text, t.FullName) {
		return models.Record{}, nil, false
	}

	rec := models.Record{Platform: "CV", URL: u, Self: true, Name: t.FullName, Emails: cv.Emails, Phones: cv.Phones,
		Location: cv.Location, Employers: cv.Employers, Education: cv.Education, Bio: cv.Summary,
		Interests: append(append([]string{}, cv.Interests...), cv.Skills...)}
	if cv.Name != "" && identity.MatchNames(cv.Name, t.FullName) == identity.NameStrong {
		rec.Name = cv.Name
	}
	rec.Websites = append(rec.Websites, cv.Links...)

	low := strings.ToLower(text)
	var matched []string
	if t.Email != "" && containsFold(cv.Emails, t.Email) {
		matched = append(matched, "e-mail")
	}
	if t.Phone != "" && phoneIn(cv.Phones, t.Phone) {
		matched = append(matched, "phone")
	}
	if t.Company != "" && strings.Contains(low, strings.ToLower(t.Company)) {
		matched = append(matched, "company")
	}
	if t.Location != "" && locationIn(low, t.Location) {
		matched = append(matched, "location")
	}
	if t.Username != "" && strings.Contains(low, strings.ToLower(t.Username)) {
		matched = append(matched, "username")
	}
	if t.Domain != "" && strings.Contains(low, strings.ToLower(t.Domain)) {
		matched = append(matched, "domain")
	}
	return rec, matched, true
}

// nameOpens reports whether every word of name appears in the first three
// non-empty lines of the text.
func nameOpens(text, name string) bool {
	var head []string
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			head = append(head, l)
			if len(head) == 3 {
				break
			}
		}
	}
	have := map[string]bool{}
	for _, w := range identity.Words(strings.Join(head, " ")) {
		have[w] = true
	}
	want := identity.Words(name)
	for _, w := range want {
		if !have[w] {
			return false
		}
	}
	return len(want) > 0
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func phoneIn(list []string, phone string) bool {
	want := onlyDigits(phone)
	if len(want) < 7 {
		return false
	}
	want = want[len(want)-min(9, len(want)):]
	for _, p := range list {
		if d := onlyDigits(p); strings.HasSuffix(d, want) {
			return true
		}
	}
	return false
}

func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// locationIn checks the first word of the supplied location (the city) appears
// in the text.
func locationIn(lowText, loc string) bool {
	for _, w := range identity.Words(loc) {
		if len(w) >= 4 && strings.Contains(lowText, w) {
			return true
		}
	}
	return false
}
