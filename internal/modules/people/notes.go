package people

import (
	"context"
	"strings"

	"github.com/sudosoc/rectool/internal/cvparse"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
)

// pastedProfile reads text the operator copied from a source rectool cannot
// open itself (a LinkedIn page they can see while logged in, a "Save to PDF"
// export, a CV, a bio). It is parsed like a CV and added as a record, so
// anything an account holder can legitimately see joins the identity
// resolution without rectool touching a login-walled site.
func pastedProfile(_ context.Context, _ *httpx.Client, t models.Target, emit func(models.Finding)) {
	text := strings.TrimSpace(t.Notes)
	if text == "" {
		return
	}
	cv := cvparse.Parse(text)
	rec := models.Record{Platform: "Pasted profile", Self: true, Name: cv.Name, Emails: cv.Emails, Phones: cv.Phones,
		Location: cv.Location, Employers: cv.Employers, Education: cv.Education, Bio: cv.Summary,
		Interests: append(append([]string{}, cv.Interests...), cv.Skills...), Websites: cv.Links}
	if rec.Name == "" && t.FullName != "" && strings.Contains(strings.ToLower(text), strings.ToLower(t.FullName)) {
		rec.Name = t.FullName
	}
	if lines := nonEmptyLines(text, 6); len(lines) >= 2 && rec.Name != "" && strings.EqualFold(lines[0], rec.Name) && len(lines[1]) <= 140 {
		rec.Headline = lines[1] // LinkedIn-style: name on the first line, headline on the second
	}
	f := finding("Pasted profile / CV text", "identity", 0.8, rec, t)
	f.Details["note"] = "text supplied by the operator; treated as the person's own statements"
	emit(f)
}

func nonEmptyLines(text string, max int) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
			if len(out) == max {
				break
			}
		}
	}
	return out
}
