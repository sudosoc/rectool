package people

import (
	"context"
	"strings"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
)

// jdig walks nested JSON objects: jdig(v, "a", "b") == v["a"]["b"].
func jdig(v any, path ...string) any {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func jstr(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func jlist(v any) []any {
	l, _ := v.([]any)
	return l
}

// orcid looks the name up in the ORCID registry and reads each plausible
// record in full. ORCID is self-curated by researchers, so employers,
// schools, keywords and links are the person's own statements.
func orcid(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
	w := strings.Fields(t.FullName)
	if len(w) < 2 {
		return
	}
	given, family := w[0], w[len(w)-1]
	var sr struct {
		Result []struct {
			ID         string   `json:"orcid-id"`
			Given      string   `json:"given-names"`
			Family     string   `json:"family-names"`
			Credit     string   `json:"credit-name"`
			OtherNames []string `json:"other-name"`
		} `json:"expanded-result"`
	}
	q := "given-names:" + given + " AND family-name:" + family
	if !getJSON(ctx, c, "https://pub.orcid.org/v3.0/expanded-search/?rows=12&q="+esc(q), nil, &sr) {
		return
	}
	n := 0
	for _, r := range sr.Result {
		if n >= 6 || ctx.Err() != nil {
			break
		}
		full := strings.TrimSpace(r.Given + " " + r.Family)
		if !nameMatches(full, t.FullName) && !nameMatches(r.Credit, t.FullName) {
			continue
		}
		var rec map[string]any
		if !getJSON(ctx, c, "https://pub.orcid.org/v3.0/"+r.ID+"/record", nil, &rec) {
			continue
		}
		n++
		emit(finding("ORCID researcher record", "identity", 0.8, orcidRecord(r.ID, rec), t))
	}
}

func orcidRecord(id string, rec map[string]any) models.Record {
	p := jdig(rec, "person")
	r := models.Record{Platform: "ORCID", URL: "https://orcid.org/" + id, Self: true, IDs: map[string]string{"orcid": id}}
	r.Name = jstr(jdig(p, "name", "credit-name", "value"))
	if r.Name == "" {
		r.Name = strings.TrimSpace(jstr(jdig(p, "name", "given-names", "value")) + " " + jstr(jdig(p, "name", "family-name", "value")))
	}
	r.Bio = jstr(jdig(p, "biography", "content"))
	for _, k := range jlist(jdig(p, "keywords", "keyword")) {
		r.Interests = appendUniq(r.Interests, jstr(jdig(k, "content")))
	}
	for _, u := range jlist(jdig(p, "researcher-urls", "researcher-url")) {
		r.Websites = appendUniq(r.Websites, jstr(jdig(u, "url", "value")))
	}
	for _, e := range jlist(jdig(p, "emails", "email")) {
		r.Emails = appendUniq(r.Emails, strings.ToLower(jstr(jdig(e, "email"))))
	}
	country := ""
	for _, a := range jlist(jdig(p, "addresses", "address")) {
		country = jstr(jdig(a, "country", "value"))
		break
	}

	place := ""
	for _, g := range jlist(jdig(rec, "activities-summary", "employments", "affiliation-group")) {
		for _, s := range jlist(jdig(g, "summaries")) {
			es := jdig(s, "employment-summary")
			org := jstr(jdig(es, "organization", "name"))
			if org == "" {
				continue
			}
			r.Employers = appendUniq(r.Employers, org)
			if jdig(es, "end-date") == nil { // current position
				if role := jstr(jdig(es, "role-title")); role != "" {
					r.Roles = appendUniq(r.Roles, role+" — "+org)
				}
				if place == "" {
					place = strings.Trim(jstr(jdig(es, "organization", "address", "city"))+", "+jstr(jdig(es, "organization", "address", "country")), ", ")
				}
			}
		}
	}
	for _, g := range jlist(jdig(rec, "activities-summary", "educations", "affiliation-group")) {
		for _, s := range jlist(jdig(g, "summaries")) {
			if org := jstr(jdig(s, "education-summary", "organization", "name")); org != "" {
				r.Education = appendUniq(r.Education, org)
			}
		}
	}
	switch {
	case place != "":
		r.Location = place
	case country != "":
		r.Location = country
	}
	if len(r.Roles) > 0 {
		r.Headline = r.Roles[0]
	}
	return r
}
