// Package jsonld reads schema.org Person data out of a page's
// <script type="application/ld+json"> blocks. LinkedIn's logged-out public
// profile view, personal home pages and many portfolio sites publish exactly
// this, so it is the most reliable way to read structured profile data.
package jsonld

import (
	"encoding/json"
	"html"
	"regexp"
	"strings"
)

// Org is an organisation a person worked for or studied at.
type Org struct {
	Name     string
	URL      string
	Location string
	Start    string
	End      string
	School   bool // EducationalOrganization
}

// Person is the subset of schema.org/Person rectool cares about.
type Person struct {
	Name        string
	URL         string
	JobTitles   []string
	WorksFor    []Org
	Alumni      []Org
	Location    string
	Image       string
	Description string
	Emails      []string
	Phones      []string
	SameAs      []string
	KnowsAbout  []string
	Languages   []string
}

var blockRe = regexp.MustCompile(`(?is)<script[^>]+type=["']application/ld\+json["'][^>]*>(.*?)</script>`)

// Persons returns every Person (or ProfilePage main entity) found in doc.
func Persons(doc string) []Person {
	var out []Person
	for _, m := range blockRe.FindAllStringSubmatch(doc, -1) {
		var v any
		if json.Unmarshal([]byte(strings.TrimSpace(html.UnescapeString(m[1]))), &v) != nil {
			if json.Unmarshal([]byte(strings.TrimSpace(m[1])), &v) != nil {
				continue
			}
		}
		walk(v, &out)
	}
	return out
}

func walk(v any, out *[]Person) {
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			walk(x, out)
		}
	case map[string]any:
		if g, ok := t["@graph"]; ok {
			walk(g, out)
		}
		if hasType(t, "Person") {
			*out = append(*out, person(t))
		}
		if me, ok := t["mainEntity"]; ok {
			walk(me, out)
		}
	}
}

func hasType(m map[string]any, want string) bool {
	for _, t := range list(m["@type"]) {
		if s, ok := t.(string); ok && strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

func list(v any) []any {
	switch t := v.(type) {
	case nil:
		return nil
	case []any:
		return t
	default:
		return []any{t}
	}
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(html.UnescapeString(t))
	case float64:
		return strings.TrimSuffix(strings.TrimSuffix(jsonNumber(t), ".0"), ".")
	case map[string]any:
		for _, k := range []string{"name", "@value", "contentUrl", "url", "text"} {
			if s := str(t[k]); s != "" {
				return s
			}
		}
	}
	return ""
}

func jsonNumber(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

func strs(v any) []string {
	var out []string
	for _, x := range list(v) {
		if s := str(x); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func orgs(v any) []Org {
	var out []Org
	for _, x := range list(v) {
		m, ok := x.(map[string]any)
		if !ok {
			if s := str(x); s != "" {
				out = append(out, Org{Name: s})
			}
			continue
		}
		o := Org{Name: str(m["name"]), URL: str(m["url"]), Location: str(m["location"])}
		if o.Location == "" {
			o.Location = address(m["address"])
		}
		if mem, ok := m["member"].(map[string]any); ok {
			o.Start, o.End = str(mem["startDate"]), str(mem["endDate"])
		}
		o.School = hasType(m, "EducationalOrganization") || hasType(m, "CollegeOrUniversity") || hasType(m, "School")
		if o.Name != "" {
			out = append(out, o)
		}
	}
	return out
}

func address(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case map[string]any:
		var parts []string
		for _, k := range []string{"addressLocality", "addressRegion", "addressCountry"} {
			s := str(t[k])
			if k == "addressCountry" && len(s) == 2 && len(parts) > 0 {
				continue // "EG" adds nothing after "Cairo, Egypt"
			}
			if s != "" && !contains(parts, s) {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	}
	return ""
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if strings.Contains(x, v) || strings.Contains(v, x) {
			return true
		}
	}
	return false
}

func person(m map[string]any) Person {
	p := Person{
		Name: str(m["name"]), URL: str(m["url"]), JobTitles: strs(m["jobTitle"]),
		WorksFor: orgs(m["worksFor"]), Alumni: orgs(m["alumniOf"]), Location: address(m["address"]),
		Image: str(m["image"]), Description: str(m["description"]), SameAs: strs(m["sameAs"]),
		KnowsAbout: strs(m["knowsAbout"]), Languages: strs(m["knowsLanguage"]),
	}
	if p.Location == "" {
		p.Location = str(m["homeLocation"])
	}
	for _, e := range strs(m["email"]) {
		p.Emails = append(p.Emails, strings.ToLower(strings.TrimPrefix(e, "mailto:")))
	}
	for _, t := range strs(m["telephone"]) {
		p.Phones = append(p.Phones, t)
	}
	return p
}
