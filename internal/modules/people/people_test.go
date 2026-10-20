package people

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sudosoc/rectool/internal/extract"
	"github.com/sudosoc/rectool/internal/jsonld"
	"github.com/sudosoc/rectool/internal/models"
)

func TestLinkedInRecord(t *testing.T) {
	p := jsonld.Person{
		Name: "Jane Roe", JobTitles: []string{"Senior Engineer"}, Location: "Cairo, Egypt", Image: "https://media.licdn.com/x.jpg",
		Description: "Builds systems.", SameAs: []string{"https://janeroe.dev", "https://www.linkedin.com/in/janeroe"},
		WorksFor:  []jsonld.Org{{Name: "Acme", Start: "2021-03"}},
		Alumni:    []jsonld.Org{{Name: "OldCo", End: "2020"}, {Name: "Cairo University", School: true}},
		Languages: []string{"Arabic"},
	}
	rec := linkedInRecord(p, extract.Meta{Title: "Jane Roe - Senior Engineer at Acme | LinkedIn"}, "https://www.linkedin.com/in/janeroe/?trk=x", "")
	if rec.URL != "https://www.linkedin.com/in/janeroe/" || rec.IDs["linkedin"] != "janeroe" || !rec.Self {
		t.Errorf("identity fields: %+v", rec)
	}
	if rec.Headline != "Senior Engineer at Acme" || strings.Join(rec.Employers, "|") != "Acme|OldCo" || strings.Join(rec.Education, "|") != "Cairo University" {
		t.Errorf("career fields: %+v", rec)
	}
	if len(rec.Websites) != 1 || rec.Websites[0] != "https://janeroe.dev" || rec.Photo == "" {
		t.Errorf("websites/photo: %+v", rec)
	}
}

func TestLinkedInKeyAndSlugs(t *testing.T) {
	for in, want := range map[string]string{
		"https://www.linkedin.com/in/Jane-Roe-1a2b3c/": "jane-roe-1a2b3c",
		"linkedin.com/in/janeroe?trk=1":                "janeroe",
		"https://www.linkedin.com/company/acme":        "",
		"https://github.com/janeroe":                   "",
	} {
		if got := liKey(in); got != want {
			t.Errorf("liKey(%q)=%q want %q", in, got, want)
		}
	}
}

const orcidJSON = `{"person":{"name":{"given-names":{"value":"Ada"},"family-name":{"value":"Lovelace"},"credit-name":null},
 "biography":{"content":"Mathematician."},
 "keywords":{"keyword":[{"content":"analytical engines"},{"content":"algorithms"}]},
 "researcher-urls":{"researcher-url":[{"url":{"value":"https://ada.example"}}]},
 "emails":{"email":[{"email":"Ada@Example.org"}]},
 "addresses":{"address":[{"country":{"value":"GB"}}]}},
 "activities-summary":{
  "employments":{"affiliation-group":[
    {"summaries":[{"employment-summary":{"role-title":"Fellow","organization":{"name":"Royal Society","address":{"city":"London","country":"GB"}},"end-date":null}}]},
    {"summaries":[{"employment-summary":{"organization":{"name":"Old Lab"},"end-date":{"year":{"value":"1840"}}}}]}]},
  "educations":{"affiliation-group":[{"summaries":[{"education-summary":{"organization":{"name":"Private tuition"}}}]}]}}}`

func TestOrcidRecord(t *testing.T) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(orcidJSON), &raw); err != nil {
		t.Fatal(err)
	}
	r := orcidRecord("0000-0001-0000-0000", raw)
	if r.Name != "Ada Lovelace" || r.IDs["orcid"] != "0000-0001-0000-0000" || r.Emails[0] != "ada@example.org" {
		t.Errorf("identity: %+v", r)
	}
	if r.Location != "London, GB" || r.Headline != "Fellow — Royal Society" {
		t.Errorf("current position drives location/headline: loc=%q head=%q", r.Location, r.Headline)
	}
	if strings.Join(r.Employers, "|") != "Royal Society|Old Lab" || strings.Join(r.Interests, ",") != "analytical engines,algorithms" || len(r.Education) != 1 {
		t.Errorf("career: %+v", r)
	}
}

func TestCVOwnership(t *testing.T) {
	cv := "Jane Roe\nCairo, Egypt\njane.roe@acme.io | +20 100 123 4567\n\nExperience\nSenior Engineer – Acme Corporation\n2021 – Present\n\nEducation\nCairo University — B.Sc.\n"
	target := models.Target{FullName: "Jane Roe", Email: "jane.roe@acme.io", Location: "Cairo", Company: "Acme"}

	rec, matched, ok := cvRecord(cv, "https://x.test/cv.pdf", target)
	if !ok || rec.Platform != "CV" || len(matched) < 3 {
		t.Fatalf("a CV matching name, e-mail, location and company must be accepted with those matches: ok=%v matched=%v", ok, matched)
	}
	if _, _, ok := cvRecord("Pietro Rossi\nMilan\n", "https://x.test/other.pdf", target); ok {
		t.Error("a CV with a different name must be rejected")
	}
	_, matched, ok = cvRecord(cv, "https://x.test/cv.pdf", models.Target{FullName: "Jane Roe"})
	if !ok || len(matched) != 0 {
		t.Errorf("name-only match must be accepted but flagged as unverified: %v %v", ok, matched)
	}
}

func TestTrustedRequiresMoreThanAName(t *testing.T) {
	rec := models.Record{Platform: "GitHub", Name: "Jane Roe", Location: "Cairo, Egypt", Self: true}
	if trusted(rec, models.Target{FullName: "Jane Roe"}) {
		t.Error("a name match alone must not make a record's leads followable")
	}
	if !trusted(rec, models.Target{FullName: "Jane Roe", Location: "Cairo"}) {
		t.Error("name + location match should be trusted")
	}
	if trusted(models.Record{Platform: "GitHub", Name: "Pietro Rossi", Location: "Cairo"}, models.Target{FullName: "Jane Roe", Location: "Cairo"}) {
		t.Error("a different name is never trusted")
	}
}

// A real live-audit failure: a colleague's CV that merely *mentions* the target must not be taken as theirs.
func TestCVThatOnlyMentionsTheNameIsRejected(t *testing.T) {
	other := "Mohit Jain\nResearcher, Microsoft Research India\nmohja@microsoft.com\n\nAcknowledgements\nThanks to Satya Nadella for the opportunity.\n"
	if _, _, ok := cvRecord(other, "https://x.test/other.pdf", models.Target{FullName: "Satya Nadella"}); ok {
		t.Fatal("a CV owned by someone else was accepted because it mentions the name")
	}
	if _, _, ok := cvRecord("Satya Nadella\nRedmond\nsatya@example.org\n", "https://x.test/own.pdf", models.Target{FullName: "Satya Nadella"}); !ok {
		t.Fatal("the person's own CV must be accepted")
	}
}

func TestPastedProfileBecomesARecord(t *testing.T) {
	text := "Jane Roe\nSenior Engineer at Acme\nCairo, Egypt\n\nExperience\nSenior Engineer – Acme\n2021 – Present\n\nEducation\nCairo University — B.Sc.\n\nSkills\nGo, Rust\n"
	var got []models.Finding
	pastedProfile(nil, nil, models.Target{FullName: "Jane Roe", Notes: text}, func(f models.Finding) { got = append(got, f) })
	if len(got) != 1 || got[0].Record == nil {
		t.Fatalf("expected one record finding, got %+v", got)
	}
	r := got[0].Record
	if r.Platform != "Pasted profile" || r.Name != "Jane Roe" || r.Headline != "Senior Engineer at Acme" || r.Location != "Cairo, Egypt" || !r.Self {
		t.Errorf("record: %+v", r)
	}
	if len(r.Education) == 0 || len(r.Employers) == 0 {
		t.Errorf("career data missing: %+v", r)
	}
	pastedProfile(nil, nil, models.Target{}, func(models.Finding) { t.Error("empty notes must emit nothing") })
}
