package cvparse

import (
	"strings"
	"testing"
)

const sample = `Jane Roe
Cairo, Egypt
jane.roe@acme.io | +20 100 123 4567 | https://janeroe.dev | https://www.linkedin.com/in/janeroe

Summary
Backend engineer focused on reliable distributed systems.

Experience
Senior Engineer – Acme Corporation
2021 – Present
Built the payments platform.
Software Engineer | OldCo
2016 - 2021

Education
Cairo University — B.Sc. Computer Engineering
2012 – 2016

Skills
Go, Rust, PostgreSQL • Kubernetes | Distributed systems

Interests
Chess, hiking; photography
`

func TestParseResume(t *testing.T) {
	cv := Parse(sample)
	if cv.Name != "Jane Roe" {
		t.Errorf("name %q", cv.Name)
	}
	if len(cv.Emails) != 1 || cv.Emails[0] != "jane.roe@acme.io" || len(cv.Phones) != 1 || cv.Phones[0] != "+201001234567" {
		t.Errorf("contacts: %v %v", cv.Emails, cv.Phones)
	}
	if cv.Location != "Cairo, Egypt" {
		t.Errorf("location %q", cv.Location)
	}
	if len(cv.Education) == 0 || !strings.Contains(cv.Education[0], "Cairo University") {
		t.Errorf("education %v", cv.Education)
	}
	joined := strings.Join(cv.Employers, "|")
	if !strings.Contains(joined, "Acme Corporation") || !strings.Contains(joined, "OldCo") {
		t.Errorf("employers %v", cv.Employers)
	}
	skills := strings.Join(cv.Skills, "|")
	for _, w := range []string{"Go", "PostgreSQL", "Kubernetes", "Distributed systems"} {
		if !strings.Contains(skills, w) {
			t.Errorf("skill %s missing in %v", w, cv.Skills)
		}
	}
	if len(cv.Interests) != 3 || !strings.Contains(cv.Summary, "Backend engineer") {
		t.Errorf("interests %v summary %q", cv.Interests, cv.Summary)
	}
	if len(cv.Links) != 2 {
		t.Errorf("links %v", cv.Links)
	}
}

func TestParseNoise(t *testing.T) {
	cv := Parse("Page 1 of 2\n\nlorem ipsum dolor")
	if cv.Name != "" || len(cv.Emails) != 0 || len(cv.Employers) != 0 {
		t.Errorf("noise produced data: %+v", cv)
	}
}

func TestCoarsePlace(t *testing.T) {
	if got := coarsePlace("12 Nile Street, Apt 4, Cairo, Egypt"); got != "Cairo, Egypt" {
		t.Fatalf("got %q", got)
	}
}
