package profiles

import (
	"strings"
	"testing"

	"github.com/sudosoc/rectool/internal/models"
)

func ent(typ, v string, strong bool) models.Entity {
	return models.Entity{Type: typ, Value: v, Strong: strong}
}

func fixtures() []models.Finding {
	return []models.Finding{
		{Source: "GitHub profile", Details: map[string]string{"name": "Linus Torvalds", "company": "Linux Foundation"},
			Entities: []models.Entity{ent(models.EntName, "Linus Torvalds", false)}},
		{Source: "GitHub commit identities", Details: map[string]string{"commit author names": "Linus Torvalds"},
			Entities: []models.Entity{ent(models.EntEmail, "torvalds@linux-foundation.org", true)}},
		{Source: "npm maintainer", Details: map[string]string{}, // someone else using the same handle
			Entities: []models.Entity{ent(models.EntEmail, "deandb2015@gmail.com", true)}},
		{Source: "Docker Hub profile", Details: map[string]string{"company": "DoLoop srls", "location": "Italy"}},
	}
}

func find(fs []models.Finding, src string) models.Finding {
	for _, f := range fs {
		if f.Source == src {
			return f
		}
	}
	return models.Finding{}
}

func TestAttributionUsernameOnly(t *testing.T) {
	out := attribute("torvalds", fixtures(), models.Target{Username: "torvalds"})

	commits := find(out, "GitHub commit identities")
	if commits.Confidence < strongThreshold || !commits.Entities[0].Strong ||
		!strings.HasPrefix(commits.Details["attribution"], "corroborated") {
		t.Errorf("commit identity of the handle's own e-mail should be corroborated: %+v", commits)
	}

	npm := find(out, "npm maintainer")
	if npm.Confidence >= strongThreshold || npm.Entities[0].Strong ||
		!strings.HasPrefix(npm.Details["attribution"], "unverified") {
		t.Errorf("unrelated npm account must stay unverified and not be followed: %+v", npm)
	}
	if d := find(out, "Docker Hub profile"); d.Confidence >= strongThreshold {
		t.Errorf("docker hub profile of a different person scored %.2f", d.Confidence)
	}
}

func TestAttributionUsesSuppliedClues(t *testing.T) {
	fs := []models.Finding{{Source: "Keybase identity proofs", Details: map[string]string{"full name": "Jane Roe", "location": "Cairo, Egypt"},
		Entities: []models.Entity{ent(models.EntName, "Jane Roe", false), ent(models.EntDomain, "janeroe.dev", true)}}}
	weak := attribute("jroe", fs, models.Target{Username: "jroe"})[0]
	if weak.Confidence >= strongThreshold || weak.Entities[1].Strong {
		t.Fatalf("no clues: should be unverified, got %.2f strong=%v", weak.Confidence, weak.Entities[1].Strong)
	}
	strong := attribute("jroe", fs, models.Target{Username: "jroe", FullName: "Jane Roe", Location: "Cairo"})[0]
	if strong.Confidence < strongThreshold || !strong.Entities[1].Strong {
		t.Fatalf("matching name+location: should be corroborated, got %.2f strong=%v", strong.Confidence, strong.Entities[1].Strong)
	}
}

func TestNameMatching(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"Linus Torvalds", "linus torvalds", true},
		{"Linus Benedict Torvalds", "Linus Torvalds", true},
		{"Linus", "Linus Torvalds", false}, // single token is too weak
		{"John Smith", "Jon Smith", false},
	} {
		if got := namesMatch(c.a, c.b); got != c.want {
			t.Errorf("namesMatch(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}
