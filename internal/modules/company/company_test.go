package company

import (
	"testing"

	"github.com/sudosoc/rectool/internal/models"
)

func cand(host string, strong bool) models.Finding {
	return models.Finding{Source: "Possible website: " + host, Confidence: 0.75, Details: map[string]string{"verification": "ok"},
		Entities: []models.Entity{{Type: models.EntDomain, Value: host, Strong: strong}}}
}

func TestSlugs(t *testing.T) {
	got := slugs("Acme Widgets, Inc.")
	if len(got) != 2 || got[0] != "acmewidgets" || got[1] != "acme-widgets" {
		t.Fatalf("%v", got)
	}
}

func TestPickBestKeepsOnlyOneStrong(t *testing.T) {
	out := pickBest([]models.Finding{cand("acme.io", true), cand("acme.org", true), cand("acme.dev", false)}, "")
	strong := 0
	for _, f := range out {
		if f.Entities[0].Strong {
			strong++
			if f.Entities[0].Value != "acme.org" {
				t.Errorf("preferred TLD should win, got %s", f.Entities[0].Value)
			}
		}
	}
	if strong != 1 {
		t.Fatalf("want exactly one strong candidate, got %d", strong)
	}
}

func TestPickBestPrefersKnownDomain(t *testing.T) {
	out := pickBest([]models.Finding{cand("acme.com", true), cand("acme.io", true)}, "acme.io")
	for _, f := range out {
		if f.Entities[0].Strong != (f.Entities[0].Value == "acme.io") {
			t.Fatalf("operator's own domain must win: %+v", f.Entities[0])
		}
	}
}
