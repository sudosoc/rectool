package geo

import (
	"testing"

	"github.com/sudosoc/rectool/internal/models"
)

func TestInferOffset(t *testing.T) {
	// active 08:00-22:00 local at UTC+2 => UTC 06..20, quiet 21..05 UTC
	var h [24]int
	for hr := 6; hr <= 20; hr++ {
		h[hr] = 20
	}
	off, conf, ok := InferOffset(h)
	if !ok || off != 2 || conf < 0.3 {
		t.Fatalf("offset=%v conf=%v ok=%v", off, conf, ok)
	}
	var flat [24]int
	for i := range flat {
		flat[i] = 10
	}
	if _, _, ok := InferOffset(flat); ok {
		t.Fatal("flat activity should give no estimate")
	}
	var few [24]int
	few[5] = 3
	if _, _, ok := InferOffset(few); ok {
		t.Fatal("too few events accepted")
	}
}

func TestAnalyseClusters(t *testing.T) {
	pts := []models.GeoPoint{
		{Label: "Cairo, Egypt", Kind: "self-declared", Lat: 30.04, Lon: 31.23, Country: "Egypt", CountryCode: "EG", Precision: "city", Weight: 0.7},
		{Label: "Giza", Kind: "self-declared", Lat: 30.01, Lon: 31.21, Country: "Egypt", CountryCode: "EG", Precision: "city", Weight: 0.7},
		{Label: "EG", Kind: "phone", Lat: 26, Lon: 30, Country: "Egypt", CountryCode: "EG", Precision: "country", Weight: 0.2},
		{Label: "Berlin", Kind: "ip", Lat: 52.5, Lon: 13.4, Country: "Germany", CountryCode: "DE", Precision: "city", Weight: 0.3},
	}
	s := Analyse(pts, "Cairo", &Place{Lat: 30.04, Lon: 31.23, CountryCode: "EG", Precision: "city"})
	if len(s.Clusters) != 2 || s.Clusters[0].CountryCode != "EG" || len(s.Clusters[0].Points) != 3 {
		t.Fatalf("clusters: %+v", s.Clusters)
	}
	if s.Clusters[0].Score <= 0.9 || s.GivenFit != "agrees" {
		t.Fatalf("score=%v fit=%s", s.Clusters[0].Score, s.GivenFit)
	}
	if s.Conflict != "" {
		t.Fatalf("unexpected conflict: %s", s.Conflict)
	}
}

func TestClean(t *testing.T) {
	for _, junk := range []string{"Remote", "Earth", "🌍", "n/a", "  "} {
		if Clean(junk) != "" {
			t.Errorf("%q should be junk", junk)
		}
	}
	if Clean("Cairo, Egypt 🇪🇬") != "Cairo, Egypt" {
		t.Errorf("got %q", Clean("Cairo, Egypt 🇪🇬"))
	}
}
