package phone

import (
	"context"
	"testing"

	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

func run(t *testing.T, tg models.Target) []models.Finding {
	t.Helper()
	var out []models.Finding
	if err := New().Scan(context.Background(), tg, scanner.Deps{}, func(f models.Finding) { out = append(out, f) }); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestValidInternationalNumber(t *testing.T) {
	fs := run(t, models.Target{Phone: "+442071838750"})
	if len(fs) != 1 || fs[0].Details["region (ISO)"] != "GB" || fs[0].Details["valid"] != "yes" ||
		fs[0].Details["E.164"] != "+442071838750" || fs[0].Details["line type"] != "fixed line" {
		t.Fatalf("%+v", fs)
	}
}

func TestNationalNumberNeedsRegionHint(t *testing.T) {
	if fs := run(t, models.Target{Phone: "2071838750"}); len(fs) != 1 || fs[0].Status != models.StatusUncertain {
		t.Fatalf("no region: should be uncertain with a hint: %+v", fs)
	}
	fs := run(t, models.Target{Phone: "02071838750", Location: "London, United Kingdom"})
	if len(fs) != 1 || fs[0].Details["region (ISO)"] != "GB" {
		t.Fatalf("location hint should resolve the region: %+v", fs)
	}
}
