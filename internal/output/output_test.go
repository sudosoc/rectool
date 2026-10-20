package output

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/sudosoc/rectool/internal/models"
)

func sample() *models.Report {
	return &models.Report{
		Tool: "rectool", Version: "t", StartedAt: time.Now(), FinishedAt: time.Now(),
		Target: models.Target{FullName: "Jane Roe", Email: "jane@example.com"},
		Entities: []models.Entity{{Type: models.EntEmail, Value: "jane@example.com", Strong: true, Source: "x"},
			{Type: models.EntDomain, Value: "example.com"}, {Type: models.EntUsername, Value: "jroe"}},
		Findings: []models.Finding{{Module: "people", Source: "ORCID", Category: "person", URL: "javascript:alert(1)", Status: models.StatusFound,
			Confidence: 0.8, Details: map[string]string{"name": "<script>alert(1)</script>"}}},
		Identities: []models.Identity{{ID: 1, Label: "Jane Roe", Score: 0.9, Primary: true,
			Emails: []models.Fact{{Value: "jane@example.com", Sources: []string{"Gravatar"}, Confirmed: true}},
			Docs:   []string{"javascript:alert(2)"}}},
	}
}

func TestAllFormats(t *testing.T) {
	r := sample()
	for _, f := range []string{"json", "csv", "txt", "html", "graphml", "stix", "entities"} {
		var b bytes.Buffer
		if err := Render(&b, r, f); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if b.Len() == 0 {
			t.Fatalf("%s empty", f)
		}
		switch f {
		case "graphml":
			if err := xml.Unmarshal(b.Bytes(), new(struct{ XMLName xml.Name })); err != nil {
				t.Fatalf("graphml not well-formed: %v", err)
			}
		case "stix":
			var v map[string]any
			if err := json.Unmarshal(b.Bytes(), &v); err != nil || v["type"] != "bundle" {
				t.Fatalf("stix invalid: %v", err)
			}
		case "html":
			h := b.String()
			if strings.Contains(h, "<script>alert") || strings.Contains(h, `href="javascript:`) {
				t.Fatal("html report is not escaped")
			}
			if !strings.Contains(h, "Jane Roe") {
				t.Fatal("identity missing")
			}
		}
	}
	if err := Render(&bytes.Buffer{}, r, "bogus"); err == nil {
		t.Fatal("unknown format accepted")
	}
}
