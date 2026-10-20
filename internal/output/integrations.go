package output

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/browser"
	"github.com/sudosoc/rectool/internal/models"
)

// writePDF prints the HTML report with the local Chrome / Chromium / Edge.
func writePDF(w io.Writer, r *models.Report) error {
	bin, err := browser.Find()
	if err != nil {
		return fmt.Errorf("pdf needs a local browser: %w (the html format can be printed to PDF by hand)", err)
	}
	dir, err := os.MkdirTemp("", "rectool-pdf-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	htmlPath, pdfPath := filepath.Join(dir, "report.html"), filepath.Join(dir, "report.pdf")
	fh, err := os.OpenFile(htmlPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	err = writeHTML(fh, r)
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := browser.PrintPDF(context.Background(), bin, htmlPath, pdfPath); err != nil {
		return err
	}
	data, err := os.ReadFile(pdfPath)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

type kv struct{ typ, val, source string }

// flatEntities lists the target's inputs plus every discovered entity.
func flatEntities(r *models.Report) []kv {
	var out []kv
	seen := map[string]bool{}
	add := func(t, v, s string) {
		if v = strings.TrimSpace(v); v == "" || seen[t+"\x00"+strings.ToLower(v)] {
			return
		}
		seen[t+"\x00"+strings.ToLower(v)] = true
		out = append(out, kv{t, v, s})
	}
	t := r.Target
	for _, p := range [][2]string{{models.EntName, t.FullName}, {models.EntUsername, t.Username}, {models.EntUsername, t.Alias}, {models.EntEmail, t.Email},
		{models.EntPhone, t.Phone}, {models.EntDomain, t.Domain}, {models.EntIP, t.IP}, {models.EntOrg, t.Company}, {models.EntLocation, t.Location}} {
		add(p[0], p[1], "input")
	}
	for _, e := range r.Entities {
		add(e.Type, e.Value, e.Source)
	}
	for _, id := range r.Identities {
		if id.Weak {
			continue
		}
		add(models.EntName, id.Label, "identity resolution")
		break
	}
	if g := r.Geo; g != nil && len(g.Clusters) > 0 {
		add(models.EntLocation, g.Clusters[0].Label, "location analysis")
	}
	return out
}

// writeMISP emits a MISP event (import with "Add event > Import from MISP format").
func writeMISP(w io.Writer, r *models.Report) error {
	type attr struct {
		Type     string `json:"type"`
		Category string `json:"category"`
		Value    string `json:"value"`
		Comment  string `json:"comment,omitempty"`
		ToIDS    bool   `json:"to_ids"`
	}
	var attrs []attr
	for _, e := range flatEntities(r) {
		a := attr{Value: e.val, Comment: "rectool: " + e.source, Category: "Other", Type: "text"}
		switch e.typ {
		case models.EntEmail:
			a.Type, a.Category = "email", "Social network"
		case models.EntDomain:
			a.Type, a.Category = "domain", "Network activity"
		case models.EntIP:
			a.Type, a.Category = "ip-dst", "Network activity"
		case models.EntURL, models.EntImage:
			a.Type, a.Category = "url", "Network activity"
		case models.EntPhone:
			a.Type, a.Category = "phone-number", "Social network"
		case models.EntUsername:
			a.Type, a.Category = "text", "Social network"
			a.Comment = "username; " + a.Comment
		case models.EntName:
			a.Type, a.Category = "text", "Person"
			a.Comment = "person name; " + a.Comment
		}
		attrs = append(attrs, a)
	}
	ev := map[string]any{"Event": map[string]any{
		"info": "rectool: " + strings.TrimSpace(r.Target.FullName+" "+r.Target.Username+" "+r.Target.Email+" "+r.Target.Domain),
		"date": r.StartedAt.Format("2006-01-02"), "threat_level_id": "4", "analysis": "0", "distribution": "0", "Attribute": attrs}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(ev)
}

// writeSpiderFoot emits SpiderFoot's CSV column layout so results can be
// compared with or loaded next to a SpiderFoot scan.
func writeSpiderFoot(w io.Writer, r *models.Report) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"Updated", "Type", "Module", "Source", "F/P", "Data"})
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	for _, e := range flatEntities(r) {
		t := map[string]string{models.EntEmail: "EMAILADDR", models.EntDomain: "DOMAIN_NAME", models.EntIP: "IP_ADDRESS", models.EntPhone: "PHONE_NUMBER",
			models.EntUsername: "USERNAME", models.EntName: "HUMAN_NAME", models.EntURL: "LINKED_URL_EXTERNAL", models.EntImage: "LINKED_URL_EXTERNAL",
			models.EntLocation: "GEOINFO", models.EntOrg: "COMPANY_NAME"}[e.typ]
		if t == "" {
			continue
		}
		_ = cw.Write([]string{now, t, "rectool", csvSafe(e.source), "0", csvSafe(e.val)})
	}
	cw.Flush()
	return cw.Error()
}

// writeMaltego emits a CSV for Maltego's "Import Graph from Table" wizard,
// with Maltego's entity type names in the first column.
func writeMaltego(w io.Writer, r *models.Report) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"Entity Type", "Value", "Notes"})
	for _, e := range flatEntities(r) {
		t := map[string]string{models.EntEmail: "maltego.EmailAddress", models.EntDomain: "maltego.Domain", models.EntIP: "maltego.IPv4Address",
			models.EntPhone: "maltego.PhoneNumber", models.EntUsername: "maltego.Alias", models.EntName: "maltego.Person", models.EntURL: "maltego.URL",
			models.EntImage: "maltego.Image", models.EntLocation: "maltego.Location", models.EntOrg: "maltego.Organization"}[e.typ]
		if t == "" {
			continue
		}
		_ = cw.Write([]string{t, csvSafe(e.val), csvSafe("found by " + e.source)})
	}
	cw.Flush()
	return cw.Error()
}
