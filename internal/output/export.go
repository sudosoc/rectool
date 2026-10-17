package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/models"
)

// Export writes the report in each requested format ("json", "csv", "txt")
// into dir and returns the created paths. Files are 0600: reports contain PII.
func Export(r *models.Report, dir, base string, formats []string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var paths []string
	for _, f := range formats {
		f = strings.ToLower(strings.TrimSpace(f))
		var (
			write func(io.Writer, *models.Report) error
		)
		switch f {
		case "json":
			write = writeJSON
		case "csv":
			write = writeCSV
		case "txt":
			write = writeTXT
		case "":
			continue
		default:
			return paths, fmt.Errorf("unknown format %q (json, csv, txt)", f)
		}
		p := filepath.Join(dir, base+"."+f)
		fh, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return paths, err
		}
		err = write(fh, r)
		if cerr := fh.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return paths, fmt.Errorf("%s: %w", p, err)
		}
		paths = append(paths, p)
	}
	return paths, nil
}

func writeJSON(w io.Writer, r *models.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func writeCSV(w io.Writer, r *models.Report) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"module", "source", "category", "url", "status", "confidence", "details", "timestamp"})
	for _, f := range r.Findings {
		details, _ := json.Marshal(f.Details)
		_ = cw.Write([]string{
			csvSafe(f.Module), csvSafe(f.Source), csvSafe(f.Category), csvSafe(f.URL),
			string(f.Status), fmt.Sprintf("%.2f", f.Confidence),
			csvSafe(string(details)), f.Timestamp.Format(time.RFC3339),
		})
	}
	cw.Flush()
	return cw.Error()
}

// csvSafe neutralises spreadsheet formula injection: scraped content is
// attacker-controlled and these files get opened in Excel.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func writeTXT(w io.Writer, r *models.Report) error {
	var b strings.Builder
	line := strings.Repeat("=", 64)
	fmt.Fprintf(&b, "%s\n %s v%s — reconnaissance report\n%s\n", line, r.Tool, r.Version, line)
	fmt.Fprintf(&b, "Started : %s\nFinished: %s\n", r.StartedAt.Format(time.RFC1123), r.FinishedAt.Format(time.RFC1123))
	if r.Interrupted {
		b.WriteString("NOTE    : run was interrupted; results are partial\n")
	}

	b.WriteString("\nTARGET\n")
	for _, kv := range [][2]string{
		{"Full name", r.Target.FullName}, {"Username", r.Target.Username}, {"Email", r.Target.Email},
		{"Phone", r.Target.Phone}, {"Domain", r.Target.Domain}, {"IP address", r.Target.IP},
		{"Company", r.Target.Company}, {"Location", r.Target.Location},
		{"Derived aliases", strings.Join(r.Target.Aliases, ", ")},
	} {
		if kv[1] != "" {
			fmt.Fprintf(&b, "  %-16s %s\n", kv[0]+":", kv[1])
		}
	}

	if len(r.Entities) > 0 {
		fmt.Fprintf(&b, "\nDISCOVERED ENTITIES (%d)\n", len(r.Entities))
		for _, e := range r.Entities {
			strong := " "
			if e.Strong {
				strong = "*"
			}
			fmt.Fprintf(&b, "  %s %-9s %-40s <- %s\n", strong, e.Type, e.Value, e.Source)
		}
		b.WriteString("  (* = strong lead, followed automatically)\n")
	}

	b.WriteString("\nMODULES\n")
	for _, m := range r.Modules {
		name := m.Name
		if m.Via != "" {
			name += " <- " + m.Via
		}
		fmt.Fprintf(&b, "  %-10s checked=%d found=%d errors=%d (%.1fs)", name, m.Checked, m.Found, m.Errors, float64(m.DurationMS)/1000)
		if m.Error != "" {
			fmt.Fprintf(&b, " ERROR: %s", m.Error)
		}
		b.WriteByte('\n')
	}

	byCat := map[string][]models.Finding{}
	for _, f := range r.Hits() {
		byCat[f.Module+"/"+orDefault(f.Category, "other")] = append(byCat[f.Module+"/"+orDefault(f.Category, "other")], f)
	}
	keys := make([]string, 0, len(byCat))
	for k := range byCat {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fmt.Fprintf(&b, "\nFINDINGS (%d)\n", len(r.Hits()))
	for _, k := range keys {
		fmt.Fprintf(&b, "\n  [%s]\n", k)
		for _, f := range byCat[k] {
			mark := "+"
			if f.Status != models.StatusFound {
				mark = "?"
			}
			fmt.Fprintf(&b, "   %s %s  (%.0f%%)\n", mark, f.Source, f.Confidence*100)
			if f.URL != "" {
				fmt.Fprintf(&b, "       %s\n", f.URL)
			}
			if f.Via != "" {
				fmt.Fprintf(&b, "       via %s\n", f.Via)
			}
			for _, l := range detailLines(f.Details, 0) {
				fmt.Fprintf(&b, "       %s\n", l)
			}
		}
	}
	if len(r.Failures) > 0 {
		fmt.Fprintf(&b, "\nCOVERAGE GAPS — %d checks could not be completed (absence of a result is NOT evidence of absence)\n", len(r.Failures))
		for i, f := range r.Failures {
			if i >= 60 {
				fmt.Fprintf(&b, "  … and %d more (see the JSON report)\n", len(r.Failures)-i)
				break
			}
			fmt.Fprintf(&b, "  - %s / %s: %s\n", f.Module, f.Source, f.Error)
		}
	}
	if len(r.Settings) > 0 {
		keys := make([]string, 0, len(r.Settings))
		for k := range r.Settings {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("\nRUN SETTINGS\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "  %-18s %s\n", k+":", r.Settings[k])
		}
	}
	if r.Integrity != nil {
		fmt.Fprintf(&b, "\nINTEGRITY  %s  %s\n  (digest of target + entities + findings; recompute from the JSON report to verify)\n", r.Integrity.Algorithm, r.Integrity.Digest)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// Render writes the report in one format ("json", "csv" or "txt") to w.
func Render(w io.Writer, r *models.Report, format string) error {
	switch strings.ToLower(format) {
	case "json":
		return writeJSON(w, r)
	case "csv":
		return writeCSV(w, r)
	case "txt":
		return writeTXT(w, r)
	}
	return fmt.Errorf("unknown format %q (json, csv, txt)", format)
}
