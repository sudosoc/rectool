// Package breach reports which known data breaches an e-mail address appears
// in, using the public XposedOrNot index (no key). Only the breach names,
// dates and the kinds of data exposed are reported; never the data itself.
package breach

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

type Scanner struct{}

var _ scanner.Scanner = (*Scanner)(nil)

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "breach" }
func (s *Scanner) Description() string {
	return "known data breaches an e-mail address appears in (names, dates and data types only)"
}
func (s *Scanner) CanRun(t models.Target) bool { return strings.Contains(t.Email, "@") }

func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	email := strings.TrimSpace(t.Email)
	resp, err := d.HTTP.Do(ctx, httpx.Request{URL: "https://api.xposedornot.com/v1/check-email/" + url.PathEscape(email),
		Timeout: 25 * time.Second, Headers: map[string]string{"Accept": "application/json"}})
	if err != nil {
		emit(models.Finding{Source: "XposedOrNot", Category: "breach", Status: models.StatusError, Details: map[string]string{"error": err.Error()}})
		return nil
	}
	if resp.StatusCode == 404 {
		emit(models.Finding{Source: "XposedOrNot", Category: "breach", Status: models.StatusNotFound, Confidence: 0.7,
			Details: map[string]string{"result": "not found in the known breaches of this index (not proof the address was never exposed)"}})
		return nil
	}
	if resp.StatusCode != 200 {
		emit(models.Finding{Source: "XposedOrNot", Category: "breach", Status: models.StatusError, Details: map[string]string{"error": fmt.Sprintf("HTTP %d", resp.StatusCode)}})
		return nil
	}
	var r struct {
		Breaches [][]string `json:"breaches"`
	}
	if json.Unmarshal(resp.Body, &r) != nil || len(r.Breaches) == 0 || len(r.Breaches[0]) == 0 {
		return nil
	}
	names := r.Breaches[0]
	det := map[string]string{"breaches": fmt.Sprint(len(names)), "names": strings.Join(clip(names, 40), ", ")}
	if more := len(names) - 40; more > 0 {
		det["names"] += fmt.Sprintf(" … and %d more", more)
	}
	for k, v := range analytics(ctx, d.HTTP, email) {
		det[k] = v
	}
	det["note"] = "shows that the address appears in leaked datasets; the data itself is not retrieved. A hit does not mean the owner was careless"
	emit(models.Finding{Source: "XposedOrNot breach index", Category: "breach", Status: models.StatusFound, Confidence: 0.85, Details: det})
	return nil
}

func clip(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// analytics adds the years and data classes of the exposures when available.
func analytics(ctx context.Context, c *httpx.Client, email string) map[string]string {
	out := map[string]string{}
	resp, err := c.Do(ctx, httpx.Request{URL: "https://api.xposedornot.com/v1/breach-analytics?email=" + url.QueryEscape(email), Timeout: 25 * time.Second})
	if err != nil || resp.StatusCode != 200 {
		return out
	}
	var r struct {
		Exposed struct {
			Details []struct {
				Breach string `json:"breach"`
				Date   string `json:"xposed_date"`
				Data   string `json:"xposed_data"`
			} `json:"breaches_details"`
		} `json:"ExposedBreaches"`
	}
	if json.Unmarshal(resp.Body, &r) != nil {
		return out
	}
	years := map[string]bool{}
	classes := map[string]bool{}
	for _, b := range r.Exposed.Details {
		if len(b.Date) >= 4 {
			years[b.Date[:4]] = true
		}
		for _, c := range strings.Split(b.Data, ";") {
			if c = strings.TrimSpace(c); c != "" {
				classes[c] = true
			}
		}
	}
	if len(years) > 0 {
		out["years exposed"] = strings.Join(sorted(years), ", ")
	}
	if len(classes) > 0 {
		out["data types exposed"] = strings.Join(clip(sorted(classes), 25), ", ")
	}
	return out
}

func sorted(m map[string]bool) []string {
	var s []string
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}
