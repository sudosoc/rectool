// Package people looks a full name up in public identity registries that need
// no key: Wikidata, ORCID (researchers), OpenAlex (authors) and GitHub user
// search. Names are ambiguous, so everything here is a low-confidence lead.
package people

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

// Scanner is the people module.
type Scanner struct{}

var _ scanner.Scanner = (*Scanner)(nil)

// New builds the module.
func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "people" }
func (s *Scanner) Description() string {
	return "full name in Wikidata, ORCID, OpenAlex and GitHub user search"
}
func (s *Scanner) CanRun(t models.Target) bool { return len(strings.Fields(t.FullName)) >= 2 }

func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	name := t.FullName
	jobs := []func(){
		func() { wikidata(ctx, d.HTTP, name, emit) },
		func() { orcid(ctx, d.HTTP, name, emit) },
		func() { openAlex(ctx, d.HTTP, name, emit) },
		func() { githubSearch(ctx, d.HTTP, name, t.Location, emit) },
	}
	var (
		wg   sync.WaitGroup
		done atomic.Int64
	)
	for _, j := range jobs {
		wg.Add(1)
		if err := d.Pool.Submit(ctx, func() {
			defer wg.Done()
			j()
			if d.Progress != nil {
				d.Progress(s.Name(), int(done.Add(1)), len(jobs))
			}
		}); err != nil {
			wg.Done()
			break
		}
	}
	wg.Wait()
	return ctx.Err()
}

func fnd(source, link string, conf float64, d map[string]string, ents ...models.Entity) models.Finding {
	return models.Finding{Source: source, Category: "identity", URL: link, Status: models.StatusFound,
		Confidence: conf, Details: d, Entities: ents}
}

func getJSON(ctx context.Context, c *httpx.Client, u string, hdr map[string]string, out any) bool {
	if hdr == nil {
		hdr = map[string]string{}
	}
	if hdr["Accept"] == "" {
		hdr["Accept"] = "application/json"
	}
	resp, err := c.Do(ctx, httpx.Request{URL: u, Timeout: 20 * time.Second, Headers: hdr})
	if err != nil || resp.StatusCode != 200 {
		return false
	}
	return json.Unmarshal(resp.Body, out) == nil
}

func wikidata(ctx context.Context, c *httpx.Client, name string, emit func(models.Finding)) {
	var r struct {
		Search []struct {
			ID          string `json:"id"`
			Label       string `json:"label"`
			Description string `json:"description"`
		} `json:"search"`
	}
	if !getJSON(ctx, c, "https://www.wikidata.org/w/api.php?action=wbsearchentities&language=en&format=json&limit=5&search="+url.QueryEscape(name), nil, &r) {
		return
	}
	for _, s := range r.Search {
		if !strings.EqualFold(s.Label, name) {
			continue
		}
		emit(fnd("Wikidata: "+s.Label, "https://www.wikidata.org/wiki/"+s.ID, 0.35, map[string]string{
			"description": s.Description, "id": s.ID,
			"note": "exact name match; common names collide, check the description",
		}))
	}
}

func orcid(ctx context.Context, c *httpx.Client, name string, emit func(models.Finding)) {
	parts := strings.Fields(name)
	given, family := parts[0], parts[len(parts)-1]
	var r struct {
		NumFound int `json:"num-found"`
		Result   []struct {
			ID struct {
				URI string `json:"uri"`
			} `json:"orcid-identifier"`
		} `json:"result"`
	}
	q := "given-names:" + given + " AND family-name:" + family
	if !getJSON(ctx, c, "https://pub.orcid.org/v3.0/expanded-search/?rows=5&q="+url.QueryEscape(q), nil, &r) {
		return
	}
	for _, x := range r.Result {
		emit(fnd("ORCID researcher record", x.ID.URI, 0.3, map[string]string{
			"matches for this name": strconv.Itoa(r.NumFound),
			"note":                  "name match only; open the record to check affiliation",
		}))
	}
}

func openAlex(ctx context.Context, c *httpx.Client, name string, emit func(models.Finding)) {
	var r struct {
		Results []struct {
			ID            string `json:"id"`
			DisplayName   string `json:"display_name"`
			WorksCount    int    `json:"works_count"`
			LastKnownInst []struct {
				DisplayName string `json:"display_name"`
				Country     string `json:"country_code"`
			} `json:"last_known_institutions"`
		} `json:"results"`
	}
	if !getJSON(ctx, c, "https://api.openalex.org/authors?per-page=3&search="+url.QueryEscape(name), nil, &r) {
		return
	}
	for _, a := range r.Results {
		if !strings.EqualFold(a.DisplayName, name) {
			continue
		}
		d := map[string]string{"works": strconv.Itoa(a.WorksCount), "note": "name match only"}
		var insts []string
		for _, i := range a.LastKnownInst {
			insts = append(insts, i.DisplayName+" ("+i.Country+")")
		}
		if len(insts) > 0 {
			d["last known institutions"] = strings.Join(insts, ", ")
		}
		emit(fnd("OpenAlex author: "+a.DisplayName, a.ID, 0.3, d))
	}
}

func githubSearch(ctx context.Context, c *httpx.Client, name, location string, emit func(models.Finding)) {
	q := `"` + name + `" in:fullname`
	if location != "" {
		q += ` location:"` + location + `"`
	}
	var r struct {
		Total int `json:"total_count"`
		Items []struct {
			Login   string `json:"login"`
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}
	if !getJSON(ctx, c, "https://api.github.com/search/users?per_page=5&q="+url.QueryEscape(q), nil, &r) || len(r.Items) == 0 {
		return
	}
	var logins []string
	var ents []models.Entity
	for _, it := range r.Items {
		logins = append(logins, it.Login)
		ents = append(ents, models.Entity{Type: models.EntUsername, Value: it.Login}) // weak: many people share a name
	}
	emit(fnd("GitHub users named "+name, "https://github.com/search?type=users&q="+url.QueryEscape(name), 0.3, map[string]string{
		"matches": strconv.Itoa(r.Total), "top logins": strings.Join(logins, ", "),
		"note": "full-name search; each login is only a candidate",
	}, ents...))
}
