// Package bizreg queries official business registers that publish an open API
// without a key: the French register (company, address, activity, size and
// officers) and the Norwegian one (company, address, activity, staff). Results
// are for the company name given, so several similarly named companies may
// appear; check the number and address.
package bizreg

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

type Scanner struct{}

var _ scanner.Scanner = (*Scanner)(nil)

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "bizreg" }
func (s *Scanner) Description() string {
	return "official company registers with open APIs (France, Norway): number, address, activity, size, officers"
}
func (s *Scanner) CanRun(t models.Target) bool { return strings.TrimSpace(t.Company) != "" }

func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	var wg sync.WaitGroup
	for _, j := range []func(){
		func() { france(ctx, d.HTTP, t.Company, emit) },
		func() { norway(ctx, d.HTTP, t.Company, emit) },
	} {
		wg.Add(1)
		j := j
		if err := d.Pool.Submit(ctx, func() { defer wg.Done(); j() }); err != nil {
			wg.Done()
			break
		}
	}
	wg.Wait()
	return ctx.Err()
}

func getJSON(ctx context.Context, c *httpx.Client, u string, out any) bool {
	resp, err := c.Do(ctx, httpx.Request{URL: u, Timeout: 25 * time.Second, MaxBody: 4 << 20, Headers: map[string]string{"Accept": "application/json"}})
	if err != nil || resp.StatusCode != 200 {
		return false
	}
	return json.Unmarshal(resp.Body, out) == nil
}

func put(d map[string]string, k, v string) {
	if v = strings.TrimSpace(v); v != "" {
		d[k] = v
	}
}

func france(ctx context.Context, c *httpx.Client, name string, emit func(models.Finding)) {
	var r struct {
		Results []struct {
			Siren    string `json:"siren"`
			Name     string `json:"nom_complet"`
			Legal    string `json:"nature_juridique"`
			Created  string `json:"date_creation"`
			Activity string `json:"activite_principale"`
			Size     string `json:"tranche_effectif_salarie"`
			Siege    struct {
				Address string `json:"adresse"`
				Coords  string `json:"coordonnees"`
				Active  string `json:"etat_administratif"`
			} `json:"siege"`
			Dirigeants []struct {
				Nom     string `json:"nom"`
				Prenoms string `json:"prenoms"`
				Qualite string `json:"qualite"`
				Type    string `json:"type_dirigeant"`
				Denom   string `json:"denomination"`
			} `json:"dirigeants"`
		} `json:"results"`
	}
	if !getJSON(ctx, c, "https://recherche-entreprises.api.gouv.fr/search?per_page=5&q="+url.QueryEscape(name), &r) {
		return
	}
	for _, co := range r.Results {
		if !strings.Contains(strings.ToLower(co.Name), strings.ToLower(strings.Fields(name)[0])) {
			continue
		}
		d := map[string]string{"register": "France (recherche-entreprises)", "SIREN": co.Siren}
		put(d, "name", co.Name)
		put(d, "created", co.Created)
		put(d, "activity code (NAF)", co.Activity)
		put(d, "head office", co.Siege.Address)
		put(d, "status", map[string]string{"A": "active", "C": "ceased"}[co.Siege.Active])
		put(d, "staff band code", co.Size)
		var officers []string
		var ents []models.Entity
		for _, o := range co.Dirigeants {
			who := strings.TrimSpace(strings.Join(strings.Fields(o.Prenoms+" "+o.Nom), " "))
			if who == "" {
				who = o.Denom
			}
			if who != "" {
				officers = append(officers, fmt.Sprintf("%s (%s)", who, o.Qualite))
				if strings.Contains(strings.ToLower(o.Type), "physique") && strings.Contains(who, " ") {
					ents = append(ents, models.Entity{Type: models.EntName, Value: who})
				}
			}
			if len(officers) >= 12 {
				break
			}
		}
		put(d, "officers", strings.Join(officers, "; "))
		if co.Siege.Address != "" {
			ents = append(ents, models.Entity{Type: models.EntLocation, Value: co.Siege.Address})
		}
		emit(models.Finding{Source: "French register: " + co.Name, Category: "registry", URL: "https://annuaire-entreprises.data.gouv.fr/entreprise/" + co.Siren,
			Status: models.StatusFound, Confidence: 0.85, Details: d, Entities: ents})
	}
}

func norway(ctx context.Context, c *httpx.Client, name string, emit func(models.Finding)) {
	var r struct {
		Embedded struct {
			Units []struct {
				Name    string `json:"navn"`
				Number  string `json:"organisasjonsnummer"`
				Founded string `json:"stiftelsesdato"`
				Staff   int    `json:"antallAnsatte"`
				Site    string `json:"hjemmeside"`
				Form    struct {
					Desc string `json:"beskrivelse"`
				} `json:"organisasjonsform"`
				Industry struct {
					Desc string `json:"beskrivelse"`
				} `json:"naeringskode1"`
				Addr struct {
					Lines  []string `json:"adresse"`
					Postal string   `json:"postnummer"`
					Town   string   `json:"poststed"`
				} `json:"forretningsadresse"`
			} `json:"enheter"`
		} `json:"_embedded"`
	}
	if !getJSON(ctx, c, "https://data.brreg.no/enhetsregisteret/api/enheter?size=5&navn="+url.QueryEscape(name), &r) {
		return
	}
	for _, u := range r.Embedded.Units {
		if !strings.Contains(strings.ToLower(u.Name), strings.ToLower(strings.Fields(name)[0])) {
			continue
		}
		d := map[string]string{"register": "Norway (Brønnøysund)", "organisation number": u.Number}
		put(d, "name", u.Name)
		put(d, "legal form", u.Form.Desc)
		put(d, "industry", u.Industry.Desc)
		put(d, "founded", u.Founded)
		put(d, "website", u.Site)
		if u.Staff > 0 {
			d["employees"] = fmt.Sprint(u.Staff)
		}
		addr := strings.TrimSpace(strings.Join(append(append([]string{}, u.Addr.Lines...), u.Addr.Postal+" "+u.Addr.Town), ", "))
		put(d, "address", addr)
		var ents []models.Entity
		if addr != "" {
			ents = append(ents, models.Entity{Type: models.EntLocation, Value: u.Addr.Town + ", Norway"})
		}
		if site := strings.TrimPrefix(strings.TrimPrefix(u.Site, "https://"), "http://"); site != "" {
			ents = append(ents, models.Entity{Type: models.EntDomain, Value: strings.TrimPrefix(strings.Split(site, "/")[0], "www.")})
		}
		emit(models.Finding{Source: "Norwegian register: " + u.Name, Category: "registry", URL: "https://data.brreg.no/enhetsregisteret/oppslag/enheter/" + u.Number,
			Status: models.StatusFound, Confidence: 0.85, Details: d, Entities: ents})
	}
}
