package company

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
)

// gleif queries the Global LEI Foundation registry: official legal-entity
// records (legal name, registered and headquarters address, jurisdiction,
// legal form, status, registration dates). Only entities that actually
// contain the company's name tokens are reported.
func gleif(ctx context.Context, c *httpx.Client, name string, tokens []string, emit func(models.Finding)) {
	var r struct {
		Meta struct {
			Pagination struct {
				Total int `json:"total"`
			} `json:"pagination"`
		} `json:"meta"`
		Data []struct {
			Attributes struct {
				LEI    string `json:"lei"`
				Entity struct {
					LegalName struct {
						Name string `json:"name"`
					} `json:"legalName"`
					LegalAddress gleifAddr `json:"legalAddress"`
					HQAddress    gleifAddr `json:"headquartersAddress"`
					Jurisdiction string    `json:"jurisdiction"`
					Category     string    `json:"category"`
					Status       string    `json:"status"`
					CreationDate string    `json:"creationDate"`
					RegisteredAs string    `json:"registeredAs"`
					LegalForm    struct {
						Other string `json:"other"`
						ID    string `json:"id"`
					} `json:"legalForm"`
					OtherNames []struct {
						Name string `json:"name"`
					} `json:"otherNames"`
				} `json:"entity"`
			} `json:"attributes"`
		} `json:"data"`
	}
	u := "https://api.gleif.org/api/v1/lei-records?page%5Bsize%5D=8&filter%5Bfulltext%5D=" + url.QueryEscape(name)
	if !getJSON(ctx, c, u, &r) {
		return
	}
	emitted := 0
	for _, rec := range r.Data {
		e := rec.Attributes.Entity
		legal := e.LegalName.Name
		low := strings.ToLower(legal)
		match := len(tokens) > 0
		for _, t := range tokens {
			if !strings.Contains(low, t) {
				match = false
			}
		}
		if !match || emitted >= 5 {
			continue
		}
		emitted++
		d := map[string]string{"LEI": rec.Attributes.LEI, "legal name": legal, "status": e.Status}
		put(d, "jurisdiction", e.Jurisdiction)
		put(d, "category", e.Category)
		put(d, "legal form", strings.TrimSpace(e.LegalForm.Other+" "+e.LegalForm.ID))
		put(d, "registered as (local ID)", e.RegisteredAs)
		put(d, "legal address", e.LegalAddress.String())
		put(d, "headquarters", e.HQAddress.String())
		put(d, "created", e.CreationDate)
		var others []string
		for _, o := range e.OtherNames {
			others = append(others, o.Name)
		}
		put(d, "other names", strings.Join(others, ", "))
		d["note"] = "official GLEIF record; several legal entities can share a brand name"
		var ents []models.Entity
		if loc := e.HQAddress.short(); loc != "" {
			ents = append(ents, models.Entity{Type: models.EntLocation, Value: loc})
		}
		emit(fnd("Legal entity: "+legal, "registry", "https://search.gleif.org/#/record/"+rec.Attributes.LEI, 0.8, d, ents...))
	}
	if emitted == 0 && r.Meta.Pagination.Total > 0 {
		emit(fnd("GLEIF registry", "registry", "", 0.3, map[string]string{
			"results": strconv.Itoa(r.Meta.Pagination.Total),
			"note":    "records exist but none contain every word of the name; try the exact legal name"}))
	}
}

type gleifAddr struct {
	AddressLines []string `json:"addressLines"`
	City         string   `json:"city"`
	Region       string   `json:"region"`
	Country      string   `json:"country"`
	PostalCode   string   `json:"postalCode"`
}

func (a gleifAddr) String() string {
	parts := append([]string(nil), a.AddressLines...)
	for _, p := range []string{a.City, a.Region, a.PostalCode, a.Country} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, ", ")
}

func (a gleifAddr) short() string {
	var parts []string
	for _, p := range []string{a.City, a.Country} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, ", ")
}
