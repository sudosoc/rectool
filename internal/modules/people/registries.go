package people

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
)

// More public records that name people: research indexes (arXiv, Europe PMC,
// INSPIRE-HEP), the French company register (officers), MusicBrainz (artists)
// and the Stack Exchange network. All keyless. A name can match several
// people, so each result is a separate candidate for identity resolution.

func ua() map[string]string {
	return map[string]string{"User-Agent": "rectool/1.0 (+https://github.com/sudosoc/rectool)", "Accept": "application/json"}
}

func two(name string) bool { return len(strings.Fields(name)) >= 2 }

// arXiv lists preprints by authors of this name: subject areas and any
// affiliation the authors gave.
func arxiv(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
	if !two(t.FullName) {
		return
	}
	q := `au:"` + strings.ReplaceAll(t.FullName, " ", "+") + `"`
	resp, err := c.Do(ctx, httpx.Request{URL: "https://export.arxiv.org/api/query?max_results=25&search_query=" + strings.ReplaceAll(url.QueryEscape(q), "%2B", "+"), Timeout: 30 * time.Second})
	if err != nil || resp.StatusCode != 200 {
		return
	}
	var feed struct {
		Entries []struct {
			Title   string `xml:"title"`
			Authors []struct {
				Name string `xml:"name"`
				Aff  string `xml:"affiliation"`
			} `xml:"author"`
			Categories []struct {
				Term string `xml:"term,attr"`
			} `xml:"category"`
		} `xml:"entry"`
	}
	if xml.Unmarshal(resp.Body, &feed) != nil || len(feed.Entries) == 0 {
		return
	}
	name := ""
	cats := map[string]int{}
	affs := []string{}
	var titles []string
	papers := 0
	for _, e := range feed.Entries {
		hit := false
		for _, a := range e.Authors {
			if nameMatches(a.Name, t.FullName) {
				hit = true
				name = a.Name
				if a.Aff != "" {
					affs = appendUniq(affs, strings.TrimSpace(a.Aff))
				}
			}
		}
		if !hit {
			continue
		}
		papers++
		for _, c := range e.Categories {
			cats[c.Term]++
		}
		if len(titles) < 3 {
			titles = append(titles, strings.Join(strings.Fields(e.Title), " "))
		}
	}
	if papers == 0 {
		return
	}
	var interests []string
	for _, k := range topKeys(cats, 5) {
		interests = append(interests, "arXiv "+k)
	}
	rec := models.Record{Platform: "arXiv", URL: "https://arxiv.org/a/" + strings.ReplaceAll(strings.ToLower(t.FullName), " ", "_"), Name: name, Employers: affs, Interests: interests,
		Bio: fmt.Sprintf("%d preprint(s) under this name, e.g. %s", papers, strings.Join(titles, "; "))}
	emit(finding("arXiv authors", "person", 0.45, rec, t))
}

func topKeys(m map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	var l []kv
	for k, v := range m {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].v != l[j].v {
			return l[i].v > l[j].v
		}
		return l[i].k < l[j].k
	})
	var out []string
	for i, x := range l {
		if i >= n {
			break
		}
		out = append(out, x.k)
	}
	return out
}

// europePMC reads author lists of life-science papers: affiliations and ORCID
// iDs per author, grouped so different people with the same name stay apart.
func europePMC(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
	if !two(t.FullName) {
		return
	}
	var r struct {
		ResultList struct {
			Result []struct {
				Journal    string `json:"journalTitle"`
				AuthorList struct {
					Author []struct {
						FullName string `json:"fullName"`
						AuthorID struct {
							Type  string `json:"type"`
							Value string `json:"value"`
						} `json:"authorId"`
						Aff struct {
							List []struct {
								Affiliation string `json:"affiliation"`
							} `json:"authorAffiliation"`
						} `json:"authorAffiliationDetailsList"`
					} `json:"author"`
				} `json:"authorList"`
			} `json:"result"`
		} `json:"resultList"`
	}
	q := `AUTH:"` + t.FullName + `"`
	if !getJSON(ctx, c, "https://www.ebi.ac.uk/europepmc/webservices/rest/search?resultType=core&format=json&pageSize=40&query="+esc(q), ua(), &r) {
		return
	}
	type cand struct {
		name, orcid string
		affs, jrn   []string
		n           int
	}
	cands := map[string]*cand{}
	for _, res := range r.ResultList.Result {
		for _, a := range res.AuthorList.Author {
			if !nameMatches(a.FullName, t.FullName) {
				continue
			}
			aff := ""
			if len(a.Aff.List) > 0 {
				aff = strings.TrimSpace(a.Aff.List[0].Affiliation)
			}
			key := ""
			if strings.EqualFold(a.AuthorID.Type, "ORCID") {
				key = a.AuthorID.Value
			}
			if key == "" {
				key = "aff:" + strings.ToLower(aff)
			}
			cd := cands[key]
			if cd == nil {
				cd = &cand{name: a.FullName}
				if strings.HasPrefix(key, "0000") {
					cd.orcid = key
				}
				cands[key] = cd
			}
			cd.n++
			if aff != "" {
				cd.affs = appendUniq(cd.affs, clip(aff, 160))
			}
			if res.Journal != "" {
				cd.jrn = appendUniq(cd.jrn, res.Journal)
			}
		}
	}
	keys := make([]string, 0, len(cands))
	for k := range cands {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	emitted := 0
	for _, k := range keys {
		cd := cands[k]
		if cd.orcid == "" && !affiliationHint(cd.affs, t) {
			continue // an anonymous author entry that agrees with nothing you gave
		}
		if emitted >= 5 {
			break
		}
		emitted++
		rec := models.Record{Platform: "Europe PMC", Name: cd.name, Employers: cd.affs, Interests: cd.jrn[:min(5, len(cd.jrn))], IDs: map[string]string{},
			Bio: fmt.Sprintf("%d life-science paper(s) under this author entry", cd.n)}
		if cd.orcid != "" {
			rec.IDs["orcid"] = cd.orcid
			rec.URL = "https://orcid.org/" + cd.orcid
		}
		emit(finding("Europe PMC authors", "person", 0.5, rec, t))
	}
}

// inspire reads the high-energy physics author index: positions held, ORCID.
func inspire(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
	if !two(t.FullName) {
		return
	}
	var r struct {
		Hits struct {
			Hits []struct {
				Meta struct {
					Name struct {
						Value string `json:"value"`
					} `json:"name"`
					Positions []struct {
						Institution string `json:"institution"`
						Rank        string `json:"rank"`
						Current     bool   `json:"current"`
					} `json:"positions"`
					IDs []struct {
						Schema string `json:"schema"`
						Value  string `json:"value"`
					} `json:"ids"`
					URLs []struct {
						Value string `json:"value"`
					} `json:"urls"`
				} `json:"metadata"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if !getJSON(ctx, c, "https://inspirehep.net/api/authors?size=6&fields=name,positions,ids,urls&q="+esc(t.FullName), ua(), &r) {
		return
	}
	for _, h := range r.Hits.Hits {
		m := h.Meta
		// INSPIRE stores "Last, First"
		nm := m.Name.Value
		if i := strings.Index(nm, ","); i > 0 {
			nm = strings.TrimSpace(nm[i+1:]) + " " + strings.TrimSpace(nm[:i])
		}
		if !nameMatches(nm, t.FullName) {
			continue
		}
		rec := models.Record{Platform: "INSPIRE-HEP", Name: nm, IDs: map[string]string{}}
		for _, p := range m.Positions {
			if p.Institution == "" {
				continue
			}
			if p.Current {
				rec.Employers = appendUniq(rec.Employers, p.Institution)
				if p.Rank != "" {
					rec.Roles = appendUniq(rec.Roles, p.Rank+" at "+p.Institution)
				}
			} else {
				rec.Employers = appendUniq(rec.Employers, p.Institution)
			}
		}
		for _, id := range m.IDs {
			switch strings.ToUpper(id.Schema) {
			case "ORCID":
				rec.IDs["orcid"] = id.Value
				rec.URL = "https://orcid.org/" + id.Value
			case "INSPIRE BAI":
				rec.IDs["inspire"] = id.Value
			}
		}
		for _, u := range m.URLs {
			rec.Websites = appendUniq(rec.Websites, u.Value)
		}
		if rec.URL == "" {
			rec.URL = "https://inspirehep.net/authors?q=" + esc(t.FullName)
		}
		emit(finding("INSPIRE-HEP author", "person", 0.55, rec, t))
	}
}

// franceCompanies searches the official French company register: people who
// are officers (dirigeants) of French companies appear by name with their role.
func franceCompanies(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
	if !two(t.FullName) {
		return
	}
	var r struct {
		Results []struct {
			Siren string `json:"siren"`
			Name  string `json:"nom_complet"`
			Siege struct {
				Commune string `json:"libelle_commune"`
				Dept    string `json:"departement"`
			} `json:"siege"`
			Dirigeants []struct {
				Nom     string `json:"nom"`
				Prenoms string `json:"prenoms"`
				Qualite string `json:"qualite"`
				Type    string `json:"type_dirigeant"`
			} `json:"dirigeants"`
		} `json:"results"`
	}
	if !getJSON(ctx, c, "https://recherche-entreprises.api.gouv.fr/search?per_page=25&q="+esc(t.FullName), ua(), &r) {
		return
	}
	n := 0
	for _, co := range r.Results {
		for _, d := range co.Dirigeants {
			if !strings.Contains(strings.ToLower(d.Type), "physique") {
				continue
			}
			first := strings.Fields(d.Prenoms)
			if len(first) == 0 {
				continue
			}
			full := first[0] + " " + d.Nom
			if !nameMatches(full, t.FullName) || n >= 5 {
				continue
			}
			n++
			rec := models.Record{Platform: "French company register", URL: "https://annuaire-entreprises.data.gouv.fr/entreprise/" + co.Siren, Name: strings.Title(strings.ToLower(full)),
				Employers: []string{co.Name}, Roles: []string{d.Qualite + " of " + co.Name}, Headline: d.Qualite,
				Location: strings.Join(nonEmptyS(co.Siege.Commune, co.Siege.Dept), ", ") + ", France"}
			emit(finding("French company register officer", "person", 0.5, rec, t))
		}
	}
}

func nonEmptyS(v ...string) []string {
	var out []string
	for _, s := range v {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// musicBrainz lists people recorded as artists with the name: country, area and
// a short disambiguation.
func musicBrainz(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
	if !two(t.FullName) {
		return
	}
	var r struct {
		Artists []struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Type  string `json:"type"`
			Score int    `json:"score"`
			Area  struct {
				Name string `json:"name"`
			} `json:"area"`
			Country string `json:"country"`
			Disamb  string `json:"disambiguation"`
			Life    struct {
				Begin string `json:"begin"`
			} `json:"life-span"`
		} `json:"artists"`
	}
	if !getJSON(ctx, c, "https://musicbrainz.org/ws/2/artist?fmt=json&limit=5&query=artist:%22"+esc(t.FullName)+"%22", ua(), &r) {
		return
	}
	n := 0
	for _, a := range r.Artists {
		if a.Type != "Person" || a.Score < 90 || !nameMatches(a.Name, t.FullName) || n >= 3 {
			continue
		}
		n++
		rec := models.Record{Platform: "MusicBrainz", URL: "https://musicbrainz.org/artist/" + a.ID, Name: a.Name, Headline: firstNonEmpty2(a.Disamb, "recorded artist"),
			Location: firstNonEmpty2(a.Area.Name, a.Country), IDs: map[string]string{"musicbrainz": a.ID}}
		emit(finding("MusicBrainz artist", "person", 0.4, rec, t))
	}
}

func firstNonEmpty2(v ...string) string {
	for _, s := range v {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}

// stackNetwork lists the other Stack Exchange communities a member is active
// in, which shows hobbies and professions the one profile hides.
func stackNetwork(ctx context.Context, c *httpx.Client, accountID int) []string {
	if accountID == 0 {
		return nil
	}
	var r struct {
		Items []struct {
			Site string `json:"site_name"`
			Rep  int    `json:"reputation"`
		} `json:"items"`
	}
	if !getJSON(ctx, c, "https://api.stackexchange.com/2.3/users/"+fmt.Sprint(accountID)+"/associated?pagesize=40", nil, &r) {
		return nil
	}
	var out []string
	for _, s := range r.Items {
		if s.Rep >= 100 && s.Site != "Stack Overflow" && s.Site != "Meta Stack Exchange" {
			out = append(out, s.Site)
		}
		if len(out) >= 8 {
			break
		}
	}
	return out
}
