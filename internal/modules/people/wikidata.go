package people

import (
	"context"
	"net/url"
	"strings"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
)

// wikidata reads structured facts about notable people: occupation,
// employer, education, residence/birthplace, official website, and the
// IDs they hold on other platforms (ORCID, GitHub, X, Instagram…). Those IDs
// are *verified cross-links*, which lets identity resolution join records
// across platforms without guessing.
func wikidata(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
	var sr struct {
		Search []struct {
			ID          string `json:"id"`
			Label       string `json:"label"`
			Description string `json:"description"`
		} `json:"search"`
	}
	if !getJSON(ctx, c, "https://www.wikidata.org/w/api.php?action=wbsearchentities&language=en&format=json&limit=8&type=item&search="+esc(t.FullName), nil, &sr) {
		return
	}
	var ids []string
	desc := map[string]string{}
	for _, s := range sr.Search {
		if nameMatches(s.Label, t.FullName) {
			ids = append(ids, s.ID)
			desc[s.ID] = s.Description
		}
		if len(ids) >= 4 {
			break
		}
	}
	if len(ids) == 0 {
		return
	}
	var ent struct {
		Entities map[string]struct {
			Claims map[string][]struct {
				Mainsnak struct {
					Datavalue struct {
						Value any `json:"value"`
					} `json:"datavalue"`
				} `json:"mainsnak"`
			} `json:"claims"`
			Labels map[string]struct {
				Value string `json:"value"`
			} `json:"labels"`
		} `json:"entities"`
	}
	if !getJSON(ctx, c, "https://www.wikidata.org/w/api.php?action=wbgetentities&format=json&props=claims%7Clabels&languages=en&ids="+strings.Join(ids, "%7C"), nil, &ent) {
		return
	}

	claimItems := func(q string, p string) []string {
		var out []string
		for _, cl := range ent.Entities[q].Claims[p] {
			if m, ok := cl.Mainsnak.Datavalue.Value.(map[string]any); ok {
				if id := jstr(m["id"]); id != "" {
					out = append(out, id)
				}
			}
		}
		return out
	}
	claimStrings := func(q, p string) []string {
		var out []string
		for _, cl := range ent.Entities[q].Claims[p] {
			if s, ok := cl.Mainsnak.Datavalue.Value.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}

	// resolve every referenced item to its English label in one call
	need := map[string]bool{}
	for _, q := range ids {
		for _, p := range []string{"P106", "P108", "P69", "P19", "P551", "P937", "P27"} {
			for _, v := range claimItems(q, p) {
				need[v] = true
			}
		}
	}
	labels := map[string]string{}
	if len(need) > 0 {
		var list []string
		for k := range need {
			list = append(list, k)
			if len(list) >= 50 {
				break
			}
		}
		var lr struct {
			Entities map[string]struct {
				Labels map[string]struct {
					Value string `json:"value"`
				} `json:"labels"`
			} `json:"entities"`
		}
		if getJSON(ctx, c, "https://www.wikidata.org/w/api.php?action=wbgetentities&format=json&props=labels&languages=en&ids="+strings.Join(list, "%7C"), nil, &lr) {
			for k, v := range lr.Entities {
				labels[k] = v.Labels["en"].Value
			}
		}
	}
	lab := func(ids []string) []string {
		var out []string
		for _, id := range ids {
			if l := labels[id]; l != "" {
				out = appendUniq(out, l)
			}
		}
		return out
	}

	for _, q := range ids {
		isHuman := false
		for _, v := range claimItems(q, "P31") {
			if v == "Q5" {
				isHuman = true
			}
		}
		if !isHuman {
			continue
		}
		e := ent.Entities[q]
		rec := models.Record{Platform: "Wikidata", URL: "https://www.wikidata.org/wiki/" + q, Name: e.Labels["en"].Value,
			Headline: desc[q], Roles: lab(claimItems(q, "P106")), Employers: lab(claimItems(q, "P108")),
			Education: lab(claimItems(q, "P69")), IDs: map[string]string{"wikidata": q}}
		born := lab(claimItems(q, "P19"))
		home := append(lab(claimItems(q, "P551")), lab(claimItems(q, "P937"))...)
		switch {
		case len(home) > 0:
			rec.Location = home[0]
		case len(born) > 0:
			rec.Location = born[0]
		}
		var bio []string
		if len(born) > 0 {
			bio = append(bio, "Born in "+born[0])
		}
		if c := lab(claimItems(q, "P27")); len(c) > 0 {
			bio = append(bio, "citizen of "+strings.Join(c, ", "))
		}
		rec.Bio = strings.Join(bio, "; ")
		rec.Websites = claimStrings(q, "P856")
		if v := claimStrings(q, "P496"); len(v) > 0 {
			rec.IDs["orcid"] = v[0]
		}
		if v := claimStrings(q, "P6634"); len(v) > 0 {
			rec.IDs["linkedin_numeric"] = v[0]
		}
		for _, x := range []struct{ prop, plat string }{{"P2002", "twitter"}, {"P2003", "instagram"}, {"P2037", "github"}, {"P2013", "facebook"}} {
			for _, h := range claimStrings(q, x.prop) {
				rec.Usernames = append(rec.Usernames, x.plat+":"+h)
			}
		}
		if img := claimStrings(q, "P18"); len(img) > 0 {
			rec.Photo = "https://commons.wikimedia.org/wiki/Special:FilePath/" + url.PathEscape(img[0]) + "?width=500"
		}
		emit(finding("Wikidata person", "identity", 0.8, rec, t))
	}
}
