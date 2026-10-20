package people

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
)

// openAlex returns researcher profiles with institutions and research topics
// (a good proxy for a person's professional interests).
func openAlex(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
	var r struct {
		Results []struct {
			ID           string `json:"id"`
			DisplayName  string `json:"display_name"`
			ORCID        string `json:"orcid"`
			WorksCount   int    `json:"works_count"`
			CitedByCount int    `json:"cited_by_count"`
			Institutions []struct {
				DisplayName string `json:"display_name"`
				CountryCode string `json:"country_code"`
			} `json:"last_known_institutions"`
			Topics []struct {
				DisplayName string `json:"display_name"`
			} `json:"topics"`
		} `json:"results"`
	}
	if !getJSON(ctx, c, "https://api.openalex.org/authors?per-page=10&search="+esc(t.FullName), nil, &r) {
		return
	}
	type cand struct {
		idx   int
		works int
	}
	var cands []cand
	for i, a := range r.Results {
		if nameMatches(a.DisplayName, t.FullName) {
			cands = append(cands, cand{i, a.WorksCount})
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].works > cands[j].works })
	for k, cd := range cands {
		if k >= 4 {
			break
		}
		a := r.Results[cd.idx]
		short := a.ID[strings.LastIndex(a.ID, "/")+1:]
		rec := models.Record{Platform: "OpenAlex", URL: a.ID, Name: a.DisplayName, IDs: map[string]string{"openalex": short},
			Bio: fmt.Sprintf("%d publications, %d citations", a.WorksCount, a.CitedByCount)}
		if o := strings.TrimPrefix(a.ORCID, "https://orcid.org/"); o != "" {
			rec.IDs["orcid"] = o
		}
		for _, in := range a.Institutions {
			rec.Employers = appendUniq(rec.Employers, in.DisplayName)
			if rec.Location == "" {
				rec.Location = in.CountryCode
			}
		}
		for i, tp := range a.Topics {
			if i >= 8 {
				break
			}
			rec.Interests = appendUniq(rec.Interests, tp.DisplayName)
		}
		emit(finding("OpenAlex author", "identity", 0.6, rec, t))
	}
}

// githubPeople finds GitHub users by full name (narrowed by the location when
// given) and reads each profile.
func githubPeople(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
	q := `"` + t.FullName + `" in:fullname`
	if t.Location != "" {
		q += ` location:"` + t.Location + `"`
	}
	var sr struct {
		Items []struct {
			Login string `json:"login"`
		} `json:"items"`
	}
	if !getJSON(ctx, c, "https://api.github.com/search/users?per_page=8&q="+esc(q), map[string]string{"Accept": "application/vnd.github+json"}, &sr) {
		return
	}
	for i, it := range sr.Items {
		if i >= 6 || ctx.Err() != nil {
			break
		}
		var u struct {
			Login    string `json:"login"`
			Name     string `json:"name"`
			Company  string `json:"company"`
			Blog     string `json:"blog"`
			Location string `json:"location"`
			Email    string `json:"email"`
			Bio      string `json:"bio"`
			Twitter  string `json:"twitter_username"`
			Avatar   string `json:"avatar_url"`
			HTMLURL  string `json:"html_url"`
		}
		if !getJSON(ctx, c, "https://api.github.com/users/"+esc(it.Login), map[string]string{"Accept": "application/vnd.github+json"}, &u) || !nameMatches(u.Name, t.FullName) {
			continue
		}
		rec := models.Record{Platform: "GitHub", URL: u.HTMLURL, Self: true, Name: u.Name, Location: u.Location,
			Bio: u.Bio, Photo: u.Avatar, Usernames: []string{"github:" + u.Login}}
		if co := strings.TrimPrefix(strings.TrimSpace(u.Company), "@"); co != "" {
			rec.Employers = []string{co}
		}
		if u.Blog != "" {
			rec.Websites = []string{u.Blog}
		}
		if u.Email != "" {
			rec.Emails = []string{strings.ToLower(u.Email)}
		}
		if u.Twitter != "" {
			rec.Usernames = append(rec.Usernames, "twitter:"+u.Twitter)
		}
		emit(finding("GitHub user named "+u.Name, "identity", 0.7, rec, t))
	}
}
