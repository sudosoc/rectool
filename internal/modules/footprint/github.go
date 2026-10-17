package footprint

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
)

func ghJSON(ctx context.Context, c *httpx.Client, u string, out any) bool {
	resp, err := c.Do(ctx, httpx.Request{URL: u, Timeout: 20 * time.Second,
		Headers: map[string]string{"Accept": "application/vnd.github+json"}})
	if err != nil || resp.StatusCode != 200 {
		return false
	}
	return json.Unmarshal(resp.Body, out) == nil
}

// githubByEmail finds GitHub accounts that publish this address, and commits
// authored with it. Both tie the e-mail to a username with high confidence,
// which is the bridge from "an e-mail" to "a developer identity".
func githubByEmail(ctx context.Context, c *httpx.Client, email string, emit func(models.Finding)) {
	var users struct {
		Total int `json:"total_count"`
		Items []struct {
			Login   string `json:"login"`
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}
	if ghJSON(ctx, c, "https://api.github.com/search/users?per_page=3&q="+url.QueryEscape(email+" in:email"), &users) && len(users.Items) > 0 {
		// GitHub's e-mail search is fuzzy: confirm each hit really publishes
		// exactly this address before treating it as the owner's account.
		var logins []string
		var ents []models.Entity
		for _, u := range users.Items {
			var prof struct {
				Email string `json:"email"`
			}
			if !ghJSON(ctx, c, "https://api.github.com/users/"+url.PathEscape(u.Login), &prof) || !strings.EqualFold(prof.Email, email) {
				continue
			}
			logins = append(logins, u.Login)
			ents = append(ents, models.Entity{Type: models.EntUsername, Value: u.Login, Strong: true})
		}
		if len(logins) > 0 {
			emit(models.Finding{Source: "GitHub account publishing this e-mail", Category: "email-account",
				URL: "https://github.com/" + logins[0], Status: models.StatusFound, Confidence: 0.95,
				Details:  map[string]string{"logins": strings.Join(logins, ", "), "verified": "the profile's public e-mail equals the address"},
				Entities: ents})
		}
	}

	var commits struct {
		Total int `json:"total_count"`
		Items []struct {
			Commit struct {
				Author struct {
					Name string `json:"name"`
					Date string `json:"date"`
				} `json:"author"`
			} `json:"commit"`
			Author *struct {
				Login string `json:"login"`
			} `json:"author"`
			Repository struct {
				FullName string `json:"full_name"`
				HTMLURL  string `json:"html_url"`
			} `json:"repository"`
		} `json:"items"`
	}
	resp, err := c.Do(ctx, httpx.Request{
		URL:     "https://api.github.com/search/commits?per_page=5&q=" + url.QueryEscape("author-email:"+email),
		Timeout: 20 * time.Second,
		Headers: map[string]string{"Accept": "application/vnd.github+json"},
	})
	if err != nil || resp.StatusCode != 200 || json.Unmarshal(resp.Body, &commits) != nil || len(commits.Items) == 0 {
		return
	}
	names := map[string]bool{}
	logins := map[string]bool{}
	var repos []string
	var ents []models.Entity
	for _, it := range commits.Items {
		if n := strings.TrimSpace(it.Commit.Author.Name); n != "" && !names[n] {
			names[n] = true
			ents = append(ents, models.Entity{Type: models.EntName, Value: n})
		}
		if it.Author != nil && it.Author.Login != "" && !logins[it.Author.Login] {
			logins[it.Author.Login] = true
			ents = append(ents, models.Entity{Type: models.EntUsername, Value: it.Author.Login, Strong: true})
		}
		repos = append(repos, it.Repository.FullName)
	}
	d := map[string]string{"commits authored with this e-mail": strconv.Itoa(commits.Total),
		"repositories (sample)": strings.Join(repos, ", ")}
	var nl, ll []string
	for n := range names {
		nl = append(nl, n)
	}
	for l := range logins {
		ll = append(ll, l)
	}
	if len(nl) > 0 {
		d["author names used"] = strings.Join(nl, ", ")
	}
	if len(ll) > 0 {
		d["GitHub logins"] = strings.Join(ll, ", ")
	}
	emit(models.Finding{Source: "Git commits authored with this e-mail", Category: "email-account",
		URL: commits.Items[0].Repository.HTMLURL, Status: models.StatusFound, Confidence: 0.9, Details: d, Entities: ents})
}
