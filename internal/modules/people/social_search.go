package people

import (
	"context"
	"strings"

	"github.com/sudosoc/rectool/internal/geo"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
)

// blueskySearch looks people up by name among Bluesky's public profiles.
func blueskySearch(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
	if len(strings.Fields(t.FullName)) < 2 {
		return
	}
	var r struct {
		Actors []struct {
			Handle      string `json:"handle"`
			DisplayName string `json:"displayName"`
			Description string `json:"description"`
			Avatar      string `json:"avatar"`
		} `json:"actors"`
	}
	if !getJSON(ctx, c, "https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors?limit=15&q="+esc(t.FullName), nil, &r) {
		return
	}
	n := 0
	for _, a := range r.Actors {
		if !nameMatches(a.DisplayName, t.FullName) || n >= 4 {
			continue
		}
		n++
		rec := models.Record{Platform: "Bluesky", URL: "https://bsky.app/profile/" + a.Handle, Name: a.DisplayName, Bio: clip(a.Description, 400),
			Photo: a.Avatar, Usernames: []string{"bluesky:" + a.Handle}, Self: true}
		if ps := geo.PlacesInText(a.Description); len(ps) > 0 {
			rec.Location = ps[0]
		}
		emit(finding("Bluesky profile search", "person", 0.45, rec, t))
	}
}

// mastodonSearch looks people up by name on a large Mastodon server. Profile
// metadata fields often hold a website or place the person added themself.
func mastodonSearch(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
	if len(strings.Fields(t.FullName)) < 2 {
		return
	}
	var r struct {
		Accounts []struct {
			URL     string `json:"url"`
			Acct    string `json:"acct"`
			Display string `json:"display_name"`
			Note    string `json:"note"`
			Avatar  string `json:"avatar"`
			Fields  []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"fields"`
			Bot bool `json:"bot"`
		} `json:"accounts"`
	}
	if !getJSON(ctx, c, "https://mastodon.social/api/v2/search?type=accounts&limit=10&q="+esc(t.FullName), nil, &r) {
		return
	}
	n := 0
	for _, a := range r.Accounts {
		if a.Bot || !nameMatches(a.Display, t.FullName) || n >= 4 {
			continue
		}
		n++
		rec := models.Record{Platform: "Mastodon", URL: a.URL, Name: a.Display, Bio: clip(stripHTML(a.Note), 400), Photo: a.Avatar,
			Usernames: []string{"mastodon:" + a.Acct}, Self: true}
		for _, f := range a.Fields {
			v := stripHTML(f.Value)
			k := strings.ToLower(f.Name)
			switch {
			case strings.Contains(k, "location") || strings.Contains(k, "city") || strings.Contains(k, "based") || strings.Contains(k, "from"):
				if rec.Location == "" {
					rec.Location = v
				}
			case strings.HasPrefix(v, "http"):
				rec.Websites = append(rec.Websites, v)
			}
		}
		if rec.Location == "" {
			if ps := geo.PlacesInText(rec.Bio); len(ps) > 0 {
				rec.Location = ps[0]
			}
		}
		emit(finding("Mastodon profile search", "person", 0.45, rec, t))
	}
}
