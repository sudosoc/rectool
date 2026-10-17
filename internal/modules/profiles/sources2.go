package profiles

import (
	"context"
	"encoding/xml"
	"strconv"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/extract"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
)

func init() {
	enrichers = append(enrichers,
		enricher{"gravatar", gravatarUser},
		enricher{"bluesky", bluesky},
		enricher{"wikipedia", wikipediaUser},
		enricher{"steam", steam},
		enricher{"codeforces", codeforces},
		enricher{"codeberg", codeberg},
		enricher{"huggingface", huggingFace},
		enricher{"cratesio", cratesIO},
		enricher{"telegram", telegram},
	)
}

func gravatarUser(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Entry []struct {
			DisplayName     string `json:"displayName"`
			AboutMe         string `json:"aboutMe"`
			CurrentLocation string `json:"currentLocation"`
			ProfileURL      string `json:"profileUrl"`
			ThumbnailURL    string `json:"thumbnailUrl"`
			Name            struct {
				Formatted string `json:"formatted"`
			} `json:"name"`
			URLs []struct {
				Value string `json:"value"`
			} `json:"urls"`
			Accounts []struct {
				Domain   string `json:"domain"`
				Username string `json:"username"`
				Verified string `json:"verified"`
			} `json:"accounts"`
		} `json:"entry"`
	}
	if !getJSON(ctx, c, "https://gravatar.com/"+esc(user)+".json", &r) || len(r.Entry) == 0 {
		return
	}
	e := r.Entry[0]
	d := map[string]string{}
	put(d, "display name", e.DisplayName)
	put(d, "name", e.Name.Formatted)
	put(d, "location", e.CurrentLocation)
	put(d, "about", e.AboutMe)
	if e.ThumbnailURL != "" {
		put(d, "avatar", e.ThumbnailURL+"?s=512")
	}
	var ents []models.Entity
	var acc, sites []string
	for _, a := range e.Accounts {
		acc = append(acc, a.Domain+": "+a.Username)
		if x, ok := userEnt(a.Username, a.Verified == "true"); ok {
			ents = append(ents, x)
		}
	}
	for _, u := range e.URLs {
		sites = append(sites, u.Value)
		if x, ok := siteEnt(u.Value, true); ok {
			ents = append(ents, x)
		}
	}
	put(d, "linked accounts", strings.Join(acc, ", "))
	put(d, "websites", strings.Join(sites, ", "))
	if strings.Contains(e.Name.Formatted, " ") {
		ents = append(ents, models.Entity{Type: models.EntName, Value: e.Name.Formatted})
	}
	emit(profile("Gravatar profile (by username)", e.ProfileURL, 0.85, d, ents...))
}

func bluesky(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	handle := user
	if !strings.Contains(handle, ".") {
		handle += ".bsky.social"
	}
	var r struct {
		Handle      string `json:"handle"`
		DisplayName string `json:"displayName"`
		Avatar      string `json:"avatar"`
		Description string `json:"description"`
		Followers   int    `json:"followersCount"`
		Follows     int    `json:"followsCount"`
		Posts       int    `json:"postsCount"`
		CreatedAt   string `json:"createdAt"`
	}
	if !getJSON(ctx, c, "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor="+esc(handle), &r) || r.Handle == "" {
		return
	}
	d := map[string]string{"followers": strconv.Itoa(r.Followers), "following": strconv.Itoa(r.Follows), "posts": strconv.Itoa(r.Posts)}
	put(d, "display name", r.DisplayName)
	put(d, "bio", r.Description)
	put(d, "created", r.CreatedAt)
	put(d, "avatar", r.Avatar)
	var ents []models.Entity
	for _, e := range emailsIn(r.Description) {
		ents = append(ents, models.Entity{Type: models.EntEmail, Value: e, Strong: true})
	}
	emit(profile("Bluesky profile", "https://bsky.app/profile/"+r.Handle, 0.85, d, ents...))
}

func wikipediaUser(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Query struct {
			Users []struct {
				Name         string   `json:"name"`
				EditCount    int      `json:"editcount"`
				Registration string   `json:"registration"`
				Groups       []string `json:"groups"`
				Missing      *string  `json:"missing"`
				Invalid      *string  `json:"invalid"`
			} `json:"users"`
		} `json:"query"`
	}
	if !getJSON(ctx, c, "https://en.wikipedia.org/w/api.php?action=query&list=users&format=json&usprop=registration%7Ceditcount%7Cgroups&ususers="+esc(user), &r) ||
		len(r.Query.Users) == 0 || r.Query.Users[0].Missing != nil || r.Query.Users[0].Invalid != nil {
		return
	}
	u := r.Query.Users[0]
	d := map[string]string{"edits": strconv.Itoa(u.EditCount), "registered": u.Registration}
	put(d, "groups", strings.Join(u.Groups, ", "))
	emit(profile("Wikipedia user", "https://en.wikipedia.org/wiki/User:"+esc(user), 0.75, d))
}

func steam(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	resp, err := c.Do(ctx, httpx.Request{URL: "https://steamcommunity.com/id/" + esc(user) + "/?xml=1", Timeout: 15 * time.Second})
	if err != nil || resp.StatusCode != 200 {
		return
	}
	var r struct {
		SteamID64   string `xml:"steamID64"`
		SteamID     string `xml:"steamID"`
		RealName    string `xml:"realname"`
		Location    string `xml:"location"`
		Summary     string `xml:"summary"`
		MemberSince string `xml:"memberSince"`
		AvatarFull  string `xml:"avatarFull"`
		Limited     string `xml:"isLimitedAccount"`
		Error       string `xml:"error"`
	}
	if xml.Unmarshal(resp.Body, &r) != nil || r.SteamID64 == "" || r.Error != "" {
		return
	}
	d := map[string]string{"steam id": r.SteamID64, "member since": r.MemberSince}
	put(d, "display name", r.SteamID)
	put(d, "real name", r.RealName)
	put(d, "location", r.Location)
	put(d, "summary", stripTags(r.Summary))
	put(d, "avatar", r.AvatarFull)
	var ents []models.Entity
	if strings.Contains(r.RealName, " ") {
		ents = append(ents, models.Entity{Type: models.EntName, Value: r.RealName})
	}
	for _, e := range emailsIn(stripTags(r.Summary)) {
		ents = append(ents, models.Entity{Type: models.EntEmail, Value: e, Strong: true})
	}
	emit(profile("Steam community profile", "https://steamcommunity.com/id/"+user, 0.85, d, ents...))
}

func codeforces(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Status string `json:"status"`
		Result []struct {
			Handle       string `json:"handle"`
			FirstName    string `json:"firstName"`
			LastName     string `json:"lastName"`
			Country      string `json:"country"`
			City         string `json:"city"`
			Organization string `json:"organization"`
			Rating       int    `json:"rating"`
			Rank         string `json:"rank"`
			Registered   int64  `json:"registrationTimeSeconds"`
			TitlePhoto   string `json:"titlePhoto"`
		} `json:"result"`
	}
	if !getJSON(ctx, c, "https://codeforces.com/api/user.info?handles="+esc(user), &r) || r.Status != "OK" || len(r.Result) == 0 {
		return
	}
	u := r.Result[0]
	d := map[string]string{"rating": strconv.Itoa(u.Rating), "registered": time.Unix(u.Registered, 0).UTC().Format("2006-01-02")}
	put(d, "name", strings.TrimSpace(u.FirstName+" "+u.LastName))
	put(d, "location", strings.TrimSpace(strings.Trim(u.City+", "+u.Country, ", ")))
	put(d, "company", u.Organization)
	put(d, "rank", u.Rank)
	if strings.HasPrefix(u.TitlePhoto, "//") {
		u.TitlePhoto = "https:" + u.TitlePhoto
	}
	put(d, "avatar", u.TitlePhoto)
	var ents []models.Entity
	if n := strings.TrimSpace(u.FirstName + " " + u.LastName); strings.Contains(n, " ") {
		ents = append(ents, models.Entity{Type: models.EntName, Value: n})
	}
	emit(profile("Codeforces profile", "https://codeforces.com/profile/"+u.Handle, 0.85, d, ents...))
}

func codeberg(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Login       string `json:"login"`
		FullName    string `json:"full_name"`
		Email       string `json:"email"`
		Location    string `json:"location"`
		Website     string `json:"website"`
		Description string `json:"description"`
		Created     string `json:"created"`
		Followers   int    `json:"followers_count"`
		HTMLURL     string `json:"html_url"`
		AvatarURL   string `json:"avatar_url"`
	}
	if !getJSON(ctx, c, "https://codeberg.org/api/v1/users/"+esc(user), &r) || r.Login == "" {
		return
	}
	d := map[string]string{"followers": strconv.Itoa(r.Followers)}
	put(d, "name", r.FullName)
	put(d, "location", r.Location)
	put(d, "website", r.Website)
	put(d, "bio", r.Description)
	put(d, "created", r.Created)
	put(d, "avatar", r.AvatarURL)
	put(d, "public email", r.Email)
	var ents []models.Entity
	if e, ok := emailEnt(r.Email, true); ok {
		ents = append(ents, e)
	}
	if e, ok := siteEnt(r.Website, true); ok {
		ents = append(ents, e)
	}
	if strings.Contains(r.FullName, " ") {
		ents = append(ents, models.Entity{Type: models.EntName, Value: r.FullName})
	}
	emit(profile("Codeberg profile", r.HTMLURL, 0.85, d, ents...))
}

func huggingFace(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		FullName  string `json:"fullname"`
		Name      string `json:"name"`
		IsPro     bool   `json:"isPro"`
		Created   string `json:"createdAt"`
		AvatarURL string `json:"avatarUrl"`
		Models    int    `json:"numModels"`
		Datasets  int    `json:"numDatasets"`
		Spaces    int    `json:"numSpaces"`
	}
	if !getJSON(ctx, c, "https://huggingface.co/api/users/"+esc(user)+"/overview", &r) || r.Name == "" {
		return
	}
	d := map[string]string{"models": strconv.Itoa(r.Models), "datasets": strconv.Itoa(r.Datasets), "spaces": strconv.Itoa(r.Spaces)}
	put(d, "name", r.FullName)
	put(d, "created", r.Created)
	put(d, "avatar", r.AvatarURL)
	var ents []models.Entity
	if strings.Contains(r.FullName, " ") {
		ents = append(ents, models.Entity{Type: models.EntName, Value: r.FullName})
	}
	emit(profile("Hugging Face profile", "https://huggingface.co/"+user, 0.8, d, ents...))
}

func cratesIO(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		User struct {
			Login string `json:"login"`
			Name  string `json:"name"`
			URL   string `json:"url"`
		} `json:"user"`
	}
	if !getJSON(ctx, c, "https://crates.io/api/v1/users/"+esc(user), &r) || r.User.Login == "" {
		return
	}
	d := map[string]string{}
	put(d, "name", r.User.Name)
	put(d, "profile", r.User.URL)
	var ents []models.Entity
	if strings.Contains(r.User.Name, " ") {
		ents = append(ents, models.Entity{Type: models.EntName, Value: r.User.Name})
	}
	emit(profile("crates.io user", "https://crates.io/users/"+user, 0.8, d, ents...))
}

// telegram reads the public preview page of a handle (t.me/<name>).
func telegram(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	resp, err := c.Do(ctx, httpx.Request{URL: "https://t.me/" + esc(user), Timeout: 15 * time.Second})
	if err != nil || resp.StatusCode != 200 {
		return
	}
	m := extract.ParseMeta(string(resp.Body))
	title := strings.TrimSpace(m.OGTitle)
	if title == "" || strings.HasPrefix(title, "Telegram: Contact") || strings.HasPrefix(title, "Telegram: Join") {
		return
	}
	d := map[string]string{"display name": title}
	put(d, "bio", m.Description)
	put(d, "avatar", m.OGImage)
	var ents []models.Entity
	for _, e := range emailsIn(m.Description) {
		ents = append(ents, models.Entity{Type: models.EntEmail, Value: e, Strong: true})
	}
	if strings.Contains(title, " ") {
		ents = append(ents, models.Entity{Type: models.EntName, Value: title})
	}
	emit(profile("Telegram public profile", "https://t.me/"+user, 0.7, d, ents...))
}
