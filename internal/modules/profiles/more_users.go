package profiles

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/extract"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
)

// Username enrichers for platforms that publish structured public profiles:
// developer communities, learning and coding-practice sites, gaming and
// forums. Each emits the real name, bio, location, picture and linked
// accounts the person put there.

func init() {
	enrichers = append(enrichers,
		enricher{"lobsters", lobsters},
		enricher{"duolingo", duolingo},
		enricher{"launchpad", launchpad},
		enricher{"hexpm", hexPM},
		enricher{"metacpan", metaCPAN},
		enricher{"kitsu", kitsu},
		enricher{"minecraft", minecraft},
		enricher{"leetcode", leetcode},
		enricher{"codewars", codewars},
		enricher{"matrix", matrix},
		enricher{"gitea", giteaCom},
		enricher{"commons", wikiCommons},
	)
}

func linkedFrom(links ...string) (accts []string, ents []models.Entity) {
	var clean []string
	for _, l := range links {
		if l = strings.TrimSpace(l); l != "" {
			clean = append(clean, l)
		}
	}
	for _, p := range extract.Social(clean) {
		accts = append(accts, p.Platform+": "+p.Handle)
		if x, ok := userEnt(p.Handle, false); ok {
			ents = append(ents, x)
		}
	}
	for _, l := range clean {
		if x, ok := siteEnt(l, false); ok {
			ents = append(ents, x)
		}
	}
	return
}

func realName(d map[string]string, n string) {
	n = strings.TrimSpace(n)
	put(d, "display name", n)
	if strings.Contains(n, " ") && len(n) < 60 {
		put(d, "name", n)
	}
}

func nameEnt(d map[string]string, ents []models.Entity) []models.Entity {
	if n := d["name"]; n != "" {
		ents = append(ents, models.Entity{Type: models.EntName, Value: n})
	}
	return ents
}

// lobsters: a technical community with invite trees; profiles list the
// member's GitHub and Twitter and who invited them.
func lobsters(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Username  string `json:"username"`
		Created   string `json:"created_at"`
		About     string `json:"about"`
		Avatar    string `json:"avatar_url"`
		InvitedBy string `json:"invited_by_user"`
		GitHub    string `json:"github_username"`
		Twitter   string `json:"twitter_username"`
		Karma     int    `json:"karma"`
	}
	if !getJSON(ctx, c, "https://lobste.rs/~"+esc(user)+".json", &r) || r.Username == "" {
		return
	}
	d := map[string]string{"area": "community"}
	put(d, "about", r.About)
	put(d, "created", r.Created)
	put(d, "invited by", r.InvitedBy)
	if r.Avatar != "" {
		put(d, "avatar", "https://lobste.rs"+r.Avatar)
	}
	var accts []string
	var ents []models.Entity
	if r.GitHub != "" {
		accts = append(accts, "github: "+r.GitHub)
		if x, ok := userEnt(r.GitHub, false); ok {
			ents = append(ents, x)
		}
	}
	if r.Twitter != "" {
		accts = append(accts, "twitter: "+r.Twitter)
		if x, ok := userEnt(r.Twitter, false); ok {
			ents = append(ents, x)
		}
	}
	put(d, "linked accounts", strings.Join(accts, ", "))
	emit(profile("Lobsters profile", "https://lobste.rs/~"+esc(user), 0.6, d, ents...))
}

func duolingo(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Users []struct {
			Name     string `json:"name"`
			Username string `json:"username"`
			Bio      string `json:"bio"`
			Location string `json:"location"`
			Picture  string `json:"picture"`
			Streak   int    `json:"streak"`
			Courses  []struct {
				Title string `json:"title"`
			} `json:"courses"`
		} `json:"users"`
	}
	if !getJSON(ctx, c, "https://www.duolingo.com/2017-06-30/users?username="+url.QueryEscape(user), &r) || len(r.Users) == 0 {
		return
	}
	u := r.Users[0]
	d := map[string]string{"area": "learning"}
	realName(d, u.Name)
	put(d, "about", u.Bio)
	put(d, "location", u.Location)
	if u.Picture != "" && !strings.Contains(u.Picture, "default") {
		put(d, "avatar", "https:"+strings.TrimPrefix(u.Picture, "https:")+"/xlarge")
	}
	var langs []string
	for _, co := range u.Courses {
		langs = append(langs, co.Title)
		if len(langs) >= 8 {
			break
		}
	}
	put(d, "learning", strings.Join(langs, ", "))
	if u.Streak > 0 {
		d["streak (days)"] = fmt.Sprint(u.Streak)
	}
	emit(profile("Duolingo profile", "https://www.duolingo.com/profile/"+esc(user), 0.55, d, nameEnt(d, nil)...))
}

func launchpad(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Display  string `json:"display_name"`
		Name     string `json:"name"`
		Created  string `json:"date_created"`
		TimeZone string `json:"time_zone"`
		Home     string `json:"homepage_content"`
		IsTeam   bool   `json:"is_team"`
		Link     string `json:"web_link"`
		Karma    int    `json:"karma"`
	}
	if !getJSON(ctx, c, "https://api.launchpad.net/1.0/~"+esc(user), &r) || r.Name == "" || r.IsTeam {
		return
	}
	d := map[string]string{"area": "open source"}
	realName(d, r.Display)
	put(d, "created", r.Created)
	put(d, "time zone", r.TimeZone)
	put(d, "about", r.Home)
	if r.Karma > 0 {
		d["karma"] = fmt.Sprint(r.Karma)
	}
	emit(profile("Launchpad profile", firstNonEmpty(r.Link, "https://launchpad.net/~"+esc(user)), 0.55, d, nameEnt(d, nil)...))
}

// hexPM lists the e-mail an Elixir/Erlang package author publishes and the
// accounts they link.
func hexPM(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Username string            `json:"username"`
		Email    string            `json:"email"`
		Name     string            `json:"full_name"`
		Handles  map[string]string `json:"handles"`
		Inserted string            `json:"inserted_at"`
		URL      string            `json:"url"`
	}
	if !getJSON(ctx, c, "https://hex.pm/api/users/"+esc(user), &r) || r.Username == "" {
		return
	}
	d := map[string]string{"area": "open source"}
	realName(d, r.Name)
	put(d, "created", r.Inserted)
	var ents []models.Entity
	if x, ok := emailEnt(r.Email, false); ok {
		put(d, "e-mail", x.Value)
		ents = append(ents, x)
	}
	var accts []string
	for k, v := range r.Handles {
		if v = strings.TrimSpace(v); v != "" {
			accts = append(accts, k+": "+v)
			if x, ok := userEnt(v, false); ok {
				ents = append(ents, x)
			}
		}
	}
	put(d, "linked accounts", strings.Join(accts, ", "))
	emit(profile("Hex.pm profile", "https://hex.pm/users/"+esc(user), 0.55, d, nameEnt(d, ents)...))
}

// metaCPAN: Perl authors publish name, city, country, website and e-mail.
func metaCPAN(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Name     string   `json:"name"`
		City     string   `json:"city"`
		Region   string   `json:"region"`
		Country  string   `json:"country"`
		Website  []string `json:"website"`
		Email    any      `json:"email"`
		Gravatar string   `json:"gravatar_url"`
		Profile  []struct {
			Name string `json:"name"`
			ID   string `json:"id"`
		} `json:"profile"`
	}
	if !getJSON(ctx, c, "https://fastapi.metacpan.org/v1/author/"+esc(strings.ToUpper(user)), &r) || r.Name == "" {
		return
	}
	d := map[string]string{"area": "open source"}
	realName(d, r.Name)
	put(d, "location", strings.Join(nonEmpty(r.City, r.Region, strings.ToUpper(r.Country)), ", "))
	put(d, "avatar", r.Gravatar)
	var ents []models.Entity
	for _, e := range emailList(r.Email) {
		if x, ok := emailEnt(e, false); ok {
			ents = append(ents, x)
			put(d, "e-mail", x.Value)
		}
	}
	var links []string
	links = append(links, r.Website...)
	var accts []string
	for _, p := range r.Profile {
		accts = append(accts, p.Name+": "+p.ID)
		if x, ok := userEnt(p.ID, false); ok {
			ents = append(ents, x)
		}
	}
	a2, e2 := linkedFrom(links...)
	accts = append(accts, a2...)
	ents = append(ents, e2...)
	put(d, "websites", strings.Join(links, ", "))
	put(d, "linked accounts", strings.Join(accts, ", "))
	emit(profile("MetaCPAN author", "https://metacpan.org/author/"+esc(strings.ToUpper(user)), 0.6, d, nameEnt(d, ents)...))
}

func nonEmpty(v ...string) []string {
	var out []string
	for _, s := range v {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func emailList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func kitsu(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Data []struct {
			Attributes struct {
				Name     string `json:"name"`
				About    string `json:"about"`
				Location string `json:"location"`
				Birthday string `json:"birthday"`
				Created  string `json:"createdAt"`
				Avatar   struct {
					Original string `json:"original"`
				} `json:"avatar"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if !getJSON(ctx, c, "https://kitsu.io/api/edge/users?filter%5Bname%5D="+url.QueryEscape(user)+"&page%5Blimit%5D=1", &r) || len(r.Data) == 0 {
		return
	}
	a := r.Data[0].Attributes
	if !strings.EqualFold(a.Name, user) {
		return
	}
	d := map[string]string{"area": "anime"}
	put(d, "about", a.About)
	put(d, "location", a.Location)
	put(d, "created", a.Created)
	put(d, "avatar", a.Avatar.Original)
	emit(profile("Kitsu profile", "https://kitsu.io/users/"+esc(user), 0.5, d))
}

func minecraft(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if !getJSON(ctx, c, "https://api.mojang.com/users/profiles/minecraft/"+esc(user), &r) || r.ID == "" {
		return
	}
	d := map[string]string{"area": "games", "uuid": r.ID, "name history": "https://namemc.com/profile/" + r.Name}
	put(d, "avatar", "https://mc-heads.net/avatar/"+r.ID+"/256")
	emit(profile("Minecraft account", "https://namemc.com/profile/"+esc(r.Name), 0.45, d))
}

func leetcode(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	body := `{"query":"query($u:String!){matchedUser(username:$u){username profile{realName countryName company school userAvatar aboutMe}}}","variables":{"u":` + jsonStr(user) + `}}`
	resp, err := c.Do(ctx, httpx.Request{URL: "https://leetcode.com/graphql", Method: "POST", Body: body, Timeout: 20 * time.Second,
		Headers: map[string]string{"Content-Type": "application/json", "Referer": "https://leetcode.com/"}})
	if err != nil || resp.StatusCode != 200 {
		return
	}
	var r struct {
		Data struct {
			User *struct {
				Username string `json:"username"`
				Profile  struct {
					RealName string `json:"realName"`
					Country  string `json:"countryName"`
					Company  string `json:"company"`
					School   string `json:"school"`
					Avatar   string `json:"userAvatar"`
					About    string `json:"aboutMe"`
				} `json:"profile"`
			} `json:"matchedUser"`
		} `json:"data"`
	}
	if json.Unmarshal(resp.Body, &r) != nil || r.Data.User == nil {
		return
	}
	p := r.Data.User.Profile
	d := map[string]string{"area": "coding practice"}
	realName(d, p.RealName)
	put(d, "location", p.Country)
	put(d, "company", p.Company)
	put(d, "school", p.School)
	put(d, "about", p.About)
	if !strings.Contains(p.Avatar, "default") {
		put(d, "avatar", p.Avatar)
	}
	var ents []models.Entity
	if p.Company != "" {
		ents = append(ents, models.Entity{Type: models.EntOrg, Value: p.Company})
	}
	emit(profile("LeetCode profile", "https://leetcode.com/u/"+esc(user)+"/", 0.55, d, nameEnt(d, ents)...))
}

func codewars(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Username string   `json:"username"`
		Name     string   `json:"name"`
		Clan     string   `json:"clan"`
		Skills   []string `json:"skills"`
		Honor    int      `json:"honor"`
	}
	if !getJSON(ctx, c, "https://www.codewars.com/api/v1/users/"+esc(user), &r) || r.Username == "" {
		return
	}
	d := map[string]string{"area": "coding practice"}
	realName(d, r.Name)
	put(d, "clan", r.Clan)
	put(d, "skills", strings.Join(r.Skills, ", "))
	if r.Honor > 0 {
		d["honor"] = fmt.Sprint(r.Honor)
	}
	emit(profile("Codewars profile", "https://www.codewars.com/users/"+esc(user), 0.5, d, nameEnt(d, nil)...))
}

func matrix(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Display string `json:"displayname"`
	}
	mxid := "@" + strings.ToLower(user) + ":matrix.org"
	if !getJSON(ctx, c, "https://matrix.org/_matrix/client/v3/profile/"+url.PathEscape(mxid), &r) || r.Display == "" {
		return
	}
	d := map[string]string{"area": "chat", "matrix id": mxid}
	realName(d, r.Display)
	emit(profile("Matrix profile", "https://matrix.to/#/"+mxid, 0.45, d, nameEnt(d, nil)...))
}

// giteaCom reads a profile on gitea.com (Codeberg is covered separately).
func giteaCom(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Login    string `json:"login"`
		Full     string `json:"full_name"`
		Email    string `json:"email"`
		Location string `json:"location"`
		Website  string `json:"website"`
		Desc     string `json:"description"`
		Avatar   string `json:"avatar_url"`
		Created  string `json:"created"`
	}
	if !getJSON(ctx, c, "https://gitea.com/api/v1/users/"+esc(user), &r) || r.Login == "" {
		return
	}
	d := map[string]string{"area": "open source"}
	realName(d, r.Full)
	put(d, "location", r.Location)
	put(d, "about", r.Desc)
	put(d, "created", r.Created)
	put(d, "website", r.Website)
	if !strings.Contains(r.Avatar, "identicon") {
		put(d, "avatar", r.Avatar)
	}
	var ents []models.Entity
	if x, ok := emailEnt(r.Email, false); ok && !strings.Contains(x.Value, "gitea") {
		put(d, "e-mail", x.Value)
		ents = append(ents, x)
	}
	if x, ok := siteEnt(r.Website, false); ok {
		ents = append(ents, x)
	}
	emit(profile("Gitea.com profile", "https://gitea.com/"+esc(user), 0.55, d, nameEnt(d, ents)...))
}

// wikiCommons shows whether the handle is an active Wikimedia contributor.
func wikiCommons(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Query struct {
			Users []struct {
				Name    string `json:"name"`
				Edits   int    `json:"editcount"`
				Reg     string `json:"registration"`
				Missing any    `json:"missing"`
			} `json:"users"`
		} `json:"query"`
	}
	if !getJSON(ctx, c, "https://commons.wikimedia.org/w/api.php?action=query&list=users&format=json&usprop=editcount%7Cregistration&ususers="+url.QueryEscape(user), &r) ||
		len(r.Query.Users) == 0 || r.Query.Users[0].Missing != nil || r.Query.Users[0].Edits < 5 {
		return
	}
	u := r.Query.Users[0]
	d := map[string]string{"area": "community", "edits": fmt.Sprint(u.Edits)}
	put(d, "registered", u.Reg)
	emit(profile("Wikimedia Commons user", "https://commons.wikimedia.org/wiki/User:"+esc(u.Name), 0.4, d))
}
