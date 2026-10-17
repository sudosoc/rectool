package profiles

import (
	"context"
	"html"
	"strconv"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
)

func githubProfile(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Login, Name, Company, Blog, Location, Email, Bio string
		TwitterUsername                                  string `json:"twitter_username"`
		PublicRepos                                      int    `json:"public_repos"`
		PublicGists                                      int    `json:"public_gists"`
		Followers                                        int    `json:"followers"`
		Following                                        int    `json:"following"`
		CreatedAt                                        string `json:"created_at"`
		UpdatedAt                                        string `json:"updated_at"`
		Hireable                                         *bool  `json:"hireable"`
		HTMLURL                                          string `json:"html_url"`
		AvatarURL                                        string `json:"avatar_url"`
		Type                                             string `json:"type"`
	}
	if !getJSON(ctx, c, "https://api.github.com/users/"+esc(user), &r) || r.Login == "" {
		return
	}
	d := map[string]string{}
	put(d, "name", r.Name)
	put(d, "company", r.Company)
	put(d, "location", r.Location)
	put(d, "bio", r.Bio)
	put(d, "website", r.Blog)
	put(d, "public email", r.Email)
	put(d, "twitter", r.TwitterUsername)
	put(d, "account type", r.Type)
	put(d, "created", r.CreatedAt)
	put(d, "last active", r.UpdatedAt)
	d["public repos"] = strconv.Itoa(r.PublicRepos)
	d["followers"] = strconv.Itoa(r.Followers)
	d["following"] = strconv.Itoa(r.Following)
	put(d, "avatar", r.AvatarURL)

	var ents []models.Entity
	if e, ok := emailEnt(r.Email, true); ok {
		ents = append(ents, e)
	}
	if e, ok := siteEnt(r.Blog, true); ok {
		ents = append(ents, e)
	}
	if e, ok := userEnt(r.TwitterUsername, true); ok {
		ents = append(ents, e)
	}
	if r.Name != "" {
		ents = append(ents, models.Entity{Type: models.EntName, Value: r.Name})
	}
	emit(profile("GitHub profile", r.HTMLURL, 0.95, d, ents...))

	// SSH public keys are public and unique to a person's machines.
	if resp, err := c.Do(ctx, httpx.Request{URL: "https://github.com/" + esc(user) + ".keys", Timeout: 10 * time.Second}); err == nil && resp.StatusCode == 200 {
		if keys := strings.Fields(strings.TrimSpace(string(resp.Body))); len(keys) > 0 {
			n := strings.Count(string(resp.Body), "ssh-")
			if n > 0 {
				emit(profile("GitHub public SSH keys", "https://github.com/"+user+".keys", 0.9,
					map[string]string{"keys": strconv.Itoa(n), "note": "the same key on another service proves the same person"}))
			}
		}
	}
}

// githubCommits reads author identities from recent commits of the user's own
// repositories. Git stores the author's e-mail in every commit.
func githubCommits(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var repos []struct {
		Name string `json:"name"`
		Fork bool   `json:"fork"`
	}
	if !getJSON(ctx, c, "https://api.github.com/users/"+esc(user)+"/repos?sort=pushed&per_page=8&type=owner", &repos) {
		return
	}
	emails := map[string]string{}
	names := map[string]bool{}
	checked := 0
	for _, rp := range repos {
		if rp.Fork || checked >= 3 {
			continue
		}
		checked++
		var commits []struct {
			Commit struct {
				Author struct {
					Name  string `json:"name"`
					Email string `json:"email"`
				} `json:"author"`
			} `json:"commit"`
			Author struct {
				Login string `json:"login"`
			} `json:"author"`
		}
		if !getJSON(ctx, c, "https://api.github.com/repos/"+esc(user)+"/"+esc(rp.Name)+"/commits?author="+esc(user)+"&per_page=10", &commits) {
			continue
		}
		for _, cm := range commits {
			if !strings.EqualFold(cm.Author.Login, user) {
				continue
			}
			if e, ok := emailEnt(cm.Commit.Author.Email, true); ok {
				emails[e.Value] = rp.Name
			}
			if n := strings.TrimSpace(cm.Commit.Author.Name); n != "" {
				names[n] = true
			}
		}
	}
	if len(emails) == 0 && len(names) == 0 {
		return
	}
	d := map[string]string{"note": "git commit metadata of the user's own repositories"}
	var ents []models.Entity
	var el, nl []string
	for e, repo := range emails {
		el = append(el, e+" (in "+repo+")")
		ents = append(ents, models.Entity{Type: models.EntEmail, Value: e, Strong: true})
	}
	for n := range names {
		nl = append(nl, n)
		ents = append(ents, models.Entity{Type: models.EntName, Value: n})
	}
	put(d, "commit e-mails", strings.Join(el, ", "))
	put(d, "commit author names", strings.Join(nl, ", "))
	emit(profile("GitHub commit identities", "https://github.com/"+user, 0.9, d, ents...))
}

func keybase(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Them []*struct {
			Basics struct {
				Username string `json:"username"`
			} `json:"basics"`
			Pictures struct {
				Primary struct {
					URL string `json:"url"`
				} `json:"primary"`
			} `json:"pictures"`
			Profile struct {
				FullName string `json:"full_name"`
				Location string `json:"location"`
				Bio      string `json:"bio"`
			} `json:"profile"`
			Proofs struct {
				All []struct {
					ProofType  string `json:"proof_type"`
					Nametag    string `json:"nametag"`
					ServiceURL string `json:"service_url"`
				} `json:"all"`
			} `json:"proofs_summary"`
		} `json:"them"`
	}
	if !getJSON(ctx, c, "https://keybase.io/_/api/1.0/user/lookup.json?fields=basics,profile,pictures,proofs_summary&usernames="+esc(user), &r) ||
		len(r.Them) == 0 || r.Them[0] == nil {
		return
	}
	k := r.Them[0]
	d := map[string]string{}
	put(d, "full name", k.Profile.FullName)
	put(d, "location", k.Profile.Location)
	put(d, "bio", k.Profile.Bio)
	put(d, "avatar", k.Pictures.Primary.URL)
	var ents []models.Entity
	var proofs []string
	for _, p := range k.Proofs.All {
		proofs = append(proofs, p.ProofType+": "+p.Nametag)
		switch p.ProofType {
		case "dns", "generic_web_site":
			if e, ok := siteEnt(p.Nametag, true); ok {
				ents = append(ents, e)
			}
		case "twitter", "github", "reddit", "hackernews", "mastodon", "facebook":
			if e, ok := userEnt(strings.SplitN(p.Nametag, "@", 2)[0], true); ok {
				ents = append(ents, e)
			}
		}
	}
	put(d, "cryptographically verified accounts", strings.Join(proofs, ", "))
	if k.Profile.FullName != "" {
		ents = append(ents, models.Entity{Type: models.EntName, Value: k.Profile.FullName})
	}
	emit(profile("Keybase identity proofs", "https://keybase.io/"+user, 0.97, d, ents...))
}

func gitlab(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r []struct {
		ID        int    `json:"id"`
		Name      string `json:"name"`
		Username  string `json:"username"`
		State     string `json:"state"`
		WebURL    string `json:"web_url"`
		AvatarURL string `json:"avatar_url"`
	}
	if !getJSON(ctx, c, "https://gitlab.com/api/v4/users?username="+esc(user), &r) || len(r) == 0 {
		return
	}
	d := map[string]string{"state": r[0].State, "id": strconv.Itoa(r[0].ID)}
	put(d, "name", r[0].Name)
	put(d, "avatar", r[0].AvatarURL)
	var ents []models.Entity
	if r[0].Name != "" {
		ents = append(ents, models.Entity{Type: models.EntName, Value: r[0].Name})
	}
	emit(profile("GitLab profile", r[0].WebURL, 0.9, d, ents...))
}

// npm exposes maintainer e-mail addresses in package metadata.
func npm(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Total   int `json:"total"`
		Objects []struct {
			Package struct {
				Name      string `json:"name"`
				Publisher struct {
					Username string `json:"username"`
					Email    string `json:"email"`
				} `json:"publisher"`
				Maintainers []struct {
					Username string `json:"username"`
					Email    string `json:"email"`
				} `json:"maintainers"`
			} `json:"package"`
		} `json:"objects"`
	}
	if !getJSON(ctx, c, "https://registry.npmjs.org/-/v1/search?size=10&text=maintainer:"+esc(user), &r) || len(r.Objects) == 0 {
		return
	}
	emails := map[string]bool{}
	var pkgs []string
	for _, o := range r.Objects {
		pkgs = append(pkgs, o.Package.Name)
		if strings.EqualFold(o.Package.Publisher.Username, user) {
			emails[strings.ToLower(o.Package.Publisher.Email)] = true
		}
		for _, m := range o.Package.Maintainers {
			if strings.EqualFold(m.Username, user) {
				emails[strings.ToLower(m.Email)] = true
			}
		}
	}
	d := map[string]string{"packages (sample)": strings.Join(pkgs, ", "), "total packages": strconv.Itoa(r.Total)}
	var ents []models.Entity
	var el []string
	for e := range emails {
		if ent, ok := emailEnt(e, true); ok {
			el = append(el, ent.Value)
			ents = append(ents, ent)
		}
	}
	put(d, "maintainer e-mail", strings.Join(el, ", "))
	emit(profile("npm maintainer", "https://www.npmjs.com/~"+user, 0.9, d, ents...))
}

func hackerNews(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		ID      string `json:"id"`
		About   string `json:"about"`
		Karma   int    `json:"karma"`
		Created int64  `json:"created"`
	}
	if !getJSON(ctx, c, "https://hacker-news.firebaseio.com/v0/user/"+esc(user)+".json", &r) || r.ID == "" {
		return
	}
	d := map[string]string{"karma": strconv.Itoa(r.Karma),
		"created": time.Unix(r.Created, 0).UTC().Format("2006-01-02")}
	about := stripTags(r.About)
	put(d, "about", about)
	var ents []models.Entity
	for _, e := range emailsIn(about) {
		ents = append(ents, models.Entity{Type: models.EntEmail, Value: e, Strong: true})
	}
	emit(profile("Hacker News profile", "https://news.ycombinator.com/user?id="+user, 0.9, d, ents...))
}

func devTo(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Name, Summary, Location string
		GithubUsername          string `json:"github_username"`
		TwitterUsername         string `json:"twitter_username"`
		WebsiteURL              string `json:"website_url"`
		ProfileImage            string `json:"profile_image"`
		JoinedAt                string `json:"joined_at"`
		Username                string `json:"username"`
	}
	if !getJSON(ctx, c, "https://dev.to/api/users/by_username?url="+esc(user), &r) || r.Username == "" {
		return
	}
	d := map[string]string{}
	put(d, "name", r.Name)
	put(d, "summary", r.Summary)
	put(d, "location", r.Location)
	put(d, "website", r.WebsiteURL)
	put(d, "github", r.GithubUsername)
	put(d, "twitter", r.TwitterUsername)
	put(d, "joined", r.JoinedAt)
	put(d, "avatar", r.ProfileImage)
	var ents []models.Entity
	if e, ok := siteEnt(r.WebsiteURL, true); ok {
		ents = append(ents, e)
	}
	for _, u := range []string{r.GithubUsername, r.TwitterUsername} {
		if e, ok := userEnt(u, true); ok {
			ents = append(ents, e)
		}
	}
	emit(profile("DEV Community profile", "https://dev.to/"+user, 0.9, d, ents...))
}

func dockerHub(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Username    string `json:"username"`
		FullName    string `json:"full_name"`
		Location    string `json:"location"`
		Company     string `json:"company"`
		Type        string `json:"type"`
		DateJoined  string `json:"date_joined"`
		GravatarURL string `json:"gravatar_url"`
	}
	if !getJSON(ctx, c, "https://hub.docker.com/v2/users/"+esc(user)+"/", &r) || r.Username == "" {
		return
	}
	d := map[string]string{}
	put(d, "name", r.FullName)
	put(d, "location", r.Location)
	put(d, "company", r.Company)
	put(d, "joined", r.DateJoined)
	put(d, "type", r.Type)
	put(d, "avatar", r.GravatarURL)
	emit(profile("Docker Hub profile", "https://hub.docker.com/u/"+user, 0.85, d))
}

func mastodon(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		DisplayName string `json:"display_name"`
		Avatar      string `json:"avatar"`
		Note        string `json:"note"`
		URL         string `json:"url"`
		Followers   int    `json:"followers_count"`
		Statuses    int    `json:"statuses_count"`
		CreatedAt   string `json:"created_at"`
		Fields      []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"fields"`
	}
	if !getJSON(ctx, c, "https://mastodon.social/api/v1/accounts/lookup?acct="+esc(user), &r) || r.URL == "" {
		return
	}
	d := map[string]string{"followers": strconv.Itoa(r.Followers), "posts": strconv.Itoa(r.Statuses)}
	put(d, "display name", r.DisplayName)
	put(d, "bio", stripTags(r.Note))
	put(d, "avatar", r.Avatar)
	put(d, "created", r.CreatedAt)
	var ents []models.Entity
	for _, f := range r.Fields {
		v := stripTags(f.Value)
		put(d, "field: "+f.Name, v)
		if e, ok := siteEnt(v, true); ok {
			ents = append(ents, e)
		}
	}
	emit(profile("Mastodon (mastodon.social)", r.URL, 0.85, d, ents...))
}

func stackOverflow(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Items []struct {
			DisplayName  string `json:"display_name"`
			Location     string `json:"location"`
			WebsiteURL   string `json:"website_url"`
			Link         string `json:"link"`
			Reputation   int    `json:"reputation"`
			CreationDate int64  `json:"creation_date"`
			ProfileImage string `json:"profile_image"`
		} `json:"items"`
	}
	if !getJSON(ctx, c, "https://api.stackexchange.com/2.3/users?pagesize=5&site=stackoverflow&inname="+esc(user), &r) {
		return
	}
	for _, it := range r.Items {
		if !strings.EqualFold(it.DisplayName, user) {
			continue
		}
		d := map[string]string{"reputation": strconv.Itoa(it.Reputation),
			"member since": time.Unix(it.CreationDate, 0).UTC().Format("2006-01-02"),
			"note":         "matched by exact display name only; may be a different person"}
		put(d, "location", it.Location)
		put(d, "website", it.WebsiteURL)
		put(d, "avatar", it.ProfileImage)
		var ents []models.Entity
		if e, ok := siteEnt(it.WebsiteURL, false); ok {
			ents = append(ents, e)
		}
		emit(profile("Stack Overflow profile", it.Link, 0.5, d, ents...))
		return
	}
}

func lichess(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		ID, Username string
		Profile      struct {
			RealName string `json:"realName"`
			Location string `json:"location"`
			Bio      string `json:"bio"`
			Links    string `json:"links"`
			Country  string `json:"country"`
		} `json:"profile"`
		CreatedAt int64 `json:"createdAt"`
	}
	if !getJSON(ctx, c, "https://lichess.org/api/user/"+esc(user), &r) || r.ID == "" {
		return
	}
	d := map[string]string{"created": time.UnixMilli(r.CreatedAt).UTC().Format("2006-01-02")}
	put(d, "real name", r.Profile.RealName)
	put(d, "location", r.Profile.Location)
	put(d, "country", r.Profile.Country)
	put(d, "bio", r.Profile.Bio)
	put(d, "links", r.Profile.Links)
	var ents []models.Entity
	if r.Profile.RealName != "" {
		ents = append(ents, models.Entity{Type: models.EntName, Value: r.Profile.RealName})
	}
	emit(profile("Lichess profile", "https://lichess.org/@/"+user, 0.85, d, ents...))
}

func chessCom(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Name      string `json:"name"`
		Location  string `json:"location"`
		Country   string `json:"country"`
		URL       string `json:"url"`
		JoinedAt  int64  `json:"joined"`
		Followers int    `json:"followers"`
		Avatar    string `json:"avatar"`
	}
	if !getJSON(ctx, c, "https://api.chess.com/pub/player/"+esc(strings.ToLower(user)), &r) || r.URL == "" {
		return
	}
	d := map[string]string{"followers": strconv.Itoa(r.Followers),
		"joined": time.Unix(r.JoinedAt, 0).UTC().Format("2006-01-02")}
	put(d, "name", r.Name)
	put(d, "location", r.Location)
	put(d, "country", r.Country)
	put(d, "avatar", r.Avatar)
	var ents []models.Entity
	if r.Name != "" {
		ents = append(ents, models.Entity{Type: models.EntName, Value: r.Name})
	}
	emit(profile("Chess.com profile", r.URL, 0.85, d, ents...))
}

func reddit(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	var r struct {
		Data struct {
			Name         string  `json:"name"`
			Created      float64 `json:"created_utc"`
			LinkKarma    int     `json:"link_karma"`
			CommentKarma int     `json:"comment_karma"`
			IconImg      string  `json:"icon_img"`
			Subreddit    struct {
				PublicDescription string `json:"public_description"`
				Title             string `json:"title"`
			} `json:"subreddit"`
		} `json:"data"`
	}
	if !getJSON(ctx, c, "https://www.reddit.com/user/"+esc(user)+"/about.json", &r) || r.Data.Name == "" {
		return
	}
	d := map[string]string{"link karma": strconv.Itoa(r.Data.LinkKarma), "comment karma": strconv.Itoa(r.Data.CommentKarma),
		"created": time.Unix(int64(r.Data.Created), 0).UTC().Format("2006-01-02")}
	put(d, "bio", r.Data.Subreddit.PublicDescription)
	put(d, "display title", r.Data.Subreddit.Title)
	put(d, "avatar", html.UnescapeString(r.Data.IconImg))
	emit(profile("Reddit profile", "https://www.reddit.com/user/"+user, 0.85, d))
}
