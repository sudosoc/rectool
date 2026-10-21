package profiles

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/extract"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
)

// More social and creative platforms. None offers a keyless API, but every
// public profile page carries the person's display name, bio and picture in
// its Open Graph tags, which is enough to tell people apart and to tie a
// handle to a real name. Link hubs (Linktree and similar) are more valuable
// still: a person lists their other accounts there themselves.

type ogSite struct {
	name, area, tmpl string
}

var ogSites = []ogSite{
	{"Medium", "writing", "https://medium.com/@%s"},
	{"Substack", "writing", "https://%s.substack.com/about"},
	{"Tumblr", "blogging", "https://%s.tumblr.com/"},
	{"Vimeo", "video", "https://vimeo.com/%s"},
	{"SoundCloud", "music", "https://soundcloud.com/%s"},
	{"Pinterest", "creative", "https://www.pinterest.com/%s/"},
	{"Behance", "creative", "https://www.behance.net/%s"},
	{"Dribbble", "creative", "https://dribbble.com/%s"},
	{"DeviantArt", "creative", "https://www.deviantart.com/%s"},
	{"Flickr", "photography", "https://www.flickr.com/people/%s/"},
	{"500px", "photography", "https://500px.com/p/%s"},
	{"Kaggle", "data science", "https://www.kaggle.com/%s"},
	{"Replit", "coding", "https://replit.com/@%s"},
	{"Itch.io", "games", "https://%s.itch.io/"},
	{"Goodreads", "books", "https://www.goodreads.com/%s"},
	{"Letterboxd", "film", "https://letterboxd.com/%s/"},
	{"Last.fm", "music", "https://www.last.fm/user/%s"},
	{"Bandcamp", "music", "https://%s.bandcamp.com/"},
	{"Twitch", "streaming", "https://www.twitch.tv/%s"},
	{"Product Hunt", "business", "https://www.producthunt.com/@%s"},
	{"AngelList", "business", "https://wellfound.com/u/%s"},
	{"Quora", "q&a", "https://www.quora.com/profile/%s"},
	{"Patreon", "creators", "https://www.patreon.com/%s"},
	{"Ko-fi", "creators", "https://ko-fi.com/%s"},
	{"Buy Me a Coffee", "creators", "https://www.buymeacoffee.com/%s"},
	{"Gumroad", "creators", "https://%s.gumroad.com/"},
	{"Etsy", "shop", "https://www.etsy.com/shop/%s"},
	{"Telegraph", "writing", "https://telegra.ph/%s"},
}

type hubSite struct{ name, tmpl string }

var hubSites = []hubSite{
	{"Linktree", "https://linktr.ee/%s"},
	{"Beacons", "https://beacons.ai/%s"},
	{"bio.link", "https://bio.link/%s"},
	{"lnk.bio", "https://lnk.bio/%s"},
	{"Solo.to", "https://solo.to/%s"},
	{"Carrd", "https://%s.carrd.co/"},
	{"about.me", "https://about.me/%s"},
	{"Linkin.bio", "https://linkin.bio/%s"},
	{"Campsite", "https://campsite.bio/%s"},
	{"Taplink", "https://taplink.cc/%s"},
	{"Allmylinks", "https://allmylinks.com/%s"},
	{"Linkpop", "https://linkpop.com/%s"},
	{"Milkshake", "https://%s.mlkshk.app/"},
}

func init() {
	for _, s := range ogSites {
		s := s
		enrichers = append(enrichers, enricher{strings.ToLower(s.name), func(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
			ogProfile(ctx, c, s, user, emit)
		}})
	}
	enrichers = append(enrichers, enricher{"linkhubs", linkHubs}, enricher{"hashnode", hashnode})
}

var notFoundTitle = regexp.MustCompile(`(?i)(not found|doesn.t exist|does not exist|no such|404|page unavailable|couldn.t find|available for registration|claim this)`)

// pageFor fetches a profile page and rejects the soft-404 patterns sites use
// for names that do not exist (redirect to the home page, generic titles).
func pageFor(ctx context.Context, c *httpx.Client, link, user string) (string, extract.Meta, string, bool) {
	resp, err := c.Do(ctx, httpx.Request{URL: link, Timeout: 20 * time.Second, MaxBody: 2 << 20,
		Headers: map[string]string{"Accept-Language": "en-US,en;q=0.9"}})
	if err != nil || resp.StatusCode != 200 {
		return "", extract.Meta{}, "", false
	}
	body := string(resp.Body)
	meta := extract.ParseMeta(body)
	title := firstNonEmpty(meta.OGTitle, meta.Title)
	if title == "" || notFoundTitle.MatchString(title) {
		return "", meta, "", false
	}
	// a real profile page mentions the handle; a generic landing page does not
	if !strings.Contains(strings.ToLower(body), strings.ToLower(user)) {
		return "", meta, "", false
	}
	// a redirect that dropped the username means the account does not exist
	if fu, err := url.Parse(resp.FinalURL); err == nil {
		if !strings.Contains(strings.ToLower(resp.FinalURL), strings.ToLower(user)) && len(strings.Trim(fu.Path, "/")) < 2 {
			return "", meta, "", false
		}
	}
	return body, meta, resp.FinalURL, true
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}

// cleanTitle strips the site name from "Jane Roe | Medium" style titles.
func cleanTitle(t, site string) string {
	t = html.UnescapeString(strings.TrimSpace(t))
	for _, sep := range []string{" | ", " – ", " - ", " — ", " · ", " on "} {
		if i := strings.Index(t, sep); i > 0 {
			head, tail := t[:i], t[i+len(sep):]
			if strings.Contains(strings.ToLower(tail), strings.ToLower(site)) || strings.Contains(strings.ToLower(head), strings.ToLower(site)) {
				if strings.Contains(strings.ToLower(head), strings.ToLower(site)) {
					return strings.TrimSpace(tail)
				}
				return strings.TrimSpace(head)
			}
		}
	}
	return t
}

func ogProfile(ctx context.Context, c *httpx.Client, s ogSite, user string, emit func(models.Finding)) {
	link := fmt.Sprintf(s.tmpl, esc(user))
	_, meta, final, ok := pageFor(ctx, c, link, user)
	if !ok {
		return
	}
	name := cleanTitle(firstNonEmpty(meta.OGTitle, meta.Title), s.name)
	d := map[string]string{"area": s.area}
	put(d, "display name", name)
	put(d, "about", html.UnescapeString(firstNonEmpty(meta.Description)))
	if img := meta.OGImage; img != "" && !strings.Contains(strings.ToLower(img), "default") {
		put(d, "avatar", img)
	}
	if strings.Contains(name, " ") && !strings.EqualFold(name, user) && len(name) < 60 {
		put(d, "name", name)
	}
	var ents []models.Entity
	if n := d["name"]; n != "" {
		ents = append(ents, models.Entity{Type: models.EntName, Value: n})
	}
	emit(profile(s.name+" profile", final, 0.5, d, ents...))
}

// linkHubs reads "link in bio" pages: the person lists their other accounts
// there themselves, so each one is a strong cross-link.
func linkHubs(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	for _, h := range hubSites {
		link := fmt.Sprintf(h.tmpl, esc(user))
		body, meta, final, ok := pageFor(ctx, c, link, user)
		if !ok {
			continue
		}
		urls := collectLinks(body)
		hubHost := hostOf(final)
		var social []string
		var accts []string
		var sites []string
		seen := map[string]bool{}
		for _, p := range extract.Social(urls) {
			if hostOf(p.URL) == hubHost {
				continue
			}
			accts = append(accts, p.Platform+": "+p.Handle)
			social = append(social, p.URL)
			seen[p.URL] = true
		}
		for _, u := range urls {
			if seen[u] || hostOf(u) == hubHost || skipHost(hostOf(u)) {
				continue
			}
			seen[u] = true
			sites = append(sites, u)
			if len(sites) >= 12 {
				break
			}
		}
		if len(accts) == 0 && len(sites) == 0 {
			continue
		}
		d := map[string]string{"hub": h.name, "area": "link hub"}
		name := cleanTitle(firstNonEmpty(meta.OGTitle, meta.Title), h.name)
		put(d, "display name", name)
		if strings.Contains(name, " ") && len(name) < 60 {
			put(d, "name", name)
		}
		put(d, "about", html.UnescapeString(firstNonEmpty(meta.Description)))
		if img := meta.OGImage; img != "" {
			put(d, "avatar", img)
		}
		put(d, "linked accounts", strings.Join(accts, ", "))
		put(d, "websites", strings.Join(append(social, sites...), ", "))
		var ents []models.Entity
		for _, p := range extract.Social(urls) {
			if x, ok := userEnt(p.Handle, false); ok {
				ents = append(ents, x)
			}
		}
		for _, u := range sites {
			if x, ok := siteEnt(u, false); ok {
				ents = append(ents, x)
			}
		}
		emit(profile("Link hub: "+h.name, final, 0.7, d, ents...))
	}
}

var hrefAny = regexp.MustCompile(`https?:\\?/\\?/[^\s"'<>\\)]+`)

func collectLinks(body string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range hrefAny.FindAllString(body, -1) {
		m = strings.ReplaceAll(m, `\/`, "/")
		m = strings.TrimRight(m, `.,;)`)
		if i := strings.Index(m, `\u`); i > 0 {
			m = m[:i]
		}
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
		if len(out) >= 400 {
			break
		}
	}
	return out
}

func hostOf(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(strings.ToLower(p.Hostname()), "www.")
}

// skipHost drops the assets, trackers and legal pages every hub page embeds.
func skipHost(h string) bool {
	if h == "" {
		return true
	}
	for _, bad := range []string{"cloudfront", "googleapis", "gstatic", "google.com", "googletagmanager", "doubleclick", "cdn.", "static.", "w3.org", "schema.org",
		"fonts.", "cloudflare", "amazonaws", "sentry", "segment.", "facebook.net", "apple.com", "play.google", "intercom", "hotjar", "jsdelivr", "unpkg", "gravatar",
		"linktr.ee", "beacons.ai", "bio.link", "stripe", "paypal.com/legal", "onetrust", "cookiebot", "wp.com", "wordpress.org", "youtube.com/embed"} {
		if strings.Contains(h, bad) {
			return true
		}
	}
	return false
}

// hashnode reads a developer blog profile through its public GraphQL API: real
// name, bio, location and the social links the author added.
func hashnode(ctx context.Context, c *httpx.Client, user string, emit func(models.Finding)) {
	q := `{"query":"query($u:String!){user(username:$u){name username bio{text} location profilePicture socialMediaLinks{website github twitter instagram linkedin youtube facebook}}}","variables":{"u":` + jsonStr(user) + `}}`
	resp, err := c.Do(ctx, httpx.Request{URL: "https://gql.hashnode.com/", Method: "POST", Body: q, Timeout: 20 * time.Second,
		Headers: map[string]string{"Content-Type": "application/json", "Accept": "application/json"}})
	if err != nil || resp.StatusCode != 200 {
		return
	}
	var r struct {
		Data struct {
			User *struct {
				Name     string                `json:"name"`
				Bio      struct{ Text string } `json:"bio"`
				Location string                `json:"location"`
				Picture  string                `json:"profilePicture"`
				Social   map[string]string     `json:"socialMediaLinks"`
			} `json:"user"`
		} `json:"data"`
	}
	if json.Unmarshal(resp.Body, &r) != nil || r.Data.User == nil {
		return
	}
	u := r.Data.User
	d := map[string]string{"area": "writing"}
	put(d, "display name", u.Name)
	if strings.Contains(u.Name, " ") {
		put(d, "name", u.Name)
	}
	put(d, "about", u.Bio.Text)
	put(d, "location", u.Location)
	put(d, "avatar", u.Picture)
	var links []string
	var ents []models.Entity
	for _, v := range u.Social {
		if v = strings.TrimSpace(v); v != "" {
			links = append(links, v)
		}
	}
	for _, p := range extract.Social(links) {
		if x, ok := userEnt(p.Handle, false); ok {
			ents = append(ents, x)
		}
	}
	for _, l := range links {
		if x, ok := siteEnt(l, false); ok {
			ents = append(ents, x)
		}
	}
	put(d, "websites", strings.Join(links, ", "))
	emit(profile("Hashnode profile", "https://hashnode.com/@"+esc(user), 0.65, d, ents...))
}

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
