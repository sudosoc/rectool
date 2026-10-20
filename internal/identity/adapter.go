package identity

import (
	"crypto/md5" //nolint:gosec // Gravatar identifies accounts by the MD5 of the address
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"

	"github.com/sudosoc/rectool/internal/models"
)

// ResolveFindings turns every person-like finding into a Record, attaches the
// downloaded pictures' perceptual hashes, and resolves identities.
func ResolveFindings(findings []models.Finding, t models.Target, photos []models.Photo) Result {
	hashes := map[string]uint64{}
	for _, p := range photos {
		if len(p.DHash) == 16 {
			if v, err := strconv.ParseUint(p.DHash, 16, 64); err == nil {
				hashes[p.URL] = v
			}
		}
	}
	a := FromTarget(t)
	var inputs []Input
	for _, f := range findings {
		if f.Status != models.StatusFound && f.Status != models.StatusUncertain {
			continue
		}
		rec, ok := RecordFromFinding(f, a)
		if !ok {
			continue
		}
		in := Input{Rec: rec, Source: f.Module + ": " + f.Source}
		if h, ok := hashes[rec.Photo]; ok {
			in.PhotoHash, in.HasHash = h, true
		}
		inputs = append(inputs, in)
	}
	return Resolve(inputs, a)
}

var platformNames = []struct{ prefix, name string }{
	{"GitHub", "GitHub"}, {"GitLab", "GitLab"}, {"Keybase", "Keybase"}, {"npm", "npm"}, {"Hacker News", "Hacker News"},
	{"DEV", "DEV"}, {"Docker Hub", "Docker Hub"}, {"Mastodon", "Mastodon"}, {"Stack Overflow", "Stack Overflow"},
	{"Lichess", "Lichess"}, {"Chess.com", "Chess.com"}, {"Codeforces", "Codeforces"}, {"Codeberg", "Codeberg"},
	{"Hugging Face", "Hugging Face"}, {"Steam", "Steam"}, {"Telegram", "Telegram"}, {"Bluesky", "Bluesky"},
	{"Gravatar", "Gravatar"}, {"Reddit", "Reddit"}, {"crates.io", "crates.io"}, {"Wikipedia", "Wikipedia"},
}

func platformOf(source string) string {
	for _, p := range platformNames {
		if strings.HasPrefix(source, p.prefix) {
			return p.name
		}
	}
	return ""
}

func first(d map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(d[k]); v != "" {
			return v
		}
	}
	return ""
}

// splitList splits "a, b | c" style detail values.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '|' || r == ';' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func emailFromVia(via string) string {
	if strings.HasPrefix(via, "email:") {
		return strings.ToLower(strings.TrimPrefix(via, "email:"))
	}
	return ""
}

// RecordFromFinding converts a finding into a person Record when it describes
// a profile. Findings that already carry a Record are used as is.
func RecordFromFinding(f models.Finding, a Anchors) (models.Record, bool) {
	if f.Record != nil {
		r := *f.Record
		if r.Platform == "" {
			r.Platform = f.Source
		}
		if r.URL == "" {
			r.URL = f.URL
		}
		return r, true
	}
	d := f.Details
	switch {
	case f.Module == "profiles" && f.Category == "profile":
		return profileRecord(f), true

	case f.Module == "footprint" && f.Source == "Gravatar profile":
		r := models.Record{Platform: "Gravatar", URL: f.URL, Self: true, Photo: d["avatar"],
			Name: first(d, "full name", "display name"), Location: d["location"], Bio: d["about"]}
		if u := d["username"]; u != "" {
			r.Usernames = append(r.Usernames, "gravatar:"+u)
		}
		for _, acct := range splitList(d["linked accounts"]) {
			if dom, user, ok := strings.Cut(acct, ": "); ok {
				r.Usernames = append(r.Usernames, strings.ToLower(strings.TrimSuffix(dom, ".com"))+":"+user)
			}
		}
		r.Websites = splitList(d["websites"])
		r.Emails = emailOf(f, a, d["md5"])
		return r, true

	case f.Module == "footprint" && strings.HasPrefix(f.Source, "GitHub account publishing"):
		r := models.Record{Platform: "GitHub", URL: f.URL, Self: true, Emails: emailOf(f, a, "")}
		for _, l := range splitList(d["logins"]) {
			r.Usernames = append(r.Usernames, "github:"+l)
		}
		return r, true

	case f.Module == "footprint" && strings.HasPrefix(f.Source, "Git commits authored"):
		r := models.Record{Platform: "GitHub", URL: f.URL, Self: true, Emails: emailOf(f, a, "")}
		r.Name = first(d, "author names used")
		if i := strings.IndexAny(r.Name, ",|"); i > 0 {
			r.Name = strings.TrimSpace(r.Name[:i])
		}
		for _, l := range splitList(d["GitHub logins"]) {
			r.Usernames = append(r.Usernames, "github:"+l)
		}
		return r, true

	case f.Module == "domain" && strings.HasPrefix(f.Source, "WHOIS / RDAP"):
		r := models.Record{Platform: "WHOIS", URL: f.URL}
		for _, k := range []string{"registrant", "administrative", "technical"} {
			if v := d[k]; v != "" {
				parts := strings.Split(v, " · ")
				if len(parts) > 0 && r.Name == "" {
					r.Name = parts[0]
				}
				for _, p := range parts[1:] {
					if strings.Contains(p, "@") {
						r.Emails = append(r.Emails, strings.ToLower(p))
					}
				}
			}
		}
		if r.Name == "" && len(r.Emails) == 0 {
			return r, false
		}
		return r, true
	}
	return models.Record{}, false
}

// emailOf finds the e-mail a footprint finding is about: the pivot lead it
// was found through, or the supplied e-mail (checked against the Gravatar hash
// when one is given).
func emailOf(f models.Finding, a Anchors, md5hex string) []string {
	if e := emailFromVia(f.Via); e != "" {
		return []string{e}
	}
	if a.Email == "" {
		return nil
	}
	if md5hex != "" {
		sum := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(a.Email)))) //nolint:gosec
		if hex.EncodeToString(sum[:]) != md5hex {
			return nil
		}
	}
	return []string{strings.ToLower(a.Email)}
}

func profileRecord(f models.Finding) models.Record {
	d := f.Details
	plat := platformOf(f.Source)
	if plat == "" {
		plat = strings.TrimSuffix(strings.Fields(f.Source + " ")[0], ":")
	}
	r := models.Record{Platform: plat, URL: f.URL, Self: true,
		Name:     first(d, "name", "full name", "real name", "display name", "commit author names"),
		Location: first(d, "location"), Photo: d["avatar"],
		Bio: first(d, "bio", "summary", "about", "description")}
	if c := strings.TrimPrefix(strings.TrimSpace(d["company"]), "@"); c != "" {
		r.Employers = append(r.Employers, c)
	}
	if w := first(d, "website", "websites"); w != "" {
		r.Websites = append(r.Websites, splitList(w)...)
	}
	if e := first(d, "public email"); e != "" {
		r.Emails = append(r.Emails, strings.ToLower(e))
	}
	for _, e := range splitList(d["maintainer e-mail"]) {
		r.Emails = append(r.Emails, strings.ToLower(e))
	}
	for _, e := range splitList(d["commit e-mails"]) {
		if at := strings.IndexByte(e, ' '); at > 0 {
			e = e[:at]
		}
		r.Emails = append(r.Emails, strings.ToLower(e))
	}
	if h := d["handle"]; h != "" {
		r.Usernames = append(r.Usernames, strings.ToLower(plat)+":"+h)
	}
	if t := d["twitter"]; t != "" {
		r.Usernames = append(r.Usernames, "twitter:"+strings.TrimPrefix(t, "@"))
	}
	if g := d["github"]; g != "" {
		r.Usernames = append(r.Usernames, "github:"+g)
	}
	// Keybase: "twitter: foo, github: bar, dns: example.org"
	for _, p := range splitList(d["cryptographically verified accounts"]) {
		kind, val, ok := strings.Cut(p, ": ")
		if !ok {
			continue
		}
		switch kind {
		case "dns", "generic_web_site":
			r.Websites = append(r.Websites, val)
		default:
			r.Usernames = append(r.Usernames, kind+":"+val)
		}
	}
	if r.Name == "" && strings.Contains(f.Source, "commit") {
		r.Name = d["commit author names"]
	}
	if u, err := url.Parse(r.URL); err == nil && u.Host == "" {
		r.URL = ""
	}
	return r
}
