// Package devtrace digs the metadata developers leave in public: the e-mail
// addresses and names in their public commits, the e-mails on their verified
// GPG keys, public organisations and languages, package-registry maintainer
// e-mails, and PGP keyserver identities. All of it is published openly, but
// almost nobody looks.
package devtrace

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

type Scanner struct{}

var _ scanner.Scanner = (*Scanner)(nil)

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "devtrace" }
func (s *Scanner) Description() string {
	return "public developer traces: commit e-mails, GPG key e-mails, organisations, languages, package maintainers, PGP keyserver"
}
func (s *Scanner) CanRun(t models.Target) bool {
	return strings.TrimSpace(t.Username) != "" || strings.TrimSpace(t.Alias) != "" || strings.Contains(t.Email, "@")
}

func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	var handles []string
	for _, h := range []string{t.Username, t.Alias} {
		h = strings.TrimPrefix(strings.TrimSpace(h), "@")
		if h != "" && !strings.ContainsAny(h, " /@") && !has(handles, h) {
			handles = append(handles, h)
		}
	}
	var jobs []func()
	for _, h := range handles {
		h := h
		jobs = append(jobs,
			func() { commitEmails(ctx, d.HTTP, h, emit) },
			func() { gpgKeys(ctx, d.HTTP, h, emit) },
			func() { orgsAndLanguages(ctx, d.HTTP, h, emit) },
			func() { npmMaintainer(ctx, d.HTTP, h, emit) },
			func() { rubyGems(ctx, d.HTTP, h, emit) },
		)
	}
	if strings.Contains(t.Email, "@") {
		e := strings.TrimSpace(t.Email)
		jobs = append(jobs, func() { pgpKeyserver(ctx, d.HTTP, e, emit) })
	}
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		j := j
		if err := d.Pool.Submit(ctx, func() { defer wg.Done(); j() }); err != nil {
			wg.Done()
			break
		}
	}
	wg.Wait()
	return ctx.Err()
}

func has(s []string, v string) bool {
	for _, x := range s {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func getJSON(ctx context.Context, c *httpx.Client, u string, out any) (int, bool) {
	resp, err := c.Do(ctx, httpx.Request{URL: u, Timeout: 25 * time.Second, MaxBody: 6 << 20, Headers: map[string]string{"Accept": "application/json"}})
	if err != nil {
		return 0, false
	}
	if resp.StatusCode != 200 {
		return resp.StatusCode, false
	}
	return 200, json.Unmarshal(resp.Body, out) == nil
}

func isNoReply(e string) bool {
	e = strings.ToLower(e)
	return strings.Contains(e, "noreply") || strings.HasSuffix(e, "@localhost") || strings.HasSuffix(e, ".local") || strings.HasSuffix(e, ".(none)") ||
		strings.HasSuffix(e, "@example.com")
}

func rateLimited(source string, code int, emit func(models.Finding)) {
	if code == 403 || code == 429 {
		emit(models.Finding{Source: source, Category: "developer", Status: models.StatusError,
			Details: map[string]string{"error": fmt.Sprintf("HTTP %d: rate-limited (GitHub allows 60 unauthenticated requests per hour per IP); retry later or use a proxy", code)}})
	}
}

// commitEmails reads the account's public events: every push lists the name
// and e-mail each commit was authored with. People often commit with a real
// address even when their profile hides it.
func commitEmails(ctx context.Context, c *httpx.Client, h string, emit func(models.Finding)) {
	type author struct {
		Name, Email string
		n           int
		repos       map[string]bool
	}
	by := map[string]*author{}
	for page := 1; page <= 3; page++ {
		var ev []struct {
			Type    string                `json:"type"`
			Repo    struct{ Name string } `json:"repo"`
			Payload struct {
				Commits []struct {
					Author struct{ Name, Email string } `json:"author"`
				} `json:"commits"`
			} `json:"payload"`
		}
		code, ok := getJSON(ctx, c, "https://api.github.com/users/"+url.PathEscape(h)+"/events/public?per_page=100&page="+fmt.Sprint(page), &ev)
		if !ok {
			rateLimited("GitHub commit authors", code, emit)
			break
		}
		for _, e := range ev {
			if e.Type != "PushEvent" {
				continue
			}
			for _, cm := range e.Payload.Commits {
				em := strings.ToLower(strings.TrimSpace(cm.Author.Email))
				if em == "" || isNoReply(em) {
					continue
				}
				a := by[em]
				if a == nil {
					a = &author{Name: cm.Author.Name, Email: em, repos: map[string]bool{}}
					by[em] = a
				}
				a.n++
				a.repos[e.Repo.Name] = true
			}
		}
		if len(ev) < 100 {
			break
		}
	}
	if len(by) == 0 {
		return
	}
	var list []*author
	for _, a := range by {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n })
	var lines []string
	var ents []models.Entity
	for _, a := range list {
		lines = append(lines, fmt.Sprintf("%s <%s> — %d commit(s)", a.Name, a.Email, a.n))
		ents = append(ents, models.Entity{Type: models.EntEmail, Value: a.Email})
		if a.Name != "" && strings.Contains(a.Name, " ") {
			ents = append(ents, models.Entity{Type: models.EntName, Value: a.Name})
		}
	}
	emit(models.Finding{Source: "GitHub commit authors", Category: "developer", Status: models.StatusFound, Confidence: 0.7,
		URL: "https://github.com/" + h,
		Details: map[string]string{"handle": h, "authors in public commits": strings.Join(lines, "; "),
			"note": "names and e-mails the account's recent public commits were authored with; verify it is the same person before relying on it"},
		Entities: ents})
}

// gpgKeys lists the e-mails on the account's GPG keys. GitHub marks which
// are verified, so those are strong evidence of ownership.
func gpgKeys(ctx context.Context, c *httpx.Client, h string, emit func(models.Finding)) {
	var keys []struct {
		KeyID  string `json:"key_id"`
		Emails []struct {
			Email    string `json:"email"`
			Verified bool   `json:"verified"`
		} `json:"emails"`
		Created string `json:"created_at"`
		Expires string `json:"expires_at"`
	}
	code, ok := getJSON(ctx, c, "https://api.github.com/users/"+url.PathEscape(h)+"/gpg_keys", &keys)
	if !ok {
		rateLimited("GitHub GPG keys", code, emit)
		return
	}
	var lines []string
	var ents []models.Entity
	for _, k := range keys {
		for _, e := range k.Emails {
			if e.Email == "" || isNoReply(e.Email) {
				continue
			}
			v := "unverified"
			if e.Verified {
				v = "verified by GitHub"
			}
			lines = append(lines, fmt.Sprintf("%s (key %s, %s, created %.10s)", e.Email, k.KeyID, v, k.Created))
			ents = append(ents, models.Entity{Type: models.EntEmail, Value: e.Email, Strong: e.Verified})
		}
	}
	if len(lines) == 0 {
		return
	}
	emit(models.Finding{Source: "GitHub GPG key e-mails", Category: "developer", Status: models.StatusFound, Confidence: 0.85, URL: "https://github.com/" + h + ".gpg",
		Details:  map[string]string{"handle": h, "e-mails on GPG keys": strings.Join(lines, "; ")},
		Entities: ents})
}

// orgsAndLanguages summarises public organisation memberships and what the
// account actually writes (languages, topics, stars), which shows skills and
// affiliations the profile text leaves out.
func orgsAndLanguages(ctx context.Context, c *httpx.Client, h string, emit func(models.Finding)) {
	var orgs []struct {
		Login string `json:"login"`
	}
	oc, ok := getJSON(ctx, c, "https://api.github.com/users/"+url.PathEscape(h)+"/orgs", &orgs)
	if !ok {
		rateLimited("GitHub organisations", oc, emit)
	}
	var repos []struct {
		Name     string   `json:"name"`
		Fork     bool     `json:"fork"`
		Language string   `json:"language"`
		Stars    int      `json:"stargazers_count"`
		Topics   []string `json:"topics"`
		Created  string   `json:"created_at"`
	}
	rc, rok := getJSON(ctx, c, "https://api.github.com/users/"+url.PathEscape(h)+"/repos?per_page=100&sort=pushed", &repos)
	if !rok {
		rateLimited("GitHub repositories", rc, emit)
	}
	d := map[string]string{"handle": h}
	var ents []models.Entity
	if len(orgs) > 0 {
		var names []string
		for _, o := range orgs {
			names = append(names, o.Login)
			ents = append(ents, models.Entity{Type: models.EntOrg, Value: o.Login})
		}
		d["public organisations"] = strings.Join(names, ", ")
	}
	if len(repos) > 0 {
		lang := map[string]int{}
		topics := map[string]int{}
		own, stars := 0, 0
		oldest := ""
		for _, r := range repos {
			if r.Fork {
				continue
			}
			own++
			stars += r.Stars
			if r.Language != "" {
				lang[r.Language]++
			}
			for _, t := range r.Topics {
				topics[t]++
			}
			if oldest == "" || (r.Created != "" && r.Created < oldest) {
				oldest = r.Created
			}
		}
		d["own repositories (latest 100)"] = fmt.Sprint(own)
		d["stars received"] = fmt.Sprint(stars)
		if l := top(lang, 6); l != "" {
			d["main languages"] = l
		}
		if t := top(topics, 10); t != "" {
			d["topics"] = t
		}
		if len(oldest) >= 10 {
			d["oldest of these repositories"] = oldest[:10]
		}
	}
	if len(d) == 1 {
		return
	}
	emit(models.Finding{Source: "GitHub activity profile", Category: "developer", Status: models.StatusFound, Confidence: 0.6, URL: "https://github.com/" + h,
		Details: d, Entities: ents})
}

func top(m map[string]int, n int) string {
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
		out = append(out, fmt.Sprintf("%s (%d)", x.k, x.v))
	}
	return strings.Join(out, ", ")
}

// npmMaintainer finds packages published under the handle; npm shows the
// publisher's e-mail address on each.
func npmMaintainer(ctx context.Context, c *httpx.Client, h string, emit func(models.Finding)) {
	var r struct {
		Total   int `json:"total"`
		Objects []struct {
			Package struct {
				Name       string                             `json:"name"`
				Publisher  struct{ Username, Email string }   `json:"publisher"`
				Maintainer []struct{ Username, Email string } `json:"maintainers"`
			} `json:"package"`
		} `json:"objects"`
	}
	if _, ok := getJSON(ctx, c, "https://registry.npmjs.org/-/v1/search?size=25&text=maintainer:"+url.QueryEscape(h), &r); !ok || len(r.Objects) == 0 {
		return
	}
	emails := map[string]bool{}
	var pkgs []string
	for _, o := range r.Objects {
		if len(pkgs) < 8 {
			pkgs = append(pkgs, o.Package.Name)
		}
		for _, m := range o.Package.Maintainer {
			if strings.EqualFold(m.Username, h) && m.Email != "" && !isNoReply(m.Email) {
				emails[strings.ToLower(m.Email)] = true
			}
		}
	}
	d := map[string]string{"handle": h, "packages": fmt.Sprint(r.Total), "examples": strings.Join(pkgs, ", ")}
	var ents []models.Entity
	for e := range emails {
		ents = append(ents, models.Entity{Type: models.EntEmail, Value: e})
	}
	if len(ents) > 0 {
		var es []string
		for _, e := range ents {
			es = append(es, e.Value)
		}
		sort.Strings(es)
		d["maintainer e-mail"] = strings.Join(es, ", ")
	}
	d["note"] = "npm account with this exact username; it may belong to a different person than your subject"
	emit(models.Finding{Source: "npm packages", Category: "developer", Status: models.StatusUncertain, Confidence: 0.5,
		URL: "https://www.npmjs.com/~" + h, Details: d, Entities: ents})
}

func rubyGems(ctx context.Context, c *httpx.Client, h string, emit func(models.Finding)) {
	var gems []struct {
		Name    string `json:"name"`
		Authors string `json:"authors"`
	}
	if _, ok := getJSON(ctx, c, "https://rubygems.org/api/v1/owners/"+url.PathEscape(h)+"/gems.json", &gems); !ok || len(gems) == 0 {
		return
	}
	var names []string
	authors := map[string]bool{}
	for i, g := range gems {
		if i < 8 {
			names = append(names, g.Name)
		}
		if g.Authors != "" {
			authors[g.Authors] = true
		}
	}
	var al []string
	for a := range authors {
		al = append(al, a)
	}
	sort.Strings(al)
	emit(models.Finding{Source: "RubyGems", Category: "developer", Status: models.StatusUncertain, Confidence: 0.45, URL: "https://rubygems.org/profiles/" + h,
		Details: map[string]string{"handle": h, "gems": fmt.Sprint(len(gems)), "examples": strings.Join(names, ", "), "author names on gems": strings.Join(clip(al, 8), "; "),
			"note": "RubyGems account with this exact username; may belong to someone else"}})
}

func clip(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// pgpKeyserver lists the identities on public PGP keys that carry the e-mail:
// real names, other addresses, and when each key was made.
func pgpKeyserver(ctx context.Context, c *httpx.Client, email string, emit func(models.Finding)) {
	resp, err := c.Do(ctx, httpx.Request{URL: "https://keyserver.ubuntu.com/pks/lookup?op=vindex&options=mr&search=" + url.QueryEscape(email), Timeout: 25 * time.Second})
	if err != nil || resp.StatusCode != 200 {
		return
	}
	var uids []string
	var ents []models.Entity
	seen := map[string]bool{}
	for _, line := range strings.Split(string(resp.Body), "\n") {
		if !strings.HasPrefix(line, "uid:") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 2 {
			continue
		}
		uid, _ := url.QueryUnescape(strings.ReplaceAll(f[1], "+", "%2B"))
		if uid == "" || seen[uid] {
			continue
		}
		seen[uid] = true
		uids = append(uids, uid)
		if i, j := strings.Index(uid, "<"), strings.Index(uid, ">"); i > 0 && j > i {
			name := strings.TrimSpace(uid[:i])
			em := strings.ToLower(uid[i+1 : j])
			if strings.Contains(name, " ") {
				ents = append(ents, models.Entity{Type: models.EntName, Value: name})
			}
			if !strings.EqualFold(em, email) {
				ents = append(ents, models.Entity{Type: models.EntEmail, Value: em})
			}
		}
	}
	if len(uids) == 0 {
		return
	}
	emit(models.Finding{Source: "PGP keyserver", Category: "developer", Status: models.StatusFound, Confidence: 0.75, URL: "https://keyserver.ubuntu.com/pks/lookup?op=vindex&search=" + url.QueryEscape(email),
		Details: map[string]string{"identities on keys with this e-mail": strings.Join(clip(uids, 12), "; "),
			"note": "anyone can upload a key with any e-mail, so a name here is a lead until a second source agrees"},
		Entities: ents})
}
