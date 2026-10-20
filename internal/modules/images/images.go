// Package images hunts for pictures of the subject beyond what the profile
// collectors already return:
//
//   - avatars for the given handle on major services (via unavatar.io, a public
//     avatar resolver, so no site-by-site scraping or login is needed);
//   - web image search results for the full name, filtered to pages whose
//     title actually contains the name.
//
// Neither is proof of identity. A handle can belong to someone else and a web
// image of a common name can show a stranger, so every result is labelled with
// how it was found, emitted as an unverified candidate, and left to the photo
// stage (which groups identical pictures) and the operator to judge.
package images

import (
	"context"
	"encoding/json"
	"html"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/identity"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

// Scanner is the images module.
type Scanner struct{}

var _ scanner.Scanner = (*Scanner)(nil)

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "images" }
func (s *Scanner) Description() string {
	return "pictures of the subject: avatars for a handle on major services and web image search for the name"
}

func (s *Scanner) CanRun(t models.Target) bool {
	return len(strings.Fields(t.FullName)) >= 2 || strings.TrimSpace(t.Username) != "" || strings.TrimSpace(t.Alias) != ""
}

// avatarServices are services unavatar.io can resolve by handle.
var avatarServices = []string{"github", "x", "gitlab", "reddit", "twitch", "youtube", "tiktok", "telegram", "soundcloud", "substack", "dribbble", "behance", "medium", "deviantart", "pinterest", "spotify", "patreon", "linktree"}

func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	var handles []string
	for _, h := range []string{t.Username, t.Alias} {
		h = strings.TrimPrefix(strings.TrimSpace(h), "@")
		if h != "" && !strings.ContainsAny(h, " /@") && !contains(handles, h) {
			handles = append(handles, h)
		}
	}
	type job func()
	var jobs []job
	for _, h := range handles {
		for _, svc := range avatarServices {
			h, svc := h, svc
			jobs = append(jobs, func() { avatar(ctx, d.HTTP, svc, h, emit) })
		}
	}
	if len(strings.Fields(t.FullName)) >= 2 {
		jobs = append(jobs, func() { bingImages(ctx, d.HTTP, t, emit) })
	}
	var (
		wg   sync.WaitGroup
		done atomic.Int64
	)
	for _, j := range jobs {
		wg.Add(1)
		j := j
		if err := d.Pool.Submit(ctx, func() {
			defer wg.Done()
			j()
			if d.Progress != nil {
				d.Progress(s.Name(), int(done.Add(1)), len(jobs))
			}
		}); err != nil {
			wg.Done()
			break
		}
	}
	wg.Wait()
	return ctx.Err()
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

// avatar asks the resolver for a handle's picture. fallback=false makes it
// answer 404 instead of a generic placeholder.
func avatar(ctx context.Context, c *httpx.Client, svc, handle string, emit func(models.Finding)) {
	u := "https://unavatar.io/" + svc + "/" + url.PathEscape(handle) + "?fallback=false"
	resp, err := c.Do(ctx, httpx.Request{URL: u, Timeout: 20 * time.Second})
	if err != nil || resp.StatusCode != 200 {
		return
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "image/") {
		return
	}
	emit(models.Finding{Source: "Avatar: " + svc, Category: "photo", URL: u, Status: models.StatusUncertain, Confidence: 0.4,
		Details: map[string]string{"handle": handle, "service": svc,
			"note": "avatar of this handle on " + svc + " (resolved by unavatar.io); the handle may belong to someone else"},
		Entities: []models.Entity{{Type: models.EntImage, Value: u}}})
}

var bingTile = regexp.MustCompile(`(?s)class="iusc"[^>]*\sm="([^"]+)"`)

type bingMeta struct {
	Murl string `json:"murl"`
	Turl string `json:"turl"`
	Purl string `json:"purl"`
	T    string `json:"t"`
}

// bingImages runs a web image search for the quoted name and keeps results
// whose page title contains every word of the name.
func bingImages(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
	q := `"` + t.FullName + `"`
	if t.Company != "" {
		q += " " + t.Company
	}
	u := "https://www.bing.com/images/search?form=HDRSC2&q=" + url.QueryEscape(q)
	resp, err := c.Do(ctx, httpx.Request{URL: u, Timeout: 25 * time.Second, MaxBody: 4 << 20,
		Headers: map[string]string{"Accept-Language": "en-US,en;q=0.9"}})
	if err != nil || resp.StatusCode != 200 {
		return
	}
	words := identity.Words(t.FullName)
	n := 0
	seen := map[string]bool{}
	for _, m := range bingTile.FindAllStringSubmatch(string(resp.Body), -1) {
		var meta bingMeta
		if json.Unmarshal([]byte(html.UnescapeString(m[1])), &meta) != nil || meta.Turl == "" {
			continue
		}
		title := strings.Join(identity.Words(meta.T), " ")
		ok := true
		for _, w := range words {
			if !strings.Contains(title, w) {
				ok = false
				break
			}
		}
		if !ok || seen[meta.Murl] {
			continue
		}
		seen[meta.Murl] = true
		det := map[string]string{"page": meta.Purl, "title": meta.T, "original image": meta.Murl,
			"note": "found by web image search for the name; unverified, may show a different person with the same name"}
		emit(models.Finding{Source: "Web image search", Category: "photo", URL: meta.Purl, Status: models.StatusUncertain, Confidence: 0.3,
			Details: det, Entities: []models.Entity{{Type: models.EntImage, Value: meta.Turl}}})
		if n++; n >= 12 {
			break
		}
	}
}
