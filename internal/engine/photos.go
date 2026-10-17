package engine

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sudosoc/rectool/internal/media"
	"github.com/sudosoc/rectool/internal/models"
)

const maxPhotos = 40

var (
	imageKeys     = []string{"avatar", "photo", "picture"}
	notPortrait   = regexp.MustCompile(`(?i)(logo|favicon|sprite|banner|placeholder|blank|default|no[-_]?avatar|no-title|missing\.|open-?graph|og-image|user-default|/users/thumbs/|tile|icon-\d|/icons?/|\.svg(\?|$)|\.ico(\?|$))`)
	profileImgURL = regexp.MustCompile(`(?i)(avatar|profile|user|photo|picture|portrait|pfp|userpic|member|people|account|headshot|gravatar)`)
)

// addImageEntities turns avatar-like detail values into image entities so the
// photo stage can download and compare them. Generic site pages (the "social"
// existence probe) usually expose a logo as og:image, so those are accepted
// only when the URL itself looks like a profile picture.
func addImageEntities(f *models.Finding) {
	for _, k := range imageKeys {
		raw := strings.TrimSpace(f.Details[k])
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || notPortrait.MatchString(raw) {
			continue
		}
		if f.Module == "social" && !profileImgURL.MatchString(raw) {
			continue
		}
		f.Entities = append(f.Entities, models.Entity{Type: models.EntImage, Value: raw})
	}
}

// photoStage downloads every discovered picture (safely, see package media),
// fingerprints it, and groups copies of the same picture. A photo that appears
// under several accounts is the strongest cheap evidence that they belong to
// one person, so each such group is reported as its own finding.
func (e *Engine) photoStage(ctx context.Context, rep *models.Report) {
	type src struct {
		url     string
		sources []string
	}
	idx := map[string]*src{}
	var order []string
	for _, ent := range rep.Entities {
		if ent.Type != models.EntImage {
			continue
		}
		if s, ok := idx[ent.Value]; ok {
			s.sources = append(s.sources, ent.Source)
			continue
		}
		idx[ent.Value] = &src{url: ent.Value, sources: []string{ent.Source}}
		order = append(order, ent.Value)
	}
	// An entity is de-duplicated across findings, so collect every source from the findings too.
	for _, f := range rep.Findings {
		for _, ent := range f.Entities {
			if ent.Type == models.EntImage {
				if s, ok := idx[ent.Value]; ok {
					lbl := f.Module + ": " + f.Source
					if !contains(s.sources, lbl) {
						s.sources = append(s.sources, lbl)
					}
				}
			}
		}
	}
	if len(order) == 0 || ctx.Err() != nil {
		return
	}
	if len(order) > maxPhotos {
		order = order[:maxPhotos]
	}

	start := time.Now()
	imgs := make([]*media.Image, len(order))
	errs := make([]string, len(order))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for i, u := range order {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			img, err := media.Fetch(ctx, e.http, u)
			if err != nil {
				errs[i] = err.Error()
				return
			}
			imgs[i] = img
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}

	// union-find over similar images
	parent := make([]int, len(order))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	for i := range imgs {
		for j := i + 1; j < len(imgs); j++ {
			if imgs[i] != nil && imgs[j] != nil && media.Similar(imgs[i], imgs[j]) {
				parent[find(i)] = find(j)
			}
		}
	}
	members := map[int][]int{}
	for i := range imgs {
		if imgs[i] != nil {
			members[find(i)] = append(members[find(i)], i)
		}
	}

	groupNo := map[int]int{}
	next := 0
	var groups []int
	for root, m := range members {
		if len(m) > 1 {
			groups = append(groups, root)
		}
	}
	sort.Ints(groups)
	for _, root := range groups {
		next++
		groupNo[root] = next
	}

	fetched := 0
	for i, u := range order {
		p := models.Photo{URL: u, Sources: idx[u].sources}
		if imgs[i] == nil {
			p.Error = errs[i]
		} else {
			fetched++
			im := imgs[i]
			p.ContentType, p.Bytes, p.Width, p.Height, p.SHA256, p.DHash = im.ContentType, im.Bytes, im.Width, im.Height, im.SHA256, im.DHashHex()
			p.Group = groupNo[find(i)]
		}
		rep.Photos = append(rep.Photos, p)
	}
	sort.SliceStable(rep.Photos, func(a, b int) bool {
		pa, pb := rep.Photos[a], rep.Photos[b]
		if (pa.Group > 0) != (pb.Group > 0) {
			return pa.Group > 0
		}
		if pa.Group != pb.Group {
			return pa.Group < pb.Group
		}
		return pa.Error == "" && pb.Error != ""
	})

	found := 0
	for _, root := range groups {
		var urls, sources []string
		seen := map[string]bool{}
		for _, i := range members[root] {
			urls = append(urls, order[i])
			for _, s := range idx[order[i]].sources {
				if !seen[s] {
					seen[s] = true
					sources = append(sources, s)
				}
			}
		}
		// Independent evidence needs different sites: one account served from two
		// CDN hostnames of the same service (or found by two collectors) is not a match.
		sites := map[string]bool{}
		for _, u := range urls {
			sites[siteKey(u)] = true
		}
		if len(sources) < 2 || len(sites) < 2 {
			continue
		}
		found++
		f := models.Finding{
			Module: "photos", Source: fmt.Sprintf("Same profile picture on %d sources", len(sources)), Category: "photo",
			URL: urls[0], Status: models.StatusFound, Confidence: 0.85, Timestamp: time.Now().UTC(),
			Details: map[string]string{
				"sources": strings.Join(sources, " | "),
				"images":  strings.Join(urls, " | "),
				"why":     "visually identical pictures (perceptual hash match) are rarely coincidence: the accounts above very likely belong to the same person",
				"caveat":  "stock images, memes and default avatars also repeat; open the images to confirm it is a real photo",
			},
		}
		rep.Findings = append(rep.Findings, f)
		if e.OnFinding != nil {
			e.OnFinding(f)
		}
	}
	rep.Modules = append(rep.Modules, models.ModuleRun{
		Name: "photos", DurationMS: time.Since(start).Milliseconds(), Checked: len(order), Found: found, Errors: len(order) - fetched,
	})
	for i := range order {
		if imgs[i] == nil {
			rep.Failures = append(rep.Failures, models.Failure{Module: "photos", Source: order[i], Error: errs[i]})
		}
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

var secondLevel = map[string]bool{"co.uk": true, "org.uk": true, "ac.uk": true, "com.au": true, "net.au": true, "co.jp": true,
	"co.nz": true, "com.br": true, "com.cn": true, "co.in": true, "co.za": true, "com.tr": true, "com.pl": true, "com.ru": true}

// siteKey approximates the registrable domain of a URL's host (IP literals and
// single-label hosts are returned as is).
func siteKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	h := strings.ToLower(u.Hostname())
	parts := strings.Split(h, ".")
	if len(parts) <= 2 || (len(parts) == 4 && isDigits(parts[0])) {
		return h
	}
	n := 2
	if secondLevel[strings.Join(parts[len(parts)-2:], ".")] {
		n = 3
	}
	return strings.Join(parts[len(parts)-n:], ".")
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
