// Package health probes the public services rectool depends on, so an empty
// result can be told apart from a source that is down or blocking.
package health

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
)

// Source is one service and a cheap request that shows it is working.
type Source struct {
	Name, Used, URL string
}

// Sources are checked with plain GETs; any HTTP status below 400 counts as up.
var Sources = []Source{
	{"GitHub API", "profiles, people, activity", "https://api.github.com/rate_limit"},
	{"Wikidata", "people", "https://www.wikidata.org/w/api.php?action=query&meta=siteinfo&format=json"},
	{"Wikipedia", "people, activity", "https://en.wikipedia.org/api/rest_v1/page/summary/Earth"},
	{"ORCID", "people", "https://pub.orcid.org/v3.0/expanded-search/?q=smith&rows=1"},
	{"OpenAlex", "people", "https://api.openalex.org/authors?search=smith&per-page=1"},
	{"Crossref", "people", "https://api.crossref.org/works?rows=1"},
	{"Stack Exchange", "people", "https://api.stackexchange.com/2.3/info?site=stackoverflow"},
	{"Hugging Face", "people", "https://huggingface.co/api/quicksearch?type=user&q=smith"},
	{"Hacker News", "activity", "https://hn.algolia.com/api/v1/search?query=a&hitsPerPage=1"},
	{"Codeforces", "activity", "https://codeforces.com/api/user.info?handles=tourist"},
	{"Bluesky", "activity", "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=bsky.app"},
	{"Mastodon", "activity, webfinger", "https://mastodon.social/api/v1/instance"},
	{"Lichess", "activity", "https://lichess.org/api/user/DrNykterstein"},
	{"Nominatim", "location", "https://nominatim.openstreetmap.org/status.php?format=json"},
	{"OSM tiles", "location map", "https://tile.openstreetmap.org/0/0/0.png"},
	{"ipwho.is", "ip geolocation", "https://ipwho.is/1.1.1.1"},
	{"Internet Archive", "archive history", "https://web.archive.org/cdx/search/cdx?url=example.com&limit=1&output=json"},
	{"unavatar", "photos", "https://unavatar.io/github/github?fallback=false"},
	{"Bing", "photos, search", "https://www.bing.com/images/search?q=test"},
	{"XposedOrNot", "breach", "https://api.xposedornot.com/v1/check-email/test@example.com"},
	{"GLEIF", "company", "https://api.gleif.org/api/v1/lei-records?page%5Bsize%5D=1"},
	{"crt.sh", "domain", "https://crt.sh/?q=example.com&output=json&exclude=expired"},
	{"WhatsMyName list", "social", "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"},
}

// Result is the outcome of one probe.
type Result struct {
	Name   string `json:"name"`
	Used   string `json:"used_by"`
	OK     bool   `json:"ok"`
	Status int    `json:"status"`
	MS     int64  `json:"ms"`
	Error  string `json:"error,omitempty"`
}

// Check probes every source concurrently (at most 8 at a time).
func Check(ctx context.Context, c *httpx.Client) []Result {
	out := make([]Result, len(Sources))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, s := range Sources {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, s Source) {
			defer func() { <-sem; wg.Done() }()
			start := time.Now()
			r := Result{Name: s.Name, Used: s.Used}
			resp, err := c.Do(ctx, httpx.Request{URL: s.URL, Timeout: 15 * time.Second, MaxBody: 64 << 10,
				Headers: map[string]string{"User-Agent": "rectool/1.0 (+https://github.com/sudosoc/rectool)"}})
			r.MS = time.Since(start).Milliseconds()
			switch {
			case err != nil:
				r.Error = err.Error()
			default:
				r.Status = resp.StatusCode
				// 404 from lookup-style APIs (e.g. no breaches) still proves the service answers
				r.OK = resp.StatusCode < 400 || resp.StatusCode == 404
				if !r.OK {
					r.Error = "HTTP " + itoa(resp.StatusCode)
				}
			}
			out[i] = r
		}(i, s)
	}
	wg.Wait()
	sort.SliceStable(out, func(a, b int) bool { return !out[a].OK && out[b].OK })
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
