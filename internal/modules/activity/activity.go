// Package activity estimates the subject's timezone from when their public
// accounts are active. Nobody posts at 4 a.m. local time, so the quietest
// stretch of a few hundred timestamps points at the UTC offset. It reads only
// timestamps of public events, never their content.
package activity

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sudosoc/rectool/internal/geo"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

type Scanner struct{}

var _ scanner.Scanner = (*Scanner)(nil)

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "activity" }
func (s *Scanner) Description() string {
	return "timezone estimate from the hours a username is active on GitHub, Hacker News, Wikipedia, Codeforces, Bluesky, Mastodon and Lichess"
}
func (s *Scanner) CanRun(t models.Target) bool {
	return strings.TrimSpace(t.Username) != "" || strings.TrimSpace(t.Alias) != ""
}

func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	var handles []string
	for _, h := range []string{t.Username, t.Alias} {
		h = strings.TrimPrefix(strings.TrimSpace(h), "@")
		if h != "" && !strings.ContainsAny(h, " /@") {
			dup := false
			for _, x := range handles {
				dup = dup || strings.EqualFold(x, h)
			}
			if !dup {
				handles = append(handles, h)
			}
		}
	}
	var wg sync.WaitGroup
	for _, h := range handles {
		for name, fn := range sources {
			h, name, fn := h, name, fn
			wg.Add(1)
			if err := d.Pool.Submit(ctx, func() {
				defer wg.Done()
				if f, ok := finding(name, h, fn(ctx, d.HTTP, h)); ok {
					emit(f)
				}
			}); err != nil {
				wg.Done()
			}
		}
	}
	wg.Wait()
	return ctx.Err()
}

func finding(source, handle string, ts []time.Time) (models.Finding, bool) {
	if len(ts) < 10 {
		return models.Finding{}, false
	}
	var hours [24]int
	for _, t := range ts {
		hours[t.UTC().Hour()]++
	}
	hs := make([]string, 24)
	for i, v := range hours {
		hs[i] = strconv.Itoa(v)
	}
	d := map[string]string{"handle": handle, "source": source, "events": strconv.Itoa(len(ts)), "hours_utc": strings.Join(hs, ","),
		"first event": ts[len(ts)-1].UTC().Format("2006-01-02"), "last event": ts[0].UTC().Format("2006-01-02")}
	conf := 0.3
	if off, c, ok := geo.InferOffset(hours); ok {
		d["estimated offset"] = geo.OffsetLabel(off)
		d["likely regions"] = strings.Join(geo.OffsetRegions(off), "; ")
		d["offset confidence"] = strconv.FormatFloat(c, 'f', 2, 64)
		conf = c
	} else {
		d["estimated offset"] = "unclear (activity spread over all hours or too few events)"
	}
	d["note"] = "inferred from when the account is active, assuming a normal sleep pattern; shift workers and automation break it"
	return models.Finding{Source: source + " activity hours", Category: "activity", Status: models.StatusFound, Confidence: conf, Details: d}, true
}

func githubTimes(ctx context.Context, c *httpx.Client, h string) []time.Time {
	var out []time.Time
	for page := 1; page <= 3; page++ {
		var ev []struct {
			Created time.Time `json:"created_at"`
		}
		if !getJSON(ctx, c, "https://api.github.com/users/"+h+"/events/public?per_page=100&page="+strconv.Itoa(page), &ev) || len(ev) == 0 {
			break
		}
		for _, e := range ev {
			out = append(out, e.Created)
		}
		if len(ev) < 100 {
			break
		}
	}
	return out
}

func hnTimes(ctx context.Context, c *httpx.Client, h string) []time.Time {
	var r struct {
		Hits []struct {
			At int64 `json:"created_at_i"`
		} `json:"hits"`
	}
	if !getJSON(ctx, c, "https://hn.algolia.com/api/v1/search_by_date?tags=author_"+h+"&hitsPerPage=1000", &r) {
		return nil
	}
	out := make([]time.Time, 0, len(r.Hits))
	for _, x := range r.Hits {
		out = append(out, time.Unix(x.At, 0))
	}
	return out
}

func getJSON(ctx context.Context, c *httpx.Client, u string, out any) bool {
	resp, err := c.Do(ctx, httpx.Request{URL: u, Timeout: 25 * time.Second, MaxBody: 6 << 20, Headers: map[string]string{"Accept": "application/json"}})
	if err != nil || resp.StatusCode != 200 {
		return false
	}
	return json.Unmarshal(resp.Body, out) == nil
}

// sources lists every place whose public timestamps are read.
var sources = map[string]func(context.Context, *httpx.Client, string) []time.Time{
	"GitHub":      githubTimes,
	"Hacker News": hnTimes,
	"Wikipedia":   wikipediaTimes,
	"Codeforces":  codeforcesTimes,
	"Bluesky":     blueskyTimes,
	"Mastodon":    mastodonTimes,
	"Lichess":     lichessTimes,
}

func wikipediaTimes(ctx context.Context, c *httpx.Client, h string) []time.Time {
	var r struct {
		Query struct {
			Contribs []struct {
				Timestamp time.Time `json:"timestamp"`
			} `json:"usercontribs"`
		} `json:"query"`
	}
	if !getJSON(ctx, c, "https://en.wikipedia.org/w/api.php?action=query&list=usercontribs&format=json&uclimit=500&ucprop=timestamp&ucuser="+url.QueryEscape(h), &r) {
		return nil
	}
	var out []time.Time
	for _, x := range r.Query.Contribs {
		out = append(out, x.Timestamp)
	}
	return out
}

func codeforcesTimes(ctx context.Context, c *httpx.Client, h string) []time.Time {
	var r struct {
		Result []struct {
			At int64 `json:"creationTimeSeconds"`
		} `json:"result"`
	}
	if !getJSON(ctx, c, "https://codeforces.com/api/user.status?from=1&count=300&handle="+url.QueryEscape(h), &r) {
		return nil
	}
	var out []time.Time
	for _, x := range r.Result {
		out = append(out, time.Unix(x.At, 0))
	}
	return out
}

func blueskyTimes(ctx context.Context, c *httpx.Client, h string) []time.Time {
	if !strings.Contains(h, ".") {
		h += ".bsky.social"
	}
	var r struct {
		Feed []struct {
			Post struct {
				Record struct {
					Created time.Time `json:"createdAt"`
				} `json:"record"`
			} `json:"post"`
			Reason any `json:"reason"` // set for reposts, whose time is not the author's own
		} `json:"feed"`
	}
	if !getJSON(ctx, c, "https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed?limit=100&filter=posts_with_replies&actor="+url.QueryEscape(h), &r) {
		return nil
	}
	var out []time.Time
	for _, x := range r.Feed {
		if x.Reason == nil {
			out = append(out, x.Post.Record.Created)
		}
	}
	return out
}

var mastodonHosts = []string{"mastodon.social", "mstdn.social", "fosstodon.org", "infosec.exchange", "hachyderm.io", "mas.to"}

func mastodonTimes(ctx context.Context, c *httpx.Client, h string) []time.Time {
	for _, host := range mastodonHosts {
		var acct struct {
			ID string `json:"id"`
		}
		if !getJSON(ctx, c, "https://"+host+"/api/v1/accounts/lookup?acct="+url.QueryEscape(h), &acct) || acct.ID == "" {
			continue
		}
		var st []struct {
			Created time.Time `json:"created_at"`
		}
		if !getJSON(ctx, c, "https://"+host+"/api/v1/accounts/"+acct.ID+"/statuses?limit=40&exclude_reblogs=true", &st) {
			continue
		}
		var out []time.Time
		for _, x := range st {
			out = append(out, x.Created)
		}
		return out
	}
	return nil
}

func lichessTimes(ctx context.Context, c *httpx.Client, h string) []time.Time {
	resp, err := c.Do(ctx, httpx.Request{URL: "https://lichess.org/api/games/user/" + url.PathEscape(h) + "?max=300&moves=false&tags=false",
		Timeout: 30 * time.Second, MaxBody: 6 << 20, Headers: map[string]string{"Accept": "application/x-ndjson"}})
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	var out []time.Time
	for _, line := range strings.Split(string(resp.Body), "\n") {
		var g struct {
			At int64 `json:"createdAt"`
		}
		if json.Unmarshal([]byte(line), &g) == nil && g.At > 0 {
			out = append(out, time.UnixMilli(g.At))
		}
	}
	return out
}
