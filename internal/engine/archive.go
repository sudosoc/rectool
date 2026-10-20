package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
)

// archiveStage asks the Internet Archive when each profile page of the best
// match, and the target's own site, was first and last captured and how many
// months it was captured in. It shows how long an account has existed, and
// leaves a trail when a profile was later deleted or renamed.
func (e *Engine) archiveStage(ctx context.Context, rep *models.Report) {
	urls := map[string]bool{}
	var order []string
	add := func(u string) {
		if strings.HasPrefix(u, "http") && !urls[u] && len(order) < 10 {
			urls[u] = true
			order = append(order, u)
		}
	}
	for _, id := range rep.Identities {
		if id.Weak {
			continue
		}
		for _, r := range id.Records {
			add(r.URL)
		}
		break
	}
	if d := strings.TrimSpace(rep.Target.Domain); d != "" {
		add("https://" + d + "/")
	}
	for _, l := range rep.Target.Links {
		add(l)
	}
	if len(order) == 0 || ctx.Err() != nil {
		return
	}
	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		sem = make(chan struct{}, 3)
	)
	for _, u := range order {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer func() { <-sem; wg.Done() }()
			first := cdx(ctx, e.http, u, "limit=1")
			if first == "" {
				return
			}
			last := cdx(ctx, e.http, u, "limit=-1")
			months := cdxCount(ctx, e.http, u)
			d := map[string]string{"page": u, "first archived": isoFromTS(first), "last archived": isoFromTS(last), "months with snapshots": fmt.Sprint(months),
				"note": "Internet Archive captures; a page last archived long ago may have been deleted or renamed"}
			f := models.Finding{Module: "archive", Source: "Archive history: " + shortURL(u), Category: "archive", URL: "https://web.archive.org/web/*/" + u,
				Status: models.StatusFound, Confidence: 0.9, Details: d, Timestamp: time.Now().UTC()}
			mu.Lock()
			rep.Findings = append(rep.Findings, f)
			mu.Unlock()
			if e.OnFinding != nil {
				e.OnFinding(f)
			}
		}(u)
	}
	wg.Wait()
}

func isoFromTS(ts string) string {
	if len(ts) >= 8 {
		return ts[:4] + "-" + ts[4:6] + "-" + ts[6:8]
	}
	return ts
}

func cdx(ctx context.Context, c *httpx.Client, u, extra string) string {
	resp, err := c.Do(ctx, httpx.Request{URL: "https://web.archive.org/cdx/search/cdx?output=json&fl=timestamp&" + extra + "&url=" + url.QueryEscape(u), Timeout: 30 * time.Second})
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	var rows [][]string
	if json.Unmarshal(resp.Body, &rows) != nil || len(rows) < 2 || len(rows[1]) == 0 {
		return ""
	}
	return rows[1][0]
}

func cdxCount(ctx context.Context, c *httpx.Client, u string) int {
	resp, err := c.Do(ctx, httpx.Request{URL: "https://web.archive.org/cdx/search/cdx?output=json&fl=timestamp&collapse=timestamp:6&limit=1000&url=" + url.QueryEscape(u), Timeout: 30 * time.Second})
	if err != nil || resp.StatusCode != 200 {
		return 0
	}
	var rows [][]string
	if json.Unmarshal(resp.Body, &rows) != nil || len(rows) < 2 {
		return 0
	}
	return len(rows) - 1
}
