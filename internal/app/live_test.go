package app

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sudosoc/rectool/internal/models"
)

// TestLiveAudit runs the real engine against the live internet. It is skipped
// unless RECTOOL_LIVE=1, and is meant for a manual coverage audit:
//
//	RECTOOL_LIVE=1 go test ./internal/app -run TestLiveAudit -v -timeout 15m
//
// Inputs come from RECTOOL_LIVE_USER / _EMAIL / _DOMAIN / _NAME (defaults are a
// well-known public figure).
func TestLiveAudit(t *testing.T) {
	if os.Getenv("RECTOOL_LIVE") != "1" {
		t.Skip("set RECTOOL_LIVE=1 to run the live audit")
	}
	env := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	tg := models.Target{
		Username: env("RECTOOL_LIVE_USER", "torvalds"), Email: env("RECTOOL_LIVE_EMAIL", "torvalds@linux-foundation.org"),
		Domain: env("RECTOOL_LIVE_DOMAIN", ""), FullName: env("RECTOOL_LIVE_NAME", "Linus Torvalds"),
	}
	opts := Defaults()
	opts.NoWayback = true
	opts.DorkDelay = time.Second
	opts.MaxDorks = 10
	opts.Modules = strings.Split(env("RECTOOL_LIVE_MODULES", "profiles,footprint,people,social"), ",")
	built, err := Build(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	rep, err := built.Engine.Run(ctx, tg)
	if err != nil {
		t.Fatal(err)
	}

	cats := map[string]int{}
	for _, f := range rep.Findings {
		cats[f.Module+"/"+f.Category]++
	}
	var keys []string
	for k := range cats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Logf("findings=%d entities=%d photos=%d failures=%d leads=%d", len(rep.Findings), len(rep.Entities), len(rep.Photos), len(rep.Failures), len(rep.ManualLeads))
	for _, k := range keys {
		t.Logf("  %-32s %d", k, cats[k])
	}
	for _, p := range rep.Photos {
		t.Logf("photo group=%d %dx%d %s <- %s", p.Group, p.Width, p.Height, p.URL, strings.Join(p.Sources, " | "))
	}
	for _, f := range rep.Findings {
		if f.Module == "photos" {
			t.Logf("PHOTO MATCH: %s :: %s", f.Source, f.Details["sources"])
		}
	}
}
