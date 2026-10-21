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
		Company: env("RECTOOL_LIVE_COMPANY", ""), Location: env("RECTOOL_LIVE_LOCATION", ""),
	}
	if os.Getenv("RECTOOL_LIVE_BLANK") == "1" { // only what RECTOOL_LIVE_* explicitly sets
		tg = models.Target{Username: os.Getenv("RECTOOL_LIVE_USER"), Email: os.Getenv("RECTOOL_LIVE_EMAIL"), Domain: os.Getenv("RECTOOL_LIVE_DOMAIN"),
			FullName: os.Getenv("RECTOOL_LIVE_NAME"), Company: os.Getenv("RECTOOL_LIVE_COMPANY"), Location: os.Getenv("RECTOOL_LIVE_LOCATION")}
	}
	if os.Getenv("RECTOOL_LIVE_NOUSER") == "1" {
		tg.Username, tg.Email = "", ""
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
	if os.Getenv("RECTOOL_LIVE_SOURCES") == "1" {
		for _, f := range rep.Findings {
			if f.Module != "social" && f.Status != models.StatusNotFound {
				t.Logf("SRC %s/%s [%s] %s", f.Module, f.Source, f.Status, f.Details["error"])
			}
		}
	}
	t.Logf("findings=%d entities=%d photos=%d failures=%d leads=%d", len(rep.Findings), len(rep.Entities), len(rep.Photos), len(rep.Failures), len(rep.ManualLeads))
	for _, k := range keys {
		t.Logf("  %-32s %d", k, cats[k])
	}
	for _, p := range rep.Photos {
		t.Logf("photo group=%d %dx%d %s <- %s", p.Group, p.Width, p.Height, p.URL, strings.Join(p.Sources, " | "))
	}
	if g := rep.Geo; g != nil {
		t.Logf("GEO consensus=%q conflict=%q given=%q fit=%s", g.Consensus, g.Conflict, g.Given, g.GivenFit)
		for _, p := range g.Points {
			t.Logf("  point %-14s %-9s w=%.2f %s -> %.3f,%.3f %s", p.Kind, p.Precision, p.Weight, p.Label, p.Lat, p.Lon, p.Country)
		}
		for _, c := range g.Clusters {
			t.Logf("  cluster %.2f %s kinds=%v", c.Score, c.Label, c.Kinds)
		}
		if g.TZ != nil {
			t.Logf("  tz %s conf=%.2f events=%d %v", g.TZ.Label, g.TZ.Confidence, g.TZ.Events, g.TZ.Regions)
		}
		for _, n := range g.Notes {
			t.Logf("  note: %s", n)
		}
	}
	t.Logf("ambiguity: %q", rep.Ambiguity)
	for _, id := range rep.Identities {
		var plats []string
		for _, r := range id.Records {
			plats = append(plats, r.Platform)
		}
		t.Logf("IDENTITY #%d score=%.2f primary=%v matched=%v :: %s", id.ID, id.Score, id.Primary, id.Matched, id.Label)
		t.Logf("    records=%v", plats)
		show := func(name string, facts []models.Fact) {
			var v []string
			for i, f := range facts {
				if i >= 4 {
					break
				}
				mark := ""
				if f.Confirmed {
					mark = "✔"
				}
				v = append(v, f.Value+mark)
			}
			if len(v) > 0 {
				t.Logf("    %-10s %s", name, strings.Join(v, " | "))
			}
		}
		show("employers", id.Employers)
		show("locations", id.Locations)
		show("emails", id.Emails)
		show("education", id.Education)
		show("interests", id.Interests)
		show("websites", id.Websites)
		show("usernames", id.Usernames)
		if len(id.Docs) > 0 {
			t.Logf("    CV docs: %v", id.Docs)
		}
	}
	for _, f := range rep.Findings {
		if f.Module == "photos" {
			t.Logf("PHOTO MATCH: %s :: %s", f.Source, f.Details["sources"])
		}
	}
}
