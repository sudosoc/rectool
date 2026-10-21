// Package app assembles a ready-to-run engine (HTTP client, shared searcher,
// all modules) from one Options value. The CLI and the web UI both build
// engines through it, so they always behave identically.
package app

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/sudosoc/rectool/internal/engine"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/modules/activity"
	"github.com/sudosoc/rectool/internal/modules/asn"
	"github.com/sudosoc/rectool/internal/modules/bizreg"
	"github.com/sudosoc/rectool/internal/modules/breach"
	"github.com/sudosoc/rectool/internal/modules/company"
	"github.com/sudosoc/rectool/internal/modules/crypto"
	"github.com/sudosoc/rectool/internal/modules/devtrace"
	"github.com/sudosoc/rectool/internal/modules/docmeta"
	"github.com/sudosoc/rectool/internal/modules/domain"
	"github.com/sudosoc/rectool/internal/modules/dorks"
	"github.com/sudosoc/rectool/internal/modules/footprint"
	"github.com/sudosoc/rectool/internal/modules/images"
	"github.com/sudosoc/rectool/internal/modules/ip"
	"github.com/sudosoc/rectool/internal/modules/mentions"
	"github.com/sudosoc/rectool/internal/modules/people"
	"github.com/sudosoc/rectool/internal/modules/phone"
	"github.com/sudosoc/rectool/internal/modules/profiles"
	"github.com/sudosoc/rectool/internal/modules/records"
	"github.com/sudosoc/rectool/internal/modules/sitefiles"
	"github.com/sudosoc/rectool/internal/modules/social"
	"github.com/sudosoc/rectool/internal/modules/syswrap"
)

// Options is the complete configuration of one engine.
type Options struct {
	// engine / transport
	Workers    int
	Timeout    time.Duration
	Retries    int
	Proxies    []string
	Insecure   bool
	InFlight   int // max simultaneous HTTP requests (0 = default)
	Modules    []string
	Derive     bool
	KeepAll    bool
	NoPivot    bool // do not follow discovered emails/domains/IPs/usernames
	MaxPivots  int
	PivotDepth int
	Browser    bool // read LinkedIn public profiles with the local headless browser when HTTP is refused
	Aggressive bool // maximum coverage: derive usernames, verify hits, deeper/wider pivoting, more dorks

	// social
	SitesFile  string
	Categories []string
	Verify     bool
	AllSites   bool // ignore the list of sites disabled by -selftest-sites

	// dorks / footprint
	NoWayback   bool // skip the Internet Archive query in the domain module
	DorkEngines []string
	DorkDelay   time.Duration
	MaxDorks    int
	Searcher    *dorks.Searcher // optional: share rate-limit state across engines

	// syswrap
	Tools       []string
	ToolsFile   string
	ToolTimeout time.Duration
}

// Defaults returns the options used when a flag or UI field is left unset.
func Defaults() Options {
	return Options{
		Workers: 200, Timeout: 12 * time.Second, Retries: 1,
		DorkEngines: []string{"brave", "bing", "duckduckgo", "google"},
		DorkDelay:   3 * time.Second, MaxDorks: 60, MaxPivots: 10, PivotDepth: 2,
	}
}

// Built is an engine plus a few facts about how it was configured.
type Built struct {
	Engine      *engine.Engine
	SocialSites int
}

// Build wires every module into a new engine. New modules are registered here,
// once, for both front ends.
func Build(o Options) (*Built, error) {
	o = o.applyPreset()
	httpClient, err := httpx.New(httpx.Options{
		Timeout: o.Timeout, Retries: o.Retries, Proxies: o.Proxies, InsecureTLS: o.Insecure, MaxInFlight: o.InFlight,
	})
	if err != nil {
		return nil, err
	}
	eng := engine.New(engine.Config{
		Workers: o.Workers, Modules: o.Modules, DeriveFromName: o.Derive, KeepAll: o.KeepAll,
		Pivot: !o.NoPivot, MaxPivots: o.MaxPivots, PivotDepth: o.PivotDepth,
	}, httpClient)

	eng.Meta = map[string]string{
		"aggressive": strconv.FormatBool(o.Aggressive), "verify_social": strconv.FormatBool(o.Verify),
		"browser": strconv.FormatBool(o.Browser), "proxies": strconv.Itoa(len(o.Proxies)), "wayback": strconv.FormatBool(!o.NoWayback),
	}

	socialMod, err := social.New(social.Config{
		SitesFile: ResolveSites(o.SitesFile), Categories: o.Categories, Verify: o.Verify,
		DisabledFile: disabledFile(o.AllSites),
	})
	if err != nil {
		return nil, fmt.Errorf("social module: %w", err)
	}
	eng.Register(socialMod)

	// One Searcher is shared so dorks and footprint together respect the
	// per-engine rate limit and blocked-engine state.
	searcher := o.Searcher
	if searcher == nil {
		if searcher, err = dorks.NewSearcher(o.DorkEngines, o.DorkDelay); err != nil {
			return nil, fmt.Errorf("search engines: %w", err)
		}
	}
	dorkMod, err := dorks.New(dorks.Config{Searcher: searcher, MaxDorks: o.MaxDorks})
	if err != nil {
		return nil, fmt.Errorf("dorks module: %w", err)
	}
	eng.Register(dorkMod)

	footMod, err := footprint.New(footprint.Config{Searcher: searcher})
	if err != nil {
		return nil, fmt.Errorf("footprint module: %w", err)
	}
	eng.Register(footMod)

	sysMod, err := syswrap.New(syswrap.Config{Tools: o.Tools, ToolsFile: o.ToolsFile, TimeoutCap: o.ToolTimeout})
	if err != nil {
		return nil, fmt.Errorf("syswrap module: %w", err)
	}
	eng.Register(sysMod)

	eng.Register(domain.New(domain.Config{Wayback: !o.NoWayback}))
	eng.Register(ip.New())
	eng.Register(profiles.New())
	eng.Register(company.New())
	eng.Register(people.New(people.Config{Searcher: searcher, Browser: o.Browser}))
	eng.Register(images.New())
	eng.Register(breach.New())
	eng.Register(sitefiles.New())
	eng.Register(bizreg.New())
	eng.Register(mentions.New())
	eng.Register(devtrace.New())
	eng.Register(docmeta.New())
	eng.Register(records.New())
	eng.Register(activity.New())
	eng.Register(phone.New())
	eng.Register(crypto.New())
	eng.Register(asn.New())

	return &Built{Engine: eng, SocialSites: socialMod.SiteCount()}, nil
}

// ResolveSites returns the explicit sites path, or the first installed
// WhatsMyName list found in the standard Linux data locations (placed there by
// install.sh), or "" to fall back to the small embedded list.
func ResolveSites(explicit string) string {
	if explicit != "" {
		return explicit
	}
	var dirs []string
	if d := os.Getenv("RECTOOL_DATA"); d != "" {
		dirs = append(dirs, d)
	}
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		dirs = append(dirs, x+"/rectool")
	} else if h, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, h+"/.local/share/rectool")
	}
	dirs = append(dirs, "/usr/local/share/rectool", "/usr/share/rectool")
	for _, d := range dirs {
		p := d + "/wmn-data.json"
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return p
		}
	}
	return ""
}

// applyPreset expands Aggressive into the individual knobs (only raising them,
// never lowering something the operator set explicitly).
func (o Options) applyPreset() Options {
	if !o.Aggressive {
		return o
	}
	o.Derive = true
	o.Verify = true
	if o.MaxPivots < 25 {
		o.MaxPivots = 25
	}
	if o.PivotDepth < 3 {
		o.PivotDepth = 3
	}
	if o.MaxDorks < 120 {
		o.MaxDorks = 120
	}
	return o
}

// DataDir is where rectool keeps downloaded/generated data: $RECTOOL_DATA,
// else $XDG_DATA_HOME/rectool, else ~/.local/share/rectool.
func DataDir() string {
	if d := os.Getenv("RECTOOL_DATA"); d != "" {
		return d
	}
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return x + "/rectool"
	}
	if h, err := os.UserHomeDir(); err == nil {
		return h + "/.local/share/rectool"
	}
	return ""
}

// DisabledSitesPath is the file written by the site self-test.
func DisabledSitesPath() string {
	if d := DataDir(); d != "" {
		return d + "/sites-disabled.json"
	}
	return ""
}

func disabledFile(all bool) string {
	if all {
		return ""
	}
	return DisabledSitesPath()
}
