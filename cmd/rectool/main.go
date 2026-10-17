// Command rectool is an API-less OSINT reconnaissance tool (CLI and web UI).
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sudosoc/rectool/internal/app"
	"github.com/sudosoc/rectool/internal/engine"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/modules/social"
	"github.com/sudosoc/rectool/internal/output"
	"github.com/sudosoc/rectool/internal/web"
)

func main() { os.Exit(run()) }

func run() int {
	def := app.Defaults()
	var (
		fullName = flag.String("n", "", "full name")
		username = flag.String("u", "", "username / handle")
		email    = flag.String("e", "", "email address")
		phone    = flag.String("p", "", "phone number (international format, e.g. +15551234567)")
		domain   = flag.String("d", "", "domain, website or social-profile URL")
		ipAddr   = flag.String("ip", "", "IP address")
		company  = flag.String("c", "", "company / organisation name")
		location = flag.String("l", "", "location (city / country) to focus searches")
		alias    = flag.String("a", "", "nickname / alias / known-as")
		asnFlag  = flag.String("asn", "", "autonomous system number, e.g. AS13335")
		wallet   = flag.String("w", "", "Bitcoin or Ethereum wallet address")
		aggress  = flag.Bool("aggressive", false, "maximum coverage: derive usernames, verify hits, deeper and wider pivoting, more dorks")
		depth    = flag.Int("pivot-depth", def.PivotDepth, "rounds of following discovered leads")

		webAddr  = flag.String("web", "", "start the web UI on this address instead of scanning (e.g. 127.0.0.1:8080)")
		webToken = flag.String("web-token", "", "access token for the web UI (default: random, printed at startup)")
		webMax   = flag.Int("web-max-scans", 2, "maximum concurrent scans in the web UI")

		modules    = flag.String("modules", "", "comma-separated modules to run (default: all applicable)")
		showVer    = flag.Bool("version", false, "print version and exit")
		listMods   = flag.Bool("list-modules", false, "list modules and exit")
		selfTest   = flag.Bool("selftest-sites", false, "test every social site against a known account, disable unreliable ones, and exit")
		allSites   = flag.Bool("all-sites", false, "use every social site, including ones a self-test disabled")
		workers    = flag.Int("workers", def.Workers, "concurrent workers in the shared pool")
		inflight   = flag.Int("inflight", 0, "maximum simultaneous HTTP requests (default 110; lower it on weak networks)")
		timeout    = flag.Duration("timeout", def.Timeout, "per-request timeout")
		retries    = flag.Int("retries", def.Retries, "retries on transient network errors / 429 / 5xx")
		proxies    = flag.String("proxy", "", "comma-separated proxies (http://, socks5://), rotated round-robin")
		proxyFile  = flag.String("proxy-file", "", "file with one proxy URL per line")
		insecure   = flag.Bool("insecure", false, "skip TLS certificate verification")
		sitesFile  = flag.String("sites", "", "custom site list in WhatsMyName JSON format")
		categories = flag.String("categories", "", "restrict social sites to these categories (comma-separated)")
		verify     = flag.Bool("verify", false, "re-test hits with a random canary username to drop false positives")
		derive     = flag.Bool("derive", false, "derive candidate usernames from the full name")
		noPivot    = flag.Bool("no-pivot", false, "do not follow discovered emails/domains/IPs/usernames")
		maxPivots  = flag.Int("max-pivots", def.MaxPivots, "maximum discovered leads to follow")
		noWayback  = flag.Bool("no-wayback", false, "skip the Internet Archive query (domain module)")
		outDir     = flag.String("o", "", "output directory for reports (omit to skip export)")
		formats    = flag.String("formats", "json,csv,txt", "report formats")
		verbose    = flag.Bool("v", false, "keep not-found/error records in exported reports")
		dorkEngine = flag.String("dork-engines", strings.Join(def.DorkEngines, ","), "search engines for dorking, tried in order")
		maxDorks   = flag.Int("max-dorks", def.MaxDorks, "maximum dorks to run")
		dorkDelay  = flag.Duration("dork-delay", def.DorkDelay, "minimum delay between requests to one search engine")
		tools      = flag.String("tools", "", "external tools for the syswrap module (default: all installed)")
		toolsFile  = flag.String("tools-file", "", "JSON file defining extra external-tool wrappers")
		toolCap    = flag.Duration("tool-timeout", 0, "cap on any external tool runtime (0 = per-tool default)")
		noColor    = flag.Bool("no-color", false, "disable colour output")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: rectool [options]\n       rectool -web 127.0.0.1:8080\n\nAll identifiers are optional; with none given on a terminal you are prompted.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVer {
		fmt.Println("rectool", engine.Version)
		return 0
	}

	ui := output.NewConsole(*noColor)

	proxyList := splitCSV(*proxies)
	if *proxyFile != "" {
		lines, err := readLines(*proxyFile)
		if err != nil {
			ui.Error("proxy file: %v", err)
			return 2
		}
		proxyList = append(proxyList, lines...)
	}

	opts := app.Options{
		Workers: *workers, Timeout: *timeout, Retries: *retries, Proxies: proxyList, Insecure: *insecure, InFlight: *inflight,
		Modules: splitCSV(*modules), Derive: *derive, KeepAll: *verbose,
		NoPivot: *noPivot, MaxPivots: *maxPivots, PivotDepth: *depth, NoWayback: *noWayback, Aggressive: *aggress,
		SitesFile: *sitesFile, Categories: splitCSV(*categories), Verify: *verify,
		DorkEngines: splitCSV(*dorkEngine), DorkDelay: *dorkDelay, MaxDorks: *maxDorks,
		Tools: splitCSV(*tools), ToolsFile: *toolsFile, ToolTimeout: *toolCap,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts.AllSites = *allSites
	if *selfTest {
		return runSelfTest(ctx, ui, opts, *timeout)
	}
	if *webAddr != "" {
		return runWeb(ctx, ui, opts, *webAddr, *webToken, *webMax, *outDir)
	}

	built, err := app.Build(opts)
	if err != nil {
		ui.Error("%v", err)
		return 2
	}
	eng := built.Engine

	if *listMods {
		for _, s := range eng.Scanners() {
			fmt.Printf("%-10s %s\n", s.Name(), s.Description())
		}
		return 0
	}

	target := models.Target{
		FullName: *fullName, Username: *username, Email: *email, Phone: *phone,
		Domain: *domain, IP: *ipAddr, Company: *company, Location: *location,
		Alias: *alias, ASN: *asnFlag, Wallet: *wallet,
	}
	if target.IsEmpty() && isTerminal(os.Stdin) {
		target = promptTarget()
	}

	ui.Banner(engine.Version)
	eng.OnFinding = ui.Finding
	eng.OnProgress = ui.Progress

	ui.Info("loaded %d social platforms, %d workers, %d proxies", built.SocialSites, *workers, len(proxyList))
	rep, err := eng.Run(ctx, target)
	if err != nil {
		ui.Error("%v", err)
		return 1
	}
	ui.Summary(rep)

	if *outDir != "" {
		base := "rectool_" + rep.StartedAt.Format("20060102_150405")
		paths, err := output.Export(rep, *outDir, base, splitCSV(*formats))
		for _, p := range paths {
			ui.Info("wrote %s", p)
		}
		if err != nil {
			ui.Error("export: %v", err)
			return 1
		}
	}
	if rep.Interrupted {
		return 130
	}
	return 0
}

// runSelfTest probes each social site with a known account and a random one,
// prints a verdict summary, and stores the unreliable sites so later scans
// skip them (they would only add false results).
func runSelfTest(ctx context.Context, ui *output.Console, opts app.Options, timeout time.Duration) int {
	opts.AllSites = true
	hc, err := httpx.New(httpx.Options{Timeout: timeout, Retries: 1, Proxies: opts.Proxies})
	if err != nil {
		ui.Error("%v", err)
		return 2
	}
	sm, err := social.New(social.Config{SitesFile: app.ResolveSites(opts.SitesFile)})
	if err != nil {
		ui.Error("%v", err)
		return 2
	}
	sites := sm.Sites()
	ui.Info("self-testing %d sites (one known + one random account each)…", len(sites))
	res := social.SelfTest(ctx, hc, sites, 40, func(done, total int) { ui.Progress("selftest", done, total) })
	if ctx.Err() != nil {
		ui.Warn("interrupted; nothing saved")
		return 130
	}
	counts := map[string]int{}
	var disable []string
	for _, h := range res {
		counts[h.Status]++
		if h.Status == social.HealthBroken || h.Status == social.HealthNoisy {
			disable = append(disable, h.Site)
		}
	}
	ui.Info("ok=%d broken=%d noisy=%d blocked-from-here=%d untested=%d", counts[social.HealthOK], counts[social.HealthBroken],
		counts[social.HealthNoisy], counts[social.HealthBlocked], counts[social.HealthUntested])
	path := app.DisabledSitesPath()
	if path == "" {
		ui.Warn("no data directory; set RECTOOL_DATA to save the result")
		return 1
	}
	if err := social.SaveDisabled(path, disable); err != nil {
		ui.Error("saving %s: %v", path, err)
		return 1
	}
	ui.Info("disabled %d unreliable sites -> %s (use -all-sites to ignore, delete the file to reset)", len(disable), path)
	return 0
}

// runWeb starts the browser UI and blocks until interrupted.
func runWeb(ctx context.Context, ui *output.Console, opts app.Options, addr, token string, maxScans int, reportDir string) int {
	srv, err := web.New(ctx, web.Config{Addr: addr, Token: token, Base: opts, MaxRunning: maxScans, ReportDir: reportDir})
	if err != nil {
		ui.Error("web: %v", err)
		return 2
	}
	ui.Banner(engine.Version)
	if !srv.Loopback() {
		ui.Warn("listening on a non-loopback address: traffic is plain HTTP. Put it behind TLS (reverse proxy / SSH tunnel) and keep the token secret.")
	}
	err = srv.Run(ctx, func() {
		ui.Info("web UI ready — open this URL (contains your access token):")
		fmt.Println("\n    " + srv.URL() + "\n")
		ui.Info("press Ctrl-C to stop")
	})
	if err != nil {
		ui.Error("web: %v", err)
		return 1
	}
	return 0
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, nil
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func promptTarget() models.Target {
	in := bufio.NewReader(os.Stdin)
	ask := func(label string) string {
		fmt.Fprintf(os.Stderr, "%s (Enter to skip): ", label)
		s, _ := in.ReadString('\n')
		return strings.TrimSpace(s)
	}
	return models.Target{
		FullName: ask("Full name"), Username: ask("Username"), Email: ask("Email"), Phone: ask("Phone"),
		Alias: ask("Nickname / alias"), Domain: ask("Domain / website / profile URL"), IP: ask("IP address"),
		ASN: ask("ASN"), Wallet: ask("Crypto wallet"), Company: ask("Company"), Location: ask("Location"),
	}
}
