// Package engine is the core controller. It enriches the operator's inputs,
// picks which registered modules apply, runs them concurrently on a shared
// worker pool, aggregates their findings into a Report, and then follows the
// strongest new leads (emails, domains, IPs, usernames) in a second pass.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/intel"
	"github.com/sudosoc/rectool/internal/leads"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/pool"
	"github.com/sudosoc/rectool/internal/scanner"
)

const (
	ToolName = "rectool"
	Version  = "0.2.0"
)

var (
	ErrNoInput      = errors.New("no input supplied: provide at least one of name, username, email, phone, domain, IP or company")
	ErrNothingToRun = errors.New("no module is applicable to the supplied inputs")
)

// pivotModules says which modules investigate a newly discovered entity type.
// Pivoting is deliberately narrow: it deepens what was found rather than
// re-running every module on every lead.
var pivotModules = map[string][]string{
	models.EntEmail:    {"footprint"},
	models.EntDomain:   {"domain"},
	models.EntIP:       {"ip"},
	models.EntUsername: {"social", "profiles"},
}

// Config controls an engine run.
type Config struct {
	Workers        int      // concurrent tasks in the shared pool (default 200)
	QueueSize      int      // pending-task buffer (default 4*Workers)
	Modules        []string // restrict to these module names; empty = all applicable
	DeriveFromName bool     // derive candidate usernames from the full name
	MaxAliases     int      // cap on derived usernames (default 6)
	KeepAll        bool     // retain not_found/error findings in the report
	Pivot          bool     // follow strong discovered entities
	MaxPivots      int      // cap on followed entities over the whole run (default 10)
	PivotDepth     int      // how many rounds of following (default 2: input -> lead -> lead of the lead)
}

// Engine wires scanners, the HTTP client and the worker pool together.
type Engine struct {
	cfg      Config
	http     *httpx.Client
	scanners []scanner.Scanner

	// Optional live hooks, called from internal goroutines (must be
	// concurrency-safe). Set before Run.
	OnFinding  func(models.Finding)
	OnProgress func(module string, done, total int)

	// Meta is copied into Report.Settings (set by the application so reports
	// record how they were produced).
	Meta map[string]string
}

// New creates an engine around an already-configured HTTP client.
func New(cfg Config, c *httpx.Client) *Engine {
	if cfg.Workers <= 0 {
		cfg.Workers = 200
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = cfg.Workers * 4
	}
	if cfg.MaxAliases <= 0 {
		cfg.MaxAliases = 6
	}
	if cfg.MaxPivots <= 0 {
		cfg.MaxPivots = 10
	}
	if cfg.PivotDepth <= 0 {
		cfg.PivotDepth = 2
	}
	return &Engine{cfg: cfg, http: c}
}

// Register adds a module. Call before Run.
func (e *Engine) Register(s scanner.Scanner) { e.scanners = append(e.scanners, s) }

// Scanners lists registered modules (for -list-modules).
func (e *Engine) Scanners() []scanner.Scanner { return e.scanners }

// Plan returns the modules that will run for t, plus a human-readable list of
// those skipped and why.
func (e *Engine) Plan(t models.Target) (run []scanner.Scanner, skipped []string, err error) {
	return e.plan(t, e.cfg.Modules)
}

func (e *Engine) plan(t models.Target, only []string) (run []scanner.Scanner, skipped []string, err error) {
	want := map[string]bool{}
	for _, m := range only {
		want[strings.ToLower(strings.TrimSpace(m))] = true
	}
	known := map[string]bool{}
	for _, s := range e.scanners {
		known[s.Name()] = true
	}
	for m := range want {
		if m != "" && !known[m] {
			return nil, nil, fmt.Errorf("unknown module %q", m)
		}
	}
	for _, s := range e.scanners {
		switch {
		case len(want) > 0 && !want[s.Name()]:
			skipped = append(skipped, s.Name()+": not selected")
		case !s.CanRun(t):
			skipped = append(skipped, s.Name()+": required input not provided")
		default:
			run = append(run, s)
		}
	}
	return run, skipped, nil
}

func statusRank(s models.Status) int {
	switch s {
	case models.StatusFound:
		return 0
	case models.StatusUncertain:
		return 1
	case models.StatusNotFound:
		return 2
	default:
		return 3
	}
}

type counts struct{ checked, found, errors int }

// Run executes the plan for t, then (if enabled) follows the strongest new
// leads once. If ctx is cancelled mid-run the partial report is still returned
// with Interrupted set.
func (e *Engine) Run(ctx context.Context, t models.Target) (*models.Report, error) {
	if t.IsEmpty() {
		return nil, ErrNoInput
	}
	if err := Enrich(&t, e.cfg.DeriveFromName, e.cfg.MaxAliases); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}
	mods, skipped, err := e.Plan(t)
	if err != nil {
		return nil, err
	}
	if len(mods) == 0 {
		return nil, ErrNothingToRun
	}

	rep := &models.Report{
		Tool: ToolName, Version: Version, Target: t,
		StartedAt: time.Now().UTC(), Skipped: skipped,
	}
	e.runTarget(ctx, t, mods, "", rep)

	if e.cfg.Pivot {
		seen := seedSeen(rep.Target)
		budget := e.cfg.MaxPivots
		for depth := 0; depth < e.cfg.PivotDepth && budget > 0 && ctx.Err() == nil; depth++ {
			ps := e.pivots(rep, seen, budget)
			if len(ps) == 0 {
				break
			}
			for _, p := range ps {
				if ctx.Err() != nil {
					break
				}
				allowed := p.modules
				if len(e.cfg.Modules) > 0 { // honour an explicit -modules restriction
					allowed = intersect(p.modules, e.cfg.Modules)
				}
				pm, _, perr := e.plan(p.target, allowed)
				if perr != nil || len(pm) == 0 || len(allowed) == 0 {
					continue
				}
				budget--
				e.runTarget(ctx, p.target, pm, p.via, rep)
			}
		}
	}

	rep.Entities = collectEntities(rep)
	e.photoStage(ctx, rep)
	rep.ManualLeads = leads.Build(rep.Target)
	rep.Interrupted = ctx.Err() != nil
	rep.FinishedAt = time.Now().UTC()
	rep.Settings = e.settings()

	sort.SliceStable(rep.Findings, func(a, b int) bool {
		fa, fb := rep.Findings[a], rep.Findings[b]
		if ra, rb := statusRank(fa.Status), statusRank(fb.Status); ra != rb {
			return ra < rb
		}
		if fa.Module != fb.Module {
			return fa.Module < fb.Module
		}
		return strings.ToLower(fa.Source) < strings.ToLower(fb.Source)
	})
	rep.Integrity = digest(rep)
	return rep, nil
}

func (e *Engine) settings() map[string]string {
	m := map[string]string{
		"pivot":            strconv.FormatBool(e.cfg.Pivot),
		"pivot_depth":      strconv.Itoa(e.cfg.PivotDepth),
		"max_pivots":       strconv.Itoa(e.cfg.MaxPivots),
		"derive_from_name": strconv.FormatBool(e.cfg.DeriveFromName),
		"workers":          strconv.Itoa(e.cfg.Workers),
	}
	if len(e.cfg.Modules) > 0 {
		m["modules"] = strings.Join(e.cfg.Modules, ",")
	}
	for k, v := range e.Meta {
		m[k] = v
	}
	return m
}

// digest fingerprints the evidence (target, entities, findings) so a stored
// report can be checked for tampering or accidental edits.
func digest(rep *models.Report) *models.Integrity {
	b, _ := json.Marshal(struct {
		Target   models.Target    `json:"target"`
		Entities []models.Entity  `json:"entities"`
		Findings []models.Finding `json:"findings"`
	}{rep.Target, rep.Entities, rep.Findings})
	sum := sha256.Sum256(b)
	return &models.Integrity{Algorithm: "sha256", Digest: hex.EncodeToString(sum[:]),
		Findings: len(rep.Findings), Entities: len(rep.Entities)}
}

// runTarget runs mods against one target on a fresh pool and appends the
// results to rep. via is empty for the primary run, or "type:value" for a pivot.
func (e *Engine) runTarget(ctx context.Context, t models.Target, mods []scanner.Scanner, via string, rep *models.Report) {
	wp := pool.New(e.cfg.Workers, e.cfg.QueueSize)

	label := func(name string) string {
		if via == "" {
			return name
		}
		return name + " ↳ " + via
	}
	var progress func(string, int, int)
	if e.OnProgress != nil {
		progress = func(module string, done, total int) { e.OnProgress(label(module), done, total) }
	}
	deps := scanner.Deps{HTTP: e.http, Pool: wp, Progress: progress}

	// Single collector goroutine owns the findings and counters, so no
	// locking is needed on the hot path.
	findings := make(chan models.Finding, 512)
	perModule := map[string]*counts{}
	for _, m := range mods {
		perModule[m.Name()] = &counts{}
	}
	var kept []models.Finding
	var failed []models.Failure
	var collector sync.WaitGroup
	collector.Add(1)
	go func() {
		defer collector.Done()
		for f := range findings {
			c := perModule[f.Module]
			c.checked++
			switch f.Status {
			case models.StatusFound:
				c.found++
			case models.StatusError:
				c.errors++
				if len(failed) < maxFailures {
					failed = append(failed, models.Failure{Module: f.Module, Source: f.Source, Via: f.Via,
						Error: f.Details["error"]})
				}
			}
			positive := f.Status == models.StatusFound || f.Status == models.StatusUncertain
			if positive || e.cfg.KeepAll {
				kept = append(kept, f)
			}
			if positive && e.OnFinding != nil {
				e.OnFinding(f)
			}
		}
	}()

	runs := make([]models.ModuleRun, len(mods))
	var wg sync.WaitGroup
	for i, m := range mods {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			emit := func(f models.Finding) {
				f.Module = m.Name()
				f.Via = via
				if f.Timestamp.IsZero() {
					f.Timestamp = time.Now().UTC()
				}
				if f.Status == models.StatusFound || f.Status == models.StatusUncertain {
					addImageEntities(&f)
				}
				for k := range f.Entities {
					f.Entities[k].Source = m.Name() + ": " + f.Source
				}
				select {
				case findings <- f:
				case <-ctx.Done():
				}
			}
			var scanErr error
			func() {
				defer func() {
					if r := recover(); r != nil {
						scanErr = fmt.Errorf("panic: %v\n%s", r, debug.Stack())
					}
				}()
				scanErr = m.Scan(ctx, t, deps, emit)
			}()
			runs[i] = models.ModuleRun{Name: m.Name(), Via: via, DurationMS: time.Since(start).Milliseconds()}
			if scanErr != nil && !errors.Is(scanErr, context.Canceled) {
				runs[i].Error = scanErr.Error()
			}
		}()
	}
	wg.Wait()
	wp.Close()
	close(findings)
	collector.Wait()

	for i := range runs {
		c := perModule[runs[i].Name]
		runs[i].Checked, runs[i].Found, runs[i].Errors = c.checked, c.found, c.errors
	}
	rep.Modules = append(rep.Modules, runs...)
	rep.Findings = append(rep.Findings, kept...)
	rep.Failures = append(rep.Failures, failed...)
}

const maxFailures = 400

type pivot struct {
	target  models.Target
	modules []string
	via     string
}

// seedSeen marks the identifiers the operator supplied as already investigated.
func seedSeen(t models.Target) map[string]bool {
	seen := map[string]bool{}
	mark := func(typ, v string) {
		if v != "" {
			seen[typ+":"+strings.ToLower(v)] = true
		}
	}
	mark(models.EntEmail, t.Email)
	mark(models.EntDomain, t.Domain)
	mark(models.EntIP, t.IP)
	for _, u := range t.Usernames() {
		mark(models.EntUsername, u)
	}
	return seen
}

// pivots picks the strongest not-yet-followed entities found so far and marks
// them seen. A strong e-mail on a non-public domain also yields that domain.
func (e *Engine) pivots(rep *models.Report, seen map[string]bool, limit int) []pivot {
	byType := map[string][]models.Entity{}
	add := func(ent models.Entity) {
		if len(pivotModules[ent.Type]) == 0 {
			return
		}
		k := ent.Type + ":" + strings.ToLower(ent.Value)
		if seen[k] {
			return
		}
		seen[k] = true
		byType[ent.Type] = append(byType[ent.Type], ent)
	}
	for _, ent := range collectEntities(rep) {
		if !ent.Strong {
			continue
		}
		add(ent)
		if ent.Type == models.EntEmail {
			if _, d, ok := strings.Cut(ent.Value, "@"); ok && !intel.IsFreeMail(d) && !intel.IsDisposable(d) {
				if nd, ok := intel.NormalizeDomain(d); ok {
					add(models.Entity{Type: models.EntDomain, Value: nd, Strong: true, Source: "e-mail domain of " + ent.Value})
				}
			}
		}
	}

	var out []pivot
	// Priority: emails and domains are the richest leads.
	for _, typ := range []string{models.EntEmail, models.EntDomain, models.EntIP, models.EntUsername} {
		for _, ent := range byType[typ] {
			if len(out) >= limit {
				return out
			}
			var nt models.Target
			switch typ {
			case models.EntEmail:
				nt.Email = ent.Value
			case models.EntDomain:
				nt.Domain = ent.Value
			case models.EntIP:
				nt.IP = ent.Value
			case models.EntUsername:
				nt.Username = ent.Value
			}
			out = append(out, pivot{target: nt, modules: pivotModules[typ], via: typ + ":" + ent.Value})
		}
	}
	return out
}

// collectEntities returns every distinct entity mentioned by the report's
// findings (first source wins), strong ones first.
func collectEntities(rep *models.Report) []models.Entity {
	seen := map[string]int{}
	var out []models.Entity
	for _, f := range rep.Findings {
		for _, ent := range f.Entities {
			k := ent.Type + ":" + strings.ToLower(ent.Value)
			if i, dup := seen[k]; dup {
				out[i].Strong = out[i].Strong || ent.Strong
				continue
			}
			seen[k] = len(out)
			out = append(out, ent)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Strong != out[j].Strong {
			return out[i].Strong
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func intersect(a, b []string) []string {
	set := map[string]bool{}
	for _, x := range b {
		set[strings.ToLower(strings.TrimSpace(x))] = true
	}
	var out []string
	for _, x := range a {
		if set[x] {
			out = append(out, x)
		}
	}
	return out
}
