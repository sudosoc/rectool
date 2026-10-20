package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sudosoc/rectool/internal/app"
	"github.com/sudosoc/rectool/internal/engine"
	"github.com/sudosoc/rectool/internal/identity"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/output"
)

const (
	stateRunning   = "running"
	stateDone      = "done"
	stateCancelled = "cancelled"
	stateFailed    = "failed"
)

// event is one entry of a scan's append-only log, streamed to browsers via SSE.
type event struct {
	Type string `json:"type"` // finding | done | error
	Data any    `json:"data"`
}

// scan is one run of the engine plus everything the UI needs to follow it.
type scan struct {
	ID      string
	Target  models.Target
	Created time.Time

	mu       sync.Mutex
	state    string
	errMsg   string
	events   []event
	notify   chan struct{} // closed and replaced whenever events grows
	progress map[string][2]int
	hits     int
	report   *models.Report
	all      []models.Finding // positive findings so far, for live identity resolution
	cancel   context.CancelFunc
}

func (sc *scan) push(ev event) {
	sc.mu.Lock()
	sc.events = append(sc.events, ev)
	close(sc.notify)
	sc.notify = make(chan struct{})
	sc.mu.Unlock()
}

// finish records the final state and appends the closing event in one critical
// section, so a streaming client can never observe "finished" without also
// being able to read the final event.
func (sc *scan) finish(state, errMsg string, rep *models.Report, ev event) {
	sc.mu.Lock()
	sc.state, sc.errMsg, sc.report = state, errMsg, rep
	sc.events = append(sc.events, ev)
	close(sc.notify)
	sc.notify = make(chan struct{})
	sc.mu.Unlock()
}

func (sc *scan) setProgress(module string, done, total int) {
	sc.mu.Lock()
	sc.progress[module] = [2]int{done, total}
	sc.mu.Unlock()
}

// snapshot is a consistent copy of the mutable parts of a scan.
type snapshot struct {
	events   []event
	notify   chan struct{}
	progress map[string][2]int
	state    string
}

func (sc *scan) snapshotFrom(idx int) snapshot {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	s := snapshot{notify: sc.notify, state: sc.state, progress: make(map[string][2]int, len(sc.progress))}
	if idx < len(sc.events) {
		s.events = append([]event(nil), sc.events[idx:]...)
	}
	for k, v := range sc.progress {
		s.progress[k] = v
	}
	return s
}

// Summary is the list/detail representation sent to the browser.
type Summary struct {
	ID       string            `json:"id"`
	State    string            `json:"state"`
	Error    string            `json:"error,omitempty"`
	Target   models.Target     `json:"target"`
	Created  time.Time         `json:"created"`
	Hits     int               `json:"hits"`
	Progress map[string][2]int `json:"progress"`
}

func (sc *scan) summary() Summary {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	p := make(map[string][2]int, len(sc.progress))
	for k, v := range sc.progress {
		p[k] = v
	}
	return Summary{ID: sc.ID, State: sc.state, Error: sc.errMsg, Target: sc.Target,
		Created: sc.Created, Hits: sc.hits, Progress: p}
}

func (sc *scan) finished() bool {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.state != stateRunning
}

// ScanRequest is the JSON body of POST /api/scans. Only a safe subset of the
// engine options is exposed to the browser; paths and external-tool settings
// stay under the operator's command-line control.
type ScanRequest struct {
	FullName   string   `json:"full_name"`
	Username   string   `json:"username"`
	Email      string   `json:"email"`
	Phone      string   `json:"phone"`
	Domain     string   `json:"domain"`
	IP         string   `json:"ip"`
	Company    string   `json:"company"`
	Location   string   `json:"location"`
	Alias      string   `json:"alias"`
	Notes      string   `json:"notes"`
	ASN        string   `json:"asn"`
	Wallet     string   `json:"wallet"`
	Modules    []string `json:"modules"`
	Aggressive bool     `json:"aggressive"`
	Browser    bool     `json:"browser"`
	Verify     bool     `json:"verify"`
	Derive     bool     `json:"derive"`
	NoPivot    bool     `json:"no_pivot"`
	Proxies    []string `json:"proxies"`
}

var (
	errBusy    = errors.New("too many scans running; wait for one to finish or cancel it")
	errNoInput = errors.New("provide at least one identifier")
)

// manager owns all scans of the server.
type manager struct {
	base       app.Options
	maxRunning int
	maxKept    int
	reportDir  string
	cases      *caseStore

	mu    sync.Mutex
	scans map[string]*scan
	order []string // creation order
	root  context.Context

	imgMu  sync.Mutex
	images map[string]bool // picture URLs discovered by scans: the only ones the image proxy will fetch
}

// addImage records a discovered picture URL so the proxy may serve it.
func (m *manager) addImage(u string) {
	m.imgMu.Lock()
	if m.images == nil {
		m.images = map[string]bool{}
	}
	if len(m.images) < 5000 {
		m.images[u] = true
	}
	m.imgMu.Unlock()
}

func (m *manager) knownImage(u string) bool {
	m.imgMu.Lock()
	defer m.imgMu.Unlock()
	return m.images[u]
}

func newManager(root context.Context, base app.Options, maxRunning int, reportDir string) *manager {
	return &manager{base: base, maxRunning: maxRunning, maxKept: 50, reportDir: reportDir,
		scans: map[string]*scan{}, root: root}
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func validateRequest(r *ScanRequest) error {
	r.Notes = strings.TrimSpace(r.Notes)
	if len(r.Notes) > 30000 {
		return errors.New("pasted text too long (max 30000 characters)")
	}
	for _, f := range []*string{&r.FullName, &r.Username, &r.Email, &r.Phone, &r.Domain, &r.IP, &r.Company, &r.Location, &r.Alias, &r.ASN, &r.Wallet} {
		*f = strings.TrimSpace(*f)
		if len(*f) > 200 {
			return errors.New("field too long (max 200 characters)")
		}
	}
	if len(r.Proxies) > 50 {
		return errors.New("too many proxies")
	}
	if r.FullName == "" && r.Username == "" && r.Email == "" && r.Phone == "" && r.Domain == "" && r.IP == "" && r.Company == "" && r.Alias == "" && r.ASN == "" && r.Wallet == "" && r.Notes == "" {
		return errNoInput
	}
	return nil
}

func (m *manager) start(req ScanRequest) (*scan, error) {
	if err := validateRequest(&req); err != nil {
		return nil, err
	}

	// Validate/normalise the identifiers up front so mistakes (a malformed
	// domain or IP) are reported to the form instead of failing the run later.
	probe := models.Target{FullName: req.FullName, Username: req.Username, Email: req.Email, Phone: req.Phone,
		Domain: req.Domain, IP: req.IP, Company: req.Company, Location: req.Location,
		Alias: req.Alias, ASN: req.ASN, Wallet: req.Wallet, Notes: req.Notes}
	if err := engine.Enrich(&probe, false, 0); err != nil {
		return nil, err
	}

	opts := m.base
	opts.Modules = req.Modules
	opts.Verify = req.Verify
	opts.Derive = req.Derive
	opts.NoPivot = req.NoPivot
	opts.Aggressive = req.Aggressive
	opts.Browser = req.Browser
	if len(req.Proxies) > 0 {
		opts.Proxies = req.Proxies
	}
	built, err := app.Build(opts)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	running := 0
	for _, s := range m.scans {
		if !s.finished() {
			running++
		}
	}
	if running >= m.maxRunning {
		m.mu.Unlock()
		return nil, errBusy
	}
	ctx, cancel := context.WithCancel(m.root)
	sc := &scan{
		ID: newID(), Created: time.Now().UTC(), state: stateRunning, cancel: cancel,
		notify: make(chan struct{}), progress: map[string][2]int{},
		Target: models.Target{FullName: req.FullName, Username: req.Username, Email: req.Email, Phone: req.Phone,
			Domain: req.Domain, IP: req.IP, Company: req.Company, Location: req.Location,
			Alias: req.Alias, ASN: req.ASN, Wallet: req.Wallet},
	}
	m.scans[sc.ID] = sc
	m.order = append(m.order, sc.ID)
	m.evictLocked()
	m.mu.Unlock()

	eng := built.Engine
	eng.OnProgress = sc.setProgress
	eng.OnFinding = func(f models.Finding) {
		sc.mu.Lock()
		sc.hits++
		if len(sc.all) < 6000 {
			sc.all = append(sc.all, f)
		}
		sc.mu.Unlock()
		for _, ent := range f.Entities {
			if ent.Type == models.EntImage {
				m.addImage(ent.Value)
			}
		}
		sc.push(event{Type: "finding", Data: f})
	}

	go liveIdentities(ctx, sc, probe)

	go func() {
		defer cancel()
		rep, err := eng.Run(ctx, sc.Target)
		if err != nil {
			sc.finish(stateFailed, err.Error(), nil, event{Type: "error", Data: map[string]string{"error": err.Error()}})
			return
		}
		m.saveReport(rep)
		summary := *rep
		summary.Findings = nil // hits were already streamed
		state := stateDone
		if rep.Interrupted {
			state = stateCancelled
		}
		sc.finish(state, "", rep, event{Type: "done", Data: summary})
	}()
	return sc, nil
}

// saveReport optionally persists finished reports (JSON/CSV/TXT, mode 0600).
func (m *manager) saveReport(rep *models.Report) {
	m.cases.save(rep)
	if m.reportDir == "" {
		return
	}
	base := fmt.Sprintf("rectool_%s", rep.StartedAt.Format("20060102_150405"))
	if _, err := output.Export(rep, m.reportDir, base, []string{"json", "csv", "txt"}); err != nil {
		fmt.Fprintln(os.Stderr, "[!] saving report:", err)
	}
}

// evictLocked drops the oldest finished scans beyond maxKept.
func (m *manager) evictLocked() {
	for len(m.order) > m.maxKept {
		dropped := false
		for i, id := range m.order {
			if m.scans[id].finished() {
				delete(m.scans, id)
				m.order = append(m.order[:i], m.order[i+1:]...)
				dropped = true
				break
			}
		}
		if !dropped {
			return
		}
	}
}

func (m *manager) get(id string) (*scan, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sc, ok := m.scans[id]
	return sc, ok
}

func (m *manager) list() []Summary {
	m.mu.Lock()
	scans := make([]*scan, 0, len(m.scans))
	for _, s := range m.scans {
		scans = append(scans, s)
	}
	m.mu.Unlock()
	sort.Slice(scans, func(i, j int) bool { return scans[i].Created.After(scans[j].Created) })
	out := make([]Summary, len(scans))
	for i, s := range scans {
		out[i] = s.summary()
	}
	return out
}

// liveIdentities re-resolves identities every few seconds while a scan runs, so
// the browser shows who the findings add up to (and whether it is ambiguous)
// long before the scan ends. Pictures are not downloaded yet at this point, so
// picture-based links only appear in the final report.
func liveIdentities(ctx context.Context, sc *scan, t models.Target) {
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	last := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		sc.mu.Lock()
		n := len(sc.all)
		snap := append([]models.Finding(nil), sc.all...)
		sc.mu.Unlock()
		if n == last {
			continue
		}
		last = n
		res := identity.ResolveFindings(snap, t, nil)
		if len(res.Identities) == 0 {
			continue
		}
		sc.push(event{Type: "identities", Data: map[string]any{
			"identities": res.Identities, "ambiguity": res.Note, "same_name": res.SameName, "target": t,
		}})
	}
}
