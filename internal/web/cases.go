package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/models"
)

// Saved cases: every finished scan is stored as a JSON report (0600) so a
// person can be re-opened later and two runs compared to see what changed.

var caseIDRe = regexp.MustCompile(`^\d{8}_\d{6}_[0-9a-f]{8}$`)

type caseStore struct{ dir string }

// DefaultCaseDir picks the per-user data directory for saved cases.
func DefaultCaseDir() string {
	if d := os.Getenv("RECTOOL_CASES"); d != "" {
		return d
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "rectool", "cases")
	}
	return ""
}

func (c *caseStore) save(rep *models.Report) {
	if c == nil || c.dir == "" {
		return
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "[!] cases:", err)
		return
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	id := rep.StartedAt.Format("20060102_150405") + "_" + hex.EncodeToString(b)
	data, err := json.Marshal(rep)
	if err != nil {
		return
	}
	if err := os.WriteFile(filepath.Join(c.dir, id+".json"), data, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "[!] cases:", err)
	}
}

type caseInfo struct {
	ID         string `json:"id"`
	At         string `json:"at"`
	Title      string `json:"title"`
	Findings   int    `json:"findings"`
	Identities int    `json:"identities"`
	Best       string `json:"best,omitempty"`
}

func targetTitle(t models.Target) string {
	var parts []string
	for _, v := range []string{t.FullName, t.Username, t.Email, t.Phone, t.Domain, t.IP, t.Company, t.Alias, t.ASN, t.Wallet} {
		if v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, " · ")
}

func (c *caseStore) list() []caseInfo {
	out := []caseInfo{}
	if c == nil || c.dir == "" {
		return out
	}
	ents, err := os.ReadDir(c.dir)
	if err != nil {
		return out
	}
	names := []string{}
	for _, e := range ents {
		if n := strings.TrimSuffix(e.Name(), ".json"); !e.IsDir() && n != e.Name() && caseIDRe.MatchString(n) {
			names = append(names, n)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if len(names) > 100 {
		names = names[:100]
	}
	for _, id := range names {
		rep, err := c.load(id)
		if err != nil {
			continue
		}
		ci := caseInfo{ID: id, At: rep.StartedAt.Format(time.RFC3339), Title: targetTitle(rep.Target), Findings: len(rep.Hits()), Identities: len(rep.Identities)}
		if len(rep.Identities) > 0 {
			ci.Best = rep.Identities[0].Label
		}
		out = append(out, ci)
	}
	return out
}

func (c *caseStore) load(id string) (*models.Report, error) {
	if !caseIDRe.MatchString(id) {
		return nil, fmt.Errorf("bad case id")
	}
	data, err := os.ReadFile(filepath.Join(c.dir, id+".json"))
	if err != nil {
		return nil, err
	}
	var rep models.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}

func (c *caseStore) remove(id string) error {
	if !caseIDRe.MatchString(id) {
		return fmt.Errorf("bad case id")
	}
	return os.Remove(filepath.Join(c.dir, id+".json"))
}

func (s *Server) handleCases(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.cases.list())
}

func (s *Server) handleCaseGet(w http.ResponseWriter, r *http.Request) {
	rep, err := s.cases.load(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such case")
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleCaseDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.cases.remove(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, "no such case")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleCaseOpen re-creates a finished scan from a saved case so the whole UI
// (tabs, exports, pictures) works on it exactly as on a live scan.
func (s *Server) handleCaseOpen(w http.ResponseWriter, r *http.Request) {
	rep, err := s.cases.load(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such case")
		return
	}
	sc := s.mgr.restore(rep)
	writeJSON(w, http.StatusOK, map[string]string{"id": sc.ID})
}

// restore builds a finished scan whose event log replays a saved report.
func (m *manager) restore(rep *models.Report) *scan {
	sc := &scan{ID: newID(), Created: rep.StartedAt, state: stateDone, notify: make(chan struct{}), progress: map[string][2]int{},
		Target: rep.Target, report: rep}
	for _, f := range rep.Findings {
		sc.events = append(sc.events, event{Type: "finding", Data: f})
		sc.hits++
		for _, ent := range f.Entities {
			if ent.Type == models.EntImage {
				m.addImage(ent.Value)
			}
		}
	}
	for _, p := range rep.Photos {
		m.addImage(p.URL)
	}
	if len(rep.Identities) > 0 {
		sc.events = append(sc.events, event{Type: "identities", Data: map[string]any{
			"identities": rep.Identities, "ambiguity": rep.Ambiguity, "same_name": 0, "target": rep.Target}})
	}
	summary := *rep
	summary.Findings = nil
	sc.events = append(sc.events, event{Type: "done", Data: summary})
	m.mu.Lock()
	m.scans[sc.ID] = sc
	m.order = append(m.order, sc.ID)
	m.evictLocked()
	m.mu.Unlock()
	return sc
}
