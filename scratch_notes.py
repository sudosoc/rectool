def edit(p, pairs):
    s = open(p, encoding='utf-8').read()
    for a, b in pairs:
        assert a in s, (p, a[:60])
        s = s.replace(a, b, 1)
    open(p, 'w', encoding='utf-8').write(s)

edit('internal/web/cases.go', [
    ('// handleCaseOpen re-creates', '''// handleNotes stores one analyst note on a finished scan and rewrites the saved
// case, so notes travel with the case and appear in the reports.
func (s *Server) handleNotes(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.mgr.get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such scan")
		return
	}
	var req struct {
		Key  string `json:"key"`
		Text string `json:"text"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil || req.Key == "" || len(req.Key) > 300 || len(req.Text) > 4000 {
		writeErr(w, http.StatusBadRequest, "bad note")
		return
	}
	sc.mu.Lock()
	rep := sc.report
	if rep == nil {
		sc.mu.Unlock()
		writeErr(w, http.StatusConflict, "notes can be added when the scan has finished")
		return
	}
	if rep.Notes == nil {
		rep.Notes = map[string]string{}
	}
	if strings.TrimSpace(req.Text) == "" {
		delete(rep.Notes, req.Key)
	} else if len(rep.Notes) < 300 || rep.Notes[req.Key] != "" {
		rep.Notes[req.Key] = req.Text
	}
	id := sc.caseID
	sc.mu.Unlock()
	s.cases.update(id, rep)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleCaseOpen re-creates'''),
])
edit('internal/web/server.go', [
    ('	mux.HandleFunc("GET /api/health", s.handleHealth)', '	mux.HandleFunc("POST /api/scans/{id}/notes", s.handleNotes)\n	mux.HandleFunc("GET /api/health", s.handleHealth)'),
])
# exports: notes in TXT and HTML
edit('internal/output/export.go', [
    ('	if g := r.Geo; g != nil {\n		b.WriteString("\\nLOCATION ANALYSIS\\n")', '''	if len(r.Notes) > 0 {
		b.WriteString("\\nANALYST NOTES\\n")
		keys := make([]string, 0, len(r.Notes))
		for k := range r.Notes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "  [%s]\\n    %s\\n", noteTitle(k), strings.ReplaceAll(r.Notes[k], "\\n", "\\n    "))
		}
	}
	if g := r.Geo; g != nil {
		b.WriteString("\\nLOCATION ANALYSIS\\n")'''),
])
