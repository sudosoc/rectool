// Package web serves rectool's browser UI: a small JSON API, live results over
// Server-Sent Events, and an embedded single-page front end (no CDN, no
// external assets).
//
// Because the tool handles personal data and makes outbound requests on the
// operator's behalf, the server is locked down by default: it binds to
// loopback, requires a random access token (exchanged once for an HttpOnly
// SameSite=Strict cookie), rejects foreign Host/Origin headers and sends a
// strict Content-Security-Policy.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/app"
	"github.com/sudosoc/rectool/internal/engine"
	"github.com/sudosoc/rectool/internal/health"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/media"
	"github.com/sudosoc/rectool/internal/modules/dorks"
	"github.com/sudosoc/rectool/internal/output"
)

//go:embed static
var staticFS embed.FS

const cookieName = "rectool_session"

// Config configures the server.
type Config struct {
	Addr       string      // listen address, default 127.0.0.1:8080
	Token      string      // access token; generated when empty
	Base       app.Options // defaults for every scan (proxies, workers, sites, ...)
	MaxRunning int         // concurrent scans (default 2)
	ReportDir  string      // when set, finished reports are also saved here
	CaseDir    string      // when set, finished scans are kept as re-openable cases here
}

// Server is the web UI server.
type Server struct {
	cfg      Config
	token    string
	mgr      *manager
	cases    *caseStore
	modules  []moduleInfo
	siteCnt  int
	loopback bool
	handler  http.Handler
	img      *httpx.Client // fetches profile pictures for the image proxy
}

type moduleInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// New validates the configuration and prepares the server.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8080"
	}
	if cfg.MaxRunning <= 0 {
		cfg.MaxRunning = 2
	}
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("invalid listen address %q: %w", cfg.Addr, err)
	}
	s := &Server{cfg: cfg, token: cfg.Token}
	if s.token == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		s.token = hex.EncodeToString(b)
	}
	if len(s.token) < 16 {
		return nil, errors.New("access token must be at least 16 characters")
	}
	ip := net.ParseIP(host)
	s.loopback = host == "localhost" || (ip != nil && ip.IsLoopback())

	// All scans share one Searcher so search-engine rate limits and "blocked"
	// state hold across scans, not per scan.
	if cfg.Base.Searcher == nil {
		sr, err := dorks.NewSearcher(cfg.Base.DorkEngines, cfg.Base.DorkDelay)
		if err != nil {
			return nil, err
		}
		cfg.Base.Searcher = sr
	}
	built, err := app.Build(cfg.Base)
	if err != nil {
		return nil, err
	}
	for _, sc := range built.Engine.Scanners() {
		s.modules = append(s.modules, moduleInfo{sc.Name(), sc.Description()})
	}
	s.siteCnt = built.SocialSites
	s.mgr = newManager(ctx, cfg.Base, cfg.MaxRunning, cfg.ReportDir)
	s.cases = &caseStore{dir: cfg.CaseDir}
	s.mgr.cases = s.cases
	if s.img, err = httpx.New(httpx.Options{Timeout: cfg.Base.Timeout, Retries: 1, Proxies: cfg.Base.Proxies}); err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/info", s.handleInfo)
	mux.HandleFunc("GET /api/scans", s.handleList)
	mux.HandleFunc("POST /api/scans", s.handleStart)
	mux.HandleFunc("GET /api/scans/{id}", s.handleGet)
	mux.HandleFunc("POST /api/scans/{id}/cancel", s.handleCancel)
	mux.HandleFunc("GET /api/scans/{id}/events", s.handleEvents)
	mux.HandleFunc("GET /api/scans/{id}/export", s.handleExport)
	mux.HandleFunc("POST /api/scans/{id}/notes", s.handleNotes)
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/cases", s.handleCases)
	mux.HandleFunc("GET /api/cases/{id}", s.handleCaseGet)
	mux.HandleFunc("POST /api/cases/{id}/open", s.handleCaseOpen)
	mux.HandleFunc("DELETE /api/cases/{id}", s.handleCaseDelete)
	mux.HandleFunc("GET /api/img", s.handleImage)
	mux.HandleFunc("GET /api/tile/{z}/{x}/{y}", newTileProxy(s.img).handle)
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /", http.FileServerFS(sub))

	s.handler = s.secure(mux)
	return s, nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, health.Check(ctx, s.img))
}

// Token returns the access token.
func (s *Server) Token() string { return s.token }

// Handler exposes the full middleware chain (used by tests).
func (s *Server) Handler() http.Handler { return s.handler }

// URL is the address (with token) the operator should open.
func (s *Server) URL() string {
	host, port, _ := net.SplitHostPort(s.cfg.Addr)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port) + "/?token=" + s.token
}

// Loopback reports whether the server only listens on a loopback interface.
func (s *Server) Loopback() bool { return s.loopback }

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context, onReady func()) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No WriteTimeout: SSE streams are long-lived.
	}
	if onReady != nil {
		onReady()
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		return nil
	}
}

// ------------------------------------------------------------- middleware --

func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")

		// DNS-rebinding defence: on loopback only accept loopback host names.
		if s.loopback && !loopbackHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}

		// First visit: ?token=… on the root exchanges the token for a cookie.
		if r.Method == http.MethodGet && r.URL.Path == "/" {
			if t := r.URL.Query().Get("token"); t != "" {
				if !s.tokenOK(t) {
					http.Error(w, "invalid token", http.StatusUnauthorized)
					return
				}
				http.SetCookie(w, &http.Cookie{
					Name: cookieName, Value: s.token, Path: "/", HttpOnly: true,
					SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600,
				})
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
		}

		c, err := r.Cookie(cookieName)
		if (err != nil || !s.tokenOK(c.Value)) && !s.tokenOK(r.Header.Get("X-Rectool-Token")) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "rectool: unauthorized. Open the URL printed in the terminal (it contains ?token=…).")
			return
		}

		// CSRF: state-changing requests must be same-origin and carry a custom header.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" {
				u, err := url.Parse(o)
				if err != nil || u.Host != r.Host {
					http.Error(w, "cross-origin request refused", http.StatusForbidden)
					return
				}
			}
			if r.Header.Get("X-Requested-With") != "rectool" {
				http.Error(w, "missing X-Requested-With header", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) tokenOK(t string) bool {
	return subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) == 1
}

func loopbackHost(hostport string) bool {
	h := hostport
	if hh, _, err := net.SplitHostPort(hostport); err == nil {
		h = hh
	}
	h = strings.Trim(strings.ToLower(h), "[]")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// --------------------------------------------------------------- handlers --

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) handleInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version": engine.Version, "modules": s.modules, "social_sites": s.siteCnt,
	})
}

func (s *Server) handleList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.list())
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	known := map[string]bool{}
	for _, m := range s.modules {
		known[m.Name] = true
	}
	for _, m := range req.Modules {
		if !known[m] {
			writeErr(w, http.StatusBadRequest, "unknown module: "+m)
			return
		}
	}
	sc, err := s.mgr.start(req)
	switch {
	case errors.Is(err, errBusy):
		writeErr(w, http.StatusTooManyRequests, err.Error())
	case err != nil:
		writeErr(w, http.StatusBadRequest, err.Error())
	default:
		writeJSON(w, http.StatusAccepted, sc.summary())
	}
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.mgr.get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such scan")
		return
	}
	writeJSON(w, http.StatusOK, sc.summary())
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.mgr.get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such scan")
		return
	}
	sc.cancel()
	writeJSON(w, http.StatusAccepted, sc.summary())
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.mgr.get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such scan")
		return
	}
	sc.mu.Lock()
	rep := sc.report
	sc.mu.Unlock()
	if rep == nil {
		writeErr(w, http.StatusConflict, "scan has no report yet")
		return
	}
	format := strings.ToLower(r.URL.Query().Get("format"))
	ct, ext, ok := output.ContentType(format)
	if !ok {
		writeErr(w, http.StatusBadRequest, "format must be one of: "+output.Formats)
		return
	}
	w.Header().Set("Content-Type", ct+"; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="rectool_`+sc.ID+"."+ext+`"`)
	_ = output.Render(w, rep, format)
}

// handleEvents streams a scan's log as Server-Sent Events. The full history is
// replayed first (so reloading the page loses nothing), then new events follow.
// Progress is sent as ephemeral snapshots, at most every 700 ms and only when
// it changed.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.mgr.get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such scan")
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	idx := 0
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			idx = n + 1
		}
	}
	send := func(id int, typ string, data any) bool {
		b, err := json.Marshal(data)
		if err != nil {
			return false
		}
		if id >= 0 {
			_, err = fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", id, typ, b)
		} else {
			_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", typ, b)
		}
		return err == nil
	}

	tick := time.NewTicker(700 * time.Millisecond)
	defer tick.Stop()
	lastProgress := ""
	for {
		snap := sc.snapshotFrom(idx)
		for _, ev := range snap.events {
			if !send(idx, ev.Type, ev.Data) {
				return
			}
			idx++
		}
		if pj, _ := json.Marshal(snap.progress); string(pj) != lastProgress {
			lastProgress = string(pj)
			if !send(-1, "progress", snap.progress) {
				return
			}
		}
		fl.Flush()

		if snap.state != stateRunning && len(snap.events) == 0 {
			return // everything delivered, including the final done/error event
		}
		select {
		case <-snap.notify:
		case <-tick.C:
		case <-r.Context().Done():
			return
		}
	}
}

// handleImage proxies a profile picture that a scan discovered. Going through
// the server keeps the operator's browser from contacting third-party hosts
// (no IP / Referer leak, works with the strict CSP) and lets the fetch be
// SSRF-guarded. Only URLs found by scans are served, so it is not an open proxy.
func (s *Server) handleImage(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("u")
	if u == "" || !s.mgr.knownImage(u) {
		writeErr(w, http.StatusForbidden, "unknown image")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	img, err := media.Fetch(ctx, s.img, u)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	h := w.Header()
	h.Set("Content-Type", img.ContentType)
	h.Set("Cache-Control", "private, max-age=600")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Content-Length", strconv.Itoa(len(img.Data)))
	_, _ = w.Write(img.Data)
}
