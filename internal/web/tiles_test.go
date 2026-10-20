package web

import (
	"context"
	"github.com/sudosoc/rectool/internal/app"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestTileRejectsBadCoordinates(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /t/{z}/{x}/{y}", newTileProxy(nil).handle)
	for _, p := range []string{"/t/99/1/1", "/t/3/9/1", "/t/3/-1/1", "/t/x/1/1", "/t/13/1/1"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s -> %d", p, rec.Code)
		}
	}
}

func TestLiveTile(t *testing.T) {
	if os.Getenv("RECTOOL_LIVE") == "" {
		t.Skip("live")
	}
	c, _ := httpx.New(httpx.Options{Timeout: 20 * time.Second, Retries: 1})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /t/{z}/{x}/{y}", newTileProxy(c).handle)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/t/5/19/12", nil))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/png" || rec.Body.Len() < 100 {
		t.Fatalf("code=%d len=%d", rec.Code, rec.Body.Len())
	}
}

func TestCasesRoundTrip(t *testing.T) {
	cs := &caseStore{dir: t.TempDir()}
	rep := &models.Report{StartedAt: time.Now().UTC(), Target: models.Target{FullName: "Jane Roe"},
		Findings: []models.Finding{{Module: "people", Source: "ORCID", Status: models.StatusFound}}}
	cs.save(rep)
	l := cs.list()
	if len(l) != 1 || l[0].Title != "Jane Roe" || l[0].Findings != 1 {
		t.Fatalf("list: %+v", l)
	}
	got, err := cs.load(l[0].ID)
	if err != nil || got.Target.FullName != "Jane Roe" {
		t.Fatalf("load: %v %+v", err, got)
	}
	if _, err := cs.load("../../etc/passwd"); err == nil {
		t.Fatal("path traversal accepted")
	}
	m := newManager(context.Background(), app.Options{}, 1, "")
	sc := m.restore(got)
	if !sc.finished() || len(sc.events) != 2 {
		t.Fatalf("restore: state=%s events=%d", sc.state, len(sc.events))
	}
	if err := cs.remove(l[0].ID); err != nil || len(cs.list()) != 0 {
		t.Fatal("remove failed")
	}
}
