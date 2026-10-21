package sitefiles

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/pool"
	"github.com/sudosoc/rectool/internal/scanner"
)

func TestSiteFiles(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/humans.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "/* TEAM */\nChief: Jane Roe\nContact: jane@corp.example\n")
	})
	mux.HandleFunc("/ads.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "google.com, pub-1234567890, DIRECT, f08c47fec0942fa0\nownerdomain=corp.example\n")
	})
	mux.HandleFunc("/wp-json/wp/v2/users", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"name":"John Smith","slug":"jsmith","description":"Editor"}]`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	c, _ := httpx.New(httpx.Options{Timeout: 5 * time.Second, InsecureTLS: true})
	p := pool.New(4, 16)
	defer p.Close()
	var mu sync.Mutex
	got := map[string]models.Finding{}
	err := New().Scan(context.Background(), models.Target{Domain: strings.TrimPrefix(srv.URL, "https://")}, scanner.Deps{HTTP: c, Pool: p},
		func(f models.Finding) { mu.Lock(); got[f.Source] = f; mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	if f := got["humans.txt"]; !strings.Contains(f.Details["credits"], "Jane Roe") || len(f.Entities) != 1 {
		t.Fatalf("humans: %+v", f)
	}
	if f := got["ads.txt"]; !strings.Contains(f.Details["publisher accounts"], "pub-1234567890") || !strings.Contains(f.Details["declared owner / contact"], "corp.example") {
		t.Fatalf("ads: %+v", f)
	}
	if f := got["WordPress authors"]; !strings.Contains(f.Details["who"], "John Smith") {
		t.Fatalf("wp: %+v", f)
	}
}
