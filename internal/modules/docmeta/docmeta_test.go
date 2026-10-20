package docmeta

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/pool"
	"github.com/sudosoc/rectool/internal/scanner"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPDFMeta(t *testing.T) {
	pdf := []byte("%PDF-1.4 1 0 obj << /Author (Jane Roe) /Creator (Microsoft\\) Word) /Producer (Acme PDF 3) /CreationDate (D:20200105103000+02'00') >> endobj")
	m := pdfMeta(pdf)
	if m.Author != "Jane Roe" || m.Created != "2020-01-05" || m.Software != "Microsoft) Word / Acme PDF 3" {
		t.Fatalf("%+v", m)
	}
}

func TestOOXMLMeta(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("docProps/core.xml")
	w.Write([]byte(`<cp:coreProperties><dc:creator>jroe</dc:creator><cp:lastModifiedBy>John Smith</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">2021-03-04T10:00:00Z</dcterms:created></cp:coreProperties>`))
	w2, _ := zw.Create("docProps/app.xml")
	w2.Write([]byte(`<Properties><Application>Microsoft Office Word</Application><AppVersion>16.0000</AppVersion><Company>Acme Corp</Company></Properties>`))
	zw.Close()
	m := ooxmlMeta(buf.Bytes())
	if m.Author != "jroe" || m.LastBy != "John Smith" || m.Company != "Acme Corp" || m.Created != "2021-03-04" || m.Software != "Microsoft Office Word 16.0000" {
		t.Fatalf("%+v", m)
	}
}

func TestScanReadsSiteDocuments(t *testing.T) {
	pdf := []byte("%PDF-1.4 << /Author (jsmith) /Producer (Acme PDF) >>")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<a href="/files/report.pdf">r</a> <a href="https://other.example/x.pdf">x</a>`)
	})
	mux.HandleFunc("/files/report.pdf", func(w http.ResponseWriter, r *http.Request) { w.Write(pdf) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	c, _ := httpx.New(httpx.Options{Timeout: 5 * time.Second, InsecureTLS: true})
	p := pool.New(2, 8)
	defer p.Close()
	var got []models.Finding
	var mu sync.Mutex
	host := strings.TrimPrefix(srv.URL, "https://")
	err := New().Scan(context.Background(), models.Target{Domain: host}, scanner.Deps{HTTP: c, Pool: p}, func(f models.Finding) { mu.Lock(); got = append(got, f); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range got {
		if f.Source == "Document authors (summary)" && strings.Contains(f.Details["people named in metadata"], "jsmith") {
			found = true
		}
	}
	if !found {
		t.Fatalf("author not reported: %+v", got)
	}
}
