// Package docmeta reads the hidden metadata of documents a site publishes
// (PDF, Word, Excel, PowerPoint, OpenDocument): the author's name, the last
// person who saved it, their organisation, and the software used. These fields
// often carry a real name or a local account name the authors never meant to
// publish. Only documents the site itself links to are read.
package docmeta

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

type Scanner struct{}

var _ scanner.Scanner = (*Scanner)(nil)

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "docmeta" }
func (s *Scanner) Description() string {
	return "author, last editor, organisation and software hidden in documents a site publishes"
}
func (s *Scanner) CanRun(t models.Target) bool {
	if strings.TrimSpace(t.Domain) != "" {
		return true
	}
	for _, l := range t.Links {
		if isDoc(l) {
			return true
		}
	}
	return false
}

const (
	maxDocs  = 12
	maxBytes = 8 << 20
)

var (
	docExt  = regexp.MustCompile(`(?i)\.(pdf|docx|xlsx|pptx|odt|ods|odp)(\?|#|$)`)
	hrefRe  = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`)
	locRe   = regexp.MustCompile(`(?i)<loc>\s*([^<\s]+)\s*</loc>`)
	sitemap = regexp.MustCompile(`(?im)^\s*sitemap:\s*(\S+)`)
)

func isDoc(u string) bool { return docExt.MatchString(u) }

func (s *Scanner) Scan(ctx context.Context, t models.Target, d scanner.Deps, emit func(models.Finding)) error {
	var docs []string
	seen := map[string]bool{}
	add := func(u string) {
		if isDoc(u) && !seen[u] && len(docs) < maxDocs {
			seen[u] = true
			docs = append(docs, u)
		}
	}
	for _, l := range t.Links {
		add(l)
	}
	if dom := strings.TrimSpace(t.Domain); dom != "" {
		base := "https://" + dom + "/"
		if resp, err := d.HTTP.Do(ctx, httpx.Request{URL: base, Timeout: 20 * time.Second, MaxBody: 2 << 20}); err == nil && resp.StatusCode == 200 {
			bu, _ := url.Parse(resp.FinalURL)
			for _, m := range hrefRe.FindAllStringSubmatch(string(resp.Body), -1) {
				if abs := resolve(bu, m[1]); abs != "" {
					add(abs)
				}
			}
		}
		var maps []string
		if resp, err := d.HTTP.Do(ctx, httpx.Request{URL: base + "robots.txt", Timeout: 15 * time.Second, MaxBody: 1 << 20}); err == nil && resp.StatusCode == 200 {
			for _, m := range sitemap.FindAllStringSubmatch(string(resp.Body), -1) {
				maps = append(maps, m[1])
			}
		}
		if len(maps) == 0 {
			maps = []string{base + "sitemap.xml"}
		}
		for i, sm := range maps {
			if i >= 3 {
				break
			}
			if resp, err := d.HTTP.Do(ctx, httpx.Request{URL: sm, Timeout: 20 * time.Second, MaxBody: 4 << 20}); err == nil && resp.StatusCode == 200 {
				for _, m := range locRe.FindAllStringSubmatch(string(resp.Body), -1) {
					add(m[1])
				}
			}
		}
	}
	if len(docs) == 0 {
		return nil
	}
	type result struct {
		url  string
		meta meta
	}
	var (
		mu  sync.Mutex
		res []result
		wg  sync.WaitGroup
	)
	for _, u := range docs {
		wg.Add(1)
		u := u
		if err := d.Pool.Submit(ctx, func() {
			defer wg.Done()
			resp, err := d.HTTP.Do(ctx, httpx.Request{URL: u, Timeout: 40 * time.Second, MaxBody: maxBytes})
			if err != nil || resp.StatusCode != 200 {
				return
			}
			m := extract(u, resp.Body)
			if m.empty() {
				return
			}
			mu.Lock()
			res = append(res, result{u, m})
			mu.Unlock()
		}); err != nil {
			wg.Done()
			break
		}
	}
	wg.Wait()
	if len(res) == 0 {
		return nil
	}
	sort.Slice(res, func(i, j int) bool { return res[i].url < res[j].url })
	people := map[string]int{}
	software := map[string]bool{}
	orgs := map[string]bool{}
	for _, r := range res {
		det := map[string]string{"document": r.url}
		for k, v := range r.meta.fields() {
			det[k] = v
		}
		emit(models.Finding{Source: "Document metadata: " + short(r.url), Category: "document-metadata", URL: r.url, Status: models.StatusFound, Confidence: 0.8, Details: det})
		for _, p := range []string{r.meta.Author, r.meta.LastBy} {
			if p = strings.TrimSpace(p); p != "" {
				people[p]++
			}
		}
		if r.meta.Software != "" {
			software[r.meta.Software] = true
		}
		if r.meta.Company != "" {
			orgs[r.meta.Company] = true
		}
	}
	var names []string
	var ents []models.Entity
	for p, n := range people {
		names = append(names, fmt.Sprintf("%s (%d doc)", p, n))
		switch {
		case strings.Contains(p, " "):
			ents = append(ents, models.Entity{Type: models.EntName, Value: p})
		case len(p) >= 3 && len(p) <= 24 && !strings.ContainsAny(p, "@/\\"):
			ents = append(ents, models.Entity{Type: models.EntUsername, Value: p})
		}
	}
	sort.Strings(names)
	for o := range orgs {
		ents = append(ents, models.Entity{Type: models.EntOrg, Value: o})
	}
	d2 := map[string]string{"documents read": fmt.Sprint(len(res)), "people named in metadata": strings.Join(names, "; "),
		"note": "authors and last editors recorded inside the files; account names such as 'jsmith' are often real login names of staff"}
	if len(software) > 0 {
		var sw []string
		for s := range software {
			sw = append(sw, s)
		}
		sort.Strings(sw)
		d2["software used"] = strings.Join(sw, "; ")
	}
	if len(orgs) > 0 {
		var ol []string
		for o := range orgs {
			ol = append(ol, o)
		}
		sort.Strings(ol)
		d2["organisation recorded"] = strings.Join(ol, "; ")
	}
	emit(models.Finding{Source: "Document authors (summary)", Category: "document-metadata", Status: models.StatusFound, Confidence: 0.75, Details: d2, Entities: ents})
	return nil
}

func short(u string) string {
	if len(u) > 70 {
		return u[:70] + "…"
	}
	return u
}

func resolve(base *url.URL, ref string) string {
	if base == nil {
		return ""
	}
	r, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(r)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	// same site only: documents hosted elsewhere are not this site's own
	if !strings.EqualFold(strings.TrimPrefix(abs.Hostname(), "www."), strings.TrimPrefix(base.Hostname(), "www.")) {
		return ""
	}
	abs.Fragment = ""
	return abs.String()
}

type meta struct {
	Author, LastBy, Company, Software, Title, Created, Modified string
}

func (m meta) empty() bool {
	return m.Author == "" && m.LastBy == "" && m.Company == "" && m.Software == "" && m.Title == ""
}

func (m meta) fields() map[string]string {
	out := map[string]string{}
	for k, v := range map[string]string{"author": m.Author, "last saved by": m.LastBy, "organisation": m.Company, "software": m.Software,
		"title": m.Title, "created": m.Created, "modified": m.Modified} {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

func extract(u string, data []byte) meta {
	l := strings.ToLower(u)
	switch {
	case strings.Contains(l, ".pdf"):
		return pdfMeta(data)
	case strings.Contains(l, ".docx"), strings.Contains(l, ".xlsx"), strings.Contains(l, ".pptx"):
		return ooxmlMeta(data)
	case strings.Contains(l, ".odt"), strings.Contains(l, ".ods"), strings.Contains(l, ".odp"):
		return odfMeta(data)
	}
	return meta{}
}

var (
	pdfStr  = func(key string) *regexp.Regexp { return regexp.MustCompile(`/` + key + `\s*\(((?:\\.|[^\\)])*)\)`) }
	pdfAuth = pdfStr("Author")
	pdfCre  = pdfStr("Creator")
	pdfProd = pdfStr("Producer")
	pdfTit  = pdfStr("Title")
	pdfDate = pdfStr("CreationDate")
	pdfMod  = pdfStr("ModDate")
	xmpCre  = regexp.MustCompile(`(?s)<dc:creator>.*?<rdf:li[^>]*>(.*?)</rdf:li>`)
)

func pdfVal(re *regexp.Regexp, b []byte) string {
	m := re.FindSubmatch(b)
	if m == nil {
		return ""
	}
	s := string(m[1])
	s = strings.NewReplacer(`\(`, "(", `\)`, ")", `\\`, `\`).Replace(s)
	if strings.HasPrefix(s, "\xfe\xff") { // UTF-16BE
		var r []rune
		for i := 2; i+1 < len(s); i += 2 {
			r = append(r, rune(s[i])<<8|rune(s[i+1]))
		}
		s = string(r)
	}
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 32 {
			return -1
		}
		return r
	}, s))
}

func pdfDateISO(s string) string {
	s = strings.TrimPrefix(s, "D:")
	if len(s) >= 8 {
		return s[:4] + "-" + s[4:6] + "-" + s[6:8]
	}
	return s
}

func pdfMeta(b []byte) meta {
	m := meta{Author: pdfVal(pdfAuth, b), Title: pdfVal(pdfTit, b), Created: pdfDateISO(pdfVal(pdfDate, b)), Modified: pdfDateISO(pdfVal(pdfMod, b))}
	sw := []string{}
	for _, v := range []string{pdfVal(pdfCre, b), pdfVal(pdfProd, b)} {
		if v != "" {
			sw = append(sw, v)
		}
	}
	m.Software = strings.Join(sw, " / ")
	if m.Author == "" {
		if x := xmpCre.FindSubmatch(b); x != nil {
			m.Author = strings.TrimSpace(string(x[1]))
		}
	}
	return m
}

func tag(xml, name string) string {
	re := regexp.MustCompile(`(?s)<` + regexp.QuoteMeta(name) + `[^>]*>(.*?)</` + regexp.QuoteMeta(name) + `>`)
	if m := re.FindStringSubmatch(xml); m != nil {
		return strings.TrimSpace(strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'").Replace(m[1]))
	}
	return ""
}

func readZip(data []byte, names ...string) map[string]string {
	out := map[string]string{}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return out
	}
	for _, f := range zr.File {
		for _, n := range names {
			if f.Name == n {
				rc, err := f.Open()
				if err != nil {
					continue
				}
				var buf bytes.Buffer
				_, _ = buf.ReadFrom(&limited{rc, 1 << 20})
				rc.Close()
				out[n] = buf.String()
			}
		}
	}
	return out
}

type limited struct {
	r interface{ Read([]byte) (int, error) }
	n int
}

func (l *limited) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, fmt.Errorf("limit")
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= n
	return n, err
}

func ooxmlMeta(data []byte) meta {
	f := readZip(data, "docProps/core.xml", "docProps/app.xml")
	core, app := f["docProps/core.xml"], f["docProps/app.xml"]
	m := meta{Author: tag(core, "dc:creator"), LastBy: tag(core, "cp:lastModifiedBy"), Title: tag(core, "dc:title"),
		Created: trimDate(tag(core, "dcterms:created")), Modified: trimDate(tag(core, "dcterms:modified")), Company: tag(app, "Company")}
	sw := tag(app, "Application")
	if v := tag(app, "AppVersion"); sw != "" && v != "" {
		sw += " " + v
	}
	m.Software = sw
	return m
}

func odfMeta(data []byte) meta {
	x := readZip(data, "meta.xml")["meta.xml"]
	return meta{Author: firstNon(tag(x, "meta:initial-creator"), tag(x, "dc:creator")), LastBy: tag(x, "dc:creator"), Title: tag(x, "dc:title"),
		Created: trimDate(tag(x, "meta:creation-date")), Modified: trimDate(tag(x, "dc:date")), Software: tag(x, "meta:generator")}
}

func firstNon(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func trimDate(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}
