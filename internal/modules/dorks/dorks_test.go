package dorks

import (
	"strings"
	"testing"

	"github.com/sudosoc/rectool/internal/models"
)

func TestGenerate(t *testing.T) {
	ds := Generate(models.Target{FullName: "Jane Doe", Email: "jane@x.org", Phone: "+15551234567"})
	var qs []string
	for _, d := range ds {
		qs = append(qs, d.Query)
	}
	all := strings.Join(qs, "\n")
	for _, want := range []string{`"Jane Doe" site:linkedin.com/in`, `"jane@x.org" -site:x.org`, `"15551234567"`} {
		if !strings.Contains(all, want) {
			t.Errorf("missing dork %s", want)
		}
	}
}

func TestParseDDG(t *testing.T) {
	body := `<a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fa&amp;rut=1">Ex <b>Title</b></a>`
	r, err := duckduckgo{}.parse(200, []byte(body))
	if err != nil || len(r) != 1 || r[0].URL != "https://example.com/a" || r[0].Title != "Ex Title" {
		t.Fatalf("got %+v %v", r, err)
	}
	if _, err := (duckduckgo{}).parse(202, nil); err != errBlocked {
		t.Fatal("202 should be blocked")
	}
}

func TestParseGoogle(t *testing.T) {
	body := `<a href="/url?q=https://example.org/p&amp;sa=U"><h3 class="x">Hit</h3></a>`
	r, err := google{}.parse(200, []byte(body))
	if err != nil || len(r) != 1 || r[0].URL != "https://example.org/p" {
		t.Fatalf("got %+v %v", r, err)
	}
	if _, err := (google{}).parse(200, []byte("<a href='/sorry/index'>")); err != errBlocked {
		t.Fatal("expected blocked")
	}
}

func TestParseBing(t *testing.T) {
	body := `<h2><a target="_blank" href="https://www.bing.com/ck/a?!&amp;&amp;p=x&amp;u=a1aHR0cHM6Ly93d3cuZmFjZWJvb2suY29tLw&amp;ntb=1">Log into <strong>Facebook</strong></a></h2>`
	r, err := bing{}.parse(200, []byte(body))
	if err != nil || len(r) != 1 || r[0].URL != "https://www.facebook.com/" || r[0].Title != "Log into Facebook" {
		t.Fatalf("got %+v %v", r, err)
	}
}

func TestMatchesSite(t *testing.T) {
	if !matchesSite(`"x" site:github.com`, "https://gist.github.com/a") || matchesSite(`"x" site:github.com`, "https://zhihu.com/q") {
		t.Fatal("site filter wrong")
	}
	if !matchesSite(`"x" -site:example.org`, "https://anything.net") {
		t.Fatal("negative site: must not filter")
	}
}

func TestRelevant(t *testing.T) {
	q := `"Jane Doe" site:github.com`
	if !relevant(q, result{Title: "jane doe (jdoe)", URL: "https://github.com/jdoe"}) {
		t.Fatal("should be relevant")
	}
	if relevant(q, result{Title: "Chrome extensions", URL: "https://stackoverflow.com/q/1"}) {
		t.Fatal("should be dropped")
	}
}

func TestGenerateDomainCompanyIP(t *testing.T) {
	ds := Generate(models.Target{Domain: "acme.com", Company: "Acme Inc", IP: "203.0.113.9", Location: "Cairo"})
	var qs []string
	for _, d := range ds {
		qs = append(qs, d.Query)
	}
	all := strings.Join(qs, " | ")
	for _, want := range []string{`site:acme.com`, `site:*.acme.com -site:www.acme.com`, `"@acme.com"`, `"Acme Inc" "Cairo"`, `"203.0.113.9"`} {
		if !strings.Contains(all, want) {
			t.Errorf("missing dork %s", want)
		}
	}
}

func TestParseBrave(t *testing.T) {
	body := `<div class="snippet svelte-x" data-pos="0" data-type="web"><div class="result-content"><a href="https://github.com/torvalds" target="_self" class="svelte-14r20fy l1"><div class="title search-snippet-title line-clamp-1 svelte-14r20fy" title="torvalds (Linus Torvalds) · GitHub">torvalds</div></a><div class="generic-snippet svelte-1c"><div class="content desktop-default-regular t-primary line-clamp-dynamic svelte-1c">Linus <strong>Torvalds</strong> has 8 repos</div></div></div></div>`
	r, err := brave{}.parse(200, []byte(body))
	if err != nil || len(r) != 1 || r[0].URL != "https://github.com/torvalds" || !strings.Contains(r[0].Title, "Linus Torvalds") || !strings.Contains(r[0].Snippet, "8 repos") {
		t.Fatalf("got %+v %v", r, err)
	}
}
