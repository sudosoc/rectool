package extract

import (
	"net/http"
	"strings"
	"testing"
)

func TestEmails(t *testing.T) {
	got := Emails(`Contact: Sales@Example.org, bob [at] corp [dot] io, logo@2x.png, <b>jane.doe+x@mail.corp.co.uk</b>.`)
	want := []string{"bob@corp.io", "jane.doe+x@mail.corp.co.uk", "sales@example.org"}
	// "example.org" is filtered as a documentation domain only for "example." prefix match
	if strings.Join(got, ",") != strings.Join([]string{"bob@corp.io", "jane.doe+x@mail.corp.co.uk"}, ",") {
		t.Fatalf("got %v want (without example.*) %v", got, want)
	}
}

func TestPhones(t *testing.T) {
	doc := `<a href="tel:+44 20 7183 8750">call</a> or +1 (555) 123-4567 today. Order 12345678 ref 2024-01-05`
	got := strings.Join(Phones(doc), ",")
	if got != "+442071838750,+15551234567" {
		t.Fatalf("got %s", got)
	}
}

func TestSocialAndLinks(t *testing.T) {
	doc := `<a href="https://twitter.com/jdoe">t</a><a href="/in">x</a><a href="https://twitter.com/intent/tweet?x=1">share</a>
	<a href="https://github.com/jdoe/">g</a><a href="https://www.linkedin.com/in/john-doe-123/">l</a><a href="mailto:a@b.co">m</a>`
	links := Links(doc, "https://site.test/page")
	if len(links) != 5 { // mailto is dropped
		t.Fatalf("links: %v", links)
	}
	var got []string
	for _, p := range Social(links) {
		got = append(got, p.Platform+":"+p.Handle)
	}
	if strings.Join(got, ",") != "twitter:jdoe,github:jdoe,linkedin:in/john-doe-123" {
		t.Fatalf("social: %v", got)
	}
}

func TestMetaTrackingTech(t *testing.T) {
	doc := `<html><head><title> Acme &amp; Co </title><meta name="description" content="We build things"><meta property="og:image" content="/i.png">
	<meta name="generator" content="WordPress 6.5"><link rel="canonical" href="https://acme.test/"></head>
	<body><script>ga('create','UA-1234567-1');gtag('config','G-ABCDEF1234');</script><img src="/wp-content/x.png"></body></html>`
	m := ParseMeta(doc)
	if m.Title != "Acme & Co" || m.Description != "We build things" || m.Generator != "WordPress 6.5" || m.Canonical != "https://acme.test/" {
		t.Fatalf("%+v", m)
	}
	ids := TrackingIDs(doc)
	if ids["google-analytics"][0] != "UA-1234567-1" || ids["google-analytics-4"][0] != "G-ABCDEF1234" {
		t.Fatalf("%v", ids)
	}
	h := http.Header{}
	h.Set("Server", "nginx")
	h.Set("CF-Ray", "abc")
	tech := strings.Join(Tech(h, doc), "|")
	for _, w := range []string{"Server: nginx", "Cloudflare", "WordPress"} {
		if !strings.Contains(tech, w) {
			t.Errorf("tech missing %s in %s", w, tech)
		}
	}
}
