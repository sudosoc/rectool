package dorks

import (
	"fmt"
	"strings"

	"github.com/sudosoc/rectool/internal/models"
)

// Dork is one search query plus the intelligence category it targets.
type Dork struct {
	Query    string
	Category string
}

// Generate builds search dorks from every identifier the target carries,
// ordered from highest to lowest expected value so a MaxDorks cap drops the
// weakest first. Domain/company/IP dorks come first because they are the most
// specific.
func Generate(t models.Target) []Dork {
	var out []Dork
	add := func(cat, format string, a ...any) { out = append(out, Dork{fmt.Sprintf(format, a...), cat}) }
	loc := t.Location

	if d := t.Domain; d != "" {
		add("domain", `site:%s`, d)
		add("documents", `site:%s (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:ppt OR filetype:pptx)`, d)
		add("exposure", `site:%s (filetype:env OR filetype:sql OR filetype:bak OR filetype:log OR filetype:conf OR filetype:ini OR filetype:yml OR filetype:xml)`, d)
		add("exposure", `site:%s intitle:"index of"`, d)
		add("admin", `site:%s (inurl:admin OR inurl:login OR inurl:dashboard OR inurl:portal OR inurl:signin)`, d)
		add("exposure", `site:%s (intext:"sql syntax near" OR intext:"Warning: mysql" OR intext:"Fatal error" OR intext:"stack trace")`, d)
		add("subdomain", `site:*.%s -site:www.%s`, d, d)
		add("email", `"@%s"`, d)
		add("leaks", `"@%s" (site:pastebin.com OR site:ghostbin.com OR site:paste.ee OR site:controlc.com)`, d)
		add("code", `"%s" (site:github.com OR site:gitlab.com OR site:bitbucket.org OR site:gist.github.com)`, d)
		add("mentions", `"%s" -site:%s`, d, d)
		add("people", `site:linkedin.com/in "%s"`, d)
	}
	if c := t.Company; c != "" {
		add("company", `"%s"`, c)
		if loc != "" {
			add("company", `"%s" "%s"`, c, loc)
		}
		add("profile", `"%s" site:linkedin.com/company`, c)
		add("company", `"%s" (site:crunchbase.com OR site:opencorporates.com OR site:glassdoor.com OR site:bloomberg.com OR site:dnb.com)`, c)
		add("people", `"%s" site:linkedin.com/in`, c)
		add("documents", `"%s" (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx)`, c)
		add("email", `"%s" ("@" OR "email" OR "contact")`, c)
		add("code", `"%s" (site:github.com OR site:gitlab.com OR site:pastebin.com)`, c)
	}
	if ip := t.IP; ip != "" {
		add("ip", `"%s"`, ip)
		add("reputation", `"%s" (site:abuseipdb.com OR site:virustotal.com OR site:otx.alienvault.com OR site:greynoise.io)`, ip)
		add("leaks", `"%s" (site:pastebin.com OR site:github.com OR site:gist.github.com)`, ip)
	}
	if n := t.FullName; n != "" {
		add("name", `"%s"`, n)
		if loc != "" {
			add("name", `"%s" "%s"`, n, loc)
		}
		for _, site := range []string{"linkedin.com/in", "facebook.com", "twitter.com", "instagram.com", "github.com"} {
			add("profile", `"%s" site:%s`, n, site)
		}
		add("documents", `"%s" (filetype:pdf OR filetype:doc OR filetype:docx)`, n)
		add("documents", `"%s" (resume OR cv OR "curriculum vitae")`, n)
		add("documents", `"%s" (filetype:xls OR filetype:xlsx OR filetype:csv)`, n)
		if c := t.Company; c != "" {
			add("people", `"%s" "%s"`, n, c)
		}
	}
	if w := t.Wallet; w != "" {
		add("crypto", `"%s"`, w)
		add("crypto", `"%s" (scam OR fraud OR phishing OR ransomware OR "bitcoin abuse" OR stolen)`, w)
		add("leaks", `"%s" (site:pastebin.com OR site:github.com OR site:gist.github.com OR site:reddit.com OR site:twitter.com)`, w)
	}
	if a := t.ASN; a != "" {
		add("network", `"%s"`, a)
	}
	if a := t.Alias; a != "" {
		add("alias", `"%s"`, a)
		if loc != "" {
			add("alias", `"%s" "%s"`, a, loc)
		}
		add("profile", `"%s" (site:twitter.com OR site:instagram.com OR site:facebook.com OR site:tiktok.com OR site:youtube.com)`, a)
		add("leaks", `"%s" (site:pastebin.com OR site:github.com OR site:reddit.com)`, a)
	}
	if e := t.Email; e != "" {
		local, domain, _ := strings.Cut(e, "@")
		add("email", `"%s"`, e)
		add("leaks", `"%s" (site:pastebin.com OR site:ghostbin.com OR site:paste.ee)`, e)
		add("leaks", `"%s" (filetype:txt OR filetype:log OR filetype:csv OR filetype:sql)`, e)
		add("code", `"%s" (site:github.com OR site:gitlab.com OR site:bitbucket.org)`, e)
		if domain != "" {
			add("email", `"%s" -site:%s`, e, domain)
		}
		if local != "" {
			add("email", `intext:"%s" intext:"@"`, local)
		}
	}
	if u := t.Username; u != "" {
		add("username", `"%s"`, u)
		add("username", `inurl:"%s" -site:github.com`, u)
		add("leaks", `"%s" (site:pastebin.com OR site:ghostbin.com)`, u)
		add("code", `"%s" (site:github.com OR site:gitlab.com)`, u)
	}
	if p := t.Phone; p != "" {
		add("phone", `"%s"`, p)
		if d := strings.TrimPrefix(p, "+"); d != p {
			add("phone", `"%s"`, d)
		}
		add("leaks", `"%s" (filetype:pdf OR filetype:xls OR filetype:txt)`, p)
	}
	return out
}
