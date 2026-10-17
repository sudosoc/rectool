// Package extract pulls structured intelligence out of untrusted HTML/text:
// e-mail addresses, phone numbers, social-profile links, page metadata,
// analytics/tracking IDs and technology fingerprints.
package extract

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var (
	scriptRe  = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	styleRe   = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	commentRe = regexp.MustCompile(`(?s)<!--.*?-->`)
	tagRe     = regexp.MustCompile(`(?s)<[^>]*>`)
	spaceRe   = regexp.MustCompile(`\s+`)
)

// Text returns the visible text of an HTML document.
func Text(doc string) string {
	s := scriptRe.ReplaceAllString(doc, " ")
	s = styleRe.ReplaceAllString(s, " ")
	s = commentRe.ReplaceAllString(s, " ")
	s = tagRe.ReplaceAllString(s, " ")
	return spaceRe.ReplaceAllString(html.UnescapeString(s), " ")
}

// ---- e-mail / phone ----------------------------------------------------

var emailRe = regexp.MustCompile(`(?i)[a-z0-9][a-z0-9._%+-]{0,63}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,24}`)

var junkEmailSuffix = []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js", ".woff", ".woff2"}

// Emails returns the distinct, lower-cased addresses in text. It also decodes
// the common "[at]" / "(dot)" obfuscations.
func Emails(text string) []string {
	text = html.UnescapeString(text)
	text = deobfuscate(text)
	seen := map[string]bool{}
	var out []string
	for _, m := range emailRe.FindAllString(text, -1) {
		m = strings.ToLower(strings.TrimRight(m, ".-"))
		bad := false
		for _, s := range junkEmailSuffix {
			if strings.HasSuffix(m, s) {
				bad = true
			}
		}
		if bad || strings.Contains(m, "example.") || strings.HasPrefix(m, "u003e") || seen[m] || placeholderEmail(m) {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

var (
	atRe  = regexp.MustCompile(`(?i)\s*[\[\(\{]\s*at\s*[\]\)\}]\s*`)
	dotRe = regexp.MustCompile(`(?i)\s*[\[\(\{]\s*dot\s*[\]\)\}]\s*`)
)

func deobfuscate(s string) string {
	s = atRe.ReplaceAllString(s, "@")
	return dotRe.ReplaceAllString(s, ".")
}

var (
	telHrefRe = regexp.MustCompile(`(?i)href=["']tel:([^"']{6,30})["']`)
	intlPhone = regexp.MustCompile(`\+\d{1,3}[\s.\-()]*\d[\d\s.\-()]{6,16}\d`)
)

// Phones returns international-format numbers (starting with '+') found in
// text, plus any tel: links. Bare national numbers are ignored on purpose:
// they cannot be told apart from IDs and dates.
func Phones(doc string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(raw string) {
		var b strings.Builder
		for i, r := range raw {
			if r >= '0' && r <= '9' || (r == '+' && i == 0) {
				b.WriteRune(r)
			}
		}
		n := b.String()
		if d := len(strings.TrimPrefix(n, "+")); d < 8 || d > 15 || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, m := range telHrefRe.FindAllStringSubmatch(doc, -1) {
		add(strings.TrimSpace(html.UnescapeString(m[1])))
	}
	for _, m := range intlPhone.FindAllString(Text(doc), -1) {
		add(m)
	}
	return out
}

// ---- links / social ---------------------------------------------------

var hrefRe = regexp.MustCompile(`(?i)<a\s[^>]*?href=["']([^"'#][^"']*)["']`)

// Links returns absolute http(s) URLs of all anchors in doc, resolved
// against base.
func Links(doc, base string) []string {
	b, _ := url.Parse(base)
	seen := map[string]bool{}
	var out []string
	for _, m := range hrefRe.FindAllStringSubmatch(doc, -1) {
		u, err := url.Parse(strings.TrimSpace(html.UnescapeString(m[1])))
		if err != nil {
			continue
		}
		if b != nil {
			u = b.ResolveReference(u)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			continue
		}
		s := u.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Profile is a social-media account referenced by a link.
type Profile struct {
	Platform string `json:"platform"`
	Handle   string `json:"handle"`
	URL      string `json:"url"`
}

var socialRules = []struct {
	platform string
	re       *regexp.Regexp
}{
	{"twitter", regexp.MustCompile(`(?i)^https?://(?:www\.|mobile\.)?(?:twitter|x)\.com/(@?[A-Za-z0-9_]{1,15})/?(?:\?.*)?$`)},
	{"facebook", regexp.MustCompile(`(?i)^https?://(?:www\.|m\.)?facebook\.com/(?:people/[^/]+/)?([A-Za-z0-9.\-]{3,}|\d{6,})/?(?:\?.*)?$`)},
	{"instagram", regexp.MustCompile(`(?i)^https?://(?:www\.)?instagram\.com/([A-Za-z0-9_.]{1,30})/?(?:\?.*)?$`)},
	{"linkedin", regexp.MustCompile(`(?i)^https?://(?:[a-z]{2,3}\.)?linkedin\.com/((?:in|company|school)/[A-Za-z0-9_%\-]+)/?`)},
	{"github", regexp.MustCompile(`(?i)^https?://(?:www\.)?github\.com/([A-Za-z0-9\-]{1,39})/?$`)},
	{"gitlab", regexp.MustCompile(`(?i)^https?://(?:www\.)?gitlab\.com/([A-Za-z0-9_.\-]{2,})/?$`)},
	{"youtube", regexp.MustCompile(`(?i)^https?://(?:www\.)?youtube\.com/((?:@|c/|channel/|user/)[A-Za-z0-9_.\-]+)`)},
	{"tiktok", regexp.MustCompile(`(?i)^https?://(?:www\.)?tiktok\.com/(@[A-Za-z0-9_.]{2,24})`)},
	{"telegram", regexp.MustCompile(`(?i)^https?://(?:t|telegram)\.me/([A-Za-z0-9_]{4,32})/?$`)},
	{"medium", regexp.MustCompile(`(?i)^https?://(?:www\.)?medium\.com/(@[A-Za-z0-9_.\-]+)`)},
	{"reddit", regexp.MustCompile(`(?i)^https?://(?:www\.)?reddit\.com/(?:u|user)/([A-Za-z0-9_\-]{3,20})`)},
	{"pinterest", regexp.MustCompile(`(?i)^https?://(?:www\.)?pinterest\.com/([A-Za-z0-9_]{3,30})/?$`)},
	{"mastodon", regexp.MustCompile(`(?i)^https?://[a-z0-9.\-]+/(@[A-Za-z0-9_]{1,30})/?$`)},
	{"whatsapp", regexp.MustCompile(`(?i)^https?://(?:wa\.me|api\.whatsapp\.com/send\?phone=)/?(\d{7,15})`)},
	{"discord", regexp.MustCompile(`(?i)^https?://discord(?:app)?\.(?:gg|com/invite)/([A-Za-z0-9\-]+)`)},
}

var sharePaths = regexp.MustCompile(`(?i)/(share|sharer|intent|home|login|hashtag|explore|search|about|privacy|terms|policies|help|settings|pages|dialog|plugins)(?:/|\?|\.php|$)`)

// Social recognises social-network profile URLs among links.
func Social(links []string) []Profile {
	seen := map[string]bool{}
	var out []Profile
	for _, l := range links {
		if sharePaths.MatchString(l) {
			continue
		}
		for _, r := range socialRules {
			if m := r.re.FindStringSubmatch(l); m != nil {
				if r.platform == "mastodon" && (strings.Contains(l, "medium.com") || strings.Contains(l, "twitter.com") || strings.Contains(l, "youtube.com") || strings.Contains(l, "tiktok.com")) {
					continue
				}
				key := r.platform + "/" + strings.ToLower(m[1])
				if !seen[key] {
					seen[key] = true
					out = append(out, Profile{Platform: r.platform, Handle: strings.TrimPrefix(m[1], "@"), URL: l})
				}
				break
			}
		}
	}
	return out
}

// ---- metadata ---------------------------------------------------------

// Meta is the descriptive metadata of a page.
type Meta struct {
	Title       string
	Description string
	OGTitle     string
	OGImage     string
	OGSiteName  string
	Author      string
	Generator   string
	Canonical   string
	Keywords    string
}

var (
	titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	metaRe  = regexp.MustCompile(`(?is)<meta\s+([^>]+?)/?>`)
	attrRe  = regexp.MustCompile(`(?is)([a-zA-Z:\-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	linkRe  = regexp.MustCompile(`(?is)<link\s+([^>]+?)/?>`)
)

func attrs(s string) map[string]string {
	m := map[string]string{}
	for _, a := range attrRe.FindAllStringSubmatch(s, -1) {
		v := a[2]
		if v == "" {
			v = a[3]
		}
		m[strings.ToLower(a[1])] = html.UnescapeString(v)
	}
	return m
}

// ParseMeta reads <title>, <meta> and canonical <link> tags.
func ParseMeta(doc string) Meta {
	var m Meta
	if t := titleRe.FindStringSubmatch(doc); t != nil {
		m.Title = strings.TrimSpace(spaceRe.ReplaceAllString(html.UnescapeString(tagRe.ReplaceAllString(t[1], "")), " "))
	}
	for _, mm := range metaRe.FindAllStringSubmatch(doc, -1) {
		a := attrs(mm[1])
		key := strings.ToLower(a["property"])
		if key == "" {
			key = strings.ToLower(a["name"])
		}
		c := strings.TrimSpace(a["content"])
		if c == "" {
			continue
		}
		switch key {
		case "description":
			m.Description = c
		case "og:title":
			m.OGTitle = c
		case "og:description":
			if m.Description == "" {
				m.Description = c
			}
		case "og:image":
			m.OGImage = c
		case "og:site_name":
			m.OGSiteName = c
		case "author", "article:author":
			m.Author = c
		case "generator":
			m.Generator = c
		case "keywords":
			m.Keywords = c
		}
	}
	for _, lm := range linkRe.FindAllStringSubmatch(doc, -1) {
		a := attrs(lm[1])
		if strings.EqualFold(a["rel"], "canonical") {
			m.Canonical = a["href"]
		}
	}
	return m
}

// ---- tracking IDs -----------------------------------------------------

var trackingRules = []struct {
	name string
	re   *regexp.Regexp
}{
	{"google-analytics", regexp.MustCompile(`\b(UA-\d{4,10}-\d{1,3})\b`)},
	{"google-analytics-4", regexp.MustCompile(`\b(G-[A-Z0-9]{8,12})\b`)},
	{"google-tag-manager", regexp.MustCompile(`\b(GTM-[A-Z0-9]{4,8})\b`)},
	{"google-adsense", regexp.MustCompile(`\b(pub-\d{10,18})\b`)},
	{"facebook-pixel", regexp.MustCompile(`fbq\(\s*['"]init['"]\s*,\s*['"](\d{8,20})['"]`)},
	{"hotjar", regexp.MustCompile(`hjid\s*[:=]\s*(\d{5,9})`)},
}

// TrackingIDs returns analytics identifiers by vendor. The same ID on two
// sites is strong evidence that one party runs both.
func TrackingIDs(doc string) map[string][]string {
	out := map[string][]string{}
	for _, r := range trackingRules {
		seen := map[string]bool{}
		for _, m := range r.re.FindAllStringSubmatch(doc, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				out[r.name] = append(out[r.name], m[1])
			}
		}
	}
	return out
}

// ---- technology fingerprints -----------------------------------------

var techBody = []struct {
	name string
	sub  string
}{
	{"WordPress", "/wp-content/"}, {"WordPress", "/wp-includes/"}, {"Drupal", "/sites/default/files"},
	{"Joomla", "/media/jui/"}, {"Shopify", "cdn.shopify.com"}, {"Wix", "static.wixstatic.com"},
	{"Squarespace", "static1.squarespace.com"}, {"Webflow", "assets.website-files.com"},
	{"Ghost", "ghost-sdk"}, {"Magento", "/static/frontend/Magento"}, {"PrestaShop", "/themes/classic/"},
	{"React", "data-reactroot"}, {"Next.js", "/_next/static/"}, {"Nuxt", "/_nuxt/"}, {"Angular", "ng-version"},
	{"Vue.js", "data-v-app"}, {"Gatsby", "___gatsby"}, {"jQuery", "jquery"}, {"Bootstrap", "bootstrap"},
	{"Tailwind CSS", "tailwind"}, {"Cloudflare", "cdnjs.cloudflare.com"}, {"Google Fonts", "fonts.googleapis.com"},
	{"reCAPTCHA", "google.com/recaptcha"}, {"Stripe", "js.stripe.com"}, {"Intercom", "widget.intercom.io"},
	{"HubSpot", "js.hs-scripts.com"}, {"Zendesk", "static.zdassets.com"}, {"Cloudflare Turnstile", "challenges.cloudflare.com"},
}

// Tech guesses the technology stack from response headers and the page body.
func Tech(h http.Header, doc string) []string {
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
		}
	}
	if v := h.Get("Server"); v != "" {
		add("Server: " + v)
	}
	if v := h.Get("X-Powered-By"); v != "" {
		add("X-Powered-By: " + v)
	}
	if h.Get("CF-Ray") != "" {
		add("Cloudflare")
	}
	if h.Get("X-Vercel-Id") != "" {
		add("Vercel")
	}
	if h.Get("X-Amz-Cf-Id") != "" || strings.Contains(h.Get("Via"), "CloudFront") {
		add("AWS CloudFront")
	}
	if h.Get("X-Drupal-Cache") != "" {
		add("Drupal")
	}
	if strings.Contains(strings.ToLower(h.Get("X-Generator")), "drupal") {
		add("Drupal")
	}
	if h.Get("X-Shopify-Stage") != "" {
		add("Shopify")
	}
	low := strings.ToLower(doc)
	for _, t := range techBody {
		if strings.Contains(low, strings.ToLower(t.sub)) {
			add(t.name)
		}
	}
	if m := ParseMeta(doc); m.Generator != "" {
		add("Generator: " + m.Generator)
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var placeholderDomains = map[string]bool{"domain.com": true, "yourdomain.com": true, "yourcompany.com": true,
	"email.com": true, "company.com": true, "test.com": true, "sentry.io": true, "sentry.wixpress.com": true,
	"wixpress.com": true, "mysite.com": true, "website.com": true, "site.com": true, "yoursite.com": true}

var placeholderLocals = map[string]bool{"you": true, "name": true, "user": true, "your": true, "yourname": true,
	"username": true, "email": true, "someone": true, "john.doe": true, "jane.doe": true, "first.last": true}

// placeholderEmail drops obvious template addresses ("you@domain.com") that
// web pages and docs use as form hints.
func placeholderEmail(e string) bool {
	local, domain, ok := strings.Cut(e, "@")
	if !ok {
		return true
	}
	return placeholderDomains[domain] || (placeholderLocals[local] && placeholderDomains[domain])
}
