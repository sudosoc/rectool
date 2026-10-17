package domain

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
)

func lookupCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 6*time.Second)
}

// mailProviders maps substrings of MX hosts / SPF includes to a provider.
var mailProviders = []struct{ sub, name string }{
	{"aspmx.l.google.com", "Google Workspace"}, {"google.com", "Google Workspace"}, {"googlemail.com", "Google Workspace"},
	{"protection.outlook.com", "Microsoft 365"}, {"outlook.com", "Microsoft 365"},
	{"protonmail.ch", "Proton Mail"}, {"zoho.", "Zoho Mail"}, {"mimecast", "Mimecast"},
	{"pphosted.com", "Proofpoint"}, {"yandex.net", "Yandex Mail"}, {"fastmail.com", "Fastmail"},
	{"mailgun.org", "Mailgun"}, {"sendgrid.net", "SendGrid"}, {"amazonses.com", "Amazon SES"},
	{"mandrillapp.com", "Mandrill"}, {"mailchimp", "Mailchimp"}, {"spf.mailjet.com", "Mailjet"},
	{"secureserver.net", "GoDaddy"}, {"ovh.net", "OVH"}, {"hostinger", "Hostinger"}, {"messagingengine.com", "Fastmail"},
	{"icloud.com", "iCloud Mail"}, {"qq.com", "Tencent Exmail"}, {"barracudanetworks.com", "Barracuda"},
}

// verificationTokens identifies SaaS the owner signed up for, from TXT records.
var verificationTokens = []struct{ prefix, service string }{
	{"google-site-verification=", "Google Search Console / Workspace"}, {"ms=ms", "Microsoft 365"},
	{"facebook-domain-verification=", "Facebook / Meta Business"}, {"atlassian-domain-verification=", "Atlassian"},
	{"docusign=", "DocuSign"}, {"stripe-verification=", "Stripe"}, {"apple-domain-verification=", "Apple"},
	{"adobe-idp-site-verification=", "Adobe"}, {"zoom-domain-verification=", "Zoom"},
	{"slack-domain-verification=", "Slack"}, {"onetrust-domain-verification=", "OneTrust"},
	{"have-i-been-pwned-verification=", "Have I Been Pwned"}, {"mailchimp=", "Mailchimp"},
	{"hubspot-developer-verification=", "HubSpot"}, {"shopify-verification-code=", "Shopify"},
	{"github-challenge-", "GitHub org verification"}, {"cisco-ci-domain-verification=", "Cisco"},
	{"miro-verification=", "Miro"}, {"dropbox-domain-verification=", "Dropbox"}, {"airtable-verification=", "Airtable"},
	{"notion-domain-verification=", "Notion"}, {"canva-site-verification=", "Canva"}, {"zapier-domain-verification=", "Zapier"},
	{"detectify-verification=", "Detectify"}, {"_github-pages-challenge", "GitHub Pages"},
	{"postmark-verification", "Postmark"}, {"sendinblue-code", "Brevo (Sendinblue)"}, {"yandex-verification:", "Yandex"},
	{"mongodb-site-verification=", "MongoDB Atlas"}, {"smartsheet-site-validation=", "Smartsheet"},
}

var dkimSelectors = []string{"google", "selector1", "selector2", "default", "k1", "k2", "k3", "mail", "dkim",
	"s1", "s2", "mandrill", "smtp", "zoho", "mxvault", "everlytickey1", "pm", "protonmail"}

func dnsJob(ctx context.Context, _ *httpx.Client, domain string, emit func(models.Finding)) {
	r := net.DefaultResolver
	d := map[string]string{}

	lctx, cancel := lookupCtx(ctx)
	ips, _ := r.LookupIP(lctx, "ip", domain)
	cancel()
	var a4, a6 []string
	var ents []models.Entity
	for _, ip := range ips {
		if ip.To4() != nil {
			a4 = append(a4, ip.String())
			ents = append(ents, models.Entity{Type: models.EntIP, Value: ip.String(), Strong: true})
		} else {
			a6 = append(a6, ip.String())
		}
	}
	sort.Strings(a4)
	sort.Strings(a6)
	put(d, "A", strings.Join(a4, ", "))
	put(d, "AAAA", strings.Join(a6, ", "))

	lctx, cancel = lookupCtx(ctx)
	mxs, _ := r.LookupMX(lctx, domain)
	cancel()
	sort.Slice(mxs, func(i, j int) bool { return mxs[i].Pref < mxs[j].Pref })
	var mxHosts []string
	for _, m := range mxs {
		mxHosts = append(mxHosts, strings.TrimSuffix(m.Host, "."))
	}
	put(d, "MX", strings.Join(mxHosts, ", "))

	lctx, cancel = lookupCtx(ctx)
	nss, _ := r.LookupNS(lctx, domain)
	cancel()
	var nsHosts []string
	for _, n := range nss {
		nsHosts = append(nsHosts, strings.TrimSuffix(n.Host, "."))
	}
	sort.Strings(nsHosts)
	put(d, "NS", strings.Join(nsHosts, ", "))

	lctx, cancel = lookupCtx(ctx)
	txts, _ := r.LookupTXT(lctx, domain)
	cancel()
	put(d, "TXT", list(txts, 12))

	lctx, cancel = lookupCtx(ctx)
	if cn, err := r.LookupCNAME(lctx, domain); err == nil && strings.TrimSuffix(cn, ".") != domain {
		put(d, "CNAME", strings.TrimSuffix(cn, "."))
	}
	cancel()

	if len(d) == 0 {
		emit(errFinding("DNS records", "dns", context.DeadlineExceeded))
		return
	}
	emit(fnd("DNS records", "dns", "", 0.95, d, ents...))

	// ---- e-mail infrastructure ------------------------------------------
	em := map[string]string{}
	providers := map[string]bool{}
	for _, h := range mxHosts {
		for _, p := range mailProviders {
			if strings.Contains(strings.ToLower(h), p.sub) {
				providers[p.name] = true
				break
			}
		}
	}
	var spf string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			spf = t
		}
	}
	if spf != "" {
		put(em, "SPF", spf)
		for _, tok := range strings.Fields(spf) {
			if strings.HasPrefix(tok, "include:") {
				for _, p := range mailProviders {
					if strings.Contains(strings.ToLower(tok), p.sub) {
						providers[p.name] = true
					}
				}
			}
		}
		switch {
		case strings.Contains(spf, "-all"):
			em["SPF policy"] = "strict (-all)"
		case strings.Contains(spf, "~all"):
			em["SPF policy"] = "soft fail (~all)"
		case strings.Contains(spf, "?all"), strings.Contains(spf, "+all"):
			em["SPF policy"] = "permissive — spoofable"
		}
	} else if len(mxHosts) > 0 {
		em["SPF"] = "missing — domain can be spoofed"
	}

	lctx, cancel = lookupCtx(ctx)
	dm, _ := r.LookupTXT(lctx, "_dmarc."+domain)
	cancel()
	var dmarcEnts []models.Entity
	dmarc := ""
	for _, t := range dm {
		if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
			dmarc = t
		}
	}
	if dmarc != "" {
		put(em, "DMARC", dmarc)
		for _, part := range strings.Split(dmarc, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "p=") {
				em["DMARC policy"] = strings.TrimPrefix(part, "p=")
			}
			if strings.HasPrefix(part, "rua=") || strings.HasPrefix(part, "ruf=") {
				for _, addr := range strings.Split(part[4:], ",") {
					addr = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(addr), "mailto:"))
					if i := strings.IndexByte(addr, '!'); i > 0 {
						addr = addr[:i]
					}
					if strings.Contains(addr, "@") {
						dmarcEnts = append(dmarcEnts, models.Entity{Type: models.EntEmail, Value: addr})
					}
				}
			}
		}
	} else if len(mxHosts) > 0 {
		em["DMARC"] = "missing"
	}

	var selectors []string
	for _, sel := range dkimSelectors {
		lctx, cancel = lookupCtx(ctx)
		recs, _ := r.LookupTXT(lctx, sel+"._domainkey."+domain)
		cn, cerr := r.LookupCNAME(lctx, sel+"._domainkey."+domain)
		cancel()
		if len(recs) > 0 || (cerr == nil && cn != "" && !strings.HasPrefix(cn, sel+"._domainkey")) {
			selectors = append(selectors, sel)
		}
		if ctx.Err() != nil {
			return
		}
	}
	put(em, "DKIM selectors found", strings.Join(selectors, ", "))
	var names []string
	for p := range providers {
		names = append(names, p)
	}
	sort.Strings(names)
	put(em, "Mail provider(s)", strings.Join(names, ", "))
	if len(em) > 0 {
		emit(fnd("E-mail infrastructure & security", "email-security", "", 0.9, em, dmarcEnts...))
	}

	// ---- SaaS used by the owner (domain verification tokens) ------------
	var services []string
	seen := map[string]bool{}
	for _, t := range txts {
		lt := strings.ToLower(t)
		for _, v := range verificationTokens {
			if strings.HasPrefix(lt, v.prefix) || strings.Contains(lt, v.prefix) {
				if !seen[v.service] {
					seen[v.service] = true
					services = append(services, v.service)
				}
			}
		}
	}
	if len(services) > 0 {
		sort.Strings(services)
		emit(fnd("Third-party services (from TXT records)", "tech", "", 0.8,
			map[string]string{"services": strings.Join(services, ", "),
				"note": "domain-verification tokens show which SaaS the owner signed up for"}))
	}
}
