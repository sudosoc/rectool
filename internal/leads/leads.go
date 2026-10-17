// Package leads lists, for each identifier, the sources that matter but cannot
// be queried automatically without an account, a CAPTCHA, or payment. rectool
// never works around those barriers; instead it hands the operator ready-made
// links so nothing is silently skipped.
package leads

import (
	"net/url"
	"strings"

	"github.com/sudosoc/rectool/internal/models"
)

func q(s string) string { return url.QueryEscape(s) }
func p(s string) string { return url.PathEscape(s) }

// Build returns the manual follow-ups for t, grouped by identifier type.
func Build(t models.Target) []models.Lead {
	var out []models.Lead
	add := func(group, label, u, why string) {
		out = append(out, models.Lead{Group: group, Label: label, URL: u, Why: why})
	}

	for _, u := range t.Usernames() {
		if len(out) > 400 {
			break
		}
		add("username", "Instagram", "https://www.instagram.com/"+p(u)+"/", "needs login to browse reliably")
		add("username", "X / Twitter", "https://x.com/"+p(u), "blocks anonymous scraping")
		add("username", "Facebook", "https://www.facebook.com/"+p(u), "needs login")
		add("username", "TikTok", "https://www.tiktok.com/@"+p(u), "anti-bot protected")
		add("username", "YouTube", "https://www.youtube.com/@"+p(u), "JavaScript-rendered")
		add("username", "Threads", "https://www.threads.net/@"+p(u), "needs login")
		add("username", "Snapchat", "https://www.snapchat.com/add/"+p(u), "app-first")
		add("username", "LinkedIn (search)", "https://www.linkedin.com/search/results/all/?keywords="+q(u), "needs login")
		add("username", "Web search", "https://www.google.com/search?q="+q(`"`+u+`"`), "search engines block scraping")
		break // the primary handle is enough; aliases are covered by the automatic checks
	}
	if t.FullName != "" {
		add("name", "LinkedIn people", "https://www.linkedin.com/search/results/people/?keywords="+q(t.FullName), "needs login")
		add("name", "Facebook people", "https://www.facebook.com/search/people/?q="+q(t.FullName), "needs login")
		add("name", "X / Twitter people", "https://x.com/search?f=user&q="+q(t.FullName), "needs login")
		add("name", "Web search", "https://www.google.com/search?q="+q(`"`+t.FullName+`"`), "search engines block scraping")
		add("name", "Image search", "https://www.google.com/search?tbm=isch&q="+q(`"`+t.FullName+`"`), "visual identification is manual")
		add("name", "Google Scholar", "https://scholar.google.com/scholar?q="+q(`author:"`+t.FullName+`"`), "CAPTCHA protected")
	}
	if t.Alias != "" {
		add("alias", "Web search", "https://www.google.com/search?q="+q(`"`+t.Alias+`"`), "search engines block scraping")
	}
	if t.Email != "" {
		add("email", "Epieos (accounts by e-mail)", "https://epieos.com/?q="+q(t.Email)+"&t=email", "CAPTCHA / JavaScript")
		add("email", "Have I Been Pwned", "https://haveibeenpwned.com/account/"+p(t.Email), "breach lookup needs a human check")
		add("email", "IntelX", "https://intelx.io/?s="+q(t.Email), "paid / account for full results")
		add("email", "DeHashed", "https://dehashed.com/search?query="+q(t.Email), "paid; breach data")
		add("email", "Web search", "https://www.google.com/search?q="+q(`"`+t.Email+`"`), "search engines block scraping")
	}
	if t.Phone != "" {
		digits := strings.TrimPrefix(t.Phone, "+")
		add("phone", "WhatsApp", "https://wa.me/"+p(digits), "shows a profile photo only if the number is registered and public")
		add("phone", "Telegram", "https://t.me/+"+p(digits), "same")
		add("phone", "Truecaller", "https://www.truecaller.com/search/global/"+p(digits), "needs login")
		add("phone", "Sync.ME", "https://sync.me/search/?number="+q(t.Phone), "needs login")
		add("phone", "Web search", "https://www.google.com/search?q="+q(`"`+t.Phone+`"`), "search engines block scraping")
	}
	if t.Domain != "" {
		d := t.Domain
		add("domain", "VirusTotal", "https://www.virustotal.com/gui/domain/"+p(d), "needs an account for full data")
		add("domain", "urlscan.io", "https://urlscan.io/search/#"+q("domain:"+d), "JavaScript app")
		add("domain", "SecurityTrails", "https://securitytrails.com/domain/"+p(d)+"/dns", "historical DNS is paid")
		add("domain", "Shodan", "https://www.shodan.io/search?query="+q("hostname:"+d), "needs an account")
		add("domain", "Censys", "https://search.censys.io/search?q="+q(d), "needs an account")
		add("domain", "BuiltWith", "https://builtwith.com/"+p(d), "full history is paid")
		add("domain", "Wayback Machine", "https://web.archive.org/web/*/"+d, "interactive calendar")
		add("domain", "ViewDNS reverse WHOIS", "https://viewdns.info/reversewhois/?q="+q(d), "CAPTCHA")
	}
	if t.IP != "" {
		add("ip", "Shodan", "https://www.shodan.io/host/"+p(t.IP), "full banners need an account")
		add("ip", "Censys", "https://search.censys.io/hosts/"+p(t.IP), "needs an account")
		add("ip", "VirusTotal", "https://www.virustotal.com/gui/ip-address/"+p(t.IP), "needs an account")
		add("ip", "AbuseIPDB", "https://www.abuseipdb.com/check/"+p(t.IP), "reports need an account")
		add("ip", "AlienVault OTX", "https://otx.alienvault.com/indicator/ip/"+p(t.IP), "needs an account")
		add("ip", "BGP.HE.net", "https://bgp.he.net/ip/"+p(t.IP), "interactive")
	}
	if t.ASN != "" {
		n := strings.TrimPrefix(t.ASN, "AS")
		add("asn", "BGP.HE.net", "https://bgp.he.net/AS"+p(n), "interactive")
		add("asn", "PeeringDB", "https://www.peeringdb.com/asn/"+p(n), "interactive")
	}
	if t.Company != "" {
		add("company", "OpenCorporates", "https://opencorporates.com/companies?q="+q(t.Company), "CAPTCHA protected")
		add("company", "LinkedIn companies", "https://www.linkedin.com/search/results/companies/?keywords="+q(t.Company), "needs login")
		add("company", "Crunchbase", "https://www.crunchbase.com/textsearch?q="+q(t.Company), "anti-bot protected")
		add("company", "SEC EDGAR", "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company="+q(t.Company), "US filings; needs a contact User-Agent")
		add("company", "Web search", "https://www.google.com/search?q="+q(`"`+t.Company+`"`), "search engines block scraping")
	}
	if t.Wallet != "" {
		w := t.Wallet
		add("wallet", "Chainabuse", "https://www.chainabuse.com/address/"+p(w), "scam reports; JavaScript app")
		add("wallet", "ScamSearch", "https://scamsearch.io/search_report?searchoption=all&search="+q(w), "needs an account")
		add("wallet", "Breadcrumbs / OKLink", "https://www.oklink.com/multi-search#key="+q(w), "multi-chain explorer, JavaScript app")
		if strings.HasPrefix(w, "0x") {
			add("wallet", "Etherscan", "https://etherscan.io/address/"+p(w), "labels and token holdings (CAPTCHA)")
		} else {
			add("wallet", "WalletExplorer", "https://www.walletexplorer.com/address/"+p(w), "clusters wallets by owner")
		}
	}
	return out
}
