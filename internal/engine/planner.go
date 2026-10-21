package engine

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode"

	"github.com/sudosoc/rectool/internal/extract"
	"github.com/sudosoc/rectool/internal/intel"
	"github.com/sudosoc/rectool/internal/models"
)

// Enrich is the "intelligence" step that runs before dispatch: it validates
// and normalises the inputs and derives extra pivots from them (candidate
// usernames, the e-mail's own domain). It mutates t in place.
func Enrich(t *models.Target, deriveFromName bool, maxAliases int) error {
	t.Username = strings.TrimSpace(t.Username)
	t.FullName = strings.Join(strings.Fields(t.FullName), " ")
	t.Company = strings.Join(strings.Fields(t.Company), " ")
	t.Location = strings.Join(strings.Fields(t.Location), " ")
	t.Phone = normalisePhone(t.Phone)

	if t.Email != "" {
		addr, err := mail.ParseAddress(strings.TrimSpace(t.Email))
		if err != nil {
			return fmt.Errorf("email: %w", err)
		}
		t.Email = strings.ToLower(addr.Address)
	}
	t.Alias = strings.Join(strings.Fields(t.Alias), " ")
	t.Notes = strings.TrimSpace(t.Notes)
	if len(t.Notes) > 30000 {
		t.Notes = t.Notes[:30000]
	}
	if t.Domain != "" {
		// A pasted profile link (twitter.com/x, github.com/x, …) is a username,
		// not a domain to investigate.
		if prof, ok := profileFromURL(t.Domain); ok {
			link := strings.TrimSpace(t.Domain)
			if !strings.Contains(link, "://") {
				link = "https://" + link
			}
			t.Links = appendLink(t.Links, link)
			if isLinkedIn(link) {
				// A LinkedIn vanity slug is rarely the handle used elsewhere, so it is
				// not probed as a username; its name part is a usable full name.
				if t.FullName == "" {
					t.FullName = nameFromSlug(prof)
				}
			} else if t.Username == "" {
				t.Username = prof
			} else if !strings.EqualFold(t.Username, prof) {
				t.Aliases = append(t.Aliases, prof)
			}
			t.Domain = ""
		} else {
			d, ok := intel.NormalizeDomain(t.Domain)
			if !ok {
				return fmt.Errorf("domain: %q is not a valid domain or URL", t.Domain)
			}
			t.Domain = d
		}
	}
	if t.ASN != "" {
		asn, ok := normaliseASN(t.ASN)
		if !ok {
			return fmt.Errorf("asn: %q is not an AS number (e.g. AS13335)", t.ASN)
		}
		t.ASN = asn
	}
	if t.Wallet != "" {
		t.Wallet = strings.TrimSpace(t.Wallet)
		if !validWallet(t.Wallet) {
			return fmt.Errorf("wallet: %q is not a Bitcoin or Ethereum address", t.Wallet)
		}
	}
	if t.IP != "" {
		a, ok := intel.NormalizeIP(t.IP)
		if !ok {
			return fmt.Errorf("ip: %q is not a valid IP address", t.IP)
		}
		t.IP = a.String()
	}

	// An e-mail on a non-public domain points at the person's employer or own
	// site: investigate that domain too.
	if at := strings.LastIndexByte(t.Email, '@'); at > 0 && t.Domain == "" {
		if d := t.Email[at+1:]; !intel.IsFreeMail(d) && !intel.IsDisposable(d) {
			if nd, ok := intel.NormalizeDomain(d); ok {
				t.Domain = nd
			}
		}
	}

	var aliases []string
	if at := strings.LastIndexByte(t.Email, '@'); at > 0 {
		local := t.Email[:at]
		if plus := strings.IndexByte(local, '+'); plus > 0 {
			local = local[:plus] // drop +tag
		}
		aliases = append(aliases, localVariants(local)...)
	}
	if deriveFromName {
		aliases = append(aliases, namePermutations(t.FullName)...)
	}
	aliases = append(aliases, aliasVariants(t.Alias)...)

	seen := map[string]bool{strings.ToLower(t.Username): true}
	kept := append([]string(nil), t.Aliases...) // aliases already present (e.g. from a pasted profile URL)
	t.Aliases = t.Aliases[:0]
	for _, a := range append(kept, aliases...) {
		a = strings.TrimSpace(a)
		if len(a) < 3 || seen[strings.ToLower(a)] {
			continue
		}
		seen[strings.ToLower(a)] = true
		t.Aliases = append(t.Aliases, a)
		if maxAliases > 0 && len(t.Aliases) >= maxAliases {
			break
		}
	}
	return nil
}

// normalisePhone keeps digits and a single leading '+'.
func normalisePhone(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	var b strings.Builder
	for i, r := range p {
		switch {
		case unicode.IsDigit(r):
			b.WriteRune(r)
		case r == '+' && i == 0:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// namePermutations produces the handful of username shapes people most often
// pick for a "First [Middle] Last" name.
func namePermutations(full string) []string {
	var parts []string
	for _, p := range strings.Fields(full) {
		if s := asciiLower(p); s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) < 2 {
		return nil
	}
	f, l := parts[0], parts[len(parts)-1]
	return []string{
		f + l, f + "." + l, f + "_" + l, f + "-" + l,
		f[:1] + l, f + l[:1], l + f, l + "." + f,
	}
}

func asciiLower(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var (
	asnRe = regexp.MustCompile(`(?i)^(?:AS)?(\d{1,10})$`)
	btcRe = regexp.MustCompile(`^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,87})$`)
	ethRe = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
)

func normaliseASN(s string) (string, bool) {
	m := asnRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", false
	}
	return "AS" + m[1], true
}

func validWallet(s string) bool { return btcRe.MatchString(s) || ethRe.MatchString(s) }

// aliasVariants turns a nickname into the handles people derive from it:
// "Dark Knight" -> darkknight, dark.knight, dark_knight, dark-knight.
func aliasVariants(alias string) []string {
	words := strings.Fields(strings.ToLower(alias))
	for i, w := range words {
		words[i] = strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				return r
			}
			return -1
		}, w)
	}
	var clean []string
	for _, w := range words {
		if w != "" {
			clean = append(clean, w)
		}
	}
	switch len(clean) {
	case 0:
		return nil
	case 1:
		return clean
	}
	return []string{strings.Join(clean, ""), strings.Join(clean, "."), strings.Join(clean, "_"), strings.Join(clean, "-")}
}

// profileFromURL recognises social-network profile links and returns the handle.
func profileFromURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	ps := extract.Social([]string{raw})
	if len(ps) == 0 {
		return "", false
	}
	h := ps[0].Handle
	for _, pre := range []string{"in/", "company/", "school/", "c/", "channel/", "user/"} {
		h = strings.TrimPrefix(h, pre)
	}
	h = strings.Trim(h, "/@ ")
	return h, h != ""
}

func appendLink(links []string, l string) []string {
	for _, x := range links {
		if strings.EqualFold(strings.TrimSuffix(x, "/"), strings.TrimSuffix(l, "/")) {
			return links
		}
	}
	return append(links, l)
}

func isLinkedIn(link string) bool { return strings.Contains(strings.ToLower(link), "linkedin.com/") }

// nameFromSlug turns "jane-roe-1a2b3c" into "Jane Roe" (a trailing token that
// contains digits is LinkedIn's disambiguation suffix, not part of the name).
func nameFromSlug(slug string) string {
	var parts []string
	for _, w := range strings.FieldsFunc(slug, func(r rune) bool { return r == '-' || r == '_' || r == '.' }) {
		if strings.IndexFunc(w, unicode.IsDigit) >= 0 {
			continue
		}
		parts = append(parts, strings.ToUpper(w[:1])+w[1:])
	}
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts, " ")
}

// localVariants returns the e-mail local part and the handles people commonly
// build from the same stem: "vindiesel2791978" is usually "vindiesel" elsewhere,
// and "john.doe" is "johndoe" or "john_doe".
func localVariants(local string) []string {
	out := []string{local}
	stem := strings.TrimRight(local, "0123456789")
	if len(local)-len(stem) >= 2 && len(stem) >= 4 {
		out = append(out, stem)
	}
	if strings.ContainsAny(local, "._-") {
		flat := strings.NewReplacer(".", "", "_", "", "-", "").Replace(local)
		out = append(out, flat, strings.ReplaceAll(local, ".", "_"), strings.ReplaceAll(strings.ReplaceAll(local, "_", "."), "-", "."))
	}
	return out
}
