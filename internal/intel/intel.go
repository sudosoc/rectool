// Package intel holds small, dependency-free helpers shared by the planner and
// the modules: input normalisation and static knowledge lists.
package intel

import (
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

var freeMail = setOf("gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com", "hotmail.com",
	"live.com", "msn.com", "proton.me", "protonmail.com", "pm.me", "icloud.com", "me.com", "mac.com", "aol.com",
	"gmx.com", "gmx.net", "mail.com", "zoho.com", "yandex.com", "yandex.ru", "mail.ru", "qq.com", "163.com",
	"126.com", "web.de", "t-online.de", "orange.fr", "free.fr", "libero.it", "rediffmail.com", "tutanota.com",
	"tuta.io", "fastmail.com", "hey.com")

var disposable = setOf("mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
	"yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com", "throwawaymail.com",
	"maildrop.cc", "dispostable.com", "fakeinbox.com", "temp-mail.org")

func setOf(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}

// IsFreeMail reports whether d is a public mailbox provider (a domain that
// says nothing about the person's employer or own website).
func IsFreeMail(d string) bool { return freeMail[strings.ToLower(d)] }

// IsDisposable reports whether d is a throwaway-mail provider.
func IsDisposable(d string) bool { return disposable[strings.ToLower(d)] }

var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$`)

// NormalizeDomain accepts a host name or a URL ("https://www.Example.com/x?y")
// and returns the lower-case host name. ok is false when it is not a valid
// DNS name (IP literals are rejected; use NormalizeIP for those).
func NormalizeDomain(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", false
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if _, err := netip.ParseAddr(h); err == nil {
		return "", false
	}
	if !domainRe.MatchString(h) {
		return "", false
	}
	return h, true
}

// NormalizeIP parses an IPv4/IPv6 address (brackets and zone are tolerated).
func NormalizeIP(s string) (netip.Addr, bool) {
	s = strings.Trim(strings.TrimSpace(s), "[]")
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.WithZone(""), true
}

// ReverseDNSName returns the label sequence used for reverse DNS lookups
// without the arpa suffix: "4.3.2.1" for 1.2.3.4, nibble-reversed for IPv6.
func ReverseDNSName(a netip.Addr) string {
	if a.Is4() {
		b := a.As4()
		return itoa(b[3]) + "." + itoa(b[2]) + "." + itoa(b[1]) + "." + itoa(b[0])
	}
	const hexd = "0123456789abcdef"
	b := a.As16()
	var sb strings.Builder
	for i := 15; i >= 0; i-- {
		sb.WriteByte(hexd[b[i]&0xf])
		sb.WriteByte('.')
		sb.WriteByte(hexd[b[i]>>4])
		if i > 0 {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

func itoa(b byte) string {
	if b == 0 {
		return "0"
	}
	var d [3]byte
	i := 3
	for b > 0 {
		i--
		d[i] = '0' + b%10
		b /= 10
	}
	return string(d[i:])
}

// PublicIP reports whether a is a globally routable unicast address (not
// private, loopback, link-local, multicast or unspecified).
func PublicIP(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast()
}
