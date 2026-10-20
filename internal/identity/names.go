// Package identity resolves a pile of per-source person records into distinct
// people. Facts about different individuals who merely share a name or a handle
// must never be merged, so records are clustered only on evidence (shared
// e-mail, phone, unique IDs, linked accounts and websites, the same profile
// picture, or the same name plus several matching attributes) and every
// resulting identity is scored against what the operator actually supplied.
package identity

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// fold lower-cases, strips diacritics and collapses everything that is not a
// letter or digit to single spaces ("José  O'Neil" -> "jose o neil").
func fold(s string) string {
	var b strings.Builder
	prevSpace := true
	for _, r := range norm.NFD.String(strings.ToLower(s)) {
		switch {
		case unicode.Is(unicode.Mn, r):
			continue
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			prevSpace = false
		default:
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
		}
	}
	return strings.TrimSpace(b.String())
}

func words(s string) []string { return strings.Fields(fold(s)) }

// NameMatch is how well two personal names agree.
type NameMatch int

const (
	NameNone    NameMatch = iota
	NamePartial           // initials, or a single shared word
	NameStrong            // same words in any order, or one is the other minus a middle name
)

// MatchNames compares two personal names, tolerant of order, accents, middle
// names and initials ("J. Roe" ~ "Jane Roe").
func MatchNames(a, b string) NameMatch {
	wa, wb := words(a), words(b)
	if len(wa) == 0 || len(wb) == 0 {
		return NameNone
	}
	if len(wa) >= 2 && len(wb) >= 2 {
		if subset(wa, wb) || subset(wb, wa) {
			return NameStrong
		}
		// initial + same last word: "j roe" vs "jane roe"
		fa, la := wa[0], wa[len(wa)-1]
		fb, lb := wb[0], wb[len(wb)-1]
		if la == lb && (len(fa) == 1 && strings.HasPrefix(fb, fa) || len(fb) == 1 && strings.HasPrefix(fa, fb)) {
			return NamePartial
		}
		return NameNone
	}
	// a mononym / handle-like name against a full name: only a partial hint
	short, long := wa, wb
	if len(wb) < len(wa) {
		short, long = wb, wa
	}
	if len(short) == 1 && len(short[0]) >= 4 {
		for _, w := range long {
			if w == short[0] {
				return NamePartial
			}
		}
	}
	return NameNone
}

func subset(small, big []string) bool {
	set := map[string]bool{}
	for _, w := range big {
		set[w] = true
	}
	for _, w := range small {
		if !set[w] {
			return false
		}
	}
	return true
}

// overlap reports whether two free-text values (places, organisations,
// schools) share a meaningful word.
func overlap(a, b string) bool {
	fa, fb := fold(a), fold(b)
	if fa == "" || fb == "" {
		return false
	}
	if fa == fb {
		return true
	}
	set := map[string]bool{}
	for _, w := range strings.Fields(fa) {
		if len(w) >= 4 && !stop[w] {
			set[w] = true
		}
	}
	for _, w := range strings.Fields(fb) {
		if len(w) >= 4 && set[w] {
			return true
		}
	}
	return false
}

// stop words that make poor evidence on their own.
var stop = map[string]bool{
	"university": true, "college": true, "institute": true, "school": true, "united": true, "states": true,
	"company": true, "limited": true, "corporation": true, "group": true, "technologies": true, "technology": true,
	"international": true, "national": true, "kingdom": true, "republic": true, "city": true, "area": true,
	"greater": true, "region": true, "inc": true, "llc": true, "ltd": true, "the": true,
}

// Words returns the folded (lower-case, accent-free) words of a name.
func Words(s string) []string { return words(s) }
