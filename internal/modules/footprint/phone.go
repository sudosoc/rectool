package footprint

import (
	"regexp"
	"strings"

	"github.com/sudosoc/rectool/internal/models"
)

// callingCodes maps ITU country calling codes to a country label. Longest
// prefix wins (3, then 2, then 1 digits). Not exhaustive; unknown codes are
// simply reported without a country.
var callingCodes = map[string]string{
	"1": "US/CA (NANP)", "7": "RU/KZ", "20": "Egypt", "27": "South Africa", "30": "Greece",
	"31": "Netherlands", "32": "Belgium", "33": "France", "34": "Spain", "36": "Hungary",
	"39": "Italy", "40": "Romania", "41": "Switzerland", "43": "Austria", "44": "United Kingdom",
	"45": "Denmark", "46": "Sweden", "47": "Norway", "48": "Poland", "49": "Germany",
	"51": "Peru", "52": "Mexico", "54": "Argentina", "55": "Brazil", "56": "Chile",
	"57": "Colombia", "58": "Venezuela", "60": "Malaysia", "61": "Australia", "62": "Indonesia",
	"63": "Philippines", "64": "New Zealand", "65": "Singapore", "66": "Thailand", "81": "Japan",
	"82": "South Korea", "84": "Vietnam", "86": "China", "90": "Turkey", "91": "India",
	"92": "Pakistan", "93": "Afghanistan", "94": "Sri Lanka", "98": "Iran", "212": "Morocco",
	"213": "Algeria", "216": "Tunisia", "218": "Libya", "234": "Nigeria", "254": "Kenya",
	"351": "Portugal", "353": "Ireland", "358": "Finland", "380": "Ukraine", "420": "Czechia",
	"880": "Bangladesh", "961": "Lebanon", "962": "Jordan", "964": "Iraq", "965": "Kuwait",
	"966": "Saudi Arabia", "971": "UAE", "972": "Israel", "974": "Qatar",
}

// phoneInfo is the offline analysis of a phone number.
type phoneInfo struct {
	digits   string // all digits as supplied
	cc       string // calling code, "" when unknown
	national string // digits after the calling code
	country  string
}

func parsePhone(p string) phoneInfo {
	var b strings.Builder
	for _, r := range p {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	pi := phoneInfo{digits: b.String(), national: b.String()}
	if !strings.HasPrefix(p, "+") {
		return pi
	}
	for n := 3; n >= 1; n-- {
		if len(pi.digits) > n+4 {
			if c, ok := callingCodes[pi.digits[:n]]; ok {
				pi.cc, pi.national, pi.country = pi.digits[:n], pi.digits[n:], c
				break
			}
		}
	}
	return pi
}

func group(s string, sizes ...int) string {
	var parts []string
	for _, n := range sizes {
		if len(s) < n {
			break
		}
		parts, s = append(parts, s[:n]), s[n:]
	}
	if s != "" {
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

// variants lists the written forms worth searching for.
func (pi phoneInfo) variants() []string {
	if pi.cc == "" {
		return []string{pi.digits, group(pi.digits, 3, 3, 4)}
	}
	v := []string{"+" + pi.digits}
	if pi.cc == "1" && len(pi.national) == 10 {
		n := pi.national
		return append(v, "("+n[:3]+") "+n[3:6]+"-"+n[6:], n[:3]+"-"+n[3:6]+"-"+n[6:], "+1 "+n[:3]+" "+n[3:6]+" "+n[6:])
	}
	return append(v, "+"+pi.cc+" "+group(pi.national, 3, 3, 3), "0"+pi.national)
}

func (pi phoneInfo) finding() models.Finding {
	d := map[string]string{"digits": pi.digits, "variants": strings.Join(pi.variants(), " | ")}
	if pi.cc != "" {
		d["country_code"], d["country"], d["national"] = "+"+pi.cc, pi.country, pi.national
	} else {
		d["note"] = "no leading '+': country could not be determined"
	}
	return models.Finding{Source: "phone analysis", Category: "phone", Status: models.StatusFound, Confidence: 0.9, Details: d}
}

// sepPattern builds a regex that matches the digit string with any usual
// separators ( ) - . whitespace between digits.
func sepPattern(digits string) string {
	parts := make([]string, len(digits))
	for i, d := range digits {
		parts[i] = string(d)
	}
	return strings.Join(parts, `[\s().\-]*`)
}

// phoneMatcher finds the number in any common formatting. International form
// (country code + national) scores higher than national form alone, which is
// more ambiguous.
func (pi phoneInfo) matcher() matcher {
	const pre, post = `(?:^|[^0-9])`, `(?:[^0-9]|$)`
	full := pi.digits
	alts := []string{`\+?[\s]*` + sepPattern(full)}
	if pi.cc != "" && len(pi.national) >= 8 {
		alts = append(alts, `0?`+sepPattern(pi.national))
	}
	re := regexp.MustCompile(pre + `(?:` + strings.Join(alts, `|`) + `)` + post)
	return matcher{
		re: re,
		conf: func(m string) float64 {
			if pi.cc != "" && !strings.Contains(m, "+") && countDigits(m) <= len(pi.national)+1 {
				return 0.6 // national form only
			}
			return 0.85
		},
	}
}

func countDigits(s string) int {
	n := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			n++
		}
	}
	return n
}
