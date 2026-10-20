// Package cvparse pulls structured facts out of the plain text of a CV /
// resume: contact points, education, employers, skills, interests and a
// location. It is heuristic by nature (CV layouts are free-form), so callers
// treat the output as claims to corroborate, not as ground truth.
package cvparse

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/sudosoc/rectool/internal/extract"
)

// CV is the structured view of a resume.
type CV struct {
	Name      string
	Emails    []string
	Phones    []string
	Location  string
	Education []string
	Employers []string
	Skills    []string
	Interests []string
	Summary   string
	Links     []string
}

var headings = []struct {
	section string
	re      *regexp.Regexp
}{
	{"education", regexp.MustCompile(`(?i)^(education|academic (background|qualifications)|qualifications|studies)\b`)},
	{"experience", regexp.MustCompile(`(?i)^(work |professional |employment |relevant )?(experience|history)\b|^(employment|career)\b`)},
	{"skills", regexp.MustCompile(`(?i)^((technical|core|key) )?(skills|competenc(ies|e)|expertise|technologies)\b`)},
	{"interests", regexp.MustCompile(`(?i)^(interests|hobbies|activities)\b`)},
	{"summary", regexp.MustCompile(`(?i)^(summary|profile|about( me)?|objective|personal statement)\b`)},
	{"other", regexp.MustCompile(`(?i)^(languages|projects|publications|certifications?|awards|references|volunteer(ing)?)\b`)},
}

var (
	dateRange = regexp.MustCompile(`(?i)\b((19|20)\d\d)\s*(-|–|—|to)\s*(((19|20)\d\d)|present|current|now|ongoing)\b`)
	eduWord   = regexp.MustCompile(`(?i)\b(universit\w*|college|institute|school of|b\.?\s?sc|m\.?\s?sc|ph\.?d|bachelor|master|diploma|faculty|academy|b\.?eng|m\.?eng|mba)\b`)
	locLabel  = regexp.MustCompile(`(?i)^(?:location|address|city|based in|lives in)\s*[:\-]\s*(.{3,60})$`)
	cityLine  = regexp.MustCompile(`^[\p{Lu}][\p{L} .'\-]{1,30},\s*[\p{Lu}][\p{L} .'\-]{1,30}$`)
	urlRe     = regexp.MustCompile(`https?://[^\s<>"')]+`)
	bullets   = strings.NewReplacer("•", "\n", "·", "\n", "●", "\n", "▪", "\n", "|", "\n", ";", "\n")
)

// Parse reads a resume's text.
func Parse(text string) CV {
	text = strings.ReplaceAll(text, "\r", "")
	var lines []string
	for _, l := range strings.Split(text, "\n") {
		if l = strings.Join(strings.Fields(l), " "); l != "" {
			lines = append(lines, l)
		}
	}
	cv := CV{Emails: extract.Emails(text), Phones: extract.Phones(text)}
	for _, u := range urlRe.FindAllString(text, -1) {
		cv.Links = appendUnique(cv.Links, strings.TrimRight(u, ".,"))
	}

	sections := map[string][]string{}
	cur := ""
	for i, l := range lines {
		if sec := headingOf(l); sec != "" {
			cur = sec
			continue
		}
		if i < 12 && cv.Name == "" && looksLikeName(l) {
			cv.Name = l
		}
		if cur != "" {
			sections[cur] = append(sections[cur], l)
		}
	}

	for i, l := range lines {
		if m := locLabel.FindStringSubmatch(l); m != nil {
			cv.Location = coarsePlace(strings.TrimSpace(m[1]))
			break
		}
		if i < 14 && cv.Location == "" && cityLine.MatchString(l) && !looksLikeName(l) && len(strings.Fields(l)) <= 5 {
			cv.Location = l
		}
	}

	for _, l := range sections["education"] {
		if eduWord.MatchString(l) && len(l) <= 140 {
			cv.Education = appendUnique(cv.Education, l)
		}
	}
	if len(cv.Education) == 0 { // some CVs have no heading
		for _, l := range lines {
			if eduWord.MatchString(l) && len(l) <= 100 && !dateOnly(l) {
				cv.Education = appendUnique(cv.Education, l)
				if len(cv.Education) >= 4 {
					break
				}
			}
		}
	}
	exp := sections["experience"]
	for i, l := range exp {
		if !dateRange.MatchString(l) {
			continue
		}
		cand := strings.TrimSpace(dateRange.ReplaceAllString(l, ""))
		cand = strings.Trim(cand, " -–—|,·()")
		if len(cand) < 3 && i > 0 {
			cand = exp[i-1]
		}
		if len(cand) < 3 && i+1 < len(exp) {
			cand = exp[i+1]
		}
		if len(cand) >= 3 && len(cand) <= 90 && !dateOnly(cand) {
			cv.Employers = appendUnique(cv.Employers, cand)
		}
		if len(cv.Employers) >= 8 {
			break
		}
	}
	cv.Skills = items(sections["skills"], 40)
	cv.Interests = items(sections["interests"], 20)
	if s := strings.Join(sections["summary"], " "); s != "" {
		cv.Summary = strings.TrimSpace(clip(s, 400))
	}
	return cv
}

func headingOf(l string) string {
	t := strings.Trim(l, " :-–—_*#")
	if len(t) > 40 || len(t) < 3 {
		return ""
	}
	for _, h := range headings {
		if h.re.MatchString(t) {
			return h.section
		}
	}
	return ""
}

func looksLikeName(l string) bool {
	if strings.ContainsAny(l, "@0123456789:/,") {
		return false
	}
	w := strings.Fields(l)
	if len(w) < 2 || len(w) > 4 || headingOf(l) != "" {
		return false
	}
	for _, x := range w {
		r := []rune(strings.Trim(x, ".,"))
		if len(r) == 0 || !unicode.IsLetter(r[0]) || !unicode.IsUpper(r[0]) {
			return false
		}
	}
	low := strings.ToLower(l)
	for _, bad := range []string{"curriculum", "resume", "resumé", "page ", "contact", "university", "engineer", "developer", "manager"} {
		if strings.Contains(low, bad) {
			return false
		}
	}
	return true
}

func dateOnly(s string) bool {
	return strings.TrimSpace(dateRange.ReplaceAllString(s, "")) == ""
}

func items(lines []string, max int) []string {
	var out []string
	for _, l := range lines {
		for _, p := range strings.FieldsFunc(bullets.Replace(l), func(r rune) bool { return r == '\n' || r == ',' }) {
			p = strings.Trim(strings.TrimSpace(p), "-–—:*")
			if len(p) >= 2 && len(p) <= 32 {
				out = appendUnique(out, p)
			}
			if len(out) >= max {
				return out
			}
		}
	}
	return out
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if strings.EqualFold(x, v) {
			return s
		}
	}
	return append(s, v)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

var streetWord = regexp.MustCompile(`(?i)(^\d|\b(street|st\.|road|rd\.|avenue|ave\.|apt|apartment|floor|building|blvd|lane|ln\.|p\.?o\.? box)\b|شارع|عمارة)`)

// coarsePlace keeps a CV's location at city level: street-level parts of an
// address ("12 Nile St, Apt 4, Cairo, Egypt") are dropped on purpose.
func coarsePlace(s string) string {
	parts := strings.Split(s, ",")
	var keep []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" && !streetWord.MatchString(p) {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, ", ")
}
