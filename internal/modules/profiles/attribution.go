package profiles

import (
	"regexp"
	"sort"
	"strings"

	"github.com/sudosoc/rectool/internal/intel"
	"github.com/sudosoc/rectool/internal/models"
)

// A username is not an identity: "torvalds" on npm or Docker Hub is usually a
// different person from "torvalds" on GitHub. Before any lead from a profile
// is followed, the profile is scored against what we already know:
//
//   - the identifiers the operator supplied (name, e-mail, domain, company, location)
//   - other profiles of the same handle (shared name / website / location)
//   - internal consistency (a commit e-mail whose local part matches the handle)
//
// Only profiles that reach strongThreshold keep their strong entities; the rest
// are reported as unverified, low-confidence leads and are not pivoted on.
const (
	baseScore       = 0.40
	strongThreshold = 0.65
)

var nonLetters = regexp.MustCompile(`[^\p{L}\p{N}]+`)

func normWords(s string) []string {
	var out []string
	for _, w := range strings.Fields(nonLetters.ReplaceAllString(strings.ToLower(s), " ")) {
		if len(w) >= 2 {
			out = append(out, w)
		}
	}
	return out
}

func squash(s string) string { return strings.Join(normWords(s), "") }

// namesMatch: equal token sets, or one side (≥2 tokens) contained in the other.
func namesMatch(a, b string) bool {
	wa, wb := normWords(a), normWords(b)
	if len(wa) < 2 || len(wb) < 2 {
		return false
	}
	return subset(wa, wb) || subset(wb, wa)
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

// shareToken: any word of ≥4 letters in common (locations, company names).
func shareToken(a, b string) bool {
	set := map[string]bool{}
	for _, w := range normWords(a) {
		if len(w) >= 4 {
			set[w] = true
		}
	}
	for _, w := range normWords(b) {
		if len(w) >= 4 && set[w] {
			return true
		}
	}
	return false
}

// profile attributes extracted from one finding.
type attrs struct {
	names     []string
	locations []string
	companies []string
	domains   []string // website / non-free e-mail domains
	emails    []string
}

func attrsOf(f models.Finding) attrs {
	var a attrs
	for _, k := range []string{"name", "full name", "real name", "display name", "commit author names"} {
		if v := f.Details[k]; v != "" {
			a.names = append(a.names, strings.Split(v, ", ")...)
		}
	}
	if v := f.Details["location"]; v != "" {
		a.locations = append(a.locations, v)
	}
	if v := f.Details["company"]; v != "" {
		a.companies = append(a.companies, v)
	}
	for _, e := range f.Entities {
		switch e.Type {
		case models.EntName:
			a.names = append(a.names, e.Value)
		case models.EntDomain:
			a.domains = append(a.domains, e.Value)
		case models.EntEmail:
			a.emails = append(a.emails, e.Value)
			if _, d, ok := strings.Cut(e.Value, "@"); ok && !intel.IsFreeMail(d) {
				a.domains = append(a.domains, d)
			}
		}
	}
	return a
}

func domainMatchesCompany(domain, company string) bool {
	label := squash(strings.SplitN(domain, ".", 2)[0])
	c := squash(company)
	return len(label) >= 4 && len(c) >= 4 && (strings.Contains(c, label) || strings.Contains(label, c))
}

// emailMatchesHandle: the e-mail's local part contains the username (≥4 chars)
// or both the first and last name of the profile.
func emailMatchesHandle(email, user string, names []string) bool {
	local, _, _ := strings.Cut(strings.ToLower(email), "@")
	local = nonLetters.ReplaceAllString(local, "")
	u := nonLetters.ReplaceAllString(strings.ToLower(user), "")
	if len(u) >= 4 && strings.Contains(local, u) {
		return true
	}
	for _, n := range names {
		w := normWords(n)
		if len(w) >= 2 && strings.Contains(local, w[0]) && strings.Contains(local, w[len(w)-1]) {
			return true
		}
	}
	return false
}

// attribute re-scores findings for one username and decides which entities
// stay "strong" (worth following).
func attribute(user string, fs []models.Finding, t models.Target) []models.Finding {
	as := make([]attrs, len(fs))
	for i, f := range fs {
		as[i] = attrsOf(f)
	}
	build := func(i int, force bool) models.Finding {
		f := fs[i]
		a := as[i]
		score := baseScore
		var why []string

		// 1. operator-supplied identifiers
		tname := false
		for _, n := range a.names {
			if t.FullName != "" && namesMatch(n, t.FullName) {
				tname = true
			}
		}
		if tname {
			score += 0.25
			why = append(why, "name matches the supplied full name")
		}
		other := false
		if t.Email != "" {
			for _, e := range a.emails {
				if strings.EqualFold(e, t.Email) {
					other = true
				}
			}
		}
		for _, d := range a.domains {
			if t.Domain != "" && (d == t.Domain || strings.HasSuffix(d, "."+t.Domain)) {
				other = true
			}
			if t.Company != "" && domainMatchesCompany(d, t.Company) {
				other = true
			}
		}
		for _, c := range a.companies {
			if t.Company != "" && shareToken(c, t.Company) {
				other = true
			}
		}
		for _, l := range a.locations {
			if t.Location != "" && shareToken(l, t.Location) {
				other = true
			}
		}
		if other {
			score += 0.15
			why = append(why, "matches supplied email/domain/company/location")
		}

		// 2. agreement with profiles on other platforms
		peer := false
		for j := range fs {
			if j == i || fs[j].Source == f.Source || sameAccount(f.Source, fs[j].Source) {
				continue
			}
			if agree(a, as[j]) {
				peer = true
			}
		}
		if peer {
			score += 0.20
			why = append(why, "details agree with another platform's profile")
		}

		// 3. internal consistency: a contact e-mail that looks like the handle/name
		consistent := false
		for _, e := range a.emails {
			if emailMatchesHandle(e, user, a.names) {
				consistent = true
			}
		}
		if consistent {
			score += 0.25
			why = append(why, "e-mail address matches the handle / name")
		}
		// the website named in a profile agreeing with its company
		for _, d := range a.domains {
			for _, c := range a.companies {
				if domainMatchesCompany(d, c) {
					score += 0.10
					why = append(why, "website matches the company")
				}
			}
		}

		if force && score < strongThreshold {
			score = strongThreshold
			why = append(why, "same GitHub account as a corroborated commit identity")
		}
		if score > 0.95 {
			score = 0.95
		}
		strong := score >= strongThreshold
		nf := f
		nf.Confidence = score
		nf.Details = cloneMap(f.Details)
		if strong {
			nf.Details["attribution"] = "corroborated: " + strings.Join(dedupe(why), "; ")
		} else {
			nf.Details["attribution"] = "unverified: matched by username only — someone else may use this handle"
		}
		nf.Entities = append([]models.Entity(nil), f.Entities...)
		// Context entities: shown to the operator, never followed.
		for _, l := range a.locations {
			nf.Entities = append(nf.Entities, models.Entity{Type: models.EntLocation, Value: strings.TrimSpace(l)})
		}
		for _, c := range a.companies {
			nf.Entities = append(nf.Entities, models.Entity{Type: models.EntOrg, Value: strings.TrimSpace(c)})
		}
		for k := range nf.Entities {
			e := &nf.Entities[k]
			switch {
			case e.Type == models.EntName:
				// names are context, never followed
			case e.Type == models.EntEmail && emailMatchesHandle(e.Value, user, a.names):
				e.Strong = true
			default:
				e.Strong = e.Strong && strong
			}
		}
		return nf
	}

	out := make([]models.Finding, len(fs))
	for i := range fs {
		out[i] = build(i, false)
	}
	// Findings from one GitHub account (profile, keys, commits) stand or fall
	// together: if the commit identity is corroborated, so is the account.
	groupStrong := false
	for i := range out {
		if isGitHub(fs[i].Source) && out[i].Confidence >= strongThreshold {
			groupStrong = true
		}
	}
	if groupStrong {
		for i := range out {
			if isGitHub(fs[i].Source) && out[i].Confidence < strongThreshold {
				out[i] = build(i, true)
			}
		}
	}
	return out
}

func isGitHub(src string) bool { return strings.HasPrefix(src, "GitHub") }

func sameAccount(a, b string) bool {
	return strings.HasPrefix(a, "GitHub") && strings.HasPrefix(b, "GitHub")
}

// agree reports whether two profiles share a name, website domain, or a
// location together with a company.
func agree(a, b attrs) bool {
	for _, x := range a.names {
		for _, y := range b.names {
			if namesMatch(x, y) {
				return true
			}
		}
	}
	for _, x := range a.domains {
		for _, y := range b.domains {
			if x == y {
				return true
			}
		}
	}
	loc, comp := false, false
	for _, x := range a.locations {
		for _, y := range b.locations {
			if shareToken(x, y) {
				loc = true
			}
		}
	}
	for _, x := range a.companies {
		for _, y := range b.companies {
			if shareToken(x, y) {
				comp = true
			}
		}
	}
	return loc && comp
}

func cloneMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
