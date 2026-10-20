package identity

import (
	"net/url"
	"sort"
	"strings"

	"github.com/sudosoc/rectool/internal/models"
)

type acc struct {
	display   string
	platforms map[string]bool
	self      bool
	extra     int // tie-breaker: insertion order
}

type accList struct {
	items []*acc
	same  func(a, b string) bool
	pick  func(old, new string) string // which display value to keep when two merge
}

func (l *accList) add(val, platform string, self bool) {
	val = strings.TrimSpace(val)
	if val == "" {
		return
	}
	for _, it := range l.items {
		if l.same(it.display, val) {
			it.platforms[platform] = true
			it.self = it.self || self
			if l.pick != nil {
				it.display = l.pick(it.display, val)
			}
			return
		}
	}
	l.items = append(l.items, &acc{display: val, platforms: map[string]bool{platform: true}, self: self, extra: len(l.items)})
}

func (l *accList) facts() []models.Fact {
	out := make([]models.Fact, 0, len(l.items))
	for _, it := range l.items {
		var src []string
		for p := range it.platforms {
			src = append(src, p)
		}
		sort.Strings(src)
		out = append(out, models.Fact{Value: it.display, Sources: src, Confirmed: len(src) >= 2, Self: it.self})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confirmed != out[j].Confirmed {
			return out[i].Confirmed
		}
		if len(out[i].Sources) != len(out[j].Sources) {
			return len(out[i].Sources) > len(out[j].Sources)
		}
		return out[i].Self && !out[j].Self
	})
	return out
}

func longer(a, b string) string {
	if len(b) > len(a) {
		return b
	}
	return a
}

func exact(a, b string) bool { return fold(a) == fold(b) }

func sameHost(a, b string) bool { return normSite(a) == normSite(b) }

func normSite(s string) string {
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return strings.ToLower(s)
	}
	return strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.") + strings.TrimSuffix(u.Path, "/")
}

func sameDigits(a, b string) bool {
	da, db := digits(a), digits(b)
	if len(da) < 7 || len(db) < 7 {
		return da == db
	}
	n := min(len(da), len(db), 9)
	return da[len(da)-n:] == db[len(db)-n:]
}

func noisyOr(ws ...float64) float64 {
	p := 1.0
	for _, w := range ws {
		p *= 1 - w
	}
	return 1 - p
}

var authoritative = map[string]bool{"LinkedIn": true, "ORCID": true, "Wikidata": true, "GitHub": true, "Website": true, "CV": true, "Keybase": true}

// build merges one cluster of records into an Identity and scores it.
func build(nodes []*node, members []int, a Anchors, reasons []string) models.Identity {
	names := &accList{same: func(x, y string) bool { return MatchNames(x, y) == NameStrong }, pick: longer}
	heads := &accList{same: exact}
	emps := &accList{same: overlap, pick: longer}
	locs := &accList{same: overlap, pick: longer}
	edu := &accList{same: overlap, pick: longer}
	ints := &accList{same: exact}
	emails := &accList{same: exact}
	phones := &accList{same: sameDigits}
	users := &accList{same: exact}
	sites := &accList{same: sameHost}

	id := models.Identity{IDs: map[string]string{}}
	photoSeen := map[string]bool{}
	platforms := map[string]bool{}
	var bioBest string
	var bioSelf bool

	for _, i := range members {
		r := nodes[i].in.Rec
		src := nodes[i].in.Source
		platforms[r.Platform] = true
		id.Records = append(id.Records, models.RecordRef{Platform: r.Platform, URL: r.URL, Source: src, Self: r.Self})
		names.add(r.Name, r.Platform, r.Self)
		heads.add(r.Headline, r.Platform, r.Self)
		for _, e := range r.Employers {
			emps.add(e, r.Platform, r.Self)
		}
		for _, e := range r.Roles {
			heads.add(e, r.Platform, r.Self)
		}
		locs.add(r.Location, r.Platform, r.Self)
		for _, e := range r.Education {
			edu.add(e, r.Platform, r.Self)
		}
		for _, e := range r.Interests {
			ints.add(e, r.Platform, r.Self)
		}
		for _, e := range r.Emails {
			emails.add(strings.ToLower(e), r.Platform, r.Self)
		}
		for _, e := range r.Phones {
			phones.add(e, r.Platform, r.Self)
		}
		for _, e := range r.Usernames {
			users.add(e, r.Platform, r.Self)
		}
		if r.Self && r.URL != "" {
			if k := acctKey(r.URL); k != "" {
				p := strings.SplitN(k, ":", 3)
				users.add(p[1]+":"+p[2], r.Platform, true)
			}
		}
		for _, w := range r.Websites {
			if acctKey(w) == "" {
				sites.add(w, r.Platform, r.Self)
			}
		}
		if r.Photo != "" && !photoSeen[r.Photo] {
			photoSeen[r.Photo] = true
			id.Photos = append(id.Photos, r.Photo)
		}
		if r.Platform == "CV" && r.URL != "" {
			id.Docs = append(id.Docs, r.URL)
		}
		if r.Bio != "" && (len(r.Bio) > len(bioBest) || (r.Self && !bioSelf)) {
			bioBest, bioSelf = r.Bio, r.Self
		}
		for k, v := range r.IDs {
			id.IDs[k] = v
		}
	}
	id.Names, id.Headlines, id.Employers, id.Locations = names.facts(), heads.facts(), emps.facts(), locs.facts()
	id.Education, id.Interests, id.Emails, id.Phones = edu.facts(), ints.facts(), emails.facts(), phones.facts()
	id.Usernames, id.Websites = users.facts(), sites.facts()
	id.Bio = bioBest
	id.Reasons = reasons
	if len(id.IDs) == 0 {
		id.IDs = nil
	}

	score, matched := scoreIdentity(&id, a, len(platforms))
	id.Score, id.Matched = score, matched
	id.Conflicts = conflicts(&id)
	id.Label = label(&id)
	return id
}

func label(id *models.Identity) string {
	name := "Unnamed profile"
	if len(id.Names) > 0 {
		name = id.Names[0].Value
	}
	var tail []string
	if len(id.Headlines) > 0 {
		tail = append(tail, id.Headlines[0].Value)
	} else if len(id.Employers) > 0 {
		tail = append(tail, id.Employers[0].Value)
	}
	if len(id.Locations) > 0 {
		tail = append(tail, id.Locations[0].Value)
	}
	if len(tail) == 0 {
		return name
	}
	return name + " — " + strings.Join(tail, ", ")
}

func conflicts(id *models.Identity) []string {
	var out []string
	if len(id.Locations) > 1 {
		disjoint := true
		for i := 0; i < len(id.Locations) && disjoint; i++ {
			for j := i + 1; j < len(id.Locations); j++ {
				if overlap(id.Locations[i].Value, id.Locations[j].Value) {
					disjoint = false
					break
				}
			}
		}
		if disjoint {
			var v []string
			for _, l := range id.Locations {
				v = append(v, l.Value)
			}
			out = append(out, "sources place this person in different locations: "+strings.Join(v, " | ")+" (they may have moved, or these may be different people)")
		}
	}
	if len(id.Names) > 1 {
		for i := 1; i < len(id.Names); i++ {
			if MatchNames(id.Names[0].Value, id.Names[i].Value) == NameNone {
				out = append(out, "names differ across sources: "+id.Names[0].Value+" vs "+id.Names[i].Value)
				break
			}
		}
	}
	return out
}

// scoreIdentity rates how well an identity matches the supplied anchors.
func scoreIdentity(id *models.Identity, a Anchors, platformCount int) (float64, []string) {
	var ws []float64
	var matched []string
	hit := func(name string, w float64) { ws = append(ws, w); matched = append(matched, name) }
	anchored := false

	if a.Name != "" {
		anchored = true
		best := NameNone
		for _, n := range id.Names {
			if m := MatchNames(a.Name, n.Value); m > best {
				best = m
			}
		}
		switch best {
		case NameStrong:
			hit("name", 0.30)
		case NamePartial:
			hit("name (partial)", 0.12)
		}
	}
	if a.Email != "" {
		anchored = true
		for _, e := range id.Emails {
			if strings.EqualFold(e.Value, a.Email) {
				hit("e-mail", 0.60)
				break
			}
		}
	}
	if a.Phone != "" {
		anchored = true
		for _, p := range id.Phones {
			if sameDigits(p.Value, a.Phone) {
				hit("phone", 0.60)
				break
			}
		}
	}
	if a.Username != "" {
		anchored = true
		for _, u := range id.Usernames {
			if _, h, ok := strings.Cut(u.Value, ":"); ok && strings.EqualFold(strings.TrimPrefix(h, "@"), a.Username) {
				hit("username", 0.35)
				break
			}
		}
	}
	if a.Alias != "" {
		anchored = true
		fa := strings.ReplaceAll(fold(a.Alias), " ", "")
		found := false
		for _, u := range id.Usernames {
			if _, h, ok := strings.Cut(u.Value, ":"); ok && strings.ReplaceAll(fold(h), " ", "") == fa {
				found = true
			}
		}
		for _, n := range id.Names {
			if strings.ReplaceAll(fold(n.Value), " ", "") == fa {
				found = true
			}
		}
		if found {
			hit("alias", 0.18)
		}
	}
	if a.Domain != "" {
		anchored = true
		d := strings.ToLower(a.Domain)
		ok := false
		for _, s := range id.Websites {
			h := strings.SplitN(normSite(s.Value), "/", 2)[0]
			if h == d || strings.HasSuffix(h, "."+d) {
				ok = true
			}
		}
		for _, e := range id.Emails {
			if _, dom, cut := strings.Cut(e.Value, "@"); cut && (dom == d || strings.HasSuffix(dom, "."+d)) {
				ok = true
			}
		}
		if ok {
			hit("domain", 0.40)
		}
	}
	if a.Company != "" {
		anchored = true
		for _, e := range id.Employers {
			if overlap(e.Value, a.Company) {
				hit("company", 0.22)
				break
			}
		}
	}
	if a.Location != "" {
		anchored = true
		for _, l := range id.Locations {
			if overlap(l.Value, a.Location) {
				hit("location", 0.15)
				break
			}
		}
	}
	for _, link := range a.Links {
		anchored = true
		want := acctKey(link)
		for _, r := range id.Records {
			if r.URL != "" && (strings.EqualFold(strings.TrimSuffix(r.URL, "/"), strings.TrimSuffix(link, "/")) || (want != "" && acctKey(r.URL) == want)) {
				hit("profile link", 0.70)
				break
			}
		}
	}

	// independent corroboration: the more platforms agree, the likelier it is one real person
	if platformCount > 1 {
		ws = append(ws, minF(0.2, 0.05*float64(platformCount-1)))
	}
	// a profile with many independently stated facts is likelier to be a real,
	// well-documented person than a thin stub (also breaks ties between candidates)
	facts := len(id.Employers) + len(id.Locations) + len(id.Education) + len(id.Interests) + len(id.Emails) +
		len(id.Phones) + len(id.Websites) + len(id.Usernames) + len(id.Headlines)
	if facts > 0 {
		ws = append(ws, minF(0.15, 0.012*float64(facts)))
	}
	score := noisyOr(ws...)
	if !anchored {
		score = noisyOr(0.2, score)
	}

	// contradictions with what the operator said
	if a.Name != "" && len(id.Names) > 0 && !containsPrefix(matched, "name") {
		score *= 0.5
	}
	if a.Location != "" && len(id.Locations) > 0 && !contains(matched, "location") {
		score *= 0.8
	}
	if a.Company != "" && len(id.Employers) > 0 && !contains(matched, "company") {
		score *= 0.88
	}
	return minF(score, 0.99), matched
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func containsPrefix(s []string, p string) bool {
	for _, x := range s {
		if strings.HasPrefix(x, p) {
			return true
		}
	}
	return false
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
