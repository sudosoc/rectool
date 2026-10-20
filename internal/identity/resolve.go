package identity

import (
	"fmt"
	"math/bits"
	"net/url"
	"sort"
	"strings"

	"github.com/sudosoc/rectool/internal/extract"
	"github.com/sudosoc/rectool/internal/intel"
	"github.com/sudosoc/rectool/internal/models"
)

// Input is one record plus where it came from.
type Input struct {
	Rec       models.Record
	Source    string // "module: finding source"
	PhotoHash uint64 // perceptual hash of Rec.Photo, when it was downloaded
	HasHash   bool
}

// Anchors are the identifiers the operator supplied; identities are scored by
// how many of them they match.
type Anchors struct {
	Name, Username, Alias, Email, Phone, Domain, Company, Location string
	Links                                                          []string
}

// FromTarget extracts the anchors of a target.
func FromTarget(t models.Target) Anchors {
	return Anchors{Name: t.FullName, Username: t.Username, Alias: t.Alias, Email: t.Email, Phone: t.Phone,
		Domain: t.Domain, Company: t.Company, Location: t.Location, Links: t.Links}
}

// Result is the outcome of a resolution.
type Result struct {
	Identities []models.Identity
	Ambiguous  bool
	SameName   int    // identities whose name matches the supplied one
	Note       string // human-readable ambiguity explanation
}

type node struct {
	in    Input
	keys  []string
	uniq  map[string]string // unique-ID kind -> value (an identity has at most one of each)
	names []string
}

// platform sites that identify an account, not a person's own website.
var platformHosts = map[string]bool{
	"twitter.com": true, "x.com": true, "github.com": true, "gitlab.com": true, "linkedin.com": true, "facebook.com": true,
	"instagram.com": true, "youtube.com": true, "youtu.be": true, "medium.com": true, "t.me": true, "reddit.com": true,
	"keybase.io": true, "mastodon.social": true, "tiktok.com": true, "pinterest.com": true, "orcid.org": true,
	"wikipedia.org": true, "wikidata.org": true, "google.com": true, "bsky.app": true, "stackoverflow.com": true,
}

var uniqueKinds = map[string]bool{"orcid": true, "wikidata": true, "openalex": true}

func hostOf(raw string) string {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
}

func digits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// acctKey turns a profile URL into "acct:platform:handle".
func acctKey(raw string) string {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	for _, p := range extract.Social([]string{raw}) {
		h := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(p.Handle, "in/"), "@"))
		return "acct:" + p.Platform + ":" + h
	}
	return ""
}

func newNode(in Input) *node {
	r := in.Rec
	n := &node{in: in, uniq: map[string]string{}}
	add := func(k string) {
		if k != "" {
			n.keys = append(n.keys, k)
		}
	}
	for _, e := range r.Emails {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			add("email:" + e)
		}
	}
	for _, p := range r.Phones {
		if d := digits(p); len(d) >= 7 {
			add("phone:" + d)
		}
	}
	for k, v := range r.IDs {
		k, v = strings.ToLower(k), strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		if uniqueKinds[k] {
			n.uniq[k] = v
			add("id:" + k + ":" + v)
		} else {
			add("acct:" + k + ":" + v)
		}
	}
	for _, u := range r.Usernames {
		if plat, handle, ok := strings.Cut(u, ":"); ok && handle != "" {
			add("acct:" + strings.ToLower(plat) + ":" + strings.ToLower(strings.TrimPrefix(handle, "@")))
		}
	}
	if r.URL != "" {
		add(acctKey(r.URL))
	}
	for _, w := range r.Websites {
		if k := acctKey(w); k != "" {
			add(k)
			continue
		}
		if h := hostOf(w); h != "" && !platformHosts[h] {
			add("site:" + h)
		}
	}
	if r.Platform == "Website" && r.URL != "" {
		if h := hostOf(r.URL); h != "" && !platformHosts[h] {
			add("site:" + h)
		}
	}
	if r.Name != "" {
		n.names = append(n.names, r.Name)
	}
	return n
}

// ---------------------------------------------------------------- union-find

type uf struct{ p []int }

func newUF(n int) *uf {
	u := &uf{p: make([]int, n)}
	for i := range u.p {
		u.p[i] = i
	}
	return u
}
func (u *uf) find(x int) int {
	for u.p[x] != x {
		u.p[x] = u.p[u.p[x]]
		x = u.p[x]
	}
	return x
}

// Resolve clusters records into identities and ranks them against the anchors.
func Resolve(inputs []Input, a Anchors) Result {
	n := len(inputs)
	if n == 0 {
		return Result{}
	}
	nodes := make([]*node, n)
	for i, in := range inputs {
		nodes[i] = newNode(in)
	}
	u := newUF(n)
	reasons := map[int][]string{} // root -> reasons (re-keyed after all unions)
	type edge struct {
		a, b   int
		reason string
	}
	var edges []edge

	// clusterUniq returns the unique-ID values present in the cluster of x.
	clusterUniq := func(x int) map[string]string {
		out := map[string]string{}
		r := u.find(x)
		for i := range nodes {
			if u.find(i) == r {
				for k, v := range nodes[i].uniq {
					out[k] = v
				}
			}
		}
		return out
	}
	conflict := func(x, y int) bool {
		ux, uy := clusterUniq(x), clusterUniq(y)
		for k, v := range ux {
			if w, ok := uy[k]; ok && w != v {
				return true
			}
		}
		return false
	}
	var blocked [][2]int // same-platform duplicates that some evidence tried to join
	union := func(x, y int, why string, enforcePlatform bool) {
		rx, ry := u.find(x), u.find(y)
		if rx == ry || conflict(x, y) {
			return
		}
		// Two different accounts on the same platform are two accounts (a person has
		// one GitHub, one LinkedIn…). Impersonators copy a name, place, employer and
		// even an e-mail, so only a unique ID (ORCID, Wikidata…) may join them.
		if enforcePlatform && platformConflict(nodes, u, x, y) {
			blocked = append(blocked, [2]int{x, y})
			return
		}
		u.p[rx] = ry
		edges = append(edges, edge{x, y, why})
	}

	// 1. strong keys
	first := map[string]int{}
	for i, nd := range nodes {
		for _, k := range nd.keys {
			if j, ok := first[k]; ok {
				union(i, j, fmt.Sprintf("%s and %s share %s", nodes[j].in.Rec.Platform, nd.in.Rec.Platform, describeKey(k)), !strings.HasPrefix(k, "id:"))
			} else {
				first[k] = i
			}
		}
	}
	// 2. the same profile picture
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if nodes[i].in.HasHash && nodes[j].in.HasHash && bits.OnesCount64(nodes[i].in.PhotoHash^nodes[j].in.PhotoHash) <= 6 {
				union(i, j, fmt.Sprintf("%s and %s use the same profile picture", nodes[i].in.Rec.Platform, nodes[j].in.Rec.Platform), true)
			}
		}
	}
	// 3. same name plus several independent matching attributes
	for pass := 0; pass < 2; pass++ {
		for i := 0; i < n; i++ {
			for j := i + 1; j < n; j++ {
				if u.find(i) == u.find(j) {
					continue
				}
				nm := bestNameMatch(nodes[i].names, nodes[j].names)
				if nm == NameNone {
					continue
				}
				sup, what := supports(nodes[i].in.Rec, nodes[j].in.Rec)
				if (nm == NameStrong && sup >= 2) || (nm == NamePartial && sup >= 3) {
					union(i, j, fmt.Sprintf("%s and %s: same name and same %s", nodes[i].in.Rec.Platform, nodes[j].in.Rec.Platform, strings.Join(what, ", ")), true)
				}
			}
		}
	}
	for _, e := range edges {
		r := u.find(e.a)
		reasons[r] = append(reasons[r], e.reason)
	}

	// clusters
	members := map[int][]int{}
	for i := range nodes {
		members[u.find(i)] = append(members[u.find(i)], i)
	}
	type built struct {
		id      models.Identity
		members []int
	}
	var bs []built
	for root, m := range members {
		bs = append(bs, built{build(nodes, m, a, reasons[root]), m})
	}
	sort.SliceStable(bs, func(i, j int) bool {
		if bs[i].id.Score != bs[j].id.Score {
			return bs[i].id.Score > bs[j].id.Score
		}
		return len(bs[i].id.Records) > len(bs[j].id.Records)
	})
	if len(bs) > 12 {
		bs = bs[:12]
	}
	ids := make([]models.Identity, len(bs))
	nodeIdx := map[int]int{}
	for i, b := range bs {
		b.id.ID = i + 1
		ids[i] = b.id
		for _, m := range b.members {
			nodeIdx[m] = i
		}
	}

	for i := range ids {
		ids[i].Weak = isWeak(ids[i])
	}
	// An identity that shares a name/e-mail/place with a better-matching one but
	// sits on the same platforms as *different accounts* is a duplicate or a copy
	// (alias, impersonator), not a second person: demote it.
	for _, p := range blocked {
		ia, ok1 := nodeIdx[p[0]]
		ib, ok2 := nodeIdx[p[1]]
		if !ok1 || !ok2 || ia == ib {
			continue
		}
		hi, lo := ia, ib
		if lo < hi {
			hi, lo = lo, hi
		}
		if !ids[lo].Weak {
			ids[lo].Weak = true
			ids[lo].Reasons = append(ids[lo].Reasons, fmt.Sprintf("looks like a duplicate or copy of the better-matching identity #%d (same platform, same details)", ids[hi].ID))
		}
	}
	res := Result{Identities: ids}
	if a.Name != "" {
		for _, id := range ids {
			for _, nm := range id.Names {
				if MatchNames(a.Name, nm.Value) != NameNone {
					res.SameName++
					break
				}
			}
		}
	}
	if len(ids) > 0 && ids[0].Score >= 0.45 {
		ids[0].Primary = true
	}
	// Ambiguity counts only identities with a name or real substance: a lone unnamed
	// account that shares the handle is not a "person who plausibly matches".
	var strong []models.Identity
	for _, id := range ids {
		if !id.Weak {
			strong = append(strong, id)
		}
	}
	if len(strong) >= 2 && strong[1].Score >= 0.3 && strong[1].Score >= 0.65*strong[0].Score {
		res.Ambiguous = true
		res.Note = fmt.Sprintf("%d different people plausibly match. They are kept apart; add a location, employer, e-mail or username to narrow it down.", countPlausible(strong))
		for i := range ids {
			ids[i].Primary = false
		}
	}
	return res
}

func countPlausible(ids []models.Identity) int {
	c := 0
	for _, id := range ids {
		if id.Score >= 0.3 && id.Score >= 0.65*ids[0].Score {
			c++
		}
	}
	return c
}

func describeKey(k string) string {
	parts := strings.SplitN(k, ":", 3)
	switch parts[0] {
	case "email":
		return "the e-mail " + parts[1]
	case "phone":
		return "the phone number " + parts[1]
	case "id":
		return "the " + parts[1] + " ID " + parts[2]
	case "acct":
		return "the " + parts[1] + " account " + parts[2]
	case "site":
		return "the website " + parts[1]
	}
	return k
}

func bestNameMatch(a, b []string) NameMatch {
	best := NameNone
	for _, x := range a {
		for _, y := range b {
			if m := MatchNames(x, y); m > best {
				best = m
			}
		}
	}
	return best
}

// supports counts independent attributes two records agree on.
func supports(a, b models.Record) (int, []string) {
	var what []string
	if overlap(a.Location, b.Location) {
		what = append(what, "location")
	}
	if anyOverlap(a.Employers, b.Employers) {
		what = append(what, "employer")
	}
	if anyOverlap(a.Education, b.Education) {
		what = append(what, "school")
	}
	if domainOverlap(a, b) {
		what = append(what, "e-mail domain")
	}
	if bioSimilar(a.Bio, b.Bio) {
		what = append(what, "bio text")
	}
	// The same handle on two different platforms next to the same name is strong
	// evidence of one person (it counts double).
	if sameHandleAcrossPlatforms(a, b) {
		what = append(what, "handle", "handle on both platforms")
	}
	return len(what), what
}

func anyOverlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if overlap(x, y) {
				return true
			}
		}
	}
	return false
}

func domainOverlap(a, b models.Record) bool {
	dom := func(r models.Record) map[string]bool {
		m := map[string]bool{}
		for _, e := range r.Emails {
			if _, d, ok := strings.Cut(strings.ToLower(e), "@"); ok && !intel.IsFreeMail(d) {
				m[d] = true
			}
		}
		return m
	}
	da, db := dom(a), dom(b)
	for d := range da {
		if db[d] {
			return true
		}
	}
	return false
}

// sameHandleAcrossPlatforms: both records name an account with the same handle
// (≥4 characters) on different platforms, e.g. github:satyanadella and
// twitter:satyanadella.
func sameHandleAcrossPlatforms(a, b models.Record) bool {
	type acct struct{ plat, handle string }
	collect := func(r models.Record) []acct {
		var out []acct
		for _, u := range r.Usernames {
			if p, h, ok := strings.Cut(u, ":"); ok && len(h) >= 4 {
				out = append(out, acct{strings.ToLower(p), strings.ToLower(strings.TrimPrefix(h, "@"))})
			}
		}
		if k := acctKey(r.URL); k != "" {
			parts := strings.SplitN(k, ":", 3)
			if len(parts) == 3 && len(parts[2]) >= 4 {
				out = append(out, acct{parts[1], parts[2]})
			}
		}
		return out
	}
	for _, x := range collect(a) {
		for _, y := range collect(b) {
			if x.handle == y.handle && x.plat != y.plat {
				return true
			}
		}
	}
	return false
}

// platformConflict reports whether merging the clusters of x and y would put
// two distinct accounts of the same platform into one identity.
func platformConflict(nodes []*node, u *uf, x, y int) bool {
	type acct struct{ plat, key string }
	collect := func(root int) map[string]map[string]bool {
		out := map[string]map[string]bool{}
		for i := range nodes {
			if u.find(i) != root {
				continue
			}
			r := nodes[i].in.Rec
			plat := strings.ToLower(r.Platform)
			if plat == "" || plat == "website" || plat == "cv" || plat == "whois" || plat == "pasted profile" {
				continue // documents and sites can legitimately repeat
			}
			if out[plat] == nil {
				out[plat] = map[string]bool{}
			}
			key := strings.ToLower(strings.TrimSuffix(r.URL, "/"))
			if k := acctKey(r.URL); k != "" {
				key = k
			}
			out[plat][key] = true
		}
		return out
	}
	a, b := collect(u.find(x)), collect(u.find(y))
	for plat, ka := range a {
		kb, ok := b[plat]
		if !ok {
			continue
		}
		for k := range ka {
			if !kb[k] {
				return true
			}
		}
	}
	return false
}

// isWeak: a single unnamed account that matched only through its handle.
func isWeak(id models.Identity) bool {
	if len(id.Names) > 0 || len(id.Records) != 1 {
		return false
	}
	for _, m := range id.Matched {
		if m != "username" && m != "alias" {
			return false
		}
	}
	return true
}

// bioSimilar reports whether two profile descriptions are the same text, or
// nearly (people paste one bio everywhere): at least eight words and 85%
// word overlap.
func bioSimilar(a, b string) bool {
	wa, wb := words(a), words(b)
	if len(wa) < 8 || len(wb) < 8 {
		return false
	}
	set := map[string]bool{}
	for _, w := range wa {
		set[w] = true
	}
	union := len(set)
	inter := 0
	seen := map[string]bool{}
	for _, w := range wb {
		if seen[w] {
			continue
		}
		seen[w] = true
		if set[w] {
			inter++
		} else {
			union++
		}
	}
	return float64(inter)/float64(union) >= 0.85
}
