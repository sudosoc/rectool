package identity

import (
	"strings"
	"testing"

	"github.com/sudosoc/rectool/internal/models"
)

func in(platform, source string, r models.Record) Input {
	r.Platform = platform
	return Input{Rec: r, Source: source}
}

func TestMatchNames(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want NameMatch
	}{
		{"Linus Torvalds", "linus torvalds", NameStrong},
		{"Torvalds, Linus", "Linus Torvalds", NameStrong},
		{"Linus Benedict Torvalds", "Linus Torvalds", NameStrong},
		{"José Núñez", "Jose Nunez", NameStrong},
		{"J. Roe", "Jane Roe", NamePartial},
		{"John Smith", "Jon Smith", NameNone},
		{"Jane Roe", "Jane Doe", NameNone},
		{"torvalds", "Linus Torvalds", NamePartial},
	} {
		if got := MatchNames(c.a, c.b); got != c.want {
			t.Errorf("MatchNames(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

// The failure that motivated this package: the same handle on several sites
// belongs to different people, and they must not be blended.
func TestSameHandleDifferentPeopleStayApart(t *testing.T) {
	res := Resolve([]Input{
		in("GitHub", "profiles: GitHub profile", models.Record{Name: "Linus Torvalds", Self: true, URL: "https://github.com/torvalds",
			Employers: []string{"Linux Foundation"}, Emails: []string{"torvalds@linux-foundation.org"}, Usernames: []string{"github:torvalds"}}),
		in("Gravatar", "footprint: Gravatar profile", models.Record{Emails: []string{"torvalds@linux-foundation.org"}, Self: true, Photo: "https://g/a.png"}),
		in("npm", "profiles: npm maintainer", models.Record{Usernames: []string{"npm:torvalds"}, Emails: []string{"deandb2015@gmail.com"}}),
		in("Docker Hub", "profiles: Docker Hub profile", models.Record{Usernames: []string{"dockerhub:torvalds"}, Employers: []string{"DoLoop srls"}, Location: "Italy"}),
	}, Anchors{Username: "torvalds", Email: "torvalds@linux-foundation.org", Name: "Linus Torvalds"})

	top := res.Identities[0]
	if len(top.Records) != 2 || !top.Primary {
		t.Fatalf("GitHub + Gravatar (shared e-mail) must form one identity: %+v", top.Records)
	}
	for _, r := range top.Records {
		if r.Platform == "npm" || r.Platform == "Docker Hub" {
			t.Errorf("another person's profile leaked into the identity: %s", r.Platform)
		}
	}
	for _, e := range top.Emails {
		if e.Value == "deandb2015@gmail.com" {
			t.Fatal("stranger's e-mail blended in")
		}
	}
	if top.Score < 0.8 || !contains(top.Matched, "e-mail") || !contains(top.Matched, "username") {
		t.Errorf("score %.2f matched %v", top.Score, top.Matched)
	}
	if len(res.Identities) != 3 { // identity + npm person + docker person
		t.Errorf("expected 3 separate people, got %d", len(res.Identities))
	}
}

func TestSameNameDifferentPeopleNeedAnchors(t *testing.T) {
	cairo := in("LinkedIn", "people: LinkedIn", models.Record{Name: "Jane Roe", Location: "Cairo, Egypt", Employers: []string{"Acme"}, Self: true, URL: "https://www.linkedin.com/in/janeroe"})
	berlin := in("GitHub", "people: GitHub", models.Record{Name: "Jane Roe", Location: "Berlin, Germany", Employers: []string{"Foo GmbH"}, Self: true, URL: "https://github.com/jroe"})

	res := Resolve([]Input{cairo, berlin}, Anchors{Name: "Jane Roe"})
	if len(res.Identities) != 2 {
		t.Fatalf("two Jane Roes with different place and employer must stay apart, got %d", len(res.Identities))
	}
	if !res.Ambiguous || res.SameName != 2 || res.Note == "" {
		t.Errorf("name alone is ambiguous: %+v", res)
	}

	res = Resolve([]Input{cairo, berlin}, Anchors{Name: "Jane Roe", Location: "Cairo", Company: "Acme"})
	if res.Ambiguous {
		t.Errorf("location + company should disambiguate: %+v", res.Note)
	}
	if !res.Identities[0].Primary || !strings.Contains(res.Identities[0].Label, "Cairo") {
		t.Errorf("best match should be the Cairo profile: %s", res.Identities[0].Label)
	}
	if res.Identities[0].Score <= res.Identities[1].Score*1.5 {
		t.Errorf("scores should separate clearly: %.2f vs %.2f", res.Identities[0].Score, res.Identities[1].Score)
	}
}

func TestLinkingEvidence(t *testing.T) {
	// shared ORCID links ORCID and OpenAlex records; shared photo links GitHub and Twitter;
	// the same name + location + employer links a CV to the LinkedIn page.
	res := Resolve([]Input{
		in("ORCID", "people: ORCID", models.Record{Name: "Ada Lovelace", IDs: map[string]string{"orcid": "0000-0001"}}),
		in("OpenAlex", "people: OpenAlex", models.Record{Name: "A. Lovelace", IDs: map[string]string{"orcid": "0000-0001"}, Interests: []string{"Analytical engines"}}),
		{Rec: models.Record{Platform: "GitHub", Name: "ada", Photo: "p1"}, Source: "profiles: GitHub", PhotoHash: 0xF0F0F0F0F0F0F0F0, HasHash: true},
		{Rec: models.Record{Platform: "Twitter", Name: "Ada L", Photo: "p2"}, Source: "social", PhotoHash: 0xF0F0F0F0F0F0F0F1, HasHash: true},
		in("LinkedIn", "people: LinkedIn", models.Record{Name: "Grace Hopper", Location: "Arlington, Virginia", Employers: []string{"US Navy"}, Self: true}),
		in("CV", "people: CV", models.Record{Name: "Grace Hopper", Location: "Arlington, VA", Employers: []string{"U.S. Navy Reserve"}}),
		in("ORCID", "people: other ORCID", models.Record{Name: "Ada Lovelace", IDs: map[string]string{"orcid": "0000-0002"}}),
	}, Anchors{})

	counts := map[int]int{}
	for _, id := range res.Identities {
		counts[len(id.Records)]++
	}
	// Ada(ORCID+OpenAlex)=2, GitHub+Twitter=2, Grace(LinkedIn+CV)=2, the second Ada with a different ORCID stays alone=1
	if counts[2] != 3 || counts[1] != 1 {
		t.Fatalf("clusters: %v (%d identities)", counts, len(res.Identities))
	}
	var haveReason bool
	for _, id := range res.Identities {
		for _, r := range id.Reasons {
			if strings.Contains(r, "orcid ID 0000-0001") {
				haveReason = true
			}
		}
	}
	if !haveReason {
		t.Error("link reasons must explain why records were merged")
	}
}

func TestFactsAreConfirmedByIndependentPlatforms(t *testing.T) {
	res := Resolve([]Input{
		in("LinkedIn", "a", models.Record{Name: "Jane Roe", Headline: "Engineer", Location: "Cairo, Egypt", Employers: []string{"Acme Corporation"}, Emails: []string{"jane@acme.io"}, Self: true, Websites: []string{"https://janeroe.dev"}}),
		in("GitHub", "b", models.Record{Name: "Jane Roe", Location: "Cairo", Employers: []string{"Acme"}, Emails: []string{"jane@acme.io"}, Self: true, Websites: []string{"https://www.janeroe.dev/"}}),
	}, Anchors{Name: "Jane Roe", Domain: "janeroe.dev"})
	if len(res.Identities) != 1 {
		t.Fatalf("shared e-mail should merge: %d", len(res.Identities))
	}
	id := res.Identities[0]
	if !id.Locations[0].Confirmed || !id.Employers[0].Confirmed || !id.Emails[0].Confirmed || !id.Websites[0].Confirmed {
		t.Errorf("two platforms agree -> confirmed: loc=%+v emp=%+v mail=%+v site=%+v", id.Locations, id.Employers, id.Emails, id.Websites)
	}
	if id.Headlines[0].Confirmed {
		t.Error("a headline stated by one platform is not confirmed")
	}
	if !contains(id.Matched, "domain") {
		t.Errorf("domain anchor should match: %v", id.Matched)
	}
}

func TestNameContradictionLowersScore(t *testing.T) {
	good := in("GitHub", "a", models.Record{Name: "Jane Roe", Usernames: []string{"github:jroe"}})
	bad := in("Docker Hub", "b", models.Record{Name: "Pietro Rossi", Usernames: []string{"dockerhub:jroe"}})
	res := Resolve([]Input{good, bad}, Anchors{Name: "Jane Roe", Username: "jroe"})
	if res.Identities[0].Names[0].Value != "Jane Roe" || res.Identities[0].Score <= 2*res.Identities[1].Score {
		t.Errorf("a profile with a different name must score far lower: %.2f vs %.2f", res.Identities[0].Score, res.Identities[1].Score)
	}
}

func TestProfileLinkAnchorWins(t *testing.T) {
	li := in("LinkedIn", "a", models.Record{Name: "Some Body", URL: "https://www.linkedin.com/in/some-body", Self: true})
	other := in("GitHub", "b", models.Record{Name: "Some Body", URL: "https://github.com/sbody", Self: true})
	res := Resolve([]Input{other, li}, Anchors{Name: "Some Body", Links: []string{"https://linkedin.com/in/some-body/"}})
	if res.Identities[0].Records[0].Platform != "LinkedIn" || !contains(res.Identities[0].Matched, "profile link") {
		t.Errorf("the pasted profile must win: %+v", res.Identities[0])
	}
}

func TestSameNamePlusSameHandleAcrossPlatformsMerges(t *testing.T) {
	// the live-audit case: a GitHub profile and a Wikidata entry share no ID, but name + handle agree
	res := Resolve([]Input{
		in("GitHub", "a", models.Record{Name: "Satya Nadella", URL: "https://github.com/satyanadella", Usernames: []string{"github:satyanadella"}, Employers: []string{"Microsoft"}, Self: true}),
		in("Wikidata", "b", models.Record{Name: "Satya Nadella", Usernames: []string{"twitter:satyanadella"}, Employers: []string{"Microsoft"}}),
		in("OpenAlex", "c", models.Record{Name: "Satya Nadella", Interests: []string{"Management"}}),
	}, Anchors{Name: "Satya Nadella"})
	if len(res.Identities) != 2 || len(res.Identities[0].Records) != 2 {
		t.Fatalf("GitHub + Wikidata must merge, OpenAlex (no link) stays apart: %d identities, first has %d records", len(res.Identities), len(res.Identities[0].Records))
	}
	if res.Identities[0].Score <= res.Identities[1].Score {
		t.Errorf("the corroborated, richer identity must outrank the thin one: %.2f vs %.2f", res.Identities[0].Score, res.Identities[1].Score)
	}
	// different handles never merge
	res = Resolve([]Input{
		in("GitHub", "a", models.Record{Name: "Pat Lee", Usernames: []string{"github:patlee1"}}),
		in("Wikidata", "b", models.Record{Name: "Pat Lee", Usernames: []string{"twitter:otherpat"}}),
	}, Anchors{})
	if len(res.Identities) != 2 {
		t.Error("same name with different handles must stay apart")
	}
}

// Live-audit failure: impersonator GitHub accounts copy the real person's name,
// location and employer, and used to be soft-merged into the real identity.
func TestImpersonatorOnSamePlatformIsNotMerged(t *testing.T) {
	real := in("GitHub", "a", models.Record{Name: "Linus Torvalds", URL: "https://github.com/torvalds", Self: true,
		Location: "Portland, OR", Employers: []string{"Linux Foundation"}, Usernames: []string{"github:torvalds"}})
	wiki := in("Wikidata", "b", models.Record{Name: "Linus Torvalds", Location: "Portland, Oregon", Employers: []string{"Linux Foundation"},
		Usernames: []string{"github:torvalds"}, IDs: map[string]string{"wikidata": "Q34253"}})
	fake := in("GitHub", "c", models.Record{Name: "Linus Torvalds", URL: "https://github.com/torvalds1", Self: true,
		Location: "Portland, OR", Employers: []string{"Linux Foundation"}, Usernames: []string{"github:torvalds1"}})

	res := Resolve([]Input{real, wiki, fake}, Anchors{Name: "Linus Torvalds", Username: "torvalds", Location: "Portland"})
	if len(res.Identities) != 2 {
		t.Fatalf("the clone must stay a separate identity: %d", len(res.Identities))
	}
	top := res.Identities[0]
	if len(top.Records) != 2 {
		t.Fatalf("real GitHub + Wikidata (explicit github ID) form the identity: %+v", top.Records)
	}
	for _, r := range top.Records {
		if strings.Contains(r.URL, "torvalds1") {
			t.Error("impersonator merged into the real identity")
		}
	}
}

func TestHandleOnlyAccountsAreWeakAndDoNotCauseAmbiguity(t *testing.T) {
	res := Resolve([]Input{
		in("GitHub", "a", models.Record{Name: "Jane Roe", Location: "Cairo", Usernames: []string{"github:jroe"}, URL: "https://github.com/jroe", Self: true}),
		in("npm", "b", models.Record{Usernames: []string{"npm:jroe"}}),
		in("Keybase", "c", models.Record{Usernames: []string{"keybase:jroe"}}),
		in("Bluesky", "d", models.Record{Usernames: []string{"bluesky:jroe"}}),
	}, Anchors{Name: "Jane Roe", Username: "jroe", Location: "Cairo"})
	if res.Ambiguous {
		t.Errorf("lone handle matches are not competing people: %s", res.Note)
	}
	if !res.Identities[0].Primary || res.Identities[0].Weak {
		t.Errorf("the named, anchored profile is the primary identity: %+v", res.Identities[0])
	}
	weak := 0
	for _, id := range res.Identities {
		if id.Weak {
			weak++
		}
	}
	if weak != 3 {
		t.Errorf("expected 3 weak handle-only accounts, got %d", weak)
	}
}
