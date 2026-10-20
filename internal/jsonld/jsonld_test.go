package jsonld

import "testing"

// Shaped like LinkedIn's logged-out public profile.
const linkedInStyle = `<html><head><script type="application/ld+json">{"@context":"http://schema.org","@graph":[
{"@type":"Person","name":"Jane Roe","jobTitle":["Senior Engineer","Mentor"],
 "worksFor":[{"@type":"Organization","name":"Acme","url":"https://www.linkedin.com/company/acme","location":"Cairo, Egypt","member":{"@type":"OrganizationRole","startDate":"2021-03"}}],
 "alumniOf":[{"@type":"Organization","name":"OldCo","member":{"startDate":2015,"endDate":2020}},
             {"@type":"EducationalOrganization","name":"Cairo University","member":{"startDate":2009,"endDate":2013}}],
 "address":{"@type":"PostalAddress","addressLocality":"Cairo, Egypt","addressCountry":"EG"},
 "image":{"@type":"ImageObject","contentUrl":"https://media.licdn.com/p/1.jpg"},
 "description":"Builds reliable systems.","sameAs":["https://janeroe.dev"],"knowsLanguage":[{"@type":"Language","name":"Arabic"},"English"]},
{"@type":"WebSite","name":"ignored"}]}</script></head></html>`

func TestPersonsLinkedInStyle(t *testing.T) {
	ps := Persons(linkedInStyle)
	if len(ps) != 1 {
		t.Fatalf("persons: %+v", ps)
	}
	p := ps[0]
	if p.Name != "Jane Roe" || len(p.JobTitles) != 2 || p.JobTitles[0] != "Senior Engineer" {
		t.Errorf("basic fields: %+v", p)
	}
	if len(p.WorksFor) != 1 || p.WorksFor[0].Name != "Acme" || p.WorksFor[0].Start != "2021-03" || p.WorksFor[0].Location != "Cairo, Egypt" {
		t.Errorf("worksFor: %+v", p.WorksFor)
	}
	if len(p.Alumni) != 2 || p.Alumni[0].School || !p.Alumni[1].School || p.Alumni[0].End != "2020" {
		t.Errorf("alumni (past job vs school): %+v", p.Alumni)
	}
	if p.Location != "Cairo, Egypt" || p.Image != "https://media.licdn.com/p/1.jpg" || p.Description == "" || len(p.SameAs) != 1 {
		t.Errorf("location/image/etc: %+v", p)
	}
	if len(p.Languages) != 2 {
		t.Errorf("languages: %v", p.Languages)
	}
}

func TestPersonsTolerantOfOtherShapes(t *testing.T) {
	doc := `<script type="application/ld+json">[{"@type":"Person","name":"A B","email":"mailto:A@B.org","telephone":"+1 555 0100","address":"Berlin"},{"@type":["Thing","Person"],"name":"C D"}]</script>
	<script type="application/ld+json">{not json}</script>
	<script type="application/ld+json">{"@type":"ProfilePage","mainEntity":{"@type":"Person","name":"E F"}}</script>`
	ps := Persons(doc)
	if len(ps) != 3 || ps[0].Emails[0] != "a@b.org" || ps[0].Location != "Berlin" || ps[1].Name != "C D" || ps[2].Name != "E F" {
		t.Fatalf("%+v", ps)
	}
	if len(Persons("<html>no data</html>")) != 0 {
		t.Error("no blocks -> no persons")
	}
}
