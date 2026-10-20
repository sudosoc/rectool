package models

// Record is one candidate profile of *a* person, as published by one source
// (a LinkedIn page, an ORCID record, a GitHub profile…). Records are the raw
// material of identity resolution: they are clustered into identities, so
// that facts about different people who merely share a name or a handle are
// never blended into one profile.
type Record struct {
	Platform  string            `json:"platform"` // "LinkedIn", "ORCID", "GitHub", "Website", "CV"…
	URL       string            `json:"url,omitempty"`
	Name      string            `json:"name,omitempty"`
	Headline  string            `json:"headline,omitempty"` // job title / tagline
	Employers []string          `json:"employers,omitempty"`
	Roles     []string          `json:"roles,omitempty"`
	Location  string            `json:"location,omitempty"`
	Emails    []string          `json:"emails,omitempty"`
	Phones    []string          `json:"phones,omitempty"`
	Usernames []string          `json:"usernames,omitempty"` // "platform:handle"
	Websites  []string          `json:"websites,omitempty"`
	Photo     string            `json:"photo,omitempty"`
	Education []string          `json:"education,omitempty"`
	Interests []string          `json:"interests,omitempty"`
	Bio       string            `json:"bio,omitempty"`
	IDs       map[string]string `json:"ids,omitempty"`  // unique identifiers: orcid, wikidata, linkedin, github, openalex…
	Self      bool              `json:"self,omitempty"` // authored by the person themself (a profile / CV / home page), not a third-party record
}

// Fact is one attribute value of an identity together with its provenance.
type Fact struct {
	Value     string   `json:"value"`
	Sources   []string `json:"sources"`             // platforms that state it
	Confirmed bool     `json:"confirmed,omitempty"` // stated by two or more independent platforms
	Self      bool     `json:"self,omitempty"`      // at least one source is the person's own profile
}

// RecordRef points from an identity back to a contributing record.
type RecordRef struct {
	Platform string `json:"platform"`
	URL      string `json:"url,omitempty"`
	Source   string `json:"source"` // "module: finding source"
	Self     bool   `json:"self,omitempty"`
}

// Identity is one resolved person: a cluster of records judged to describe the
// same individual, scored against the identifiers the operator supplied.
type Identity struct {
	ID        int      `json:"id"`
	Label     string   `json:"label"`
	Score     float64  `json:"score"` // 0–1: how well this person matches what the operator gave
	Primary   bool     `json:"primary,omitempty"`
	Weak      bool     `json:"weak,omitempty"`      // matched only by a shared handle: an unnamed single account, probably someone else
	Matched   []string `json:"matched,omitempty"`   // which supplied identifiers it matches
	Reasons   []string `json:"reasons,omitempty"`   // why its records were linked
	Conflicts []string `json:"conflicts,omitempty"` // attributes its sources disagree on

	Names     []Fact `json:"names,omitempty"`
	Headlines []Fact `json:"headlines,omitempty"`
	Employers []Fact `json:"employers,omitempty"`
	Locations []Fact `json:"locations,omitempty"`
	Education []Fact `json:"education,omitempty"`
	Interests []Fact `json:"interests,omitempty"`
	Emails    []Fact `json:"emails,omitempty"`
	Phones    []Fact `json:"phones,omitempty"`
	Usernames []Fact `json:"usernames,omitempty"`
	Websites  []Fact `json:"websites,omitempty"`

	Photos  []string          `json:"photos,omitempty"`
	Bio     string            `json:"bio,omitempty"`
	IDs     map[string]string `json:"ids,omitempty"`
	Docs    []string          `json:"documents,omitempty"` // CV / resume URLs
	Records []RecordRef       `json:"records"`
}
