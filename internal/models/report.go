package models

import "time"

// Status is the outcome of a single check.
type Status string

const (
	StatusFound     Status = "found"
	StatusNotFound  Status = "not_found"
	StatusUncertain Status = "uncertain"
	StatusError     Status = "error"
)

// Entity types a finding can point at. The engine may pivot on them.
const (
	EntEmail    = "email"
	EntDomain   = "domain"
	EntIP       = "ip"
	EntUsername = "username"
	EntPhone    = "phone"
	EntName     = "name"
	EntURL      = "url"
	EntLocation = "location"
	EntOrg      = "organisation"
	EntImage    = "image" // a profile picture / photo URL
)

// Entity is something new learned about the subject (an email, a domain, a
// username…). Strong entities are well enough attributed to the subject that
// the engine will follow them in a second pass.
type Entity struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Strong bool   `json:"strong,omitempty"`
	Source string `json:"source,omitempty"` // filled in by the engine: module/source that found it
}

// Finding is one piece of intelligence (or one failed/negative check) emitted
// by a scanner module.
type Finding struct {
	Module     string            `json:"module"`
	Source     string            `json:"source"`
	Category   string            `json:"category,omitempty"`
	URL        string            `json:"url,omitempty"`
	Status     Status            `json:"status"`
	Confidence float64           `json:"confidence"`
	Details    map[string]string `json:"details,omitempty"`
	Entities   []Entity          `json:"entities,omitempty"`
	Record     *Record           `json:"record,omitempty"` // set when the finding describes a person profile
	Via        string            `json:"via,omitempty"`    // set when found by following another finding, e.g. "email:a@b.c"
	Timestamp  time.Time         `json:"timestamp"`
}

// ModuleRun summarises the execution of one scanner.
type ModuleRun struct {
	Name       string `json:"name"`
	Via        string `json:"via,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Checked    int    `json:"checked"`
	Found      int    `json:"found"`
	Errors     int    `json:"errors"`
	Error      string `json:"error,omitempty"`
}

// Report is the complete result of one engine run.
type Report struct {
	Tool        string      `json:"tool"`
	Version     string      `json:"version"`
	Target      Target      `json:"target"`
	StartedAt   time.Time   `json:"started_at"`
	FinishedAt  time.Time   `json:"finished_at"`
	Interrupted bool        `json:"interrupted,omitempty"`
	Modules     []ModuleRun `json:"modules"`
	Skipped     []string    `json:"skipped,omitempty"`
	Entities    []Entity    `json:"entities,omitempty"`
	Findings    []Finding   `json:"findings"`

	// Failures lists checks that could not be completed (blocked, timed out,
	// service offline). They are coverage gaps: a missing result is not proof
	// that nothing exists.
	Identities  []Identity        `json:"identities,omitempty"` // resolved people, best match first
	Ambiguity   string            `json:"ambiguity,omitempty"`  // set when several people plausibly match
	Photos      []Photo           `json:"photos,omitempty"`
	Timeline    []TimelineEvent   `json:"timeline,omitempty"`
	Notes       map[string]string `json:"notes,omitempty"` // analyst notes keyed by what they are about
	Geo         *GeoSummary       `json:"geo,omitempty"`   // where the subject probably is, with evidence
	ManualLeads []Lead            `json:"manual_leads,omitempty"`
	Failures    []Failure         `json:"failures,omitempty"`
	Settings    map[string]string `json:"settings,omitempty"` // how the run was configured, for reproducibility
	Integrity   *Integrity        `json:"integrity,omitempty"`
}

// Failure is one check that did not complete.
type Failure struct {
	Module string `json:"module"`
	Source string `json:"source"`
	Error  string `json:"error"`
	Via    string `json:"via,omitempty"`
}

// Integrity lets a report be verified later: Digest is the SHA-256 of the
// canonical JSON of the target, entities and findings.
type Integrity struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
	Findings  int    `json:"findings"`
	Entities  int    `json:"entities"`
}

// Hits returns only the positive findings.
func (r *Report) Hits() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Status == StatusFound || f.Status == StatusUncertain {
			out = append(out, f)
		}
	}
	return out
}

// Photo is a downloaded profile picture with fingerprints. Photos whose
// perceptual hashes match share a Group number (> 0): the same picture is used
// in several places, which is strong evidence that the accounts belong together.
type Photo struct {
	URL         string   `json:"url"`
	Sources     []string `json:"sources"`
	ContentType string   `json:"content_type,omitempty"`
	Bytes       int      `json:"bytes"`
	Width       int      `json:"width"`
	Height      int      `json:"height"`
	SHA256      string   `json:"sha256"`
	DHash       string   `json:"dhash,omitempty"`
	GPS         string   `json:"gps,omitempty"`    // "lat,lon" read from the file's EXIF
	Taken       string   `json:"taken,omitempty"`  // EXIF capture time
	Camera      string   `json:"camera,omitempty"` // EXIF make and model
	Group       int      `json:"group,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// Lead is a manual follow-up: a source that cannot be queried automatically
// (login, CAPTCHA, paid) but is worth opening by hand for this identifier.
type Lead struct {
	Group string `json:"group"` // identifier type it applies to
	Label string `json:"label"`
	URL   string `json:"url"`
	Why   string `json:"why"`
}

// GeoPoint is one piece of location evidence, geocoded.
type GeoPoint struct {
	Label       string   `json:"label"`   // text as found, e.g. "Cairo, Egypt"
	Kind        string   `json:"kind"`    // self-declared | organisation | ip | phone | exif | activity | given
	Sources     []string `json:"sources"` // where it was stated
	Lat         float64  `json:"lat"`
	Lon         float64  `json:"lon"`
	Place       string   `json:"place,omitempty"` // geocoder's canonical name
	City        string   `json:"city,omitempty"`
	Region      string   `json:"region,omitempty"`
	Country     string   `json:"country,omitempty"`
	CountryCode string   `json:"country_code,omitempty"`
	Precision   string   `json:"precision"` // exact | city | region | country
	Weight      float64  `json:"weight"`    // how much this kind of evidence is trusted
}

// GeoCluster groups evidence that points to the same place.
type GeoCluster struct {
	Label       string   `json:"label"`
	Lat         float64  `json:"lat"`
	Lon         float64  `json:"lon"`
	Country     string   `json:"country,omitempty"`
	CountryCode string   `json:"country_code,omitempty"`
	Score       float64  `json:"score"`  // 0-1, noisy-OR of its evidence weights
	Kinds       []string `json:"kinds"`  // evidence types that support it
	Points      []int    `json:"points"` // indexes into GeoSummary.Points
}

// TZEstimate is a timezone guessed from when the subject is active online.
type TZEstimate struct {
	Offset     float64    `json:"utc_offset"`
	Label      string     `json:"label"` // "UTC+02:00"
	Confidence float64    `json:"confidence"`
	Events     int        `json:"events"`
	Hours      [24]int    `json:"hours_utc"` // activity histogram by UTC hour
	Grid       [7][24]int `json:"grid_utc"`  // weekday (Mon=0) x UTC hour
	Regions    []string   `json:"regions,omitempty"`
	Sources    []string   `json:"sources,omitempty"`
}

// GeoSummary is the location analysis of a report.
type GeoSummary struct {
	Points    []GeoPoint   `json:"points"`
	Clusters  []GeoCluster `json:"clusters"`
	Consensus string       `json:"consensus,omitempty"` // best-supported place
	Conflict  string       `json:"conflict,omitempty"`  // set when evidence disagrees
	Given     string       `json:"given,omitempty"`     // the location the operator supplied
	GivenFit  string       `json:"given_fit,omitempty"` // agrees | differs | unknown
	TZ        *TZEstimate  `json:"timezone,omitempty"`
	Notes     []string     `json:"notes,omitempty"`
}

// TimelineEvent is one dated fact.
type TimelineEvent struct {
	Date   string `json:"date"` // YYYY-MM-DD
	Event  string `json:"event"`
	Source string `json:"source"`
	URL    string `json:"url,omitempty"`
}
