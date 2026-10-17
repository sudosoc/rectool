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
	Via        string            `json:"via,omitempty"` // set when found by following another finding, e.g. "email:a@b.c"
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
	Photos      []Photo           `json:"photos,omitempty"`
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
