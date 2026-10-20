package engine

import (
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/identity"
	"github.com/sudosoc/rectool/internal/models"
)

var isoDate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}`)

// dateKeys are finding-detail keys that hold a date, with the sentence they
// become on the timeline.
var dateKeys = map[string]string{
	"created": "account created", "joined": "joined", "member since": "member since", "first event": "first public activity seen",
	"last event": "last public activity seen", "snapshot date": "archived copy", "first archived": "first archived copy",
	"last archived": "latest archived copy", "registered": "registered", "registration": "registered", "last changed": "record last changed",
	"expires": "expires", "updated": "profile updated", "created at": "created",
}

// timelineStage orders every dated fact (account creations, first and last
// activity, archive snapshots, domain registration, photo capture times) into
// one chronology, so changes and gaps are visible.
func (e *Engine) timelineStage(rep *models.Report) {
	own := map[string]bool{}
	haveID := false
	for _, id := range rep.Identities {
		if id.Weak {
			continue
		}
		haveID = true
		for _, r := range id.Records {
			own[r.URL] = true
		}
		break
	}
	var ev []models.TimelineEvent
	seen := map[string]bool{}
	for _, f := range rep.Hits() {
		personal := f.Module == "profiles" || f.Module == "people" || f.Module == "social"
		if haveID && personal && !own[f.URL] {
			continue // a record of a different person
		}
		for k, d := range f.Details {
			label, ok := dateKeys[strings.ToLower(k)]
			if !ok || !isoDate.MatchString(d) {
				continue
			}
			date := d[:10]
			key := date + f.Source + label
			if seen[key] {
				continue
			}
			seen[key] = true
			ev = append(ev, models.TimelineEvent{Date: date, Event: label, Source: f.Source, URL: f.URL})
		}
	}
	for _, p := range rep.Photos {
		if p.Taken != "" && len(p.Taken) >= 10 {
			ev = append(ev, models.TimelineEvent{Date: strings.ReplaceAll(p.Taken[:10], ":", "-"), Event: "photo taken (EXIF)", Source: strings.Join(p.Sources, ", "), URL: p.URL})
		}
	}
	if len(ev) == 0 {
		return
	}
	sort.SliceStable(ev, func(i, j int) bool { return ev[i].Date < ev[j].Date })
	rep.Timeline = ev
}

// cloneStage looks for impersonation: profiles on different platforms that
// carry the same long bio text but different names are copies of each other,
// and one of them is probably not the real person.
func (e *Engine) cloneStage(rep *models.Report) {
	type rec struct {
		name, platform, url string
	}
	byBio := map[string][]rec{}
	for _, f := range rep.Hits() {
		r := f.Record
		if r == nil || len(strings.TrimSpace(r.Bio)) < 50 {
			continue
		}
		key := strings.Join(strings.Fields(strings.ToLower(r.Bio)), " ")
		byBio[key] = append(byBio[key], rec{r.Name, r.Platform, r.URL})
	}
	for bio, recs := range byBio {
		if len(recs) < 2 {
			continue
		}
		diff := false
		var where []string
		for i, a := range recs {
			where = append(where, a.platform+" ("+a.name+")")
			for _, b := range recs[i+1:] {
				if a.name != "" && b.name != "" && identity.MatchNames(a.name, b.name) == identity.NameNone && a.platform != b.platform {
					diff = true
				}
			}
		}
		if !diff {
			continue
		}
		snippet := bio
		if len(snippet) > 120 {
			snippet = snippet[:120] + "…"
		}
		f := models.Finding{Module: "integrity", Source: "Copied profile text", Category: "integrity", Status: models.StatusUncertain, Confidence: 0.7,
			Details: map[string]string{"text": snippet, "found on": strings.Join(where, "; "),
				"note": "the same bio appears under different names: one profile may be an impersonation or a copy. Treat both with care."},
			Timestamp: time.Now().UTC()}
		rep.Findings = append(rep.Findings, f)
		if e.OnFinding != nil {
			e.OnFinding(f)
		}
	}
}
