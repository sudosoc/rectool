package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/identity"
	"github.com/sudosoc/rectool/internal/models"
)

// identityStage resolves the collected person records into distinct people and
// scores each against what the operator supplied, so facts about different
// individuals are never blended. The outcome is stored on the report and
// summarised as one finding.
func (e *Engine) identityStage(rep *models.Report) {
	res := identity.ResolveFindings(rep.Findings, rep.Target, rep.Photos)
	if len(res.Identities) == 0 {
		return
	}
	rep.Identities = res.Identities
	rep.Ambiguity = res.Note

	top := res.Identities[0]
	d := map[string]string{
		"people found": fmt.Sprint(len(res.Identities)),
		"best match":   top.Label,
		"match score":  fmt.Sprintf("%.0f%%", top.Score*100),
		"matched on":   strings.Join(top.Matched, ", "),
	}
	if res.Note != "" {
		d["ambiguity"] = res.Note
	}
	if res.SameName > 1 {
		d["people with this name"] = fmt.Sprint(res.SameName)
	}
	conf := top.Score
	f := models.Finding{Module: "identity", Source: "Identity resolution", Category: "identity", Status: models.StatusFound,
		Confidence: conf, Details: d, Timestamp: time.Now().UTC()}
	rep.Findings = append(rep.Findings, f)
	if e.OnFinding != nil {
		e.OnFinding(f)
	}
}

// pivotFilter decides which discovered leads may be followed. Leads that
// belong to a person other than the best-matching identity are never
// followed, and when several people plausibly match, no identity-derived lead
// is followed at all until the operator narrows it down. Leads that came from
// infrastructure (domains, IPs) rather than a person's profile pass through.
func (e *Engine) pivotFilter(rep *models.Report) func(models.Entity) bool {
	res := identity.ResolveFindings(rep.Findings, rep.Target, nil)
	if len(res.Identities) == 0 {
		return func(models.Entity) bool { return true }
	}
	keys := func(id models.Identity) map[string]bool {
		m := map[string]bool{}
		for _, f := range id.Emails {
			m[models.EntEmail+":"+strings.ToLower(f.Value)] = true
		}
		for _, f := range id.Usernames {
			if _, h, ok := strings.Cut(f.Value, ":"); ok {
				m[models.EntUsername+":"+strings.ToLower(strings.TrimPrefix(h, "@"))] = true
			}
		}
		for _, f := range id.Websites {
			if d := hostOnly(f.Value); d != "" {
				m[models.EntDomain+":"+d] = true
			}
		}
		return m
	}
	allowed := map[string]bool{}
	blocked := map[string]bool{}
	for i, id := range res.Identities {
		k := keys(id)
		if i == 0 && id.Primary && !res.Ambiguous {
			for x := range k {
				allowed[x] = true
			}
			continue
		}
		for x := range k {
			blocked[x] = true
		}
	}
	return func(ent models.Entity) bool {
		k := ent.Type + ":" + strings.ToLower(ent.Value)
		if allowed[k] {
			return true
		}
		return !blocked[k]
	}
}

func hostOnly(raw string) string {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	i := strings.Index(raw, "://")
	h := raw[i+3:]
	if j := strings.IndexAny(h, "/?#:"); j >= 0 {
		h = h[:j]
	}
	return strings.TrimPrefix(strings.ToLower(h), "www.")
}
