package identity

import "strings"

// platformReliability is how far a fact stated by a platform can be trusted
// when it is the only source: official or verified registries are high;
// free-text profile fields anyone can type are lower; web search snippets lowest.
var platformReliability = map[string]float64{
	"orcid": 0.85, "wikidata": 0.8, "wikipedia": 0.8, "openalex": 0.7, "crossref": 0.6, "gleif": 0.9,
	"github": 0.6, "gitlab": 0.55, "keybase": 0.65, "stack overflow": 0.5, "hugging face": 0.5, "linkedin": 0.65,
	"gravatar": 0.55, "npm": 0.5, "docker hub": 0.45, "reddit": 0.4, "hacker news": 0.4, "mastodon": 0.45, "bluesky": 0.45,
	"telegram": 0.4, "steam": 0.4, "lichess": 0.4, "chess.com": 0.4, "codeforces": 0.45, "dev.to": 0.45, "crates.io": 0.5,
	"cv": 0.6, "website": 0.55, "fediverse": 0.45,
}

// Reliability returns the single-source trust of a platform (0.35 if unknown).
func Reliability(platform string) float64 {
	if v, ok := platformReliability[strings.ToLower(strings.TrimSpace(platform))]; ok {
		return v
	}
	return 0.35
}

// factTrust combines independent sources as a noisy-OR, capped below certainty.
func factTrust(sources []string, self bool) float64 {
	miss := 1.0
	for _, s := range sources {
		miss *= 1 - Reliability(s)
	}
	t := 1 - miss
	if self {
		t = 1 - (1-t)*0.85
	}
	if t > 0.97 {
		t = 0.97
	}
	return float64(int(t*100+0.5)) / 100
}
