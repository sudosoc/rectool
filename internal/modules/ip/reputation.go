package ip

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
)

// greyNoiseJob asks GreyNoise's community endpoint whether the address is
// known internet background noise (mass scanners, botnets) or a benign
// service (RIOT: Google, Cloudflare, CDNs…). It helps decide if an IP is
// attacker infrastructure, shared infrastructure, or just a home user.
func greyNoiseJob(ctx context.Context, c *httpx.Client, a netip.Addr, emit func(models.Finding)) {
	var r struct {
		IP             string `json:"ip"`
		Noise          bool   `json:"noise"`
		Riot           bool   `json:"riot"`
		Classification string `json:"classification"`
		Name           string `json:"name"`
		LastSeen       string `json:"last_seen"`
		Message        string `json:"message"`
		Link           string `json:"link"`
	}
	if !getJSON(ctx, c, "https://api.greynoise.io/v3/community/"+a.String(), 15*time.Second, &r) || r.IP == "" {
		return
	}
	d := map[string]string{"internet noise (mass scanner)": yesNo(r.Noise), "known benign service (RIOT)": yesNo(r.Riot)}
	put(d, "classification", r.Classification)
	put(d, "actor / service", r.Name)
	put(d, "last seen", r.LastSeen)
	put(d, "message", r.Message)
	conf := 0.8
	if !r.Noise && !r.Riot {
		conf = 0.5 // "not observed" is weak evidence either way
	}
	link := r.Link
	if !strings.HasPrefix(link, "https://") {
		link = "https://viz.greynoise.io/ip/" + a.String()
	}
	emit(fnd("Reputation (GreyNoise community)", "reputation", link, conf, d))
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
