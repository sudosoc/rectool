package domain

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sudosoc/rectool/internal/models"
)

// takeoverServices are third-party platforms where an unclaimed hostname can
// often be registered by anyone. A CNAME pointing at one of them while the
// target name no longer resolves is the classic "dangling record".
var takeoverServices = []struct{ suffix, service string }{
	{".github.io", "GitHub Pages"}, {".herokuapp.com", "Heroku"}, {".herokudns.com", "Heroku"},
	{".s3.amazonaws.com", "AWS S3"}, {".s3-website", "AWS S3 website"}, {".elasticbeanstalk.com", "AWS Elastic Beanstalk"},
	{".azurewebsites.net", "Azure App Service"}, {".cloudapp.net", "Azure Cloud Services"}, {".cloudapp.azure.com", "Azure"},
	{".trafficmanager.net", "Azure Traffic Manager"}, {".blob.core.windows.net", "Azure Blob"},
	{".netlify.app", "Netlify"}, {".netlify.com", "Netlify"}, {".vercel.app", "Vercel"}, {".surge.sh", "Surge"},
	{".pantheonsite.io", "Pantheon"}, {".wordpress.com", "WordPress.com"}, {".ghost.io", "Ghost"},
	{".readme.io", "Readme"}, {".helpscoutdocs.com", "Help Scout"}, {".zendesk.com", "Zendesk"},
	{".cargocollective.com", "Cargo"}, {".bitbucket.io", "Bitbucket"}, {".fastly.net", "Fastly"},
	{".myshopify.com", "Shopify"}, {".statuspage.io", "Statuspage"}, {".unbouncepages.com", "Unbounce"},
	{".fly.dev", "Fly.io"}, {".firebaseapp.com", "Firebase"}, {".web.app", "Firebase Hosting"},
	{".tumblr.com", "Tumblr"}, {".webflow.io", "Webflow"}, {".uservoice.com", "UserVoice"},
}

// takeoverCandidates inspects the CNAME of each non-resolving name.
func takeoverCandidates(ctx context.Context, domain string, dead []string, emit func(models.Finding)) {
	type hit struct{ name, target, service string }
	var (
		mu   sync.Mutex
		hits []hit
		wg   sync.WaitGroup
		sem  = make(chan struct{}, 16)
	)
	for _, n := range dead {
		n = strings.TrimSuffix(n, " (wildcard)")
		if strings.HasSuffix(n, ")") || !sameSite(n, domain) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			cn, err := net.DefaultResolver.LookupCNAME(lctx, n)
			cn = strings.TrimSuffix(strings.ToLower(cn), ".")
			if err != nil || cn == "" || cn == n {
				return
			}
			for _, s := range takeoverServices {
				if strings.HasSuffix(cn, s.suffix) || strings.Contains(cn, s.suffix+".") {
					mu.Lock()
					hits = append(hits, hit{n, cn, s.service})
					mu.Unlock()
					return
				}
			}
		}()
	}
	wg.Wait()
	sort.Slice(hits, func(i, j int) bool { return hits[i].name < hits[j].name })
	for _, h := range hits {
		emit(fnd("Possible subdomain takeover: "+h.name, "takeover", "", 0.6, map[string]string{
			"CNAME target": h.target, "platform": h.service,
			"why":    "the name does not resolve but its CNAME points at a third-party platform where it may be unclaimed",
			"verify": "check whether the target service shows an 'unclaimed / not found' page before treating it as exploitable",
		}))
	}
}
