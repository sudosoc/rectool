package people

import (
	"context"
	"net/url"
	"sort"
	"strings"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
)

// crossref finds papers whose author list contains the name and groups the
// matching author entries by ORCID (or, lacking one, by affiliation) so that
// two researchers sharing a name stay separate candidates.
func crossref(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
	if len(strings.Fields(t.FullName)) < 2 {
		return
	}
	var r struct {
		Message struct {
			Items []struct {
				Title          []string `json:"title"`
				ContainerTitle []string `json:"container-title"`
				Author         []struct {
					Given       string `json:"given"`
					Family      string `json:"family"`
					ORCID       string `json:"ORCID"`
					Affiliation []struct {
						Name string `json:"name"`
					} `json:"affiliation"`
				} `json:"author"`
			} `json:"items"`
		} `json:"message"`
	}
	if !getJSON(ctx, c, "https://api.crossref.org/works?rows=40&select=title,container-title,author&query.author="+esc(t.FullName), nil, &r) {
		return
	}
	type cand struct {
		name, orcid string
		affs        []string
		venues      []string
		papers      []string
	}
	cands := map[string]*cand{}
	for _, it := range r.Message.Items {
		for _, a := range it.Author {
			full := strings.TrimSpace(a.Given + " " + a.Family)
			if !nameMatches(full, t.FullName) {
				continue
			}
			var aff string
			if len(a.Affiliation) > 0 {
				aff = strings.TrimSpace(a.Affiliation[0].Name)
			}
			orcid := strings.TrimPrefix(strings.TrimPrefix(a.ORCID, "http://orcid.org/"), "https://orcid.org/")
			key := orcid
			if key == "" {
				key = "aff:" + strings.ToLower(aff)
			}
			cd := cands[key]
			if cd == nil {
				cd = &cand{name: full, orcid: orcid}
				cands[key] = cd
			}
			if aff != "" {
				cd.affs = appendUniq(cd.affs, aff)
			}
			for _, v := range it.ContainerTitle {
				cd.venues = appendUniq(cd.venues, v)
			}
			if len(it.Title) > 0 {
				cd.papers = appendUniq(cd.papers, it.Title[0])
			}
		}
	}
	keys := make([]string, 0, len(cands))
	for k := range cands {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	emitted := 0
	for _, k := range keys {
		if emitted >= 5 {
			break
		}
		cd := cands[k]
		if cd.orcid == "" && !affiliationHint(cd.affs, t) {
			continue // an anonymous author entry that agrees with nothing the operator gave: noise
		}
		rec := models.Record{Platform: "Crossref", Name: cd.name, Employers: cd.affs, Interests: cd.venues[:min(5, len(cd.venues))], IDs: map[string]string{}}
		if cd.orcid != "" {
			rec.IDs["orcid"] = cd.orcid
			rec.URL = "https://orcid.org/" + cd.orcid
		}
		if len(cd.papers) > 0 {
			rec.Bio = "Papers: " + strings.Join(cd.papers[:min(3, len(cd.papers))], "; ")
		}
		emit(finding("Crossref", "person", 0.5, rec, t))
		emitted++
	}
}

// affiliationHint reports whether any affiliation mentions the operator's
// company, location or e-mail domain.
func affiliationHint(affs []string, t models.Target) bool {
	hints := []string{t.Company, t.Location}
	if i := strings.LastIndex(t.Email, "@"); i >= 0 {
		hints = append(hints, strings.SplitN(t.Email[i+1:], ".", 2)[0])
	}
	for _, a := range affs {
		la := strings.ToLower(a)
		for _, h := range hints {
			if h = strings.ToLower(strings.TrimSpace(h)); len(h) >= 4 && strings.Contains(la, h) {
				return true
			}
		}
	}
	return false
}

// wikipediaPerson reads the encyclopedia summary of a person: description,
// extract, photo and the Wikidata item that ties it to other platforms.
func wikipediaPerson(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
	if len(strings.Fields(t.FullName)) < 2 {
		return
	}
	var r struct {
		Type        string `json:"type"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Extract     string `json:"extract"`
		Wikibase    string `json:"wikibase_item"`
		Thumbnail   struct {
			Source string `json:"source"`
		} `json:"thumbnail"`
		URLs struct {
			Desktop struct {
				Page string `json:"page"`
			} `json:"desktop"`
		} `json:"content_urls"`
	}
	if !getJSON(ctx, c, "https://en.wikipedia.org/api/rest_v1/page/summary/"+url.PathEscape(strings.ReplaceAll(t.FullName, " ", "_")), nil, &r) {
		return
	}
	if r.Type != "standard" || !nameMatches(r.Title, t.FullName) {
		return
	}
	d := strings.ToLower(r.Description)
	if d == "" || strings.Contains(d, "disambiguation") {
		return
	}
	rec := models.Record{Platform: "Wikipedia", URL: r.URLs.Desktop.Page, Name: r.Title, Headline: r.Description,
		Bio: r.Extract, Photo: r.Thumbnail.Source, IDs: map[string]string{}}
	if r.Wikibase != "" {
		rec.IDs["wikidata"] = r.Wikibase
	}
	emit(finding("Wikipedia", "person", 0.55, rec, t))
}

var fediverse = []string{"mastodon.social", "mstdn.social", "fosstodon.org", "infosec.exchange", "hachyderm.io", "mas.to", "techhub.social", "chaos.social"}

// webfinger asks well-known Fediverse servers whether a handle exists. This is
// an open standard (RFC 7033), no scraping involved.
func webfinger(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
	handles := []string{}
	for _, h := range []string{t.Username, t.Alias} {
		h = strings.TrimPrefix(strings.TrimSpace(h), "@")
		if h != "" && !strings.ContainsAny(h, " @/") {
			handles = appendUniq(handles, h)
		}
	}
	for _, h := range handles {
		for _, host := range fediverse {
			var r struct {
				Subject string `json:"subject"`
				Links   []struct {
					Rel  string `json:"rel"`
					Href string `json:"href"`
				} `json:"links"`
			}
			if !getJSON(ctx, c, "https://"+host+"/.well-known/webfinger?resource=acct:"+esc(h)+"@"+host, map[string]string{"Accept": "application/jrd+json"}, &r) || r.Subject == "" {
				continue
			}
			page := "https://" + host + "/@" + h
			for _, l := range r.Links {
				if l.Rel == "http://webfinger.net/rel/profile-page" && l.Href != "" {
					page = l.Href
				}
			}
			rec := models.Record{Platform: "Fediverse", URL: page, Usernames: []string{"mastodon:" + h + "@" + host}, Self: true}
			emit(finding("Fediverse WebFinger", "social", 0.6, rec, t))
		}
	}
}

// archived lists Wayback snapshots of profile pages the operator supplied or
// that were found, so deleted or renamed profiles still leave a trail.
func archived(ctx context.Context, c *httpx.Client, t models.Target, emit func(models.Finding)) {
	n := 0
	for _, l := range t.Links {
		if n >= 6 {
			break
		}
		if !strings.HasPrefix(l, "http") {
			continue
		}
		n++
		var r struct {
			Snapshots struct {
				Closest struct {
					Available bool   `json:"available"`
					URL       string `json:"url"`
					Timestamp string `json:"timestamp"`
				} `json:"closest"`
			} `json:"archived_snapshots"`
		}
		if !getJSON(ctx, c, "https://archive.org/wayback/available?url="+esc(l), nil, &r) || !r.Snapshots.Closest.Available {
			continue
		}
		ts := r.Snapshots.Closest.Timestamp
		if len(ts) >= 8 {
			ts = ts[:4] + "-" + ts[4:6] + "-" + ts[6:8]
		}
		emit(models.Finding{Source: "Internet Archive", Category: "archive", URL: r.Snapshots.Closest.URL, Status: models.StatusFound,
			Confidence: 0.9, Details: map[string]string{"original": l, "snapshot date": ts,
				"note": "archived copy of a profile link; useful when the live page was deleted or renamed"}})
	}
}
