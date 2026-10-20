package engine

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/geo"
	"github.com/sudosoc/rectool/internal/models"
)

const maxGeocodes = 16

type rawGeo struct {
	label   string
	kind    string
	sources []string
	weight  float64
	place   *geo.Place // set when coordinates are already known
}

// locationStage gathers every location clue in the report (the best-matching
// person's profile locations, IP geolocation, phone region, company
// addresses, EXIF GPS in published pictures, activity hours), geocodes them,
// clusters those that agree, scores each cluster and reports the best-supported
// place together with any conflict. It never searches for street addresses.
func (e *Engine) locationStage(ctx context.Context, rep *models.Report) {
	var raws []rawGeo
	add := func(r rawGeo) {
		for i := range raws {
			if strings.EqualFold(raws[i].label, r.label) && raws[i].kind == r.kind {
				for _, s := range r.sources {
					raws[i].sources = addUnique(raws[i].sources, s)
				}
				return
			}
		}
		raws = append(raws, r)
	}

	var notes []string
	// platforms whose account belongs to the best-matching person: only their
	// activity may inform the timezone (a handle can be someone else's elsewhere)
	owned := map[string]bool{}
	haveID := false
	// 1) the best-matching person's own locations
	for _, id := range rep.Identities {
		if id.Weak {
			continue
		}
		haveID = true
		for _, r := range id.Records {
			owned[strings.ToLower(r.Platform)] = true
		}
		for _, f := range id.Locations {
			w := geo.Weight("self-declared")
			if f.Confirmed {
				w = 0.88
			} else if !f.Self {
				w = 0.5 // stated by a third-party record only (may be a birthplace or an old address)
			}
			add(rawGeo{label: f.Value, kind: "self-declared", sources: f.Sources, weight: w})
		}
		// places mentioned in the bio ("based in Lyon"): weaker than a location field
		for _, p := range geo.PlacesInText(id.Bio) {
			add(rawGeo{label: p, kind: "self-declared", sources: []string{"bio text"}, weight: 0.45})
		}
		if !id.Primary {
			notes = append(notes, "No single person is a confirmed match; locations are those of the best candidate ("+id.Label+").")
		}
		break
	}

	// 2) technical and registry signals tied to the inputs
	var hours [24]int
	var grid [7][24]int
	var tzSources []string
	events := 0
	for _, f := range rep.Hits() {
		d := f.Details
		switch {
		case f.Module == "ip" && f.Category == "geo":
			var parts []string
			for _, k := range []string{"city", "region", "country"} {
				if d[k] != "" {
					parts = append(parts, d[k])
				}
			}
			r := rawGeo{label: strings.Join(parts, ", "), kind: "ip", sources: []string{"ip: " + f.Source}, weight: geo.Weight("ip")}
			if ll := strings.Split(d["coordinates"], ","); len(ll) == 2 {
				la, e1 := strconv.ParseFloat(strings.TrimSpace(ll[0]), 64)
				lo, e2 := strconv.ParseFloat(strings.TrimSpace(ll[1]), 64)
				if e1 == nil && e2 == nil {
					r.place = &geo.Place{Lat: la, Lon: lo, City: d["city"], Region: d["region"], Country: d["country"], Precision: "city"}
				}
			}
			if r.label != "" {
				add(r)
			}
		case f.Module == "phone" && f.Category == "phone":
			if a := d["area / location"]; a != "" {
				add(rawGeo{label: a + " (" + d["region (ISO)"] + ")", kind: "phone", sources: []string{"phone number allocation"}, weight: geo.Weight("phone")})
			} else if iso := d["region (ISO)"]; iso != "" {
				add(rawGeo{label: iso, kind: "phone", sources: []string{"phone number allocation"}, weight: 0.2})
			}
		case f.Module == "company":
			for _, en := range f.Entities {
				if en.Type == models.EntLocation && en.Value != "" {
					add(rawGeo{label: en.Value, kind: "organisation", sources: []string{"company registry: " + f.Source}, weight: geo.Weight("organisation")})
				}
			}
		case f.Module == "activity":
			if f.Via != "" {
				continue // a handle that was only discovered, not supplied
			}
			if haveID && !owned[strings.ToLower(d["source"])] {
				continue // account not tied to the matched person
			}
			if hs := strings.Split(d["hours_utc"], ","); len(hs) == 24 {
				for i, h := range hs {
					n, _ := strconv.Atoi(h)
					hours[i] += n
					events += n
				}
				if wk := strings.Split(d["week_utc"], ","); len(wk) == 168 {
					for i, v := range wk {
						n, _ := strconv.Atoi(v)
						grid[i/24][i%24] += n
					}
				}
				tzSources = append(tzSources, d["source"]+" ("+d["handle"]+")")
			}
		}
	}

	// 3) GPS in published pictures. A picture found only by web image search
	// is not evidence about the subject.
	for _, p := range rep.Photos {
		if p.GPS == "" {
			continue
		}
		own := false
		for _, s := range p.Sources {
			if !strings.HasPrefix(s, "images:") {
				own = true
			}
		}
		if own {
			add(rawGeo{label: p.GPS, kind: "exif", sources: append([]string{"EXIF GPS in " + shortURL(p.URL)}, p.Sources...), weight: geo.Weight("exif")})
		}
	}

	if len(raws) == 0 && events == 0 && strings.TrimSpace(rep.Target.Location) == "" {
		return
	}

	gc := geo.NewGeocoder(e.http)
	var points []models.GeoPoint
	lookups := 0
	for _, r := range raws {
		p := r.place
		if p == nil {
			if lookups >= maxGeocodes || ctx.Err() != nil {
				continue
			}
			lookups++
			var ok bool
			if p, ok = gc.Geocode(ctx, r.label); !ok {
				continue
			}
		}
		pt := models.GeoPoint{Label: r.label, Kind: r.kind, Sources: r.sources, Lat: p.Lat, Lon: p.Lon, Place: p.Display,
			City: p.City, Region: p.Region, Country: p.Country, CountryCode: p.CountryCode, Precision: p.Precision, Weight: r.weight}
		if r.kind == "exif" {
			pt.Precision = "exact"
		}
		// coarse evidence says less: a bare country narrows little
		switch pt.Precision {
		case "country":
			pt.Weight *= 0.6
		case "region":
			pt.Weight *= 0.85
		}
		points = append(points, pt)
	}

	var givenPlace *geo.Place
	if g := strings.TrimSpace(rep.Target.Location); g != "" && ctx.Err() == nil {
		givenPlace, _ = gc.Geocode(ctx, g)
	}
	sum := geo.Analyse(points, rep.Target.Location, givenPlace)
	sum.Notes = notes

	// timezone from activity hours, checked against the leading place
	if off, conf, ok := geo.InferOffset(hours); ok {
		tz := &models.TZEstimate{Offset: off, Label: geo.OffsetLabel(off), Confidence: math.Round(conf*100) / 100, Events: events,
			Hours: hours, Grid: grid, Regions: geo.OffsetRegions(off), Sources: tzSources}
		sum.TZ = tz
		if len(sum.Clusters) > 0 {
			top := sum.Clusters[0]
			expected := top.Lon / 15
			if math.Abs(expected-off) <= 2.5 {
				sum.Notes = append(sum.Notes, fmt.Sprintf("Activity hours (%s) are consistent with %s.", tz.Label, top.Label))
				points = append(points, models.GeoPoint{Label: "activity pattern " + tz.Label, Kind: "activity", Sources: tzSources,
					Lat: top.Lat, Lon: top.Lon, Country: top.Country, CountryCode: top.CountryCode, Precision: "country", Weight: geo.Weight("activity") * conf / 0.5})
				g2 := geo.Analyse(points, rep.Target.Location, givenPlace)
				g2.Notes, g2.TZ = sum.Notes, tz
				sum = g2
			} else {
				sum.Notes = append(sum.Notes, fmt.Sprintf("Activity hours suggest %s, which does not fit %s; the person may be elsewhere, travelling, or the handles may belong to someone else.", tz.Label, top.Label))
			}
		}
	} else if events > 0 {
		sum.Notes = append(sum.Notes, fmt.Sprintf("%d public events were seen but their hours show no clear quiet period, so no timezone was inferred.", events))
	}
	if len(sum.Points) == 0 && sum.TZ == nil {
		return
	}
	rep.Geo = sum

	d := map[string]string{"evidence points": fmt.Sprint(len(sum.Points))}
	if sum.Consensus != "" {
		d["most likely location"] = sum.Consensus
	}
	if sum.Conflict != "" {
		d["conflict"] = sum.Conflict
	}
	if sum.TZ != nil {
		d["timezone"] = sum.TZ.Label
	}
	if sum.GivenFit != "" && sum.GivenFit != "unknown" {
		d["vs the location you gave"] = sum.GivenFit
	}
	f := models.Finding{Module: "geo", Source: "Location analysis", Category: "location", Status: models.StatusFound, Details: d, Timestamp: time.Now().UTC()}
	if len(sum.Clusters) > 0 {
		f.Confidence = sum.Clusters[0].Score
		f.Entities = []models.Entity{{Type: models.EntLocation, Value: sum.Clusters[0].Label}}
	} else {
		f.Confidence = 0.3
	}
	rep.Findings = append(rep.Findings, f)
	if e.OnFinding != nil {
		e.OnFinding(f)
	}
}

func addUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func shortURL(u string) string {
	if len(u) > 70 {
		return u[:70] + "…"
	}
	return u
}
