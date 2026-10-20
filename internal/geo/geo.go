// Package geo turns scattered location clues into one assessed answer: it
// geocodes free-text places, groups evidence that points to the same place,
// scores each group, and estimates a timezone from activity hours.
//
// Only coarse, publicly self-declared or technical signals are used (a profile's
// "location" field, IP geolocation, phone number region, EXIF GPS in a public
// picture, activity hours). Nothing here looks for a street address.
package geo

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
)

// Place is a geocoded location.
type Place struct {
	Lat, Lon    float64
	Display     string
	City        string
	Region      string
	Country     string
	CountryCode string
	Precision   string // city | region | country
}

// Geocoder resolves text to coordinates with OpenStreetMap Nominatim (public,
// keyless; limited to one request per second, so lookups are serialised and
// cached for the run).
type Geocoder struct {
	c     *httpx.Client
	mu    sync.Mutex
	last  time.Time
	cache map[string]*Place
}

func NewGeocoder(c *httpx.Client) *Geocoder { return &Geocoder{c: c, cache: map[string]*Place{}} }

var (
	junkPlace = regexp.MustCompile(`(?i)^(remote|worldwide|earth|the internet|internet|everywhere|anywhere|global|planet earth|home|n/?a|none|unknown|\?+|-+|mars|moon|localhost|the cloud|cloud|online|earth\W*)$`)
	latLon    = regexp.MustCompile(`^\s*(-?\d{1,2}\.\d+)\s*[,; ]\s*(-?\d{1,3}\.\d+)\s*$`)
	emojiRE   = regexp.MustCompile(`[\x{1F000}-\x{1FFFF}\x{2600}-\x{27BF}\x{FE0F}]`)
)

// Clean strips emoji and decoration from a place string; "" means unusable.
func Clean(s string) string {
	s = emojiRE.ReplaceAllString(s, "")
	s = strings.Join(strings.Fields(strings.Trim(s, " \t|•·–—-~*")), " ")
	if len(s) < 2 || len(s) > 120 || junkPlace.MatchString(s) {
		return ""
	}
	if i := strings.IndexAny(s, "|•"); i > 0 { // "Cairo | Dubai": keep the first
		s = strings.TrimSpace(s[:i])
	}
	return s
}

// Geocode resolves q. ok is false when nothing plausible was found.
func (g *Geocoder) Geocode(ctx context.Context, q string) (*Place, bool) {
	q = Clean(q)
	if q == "" {
		return nil, false
	}
	key := strings.ToLower(q)
	g.mu.Lock()
	if p, ok := g.cache[key]; ok {
		g.mu.Unlock()
		return p, p != nil
	}
	// serialise: Nominatim allows 1 request/second
	if d := time.Until(g.last.Add(1100 * time.Millisecond)); d > 0 {
		select {
		case <-ctx.Done():
			g.mu.Unlock()
			return nil, false
		case <-time.After(d):
		}
	}
	g.last = time.Now()
	g.mu.Unlock()

	var u string
	if m := latLon.FindStringSubmatch(q); m != nil {
		u = "https://nominatim.openstreetmap.org/reverse?format=jsonv2&addressdetails=1&accept-language=en&zoom=10&lat=" + m[1] + "&lon=" + m[2]
	} else {
		u = "https://nominatim.openstreetmap.org/search?format=jsonv2&addressdetails=1&limit=1&accept-language=en&q=" + url.QueryEscape(q)
	}
	resp, err := g.c.Do(ctx, httpx.Request{URL: u, Timeout: 20 * time.Second,
		Headers: map[string]string{"User-Agent": "rectool/1.0 (+https://github.com/sudosoc/rectool)", "Accept": "application/json"}})
	var p *Place
	if err == nil && resp.StatusCode == 200 {
		p = parseNominatim(resp.Body)
	}
	if err == nil && resp.StatusCode != 429 {
		g.mu.Lock()
		g.cache[key] = p
		g.mu.Unlock()
	}
	return p, p != nil
}

func parseNominatim(body []byte) *Place {
	type rec struct {
		Lat         string            `json:"lat"`
		Lon         string            `json:"lon"`
		Display     string            `json:"display_name"`
		AddressType string            `json:"addresstype"`
		Importance  float64           `json:"importance"`
		Address     map[string]string `json:"address"`
	}
	var one rec
	var many []rec
	if json.Unmarshal(body, &many) != nil || len(many) == 0 {
		if json.Unmarshal(body, &one) != nil || one.Lat == "" {
			return nil
		}
		many = []rec{one}
	}
	r := many[0]
	lat, e1 := strconv.ParseFloat(r.Lat, 64)
	lon, e2 := strconv.ParseFloat(r.Lon, 64)
	if e1 != nil || e2 != nil {
		return nil
	}
	a := r.Address
	p := &Place{Lat: lat, Lon: lon, Display: r.Display, Country: a["country"], CountryCode: strings.ToUpper(a["country_code"]), Region: firstOf(a, "state", "region", "province", "county")}
	p.City = firstOf(a, "city", "town", "village", "municipality", "hamlet", "suburb")
	switch r.AddressType {
	case "country":
		p.Precision = "country"
	case "state", "region", "province", "county", "state_district", "territory":
		p.Precision = "region"
	default:
		p.Precision = "city"
	}
	return p
}

func firstOf(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if m[k] != "" {
			return m[k]
		}
	}
	return ""
}

// Haversine returns the great-circle distance in kilometres.
func Haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371.0
	rad := math.Pi / 180
	dLat, dLon := (lat2-lat1)*rad, (lon2-lon1)*rad
	a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * r * math.Asin(math.Sqrt(a))
}

// Weight of each kind of evidence: how much it says about where the person
// is, on its own.
var kindWeight = map[string]float64{
	"self-declared": 0.7,  // the person's own profile says so
	"exif":          0.8,  // GPS inside a picture they published
	"organisation":  0.4,  // employer / company registry address
	"ip":            0.3,  // IP geolocation (often the ISP's city)
	"phone":         0.3,  // number allocation region
	"activity":      0.35, // timezone from activity hours
}

// Weight returns the base trust for an evidence kind.
func Weight(kind string) float64 {
	if w, ok := kindWeight[kind]; ok {
		return w
	}
	return 0.2
}

// Analyse clusters points and fills the summary's clusters, consensus and
// conflict. given is the location the operator supplied (may be empty).
func Analyse(points []models.GeoPoint, given string, givenPlace *Place) *models.GeoSummary {
	s := &models.GeoSummary{Points: points, Given: given}
	type cl struct {
		models.GeoCluster
		w []float64
	}
	var cls []*cl
	attach := func(i int, p models.GeoPoint) {
		for _, c := range cls {
			ok := false
			switch p.Precision {
			case "country":
				ok = c.CountryCode != "" && c.CountryCode == p.CountryCode
			case "region":
				ok = c.CountryCode == p.CountryCode && Haversine(c.Lat, c.Lon, p.Lat, p.Lon) < 400
			default:
				ok = Haversine(c.Lat, c.Lon, p.Lat, p.Lon) < 120
			}
			if ok {
				c.Points = append(c.Points, i)
				c.w = append(c.w, p.Weight)
				c.Kinds = addUniq(c.Kinds, p.Kind)
				return
			}
		}
		lbl := p.City
		if lbl == "" {
			lbl = firstNonEmpty(p.Region, p.Country, p.Label)
		}
		if p.City != "" && p.Country != "" {
			lbl += ", " + p.Country
		} else if p.City == "" && p.Region != "" && p.Country != "" {
			lbl = p.Region + ", " + p.Country
		}
		cls = append(cls, &cl{GeoCluster: models.GeoCluster{Label: lbl, Lat: p.Lat, Lon: p.Lon, Country: p.Country, CountryCode: p.CountryCode,
			Points: []int{i}, Kinds: []string{p.Kind}}, w: []float64{p.Weight}})
	}
	// precise points first so coarse ones attach to them
	order := make([]int, len(points))
	for i := range order {
		order[i] = i
	}
	rank := map[string]int{"exact": 0, "city": 1, "region": 2, "country": 3}
	sort.SliceStable(order, func(a, b int) bool { return rank[points[order[a]].Precision] < rank[points[order[b]].Precision] })
	for _, i := range order {
		attach(i, points[i])
	}
	for _, c := range cls {
		miss := 1.0
		for _, w := range c.w {
			miss *= 1 - w
		}
		c.Score = math.Round((1-miss)*100) / 100
		s.Clusters = append(s.Clusters, c.GeoCluster)
	}
	sort.SliceStable(s.Clusters, func(i, j int) bool { return s.Clusters[i].Score > s.Clusters[j].Score })
	if len(s.Clusters) == 0 {
		s.GivenFit = "unknown"
		return s
	}
	top := s.Clusters[0]
	s.Consensus = fmt.Sprintf("%s (%.0f%%)", top.Label, top.Score*100)
	if len(s.Clusters) > 1 {
		sec := s.Clusters[1]
		if sec.Score >= 0.5*top.Score && sec.CountryCode != top.CountryCode {
			s.Conflict = fmt.Sprintf("Evidence disagrees: %s (%.0f%%) vs %s (%.0f%%). The person may have moved, travel, or these may be different people.", top.Label, top.Score*100, sec.Label, sec.Score*100)
		}
	}
	s.GivenFit = "unknown"
	if givenPlace != nil {
		s.GivenFit = "differs"
		for _, c := range s.Clusters {
			if (givenPlace.Precision == "country" && givenPlace.CountryCode == c.CountryCode) ||
				Haversine(givenPlace.Lat, givenPlace.Lon, c.Lat, c.Lon) < 150 {
				s.GivenFit = "agrees"
				break
			}
		}
	}
	return s
}

func addUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func firstNonEmpty(v ...string) string {
	for _, x := range v {
		if x != "" {
			return x
		}
	}
	return ""
}

// ------------------------------------------------------------- timezone

// InferOffset estimates the UTC offset from a 24-bucket UTC activity
// histogram. People are least active while asleep, so the quietest 7-hour
// window is assumed to be centred on about 03:30 local time. Returns ok=false
// when there are too few events or no clear quiet window.
func InferOffset(hours [24]int) (offset float64, confidence float64, ok bool) {
	total := 0
	for _, h := range hours {
		total += h
	}
	if total < 40 {
		return 0, 0, false
	}
	const win = 7
	sums := make([]int, 24)
	best := math.MaxInt
	for s := 0; s < 24; s++ {
		for k := 0; k < win; k++ {
			sums[s] += hours[(s+k)%24]
		}
		if sums[s] < best {
			best = sums[s]
		}
	}
	// when several windows tie (a long silent stretch), centre on all of them
	var sx, sy float64
	for s := 0; s < 24; s++ {
		if sums[s] == best {
			ang := 2 * math.Pi * float64(s) / 24
			sx += math.Cos(ang)
			sy += math.Sin(ang)
		}
	}
	bestStart := math.Atan2(sy, sx) * 24 / (2 * math.Pi)
	if bestStart < 0 {
		bestStart += 24
	}
	mean := float64(total) * win / 24
	if mean == 0 {
		return 0, 0, false
	}
	contrast := 1 - float64(best)/mean // 1 = totally silent window, 0 = flat
	if contrast < 0.45 {
		return 0, contrast / 2, false
	}
	centre := bestStart + float64(win)/2 // UTC hour (centre of the quiet window)
	off := 3.5 - centre
	for off < -12 {
		off += 24
	}
	for off > 14 {
		off -= 24
	}
	off = math.Round(off) // whole hours; half-hour zones cannot be told apart this way
	conf := math.Min(0.8, contrast*0.7*math.Min(1, float64(total)/200))
	return off, conf, true
}

// OffsetLabel formats +2 as "UTC+02:00".
func OffsetLabel(off float64) string {
	sign := "+"
	if off < 0 {
		sign, off = "-", -off
	}
	return fmt.Sprintf("UTC%s%02d:00", sign, int(off))
}

var offsetRegions = map[int][]string{
	-8: {"US/Canada Pacific (Los Angeles, Vancouver)"}, -7: {"US Mountain (Denver, Phoenix)"}, -6: {"US Central (Chicago), Mexico City"},
	-5: {"US Eastern (New York, Toronto), Colombia, Peru"}, -4: {"Atlantic Canada, Venezuela, Chile"}, -3: {"Brazil (Sao Paulo), Argentina"},
	0: {"UK, Ireland, Portugal, Ghana"}, 1: {"Central Europe (Paris, Berlin, Rome), Nigeria, Algeria"},
	2: {"Egypt, Greece, Finland, Ukraine, Israel, South Africa"}, 3: {"Saudi Arabia, Iraq, Turkey, Moscow, Kenya"},
	4: {"UAE, Oman, Azerbaijan"}, 5: {"Pakistan, Uzbekistan"}, 6: {"Bangladesh, Kazakhstan"}, 7: {"Thailand, Vietnam, Indonesia (Jakarta)"},
	8: {"China, Singapore, Malaysia, Philippines, Perth"}, 9: {"Japan, South Korea"}, 10: {"Australia East (Sydney, Melbourne)"}, 12: {"New Zealand"},
}

// OffsetRegions lists places that observe the given whole-hour offset.
func OffsetRegions(off float64) []string { return offsetRegions[int(off)] }
