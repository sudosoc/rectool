package output

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/media"
	"github.com/sudosoc/rectool/internal/models"
)

// maxEmbedded caps the total size of pictures inlined into the HTML report.
const maxEmbedded = 8 << 20

type htmlFactGroup struct {
	Title string
	Facts []models.Fact
}

type htmlIdentity struct {
	models.Identity
	Pct    int
	Groups []htmlFactGroup
	Photos []template.URL
}

type htmlFinding struct {
	Source, URL, Via string
	Pct              int
	Lines            []string
}

type htmlCategory struct {
	Name     string
	Findings []htmlFinding
}

type htmlData struct {
	R          *models.Report
	Started    string
	Duration   string
	Target     [][2]string
	Summary    []string
	Identities []htmlIdentity
	Gallery    []htmlPhoto
	Categories []htmlCategory
	Failures   []models.Failure
	MoreFail   int
	Settings   [][2]string
}

type htmlPhoto struct {
	Src     template.URL
	Sources string
	Group   int
	Info    string
}

func dataURI(img *media.Image, budget *int) (template.URL, bool) {
	if img == nil || len(img.Data) == 0 || *budget < len(img.Data) {
		return "", false
	}
	ct := strings.ToLower(strings.Split(img.ContentType, ";")[0])
	switch ct {
	case "image/png", "image/jpeg", "image/gif", "image/webp":
	default:
		return "", false
	}
	*budget -= len(img.Data)
	return template.URL("data:" + ct + ";base64," + base64.StdEncoding.EncodeToString(img.Data)), true
}

func writeHTML(w io.Writer, r *models.Report) error {
	budget := maxEmbedded
	d := htmlData{R: r, Started: r.StartedAt.Format(time.RFC1123), Duration: r.FinishedAt.Sub(r.StartedAt).Round(time.Second).String()}
	t := r.Target
	for _, kv := range [][2]string{{"Full name", t.FullName}, {"Username", t.Username}, {"E-mail", t.Email}, {"Phone", t.Phone},
		{"Domain", t.Domain}, {"IP", t.IP}, {"ASN", t.ASN}, {"Company", t.Company}, {"Wallet", t.Wallet}, {"Location", t.Location},
		{"Aliases", strings.Join(t.Aliases, ", ")}} {
		if kv[1] != "" {
			d.Target = append(d.Target, kv)
		}
	}
	if len(r.Identities) > 0 && !r.Identities[0].Weak {
		top := r.Identities[0]
		d.Summary = append(d.Summary, fmt.Sprintf("Best match: %s (match score %d%%)", top.Label, int(top.Score*100+0.5)))
		for _, p := range []struct {
			n string
			c int
		}{{"e-mail address(es)", len(top.Emails)}, {"phone number(s)", len(top.Phones)}, {"account(s)", len(top.Usernames)}, {"employer(s)", len(top.Employers)}, {"website(s)", len(top.Websites)}} {
			if p.c > 0 {
				d.Summary = append(d.Summary, fmt.Sprintf("%d %s", p.c, p.n))
			}
		}
	}
	if r.Ambiguity != "" {
		d.Summary = append(d.Summary, "Ambiguity: "+r.Ambiguity)
	}
	if g := r.Geo; g != nil && g.Consensus != "" {
		d.Summary = append(d.Summary, "Most likely location: "+g.Consensus)
	}
	d.Summary = append(d.Summary, fmt.Sprintf("%d findings from %d collectors; %d checks could not complete", len(r.Hits()), len(r.Modules), len(r.Failures)))
	for _, id := range r.Identities {
		hi := htmlIdentity{Identity: id, Pct: int(id.Score*100 + 0.5)}
		for _, g := range []htmlFactGroup{
			{"Names", id.Names}, {"Headline / roles", id.Headlines}, {"Employers", id.Employers}, {"Location", id.Locations},
			{"Education", id.Education}, {"Interests", id.Interests}, {"E-mail", id.Emails}, {"Phone", id.Phones},
			{"Accounts", id.Usernames}, {"Websites", id.Websites},
		} {
			if len(g.Facts) > 0 {
				hi.Groups = append(hi.Groups, g)
			}
		}
		for _, u := range id.Photos {
			if len(hi.Photos) >= 3 {
				break
			}
			if uri, ok := dataURI(media.Cached(u), &budget); ok {
				hi.Photos = append(hi.Photos, uri)
			}
		}
		d.Identities = append(d.Identities, hi)
	}
	for _, p := range r.Photos {
		if uri, ok := dataURI(media.Cached(p.URL), &budget); ok {
			info := fmt.Sprintf("%dx%d", p.Width, p.Height)
			d.Gallery = append(d.Gallery, htmlPhoto{Src: uri, Sources: strings.Join(p.Sources, ", "), Group: p.Group, Info: info})
		}
	}
	byCat := map[string][]htmlFinding{}
	for _, f := range r.Hits() {
		k := f.Module + " / " + orDefault(f.Category, "other")
		byCat[k] = append(byCat[k], htmlFinding{Source: f.Source, URL: safeURL(f.URL), Via: f.Via, Pct: int(f.Confidence*100 + 0.5), Lines: detailLines(f.Details, 0)})
	}
	keys := make([]string, 0, len(byCat))
	for k := range byCat {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		d.Categories = append(d.Categories, htmlCategory{Name: k, Findings: byCat[k]})
	}
	d.Failures = r.Failures
	if len(d.Failures) > 80 {
		d.MoreFail = len(d.Failures) - 80
		d.Failures = d.Failures[:80]
	}
	skeys := make([]string, 0, len(r.Settings))
	for k := range r.Settings {
		skeys = append(skeys, k)
	}
	sort.Strings(skeys)
	for _, k := range skeys {
		d.Settings = append(d.Settings, [2]string{k, r.Settings[k]})
	}
	return reportTmpl.Execute(w, d)
}

// safeURL keeps only http(s) links; scraped data must never become a script link.
func safeURL(u string) string {
	l := strings.ToLower(strings.TrimSpace(u))
	if strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
		return strings.TrimSpace(u)
	}
	return ""
}

var reportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"safe": safeURL,
	"join": strings.Join,
	"pct":  func(f float64) int { return int(f*100 + 0.5) },
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>rectool report</title>
<style>
:root{--bg:#0e1116;--fg:#d7dde5;--mut:#8b96a5;--card:#161b22;--line:#262e38;--acc:#3fb6a8;--ok:#3fb950;--warn:#d29922}
@media print{:root{--bg:#fff;--fg:#111;--mut:#555;--card:#fff;--line:#ccc;--acc:#0a6;--ok:#070;--warn:#a60}a{color:#000}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 10px;color:var(--acc);border-bottom:1px solid var(--line);padding-bottom:4px}
h3{font-size:14px;margin:14px 0 6px}
.mut{color:var(--mut)}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:10px 0;break-inside:avoid}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:3px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;width:150px}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;border:1px solid var(--line);font-size:12px;margin-left:6px}
.ok{color:var(--ok)}.warn{color:var(--warn)}
.fact{margin:2px 0}.src{color:var(--mut);font-size:12px}
.photos img{width:120px;height:120px;object-fit:cover;border-radius:8px;border:1px solid var(--line);margin:0 8px 8px 0}
.gal{display:inline-block;margin:0 10px 10px 0;text-align:center;font-size:11px;color:var(--mut);max-width:130px}
.gal img{width:120px;height:120px;object-fit:cover;border-radius:8px;border:1px solid var(--line)}
a{color:var(--acc);word-break:break-all}code{font-size:12px;word-break:break-all}
</style></head><body><main>
<h1>rectool reconnaissance report</h1>
<div class="mut">{{.R.Tool}} v{{.R.Version}} · {{.Started}} · duration {{.Duration}}{{if .R.Interrupted}} · <span class="warn">interrupted: results are partial</span>{{end}}</div>

<h2>Target</h2>
<div class="card"><table>{{range .Target}}<tr><th>{{index . 0}}</th><td>{{index . 1}}</td></tr>{{end}}</table></div>

<h2>Summary</h2>
<div class="card">{{range .Summary}}<div>• {{.}}</div>{{end}}</div>

<h2>Identities</h2>
{{if .R.Ambiguity}}<div class="card warn">{{.R.Ambiguity}}</div>{{end}}
{{range .Identities}}{{if not .Weak}}
<div class="card"><h3>{{.Label}} <span class="pill">match {{.Pct}}%</span>{{if .Primary}}<span class="pill ok">best match</span>{{end}}</h3>
{{if .Photos}}<div class="photos">{{range .Photos}}<img src="{{.}}" alt="">{{end}}</div>{{end}}
{{if .Bio}}<p>{{.Bio}}</p>{{end}}
{{if .Matched}}<div class="mut">matches your input: {{join .Matched ", "}}</div>{{end}}
{{if .Conflicts}}<div class="warn">sources disagree on: {{join .Conflicts ", "}}</div>{{end}}
<table>{{range .Groups}}<tr><th>{{.Title}}</th><td>{{range .Facts}}<div class="fact">{{.Value}}{{if .Confirmed}} <span class="ok" title="stated by 2+ platforms">✔ confirmed</span>{{else if .Self}} <span class="src">self-reported</span>{{end}} <span class="src">({{join .Sources ", "}})</span></div>{{end}}</td></tr>{{end}}
{{if .Docs}}<tr><th>Documents / CV</th><td>{{range .Docs}}<div>{{if safe .}}<a href="{{safe .}}">{{.}}</a>{{else}}{{.}}{{end}}</div>{{end}}</td></tr>{{end}}
<tr><th>Sources</th><td>{{range .Records}}<div class="fact">{{if safe .URL}}<a href="{{safe .URL}}">{{.Platform}}</a>{{else}}{{.Platform}}{{end}}{{if .Self}} <span class="src">own profile</span>{{end}}</div>{{end}}</td></tr>
</table></div>
{{end}}{{else}}<div class="mut">No person could be resolved from the data.</div>{{end}}

{{if .R.Geo}}<h2>Location</h2><div class="card">{{if .R.Geo.Consensus}}<b>Most likely: {{.R.Geo.Consensus}}</b>{{end}}
{{if .R.Geo.Conflict}}<div class="warn">{{.R.Geo.Conflict}}</div>{{end}}
{{if .R.Geo.TZ}}<div class="mut">Timezone from activity hours: {{.R.Geo.TZ.Label}} ({{.R.Geo.TZ.Events}} events)</div>{{end}}
<table>{{range .R.Geo.Points}}<tr><th>{{.Kind}}</th><td>{{.Label}} <span class="src">→ {{.City}} {{.Region}} {{.Country}} · {{.Precision}} · trust {{pct .Weight}}%</span></td></tr>{{end}}</table></div>{{end}}

{{if .Gallery}}<h2>Pictures</h2><div>{{range .Gallery}}<div class="gal"><img src="{{.Src}}" alt=""><br>{{.Sources}}{{if .Group}}<br>same picture group {{.Group}}{{end}}</div>{{end}}</div>{{end}}

<h2>Findings</h2>
{{range .Categories}}<h3>{{.Name}}</h3>
{{range .Findings}}<div class="card"><b>{{.Source}}</b> <span class="pill">{{.Pct}}%</span>{{if .Via}} <span class="src">via {{.Via}}</span>{{end}}
{{if .URL}}<div><a href="{{.URL}}">{{.URL}}</a></div>{{end}}
{{range .Lines}}<div class="src">{{.}}</div>{{end}}</div>{{end}}
{{end}}

{{if .R.ManualLeads}}<h2>Manual leads</h2><div class="card"><div class="mut">Sources that need a login, CAPTCHA or payment. rectool does not bypass those; open them yourself.</div>
{{range .R.ManualLeads}}<div class="fact"><b>{{.Group}}</b> · {{if safe .URL}}<a href="{{safe .URL}}">{{.Label}}</a>{{else}}{{.Label}}{{end}} <span class="src">{{.Why}}</span></div>{{end}}</div>{{end}}

{{if .Failures}}<h2>Coverage gaps</h2><div class="card"><div class="mut">Checks that could not complete. A missing result is not evidence of absence.</div>
{{range .Failures}}<div class="src">{{.Module}} / {{.Source}}: {{.Error}}</div>{{end}}{{if .MoreFail}}<div class="src">… and {{.MoreFail}} more (see the JSON report)</div>{{end}}</div>{{end}}

{{if .Settings}}<h2>Run settings</h2><div class="card"><table>{{range .Settings}}<tr><th>{{index . 0}}</th><td>{{index . 1}}</td></tr>{{end}}</table></div>{{end}}
{{if .R.Integrity}}<h2>Integrity</h2><div class="card"><code>{{.R.Integrity.Algorithm}} {{.R.Integrity.Digest}}</code><div class="mut">Digest of target + entities + findings in the JSON report; recompute it to verify nothing was edited.</div></div>{{end}}
<p class="mut">Generated from public sources. Treat entries as leads to verify, not conclusions about a person. Print this page to save a PDF.</p>
</main></body></html>`))
