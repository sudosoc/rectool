package engine

import (
	"context"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/media"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

// fake is a scripted module.
type fake struct {
	name string
	can  func(models.Target) bool
	run  func(t models.Target, emit func(models.Finding))

	mu   sync.Mutex
	seen []models.Target
}

func (f *fake) Name() string                { return f.name }
func (f *fake) Description() string         { return "fake " + f.name }
func (f *fake) CanRun(t models.Target) bool { return f.can(t) }
func (f *fake) Scan(_ context.Context, t models.Target, _ scanner.Deps, emit func(models.Finding)) error {
	f.mu.Lock()
	f.seen = append(f.seen, t)
	f.mu.Unlock()
	if f.run != nil {
		f.run(t, emit)
	}
	return nil
}

func newEngine(t *testing.T, cfg Config) (*Engine, *fake, *fake) {
	t.Helper()
	c, err := httpx.New(httpx.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e := New(cfg, c)
	social := &fake{name: "social", can: func(t models.Target) bool { return t.Username != "" },
		run: func(_ models.Target, emit func(models.Finding)) {
			emit(models.Finding{Source: "profile", Status: models.StatusFound, Confidence: 0.9, Entities: []models.Entity{
				{Type: models.EntEmail, Value: "found@corp.example", Strong: true},
				{Type: models.EntDomain, Value: "weak.example", Strong: false},
				{Type: models.EntEmail, Value: "Found@Corp.example", Strong: true}, // duplicate, different case
			}})
		}}
	foot := &fake{name: "footprint", can: func(t models.Target) bool { return t.Email != "" }}
	e.Register(social)
	e.Register(foot)
	return e, social, foot
}

func TestPivotFollowsOnlyStrongEntities(t *testing.T) {
	e, _, foot := newEngine(t, Config{Pivot: true})
	rep, err := e.Run(context.Background(), models.Target{Username: "someone"})
	if err != nil {
		t.Fatal(err)
	}
	if len(foot.seen) != 1 || foot.seen[0].Email != "found@corp.example" {
		t.Fatalf("footprint should run exactly once on the strong, de-duplicated email; ran on %+v", foot.seen)
	}
	var via string
	for _, m := range rep.Modules {
		if m.Name == "footprint" {
			via = m.Via
		}
	}
	if via != "email:found@corp.example" {
		t.Errorf("pivot run must record where it came from, got %q", via)
	}
	if len(rep.Entities) != 2 { // the e-mail (merged duplicates) and the weak domain
		t.Errorf("entities = %+v", rep.Entities)
	}
}

func TestPivotDisabledAndRestricted(t *testing.T) {
	e, _, foot := newEngine(t, Config{Pivot: false})
	if _, err := e.Run(context.Background(), models.Target{Username: "someone"}); err != nil {
		t.Fatal(err)
	}
	if len(foot.seen) != 0 {
		t.Fatal("pivot disabled but footprint ran")
	}

	e, _, foot = newEngine(t, Config{Pivot: true, Modules: []string{"social"}})
	if _, err := e.Run(context.Background(), models.Target{Username: "someone"}); err != nil {
		t.Fatal(err)
	}
	if len(foot.seen) != 0 {
		t.Fatal("-modules social must also restrict pivot runs")
	}
}

func TestPivotDoesNotRepeatSuppliedIdentifiers(t *testing.T) {
	e, _, foot := newEngine(t, Config{Pivot: true})
	if _, err := e.Run(context.Background(), models.Target{Username: "someone", Email: "found@corp.example"}); err != nil {
		t.Fatal(err)
	}
	if len(foot.seen) != 1 { // only the primary run; the entity equals the supplied e-mail
		t.Fatalf("footprint ran %d times", len(foot.seen))
	}
}

func TestEnrichNormalisesAndValidates(t *testing.T) {
	tg := models.Target{Domain: "HTTPS://WWW.Example.com/path?x=1", IP: " [2001:db8::1] ", Email: "Jane.Doe+tag@Corp.Example.org", Company: "  Acme   Inc "}
	if err := Enrich(&tg, false, 5); err != nil {
		t.Fatal(err)
	}
	if tg.Domain != "www.example.com" || tg.IP != "2001:db8::1" || tg.Company != "Acme Inc" || tg.Email != "jane.doe+tag@corp.example.org" {
		t.Fatalf("%+v", tg)
	}
	if len(tg.Aliases) != 1 || tg.Aliases[0] != "jane.doe" {
		t.Errorf("aliases %v", tg.Aliases)
	}
	for _, bad := range []models.Target{{Domain: "not a domain"}, {IP: "999.1.1.1"}, {Email: "nope"}} {
		if err := Enrich(&bad, false, 5); err == nil {
			t.Errorf("expected error for %+v", bad)
		}
	}
	// A custom-domain e-mail contributes its domain; a free-mail one does not.
	a := models.Target{Email: "x@corp.example.org"}
	_ = Enrich(&a, false, 5)
	b := models.Target{Email: "x@gmail.com"}
	_ = Enrich(&b, false, 5)
	if a.Domain != "corp.example.org" || b.Domain != "" {
		t.Errorf("derived domains: %q %q", a.Domain, b.Domain)
	}
}

func TestEnrichNewInputs(t *testing.T) {
	// A pasted profile link becomes a username, not a domain to investigate.
	a := models.Target{Domain: "https://twitter.com/SomeUser"}
	if err := Enrich(&a, false, 5); err != nil || a.Username != "SomeUser" || a.Domain != "" {
		t.Fatalf("profile URL: %+v err=%v", a, err)
	}
	b := models.Target{Username: "main", Domain: "https://github.com/other-handle/"}
	_ = Enrich(&b, false, 5)
	if b.Username != "main" || len(b.Aliases) != 1 || b.Aliases[0] != "other-handle" || b.Domain != "" {
		t.Fatalf("second profile should become an alias: %+v", b)
	}
	c := models.Target{Alias: "Dark Knight", ASN: "13335", Wallet: "0x00000000219ab540356cBB839Cbe05303d7705Fa"}
	if err := Enrich(&c, false, 8); err != nil {
		t.Fatal(err)
	}
	if c.ASN != "AS13335" {
		t.Errorf("asn %q", c.ASN)
	}
	want := map[string]bool{"darkknight": true, "dark.knight": true, "dark_knight": true, "dark-knight": true}
	for _, al := range c.Aliases {
		delete(want, al)
	}
	if len(want) != 0 {
		t.Errorf("alias variants missing %v (have %v)", want, c.Aliases)
	}
	for _, bad := range []models.Target{{ASN: "AS12x"}, {Wallet: "not-a-wallet"}} {
		if err := Enrich(&bad, false, 5); err == nil {
			t.Errorf("expected error for %+v", bad)
		}
	}
	if (models.Target{Location: "Cairo"}).IsEmpty() == false {
		t.Error("location alone must not count as input")
	}
}

// portrait draws a synthetic "photo" (gradient + dark oval) at any size.
func portrait(w, h int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			v := uint8(40 + (y*180)/h)
			dx, dy := float64(x-w/2)/float64(w/3), float64(y-h/2)/float64(h/3)
			if dx*dx+dy*dy < 1 {
				v = 30
			}
			img.Set(x, y, color.RGBA{v, v, v, 255})
		}
	}
	return img
}

func TestPhotoStageGroupsSamePictureAcrossSources(t *testing.T) {
	media.AllowPrivateHostsForTests(true)
	defer media.AllowPrivateHostsForTests(false)

	mux := http.NewServeMux()
	serve := func(path string, img image.Image, jpg bool) {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			if jpg {
				w.Header().Set("Content-Type", "image/jpeg")
				_ = jpeg.Encode(w, img, &jpeg.Options{Quality: 75})
				return
			}
			w.Header().Set("Content-Type", "image/png")
			_ = png.Encode(w, img)
		})
	}
	other := image.NewRGBA(image.Rect(0, 0, 200, 200))
	for y := 0; y < 200; y++ {
		for x := 0; x < 200; x++ {
			other.Set(x, y, color.RGBA{uint8(x), uint8(255 - x), uint8(y), 255})
		}
	}
	serve("/github.png", portrait(460, 460), false)
	serve("/gitlab.jpg", portrait(120, 120), true) // same picture, smaller, re-encoded
	serve("/steam.png", other, false)              // a different picture
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, _ := httpx.New(httpx.Options{})
	e := New(Config{Workers: 4}, c)
	var got []models.Finding
	var mu sync.Mutex
	e.OnFinding = func(f models.Finding) { mu.Lock(); got = append(got, f); mu.Unlock() }
	e.Register(&fake{name: "profiles", can: func(t models.Target) bool { return t.Username != "" },
		run: func(_ models.Target, emit func(models.Finding)) {
			// Different host names so the two copies count as independent sites.
			local := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
			emit(models.Finding{Source: "GitHub profile", Status: models.StatusFound, Confidence: 0.9, Details: map[string]string{"avatar": srv.URL + "/github.png"}})
			emit(models.Finding{Source: "GitLab profile", Status: models.StatusFound, Confidence: 0.9, Details: map[string]string{"avatar": local + "/gitlab.jpg"}})
			emit(models.Finding{Source: "Steam profile", Status: models.StatusFound, Confidence: 0.9, Details: map[string]string{"avatar": srv.URL + "/steam.png"}})
		}})

	rep, err := e.Run(context.Background(), models.Target{Username: "someone"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Photos) != 3 {
		t.Fatalf("photos = %+v", rep.Photos)
	}
	grouped := 0
	for _, p := range rep.Photos {
		if p.Group > 0 {
			grouped++
			if strings.Contains(p.URL, "steam") {
				t.Errorf("the different picture must not be grouped: %+v", p)
			}
		}
		if p.SHA256 == "" || p.Width == 0 {
			t.Errorf("photo not analysed: %+v", p)
		}
	}
	if grouped != 2 {
		t.Fatalf("expected the two copies grouped, got %d: %+v", grouped, rep.Photos)
	}
	var group *models.Finding
	for i := range rep.Findings {
		if rep.Findings[i].Module == "photos" {
			group = &rep.Findings[i]
		}
	}
	if group == nil || !strings.Contains(group.Source, "2 sources") || group.Confidence < 0.8 {
		t.Fatalf("missing 'same picture' finding: %+v", group)
	}
	if len(got) == 0 {
		t.Error("the group finding must also be streamed to OnFinding")
	}
}

func TestAddImageEntitiesFiltersLogos(t *testing.T) {
	f := models.Finding{Module: "social", Details: map[string]string{"avatar": "https://site.test/assets/logo-wide.png"}}
	addImageEntities(&f)
	if len(f.Entities) != 0 {
		t.Fatalf("site logo accepted: %+v", f.Entities)
	}
	f = models.Finding{Module: "social", Details: map[string]string{"avatar": "https://cdn.test/avatars/u/123.jpg"}}
	addImageEntities(&f)
	if len(f.Entities) != 1 || f.Entities[0].Type != models.EntImage {
		t.Fatalf("avatar-like URL rejected: %+v", f.Entities)
	}
	f = models.Finding{Module: "profiles", Details: map[string]string{"avatar": "https://x.test/p/9.png"}}
	addImageEntities(&f)
	if len(f.Entities) != 1 {
		t.Fatalf("profile enrichers are trusted: %+v", f.Entities)
	}
}

func TestSiteKeyAndPlaceholderFilter(t *testing.T) {
	for in, want := range map[string]string{
		"https://avatars.akamai.steamstatic.com/x.jpg": "steamstatic.com",
		"https://avatars.fastly.steamstatic.com/x.jpg": "steamstatic.com",
		"https://www.gravatar.com/avatar/abc":          "gravatar.com",
		"https://cdn.example.co.uk/a.png":              "example.co.uk",
		"http://127.0.0.1:8080/a.png":                  "127.0.0.1",
		"https://localhost/a.png":                      "localhost",
	} {
		if got := siteKey(in); got != want {
			t.Errorf("siteKey(%s) = %s, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"https://mastodon.social/avatars/original/missing.png", "https://userpic.codeforces.org/no-title.jpg",
		"https://abs.twimg.com/sticky/default_profile_images/default_profile_400x400.png", "https://wykop.pl/static/img/open-graph/profile.png"} {
		f := models.Finding{Module: "profiles", Details: map[string]string{"avatar": bad}}
		addImageEntities(&f)
		if len(f.Entities) != 0 {
			t.Errorf("placeholder accepted: %s", bad)
		}
	}
}
