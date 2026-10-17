package media

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sudosoc/rectool/internal/httpx"
)

// portrait draws a simple synthetic "photo": a vertical gradient with a darker
// oval, at any size, so scaled copies are comparable.
func portrait(w, h int, shift uint8) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			v := uint8(40 + (y*180)/h)
			dx, dy := float64(x-w/2)/float64(w/3), float64(y-h/2)/float64(h/3)
			if dx*dx+dy*dy < 1 {
				v = 30
			}
			img.Set(x, y, color.RGBA{v + shift, v, v, 255})
		}
	}
	return img
}

func encode(t *testing.T, img image.Image, jpg bool) []byte {
	t.Helper()
	var b bytes.Buffer
	var err error
	if jpg {
		err = jpeg.Encode(&b, img, &jpeg.Options{Quality: 70})
	} else {
		err = png.Encode(&b, img)
	}
	if err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestPerceptualHashSurvivesResizeAndReencode(t *testing.T) {
	a, err := analyse("a", encode(t, portrait(400, 400, 0), false), "image/png")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := analyse("b", encode(t, portrait(128, 128, 0), true), "image/jpeg") // smaller, JPEG
	c, _ := analyse("c", encode(t, portrait(400, 400, 0), true), "image/jpeg")
	other := image.NewRGBA(image.Rect(0, 0, 200, 200))
	for y := 0; y < 200; y++ {
		for x := 0; x < 200; x++ {
			other.Set(x, y, color.RGBA{uint8(x), uint8(255 - x), uint8(y), 255}) // horizontal gradient
		}
	}
	d, _ := analyse("d", encode(t, other, false), "image/png")

	if !a.Hashed || a.Width != 400 {
		t.Fatalf("decode failed: %+v", a)
	}
	if !Similar(a, b) || !Similar(a, c) {
		t.Errorf("same picture should match: ab=%d ac=%d", Hamming(a.DHash, b.DHash), Hamming(a.DHash, c.DHash))
	}
	if Similar(a, d) {
		t.Errorf("different pictures must not match (distance %d)", Hamming(a.DHash, d.DHash))
	}
	if len(a.DHashHex()) != 16 {
		t.Errorf("hash hex %q", a.DHashHex())
	}
}

func TestRejectsNonImagesAndUnsafeHosts(t *testing.T) {
	if _, err := analyse("x", []byte("<html>not an image</html>"), "text/html"); err == nil {
		t.Error("html must be rejected")
	}
	for _, u := range []string{"http://127.0.0.1/a.png", "http://localhost/a.png", "http://10.0.0.1/a.png",
		"http://169.254.169.254/latest", "ftp://example.com/a.png", "http://user:pw@example.com/a.png", "http://[::1]/a.png"} {
		if err := CheckURL(context.Background(), u); err == nil {
			t.Errorf("%s should be refused", u)
		}
	}
}

func TestFetchFollowsOnlySafeRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/secret.png", http.StatusFound)
	}))
	defer srv.Close()
	c, _ := httpx.New(httpx.Options{})
	// httptest listens on loopback, so even the first hop must be refused.
	if _, err := Fetch(context.Background(), c, srv.URL+"/x.png"); err == nil {
		t.Fatal("loopback server must be refused")
	}
}
