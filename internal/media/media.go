// Package media downloads profile pictures safely and fingerprints them.
//
// Fetching is SSRF-guarded (public hosts only, every redirect hop re-checked),
// size-capped and cached. Each image gets a SHA-256 and a perceptual "dHash",
// so the same photo re-used on different platforms is recognised even when it
// was re-encoded or resized.
package media

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/color"
	_ "image/gif"  // register decoders
	_ "image/jpeg" //
	_ "image/png"  //
	"math/bits"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"

	_ "golang.org/x/image/webp" // register the WebP decoder

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/intel"
)

// MaxBytes caps a downloaded image.
const MaxBytes = 4 << 20

// Image is a downloaded picture plus its fingerprints.
type Image struct {
	URL         string
	ContentType string
	Bytes       int
	Width       int
	Height      int
	SHA256      string
	DHash       uint64 // 0 when the format could not be decoded (SVG, ICO…)
	Hashed      bool
	Data        []byte
}

// DHashHex renders the perceptual hash.
func (i *Image) DHashHex() string {
	if !i.Hashed {
		return ""
	}
	const hexd = "0123456789abcdef"
	var b [16]byte
	for k := 0; k < 16; k++ {
		b[15-k] = hexd[(i.DHash>>(4*uint(k)))&0xf]
	}
	return string(b[:])
}

// Hamming is the number of differing bits between two perceptual hashes.
func Hamming(a, b uint64) int { return bits.OnesCount64(a ^ b) }

// Similar reports whether two images are almost certainly the same picture.
func Similar(a, b *Image) bool {
	if a.SHA256 == b.SHA256 {
		return true
	}
	return a.Hashed && b.Hashed && Hamming(a.DHash, b.DHash) <= 8
}

// ---------------------------------------------------------------- safety

var errUnsafe = errors.New("refusing to fetch: not a public http(s) address")

var allowPrivate bool

// AllowPrivateHostsForTests lets tests fetch from a loopback httptest server.
// Never call it outside tests.
func AllowPrivateHostsForTests(v bool) { allowPrivate = v }

// CheckURL rejects anything that is not an http(s) URL to a public host. Names
// are resolved and every address must be public (basic SSRF/DNS-rebinding guard).
func CheckURL(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return errUnsafe
	}
	if allowPrivate {
		return nil
	}
	h := strings.ToLower(u.Hostname())
	if h == "localhost" || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".localhost") {
		return errUnsafe
	}
	if a, err := netip.ParseAddr(h); err == nil {
		if !intel.PublicIP(a) {
			return errUnsafe
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, h)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("cannot resolve %s", h)
	}
	for _, ip := range ips {
		a, ok := netip.AddrFromSlice(ip.IP)
		if !ok || !intel.PublicIP(a.Unmap()) {
			return errUnsafe
		}
	}
	return nil
}

// ------------------------------------------------------------------ cache

type cache struct {
	mu    sync.Mutex
	items map[string]*Image
	order []string
	size  int
	max   int
}

var shared = &cache{items: map[string]*Image{}, max: 96 << 20}

func (c *cache) get(u string) *Image {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.items[u]
}

func (c *cache) put(img *Image) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items[img.URL]; ok {
		return
	}
	c.items[img.URL] = img
	c.order = append(c.order, img.URL)
	c.size += len(img.Data)
	for c.size > c.max && len(c.order) > 0 {
		old := c.order[0]
		c.order = c.order[1:]
		if it, ok := c.items[old]; ok {
			c.size -= len(it.Data)
			delete(c.items, old)
		}
	}
}

// ------------------------------------------------------------------ fetch

// Fetch downloads rawURL (following at most three redirects, re-validating each
// hop), verifies it is an image, and fingerprints it. Results are cached.
func Fetch(ctx context.Context, c *httpx.Client, rawURL string) (*Image, error) {
	if img := shared.get(rawURL); img != nil {
		return img, nil
	}
	cur := rawURL
	for hop := 0; hop < 4; hop++ {
		if err := CheckURL(ctx, cur); err != nil {
			return nil, err
		}
		resp, err := c.Do(ctx, httpx.Request{
			URL: cur, NoRedirect: true,
			Headers: map[string]string{"Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8", "Sec-Fetch-Dest": "image"},
		})
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			if loc == "" {
				return nil, errors.New("redirect without Location")
			}
			next, err := url.Parse(cur)
			if err != nil {
				return nil, err
			}
			ref, err := next.Parse(loc)
			if err != nil {
				return nil, err
			}
			cur = ref.String()
			continue
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		img, err := analyse(rawURL, resp.Body, resp.Header.Get("Content-Type"))
		if err != nil {
			return nil, err
		}
		shared.put(img)
		return img, nil
	}
	return nil, errors.New("too many redirects")
}

func analyse(rawURL string, data []byte, declared string) (*Image, error) {
	if len(data) == 0 {
		return nil, errors.New("empty response")
	}
	if len(data) >= MaxBytes {
		return nil, errors.New("image too large")
	}
	ct := http.DetectContentType(data)
	if !strings.HasPrefix(ct, "image/") {
		// SVG is text; accept it only when the server says so and it looks like SVG.
		if strings.Contains(strings.ToLower(declared), "svg") && bytes.Contains(data[:min(len(data), 512)], []byte("<svg")) {
			ct = "image/svg+xml"
		} else {
			return nil, fmt.Errorf("not an image (%s)", ct)
		}
	}
	sum := sha256.Sum256(data)
	img := &Image{URL: rawURL, ContentType: ct, Bytes: len(data), SHA256: hex.EncodeToString(sum[:]), Data: data}
	if m, _, err := image.Decode(bytes.NewReader(data)); err == nil {
		b := m.Bounds()
		img.Width, img.Height = b.Dx(), b.Dy()
		if img.Width >= 2 && img.Height >= 2 {
			img.DHash, img.Hashed = dhash(m), true
		}
	}
	return img, nil
}

// dhash is the classic difference hash: shrink to 9x8 luminance cells and
// compare each cell with its right neighbour. Robust to scaling, re-encoding
// and mild colour changes.
func dhash(m image.Image) uint64 {
	b := m.Bounds()
	w, h := b.Dx(), b.Dy()
	var grid [8][9]float64
	for gy := 0; gy < 8; gy++ {
		for gx := 0; gx < 9; gx++ {
			x0, x1 := b.Min.X+gx*w/9, b.Min.X+(gx+1)*w/9
			y0, y1 := b.Min.Y+gy*h/8, b.Min.Y+(gy+1)*h/8
			if x1 <= x0 {
				x1 = x0 + 1
			}
			if y1 <= y0 {
				y1 = y0 + 1
			}
			stepX, stepY := max(1, (x1-x0)/6), max(1, (y1-y0)/6)
			var sum float64
			n := 0
			for y := y0; y < y1; y += stepY {
				for x := x0; x < x1; x += stepX {
					sum += luma(m.At(x, y))
					n++
				}
			}
			grid[gy][gx] = sum / float64(n)
		}
	}
	var hash uint64
	for gy := 0; gy < 8; gy++ {
		for gx := 0; gx < 8; gx++ {
			hash <<= 1
			if grid[gy][gx] > grid[gy][gx+1] {
				hash |= 1
			}
		}
	}
	return hash
}

func luma(c color.Color) float64 {
	r, g, b, a := c.RGBA()
	if a == 0 {
		return 255 // transparent counts as white so cut-out avatars compare sensibly
	}
	return (0.299*float64(r) + 0.587*float64(g) + 0.114*float64(b)) / 257
}
