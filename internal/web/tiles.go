package web

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
)

// tileProxy serves OpenStreetMap raster tiles to the Location tab through
// this server, so the page's strict CSP stays closed and the browser never
// contacts a third party. Tiles are cached in memory (OSM's usage policy asks
// clients to cache) and zoom is capped at city level.
type tileProxy struct {
	c     *httpx.Client
	mu    sync.Mutex
	cache map[string][]byte
	order []string
}

const maxTileZoom = 12

func newTileProxy(c *httpx.Client) *tileProxy { return &tileProxy{c: c, cache: map[string][]byte{}} }

func (t *tileProxy) handle(w http.ResponseWriter, r *http.Request) {
	z, e1 := strconv.Atoi(r.PathValue("z"))
	x, e2 := strconv.Atoi(r.PathValue("x"))
	y, e3 := strconv.Atoi(r.PathValue("y"))
	if e1 != nil || e2 != nil || e3 != nil || z < 0 || z > maxTileZoom || x < 0 || y < 0 || x >= 1<<z || y >= 1<<z {
		writeErr(w, http.StatusBadRequest, "bad tile")
		return
	}
	key := strconv.Itoa(z) + "/" + strconv.Itoa(x) + "/" + strconv.Itoa(y)
	t.mu.Lock()
	data, ok := t.cache[key]
	t.mu.Unlock()
	if !ok {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		resp, err := t.c.Do(ctx, httpx.Request{URL: "https://tile.openstreetmap.org/" + key + ".png", Timeout: 15 * time.Second, MaxBody: 1 << 20,
			Headers: map[string]string{"User-Agent": "rectool/1.0 (+https://github.com/sudosoc/rectool)", "Accept": "image/png"}})
		if err != nil || resp.StatusCode != 200 {
			writeErr(w, http.StatusBadGateway, "tile unavailable")
			return
		}
		data = resp.Body
		t.mu.Lock()
		t.cache[key] = data
		t.order = append(t.order, key)
		if len(t.order) > 400 {
			delete(t.cache, t.order[0])
			t.order = t.order[1:]
		}
		t.mu.Unlock()
	}
	h := w.Header()
	h.Set("Content-Type", "image/png")
	h.Set("Cache-Control", "private, max-age=86400")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	_, _ = w.Write(data)
}
