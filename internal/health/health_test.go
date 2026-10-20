package health

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
)

func TestLiveHealth(t *testing.T) {
	if os.Getenv("RECTOOL_LIVE") == "" {
		t.Skip("live")
	}
	c, _ := httpx.New(httpx.Options{Timeout: 20 * time.Second})
	for _, r := range Check(context.Background(), c) {
		t.Logf("%-18s ok=%v %d %dms %s", r.Name, r.OK, r.Status, r.MS, r.Error)
	}
}
