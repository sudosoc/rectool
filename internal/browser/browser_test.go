package browser

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestBlocked(t *testing.T) {
	if !Blocked("<html>" + strings.Repeat("x", 300) + "authwall</html>") {
		t.Fatal("authwall not detected")
	}
	if Blocked(`<html>` + strings.Repeat("x", 300) + `{"@type":"Person","name":"A"}</html>`) {
		t.Fatal("real profile flagged as blocked")
	}
	if !Blocked("<html></html>") {
		t.Fatal("empty page accepted")
	}
}

func TestLive(t *testing.T) {
	u := os.Getenv("RECTOOL_LIVE_URL")
	if u == "" {
		t.Skip("set RECTOOL_LIVE_URL")
	}
	bin, err := Find()
	if err != nil {
		t.Fatal(err)
	}
	dom, err := DumpDOM(context.Background(), bin, u)
	t.Logf("bin=%s err=%v len=%d", bin, err, len(dom))
	i := strings.Index(dom, `"@type":"Person"`)
	t.Logf("person json-ld at %d", i)
	for _, k := range []string{"og:title", "og:description", "og:image", "<title>"} {
		if j := strings.Index(dom, k); j >= 0 {
			e := min(len(dom), j+200)
			t.Logf("%s => %s", k, strings.ReplaceAll(dom[j:e], "\n", " "))
		}
	}
}
