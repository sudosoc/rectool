package leads

import (
	"strings"
	"testing"

	"github.com/sudosoc/rectool/internal/models"
)

func TestBuildCoversEveryIdentifierAndEscapes(t *testing.T) {
	ls := Build(models.Target{
		FullName: "Jane O'Neil", Username: "jane doe", Email: "a+b@x.org", Phone: "+201001234567",
		Domain: "example.com", IP: "203.0.113.9", ASN: "AS13335", Company: "Acme & Sons", Wallet: "0x00000000219ab540356cBB839Cbe05303d7705Fa",
	})
	groups := map[string]int{}
	for _, l := range ls {
		groups[l.Group]++
		if !strings.HasPrefix(l.URL, "https://") || l.Label == "" || l.Why == "" {
			t.Errorf("malformed lead %+v", l)
		}
		if strings.ContainsAny(l.URL, " \"<>") {
			t.Errorf("unescaped characters in %q", l.URL)
		}
	}
	for _, g := range []string{"username", "name", "email", "phone", "domain", "ip", "asn", "company", "wallet"} {
		if groups[g] == 0 {
			t.Errorf("no manual leads for %s", g)
		}
	}
	if len(Build(models.Target{})) != 0 {
		t.Error("an empty target has no leads")
	}
}
