package social

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

//go:embed sites_default.json
var defaultSitesJSON []byte

const accountToken = "{account}"

// Site describes how to test for a username on one platform. The schema is
// the WhatsMyName (WMN) community format, so the 600+ site list from
// github.com/WebBreacher/WhatsMyName can be loaded directly with -sites.
type Site struct {
	Name      string            `json:"name"`
	URICheck  string            `json:"uri_check"`            // URL probed; contains {account}
	URIPretty string            `json:"uri_pretty,omitempty"` // human-facing profile URL
	ECode     int               `json:"e_code,omitempty"`     // status when the account EXISTS (default 200)
	EString   string            `json:"e_string,omitempty"`   // body marker when it exists
	MCode     int               `json:"m_code,omitempty"`     // status when it is MISSING
	MString   string            `json:"m_string,omitempty"`   // body marker when it is missing
	Cat       string            `json:"cat,omitempty"`
	Known     []string          `json:"known,omitempty"` // accounts known to exist (used by self-test)
	Headers   map[string]string `json:"headers,omitempty"`
	PostBody  string            `json:"post_body,omitempty"`

	subdomain bool
}

var subdomainSafe = regexp.MustCompile(`^[A-Za-z0-9-]{1,63}$`)

// applicable reports whether user can legally appear in this site's URL
// (e.g. a "john.doe" cannot be a subdomain).
func (s *Site) applicable(user string) bool {
	if s.subdomain {
		return subdomainSafe.MatchString(user)
	}
	return true
}

func (s *Site) checkURL(user string) string {
	return strings.ReplaceAll(s.URICheck, accountToken, user)
}

func (s *Site) prettyURL(user string) string {
	u := s.URIPretty
	if u == "" {
		u = s.URICheck
	}
	return strings.ReplaceAll(u, accountToken, user)
}

// LoadSites parses sites from path, or the embedded default list when path is
// empty. Both a bare JSON array and the WMN object form {"sites":[...]} work.
func LoadSites(path string) ([]Site, error) {
	data := defaultSitesJSON
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		data = b
	}

	var sites []Site
	var wrapped struct {
		Sites []Site `json:"sites"`
	}
	if err := json.Unmarshal(data, &wrapped); err == nil && len(wrapped.Sites) > 0 {
		sites = wrapped.Sites
	} else if err := json.Unmarshal(data, &sites); err != nil {
		return nil, fmt.Errorf("parse sites: %w", err)
	}

	seen := make(map[string]bool, len(sites))
	out := sites[:0]
	for _, s := range sites {
		if s.Name == "" || !strings.Contains(s.URICheck, accountToken) || seen[s.Name+s.URICheck] {
			continue
		}
		seen[s.Name+s.URICheck] = true
		if s.ECode == 0 {
			s.ECode = 200
		}
		if i := strings.Index(s.URICheck, "://"); i >= 0 {
			host, _, _ := strings.Cut(s.URICheck[i+3:], "/")
			s.subdomain = strings.Contains(host, accountToken)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable sites found")
	}
	return out, nil
}
