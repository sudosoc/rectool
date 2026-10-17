package syswrap

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/models"
)

// CustomSpec is the JSON schema for user-defined wrappers (-tools-file):
//
//	[{"name":"holehe","binary":"holehe","args":["--only-used","{email}"],
//	  "pattern":"^\\[\\+\\]\\s+(?P<title>\\S+)","category":"email","timeout_sec":90}]
//
// Placeholders {username} {email} {domain} {phone} in args are substituted
// and also declare which inputs the tool requires. "pattern" is matched per
// output line; named groups "title" and "url" feed the finding, and every
// other named group goes into its details.
type CustomSpec struct {
	Name       string   `json:"name"`
	Binary     string   `json:"binary"`
	Args       []string `json:"args"`
	Pattern    string   `json:"pattern"`
	Category   string   `json:"category"`
	TimeoutSec int      `json:"timeout_sec"`
}

var placeholderRe = regexp.MustCompile(`\{(username|email|domain|phone)\}`)

func loadCustomTools(path string) ([]*Tool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var specs []CustomSpec
	if err := json.Unmarshal(b, &specs); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var tools []*Tool
	for _, sp := range specs {
		t, err := sp.build()
		if err != nil {
			return nil, fmt.Errorf("tool %q: %w", sp.Name, err)
		}
		tools = append(tools, t)
	}
	return tools, nil
}

func (sp CustomSpec) build() (*Tool, error) {
	if sp.Name == "" || sp.Binary == "" {
		return nil, fmt.Errorf("name and binary are required")
	}
	re, err := regexp.Compile(sp.Pattern)
	if err != nil {
		return nil, err
	}
	var req []string
	seen := map[string]bool{}
	for _, a := range sp.Args {
		for _, m := range placeholderRe.FindAllStringSubmatch(a, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				req = append(req, m[1])
			}
		}
	}
	timeout := time.Duration(sp.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	cat := sp.Category
	if cat == "" {
		cat = "custom"
	}
	names := re.SubexpNames()

	return &Tool{
		Name: sp.Name, Binary: sp.Binary, Requires: req, Timeout: timeout,
		Args: func(in Inputs) [][]string {
			args := make([]string, len(sp.Args))
			for i, a := range sp.Args {
				args[i] = placeholderRe.ReplaceAllStringFunc(a, func(m string) string {
					return in.get(m[1 : len(m)-1])
				})
			}
			return [][]string{args}
		},
		Parse: func(in Inputs, _ []string, out string) []models.Finding {
			var res []models.Finding
			for _, line := range strings.Split(out, "\n") {
				m := re.FindStringSubmatch(strings.TrimSpace(line))
				if m == nil || len(res) >= maxItems {
					continue
				}
				d := map[string]string{"tool": sp.Name}
				title, url := sp.Name, ""
				for i, n := range names {
					switch {
					case n == "" || m[i] == "":
					case n == "title":
						title = m[i]
					case n == "url":
						url = m[i]
					default:
						d[n] = m[i]
					}
				}
				if len(names) <= 1 { // no named groups: keep the raw line
					d["line"] = strings.TrimSpace(line)
				}
				res = append(res, finding(title, cat, url, 0.6, d))
			}
			return res
		},
	}, nil
}
