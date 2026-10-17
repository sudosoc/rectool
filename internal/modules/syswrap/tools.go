package syswrap

import (
	"time"

	"github.com/sudosoc/rectool/internal/models"
)

// Tool describes how to run one external CLI program and turn its stdout into
// Findings. Each element returned by Args is one invocation's argument list.
type Tool struct {
	Name     string
	Binary   string
	Requires []string // Inputs fields that must be non-empty: username, email, domain, phone
	Timeout  time.Duration
	Args     func(Inputs) [][]string
	Parse    func(in Inputs, args []string, stdout string) []models.Finding
}

func (t *Tool) applicable(in Inputs) bool {
	for _, r := range t.Requires {
		if in.get(r) == "" {
			return false
		}
	}
	return true
}

// builtinTools is the registry of wrappers that ship with rectool.
func builtinTools() []*Tool {
	return []*Tool{
		{
			Name: "whois", Binary: "whois", Requires: []string{"domain"}, Timeout: 30 * time.Second,
			Args:  func(in Inputs) [][]string { return [][]string{{in.Domain}} },
			Parse: parseWhois,
		},
		{
			Name: "dig", Binary: "dig", Requires: []string{"domain"}, Timeout: 15 * time.Second,
			Args: func(in Inputs) [][]string {
				var a [][]string
				for _, typ := range []string{"MX", "TXT", "NS"} {
					a = append(a, []string{"+short", "+time=5", "+tries=1", typ, in.Domain})
				}
				return a
			},
			Parse: parseDig,
		},
		{
			Name: "theHarvester", Binary: "theHarvester", Requires: []string{"domain"}, Timeout: 180 * time.Second,
			Args: func(in Inputs) [][]string {
				return [][]string{{"-d", in.Domain, "-b", "crtsh,rapiddns,hackertarget", "-l", "200"}}
			},
			Parse: parseHarvester,
		},
		{
			Name: "subfinder", Binary: "subfinder", Requires: []string{"domain"}, Timeout: 180 * time.Second,
			Args:  func(in Inputs) [][]string { return [][]string{{"-d", in.Domain, "-silent"}} },
			Parse: parseSubfinder,
		},
		{
			Name: "whatweb", Binary: "whatweb", Requires: []string{"domain"}, Timeout: 90 * time.Second,
			Args: func(in Inputs) [][]string {
				return [][]string{{"-q", "--color=never", "--no-errors", "-a", "1", in.Domain}}
			},
			Parse: parseWhatweb,
		},
		{
			Name: "maigret", Binary: "maigret", Requires: []string{"username"}, Timeout: 420 * time.Second,
			Args: func(in Inputs) [][]string {
				return [][]string{{"--no-color", "--no-progressbar", "--timeout", "10", "-n", "300", in.Username}}
			},
			Parse: parseFoundLines("maigret"),
		},
		{
			Name: "holehe", Binary: "holehe", Requires: []string{"email"}, Timeout: 240 * time.Second,
			Args:  func(in Inputs) [][]string { return [][]string{{"--only-used", "--no-color", in.Email}} },
			Parse: parseHolehe,
		},
		{
			Name: "phoneinfoga", Binary: "phoneinfoga", Requires: []string{"phone"}, Timeout: 120 * time.Second,
			Args:  func(in Inputs) [][]string { return [][]string{{"scan", "-n", in.Phone}} },
			Parse: parseRawSummary("phoneinfoga", "phone"),
		},
		{
			Name: "sherlock", Binary: "sherlock", Requires: []string{"username"}, Timeout: 240 * time.Second,
			Args: func(in Inputs) [][]string {
				return [][]string{{"--print-found", "--no-color", "--timeout", "10", in.Username}}
			},
			Parse: parseSherlock,
		},
	}
}
