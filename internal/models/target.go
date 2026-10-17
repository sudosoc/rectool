// Package models holds the data structures shared by every layer of rectool.
package models

// Target is the set of (all optional) identifiers the operator supplies.
type Target struct {
	FullName string `json:"full_name,omitempty"`
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
	Alias    string `json:"alias,omitempty"`    // nickname / known-as / handle variant
	Domain   string `json:"domain,omitempty"`   // domain, website URL or social-profile URL (normalised)
	ASN      string `json:"asn,omitempty"`      // autonomous system number, e.g. AS13335
	Wallet   string `json:"wallet,omitempty"`   // Bitcoin or Ethereum/EVM address
	IP       string `json:"ip,omitempty"`       // IPv4 / IPv6 address
	Company  string `json:"company,omitempty"`  // organisation name
	Location string `json:"location,omitempty"` // city / country; used to focus searches

	// Aliases are candidate usernames derived by the engine's planner
	// (e-mail local part, name permutations). Never set by the user directly.
	Aliases []string `json:"aliases,omitempty"`
}

// IsEmpty reports whether the operator supplied no identifier at all.
// Location alone is only a refinement, so it does not count.
func (t Target) IsEmpty() bool {
	return t.FullName == "" && t.Username == "" && t.Email == "" && t.Phone == "" &&
		t.Domain == "" && t.IP == "" && t.Company == "" && t.Alias == "" && t.ASN == "" && t.Wallet == ""
}

// Usernames returns the explicit username followed by derived aliases,
// de-duplicated and in stable order.
func (t Target) Usernames() []string {
	seen := make(map[string]struct{}, len(t.Aliases)+1)
	out := make([]string, 0, len(t.Aliases)+1)
	for _, u := range append([]string{t.Username}, t.Aliases...) {
		if u == "" {
			continue
		}
		if _, dup := seen[u]; dup {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	return out
}
