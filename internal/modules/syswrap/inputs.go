package syswrap

import (
	"regexp"
	"strings"

	"github.com/sudosoc/rectool/internal/models"
)

// Inputs are the validated values substituted into tool command lines.
type Inputs struct {
	Username, Email, Domain, Phone string
}

var (
	tokenRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}$`)
	domainRe = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$`)
	phoneRe  = regexp.MustCompile(`^\+?[0-9]{5,15}$`)
)

// inputsFrom extracts and validates the values tools may receive. Anything
// that fails validation is dropped, which also prevents argument injection
// (values can never start with '-' or contain shell/whitespace characters).
func inputsFrom(t models.Target) Inputs {
	var in Inputs
	u := t.Username
	if u == "" && len(t.Aliases) > 0 {
		u = t.Aliases[0]
	}
	if tokenRe.MatchString(u) {
		in.Username = u
	}
	if tokenRe.MatchString(t.Email) {
		in.Email = t.Email
		if _, d, ok := strings.Cut(t.Email, "@"); ok && domainRe.MatchString(d) {
			in.Domain = strings.ToLower(d)
		}
	}
	if t.Domain != "" && domainRe.MatchString(t.Domain) {
		in.Domain = strings.ToLower(t.Domain)
	}
	if phoneRe.MatchString(t.Phone) {
		in.Phone = t.Phone
	}
	return in
}

func (in Inputs) get(field string) string {
	switch field {
	case "username":
		return in.Username
	case "email":
		return in.Email
	case "domain":
		return in.Domain
	case "phone":
		return in.Phone
	}
	return ""
}
