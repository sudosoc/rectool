package profiles

import (
	"html"
	"regexp"
	"strings"

	"github.com/sudosoc/rectool/internal/extract"
)

var tagStrip = regexp.MustCompile(`(?s)<[^>]*>`)

// stripTags turns an HTML fragment (bios are often HTML) into plain text.
func stripTags(s string) string {
	s = tagStrip.ReplaceAllString(s, " ")
	return strings.Join(strings.Fields(html.UnescapeString(s)), " ")
}

func emailsIn(s string) []string { return extract.Emails(s) }
