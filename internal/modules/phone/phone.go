// Package phone extracts everything a phone number reveals by itself, offline,
// using Google's libphonenumber metadata: validity, country, region, line type
// (mobile / landline / VoIP / toll-free…), original carrier, time zones and
// every common written format. Web mentions of the number are handled by the
// footprint and dorks modules.
package phone

import (
	"context"
	"strings"

	"github.com/nyaruka/phonenumbers"

	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/scanner"
)

// Scanner is the phone module.
type Scanner struct{}

var _ scanner.Scanner = (*Scanner)(nil)

// New builds the module.
func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "phone" }
func (s *Scanner) Description() string {
	return "number validity, country, line type, original carrier, time zones, formats"
}
func (s *Scanner) CanRun(t models.Target) bool { return t.Phone != "" }

var numberTypes = map[phonenumbers.PhoneNumberType]string{
	phonenumbers.FIXED_LINE: "fixed line", phonenumbers.MOBILE: "mobile",
	phonenumbers.FIXED_LINE_OR_MOBILE: "fixed line or mobile", phonenumbers.TOLL_FREE: "toll-free",
	phonenumbers.PREMIUM_RATE: "premium rate", phonenumbers.SHARED_COST: "shared cost",
	phonenumbers.VOIP: "VoIP", phonenumbers.PERSONAL_NUMBER: "personal number", phonenumbers.PAGER: "pager",
	phonenumbers.UAN: "universal access number", phonenumbers.VOICEMAIL: "voicemail", phonenumbers.UNKNOWN: "unknown",
}

// Scan parses the number. Numbers without a leading "+" are interpreted using
// the location hint when it names a country, otherwise reported as ambiguous.
func (s *Scanner) Scan(_ context.Context, t models.Target, _ scanner.Deps, emit func(models.Finding)) error {
	region := ""
	if !strings.HasPrefix(t.Phone, "+") {
		region = guessRegion(t.Location)
	}
	num, err := phonenumbers.Parse(t.Phone, region)
	if err != nil {
		emit(models.Finding{Source: "Phone number", Category: "phone", Status: models.StatusUncertain, Confidence: 0.3,
			Details: map[string]string{"error": err.Error(),
				"hint": "give the number in international format, e.g. +201001234567"}})
		return nil
	}

	d := map[string]string{}
	set := func(k, v string) {
		if v = strings.TrimSpace(v); v != "" {
			d[k] = v
		}
	}
	valid := phonenumbers.IsValidNumber(num)
	if valid {
		d["valid"] = "yes"
	} else if phonenumbers.IsPossibleNumber(num) {
		d["valid"] = "no — right length but not an allocated number range"
	} else {
		d["valid"] = "no — impossible length for this country"
	}
	set("country code", "+"+itoa(int(num.GetCountryCode())))
	set("region (ISO)", phonenumbers.GetRegionCodeForNumber(num))
	set("line type", numberTypes[phonenumbers.GetNumberType(num)])
	if geo, err := phonenumbers.GetGeocodingForNumber(num, "en"); err == nil {
		set("area / location", geo)
	}
	if car, err := phonenumbers.GetCarrierForNumber(num, "en"); err == nil {
		set("original carrier", car)
		if car != "" {
			d["carrier note"] = "carrier at allocation time; the number may have been ported since"
		}
	}
	if zones, err := phonenumbers.GetTimezonesForNumber(num); err == nil {
		set("time zones", strings.Join(zones, ", "))
	}
	set("E.164", phonenumbers.Format(num, phonenumbers.E164))
	set("international", phonenumbers.Format(num, phonenumbers.INTERNATIONAL))
	set("national", phonenumbers.Format(num, phonenumbers.NATIONAL))
	digits := strings.TrimPrefix(phonenumbers.Format(num, phonenumbers.E164), "+")
	d["chat apps (open manually)"] = "https://wa.me/" + digits + "  ·  https://t.me/+" + digits
	d["note"] = "rectool does not query caller-ID / subscriber databases; ownership cannot be derived from the number alone"

	conf := 0.95
	if !valid {
		conf = 0.5
	}
	emit(models.Finding{Source: "Phone number intelligence", Category: "phone", Status: models.StatusFound,
		Confidence: conf, Details: d})
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// guessRegion maps a few common country names in the location hint to ISO
// codes so national-format numbers can be parsed.
func guessRegion(loc string) string {
	l := strings.ToLower(loc)
	for name, code := range map[string]string{
		"egypt": "EG", "united states": "US", "usa": "US", "united kingdom": "GB", "uk": "GB", "saudi": "SA",
		"emirates": "AE", "uae": "AE", "germany": "DE", "france": "FR", "india": "IN", "pakistan": "PK",
		"turkey": "TR", "canada": "CA", "australia": "AU", "italy": "IT", "spain": "ES", "brazil": "BR",
		"nigeria": "NG", "morocco": "MA", "algeria": "DZ", "tunisia": "TN", "jordan": "JO", "kuwait": "KW",
		"qatar": "QA", "iraq": "IQ", "lebanon": "LB", "russia": "RU", "china": "CN", "japan": "JP",
	} {
		if strings.Contains(l, name) {
			return code
		}
	}
	return ""
}
