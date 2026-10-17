package domain

import (
	"context"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/rdap"
)

func rdapJob(ctx context.Context, c *httpx.Client, domain string, emit func(models.Finding)) {
	rec, err := rdap.LookupDomain(ctx, c, domain)
	if err != nil {
		if ctx.Err() == nil {
			emit(errFinding("WHOIS / RDAP", "whois", err))
		}
		return
	}
	d := map[string]string{"domain": rec.Name}
	if rec.Queried != domain {
		d["note"] = "record found for parent domain " + rec.Queried
	}
	put(d, "registrar", rec.Registrar)
	put(d, "created", rec.Created)
	put(d, "expires", rec.Expires)
	put(d, "last changed", rec.Updated)
	put(d, "status", strings.Join(rec.Status, ", "))
	put(d, "nameservers", strings.Join(rec.Nameservers, ", "))
	if rec.DNSSEC {
		d["DNSSEC"] = "signed"
	}
	if t, err := time.Parse(time.RFC3339, rec.Created); err == nil {
		d["age"] = humanAge(time.Since(t))
	}

	var ents []models.Entity
	seenEmail := map[string]bool{}
	for _, ct := range rec.Contacts {
		role := strings.Join(ct.Roles, "/")
		if role == "" {
			role = "contact"
		}
		if role == "registrar" {
			put(d, "registrar contact email", ct.Email)
			continue
		}
		label := strings.TrimSpace(strings.Join(nonEmpty(ct.Name, ct.Org, ct.Email, ct.Phone), " · "))
		if label != "" {
			d[role] = label
		}
		if strings.Contains(ct.Email, "@") && !seenEmail[ct.Email] && !strings.Contains(role, "abuse") {
			seenEmail[ct.Email] = true
			ents = append(ents, models.Entity{Type: models.EntEmail, Value: ct.Email, Strong: true})
		}
		if ct.Name != "" && (strings.Contains(role, "registrant") || strings.Contains(role, "administrative")) {
			ents = append(ents, models.Entity{Type: models.EntName, Value: ct.Name})
		}
	}
	emit(fnd("WHOIS / RDAP registration", "whois", "https://rdap.org/domain/"+rec.Queried, 0.95, d, ents...))
}

func nonEmpty(s ...string) []string {
	var out []string
	for _, v := range s {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func humanAge(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days < 60 {
		return itoa(days) + " days"
	}
	if days < 730 {
		return itoa(days/30) + " months"
	}
	return itoa(days/365) + " years"
}
