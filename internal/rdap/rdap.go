// Package rdap queries the public RDAP registries (the JSON successor of
// WHOIS) through the rdap.org bootstrap redirector. No account or key needed.
package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/httpx"
)

// Contact is a registrant / admin / tech / abuse entity.
type Contact struct {
	Roles []string
	Name  string
	Org   string
	Email string
	Phone string
}

// Domain is the parsed registration record of a domain.
type Domain struct {
	Name        string
	Queried     string // the (parent) name the record was found under
	Status      []string
	Created     string
	Expires     string
	Updated     string
	Nameservers []string
	Registrar   string
	DNSSEC      bool
	Contacts    []Contact
}

// IPNet is the parsed registration record of an IP network.
type IPNet struct {
	Handle   string
	Name     string
	Type     string
	Country  string
	Start    string
	End      string
	CIDRs    []string
	Parent   string
	Remarks  string
	Created  string
	Updated  string
	Contacts []Contact
}

type rEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rEntity struct {
	Roles    []string  `json:"roles"`
	Vcard    []any     `json:"vcardArray"`
	Entities []rEntity `json:"entities"`
	Handle   string    `json:"handle"`
}

type rDomain struct {
	LdhName     string   `json:"ldhName"`
	Status      []string `json:"status"`
	Events      []rEvent `json:"events"`
	Nameservers []struct {
		LdhName string `json:"ldhName"`
	} `json:"nameservers"`
	Entities  []rEntity `json:"entities"`
	SecureDNS struct {
		DelegationSigned bool `json:"delegationSigned"`
	} `json:"secureDNS"`
}

type rIP struct {
	Handle       string    `json:"handle"`
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Country      string    `json:"country"`
	StartAddress string    `json:"startAddress"`
	EndAddress   string    `json:"endAddress"`
	ParentHandle string    `json:"parentHandle"`
	Events       []rEvent  `json:"events"`
	Entities     []rEntity `json:"entities"`
	Remarks      []struct {
		Description []string `json:"description"`
	} `json:"remarks"`
	Cidr0 []struct {
		V4 string `json:"v4prefix"`
		V6 string `json:"v6prefix"`
		L  int    `json:"length"`
	} `json:"cidr0_cidrs"`
}

func get(ctx context.Context, c *httpx.Client, url string, out any) (int, error) {
	resp, err := c.Do(ctx, httpx.Request{
		URL: url, Timeout: 20 * time.Second,
		Headers: map[string]string{"Accept": "application/rdap+json, application/json"},
	})
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil
	}
	return 200, json.Unmarshal(resp.Body, out)
}

// LookupDomain fetches the registration record for name, walking up to the
// parent domain (up to three labels) when name itself has no record.
func LookupDomain(ctx context.Context, c *httpx.Client, name string) (*Domain, error) {
	labels := strings.Split(name, ".")
	var lastStatus int
	for i := 0; i < len(labels)-1 && i < 3; i++ {
		q := strings.Join(labels[i:], ".")
		var r rDomain
		st, err := get(ctx, c, "https://rdap.org/domain/"+q, &r)
		if err != nil {
			return nil, err
		}
		lastStatus = st
		if st != 200 {
			continue
		}
		d := &Domain{Name: strings.ToLower(r.LdhName), Queried: q, Status: r.Status, DNSSEC: r.SecureDNS.DelegationSigned}
		for _, e := range r.Events {
			switch strings.ToLower(e.Action) {
			case "registration":
				d.Created = e.Date
			case "expiration":
				d.Expires = e.Date
			case "last changed":
				d.Updated = e.Date
			}
		}
		for _, ns := range r.Nameservers {
			d.Nameservers = append(d.Nameservers, strings.ToLower(ns.LdhName))
		}
		for _, e := range r.Entities {
			d.Contacts = append(d.Contacts, flatten(e)...)
		}
		for _, c := range d.Contacts {
			for _, role := range c.Roles {
				if role == "registrar" && d.Registrar == "" {
					d.Registrar = firstNonEmpty(c.Org, c.Name)
				}
			}
		}
		return d, nil
	}
	return nil, fmt.Errorf("no RDAP record (HTTP %d)", lastStatus)
}

// LookupIP fetches the registration record of the network containing ip.
func LookupIP(ctx context.Context, c *httpx.Client, ip string) (*IPNet, error) {
	var r rIP
	st, err := get(ctx, c, "https://rdap.org/ip/"+ip, &r)
	if err != nil {
		return nil, err
	}
	if st != 200 {
		return nil, fmt.Errorf("no RDAP record (HTTP %d)", st)
	}
	n := &IPNet{Handle: r.Handle, Name: r.Name, Type: r.Type, Country: r.Country,
		Start: r.StartAddress, End: r.EndAddress, Parent: r.ParentHandle}
	for _, e := range r.Events {
		switch strings.ToLower(e.Action) {
		case "registration":
			n.Created = e.Date
		case "last changed":
			n.Updated = e.Date
		}
	}
	for _, rm := range r.Remarks {
		n.Remarks += strings.Join(rm.Description, " ") + " "
	}
	n.Remarks = strings.TrimSpace(n.Remarks)
	for _, c := range r.Cidr0 {
		p := c.V4
		if p == "" {
			p = c.V6
		}
		n.CIDRs = append(n.CIDRs, fmt.Sprintf("%s/%d", p, c.L))
	}
	for _, e := range r.Entities {
		n.Contacts = append(n.Contacts, flatten(e)...)
	}
	return n, nil
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// flatten turns an entity tree into contacts, parsing each jCard.
func flatten(e rEntity) []Contact {
	c := Contact{Roles: e.Roles}
	if len(e.Vcard) == 2 {
		if props, ok := e.Vcard[1].([]any); ok {
			for _, p := range props {
				arr, ok := p.([]any)
				if !ok || len(arr) < 4 {
					continue
				}
				name, _ := arr[0].(string)
				val, _ := arr[3].(string)
				val = strings.TrimSpace(val)
				if redacted(val) {
					continue
				}
				switch name {
				case "fn":
					c.Name = val
				case "org":
					if val == "" { // org may be an array value
						if a, ok := arr[3].([]any); ok && len(a) > 0 {
							val, _ = a[0].(string)
						}
					}
					c.Org = val
				case "email":
					c.Email = strings.ToLower(val)
				case "tel":
					c.Phone = strings.TrimPrefix(val, "tel:")
				}
			}
		}
	}
	var out []Contact
	if c.Name != "" || c.Org != "" || c.Email != "" || c.Phone != "" {
		out = append(out, c)
	}
	for _, sub := range e.Entities {
		out = append(out, flatten(sub)...)
	}
	return out
}

func redacted(v string) bool {
	l := strings.ToLower(v)
	return v == "" || strings.Contains(l, "redacted") || strings.Contains(l, "privacy") && strings.Contains(l, "contact") ||
		strings.Contains(l, "not disclosed") || strings.Contains(l, "data protected")
}

// LookupASN fetches the registration record of an autonomous system
// ("AS13335" or "13335"). The result reuses IPNet: Name, Country, Handle,
// dates, remarks and contacts are filled in.
func LookupASN(ctx context.Context, c *httpx.Client, asn string) (*IPNet, error) {
	asn = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(asn)), "AS")
	var r rIP
	st, err := get(ctx, c, "https://rdap.org/autnum/"+asn, &r)
	if err != nil {
		return nil, err
	}
	if st != 200 {
		return nil, fmt.Errorf("no RDAP record (HTTP %d)", st)
	}
	n := &IPNet{Handle: r.Handle, Name: r.Name, Type: r.Type, Country: r.Country}
	for _, e := range r.Events {
		switch strings.ToLower(e.Action) {
		case "registration":
			n.Created = e.Date
		case "last changed":
			n.Updated = e.Date
		}
	}
	for _, rm := range r.Remarks {
		n.Remarks += strings.Join(rm.Description, " ") + " "
	}
	n.Remarks = strings.TrimSpace(n.Remarks)
	for _, e := range r.Entities {
		n.Contacts = append(n.Contacts, flatten(e)...)
	}
	return n, nil
}
