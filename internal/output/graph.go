package output

import (
	"crypto/sha1"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/models"
)

// The entity/relationship view of a report, shared by GraphML and STIX.
type gnode struct {
	ID, Type, Label string
	Strong          bool
}
type gedge struct{ From, To, Label string }

func nodeID(typ, val string) string {
	h := sha1.Sum([]byte(typ + "\x00" + strings.ToLower(val)))
	return "n" + hex.EncodeToString(h[:6])
}

func buildGraph(r *models.Report) ([]gnode, []gedge) {
	nodes := map[string]gnode{}
	var edges []gedge
	seenEdge := map[string]bool{}
	add := func(typ, val string, strong bool) string {
		id := nodeID(typ, val)
		if n, ok := nodes[id]; ok {
			if strong && !n.Strong {
				n.Strong = true
				nodes[id] = n
			}
			return id
		}
		nodes[id] = gnode{ID: id, Type: typ, Label: val, Strong: strong}
		return id
	}
	link := func(a, b, label string) {
		k := a + ">" + b + label
		if a != b && !seenEdge[k] {
			seenEdge[k] = true
			edges = append(edges, gedge{a, b, label})
		}
	}
	var roots []string
	t := r.Target
	for _, kv := range [][2]string{{models.EntName, t.FullName}, {models.EntUsername, t.Username}, {models.EntEmail, t.Email},
		{models.EntPhone, t.Phone}, {models.EntDomain, t.Domain}, {models.EntIP, t.IP}, {"company", t.Company}, {"asn", t.ASN}, {"wallet", t.Wallet}} {
		if kv[1] != "" {
			roots = append(roots, add(kv[0], kv[1], true))
		}
	}
	for _, f := range r.Findings {
		if f.Status != models.StatusFound && f.Status != models.StatusUncertain {
			continue
		}
		var fid string
		if f.URL != "" {
			fid = add("url", f.URL, false)
		}
		for _, e := range f.Entities {
			eid := add(e.Type, e.Value, e.Strong)
			if fid != "" {
				link(fid, eid, "mentions")
			}
		}
		if fid != "" && len(roots) > 0 && f.Via == "" {
			link(roots[0], fid, f.Source)
		}
	}
	for _, e := range r.Entities {
		add(e.Type, e.Value, e.Strong)
	}
	for _, id := range r.Identities {
		if id.Weak {
			continue
		}
		iid := add("person", id.Label, id.Primary)
		for _, ref := range id.Records {
			if ref.URL != "" {
				link(iid, add("url", ref.URL, false), ref.Platform)
			}
		}
		for _, grp := range []struct {
			typ   string
			facts []models.Fact
		}{{models.EntEmail, id.Emails}, {models.EntPhone, id.Phones}, {models.EntOrg, id.Employers}, {models.EntLocation, id.Locations},
			{models.EntUsername, id.Usernames}, {models.EntDomain, id.Websites}} {
			for _, f := range grp.facts {
				link(iid, add(grp.typ, f.Value, f.Confirmed), grp.typ)
			}
		}
	}
	ns := make([]gnode, 0, len(nodes))
	for _, n := range nodes {
		ns = append(ns, n)
	}
	sort.Slice(ns, func(i, j int) bool { return ns[i].ID < ns[j].ID })
	return ns, edges
}

// writeGraphML emits a GraphML graph that opens in Gephi, yEd and Maltego.
func writeGraphML(w io.Writer, r *models.Report) error {
	nodes, edges := buildGraph(r)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<graphml xmlns="http://graphml.graphdrawing.org/xmlns">` + "\n")
	b.WriteString(`<key id="type" for="node" attr.name="type" attr.type="string"/>` + "\n")
	b.WriteString(`<key id="label" for="node" attr.name="label" attr.type="string"/>` + "\n")
	b.WriteString(`<key id="strong" for="node" attr.name="strong" attr.type="boolean"/>` + "\n")
	b.WriteString(`<key id="rel" for="edge" attr.name="relation" attr.type="string"/>` + "\n")
	b.WriteString(`<graph id="rectool" edgedefault="directed">` + "\n")
	for _, n := range nodes {
		fmt.Fprintf(&b, `<node id="%s"><data key="type">%s</data><data key="label">%s</data><data key="strong">%t</data></node>`+"\n",
			n.ID, xmlEsc(n.Type), xmlEsc(n.Label), n.Strong)
	}
	for i, e := range edges {
		fmt.Fprintf(&b, `<edge id="e%d" source="%s" target="%s"><data key="rel">%s</data></edge>`+"\n", i, e.From, e.To, xmlEsc(e.Label))
	}
	b.WriteString("</graph>\n</graphml>\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func xmlEsc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		return r
	}, s)))
	return b.String()
}

// writeEntitiesCSV lists every discovered entity with where it came from.
func writeEntitiesCSV(w io.Writer, r *models.Report) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"type", "value", "strong", "source"})
	for _, e := range r.Entities {
		_ = cw.Write([]string{e.Type, csvSafe(e.Value), fmt.Sprint(e.Strong), csvSafe(e.Source)})
	}
	cw.Flush()
	return cw.Error()
}

// writeSTIX emits a STIX 2.1 bundle: observables (email-addr, domain-name,
// ipv4/6-addr, url, user-account) plus an identity SDO per resolved person.
func writeSTIX(w io.Writer, r *models.Report) error {
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	uuidOf := func(key string) string {
		h := sha1.Sum([]byte("rectool:" + key))
		x := hex.EncodeToString(h[:16])
		return x[0:8] + "-" + x[8:12] + "-5" + x[13:16] + "-a" + x[17:20] + "-" + x[20:32]
	}
	objs := []map[string]any{}
	seen := map[string]bool{}
	obs := func(typ, val string) {
		var o map[string]any
		switch typ {
		case models.EntEmail:
			o = map[string]any{"type": "email-addr", "value": val}
		case models.EntDomain:
			o = map[string]any{"type": "domain-name", "value": val}
		case models.EntIP:
			kind := "ipv4-addr"
			if strings.Contains(val, ":") {
				kind = "ipv6-addr"
			}
			o = map[string]any{"type": kind, "value": val}
		case models.EntURL, models.EntImage:
			o = map[string]any{"type": "url", "value": val}
		case models.EntUsername:
			o = map[string]any{"type": "user-account", "account_login": val}
		default:
			return
		}
		o["spec_version"] = "2.1"
		id := fmt.Sprintf("%s--%s", o["type"], uuidOf(typ+"|"+strings.ToLower(val)))
		o["id"] = id
		if !seen[id] {
			seen[id] = true
			objs = append(objs, o)
		}
	}
	for _, e := range r.Entities {
		obs(e.Type, e.Value)
	}
	for _, f := range r.Hits() {
		if f.URL != "" {
			obs(models.EntURL, f.URL)
		}
	}
	for _, id := range r.Identities {
		if id.Weak {
			continue
		}
		o := map[string]any{"type": "identity", "spec_version": "2.1", "id": "identity--" + uuidOf(fmt.Sprintf("person|%d|%s", id.ID, id.Label)),
			"created": now, "modified": now, "name": id.Label, "identity_class": "individual",
			"confidence": int(id.Score * 100)}
		var contact []string
		for _, f := range id.Emails {
			contact = append(contact, "email:"+f.Value)
		}
		for _, f := range id.Phones {
			contact = append(contact, "phone:"+f.Value)
		}
		if len(contact) > 0 {
			o["contact_information"] = strings.Join(contact, "; ")
		}
		if id.Bio != "" {
			o["description"] = id.Bio
		}
		objs = append(objs, o)
	}
	bundle := map[string]any{"type": "bundle", "id": "bundle--" + uuidOf("bundle|"+now+"|"+r.Target.FullName+r.Target.Username+r.Target.Email), "objects": objs}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bundle)
}
