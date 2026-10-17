package output

import (
	"sort"
	"strings"
)

// detailLines renders a finding's details as "key: value" lines in a stable
// order (the most informative keys first), clipping very long values.
func detailLines(d map[string]string, max int) []string {
	if len(d) == 0 {
		return nil
	}
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		ri, rj := rank(keys[i]), rank(keys[j])
		if ri != rj {
			return ri < rj
		}
		return keys[i] < keys[j]
	})
	var out []string
	for _, k := range keys {
		v := strings.Join(strings.Fields(d[k]), " ")
		if len(v) > 260 {
			v = v[:260] + "…"
		}
		out = append(out, k+": "+v)
		if max > 0 && len(out) >= max {
			break
		}
	}
	return out
}

// rank sorts housekeeping keys (notes, hashes, http status) after real data.
func rank(k string) int {
	switch k {
	case "note", "md5", "http_status", "avatar", "username", "rank", "engine", "query", "host":
		return 2
	}
	return 1
}
