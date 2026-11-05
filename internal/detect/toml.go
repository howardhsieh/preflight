package detect

import (
	"strings"
)

// readTOML reads a TOML file into the same map[string]any shape readJSONC
// produces, covering the subset Codex's config.toml uses: [a.b] tables,
// string / boolean / number scalars and flat arrays of strings. Anything
// else is skipped rather than failing, because the detector only needs the
// mcp_servers tables and the notify array.
func readTOML(c *Context, p string) ([]byte, map[string]any, bool) {
	data, ok := c.Read(p)
	if !ok {
		return nil, nil, false
	}
	return data, parseTOML(data), true
}

func parseTOML(data []byte) map[string]any {
	root := map[string]any{}
	cur := root
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			name := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(line, "[["), "]]"), "[]")
			cur = tomlTable(root, strings.TrimSpace(name))
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.Trim(strings.TrimSpace(key), `"'`)
		if key == "" {
			continue
		}
		cur[key] = tomlValue(strings.TrimSpace(val))
	}
	return root
}

// tomlTable returns (creating as needed) the nested table for a dotted name
// such as mcp_servers."my server".
func tomlTable(root map[string]any, name string) map[string]any {
	cur := root
	for _, part := range splitTOMLKey(name) {
		next, ok := cur[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[part] = next
		}
		cur = next
	}
	return cur
}

func splitTOMLKey(name string) []string {
	var parts []string
	var b strings.Builder
	quote := byte(0)
	for i := 0; i < len(name); i++ {
		ch := name[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			} else {
				b.WriteByte(ch)
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == '.':
			parts = append(parts, strings.TrimSpace(b.String()))
			b.Reset()
		default:
			b.WriteByte(ch)
		}
	}
	if s := strings.TrimSpace(b.String()); s != "" {
		parts = append(parts, s)
	}
	return parts
}

func tomlValue(v string) any {
	switch {
	case v == "":
		return ""
	case v[0] == '[':
		var items []any
		inner := strings.TrimSuffix(strings.TrimPrefix(v, "["), "]")
		for _, it := range strings.Split(inner, ",") {
			if s := tomlScalar(strings.TrimSpace(it)); s != "" {
				items = append(items, s)
			}
		}
		return items
	case v == "true":
		return true
	case v == "false":
		return false
	}
	return tomlScalar(v)
}

func tomlScalar(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
		if i := strings.IndexByte(v[1:], v[0]); i >= 0 {
			return v[1 : i+1]
		}
		return v[1:]
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return v
}
