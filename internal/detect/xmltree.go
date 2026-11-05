package detect

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
)

// xmlNode is a minimal element tree for the XML dialects JetBrains writes.
// Only element names, attributes and nesting are kept; character data is
// never needed by the detectors.
type xmlNode struct {
	Name     string
	Attr     map[string]string
	Children []*xmlNode
}

// maxXMLNodes bounds the tree so a hostile file cannot exhaust memory
// (the file itself is already capped at MaxReadBytes).
const maxXMLNodes = 200000

// parseXML builds the element tree of data. It is lenient about encodings
// and markup errors so that a slightly broken but mostly valid .idea file
// still yields its configurations. External entities are never resolved
// (encoding/xml does not support them).
func parseXML(data []byte) *xmlNode {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = false
	d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	root := &xmlNode{Name: "#document", Attr: map[string]string{}}
	stack := []*xmlNode{root}
	nodes := 0
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if nodes++; nodes > maxXMLNodes {
				return root
			}
			n := &xmlNode{Name: t.Name.Local, Attr: make(map[string]string, len(t.Attr))}
			for _, a := range t.Attr {
				n.Attr[a.Name.Local] = a.Value
			}
			parent := stack[len(stack)-1]
			parent.Children = append(parent.Children, n)
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	return root
}

// walk visits every element depth-first.
func (n *xmlNode) walk(fn func(*xmlNode)) {
	for _, c := range n.Children {
		fn(c)
		c.walk(fn)
	}
}

// find returns every descendant element with the given name.
func (n *xmlNode) find(name string) []*xmlNode {
	var out []*xmlNode
	n.walk(func(c *xmlNode) {
		if c.Name == name {
			out = append(out, c)
		}
	})
	return out
}

// component returns the <component name="..."> elements with that name.
func (n *xmlNode) component(name string) []*xmlNode {
	var out []*xmlNode
	for _, c := range n.find("component") {
		if c.Attr["name"] == name {
			out = append(out, c)
		}
	}
	return out
}

// options flattens <option name="K" value="V"/> children (at any depth) into
// a map, keeping the first value for a name.
func (n *xmlNode) options() map[string]string {
	m := map[string]string{}
	n.walk(func(c *xmlNode) {
		if c.Name != "option" {
			return
		}
		k, v := c.Attr["name"], c.Attr["value"]
		if _, dup := m[k]; k != "" && v != "" && !dup {
			m[k] = v
		}
	})
	return m
}

// attrLine returns the 1-based line of the first `name="value"` attribute in
// data, or 0. XML attribute values are quoted with either quote character.
func attrLine(data []byte, name, value string) int {
	for _, q := range []string{`"`, `'`} {
		if l := lineOf(data, name+"="+q+value+q); l > 0 {
			return l
		}
	}
	return 0
}

// xmlValue unescapes the handful of entities JetBrains uses in attributes.
func xmlValue(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	return strings.NewReplacer("&quot;", `"`, "&apos;", "'", "&lt;", "<", "&gt;", ">", "&amp;", "&", "&#10;", "\n").Replace(s)
}
