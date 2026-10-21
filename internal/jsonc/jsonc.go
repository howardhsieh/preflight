// Package jsonc reads the "JSON with comments" dialect used by VS Code,
// devcontainers and several AI agent configs.
package jsonc

import (
	"bytes"
	"encoding/json"
)

// Standardize converts JSONC (comments and trailing commas) into strict JSON.
// Comments are replaced with spaces so newlines, and therefore line numbers,
// are preserved.
func Standardize(src []byte) []byte {
	out := bytes.Clone(bytes.TrimPrefix(src, []byte("\xef\xbb\xbf")))
	stripComments(out)
	stripTrailingCommas(out)
	return out
}

// Unmarshal parses JSONC into v.
func Unmarshal(src []byte, v any) error {
	return json.Unmarshal(Standardize(src), v)
}

func stripComments(b []byte) {
	inStr := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			switch c {
			case '\\':
				i++
			case '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for ; i < len(b) && b[i] != '\n'; i++ {
				b[i] = ' '
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			b[i], b[i+1] = ' ', ' '
			for i += 2; i < len(b); i++ {
				if b[i] == '*' && i+1 < len(b) && b[i+1] == '/' {
					b[i], b[i+1] = ' ', ' '
					i++
					break
				}
				if b[i] != '\n' {
					b[i] = ' '
				}
			}
		}
	}
}

func stripTrailingCommas(b []byte) {
	inStr := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			switch c {
			case '\\':
				i++
			case '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case ',':
			j := i + 1
			for j < len(b) && isSpace(b[j]) {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				b[i] = ' '
			}
		}
	}
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
