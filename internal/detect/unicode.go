package detect

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/howardhsieh/preflight/internal/finding"
)

// maxUnicodeScanBytes skips very large files (data dumps, bundles) for the
// per-rune scan.
const maxUnicodeScanBytes = 2 << 20

var binaryExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true, ".bmp": true, ".webp": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true, ".pdf": true, ".zip": true,
	".gz": true, ".tgz": true, ".jar": true, ".mp3": true, ".mp4": true, ".mov": true, ".wasm": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".node": true, ".bin": true, ".o": true, ".a": true,
}

func detectUnicode(c *Context) []finding.Finding {
	var out []finding.Finding
	for _, f := range c.Files {
		if !f.Mode.IsRegular() || f.Size == 0 || f.Size > maxUnicodeScanBytes || binaryExts[ext(f.Path)] {
			continue
		}
		data, ok := c.Read(f.Path)
		if !ok || isBinary(data[:min(len(data), 8000)]) || !utf8.Valid(data) {
			continue
		}
		out = append(out, scanRunes(f.Path, data)...)
	}
	return out
}

func isBidi(r rune) bool { return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) }

func isASCIILetter(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }

type runeHit struct {
	count, line int
}

func (h *runeHit) add(line int) {
	if h.count == 0 {
		h.line = line
	}
	h.count++
}

func scanRunes(file string, data []byte) []finding.Finding {
	var tags, bidi, zw runeHit
	var hidden strings.Builder
	line := 1
	var prev rune
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		next, _ := utf8.DecodeRune(data[i+size:])
		switch {
		case r == '\n':
			line++
		case r >= 0xE0000 && r <= 0xE007F:
			tags.add(line)
			if r >= 0xE0020 && r <= 0xE007E && hidden.Len() < 400 {
				hidden.WriteRune(r - 0xE0000)
			}
		case isBidi(r):
			bidi.add(line)
		case r == 0x200B || r == 0x2060 || (r == 0xFEFF && i != 0):
			zw.add(line)
		case (r == 0x200C || r == 0x200D) && isASCIILetter(prev) && isASCIILetter(next):
			// Joiners are legitimate in emoji and some scripts; inside an
			// ASCII word they only serve to hide or split text.
			zw.add(line)
		}
		prev = r
		i += size
	}

	var out []finding.Finding
	if tags.count > 0 {
		fd := newFinding("PF601", finding.Critical, finding.TriggerNone, file, tags.line,
			fmt.Sprintf("%d invisible Unicode Tag characters hide text from humans but not from AI models", tags.count))
		if hidden.Len() > 0 {
			fd.Evidence = "decoded: " + truncate(hidden.String(), 200)
		}
		out = append(out, fd)
	}
	if bidi.count > 0 {
		out = append(out, newFinding("PF602", finding.High, finding.TriggerNone, file, bidi.line,
			fmt.Sprintf("%d bidirectional control characters can reorder how this text is displayed", bidi.count)))
	}
	if zw.count > 0 {
		// Stray zero-width spaces are common in copied prose; they matter
		// in files an agent obeys or code a human reviews.
		sev := finding.Info
		switch {
		case isAgentInstructionFile(file):
			sev = finding.Medium
		case scriptExts[ext(file)]:
			sev = finding.Low
		}
		out = append(out, newFinding("PF603", sev, finding.TriggerNone, file, zw.line,
			fmt.Sprintf("%d zero-width characters are hidden in the text", zw.count)))
	}
	return out
}
