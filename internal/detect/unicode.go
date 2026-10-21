package detect

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
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

// i18nPathRe marks translation resources, where right-to-left languages
// legitimately use bidirectional control characters.
var i18nPathRe = regexp.MustCompile(`(?i)(^|/)(i18n|l10n|locales?|lang|langs|languages?|translations?|messages)(/|$)`)

func isI18nPath(p string) bool { return i18nPathRe.MatchString(path.Dir(p) + "/") }

// isMarkup catches XML files with code-like extensions, such as Qt's
// translation .ts files.
func isMarkup(data []byte) bool {
	head := bytes.TrimSpace(data[:min(len(data), 64)])
	return bytes.HasPrefix(head, []byte("<?xml")) || bytes.HasPrefix(head, []byte("<!DOCTYPE"))
}

var dataExts = map[string]bool{".txt": true, ".json": true, ".csv": true, ".tsv": true, ".yaml": true, ".yml": true, ".xml": true}

var lettersOnly = regexp.MustCompile(`^[a-z]+$`)

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

const (
	blackFlag = 0x1F3F4 // 🏴, the base of subdivision flags such as 🏴󠁧󠁢󠁥󠁮󠁧󠁿
	tagCancel = 0xE007F
)

func isTag(r rune) bool { return r >= 0xE0000 && r <= 0xE007F }

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
	inFlag := false // inside a 🏴 + tag sequence, which is a legitimate emoji
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		next, _ := utf8.DecodeRune(data[i+size:])
		switch {
		case r == '\n':
			line++
		case isTag(r):
			if prev == blackFlag {
				inFlag = true
			}
			if inFlag {
				if r == tagCancel {
					inFlag = false
				}
				break
			}
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
		decoded := hidden.String()
		// Smuggled instructions decode to words. A handful of tag letters
		// (an unlisted subdivision flag) or bare tag controls do not.
		sev := finding.Critical
		switch {
		case len(decoded) < 6 || (len(decoded) <= 8 && lettersOnly.MatchString(decoded)):
			sev = finding.Low
		case isTestFile(file):
			sev = finding.Medium // test suites for tag stripping contain tags on purpose
		case dataExts[ext(file)]:
			sev = finding.High // string corpora and unicode data tables
		}
		fd := newFinding("PF601", sev, finding.TriggerNone, file, tags.line,
			fmt.Sprintf("%d invisible Unicode Tag characters hide text from humans but not from AI models", tags.count))
		if decoded != "" {
			fd.Evidence = "decoded: " + truncate(decoded, 200)
		}
		out = append(out, fd)
	}
	if bidi.count > 0 {
		// Trojan Source needs the characters inside code a human reviews.
		// Right-to-left resource files, prose and bundles use them legitimately.
		sev := finding.High
		switch {
		case isI18nPath(file) || !scriptExts[ext(file)] || isMarkup(data) || isBundled(file) || isMinified(data):
			sev = finding.Low
		case isTestFile(file):
			sev = finding.Medium
		}
		out = append(out, newFinding("PF602", sev, finding.TriggerNone, file, bidi.line,
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
