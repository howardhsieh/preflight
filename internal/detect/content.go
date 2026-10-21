package detect

import (
	"bytes"
	"fmt"
	"math"
	"path"
	"regexp"
	"strings"

	"github.com/howardhsieh/preflight/internal/finding"
	"github.com/howardhsieh/preflight/internal/walker"
)

var scriptExts = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true, ".tsx": true, ".mts": true, ".cts": true,
	".py": true, ".pyw": true, ".sh": true, ".bash": true, ".zsh": true, ".ps1": true, ".psm1": true,
	".bat": true, ".cmd": true, ".rb": true, ".php": true, ".pl": true, ".vbs": true,
}

var (
	offscreenRe = regexp.MustCompile(`[ \t]{150,}\S`)
	execCallRe  = regexp.MustCompile(`(\beval|\bexec|\bexecSync|\bspawn|\bspawnSync|\bexecFile|\bFunction|\bsystem|\bpopen|Invoke-Expression|\biex)\s*\(`)
	decodeRe    = regexp.MustCompile(`(\batob\s*\(|Buffer\.from\([^)]*['"](base64|hex)['"]|b64decode|base64\s+(-d|--decode)|FromBase64String|String\.fromCharCode|codecs\.decode|bytes\.fromhex|unhexlify|zlib\.decompress|marshal\.loads)`)
	networkRe   = regexp.MustCompile(`(\bfetch\s*\(|\baxios\b|https?\.(get|request)\s*\(|XMLHttpRequest|require\(\s*['"](node-fetch|request|got)['"]\s*\)|urllib\.request|urlopen|requests\.(get|post)|Invoke-WebRequest|\bcurl\s|\bwget\s)`)
	dynExecRe   = regexp.MustCompile(`(\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(\s*['"]require|vm\.runIn\w*\(|\bexec\s*\(\s*(compile|requests|urllib|response|r\.text|res\b))`)
	base64Re    = regexp.MustCompile(`[A-Za-z0-9+/]{400,}={0,2}`)
	hexRe       = regexp.MustCompile(`[0-9a-fA-F]{600,}`)
	payloadRe   = regexp.MustCompile(`(?i)(api\.npoint\.io|jsonkeeper\.com|pastebin\.com/raw|paste\.ee/r/|rentry\.co/[^\s'"]+/raw|hastebin\.com|transfer\.sh|bashupload\.com|\.trycloudflare\.com|ngrok(-free)?\.(io|app))`)
	ipURLRe     = regexp.MustCompile(`https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
)

// isScriptFile reports whether f should get content analysis.
func isScriptFile(c *Context, f walker.File) bool {
	if !f.Mode.IsRegular() || f.Size == 0 {
		return false
	}
	if scriptExts[ext(f.Path)] || underDir(f.Path, ".husky") || underDir(f.Path, ".githooks") || underDir(f.Path, ".claude/hooks") {
		return true
	}
	base := path.Base(f.Path)
	if strings.HasPrefix(base, ".env") {
		return true
	}
	if ext(f.Path) == "" {
		return bytes.HasPrefix(c.Head(f.Path, 2), []byte("#!"))
	}
	return false
}

// remoteExecWindow is how many bytes around a dynamic eval a network call
// must appear in for PF703.
const remoteExecWindow = 1500

var testPathRe = regexp.MustCompile(`(?i)(^|/)(tests?|__tests__|spec|specs|fixtures?|testdata|e2e)/|[._-](test|spec)\.[a-z]+$|(^|/)test_[^/]+\.py$|(^|/)conftest\.py$`)

func isTestFile(p string) bool { return testPathRe.MatchString(p) }

// lineText returns the full line containing byte offset off.
func lineText(data []byte, off int) string {
	start := bytes.LastIndexByte(data[:off], '\n') + 1
	end := bytes.IndexByte(data[off:], '\n')
	if end < 0 {
		end = len(data)
	} else {
		end += off
	}
	return string(data[start:end])
}

// isBundled marks generated or vendored code, where long lines and inline
// data are normal.
func isBundled(p string) bool {
	base := path.Base(p)
	return strings.Contains(base, ".min.") || strings.Contains(base, "bundle.") || strings.Contains(base, ".chunk.") ||
		underDir(p, "dist") || underDir(p, "vendor") || underDir(p, "build") ||
		underDir(p, "node_modules") || strings.HasSuffix(p, ".map")
}

func detectContent(c *Context) []finding.Finding {
	var out []finding.Finding
	for _, f := range c.Files {
		if !isScriptFile(c, f) {
			continue
		}
		data, ok := c.Read(f.Path)
		if !ok || isBinary(data[:min(len(data), 8000)]) {
			continue
		}
		out = append(out, analyzeScript(f.Path, data)...)
	}
	return out
}

// analyzeScript runs the content heuristics on one file. It is also used for
// disguised files whose extension hides that they contain code.
func analyzeScript(file string, data []byte) []finding.Finding {
	var out []finding.Finding
	bundled := isBundled(file)

	offscreenDone, decodeDone := false, false
	lineNo := 0
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		lineNo++
		if !offscreenDone {
			if loc := offscreenRe.FindIndex(line); loc != nil {
				fd := newFinding("PF701", finding.High, finding.TriggerNone, file, lineNo,
					fmt.Sprintf("Code is hidden after %d characters of whitespace, past the edge of the editor", loc[1]-loc[0]-1))
				fd.Evidence = truncate(string(line[loc[1]-1:]), 160)
				out = append(out, fd)
				offscreenDone = true
			}
		}
		if !decodeDone && execCallRe.Match(line) && decodeRe.Match(line) {
			sev := finding.High
			if bundled || isTestFile(file) {
				sev = finding.Medium
			}
			fd := newFinding("PF702", sev, finding.TriggerNone, file, lineNo,
				"Decodes data and executes it on the same line")
			fd.Evidence = truncate(string(line), 160)
			out = append(out, fd)
			decodeDone = true
		}
	}

	// A network call and a dynamic eval anywhere in the same file is too
	// loose (test suites mention both constantly); require them to be close.
	for _, loc := range dynExecRe.FindAllIndex(data, -1) {
		window := data[max(0, loc[0]-remoteExecWindow):min(len(data), loc[1]+remoteExecWindow)]
		if !networkRe.Match(window) {
			continue
		}
		sev := finding.High
		if bundled || isTestFile(file) {
			sev = finding.Medium
		}
		fd := newFinding("PF703", sev, finding.TriggerNone, file, lineAt(data, loc[0]),
			"Downloads data and evaluates it as code")
		fd.Evidence = truncate(lineText(data, loc[0]), 160)
		out = append(out, fd)
		break
	}

	if !bundled {
		if loc := findEncodedBlob(data); loc != nil {
			sev := finding.Medium
			if isTestFile(file) {
				sev = finding.Low // fixtures are usually encoded sample data
			}
			fd := newFinding("PF704", sev, finding.TriggerNone, file, lineAt(data, loc[0]),
				fmt.Sprintf("Embeds a %d-character encoded blob", loc[1]-loc[0]))
			fd.Evidence = truncate(string(data[loc[0]:loc[0]+60]), 80)
			out = append(out, fd)
		}
	}

	if loc := payloadRe.FindIndex(data); loc != nil {
		fd := newFinding("PF705", finding.Medium, finding.TriggerNone, file, lineAt(data, loc[0]),
			"References a paste/JSON hosting service often used to stage malware payloads")
		fd.Evidence = string(data[loc[0]:loc[1]])
		out = append(out, fd)
	}

	for _, m := range ipURLRe.FindAllSubmatchIndex(data, -1) {
		if isNonRoutableIP(string(data[m[2]:m[3]])) {
			continue
		}
		// Raw IPs are a weak signal on their own: tests and docs use them
		// constantly. They mostly matter as part of a chain.
		sev := finding.Low
		if isTestFile(file) || !scriptExts[ext(file)] {
			sev = finding.Info
		}
		fd := newFinding("PF706", sev, finding.TriggerNone, file, lineAt(data, m[0]),
			"Contacts a public IP address directly")
		fd.Evidence = string(data[m[0]:m[1]])
		out = append(out, fd)
		break
	}
	return out
}

// mediaBase64Prefixes are the encodings of common file headers: PNG, JPEG,
// GIF, ZIP/JAR/DOCX, gzip, PDF, RIFF (WebP/WAV), WOFF2 and ICO.
var mediaBase64Prefixes = []string{"iVBOR", "/9j/", "R0lGOD", "UEsDB", "H4sI", "JVBER", "UklGR", "d09GM", "AAABAA"}

func findEncodedBlob(data []byte) []int {
	for _, loc := range base64Re.FindAllIndex(data, -1) {
		before := data[max(0, loc[0]-160):loc[0]]
		if bytes.Contains(before, []byte("data:")) || bytes.Contains(before, []byte("base64,")) ||
			bytes.Contains(before, []byte("sourceMappingURL")) {
			continue // inline images, fonts and source maps
		}
		blob := data[loc[0]:loc[1]]
		if hasAnyPrefix(blob, mediaBase64Prefixes) {
			continue
		}
		if entropy(blob) >= 4.5 {
			return loc
		}
	}
	return hexRe.FindIndex(data)
}

func hasAnyPrefix(b []byte, prefixes []string) bool {
	for _, p := range prefixes {
		if bytes.HasPrefix(b, []byte(p)) {
			return true
		}
	}
	return false
}

func entropy(b []byte) float64 {
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	var h float64
	for _, n := range counts {
		if n == 0 {
			continue
		}
		p := float64(n) / float64(len(b))
		h -= p * math.Log2(p)
	}
	return h
}

// wellKnownIPs are public resolvers and the example.com address, which
// appear in docs and tests far more often than in malware.
var wellKnownIPs = map[string]bool{
	"8.8.8.8": true, "8.8.4.4": true, "1.1.1.1": true, "1.0.0.1": true, "9.9.9.9": true,
	"93.184.216.34": true, "93.184.215.14": true, "255.255.255.255": true,
}

// isNonRoutableIP reports private, loopback, link-local, carrier-grade NAT,
// documentation (RFC 5737) and well-known public addresses.
func isNonRoutableIP(ip string) bool {
	if wellKnownIPs[ip] {
		return true
	}
	var a, b, c, d int
	if n, _ := fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d); n != 4 {
		return true
	}
	switch {
	case a == 0, a == 10, a == 127:
		return true
	case a == 100 && b >= 64 && b <= 127:
		return true
	case a == 169 && b == 254:
		return true
	case a == 172 && b >= 16 && b <= 31:
		return true
	case a == 192 && (b == 168 || (b == 0 && (c == 2 || c == 0))):
		return true
	case a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)):
		return true
	case a == 203 && b == 0 && c == 113:
		return true
	case a >= 224:
		return true
	}
	return false
}
