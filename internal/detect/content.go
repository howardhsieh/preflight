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
	ipURLRe     = regexp.MustCompile(`https?://(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}`)
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

// isBundled marks generated or vendored code, where long lines and inline
// data are normal.
func isBundled(p string) bool {
	return strings.Contains(p, ".min.") || underDir(p, "dist") || underDir(p, "vendor") ||
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
			fd := newFinding("PF702", finding.High, finding.TriggerNone, file, lineNo,
				"Decodes data and executes it on the same line")
			fd.Evidence = truncate(string(line), 160)
			out = append(out, fd)
			decodeDone = true
		}
	}

	if networkRe.Match(data) {
		if loc := dynExecRe.FindIndex(data); loc != nil {
			sev := finding.High
			if bundled {
				sev = finding.Medium
			}
			out = append(out, newFinding("PF703", sev, finding.TriggerNone, file, lineAt(data, loc[0]),
				"Downloads data and evaluates it as code"))
		}
	}

	if !bundled {
		if loc := findEncodedBlob(data); loc != nil {
			fd := newFinding("PF704", finding.Medium, finding.TriggerNone, file, lineAt(data, loc[0]),
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
		if isPrivateIPPrefix(string(data[m[2]:m[3]]), string(data[m[4]:m[5]])) {
			continue
		}
		fd := newFinding("PF706", finding.Medium, finding.TriggerNone, file, lineAt(data, m[0]),
			"Contacts a public IP address directly")
		fd.Evidence = string(data[m[0]:m[1]])
		out = append(out, fd)
		break
	}
	return out
}

func findEncodedBlob(data []byte) []int {
	for _, loc := range base64Re.FindAllIndex(data, -1) {
		if bytes.Contains(data[max(0, loc[0]-40):loc[0]], []byte("data:")) {
			continue // inline images and fonts
		}
		if entropy(data[loc[0]:loc[1]]) >= 4.5 {
			return loc
		}
	}
	return hexRe.FindIndex(data)
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

func isPrivateIPPrefix(a, b string) bool {
	switch a {
	case "0", "10", "127":
		return true
	case "192":
		return b == "168"
	case "169":
		return b == "254"
	case "172":
		n := 0
		fmt.Sscan(b, &n)
		return n >= 16 && n <= 31
	}
	return false
}
