package detect

import (
	"bytes"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/howardhsieh/preflight/internal/finding"
)

func hasPrefix(prefixes ...string) func([]byte) bool {
	return func(h []byte) bool {
		for _, p := range prefixes {
			if bytes.HasPrefix(h, []byte(p)) {
				return true
			}
		}
		return false
	}
}

// magicByExt checks that a file starts with the signature its extension claims.
var magicByExt = map[string]func([]byte) bool{
	".png":   hasPrefix("\x89PNG\r\n\x1a\n"),
	".jpg":   hasPrefix("\xff\xd8\xff"),
	".jpeg":  hasPrefix("\xff\xd8\xff"),
	".gif":   hasPrefix("GIF87a", "GIF89a"),
	".ico":   hasPrefix("\x00\x00\x01\x00", "\x89PNG"),
	".bmp":   hasPrefix("BM"),
	".webp":  func(h []byte) bool { return len(h) >= 12 && string(h[:4]) == "RIFF" && string(h[8:12]) == "WEBP" },
	".woff":  hasPrefix("wOFF"),
	".woff2": hasPrefix("wOF2"),
	".ttf":   hasPrefix("\x00\x01\x00\x00", "true", "ttcf", "OTTO"),
	".otf":   hasPrefix("OTTO", "\x00\x01\x00\x00"),
	".pdf":   hasPrefix("%PDF"),
	".zip":   hasPrefix("PK\x03\x04", "PK\x05\x06"),
	".gz":    hasPrefix("\x1f\x8b"),
	".wasm":  hasPrefix("\x00asm"),
	".mp4":   func(h []byte) bool { return len(h) >= 8 && string(h[4:8]) == "ftyp" },
}

var nativeExts = map[string]bool{".exe": true, ".dll": true, ".so": true, ".dylib": true, ".node": true, ".bin": true, ".o": true, ".a": true}

func isNative(h []byte) bool {
	return hasPrefix("\x7fELF", "\xfe\xed\xfa\xce", "\xfe\xed\xfa\xcf", "\xce\xfa\xed\xfe", "\xcf\xfa\xed\xfe", "MZ")(h) ||
		(bytes.HasPrefix(h, []byte("\xca\xfe\xba\xbe")) && len(h) > 7 && h[7] < 20) // fat Mach-O, not a Java class
}

func looksText(h []byte) bool {
	if len(h) == 0 {
		return false
	}
	printable := 0
	for _, c := range h {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f) || c >= 0x80 {
			printable++
		}
	}
	return !isBinary(h) && float64(printable)/float64(len(h)) > 0.95
}

var codeMarkers = [][]byte{
	[]byte("function"), []byte("require("), []byte("=>"), []byte("import "), []byte("eval("),
	[]byte("const "), []byte("var "), []byte("#!/"), []byte("<script"), []byte("exec("),
}

func looksLikeCode(b []byte) bool {
	hits := 0
	for _, m := range codeMarkers {
		if bytes.Contains(b, m) {
			hits++
		}
	}
	return hits >= 2
}

func detectFilesystem(c *Context) []finding.Finding {
	var out []finding.Finding
	for _, f := range c.Files {
		if f.LinkTarget != "" {
			if fd, ok := symlinkEscape(f.Path, f.LinkTarget); ok {
				out = append(out, fd)
			}
			continue
		}
		if !f.Mode.IsRegular() || f.Size == 0 {
			continue
		}
		e := ext(f.Path)
		head := c.Head(f.Path, 512)
		if want, ok := magicByExt[e]; ok && !want(head) {
			out = append(out, disguised(c, f.Path, e, head)...)
			continue
		}
		if isNative(head) {
			sev := finding.Medium
			if nativeExts[e] {
				sev = finding.Low
			}
			out = append(out, newFinding("PF802", sev, finding.TriggerNone, f.Path, 0,
				"Compiled executable committed to the repository"))
		}
	}
	return out
}

func disguised(c *Context, file, e string, head []byte) []finding.Finding {
	switch {
	case isNative(head):
		return []finding.Finding{newFinding("PF801", finding.Critical, finding.TriggerNone, file, 0,
			fmt.Sprintf("Compiled executable disguised with a %s extension", e))}
	case looksText(head):
		data, _ := c.Read(file)
		if looksLikeCode(data) {
			fd := newFinding("PF801", finding.Critical, finding.TriggerNone, file, 0,
				fmt.Sprintf("Script code disguised as a %s file", e))
			fd.Evidence = truncate(string(head), 120)
			// Run the script heuristics too, since the extension hid it from them.
			return append([]finding.Finding{fd}, analyzeScript(file, data)...)
		}
		return []finding.Finding{newFinding("PF801", finding.High, finding.TriggerNone, file, 0,
			fmt.Sprintf("Text file disguised as a %s file", e))}
	default:
		return []finding.Finding{newFinding("PF801", finding.Low, finding.TriggerNone, file, 0,
			fmt.Sprintf("Contents do not match the %s extension", e))}
	}
}

func symlinkEscape(file, target string) (finding.Finding, bool) {
	t := filepath.ToSlash(target)
	joined := path.Join(path.Dir(file), t)
	if !path.IsAbs(t) && !filepath.IsAbs(target) && joined != ".." && !strings.HasPrefix(joined, "../") {
		return finding.Finding{}, false
	}
	fd := newFinding("PF803", finding.High, finding.TriggerNone, file, 0,
		"Symlink points outside the repository")
	fd.Evidence = target
	return fd, true
}
