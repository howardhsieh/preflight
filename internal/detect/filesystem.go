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

type magicType struct {
	ext string
	ok  func([]byte) bool
}

// magicTypes lists the signatures a file must start with to match its
// extension. Order matters only for naming what a mismatched file really is.
var magicTypes = []magicType{
	{".png", hasPrefix("\x89PNG\r\n\x1a\n")},
	{".jpg", hasPrefix("\xff\xd8\xff")},
	{".jpeg", hasPrefix("\xff\xd8\xff")},
	{".gif", hasPrefix("GIF87a", "GIF89a")},
	{".ico", hasPrefix("\x00\x00\x01\x00", "\x89PNG")},
	{".bmp", hasPrefix("BM")},
	{".webp", func(h []byte) bool { return len(h) >= 12 && string(h[:4]) == "RIFF" && string(h[8:12]) == "WEBP" }},
	{".woff", hasPrefix("wOFF")},
	{".woff2", hasPrefix("wOF2")},
	{".ttf", hasPrefix("\x00\x01\x00\x00", "true", "ttcf", "OTTO")},
	{".otf", hasPrefix("OTTO", "\x00\x01\x00\x00")},
	{".pdf", hasPrefix("%PDF")},
	{".zip", hasPrefix("PK\x03\x04", "PK\x05\x06")},
	{".gz", hasPrefix("\x1f\x8b")},
	{".wasm", hasPrefix("\x00asm")},
	{".mp4", func(h []byte) bool { return len(h) >= 8 && string(h[4:8]) == "ftyp" }},
}

var magicByExt = func() map[string]func([]byte) bool {
	m := make(map[string]func([]byte) bool, len(magicTypes))
	for _, t := range magicTypes {
		m[t.ext] = t.ok
	}
	return m
}()

// actualType names the media type a header really has, or "".
func actualType(head []byte) string {
	for _, t := range magicTypes {
		if t.ok(head) {
			return strings.TrimPrefix(t.ext, ".")
		}
	}
	return ""
}

// isLFSPointer recognises a Git LFS pointer, which is what a clone without
// LFS smudging leaves in place of a large binary.
func isLFSPointer(h []byte) bool {
	return bytes.HasPrefix(h, []byte("version https://git-lfs.github.com/spec/"))
}

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
		if isLFSPointer(head) {
			continue // the real content was never fetched
		}
		if want, ok := magicByExt[e]; ok && !want(head) {
			out = append(out, disguised(c, f.Path, e, head)...)
			continue
		}
		if isNative(head) {
			// Committed binaries are a smell, not an attack by themselves;
			// a trigger that runs one is reported as a chain.
			out = append(out, newFinding("PF802", finding.Low, finding.TriggerNone, f.Path, 0,
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
		lower := bytes.ToLower(bytes.TrimSpace(head))
		if bytes.HasPrefix(lower, []byte("<!doctype html")) || bytes.HasPrefix(lower, []byte("<html")) {
			// A web page saved where a binary should be: a broken download,
			// not something a trigger can execute.
			return []finding.Finding{newFinding("PF801", finding.Low, finding.TriggerNone, file, 0,
				fmt.Sprintf("HTML page saved with a %s extension", e))}
		}
		if looksLikeCode(data) {
			fd := newFinding("PF801", finding.Critical, finding.TriggerNone, file, 0,
				fmt.Sprintf("Script code disguised as a %s file", e))
			fd.Evidence = truncate(string(head), 120)
			// Run the script heuristics too, since the extension hid it from them.
			return append([]finding.Finding{fd}, analyzeScript(file, data)...)
		}
		trimmed := bytes.TrimSpace(head)
		switch {
		case bytes.HasPrefix(trimmed, []byte("<svg")) || bytes.HasPrefix(trimmed, []byte("<?xml")):
			return []finding.Finding{newFinding("PF801", finding.Info, finding.TriggerNone, file, 0,
				fmt.Sprintf("File is really SVG/XML, not a %s", e))}
		case isTestFile(file):
			// Reference outputs and fixtures routinely borrow media extensions.
			return []finding.Finding{newFinding("PF801", finding.Info, finding.TriggerNone, file, 0,
				fmt.Sprintf("Text file with a %s extension (test data)", e))}
		}
		// Text that is not code cannot run; it is odd, not dangerous.
		return []finding.Finding{newFinding("PF801", finding.Low, finding.TriggerNone, file, 0,
			fmt.Sprintf("Text file with a %s extension", e))}
	default:
		if real := actualType(head); real != "" {
			// A PNG saved as .jpg is sloppy, not dangerous.
			return []finding.Finding{newFinding("PF801", finding.Info, finding.TriggerNone, file, 0,
				fmt.Sprintf("File is really a %s, not a %s", real, e))}
		}
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
	sev := finding.High
	if isTestFile(file) {
		sev = finding.Low // symlink handling is a common thing to test
	}
	fd := newFinding("PF803", sev, finding.TriggerNone, file, 0,
		"Symlink points outside the repository")
	fd.Evidence = target
	return fd, true
}
