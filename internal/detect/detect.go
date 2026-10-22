// Package detect holds the individual checks preflight runs against a
// repository. Detectors only read files; nothing in a scanned repository is
// ever executed.
package detect

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/howardhsieh/preflight/internal/finding"
	"github.com/howardhsieh/preflight/internal/walker"
)

// deadlineCheckEvery is how often the per-file loops test the context, so the
// check itself costs almost nothing.
const deadlineCheckEvery = 64

// MaxReadBytes caps how much of any single file is read.
const MaxReadBytes = 4 << 20

// Context gives detectors read-only access to the repository being scanned.
type Context struct {
	Root     string
	Files    []walker.File
	index    map[string]int
	executed map[string]bool
	ctx      context.Context
}

// NewContext indexes the walked files of root.
func NewContext(root string, files []walker.File) *Context {
	idx := make(map[string]int, len(files))
	for i, f := range files {
		idx[f.Path] = i
	}
	return &Context{Root: root, Files: files, index: idx, executed: map[string]bool{}}
}

// SetExecuted records the files that a trigger (a folderOpen task, an install
// script, an agent hook, …) would run. Content detectors use this to avoid
// discounting a payload just because it sits in dist/ or tests/.
func (c *Context) SetExecuted(paths []string) {
	for _, p := range paths {
		c.executed[p] = true
	}
}

// IsExecuted reports whether a trigger would run this file.
func (c *Context) IsExecuted(p string) bool { return c.executed[p] }

// SetContext attaches a context whose cancellation or deadline the per-file
// detector loops honour, so a hostile repository cannot make a scan run forever.
func (c *Context) SetContext(ctx context.Context) { c.ctx = ctx }

// Expired reports whether the attached context is done.
func (c *Context) Expired() bool { return c.ctx != nil && c.ctx.Err() != nil }

// Lookup returns the file at the given repository-relative path.
func (c *Context) Lookup(p string) (walker.File, bool) {
	i, ok := c.index[p]
	if !ok {
		return walker.File{}, false
	}
	return c.Files[i], true
}

// Read returns up to MaxReadBytes of a regular file. Symlinks are never read.
func (c *Context) Read(p string) ([]byte, bool) {
	return c.readN(p, MaxReadBytes)
}

// Head returns the first n bytes of a regular file.
func (c *Context) Head(p string, n int) []byte {
	b, _ := c.readN(p, int64(n))
	return b
}

func (c *Context) readN(p string, n int64) ([]byte, bool) {
	f, ok := c.Lookup(p)
	if !ok || !f.Mode.IsRegular() {
		return nil, false
	}
	fh, err := os.Open(filepath.Join(c.Root, filepath.FromSlash(p)))
	if err != nil {
		return nil, false
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, n))
	if err != nil {
		return nil, false
	}
	return b, true
}

// Detector is one family of checks.
type Detector struct {
	Name string
	Run  func(*Context) []finding.Finding
}

// TriggerDetectors parse configuration and record which files would run.
// They are executed first so that content detectors know a file's targets.
func TriggerDetectors() []Detector {
	return []Detector{
		{"vscode", detectVSCode},
		{"devcontainer", detectDevcontainer},
		{"packages", detectPackages},
		{"git", detectGit},
		{"agents", detectAgents},
	}
}

// ContentDetectors analyze file contents, using Context.IsExecuted.
func ContentDetectors() []Detector {
	return []Detector{
		{"unicode", detectUnicode},
		{"content", detectContent},
		{"filesystem", detectFilesystem},
	}
}

// All returns every detector in a stable order.
func All() []Detector {
	return append(TriggerDetectors(), ContentDetectors()...)
}

// SplitVirtualenvs removes the contents of Python virtualenvs (directories
// holding pyvenv.cfg) from files and reports each one once. Local virtualenvs
// are common and full of symlinks and native libraries; scanning them only
// produces noise.
func SplitVirtualenvs(files []walker.File) ([]walker.File, []finding.Finding) {
	var roots []string
	for _, f := range files {
		if path.Base(f.Path) == "pyvenv.cfg" {
			roots = append(roots, dirOf(f.Path))
		}
	}
	if len(roots) == 0 {
		return files, nil
	}
	var kept []walker.File
outer:
	for _, f := range files {
		for _, r := range roots {
			if r == "" || strings.HasPrefix(f.Path, r+"/") {
				continue outer
			}
		}
		kept = append(kept, f)
	}
	var out []finding.Finding
	for _, r := range roots {
		fd := newFinding("PF106", finding.Low, finding.TriggerIDESettings, path.Join(r, "pyvenv.cfg"), 0,
			"Python virtualenv: VS Code may auto-select its interpreter. Expected if you created it; "+
				"highly unusual in a freshly cloned repository")
		out = append(out, fd)
	}
	return kept, out
}

func newFinding(id string, sev finding.Severity, trig finding.Trigger, file string, line int, msg string) finding.Finding {
	r, ok := finding.RuleByID(id)
	if !ok {
		panic(fmt.Sprintf("detect: unknown rule %s", id))
	}
	return finding.Finding{RuleID: id, Rule: r.Name, Severity: sev, Trigger: trig, File: file, Line: line, Message: msg}
}

// lineOf returns the 1-based line of the first occurrence of needle, or 0.
func lineOf(data []byte, needle string) int {
	i := bytes.Index(data, []byte(needle))
	if i < 0 {
		return 0
	}
	return lineAt(data, i)
}

func lineAt(data []byte, off int) int {
	return bytes.Count(data[:off], []byte{'\n'}) + 1
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func ext(p string) string { return strings.ToLower(path.Ext(p)) }

// dirOf returns the directory of p, using "" for the repository root.
func dirOf(p string) string {
	d := path.Dir(p)
	if d == "." {
		return ""
	}
	return d
}

func underDir(p, dir string) bool {
	return strings.HasPrefix(p, dir+"/") || strings.Contains(p, "/"+dir+"/")
}

var pathVarPrefixes = []string{
	"${workspaceFolder}/", "${workspaceRoot}/", "${containerWorkspaceFolder}/",
	"${localWorkspaceFolder}/", "$CLAUDE_PROJECT_DIR/", "${CLAUDE_PROJECT_DIR}/",
	"$CLAUDE_PLUGIN_ROOT/", "${CLAUDE_PLUGIN_ROOT}/",
}

// commandTargets returns repository files referenced by a command line,
// resolved relative to baseDir and to the repository root.
func commandTargets(c *Context, baseDir, cmd string) []string {
	cmd = strings.NewReplacer(`"`, "", "'", "").Replace(cmd)
	for _, p := range pathVarPrefixes {
		cmd = strings.ReplaceAll(cmd, p, "")
	}
	split := func(r rune) bool { return unicode.IsSpace(r) || strings.ContainsRune(";&|()<>=`,", r) }

	seen := map[string]bool{}
	var out []string
	for _, tok := range strings.FieldsFunc(cmd, split) {
		if strings.HasPrefix(tok, "-") || strings.Contains(tok, "://") || path.IsAbs(tok) || strings.HasPrefix(tok, "$") {
			continue
		}
		for _, base := range []string{baseDir, ""} {
			cand := path.Join(base, tok)
			if cand == "." || strings.HasPrefix(cand, "..") {
				continue
			}
			if hit := resolveFile(c, cand); hit != "" && !seen[hit] {
				seen[hit] = true
				out = append(out, hit)
				break
			}
		}
	}
	return out
}

// resolveExts are the extensions a bare command target may resolve to, across
// the languages the threat model covers (not only Node).
var resolveExts = []string{"", ".js", ".cjs", ".mjs", ".ts", ".tsx", ".py", ".sh", ".bash", ".rb", ".pl", ".ps1",
	"/index.js", "/index.mjs", "/index.ts", "/__main__.py", "/main.py"}

// resolveFile mirrors how interpreters and shells find a script from a bare
// name: the path itself, then with a language extension, then a package entry
// point.
func resolveFile(c *Context, p string) string {
	for _, suffix := range resolveExts {
		cand := p + suffix
		if f, ok := c.Lookup(cand); ok && !f.Mode.IsDir() {
			return cand
		}
	}
	return ""
}

// str returns v as a string when it is one (or an object with a "value").
func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		if s, ok := t["value"].(string); ok {
			return s
		}
	}
	return ""
}

// commandString flattens the string / array / object command forms used by
// tasks.json and devcontainer.json.
func commandString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			if s := str(e); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	case map[string]any:
		keys := sortedKeys(t)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			if s := commandString(t[k]); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ; ")
	}
	return ""
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func isBinary(head []byte) bool { return bytes.IndexByte(head, 0) >= 0 }
