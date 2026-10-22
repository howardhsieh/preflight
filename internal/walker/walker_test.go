package walker

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func paths(r *Result) map[string]File {
	m := map[string]File{}
	for _, f := range r.Files {
		m[f.Path] = f
	}
	return m
}

func TestWalkBasicsAndExclude(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.js", "x")
	write(t, root, "sub/b.js", "x")
	write(t, root, ".git/config", "x") // always skipped
	write(t, root, "node_modules/dep/c.js", "x")

	r, err := Walk(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	p := paths(r)
	if _, ok := p["a.js"]; !ok {
		t.Error("missing a.js")
	}
	if _, ok := p[".git/config"]; ok {
		t.Error(".git should always be skipped")
	}
	if _, ok := p["node_modules/dep/c.js"]; !ok {
		t.Error("node_modules is listed unless excluded")
	}

	r, _ = Walk(root, Options{Exclude: []string{"node_modules", "sub/*.js"}})
	p = paths(r)
	if _, ok := p["node_modules/dep/c.js"]; ok {
		t.Error("node_modules exclude ignored")
	}
	if _, ok := p["sub/b.js"]; ok {
		t.Error("glob exclude ignored")
	}
}

func TestWalkDoesNotFollowSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privilege on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	write(t, outside, "secret.js", "eval(1)")
	write(t, root, "keep.js", "x")
	// A symlink to a directory outside the repo, and a self-loop.
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skip("symlinks unsupported:", err)
	}
	if err := os.Symlink(filepath.Join(root, "loop"), filepath.Join(root, "loop")); err != nil {
		t.Skip(err)
	}
	r, err := Walk(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Files {
		if f.Path == "link/secret.js" {
			t.Fatal("walker followed a directory symlink out of the repo")
		}
		if f.Path == "link" && f.LinkTarget == "" {
			t.Error("symlink recorded without its target")
		}
	}
}

func TestWalkMaxFiles(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 10; i++ {
		write(t, root, filepath.Join("d", string(rune('a'+i))+".js"), "x")
	}
	r, err := Walk(root, Options{MaxFiles: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || len(r.Files) != 3 {
		t.Errorf("MaxFiles=3: got %d files, truncated=%v", len(r.Files), r.Truncated)
	}
}
