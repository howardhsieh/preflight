// Package walker lists the files in a repository without following symlinks
// or reading file contents.
package walker

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// File is one non-directory entry in the repository.
type File struct {
	Path       string // slash-separated, relative to the root
	Size       int64
	Mode       fs.FileMode
	LinkTarget string // set for symlinks
}

// Options controls a walk.
type Options struct {
	// Exclude holds paths or glob patterns (matched against the relative path
	// and against the base name) to skip.
	Exclude  []string
	MaxFiles int
}

// Result is the outcome of a walk.
type Result struct {
	Files     []File
	Truncated bool
}

// DefaultMaxFiles bounds the walk so a hostile repository cannot exhaust memory.
const DefaultMaxFiles = 200000

// Walk lists every file under root. Symlinks are recorded, never followed.
func Walk(root string, opt Options) (*Result, error) {
	if opt.MaxFiles <= 0 {
		opt.MaxFiles = DefaultMaxFiles
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}

	res := &Result{}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err
			}
			return nil // unreadable entries are skipped
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if d.Name() == ".git" || excluded(rel, opt.Exclude) {
				return filepath.SkipDir
			}
			return nil
		}
		if excluded(rel, opt.Exclude) {
			return nil
		}
		if len(res.Files) >= opt.MaxFiles {
			res.Truncated = true
			return filepath.SkipAll
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		f := File{Path: rel, Size: fi.Size(), Mode: fi.Mode()}
		if fi.Mode()&fs.ModeSymlink != 0 {
			f.LinkTarget, _ = os.Readlink(p)
		}
		res.Files = append(res.Files, f)
		return nil
	})
	return res, err
}

func excluded(rel string, patterns []string) bool {
	for _, pat := range patterns {
		pat = strings.TrimSuffix(filepath.ToSlash(strings.TrimSpace(pat)), "/")
		pat = strings.TrimPrefix(pat, "./")
		if pat == "" {
			continue
		}
		if rel == pat || strings.HasPrefix(rel, pat+"/") {
			return true
		}
		if ok, _ := path.Match(pat, rel); ok {
			return true
		}
		if ok, _ := path.Match(pat, path.Base(rel)); ok {
			return true
		}
	}
	return false
}
