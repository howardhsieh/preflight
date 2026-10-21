package detect

import (
	"fmt"
	"path"
	"strings"

	"github.com/howardhsieh/preflight/internal/finding"
)

func detectGit(c *Context) []finding.Finding {
	var out []finding.Finding
	for _, f := range c.Files {
		switch {
		case f.Path == ".gitmodules":
			out = append(out, gitmodules(c, f.Path)...)
		case path.Base(f.Path) == ".gitattributes":
			out = append(out, gitattributes(c, f.Path)...)
		case strings.HasPrefix(f.Path, ".husky/") && !strings.HasPrefix(f.Path, ".husky/_/"):
			fd := newFinding("PF402", finding.Low, finding.TriggerGit, f.Path, 0,
				"Husky git hook is activated by npm install and runs on git commands")
			fd.Targets = []string{f.Path}
			out = append(out, fd)
		}
	}
	return out
}

func gitmodules(c *Context, file string) []finding.Finding {
	data, ok := c.Read(file)
	if !ok {
		return nil
	}
	var out []finding.Finding
	for i, raw := range strings.Split(string(data), "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(raw), "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch {
		case key == "url" && (strings.HasPrefix(val, "ext::") || strings.HasPrefix(val, "-")):
			fd := newFinding("PF401", finding.High, finding.TriggerGit, file, i+1,
				"Submodule URL can make git run a command")
			fd.Evidence = truncate(val, 200)
			out = append(out, fd)
		case key == "url" && strings.HasPrefix(val, "file://"):
			fd := newFinding("PF401", finding.Medium, finding.TriggerGit, file, i+1,
				"Submodule is cloned from a local file:// path")
			fd.Evidence = truncate(val, 200)
			out = append(out, fd)
		case key == "path" && strings.Contains("/"+strings.ToLower(val)+"/", "/.git/"):
			fd := newFinding("PF401", finding.High, finding.TriggerGit, file, i+1,
				fmt.Sprintf("Submodule path %q reaches into a .git directory", val))
			out = append(out, fd)
		}
	}
	return out
}

func gitattributes(c *Context, file string) []finding.Finding {
	data, ok := c.Read(file)
	if !ok {
		return nil
	}
	var out []finding.Finding
	for i, l := range strings.Split(string(data), "\n") {
		for _, attr := range strings.Fields(l) {
			name, val, ok := strings.Cut(attr, "=")
			if !ok || (name != "filter" && name != "diff") || val == "lfs" {
				continue
			}
			out = append(out, newFinding("PF403", finding.Low, finding.TriggerGit, file, i+1,
				fmt.Sprintf("Requests custom %s driver %q (only runs if your git config defines it)", name, val)))
		}
	}
	return out
}
