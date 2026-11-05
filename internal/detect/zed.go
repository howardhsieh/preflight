package detect

import (
	"fmt"
	"path"
	"strings"

	"github.com/howardhsieh/preflight/internal/finding"
)

// Zed reads .zed/settings.json from the project and, unlike VS Code, has no
// workspace-trust prompt in front of it: a language-server binary path, an
// external formatter command or a terminal shell program named there runs
// as soon as a matching file is opened, formatted or a terminal is spawned.

// zedExecKeys are the dotted-key suffixes that name a program Zed launches.
var zedExecKeys = []string{".binary.path", ".external.command", ".shell.program", "shell.program"}

func detectZed(c *Context) []finding.Finding {
	var out []finding.Finding
	for _, f := range c.Files {
		if path.Base(f.Path) != "settings.json" || path.Base(path.Dir(f.Path)) != ".zed" {
			continue
		}
		data, doc, ok := readJSONC(c, f.Path)
		if !ok {
			continue
		}
		walkSettings("", doc, func(key string, val any) {
			leaf := key[strings.LastIndex(key, ".")+1:]
			line := lineOf(data, `"`+leaf+`"`)
			if strings.Contains(key, ".env.") && injectEnvVars[leaf] {
				fd := newFinding("PF122", finding.High, finding.TriggerIDESettings, f.Path, line,
					fmt.Sprintf("Zed settings inject %s into processes the editor starts", leaf))
				fd.Evidence = truncate(fmt.Sprint(val), 200)
				out = append(out, fd)
				return
			}
			s, ok := val.(string)
			if !ok || !hasAnySuffix(key, zedExecKeys) {
				return
			}
			var targets []string
			for _, t := range commandTargets(c, "", s) {
				if looksExecutable(c, t) {
					targets = append(targets, t)
				}
			}
			if len(targets) == 0 {
				return // a tool on PATH or in node_modules
			}
			fd := newFinding("PF121", finding.High, finding.TriggerIDESettings, f.Path, line,
				fmt.Sprintf("%s points Zed at %s inside the repository", key, targets[0]))
			fd.Evidence = truncate(s, 200)
			fd.Targets = targets
			out = append(out, fd)
		})
	}
	return out
}

func hasAnySuffix(s string, suffixes []string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}
