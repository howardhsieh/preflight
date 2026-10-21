package detect

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/howardhsieh/preflight/internal/finding"
	"github.com/howardhsieh/preflight/internal/jsonc"
)

func detectVSCode(c *Context) []finding.Finding {
	var out []finding.Finding
	for _, f := range c.Files {
		inVSCode := path.Base(path.Dir(f.Path)) == ".vscode"
		switch {
		case inVSCode && path.Base(f.Path) == "tasks.json":
			data, doc, ok := readJSONC(c, f.Path)
			if ok {
				tasks, _ := doc["tasks"].([]any)
				out = append(out, vscodeTasks(c, f.Path, data, tasks)...)
			}
		case inVSCode && path.Base(f.Path) == "settings.json":
			data, doc, ok := readJSONC(c, f.Path)
			if ok {
				out = append(out, vscodeSettings(c, f.Path, data, doc)...)
			}
		case strings.HasSuffix(f.Path, ".code-workspace"):
			data, doc, ok := readJSONC(c, f.Path)
			if !ok {
				continue
			}
			if t, ok := doc["tasks"].(map[string]any); ok {
				tasks, _ := t["tasks"].([]any)
				out = append(out, vscodeTasks(c, f.Path, data, tasks)...)
			}
			if s, ok := doc["settings"].(map[string]any); ok {
				out = append(out, vscodeSettings(c, f.Path, data, s)...)
			}
		}
	}
	return out
}

func readJSONC(c *Context, p string) ([]byte, map[string]any, bool) {
	data, ok := c.Read(p)
	if !ok {
		return nil, nil, false
	}
	var doc map[string]any
	if err := jsonc.Unmarshal(data, &doc); err != nil {
		return data, nil, false
	}
	return data, doc, true
}

func vscodeTasks(c *Context, file string, data []byte, tasks []any) []finding.Finding {
	var out []finding.Finding
	for _, raw := range tasks {
		t, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		opts, _ := t["runOptions"].(map[string]any)
		if str(opts["runOn"]) != "folderOpen" {
			continue
		}
		label := str(t["label"])
		if label == "" {
			label = str(t["taskName"])
		}
		cmd := taskCommand(t)
		line := lineOf(data, `"`+label+`"`)
		if label == "" || line == 0 {
			line = lineOf(data, "folderOpen")
		}
		fd := newFinding("PF101", finding.Critical, finding.TriggerIDEOpen, file, line,
			fmt.Sprintf("Task %q runs automatically when the folder is opened", label))
		fd.Evidence = truncate(cmd, 300)
		fd.Targets = commandTargets(c, "", cmd)
		out = append(out, fd)
	}
	return out
}

// taskCommand joins a task's command and args, including OS-specific overrides.
func taskCommand(t map[string]any) string {
	var parts []string
	add := func(m map[string]any) {
		cmd := str(m["command"])
		if cmd == "" {
			return
		}
		if args, ok := m["args"].([]any); ok {
			for _, a := range args {
				cmd += " " + str(a)
			}
		}
		parts = append(parts, cmd)
	}
	add(t)
	for _, osKey := range []string{"windows", "osx", "linux"} {
		if m, ok := t[osKey].(map[string]any); ok {
			add(m)
		}
	}
	return strings.Join(parts, " ; ")
}

var (
	execSettingRe = regexp.MustCompile(`(?i)(path|executable|executablepath|interpreter|runtime|runtimeexecutable|shell|command|binary)$`)
	injectEnvVars = map[string]bool{
		"NODE_OPTIONS": true, "LD_PRELOAD": true, "DYLD_INSERT_LIBRARIES": true, "PYTHONSTARTUP": true,
		"BASH_ENV": true, "ENV": true, "PERL5OPT": true, "RUBYOPT": true, "PROMPT_COMMAND": true,
	}
)

func vscodeSettings(c *Context, file string, data []byte, doc map[string]any) []finding.Finding {
	var out []finding.Finding
	walkSettings("", doc, func(key string, val any) {
		leaf := key[strings.LastIndex(key, ".")+1:]
		line := lineOf(data, `"`+leaf+`"`)
		switch {
		case key == "task.allowAutomaticTasks" && (val == "on" || val == true):
			out = append(out, newFinding("PF102", finding.High, finding.TriggerIDEOpen, file, line,
				"Settings set task.allowAutomaticTasks to \"on\" so auto-run tasks start without asking"))
		case strings.HasPrefix(key, "security.workspace.trust"):
			out = append(out, newFinding("PF105", finding.Medium, finding.TriggerIDESettings, file, line,
				fmt.Sprintf("Workspace settings try to change %s", key)))
		case strings.Contains(key, ".env.") && injectEnvVars[leaf]:
			fd := newFinding("PF104", finding.High, finding.TriggerIDESettings, file, line,
				fmt.Sprintf("Settings inject %s into processes VS Code starts", leaf))
			fd.Evidence = truncate(fmt.Sprint(val), 200)
			out = append(out, fd)
		default:
			s, ok := val.(string)
			if !ok || !execSettingRe.MatchString(leaf) || strings.Contains(s, "://") {
				return
			}
			var targets []string
			for _, t := range commandTargets(c, "", s) {
				if looksExecutable(c, t) {
					targets = append(targets, t)
				}
			}
			if len(targets) == 0 {
				return // a config file such as .prettierrc or pyproject.toml
			}
			fd := newFinding("PF103", finding.High, finding.TriggerIDESettings, file, line,
				fmt.Sprintf("%s points at %s inside the repository", key, targets[0]))
			fd.Evidence = truncate(s, 200)
			fd.Targets = targets
			out = append(out, fd)
		}
	})
	return out
}

var execExts = map[string]bool{".exe": true, ".cmd": true, ".bat": true, ".com": true}

// looksExecutable reports whether a repository file could run as a program:
// a script by extension or shebang, a Windows executable, or a native binary.
func looksExecutable(c *Context, p string) bool {
	e := ext(p)
	if scriptExts[e] || execExts[e] {
		return true
	}
	head := c.Head(p, 64)
	return bytes.HasPrefix(head, []byte("#!")) || isNative(head)
}

// walkSettings visits leaf values with their dotted keys.
func walkSettings(prefix string, v any, fn func(string, any)) {
	m, ok := v.(map[string]any)
	if !ok {
		fn(prefix, v)
		return
	}
	for _, k := range sortedKeys(m) {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		walkSettings(key, m[k], fn)
	}
}
