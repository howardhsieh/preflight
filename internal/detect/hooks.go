package detect

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/howardhsieh/preflight/internal/finding"
)

// Git hook managers turn a committed config file into commands that run on
// the developer's first commit. pre-commit installs from
// .pre-commit-config.yaml; lefthook and simple-git-hooks are installed by a
// package.json prepare script. Hooks that reference public repositories are
// not findings: only local hooks name a command the repository controls.

// preCommitHook is one entry under `repo: local`.
type preCommitHook struct {
	id, entry, language string
	args                []string
	line                int
}

var (
	yamlKeyRe      = regexp.MustCompile(`^(\s*)(- )?([A-Za-z_][\w-]*):\s*(.*)$`)
	lefthookRunRe  = regexp.MustCompile(`(?m)^\s*(run|runner):\s*(.+)$`)
	lefthookFiles  = map[string]bool{"lefthook.yml": true, "lefthook.yaml": true, ".lefthook.yml": true, ".lefthook.yaml": true, "lefthook-local.yml": true, ".lefthook-local.yml": true}
	knownHookTools = map[string]bool{
		"mypy": true, "black": true, "ruff": true, "flake8": true, "pylint": true, "isort": true, "pytest": true,
		"eslint": true, "prettier": true, "tsc": true, "npm": true, "npx": true, "pnpm": true, "yarn": true, "bun": true,
		"cargo": true, "rustfmt": true, "go": true, "gofmt": true, "goimports": true, "golangci-lint": true,
		"make": true, "poetry": true, "uv": true, "python": true, "python3": true, "terraform": true, "tflint": true,
		"shellcheck": true, "hadolint": true, "swiftlint": true, "swiftformat": true, "clang-format": true, "dotnet": true,
		"bundle": true, "rubocop": true, "mix": true, "php": true, "composer": true, "sh": true, "bash": true, "echo": true, "true": true,
	}
)

func detectHookManagers(c *Context) []finding.Finding {
	var out []finding.Finding
	for _, f := range c.Files {
		base := path.Base(f.Path)
		switch {
		case base == ".pre-commit-config.yaml" || base == ".pre-commit-config.yml":
			out = append(out, preCommitConfig(c, f.Path)...)
		case lefthookFiles[base]:
			out = append(out, lefthookConfig(c, f.Path)...)
		case base == "package.json" && !underDir(f.Path, "node_modules"):
			out = append(out, packageJSONHooks(c, f.Path)...)
		}
	}
	return out
}

// yamlScalar strips quotes and a trailing comment from a YAML scalar.
func yamlScalar(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

// yamlFlowList splits `[a, "b c"]` into its items.
func yamlFlowList(s string) []string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") {
		return nil
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	var out []string
	for _, p := range strings.Split(s, ",") {
		if v := yamlScalar(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// parsePreCommitLocalHooks is a purpose-built reader for the two-level
// `repos:` / `hooks:` lists of .pre-commit-config.yaml. It tracks indentation
// rather than parsing YAML in general, which is enough for the files
// pre-commit itself accepts and keeps the scanner dependency-free.
func parsePreCommitLocalHooks(data []byte) []preCommitHook {
	var hooks []preCommitHook
	var cur *preCommitHook
	local := false
	repoIndent, hookIndent := -1, -1
	inArgs := false
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		// Block-list items of args: "    - --foo".
		if inArgs && cur != nil && strings.HasPrefix(strings.TrimSpace(line), "- ") && indent > hookIndent {
			if v := yamlScalar(strings.TrimPrefix(strings.TrimSpace(line), "- ")); v != "" {
				cur.args = append(cur.args, v)
			}
			continue
		}
		inArgs = false
		m := yamlKeyRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		listItem, key, val := m[2] != "", m[3], m[4]
		switch {
		case key == "repo" && listItem:
			local = yamlScalar(val) == "local"
			repoIndent, hookIndent, cur = indent, -1, nil
		case !local || indent <= repoIndent:
			cur = nil
		case listItem && (hookIndent < 0 || indent == hookIndent):
			// "- id: x" (or any key opening a list item) starts a hook.
			hookIndent = indent
			hooks = append(hooks, preCommitHook{line: i + 1})
			cur = &hooks[len(hooks)-1]
			setHookField(cur, key, val)
		case cur != nil && indent > hookIndent:
			setHookField(cur, key, val)
			inArgs = key == "args" && strings.TrimSpace(val) == ""
		}
	}
	return hooks
}

func setHookField(h *preCommitHook, key, val string) {
	switch key {
	case "id":
		h.id = yamlScalar(val)
	case "entry":
		h.entry = yamlScalar(val)
	case "language":
		h.language = yamlScalar(val)
	case "args":
		h.args = append(h.args, yamlFlowList(val)...)
	}
}

func preCommitConfig(c *Context, file string) []finding.Finding {
	data, ok := c.Read(file)
	if !ok {
		return nil
	}
	dir := dirOf(file)
	var out []finding.Finding
	for _, h := range parsePreCommitLocalHooks(data) {
		if h.entry == "" {
			continue
		}
		cmd := strings.TrimSpace(h.entry + " " + strings.Join(h.args, " "))
		targets := commandTargets(c, dir, cmd)
		// `entry: mypy` with language: python is a tool from PyPI; a repo
		// script or a shell pipeline is what an attacker would ship.
		sev := finding.Low
		switch {
		case riskyCmdRe.MatchString(cmd):
			sev = finding.High
		case len(targets) > 0 || h.language == "script":
			sev = finding.Medium
		case !isKnownHookTool(cmd):
			sev = finding.Medium
		}
		name := h.id
		if name == "" {
			name = h.entry
		}
		fd := newFinding("PF404", sev, finding.TriggerGit, file, h.line,
			fmt.Sprintf("Local pre-commit hook %q runs on every commit once pre-commit is installed (language: %s)", name, orUnknown(h.language)))
		fd.Evidence = truncate(cmd, 300)
		fd.Targets = targets
		out = append(out, fd)
	}
	return out
}

func orUnknown(s string) string {
	if s == "" {
		return "unspecified"
	}
	return s
}

// isKnownHookTool reports whether every command in a hook line starts with
// a well-known linter, formatter or build tool.
func isKnownHookTool(cmd string) bool {
	parts := strings.FieldsFunc(cmd, func(r rune) bool { return r == ';' || r == '&' || r == '|' })
	if len(parts) == 0 {
		return false
	}
	for _, p := range parts {
		fields := strings.Fields(p)
		if len(fields) == 0 || !knownHookTools[path.Base(fields[0])] {
			return false
		}
	}
	return true
}

func lefthookConfig(c *Context, file string) []finding.Finding {
	data, ok := c.Read(file)
	if !ok {
		return nil
	}
	var out []finding.Finding
	for _, m := range lefthookRunRe.FindAllSubmatchIndex(data, -1) {
		cmd := yamlScalar(string(data[m[4]:m[5]]))
		if cmd == "" || strings.HasPrefix(cmd, "{") {
			continue
		}
		out = append(out, hookConfigFinding(c, file, lineAt(data, m[0]), "lefthook", cmd))
	}
	return out
}

// packageJSONHooks reads the "simple-git-hooks" object and the legacy husky
// v4 "husky": {"hooks": {...}} block, both installed by a prepare script.
func packageJSONHooks(c *Context, file string) []finding.Finding {
	data, ok := c.Read(file)
	if !ok {
		return nil
	}
	var pkg struct {
		SimpleGitHooks map[string]any `json:"simple-git-hooks"`
		Husky          struct {
			Hooks map[string]any `json:"hooks"`
		} `json:"husky"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return nil
	}
	var out []finding.Finding
	for manager, hooks := range map[string]map[string]any{"simple-git-hooks": pkg.SimpleGitHooks, "husky": pkg.Husky.Hooks} {
		for _, event := range sortedKeys(hooks) {
			cmd := str(hooks[event])
			if cmd == "" {
				continue
			}
			out = append(out, hookConfigFinding(c, file, lineOf(data, `"`+event+`"`), manager, cmd))
		}
	}
	return out
}

func hookConfigFinding(c *Context, file string, line int, manager, cmd string) finding.Finding {
	targets := commandTargets(c, dirOf(file), cmd)
	sev := finding.Low // the same footing as a .husky/ hook (PF402)
	if riskyCmdRe.MatchString(cmd) {
		sev = finding.High
	}
	fd := newFinding("PF405", sev, finding.TriggerGit, file, line,
		fmt.Sprintf("%s hook runs on git operations once installed (usually by npm install)", manager))
	fd.Evidence = truncate(cmd, 300)
	fd.Targets = targets
	return fd
}
