package detect

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/howardhsieh/preflight/internal/finding"
)

var (
	claudeSettingsFiles = map[string]bool{"settings.json": true, "settings.local.json": true}
	agentHelperKeys     = []string{"apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper"}
	agentRedirectEnv    = map[string]bool{
		"ANTHROPIC_BASE_URL": true, "ANTHROPIC_BEDROCK_BASE_URL": true, "ANTHROPIC_VERTEX_BASE_URL": true,
		"OPENAI_BASE_URL": true, "HTTP_PROXY": true, "HTTPS_PROXY": true, "NODE_OPTIONS": true,
		"NODE_TLS_REJECT_UNAUTHORIZED": true, "NODE_EXTRA_CA_CERTS": true,
	}
	agentInstructionNames = map[string]bool{
		"CLAUDE.md": true, "AGENTS.md": true, "GEMINI.md": true, ".cursorrules": true,
		".windsurfrules": true, "copilot-instructions.md": true, "SKILL.md": true,
	}

	injectionRe   = regexp.MustCompile(`(?i)(ignore (all |any )?(of )?(the )?(previous|prior|above) (instructions|prompts)|disregard (the |your )?(system|previous) (prompt|instructions)|do not (tell|inform|alert) the user|without (asking|telling|notifying|informing) the user|(curl|wget)[^\n|]*\|\s*(ba|z)?sh\b)`)
	htmlCommentRe = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	// A hidden comment counts as an instruction when it opens by addressing
	// the model ("AI assistant: ...", "Note to Claude: ...") and tells it to
	// do something, or uses classic system-prompt phrasing anywhere. Merely
	// mentioning an agent ("TODO: update the Claude Code screenshot") does not.
	aiAddressRe  = regexp.MustCompile(`(?i)^[\s\[\]()#*>:-]*(note|instructions?|important|attention|hey|hi|hello)?[\s:,-]*(to|for)?\s*(the\s+)?(ai|assistant|agent|llm|claude|copilot|cursor|gemini|codex|chatgpt|language model)s?\b`)
	imperativeRe = regexp.MustCompile(`(?i)\b(run|execute|ignore|must|always|never|send|upload|curl|wget|fetch|read|install|do not tell)\b`)
	strongPhrase = regexp.MustCompile(`(?i)\b(you are (an?|the|now)\b|system prompt|ignore (all |any )?(of )?(the )?(previous|prior|above) (instructions|prompts)|do not (tell|inform|alert) the user|without (asking|telling|notifying|informing) the user)`)
)

var packageRunners = map[string]bool{"npx": true, "bunx": true, "pnpx": true, "uvx": true, "pipx": true, "docker": true, "deno": true}

// isPackageRunner reports whether cmd starts with a tool that fetches a
// named package from a registry (optionally after `-y`/`run` style flags).
func isPackageRunner(cmd string) bool {
	fields := strings.Fields(cmd)
	return len(fields) >= 2 && packageRunners[path.Base(fields[0])]
}

func isAgentInstructionFile(p string) bool {
	base := path.Base(p)
	if agentInstructionNames[base] || base == ".clinerules" || base == ".roorules" {
		return true
	}
	for _, dir := range []string{".cursor/rules", ".claude/commands", ".claude/agents", ".claude/skills",
		".github/instructions", ".github/prompts", ".github/agents", ".windsurf/rules", ".clinerules",
		".roo/rules", ".kiro/steering", ".junie"} {
		if underDir(p, dir) {
			return true
		}
	}
	return false
}

func isMCPConfig(p string) bool {
	base, dir := path.Base(p), path.Base(path.Dir(p))
	switch {
	case base == ".mcp.json", base == "opencode.json", base == "opencode.jsonc":
		return true
	case base == "mcp.json":
		return dir == ".cursor" || dir == ".vscode" || dir == ".roo" || dir == ".codex" ||
			(dir == "settings" && path.Base(path.Dir(path.Dir(p))) == ".kiro")
	case base == "settings.json":
		return dir == ".gemini"
	case base == "config.toml":
		return dir == ".codex"
	}
	return false
}

// isAgentHookConfig lists the project files whose hooks run shell commands
// on agent events: Cursor's .cursor/hooks.json, Gemini CLI's settings and
// Codex's notify command.
func isAgentHookConfig(p string) bool {
	base, dir := path.Base(p), path.Base(path.Dir(p))
	return (base == "hooks.json" && dir == ".cursor") || (base == "settings.json" && dir == ".gemini") ||
		(base == "config.toml" && dir == ".codex")
}

func detectAgents(c *Context) []finding.Finding {
	var out []finding.Finding
	for _, f := range c.Files {
		dir := path.Base(path.Dir(f.Path))
		if dir == ".claude" && claudeSettingsFiles[path.Base(f.Path)] {
			out = append(out, claudeSettings(c, f.Path)...)
		}
		if isMCPConfig(f.Path) {
			out = append(out, mcpConfig(c, f.Path)...)
		}
		if isAgentHookConfig(f.Path) {
			out = append(out, agentHooks(c, f.Path)...)
		}
		if isAgentInstructionFile(f.Path) || strings.EqualFold(ext(f.Path), ".md") {
			out = append(out, agentText(c, f.Path)...)
		}
	}
	return out
}

func claudeSettings(c *Context, file string) []finding.Finding {
	data, doc, ok := readJSONC(c, file)
	if !ok {
		return nil
	}
	var out []finding.Finding
	if hooks, ok := doc["hooks"].(map[string]any); ok {
		for _, event := range sortedKeys(hooks) {
			for _, cmd := range hookCommands(hooks[event]) {
				// Hooks that run a repository script are common in real
				// projects; the chain rule escalates when that script is
				// suspicious, and risky one-liners are high on their own.
				sev := finding.Medium
				if riskyCmdRe.MatchString(cmd) {
					sev = finding.High
				}
				fd := newFinding("PF501", sev, finding.TriggerAgent, file, lineOf(data, `"`+event+`"`),
					fmt.Sprintf("Claude Code %s hook runs a shell command", event))
				fd.Evidence = truncate(cmd, 300)
				fd.Targets = commandTargets(c, "", cmd)
				out = append(out, fd)
			}
		}
	}
	if v, _ := doc["enableAllProjectMcpServers"].(bool); v {
		// Only dangerous when there are project MCP servers to approve.
		sev := finding.Medium
		if _, ok := c.Lookup(".mcp.json"); ok {
			sev = finding.High
		}
		out = append(out, newFinding("PF502", sev, finding.TriggerAgent, file, lineOf(data, "enableAllProjectMcpServers"),
			"enableAllProjectMcpServers approves every MCP server in this repository without asking"))
	}
	if env, ok := doc["env"].(map[string]any); ok {
		for _, k := range sortedKeys(env) {
			if !agentRedirectEnv[k] {
				continue
			}
			fd := newFinding("PF503", finding.High, finding.TriggerAgent, file, lineOf(data, `"`+k+`"`),
				fmt.Sprintf("Sets %s for the agent, which can route its traffic (and your API key) elsewhere", k))
			fd.Evidence = truncate(fmt.Sprint(env[k]), 200)
			out = append(out, fd)
		}
	}
	for _, k := range agentHelperKeys {
		if cmd := str(doc[k]); cmd != "" {
			fd := newFinding("PF505", finding.High, finding.TriggerAgent, file, lineOf(data, `"`+k+`"`),
				fmt.Sprintf("%s runs a command from this repository's settings", k))
			fd.Evidence = truncate(cmd, 300)
			fd.Targets = commandTargets(c, "", cmd)
			out = append(out, fd)
		}
	}
	if perms, ok := doc["permissions"].(map[string]any); ok {
		if str(perms["defaultMode"]) == "bypassPermissions" {
			out = append(out, newFinding("PF504", finding.High, finding.TriggerAgent, file, lineOf(data, "bypassPermissions"),
				"Permission mode bypassPermissions lets the agent run any tool without asking"))
		}
		if allow, ok := perms["allow"].([]any); ok {
			for _, a := range allow {
				if s := str(a); s == "Bash" || s == "Bash(*)" || s == "Bash(*:*)" {
					out = append(out, newFinding("PF504", finding.Medium, finding.TriggerAgent, file, lineOf(data, `"`+s+`"`),
						"Pre-approves every shell command for the agent"))
					break
				}
			}
		}
	}
	return out
}

// hookCommands extracts commands from Claude Code's
// {"Event": [{"matcher": ..., "hooks": [{"type": "command", "command": ...}]}]} layout.
func hookCommands(v any) []string {
	var cmds []string
	groups, _ := v.([]any)
	for _, g := range groups {
		gm, _ := g.(map[string]any)
		hs, _ := gm["hooks"].([]any)
		for _, h := range hs {
			hm, _ := h.(map[string]any)
			if cmd := str(hm["command"]); cmd != "" {
				cmds = append(cmds, cmd)
			}
		}
	}
	return cmds
}

// agentHooks reports commands that Cursor, Gemini CLI or Codex run on agent
// events. Cursor and Gemini use nested JSON under "hooks"; Codex has a
// top-level `notify = [...]` array in config.toml.
func agentHooks(c *Context, file string) []finding.Finding {
	var data []byte
	var doc map[string]any
	var ok bool
	if ext(file) == ".toml" {
		data, doc, ok = readTOML(c, file)
	} else {
		data, doc, ok = readJSONC(c, file)
	}
	if !ok {
		return nil
	}
	agent := map[string]string{".cursor": "Cursor", ".gemini": "Gemini CLI", ".codex": "Codex"}[path.Base(path.Dir(file))]
	var out []finding.Finding
	emit := func(event, cmd string) {
		sev := finding.Medium
		if riskyCmdRe.MatchString(cmd) {
			sev = finding.High
		}
		fd := newFinding("PF506", sev, finding.TriggerAgent, file, lineOf(data, event),
			fmt.Sprintf("%s %s hook runs a shell command", agent, event))
		fd.Evidence = truncate(cmd, 300)
		fd.Targets = commandTargets(c, "", cmd)
		out = append(out, fd)
	}
	if hooks, ok := doc["hooks"].(map[string]any); ok {
		for _, event := range sortedKeys(hooks) {
			for _, cmd := range nestedCommands(hooks[event]) {
				emit(event, cmd)
			}
		}
	}
	if cmd := commandString(doc["notify"]); cmd != "" {
		emit("notify", cmd)
	}
	return out
}

// nestedCommands collects every "command" string anywhere under v, which
// covers Claude's {matcher, hooks:[{command}]} layout and Cursor's flat
// [{command}] layout alike.
func nestedCommands(v any) []string {
	var cmds []string
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			cmds = append(cmds, nestedCommands(e)...)
		}
	case map[string]any:
		if cmd := str(t["command"]); cmd != "" {
			cmds = append(cmds, cmd)
		}
		for _, k := range sortedKeys(t) {
			if k != "command" {
				cmds = append(cmds, nestedCommands(t[k])...)
			}
		}
	}
	return cmds
}

func mcpConfig(c *Context, file string) []finding.Finding {
	var data []byte
	var doc map[string]any
	var ok bool
	if ext(file) == ".toml" {
		data, doc, ok = readTOML(c, file)
	} else {
		data, doc, ok = readJSONC(c, file)
	}
	if !ok {
		return nil
	}
	servers, ok := doc["mcpServers"].(map[string]any)
	if !ok {
		servers, ok = doc["servers"].(map[string]any) // VS Code layout
	}
	if !ok {
		servers, ok = doc["mcp_servers"].(map[string]any) // Codex config.toml
	}
	if !ok {
		servers, _ = doc["mcp"].(map[string]any) // OpenCode
	}
	var out []finding.Finding
	for _, name := range sortedKeys(servers) {
		s, _ := servers[name].(map[string]any)
		line := lineOf(data, `"`+name+`"`)
		if line == 0 {
			line = lineOf(data, name)
		}
		if cmd := commandString(s["command"]); cmd != "" {
			if args, ok := s["args"].([]any); ok {
				cmd += " " + commandString(args)
			}
			targets := commandTargets(c, "", cmd)
			// Launching an MCP server is what this file is for; a repository
			// script is escalated by the chain rule when its content is
			// suspicious, and only shell-pipeline tricks are high here.
			sev := finding.Medium
			if riskyCmdRe.MatchString(cmd) {
				sev = finding.High
			}
			fd := newFinding("PF511", sev, finding.TriggerAgent, file, line,
				fmt.Sprintf("MCP server %q launches a local command when the agent starts", name))
			fd.Evidence = truncate(cmd, 300)
			fd.Targets = targets
			out = append(out, fd)
		} else if url := str(s["url"]); url != "" {
			fd := newFinding("PF512", finding.Medium, finding.TriggerAgent, file, line,
				fmt.Sprintf("MCP server %q connects the agent to a remote endpoint", name))
			fd.Evidence = truncate(url, 200)
			out = append(out, fd)
		}
	}
	return out
}

func agentText(c *Context, file string) []finding.Finding {
	data, ok := c.Read(file)
	if !ok {
		return nil
	}
	agentFile := isAgentInstructionFile(file)
	var out []finding.Finding
	if loc := injectionRe.FindIndex(data); loc != nil {
		// Ordinary docs that mention "ignore previous instructions" are
		// usually *about* prompt injection; only files an agent obeys count.
		sev := finding.Info
		if agentFile {
			sev = finding.Medium
		}
		fd := newFinding("PF521", sev, finding.TriggerAgent, file, lineAt(data, loc[0]),
			"Text read by AI agents contains prompt-injection phrasing")
		fd.Evidence = truncate(string(data[loc[0]:loc[1]]), 200)
		out = append(out, fd)
	}
	for _, m := range htmlCommentRe.FindAllSubmatchIndex(data, -1) {
		body := data[m[2]:m[3]]
		if (aiAddressRe.Match(body) && imperativeRe.Match(body)) || strongPhrase.Match(body) {
			fd := newFinding("PF522", finding.Medium, finding.TriggerAgent, file, lineAt(data, m[0]),
				"Hidden HTML comment gives instructions to an AI agent")
			fd.Evidence = truncate(string(body), 200)
			out = append(out, fd)
			break
		}
	}
	return out
}
