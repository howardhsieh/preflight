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
	aiAddressRe   = regexp.MustCompile(`(?i)\b(ai|assistant|agent|llm|claude|copilot|cursor|gemini|codex|chatgpt|language model)\b`)
	imperativeRe  = regexp.MustCompile(`(?i)\b(run|execute|ignore|must|always|never|send|upload|curl|wget|fetch|read|install|do not tell)\b`)
)

func isAgentInstructionFile(p string) bool {
	return agentInstructionNames[path.Base(p)] ||
		underDir(p, ".cursor/rules") || underDir(p, ".claude/commands") ||
		underDir(p, ".claude/agents") || underDir(p, ".claude/skills") || underDir(p, ".github/instructions")
}

func isMCPConfig(p string) bool {
	base, dir := path.Base(p), path.Base(path.Dir(p))
	return base == ".mcp.json" || (base == "mcp.json" && (dir == ".cursor" || dir == ".vscode" || dir == ".roo")) ||
		(base == "settings.json" && dir == ".gemini")
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
				fd := newFinding("PF501", finding.High, finding.TriggerAgent, file, lineOf(data, `"`+event+`"`),
					fmt.Sprintf("Claude Code %s hook runs a shell command", event))
				fd.Evidence = truncate(cmd, 300)
				fd.Targets = commandTargets(c, "", cmd)
				out = append(out, fd)
			}
		}
	}
	if v, _ := doc["enableAllProjectMcpServers"].(bool); v {
		out = append(out, newFinding("PF502", finding.High, finding.TriggerAgent, file, lineOf(data, "enableAllProjectMcpServers"),
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

func mcpConfig(c *Context, file string) []finding.Finding {
	data, doc, ok := readJSONC(c, file)
	if !ok {
		return nil
	}
	servers, ok := doc["mcpServers"].(map[string]any)
	if !ok {
		servers, _ = doc["servers"].(map[string]any) // VS Code layout
	}
	var out []finding.Finding
	for _, name := range sortedKeys(servers) {
		s, _ := servers[name].(map[string]any)
		line := lineOf(data, `"`+name+`"`)
		if cmd := str(s["command"]); cmd != "" {
			if args, ok := s["args"].([]any); ok {
				cmd += " " + commandString(args)
			}
			fd := newFinding("PF511", finding.High, finding.TriggerAgent, file, line,
				fmt.Sprintf("MCP server %q launches a local command when the agent starts", name))
			fd.Evidence = truncate(cmd, 300)
			fd.Targets = commandTargets(c, "", cmd)
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
		sev := finding.Low
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
		if aiAddressRe.Match(body) && imperativeRe.Match(body) {
			fd := newFinding("PF522", finding.Medium, finding.TriggerAgent, file, lineAt(data, m[0]),
				"Hidden HTML comment gives instructions to an AI agent")
			fd.Evidence = truncate(string(body), 200)
			out = append(out, fd)
			break
		}
	}
	return out
}
