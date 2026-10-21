package finding

// Rule documents a check that preflight performs.
type Rule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Rules is the catalogue of every rule a detector may emit.
var Rules = []Rule{
	{"PF001", "auto-exec-chain", "An automatic trigger executes a file that also contains suspicious code."},

	{"PF101", "vscode-folderopen-task", "A VS Code task is configured to run automatically when the folder is opened."},
	{"PF102", "vscode-auto-tasks-enabled", "Workspace settings try to allow automatic tasks without prompting."},
	{"PF103", "vscode-repo-executable", "A workspace setting points VS Code or an extension at an executable inside the repository."},
	{"PF104", "vscode-env-injection", "Workspace settings inject environment variables that load code into every process."},
	{"PF105", "vscode-trust-setting", "Workspace settings try to change Workspace Trust behaviour."},
	{"PF106", "python-virtualenv", "A Python virtualenv is present; IDEs may auto-select its interpreter. Its contents are not scanned."},

	{"PF201", "devcontainer-host-command", "devcontainer initializeCommand runs on the host before the container exists."},
	{"PF202", "devcontainer-lifecycle-command", "devcontainer lifecycle command runs when the container is created or started."},
	{"PF203", "devcontainer-credential-mount", "The dev container mounts credential directories from the host."},
	{"PF204", "devcontainer-privileged", "The dev container requests privileged or host-level access."},

	{"PF301", "npm-install-script", "package.json defines a script that runs during npm install."},
	{"PF302", "npm-run-script", "package.json script that runs when you start, test or build the project."},
	{"PF303", "non-registry-dependency", "A dependency is fetched from a URL or git repository instead of the registry."},
	{"PF304", "git-hookspath-override", "A script changes git's core.hooksPath to run repository-controlled hooks."},
	{"PF311", "setup-py-suspicious", "setup.py runs commands or makes network requests at install time."},
	{"PF312", "in-tree-build-backend", "pyproject.toml loads a build backend from inside the repository."},
	{"PF313", "cargo-build-script", "Cargo build.rs runs commands or makes network requests at build time."},
	{"PF321", "direnv-envrc", ".envrc runs automatically when you cd into the directory with direnv."},

	{"PF401", "gitmodules-suspicious", ".gitmodules contains a URL or path that can be abused for code execution."},
	{"PF402", "git-hook-installer", "The repository ships git hooks that an install step activates."},
	{"PF403", "gitattributes-filter", ".gitattributes requests a custom filter or diff driver."},

	{"PF501", "claude-code-hook", "Claude Code project settings define hooks that run shell commands."},
	{"PF502", "agent-mcp-auto-approve", "Agent settings auto-approve every MCP server in the project."},
	{"PF503", "agent-traffic-redirect", "Agent settings redirect API traffic or weaken TLS through environment variables."},
	{"PF504", "agent-broad-permissions", "Agent settings grant unrestricted shell access or bypass permission prompts."},
	{"PF505", "agent-helper-command", "Agent settings run a helper command (for example apiKeyHelper)."},
	{"PF511", "mcp-local-server", "An MCP config launches a local command when the agent starts."},
	{"PF512", "mcp-remote-server", "An MCP config connects the agent to a remote server."},
	{"PF521", "agent-instruction-injection", "Text that AI agents read contains prompt-injection phrasing."},
	{"PF522", "hidden-comment-instruction", "A hidden HTML comment in Markdown addresses an AI agent."},

	{"PF601", "unicode-tag-smuggling", "Invisible Unicode Tag characters hide text that AI models can read."},
	{"PF602", "bidi-control", "Bidirectional control characters can make code display differently from how it runs (Trojan Source)."},
	{"PF603", "zero-width-chars", "Zero-width characters are hidden inside text."},

	{"PF701", "offscreen-code", "Code is pushed far to the right by whitespace so editors do not show it."},
	{"PF702", "decode-and-execute", "Encoded data is decoded and executed on the same line."},
	{"PF703", "remote-code-execution", "The file downloads data and evaluates it as code."},
	{"PF704", "encoded-blob", "A large high-entropy encoded blob is embedded in source code."},
	{"PF705", "payload-host", "The file references a paste or JSON hosting service commonly used to stage payloads."},
	{"PF706", "ip-literal-url", "The file contacts a public IP address directly instead of a domain."},

	{"PF801", "disguised-file", "File contents do not match its extension (for example a script named like a font)."},
	{"PF802", "native-executable", "A compiled executable is committed to the repository."},
	{"PF803", "symlink-escape", "A symlink points outside the repository."},
}

var ruleIndex = func() map[string]Rule {
	m := make(map[string]Rule, len(Rules))
	for _, r := range Rules {
		m[r.ID] = r
	}
	return m
}()

// RuleByID returns the rule with the given ID.
func RuleByID(id string) (Rule, bool) {
	r, ok := ruleIndex[id]
	return r, ok
}
