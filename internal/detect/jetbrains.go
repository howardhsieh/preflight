package detect

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/howardhsieh/preflight/internal/finding"
)

// JetBrains IDEs (IntelliJ, PyCharm, WebStorm, GoLand, …) store run
// configurations as XML in .run/*.run.xml, .idea/runConfigurations/*.xml and
// .idea/workspace.xml. Startup Tasks (Settings → Tools → Startup Tasks) make a
// run configuration execute when the project is opened; File Watchers run a
// program every time a file is saved. Both are honoured once the developer
// clicks "Trust Project", exactly like VS Code's folderOpen tasks.

// runConfig is one <configuration> element with the command-like text it carries.
type runConfig struct {
	file, name, kind string
	line             int
	cmd              string   // every path/command/parameter option joined
	beforeRun        []string // names of run configurations in "Before launch"
	externalTools    []string // IDE-level external tools in "Before launch"
}

// runOptionRe selects the <option name="..."> values that hold commands,
// scripts, interpreters, parameters or paths.
var runOptionRe = regexp.MustCompile(`(?i)(SCRIPT|PARAMETERS|INTERPRETER|PATH|COMMAND|PROGRAM|EXECUTABLE|ARGUMENTS|TASK|OPTIONS)`)

// runAttrSkip lists <configuration> attributes that are not commands.
var runAttrSkip = map[string]bool{"name": true, "type": true, "factoryName": true, "default": true,
	"folderName": true, "temporary": true, "nameIsGenerated": true, "activateToolWindowBeforeRun": true,
	"singleton": true, "editBeforeRun": true, "selected": true}

func isRunConfigFile(p string) bool {
	base, dir := path.Base(p), path.Base(path.Dir(p))
	switch {
	case strings.HasSuffix(base, ".run.xml") && dir == ".run":
		return true
	case ext(p) == ".xml" && dir == "runConfigurations" && path.Base(path.Dir(path.Dir(p))) == ".idea":
		return true
	case base == "workspace.xml" && dir == ".idea":
		return true
	}
	return false
}

func parseRunConfigs(c *Context, file string) []runConfig {
	data, ok := c.Read(file)
	if !ok {
		return nil
	}
	var out []runConfig
	for _, el := range parseXML(data).find("configuration") {
		name := el.Attr["name"]
		if name == "" || el.Attr["type"] == "" || el.Attr["default"] == "true" {
			continue // templates, or startup-task references (name and id only)
		}
		rc := runConfig{file: file, name: name, kind: el.Attr["type"], line: attrLine(data, "name", name)}
		var parts []string
		for _, k := range sortedKeys(el.Attr) {
			if !runAttrSkip[k] {
				parts = append(parts, xmlValue(el.Attr[k]))
			}
		}
		opts := el.options()
		for _, k := range sortedKeys(opts) {
			if runOptionRe.MatchString(k) && !strings.HasPrefix(k, "INDEPENDENT_") {
				parts = append(parts, xmlValue(opts[k]))
			}
		}
		el.walk(func(n *xmlNode) {
			switch {
			case n.Name == "env" && n.Attr["value"] != "":
				parts = append(parts, xmlValue(n.Attr["value"]))
			case n.Name == "option" && n.Attr["name"] == "RunConfigurationTask" && n.Attr["enabled"] != "false":
				if r := n.Attr["run_configuration_name"]; r != "" {
					rc.beforeRun = append(rc.beforeRun, r)
				}
			case n.Name == "option" && n.Attr["name"] == "ToolBeforeRunTask" && n.Attr["enabled"] != "false":
				rc.externalTools = append(rc.externalTools, strings.TrimPrefix(n.Attr["actionId"], "Tool_External Tools_"))
			}
		})
		rc.cmd = strings.Join(parts, " ")
		out = append(out, rc)
	}
	return out
}

// startupTaskNames returns the run configuration names registered as
// Startup Tasks in .idea/startup.xml (shared) or .idea/workspace.xml (local).
func startupTaskNames(c *Context, file string) ([]byte, []string) {
	data, ok := c.Read(file)
	if !ok {
		return nil, nil
	}
	var names []string
	doc := parseXML(data)
	for _, comp := range []string{"ProjectStartupSharedConfiguration", "ProjectStartupLocalConfiguration"} {
		for _, el := range doc.component(comp) {
			for _, cfg := range el.find("configuration") {
				if n := cfg.Attr["name"]; n != "" {
					names = append(names, n)
				}
			}
		}
	}
	return data, names
}

func detectJetBrains(c *Context) []finding.Finding {
	var configs []runConfig
	type startup struct {
		file  string
		data  []byte
		names []string
	}
	var startups []startup
	var out []finding.Finding
	for _, f := range c.Files {
		base, dir := path.Base(f.Path), path.Base(path.Dir(f.Path))
		if isRunConfigFile(f.Path) {
			configs = append(configs, parseRunConfigs(c, f.Path)...)
		}
		if dir != ".idea" {
			continue
		}
		switch base {
		case "startup.xml", "workspace.xml":
			if data, names := startupTaskNames(c, f.Path); len(names) > 0 {
				startups = append(startups, startup{f.Path, data, names})
			}
		case "watcherTasks.xml":
			out = append(out, fileWatchers(c, f.Path)...)
		case "externalDependencies.xml":
			out = append(out, pluginRequests(c, f.Path)...)
		}
	}

	byName := map[string]*runConfig{}
	for i := range configs {
		if _, dup := byName[configs[i].name]; !dup {
			byName[configs[i].name] = &configs[i]
		}
	}
	// resolve follows "Before launch" chains to collect everything a
	// configuration would run, bounded so a cycle cannot loop.
	var resolve func(rc *runConfig, depth int, seen map[string]bool) (cmd string, targets []string, tools []string)
	resolve = func(rc *runConfig, depth int, seen map[string]bool) (string, []string, []string) {
		seen[rc.name] = true
		cmd := rc.cmd
		// .run/ and .idea/ sit at the project root (or a subproject root):
		// resolve relative to their parent, then the repository root.
		targets := commandTargets(c, dirOf(path.Dir(rc.file)), rc.cmd)
		tools := append([]string(nil), rc.externalTools...)
		if depth >= 3 {
			return cmd, targets, tools
		}
		for _, dep := range rc.beforeRun {
			d, ok := byName[dep]
			if !ok || seen[dep] {
				continue
			}
			dc, dt, dtools := resolve(d, depth+1, seen)
			cmd = dc + " ; " + cmd
			targets = append(dt, targets...)
			tools = append(dtools, tools...)
		}
		return cmd, targets, tools
	}

	startupNames := map[string]bool{}
	for _, s := range startups {
		for _, name := range s.names {
			startupNames[name] = true
			line := attrLine(s.data, "name", name)
			rc, ok := byName[name]
			if !ok {
				// The configuration lives in the developer's own IDE, not in
				// the repository, so we cannot say what it runs.
				out = append(out, newFinding("PF111", finding.High, finding.TriggerIDEOpen, s.file, line,
					fmt.Sprintf("Startup task runs configuration %q when the project is opened (configuration not found in the repository)", name)))
				continue
			}
			cmd, targets, tools := resolve(rc, 0, map[string]bool{})
			fd := newFinding("PF111", finding.Critical, finding.TriggerIDEOpen, s.file, line,
				fmt.Sprintf("Startup task runs configuration %q (%s) when the project is opened", name, rc.file))
			fd.Evidence = truncate(withTools(cmd, tools), 300)
			fd.Targets = uniq(targets)
			out = append(out, fd)
		}
	}

	for i := range configs {
		rc := &configs[i]
		if startupNames[rc.name] {
			continue
		}
		cmd, targets, tools := resolve(rc, 0, map[string]bool{})
		risky := riskyCmdRe.MatchString(cmd)
		if len(targets) == 0 && !risky {
			continue
		}
		sev := finding.Info
		if risky {
			sev = finding.Low
		}
		fd := newFinding("PF112", sev, finding.TriggerRun, rc.file, rc.line,
			fmt.Sprintf("Run configuration %q executes %s", rc.name, describeTargets(targets)))
		fd.Evidence = truncate(withTools(cmd, tools), 300)
		fd.Targets = uniq(targets)
		out = append(out, fd)
	}
	return out
}

func withTools(cmd string, tools []string) string {
	if len(tools) == 0 {
		return cmd
	}
	return cmd + " ; before launch: external tool " + strings.Join(tools, ", ") + " (defined in your IDE, not in the repository)"
}

func describeTargets(targets []string) string {
	if len(targets) == 0 {
		return "a risky command"
	}
	return strings.Join(targets, ", ")
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// fileWatchers reads .idea/watcherTasks.xml (the File Watchers plugin),
// whose tasks run a program whenever a matching file is saved.
func fileWatchers(c *Context, file string) []finding.Finding {
	data, ok := c.Read(file)
	if !ok {
		return nil
	}
	var out []finding.Finding
	for _, task := range parseXML(data).find("TaskOptions") {
		if task.Attr["isEnabled"] == "false" {
			continue
		}
		opts := task.options()
		program := xmlValue(opts["program"])
		if program == "" {
			continue
		}
		cmd := strings.TrimSpace(program + " " + xmlValue(opts["arguments"]))
		name := opts["name"]
		if name == "" {
			name = path.Base(program)
		}
		targets := commandTargets(c, "", cmd)
		// A watcher that runs a tool from node_modules or PATH is a
		// convenience; one that runs a file shipped in the repository, or
		// reaches for the network, is the attack.
		sev := finding.Medium
		if len(targets) > 0 || riskyCmdRe.MatchString(cmd) {
			sev = finding.High
		}
		fd := newFinding("PF114", sev, finding.TriggerIDESettings, file, attrLine(data, "value", opts["name"]),
			fmt.Sprintf("File Watcher %q runs a program whenever a %s file is saved", name, watcherScope(opts)))
		fd.Evidence = truncate(cmd, 300)
		fd.Targets = targets
		out = append(out, fd)
	}
	return out
}

func watcherScope(opts map[string]string) string {
	if e := opts["fileExtension"]; e != "" {
		return "." + strings.TrimPrefix(e, ".")
	}
	return "matching"
}

// pluginRequests reads .idea/externalDependencies.xml, which makes the IDE
// prompt to install plugins from the Marketplace. Plugins run with full IDE
// privileges, but the prompt is explicit, so this is informational.
func pluginRequests(c *Context, file string) []finding.Finding {
	data, ok := c.Read(file)
	if !ok {
		return nil
	}
	var ids []string
	for _, p := range parseXML(data).find("plugin") {
		if id := p.Attr["id"]; id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	fd := newFinding("PF113", finding.Info, finding.TriggerIDESettings, file, attrLine(data, "id", ids[0]),
		fmt.Sprintf("Asks to install %d IDE plugin(s) when the project is opened", len(ids)))
	fd.Evidence = truncate(strings.Join(ids, ", "), 200)
	return []finding.Finding{fd}
}
