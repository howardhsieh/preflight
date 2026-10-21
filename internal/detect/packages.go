package detect

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/howardhsieh/preflight/internal/finding"
)

var (
	installScripts = map[string]bool{
		"preinstall": true, "install": true, "postinstall": true,
		"prepare": true, "preprepare": true, "postprepare": true,
	}
	runScripts = map[string]bool{
		"start": true, "prestart": true, "dev": true, "predev": true, "serve": true,
		"test": true, "pretest": true, "build": true, "prebuild": true,
	}
	riskyCmdRe    = regexp.MustCompile(`(?i)(\bcurl\b|\bwget\b|invoke-webrequest|\biwr\b|powershell|node\s+-e|python[0-9.]*\s+-c|\beval\b|base64|\|\s*(ba|z)?sh\b|https?://)`)
	gitDepRe      = regexp.MustCompile(`^[\w.-]+/[\w.-]+(#.*)?$`)
	setupExecRe   = regexp.MustCompile(`(subprocess|os\.system|os\.popen|\bexec\(|\beval\(|__import__)`)
	setupNetRe    = regexp.MustCompile(`(urllib|urlopen|requests\.|http\.client|socket\.|urlretrieve)`)
	buildRsRiskRe = regexp.MustCompile(`(Command::new|TcpStream|reqwest|ureq::)`)
)

func detectPackages(c *Context) []finding.Finding {
	var out []finding.Finding
	for _, f := range c.Files {
		base := path.Base(f.Path)
		switch {
		case base == "package.json" && !underDir(f.Path, "node_modules"):
			out = append(out, npmPackage(c, f.Path)...)
		case base == "setup.py":
			out = append(out, setupPy(c, f.Path)...)
		case base == "pyproject.toml":
			if data, ok := c.Read(f.Path); ok {
				if l := lineOf(data, "backend-path"); l > 0 {
					out = append(out, newFinding("PF312", finding.Medium, finding.TriggerInstall, f.Path, l,
						"pyproject.toml loads its build backend from the repository, so pip install runs repository code"))
				}
			}
		case base == "build.rs":
			if data, ok := c.Read(f.Path); ok {
				if loc := buildRsRiskRe.FindIndex(data); loc != nil {
					out = append(out, newFinding("PF313", finding.Medium, finding.TriggerBuild, f.Path, lineAt(data, loc[0]),
						"Cargo build script runs commands or opens network connections during cargo build"))
				}
			}
		case base == ".envrc":
			out = append(out, envrc(c, f.Path)...)
		}
	}
	return out
}

func npmPackage(c *Context, file string) []finding.Finding {
	data, ok := c.Read(file)
	if !ok {
		return nil
	}
	var pkg struct {
		Scripts              map[string]string `json:"scripts"`
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return nil
	}
	dir := dirOf(file)
	var out []finding.Finding
	for _, name := range sortedKeys(pkg.Scripts) {
		script := pkg.Scripts[name]
		line := lineOf(data, `"`+name+`"`)
		if strings.Contains(script, "core.hooksPath") {
			fd := newFinding("PF304", finding.High, finding.TriggerInstall, file, line,
				fmt.Sprintf("Script %q points git at repository-controlled hooks", name))
			fd.Evidence = truncate(script, 300)
			out = append(out, fd)
		}
		switch {
		case installScripts[name]:
			sev := finding.Medium
			if riskyCmdRe.MatchString(script) {
				sev = finding.High
			}
			fd := newFinding("PF301", sev, finding.TriggerInstall, file, line,
				fmt.Sprintf("%q script runs automatically during npm install", name))
			fd.Evidence = truncate(script, 300)
			fd.Targets = commandTargets(c, dir, script)
			out = append(out, fd)
		case runScripts[name]:
			// Interview "take-home" repos usually ask you to run npm start or
			// npm test, so these matter when they lead to suspicious files.
			targets := commandTargets(c, dir, script)
			if len(targets) == 0 {
				continue
			}
			fd := newFinding("PF302", finding.Info, finding.TriggerRun, file, line,
				fmt.Sprintf("npm run %s executes %s", name, strings.Join(targets, ", ")))
			fd.Evidence = truncate(script, 300)
			fd.Targets = targets
			out = append(out, fd)
		}
	}
	for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies} {
		for _, name := range sortedKeys(deps) {
			spec := deps[name]
			if !isNonRegistrySpec(spec) {
				continue
			}
			fd := newFinding("PF303", finding.Low, finding.TriggerInstall, file, lineOf(data, `"`+name+`"`),
				fmt.Sprintf("Dependency %q is fetched from %s instead of the npm registry", name, truncate(spec, 80)))
			out = append(out, fd)
		}
	}
	return out
}

func isNonRegistrySpec(spec string) bool {
	for _, p := range []string{"git+", "git:", "git@", "http:", "https:", "github:", "gitlab:", "bitbucket:"} {
		if strings.HasPrefix(spec, p) {
			return true
		}
	}
	return gitDepRe.MatchString(spec)
}

func setupPy(c *Context, file string) []finding.Finding {
	data, ok := c.Read(file)
	if !ok {
		return nil
	}
	execLoc := setupExecRe.FindIndex(data)
	netLoc := setupNetRe.FindIndex(data)
	if execLoc == nil && netLoc == nil {
		return nil
	}
	sev, loc, msg := finding.Medium, execLoc, "setup.py runs commands at install time"
	switch {
	case execLoc != nil && netLoc != nil:
		sev, msg = finding.High, "setup.py runs commands and makes network requests at install time"
	case execLoc == nil:
		loc, msg = netLoc, "setup.py makes network requests at install time"
	}
	return []finding.Finding{newFinding("PF311", sev, finding.TriggerInstall, file, lineAt(data, loc[0]), msg)}
}

func envrc(c *Context, file string) []finding.Finding {
	data, ok := c.Read(file)
	if !ok {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return nil
	}
	body := strings.Join(lines, " ; ")
	sev := finding.Medium
	if riskyCmdRe.MatchString(body) {
		sev = finding.High
	}
	fd := newFinding("PF321", sev, finding.TriggerShellEnter, file, 1,
		".envrc is executed by direnv when you cd into this directory (after direnv allow)")
	fd.Evidence = truncate(body, 300)
	fd.Targets = commandTargets(c, dirOf(file), body)
	return []finding.Finding{fd}
}
