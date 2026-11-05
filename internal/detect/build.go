package detect

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/howardhsieh/preflight/internal/finding"
)

// Build-system vectors: the Gradle and Maven wrappers download and run a
// build tool from whatever URL the repository names; Gradle build scripts
// are evaluated the moment a JetBrains IDE imports the project; Maven reads
// JVM flags, including -javaagent, from .mvn/jvm.config; and a Nix shellHook
// runs on nix develop (automatically through direnv's use flake / use nix).

var (
	officialWrapperHosts = map[string]bool{
		"services.gradle.org": true, "repo.maven.apache.org": true, "repo1.maven.org": true, "repo.maven.org": true,
	}
	gradleExecRe = regexp.MustCompile(`(\bexec\s*\{|\bexec\s*\(|\bcommandLine\b|ProcessBuilder|Runtime\.getRuntime\(\)\.exec|\.execute\(\)|providers\.exec\b|\bexecOperations\b)`)
	// Actual connections, not mentions: readText() on a file, "java.net" in
	// an OSGi header or an import line are everyday build-script content.
	gradleNetRe = regexp.MustCompile(`(\.openStream\(\)|\.openConnection\(\)|HttpURLConnection|HttpClient\.new(HttpClient|Builder)\(|\bURL\s*\([^)\n]*\)\s*\.(readText|readBytes|openStream|openConnection|text\b|getText|bytes\b)|\bSocket\s*\(|\.toURL\(\)\s*\.(readText|readBytes|openStream|openConnection|text\b|getText))`)
	// Documentation samples and test projects carry local plugin repositories
	// on purpose; they are only built when someone opens that directory.
	samplePathRe = regexp.MustCompile(`(?i)(^|/)(docs?|samples?|examples?|snippets|demos?|tutorials?)/`)
	// Repository URLs inside pluginManagement / buildscript blocks:
	// url "…", url = "…", url = uri("…"), setUrl("…"), maven("…"), and the
	// file("…") form for local directories.
	gradleRepoURLRe = regexp.MustCompile(`\b(?:url|setUrl|maven|file)\s*[=(]?\s*(?:uri\s*\(\s*)?["']([^"'\s)]+)["']`)
	gradleDirPrefix = regexp.MustCompile(`^\$\{?(rootDir|projectDir|rootProject\.projectDir|layout\.projectDirectory(\.asFile)?|project\.rootDir|project\.projectDir)\}?/`)
	javaAgentRe     = regexp.MustCompile(`-(javaagent|agentpath|agentlib):(\S*)`)
	nixHookRe       = regexp.MustCompile(`(?m)^\s*shellHook\s*=\s*('')?`)
	useNixRe        = regexp.MustCompile(`(?m)^\s*use\s+(flake|nix)\b`)
)

func detectBuild(c *Context) []finding.Finding {
	var out []finding.Finding
	for _, f := range c.Files {
		base := path.Base(f.Path)
		switch {
		case base == "gradle-wrapper.properties" || base == "maven-wrapper.properties":
			out = append(out, wrapperProperties(c, f.Path)...)
		case strings.HasSuffix(base, ".gradle") || strings.HasSuffix(base, ".gradle.kts"):
			out = append(out, gradleScript(c, f.Path)...)
		case base == "jvm.config" && path.Base(path.Dir(f.Path)) == ".mvn":
			out = append(out, mavenJVMConfig(c, f.Path)...)
		case ext(f.Path) == ".nix":
			out = append(out, nixShellHook(c, f.Path)...)
		}
	}
	return out
}

func wrapperProperties(c *Context, file string) []finding.Finding {
	data, ok := c.Read(file)
	if !ok {
		return nil
	}
	tool := "Gradle"
	if strings.HasPrefix(path.Base(file), "maven") {
		tool = "Maven"
	}
	var out []finding.Finding
	for i, raw := range strings.Split(string(data), "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(raw), "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		if key != "distributionUrl" && key != "wrapperUrl" {
			continue
		}
		val = strings.ReplaceAll(val, `\:`, ":")
		u, err := url.Parse(val)
		host := ""
		if err == nil {
			host = strings.ToLower(u.Hostname())
		}
		if officialWrapperHosts[host] {
			continue
		}
		// A corporate mirror is plausible; plaintext, a raw IP or a local
		// path is how you would deliver a doctored distribution.
		sev := finding.Medium
		msg := fmt.Sprintf("%s wrapper downloads the build tool from %s instead of the official site", tool, host)
		switch {
		case err != nil || u.Scheme == "" || u.Scheme == "file":
			sev, msg = finding.High, fmt.Sprintf("%s wrapper runs a build distribution from a local path", tool)
		case u.Scheme == "http" || looksIPLiteral(host):
			sev = finding.High
		}
		fd := newFinding("PF331", sev, finding.TriggerBuild, file, i+1, msg)
		fd.Evidence = truncate(val, 200)
		out = append(out, fd)
	}
	return out
}

func looksIPLiteral(host string) bool {
	var a, b, c, d int
	n, _ := fmt.Sscanf(host, "%d.%d.%d.%d", &a, &b, &c, &d)
	return n == 4
}

func gradleScript(c *Context, file string) []finding.Finding {
	data, ok := c.Read(file)
	if !ok {
		return nil
	}
	var out []finding.Finding
	execLoc, netLoc := gradleExecRe.FindIndex(data), gradleNetRe.FindIndex(data)
	if execLoc != nil || netLoc != nil {
		// Running git describe for a version string is routine; opening
		// a connection is not; doing both is the download-and-run shape.
		sev, loc, msg := finding.Low, execLoc, "Gradle build script runs commands when the project is imported or built"
		switch {
		case execLoc != nil && netLoc != nil:
			sev, msg = finding.High, "Gradle build script runs commands and makes network requests when the project is imported or built"
		case execLoc == nil:
			sev, loc, msg = finding.Medium, netLoc, "Gradle build script makes network requests when the project is imported or built"
		}
		fd := newFinding("PF332", sev, finding.TriggerBuild, file, lineAt(data, loc[0]), msg)
		fd.Evidence = truncate(lineText(data, loc[0]), 160)
		out = append(out, fd)
	}
	for _, blockName := range []string{"pluginManagement", "buildscript"} {
		body, off := braceBlock(data, blockName)
		if body == nil {
			continue
		}
		for _, m := range gradleRepoURLRe.FindAllSubmatchIndex(body, -1) {
			raw := string(body[m[2]:m[3]])
			var msg string
			sev := finding.High
			if strings.Contains(raw, "://") {
				u, err := url.Parse(raw)
				if err != nil {
					continue
				}
				host := strings.ToLower(u.Hostname())
				switch {
				case looksIPLiteral(host):
					msg = fmt.Sprintf("%s resolves build plugins from a raw IP address", blockName)
				case u.Scheme == "http":
					sev, msg = finding.Medium, fmt.Sprintf("%s resolves build plugins over plaintext HTTP from %s", blockName, host)
				default:
					continue // an https repository or mirror is normal
				}
			} else {
				// A local repository is only a vector when the plugin jars
				// are shipped in the repository. A path under build/ or one
				// interpolated from a property is unknown, not a finding.
				dir := strings.TrimPrefix(gradleDirPrefix.ReplaceAllString(raw, ""), "./")
				if strings.ContainsAny(dir, "${}") {
					continue
				}
				full := path.Join(dirOf(file), dir)
				if !dirHasFiles(c, full) {
					if full = dir; !dirHasFiles(c, full) {
						continue
					}
				}
				msg = fmt.Sprintf("%s resolves build plugins from %s inside the repository", blockName, dir)
				// High only when plugin code (a jar) is actually shipped and
				// this is the build a developer would open, not a sample.
				if !dirHasExt(c, full, ".jar") || samplePathRe.MatchString(file) || isTestFile(file) {
					sev = finding.Medium
				}
			}
			fd := newFinding("PF333", sev, finding.TriggerBuild, file, lineAt(data, off+m[0]), msg)
			fd.Evidence = truncate(raw, 200)
			out = append(out, fd)
			break
		}
	}
	return out
}

// dirHasExt reports whether a file with the extension sits under dir.
func dirHasExt(c *Context, dir, e string) bool {
	for _, f := range c.Files {
		if strings.HasPrefix(f.Path, dir+"/") && ext(f.Path) == e {
			return true
		}
	}
	return false
}

// dirHasFiles reports whether any walked file sits under dir.
func dirHasFiles(c *Context, dir string) bool {
	if dir == "" || dir == "." {
		return false
	}
	for _, f := range c.Files {
		if strings.HasPrefix(f.Path, dir+"/") {
			return true
		}
	}
	return false
}

// braceBlock returns the body of the first `name { ... }` block and its
// byte offset, matching braces without regard to strings or comments
// (close enough for build scripts, and bounded by the file size).
func braceBlock(data []byte, name string) ([]byte, int) {
	i := strings.Index(string(data), name)
	for i >= 0 {
		after := data[i+len(name):]
		j := 0
		for j < len(after) && (after[j] == ' ' || after[j] == '\t' || after[j] == '\r' || after[j] == '\n') {
			j++
		}
		if j < len(after) && after[j] == '{' {
			start := i + len(name) + j + 1
			depth := 1
			for k := start; k < len(data); k++ {
				switch data[k] {
				case '{':
					depth++
				case '}':
					if depth--; depth == 0 {
						return data[start:k], start
					}
				}
			}
			return data[start:], start
		}
		next := strings.Index(string(data[i+len(name):]), name)
		if next < 0 {
			break
		}
		i += len(name) + next
	}
	return nil, 0
}

func mavenJVMConfig(c *Context, file string) []finding.Finding {
	data, ok := c.Read(file)
	if !ok {
		return nil
	}
	m := javaAgentRe.FindSubmatchIndex(data)
	if m == nil {
		return nil
	}
	flag := string(data[m[0]:m[1]])
	arg := strings.SplitN(string(data[m[4]:m[5]]), "=", 2)[0]
	targets := commandTargets(c, "", arg)
	sev := finding.Medium
	switch {
	case len(targets) > 0:
		sev = finding.High
	case isTestFile(file):
		sev = finding.Low // Maven's own integration-test projects
	}
	fd := newFinding("PF334", sev, finding.TriggerBuild, file, lineAt(data, m[0]),
		"Every mvn command (and IDE import) loads a Java agent from .mvn/jvm.config")
	fd.Evidence = truncate(flag, 200)
	fd.Targets = targets
	return []finding.Finding{fd}
}

// nixShellHook reports a shellHook in a .nix file. The hook body is the
// ” … ” or "…" string that follows; a hook that only exports variables
// is low, one reached automatically through direnv is medium, and one that
// pipes the network into a shell is high.
func nixShellHook(c *Context, file string) []finding.Finding {
	data, ok := c.Read(file)
	if !ok {
		return nil
	}
	m := nixHookRe.FindSubmatchIndex(data)
	if m == nil {
		return nil
	}
	body := nixString(data[m[1]:], m[2] >= 0)
	sev := finding.Low
	if envrcUsesNix(c, dirOf(file)) {
		sev = finding.Medium
	}
	if envrcDangerRe.MatchString(body) {
		sev = finding.High
	}
	fd := newFinding("PF322", sev, finding.TriggerShellEnter, file, lineAt(data, m[0]),
		"shellHook runs when you enter the Nix development shell")
	fd.Evidence = truncate(body, 300)
	fd.Targets = commandTargets(c, dirOf(file), body)
	return []finding.Finding{fd}
}

// nixString returns the content of an indented (” ”) or plain string that
// starts at data, stopping at the first closing quote.
func nixString(data []byte, indented bool) string {
	if indented {
		if i := strings.Index(string(data), "''"); i >= 0 {
			return string(data[:i])
		}
		return string(data[:min(len(data), 2000)])
	}
	rest := strings.TrimLeft(string(data), " \t")
	if !strings.HasPrefix(rest, `"`) {
		return ""
	}
	rest = rest[1:]
	if i := strings.Index(rest, `"`); i >= 0 {
		return rest[:i]
	}
	return rest[:min(len(rest), 2000)]
}

// envrcUsesNix reports whether the .envrc of dir (or the root) enters a Nix
// shell, which runs the shellHook on cd.
func envrcUsesNix(c *Context, dir string) bool {
	for _, p := range []string{path.Join(dir, ".envrc"), ".envrc"} {
		if data, ok := c.Read(p); ok && useNixRe.Match(data) {
			return true
		}
	}
	return false
}
