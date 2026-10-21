package detect

import (
	"fmt"
	"path"
	"strings"

	"github.com/howardhsieh/preflight/internal/finding"
)

var lifecycleKeys = []string{"onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"}

var credentialDirs = []string{".ssh", ".aws", ".azure", ".kube", ".docker", ".gnupg", ".npmrc", ".config/gh", ".config/gcloud", ".git-credentials"}

func isDevcontainerFile(p string) bool {
	base := path.Base(p)
	return base == ".devcontainer.json" || (base == "devcontainer.json" && strings.Contains(p, ".devcontainer"))
}

func detectDevcontainer(c *Context) []finding.Finding {
	var out []finding.Finding
	for _, f := range c.Files {
		if !isDevcontainerFile(f.Path) {
			continue
		}
		data, doc, ok := readJSONC(c, f.Path)
		if !ok {
			continue
		}
		if v, ok := doc["initializeCommand"]; ok {
			cmd := commandString(v)
			fd := newFinding("PF201", finding.High, finding.TriggerContainer, f.Path, lineOf(data, "initializeCommand"),
				"initializeCommand runs on your host machine (not in the container) when the dev container opens")
			fd.Evidence = truncate(cmd, 300)
			fd.Targets = commandTargets(c, "", cmd)
			out = append(out, fd)
		}
		for _, k := range lifecycleKeys {
			v, ok := doc[k]
			if !ok {
				continue
			}
			cmd := commandString(v)
			fd := newFinding("PF202", finding.Low, finding.TriggerContainer, f.Path, lineOf(data, k),
				fmt.Sprintf("%s runs inside the container when it is created or started", k))
			fd.Evidence = truncate(cmd, 300)
			fd.Targets = commandTargets(c, "", cmd)
			out = append(out, fd)
		}

		var mounts []string
		if ms, ok := doc["mounts"].([]any); ok {
			for _, m := range ms {
				switch t := m.(type) {
				case string:
					mounts = append(mounts, t)
				case map[string]any:
					mounts = append(mounts, str(t["source"]))
				}
			}
		}
		mounts = append(mounts, str(doc["workspaceMount"]))
		runArgs := ""
		if ra, ok := doc["runArgs"].([]any); ok {
			runArgs = commandString(ra)
			mounts = append(mounts, runArgs)
		}
		for _, m := range mounts {
			if mountsHostCredentials(m) {
				fd := newFinding("PF203", finding.High, finding.TriggerContainer, f.Path, lineOf(data, "mounts"),
					"Dev container mounts credentials from your home directory")
				fd.Evidence = truncate(m, 200)
				out = append(out, fd)
				break
			}
		}
		if priv, _ := doc["privileged"].(bool); priv || privilegedArgs(runArgs) {
			out = append(out, newFinding("PF204", finding.Medium, finding.TriggerContainer, f.Path, lineOf(data, "privileged"),
				"Dev container requests privileged or host-level access"))
		}
	}
	return out
}

func mountsHostCredentials(s string) bool {
	l := strings.ToLower(s)
	if !strings.Contains(l, "localenv:home") && !strings.Contains(l, "localenv:userprofile") && !strings.Contains(l, "~/") {
		return false
	}
	for _, d := range credentialDirs {
		if strings.Contains(l, d) {
			return true
		}
	}
	// The whole home directory.
	return strings.Contains(l, "source=${localenv:home},") || strings.Contains(l, "source=${localenv:home}}")
}

func privilegedArgs(args string) bool {
	for _, a := range []string{"--privileged", "--pid=host", "--network=host", "--net=host", "sys_admin", "-v /:", "--volume=/:"} {
		if strings.Contains(strings.ToLower(args), a) {
			return true
		}
	}
	return false
}
