// Package clone fetches an untrusted repository with git's code-execution
// features switched off.
package clone

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
)

// ValidateURL accepts only https and ssh remotes, rejecting the transports
// and option-injection tricks that make git run commands.
func ValidateURL(u string) error {
	switch {
	case u == "":
		return errors.New("empty repository URL")
	case strings.HasPrefix(u, "-"):
		return errors.New("repository URL must not start with '-'")
	case strings.ContainsAny(u, " \t\n\r"):
		return errors.New("repository URL must not contain whitespace")
	case strings.HasPrefix(u, "https://"), strings.HasPrefix(u, "ssh://"):
		return nil
	case strings.HasPrefix(u, "git@") && strings.Contains(u, ":") && !strings.Contains(u, "::"):
		return nil
	}
	return fmt.Errorf("unsupported URL %q: use https://, ssh:// or git@host:owner/repo", u)
}

// DefaultDir derives a directory name from a repository URL.
func DefaultDir(u string) string {
	u = strings.TrimSuffix(strings.TrimSuffix(u, "/"), ".git")
	if i := strings.LastIndexAny(u, "/:"); i >= 0 {
		u = u[i+1:]
	}
	if u == "" || u == "." || u == ".." {
		return "repo"
	}
	return path.Base(u)
}

// Args returns the git arguments used for a hardened clone.
func Args(url, dest string) []string {
	return []string{
		// Per-command protections.
		"-c", "protocol.file.allow=never",
		"-c", "protocol.ext.allow=never",
		"-c", "core.fsmonitor=false",
		"-c", "submodule.recurse=false",
		"clone",
		"--no-recurse-submodules",
		"--depth=1",
		// Persisted into the new repository so later git commands stay safe.
		"--config", "core.hooksPath=/dev/null",
		"--config", "core.fsmonitor=false",
		"--", url, dest,
	}
}

// Run clones url into dest. dest must not exist yet.
func Run(ctx context.Context, url, dest string) error {
	if err := ValidateURL(url); err != nil {
		return err
	}
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("%s already exists", dest)
	}
	cmd := exec.CommandContext(ctx, "git", Args(url, dest)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_LFS_SKIP_SMUDGE=1")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
