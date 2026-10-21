package clone

import (
	"slices"
	"testing"
)

func TestValidateURL(t *testing.T) {
	ok := []string{
		"https://github.com/owner/repo",
		"https://github.com/owner/repo.git",
		"git@github.com:owner/repo.git",
		"ssh://git@github.com/owner/repo",
	}
	bad := []string{
		"", "--upload-pack=touch /tmp/x", "ext::sh -c id", "file:///etc", "/tmp/repo",
		"http://github.com/owner/repo", "https://github.com/a b", "git@host::x",
	}
	for _, u := range ok {
		if err := ValidateURL(u); err != nil {
			t.Errorf("ValidateURL(%q) = %v, want nil", u, err)
		}
	}
	for _, u := range bad {
		if ValidateURL(u) == nil {
			t.Errorf("ValidateURL(%q) accepted a dangerous URL", u)
		}
	}
}

func TestDefaultDir(t *testing.T) {
	cases := map[string]string{
		"https://github.com/owner/repo.git": "repo",
		"git@github.com:owner/tool":         "tool",
		"https://github.com/owner/x/":       "x",
		"https://github.com/..":             "repo",
	}
	for in, want := range cases {
		if got := DefaultDir(in); got != want {
			t.Errorf("DefaultDir(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestArgsEndOptions(t *testing.T) {
	args := Args("https://x/y", "dest")
	i := slices.Index(args, "--")
	if i < 0 || args[i+1] != "https://x/y" {
		t.Fatalf("URL must follow --: %v", args)
	}
	for _, want := range []string{"--no-recurse-submodules", "core.hooksPath=/dev/null", "protocol.ext.allow=never"} {
		if !slices.Contains(args, want) {
			t.Errorf("missing %s in %v", want, args)
		}
	}
}
