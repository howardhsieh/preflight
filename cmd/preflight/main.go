// Command preflight checks an untrusted repository for code that would run
// automatically when you open, install, build or hand it to an AI agent.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/howardhsieh/preflight/internal/clone"
	"github.com/howardhsieh/preflight/internal/finding"
	"github.com/howardhsieh/preflight/internal/report"
	"github.com/howardhsieh/preflight/internal/scan"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `preflight — check a repository before you open it.

Usage:
  preflight scan  [flags] [path]        Scan a local directory (default ".")
  preflight clone [flags] <url> [dir]   Clone with git hooks/submodules disabled, then scan
  preflight rules                       List every rule
  preflight version                     Print the version

Flags (scan, clone):
  -f, --format table|json|sarif   Output format (default table)
  -o, --output FILE               Write the report to FILE instead of stdout
      --fail-on SEVERITY          Exit 1 if any finding is at least this severe:
                                  none, low, medium, high, critical (default high)
      --min-severity SEVERITY     Hide table rows below this severity (default low)
      --exclude PATH              Skip a path or glob; repeatable or comma-separated
      --no-color                  Disable colored output

Exit codes: 0 no blocking findings, 1 findings at or above --fail-on, 2 error.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "scan":
		return cmdScan(args[1:], stdout, stderr, false)
	case "clone":
		return cmdScan(args[1:], stdout, stderr, true)
	case "rules":
		for _, r := range finding.Rules {
			fmt.Fprintf(stdout, "%s  %-32s %s\n", r.ID, r.Name, r.Description)
		}
		return 0
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "preflight", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "preflight: unknown command %q\n\n%s", args[0], usage)
	return 2
}

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

func cmdScan(args []string, stdout, stderr io.Writer, doClone bool) int {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		format, output, failOn, minSev string
		noColor                        bool
		exclude                        listFlag
	)
	fs.StringVar(&format, "format", "table", "")
	fs.StringVar(&format, "f", "table", "")
	fs.StringVar(&output, "output", "", "")
	fs.StringVar(&output, "o", "", "")
	fs.StringVar(&failOn, "fail-on", "high", "")
	fs.StringVar(&minSev, "min-severity", "low", "")
	fs.BoolVar(&noColor, "no-color", false, "")
	fs.Var(&exclude, "exclude", "")

	// Allow flags after positional arguments.
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			fmt.Fprintf(stderr, "preflight: %v\n\n%s", err, usage)
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}

	var failSev finding.Severity = finding.Critical + 1
	if failOn != "none" {
		s, err := finding.ParseSeverity(failOn)
		if err != nil {
			fmt.Fprintln(stderr, "preflight:", err)
			return 2
		}
		failSev = s
	}
	showSev, err := finding.ParseSeverity(minSev)
	if err != nil {
		fmt.Fprintln(stderr, "preflight:", err)
		return 2
	}
	if format != "table" && format != "json" && format != "sarif" {
		fmt.Fprintf(stderr, "preflight: unknown format %q\n", format)
		return 2
	}

	target := "."
	if doClone {
		if len(pos) == 0 || len(pos) > 2 {
			fmt.Fprint(stderr, "preflight: clone needs <url> [dir]\n\n", usage)
			return 2
		}
		target = clone.DefaultDir(pos[0])
		if len(pos) == 2 {
			target = pos[1]
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		fmt.Fprintf(stderr, "preflight: cloning %s into %s (hooks, submodules and LFS disabled)\n", pos[0], target)
		if err := clone.Run(ctx, pos[0], target); err != nil {
			fmt.Fprintln(stderr, "preflight: clone failed:", err)
			return 2
		}
	} else if len(pos) == 1 {
		target = pos[0]
	} else if len(pos) > 1 {
		fmt.Fprint(stderr, "preflight: scan takes at most one path\n\n", usage)
		return 2
	}

	res, err := scan.Run(target, scan.Options{Exclude: exclude})
	if err != nil {
		fmt.Fprintln(stderr, "preflight:", err)
		return 2
	}

	out := stdout
	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			fmt.Fprintln(stderr, "preflight:", err)
			return 2
		}
		defer f.Close()
		out = f
	}

	switch format {
	case "json":
		err = report.JSON(out, res, version)
	case "sarif":
		err = report.SARIF(out, res, version)
	default:
		color := !noColor && output == "" && os.Getenv("NO_COLOR") == "" && isTerminal(stdout)
		err = report.Table(out, res, report.TableOptions{Color: color, MinSeverity: showSev})
	}
	if err != nil && !errors.Is(err, io.ErrClosedPipe) {
		fmt.Fprintln(stderr, "preflight:", err)
		return 2
	}

	for _, f := range res.Findings {
		if f.Severity >= failSev {
			return 1
		}
	}
	return 0
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
