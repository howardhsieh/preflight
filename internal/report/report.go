// Package report renders scan results as a terminal table, JSON or SARIF.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/howardhsieh/preflight/internal/finding"
	"github.com/howardhsieh/preflight/internal/scan"
)

// TableOptions controls terminal output.
type TableOptions struct {
	Color       bool
	MinSeverity finding.Severity
}

const (
	reset = "\x1b[0m"
	bold  = "\x1b[1m"
	dim   = "\x1b[2m"
)

var sevColor = map[finding.Severity]string{
	finding.Critical: "\x1b[1;91m",
	finding.High:     "\x1b[31m",
	finding.Medium:   "\x1b[33m",
	finding.Low:      "\x1b[36m",
	finding.Info:     dim,
}

// 256-colour badges: terminal themes restyle the basic 16 colours, which
// can leave white-on-red looking like pink-on-pink.
var verdictColor = map[string]string{
	scan.VerdictDanger: "\x1b[1;38;5;231;48;5;160m",
	scan.VerdictReview: "\x1b[1;38;5;232;48;5;214m",
	scan.VerdictClean:  "\x1b[1;38;5;232;48;5;34m",
}

var advice = map[string]string{
	scan.VerdictDanger: "Do not open this repository in VS Code/Cursor, run npm install, or start an AI agent in it.\n  If you must inspect it, use a disposable VM or Codespace with Workspace Trust in Restricted Mode.",
	scan.VerdictReview: "Review the findings above before opening this repository in an IDE, installing\n  dependencies, or starting an AI agent in it.",
	scan.VerdictClean:  "No auto-execution vectors found. preflight only checks for code that runs\n  automatically; it does not prove the code itself is safe.",
}

// Table writes a human-readable report.
func Table(w io.Writer, r *scan.Result, opt TableOptions) error {
	paint := func(code, s string) string {
		if !opt.Color {
			return s
		}
		return code + s + reset
	}

	fmt.Fprintf(w, "\n %s  %s   score %d/100   %d files scanned\n\n",
		paint(verdictColor[r.Verdict], " "+r.Verdict+" "), paint(bold, r.Root), r.Score, r.FilesScanned)
	if r.Truncated {
		fmt.Fprintln(w, paint("\x1b[33m", " ! File limit reached; part of the repository was not scanned.\n"))
	}

	counts := map[finding.Severity]int{}
	shown := 0
	for _, f := range r.Findings {
		counts[f.Severity]++
		if f.Severity < opt.MinSeverity {
			continue
		}
		shown++
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		label := fmt.Sprintf("[%s]", strings.ToUpper(f.Severity.String()))
		fmt.Fprintf(w, " %s %s  %s\n", paint(sevColor[f.Severity], fmt.Sprintf("%-10s", label)), paint(bold, loc), paint(dim, f.RuleID+" "+f.Rule))
		fmt.Fprintf(w, "            %s\n", f.Message)
		if f.Evidence != "" {
			fmt.Fprintf(w, "            %s\n", paint(dim, "→ "+f.Evidence))
		}
		fmt.Fprintln(w)
	}
	if shown == 0 {
		fmt.Fprintln(w, " No findings at or above", opt.MinSeverity, "severity.")
		fmt.Fprintln(w)
	}

	var parts []string
	for s := finding.Critical; s >= finding.Low; s-- {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, " %s\n", strings.Join(parts, ", "))
	}
	_, err := fmt.Fprintf(w, " %s\n\n", advice[r.Verdict])
	return err
}

// JSON writes the result as indented JSON.
func JSON(w io.Writer, r *scan.Result, version string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Tool    string `json:"tool"`
		Version string `json:"version"`
		*scan.Result
	}{"preflight", version, r})
}
