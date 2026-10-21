// Package scan runs every detector over a repository, links automatic
// triggers to the suspicious files they execute, and scores the result.
package scan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/howardhsieh/preflight/internal/detect"
	"github.com/howardhsieh/preflight/internal/finding"
	"github.com/howardhsieh/preflight/internal/walker"
)

// Verdicts, from safest to most dangerous.
const (
	VerdictClean  = "CLEAN"
	VerdictReview = "REVIEW"
	VerdictDanger = "DANGER"
)

// Options controls a scan.
type Options struct {
	Exclude  []string
	MaxFiles int
}

// Result is the outcome of scanning one repository.
type Result struct {
	Root         string            `json:"target"`
	Verdict      string            `json:"verdict"`
	Score        int               `json:"score"`
	FilesScanned int               `json:"files_scanned"`
	Truncated    bool              `json:"truncated,omitempty"`
	Findings     []finding.Finding `json:"findings"`
}

// Run scans the repository at root.
func Run(root string, opt Options) (*Result, error) {
	w, err := walker.Walk(root, walker.Options{Exclude: opt.Exclude, MaxFiles: opt.MaxFiles})
	if err != nil {
		return nil, err
	}
	files, fs := detect.SplitVirtualenvs(w.Files)
	ctx := detect.NewContext(root, files)
	for _, d := range detect.All() {
		fs = append(fs, d.Run(ctx)...)
	}
	fs = dedupe(correlate(fs))
	sortFindings(fs)

	score, verdict := Score(fs)
	if fs == nil {
		fs = []finding.Finding{}
	}
	return &Result{Root: root, Verdict: verdict, Score: score, FilesScanned: len(w.Files), Truncated: w.Truncated, Findings: fs}, nil
}

var triggerPhrase = map[finding.Trigger]string{
	finding.TriggerIDEOpen:     "Opening the folder in VS Code",
	finding.TriggerIDESettings: "VS Code applying workspace settings",
	finding.TriggerContainer:   "Opening the dev container",
	finding.TriggerInstall:     "Installing dependencies",
	finding.TriggerRun:         "Running the project's npm script",
	finding.TriggerBuild:       "Building the project",
	finding.TriggerShellEnter:  "Entering the directory with direnv",
	finding.TriggerGit:         "Running git commands",
	finding.TriggerAgent:       "Starting an AI coding agent",
}

// correlate adds a critical PF001 finding whenever a trigger executes a file
// that has suspicious content of its own. One signal alone is often benign
// (many projects have a postinstall script); the combination rarely is.
func correlate(fs []finding.Finding) []finding.Finding {
	content := map[string][]finding.Finding{}
	for _, f := range fs {
		if f.Trigger == finding.TriggerNone && f.Severity >= finding.Medium {
			content[f.File] = append(content[f.File], f)
		}
	}
	rule, _ := finding.RuleByID("PF001")
	var chains []finding.Finding
	for _, f := range fs {
		for _, t := range f.Targets {
			hits := content[t]
			if len(hits) == 0 {
				continue
			}
			var names []string
			seen := map[string]bool{}
			for _, h := range hits {
				if !seen[h.Rule] {
					seen[h.Rule] = true
					names = append(names, h.Rule)
				}
			}
			chains = append(chains, finding.Finding{
				RuleID: rule.ID, Rule: rule.Name, Severity: finding.Critical, Trigger: f.Trigger,
				File: f.File, Line: f.Line,
				Message:  fmt.Sprintf("%s executes %s, which contains: %s", triggerPhrase[f.Trigger], t, strings.Join(names, ", ")),
				Evidence: f.Evidence, Targets: []string{t},
			})
		}
	}
	return append(fs, chains...)
}

func dedupe(fs []finding.Finding) []finding.Finding {
	seen := map[string]bool{}
	out := fs[:0]
	for _, f := range fs {
		k := fmt.Sprintf("%s|%s|%d|%s", f.RuleID, f.File, f.Line, f.Message)
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

func sortFindings(fs []finding.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
}

var weights = map[finding.Severity]int{finding.Low: 2, finding.Medium: 8, finding.High: 20, finding.Critical: 40}

// Score turns findings into a 0-100 risk score and a verdict.
func Score(fs []finding.Finding) (int, string) {
	score, worst := 0, finding.Info
	for _, f := range fs {
		score += weights[f.Severity]
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	score = min(score, 100)
	switch {
	case worst == finding.Critical:
		return score, VerdictDanger
	case worst == finding.High || score >= 20:
		return score, VerdictReview
	default:
		return score, VerdictClean
	}
}
