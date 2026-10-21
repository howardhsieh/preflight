// Package finding defines the result types shared by detectors and reporters.
package finding

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity ranks how dangerous a finding is.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "unknown"
	}
	return severityNames[s]
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// ParseSeverity converts a name such as "high" into a Severity.
func ParseSeverity(v string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(v, n) {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (want info, low, medium, high or critical)", v)
}

// Trigger describes the user action that would cause a finding's code to run.
// Content-only findings (obfuscation, hidden characters) have no trigger.
type Trigger string

const (
	TriggerNone        Trigger = ""
	TriggerIDEOpen     Trigger = "ide-open"
	TriggerIDESettings Trigger = "ide-settings"
	TriggerContainer   Trigger = "container-open"
	TriggerInstall     Trigger = "install"
	TriggerRun         Trigger = "manual-run"
	TriggerBuild       Trigger = "build"
	TriggerShellEnter  Trigger = "shell-enter"
	TriggerGit         Trigger = "git"
	TriggerAgent       Trigger = "ai-agent"
)

// Finding is a single issue found in a repository.
type Finding struct {
	RuleID   string   `json:"rule_id"`
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Trigger  Trigger  `json:"trigger,omitempty"`
	File     string   `json:"file"`
	Line     int      `json:"line,omitempty"`
	Message  string   `json:"message"`
	Evidence string   `json:"evidence,omitempty"`
	// Targets lists repository files that this trigger would execute.
	Targets []string `json:"targets,omitempty"`
}
