package report

import (
	"encoding/json"
	"io"

	"github.com/howardhsieh/preflight/internal/finding"
	"github.com/howardhsieh/preflight/internal/scan"
)

// SARIF 2.1.0, the format GitHub code scanning ingests.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string            `json:"ruleId"`
	Level      string            `json:"level"`
	Message    sarifMessage      `json:"message"`
	Locations  []sarifLocation   `json:"locations"`
	Properties map[string]string `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func sarifLevel(s finding.Severity) string {
	switch {
	case s >= finding.High:
		return "error"
	case s == finding.Medium:
		return "warning"
	default:
		return "note"
	}
}

// SARIF writes the result as a SARIF 2.1.0 log.
func SARIF(w io.Writer, r *scan.Result, version string) error {
	rules := make([]sarifRule, 0, len(finding.Rules))
	for _, rl := range finding.Rules {
		rules = append(rules, sarifRule{ID: rl.ID, Name: rl.Name, ShortDescription: sarifMessage{rl.Description}})
	}
	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		loc := sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.File}}
		if f.Line > 0 {
			loc.Region = &sarifRegion{StartLine: f.Line}
		}
		msg := f.Message
		if f.Evidence != "" {
			msg += " — " + f.Evidence
		}
		props := map[string]string{"severity": f.Severity.String()}
		if f.Trigger != finding.TriggerNone {
			props["trigger"] = string(f.Trigger)
		}
		results = append(results, sarifResult{
			RuleID: f.RuleID, Level: sarifLevel(f.Severity), Message: sarifMessage{msg},
			Locations: []sarifLocation{{loc}}, Properties: props,
		})
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "preflight", Version: version,
				InformationURI: "https://github.com/howardhsieh/preflight", Rules: rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
