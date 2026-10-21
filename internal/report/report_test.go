package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/howardhsieh/preflight/internal/finding"
	"github.com/howardhsieh/preflight/internal/scan"
)

func sample() *scan.Result {
	fs := []finding.Finding{
		{RuleID: "PF101", Rule: "vscode-folderopen-task", Severity: finding.Critical, Trigger: finding.TriggerIDEOpen,
			File: ".vscode/tasks.json", Line: 7, Message: "runs on open", Evidence: "node x.js"},
		{RuleID: "PF802", Rule: "native-executable", Severity: finding.Low, File: "bin/tool"},
	}
	score, verdict := scan.Score(fs)
	return &scan.Result{Root: "repo", Verdict: verdict, Score: score, FilesScanned: 3, Findings: fs}
}

func TestSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, sample(), "test"); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 || len(log.Runs[0].Results) != 2 {
		t.Fatalf("unexpected SARIF: %s", buf.String())
	}
	r := log.Runs[0].Results
	if r[0].Level != "error" || r[0].Locations[0].PhysicalLocation.Region.StartLine != 7 {
		t.Errorf("first result = %+v", r[0])
	}
	if r[1].Locations[0].PhysicalLocation.Region != nil {
		t.Error("line 0 must omit region (SARIF startLine must be >= 1)")
	}
}

func TestTableHidesLowSeverity(t *testing.T) {
	var buf bytes.Buffer
	if err := Table(&buf, sample(), TableOptions{MinSeverity: finding.Medium}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "DANGER") || !strings.Contains(out, ".vscode/tasks.json:7") {
		t.Errorf("missing verdict or location:\n%s", out)
	}
	if strings.Contains(out, "bin/tool") {
		t.Errorf("low finding shown despite MinSeverity:\n%s", out)
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("color codes emitted with Color=false")
	}
}
