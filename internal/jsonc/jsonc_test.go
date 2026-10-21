package jsonc

import (
	"reflect"
	"strings"
	"testing"
)

func TestUnmarshal(t *testing.T) {
	src := "\xef\xbb\xbf{\n" +
		"  // line comment\n" +
		"  \"url\": \"https://example.com//x\", /* block\n comment */\n" +
		"  \"s\": \"a,}\\\"//\",\n" +
		"  \"list\": [1, 2, // trailing\n ],\n" +
		"}"
	var got map[string]any
	if err := Unmarshal([]byte(src), &got); err != nil {
		t.Fatalf("Unmarshal: %v\n%s", err, Standardize([]byte(src)))
	}
	want := map[string]any{"url": "https://example.com//x", "s": `a,}"//`, "list": []any{1.0, 2.0}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestStandardizeKeepsLines(t *testing.T) {
	src := "{\n/* a\nb\nc */\n\"k\": 1\n}"
	if got, want := strings.Count(string(Standardize([]byte(src))), "\n"), strings.Count(src, "\n"); got != want {
		t.Errorf("newlines = %d, want %d", got, want)
	}
}
