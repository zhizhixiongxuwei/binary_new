package report

import (
	"strings"
	"testing"
)

func TestCFindingMessageTranslatesKnownRules(t *testing.T) {
	tests := []struct {
		ruleID  string
		message string
		want    string
	}{
		{
			ruleID:  "cwe-242-gets",
			message: "use of gets is unsafe",
			want:    "使用 gets 读取输入，存在缓冲区溢出风险 — use of gets is unsafe",
		},
		{
			ruleID:  "cwe-787-oob-write",
			message: "out-of-bounds write",
			want:    "越界写入风险 — out-of-bounds write",
		},
	}
	for _, test := range tests {
		got := cFindingMessage(test.ruleID, test.message)
		if got != test.want {
			t.Errorf("cFindingMessage(%q, %q) = %q, want %q",
				test.ruleID, test.message, got, test.want)
		}
		if !strings.Contains(got, test.message) {
			t.Errorf("translated message lost the original detail: %q", got)
		}
	}
}

func TestJavaFindingMessageTranslatesKnownRules(t *testing.T) {
	got := javaFindingMessage("java-sql-injection", "SQL statement built from untrusted input")
	want := "SQL 注入风险 — SQL statement built from untrusted input"
	if got != want {
		t.Errorf("javaFindingMessage() = %q, want %q", got, want)
	}
}

func TestDisplayMessageFallsBackForUnknownCodes(t *testing.T) {
	message := "unknown rule detail"
	if got := cFindingMessage("cwe-9999-unknown", message); got != message {
		t.Errorf("unknown rule translated to %q, want original %q", got, message)
	}
	if got := diagnosticMessage("not-a-code", message); got != message {
		t.Errorf("unknown diagnostic translated to %q, want original %q", got, message)
	}
}

func TestDisplayMessageOmitsEmptyOrDuplicateDetail(t *testing.T) {
	if got := cFindingMessage("cwe-369-zero-divisor", ""); got != "除零风险" {
		t.Errorf("empty message = %q, want title only", got)
	}
	if got := cFindingMessage("cwe-369-zero-divisor", "  除零风险  "); got != "除零风险" {
		t.Errorf("duplicate title = %q, want title only", got)
	}
}

func TestDiagnosticMessageTranslatesKnownCodes(t *testing.T) {
	got := diagnosticMessage("syntax_error", "expected ';' at line 3")
	want := "源码语法错误 — expected ';' at line 3"
	if got != want {
		t.Errorf("diagnosticMessage() = %q, want %q", got, want)
	}
}
