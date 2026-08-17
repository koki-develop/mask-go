package mask

import "testing"

func Test_Fixed(t *testing.T) {
	r := Fixed("[REDACTED]")
	for _, value := range []string{"", "a", "abcdef", "日本語"} {
		if got := r.Redact(Match{Value: value}); got != "[REDACTED]" {
			t.Errorf("Redact(%q) = %q, want %q", value, got, "[REDACTED]")
		}
	}
}

func Test_Fill(t *testing.T) {
	tests := []struct {
		name  string
		fill  rune
		value string
		want  string
	}{
		{name: "ascii", fill: '*', value: "abcdef", want: "******"},
		{name: "empty value", fill: '*', value: "", want: ""},
		{name: "one rune per rune, not per byte", fill: '*', value: "日本語", want: "***"},
		{name: "multi-byte fill rune", fill: '●', value: "abc", want: "●●●"},
		{name: "invalid utf-8 counts as one rune per bad byte", fill: '*', value: "\xff\xfe", want: "**"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Fill(tt.fill).Redact(Match{Value: tt.value}); got != tt.want {
				t.Errorf("Redact(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func Test_NewRedactor(t *testing.T) {
	p := fixed("p", Span{2, 4})
	var got Match
	r := NewRedactor(func(m Match) string {
		got = m
		return "X"
	})

	if out := New(WithPatterns(p), WithRedactor(r)).Mask("abcdef"); out != "abXef" {
		t.Errorf("Mask() = %q, want %q", out, "abXef")
	}
	if got.Value != "cd" {
		t.Errorf("Match.Value = %q, want %q", got.Value, "cd")
	}
	if got.Pattern != p {
		t.Errorf("Match.Pattern = %v, want the pattern that located the value", got.Pattern)
	}
}

func Test_NewRedactor_comparable(t *testing.T) {
	// Comparing interface values holding a func type panics, so the redactors
	// this package hands out must not be func types.
	redactors := map[string][2]Redactor{
		"NewRedactor": {NewRedactor(nil), NewRedactor(nil)},
		"Fixed":       {Fixed("x"), Fixed("x")},
		"Fill":        {Fill('*'), Fill('*')},
	}
	for name, pair := range redactors {
		t.Run(name, func(t *testing.T) {
			if pair[0] == pair[1] {
				t.Error("separately built redactors compared equal")
			}
			if pair[0] != pair[0] { //nolint:staticcheck // the point is that == is defined
				t.Error("a redactor did not compare equal to itself")
			}
		})
	}
}
