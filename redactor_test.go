package mask

import (
	"testing"
	"unicode/utf8"
)

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
		// Fill does not vet the rune it is given; Go turns one outside Unicode
		// into the replacement character.
		{name: "a rune outside unicode", fill: rune(-1), value: "abc", want: "\ufffd\ufffd\ufffd"},
		// A surrogate and a rune past utf8.MaxRune are both outside Unicode as
		// well, coerced the same way as the negative rune above; utf8.RuneError
		// itself is a deliberate choice rather than a coercion, and encodes to
		// the identical three bytes because it is a valid rune of its own.
		{name: "a lone surrogate", fill: rune(0xD800), value: "ab", want: "\ufffd\ufffd"},
		{name: "a rune past utf8.MaxRune", fill: rune(utf8.MaxRune + 1), value: "ab", want: "\ufffd\ufffd"},
		{name: "utf8.RuneError written deliberately", fill: utf8.RuneError, value: "ab", want: "\ufffd\ufffd"},
		// A control byte, NUL included: Fill states no restriction on r.
		{name: "the NUL rune", fill: 0, value: "abc", want: "\x00\x00\x00"},
		{name: "a newline", fill: '\n', value: "ab", want: "\n\n"},
		// Fill counts runes, which is not always what a reader sees as one
		// character: a combining mark and a zero-width joiner are runes of
		// their own, so each gets a fill rune, and "length survives" means the
		// rune count rather than the number of glyphs on screen.
		{name: "a combining mark counts as a rune of its own", fill: '*', value: "e\u0301", want: "**"},
		{name: "a zero-width joiner counts as a rune of its own", fill: '*', value: "a\u200db", want: "***"},
		// The multi-byte side of the count and the multi-byte side of the fill
		// rune, driven together rather than one at a time.
		{name: "a multi-byte fill rune over a multi-byte value", fill: '\u25cf', value: "\u65e5\u672c\u8a9e", want: "\u25cf\u25cf\u25cf"},
		{name: "a multi-byte fill rune over an invalid utf-8 value", fill: '\u25cf', value: "\xff\xfe", want: "\u25cf\u25cf"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Fill(tt.fill).Redact(Match{Value: tt.value}); got != tt.want {
				t.Errorf("Redact(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func Test_Fixed_empty(t *testing.T) {
	// Fixed("") leaves nothing at all where the value was, which is how a
	// caller drops a value rather than marking it.
	m := New(WithPatterns(fixed("p", Span{2, 4})), WithRedactor(Fixed("")))
	if got, want := m.Mask("abcdef"), "abef"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
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

// Test_Redactor_ownOutputIsWrittenThroughUntouched holds Redact's own doc
// ("It is written out as it is returned") together with Mask's ("A redaction
// is itself text, and it does not read as the value it replaced"): what a
// redactor returns is written into the output of the pass that asked for it
// without being scanned again, even where that text is itself shaped like one
// of the values the Masker is looking for.
func Test_Redactor_ownOutputIsWrittenThroughUntouched(t *testing.T) {
	t.Run("a fixed replacement shaped like the pattern's own value", func(t *testing.T) {
		// The replacement below is a valid classic GitHub token in its own
		// right — thirty-six characters after ghp_ — and is not the value
		// src carries.
		replacement := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
		m := New(WithPatterns(GitHubToken()), WithRedactor(Fixed(replacement)))
		src := "TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789"
		want := "TOKEN=" + replacement
		if got := m.Mask(src); got != want {
			t.Errorf("Mask(%q) = %q, want %q", src, got, want)
		}
	})

	t.Run("a redactor echoing the value back in a shape that is itself a value", func(t *testing.T) {
		echo := NewRedactor(func(m Match) string { return "<" + m.Value + ">" })
		m := New(WithPatterns(GitHubToken()), WithRedactor(echo))
		src := "T1=ghp_0123456789abcdefghijklmnopqrstuvwxyz T2=ghp_abcdefghijklmnopqrstuvwxyz0123456789"
		want := "T1=<ghp_0123456789abcdefghijklmnopqrstuvwxyz> T2=<ghp_abcdefghijklmnopqrstuvwxyz0123456789>"
		if got := m.Mask(src); got != want {
			t.Errorf("Mask(%q) = %q, want %q", src, got, want)
		}
	})
}

// Test_Redactor_panicLeavesTheMaskerUsable holds a Masker to what it is
// documented as being — fixed once created — against a redactor that panics:
// Mask holds no state of its own that a panicking call could leave behind, so
// the panic reaches the caller of Mask unchanged and a later call succeeds
// exactly as if the first had never been made.
func Test_Redactor_panicLeavesTheMaskerUsable(t *testing.T) {
	calls := 0
	r := NewRedactor(func(Match) string {
		calls++
		if calls == 1 {
			panic("boom")
		}
		return "X"
	})
	m := New(WithPatterns(fixed("p", Span{0, 3})), WithRedactor(r))

	func() {
		defer func() {
			if rec := recover(); rec != "boom" {
				t.Fatalf("recover() = %v, want %v", rec, "boom")
			}
		}()
		m.Mask("abcdef")
	}()

	if got, want := m.Mask("abcdef"), "Xdef"; got != want {
		t.Errorf("Mask() after the panic = %q, want %q", got, want)
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
