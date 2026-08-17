package mask

import "testing"

func Test_WithPatterns_accumulates(t *testing.T) {
	m := New(
		WithPatterns(fixed("a", Span{0, 2})),
		WithPatterns(fixed("b", Span{4, 6})),
		WithRedactor(naming),
	)
	if got, want := m.Mask("abcdef"), "<a>cd<b>"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}

func Test_WithPatterns_order(t *testing.T) {
	m := New(
		WithPatterns(fixed("a", Span{0, 6})),
		WithPatterns(fixed("b", Span{0, 6})),
		WithRedactor(naming),
	)
	if got, want := m.Mask("abcdef"), "<a>"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}

func Test_WithPatterns_noArguments(t *testing.T) {
	if got, want := New(WithPatterns()).Mask("abcdef"), "abcdef"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}

func Test_WithRedactor(t *testing.T) {
	m := New(WithPatterns(fixed("p", Span{0, 3})), WithRedactor(Fixed("X")))
	if got, want := m.Mask("abcdef"), "Xdef"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}

func Test_WithRedactor_lastWins(t *testing.T) {
	m := New(
		WithPatterns(fixed("p", Span{0, 3})),
		WithRedactor(Fixed("X")),
		WithRedactor(Fixed("Y")),
	)
	if got, want := m.Mask("abcdef"), "Ydef"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}
