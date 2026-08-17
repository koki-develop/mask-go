package mask

import (
	"strings"
	"sync"
	"testing"
)

// fixed returns a Pattern reporting name that always locates spans, whatever
// the input. It lets the resolution rules be tested without a regular
// expression in the way.
func fixed(name string, spans ...Span) Pattern {
	return NewPattern(name, func(string) []Span { return spans })
}

// naming redacts a value to the name of the pattern that located it, in angle
// brackets, so that attribution is visible in the output.
var naming = NewRedactor(func(m Match) string { return "<" + m.Pattern.Name() + ">" })

func TestMasker_Mask(t *testing.T) {
	tests := []struct {
		name     string
		patterns []Pattern
		redactor Redactor
		src      string
		want     string
	}{
		{
			name: "no patterns redacts nothing",
			src:  "abcdef",
			want: "abcdef",
		},
		{
			name:     "pattern finding nothing redacts nothing",
			patterns: []Pattern{fixed("p")},
			src:      "abcdef",
			want:     "abcdef",
		},
		{
			name:     "value in the middle",
			patterns: []Pattern{fixed("p", Span{2, 4})},
			src:      "abcdef",
			want:     "ab**ef",
		},
		{
			name:     "value at the start",
			patterns: []Pattern{fixed("p", Span{0, 2})},
			src:      "abcdef",
			want:     "**cdef",
		},
		{
			name:     "value at the end",
			patterns: []Pattern{fixed("p", Span{4, 6})},
			src:      "abcdef",
			want:     "abcd**",
		},
		{
			name:     "whole input",
			patterns: []Pattern{fixed("p", Span{0, 6})},
			src:      "abcdef",
			want:     "******",
		},
		{
			name:     "several values from one pattern",
			patterns: []Pattern{fixed("p", Span{0, 2}, Span{4, 6})},
			src:      "abcdef",
			want:     "**cd**",
		},
		{
			name:     "values from several patterns",
			patterns: []Pattern{fixed("p", Span{0, 2}), fixed("q", Span{4, 6})},
			src:      "abcdef",
			want:     "**cd**",
		},
		{
			name:     "unordered spans are sorted",
			patterns: []Pattern{fixed("p", Span{4, 6}, Span{0, 2})},
			src:      "abcdef",
			want:     "**cd**",
		},
		{
			name:     "adjacent values stay separate",
			patterns: []Pattern{fixed("p", Span{0, 2}, Span{2, 4})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "XXef",
		},
		{
			name:     "contained value merges into the containing one",
			patterns: []Pattern{fixed("p", Span{0, 6}, Span{2, 4})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "X",
		},
		{
			name:     "partly overlapping values merge",
			patterns: []Pattern{fixed("p", Span{0, 4}), fixed("q", Span{2, 6})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "X",
		},
		{
			name:     "chain of overlaps merges into one",
			patterns: []Pattern{fixed("p", Span{0, 3}, Span{2, 5}, Span{4, 6})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "X",
		},
		{
			name:     "identical values merge",
			patterns: []Pattern{fixed("p", Span{0, 2}), fixed("q", Span{0, 2})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "Xcdef",
		},
		{
			name:     "empty span is ignored",
			patterns: []Pattern{fixed("p", Span{2, 2})},
			src:      "abcdef",
			want:     "abcdef",
		},
		{
			name:     "reversed span is ignored",
			patterns: []Pattern{fixed("p", Span{4, 2})},
			src:      "abcdef",
			want:     "abcdef",
		},
		{
			name:     "span starting before the input is ignored",
			patterns: []Pattern{fixed("p", Span{-1, 2})},
			src:      "abcdef",
			want:     "abcdef",
		},
		{
			name:     "span reaching past the input is ignored",
			patterns: []Pattern{fixed("p", Span{4, 7})},
			src:      "abcdef",
			want:     "abcdef",
		},
		{
			name:     "an ignored span leaves the others alone",
			patterns: []Pattern{fixed("p", Span{4, 7}, Span{0, 2})},
			src:      "abcdef",
			want:     "**cdef",
		},
		{
			name:     "empty input",
			patterns: []Pattern{fixed("p", Span{0, 1})},
			src:      "",
			want:     "",
		},
		{
			name:     "fill counts runes, not bytes",
			patterns: []Pattern{fixed("p", Span{0, 9})},
			src:      "日本語abc",
			want:     "***abc",
		},
		{
			name:     "text around a value is left alone byte for byte",
			patterns: []Pattern{fixed("p", Span{9, 12})},
			src:      "日本語abc",
			want:     "日本語***",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []Option{WithPatterns(tt.patterns...)}
			if tt.redactor != nil {
				opts = append(opts, WithRedactor(tt.redactor))
			}
			if got := New(opts...).Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func TestMasker_Mask_attribution(t *testing.T) {
	tests := []struct {
		name     string
		patterns []Pattern
		want     string
	}{
		{
			name:     "the value starting earliest is attributed",
			patterns: []Pattern{fixed("late", Span{2, 6}), fixed("early", Span{0, 4})},
			want:     "<early>", // the two merge into the whole input
		},
		{
			name:     "on the same start the longest is attributed",
			patterns: []Pattern{fixed("short", Span{0, 2}), fixed("long", Span{0, 4})},
			want:     "<long>ef",
		},
		{
			name:     "on the same span the pattern added first is attributed",
			patterns: []Pattern{fixed("first", Span{0, 6}), fixed("second", Span{0, 6})},
			want:     "<first>",
		},
		{
			name:     "order of WithPatterns decides, not the name",
			patterns: []Pattern{fixed("second", Span{0, 6}), fixed("first", Span{0, 6})},
			want:     "<second>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(WithPatterns(tt.patterns...), WithRedactor(naming))
			if got := m.Mask("abcdef"); got != tt.want {
				t.Errorf("Mask() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMasker_Mask_coversEveryLocatedByte(t *testing.T) {
	// Whatever the overlap, no byte reported by any pattern may survive. The
	// three spans below chain from 0 to 9, so only the last byte of the input
	// is left.
	m := New(
		WithPatterns(fixed("p", Span{0, 4}, Span{2, 6}, Span{5, 9})),
		WithRedactor(NewRedactor(func(Match) string { return "" })),
	)
	if got, want := m.Mask("abcdefghij"), "j"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}

func TestMasker_Mask_withoutMatchDoesNotAllocate(t *testing.T) {
	if raceEnabled {
		// regexp allocates under the race detector even when it matches
		// nothing, which would drown out what this measures.
		t.Skip("the race detector adds allocations of its own")
	}

	src := strings.Repeat("the quick brown fox ", 100)
	for name, m := range map[string]*Masker{
		"pattern finding nothing": New(WithPatterns(fixed("p"))),
		"built-in patterns":       New(WithPatterns(DefaultPatterns()...)),
	} {
		t.Run(name, func(t *testing.T) {
			if n := testing.AllocsPerRun(100, func() { _ = m.Mask(src) }); n != 0 {
				t.Errorf("Mask() allocated %v times, want 0", n)
			}
		})
	}
}

func TestMasker_Mask_concurrentUse(t *testing.T) {
	m := New(WithPatterns(DefaultPatterns()...))
	src := "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	want := "GITHUB_TOKEN=****************************************"

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 32 {
				if got := m.Mask(src); got != want {
					t.Errorf("Mask() = %q, want %q", got, want)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func Test_New_defaultRedactor(t *testing.T) {
	m := New(WithPatterns(fixed("p", Span{0, 3})))
	if got, want := m.Mask("abcdef"), "***def"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}

func TestMasker_Mask_overlappingBuiltinPatterns(t *testing.T) {
	// The stateless installation token holds a JWT, so both built-in patterns
	// fire on it and the overlap must leave nothing of the token behind.
	m := New(WithPatterns(DefaultPatterns()...))
	src := "token=ghs_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef"
	want := "token=***********************************************************************************"
	if got := m.Mask(src); got != want {
		t.Errorf("Mask(%q) = %q, want %q", src, got, want)
	}
}

func Test_New_optionOrder(t *testing.T) {
	want := "Xdef"
	forward := New(WithPatterns(fixed("p", Span{0, 3})), WithRedactor(Fixed("X"))).Mask("abcdef")
	backward := New(WithRedactor(Fixed("X")), WithPatterns(fixed("p", Span{0, 3}))).Mask("abcdef")
	if forward != want || backward != want {
		t.Errorf("Mask() = %q and %q, want %q for both", forward, backward, want)
	}
}
