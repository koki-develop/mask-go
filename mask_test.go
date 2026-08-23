package mask

import (
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

// checkSecondPass holds masking the output of masking src to locating nothing
// out of reach of what the first pass redacted. m must redact with Fill('*'),
// which is what the run lengths below are counted as.
//
// Masking is not idempotent and the doc comment on Mask says so: a redaction
// does not read as the value it replaced, so it can open a prefix that value
// closed — an AWS access key ID written against a Slack prefix is redacted
// first and takes a Slack token with it second. So what a second pass locates
// is not by itself a defect, and the property that survives is where it may
// locate: against what the first pass wrote, or overlapping it.
//
// A value out of reach of every redaction is the defect this is here for. It
// stands in text the first pass left as it found it, with the bytes either
// side of it the ones it was written with, so nothing about it had changed
// when the first pass read over it and declined to locate it: a scan whose
// cursor carried past a value, or one that stopped at the first of two.
//
// A value the first pass located only part of is not held here, and cannot be.
// The rest of one begins exactly where the redaction of its front ended, which
// is where a value a redaction opened begins as well, so no position tells the
// two apart. What holds a scan to locating a value whole is the reference
// beside it, which Test_builtins_matchTheirReference and each pattern's fuzz
// target drive, and the spans each builtin_<name>_test.go writes out.
func checkSecondPass(t testing.TB, m *Masker, src string) {
	t.Helper()

	// Where the first pass wrote, in the offsets of the masked text. Mask
	// copies the text between the values it locates and writes a rune for a
	// rune over each of them, so the runs follow from locate alone.
	type run struct{ start, end int }
	var runs []run
	at, taken := 0, 0
	for _, f := range m.locate(src) {
		at += f.Start - taken
		end := at + utf8.RuneCountInString(src[f.Start:f.End])
		runs = append(runs, run{start: at, end: end})
		at, taken = end, f.End
	}

	masked := m.Mask(src)
	for _, s := range m.locate(masked) {
		// s.Start <= r.end and r.start <= s.End is overlapping or touching: a
		// value ending where a run begins, or beginning where one ends, has a
		// redaction for a neighbour.
		if slices.ContainsFunc(runs, func(r run) bool { return s.Start <= r.end && r.start <= s.End }) {
			continue
		}
		t.Errorf("Mask(%q) = %q, in which %q is located again at %d, with no redaction of the first pass beside it", src, masked, masked[s.Start:s.End], s.Start)
	}
}

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
		// The redactor below stands in for Fill('*') wherever a span is meant
		// to be ignored. Fill redacts an empty span to nothing, so an empty
		// span let through would leave the output untouched and the case would
		// pass on a Masker that ignores nothing at all.
		{
			name:     "empty span is ignored",
			patterns: []Pattern{fixed("p", Span{2, 2})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "abcdef",
		},
		{
			name:     "reversed span is ignored",
			patterns: []Pattern{fixed("p", Span{4, 2})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "abcdef",
		},
		{
			name:     "span starting before the input is ignored",
			patterns: []Pattern{fixed("p", Span{-1, 2})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "abcdef",
		},
		{
			name:     "span reaching past the input is ignored",
			patterns: []Pattern{fixed("p", Span{4, 7})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "abcdef",
		},
		{
			name:     "an empty span among values is ignored",
			patterns: []Pattern{fixed("p", Span{0, 2}, Span{3, 3}, Span{4, 6})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "XcdX",
		},
		{
			name:     "an ignored span leaves the others alone",
			patterns: []Pattern{fixed("p", Span{4, 7}, Span{0, 2})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "Xcdef",
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

	// Prose reaches the anchor of no built-in at all, so what it measures is
	// the search for one. The candidates below are what measures the rest: the
	// anchor of every built-in written over and over with a body too short to
	// be a value, so a candidate is opened every few bytes and every one of
	// them is dropped. A scan that allocated per candidate — a prefix compared
	// through a string conversion rather than against a slice of the input —
	// would be measured by prose alone in neither of the cases above it.
	prose := strings.Repeat("the quick brown fox ", 100)
	candidates := strings.Repeat("ey.ey.ey sk-T3BlbkF ghp_0123456789 github_pat_0 AKIA0123456789ABCDE sk_live_ sntrys_ ntn_0123 npm_0123 pypi-AgE lin_api_0 SG.0.0 AIza0 xoxb-0 glpat-0 sk-ant- hvs.0123 hvb.0123 hvr.0123 glsa_0123 rubygems_0123 ", 20)
	for name, tt := range map[string]struct {
		m   *Masker
		src string
	}{
		"pattern finding nothing":           {New(WithPatterns(fixed("p"))), prose},
		"built-in patterns":                 {New(WithPatterns(AllBuiltinPatterns()...)), prose},
		"built-in patterns over candidates": {New(WithPatterns(AllBuiltinPatterns()...)), candidates},
	} {
		t.Run(name, func(t *testing.T) {
			// A masking that located something allocates by writing its
			// output, and would measure nothing about the scans.
			if got := tt.m.Mask(tt.src); got != tt.src {
				t.Fatalf("Mask() redacted something: %q", got)
			}
			if n := testing.AllocsPerRun(100, func() { _ = tt.m.Mask(tt.src) }); n != 0 {
				t.Errorf("Mask() allocated %v times, want 0", n)
			}
		})
	}
}

func TestMasker_Mask_concurrentUse(t *testing.T) {
	// A Masker is fixed once created and documented safe for concurrent use,
	// which everything it holds must hold up in turn. The JWT scanner keeps a
	// cursor and a decoder as it goes, and both belong to the one scan; a
	// pattern and a redactor written by a caller are driven here as well, so
	// that the paths through the Masker are not only the built-in ones.
	const secret = "s3cr3t-value"
	shared := NewPattern("shared-secret", func(src string) []Span {
		var spans []Span
		for i := 0; ; {
			j := strings.Index(src[i:], secret)
			if j < 0 {
				return spans
			}
			spans = append(spans, Span{Start: i + j, End: i + j + len(secret)})
			i += j + len(secret)
		}
	})

	m := New(
		WithPatterns(AllBuiltinPatterns()...),
		WithPatterns(MustRegexp("internal-token", `INT-[0-9a-f]{32}`), shared),
		WithRedactor(naming),
	)

	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "nothing to redact",
			src:  "the quick brown fox",
			want: "the quick brown fox",
		},
		{
			name: "a github token",
			src:  "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "GITHUB_TOKEN=<github-token>",
		},
		{
			name: "a jwt",
			src:  "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: "Authorization: Bearer <jwt>",
		},
		{
			// Both built-in patterns fire here, so the merge runs concurrently
			// too.
			name: "a stateless installation token",
			src:  "token=ghs_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: "token=<github-token>",
		},
		{
			name: "a pattern given by the caller",
			src:  "INT-0123456789abcdef0123456789abcdef and password=s3cr3t-value",
			want: "<internal-token> and password=<shared-secret>",
		},
		{
			// A run dense in header prefixes drives the decoder hard without
			// any token coming of it.
			name: "many rejected jwt candidates",
			src:  strings.Repeat("eyJ", 200) + ".a.b",
			want: strings.Repeat("eyJ", 200) + ".a.b",
		},
	}

	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 32 {
				for _, tt := range tests {
					if got := m.Mask(tt.src); got != tt.want {
						t.Errorf("Mask(%s) = %q, want %q", tt.name, got, tt.want)
						return
					}
				}
			}
		})
	}
	wg.Wait()
}

func Test_New_noOptions(t *testing.T) {
	// A Masker given nothing scans with no patterns, so it redacts nothing and
	// reaches for no redactor along the way. That the redactor New falls back
	// to is the one it says is Test_New_defaultRedactor below, which needs a
	// pattern to show it.
	if got, want := New().Mask("abcdef"), "abcdef"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
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
	m := New(WithPatterns(AllBuiltinPatterns()...))
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
