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
	located := m.locate(src, 0).found
	for _, f := range located {
		at += f.Start - taken
		end := at + utf8.RuneCountInString(src[f.Start:f.End])
		runs = append(runs, run{start: at, end: end})
		at, taken = end, f.End
	}

	masked := m.Mask(src)
	again := m.locate(masked, 0).found
	for _, s := range again {
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
	return NewPattern(name, func(src string) ([]Span, int) { return spans, len(src) })
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
		// The rows below hold Span{Start, End} against the edges of a
		// six-byte input, both sides of len(src): a span landing exactly
		// there is usable only where Start still falls short of it.
		{
			name:     "empty span at offset zero",
			patterns: []Pattern{fixed("p", Span{0, 0})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "abcdef",
		},
		{
			name:     "empty span exactly at the end",
			patterns: []Pattern{fixed("p", Span{6, 6})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "abcdef",
		},
		{
			name:     "span starting exactly at the end reaches past it",
			patterns: []Pattern{fixed("p", Span{6, 7})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "abcdef",
		},
		{
			name:     "span wholly in front of the input",
			patterns: []Pattern{fixed("p", Span{-1, 0})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "abcdef",
		},
		{
			name:     "span starting inside the input but reaching one past its end",
			patterns: []Pattern{fixed("p", Span{0, 7})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "abcdef",
		},
		{
			name:     "the last byte alone is usable",
			patterns: []Pattern{fixed("p", Span{5, 6})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "abcdeX",
		},
		{
			name:     "one Find reports overlapping spans in descending order",
			patterns: []Pattern{fixed("p", Span{4, 8}, Span{0, 6})},
			redactor: Fixed("X"),
			src:      "abcdefghij",
			want:     "Xij",
		},
		{
			name:     "an unusable span reaching between two usable ones does not bridge them",
			patterns: []Pattern{fixed("p", Span{0, 2}, Span{1, 9}, Span{4, 6})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "XcdX",
		},
		{
			name:     "a contained span is reported before its container in one Find call",
			patterns: []Pattern{fixed("p", Span{2, 4}, Span{0, 6})},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "X",
		},
		{
			name: "one Find mixes a duplicate, an empty span, a reversed span, a negative-start span, a past-the-end span and two overlapping usable ones",
			patterns: []Pattern{fixed("p",
				Span{4, 7}, Span{2, 4}, Span{-1, 1}, Span{3, 3}, Span{0, 3}, Span{2, 4}, Span{5, 2},
			)},
			redactor: Fixed("X"),
			src:      "abcdef",
			want:     "Xef",
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

// TestMasker_Mask_spanCuttingARune holds Mask to what Pattern.Find's doc says
// of a span whose ends do not fall on a rune boundary: "the bytes either side
// of it are written back as they were found, so what is left of that rune
// stands beside the redaction and the output is not valid UTF-8." Such a span
// is not among the ones Pattern.Find ignores — only a span reaching outside
// src, or one whose Start is not less than its End, is — and it is not
// repaired to the rune it falls inside either: Match.Value is exactly
// src[Start:End], whatever that cuts through, and Fill counts the runes of
// that raw slice the same way it counts any other value's.
//
// "日本語abc" is 日=[0,3), 本=[3,6), 語=[6,9), a=9, b=10, c=11, so the offsets
// 1, 2, 4, 5, 7 and 8 fall inside a rune rather than at its start.
func TestMasker_Mask_spanCuttingARune(t *testing.T) {
	src := "日本語abc"
	tests := []struct {
		name      string
		span      Span
		wantValue string
		want      string
	}{
		{
			// Ends one byte into 日 (0xe6 0x97 0xa5): Value holds only its
			// lead byte, which utf8.RuneCountInString counts as one invalid
			// rune, so Fill writes one '*'. 日's two continuation bytes are
			// written back untouched, now with no lead byte in front of them.
			name:      "span ends inside a rune",
			span:      Span{0, 1},
			wantValue: "\xe6",
			want:      "*\x97\xa5本語abc",
		},
		{
			// Starts one byte into 日 and ends on the boundary in front of
			// "abc": Value holds 日's two continuation bytes (one invalid
			// rune apiece) followed by all of 本 and all of 語 (one rune
			// each), four runes altogether, so Fill writes four '*'. 日's lead
			// byte is written back alone in front of the redaction.
			name:      "span starts inside a rune",
			span:      Span{1, 9},
			wantValue: "\x97\xa5本語",
			want:      "\xe6****abc",
		},
		{
			// Starts one byte into 日 and ends one byte into 語 (0xe8 0xaa
			// 0x9e), so Value holds 日's two continuation bytes, all of 本 and
			// 語's lead byte alone — four runes again, so Fill writes four
			// '*'. 日's lead byte and 語's two trailing bytes are both written
			// back untouched, one on each side of the redaction.
			name:      "span starts and ends inside a rune",
			span:      Span{1, 7},
			wantValue: "\x97\xa5本\xe8",
			want:      "\xe6****\xaa\x9eabc",
		},
		{
			// Falls entirely between 日's lead byte and its two continuation
			// bytes: Value is one invalid byte, one rune, one '*'.
			name:      "span falls entirely inside one rune",
			span:      Span{1, 2},
			wantValue: "\x97",
			want:      "\xe6*\xa5本語abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotValue string
			capture := NewRedactor(func(m Match) string {
				gotValue = m.Value
				return "*"
			})
			New(WithPatterns(fixed("p", tt.span)), WithRedactor(capture)).Mask(src)
			if gotValue != tt.wantValue {
				t.Errorf("Match.Value = %q, want %q", gotValue, tt.wantValue)
			}

			// The default redactor, Fill('*'), is what the doc's claim about
			// the output is checked against.
			got := New(WithPatterns(fixed("p", tt.span))).Mask(src)
			if got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", src, got, tt.want)
			}
			if utf8.ValidString(got) {
				t.Errorf("Mask(%q) = %q, want invalid UTF-8: a span cutting a multi-byte rune leaves what is left of that rune beside the redaction", src, got)
			}
		})
	}
}

// TestMasker_Mask_invalidUTF8Value holds Mask end to end to what Test_Fill
// already holds Fill to alone: a located value made of bytes that are not
// valid UTF-8 counts one rune per bad byte, under the default redactor, under
// an explicit multi-byte fill rune, and standing in the middle of otherwise
// ordinary text rather than only at its start.
func TestMasker_Mask_invalidUTF8Value(t *testing.T) {
	tests := []struct {
		name     string
		patterns []Pattern
		redactor Redactor
		src      string
		want     string
	}{
		{
			name:     "invalid utf-8 at the start under the default redactor",
			patterns: []Pattern{fixed("p", Span{0, 3})},
			src:      "\xff\xfe\x00abc",
			want:     "***abc",
		},
		{
			name:     "invalid utf-8 at the start under a multi-byte fill rune",
			patterns: []Pattern{fixed("p", Span{0, 3})},
			redactor: Fill('●'),
			src:      "\xff\xfe\x00abc",
			want:     "●●●abc",
		},
		{
			name:     "invalid utf-8 standing in the middle of the input",
			patterns: []Pattern{fixed("p", Span{3, 5})},
			src:      "abc\xff\xfedef",
			want:     "abc**def",
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
		src      string // defaults to "abcdef" where empty
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
		{
			// A third span, tied with neither of the two that tie on the
			// earliest start, still extends the merged run. The tie is broken
			// among "short" and "long" alone: "long" is longer at the same
			// start, so it wins whatever "tail" goes on to add to the run.
			name: "a tie on the earliest start is broken before a later span extends the run",
			patterns: []Pattern{
				fixed("short", Span{0, 2}),
				fixed("long", Span{0, 4}),
				fixed("tail", Span{3, 10}),
			},
			src:  "abcdefghij",
			want: "<long>",
		},
		{
			// "first" and "second" are the only spans tied on the earliest
			// start; "third" merely overlaps into a wider run without taking
			// part in that tie, so it cannot win it by being the longest span
			// anywhere in the run.
			name: "a tie on the earliest start is not reopened by a span the run only later grows to include",
			patterns: []Pattern{
				fixed("first", Span{0, 4}),
				fixed("second", Span{0, 4}),
				fixed("third", Span{2, 8}),
			},
			src:  "abcdefgh",
			want: "<first>",
		},
		{
			// "a" only touches "b" (its End equals "b"'s Start), so it stays a
			// redaction of its own; "b" and "c" truly overlap and merge, with
			// "b" attributed for starting earlier.
			name:     "a value that only touches a merged run stays a separate redaction",
			patterns: []Pattern{fixed("a", Span{0, 2}), fixed("b", Span{2, 6}), fixed("c", Span{4, 8})},
			src:      "abcdefgh",
			want:     "<a><b>",
		},
		{
			// "first", "second" and "third" chain into one run transitively —
			// "first" and "third" do not themselves overlap — registered in
			// the reverse of where they start.
			name:     "a chain of three is attributed by where the spans start, not by registration order",
			patterns: []Pattern{fixed("third", Span{4, 7}), fixed("second", Span{2, 5}), fixed("first", Span{0, 3})},
			src:      "abcdefgh",
			want:     "<first>h",
		},
		{
			// "second" starts later than "first" but is registered first;
			// the two spans only touch, so sorting by position rather than by
			// registration order is what keeps them apart correctly ordered.
			name:     "touching values from two patterns are ordered by position however they are registered",
			patterns: []Pattern{fixed("second", Span{2, 4}), fixed("first", Span{0, 2})},
			src:      "abcd",
			want:     "<first><second>",
		},
		{
			name:     "a span that would have started earliest is out of the running once it is ignored (negative start)",
			patterns: []Pattern{fixed("unusable-first", Span{-1, 4}), fixed("usable", Span{1, 5})},
			want:     "a<usable>f",
		},
		{
			name:     "a span that would have started earliest is out of the running once it is ignored (reversed)",
			patterns: []Pattern{fixed("unusable-first", Span{4, 2}), fixed("usable", Span{1, 5})},
			want:     "a<usable>f",
		},
		{
			name:     "a pattern reporting only ignored spans cannot win attribution from the one reporting the real value",
			patterns: []Pattern{fixed("ghost", Span{0, 0}, Span{-1, 4}), fixed("real", Span{0, 4})},
			want:     "<real>ef",
		},
		{
			name:     "the same, with the real value's pattern registered first",
			patterns: []Pattern{fixed("real", Span{0, 4}), fixed("ghost", Span{0, 0}, Span{-1, 4})},
			want:     "<real>ef",
		},
		{
			name:     "an empty span strictly inside another pattern's usable span neither splits it nor is attributed",
			patterns: []Pattern{fixed("p", Span{0, 6}), fixed("q", Span{3, 3})},
			want:     "<p>",
		},
		{
			// "x日本語x" is x=[0,1), 日=[1,4), 本=[4,7), 語=[7,10), x=[10,11):
			// the two spans overlap on 本 and merge into one three-rune run,
			// attributed to "p" for starting earlier.
			name:     "a merged run spanning multi-byte runes is attributed to the earlier-starting pattern",
			patterns: []Pattern{fixed("p", Span{1, 7}), fixed("q", Span{4, 10})},
			src:      "x日本語x",
			want:     "x<p>x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := tt.src
			if src == "" {
				src = "abcdef"
			}
			m := New(WithPatterns(tt.patterns...), WithRedactor(naming))
			if got := m.Mask(src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", src, got, tt.want)
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
	//
	// The anchors are read out of builtinPatterns rather than written out here.
	// A string written out here covers whichever patterns existed when it was
	// last edited, and the scan left out of it reads exactly like a scan that
	// allocates nothing; reading the table is what makes a pattern arriving
	// without one fail Test_builtins_entriesAreFilledIn instead. What the entry
	// carries is still a choice made where the scan was written, and nothing
	// here can tell an anchor that opens a candidate from one a scan turns away
	// on its first byte — the note on the field says so.
	//
	// What an anchor may not do is reach work a scan means to pay for. The JWT
	// scan decodes the header of a candidate and allocates for it, four times
	// to the dot at most, so an anchor of eyJ and a dot would measure that
	// decode rather than a scan allocating per candidate, and would fail here
	// having found nothing wrong. Its anchor stops in front of the J.
	prose := strings.Repeat("the quick brown fox ", 100)
	var anchors strings.Builder
	for _, b := range builtinPatterns {
		for _, a := range b.anchors {
			anchors.WriteString(a)
			// A separator, so that a value is not built across a boundary out
			// of two anchors that are none. Which character serves is not a
			// survey of what the built-ins locate — one added tomorrow can
			// locate a value carrying any character, and the private key armor
			// carries spaces — and it does not have to be: the case
			// below fails outright if the joined text redacts anything, which
			// is what a separator that built a value would make it do.
			anchors.WriteByte(' ')
		}
	}
	candidates := strings.Repeat(anchors.String(), 20)
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
	shared := NewPattern("shared-secret", func(src string) ([]Span, int) {
		var spans []Span
		for i := 0; ; {
			j := strings.Index(src[i:], secret)
			if j < 0 {
				return spans, max(0, len(src)-len(secret)+1)
			}
			spans = append(spans, Span{Start: i + j, End: i + j + len(secret)})
			i += j + 1
		}
	})

	// valueNaming carries Match.Value into the output along with the pattern's
	// name, unlike the package-level naming redactor, so a Value read by one
	// goroutine's text but written by another's would fail a case here rather
	// than only Match.Pattern, which mask_test.go's other concurrency
	// assertions already hold to the right answer.
	valueNaming := NewRedactor(func(m Match) string { return "<" + m.Pattern.Name() + ":" + m.Value + ">" })

	m := New(
		WithPatterns(AllBuiltinPatterns()...),
		WithPatterns(MustRegexp("internal-token", `INT-[0-9a-f]{32}`), shared),
		WithRedactor(valueNaming),
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
			want: "GITHUB_TOKEN=<github-token:ghp_0123456789abcdefghijklmnopqrstuvwxyz>",
		},
		{
			name: "a jwt",
			src:  "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: "Authorization: Bearer <jwt:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef>",
		},
		{
			// Both built-in patterns fire here, so the merge runs concurrently
			// too.
			name: "a stateless installation token",
			src:  "token=ghs_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: "token=<github-token:ghs_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef>",
		},
		{
			name: "a pattern given by the caller",
			src:  "INT-0123456789abcdef0123456789abcdef and password=s3cr3t-value",
			want: "<internal-token:INT-0123456789abcdef0123456789abcdef> and password=<shared-secret:s3cr3t-value>",
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

// wordPattern is a caller-authored Pattern implementation rather than one
// built from NewPattern: a struct holding a slice, so a value of it is not
// comparable, which is exactly the kind of Pattern the Pattern doc invites a
// caller to hand to WithPatterns.
//
// The word is held as bytes rather than as a string for that alone. A field
// carried only to make the type non-comparable is a field nothing reads, which
// is what the unused check reports; a field the scan itself reads says the same
// thing about the type and says it in code that runs.
type wordPattern struct {
	word []byte
}

func (p wordPattern) Name() string { return "word" }

func (p wordPattern) Find(src string) ([]Span, int) {
	word := string(p.word)
	var spans []Span
	for i := 0; ; {
		j := strings.Index(src[i:], word)
		if j < 0 {
			// len(src)-len(word)+1 is where a word could still be forming
			// at the end of src: the bytes before it can never become a
			// match no matter what text follows, but a partial word
			// standing at the tail can, so those are not settled.
			return spans, max(0, len(src)-len(word)+1)
		}
		spans = append(spans, Span{Start: i + j, End: i + j + len(word)})
		i += j + len(word)
	}
}

func TestMasker_Mask_callerPatternImplementation(t *testing.T) {
	p := wordPattern{word: []byte("s3cr3t")}

	t.Run("alone", func(t *testing.T) {
		m := New(WithPatterns(p), WithRedactor(naming))
		if got, want := m.Mask("pw=s3cr3t"), "pw=<word>"; got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
	})

	t.Run("mixed with a built-in whose value stands against it", func(t *testing.T) {
		m := New(WithPatterns(GitHubToken(), p))
		src := "s3cr3tghp_0123456789abcdefghijklmnopqrstuvwxyz"
		want := strings.Repeat("*", len(src))
		if got := m.Mask(src); got != want {
			t.Errorf("Mask(%q) = %q, want %q", src, got, want)
		}
	})
}

// TestMasker_Mask_doesNotMutateAPatternsOwnSpanSlice holds Mask to leaving a
// Pattern's own returned slice as it found it. A Pattern may return a slice it
// keeps rather than allocating one per call — fixed does, and a hand-written
// Find avoiding an allocation would too — so a Masker that sorted spans in
// place would silently reorder it for whoever calls Find again.
func TestMasker_Mask_doesNotMutateAPatternsOwnSpanSlice(t *testing.T) {
	shared := []Span{{4, 6}, {0, 2}}
	p := NewPattern("shared", func(src string) ([]Span, int) { return shared, len(src) })

	if got, want := New(WithPatterns(p)).Mask("abcdef"), "**cd**"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
	if want := ([]Span{{4, 6}, {0, 2}}); !slices.Equal(shared, want) {
		t.Errorf("the pattern's own slice changed to %v, want %v", shared, want)
	}
}

// TestMasker_Mask_secondPassRedactsMoreAWSAgainstSlack pins the example
// Mask's own doc names: an AWS access key ID written against a Slack prefix is
// redacted on the first pass, and the asterisk Fill('*') leaves behind reopens
// the prefix Slack's scan declined the first time — the byte in front of a
// Slack prefix may not be a letter or a digit, and the last byte of the AWS
// key was a letter until the first pass wrote over it.
func TestMasker_Mask_secondPassRedactsMoreAWSAgainstSlack(t *testing.T) {
	m := New(WithPatterns(slices.Concat(AWSPatterns(), SlackPatterns())...))

	awsKey := "AKIA0123456789ABCDEF"
	slackToken := "xoxb-0123456789-0123456789012-0123456789abcdefghijklmn"
	src := awsKey + slackToken

	first := m.Mask(src)
	want1 := strings.Repeat("*", len(awsKey)) + slackToken
	if first != want1 {
		t.Fatalf("Mask(%q) = %q, want %q", src, first, want1)
	}

	second := m.Mask(first)
	want2 := strings.Repeat("*", len(src))
	if second != want2 {
		t.Errorf("Mask(%q) = %q, want %q", first, second, want2)
	}
	if second == first {
		t.Error("a second pass located nothing more here, which this input is built to make happen")
	}
	checkSecondPass(t, m, src)
}

// TestMasker_Mask_fixedEmptySplicesUnwrittenText pins Fixed("")'s doc: taking
// a value out altogether splices the text either side of it into text that
// was never written, and masking again may then redact more than masking once
// did. "sep" locates the boundary the doc calls out; "secret" locates the
// six-digit run its removal creates, which neither three-digit half is on its
// own.
func TestMasker_Mask_fixedEmptySplicesUnwrittenText(t *testing.T) {
	sep := MustRegexp("sep", `X`)
	secret := MustRegexp("secret", `[0-9]{6}`)
	m := New(WithPatterns(sep, secret), WithRedactor(Fixed("")))

	src := "123X456"
	first := m.Mask(src)
	if want := "123456"; first != want {
		t.Fatalf("Mask(%q) = %q, want %q", src, first, want)
	}

	second := m.Mask(first)
	if want := ""; second != want {
		t.Errorf("Mask(%q) = %q, want %q: the splice is a value neither pass alone could have located", first, second, want)
	}
}

// TestMasker_Mask_mergedRunOverMultiByteRunesCountsRunes holds Fill to
// counting runes of a value assembled from two patterns' spans, not the bytes
// of the run: "x日本語x" is x=[0,1), 日=[1,4), 本=[4,7), 語=[7,10), x=[10,11),
// and the two spans below overlap on 本 and merge into a three-rune run.
func TestMasker_Mask_mergedRunOverMultiByteRunesCountsRunes(t *testing.T) {
	m := New(WithPatterns(fixed("p", Span{1, 7}), fixed("q", Span{4, 10})))
	if got, want := m.Mask("x日本語x"), "x***x"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}

// TestMasker_Mask_callerPatternOverlapsABuiltin holds attribution to the
// merge/tie-break rule alone, not to whether a span came from a built-in or
// from a caller's own Pattern, in both directions of overlap and however the
// two are registered.
func TestMasker_Mask_callerPatternOverlapsABuiltin(t *testing.T) {
	wide := MustRegexp("wide", `GITHUB_TOKEN=ghp_[0-9a-z]{36}`)
	src := "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"

	t.Run("a caller pattern starting before the built-in wins attribution however it is registered", func(t *testing.T) {
		if got, want := New(WithPatterns(GitHubToken()), WithPatterns(wide), WithRedactor(naming)).Mask(src), "<wide>"; got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
		if got, want := New(WithPatterns(wide), WithPatterns(GitHubToken()), WithRedactor(naming)).Mask(src), "<wide>"; got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
	})

	t.Run("which pattern wins does not change what is redacted", func(t *testing.T) {
		want := strings.Repeat("*", len(src))
		if got := New(WithPatterns(GitHubToken()), WithPatterns(wide)).Mask(src); got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
		if got := New(WithPatterns(wide), WithPatterns(GitHubToken())).Mask(src); got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
	})

	t.Run("a built-in starting before a looser caller pattern wins attribution", func(t *testing.T) {
		hexRun := MustRegexp("hex-run", `[0-9a-z]{30}`)
		src := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
		if got, want := New(WithPatterns(GitHubToken()), WithPatterns(hexRun), WithRedactor(naming)).Mask(src), "<github-token>"; got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
	})
}

// TestMasker_Mask_twoRegexpPatternsOverlap holds two caller-built Regexp
// patterns to the same merge rule a built-in and a caller pattern are held to
// above: "Authorization: Bearer \S+" opens before "Bearer [...]+" does, so the
// merged match is attributed to the pattern that opens the line.
func TestMasker_Mask_twoRegexpPatternsOverlap(t *testing.T) {
	t.Run("whole matches overlap", func(t *testing.T) {
		auth := MustRegexp("auth-header", `Authorization: Bearer \S+`)
		bearer := MustRegexp("bearer", `Bearer [A-Za-z0-9._-]+`)
		m := New(WithPatterns(auth, bearer), WithRedactor(naming))
		src := "Authorization: Bearer abc.def"
		if got, want := m.Mask(src), "<auth-header>"; got != want {
			t.Errorf("Mask(%q) = %q, want %q", src, got, want)
		}
	})

	t.Run("the matches nest while their mask groups only overlap", func(t *testing.T) {
		// "id=12-34" is id=[0,3), then the mask group of "outer" spans [3,8)
		// ("12-34") and the mask group of "inner" spans [6,8) ("34"): the two
		// matches nest, but it is the mask groups' overlap that a Masker
		// merges.
		outer := MustRegexp("outer", `id=(?P<mask>\d+-\d+)`)
		inner := MustRegexp("inner", `-(?P<mask>\d+)`)
		m := New(WithPatterns(outer, inner), WithRedactor(naming))
		src := "id=12-34"
		if got, want := m.Mask(src), "id=<outer>"; got != want {
			t.Errorf("Mask(%q) = %q, want %q", src, got, want)
		}
	})
}

// TestMasker_Mask_vendorAccessorsCombineWithoutEnablingOthers drives a Masker
// built from two vendor accessors concatenated — the README's own idiom for
// narrowing the set to some vendors and not all — and holds it to redacting
// both while leaving a third vendor's credential alone: "a Masker scans only
// with the patterns given to it".
func TestMasker_Mask_vendorAccessorsCombineWithoutEnablingOthers(t *testing.T) {
	m := New(WithPatterns(slices.Concat(AWSPatterns(), GitHubPatterns())...))

	awsKey := "AKIA0123456789ABCDEF"
	githubToken := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	slackToken := "xoxb-0123456789-0123456789012-0123456789abcdefghijklmn"
	src := awsKey + " " + githubToken + " " + slackToken
	want := strings.Repeat("*", len(awsKey)) + " " + strings.Repeat("*", len(githubToken)) + " " + slackToken

	if got := m.Mask(src); got != want {
		t.Errorf("Mask(%q) = %q, want %q", src, got, want)
	}
}

// TestMasker_Mask_agreesWithASinglePatternUnderTheFullRegistry holds a value
// only one built-in locates to being located the same way — no wider, no
// narrower, not lost — when the Masker scans with the whole registry instead
// of with that pattern alone, which is the arrangement the gram prefilter is
// built in and one pattern could in principle shadow or lose another in.
func TestMasker_Mask_agreesWithASinglePatternUnderTheFullRegistry(t *testing.T) {
	tests := []struct {
		name    string
		pattern Pattern
		src     string
	}{
		{name: "github token", pattern: GitHubToken(), src: "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"},
		{name: "aws access key id", pattern: AWSAccessKeyID(), src: "AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF"},
		{name: "stripe secret key", pattern: StripeSecretKey(), src: "STRIPE_KEY=sk_live_0123456789abcdef01234567"},
		{name: "jwt", pattern: JWT(), src: "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alone := New(WithPatterns(tt.pattern), WithRedactor(Fixed(""))).Mask(tt.src)
			full := New(WithPatterns(AllBuiltinPatterns()...), WithRedactor(Fixed(""))).Mask(tt.src)
			if full != alone {
				t.Errorf("Mask() under the full registry = %q, want %q (same as the pattern alone)", full, alone)
			}
		})
	}
}

func TestMasker_Mask_atSize(t *testing.T) {
	t.Run("one span covering a megabyte-scale input", func(t *testing.T) {
		src := strings.Repeat("a", 1<<20)
		m := New(WithPatterns(fixed("p", Span{0, len(src)})))
		want := strings.Repeat("*", len(src))
		if got := m.Mask(src); got != want {
			// len(got) alone says nothing here: an unmasked src is 1<<20
			// runes of "a", the masked want is 1<<20 runes of "*", so a
			// defect that fails to mask anything at all still produces
			// output of the right length. Count the asterisks and show
			// where the output starts differing instead.
			stars := strings.Count(got, "*")
			i := strings.IndexFunc(got, func(r rune) bool { return r != '*' })
			t.Errorf("Mask() produced %d asterisk(s) of %d runes, want %d; first divergence at byte offset %d",
				stars, len(got), len(want), i)
		}
	})

	t.Run("hundreds of thousands of densely overlapping spans merge into one region", func(t *testing.T) {
		const n = 1<<17 + 3
		src := strings.Repeat("x", n)
		var spans []Span
		for i := 0; i+3 <= n; i++ {
			spans = append(spans, Span{i, i + 3}) // every span overlaps its neighbour
		}
		m := New(WithPatterns(fixed("p", spans...)), WithRedactor(Fixed("X")))
		if got, want := m.Mask(src), "X"; got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
	})
}

// TestMasker_Mask_manyOverlappingSpans holds the merge to correctness at a
// span count no other test in this file reaches: a run built from many
// overlapping spans, and a run built from many spans sharing a start with
// growing ends.
func TestMasker_Mask_manyOverlappingSpans(t *testing.T) {
	t.Run("a chain of many overlapping spans from one pattern merges into one region", func(t *testing.T) {
		const n = 100
		var spans []Span
		for i := 0; i+3 <= n; i++ {
			spans = append(spans, Span{i, i + 3})
		}
		src := strings.Repeat("a", n)

		if got, want := New(WithPatterns(fixed("chain", spans...)), WithRedactor(naming)).Mask(src), "<chain>"; got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
		fillWant := strings.Repeat("*", n)
		if got := New(WithPatterns(fixed("chain", spans...))).Mask(src); got != fillWant {
			t.Errorf("Mask() = %q, want %q", got, fillWant)
		}
	})

	t.Run("spans sharing a start and growing merge into one region as wide as the widest", func(t *testing.T) {
		spans := make([]Span, 30)
		for i := range spans {
			spans[i] = Span{0, 2 * (i + 1)} // {0,2}, {0,4}, ..., {0,60}
		}
		src := strings.Repeat("a", 60)
		if got, want := New(WithPatterns(fixed("p", spans...)), WithRedactor(naming)).Mask(src), "<p>"; got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
	})
}
