package mask

import (
	"cmp"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func Test_NewPattern(t *testing.T) {
	want := []Span{{1, 2}}
	var got string
	p := NewPattern("custom", func(src string) ([]Span, int) {
		got = src
		return want, len(src)
	})

	if p.Name() != "custom" {
		t.Errorf("Name() = %q, want %q", p.Name(), "custom")
	}
	if spans, _ := p.Find("abcdef"); !slices.Equal(spans, want) {
		t.Errorf("Find() = %v, want %v", spans, want)
	}
	if got != "abcdef" {
		t.Errorf("find received %q, want %q", got, "abcdef")
	}
}

func Test_NewPattern_comparable(t *testing.T) {
	// Match carries a Pattern, so == on one must never panic.
	p, q := NewPattern("a", nil), NewPattern("b", nil)
	if p == q {
		t.Error("distinct patterns compared equal")
	}
	if p != p { //nolint:staticcheck // the point is that == is defined
		t.Error("a pattern did not compare equal to itself")
	}
}

func Test_MustRegexp_find(t *testing.T) {
	tests := []struct {
		name string
		expr string
		src  string
		want []Span
	}{
		{
			name: "whole match",
			expr: `\d+`,
			src:  "a12b",
			want: []Span{{1, 3}},
		},
		{
			name: "every match",
			expr: `\d+`,
			src:  "a1b22c333",
			want: []Span{{1, 2}, {3, 5}, {6, 9}},
		},
		{
			// Find is free to report nothing as an empty slice or as none at
			// all, so the comparison here holds the two the same.
			name: "no match",
			expr: `\d+`,
			src:  "abc",
			want: nil,
		},
		{
			name: "mask group narrows the span",
			expr: `id=(?P<mask>\d+)`,
			src:  "id=123 name=a",
			want: []Span{{3, 6}},
		},
		{
			name: "mask group in every match",
			expr: `id=(?P<mask>\d+)`,
			src:  "id=1 id=22",
			want: []Span{{3, 4}, {8, 10}},
		},
		{
			name: "unnamed groups do not narrow the span",
			expr: `id=(\d+)`,
			src:  "id=123",
			want: []Span{{0, 6}},
		},
		{
			name: "a group named otherwise does not narrow the span",
			expr: `id=(?P<value>\d+)`,
			src:  "id=123",
			want: []Span{{0, 6}},
		},
		{
			name: "a mask group taking part in no match is skipped",
			expr: `id=(?:(?P<mask>\d+)|none)`,
			src:  "id=none id=12",
			want: []Span{{11, 13}},
		},
		{
			// A span reaching over nothing is a span a Masker ignores, so it
			// is not reported at all.
			name: "an empty mask group is located nowhere",
			expr: `id=(?P<mask>\d*)`,
			src:  "id=",
			want: nil,
		},
		{
			// A marker written in variants is one alternation with the group
			// named in each branch, and the branch that matched is the one
			// that must be located — not the leftmost, which is all
			// SubexpIndex reports.
			name: "a mask group named in each branch of an alternation",
			expr: `key_(?:live_(?P<mask>[0-9a-f]+)|test_(?P<mask>[0-9a-f]+))`,
			src:  "key_test_dead key_live_beef",
			want: []Span{{9, 13}, {23, 27}},
		},
		{
			// No ceiling on the width, so the candidates inside a match go
			// untried: what such an expression settles stands in front of every
			// match there is, and a window over it never opens inside one.
			name: "two mask groups taking part in one match",
			expr: `(?P<mask>a+)-(?P<mask>b+)`,
			src:  "aa-bb",
			want: []Span{{0, 2}, {3, 5}},
		},
		{
			// A match beginning inside another is located rather than stepped
			// over, which is what leaves no part of a value behind: the walk
			// Go's FindAll does would take the first forty characters and
			// report nothing of the twenty behind them.
			name: "a match beginning inside another",
			expr: `[0-9a-f]{40}`,
			src:  strings.Repeat("0123456789abcdef", 4)[:60],
			want: []Span{{0, 60}},
		},
		{
			name: "a match where no mask group took part is located nowhere",
			expr: `id=(?:(?P<mask>\d+)|(?P<mask>x+)|none)`,
			src:  "id=none",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := MustRegexp("p", tt.expr).Find(tt.src)
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_MustRegexp_name(t *testing.T) {
	if got := MustRegexp("my-pattern", `x`).Name(); got != "my-pattern" {
		t.Errorf("Name() = %q, want %q", got, "my-pattern")
	}
}

func Test_MustRegexp_invalidExpression(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("MustRegexp did not panic on an invalid expression")
		}
	}()
	MustRegexp("p", `(`)
}

func Test_MustRegexp_maskGroup(t *testing.T) {
	m := New(WithPatterns(MustRegexp("user-id", `user_id=(?P<mask>\d+)`)))
	if got, want := m.Mask("user_id=12345 name=alice"), "user_id=***** name=alice"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}

func Test_MustRegexp_maskGroupInEveryBranch(t *testing.T) {
	// What this is here for is the branch that is not the leftmost. Reading
	// one submatch index for the name would leave that branch with a group
	// that took part in nothing, drop the match on it and write the key back
	// out whole, with nothing reported anywhere.
	m := New(WithPatterns(MustRegexp("key", `key_(?:live_(?P<mask>[0-9a-f]+)|test_(?P<mask>[0-9a-f]+))`)))
	for _, tt := range []struct{ src, want string }{
		{"key_live_deadbeef", "key_live_********"},
		{"key_test_deadbeef", "key_test_********"},
	} {
		if got := m.Mask(tt.src); got != tt.want {
			t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
		}
	}
}

// checkRetain holds p to what Pattern.Find promises of the offset it reports:
// scanning src[:cut] settles the values in front of that offset, so the values
// it reports there are the values scanning the whole of src reports there, and
// no others.
//
// Both directions are checked. A value the prefix misses is a value a stream
// releases unredacted, which is what the promise is for; a value the prefix
// reports and the whole text does not is a redaction over text that was never a
// credential, which a stream cannot take back once it has written it.
func checkRetain(t testing.TB, p Pattern, src string, cut int) {
	t.Helper()

	head := src[:cut]
	got, retain := p.Find(head)
	if retain < 0 || retain > len(head) {
		t.Errorf("Find(%q) settled %d, outside the %d bytes it was given", head, retain, len(head))
		return
	}

	whole, _ := p.Find(src)
	a, b := settledSpans(got, retain), settledSpans(whole, retain)
	if !slices.Equal(a, b) {
		t.Errorf("Find(%q) settles %d and reports %v in front of it; Find(%q) reports %v there",
			head, retain, a, src, b)
	}
}

// settledSpans returns the spans of the list that begin in front of retain,
// ordered so that two lists reporting the same values compare equal whatever
// order their scans walked them in.
func settledSpans(spans []Span, retain int) []Span {
	var out []Span
	for _, s := range spans {
		if s.Start < retain {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b Span) int {
		if d := cmp.Compare(a.Start, b.Start); d != 0 {
			return d
		}
		return cmp.Compare(a.End, b.End)
	})
	return out
}

func Test_MustRegexp_retain(t *testing.T) {
	tests := []struct {
		name string
		expr string
		src  string
		want int
	}{
		{
			name: "a fixed width settles all but that width",
			expr: `INT-[0-9a-f]{4}`,
			src:  "a token: INT-dead",
			want: len("a token: INT-dead") - len("INT-dead"),
		},
		{
			name: "an alternation settles by its widest branch",
			expr: `(?:a|b)(?:ab|abcdef)`,
			src:  "0123456789",
			want: 3,
		},
		{
			// Nothing a match could open with stands anywhere in the text, so
			// there is no match in it and none in anything written behind it.
			name: "a literal opening standing nowhere settles everything",
			expr: `INT-[0-9a-f]+`,
			src:  "a token, but not one of these",
			want: len("a token, but not one of these"),
		},
		{
			// The literal stands once, and a match opening there could run on
			// for as long as the text does.
			name: "a literal opening settles the text in front of it",
			expr: `INT-[0-9a-f]+`,
			src:  "a token: INT-dead",
			want: len("a token: "),
		},
		{
			name: "a piece of the literal opening at the end settles up to it",
			expr: `INT-[0-9a-f]+`,
			src:  "a token: IN",
			want: len("a token: "),
		},
		{
			name: "a width past the input settles nothing",
			expr: `[0-9a-f]{40}`,
			src:  "short",
			want: 0,
		},
		{
			// No ceiling and nothing to open with: a match could be in progress
			// anywhere, so nothing at all is settled.
			name: "a repetition with no ceiling and no literal settles nothing",
			expr: `[0-9a-f]+`,
			src:  "a token: INT-dead",
			want: 0,
		},
		{
			name: "a star settles nothing",
			expr: `x*`,
			src:  "xxxx",
			want: 0,
		},
		{
			// The widest rune the class admits is what a repetition of it
			// counts, so an ASCII class counts one byte to the rune where a
			// class reaching past ASCII counts what that rune is written in.
			name: "a class counts the widest rune it admits",
			expr: `[^\x00-\x7f]{2}`,
			src:  "0123456789",
			want: 2,
		},
		{
			// Folding can widen a rune without the expression saying so: k
			// folds to the Kelvin sign, which UTF-8 writes in three bytes.
			name: "a folded literal counts its widest fold",
			expr: `(?i)kk`,
			src:  "0123456789",
			want: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, got := MustRegexp("p", tt.expr).Find(tt.src); got != tt.want {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, got, tt.want)
			}
		})
	}
}

func Test_MustRegexp_retainSettles(t *testing.T) {
	// The widths above say what the arithmetic gives; this says the arithmetic
	// is the right one, by holding what a prefix settles to what the whole text
	// reports there. An expression closing on $ is what makes the bound a width
	// rather than a width less one: its match stands at the end of the text and
	// is gone the moment text follows.
	exprs := []string{
		`[\x{212a}a]{3}`,
		`[\x{212a}a]{2}`,
		`(?i)k{2}`,
		`a+`,
		`[a-b]+`,
		`(?P<mask>a+)-(?P<mask>b+)`,
		// Two mask groups with nothing between them, which is what makes find
		// report a span behind one that begins later: a probe run inside a
		// match yields the first group where the match already reported the
		// second. regexpPattern.Find walks the spans from the end and so sees
		// these out of order, and what is held here is that the offset it
		// settles on is still one the whole text agrees with.
		`(?P<mask>[a-z]{1,3})[0-9]{1,3}(?P<mask>[a-z]{1,3})`,
		`(?P<mask>.{1,2})(?P<mask>[a-z]{1,3})`,
		`INT-[0-9a-f]{4}`,
		`INT-[0-9a-f]{2,6}`,
		`(?:ab|abcdef)`,
		`\bkey-[0-9]{3}\b`,
		`[0-9a-f]{4}$`,
		`^INT-[0-9a-f]{4}`,
		`INT-[0-9a-f]+`,
	}
	srcs := []string{
		"",
		// Not ASCII: a text the input cuts inside a rune is what a Reader
		// filling a fixed buffer leaves, and a span reaching to such a cut
		// does not reach the end of the input while still being a span more
		// text can carry further. The Kelvin sign is three bytes and folds
		// together with k, which is why the class below admits it.
		"a\u212a\u212aa\u212a\u212a\u212a",
		"\u212a\u212a\u212a\u212aa\u212a",
		"日本語のログ行に\u212aが混じる",
		"aaaaaaaaa",
		"abababab",
		"INT-dead",
		"a token: INT-dead and INT-beef, key-123 too",
		"INT-deadbeef",
		"key-1",
		"ab abcdef abc",
		// Text the two expressions above report spans out of order on.
		"b0ybyaya0bayy11",
		"2x _x0_bya3a33baa12b_",
	}
	for _, expr := range exprs {
		t.Run(expr, func(t *testing.T) {
			p := MustRegexp("p", expr)
			for _, src := range srcs {
				for cut := range len(src) + 1 {
					checkRetain(t, p, src, cut)
				}
			}
		})
	}
}

func Test_MustRegexp_retainIsAFixedPointOfTheRule(t *testing.T) {
	// Find settles an offset by one rule, applied to every span it reports: a
	// span reaching the end of the input, or reaching past the offset, leaves
	// the offset at most where that span begins. What Find returns is that rule
	// applied until it moves nothing, and this is what holds it there — asked
	// once more of what came back, the rule must move it nowhere.
	//
	// A pass over the spans in the order they are reported does not reach that
	// on its own, since find does not report them in the order they begin: a
	// span visited while the offset was still high, and left alone because it
	// did not reach past it, is not asked again once a span visited later
	// brings the offset below its end. Test_MustRegexp_retainSettles holds the
	// offset to being settled; this holds it to being the whole of what the
	// rule gives, which is the difference between the two.
	exprs := []string{
		`(?P<mask>[a-z]{1,3})[0-9]{1,3}(?P<mask>[a-z]{1,3})`,
		`(?P<mask>.{1,2})(?P<mask>[a-z]{1,3})`,
		`(?P<mask>.{1,2})(?P<mask>[a-z0-9]{2,5})\b`,
		`(?P<mask>[a-z]{1,3})(?P<mask>[a-z0-9]{2,5})`,
		`(?P<mask>a+)-(?P<mask>b+)`,
		`INT-[0-9a-f]{2,6}`,
	}
	srcs := []string{
		"",
		"b0ybyaya0bayy11",
		"bbxbb02cbx1x_1",
		"2x _x0_bya3a33baa12b_",
		"ya02b3y0b-_20aa0x__",
		"by yaayz0x--2-0xy",
		"-x11-2_13zbxb223x_ayz",
		"a token: INT-dead and INT-beef",
		"\u212a\u212aa\u212a",
	}
	for _, expr := range exprs {
		t.Run(expr, func(t *testing.T) {
			p := MustRegexp("p", expr)
			for _, src := range srcs {
				for cut := range len(src) + 1 {
					head := src[:cut]
					spans, retain := p.Find(head)
					for _, s := range spans {
						if s.End != len(head) && s.End <= retain {
							continue
						}
						if s.Start < retain {
							t.Errorf("Find(%q) = %v, settling %d, which %v reaches past while beginning in front of",
								head, spans, retain, s)
						}
					}
				}
			}
		})
	}
}

// fastestPair returns the least of several runs of each of a and b, which are
// the runs carrying least of the machine: a run is slowed by a collection or by
// whoever else the machine is running, and never sped up by either.
//
// Both are run once before any of them is timed, and then alternately, because
// a ratio of two readings must not carry a difference between when they were
// taken. The reading taken first pays for a clock that has not risen and for
// pages nobody has touched, and pays it in every one of its runs, so the least
// of them does not put it back.
func fastestPair(a, b func()) (time.Duration, time.Duration) {
	a()
	b()

	bestA, bestB := time.Duration(math.MaxInt64), time.Duration(math.MaxInt64)
	// A deadline read from the clock, not the readings added up: a pair too
	// quick for the clock to separate would add up to nothing and be sampled
	// for ever.
	deadline := time.Now().Add(fastestPairFloor)
	for i := 0; i < 5 || time.Now().Before(deadline); i++ {
		start := time.Now()
		a()
		bestA = min(bestA, time.Since(start))

		start = time.Now()
		b()
		bestB = min(bestB, time.Since(start))
	}
	return bestA, bestB
}

// fastestPairFloor is how long a pair is given before the least of each of its
// runs is taken, five runs apiece being the fewest whatever that comes to.
//
// A reading of a few milliseconds is one a burst of whatever else the machine
// is running can double, so five of them are five chances to be unlucky. A
// reading of a hundred is long enough that a burst is a fraction of it rather
// than a multiple, and sampling it more often buys accuracy already there. The
// floor tells the two apart without either being written down: it leaves a pair
// under the race detector at five runs and gives the same pair without it as
// many as it takes.
const fastestPairFloor = 250 * time.Millisecond

func Test_MustRegexp_findIsLinear(t *testing.T) {
	// What Find does after matching is settle an offset by walking the spans,
	// and there are two ways for that walk to cost more than the text. Walked
	// the wrong way round, a chain of spans each reaching past where the next
	// begins drains a link a pass. Walked over a list that is not in the order
	// the spans begin, an inversion drains a pass. Either is a pass a span, and
	// there is a span a byte on the texts below.
	//
	// What is asserted is the ratio and not a deadline. Doubling the text
	// doubles the work of a walk that costs the text and quadruples the work of
	// one that costs the spans, so the ratio is what tells the two apart — and
	// it says the same thing on a slow machine, under the race detector and on
	// a runner shared with somebody else, where a deadline says whatever the
	// machine was doing at the time.
	const (
		small = 1 << 15
		large = small * 2
		// Four is the quadratic answer and two the linear one. Three parts them
		// with room for the constant factors either side, which is what a walk
		// costing the text spends on the sort in front of it.
		limit = 3.0
	)

	for _, tt := range []struct{ name, expr, unit string }{
		{
			// Two mask groups with nothing between them, which is what makes a
			// probe report a span in front of one already reported: the list
			// the walk is handed is out of order at every match.
			name: "a span out of order at every match",
			expr: `(?P<mask>[a-z]{1,3})(?P<mask>[a-z0-9]{2,5})`,
			unit: "abc12",
		},
		{
			// The same, bounded behind, so the spans are reported side by side
			// rather than merged and the chain is as long as the text.
			name: "a chain the length of the text",
			expr: `(?P<mask>.{1,2})(?P<mask>[a-z0-9]{2,5})\b`,
			unit: "ab012 ",
		},
		{
			// No mask group and no merging: a span at every position of a run,
			// each reaching ten characters past where the next begins.
			name: "a span at every position",
			expr: `\B[a-z]{1,10}`,
			unit: "a",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := MustRegexp("p", tt.expr)

			text := func(n int) string { return strings.Repeat(tt.unit, n/len(tt.unit)) }
			short, long := text(small), text(large)
			a, b := fastestPair(func() { p.Find(short) }, func() { p.Find(long) })
			if a <= 0 {
				a = time.Nanosecond
			}
			if got := float64(b) / float64(a); got > limit {
				t.Errorf("Find() of %d bytes took %v and of %d bytes took %v, %.1fx for twice the text",
					small, a, large, b, got)
			}
		})
	}
}

// checkLookBehind holds p to LookBehind: what it locates from LookBehind bytes
// into what it is handed does not depend on the text in front of that.
//
// It compares what a Masker makes of the two rather than the spans as reported,
// because that is what a stream reads: values are sorted and the overlaps
// merged, and two scans reporting the same coverage differently are the same
// scan to everything downstream of the merge.
//
// The cut is one a stream could make, and no other. Two things hold of every
// cut a stream makes, and a cut meeting neither asks p about a window no stream
// ever opens:
//
//   - it stands LookBehind bytes in front of text the stream has written out,
//     and a stream writes out only what the patterns settled, so the cut is at
//     or before what p settles here;
//   - no value straddles the point the stream wrote up to. A stream stops
//     writing in front of a value that reaches past what is settled, exactly so
//     that it never has to take back half a redaction.
func checkLookBehind(t testing.TB, p Pattern, src string, cut int) {
	t.Helper()

	from := cut + LookBehind
	if cut < 0 || from > len(src) {
		return
	}
	spans, retain := p.Find(src)
	if from > retain {
		return
	}
	for _, s := range spans {
		if s.Start < from && from < s.End {
			return
		}
	}

	m := New(WithPatterns(p))
	want := make([]Span, 0, 8)
	for _, f := range m.locate(src, from).found {
		want = append(want, f.Span)
	}
	got := make([]Span, 0, len(want))
	for _, f := range m.locate(src[cut:], from-cut).found {
		got = append(got, Span{Start: f.Start + cut, End: f.End + cut})
	}

	if !slices.Equal(got, want) {
		t.Errorf("from %d on, %q gives %v and %q gives %v", from, src, want, src[cut:], got)
	}
}

// lookBehindPatterns are the patterns the LookBehind contract is driven over
// besides the built-ins: what MustRegexp builds, and what a caller writes by
// hand.
//
// The expressions are the ones whose meaning reaches in front of a match — the
// counted repetition, whose matches stand against one another; the word
// boundary and the anchors, which are decided by the character before a match —
// since an expression that reads nothing in front of itself cannot break this
// however it is matched.
func lookBehindPatterns() []Pattern {
	return []Pattern{
		MustRegexp("counted", `[0-9a-f]{40}`),
		MustRegexp("counted-short", `[0-9]{3}`),
		MustRegexp("bounded-group", `INT-(?P<mask>[0-9a-f]{8})`),
		MustRegexp("bounded-alternation", `(?:ab|abcdef)`),
		MustRegexp("word-boundary", `\bkey-[0-9]{3}\b`),
		MustRegexp("line-anchor", `(?m)^token=[0-9a-f]{6}`),
		MustRegexp("text-anchor", `\Atoken=[0-9a-f]{6}`),
		MustRegexp("unbounded", `INT-[0-9a-f]+`),
		// A group standing as far into a match as one may and still be
		// streamed, and one standing a byte further, which may not. The two
		// either side of the boundary are what say the boundary is where it is
		// claimed: a group at the far edge of the opening a window leaves is a
		// group dropped along with the match it belongs to.
		MustRegexp("mask-at-the-edge", `\bx`+strings.Repeat("A", LookBehind-utf8.UTFMax-1)+`(?P<mask>[0-9]{3})`),
		MustRegexp("mask-past-the-edge", `\bx`+strings.Repeat("A", LookBehind-utf8.UTFMax)+`(?P<mask>[0-9]{3})`),
		MustRegexp("runes", `[\x{212a}a]{3}`),
	}
}

// lookBehindInputs is text those patterns are driven over, long enough that a
// stream masking it would carry its window past the beginning: the contract is
// about what a scan reads behind itself, and text shorter than LookBehind never
// asks the question.
func lookBehindInputs() []string {
	return []string{
		strings.Repeat("0123456789abcdef", 24),
		strings.Repeat("z", 300) + "Qx" + strings.Repeat("A", LookBehind) + "123" + strings.Repeat("w", 100),
		strings.Repeat("KΩx0y\ncKKKK", 12),
		"sha=" + strings.Repeat("abcdef0123", 30),
		strings.Repeat("key-123 and INT-0123456789abcdef ", 8),
		strings.Repeat("token=0123ab\n", 20),
		strings.Repeat("no credential in this sentence, none at all. ", 6),
	}
}

func Test_patterns_readNoFurtherBackThanLookBehind(t *testing.T) {
	// What a stream rests on when it lets go of the text it has written out.
	// Every position is cut at, because the one that matters is the one a
	// value or a match happens to begin at.
	patterns := lookBehindPatterns()
	for _, b := range builtinPatterns {
		patterns = append(patterns, b.pattern())
	}

	for _, p := range patterns {
		t.Run(p.Name(), func(t *testing.T) {
			inputs := lookBehindInputs()
			for _, b := range builtinPatterns {
				inputs = append(inputs, builtinInputs(b.samples)...)
			}
			for _, src := range inputs {
				for cut := range len(src) + 1 {
					checkLookBehind(t, p, src, cut)
				}
			}
		})
	}
}

func Test_MustRegexp_settlesNothingWithoutABoundOrALiteral(t *testing.T) {
	// An expression with no ceiling on its width and nothing a match must open
	// with settles nothing, whatever it is handed: a match could be in progress
	// at any position, and there is no reading of the text that says otherwise.
	//
	// That is what lets such a pattern locate the matches Go's walk reports and
	// no others, which Test_patterns_readNoFurtherBackThanLookBehind would
	// otherwise hold it to: a pattern settling nothing is never handed a window
	// over part of a text, so what it would answer about one does not arise.
	// The two go together, and this is what keeps them together.
	for _, expr := range []string{
		// Nothing bounds where a match can begin.
		`[0-9a-f]+`,
		`(?:ab|cd)+`,
		`[A-Za-z0-9]*`,
		`(?:a|b)[0-9]{2,}`,
		// A group standing further into a match than a window is deep. What
		// decides such a group is the beginning of the match, and a window
		// opened between the two would carry that beginning outside it.
		`(?s).{80}(?P<mask>SECRET)`,
		// A group under a repetition of nothing takes part in no match. What
		// this is here for is the arithmetic rather than the redaction: a
		// repetition counted down from zero is where a width turns negative
		// and passes for a state of its own.
		`[0-9a-f]+(?P<mask>abc){0}`,
		`(?s)x[0-9a-f]{100}(?P<mask>SECRET)`,
		`(?:ab)*(?P<mask>SECRET)`,
	} {
		t.Run(expr, func(t *testing.T) {
			p := MustRegexp("p", expr)
			for _, src := range []string{"", "abcd", "0123456789abcdef", strings.Repeat("ab12", 40),
				strings.Repeat("x", 90) + "SECRET"} {
				if _, retain := p.Find(src); retain != 0 {
					t.Errorf("Find(%q) settled %d, want 0", src, retain)
				}
			}
		})
	}
}

func Test_MustRegexp_maskGroupAtTheEdgeOfAWindow(t *testing.T) {
	// A window opens LookBehind bytes in front of the text still to be written
	// out. A match beginning in the first rune of that opening is one the
	// expression may be wrong about — there is nothing in front of it for \b to
	// read — and a Masker drops what begins in the opening. So a group standing
	// inside the opening is dropped with its match, and one standing outside it
	// is not: the second is redacted on the strength of a match that was never
	// there, or missed where the whole text has one.
	//
	// Both sides of the boundary are driven, over text each expression matches,
	// and a stream is held to Mask over the pair.
	for _, at := range []int{
		LookBehind - utf8.UTFMax - 1,
		LookBehind - utf8.UTFMax,
		LookBehind - utf8.UTFMax + 1,
		LookBehind - 2,
		LookBehind - 1,
		LookBehind,
		LookBehind + 1,
	} {
		t.Run(strconv.Itoa(at), func(t *testing.T) {
			// \b is what makes the expression read the text in front of a
			// match, and a match one byte along is what the window's own
			// beginning would otherwise be taken for.
			body := strings.Repeat("A", at-1)
			p := MustRegexp("edge", `\bx`+body+`(?P<mask>[0-9]{3})`)
			m := New(WithPatterns(p), WithRedactor(Fixed("[R]")))

			for _, src := range []string{
				strings.Repeat("z", 300) + " x" + body + "123" + strings.Repeat("w", 100),
				strings.Repeat("z", 300) + "Qx" + body + "123" + strings.Repeat("w", 100),
				strings.Repeat("z", 300) + "-x" + body + "123" + strings.Repeat("w", 100),
			} {
				want := m.Mask(src)
				for _, pieces := range splits(src) {
					if got := throughWriter(t, m, pieces); got != want {
						t.Errorf("writing in %d piece(s) gave %q, Mask gives %q",
							len(pieces), got[295:min(len(got), 320)], want[295:min(len(want), 320)])
						return
					}
				}
			}
		})
	}
}

func Test_MustRegexp_isLinear(t *testing.T) {
	// A match beginning inside another is located by trying the expression
	// again at the positions inside one, and an expression with no ceiling on
	// its width would be read to the end of a run from every character of it —
	// time quadratic in the length of that run. What rules it out is that such
	// an expression settles nothing and so is never handed a window, which is
	// what lets the candidates inside a match go untried.
	//
	// What is asserted is a ratio and not a deadline, for the reason
	// Test_MustRegexp_findIsLinear gives above and for one this table has of
	// its own. A deadline holds where one number lands in the middle of the gap
	// between the two costs for every case under it, which is what
	// Test_builtins_scanIsLinear has and this has not: the bounded expression
	// below tries the candidates inside every match it finds, which is why it
	// is read at a fraction of the length the rest are. A number with room for
	// that one is a number the others never approach, and a number placed for
	// the others fires on it with no scan having changed.
	//
	// Mask is what is timed rather than Find alone: it is what a caller pays,
	// and the walk this is about is inside it. What it spends beyond the walk —
	// merging the spans, writing the output — divides by the text as the walk
	// does only because the two readings below are of one length, and that is
	// what makes timing the whole of Mask say anything about the walk.
	//
	// The two readings are of one text and of the same text in halves, rather
	// than of a text and of twice it. A scan costing the text reads the same
	// number of bytes either way, so the two readings are of one length; one
	// costing the candidates inside a match reads a quarter of the whole in
	// each half and so takes half as long over the pair. Two readings of one
	// length is what keeps whatever else the machine is running out of the
	// answer — neither is exposed to it for longer than the other, and a burst
	// of it lands on both — which two readings of two lengths cannot be, the
	// longer of them absorbing twice the interference of the shorter.
	//
	// Both a half and the whole are long enough that Go's regexp has given up
	// backtracking for the expression being timed, which it does at a length
	// inversely proportional to the size of the compiled program. Its
	// backtracker and its NFA are six to ten times apart per byte, so a half on
	// one side of that length and the whole on the other reads as a quadratic
	// scan whatever the scan does.
	//
	// The size is therefore the expression's own rather than the table's, and
	// so is what it costs to read. All but one share the width below, whose
	// half, being the shorter reading and so the one that has to clear the
	// length, stands half again above the longest of them: 65536 bytes, for a
	// program of four instructions, the shortest here. An expression added
	// below has room under that. The one that does not share the width has by
	// far the longest program, which puts its length at a tenth of that, and by
	// far the dearest scan per byte, being the one that tries the candidates
	// inside a match; read as wide as the rest it costs seconds and says no
	// more.
	const (
		// Two is the quadratic answer and one the linear one. Three halves
		// parts them with room for the constant factors either side, which is
		// the call the pair pays twice and the whole pays once.
		limit = 1.5
		wide  = 3 << 16
	)

	// The inputs are what each expression matches densely, with a byte behind
	// them that no match reaches: a run reaching the end of the text is one no
	// candidate inside can carry further, and the skip that rests on that would
	// otherwise hide what is being measured.
	for _, tt := range []struct {
		expr, unit string
		size       int
	}{
		{`[A-Za-z0-9]+`, "a", wide},
		{`a+`, "a", wide},
		{`(?:ab)+`, "ab", wide},
		{`sk-[A-Za-z0-9]+`, "sk-", wide},
		{`[0-9a-f]{40}`, "0123456789abcdef", 1 << 15},
		{`INT-(?P<mask>[0-9a-f]{8})`, "INT-0123456789abcdef", wide},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			m := New(WithPatterns(MustRegexp("p", tt.expr)))
			text := func(n int) string {
				return strings.Repeat(tt.unit, n/len(tt.unit)) + " Z"
			}
			whole := text(tt.size)
			// Two strings rather than one read twice, so that the pair reads
			// as much memory as the whole does rather than the same half of it
			// over again.
			first, second := text(tt.size/2), text(tt.size/2)

			one, halves := fastestPair(
				func() { m.Mask(whole) },
				func() { m.Mask(first); m.Mask(second) },
			)
			if halves <= 0 {
				halves = time.Nanosecond
			}
			if got := float64(one) / float64(halves); got > limit {
				t.Errorf("Mask() of %d bytes took %v and of the same text in halves %v, %.1fx for the text whole",
					len(whole), one, halves, got)
			}
		})
	}
}
