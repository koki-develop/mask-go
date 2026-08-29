package mask

import (
	"cmp"
	"slices"
	"strings"
	"testing"
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

	spans, retain := p.Find(src)
	checkLookBehindAt(t, New(WithPatterns(p)), src, spans, retain, cut)
}

// checkLookBehindAt is checkLookBehind over one cut of src, given a Masker over
// the pattern and what that pattern reports for the whole of src.
//
// Neither depends on where the cut falls, and a text is cut at every one of its
// positions: taken inside that loop they are a scan of the whole text and a
// Masker built for every byte of it, which is the greater part of what holding
// a pattern to LookBehind costs.
func checkLookBehindAt(t testing.TB, m *Masker, src string, spans []Span, retain, cut int) {
	t.Helper()

	from := cut + LookBehind
	if cut < 0 || from > len(src) {
		return
	}
	if from > retain {
		return
	}
	for _, s := range spans {
		if s.Start < from && from < s.End {
			return
		}
	}

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

	// A subtest a pattern, run in parallel with the rest: what a pattern is
	// held to here is read out of that pattern alone, and the cuts of one text
	// come to as many scans as the text has bytes. The pattern is the coarsest
	// division of that there is, which is what keeps the goroutines and the
	// testing.T holding them to what the runner can take at once.
	for _, p := range patterns {
		t.Run(p.Name(), func(t *testing.T) {
			t.Parallel()

			inputs := lookBehindInputs()
			for _, b := range builtinPatterns {
				inputs = append(inputs, builtinInputs(b.samples)...)
			}
			m := New(WithPatterns(p))
			for _, src := range inputs {
				spans, retain := p.Find(src)
				for cut := range len(src) + 1 {
					checkLookBehindAt(t, m, src, spans, retain, cut)
				}
			}
		})
	}
}
