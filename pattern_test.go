package mask

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// Test_LookBehind_value holds the exported constant to the value the doc
// states, "const LookBehind = 64", and to standing above utf8.UTFMax: several
// window-edge tests in this package and in regexp_test.go subtract
// utf8.UTFMax from it and repeat a string that many times, which panics the
// moment the constant no longer leaves room for that.
func Test_LookBehind_value(t *testing.T) {
	if LookBehind != 64 {
		t.Errorf("LookBehind = %d, want 64", LookBehind)
	}
	if LookBehind <= utf8.UTFMax {
		t.Fatalf("LookBehind = %d, want more than utf8.UTFMax (%d)", LookBehind, utf8.UTFMax)
	}
}

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

// Test_NewPattern_retain holds NewPattern to handing back the retain find
// returned rather than a value substituted for it: find owes both of
// Pattern.Find's results, and the offset is the one a wrapper could
// mistakenly normalize to 0 or to len(src) on the way through.
func Test_NewPattern_retain(t *testing.T) {
	for _, want := range []int{0, 3, 6} {
		t.Run(strconv.Itoa(want), func(t *testing.T) {
			p := NewPattern("custom", func(src string) ([]Span, int) { return nil, want })
			if _, got := p.Find("abcdef"); got != want {
				t.Errorf("Find() retain = %d, want %d", got, want)
			}
		})
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

// Test_NewPattern_comparable_sameName holds two patterns built with the same
// name to being distinct values, and to a Masker keeping the two apart by
// identity rather than by the name they share.
func Test_NewPattern_comparable_sameName(t *testing.T) {
	p := NewPattern("same", func(string) ([]Span, int) { return []Span{{0, 2}}, 0 })
	q := NewPattern("same", func(string) ([]Span, int) { return []Span{{4, 6}}, 0 })
	if p == q {
		t.Error("two patterns built with the same name compared equal")
	}

	var seen []Pattern
	redactor := NewRedactor(func(m Match) string { seen = append(seen, m.Pattern); return "X" })
	m := New(WithPatterns(p, q), WithRedactor(redactor))
	if got, want := m.Mask("abcdef"), "XcdX"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
	if want := []Pattern{p, q}; !slices.Equal(seen, want) {
		t.Errorf("redactor saw %v, want %v", seen, want)
	}
}

// Test_NewPattern_emptyName holds a Pattern whose Name is empty to still
// reaching a redactor with that name intact: Pattern.Name states no
// constraint on the string beyond what a caller should write, and a Masker
// enables no name implicitly.
func Test_NewPattern_emptyName(t *testing.T) {
	p := NewPattern("", func(src string) ([]Span, int) { return []Span{{0, 2}}, len(src) })
	if got := p.Name(); got != "" {
		t.Errorf("Name() = %q, want %q", got, "")
	}

	redactor := NewRedactor(func(m Match) string { return "<" + m.Pattern.Name() + ">" })
	m := New(WithPatterns(p), WithRedactor(redactor))
	if got, want := m.Mask("abcdef"), "<>cdef"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}

// Test_NewPattern_nilFind_panics holds a NewPattern built with a nil find to
// panicking rather than to silently locating nothing: find is called exactly
// as any other function value is, and calling a nil one is a nil pointer
// dereference regardless of what package holds it.
func Test_NewPattern_nilFind_panics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Find did not panic over a nil find")
		}
	}()
	NewPattern("p", nil).Find("abcdef")
}

// Test_NewPattern_retainOutOfRange holds Mask, a Writer and a Reader to
// surviving a caller's Find reporting a retain outside [0, len(src)] — the
// off-by-one a forgotten max(0, ...) or a stream-wide offset computed against
// the wrong length produces. gather (mask.go) clamps what a pattern reports
// into src before using it, since a Pattern is written by a caller and one
// answering past either end would otherwise release text no pattern has read,
// or hold a stream that nothing will ever settle.
func Test_NewPattern_retainOutOfRange(t *testing.T) {
	tests := []struct {
		name   string
		retain func(src string) int
	}{
		{"negative", func(src string) int { return len(src) - 100 }},
		{"past the end", func(src string) int { return len(src) + 100 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPattern("p", func(src string) ([]Span, int) { return nil, tt.retain(src) })
			m := New(WithPatterns(p))

			if got, want := m.Mask("abcdef"), "abcdef"; got != want {
				t.Errorf("Mask() = %q, want %q", got, want)
			}

			var dst strings.Builder
			w := NewWriter(&dst, m)
			for i := range len("abcdef") {
				if _, err := w.Write([]byte("abcdef")[i : i+1]); err != nil {
					t.Fatalf("Write() error = %v", err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			if got, want := dst.String(), "abcdef"; got != want {
				t.Errorf("stream gave %q, want %q", got, want)
			}
		})
	}
}

// Test_NewPattern_holdsUntilClose holds a Writer to Pattern.Find's doc for
// zero: "it is what a Find written without a stream in mind returns", and "a
// Reader or a Writer holds what no pattern has settled". A holder settling
// nothing must hold everything back, over more than one Write, until Close
// lets it go.
func Test_NewPattern_holdsUntilClose(t *testing.T) {
	p := NewPattern("holder", func(src string) ([]Span, int) { return nil, 0 })
	m := New(WithPatterns(p))

	var dst strings.Builder
	w := NewWriter(&dst, m)
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if got := dst.String(); got != "" {
		t.Errorf("after one write, dst = %q, want empty", got)
	}
	if _, err := w.Write([]byte(" world")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if got := dst.String(); got != "" {
		t.Errorf("after two writes, dst = %q, want empty", got)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got, want := dst.String(), m.Mask("hello world"); got != want {
		t.Errorf("after Close, dst = %q, want %q", got, want)
	}
}

// Test_NewPattern_holdsBackNoMoreThanRetain holds a Writer to the lower half
// of what a retain demands: it must not release the bytes from retain on,
// whatever value a caller's Find settles on. checkRetain and
// Test_patterns_readNoFurtherBackThanLookBehind hold the upper half, on the
// values a value straddling the release point makes observable in the
// output; this holds the general form, on a pattern reporting no value at
// all, where no output can show the difference.
func Test_NewPattern_holdsBackNoMoreThanRetain(t *testing.T) {
	const src = "abcdefgh"
	for _, k := range []int{0, 1, 3, len(src) - 1} {
		t.Run(strconv.Itoa(k), func(t *testing.T) {
			p := NewPattern("settlesK", func(string) ([]Span, int) { return nil, k })
			m := New(WithPatterns(p))

			var dst strings.Builder
			w := NewWriter(&dst, m)
			if _, err := w.Write([]byte(src)); err != nil {
				t.Fatalf("Write() error = %v", err)
			}
			if got := dst.String(); len(got) > k || got != src[:len(got)] {
				t.Errorf("after one write, dst = %q, want a prefix of %q no longer than %d bytes", got, src, k)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			if got, want := dst.String(), src; got != want {
				t.Errorf("after Close, dst = %q, want %q", got, want)
			}
		})
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
func checkLookBehind(t tHelper, p Pattern, src string, cut int) {
	t.Helper()

	spans, retain := p.Find(src)
	checkLookBehindAt(t, New(WithPatterns(p)), src, spans, retain, cut)
}

// tHelper is the part of testing.TB that checkLookBehind and checkLookBehindAt
// call. testing.TB itself carries a method only the testing package may
// implement, which is what keeps every implementation of it to *testing.T,
// *testing.B and *testing.F; recordingT is what a check needs instead where it
// is driven against a Pattern the property must catch, since handing such a
// pattern to a real *testing.T would fail the test asking the question rather
// than answer it.
type tHelper interface {
	Helper()
	Errorf(format string, args ...any)
}

// recordingT records whether Errorf was called, standing in for the one thing
// Test_checkLookBehind_detectsAViolation needs and a *testing.T cannot give
// it: an observation that a check failed, made without failing the test that
// makes it.
type recordingT struct{ failed bool }

func (r *recordingT) Helper()                           {}
func (r *recordingT) Errorf(format string, args ...any) { r.failed = true }

// checkLookBehindAt is checkLookBehind over one cut of src, given a Masker over
// the pattern and what that pattern reports for the whole of src.
//
// Neither depends on where the cut falls, and a text is cut at every one of its
// positions: taken inside that loop they are a scan of the whole text and a
// Masker built for every byte of it, which is the greater part of what holding
// a pattern to LookBehind costs.
//
// compared reports whether a comparison was made at all, and located whether
// what it compared included a value: both are zero for most of the cuts of
// most of the texts, since a straddling value or a cut past what is settled
// asks nothing here. Test_patterns_readNoFurtherBackThanLookBehind sums
// compared alone, so that a table driving nothing through this can be told
// from one that does; Test_patterns_valueAtTheWindowEdge reads located alone,
// to confirm the one comparison it makes there actually held a value rather
// than landing on empty text.
func checkLookBehindAt(t tHelper, m *Masker, src string, spans []Span, retain, cut int) (compared, located bool) {
	t.Helper()

	from := cut + LookBehind
	if cut < 0 || from > len(src) {
		return false, false
	}
	if from > retain {
		return false, false
	}
	for _, s := range spans {
		if s.Start < from && from < s.End {
			return false, false
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
	return true, len(want) > 0
}

// keywordPattern returns a hand-written Pattern of the shape LookBehind's size
// exists for: one reading a keyword in front of the value it locates. It
// locates the 20 bytes after every "PASSWORD=" and settles by that keyword's
// own width together with the value's, since a value cannot be told from a
// prefix of it without at least that much of the tail in hand.
func keywordPattern() Pattern {
	const keyword, valueWidth = "PASSWORD=", 20
	return NewPattern("keyword", func(src string) ([]Span, int) {
		var spans []Span
		for i := 0; i+len(keyword) <= len(src); i++ {
			if src[i:i+len(keyword)] != keyword {
				continue
			}
			start := i + len(keyword)
			if end := min(start+valueWidth, len(src)); start < end {
				spans = append(spans, Span{start, end})
			}
		}
		return spans, max(0, len(src)-(len(keyword)+valueWidth)+1)
	})
}

// substringPattern returns a hand-written Pattern locating every occurrence of
// value, settled the way a scan resting on a fixed width is: len(src) less
// value's own width, plus one, is where such a value could still be forming.
func substringPattern(value string) Pattern {
	return NewPattern("substring", func(src string) ([]Span, int) {
		var spans []Span
		for i := 0; i+len(value) <= len(src); i++ {
			if src[i:i+len(value)] == value {
				spans = append(spans, Span{i, i + len(value)})
			}
		}
		return spans, max(0, len(src)-len(value)+1)
	})
}

// settlesNothingPattern locates the same occurrences substringPattern does but
// reports that nothing is ever settled — "a Find written without a stream in
// mind", which is what zero is documented to mean.
func settlesNothingPattern(value string) Pattern {
	return NewPattern("settles-nothing", func(src string) ([]Span, int) {
		var spans []Span
		for i := 0; i+len(value) <= len(src); i++ {
			if src[i:i+len(value)] == value {
				spans = append(spans, Span{i, i + len(value)})
			}
		}
		return spans, 0
	})
}

// lookBehindPatterns are the patterns the LookBehind contract is driven over
// besides the built-ins: what MustRegexp builds, and what a caller writes by
// hand with NewPattern.
//
// The expressions are the ones whose meaning reaches in front of a match — the
// counted repetition, whose matches stand against one another; the word
// boundary and the anchors, which are decided by the character before a match —
// since an expression that reads nothing in front of itself cannot break this
// however it is matched. keywordPattern, substringPattern and
// settlesNothingPattern are what a caller writes by hand: one reading a
// keyword ahead of the value it reports, and a pair driven at both retains a
// hand-written Find can settle on.
func lookBehindPatterns() []Pattern {
	return []Pattern{
		MustRegexp("counted", `[0-9a-f]{40}`),
		MustRegexp("counted-short", `[0-9]{3}`),
		MustRegexp("bounded-group", `INT-(?P<mask>[0-9a-f]{8})`),
		MustRegexp("bounded-alternation", `(?:ab|abcdef)`),
		MustRegexp("word-boundary", `\bkey-[0-9]{3}\b`),
		// \B is decided by the character in front of a match exactly as \b is,
		// in the opposite direction: it fails where \b succeeds and holds
		// where \b fails.
		MustRegexp("non-boundary", `\Bkey-[0-9]{3}`),
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
		keywordPattern(),
		substringPattern(strings.Repeat("0123456789abcdef", 2)),
		settlesNothingPattern(strings.Repeat("0123456789abcdef", 2)),
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
		// x preceded by a space rather than a word character, which is what
		// mask-at-the-edge and mask-past-the-edge need \b to hold against: the
		// entry above puts a word character (Q) in front of x, so \b fails
		// there and neither expression ever matches it.
		strings.Repeat("z", 300) + " x" + strings.Repeat("A", LookBehind-utf8.UTFMax-1) + "123" + strings.Repeat("w", 100),
		strings.Repeat("z", 300) + " x" + strings.Repeat("A", LookBehind-utf8.UTFMax) + "123" + strings.Repeat("w", 100),
		strings.Repeat("KΩx0y\ncKKKK", 12),
		// A run the "runes" pattern, [\x{212a}a]{3}, actually matches: nothing
		// above holds three characters together out of {a, the Kelvin sign}.
		strings.Repeat("z", 300) + "KKa" + strings.Repeat("w", 100),
		strings.Repeat("aaK ", 40),
		"sha=" + strings.Repeat("abcdef0123", 30),
		strings.Repeat("key-123 and INT-0123456789abcdef ", 8),
		strings.Repeat("token=0123ab\n", 20),
		strings.Repeat("no credential in this sentence, none at all. ", 6),
		strings.Repeat("PASSWORD="+strings.Repeat("x", 20)+" and more besides ", 6),
		// Invalid UTF-8: lone continuation and lead bytes, and a NUL, each
		// standing well past LookBehind from the start and from each other, so
		// a cut landing inside one of these runs is a cut every pattern here
		// is driven against.
		strings.Repeat("\xff\xfe\x80 ok ", 40),
		strings.Repeat("a", 100) + "\xe6\x97" + strings.Repeat("b", 100),
		strings.Repeat("x\x00y", 60),
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
			var compared int
			for _, src := range inputs {
				spans, retain := p.Find(src)
				for cut := range len(src) + 1 {
					if c, _ := checkLookBehindAt(t, m, src, spans, retain, cut); c {
						compared++
					}
				}
			}
			// mask-past-the-edge stands one rune further into its match than
			// LookBehind allows, which is what turns streaming off for it
			// entirely (Regexp's doc), and settlesNothingPattern states the
			// same zero by construction. Both leave checkLookBehindAt's
			// from > retain guard firing on every cut of every input, which
			// is the boundary each exists to show rather than a hole here.
			switch p.Name() {
			case "mask-past-the-edge", "settles-nothing":
				return
			}
			// For every other pattern, a compared count of zero is a pattern
			// this held to nothing at all: every early return in
			// checkLookBehindAt firing on every cut of every input would leave
			// the subtest passing having asked the pattern no question.
			if compared == 0 {
				t.Errorf("%s: no cut of any input was ever compared", p.Name())
			}
		})
	}
}

// Test_checkLookBehind_detectsAViolation holds checkLookBehind to reporting
// the defect LookBehind rules out: "a Find whose answer at one place depends
// on the whole of the text in front of it. A scan walking the text from the
// start and stepping over each value it found would be such a Find: where the
// window begins would decide where the values fall, and a value would move
// under the window as the window moved."
//
// find here locates only the first occurrence of "KEY=" in whatever text it
// is handed and claims the whole of it settled — over the whole text that
// finds the first of two independent occurrences and never looks for the
// second, where a window opening past the first finds the second fresh. That
// is the shape the doc names, and recordingT is what lets the resulting
// mismatch be observed here without failing this test in its own right.
func Test_checkLookBehind_detectsAViolation(t *testing.T) {
	const lead, value = "KEY=AAAAAA", "KEY=BBBBBB"
	src := lead + strings.Repeat("z", 93) + value + strings.Repeat("z", 20)

	find := func(s string) ([]Span, int) {
		if i := strings.Index(s, "KEY="); i >= 0 {
			return []Span{{i, i + len(value)}}, len(s)
		}
		return nil, len(s)
	}
	p := NewPattern("stepping", find)

	rec := &recordingT{}
	checkLookBehind(rec, p, src, 10)
	if !rec.failed {
		t.Error("checkLookBehind did not report a Find whose answer depends on where the text in front of the cut ends")
	}
}

// Test_patterns_valueAtTheWindowEdge pins the alignment
// Test_MustRegexp_maskGroupAtTheEdgeOfAWindow drives for a MustRegexp pattern,
// here for a value the width rule alone locates: a built-in scan. A window
// opens LookBehind bytes in front of the text still to be written out, and a
// value beginning in the first rune of that opening is one a Masker drops.
func Test_patterns_valueAtTheWindowEdge(t *testing.T) {
	const token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	p := GitHubToken()
	m := New(WithPatterns(p))
	build := func(lead int) string {
		return strings.Repeat("z", lead) + token + strings.Repeat("w", 100)
	}

	t.Run("Start = from-1, straddling the window and dropped there", func(t *testing.T) {
		// checkLookBehindAt itself declines to compare a straddling value, so
		// what stands for the property here is the one thing that can
		// observe it: the stream still agrees with Mask at every cut.
		src := build(LookBehind - 1)
		want := m.Mask(src)
		for _, pieces := range splits(src) {
			if got := throughWriter(t, m, pieces); got != want {
				t.Errorf("writing in %d piece(s) gave %q, Mask gives %q", len(pieces), got, want)
			}
		}
	})

	for _, d := range []int{0, 1} {
		t.Run(fmt.Sprintf("Start = from+%d", d), func(t *testing.T) {
			src := build(LookBehind + d)
			spans, retain := p.Find(src)
			if _, located := checkLookBehindAt(t, m, src, spans, retain, 0); !located {
				t.Error("checkLookBehindAt compared nothing; the value was not where this test placed it")
			}
		})
	}
}

// Test_patterns_duplicateAndMixedDepthPatternsStream holds a Writer and a
// Reader to WithPatterns's "repeated options accumulate in the order given"
// where the accumulated patterns are not distinct: one Pattern value
// registered twice, and two patterns that settle at different depths, must
// each stream what Mask gives over text long enough for the window to move.
func Test_patterns_duplicateAndMixedDepthPatternsStream(t *testing.T) {
	shallow := MustRegexp("shallow", `[0-9a-f]{40}`)
	deep := MustRegexp("deep", `INT-[0-9a-f]+`)
	src := strings.Repeat("z", 200) + " " + strings.Repeat("0123456789abcdef", 3) +
		" INT-0123456789abcdef " + strings.Repeat("w", 100)

	for _, tt := range []struct {
		name     string
		patterns []Pattern
	}{
		{"the same pattern registered twice", []Pattern{shallow, shallow}},
		{"two patterns settling at different depths", []Pattern{shallow, deep}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := New(WithPatterns(tt.patterns...))
			want := m.Mask(src)
			for _, pieces := range splits(src) {
				if got := throughWriter(t, m, pieces); got != want {
					t.Errorf("writing in %d piece(s) gave %q, Mask gives %q", len(pieces), got, want)
				}
				if got := throughReader(t, m, pieces, 7); got != want {
					t.Errorf("reading in %d piece(s) at 7 bytes gave %q, Mask gives %q", len(pieces), got, want)
				}
			}
		})
	}
}

// Test_patterns_keywordPatternStreams drives keywordPattern — a Pattern
// written by hand that reads a keyword in front of what it locates, the shape
// LookBehind's size exists to leave room for — through a Writer over text long
// enough for the window to move several times, and holds it to what Mask
// gives at every cut.
func Test_patterns_keywordPatternStreams(t *testing.T) {
	p := keywordPattern()
	m := New(WithPatterns(p))
	src := strings.Repeat("pad ", 20) + "PASSWORD=" + strings.Repeat("x", 20) + strings.Repeat(" pad", 20)
	want := m.Mask(src)
	for _, pieces := range splits(src) {
		if got := throughWriter(t, m, pieces); got != want {
			t.Errorf("writing in %d piece(s) gave %q, Mask gives %q", len(pieces), got, want)
		}
	}
}
