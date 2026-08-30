// What must hold of masking text that arrives in pieces.
//
// One property carries almost the whole of it: cut a case anywhere at all,
// write the pieces through a Writer or read them through a Reader, and what
// comes out is what Mask returns for the case uncut. Mask is what the corpus
// states and what the properties beside this hold to everything masking must
// be; a stream owes the same output, so holding it to Mask holds it to all of
// that at once.
//
// What is left over is the giving up. A stream holds text back while a pattern
// is still reading a value out of it, and WithMaxRetained is where that holding
// stops — with a redaction of what is held rather than a release of it, and of
// everything after it, since letting go of the text takes the opening of the
// value with it and no pattern could then say where the value ended. That is
// the one output this library writes that Mask does not, so it is the one place
// a stream owes properties of its own, and the second half of this file states
// them.

package conformance

import (
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/koki-develop/mask-go"
)

// streamRedactors is what a stream is driven with, one entry per way a
// redaction can differ in length from what it replaced.
//
// Fill is the one a stream can get right by accident: two redactions written
// where one belongs still count the same runes, so a stream that split a merged
// value in half reads the same as one that did not. The rest are what catch
// that.
var streamRedactors = []struct {
	name     string
	redactor mask.Redactor
}{
	{name: "Fill('*')", redactor: mask.Fill('*')},
	{name: `Fixed("[REDACTED]")`, redactor: mask.Fixed("[REDACTED]")},
	{name: `Fixed("")`, redactor: mask.Fixed("")},
	{name: "marking", redactor: markRedactor},
}

// pieceReader hands over one piece per read, so that a test says where the
// stream is cut rather than leaving it to a buffer size. The list is cloned
// because reading eats it and the same cut is driven more than once.
type pieceReader struct{ pieces []string }

func newPieceReader(pieces []string) *pieceReader {
	return &pieceReader{pieces: slices.Clone(pieces)}
}

func (r *pieceReader) Read(p []byte) (int, error) {
	if len(r.pieces) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.pieces[0])
	if r.pieces[0] = r.pieces[0][n:]; r.pieces[0] == "" {
		r.pieces = r.pieces[1:]
	}
	return n, nil
}

// throughStream masks pieces through a Writer and through a Reader, both built
// with opts, and returns what each gave, so that a caller compares both against
// the same expectation.
func throughStream(t testing.TB, m *mask.Masker, pieces []string, opts ...mask.StreamOption) (written, read string) {
	t.Helper()

	var out strings.Builder
	w := mask.NewWriter(&out, m, opts...)
	for _, p := range pieces {
		if _, err := w.Write([]byte(p)); err != nil {
			t.Fatalf("Write(%q) = %v", p, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	got, err := io.ReadAll(mask.NewReader(newPieceReader(pieces), m, opts...))
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAll() = %v", err)
	}
	return out.String(), string(got)
}

// checkStream holds a stream carrying src in pieces to Mask over the whole of
// it, want being what m makes of src uncut.
//
// The Masker and what it makes of the whole text are handed in rather than
// worked out here. A case is cut at every one of its offsets and both are the
// same for every one of those cuts, so worked out here they are a Masker and a
// masking of the whole case per byte of it — several times what driving the
// stream costs.
func checkStream(t testing.TB, m *mask.Masker, src, want string, pieces []string) {
	t.Helper()

	written, read := throughStream(t, m, pieces)
	if written != want {
		t.Errorf("writing %q in %d piece(s) gave %q, Mask gives %q", src, len(pieces), written, want)
	}
	if read != want {
		t.Errorf("reading %q in %d piece(s) gave %q, Mask gives %q", src, len(pieces), read, want)
	}
}

// cutsOf returns the ways src is handed to a stream: whole, cut at every single
// offset, and one byte at a time.
//
// A byte at a time and not a rune at a time: a stream cut inside a rune is what
// a reader filling a fixed buffer leaves, and it is exactly what a cut anywhere
// has to survive.
func cutsOf(src string) [][]string {
	cuts := [][]string{{src}}
	for i := range len(src) + 1 {
		cuts = append(cuts, []string{src[:i], src[i:]})
	}
	byteAtATime := make([]string, 0, len(src))
	for i := 0; i < len(src); i++ {
		byteAtATime = append(byteAtATime, src[i:i+1])
	}
	return append(cuts, byteAtATime)
}

func TestProperties_everyCut(t *testing.T) {
	// The whole of what a stream owes. Every case, cut at every offset, under
	// every redactor a caller reaches for: a stream that released the front of
	// a value before the rest of it arrived, or that redacted twice what Mask
	// redacts once, differs from Mask here and nowhere else.
	for _, c := range readableCases(t) {
		for _, r := range streamRedactors {
			m := maskerWith(c.patterns(), r.redactor)
			want := m.Mask(c.in)
			for _, pieces := range cutsOf(c.in) {
				checkStream(t, m, c.in, want, pieces)
			}
		}
	}
}

func TestProperties_everyCutThroughEveryBuiltinSet(t *testing.T) {
	// Every case cut in two, through every built-in set. A case written for one
	// pattern says nothing about another, and a stream is where one pattern
	// holding text back changes what another one is shown.
	cases := readableCases(t)
	for _, set := range builtinSets {
		t.Run(set.name, func(t *testing.T) {
			t.Parallel()
			m := maskerWith(set.patterns, mask.Fixed("[REDACTED]"))
			for _, c := range cases {
				t.Run(c.subtest(), func(t *testing.T) {
					want := m.Mask(c.in)
					for i := range len(c.in) + 1 {
						checkStream(t, m, c.in, want, []string{c.in[:i], c.in[i:]})
					}
				})
			}
		})
	}
}

func FuzzStream(f *testing.F) {
	for _, c := range corpusCases(f) {
		f.Add(c.in, len(c.in)/2)
	}

	patterns := mask.AllBuiltinPatterns()
	maskers := make([]*mask.Masker, len(streamRedactors))
	for i, r := range streamRedactors {
		maskers[i] = maskerWith(patterns, r.redactor)
	}
	f.Fuzz(func(t *testing.T, src string, cut int) {
		// A cut is a place in src, and a fuzzer reaching this with any int at
		// all would otherwise spend its run on the panic rather than on the
		// grammars.
		if len(src) == 0 {
			cut = 0
		} else {
			cut = ((cut % (len(src) + 1)) + len(src) + 1) % (len(src) + 1)
		}
		for _, m := range maskers {
			checkStream(t, m, src, m.Mask(src), []string{src[:cut], src[cut:]})
		}
	})
}

// streamLimits is what a stream is driven at when the giving up is what is
// being driven, in bytes.
//
// A limit is reached where a pattern is still reading a value out of the text
// held back and the holding has gone past what a caller allows, so these are
// short enough that the corpus reaches them: a case here is a line or two, and
// what one of them holds is tens of bytes rather than the kibibytes a stream
// holds back before its default limit. The largest is past the length of many
// cases, which is a limit doing nothing on those and reached late on the rest,
// and the smallest is reached by anything a pattern holds at all.
var streamLimits = []int{1, 8, 64}

// streamLimitMax bounds the limit FuzzStreamGivesUp drives, which is a length
// its inputs can reach rather than one they would have to be grown to.
const streamLimitMax = 256

// givingUp is what a stream under a limit is held against, built once for a
// pattern set the way masking (properties_test.go) is: a case is cut at every
// one of its offsets and driven at every limit, and two Maskers built inside
// that loop would be more of the work than the streams they are there to drive.
//
// Two redactors, and they are the two halves of what giving up is. Fixed("")
// writes nothing where a value stood, so what is left of an output is the text
// the stream released and nothing else — which is what says whether it released
// what Mask releases and stopped where it stopped. Fill writes a rune for a
// rune, so what is left says how much of the text reached the output at all —
// which is what says that giving up redacted the rest rather than dropping it.
type givingUp struct {
	dropped *mask.Masker
	fill    *mask.Masker
}

// newGivingUp returns a givingUp over patterns.
func newGivingUp(patterns []mask.Pattern) *givingUp {
	return &givingUp{
		dropped: maskerWith(patterns, mask.Fixed("")),
		fill:    maskerWith(patterns, mask.Fill('*')),
	}
}

// check holds a stream carrying src in pieces under limit to what a stream that
// may give up owes, and reports whether this one gave up on anything. dropped
// and fill are what the two Maskers make of the whole of src, handed in for the
// reason newGivingUp gives.
//
// Nothing here holds the stream to Mask outright, which is what the properties
// above hold an unlimited one to: giving up is where the two part by design. So
// what is stated is what survives the parting.
func (g *givingUp) check(t testing.TB, src, dropped, fill string, pieces []string, limit int) bool {
	t.Helper()

	// A Writer and a Reader are two ways to one masking, limit or no limit. The
	// giving up is written once and both of them reach it, so the two parting
	// here is a stream that reaches it from one of them and not the other.
	droppedW, droppedR := throughStream(t, g.dropped, pieces, mask.WithMaxRetained(limit))
	if droppedW != droppedR {
		t.Errorf("under a limit of %d, writing %q in %d piece(s) gave %q and reading it gave %q",
			limit, src, len(pieces), droppedW, droppedR)
		return false
	}
	fillW, fillR := throughStream(t, g.fill, pieces, mask.WithMaxRetained(limit))
	if fillW != fillR {
		t.Errorf("under a limit of %d, writing %q in %d piece(s) gave %q and reading it gave %q",
			limit, src, len(pieces), fillW, fillR)
		return false
	}

	// Whatever the stream released it released masked as Mask masks it, and
	// from the giving up onwards it released nothing at all. Under Fixed("")
	// the redactions are gone from both sides, so what a stream that gave up
	// wrote is what Mask wrote as far as the stream got and stops there. A
	// stream that let go of what it was holding, or that went back to passing
	// text through once it had given up, writes the rest of the very value it
	// gave up on — and no prefix of what Mask gives holds that.
	if !strings.HasPrefix(dropped, droppedW) {
		t.Errorf("under a limit of %d, writing %q in %d piece(s) released %q, which Mask's %q does not open with",
			limit, src, len(pieces), droppedW, dropped)
	}

	// A rune out for every rune in. Giving up redacts what is held rather than
	// dropping it, so nothing goes missing, and the rune a cut falls inside is
	// held back until the rest of it arrives rather than redacted a piece at a
	// time — a redactor is handed the text it replaces, and Fill counts the
	// runes of it.
	if got, want := utf8.RuneCountInString(fillW), utf8.RuneCountInString(src); got != want {
		t.Errorf("under a limit of %d, writing %q in %d piece(s) gave %d rune(s), the text has %d",
			limit, src, len(pieces), got, want)
	}

	// Whether it gave up at all. Only the giving up parts a stream from Mask,
	// so a stream that wrote something else wrote it from there; the converse
	// is not claimed, since a stream giving up on the last value of a text
	// redacts what Mask redacts anyway.
	return fillW != fill
}

// heldByWriter returns the most a Writer under limit was left holding after a
// write: the runes handed to it that had not reached the writer underneath.
//
// m must redact with Fill, which writes a rune for a rune, or what reached the
// writer underneath says nothing about how much of the text it stands for.
func heldByWriter(t testing.TB, m *mask.Masker, src string, limit int) int {
	t.Helper()

	var out strings.Builder
	w := mask.NewWriter(&out, m, mask.WithMaxRetained(limit))
	most := 0
	for i := range src {
		if _, err := w.Write([]byte(src[i : i+1])); err != nil {
			t.Fatalf("Write() = %v", err)
		}
		most = max(most, utf8.RuneCountInString(src[:i+1])-utf8.RuneCountInString(out.String()))
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	return most
}

func TestProperties_everyCutUnderALimit(t *testing.T) {
	// Every case, cut at every offset, under every limit the corpus reaches.
	// The properties are in givingUp.check; what is here is the driving of
	// them and the count that keeps it from driving nothing.
	gaveUp := 0
	for _, c := range readableCases(t) {
		g := newGivingUp(c.patterns())
		dropped, fill := g.dropped.Mask(c.in), g.fill.Mask(c.in)
		for _, limit := range streamLimits {
			for _, pieces := range cutsOf(c.in) {
				if g.check(t, c.in, dropped, fill, pieces, limit) {
					gaveUp++
				}
			}
		}
	}

	// Counted rather than trusted. A stream that never gives up agrees with
	// Mask, which every property above passes on, so a corpus none of these
	// limits reached would leave all of them driving nothing and nothing would
	// say so.
	if gaveUp == 0 {
		t.Errorf("no case at any of the limits %v parted from what Mask gives, so none of them gave up", streamLimits)
	}
}

func TestProperties_aLimitedStreamHoldsNoMoreThanTheLimit(t *testing.T) {
	// What a limit is for, and what nothing else here would report. A stream
	// that never gives up gives what Mask gives, so every property beside this
	// one passes on it; what says it is holding is how much it is holding.
	//
	// A byte at a time is the shape that holds most: every write is a place the
	// stream may give up at and it takes the last one it can. What it may be
	// holding then is the limit — or, once it has given up, the bytes of a rune
	// the input stops inside, which are held back rather than redacted so that
	// a redactor counting what it is handed counts that rune once.
	for _, c := range readableCases(t) {
		m := maskerWith(c.patterns(), mask.Fill('*'))
		for _, limit := range streamLimits {
			want := max(limit, utf8.UTFMax-1)
			if got := heldByWriter(t, m, c.in, limit); got > want {
				t.Errorf("%s: under a limit of %d, a Writer was left holding %d rune(s), want %d at most",
					c.id(), limit, got, want)
			}
		}
	}
}

func FuzzStreamGivesUp(f *testing.F) {
	for _, c := range corpusCases(f) {
		f.Add(c.in, len(c.in)/2, 8)
	}

	g := newGivingUp(mask.AllBuiltinPatterns())
	f.Fuzz(func(t *testing.T, src string, cut, limit int) {
		// A cut is a place in src and a limit is a length src can reach, and a
		// fuzzer arriving here with any int at all would otherwise spend its
		// run on the panic rather than on the grammars. Zero is not among the
		// limits: it holds without limit, which is what FuzzStream drives.
		if len(src) == 0 {
			cut = 0
		} else {
			cut = ((cut % (len(src) + 1)) + len(src) + 1) % (len(src) + 1)
		}
		limit = ((limit%streamLimitMax)+streamLimitMax)%streamLimitMax + 1
		g.check(t, src, g.dropped.Mask(src), g.fill.Mask(src), []string{src[:cut], src[cut:]}, limit)
	})
}
