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
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
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
		n, err := w.Write([]byte(p))
		if err != nil {
			t.Fatalf("Write(%q) = %v", p, err)
		}
		// Writer.Write: "The count returned is len(p) whenever there is no
		// error." Every write made under a limit, including one made after
		// the stream has already given up, is held to this too — nothing
		// above calls throughStream without opts covering both.
		if n != len(p) {
			t.Errorf("Write(%q) = (%d, nil), want (%d, nil)", p, n, len(p))
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

func TestProperties_aStreamOverAPatternReportingSpans(t *testing.T) {
	// NewWriter and NewReader take any *Masker, and nothing in their docs
	// restricts a stream to a pattern that locates values in the text it is
	// handed rather than one reporting spans of its own whatever it is
	// handed — unusable_spans.txt's patterns, held back from every property
	// above because "the properties that follow a value around say nothing
	// about it: it does not follow a value around" (conformance/CLAUDE.md).
	// That silence covers every property comparing a stream's output to
	// Mask's; it does not cover a stream over such a pattern crashing, or a
	// Writer and a Reader disagreeing about the same offsets read from a
	// window that keeps moving under them.
	for _, c := range corpusCases(t) {
		if c.reads {
			continue // driven against Mask by the properties above already
		}
		t.Run(c.subtest(), func(t *testing.T) {
			for _, r := range streamRedactors {
				m := maskerWith(c.patterns(), r.redactor)
				for _, pieces := range cutsOf(c.in) {
					written, read := throughStream(t, m, pieces)
					if written != read {
						t.Errorf("%s: writing %q in %d piece(s) gave %q, reading it gave %q",
							r.name, c.in, len(pieces), written, read)
					}
				}
			}
		})
	}
}

func FuzzStream(f *testing.F) {
	for _, c := range corpusCases(f) {
		f.Add(c.in, len(c.in)/2)
	}
	// A cut landing inside a multi-byte rune, which is exactly what a Reader
	// filling a fixed-size buffer leaves, and what cutsOf's byte-at-a-time
	// entry already drives — but this seed reaches it deterministically under
	// a plain `go test`, without a fuzzer's mutations happening to land the
	// cut argument there first.
	f.Add("token=ghp_0123456789abcdefghijklmnopqrstuvwxyz日本語", 47)

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
	marked  *mask.Masker
	known   map[string]bool
}

// newGivingUp returns a givingUp over patterns.
func newGivingUp(patterns []mask.Pattern) *givingUp {
	known := make(map[string]bool, len(patterns))
	for _, p := range patterns {
		known[p.Name()] = true
	}
	return &givingUp{
		dropped: maskerWith(patterns, mask.Fixed("")),
		fill:    maskerWith(patterns, mask.Fill('*')),
		marked:  maskerWith(patterns, markRedactor),
		known:   known,
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
//
// src must carry neither mark rune, because the attribution below is read back
// out of marked text and a mark rune already in the text is one parseMarked
// cannot tell from a redactor's. A case of the corpus carries none by rule; a
// caller handing over generated text passes it through textWithoutMarks
// (notation_test.go) first.
func (g *givingUp) check(t testing.TB, src, dropped, fill string, pieces []string, limit int) bool {
	t.Helper()

	// Asked rather than assumed, because the way this goes wrong is silent. A
	// mark the text carries that is well formed and names a real pattern parses,
	// and the attribution below then reads the text's own mark: both assertions
	// pass for a stream that made no mark at all. A caller that forgot
	// textWithoutMarks fails here instead, at the call that forgot it.
	if strings.ContainsAny(src, string(markOpen)+string(markClose)) {
		t.Fatalf("check was handed %q, which carries a mark rune of its own; pass generated text through textWithoutMarks first", src)
	}

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

	gaveUp := fillW != fill
	if gaveUp && len(g.known) > 1 {
		// WithMaxRetained: "The redaction covers everything held at that
		// moment and is attributed to the pattern that was holding it, so a
		// redactor reading Match.Pattern sees which grammar ran long." With a
		// single pattern in play the attribution is trivially satisfied — the
		// holder is the only one there is — so this is asked only where more
		// than one pattern could have been holding.
		markedW, markedR := throughStream(t, g.marked, pieces, mask.WithMaxRetained(limit))
		if markedW != markedR {
			t.Errorf("under a limit of %d, writing %q in %d piece(s) gave %q and reading it gave %q",
				limit, src, len(pieces), markedW, markedR)
			return false
		}
		m, err := parseMarked(markedW)
		if err != nil {
			t.Fatalf("under a limit of %d, writing %q gave %q, which is not marked text: %v", limit, src, markedW, err)
		}
		if len(m.names) == 0 {
			t.Errorf("under a limit of %d, writing %q parted from Mask but the marking redactor made no mark at all", limit, src)
		} else if last := m.names[len(m.names)-1]; !g.known[last] {
			// Nothing reaches this while two things hold, and a test holds
			// each. The text carries no mark rune, which the precondition
			// above refuses rather than assumes, so every mark parsed here was
			// written by markRedactor. And no pattern's name carries one,
			// which Test_builtins_name (root package) holds for a built-in and
			// Test_patternSets_nameNoMarkRune for the rest — without it a name
			// would close its own mark early and leave the parse reading a
			// prefix g.known does not hold, which is this same failure
			// reaching by way of a pattern rather than by way of the text.
			//
			// It stands anyway, because what it states is a property of
			// attribution rather than of the notation: a give-up went to a
			// pattern the stream was given. The two tests above are what make
			// it quiet, and neither is what it is about.
			t.Errorf("under a limit of %d, writing %q attributed the give-up to %q, which is not one of the patterns given", limit, src, last)
		}
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

func TestConformance_giveUpAttributesToTheHoldingPattern(t *testing.T) {
	// WithMaxRetained's own words: a redactor reading Match.Pattern "sees
	// which grammar ran long." givingUp.check states this over the whole
	// corpus, but every readable case there is masked with a set of patterns
	// none of which shares an opening with another, so the pattern named at
	// the give-up is never in question. This is the case that puts two
	// patterns in a position to be holding the same run: a Stripe secret key
	// prefix opens first, so it is StripeSecretKey holding the run of
	// hexadecimal that never closes, and the give-up must name it rather than
	// GitHubToken, which never opened a candidate here at all.
	m := mask.New(
		mask.WithPatterns(mask.StripeSecretKey(), mask.GitHubToken()),
		mask.WithRedactor(markRedactor),
	)
	src := "sk_live_" + strings.Repeat("0123456789abcdef", 40)

	var out strings.Builder
	w := mask.NewWriter(&out, m, mask.WithMaxRetained(16))
	for i := 0; i < len(src); i += 16 {
		end := min(i+16, len(src))
		if _, err := w.Write([]byte(src[i:end])); err != nil {
			t.Fatalf("Write() = %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	got := out.String()
	m2, err := parseMarked(got)
	if err != nil {
		t.Fatalf("the output %q is not marked text: %v", got, err)
	}
	if len(m2.names) == 0 {
		t.Fatalf("writing %q under a limit made no mark at all; want it to have given up", src)
	}
	if last := m2.names[len(m2.names)-1]; last != "stripe-secret-key" {
		t.Errorf("the give-up is attributed to %q, want %q", last, "stripe-secret-key")
	}
}

func TestProperties_givingUpRedactsAWriteAtATime(t *testing.T) {
	// WithMaxRetained: "What is redacted after that is redacted a write at a
	// time, since a stream cannot hold the rest of itself back to redact it
	// as one ... and a redactor writing a fixed string writes it once a write
	// rather than once." The "rather than once" half is the contrast this
	// states: the same text, in one write, gives one fixed string; split into
	// several writes after the give-up, it gives one per write.
	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...), mask.WithRedactor(mask.Fixed("<R>")))
	src := "sk_live_" + strings.Repeat("0123456789abcdef", 8)

	var whole strings.Builder
	wWhole := mask.NewWriter(&whole, m, mask.WithMaxRetained(8))
	if _, err := wWhole.Write([]byte(src)); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if err := wWhole.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if got, want := strings.Count(whole.String(), "<R>"), 1; got != want {
		t.Fatalf("writing %q in one piece gave %d occurrence(s) of <R>, want %d", src, got, want)
	}
	if got := strings.ReplaceAll(whole.String(), "<R>", ""); got != "" {
		t.Fatalf("writing %q in one piece gave %q, want nothing but <R>", src, whole.String())
	}

	var pieces strings.Builder
	wPieces := mask.NewWriter(&pieces, m, mask.WithMaxRetained(8))
	for i := 0; i < len(src); i += 16 {
		end := min(i+16, len(src))
		if _, err := wPieces.Write([]byte(src[i:end])); err != nil {
			t.Fatalf("Write() = %v", err)
		}
	}
	if err := wPieces.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if got := strings.Count(pieces.String(), "<R>"); got <= 1 {
		t.Errorf("writing %q in several pieces after the give-up gave %d occurrence(s) of <R>, want more than 1", src, got)
	}
	if got := strings.ReplaceAll(pieces.String(), "<R>", ""); got != "" {
		t.Errorf("writing %q in several pieces gave %q, want nothing but repeats of <R>", src, pieces.String())
	}
}

func TestProperties_zeroAndNegativeLimitsNeverGiveUp(t *testing.T) {
	// WithMaxRetained: "Zero holds without limit ... Any n below zero is read
	// as that same zero rather than as a limit no text can come under." Every
	// limit in streamLimits above is positive, so this is what drives zero and
	// a negative n over the corpus instead: neither may ever part a stream
	// from Mask, at any cut.
	for _, n := range []int{0, -1, -(1 << 20)} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			t.Parallel()
			for _, c := range readableCases(t) {
				for _, r := range streamRedactors {
					m := maskerWith(c.patterns(), r.redactor)
					want := m.Mask(c.in)
					for _, pieces := range cutsOf(c.in) {
						written, read := throughStream(t, m, pieces, mask.WithMaxRetained(n))
						if written != want {
							t.Errorf("%s: WithMaxRetained(%d): writing %q in %d piece(s) gave %q, Mask gives %q",
								c.id(), n, c.in, len(pieces), written, want)
						}
						if read != want {
							t.Errorf("%s: WithMaxRetained(%d): reading %q in %d piece(s) gave %q, Mask gives %q",
								c.id(), n, c.in, len(pieces), read, want)
						}
					}
				}
			}
		})
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

func TestProperties_aStreamGivesUpNoSoonerThanTheValueItIsHolding(t *testing.T) {
	// TestProperties_everyCutUnderALimit and
	// TestProperties_aLimitedStreamHoldsNoMoreThanTheLimit hold a limited
	// stream to an upper bound: it may not hold more than the limit, and what
	// it holds under the limit still agrees with Mask. This is the lower
	// bound instead: a Writer or a Reader that gave up holding at half of
	// whatever limit it was given would pass both of those — it never holds
	// more than asked, and every corpus case is short enough that giving up
	// early still happens to agree with Mask on it.
	//
	// One case pins the lower bound instead, chosen so the arithmetic reads
	// off the case itself. NPMAccessToken locates npm_ and a floor of
	// thirty-six characters behind it, forty in all, and nothing bounds the
	// value above: it is redacted to the end of whatever run of its alphabet
	// follows the prefix. Put at the front of a stream with nothing of that
	// alphabet in front of it, the value opens a candidate that stays open for
	// as long as the run does — every character read could still be carried
	// further by the next one — so what a Writer or a Reader is holding for it
	// grows one byte at a time and stands at exactly forty the byte the floor
	// is met on. The very next byte, being outside the alphabet the run is
	// read in, closes the run there and settles the whole candidate at once:
	// unlike a pattern held to an exact count, a floor asks the byte behind the
	// run only whether the run has ended, never whether it has already run too
	// long, so nothing here costs a second look past the one that closes it.
	//
	// So a stream told to hold at least forty bytes never has to give up
	// holding this value, and one told to hold fewer than forty always does:
	// the fortieth byte is the last one a stream can still be holding when the
	// forty-first arrives and closes the value, and nothing before the
	// forty-first says a stream could have held less. What is driven below is
	// exactly that transition, one byte at a time and one limit at a time from
	// 1 to 80 — 80 being twice the value's own width, which is generous room to
	// watch the transition happen once and land where the value says it must,
	// not a width this holds a stream to.
	const (
		// npmToken is a value NPMAccessToken locates on its own: npm_ and the
		// thirty-six characters of the floor exactly, forty bytes altogether.
		// The run is the corpus's own ordered alphabet, digits then lowercase
		// letters, so it reads as a placeholder rather than as a value copied
		// from anywhere real.
		npmToken = "npm_0123456789abcdefghijklmnopqrstuvwxyz"
		// trailer stands behind the token. Its first byte is a space, which
		// belongs to no alphabet any built-in reads a value in, so it is what
		// closes the token's run the byte after the fortieth; the rest is
		// prose carrying the case well past every limit tried below, with
		// nothing in it that opens a candidate of its own.
		trailer = " and then a stretch of ordinary prose follows, long enough on its own to carry the case past every limit this test tries so that a stream always has more to write once the token ahead of it has closed"
	)
	src := npmToken + trailer
	if len(npmToken) != 40 {
		t.Fatalf("npmToken is %d byte(s), want the 40 the rationale above is built on", len(npmToken))
	}
	const maxLimit = 80
	if len(src) <= maxLimit {
		t.Fatalf("the case is %d byte(s), too short to try every limit up to %d meaningfully", len(src), maxLimit)
	}

	m := maskerWith([]mask.Pattern{mask.NPMAccessToken()}, mask.Fixed("[R]"))
	want := m.Mask(src)
	if want == src {
		t.Fatalf("Mask(%q) located nothing, so no limit here can be told from another by it", src)
	}

	pieces := make([]string, len(src))
	for i := range len(src) {
		pieces[i] = src[i : i+1]
	}

	// matches[k] is whether limit k gave what Mask gives. Index 0 is never set;
	// limits run 1 to maxLimit.
	matches := make([]bool, maxLimit+1)
	for k := 1; k <= maxLimit; k++ {
		written, read := throughStream(t, m, pieces, mask.WithMaxRetained(k))
		matches[k] = written == want && read == want
		if k >= 40 && !matches[k] {
			t.Errorf("under a limit of %d, writing gave %q and reading gave %q, Mask gives %q", k, written, read, want)
		}
	}

	// Upward closed: once a limit agrees with Mask, every limit above it does
	// too, so the limits that agree and the limits that do not meet at exactly
	// one place.
	transitions := 0
	for k := 2; k <= maxLimit; k++ {
		if matches[k] != matches[k-1] {
			transitions++
		}
	}
	if transitions > 1 {
		t.Errorf("the limits that agree with Mask are not upward closed: %v", matches[1:])
	}

	// Where that one place falls is the rationale above stated as a number: a
	// stream told to hold forty bytes never gives up on this value, and one
	// told to hold thirty-nine always does.
	if matches[39] || !matches[40] {
		t.Errorf("the transition is not at 40: matches(39)=%v matches(40)=%v", matches[39], matches[40])
	}
}

func TestConformance_readerErrorIsHeldUntilTheTextIs(t *testing.T) {
	// Reader.Read's own words, mirrored from the root package's
	// TestReader_errorIsHeldUntilTheTextIs, which drives only ASCII: "The
	// error that ended that reader is held back until the text held with it
	// has been returned." A source ending mid-rune, or holding invalid UTF-8
	// outright, is what a Reader wrapping a source that stops with an error —
	// a truncated network read, a canceled context — leaves the stream
	// holding, and nothing states that this text, too, comes back whole
	// before the error that ended the underlying reader does.
	errBoom := errors.New("boom")
	tests := []struct {
		name  string
		bytes string
	}{
		{name: "an unfinished three-byte rune", bytes: "token=ghp_012345\xe6\x97"},
		{name: "an unfinished four-byte rune", bytes: "日本語\xf0\x9f"},
		{name: "a lone continuation byte", bytes: "abc\x80"},
	}
	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mask.NewReader(&erroringReader{data: tt.bytes, err: errBoom}, m)
			got, err := io.ReadAll(r)
			if !errors.Is(err, errBoom) {
				t.Fatalf("ReadAll() error = %v, want %v", err, errBoom)
			}
			if string(got) != tt.bytes {
				t.Errorf("ReadAll() = %q, want %q read back before the error", got, tt.bytes)
			}
		})
	}
}

// erroringReader hands over its data one byte at a time and then fails with
// err instead of reporting io.EOF, the way a source that stops without a
// clean end — a truncated network read, a canceled context — does.
type erroringReader struct {
	data string
	err  error
}

func (r *erroringReader) Read(p []byte) (int, error) {
	// io.Reader permits a zero-length p and states that a call reporting 0,
	// nil means nothing happened — not EOF, not err. Falling through would
	// still copy nothing into p but would drop a byte of data regardless,
	// which is the wrong side of that contract to be wrong on: the byte is
	// gone before anything ever reads it back.
	if len(p) == 0 {
		return 0, nil
	}
	if r.data == "" {
		return 0, r.err
	}
	n := copy(p, r.data[:1])
	r.data = r.data[1:]
	return n, nil
}

func TestConformance_readerIsLinearAtScale(t *testing.T) {
	// TestConformance_scale (conformance_test.go) drives Mask itself at
	// mebibyte scale; TestStream_isLinear (root package) drives a Writer the
	// same way. Neither reaches a Reader, and NewReader wrapping an
	// io.Reader — io.ReadAll(mask.NewReader(resp.Body, m)) — is the
	// documented shape of reading a stream rather than writing one.
	const (
		size  = 1 << 20
		limit = 4 * time.Second
	)
	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...))
	unit := "sk_live_" + strings.Repeat("0123456789abcdef", 16) + "\n"
	src := strings.Repeat(unit, size/len(unit)+1)

	start := time.Now()
	r := mask.NewReader(strings.NewReader(src), m, mask.WithMaxRetained(0))
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}
	if d := time.Since(start); d > limit {
		t.Errorf("reading %d bytes through a Reader took %v, want under %v", len(src), d, limit)
	}

	want := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...)).Mask(src)
	if string(got) != want {
		t.Errorf("reading the whole stream did not match Mask of the same text")
	}
}

func FuzzStreamGivesUp(f *testing.F) {
	for _, c := range corpusCases(f) {
		f.Add(c.in, len(c.in)/2, 8)
	}

	// The inputs a fuzzer arrived at here before textWithoutMarks took the mark
	// runes out, kept so that a plain go test drives them rather than waiting on
	// a fuzzer to reach them again. What they have in common is a mark rune the
	// text itself carries; notation_test.go says what that costs, and
	// Test_textWithoutMarks is where the shapes are enumerated.
	f.Add("0«0000000000", 22, 8)
	f.Add("«0000000000", 22, 8)
	f.Add("»0000000000", 22, 8)
	// And the shape no fuzzer had to find, because it fails nothing: a mark the
	// text carries that is well formed and names a real pattern, which a check
	// reading the name back cannot tell from a redactor's.
	f.Add("«stripe-secret-key»0000000000", 22, 8)

	g := newGivingUp(mask.AllBuiltinPatterns())
	f.Fuzz(func(t *testing.T, src string, cut, limit int) {
		// givingUp.check reads marks back out of what it masked, so it owes
		// text carrying none of its own. notation_test.go says why a fuzz
		// target is where that is stated and a corpus-driven test is not.
		src = textWithoutMarks(src)

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
