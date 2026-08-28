// What must hold of masking text that arrives in pieces.
//
// One property carries the whole of it: cut a case anywhere at all, write the
// pieces through a Writer or read them through a Reader, and what comes out is
// what Mask returns for the case uncut. Mask is what the corpus states and what
// the properties beside this hold to everything masking must be; a stream owes
// the same output, so holding it to Mask holds it to all of that at once.

package conformance

import (
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

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

// throughStream masks pieces through a Writer and through a Reader and returns
// what each gave, so that a caller compares both against the same expectation.
func throughStream(t testing.TB, m *mask.Masker, pieces []string) (written, read string) {
	t.Helper()

	var out strings.Builder
	w := mask.NewWriter(&out, m)
	for _, p := range pieces {
		if _, err := w.Write([]byte(p)); err != nil {
			t.Fatalf("Write(%q) = %v", p, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	got, err := io.ReadAll(mask.NewReader(newPieceReader(pieces), m))
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAll() = %v", err)
	}
	return out.String(), string(got)
}

// checkStream holds a stream carrying src in pieces to Mask over the whole of
// it.
func checkStream(t testing.TB, patterns []mask.Pattern, redactor mask.Redactor, src string, pieces []string) {
	t.Helper()

	m := maskerWith(patterns, redactor)
	want := m.Mask(src)
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
			for _, pieces := range cutsOf(c.in) {
				checkStream(t, c.patterns(), r.redactor, c.in, pieces)
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
			for _, c := range cases {
				t.Run(c.subtest(), func(t *testing.T) {
					for i := range len(c.in) + 1 {
						checkStream(t, set.patterns, mask.Fixed("[REDACTED]"), c.in, []string{c.in[:i], c.in[i:]})
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
	f.Fuzz(func(t *testing.T, src string, cut int) {
		// A cut is a place in src, and a fuzzer reaching this with any int at
		// all would otherwise spend its run on the panic rather than on the
		// grammars.
		if len(src) == 0 {
			cut = 0
		} else {
			cut = ((cut % (len(src) + 1)) + len(src) + 1) % (len(src) + 1)
		}
		for _, r := range streamRedactors {
			checkStream(t, patterns, r.redactor, src, []string{src[:cut], src[cut:]})
		}
	})
}
