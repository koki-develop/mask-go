package mask

import (
	"encoding/binary"
	"slices"
	"strings"
	"testing"
)

// The fuzzing that belongs to no one pattern: the targets that drive a Masker,
// and the bodies fuzz targets share, wherever those targets stand. A pattern's
// own target lives with the pattern, in the builtin_<name>_test.go beside it,
// so that this file does not grow with every pattern added.

// reportedSpans reads the spans a fuzz input asks the pattern to report: two
// signed sixteen bit offsets a span, most significant byte first. Anything left
// over at the end is dropped.
func reportedSpans(raw []byte) []Span {
	var spans []Span
	for len(raw) >= 4 {
		spans = append(spans, Span{
			Start: int(int16(binary.BigEndian.Uint16(raw))),
			End:   int(int16(binary.BigEndian.Uint16(raw[2:]))),
		})
		raw = raw[4:]
	}
	return spans
}

// spanBytes writes spans the way reportedSpans reads them, so that a seed says
// what it means. Written out by hand these take four bytes a span, and a seed
// that gives one byte an offset asks for spans far past the input, which are
// ignored: seeds meant to cover the resolution rules then cover nothing.
func spanBytes(spans ...Span) []byte {
	raw := make([]byte, 0, 4*len(spans))
	for _, s := range spans {
		raw = binary.BigEndian.AppendUint16(raw, uint16(int16(s.Start)))
		raw = binary.BigEndian.AppendUint16(raw, uint16(int16(s.End)))
	}
	return raw
}

// FuzzMasker_locate checks the guarantees Mask relies on: the values it walks
// are ordered, never overlap, and between them still cover every span a pattern
// reported.
func FuzzMasker_locate(f *testing.F) {
	f.Add("abcdef", spanBytes(Span{0, 2}, Span{4, 6}))  // apart
	f.Add("abcdef", spanBytes(Span{0, 4}, Span{2, 6}))  // overlapping
	f.Add("abcdef", spanBytes(Span{0, 6}, Span{2, 4}))  // one inside the other
	f.Add("abcdef", spanBytes(Span{4, 6}, Span{0, 2}))  // out of order
	f.Add("abcdef", spanBytes(Span{0, 2}, Span{2, 4}))  // adjacent
	f.Add("abcdef", spanBytes(Span{0, 2}, Span{0, 2}))  // the same span twice
	f.Add("abcdef", spanBytes(Span{0, 6}))              // the whole input
	f.Add("abcdef", spanBytes(Span{3, 3}))              // empty
	f.Add("abcdef", spanBytes(Span{4, 2}))              // reversed
	f.Add("abcdef", spanBytes(Span{-1, 2}))             // starting before the input
	f.Add("abcdef", spanBytes(Span{4, 7}))              // reaching past it
	f.Add("abcdef", spanBytes(Span{3, 3}, Span{0, 2}))  // empty beside a value
	f.Add("abcdef", spanBytes(Span{4, 7}, Span{0, 2}))  // unusable beside a value
	f.Add("", spanBytes(Span{0, 1}))                    // no input to locate in
	f.Add("日本語abc", spanBytes(Span{0, 9}, Span{3, 12})) // overlapping, multi-byte
	f.Add("abcdef", []byte{0})                          // too few bytes for a span
	f.Add("abcdef", []byte{0, 0, 0, 2, 0})              // a trailing byte is dropped

	f.Fuzz(func(t *testing.T, src string, raw []byte) {
		reported := reportedSpans(raw)

		m := New(WithPatterns(fixed("p", reported...)))
		got := m.locate(src, 0).found

		for i, l := range got {
			if l.Start < 0 || l.End > len(src) || l.Start >= l.End {
				t.Fatalf("locate returned an unusable span %v for input of %d bytes", l.Span, len(src))
			}
			if i > 0 && l.Start < got[i-1].End {
				t.Fatalf("locate returned overlapping spans %v and %v", got[i-1].Span, l.Span)
			}
			if l.pattern == nil {
				t.Fatalf("locate returned a span with no pattern: %v", l.Span)
			}
		}

		for _, s := range reported {
			if s.Start < 0 || s.End > len(src) || s.Start >= s.End {
				continue // Find is documented to have these ignored
			}
			if !covered(got, s) {
				t.Fatalf("reported span %v is not covered by %v", s, got)
			}
		}
	})
}

func covered(got []located, s Span) bool {
	for _, l := range got {
		if l.Start <= s.Start && s.End <= l.End {
			return true
		}
	}
	return false
}

// FuzzMasker_Mask checks that masking is exhaustive: scanning the output of
// Mask with the same patterns finds nothing left to redact out of reach of what
// it redacted.
func FuzzMasker_Mask(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz")
	f.Add("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
	f.Add("ghs_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
	f.Add("github_pat_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789")
	f.Add("eyJ.eyJ.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
	f.Add("eyJx.a.beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
	f.Add("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0.encKEY.iv12.ciphertext.authTAG")
	f.Add("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0.encKEY123.iv12345.0123456789abcdef")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJhbGciOiJIUzI1NiJ9.0123456789abcdef.a.b")
	f.Add("eyIwIjoxLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
	f.Add("ghs_0123456789abcdefghijklmnopqrstuvwxyz0123_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
	f.Add("eyJ..eyJ..eyJ..eyJ..")

	m := New(WithPatterns(AllBuiltinPatterns()...))
	f.Fuzz(func(t *testing.T, src string) {
		checkSecondPass(t, m, src)
	})
}

// fuzzAgainstReference holds find to ref on every input f reaches it with.
//
// Each pattern keeps a fuzz target of its own, beside the pattern, rather than
// every pattern being driven from one: the corpus under testdata/fuzz is keyed
// on the name of the target, and a failure is minimized against the single
// pattern that carries it. Only the body the targets share lives here.
func fuzzAgainstReference(f *testing.F, find func(string) ([]Span, int), ref func(string) []Span) {
	f.Fuzz(func(t *testing.T, src string) {
		// slices.Equal holds nothing reported as an empty slice and nothing
		// reported at all the same, which Find is free to choose between.
		got, _ := find(src)
		want := ref(src)
		if !slices.Equal(got, want) {
			t.Fatalf("Find(%q) = %v, reference gives %v", src, got, want)
		}
	})
}

// normalizeCut folds an int a fuzzer handed a target into a place in src, which
// is what every target taking a cut reads one as. A fuzzer reaching such a
// target with any int at all would otherwise spend its run on the panic rather
// than on the grammars.
//
// A text of n bytes has n+1 places in it, and an empty text the one place in
// front of nothing, which is what the arithmetic below returns for it.
func normalizeCut(src string, cut int) int {
	n := len(src) + 1
	return ((cut % n) + n) % n
}

// FuzzBuiltins_retain holds every built-in to what Pattern.Find promises of the
// offset it reports, on a text and a place to cut it.
//
// One target for the whole registry rather than one to a pattern, which is what
// the per-pattern targets beside each scan are for. The inputs that find this
// wrong are not crafted against any one grammar — they are a value and a cut
// landing inside it — so a corpus keyed on one pattern's name would hold cases
// every other pattern wants, and the failure names the pattern it came from
// either way.
func FuzzBuiltins_retain(f *testing.F) {
	f.Add("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz", 20)
	f.Add("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef", 40)
	f.Add("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----\n", 31)
	f.Add("xoxb-0123456789-0123456789012-0123456789abcdefghijklmn", 5)
	f.Add("sk-0123T3BlbkFJ0123456789abcdef", 3)
	f.Add("there is no credential in this sentence", 7)
	f.Add("", 0)

	patterns := AllBuiltinPatterns()
	f.Fuzz(func(t *testing.T, src string, cut int) {
		cut = normalizeCut(src, cut)
		for _, p := range patterns {
			checkRetain(t, p, src, cut)
		}
	})
}

// FuzzPatterns_lookBehind holds every pattern to LookBehind on a text and a
// place to cut the front off it.
//
// One target for the built-ins and for what MustRegexp builds together, for the
// reason FuzzBuiltins_retain gives: what finds this wrong is a value or a match
// standing across the cut rather than anything crafted against one grammar.
func FuzzPatterns_lookBehind(f *testing.F) {
	f.Add(strings.Repeat("0123456789abcdef", 24), 65)
	f.Add("sha="+strings.Repeat("abcdef0123", 30), 70)
	f.Add(strings.Repeat("key-123 and INT-0123456789abcdef ", 8), 64)
	f.Add(strings.Repeat("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz ", 4), 64)
	f.Add(strings.Repeat("xoxb-0123456789-0123456789012-0123456789abcdefghijklmn ", 3), 100)
	f.Add("", 0)

	patterns := append(lookBehindPatterns(), AllBuiltinPatterns()...)
	f.Fuzz(func(t *testing.T, src string, cut int) {
		cut = normalizeCut(src, cut)
		for _, p := range patterns {
			checkLookBehind(t, p, src, cut)
		}
	})
}
