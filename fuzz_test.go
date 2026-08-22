package mask

import (
	"encoding/binary"
	"slices"
	"testing"
)

// The fuzzing that belongs to no one pattern: the targets that drive a Masker,
// and the body the per-pattern targets share. A pattern's own target lives with
// the pattern, in the builtin_<name>_test.go beside it, so that this file does
// not grow with every pattern added.

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
		got := m.locate(src)

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
func fuzzAgainstReference(f *testing.F, find, ref func(string) []Span) {
	f.Fuzz(func(t *testing.T, src string) {
		// slices.Equal holds nothing reported as an empty slice and nothing
		// reported at all the same, which Find is free to choose between.
		got, want := find(src), ref(src)
		if !slices.Equal(got, want) {
			t.Fatalf("Find(%q) = %v, reference gives %v", src, got, want)
		}
	})
}
