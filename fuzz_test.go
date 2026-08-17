package mask

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
)

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

// FuzzLocate checks the guarantees Mask relies on: the values it walks are
// ordered, never overlap, and between them still cover every span a pattern
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

// FuzzMaskLeavesNothingToFind checks that masking is exhaustive: scanning the
// output of Mask with the same patterns finds nothing left to redact.
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

	m := New(WithPatterns(DefaultPatterns()...))
	f.Fuzz(func(t *testing.T, src string) {
		masked := m.Mask(src)
		if left := m.locate(masked); len(left) != 0 {
			t.Fatalf("Mask(%q) = %q still holds %d value(s) to redact", src, masked, len(left))
		}
		if again := m.Mask(masked); again != masked {
			t.Fatalf("Mask is not idempotent: %q then %q", masked, again)
		}
	})
}

// referenceJWTFind locates tokens the plain way: every header prefix in turn,
// decoded and read in full, with no cursor and nothing remembered between
// candidates. The scanner in builtin.go must agree with it on every input.
func referenceJWTFind(src string) []Span {
	var spans []Span
	for offset := 0; offset < len(src); {
		i := strings.Index(src[offset:], jwtHeaderPrefix)
		if i < 0 {
			break
		}
		start := offset + i
		offset = start + 1

		dot := start
		for dot < len(src) && isBase64URLByte(src[dot]) {
			dot++
		}
		if dot == len(src) || src[dot] != '.' {
			continue
		}

		decoded, err := base64.RawURLEncoding.DecodeString(src[start:dot])
		if err != nil {
			continue
		}
		if len(decoded) < len(`{"a":0}`) || decoded[0] != '{' || decoded[1] != '"' {
			continue
		}
		if !closesObject(decoded) || !bytes.Contains(decoded, algName) {
			continue
		}

		signed := segmentsEnd(src, dot, signedSegments)
		if !signed.ok {
			continue
		}
		end := signed.end
		if encrypted := segmentsEnd(src, dot, encryptedSegments); encrypted.ok && bytes.Contains(decoded, encName) {
			end = encrypted.end
		}
		spans = append(spans, Span{Start: start, End: end})
		offset = end
	}
	return spans
}

// fuzzAgainstReference holds find to ref on every input f reaches it with.
//
// Each pattern keeps a fuzz target of its own rather than every pattern being
// driven from one: the corpus under testdata/fuzz is keyed on the name of the
// target, and a failure is minimized against the single pattern that carries
// it. Only the body the targets share lives here.
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

// FuzzJWT_matchesReference guards the cursor, the cheap checks and the decode
// the scanner remembers between candidates: none of them may change which
// tokens are located.
func FuzzJWT_matchesReference(f *testing.F) {
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
	f.Add("eyJ.eyJ.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
	f.Add("eyIwIjoxLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
	f.Add("eyLDqSI6MSwiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
	f.Add("eyeyeyey.a.b")
	f.Add("eyJhYiI6fQ.a.b")
	f.Add("eyJhbGci!!!.a.b")
	f.Add(strings.Repeat("eyJ", 8) + "aad9.a.b")
	f.Add(strings.Repeat("eyJ", 8) + "!aad9.a.b")
	f.Add("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0.k.iv.ct.tag")
	f.Add("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0.encKEY123.iv12345.0123456789abcdef")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJhbGciOiJIUzI1NiJ9.0123456789abcdef.a.b")
	f.Add("eyMiYWxnIjoieCJ9.payload.0123456789abcdef")
	f.Add("eyJeyJeyJ..eyJ..")

	fuzzAgainstReference(f, JWT().Find, referenceJWTFind)
}

// referenceGitHubToken is the expression the scanner in builtin.go reads by
// hand: the statement of what a GitHub token is, kept here so that the scan can
// be held to it. Go matches an alternation leftmost-first rather than
// leftmost-longest, which is why the stateless installation token comes before
// the classic one it opens like.
var referenceGitHubToken = MustRegexp(
	"github-token",
	`ghs_[0-9A-Za-z]+_`+jwtHeaderPrefix+`[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+`+
		`|gh[pousr]_[0-9A-Za-z]{36,}`+
		`|`+githubPATPrefix+`[0-9A-Za-z_]{82,}`,
)

// FuzzGitHubToken_matchesReference guards the hand-written scan: the cursor it
// keeps over the JWT of a stateless installation token, the order it tries the
// alternatives in and the run it shares between them may none of them change
// which tokens are located.
func FuzzGitHubToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz")
	f.Add("TOKEN_ghp_0123456789abcdefghijklmnopqrstuvwxyz_suffix")
	f.Add("ghp_0123456789abcdefghijklmnopqrstuvwxy")  // one short of a classic token
	f.Add("ghq_0123456789abcdefghijklmnopqrstuvwxyz") // not a token kind
	f.Add("gh0123456789abcdefghijklmnopqrstuvwxyz")   // no kind and no underscore
	f.Add("github_pat_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789")
	f.Add("github_pat_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012345678") // one short
	f.Add("github_pat_github_pat_github_pat_github_pat_github_pat_github_pat_github_pat_github_pat_")     // the prefix inside the body
	f.Add("ghs_11223344_eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
	f.Add("ghs_0123456789abcdefghijklmnopqrstuvwxyz_eyJhbGciOiJIUzI1NiJ9.a.b") // an app id long enough to look classic
	f.Add("ghs_0123456789abcdefghijklmnopqrstuvwxyz_config.json.bak")          // dots after a classic token
	f.Add("ghs__ey1.a.b")                                                      // no app id
	f.Add("ghs_a_ey.a.b")                                                      // no character after ey
	f.Add("ghs_a_ey1..b")                                                      // an empty segment
	f.Add("ghs_a_ey1.a")                                                       // one segment short
	f.Add("ghs_a_eyghp_0123456789abcdefghijklmnopqrstuvwxyz")                  // a classic token inside the JWT run
	f.Add("gghs_a_ey1.a.b")
	f.Add(strings.Repeat("ghs_a_ey", 16)) // candidates crowded in one run
	f.Add(strings.Repeat("ghs_a_ey", 16) + ".a.b")

	fuzzAgainstReference(f, GitHubToken().Find, referenceGitHubToken.Find)
}
