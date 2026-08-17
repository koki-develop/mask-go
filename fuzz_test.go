package mask

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

// FuzzLocate checks the guarantees Mask relies on: the values it walks are
// ordered, never overlap, and between them still cover every span a pattern
// reported.
func FuzzMasker_locate(f *testing.F) {
	f.Add("abcdef", []byte{0, 2, 4, 6})
	f.Add("abcdef", []byte{0, 4, 2, 6})
	f.Add("abcdef", []byte{0, 6, 2, 4})
	f.Add("", []byte{0, 1})
	f.Add("日本語abc", []byte{0, 9, 3, 12})

	f.Fuzz(func(t *testing.T, src string, raw []byte) {
		var reported []Span
		for len(raw) >= 4 {
			s := Span{Start: int(int16(binary.BigEndian.Uint16(raw))), End: int(int16(binary.BigEndian.Uint16(raw[2:])))}
			reported = append(reported, s)
			raw = raw[4:]
		}

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
	f.Add("eyIwIjoxLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
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
	f.Add("eyJeyJeyJ..eyJ..")

	f.Fuzz(func(t *testing.T, src string) {
		got, want := JWT().Find(src), referenceJWTFind(src)
		if len(got) == 0 && len(want) == 0 {
			return
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Find(%q) = %v, reference gives %v", src, got, want)
		}
	})
}
