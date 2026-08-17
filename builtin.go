package mask

import (
	"bytes"
	"encoding/base64"
	"slices"
	"strings"
)

// DefaultPatterns returns every built-in pattern:
//
//	m := mask.New(mask.WithPatterns(mask.DefaultPatterns()...))
//
// The set grows as patterns are added to this package. The returned slice is
// freshly allocated and may be modified by the caller.
func DefaultPatterns() []Pattern {
	return []Pattern{GitHubToken(), JWT()}
}

// GitHubToken locates GitHub credentials that carry a token prefix: personal
// access tokens (ghp_, github_pat_), OAuth app access tokens (gho_), GitHub App
// user and installation access tokens (ghu_, ghs_) and GitHub App refresh
// tokens (ghr_).
//
// GitHub documents the prefixes but no token length, and changed installation
// tokens in 2026 from 40 characters to a longer format holding a JWT. This
// pattern therefore keys on the prefix rather than on an exact length.
//
// Its name is "github-token".
func GitHubToken() Pattern { return githubToken }

// The prefix is what anchors these: a word boundary either side would drop the
// whole match, not merely trim it, where a token abuts a word character, and a
// token written as TOKEN_ghp_... would go unredacted. What may follow a token
// is held back by the character classes instead.
//
// Go matches an alternation leftmost-first rather than leftmost-longest, so the
// stateless installation token comes before the classic one it opens like.
// Written the other way round, an app id of thirty-six characters or more is
// taken for a whole classic token and the rest of the token is left to the JWT
// pattern, which leaves the underscore between them unredacted.
var githubToken = MustRegexp(
	"github-token",
	// The stateless installation token, which holds a JWT. The JWT is
	// anchored on the ey its header opens with, without which an underscore
	// and two dots written after a classic token, as in a file name, would be
	// drawn in by this alternative before the classic one is reached.
	`ghs_[0-9A-Za-z]+_`+jwtHeaderPrefix+`[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+`+
		// Classic tokens, forty characters in all.
		`|gh[pousr]_[0-9A-Za-z]{36,}`+
		// Fine grained personal access tokens.
		`|github_pat_[0-9A-Za-z_]{82,}`,
)

// JWT locates JSON Web Tokens in compact serialization: a base64url encoded
// header, followed by the two segments of a signed token or the four of an
// encrypted one, separated by dots.
//
// A header is read for the marks RFC 7515 and RFC 7516 require of one, namely a
// JSON object naming an algorithm in alg, and enc where the token is encrypted.
// Text that carries none of them is left alone.
//
// The header must open directly with a member name, as the compact JSON an
// encoder emits does. One written with space between the brace and the name is
// not located.
//
// Its name is "jwt".
func JWT() Pattern { return jsonWebToken }

// A JWT header is compact JSON, so its bytes open with {" and a member name,
// which base64url turns into ey and one further character.
const jwtHeaderPrefix = "ey"

// opensJOSEHeader reports whether c, the character following jwtHeaderPrefix,
// can be the third of an encoded {" and a member name.
//
// That character carries the two highest bits of the byte after the quote, so
// it is one of the four the base64url alphabet holds at indices 8 to 11. A
// name opening with a letter, as nearly every one does, gives J; one opening
// with a digit gives I, which the scan would pass over were it to look for eyJ
// alone.
func opensJOSEHeader(c byte) bool { return 'I' <= c && c <= 'L' }

var jsonWebToken = NewPattern("jwt", func(src string) []Span {
	var spans []Span

	// A header is a run of base64url characters, and every candidate crowded
	// inside one run reaches the same end and is followed by the same
	// segments. Working those out again at each candidate would cost time
	// quadratic in the length of src, so they are worked out once a run and
	// the cursor only ever moves forward.
	runEnd := -1
	var signed, encrypted segments

	// header does the same for the decode, which is the expensive part.
	var header headerDecoder

	for offset := 0; offset < len(src); {
		i := strings.Index(src[offset:], jwtHeaderPrefix)
		if i < 0 {
			break
		}
		start := offset + i

		// Only this starting point is ruled out by a failure below. A token
		// can still begin further along inside what was examined, so the scan
		// resumes just past the start rather than past the candidate.
		offset = start + 1

		third := start + len(jwtHeaderPrefix)
		if third >= len(src) || !opensJOSEHeader(src[third]) {
			continue
		}

		if start >= runEnd {
			runEnd = start
			for runEnd < len(src) && isBase64URLByte(src[runEnd]) {
				runEnd++
			}
			signed, encrypted = segments{}, segments{}
			if runEnd < len(src) && src[runEnd] == '.' {
				signed = segmentsEnd(src, runEnd, signedSegments)
				encrypted = segmentsEnd(src, runEnd, encryptedSegments)
			}
		}
		if !signed.ok {
			continue // a header is followed by the dot that ends it, and by segments
		}

		holdsEnc, ok := header.joseHeader(src, start, runEnd)
		if !ok {
			continue
		}

		// A header naming a content encryption algorithm belongs to an
		// encrypted token, but nothing stops a signed one from carrying that
		// name too, so a header without the segments of an encrypted token is
		// read as signed.
		end := signed.end
		if holdsEnc && encrypted.ok {
			end = encrypted.end
		}

		spans = append(spans, Span{Start: start, End: end})
		offset = end
	}
	return spans
})

// Segments following the header: two for a signed token, four for an encrypted
// one, which RFC 7516 gives five parts in all.
const (
	signedSegments    = 2
	encryptedSegments = 4
)

type segments struct {
	end int
	ok  bool
}

// segmentsEnd returns where the want segments beginning at dot end, and whether
// there are that many. Anything past them is left alone, so that the sentence a
// token sits in keeps its full stop.
func segmentsEnd(src string, dot, want int) segments {
	i := dot
	for range want {
		if i == len(src) || src[i] != '.' {
			return segments{}
		}
		for i++; i < len(src) && isBase64URLByte(src[i]); i++ {
		}
	}
	return segments{end: i, ok: true}
}

// joseHeader reports whether src[start:dot] is the header of a token, and
// whether that header names a content encryption algorithm.
//
// RFC 7515 and RFC 7516 both require the header to be a JSON object naming an
// algorithm in alg, and RFC 7516 requires enc of an encrypted one. Reading it
// for those marks rather than parsing it keeps the work spent on a candidate
// constant, which matters because a run of base64url characters can hold as
// many candidates as it has characters.
func (d *headerDecoder) joseHeader(src string, start, dot int) (encrypted, ok bool) {
	held, at, decoded := d.decode(src, start, dot)
	if held == nil {
		return false, false
	}
	// The prefix the scan looks for leaves the opening bytes no choice but {",
	// so what a candidate has yet to show is the length of an object naming a
	// member. referenceJWTFind reads those bytes rather than reason about
	// them, and the fuzz test holds the two to the same answer.
	if len(decoded) < len(`{"a":0}`) {
		return false, false
	}
	if !held.closed || held.alg < at {
		return false, false
	}
	return held.enc >= at, true
}

// headerDecoder decodes the header of a candidate token, remembering what it
// found for one dot so that the candidates crowded behind it do not each pay
// for a decode.
//
// Headers ending at the same dot that begin a whole number of base64 groups
// apart decode to suffixes of one another, three bytes to the group. There are
// four such alignments, so the decoding spent on any one dot is bounded however
// many candidates sit behind it. Only a run of base64url characters holds this
// relation, which is why the scan admits nothing else into a header.
type headerDecoder struct {
	dot        int
	alignments [4]headerDecode
}

type headerDecode struct {
	tried   bool   // whether this alignment has been decoded
	start   int    // where the header that was decoded begins
	decoded []byte // its bytes, or nil where the alignment cannot decode
	closed  bool   // whether those bytes end with the } of an object
	alg     int    // where alg is named last, or -1
	enc     int    // where enc is named last, or -1
}

// decode returns what is known about the alignment start falls in, together
// with the offset of start into the decoded bytes and those bytes from that
// offset on. It reports a nil headerDecode when the alignment cannot decode.
func (d *headerDecoder) decode(src string, start, dot int) (*headerDecode, int, []byte) {
	if d.dot != dot {
		*d = headerDecoder{dot: dot}
	}
	held := &d.alignments[(dot-start)%4]

	if !held.tried {
		*held = headerDecode{tried: true, start: start, alg: -1, enc: -1}
		decoded, err := base64.RawURLEncoding.DecodeString(src[start:dot])
		if err != nil {
			// Every header in this alignment is the same number of
			// characters past a multiple of four, so none of them decode.
			return nil, 0, nil
		}
		held.decoded = decoded
		held.closed = closesObject(decoded)
		held.alg = bytes.LastIndex(decoded, algName)
		held.enc = bytes.LastIndex(decoded, encName)
	}
	if held.decoded == nil {
		return nil, 0, nil
	}

	// Every start in this alignment sits a whole number of groups past the one
	// already decoded, three bytes to the group.
	at := (start - held.start) / 4 * 3
	return held, at, held.decoded[at:]
}

var (
	algName = []byte(`"alg"`)
	encName = []byte(`"enc"`)
)

// closesObject reports whether b ends with the } that closes a JSON object,
// which JSON allows to be followed by space.
func closesObject(b []byte) bool {
	for _, v := range slices.Backward(b) {
		switch v {
		case ' ', '\t', '\n', '\r':
		case '}':
			return true
		default:
			return false
		}
	}
	return false
}

func isBase64URLByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z' ||
		c == '-' || c == '_'
}
