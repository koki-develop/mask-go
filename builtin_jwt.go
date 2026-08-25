package mask

import (
	"bytes"
	"encoding/base64"
	"slices"
	"strings"
)

// JWT locates JSON Web Tokens in compact serialization: a base64url encoded
// header, followed by the two segments of a signed token or the four of an
// encrypted one, separated by dots.
//
// A header is read for the marks RFC 7515 and RFC 7516 require of one, namely a
// JSON object naming an algorithm in alg, and enc where the token is encrypted.
// Text that carries none of them is left alone.
//
// The header may be written with a space between the brace and the first
// member name, which JSON allows though the compact JSON an encoder emits
// carries none. One written with a tab, a carriage return or a newline there
// is not located.
//
// Its name is "jwt".
func JWT() Pattern { return jsonWebToken }

// A JWT header is a JSON object, so its bytes open with a brace and the quote
// a member name opens with, which base64url turns into ey and one further
// character. A space between the two, which JSON allows, leaves the ey where
// it is and changes only that character.
const jwtHeaderPrefix = "ey"

// jwtHeaderAnchor is the byte the scan searches the input for and
// jwtHeaderAnchorIndex is where it stands in jwtHeaderPrefix, so a candidate
// begins that many bytes in front of what a search reported. builtin_scan.go
// says why a scan searches for one byte of its prefix rather than for the
// prefix itself; what makes it this byte is that the e is the commonest letter
// in English and the y among the rarest. Over the log line these benchmarks
// are written on the e stands eight times and the y three, and a run of
// base64url characters carries the two about equally often, so nothing is
// given up on the input a token is crowded into.
//
// The GitHub scan reads jwtHeaderPrefix from here but not this: it finds its
// candidates by what opens a token of its own, and reaches a header only once
// a prefix and a body already stand in front of it.
const (
	jwtHeaderAnchor      = 'y'
	jwtHeaderAnchorIndex = 1
)

// opensJOSEHeader reports whether c, the character following jwtHeaderPrefix,
// can be the third of an encoded brace and the opening of a member name.
//
// That character carries the low four bits of the byte behind the brace and
// the two highest of the byte behind that, so each byte the prefix leaves
// standing behind the brace takes four characters of its own. The prefix
// leaves sixteen, the bytes 0x20 to 0x2f, and JSON allows two of them after a
// brace: the quote a member name opens with, at indices 8 to 11, and the space
// before one, at 0 to 3. Both are admitted, which is every byte that can
// follow the brace of a header opening with ey.
//
// The four the quote leaves are told apart by the name behind it. One opening
// with a letter, as nearly every name does, gives J; one opening with a digit
// gives I, which the scan would pass over were it to look for eyJ alone.
//
// What is left over is the whitespace the prefix itself rules out. The three
// bytes JSON allows there beside the space — a tab, a carriage return and a
// newline — each put w in the second character rather than y, so a header
// written with one is not located at all, whatever this reports. The
// conformance corpus states that.
func opensJOSEHeader(c byte) bool { return 'A' <= c && c <= 'D' || 'I' <= c && c <= 'L' }

// opensJOSEHeaderAt reports whether the base64url of a JOSE header begins at i
// in src: the ey it opens with, and a third character that can carry the brace
// and the opening of a member name behind it.
//
// This is the whole of what anchors a header without decoding one, and it is
// the strongest such anchor there is: the two characters say the first byte is
// {, and the third says the byte after it is the quote a member name opens
// with or the space JSON allows before one. Nothing further follows from the
// bytes alone.
//
// Both scans read it. A stateless installation token carries a JWT, so what
// anchors one there is what anchors one here, and a scan spelling the anchor
// again is a scan that can come to disagree with this one about what opens a
// header. The disagreement that costs the most is dropping the third
// character: ey alone says only that a run begins with two letters, which any
// word beginning ey satisfies, so a scan asking for that draws a file name
// written after an app id into a token wherever the name opens with them.
func opensJOSEHeaderAt(src string, i int) bool {
	if !strings.HasPrefix(src[i:], jwtHeaderPrefix) {
		return false
	}
	third := i + len(jwtHeaderPrefix)
	return third < len(src) && opensJOSEHeader(src[third])
}

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
		i := strings.IndexByte(src[offset:], jwtHeaderAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate becomes a token or
		// not: only the starting point is settled by what follows, never the
		// stretch of text it reaches over, and a token can begin anywhere
		// inside that stretch. Consuming a match would step over such a
		// token and leave it in the output whole — the signature of a signed
		// token is a run of base64url characters, so a second token written
		// straight after the first has its header swallowed by that run and
		// begins inside the match. The two spans then overlap, which a Masker
		// resolves into one. Stepping one byte past the anchor is
		// what leaves the next candidate one byte past this one, which
		// builtin_scan.go sets out.
		offset = anchor + 1

		if anchor < jwtHeaderAnchorIndex {
			continue
		}
		start := anchor - jwtHeaderAnchorIndex
		if !opensJOSEHeaderAt(src, start) {
			continue
		}

		if start >= runEnd {
			runEnd = base64URLRunEnd(src, start)
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
	}
	return spans
})

// Segments following the header: two for a signed token, four for an encrypted
// one, which RFC 7516 gives five parts in all.
const (
	signedSegments    = 2
	encryptedSegments = 4
)

// segmentsEnd returns where the want segments beginning at dot end, and whether
// there are that many. Anything past them is left alone, so that the sentence a
// token sits in keeps its full stop.
func segmentsEnd(src string, dot, want int) segments {
	i := dot
	for range want {
		if i == len(src) || src[i] != '.' {
			return segments{}
		}
		i = base64URLRunEnd(src, i+1)
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
	// The prefix the scan looks for leaves the opening bytes no choice but a
	// brace and the quote of a member name, or a space in the quote's place,
	// so what a candidate has yet to show is the length of an object naming a
	// member — the shorter of the two openings, since this only rules out what
	// is too short to be one at all. referenceJWTFind reads those bytes rather
	// than reason about them, and the fuzz test holds the two to the same
	// answer.
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
