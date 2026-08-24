package mask

import (
	"bytes"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"time"
)

// The JWT pattern: what it locates and what it leaves alone, written out case
// by case, the decoder its scan shares between candidates, and the reference
// that scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real.

func Test_JWT(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// {"alg":"HS256","typ":"JWT"}, then {"sub":"abc"}, then a
			// signature, each base64url without padding.
			name: "signed token",
			src:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: []Span{{0, 72}},
		},
		{
			name: "unsecured token has an empty signature",
			src:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.",
			want: []Span{{0, 56}},
		},
		{
			// The payload decodes to {"sub":"a-b_c"}.
			name: "base64url may hold - and _",
			src:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhLWJfYyJ9.ab-cd_ef",
			want: []Span{{0, 66}},
		},
		{
			name: "an empty segment is still a token",
			src:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..0123456789abcdef",
			want: []Span{{0, 54}},
		},
		{
			// The header decodes to {"alg":"dir","enc":"A128GCM"}. An
			// encrypted token carries five segments rather than three, and
			// none of them may survive.
			name: "encrypted token",
			src:  "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0.encKEY123.iv12345.ciphertextABC.authTAGxyz",
			want: []Span{{0, 82}},
		},
		{
			// The same header, but with the two segments of a signed token
			// behind it rather than the four of an encrypted one. Nothing
			// stops a signed token from naming a content encryption
			// algorithm, so this is read as signed and located whole.
			name: "encrypted header with the segments of a signed token",
			src:  "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0.encKEY123.0123456789abcdef",
			want: []Span{{0, 66}},
		},
		{
			// Three segments, where an encrypted token wants four. The count
			// falls back to the two of a signed token, so the third segment is
			// left alone rather than the whole run being drawn in.
			name: "encrypted header one segment short of an encrypted token",
			src:  "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0.encKEY123.iv12345.0123456789abcdef",
			want: []Span{{0, 57}},
		},
		{
			// The header decodes to {"0":1,"alg":"HS256"}. A member name
			// opening with a digit puts I where a letter would put J, and the
			// scan has to admit both.
			name: "member name opening with a digit",
			src:  "eyIwIjoxLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: []Span{{0, 64}},
		},
		{
			// The header decodes to {"\u00e9":1,"alg":"HS256"}, written in
			// UTF-8. A name opening past ASCII puts L there.
			name: "member name opening past ascii",
			src:  "eyLDqSI6MSwiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: []Span{{0, 66}},
		},
		{
			// The header decodes to {"alg":"HS256"} followed by a space, which
			// JSON allows after the object.
			name: "header ends in space",
			src:  "eyJhbGciOiJIUzI1NiJ9IA.payload.signature",
			want: []Span{{0, 40}},
		},
		{
			// The payload of this token is itself a header, and the segments
			// behind it are a token of its own, so the scan reports that one
			// too and the spans overlap. It is the price of coming back for
			// every start inside a match, which is what locates the case
			// below, and nothing in the bytes tells the two apart. A Masker
			// resolves the overlap into one value.
			name: "payload opens like a header",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJhbGciOiJIUzI1NiJ9.0123456789abcdef.a.b",
			want: []Span{{0, 58}, {21, 60}},
		},
		{
			// The cursor must not carry past the token it ended, or the second
			// of two tokens written side by side goes unlocated.
			name: "two tokens side by side",
			src:  "eyJhbGciOiJIUzI1NiJ9.a.0123456789abcdef eyJhbGciOiJIUzI1NiJ9.c.0123456789abcdef",
			want: []Span{{0, 39}, {40, 79}},
		},
		{
			// The same two with nothing between them. A signature is a run of
			// base64url characters, so it swallows the header of the token
			// written after it and that token begins inside the first match:
			// a scan resuming past a match would step over it and leave a
			// whole token in the output.
			name: "two tokens with nothing between them",
			src:  "eyJhbGciOiJIUzI1NiJ9.a.0123456789abcdefeyJhbGciOiJIUzI1NiJ9.c.0123456789abcdef",
			want: []Span{{0, 59}, {39, 78}},
		},
		{
			// eyJh decodes to {"a, which is shorter than the smallest object
			// naming a member.
			name: "header is too short to be an object",
			src:  "eyJh.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: nil,
		},
		{
			// Nine base64url characters are not a whole number of groups, so
			// the header does not decode at all.
			name: "header is not a base64url length",
			src:  "eyJhbGciO.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: nil,
		},
		{
			// {"ab":} opens and closes an object but names no algorithm.
			name: "header names no algorithm",
			src:  "eyJhYiI6fQ.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: nil,
		},
		{
			// The header decodes to {"alg":"HS256", which never closes.
			name: "header does not close the object",
			src:  "eyJhbGciOiJIUzI1NiI.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: nil,
		},
		{
			// The run of base64url characters stops at the first !, so what
			// follows it is not the dot that ends a header.
			name: "header ends in characters base64url has no place for",
			src:  "eyJhbGci!!!.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: nil,
		},
		{
			name: "header holds characters base64url has no place for",
			src:  "eyJ!!!!!fQ.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: nil,
		},
		{
			// The header decodes to { "alg":"HS256"}, the space JSON allows
			// between the brace and the member name. It puts A in the third
			// character rather than J.
			name: "space between the brace and the member name",
			src:  "eyAiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: []Span{{0, 58}},
		},
		{
			// The whitespace JSON allows there beside the space is not the
			// scan's to admit or decline: {\t"alg":"HS256"} opens with ew, so
			// the prefix the scan searches for is not in the text and no
			// candidate begins here at all.
			name: "tab between the brace and the member name",
			src:  "ewkiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: nil,
		},
		{
			// {\r"alg":"HS256"}, which opens with ew for the same reason. The
			// newline is stated by the conformance corpus.
			name: "carriage return between the brace and the member name",
			src:  "ew0iYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: nil,
		},
		{
			// The header decodes to {#"alg":"x"}, whose second byte is neither
			// the quote a member name opens with nor the space before one.
			// That byte puts M in the third character, one past the four the
			// quote leaves, and everything else about this candidate would
			// pass.
			name: "third character one past the class the quote leaves",
			src:  "eyMiYWxnIjoieCJ9.payload.0123456789abcdef",
			want: nil,
		},
		{
			// The same the other way: {!\xc3"alg":"x"} puts H there, one short
			// of those four.
			name: "third character one short of the class the quote leaves",
			src:  "eyHDImFsZyI6IngifQ.payload.0123456789abcdef",
			want: nil,
		},
		{
			// The class the space leaves is bounded above the same way, by
			// the same byte: {!"alg":"x"} puts E in the third character, one
			// past D. Below A there is nothing to write, A being the first
			// character of the alphabet.
			name: "third character one past the class the space leaves",
			src:  "eyEiYWxnIjoieCJ9.payload.0123456789abcdef",
			want: nil,
		},
		{
			// ey is not a header on its own, whatever follows it.
			name: "the prefix without a third character",
			src:  "ey",
			want: nil,
		},
		{
			name: "only two segments",
			src:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ",
			want: nil,
		},
		{
			name: "does not start with the header marker",
			src:  "abcdefgh.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := JWT().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_JWT_afterRejectedCandidate(t *testing.T) {
	// A candidate whose header is not JSON must not consume what it covered: a
	// real token can begin inside it. Both tokens below start at offset 8.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "rejected candidates before the token",
			src:  "eyJ.eyJ.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: []Span{{8, 80}},
		},
		{
			name: "a rejected candidate with segments of its own",
			src:  "eyJx.a.beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: []Span{{8, 80}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := JWT().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_JWT_inContext(t *testing.T) {
	m := New(WithPatterns(JWT()))
	src := "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef"
	want := "Authorization: Bearer ************************************************************************"
	if got := m.Mask(src); got != want {
		t.Errorf("Mask(%q) = %q, want %q", src, got, want)
	}
}

func Test_JWT_leavesWhatFollowsAlone(t *testing.T) {
	// The segments a token has are counted, so neither the full stop of the
	// sentence it sits in nor a file extension is drawn into it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "see eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef. Next one.",
			want: "see ************************************************************************. Next one.",
		},
		{
			name: "file extension",
			src:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef.json",
			want: "************************************************************************.json",
		},
	}

	m := New(WithPatterns(JWT()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

// jwtHeaderOf returns a base64url encoded header of n bytes of JSON, padded out
// in x5c the way a header carrying a certificate chain is:
//
//	{"alg":"RS256","x5c":["aaa...aaa"]}
func jwtHeaderOf(n int) string {
	const open, shut = `{"alg":"RS256","x5c":["`, `"]}`
	json := open + strings.Repeat("a", n-len(open)-len(shut)) + shut
	return base64.RawURLEncoding.EncodeToString([]byte(json))
}

func Test_JWT_longHeader(t *testing.T) {
	// A header carrying a certificate chain in x5c runs to several thousand
	// characters. Length must not be what decides whether a token is located.
	for _, bytes := range []int{768, 6144, 65536} {
		header := jwtHeaderOf(bytes)
		src := header + ".payload.signature"
		want := []Span{{0, len(src)}}
		if got := JWT().Find(src); !slices.Equal(got, want) {
			t.Errorf("Find(header of %d bytes of JSON + %q) = %v, want %v", bytes, ".payload.signature", got, want)
		}
	}
}

// nestedHeader returns a header whose decode reads as JSON far into its length:
//
//	{"a":{"a":{"a":...0
//
// closing wraps it so that it ends with a brace and names an algorithm, giving
//
//	{"alg":"x",{"a":{"a":...0}
//
// which nothing short of parsing it can tell is not a header.
func nestedHeader(depth int, closing bool) string {
	json := strings.Repeat(`{"a":`, depth) + "0"
	if closing {
		json = `{"alg":"x",` + json + "}"
	}
	return base64.RawURLEncoding.EncodeToString([]byte(json))
}

func Test_JWT_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a run dense in header
	// prefixes holds as many candidates as it has characters. Everything a
	// candidate needs beyond a constant is worked out once for the run it
	// sits in; getting that wrong costs time quadratic in the length of
	// the input. The bound here is far above a linear scan and far below a
	// quadratic one.
	sources := map[string]string{
		"many rejected candidates":                strings.Repeat("eyJ..", 200000),
		"overlapping candidate starts":            strings.Repeat("eyJ", 200000) + "..",
		"overlapping starts of the other opening": strings.Repeat("eyI", 200000) + "..",
		"a run of the prefix alone":               strings.Repeat("ey", 300000) + "..",
		"dense starts with a near dot":            strings.Repeat(strings.Repeat("eyJ", 300)+".", 600),
		"one long run before a dot":               strings.Repeat("eyJ", 200000) + ".a.b",
		// A header that reads as JSON until its very end is what costs a
		// full parse at every candidate behind it.
		"header that parses to the end":     nestedHeader(60000, false) + ".a.b",
		"header that also passes the marks": nestedHeader(60000, true) + ".a.b",
		// aad9 makes the last base64 group of every header decode to a byte
		// that closes a JSON object, which defeats a check on that alone.
		"crafted headers that look closed": strings.Repeat("eyJ", 200000) + "aad9.a.b",
	}

	m := New(WithPatterns(JWT()))
	for name, src := range sources {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_ = m.Mask(src)
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("Mask() of %d bytes took %v", len(src), d)
			}
		})
	}
}

func Test_headerDecoder_decode(t *testing.T) {
	// The decoder hands the candidates crowded behind one dot a single decode
	// to share, and tells each of them where its own header begins in it. No
	// input reaches Find that can tell a mistake here apart from the checks
	// that follow it, so the sharing is put to the test on its own.
	const json = `{"alg":"HS256","enc":"A128GCM","x":"y"}`
	header := base64.RawURLEncoding.EncodeToString([]byte(json))
	src := header + ".payload.signature"
	dot := len(header)

	steps := []struct {
		name      string
		start     int
		dot       int
		decodes   bool // whether the alignment start falls in can decode
		at        int  // where start begins in the decode the alignment holds
		heldStart int  // the candidate that decode was made for
	}{
		{
			name:  "the first candidate of an alignment decodes its own header",
			start: 0, dot: dot, decodes: true, at: 0, heldStart: 0,
		},
		{
			// Four characters on is three bytes on, and the two headers end
			// together, so the second is a suffix of the first.
			name:  "the next candidate of that alignment shares the decode",
			start: 4, dot: dot, decodes: true, at: 3, heldStart: 0,
		},
		{
			name:  "and the one behind it",
			start: 8, dot: dot, decodes: true, at: 6, heldStart: 0,
		},
		{
			// A candidate a character along ends the same number of
			// characters past a multiple of four as no other seen so far, so
			// it decodes for itself.
			name:  "another alignment decodes separately",
			start: 1, dot: dot, decodes: true, at: 0, heldStart: 1,
		},
		{
			name:  "an alignment that is no whole number of groups long cannot decode",
			start: 3, dot: dot, decodes: false,
		},
		{
			name:  "nor can a candidate behind it",
			start: 7, dot: dot, decodes: false,
		},
		{
			// The decoder holds one dot at a time; reaching another throws
			// away everything worked out for the last.
			name:  "a further dot starts the decoder over",
			start: 0, dot: dot - 4, decodes: true, at: 0, heldStart: 0,
		},
	}

	// What the decoder carries from one call to the next is the thing under
	// test, so the steps are one walk rather than a subtest apiece: a step run
	// on its own would meet a decoder that had never seen the steps before it,
	// and fail for want of them. Each failure names the step it came from.
	var d headerDecoder
	for _, s := range steps {
		held, at, decoded := d.decode(src, s.start, s.dot)
		if !s.decodes {
			if held != nil {
				t.Errorf("%s: decode(%d, %d) = %v, want no decode", s.name, s.start, s.dot, held)
			}
			if at != 0 || decoded != nil {
				t.Errorf("%s: decode(%d, %d) = _, %d, %v, want 0 and no bytes", s.name, s.start, s.dot, at, decoded)
			}
			continue
		}
		if held == nil {
			t.Errorf("%s: decode(%d, %d) reported no decode, want one", s.name, s.start, s.dot)
			continue
		}
		if at != s.at {
			t.Errorf("%s: decode(%d, %d) put the header at %d, want %d", s.name, s.start, s.dot, at, s.at)
		}
		if held.start != s.heldStart {
			t.Errorf("%s: decode(%d, %d) holds the decode of %d, want %d", s.name, s.start, s.dot, held.start, s.heldStart)
		}
		if !bytes.Equal(decoded, held.decoded[at:]) {
			t.Errorf("%s: decode(%d, %d) = %q, want the held bytes from %d, %q", s.name, s.start, s.dot, decoded, at, held.decoded[at:])
		}

		// What the sharing must come to: the bytes a candidate is handed are
		// the ones it would get were its header decoded alone.
		want, err := base64.RawURLEncoding.DecodeString(src[s.start:s.dot])
		if err != nil {
			t.Errorf("%s: the header at %d does not decode on its own: %v", s.name, s.start, err)
			continue
		}
		if !bytes.Equal(decoded, want) {
			t.Errorf("%s: decode(%d, %d) = %q, want %q", s.name, s.start, s.dot, decoded, want)
		}
	}
}

func Test_headerDecoder_decode_recordsWhatTheHeaderNames(t *testing.T) {
	tests := []struct {
		name   string
		json   string
		closed bool
		alg    int
		enc    int
	}{
		{
			name: "an algorithm and a content encryption algorithm",
			json: `{"alg":"dir","enc":"A128GCM"}`, closed: true, alg: 1, enc: 13,
		},
		{
			name: "an algorithm alone",
			json: `{"alg":"HS256"}`, closed: true, alg: 1, enc: -1,
		},
		{
			// Only the last of a name counts, so that a candidate beginning
			// past an earlier one is not credited with it.
			name: "an algorithm named twice",
			json: `{"alg":"HS256","alg":"none"}`, closed: true, alg: 15, enc: -1,
		},
		{
			name: "neither",
			json: `{"typ":"JWT"}`, closed: true, alg: -1, enc: -1,
		},
		{
			name: "an object that never closes",
			json: `{"alg":"HS256"`, closed: false, alg: 1, enc: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := base64.RawURLEncoding.EncodeToString([]byte(tt.json))
			var d headerDecoder
			held, _, _ := d.decode(header+".a.b", 0, len(header))
			if held == nil {
				t.Fatalf("decode(%q) reported no decode", tt.json)
			}
			if held.closed != tt.closed {
				t.Errorf("closed = %v, want %v", held.closed, tt.closed)
			}
			if held.alg != tt.alg {
				t.Errorf("alg = %d, want %d", held.alg, tt.alg)
			}
			if held.enc != tt.enc {
				t.Errorf("enc = %d, want %d", held.enc, tt.enc)
			}
		})
	}
}

func Test_opensJOSEHeader(t *testing.T) {
	// The character opensJOSEHeader reads is the third of an encoded header,
	// and it is admitted exactly when the bytes behind it can be the { a
	// header opens with and either byte JSON allows after one: the quote of a
	// member name, or the space before it. Rather than repeat the reasoning
	// that arrives at A to D and I to L, the answer is taken from the decoder:
	// ey, the character, and a filler make one whole base64 group, and the
	// bytes that group decodes to say whether the character belongs.
	//
	// Every byte is put to it, so that a class grown or shrunk by one is
	// caught either side.
	for c := range 256 {
		// The byte goes in as itself. string(rune(c)) would encode the bytes
		// past ASCII as the two UTF-8 stands for, leaving the group five
		// characters long and undecodable whatever the byte, so that half the
		// range would be answered no for a reason of the test's own making.
		group := jwtHeaderPrefix + string([]byte{byte(c)}) + "A"
		decoded, err := base64.RawURLEncoding.DecodeString(group)
		// The decoder skips carriage return and newline rather than
		// refusing them, so those two bytes decode as though they were not
		// there and the group behind them answers for a character neither
		// of them is. Encoding the bytes again is what catches it: a group
		// of four characters comes back as itself, and one that was three
		// characters and a skipped byte does not.
		want := err == nil && len(decoded) >= 2 &&
			base64.RawURLEncoding.EncodeToString(decoded) == group &&
			decoded[0] == '{' && (decoded[1] == '"' || decoded[1] == ' ')
		if got := opensJOSEHeader(byte(c)); got != want {
			t.Errorf("opensJOSEHeader(%q) = %v, want %v", byte(c), got, want)
		}
	}

	// The loop above passes were both sides wrong together, so the class it
	// agrees on is written out as well.
	var admitted []byte
	for c := range 256 {
		if opensJOSEHeader(byte(c)) {
			admitted = append(admitted, byte(c))
		}
	}
	if got, want := string(admitted), "ABCDIJKL"; got != want {
		t.Errorf("opensJOSEHeader admits %q, want %q", got, want)
	}
}

func Test_opensJOSEHeaderAt(t *testing.T) {
	// The predicate both scans read. What it adds to opensJOSEHeader is the
	// arithmetic that reaches the third character, so what is written out here
	// is where that character falls: at the end of the text, one past it, and
	// inside text that carries no header at all.
	tests := []struct {
		name string
		src  string
		i    int
		want bool
	}{
		{name: "a header at the start", src: "eyJhbGciOiJIUzI1NiJ9", i: 0, want: true},
		{name: "a header further along", src: "ghs_1_eyJhbGciOiJIUzI1NiJ9", i: 6, want: true},
		{name: "the third character alone", src: "eyJ", i: 0, want: true},
		{name: "the lowest third character a quote leaves", src: "eyI", i: 0, want: true},
		{name: "the highest a quote leaves", src: "eyL", i: 0, want: true},
		{name: "one below the four a quote leaves", src: "eyH", i: 0, want: false},
		{name: "one above them", src: "eyM", i: 0, want: false},
		{name: "the lowest third character a space leaves", src: "eyA", i: 0, want: true},
		{name: "the highest a space leaves", src: "eyD", i: 0, want: true},
		{name: "one above the four a space leaves", src: "eyE", i: 0, want: false},
		{name: "a file name opening with the prefix", src: "eyes.tar.gz", i: 0, want: false},
		{name: "the prefix with no third character", src: "ey", i: 0, want: false},
		{name: "the prefix at the very end", src: "ghs_1_ey", i: 6, want: false},
		{name: "one character of the prefix", src: "e", i: 0, want: false},
		{name: "the end of the text", src: "eyJ", i: 3, want: false},
		{name: "text holding no prefix", src: "ghp_0123", i: 0, want: false},
		{name: "the prefix in capitals", src: "EYJhbGci", i: 0, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := opensJOSEHeaderAt(tt.src, tt.i); got != tt.want {
				t.Errorf("opensJOSEHeaderAt(%q, %d) = %v, want %v", tt.src, tt.i, got, tt.want)
			}
		})
	}
}

func Test_closesObject(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "object", in: `{"alg":"none"}`, want: true},
		{name: "object then space", in: `{"alg":"none"} `, want: true},
		{name: "object then the other spaces", in: "{}\t\n\r", want: true},
		{name: "no closing brace", in: `{"alg":"none"`, want: false},
		{name: "value after the brace", in: `{} x`, want: false},
		{name: "nothing", in: "", want: false},
		{name: "only space", in: "  \t\n", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := closesObject([]byte(tt.in)); got != tt.want {
				t.Errorf("closesObject(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// referenceJWTFind locates tokens the plain way: every header prefix in turn,
// decoded and read in full, with no cursor and nothing remembered between
// candidates. Every one of them is a starting point in its own right, a match
// included, because a signature run swallows the header of a token written
// straight after it and the second token then begins inside the first match.
// The scanner in builtin_jwt.go must agree with it on every input.
//
// The prefix, the alphabet, the two segment counts, the member names and what
// closes an object are spelled out here and in the three helpers below rather
// than read from builtin_jwt.go and builtin_scan.go. A reference reading those
// moves with whatever the scan is changed to, and FuzzJWT_matchesReference
// would then be holding the scan against itself rather than against a second
// statement of the rule.
func referenceJWTFind(src string) []Span {
	var spans []Span
	for offset := 0; offset < len(src); {
		i := strings.Index(src[offset:], "ey")
		if i < 0 {
			break
		}
		start := offset + i
		offset = start + 1

		dot := start
		for dot < len(src) && referenceJWTBase64URLByte(src[dot]) {
			dot++
		}
		if dot == len(src) || src[dot] != '.' {
			continue
		}

		decoded, err := base64.RawURLEncoding.DecodeString(src[start:dot])
		if err != nil {
			continue
		}
		if len(decoded) < len(`{"a":0}`) || decoded[0] != '{' || decoded[1] != '"' && decoded[1] != ' ' {
			continue
		}
		if !referenceJWTClosesObject(decoded) || !bytes.Contains(decoded, []byte(`"alg"`)) {
			continue
		}

		end, ok := referenceJWTSegmentsEnd(src, dot, 2)
		if !ok {
			continue
		}
		if encrypted, ok := referenceJWTSegmentsEnd(src, dot, 4); ok && bytes.Contains(decoded, []byte(`"enc"`)) {
			end = encrypted
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return spans
}

// referenceJWTBase64URLByte reports whether c belongs to the base64url alphabet
// of RFC 4648. Padding is not admitted: the compact serialization is defined
// without it.
func referenceJWTBase64URLByte(c byte) bool {
	return c >= '0' && c <= '9' ||
		c >= 'A' && c <= 'Z' ||
		c >= 'a' && c <= 'z' ||
		c == '-' || c == '_'
}

// referenceJWTSegmentsEnd returns where the want segments beginning at dot end,
// and whether there are that many. Anything past them is left alone, so that
// the sentence a token sits in keeps its full stop.
func referenceJWTSegmentsEnd(src string, dot, want int) (int, bool) {
	i := dot
	for range want {
		if i == len(src) || src[i] != '.' {
			return 0, false
		}
		for i++; i < len(src) && referenceJWTBase64URLByte(src[i]); {
			i++
		}
	}
	return i, true
}

// referenceJWTClosesObject reports whether b ends with the } that closes a JSON
// object, which JSON allows to be followed by space.
func referenceJWTClosesObject(b []byte) bool {
	for i := len(b) - 1; i >= 0; i-- {
		switch b[i] {
		case ' ', '\t', '\n', '\r':
		case '}':
			return true
		default:
			return false
		}
	}
	return false
}

// FuzzJWT_matchesReference guards the cursor, the cheap checks, the decode the
// scanner remembers between candidates and the byte it resumes at: none of
// them may change which tokens are located.
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
	f.Add("eyAiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
	f.Add("ewkiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
	f.Add("ew0iYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
	f.Add("eyEiYWxnIjoieCJ9.payload.0123456789abcdef")
	f.Add("eyJeyJeyJ..eyJ..")
	// A token beginning inside the match before it, which a scan resuming past
	// a match steps over. The payload that is a header in its own right, which
	// is what such a scan is bought with, is already seeded above.
	f.Add("eyJhbGciOiJIUzI1NiJ9.a.0123456789abcdefeyJhbGciOiJIUzI1NiJ9.c.0123456789abcdef")

	fuzzAgainstReference(f, JWT().Find, referenceJWTFind)
}

// jwtFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under
// a plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func jwtFindBenchmarks() []benchmarkCase {
	// The two letters a header opens with are two an English word opens with
	// as well, so the line carries the words that reach the anchor and are
	// turned away by the character behind them.
	line := `time=2026-08-17T00:00:00Z level=info msg="the survey key was eyed" `
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every three characters, all of them in one run, and
			// no dot anywhere: each reads the run cursor and stops at the
			// segments that are not there. This is the run walked once that
			// the cursor is for, without the decode behind it.
			name:  "candidates crowded in one run",
			src:   strings.Repeat("eyJ", 128),
			spans: 0,
		},
		{
			// The same run with the segments a token carries written after it,
			// which is what takes every one of those candidates as far as the
			// decode. Headers ending at one dot decode to suffixes of one
			// another four alignments over, so the decoding is bounded however
			// many candidates stand behind the dot — and this is the input
			// that would show the bound gone.
			name:  "candidates crowded in one run followed by segments",
			src:   strings.Repeat("eyJ", 128) + ".a.b",
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "authorization=Bearer " + token,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "authorization=Bearer " + token,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"authorization=Bearer "+token+"\n", 32),
			spans: 32,
		},
	}
}
