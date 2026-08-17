package mask

import (
	"bytes"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"time"
)

// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real.

func Test_GitHubToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "classic personal access token",
			src:  "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			name: "oauth app access token",
			src:  "gho_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			name: "app user access token",
			src:  "ghu_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			name: "app installation access token",
			src:  "ghs_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			name: "app refresh token",
			src:  "ghr_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			name: "fine grained personal access token",
			src:  "github_pat_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789",
			want: []Span{{0, 93}},
		},
		{
			// The ghs_APPID_JWT form GitHub moved installation tokens to in
			// 2026.
			name: "stateless installation token",
			src:  "ghs_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: []Span{{0, 83}},
		},
		{
			// An app id of thirty-six characters or more opens like a whole
			// classic token, and the alternation must still prefer the
			// stateless form: matched the other way round, the underscore
			// after the app id is left behind.
			name: "stateless installation token with a long app id",
			src:  "ghs_0123456789abcdefghijklmnopqrstuvwxyz0123_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: []Span{{0, 117}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GitHubToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GitHubToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "ghp_",
		},
		{
			// Thirty-five characters where the pattern asks for thirty-six.
			name: "body one character too short",
			src:  "ghp_0123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			name: "unknown prefix letter",
			src:  "ghx_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "prefix without separator",
			src:  "ghp0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			// Eighty-one characters where the pattern asks for eighty-two.
			name: "fine grained body one character too short",
			src:  "github_pat_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012345678",
		},
		{
			name: "an identifier that starts like the prefix",
			src:  "github_pattern_for_matching",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GitHubToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_GitHubToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "GITHUB_TOKEN=****************************************",
		},
		{
			name: "quoted",
			src:  `"ghp_0123456789abcdefghijklmnopqrstuvwxyz"`,
			want: `"****************************************"`,
		},
		{
			name: "header",
			src:  "Authorization: token ghp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "Authorization: token ****************************************",
		},
		{
			name: "twice",
			src:  "ghp_0123456789abcdefghijklmnopqrstuvwxyz ghp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "**************************************** ****************************************",
		},
	}

	m := New(WithPatterns(GitHubToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GitHubToken_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the token through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "underscore after",
			src:  "ghp_0123456789abcdefghijklmnopqrstuvwxyz_x",
			want: "****************************************_x",
		},
		{
			name: "word character before",
			src:  "xghp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "x****************************************",
		},
		{
			name: "underscore before",
			src:  "TOKEN_ghp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "TOKEN_****************************************",
		},
		{
			name: "underscore before a fine grained token",
			src:  "X_github_pat_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789",
			want: "X_*********************************************************************************************",
		},
	}

	m := New(WithPatterns(GitHubToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GitHubToken_leavesWhatFollowsAlone(t *testing.T) {
	// Only the stateless installation token carries dots and dashes, so a
	// classic one must not draw in the host or word written after it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "host",
			src:  "host=ghp_0123456789abcdefghijklmnopqrstuvwxyz.example.com",
			want: "host=****************************************.example.com",
		},
		{
			name: "dashed word",
			src:  "ghp_0123456789abcdefghijklmnopqrstuvwxyz-suffix",
			want: "****************************************-suffix",
		},
		{
			name: "sentence",
			src:  "the token is ghp_0123456789abcdefghijklmnopqrstuvwxyz.",
			want: "the token is ****************************************.",
		},
		{
			// An underscore and two dots after a classic ghs_ token are the
			// shape of the stateless form, which is tried first. Only a JWT
			// may follow the underscore, so this file name does not join the
			// token.
			name: "file name after a classic installation token",
			src:  "ghs_0123456789abcdefghijklmnopqrstuvwxyz_backup.tar.gz",
			want: "****************************************_backup.tar.gz",
		},
	}

	m := New(WithPatterns(GitHubToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GitHubToken_statelessTokenLeavesNothingBehind(t *testing.T) {
	// Both built-in patterns fire on a stateless installation token, and the
	// app id, the underscore after it and the JWT must all go, however long
	// the app id is.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "short app id",
			src:  "ghs_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: "***********************************************************************************",
		},
		{
			name: "app id as long as a classic token",
			src:  "ghs_0123456789abcdefghijklmnopqrstuvwxyz0123_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: "*********************************************************************************************************************",
		},
	}

	m := New(WithPatterns(DefaultPatterns()...))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

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
			// The payload of this token is itself a header, so a scan that
			// resumed inside a located token would report a second, overlapping
			// one. The cursor moves to the end of the token instead, and the
			// two segments the token does not reach are left alone.
			name: "payload opens like a header",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJhbGciOiJIUzI1NiJ9.0123456789abcdef.a.b",
			want: []Span{{0, 58}},
		},
		{
			// The cursor must not carry past the token it ended, or the second
			// of two tokens written side by side goes unlocated.
			name: "two tokens side by side",
			src:  "eyJhbGciOiJIUzI1NiJ9.a.0123456789abcdef eyJhbGciOiJIUzI1NiJ9.c.0123456789abcdef",
			want: []Span{{0, 39}, {40, 79}},
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
			// The header decodes to { "alg":"HS256"}. A header is read as the
			// compact JSON an encoder emits, so one holding space before the
			// member name is not located.
			name: "space between the brace and the member name",
			src:  "eyAiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: nil,
		},
		{
			// The header decodes to {#"alg":"x"}, whose second byte is not the
			// quote a member name opens with. That byte puts M in the third
			// character, one past the four the scan admits, and everything
			// else about this candidate would pass.
			name: "third character one past the class",
			src:  "eyMiYWxnIjoieCJ9.payload.0123456789abcdef",
			want: nil,
		},
		{
			// The same the other way: {!\xc3"alg":"x"} puts H there, one short
			// of the four.
			name: "third character one short of the class",
			src:  "eyHDImFsZyI6IngifQ.payload.0123456789abcdef",
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
	// sits in; getting that wrong has cost time quadratic in the length of
	// the input more than once. The bound here is far above a linear scan
	// and far below a quadratic one.
	sources := map[string]string{
		"many rejected candidates":                strings.Repeat("eyJ..", 200000),
		"overlapping candidate starts":            strings.Repeat("eyJ", 200000) + "..",
		"overlapping starts of the other opening": strings.Repeat("eyI", 200000) + "..",
		"a run of the prefix alone":               strings.Repeat("ey", 300000) + "..",
		"dense starts with a near dot":            strings.Repeat(strings.Repeat("eyJ", 300)+".", 600),
		"one long run before a dot":               strings.Repeat("eyJ", 200000) + ".a.b",
		// A header that reads as JSON until its very end once cost a full
		// parse at every candidate behind it.
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

// What DefaultPatterns reports, and that each built-in reports the name and the
// value it is documented to, is held to in builtins_test.go, which drives every
// built-in from one table rather than a pair of tests apiece.

func Test_DefaultPatterns_freshEachCall(t *testing.T) {
	first := DefaultPatterns()
	first[0] = fixed("replaced")
	if second := DefaultPatterns(); second[0] == first[0] {
		t.Error("modifying the returned slice changed what a later call returns")
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
	// and it is admitted exactly when the bytes behind it can be the { and the
	// " a header opens with. Rather than repeat the reasoning that arrives at
	// I to L, the answer is taken from the decoder: ey, the character, and a
	// filler make one whole base64 group, and the bytes that group decodes to
	// say whether the character belongs.
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
		want := err == nil && len(decoded) >= 2 && decoded[0] == '{' && decoded[1] == '"'
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
	if got, want := string(admitted), "IJKL"; got != want {
		t.Errorf("opensJOSEHeader admits %q, want %q", got, want)
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
