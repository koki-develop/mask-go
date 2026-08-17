package mask

import (
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

func Test_GitHubToken_name(t *testing.T) {
	if got := GitHubToken().Name(); got != "github-token" {
		t.Errorf("Name() = %q, want %q", got, "github-token")
	}
}

func Test_GitHubToken_sameValueEachCall(t *testing.T) {
	// Match carries the Pattern itself, so a caller comparing one against a
	// built-in must get the same value every call.
	if GitHubToken() != GitHubToken() {
		t.Error("GitHubToken() returned a different value on a second call")
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

func Test_JWT_name(t *testing.T) {
	if got := JWT().Name(); got != "jwt" {
		t.Errorf("Name() = %q, want %q", got, "jwt")
	}
}

func Test_JWT_sameValueEachCall(t *testing.T) {
	// Match carries the Pattern itself, so a caller comparing one against a
	// built-in must get the same value every call.
	if JWT() != JWT() {
		t.Error("JWT() returned a different value on a second call")
	}
}

func Test_DefaultPatterns(t *testing.T) {
	got := DefaultPatterns()
	want := []Pattern{GitHubToken(), JWT()}
	if len(got) != len(want) {
		t.Fatalf("DefaultPatterns() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("DefaultPatterns()[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func Test_DefaultPatterns_freshEachCall(t *testing.T) {
	first := DefaultPatterns()
	first[0] = fixed("replaced")
	if second := DefaultPatterns(); second[0] == first[0] {
		t.Error("modifying the returned slice changed what a later call returns")
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
