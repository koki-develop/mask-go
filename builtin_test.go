package mask

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// Bodies made only of ordered characters: valid in shape, obviously not real.
const (
	alnum36 = "0123456789abcdefghijklmnopqrstuvwxyz"
	jwtBody = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef"
)

func legacyToken(prefix string) string { return prefix + alnum36 }

func fineGrainedToken() string { return "github_pat_" + strings.Repeat(alnum36, 3)[:82] }

// statelessToken builds the ghs_APPID_JWT form GitHub moved installation
// tokens to in 2026.
func statelessToken() string { return "ghs_123456_" + jwtBody }

func Test_GitHubToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{name: "classic personal access token", src: legacyToken("ghp_")},
		{name: "oauth app access token", src: legacyToken("gho_")},
		{name: "app user access token", src: legacyToken("ghu_")},
		{name: "app installation access token", src: legacyToken("ghs_")},
		{name: "app refresh token", src: legacyToken("ghr_")},
		{name: "fine grained personal access token", src: fineGrainedToken()},
		{name: "stateless installation token", src: statelessToken()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GitHubToken().Find(tt.src); len(got) != 1 || got[0] != (Span{0, len(tt.src)}) {
				t.Errorf("Find(%q) = %v, want one span covering the whole token", tt.src, got)
			}
		})
	}
}

func Test_GitHubToken_inContext(t *testing.T) {
	token := legacyToken("ghp_")
	tests := []struct {
		name string
		src  string
		want string
	}{
		{name: "assignment", src: "GITHUB_TOKEN=" + token, want: "GITHUB_TOKEN=" + strings.Repeat("*", len(token))},
		{name: "quoted", src: `"` + token + `"`, want: `"` + strings.Repeat("*", len(token)) + `"`},
		{name: "header", src: "Authorization: token " + token, want: "Authorization: token " + strings.Repeat("*", len(token))},
		{name: "twice", src: token + " " + token, want: strings.Repeat("*", len(token)) + " " + strings.Repeat("*", len(token))},
	}

	m := New(WithPatterns(GitHubToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask() = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test_GitHubToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{name: "prefix alone", src: "ghp_"},
		{name: "body too short", src: "ghp_" + alnum36[:35]},
		{name: "unknown prefix letter", src: "ghx_" + alnum36},
		{name: "prefix without separator", src: "ghp" + alnum36},
		{name: "fine grained body too short", src: "github_pat_" + strings.Repeat(alnum36, 3)[:81]},
		{name: "an identifier that starts like the prefix", src: "github_pattern_for_matching"},
		{name: "plain prose", src: "there is no credential in this sentence"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GitHubToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_GitHubToken_name(t *testing.T) {
	if got := GitHubToken().Name(); got != "github-token" {
		t.Errorf("Name() = %q, want %q", got, "github-token")
	}
}

func Test_JWT(t *testing.T) {
	// Header, payload and signature, each base64url without padding.
	const (
		header    = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" // {"alg":"HS256","typ":"JWT"}
		payload   = "eyJzdWIiOiJhYmMifQ"                   // {"sub":"abc"}
		signature = "0123456789abcdef"
	)

	tests := []struct {
		name  string
		src   string
		found bool
	}{
		{name: "signed token", src: header + "." + payload + "." + signature, found: true},
		{name: "unsecured token has an empty signature", src: header + "." + payload + ".", found: true},
		{name: "base64url may hold - and _", src: header + "." + "eyJzdWIiOiJhLWJfYyJ9" + "." + "ab-cd_ef", found: true},
		{name: "header is too short to be an object", src: "eyJhZ" + "." + payload + "." + signature},
		{name: "header is not a base64url length", src: "eyJhbGciO" + "." + payload + "." + signature},
		// {"ab":} opens and closes an object but names no algorithm.
		{name: "header names no algorithm", src: "eyJhYiI6fQ" + "." + payload + "." + signature},
		// The final group holds characters base64url has no place for.
		{name: "header ends in undecodable characters", src: "eyJhbGci!!!" + "." + payload + "." + signature},
		{name: "only two segments", src: header + "." + payload},
		{name: "an empty segment is still a token", src: header + ".." + signature, found: true},
		{name: "does not start with the header marker", src: "abcdefgh." + payload + "." + signature},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := JWT().Find(tt.src)
			if tt.found {
				if len(got) != 1 || got[0] != (Span{0, len(tt.src)}) {
					t.Errorf("Find(%q) = %v, want one span covering the whole token", tt.src, got)
				}
				return
			}
			if len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_JWT_afterRejectedCandidate(t *testing.T) {
	// A candidate whose header is not JSON must not consume what it covered:
	// a real token can begin inside it.
	for _, prefix := range []string{"eyJ.eyJ.", "eyJx.a.b"} {
		src := prefix + jwtBody
		got := JWT().Find(src)
		if len(got) != 1 {
			t.Fatalf("Find(%q) = %v, want one span", src, got)
		}
		if located := src[got[0].Start:got[0].End]; located != jwtBody {
			t.Errorf("Find(%q) located %q, want %q", src, located, jwtBody)
		}
	}
}

func Test_JWT_encryptedToken(t *testing.T) {
	// An encrypted token carries five segments rather than three, and none of
	// them may survive.
	const jwe = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0.encKEY123.iv12345.ciphertextABC.authTAGxyz"
	if got := JWT().Find(jwe); len(got) != 1 || got[0] != (Span{0, len(jwe)}) {
		t.Errorf("Find(%q) = %v, want one span covering the whole token", jwe, got)
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
			src:  "see " + jwtBody + ". Next one.",
			want: "see " + strings.Repeat("*", len(jwtBody)) + ". Next one.",
		},
		{
			name: "file extension",
			src:  jwtBody + ".json",
			want: strings.Repeat("*", len(jwtBody)) + ".json",
		},
	}

	m := New(WithPatterns(JWT()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask() = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test_GitHubToken_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the token through whole.
	token := legacyToken("ghp_")
	fine := fineGrainedToken()
	tests := []struct {
		name string
		src  string
		want string
	}{
		{name: "underscore after", src: token + "_x", want: strings.Repeat("*", len(token)) + "_x"},
		{name: "word character before", src: "x" + token, want: "x" + strings.Repeat("*", len(token))},
		{name: "underscore before", src: "TOKEN_" + token, want: "TOKEN_" + strings.Repeat("*", len(token))},
		{name: "underscore before a fine grained token", src: "X_" + fine, want: "X_" + strings.Repeat("*", len(fine))},
	}

	m := New(WithPatterns(GitHubToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.Mask(tt.src)
			if strings.Contains(got, token) || strings.Contains(got, fine) {
				t.Fatalf("Mask(%q) = %q, which still holds the token", tt.src, got)
			}
			if got != tt.want {
				t.Errorf("Mask() = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test_GitHubToken_leavesWhatFollowsAlone(t *testing.T) {
	// Only the stateless installation token carries dots and dashes, so a
	// classic one must not draw in the host or word written after it.
	token := legacyToken("ghp_")
	stars := strings.Repeat("*", len(token))
	tests := []struct {
		name string
		src  string
		want string
	}{
		{name: "host", src: "host=" + token + ".example.com", want: "host=" + stars + ".example.com"},
		{name: "dashed word", src: token + "-suffix", want: stars + "-suffix"},
		{name: "sentence", src: "the token is " + token + ".", want: "the token is " + stars + "."},
	}

	m := New(WithPatterns(GitHubToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask() = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test_JWT_inContext(t *testing.T) {
	m := New(WithPatterns(JWT()))
	src := "Authorization: Bearer " + jwtBody
	want := "Authorization: Bearer " + strings.Repeat("*", len(jwtBody))
	if got := m.Mask(src); got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}

func Test_JWT_name(t *testing.T) {
	if got := JWT().Name(); got != "jwt" {
		t.Errorf("Name() = %q, want %q", got, "jwt")
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

// Match carries the Pattern itself, so a caller comparing one against a
// built-in must get the same value every call.

func Test_GitHubToken_sameValueEachCall(t *testing.T) {
	if GitHubToken() != GitHubToken() {
		t.Error("GitHubToken() returned a different value on a second call")
	}
}

func Test_JWT_sameValueEachCall(t *testing.T) {
	if JWT() != JWT() {
		t.Error("JWT() returned a different value on a second call")
	}
}

// jwtHeaderOf returns a base64url encoded header of n bytes of JSON, padded out
// in x5c the way a header carrying a certificate chain is.
func jwtHeaderOf(n int) string {
	const open, shut = `{"alg":"RS256","x5c":["`, `"]}`
	json := open + strings.Repeat("a", n-len(open)-len(shut)) + shut
	return base64.RawURLEncoding.EncodeToString([]byte(json))
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
		{name: "no closing brace", in: `{"alg":"none"`},
		{name: "value after the brace", in: `{} x`},
		{name: "nothing", in: ""},
		{name: "only space", in: "  \t\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := closesObject([]byte(tt.in)); got != tt.want {
				t.Errorf("closesObject(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func Test_JWT_headerEndsInSpace(t *testing.T) {
	// JSON allows space after the object, so a header written with any is
	// still a header.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"} `))
	src := header + ".payload.signature"
	if got := JWT().Find(src); len(got) != 1 || got[0] != (Span{0, len(src)}) {
		t.Errorf("Find(%q) = %v, want one span covering the whole token", src, got)
	}
}

func Test_JWT_headerHoldsNonBase64Characters(t *testing.T) {
	// The run of base64url characters stops at the !, so what follows is not
	// the dot that ends a header.
	const src = "eyJ!!!!!fQ.payload.signature"
	if got := JWT().Find(src); len(got) != 0 {
		t.Errorf("Find(%q) = %v, want no span", src, got)
	}
}

func Test_JWT_longHeader(t *testing.T) {
	// A header carrying a certificate chain in x5c runs to several thousand
	// characters. Length must not be what decides whether a token is located.
	for _, bytes := range []int{768, 6144, 65536} {
		header := jwtHeaderOf(bytes)
		src := header + ".payload.signature"
		got := JWT().Find(src)
		if len(got) != 1 || got[0] != (Span{0, len(src)}) {
			t.Errorf("Find(header of %d characters) = %v, want one span covering the whole token", len(header), got)
		}
	}
}

func Test_JWT_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a run dense in header
	// prefixes holds as many candidates as it has characters. Everything a
	// candidate needs beyond a constant is worked out once for the run it
	// sits in; getting that wrong has cost time quadratic in the length of
	// the input more than once. The bound here is far above a linear scan
	// and far below a quadratic one.
	sources := map[string]string{
		"many rejected candidates":     strings.Repeat("eyJ..", 200000),
		"overlapping candidate starts": strings.Repeat("eyJ", 200000) + "..",
		"dense starts with a near dot": strings.Repeat(strings.Repeat("eyJ", 300)+".", 600),
		"one long run before a dot":    strings.Repeat("eyJ", 200000) + ".a.b",
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

// nestedHeader returns a header whose decode reads as JSON far into its length.
// closing makes it end with a brace and name an algorithm, so that nothing
// short of parsing it can tell it is not a header.
func nestedHeader(depth int, closing bool) string {
	json := strings.Repeat(`{"a":`, depth) + "0"
	if closing {
		json = `{"alg":"x",` + json + "}"
	}
	return base64.RawURLEncoding.EncodeToString([]byte(json))
}
