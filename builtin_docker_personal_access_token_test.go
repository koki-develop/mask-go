package mask

import (
	"encoding/base64"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Docker personal access token pattern: what it locates and what it leaves
// alone, written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. The run they are built from,
// 0123456789abcdef0123456789a, is twenty-seven characters and so is a whole
// body.

func Test_DockerPersonalAccessToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "dckr_pat_0123456789abcdef0123456789a",
			want: []Span{{0, 36}},
		},
		{
			name: "a token in an environment assignment",
			src:  "DOCKER_TOKEN=dckr_pat_0123456789abcdef0123456789a",
			want: []Span{{13, 49}},
		},
		{
			// The hyphen and the underscore are base64url characters, and a
			// body is read in the whole of that alphabet.
			name: "a body carrying a hyphen and an underscore",
			src:  "dckr_pat_0123456789abcdef-123456789_",
			want: []Span{{0, 36}},
		},
		{
			// The twenty-seven behind the prefix are read as a count and not a
			// floor: what follows the thirty-sixth character is not part of the
			// token and stays in the text.
			name: "an alphabet run longer than a token is a token and what follows it",
			src:  "dckr_pat_0123456789abcdef0123456789ab",
			want: []Span{{0, 36}},
		},
		{
			// Neither token is inside the other, and nothing separates them.
			name: "two tokens with nothing between them",
			src:  "dckr_pat_0123456789abcdef0123456789adckr_pat_0123456789abcdef0123456789a",
			want: []Span{{0, 36}, {36, 72}},
		},
		{
			// The upper half of the alphabet, which every other case in this file
			// leaves untouched: the run so far has been lowercase hexadecimal
			// alone, and base64url reads every letter of both cases. The body
			// opens on the run written in uppercase and carries on through the
			// letters past F, so that the case a body is written in and the
			// letters the run never reaches are both driven at once.
			name: "a body of uppercase letters",
			src:  "dckr_pat_0123456789ABCDEFGHIJKLMNOPQ",
			want: []Span{{0, 36}},
		},
		{
			// The same body in the other case, which base64url reads as
			// readily: the run, and then the lowercase letters past f.
			name: "a body carrying the lowercase letters past the run",
			src:  "dckr_pat_0123456789abcdefghijklmnopq",
			want: []Span{{0, 36}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DockerPersonalAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DockerPersonalAccessToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "dckr_pat_",
		},
		{
			// Twenty-six characters where the pattern asks for twenty-seven.
			name: "body one character too short",
			src:  "dckr_pat_0123456789abcdef0123456789",
		},
		{
			name: "a dot in the body",
			src:  "dckr_pat_0123456789abcdef.123456789a",
		},
		{
			name: "a plus where the body would be",
			src:  "dckr_pat_+123456789abcdef0123456789a",
		},
		{
			// Standard base64 rather than base64url: the two characters
			// base64url writes as - and _ are + and /, and neither belongs to
			// the alphabet a body is read in.
			name: "a slash in the body",
			src:  "dckr_pat_0123456789abcdef/123456789+",
		},
		{
			// The three characters above stand in the middle of a body. These
			// three stand at its last character, straight in front of where the
			// count ends the token, where the same rejection has to hold.
			name: "a dot at the last character of the body",
			src:  "dckr_pat_0123456789abcdef0123456789.",
		},
		{
			name: "a space at the last character of the body",
			src:  "dckr_pat_0123456789abcdef0123456789 ",
		},
		{
			name: "a plus at the last character of the body",
			src:  "dckr_pat_0123456789abcdef0123456789+",
		},
		{
			name: "a body broken by a space",
			src:  "dckr_pat_0123456789abcdef 123456789a",
		},
		{
			name: "a body broken by a line break",
			src:  "dckr_pat_0123456789abcdef\n123456789a",
		},
		{
			name: "an uppercase prefix",
			src:  "DCKR_PAT_0123456789abcdef0123456789a",
		},
		{
			// One letter of the prefix in the other case, rather than the whole
			// of it.
			name: "the opening with one letter capitalized",
			src:  "Dckr_pat_0123456789abcdef0123456789a",
		},
		{
			name: "the kind with one letter capitalized",
			src:  "dckr_Pat_0123456789abcdef0123456789a",
		},
		{
			name: "hyphens where the prefix carries its underscores",
			src:  "dckr-pat-0123456789abcdef0123456789a",
		},
		{
			name: "the prefix without the underscore that closes it",
			src:  "dckr_pat0123456789abcdef0123456789ab",
		},
		{
			// Thirty-six base64url characters that open with something else.
			// The prefix is the whole of the anchor, so a run of the right
			// length is not a token without it.
			name: "a run of the right length opening with no prefix",
			src:  "xxxx_xxx_0123456789abcdef0123456789a",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// Forty hexadecimal characters. A digest carries no underscore, so
			// it holds no prefix to be found at.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DockerPersonalAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DockerPersonalAccessToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "DOCKER_TOKEN=dckr_pat_0123456789abcdef0123456789a",
			want: "DOCKER_TOKEN=************************************",
		},
		{
			name: "quoted",
			src:  `"dckr_pat_0123456789abcdef0123456789a"`,
			want: `"************************************"`,
		},
		{
			name: "json",
			src:  `{"secret":"dckr_pat_0123456789abcdef0123456789a"}`,
			want: `{"secret":"************************************"}`,
		},
		{
			// The command line Docker's own documentation logs a user in with.
			name: "the login command",
			src:  "docker login -u myusername -p dckr_pat_0123456789abcdef0123456789a",
			want: "docker login -u myusername -p ************************************",
		},
		{
			// The credential Docker's token endpoint is handed to exchange for
			// a bearer token.
			name: "the body of a token request",
			src:  `{"identifier":"myusername","secret":"dckr_pat_0123456789abcdef0123456789a"}`,
			want: `{"identifier":"myusername","secret":"************************************"}`,
		},
		{
			name: "twice",
			src:  "dckr_pat_0123456789abcdef0123456789a dckr_pat_0123456789abcdef-123456789_",
			want: "************************************ ************************************",
		},
	}

	m := New(WithPatterns(DockerPersonalAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DockerPersonalAccessToken_aTokenBeginningInsideAnother(t *testing.T) {
	// Every character of the prefix belongs to the alphabet a body is written
	// in, so the prefix written twice with a body behind the second is a token
	// from either of them. A scan resuming past its match would step over the
	// second and leave it in the output whole; the two spans overlap and a
	// Masker resolves them into one.
	src := "dckr_pat_dckr_pat_0123456789abcdef0123456789a"

	want := []Span{{0, 36}, {9, 45}}
	if got, _ := DockerPersonalAccessToken().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}

	m := New(WithPatterns(DockerPersonalAccessToken()))
	if got, want := m.Mask(src), strings.Repeat("*", len(src)); got != want {
		t.Errorf("Mask(%q) = %q, want %q", src, got, want)
	}
}

func Test_DockerPersonalAccessToken_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the token through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xdckr_pat_0123456789abcdef0123456789a",
			want: "x************************************",
		},
		{
			name: "underscore before",
			src:  "DOCKER_TOKEN_dckr_pat_0123456789abcdef0123456789a",
			want: "DOCKER_TOKEN_************************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this token
			// rather than trim it; without one the thirty-six characters Docker
			// issued are redacted and the one written after them, which is part
			// of no credential, stays in the text.
			name: "a character of the alphabet after",
			src:  "dckr_pat_0123456789abcdef0123456789ab",
			want: "************************************b",
		},
		{
			// A multi-byte rune written against the token on both sides. Neither
			// UTF-8 encoding shares a byte with the prefix or the body's
			// alphabet, so the token keeps its span exactly as it does against a
			// single-byte character.
			name: "a multi-byte rune before and after",
			src:  "日本語dckr_pat_0123456789abcdef0123456789a日本語",
			want: "日本語************************************日本語",
		},
	}

	m := New(WithPatterns(DockerPersonalAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DockerPersonalAccessToken_leavesWhatFollowsAlone(t *testing.T) {
	// A token carries no character the base64url alphabet does not, so ordinary
	// punctuation ends one and nothing written after it joins it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "host",
			src:  "host=dckr_pat_0123456789abcdef0123456789a.example.com",
			want: "host=************************************.example.com",
		},
		{
			name: "sentence",
			src:  "the token is dckr_pat_0123456789abcdef0123456789a.",
			want: "the token is ************************************.",
		},
		{
			// The hyphen is a body character, so what follows a token across
			// one is read as a body and the count is what ends the token rather
			// than the hyphen.
			name: "dashed word",
			src:  "dckr_pat_0123456789abcdef0123456789a-suffix",
			want: "************************************-suffix",
		},
	}

	m := New(WithPatterns(DockerPersonalAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DockerPersonalAccessToken_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix is nine
	// characters of an alphabet of sixty-four, so a base64url value long enough
	// to spell it carries a candidate, and where the twenty-seven behind it are
	// in the alphabet too, those thirty-six are redacted.
	//
	// They are held to being redacted rather than to being spared. Nothing in
	// the text tells such a run from a token — they are the same thirty-six
	// bytes — so a scan that let these through would let a real token through
	// with them, which builtin_docker_personal_access_token.go sets out. What
	// the table is for is that the cases move with the scan: one of them
	// ceasing to be located means the grammar changed, and that is a decision
	// to be taken rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "inside a base64url payload",
			src:  "payload=zzzzdckr_pat_0123456789abcdef0123456789azzzz",
			want: "payload=zzzz************************************zzzz",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the
			// Docker pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.dckr_pat_0123456789abcdef0123456789a",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.************************************",
		},
	}

	m := New(WithPatterns(DockerPersonalAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DockerPersonalAccessToken_theOrganizationTokenPrefix(t *testing.T) {
	// The second prefix Docker's credential table names, dckr_oat_, which this
	// scan does not read: the rationale beside the scan says what is missing,
	// which is a width. Both of the widths that have been claimed for it are
	// written out here, so that reading the prefix is a change somebody argues
	// for rather than one somebody notices afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the width docker's reference prints",
			src:  "dckr_oat_0123456789abcdef0123456789a",
		},
		{
			name: "the width the rulesets ask for",
			src:  "dckr_oat_0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DockerPersonalAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DockerPersonalAccessToken_theShapeItReplaced(t *testing.T) {
	// The shape Docker Hub's login endpoint took before a prefix was written in
	// front of one: a UUID with nothing to recognise it by but the vendor's
	// word beside it, which is the shape the rationale beside the scan declines
	// to read. A pattern reading it would redact every UUID a caller passes
	// through.
	src := "DOCKER_TOKEN=01234567-89ab-cdef-0123-456789abcdef"

	if got, _ := DockerPersonalAccessToken().Find(src); len(got) != 0 {
		t.Errorf("Find(%q) = %v, want no span", src, got)
	}
}

// Test_DockerPersonalAccessToken_holdsATokenTheInputCutShort states, with a
// literal number, what the second return of Find settles: a piece of the
// prefix standing at the end of the input, a candidate the end of the input
// cut short, and a whole match with nothing left unsettled behind it.
func Test_DockerPersonalAccessToken_holdsATokenTheInputCutShort(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		want   []Span
		retain int
	}{
		{
			// A piece of the prefix stands at the very end of the input, so
			// nothing behind where it opens is settled.
			name:   "a piece of the prefix at the end of the input",
			src:    "dckr_pat",
			retain: 0,
		},
		{
			name:   "a piece of the prefix behind prose",
			src:    "the token starts with dckr_pat",
			retain: len("the token starts with "),
		},
		{
			// A whole prefix and a body the input cuts short before the
			// count is met. The candidate could still become a token were
			// the input longer, so what is unsettled reaches back to where
			// the candidate opened.
			name:   "a body the input cuts short of the count",
			src:    "dckr_pat_0123456789abcdef01234",
			retain: 0,
		},
		{
			// A whole token with more text after it, ending in a byte that
			// opens no piece of the prefix, so nothing at the end of the
			// input is left unsettled.
			name:   "a whole token followed by settled text",
			src:    "dckr_pat_0123456789abcdef0123456789a tail",
			want:   []Span{{0, 36}},
			retain: len("dckr_pat_0123456789abcdef0123456789a tail"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := DockerPersonalAccessToken().Find(tt.src)
			if retain != tt.retain {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, retain, tt.retain)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_dockerPersonalAccessTokenPrefix(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a token
	// can begin inside the body of the one before it, and that holds only while
	// every character of the prefix is one a body may be written in. A prefix
	// carrying a character outside the alphabet would make the two impossible
	// to nest, and the case above pinning the nesting would stand for nothing —
	// which is not a failure anything else here reports.
	if dockerPersonalAccessTokenPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for i := range len(dockerPersonalAccessTokenPrefix) {
		if c := dockerPersonalAccessTokenPrefix[i]; !isBase64URLByte(c) {
			t.Errorf("the prefix holds %q, which no body may be written with", c)
		}
	}
}

// Test_dockerPersonalAccessTokenAnchor holds the prefix to carrying the byte the
// scan searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_dockerPersonalAccessTokenAnchor(t *testing.T) {
	if dockerPersonalAccessTokenAnchorIndex >= len(dockerPersonalAccessTokenPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", dockerPersonalAccessTokenAnchorIndex, len(dockerPersonalAccessTokenPrefix))
	}
	if c := dockerPersonalAccessTokenPrefix[dockerPersonalAccessTokenAnchorIndex]; c != dockerPersonalAccessTokenAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(dockerPersonalAccessTokenAnchor))
	}
}

// Test_dockerPersonalAccessTokenChars holds the counts to the arithmetic the
// rationale reads them as: a body is the width twenty bytes come to in base64url
// with no padding, and a token is that with the prefix in front. The widths
// either side of twenty are checked as well, since it is those that make
// twenty-seven the width of one whole number of bytes and no other.
func Test_dockerPersonalAccessTokenChars(t *testing.T) {
	if got := base64.RawURLEncoding.EncodedLen(20); got != dockerPersonalAccessTokenBodyChars {
		t.Errorf("twenty bytes encode to %d characters, the body is read as %d", got, dockerPersonalAccessTokenBodyChars)
	}
	for _, n := range []int{19, 21} {
		if got := base64.RawURLEncoding.EncodedLen(n); got == dockerPersonalAccessTokenBodyChars {
			t.Errorf("%d bytes encode to %d characters as well, so the count names no one width", n, got)
		}
	}
	if want := len(dockerPersonalAccessTokenPrefix) + dockerPersonalAccessTokenBodyChars; dockerPersonalAccessTokenChars != want {
		t.Errorf("a token is read as %d characters, the prefix and the body come to %d", dockerPersonalAccessTokenChars, want)
	}
	if dockerPersonalAccessTokenChars != 36 {
		t.Errorf("a token is read as %d characters, the rationale says thirty-six", dockerPersonalAccessTokenChars)
	}
}

func Test_isDockerPersonalAccessTokenBody(t *testing.T) {
	// The count and the alphabet together, stated over every byte rather than
	// by example: a body is exactly dockerPersonalAccessTokenBodyChars
	// characters and each of them base64url.
	body := strings.Repeat("a", dockerPersonalAccessTokenBodyChars)

	if !isDockerPersonalAccessTokenBody(body) {
		t.Errorf("isDockerPersonalAccessTokenBody(%q) = false, want a body of %d characters to be one", body, dockerPersonalAccessTokenBodyChars)
	}
	for _, s := range []string{body[:len(body)-1], body + "a"} {
		if isDockerPersonalAccessTokenBody(s) {
			t.Errorf("isDockerPersonalAccessTokenBody(%q) = true, want only %d characters to be a body", s, dockerPersonalAccessTokenBodyChars)
		}
	}

	for c := range 256 {
		b := byte(c)
		src := body[:len(body)-1] + string([]byte{b})
		if got, want := isDockerPersonalAccessTokenBody(src), isBase64URLByte(b); got != want {
			t.Errorf("isDockerPersonalAccessTokenBody(%q) = %v with %q in it, want %v", src, got, b, want)
		}
	}
}

// referenceDockerPersonalAccessToken is the expression the scan in
// builtin_docker_personal_access_token.go reads by hand: the statement of what a
// Docker personal access token is, kept here so that the scan can be held to it.
//
// The prefix, the count and the alphabet are spelled again rather than built
// from dockerPersonalAccessTokenPrefix, dockerPersonalAccessTokenBodyChars and
// isBase64URLByte. A reference sharing those declarations could not disagree
// with the scan about them, and it is exactly that disagreement the fuzz target
// below is for: the two have to be changed together or reported apart.
var referenceDockerPersonalAccessToken = regexp.MustCompile(`dckr_pat_[0-9A-Za-z_-]{27}`)

// referenceDockerPersonalAccessTokenFind locates tokens the plain way: the
// leftmost match of the expression above, then the leftmost one beginning after
// that match's first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a token can begin inside one: every character of
// the prefix is written in the alphabet a body is, so the prefix twice over with
// a body behind it holds a token the engine would never go on to try. The scan
// finds both and reports the two spans overlapping for a Masker to resolve, so
// the reference must ask about both.
//
// Resuming a byte along costs this one nothing beyond a constant, where a
// reference reading a body to the end of its run pays for it: every candidate
// reads at most thirty-six characters, here as in the scan, so neither has a run
// to walk and there is no cursor for either to be wrong about.
func referenceDockerPersonalAccessTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceDockerPersonalAccessToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzDockerPersonalAccessToken_matchesReference guards the hand-written scan:
// the prefix it searches for, the count it reads behind that prefix, the
// alphabet it reads it in and the byte it resumes at may none of them change
// which tokens are located.
func FuzzDockerPersonalAccessToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("DOCKER_TOKEN=dckr_pat_0123456789abcdef0123456789a")
	f.Add("docker login -u myusername -p dckr_pat_0123456789abcdef0123456789a")
	f.Add("dckr_pat_0123456789abcdef-123456789_")  // a hyphen and an underscore in the body
	f.Add("dckr_pat_0123456789abcdef0123456789")   // one short of a token
	f.Add("dckr_pat_0123456789abcdef0123456789ab") // and a run longer than one
	f.Add("DCKR_PAT_0123456789abcdef0123456789a")  // an uppercase prefix
	f.Add("dckr-pat-0123456789abcdef0123456789a")  // hyphens where it carries underscores
	f.Add("dckr_pat0123456789abcdef0123456789ab")  // the underscore that closes it left out
	f.Add("dckr_oat_0123456789abcdef0123456789a")  // the prefix of an organization access token
	f.Add("dckr_pat_0123456789abcdef+123456789/")  // standard base64 rather than base64url
	f.Add("dckr_pat_0123456789abcdef.123456789a")  // a dot ends the body
	f.Add("dckr_pat_0123456789abcdef 123456789a")  // and a space
	f.Add("dckr_pat_0123456789abcdef0123456789a.next")
	f.Add("dckr_pat_0123456789abcdef0123456789a\ndckr_pat_0123456789abcdef0123456789a")
	// A token beginning inside the match before it, which a scan resuming past
	// a match steps over, and two tokens with nothing between them, which is
	// the same text without the overlap.
	f.Add("dckr_pat_dckr_pat_0123456789abcdef0123456789a")
	f.Add("dckr_pat_0123456789abcdef0123456789adckr_pat_0123456789abcdef0123456789a")
	f.Add(strings.Repeat("dckr_pat_", 8))
	// Candidate positions crowded as close as they can be: every ninth byte in
	// the first, and a run that is a body to every candidate in it.
	f.Add(strings.Repeat("dckr_pat_", 32))
	f.Add(strings.Repeat("dckr_pat_", 32) + "!")
	// The prefix written inside a run of the alphabet, which is the over-match
	// the pattern admits, and the same run where a JWT signature stands.
	f.Add("payload=zzzzdckr_pat_0123456789abcdef0123456789azzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.dckr_pat_0123456789abcdef0123456789a")

	fuzzAgainstReference(f, DockerPersonalAccessToken().Find, referenceDockerPersonalAccessTokenFind)
}

// dockerPersonalAccessTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func dockerPersonalAccessTokenFindBenchmarks() []benchmarkCase {
	// The vendor's own host name carries the byte the scan searches for, so
	// this line is the shape that costs the search most while holding no token:
	// one candidate opened and turned away on the character in front of it.
	line := `time=2026-08-17T00:00:00Z level=info msg="pushing an image" url=https://hub.docker.com/v2/repositories/library/nginx/tags `
	token := "dckr_pat_0123456789abcdef0123456789a"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is nine characters a body is written with, so a run
			// can hold a candidate for every nine it has. Here each of them
			// reads the body as far as the character that is not one, which
			// stands where the run ends: the crowding this pattern admits, with
			// no value at the end of any of it.
			name:  "candidates that are not values",
			src:   strings.Repeat("dckr_pat_dckr_pat_dckr_pat_.", 16),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "token=" + token,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "token=" + token,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"token="+token+"\n", 32),
			spans: 32,
		},
	}
}
