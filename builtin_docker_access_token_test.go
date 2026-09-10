package mask

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"
)

// The Docker access token pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
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
// personal access token body and the shortest organization access token body;
// the run carried on to 0123456789abcdef0123456789abcdef is the thirty-two the
// rulesets read for the second kind.

func Test_DockerAccessToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a personal access token on its own",
			src:  "dckr_pat_0123456789abcdef0123456789a",
			want: []Span{{0, 36}},
		},
		{
			name: "an organization access token on its own",
			src:  "dckr_oat_0123456789abcdef0123456789a",
			want: []Span{{0, 36}},
		},
		{
			// The width the rulesets read for this kind, which the floor
			// reaches as readily as it reaches the shorter one.
			name: "an organization access token of the width the rulesets read",
			src:  "dckr_oat_0123456789abcdef0123456789abcdef",
			want: []Span{{0, 41}},
		},
		{
			name: "a personal access token in an environment assignment",
			src:  "DOCKER_TOKEN=dckr_pat_0123456789abcdef0123456789a",
			want: []Span{{13, 49}},
		},
		{
			name: "an organization access token in an environment assignment",
			src:  "DOCKER_TOKEN=dckr_oat_0123456789abcdef0123456789a",
			want: []Span{{13, 49}},
		},
		{
			// The hyphen and the underscore are base64url characters, and a
			// body is read in the whole of that alphabet.
			name: "a personal body carrying a hyphen and an underscore",
			src:  "dckr_pat_0123456789abcdef-123456789_",
			want: []Span{{0, 36}},
		},
		{
			name: "an organization body carrying a hyphen and an underscore",
			src:  "dckr_oat_0123456789abcdef-123456789_",
			want: []Span{{0, 36}},
		},
		{
			// The same two at the first character of a body, where the
			// underscore is the sharper of them: it doubles the one the prefix
			// closes with, so a scan reading a prefix by its separator rather
			// than by the whole literal would part from the reference here. The
			// run opens behind the separator rather than being cut short by it,
			// which is where .betterleaks.toml asks for it.
			name: "a personal body opening on an underscore",
			src:  "dckr_pat__0123456789abcdef0123456789",
			want: []Span{{0, 36}},
		},
		{
			name: "an organization body opening on an underscore",
			src:  "dckr_oat__0123456789abcdef0123456789",
			want: []Span{{0, 36}},
		},
		{
			name: "a personal body opening on a hyphen",
			src:  "dckr_pat_-0123456789abcdef0123456789",
			want: []Span{{0, 36}},
		},
		{
			name: "an organization body opening on a hyphen",
			src:  "dckr_oat_-0123456789abcdef0123456789",
			want: []Span{{0, 36}},
		},
		{
			// The twenty-seven behind the personal prefix are read as a count
			// and not a floor: what follows the thirty-sixth character is not
			// part of the token and stays in the text.
			name: "an alphabet run longer than a personal token is a token and what follows it",
			src:  "dckr_pat_0123456789abcdef0123456789ab",
			want: []Span{{0, 36}},
		},
		{
			// The same run behind the organization prefix, where the count is a
			// floor: the twenty-eighth character is inside the span rather than
			// behind it, because nothing in the text says where such a body
			// ends.
			name: "an alphabet run longer than the floor is an organization token to the end of it",
			src:  "dckr_oat_0123456789abcdef0123456789ab",
			want: []Span{{0, 37}},
		},
		{
			// Neither token is inside the other, and nothing separates them.
			name: "two personal tokens with nothing between them",
			src:  "dckr_pat_0123456789abcdef0123456789adckr_pat_0123456789abcdef0123456789a",
			want: []Span{{0, 36}, {36, 72}},
		},
		{
			// One kind written straight against the other. The personal token
			// ends at its count, and the organization token behind it runs to
			// the end of the line.
			name: "an organization token written behind a personal one",
			src:  "dckr_pat_0123456789abcdef0123456789adckr_oat_0123456789abcdef0123456789a",
			want: []Span{{0, 36}, {36, 72}},
		},
		{
			// The upper half of the alphabet, which most cases in this file
			// leave untouched: the run so far has been lowercase hexadecimal
			// alone, and base64url reads every letter of both cases. The body
			// opens on the run written in uppercase and carries on through the
			// letters past F.
			name: "a personal body of uppercase letters",
			src:  "dckr_pat_0123456789ABCDEFGHIJKLMNOPQ",
			want: []Span{{0, 36}},
		},
		{
			name: "an organization body of uppercase letters",
			src:  "dckr_oat_0123456789ABCDEFGHIJKLMNOPQ",
			want: []Span{{0, 36}},
		},
		{
			// The same body in the other case, which base64url reads as
			// readily: the run, and then the lowercase letters past f.
			name: "a personal body carrying the lowercase letters past the run",
			src:  "dckr_pat_0123456789abcdefghijklmnopq",
			want: []Span{{0, 36}},
		},
		{
			name: "an organization body carrying the lowercase letters past the run",
			src:  "dckr_oat_0123456789abcdefghijklmnopq",
			want: []Span{{0, 36}},
		},
		{
			// The far end of each letter range, which the four cases above stop
			// short of: the run, then the letters from Q to Z, so the last
			// letter of either case stands inside a body rather than behind
			// one. The body closes on the digit the run begins again at, which
			// is how twenty-seven characters reach the end of a range.
			name: "a personal body reaching the last uppercase letter",
			src:  "dckr_pat_0123456789ABCDEFQRSTUVWXYZ0",
			want: []Span{{0, 36}},
		},
		{
			name: "a personal body reaching the last lowercase letter",
			src:  "dckr_pat_0123456789abcdefqrstuvwxyz0",
			want: []Span{{0, 36}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DockerAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DockerAccessToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the personal prefix alone",
			src:  "dckr_pat_",
		},
		{
			name: "the organization prefix alone",
			src:  "dckr_oat_",
		},
		{
			// Twenty-six characters where the pattern asks for twenty-seven.
			// The personal count and the organization floor are the same
			// number, so one character short of it is short of both.
			name: "a personal body one character too short",
			src:  "dckr_pat_0123456789abcdef0123456789",
		},
		{
			name: "an organization body one character short of the floor",
			src:  "dckr_oat_0123456789abcdef0123456789",
		},
		{
			name: "a dot in the personal body",
			src:  "dckr_pat_0123456789abcdef.123456789a",
		},
		{
			// The dot ends the run, leaving sixteen characters where the floor
			// asks for twenty-seven.
			name: "a dot in the organization body",
			src:  "dckr_oat_0123456789abcdef.123456789a",
		},
		{
			name: "a plus where the personal body would be",
			src:  "dckr_pat_+123456789abcdef0123456789a",
		},
		{
			name: "a plus where the organization body would be",
			src:  "dckr_oat_+123456789abcdef0123456789a",
		},
		{
			// Standard base64 rather than base64url: the two characters
			// base64url writes as - and _ are + and /, and neither belongs to
			// the alphabet a body is read in.
			name: "a slash in the personal body",
			src:  "dckr_pat_0123456789abcdef/123456789+",
		},
		{
			name: "a slash in the organization body",
			src:  "dckr_oat_0123456789abcdef/123456789+",
		},
		{
			// The three characters above stand in the middle of a body. These
			// three stand at its last character, straight in front of where the
			// count ends the token, where the same rejection has to hold.
			name: "a dot at the last character of the personal body",
			src:  "dckr_pat_0123456789abcdef0123456789.",
		},
		{
			name: "a space at the last character of the personal body",
			src:  "dckr_pat_0123456789abcdef0123456789 ",
		},
		{
			name: "a plus at the last character of the personal body",
			src:  "dckr_pat_0123456789abcdef0123456789+",
		},
		{
			// The same three at the character the organization floor would be
			// met at, where what they end is the run rather than a count.
			name: "a dot at the last character the organization floor asks for",
			src:  "dckr_oat_0123456789abcdef0123456789.",
		},
		{
			name: "a space at the last character the organization floor asks for",
			src:  "dckr_oat_0123456789abcdef0123456789 ",
		},
		{
			name: "a plus at the last character the organization floor asks for",
			src:  "dckr_oat_0123456789abcdef0123456789+",
		},
		{
			name: "a personal body broken by a space",
			src:  "dckr_pat_0123456789abcdef 123456789a",
		},
		{
			name: "an organization body broken by a space",
			src:  "dckr_oat_0123456789abcdef 123456789a",
		},
		{
			name: "a personal body broken by a line break",
			src:  "dckr_pat_0123456789abcdef\n123456789a",
		},
		{
			name: "an organization body broken by a line break",
			src:  "dckr_oat_0123456789abcdef\n123456789a",
		},
		{
			name: "an uppercase personal prefix",
			src:  "DCKR_PAT_0123456789abcdef0123456789a",
		},
		{
			name: "an uppercase organization prefix",
			src:  "DCKR_OAT_0123456789abcdef0123456789a",
		},
		{
			// One letter of the prefix in the other case, rather than the whole
			// of it.
			name: "the opening with one letter capitalized",
			src:  "Dckr_pat_0123456789abcdef0123456789a",
		},
		{
			name: "the personal kind with one letter capitalized",
			src:  "dckr_Pat_0123456789abcdef0123456789a",
		},
		{
			name: "the organization kind with one letter capitalized",
			src:  "dckr_Oat_0123456789abcdef0123456789a",
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
			// A kind of the right width that Docker writes no token with. The
			// scan reads the kind rather than anything that stands in for one,
			// so a third word between the opening and the separator is no
			// candidate.
			name: "a kind Docker does not write",
			src:  "dckr_xyz_0123456789abcdef0123456789a",
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
			if got, _ := DockerAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DockerAccessToken_inContext(t *testing.T) {
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
			// a bearer token. An organization access token reaches it under the
			// same field, with an organization name for the identifier.
			name: "the body of a token request",
			src:  `{"identifier":"myusername","secret":"dckr_pat_0123456789abcdef0123456789a"}`,
			want: `{"identifier":"myusername","secret":"************************************"}`,
		},
		{
			name: "the body of a token request carrying an organization token",
			src:  `{"identifier":"myorg","secret":"dckr_oat_0123456789abcdef0123456789a"}`,
			want: `{"identifier":"myorg","secret":"************************************"}`,
		},
		{
			// The field Docker's own specification prints an organization
			// access token in when one is created.
			name: "the response an organization token is created in",
			src:  `{"token":"dckr_oat_0123456789abcdef0123456789a"}`,
			want: `{"token":"************************************"}`,
		},
		{
			name: "twice",
			src:  "dckr_pat_0123456789abcdef0123456789a dckr_pat_0123456789abcdef-123456789_",
			want: "************************************ ************************************",
		},
		{
			name: "one of each kind",
			src:  "dckr_pat_0123456789abcdef0123456789a dckr_oat_0123456789abcdef0123456789a",
			want: "************************************ ************************************",
		},
	}

	m := New(WithPatterns(DockerAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DockerAccessToken_theOrganizationBodyReachesTheEndOfTheRun(t *testing.T) {
	// What reading the second kind's body as a floor costs, held to being paid
	// rather than argued about. Docker states no width for this kind and the two
	// that have been claimed for it disagree, so the body has no width of its
	// own to end at and is read to the end of the run it stands in. Where a
	// token is written against more of the alphabet, those characters are
	// redacted with it.
	//
	// The personal kind is written beside each case, where the count ends the
	// token and the same characters stay in the text. That is the contrast the
	// cases are for: one scan, two readings, and the reason for the difference
	// is in builtin_docker_access_token.go.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a character of the alphabet behind an organization token",
			src:  "dckr_oat_0123456789abcdef0123456789ab",
			want: "*************************************",
		},
		{
			name: "the same character behind a personal token",
			src:  "dckr_pat_0123456789abcdef0123456789ab",
			want: "************************************b",
		},
		{
			// A word joined to the token by a hyphen, which is a body
			// character: what follows is read as body and goes with it.
			name: "a dashed word behind an organization token",
			src:  "dckr_oat_0123456789abcdef0123456789a-suffix",
			want: "*******************************************",
		},
		{
			name: "the same word behind a personal token",
			src:  "dckr_pat_0123456789abcdef0123456789a-suffix",
			want: "************************************-suffix",
		},
		{
			// Two organization tokens written against one another are one run,
			// so the first candidate reaches the end of the second token and
			// the spans merge into one redaction.
			name: "two organization tokens with nothing between them",
			src:  "dckr_oat_0123456789abcdef0123456789adckr_oat_0123456789abcdef0123456789a",
			want: strings.Repeat("*", 72),
		},
	}

	m := New(WithPatterns(DockerAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DockerAccessToken_organizationRunEndsOutsideTheAlphabet(t *testing.T) {
	// Where an organization access token ends, stated over every byte rather
	// than by example. Its body has no count to stop at, so the character that
	// is not one of the alphabet's is the whole of what ends it — and a walk
	// written as one comparison rather than as the ranges it means would end a
	// run at the wrong byte and carry a token's span past or short of where it
	// stops. The bytes that catch such a walk are the ones just above and just
	// below each range, which no case written by hand reaches.
	//
	// The body here is a whole one, then the byte, then more of the alphabet:
	// where the byte belongs to a body the span reaches the end of the input,
	// and where it does not the span is the token alone.
	//
	// The counted reading needs none of this, because
	// Test_isDockerAccessTokenPersonalBody states the same thing over every
	// byte for the helper that ends a counted body.
	const body = "0123456789abcdef0123456789a"
	const tail = "0123456789a"

	p := DockerAccessToken()
	for c := range 256 {
		b := byte(c)
		src := "dckr_oat_" + body + string([]byte{b}) + tail

		want := []Span{{0, 9 + len(body)}}
		if isBase64URLByte(b) {
			want = []Span{{0, len(src)}}
		}
		if got, _ := p.Find(src); !slices.Equal(got, want) {
			t.Errorf("Find(%q) = %v with %q closing the body, want %v", src, got, b, want)
		}
	}
}

func Test_DockerAccessToken_aTokenBeginningInsideAnother(t *testing.T) {
	// Every character of both prefixes belongs to the alphabet a body is written
	// in, so a prefix written twice with a body behind the second is a token
	// from either of them. A scan resuming past its match would step over the
	// second and leave it in the output whole; the two spans overlap and a
	// Masker resolves them into one.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a personal token inside a personal one",
			src:  "dckr_pat_dckr_pat_0123456789abcdef0123456789a",
			want: []Span{{0, 36}, {9, 45}},
		},
		{
			// The organization reading of the same shape. The outer candidate's
			// body runs to the end of the line, so both spans close there.
			name: "an organization token inside an organization one",
			src:  "dckr_oat_dckr_oat_0123456789abcdef0123456789a",
			want: []Span{{0, 45}, {9, 45}},
		},
		{
			// One kind opening inside the body of the other, which is where the
			// two readings meet: the personal span is its count, the
			// organization span behind it the rest of the run.
			name: "an organization token inside a personal one",
			src:  "dckr_pat_dckr_oat_0123456789abcdef0123456789a",
			want: []Span{{0, 36}, {9, 45}},
		},
	}

	m := New(WithPatterns(DockerAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DockerAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
			if got, want := m.Mask(tt.src), strings.Repeat("*", len(tt.src)); got != want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, want)
			}
		})
	}
}

func Test_DockerAccessToken_nextToWordCharacters(t *testing.T) {
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
			name: "underscore before an organization token",
			src:  "DOCKER_TOKEN_dckr_oat_0123456789abcdef0123456789a",
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
			// UTF-8 encoding shares a byte with a prefix or the body's
			// alphabet, so the token keeps its span exactly as it does against a
			// single-byte character.
			name: "a multi-byte rune before and after",
			src:  "日本語dckr_pat_0123456789abcdef0123456789a日本語",
			want: "日本語************************************日本語",
		},
		{
			name: "a multi-byte rune around an organization token",
			src:  "日本語dckr_oat_0123456789abcdef0123456789a日本語",
			want: "日本語************************************日本語",
		},
	}

	m := New(WithPatterns(DockerAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DockerAccessToken_leavesWhatFollowsAlone(t *testing.T) {
	// A token carries no character the base64url alphabet does not, so ordinary
	// punctuation ends one and nothing written after it joins it. That holds for
	// both readings: the dot and the full stop stand outside the alphabet, so
	// they end a run as surely as they fall past a count.
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
			name: "host behind an organization token",
			src:  "host=dckr_oat_0123456789abcdef0123456789a.example.com",
			want: "host=************************************.example.com",
		},
		{
			name: "sentence",
			src:  "the token is dckr_pat_0123456789abcdef0123456789a.",
			want: "the token is ************************************.",
		},
		{
			name: "sentence closing on an organization token",
			src:  "the token is dckr_oat_0123456789abcdef0123456789a.",
			want: "the token is ************************************.",
		},
	}

	m := New(WithPatterns(DockerAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DockerAccessToken_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. A prefix is nine characters
	// of an alphabet of sixty-four, so a base64url value long enough to spell
	// one carries a candidate, and where the twenty-seven behind it are in the
	// alphabet too, the run is redacted.
	//
	// They are held to being redacted rather than to being spared. Nothing in
	// the text tells such a run from a token — they are the same bytes — so a
	// scan that let these through would let a real token through with them,
	// which builtin_docker_access_token.go sets out. What the table is for is
	// that the cases move with the scan: one of them ceasing to be located means
	// the grammar changed, and that is a decision to be taken rather than
	// noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a personal prefix inside a base64url payload",
			src:  "payload=zzzzdckr_pat_0123456789abcdef0123456789azzzz",
			want: "payload=zzzz************************************zzzz",
		},
		{
			// The organization reading of the same text, where the floor
			// carries the span to the end of the run rather than stopping at a
			// count: the four characters behind the body go with it.
			name: "an organization prefix inside a base64url payload",
			src:  "payload=zzzzdckr_oat_0123456789abcdef0123456789azzzz",
			want: "payload=zzzz****************************************",
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

	m := New(WithPatterns(DockerAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DockerAccessToken_theShapeItReplaced(t *testing.T) {
	// The shape Docker Hub's login endpoint took before a prefix was written in
	// front of one: a UUID with nothing to recognise it by but the vendor's
	// word beside it, which is the shape the rationale beside the scan declines
	// to read. A pattern reading it would redact every UUID a caller passes
	// through.
	src := "DOCKER_TOKEN=01234567-89ab-cdef-0123-456789abcdef"

	if got, _ := DockerAccessToken().Find(src); len(got) != 0 {
		t.Errorf("Find(%q) = %v, want no span", src, got)
	}
}

// Test_DockerAccessToken_holdsATokenTheInputCutShort states, with a literal
// number, what the second return of Find settles: a piece of a prefix standing
// at the end of the input, a candidate the end of the input cut short, and a
// whole match with nothing left unsettled behind it.
func Test_DockerAccessToken_holdsATokenTheInputCutShort(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		want   []Span
		retain int
	}{
		{
			// A piece of a prefix stands at the very end of the input, so
			// nothing behind where it opens is settled.
			name:   "a piece of the personal prefix at the end of the input",
			src:    "dckr_pat",
			retain: 0,
		},
		{
			name:   "a piece of the organization prefix at the end of the input",
			src:    "dckr_oat",
			retain: 0,
		},
		{
			// The opening alone, which is a piece of either prefix and is held
			// from its own start for both.
			name:   "the opening at the end of the input",
			src:    "dckr_",
			retain: 0,
		},
		{
			name:   "a piece of the prefix behind prose",
			src:    "the token starts with dckr_pat",
			retain: len("the token starts with "),
		},
		{
			// A whole prefix and a body the input cuts short before the count
			// is met. The candidate could still become a token were the input
			// longer, so what is unsettled reaches back to where the candidate
			// opened.
			name:   "a personal body the input cuts short of the count",
			src:    "dckr_pat_0123456789abcdef01234",
			retain: 0,
		},
		{
			name:   "an organization body the input cuts short of the floor",
			src:    "dckr_oat_0123456789abcdef01234",
			retain: 0,
		},
		{
			// An organization body already past the floor and still running at
			// the end of the input. The span reported here is the text as
			// handed over, and more of the alphabet would carry it further, so
			// the candidate is unsettled even though it is a token.
			name:   "an organization body past the floor and still running",
			src:    "dckr_oat_0123456789abcdef0123456789a",
			want:   []Span{{0, 36}},
			retain: 0,
		},
		{
			// The counted reading at the end of the input, which is the answer
			// the organization case above does not have. Exactly twenty-seven
			// characters are read whatever stands behind the twenty-seventh, so
			// more text can neither lengthen this token nor take it away, and
			// the whole of the input is settled with the token in it.
			name:   "a whole personal token at the end of the input",
			src:    "dckr_pat_0123456789abcdef0123456789a",
			want:   []Span{{0, 36}},
			retain: 36,
		},
		{
			// The same claim where a run carries on past the count: the
			// twenty-eighth character belongs to no credential and the
			// twenty-ninth would not either, so this is settled where the
			// organization reading of the very same text answers nothing at
			// all.
			name:   "a personal token in a run still running at the end of the input",
			src:    "dckr_pat_0123456789abcdef0123456789ab",
			want:   []Span{{0, 36}},
			retain: 37,
		},
		{
			// A whole personal token with more text after it, ending in a byte
			// that opens no piece of a prefix, so nothing at the end of the
			// input is left unsettled.
			name:   "a whole personal token followed by settled text",
			src:    "dckr_pat_0123456789abcdef0123456789a tail",
			want:   []Span{{0, 36}},
			retain: len("dckr_pat_0123456789abcdef0123456789a tail"),
		},
		{
			// The organization kind reaches the same answer once its run is
			// closed by a character outside the alphabet: no text appended can
			// lengthen a run that has already ended.
			name:   "a whole organization token followed by settled text",
			src:    "dckr_oat_0123456789abcdef0123456789a tail",
			want:   []Span{{0, 36}},
			retain: len("dckr_oat_0123456789abcdef0123456789a tail"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := DockerAccessToken().Find(tt.src)
			if retain != tt.retain {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, retain, tt.retain)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DockerAccessToken_scanIsLinear(t *testing.T) {
	// A prefix is written in the alphabet its own body is read in, so a line of
	// prefixes is one unbroken run that holds a candidate for every nine
	// characters it has. The organization reading walks such a run to its end,
	// and walking it again at every candidate would cost time quadratic in the
	// length of the line — which is what the cursor over the run is for. The
	// bound here is far above a linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every thirty-six bytes where they are densest, because a sample
	// has to carry a whole token to be one. The crowding a line can actually
	// carry stays here.
	sources := map[string]string{
		// An anchor at every byte, none of them opening a candidate at all,
		// which is the cheapest way a position is declined.
		"an anchor every byte": strings.Repeat("k", 2000000),
		// The opening at every five characters, every one of them reaching the
		// kind and being turned away there.
		"an opening every five characters": strings.Repeat("dckr_", 400000),
		// Whole organization prefixes as close together as they go, inside one
		// run that every candidate in it would otherwise read to the end of.
		// This is the input the cursor is for.
		"an organization prefix every nine characters": strings.Repeat("dckr_oat_", 200000),
		// The same crowding under the personal kind, where a count rather than
		// a cursor is what bounds each candidate.
		"a personal prefix every nine characters": strings.Repeat("dckr_pat_", 200000),
		// The two kinds alternating, so that candidates of both readings are
		// crowded into the same run and the cursor is shared between them.
		"the two kinds alternating": strings.Repeat("dckr_oat_dckr_pat_", 100000),
		// One candidate whose body is the whole line, which is the walk that
		// reads a run to its end and finds a token at the far side of it.
		"a body that runs the length of the line": "dckr_oat_" + strings.Repeat("a", 1800000),
		// A token beginning inside every token before it, so every candidate
		// the scan opens is a token and none of the walks is wasted.
		"a token beginning inside every token": strings.Repeat("dckr_oat_0123456789abcdef0123456789a", 50000),
	}

	checkScanIsLinear(t, DockerAccessToken(), sources)
}

func Test_dockerAccessTokenPrefixes(t *testing.T) {
	// Every character of every prefix is one a body may be written in, which two
	// things rest on.
	//
	// The scan resumes one byte past the start of a candidate because a token can
	// begin inside the body of the one before it, and that holds only while a
	// prefix is written in a body's own alphabet. A prefix carrying a character
	// outside it would make the two impossible to nest, and the cases above
	// pinning the nesting would stand for nothing — which is not a failure
	// anything else here reports.
	//
	// The run cursor rests on the same claim, and it is the only thing it rests
	// on: a body read at a later candidate can fall behind one read at an
	// earlier candidate where two prefixes overlap, and what makes the remembered
	// run end the right answer from either of them is that the bytes between lie
	// inside a prefix and so inside the alphabet a run is read in. A prefix
	// carrying a character outside it would leave the cursor answering for a
	// stretch of run it never walked, and a token there would be missed rather
	// than mislocated.
	if len(dockerAccessTokenPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for _, prefix := range dockerAccessTokenPrefixes {
		for i := range len(prefix) {
			if c := prefix[i]; !isBase64URLByte(c) {
				t.Errorf("the prefix %q holds %q, which no body may be written with", prefix, c)
			}
		}
	}
}

// Test_dockerAccessTokenAnchor holds every prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_dockerAccessTokenAnchor(t *testing.T) {
	if dockerAccessTokenAnchorIndex >= len(dockerAccessTokenOpening) {
		t.Fatalf("the anchor stands at %d, the opening is %d characters", dockerAccessTokenAnchorIndex, len(dockerAccessTokenOpening))
	}
	for _, prefix := range dockerAccessTokenPrefixes {
		if c := prefix[dockerAccessTokenAnchorIndex]; c != dockerAccessTokenAnchor {
			t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", prefix, c, byte(dockerAccessTokenAnchor))
		}
	}
}

// Test_dockerAccessTokenPrefixes_areAllRead holds every prefix declared to being
// one the scan goes on to read a body behind. The prefixes decide what a Masker's
// filter lets through and what a stream holds on to, and the scan decides what is
// located; a prefix reaching the first and not the second is a pattern that keeps
// a stream waiting for a token it would never report.
//
// The body is as long as the longer of the two counts rather than as long as one
// of them, so that one value serves every prefix however far the counts move
// apart. What is asserted is that a span opens at the prefix and nothing about
// where it closes: where a body ends is each reading's own business and is
// written out case by case above, and a body built from one reading's count
// would fail here naming the wrong declaration the day the other's count moved.
func Test_dockerAccessTokenPrefixes_areAllRead(t *testing.T) {
	body := strings.Repeat("a", max(dockerAccessTokenPersonalBodyChars, dockerAccessTokenOrganizationBodyChars))
	for _, prefix := range dockerAccessTokenPrefixes {
		src := prefix + body
		got, _ := DockerAccessToken().Find(src)
		if len(got) == 0 || got[0].Start != 0 {
			t.Errorf("Find(%q) = %v, want a span opening at the prefix — %q opens a candidate the scan does not read", src, got, prefix)
		}
	}
}

// Test_dockerAccessTokenPrefixes_areBuiltFromTheKinds holds the two prefixes to
// being the opening, a kind and the separator rather than anything else. The
// prefixes are what the tail and the filter are built from and what the scan
// compares, so this is what keeps the kinds above load-bearing: a prefix respelled
// past its kind would leave the kind naming nothing.
func Test_dockerAccessTokenPrefixes_areBuiltFromTheKinds(t *testing.T) {
	kinds := []string{dockerAccessTokenPersonalKind, dockerAccessTokenOrganizationKind}
	if len(dockerAccessTokenPrefixes) != len(kinds) {
		t.Fatalf("the pattern declares %d prefixes for %d kinds", len(dockerAccessTokenPrefixes), len(kinds))
	}
	for i, prefix := range dockerAccessTokenPrefixes {
		if want := dockerAccessTokenOpening + kinds[i] + dockerAccessTokenSeparator; prefix != want {
			t.Errorf("the prefix %q is not %q, which its kind spells", prefix, want)
		}
	}
}

// Test_dockerAccessTokenPersonalChars holds the personal counts to the
// arithmetic the rationale reads them as: a body is the width twenty bytes come
// to in base64url with no padding, and a token is that with the prefix in front.
// The widths either side of twenty are checked as well, since it is those that
// make twenty-seven the width of one whole number of bytes and no other.
func Test_dockerAccessTokenPersonalChars(t *testing.T) {
	if got := base64.RawURLEncoding.EncodedLen(20); got != dockerAccessTokenPersonalBodyChars {
		t.Errorf("twenty bytes encode to %d characters, the body is read as %d", got, dockerAccessTokenPersonalBodyChars)
	}
	for _, n := range []int{19, 21} {
		if got := base64.RawURLEncoding.EncodedLen(n); got == dockerAccessTokenPersonalBodyChars {
			t.Errorf("%d bytes encode to %d characters as well, so the count names no one width", n, got)
		}
	}
	if want := len(dockerAccessTokenPersonalPrefix) + dockerAccessTokenPersonalBodyChars; dockerAccessTokenPersonalChars != want {
		t.Errorf("a token is read as %d characters, the prefix and the body come to %d", dockerAccessTokenPersonalChars, want)
	}
	if dockerAccessTokenPersonalChars != 36 {
		t.Errorf("a token is read as %d characters, the rationale says thirty-six", dockerAccessTokenPersonalChars)
	}
}

func Test_isDockerAccessTokenPersonalBody(t *testing.T) {
	// The count and the alphabet together, stated over every byte rather than
	// by example: a body is exactly dockerAccessTokenPersonalBodyChars
	// characters and each of them base64url.
	body := strings.Repeat("a", dockerAccessTokenPersonalBodyChars)

	if !isDockerAccessTokenPersonalBody(body) {
		t.Errorf("isDockerAccessTokenPersonalBody(%q) = false, want a body of %d characters to be one", body, dockerAccessTokenPersonalBodyChars)
	}
	for _, s := range []string{body[:len(body)-1], body + "a"} {
		if isDockerAccessTokenPersonalBody(s) {
			t.Errorf("isDockerAccessTokenPersonalBody(%q) = true, want only %d characters to be a body", s, dockerAccessTokenPersonalBodyChars)
		}
	}

	for c := range 256 {
		b := byte(c)
		src := body[:len(body)-1] + string([]byte{b})
		if got, want := isDockerAccessTokenPersonalBody(src), isBase64URLByte(b); got != want {
			t.Errorf("isDockerAccessTokenPersonalBody(%q) = %v with %q in it, want %v", src, got, b, want)
		}
	}
}

// referenceDockerAccessTokenFind is the statement of what a Docker access token
// is, written out the plain way and kept here so that the scan in
// builtin_docker_access_token.go can be held to it: every position is asked
// about in turn, with nothing remembered between them, and each kind is read the
// way its own paragraph of the rationale says.
//
// The prefixes, the counts and the alphabet are spelled again rather than built
// from dockerAccessTokenPrefixes, the counts beside them and isBase64URLByte. A
// reference sharing those declarations could not disagree with the scan about
// them, and it is exactly that disagreement the fuzz target below is for: the
// two have to be changed together or reported apart.
//
// It is written out rather than built on an expression, and what decided that
// was measurement. A floor spelled as a counted repetition costs an engine a
// machine as wide as the floor at every candidate, and candidates crowd as close
// as nine characters here because a prefix is written in its own body's
// alphabet. With dckr_oat_[0-9A-Za-z_-]{27,} standing where the walk below
// stands, this target ran seven hundred thousand executions in thirty seconds
// and reported none at all for stretches of that; the walk runs two and nine
// tenths million over the same thirty and never stalls. The walk costs a byte
// test where the engine costs a machine, which is what buys that back.
//
// Every position is asked about rather than resumed past, because a token can
// begin inside one: every character of both prefixes is written in the alphabet
// a body is, so a prefix twice over with a body behind it holds a token that
// resuming would step over. The scan finds both and reports the two spans
// overlapping for a Masker to resolve, so the reference must ask about both.
func referenceDockerAccessTokenFind(src string) []Span {
	var spans []Span
	for i := range len(src) {
		// A personal access token: the prefix and twenty-seven characters of
		// the alphabet, which is a token of thirty-six whatever stands behind
		// the twenty-seventh.
		if strings.HasPrefix(src[i:], "dckr_pat_") {
			body := i + len("dckr_pat_")
			if end := body + 27; end <= len(src) && isReferenceDockerAccessTokenBody(src[body:end]) {
				spans = append(spans, Span{Start: i, End: end})
			}
		}
		// An organization access token: the prefix and twenty-seven characters
		// of the alphabet at the least, read on to wherever the run of it ends.
		if strings.HasPrefix(src[i:], "dckr_oat_") {
			body := i + len("dckr_oat_")
			end := body
			for end < len(src) && isReferenceDockerAccessTokenByte(src[end]) {
				end++
			}
			if end-body >= 27 {
				spans = append(spans, Span{Start: i, End: end})
			}
		}
	}
	return spans
}

// isReferenceDockerAccessTokenBody reports whether s is every character of a
// body and nothing else.
func isReferenceDockerAccessTokenBody(s string) bool {
	for i := range len(s) {
		if !isReferenceDockerAccessTokenByte(s[i]) {
			return false
		}
	}
	return true
}

// isReferenceDockerAccessTokenByte reports whether c is a character a body may be
// written with: the letters of both cases, the digits, the hyphen and the
// underscore, spelled out here rather than read from the scan's own alphabet.
func isReferenceDockerAccessTokenByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z' ||
		c == '-' || c == '_'
}

// FuzzDockerAccessToken_matchesReference guards the hand-written scan: the
// prefixes it searches for, the counts it reads behind each of them, the
// alphabet it reads them in, the cursor it remembers a run by and the byte it
// resumes at may none of them change which tokens are located.
func FuzzDockerAccessToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("DOCKER_TOKEN=dckr_pat_0123456789abcdef0123456789a")
	f.Add("DOCKER_TOKEN=dckr_oat_0123456789abcdef0123456789a")
	f.Add("docker login -u myusername -p dckr_pat_0123456789abcdef0123456789a")
	f.Add(`{"token":"dckr_oat_0123456789abcdef0123456789a"}`)
	f.Add("dckr_oat_0123456789abcdef0123456789abcdef")   // the width the rulesets read
	f.Add("dckr_pat_0123456789abcdef-123456789_")        // a hyphen and an underscore in the body
	f.Add("dckr_oat_0123456789abcdef-123456789_")        //
	f.Add("dckr_pat_0123456789abcdef0123456789")         // one short of a token
	f.Add("dckr_oat_0123456789abcdef0123456789")         // and one short of the floor
	f.Add("dckr_pat_0123456789abcdef0123456789ab")       // a run longer than the count
	f.Add("dckr_oat_0123456789abcdef0123456789ab")       // and one longer than the floor
	f.Add("DCKR_PAT_0123456789abcdef0123456789a")        // an uppercase prefix
	f.Add("DCKR_OAT_0123456789abcdef0123456789a")        //
	f.Add("dckr-pat-0123456789abcdef0123456789a")        // hyphens where it carries underscores
	f.Add("dckr_pat0123456789abcdef0123456789ab")        // the underscore that closes it left out
	f.Add("dckr_xyz_0123456789abcdef0123456789a")        // a kind Docker does not write
	f.Add("dckr_pat_0123456789abcdef+123456789/")        // standard base64 rather than base64url
	f.Add("dckr_oat_0123456789abcdef.123456789a")        // a dot ends the run short of the floor
	f.Add("dckr_pat_0123456789abcdef 123456789a")        // and a space
	f.Add("dckr_oat_0123456789abcdef0123456789a-suffix") // a body character joins what follows
	f.Add("dckr_pat_0123456789abcdef0123456789a.next")
	f.Add("dckr_oat_0123456789abcdef0123456789a\ndckr_oat_0123456789abcdef0123456789a")
	// A token beginning inside the match before it, which a scan resuming past
	// a match steps over, and two tokens with nothing between them, which is
	// the same text without the overlap. Both kinds, and one inside the other.
	f.Add("dckr_pat_dckr_pat_0123456789abcdef0123456789a")
	f.Add("dckr_oat_dckr_oat_0123456789abcdef0123456789a")
	f.Add("dckr_pat_dckr_oat_0123456789abcdef0123456789a")
	f.Add("dckr_oat_dckr_pat_0123456789abcdef0123456789a")
	f.Add("dckr_pat_0123456789abcdef0123456789adckr_pat_0123456789abcdef0123456789a")
	f.Add("dckr_oat_0123456789abcdef0123456789adckr_oat_0123456789abcdef0123456789a")
	f.Add("dckr_pat_0123456789abcdef0123456789adckr_oat_0123456789abcdef0123456789a")
	f.Add(strings.Repeat("dckr_pat_", 8))
	f.Add(strings.Repeat("dckr_oat_", 8))
	// Candidate positions crowded as close as they can be: every ninth byte,
	// and a run that is a body to every candidate in it. The second kind is
	// where the cursor answers, so the same crowding is driven under it and
	// under both kinds at once.
	f.Add(strings.Repeat("dckr_pat_", 32))
	f.Add(strings.Repeat("dckr_oat_", 32))
	f.Add(strings.Repeat("dckr_oat_", 32) + "!")
	f.Add(strings.Repeat("dckr_oat_dckr_pat_", 16))
	f.Add("dckr_oat_" + strings.Repeat("a", 200))
	// The prefix written inside a run of the alphabet, which is the over-match
	// the pattern admits, and the same run where a JWT signature stands.
	f.Add("payload=zzzzdckr_pat_0123456789abcdef0123456789azzzz")
	f.Add("payload=zzzzdckr_oat_0123456789abcdef0123456789azzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.dckr_pat_0123456789abcdef0123456789a")

	fuzzAgainstReference(f, DockerAccessToken().Find, referenceDockerAccessTokenFind)
}

// dockerAccessTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func dockerAccessTokenFindBenchmarks() []benchmarkCase {
	// The vendor's own host name carries the byte the scan searches for, so
	// this line is the shape that costs the search most while holding no token:
	// one candidate opened and turned away on the character in front of it.
	line := `time=2026-08-17T00:00:00Z level=info msg="pushing an image" url=https://hub.docker.com/v2/repositories/library/nginx/tags `
	personal := "dckr_pat_0123456789abcdef0123456789a"
	organization := "dckr_oat_0123456789abcdef0123456789a"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A prefix is nine characters a body is written with, so a run can
			// hold a candidate for every nine it has. Here each of them reads
			// as far as the character that is not one, which stands where the
			// run ends: the crowding this pattern admits, with no value at the
			// end of any of it.
			name:  "candidates that are not values",
			src:   strings.Repeat("dckr_pat_dckr_pat_dckr_pat_.", 16),
			spans: 0,
		},
		{
			// The same crowding under the kind whose body is read to the end of
			// its run, which is what the cursor is timed on.
			name:  "organization candidates that are not values",
			src:   strings.Repeat("dckr_oat_dckr_oat_dckr_oat_.", 16),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "token=" + personal,
			spans: 1,
		},
		{
			name:  "one organization value",
			src:   line + "token=" + organization,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "token=" + personal,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"token="+personal+"\n", 32),
			spans: 32,
		},
		{
			name:  "many organization values",
			src:   strings.Repeat(line+"token="+organization+"\n", 32),
			spans: 32,
		},
	}
}
