package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Grafana service account token pattern: what it locates and what it leaves
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
// shape, obviously not real. The secret is 0123456789abcdef written twice,
// which is thirty-two characters and so is a whole one, and the checksum is
// 01234567, which is eight and so is a whole one too. Written out with the
// prefix and the underscore between them they come to the forty-six characters
// the example in Grafana's own documentation is.

func Test_GrafanaServiceAccountToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "glsa_0123456789abcdef0123456789abcdef_01234567",
			want: []Span{{0, 46}},
		},
		{
			name: "a token in an environment assignment",
			src:  "GRAFANA_TOKEN=glsa_0123456789abcdef0123456789abcdef_01234567",
			want: []Span{{14, 60}},
		},
		{
			// The secret is what util.GetRandomString draws from the letters of
			// both cases and the digits, so an uppercase secret is as ordinary
			// as a lowercase one; the checksum is hexadecimal, read in either
			// case for the reason builtin_grafana_service_account_token.go
			// gives.
			name: "an uppercase secret and checksum",
			src:  "glsa_0123456789ABCDEF0123456789ABCDEF_0123ABCD",
			want: []Span{{0, 46}},
		},
		{
			// The counts are read exactly, so what follows the forty-sixth
			// character is not part of the token and stays in the text.
			name: "a checksum run longer than the count is a token and what follows it",
			src:  "glsa_0123456789abcdef0123456789abcdef_012345678",
			want: []Span{{0, 46}},
		},
		{
			// Neither token is inside the other, and nothing separates them.
			name: "two tokens with nothing between them",
			src:  "glsa_0123456789abcdef0123456789abcdef_01234567glsa_0123456789abcdef0123456789abcdef_01234567",
			want: []Span{{0, 46}, {46, 92}},
		},
		{
			// A secret whose last four characters are glsa opens a candidate
			// four characters before that secret ends: the underscore it reads
			// as the end of its prefix is the one dividing the first token's
			// secret from its checksum, and that checksum and the twenty-four
			// characters written after the token are a secret of its own. A
			// scan resuming past a match would step over this token and leave
			// it in the output whole. The spans overlap, which a Masker
			// resolves into one.
			name: "a token beginning inside the token before it",
			src:  "glsa_0123456789abcdef0123456789abglsa_012345670123456789abcdef01234567_89abcdef",
			want: []Span{{0, 46}, {33, 79}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := GrafanaServiceAccountToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GrafanaServiceAccountToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "glsa_",
		},
		{
			name: "a secret with no checksum behind it",
			src:  "glsa_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a secret and a separator with no checksum behind them",
			src:  "glsa_0123456789abcdef0123456789abcdef_",
		},
		{
			// Thirty-one characters where the pattern asks for thirty-two, and
			// so a separator one character too early.
			name: "a secret one character too short",
			src:  "glsa_0123456789abcdef0123456789abcde_01234567",
		},
		{
			// Thirty-three, and so a separator one character too late.
			name: "a secret one character too long",
			src:  "glsa_0123456789abcdef0123456789abcdef0_01234567",
		},
		{
			name: "a checksum one character too short",
			src:  "glsa_0123456789abcdef0123456789abcdef_0123456",
		},
		{
			// The underscore is the one character of the format that is not in
			// the secret's alphabet, so nothing else divides the two.
			name: "a hyphen where the separator belongs",
			src:  "glsa_0123456789abcdef0123456789abcdef-01234567",
		},
		{
			name: "a dot where the separator belongs",
			src:  "glsa_0123456789abcdef0123456789abcdef.01234567",
		},
		{
			name: "a hyphen where the prefix carries its underscore",
			src:  "glsa-0123456789abcdef0123456789abcdef_01234567",
		},
		{
			// The secret is base62, so the underscore that ends it cannot stand
			// inside it: a second one thirty-two characters along is not
			// reached, because the run ended at the first.
			name: "an underscore inside the secret",
			src:  "glsa_0123456789abcdef_123456789abcdef_01234567",
		},
		{
			// Neither character base64url adds beyond base62 is admitted.
			name: "a hyphen inside the secret",
			src:  "glsa_0123456789abcdef-123456789abcdef_01234567",
		},
		{
			// The checksum is four bytes of a CRC32 written in hexadecimal, so
			// the letters it may carry stop at f.
			name: "a letter past f in the checksum",
			src:  "glsa_0123456789abcdef0123456789abcdef_0123456g",
		},
		{
			name: "an uppercase letter past F in the checksum",
			src:  "glsa_0123456789abcdef0123456789abcdef_0123456G",
		},
		{
			name: "a token broken by a space",
			src:  "glsa_0123456789abcdef0123456789 abcdef_01234567",
		},
		{
			name: "a token broken by a line break",
			src:  "glsa_0123456789abcdef0123456789abcdef_\n1234567",
		},
		{
			name: "an uppercase prefix",
			src:  "GLSA_0123456789abcdef0123456789abcdef_01234567",
		},
		{
			// Forty-six characters of the right shape opening with something
			// else. The prefix is the whole of the anchor.
			name: "a value of the right shape opening with no prefix",
			src:  "xxxx_0123456789abcdef0123456789abcdef_01234567",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// No word is spelled glsa, so no snake_case name reaches the prefix
			// however it is written.
			name: "a snake_case name whose segment is nearly the prefix",
			src:  "gls_0123456789abcdef0123456789abcdef_01234567",
		},
		{
			// A base64url payload can hold every character of the prefix, and
			// still has to carry the second underscore exactly thirty-two
			// characters behind the first.
			name: "the prefix with a second underscore at the wrong distance",
			src:  "glsa_0123456789abcdef_0123456789abcdef_0123456789abcdef",
		},
		{
			// The excluded characters above all stand in the middle of the
			// secret or the checksum. These stand at the secret's first
			// character, straight behind the prefix.
			name: "a hyphen at the first character of the secret",
			src:  "glsa_-123456789abcdef0123456789abcdef_01234567",
		},
		{
			name: "a dot at the first character of the secret",
			src:  "glsa_.123456789abcdef0123456789abcdef_01234567",
		},
		{
			// And this one stands inside the checksum rather than at its
			// last character, which is the only position driven elsewhere in
			// this file.
			name: "a hyphen inside the checksum",
			src:  "glsa_0123456789abcdef0123456789abcdef_0123-567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := GrafanaServiceAccountToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_GrafanaServiceAccountToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "GRAFANA_TOKEN=glsa_0123456789abcdef0123456789abcdef_01234567",
			want: "GRAFANA_TOKEN=**********************************************",
		},
		{
			// How a token reaches the API, and how it reaches a log line that
			// echoed the header.
			name: "a bearer token header",
			src:  "Authorization: Bearer glsa_0123456789abcdef0123456789abcdef_01234567",
			want: "Authorization: Bearer **********************************************",
		},
		{
			// The response a token is first read out of, which is the only
			// place Grafana ever shows it.
			name: "the response that first reports it",
			src:  `{"id":2,"name":"my-service-account-token","key":"glsa_0123456789abcdef0123456789abcdef_01234567"}`,
			want: `{"id":2,"name":"my-service-account-token","key":"**********************************************"}`,
		},
		{
			name: "a command line",
			src:  "curl -H 'Authorization: Bearer glsa_0123456789abcdef0123456789abcdef_01234567' https://example.grafana.net/api/org",
			want: "curl -H 'Authorization: Bearer **********************************************' https://example.grafana.net/api/org",
		},
		{
			name: "twice",
			src:  "glsa_0123456789abcdef0123456789abcdef_01234567 glsa_0123456789ABCDEF0123456789ABCDEF_0123ABCD",
			want: "********************************************** **********************************************",
		},
		{
			// The two spans are merged, so the token that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a token beginning inside the token before it",
			src:  "glsa_0123456789abcdef0123456789abglsa_012345670123456789abcdef01234567_89abcdef",
			want: "*******************************************************************************",
		},
	}

	m := New(WithPatterns(GrafanaServiceAccountToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GrafanaServiceAccountToken_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the token through whole. The first of them is also
	// what the tightening the Slack and Stripe scans take would cost here,
	// which builtin_grafana_service_account_token.go weighs against what it
	// would buy — which, since no word closes on glsa, is nothing.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "xglsa_0123456789abcdef0123456789abcdef_01234567",
			want: "x**********************************************",
		},
		{
			name: "underscore before",
			src:  "GRAFANA_TOKEN_glsa_0123456789abcdef0123456789abcdef_01234567",
			want: "GRAFANA_TOKEN_**********************************************",
		},
		{
			// The third class of word character neither of the two above
			// is: a bare digit immediately in front of the prefix.
			name: "digit before",
			src:  "0glsa_0123456789abcdef0123456789abcdef_01234567",
			want: "0**********************************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this token
			// rather than trim it; without one the forty-six characters Grafana
			// issued are redacted and the one written after them, which is part
			// of no credential, stays in the text.
			name: "a character of the checksum's class after",
			src:  "glsa_0123456789abcdef0123456789abcdef_012345678",
			want: "**********************************************8",
		},
	}

	m := New(WithPatterns(GrafanaServiceAccountToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GrafanaServiceAccountToken_leavesWhatFollowsAlone(t *testing.T) {
	// A token is forty-six characters and no more, so what is written after one
	// stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the token is glsa_0123456789abcdef0123456789abcdef_01234567.",
			want: "the token is **********************************************.",
		},
		{
			name: "quoted",
			src:  `"glsa_0123456789abcdef0123456789abcdef_01234567"`,
			want: `"**********************************************"`,
		},
		{
			// The hyphen belongs to neither the secret's alphabet nor the
			// checksum's, so a hyphenated word written against a token is left
			// where it stands.
			name: "dashed word",
			src:  "glsa_0123456789abcdef0123456789abcdef_01234567-suffix",
			want: "**********************************************-suffix",
		},
		{
			// The underscore belongs to neither alphabet either, however much
			// of the format is written with one: the count is what ends a
			// token, so an underscored word against one is left where it
			// stands as a hyphenated one is.
			name: "underscored word",
			src:  "glsa_0123456789abcdef0123456789abcdef_01234567_tail",
			want: "**********************************************_tail",
		},
		{
			// A multi-byte rune written against the token on both sides.
			// Neither its UTF-8 encoding nor a byte of it belongs to the
			// prefix, the secret's alphabet or the checksum's, so the
			// token keeps its span exactly as it does against a
			// single-byte character.
			name: "a multi-byte rune before and after",
			src:  "日本語glsa_0123456789abcdef0123456789abcdef_01234567日本語",
			want: "日本語**********************************************日本語",
		},
		{
			name: "an invalid byte before and after",
			src:  "\xffglsa_0123456789abcdef0123456789abcdef_01234567\xff",
			want: "\xff**********************************************\xff",
		},
	}

	m := New(WithPatterns(GrafanaServiceAccountToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GrafanaServiceAccountToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision a prefix invites is a digest written behind it, and this
	// format rules it out rather than paying for it. Hexadecimal digits are
	// base62 and a digest carries nothing that ends a run, so a scan whose body
	// is one class reads a digest as a body and says so; here the character
	// thirty-two past the prefix has to be the underscore dividing the secret
	// from the checksum, and a digest holds none.
	//
	// What is still located is a digest divided where a token divides: the
	// tokens the rest of this file is written with are exactly that, thirty-two
	// hexadecimal characters and eight more with an underscore between them,
	// and redacting them is right for the reason the count is read at all —
	// such a run is a token's format exactly, so declining it would decline
	// every token Grafana happened to write in the digits and the first six
	// letters.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// Sixty-four hexadecimal characters, which is more than a body
			// needs, so nothing but the separator turns this away.
			name: "a sha-256 behind the prefix",
			src:  "glsa_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// Forty characters, which is one short of a body as well as
			// carrying no separator.
			name: "a sha-1 behind the prefix",
			src:  "glsa_0123456789abcdef0123456789abcdef01234567",
		},
		{
			// Thirty-two, which is the length of a secret with nothing behind
			// it to be the separator.
			name: "an md5 behind the prefix",
			src:  "glsa_0123456789abcdef0123456789abcdef",
		},
		{
			// A digest carries no underscore, so it holds no prefix to be found
			// at however long it runs.
			name: "a digest on its own",
			src:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a digest and a checksum with an underscore between them",
			src:  "glsa_0123456789abcdef0123456789abcdef_01234567",
			want: []Span{{0, 46}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := GrafanaServiceAccountToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GrafanaServiceAccountToken_checksumIsNotVerified(t *testing.T) {
	// The eight characters behind the second underscore are the CRC32 of the
	// thirty-seven in front of them, and Grafana's own Decode recomputes it
	// before accepting a token. This scan reads them as a shape and stops
	// there, which builtin_grafana_service_account_token.go weighs: a token
	// whose secret is intact and whose checksum was mistyped or truncated is
	// still a secret somebody can read, and a scan verifying the checksum would
	// leave every one of them in the output.
	//
	// The two inputs below carry the same secret and different checksums. At
	// most one of them can be the CRC32 of that secret, so a scan locating both
	// is one that did not compute it — which is what the decision here means,
	// stated without this file having to hold a checksum it computed.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "one checksum",
			src:  "glsa_0123456789abcdef0123456789abcdef_01234567",
		},
		{
			name: "another over the same secret",
			src:  "glsa_0123456789abcdef0123456789abcdef_89abcdef",
		},
	}

	want := []Span{{0, 46}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := GrafanaServiceAccountToken().Find(tt.src); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, want)
			}
		})
	}
}

func Test_GrafanaServiceAccountToken_theCloudPrefix(t *testing.T) {
	// The other credential Grafana issues under a gl prefix is a Grafana Cloud
	// access policy token, which opens with glc_ and carries the base64 of a
	// JSON object behind it. It is not read, and
	// builtin_grafana_service_account_token.go says why: the object names the
	// token, so the encoding is as long as whoever created the token made it,
	// nothing published states a length, and the three rulesets reading one
	// read three different ranges. The decision is pinned here so that reading
	// glc_ is a change somebody argues for rather than one somebody notices
	// afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "an access policy token",
			src:  "glc_eyJ0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "one in an environment assignment",
			src:  "GRAFANA_CLOUD_TOKEN=glc_eyJ0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := GrafanaServiceAccountToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

// Test_GrafanaServiceAccountToken_holdsATokenTheInputCutShort states, with a
// literal number, what the second return of Find settles: a piece of the
// prefix standing at the end of the input, a candidate the end of the input
// cut short, and a whole match with nothing left unsettled behind it.
func Test_GrafanaServiceAccountToken_holdsATokenTheInputCutShort(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		want   []Span
		retain int
	}{
		{
			// A piece of the prefix stands at the end of the input: it
			// could still grow into "glsa_" with one more byte, so nothing
			// behind where it opens is settled.
			name:   "a piece of the prefix at the end of the input",
			src:    "level=info token=glsa",
			retain: len("level=info token="),
		},
		{
			// A whole prefix and a secret the input cuts short before the
			// count is met.
			name:   "a secret the input cuts short of the count",
			src:    "level=info token=glsa_0123456789abcdef012",
			retain: len("level=info token="),
		},
		{
			// A whole token with more text after it, ending in a byte
			// that opens no piece of the prefix, so nothing at the end of
			// the input is left unsettled.
			name:   "a whole token followed by settled text",
			src:    "glsa_0123456789abcdef0123456789abcdef_01234567 tail",
			want:   []Span{{0, 46}},
			retain: len("glsa_0123456789abcdef0123456789abcdef_01234567 tail"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := GrafanaServiceAccountToken().Find(tt.src)
			if retain != tt.retain {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, retain, tt.retain)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_grafanaServiceAccountTokenPrefix(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a token
	// can begin inside the one before it, and that holds on what the prefix is
	// made of: the characters in front of its last one are ones a secret is
	// written with, and its last one is the separator a token already carries.
	// A prefix built any other way would make the two impossible to nest, and
	// the case above pinning the nesting would stand for nothing — which is not
	// a failure anything else here reports.
	if grafanaServiceAccountTokenPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	if c := grafanaServiceAccountTokenPrefix[len(grafanaServiceAccountTokenPrefix)-1]; c != grafanaServiceAccountTokenSeparator {
		t.Errorf("the prefix closes with %q, want the separator %q", c, grafanaServiceAccountTokenSeparator)
	}
	for i := range len(grafanaServiceAccountTokenPrefix) - 1 {
		if c := grafanaServiceAccountTokenPrefix[i]; !isBase62Byte(c) {
			t.Errorf("the prefix holds %q, which no secret may be written with", c)
		}
	}

	// The separator ends a secret where it stands, which is what makes the
	// count either side of it readable at all and what turns away every digest
	// written behind the prefix.
	if isBase62Byte(grafanaServiceAccountTokenSeparator) {
		t.Errorf("the separator %q belongs to the alphabet a secret is written in", grafanaServiceAccountTokenSeparator)
	}
	if isGrafanaServiceAccountTokenChecksumByte(grafanaServiceAccountTokenSeparator) {
		t.Errorf("the separator %q belongs to the class a checksum is written in", grafanaServiceAccountTokenSeparator)
	}
}

// Test_grafanaServiceAccountTokenAnchor holds the prefix to carrying the byte
// the scan searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_grafanaServiceAccountTokenAnchor(t *testing.T) {
	if grafanaServiceAccountTokenAnchorIndex >= len(grafanaServiceAccountTokenPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", grafanaServiceAccountTokenAnchorIndex, len(grafanaServiceAccountTokenPrefix))
	}
	if c := grafanaServiceAccountTokenPrefix[grafanaServiceAccountTokenAnchorIndex]; c != grafanaServiceAccountTokenAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(grafanaServiceAccountTokenAnchor))
	}
}

func Test_grafanaServiceAccountTokenChars(t *testing.T) {
	// Forty-six is what the two counts come to with the prefix and the
	// separator in front of them, and what the example in Grafana's own
	// documentation is. The counts themselves are the generator's — thirty-two
	// is the length it asks util.GetRandomString for and eight is what four
	// bytes of a CRC32 come to in hexadecimal — so this is what holds them to
	// still totalling the length a published token has.
	const documented = 46
	if grafanaServiceAccountTokenChars != documented {
		t.Errorf("a token is read as %d characters, the documented example is %d", grafanaServiceAccountTokenChars, documented)
	}
}

func Test_isGrafanaServiceAccountTokenChecksumByte(t *testing.T) {
	// The hexadecimal digits and nothing else, stated over every byte rather
	// than by example. Either case is admitted where the generator writes
	// lowercase alone, which builtin_grafana_service_account_token.go weighs.
	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9' || 'a' <= b && b <= 'f' || 'A' <= b && b <= 'F'
		if got := isGrafanaServiceAccountTokenChecksumByte(b); got != want {
			t.Errorf("isGrafanaServiceAccountTokenChecksumByte(%q) = %v, want %v", b, got, want)
		}
	}
}

func Test_isGrafanaServiceAccountTokenBody(t *testing.T) {
	// The counts, the separator and the two character classes together, stated
	// over every byte rather than by example.
	secret := strings.Repeat("a", grafanaServiceAccountTokenSecretChars)
	checksum := strings.Repeat("b", grafanaServiceAccountTokenChecksumChars)
	body := secret + string(grafanaServiceAccountTokenSeparator) + checksum

	if !isGrafanaServiceAccountTokenBody(body) {
		t.Errorf("isGrafanaServiceAccountTokenBody(%q) = false, want a body of %d characters to be one", body, grafanaServiceAccountTokenBodyChars)
	}
	for _, s := range []string{body[:len(body)-1], body + "b"} {
		if isGrafanaServiceAccountTokenBody(s) {
			t.Errorf("isGrafanaServiceAccountTokenBody(%q) = true, want only %d characters to be a body", s, grafanaServiceAccountTokenBodyChars)
		}
	}

	// Every position of the body, byte by byte: the separator's position admits
	// the separator alone, the secret's positions the alphabet alone, and the
	// checksum's the hexadecimal digits alone.
	for i := range grafanaServiceAccountTokenBodyChars {
		for c := range 256 {
			b := byte(c)
			src := body[:i] + string([]byte{b}) + body[i+1:]

			var want bool
			switch {
			case i < grafanaServiceAccountTokenSecretChars:
				want = isBase62Byte(b)
			case i == grafanaServiceAccountTokenSecretChars:
				want = b == grafanaServiceAccountTokenSeparator
			default:
				want = isGrafanaServiceAccountTokenChecksumByte(b)
			}
			if got := isGrafanaServiceAccountTokenBody(src); got != want {
				t.Errorf("isGrafanaServiceAccountTokenBody(%q) = %v with %q at %d, want %v", src, got, b, i, want)
			}
		}
	}
}

// referenceGrafanaServiceAccountToken is the expression the scan in
// builtin_grafana_service_account_token.go reads by hand: the statement of what
// a Grafana service account token is, kept here so that the scan can be held to
// it.
//
// The prefix, the two counts, the separator and the two character classes are
// spelled again rather than built from grafanaServiceAccountTokenPrefix,
// grafanaServiceAccountTokenSecretChars,
// grafanaServiceAccountTokenChecksumChars, grafanaServiceAccountTokenSeparator,
// isBase62Byte and isGrafanaServiceAccountTokenChecksumByte. A reference
// sharing those declarations could not disagree with the scan about them, and
// it is exactly that disagreement the fuzz target below is for: the two have to
// be changed together or reported apart.
//
// The counted repetitions here are thirty-two and eight, so the machine an
// engine builds for a candidate is forty states wide and bounded, and the
// prefix in front of them is one literal, which is what an engine searches the
// text for. That is what lets this reference be an expression at all, where the
// Anthropic one is written out for a floor spelled as a counted repetition and
// the Notion one for an alternation of two literals.
var referenceGrafanaServiceAccountToken = regexp.MustCompile(`glsa_[0-9A-Za-z]{32}_[0-9A-Fa-f]{8}`)

// referenceGrafanaServiceAccountTokenFind locates tokens the plain way: the
// leftmost match of the expression above, then the leftmost one beginning after
// that match's first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a token can begin inside one: the four letters of
// the prefix belong to the alphabet a secret is written in and the underscore
// behind them is the separator a token already carries, so a secret closing with
// glsa opens a candidate the engine would never go on to try. The scan finds
// both and reports the two spans overlapping for a Masker to resolve, so the
// reference must ask about both.
//
// Resuming a byte along costs this one nothing beyond a constant: every
// candidate reads at most forty-six characters, here as in the scan, so
// neither has a run to walk and there is no cursor for either to be wrong
// about.
func referenceGrafanaServiceAccountTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceGrafanaServiceAccountToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzGrafanaServiceAccountToken_matchesReference guards the hand-written scan:
// the prefix it searches for, the two counts it reads behind that prefix, the
// separator between them, the two character classes it reads them in and the
// byte it resumes at may none of them change which tokens are located.
func FuzzGrafanaServiceAccountToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("GRAFANA_TOKEN=glsa_0123456789abcdef0123456789abcdef_01234567")
	f.Add("glsa_0123456789ABCDEF0123456789ABCDEF_0123ABCD")  // an uppercase secret and checksum
	f.Add("glsa_0123456789abcdef0123456789abcde_01234567")   // a secret one short
	f.Add("glsa_0123456789abcdef0123456789abcdef0_01234567") // and one long
	f.Add("glsa_0123456789abcdef0123456789abcdef_0123456")   // a checksum one short
	f.Add("glsa_0123456789abcdef0123456789abcdef_012345678") // and a run longer than one
	f.Add("glsa_0123456789abcdef0123456789abcdef-01234567")  // a hyphen where the separator belongs
	f.Add("glsa-0123456789abcdef0123456789abcdef_01234567")  // a hyphen where the prefix carries its underscore
	f.Add("glsa_0123456789abcdef_123456789abcdef_01234567")  // an underscore inside the secret
	f.Add("glsa_0123456789abcdef-123456789abcdef_01234567")  // and a hyphen
	f.Add("glsa_0123456789abcdef0123456789abcdef_0123456g")  // a letter past f in the checksum
	f.Add("GLSA_0123456789abcdef0123456789abcdef_01234567")  // an uppercase prefix
	f.Add("glsa_0123456789abcdef0123456789abcdef_\n1234567")
	f.Add("xglsa_0123456789abcdef0123456789abcdef_01234567")
	// A digest behind the prefix, which the separator turns away, and one long
	// enough that nothing else could have.
	f.Add("glsa_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// A token beginning inside the match before it, which a scan resuming past
	// a match steps over, and two tokens with nothing between them, which is
	// the same text without the overlap.
	f.Add("glsa_0123456789abcdef0123456789abglsa_012345670123456789abcdef01234567_89abcdef")
	f.Add("glsa_0123456789abcdef0123456789abcdef_01234567glsa_0123456789abcdef0123456789abcdef_01234567")
	// Candidate positions crowded as close as they can be, and a run of
	// separators, which is where the count either side of one is decided.
	f.Add(strings.Repeat("glsa_", 32))
	f.Add(strings.Repeat("glsa_", 32) + "0123456789abcdef0123456789abcdef_01234567")
	f.Add(strings.Repeat("glsa_0123456789abcdef0123456789abcdef_", 8))
	f.Add(strings.Repeat("_", 128))
	// The Grafana Cloud access policy token this pattern declines to read.
	f.Add("glc_eyJ0123456789abcdef0123456789abcdef0123456789abcdef")

	fuzzAgainstReference(f, GrafanaServiceAccountToken().Find, referenceGrafanaServiceAccountTokenFind)
}

// grafanaServiceAccountTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func grafanaServiceAccountTokenFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://example.grafana.net/api/org `
	token := "glsa_0123456789abcdef0123456789abcdef_01234567"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is five characters, so a run of them holds a candidate
			// for every five it has. Each of these is turned away by the one
			// comparison the separator's position costs, which is the cheapest
			// this scan declines a candidate for and the way every digest
			// behind the prefix is declined.
			name:  "candidates that are not values",
			src:   strings.Repeat("glsa_", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: a secret of the right length and
			// a separator where one belongs, so the whole of the checksum is
			// walked before its last character turns the candidate away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("glsa_0123456789abcdef0123456789abcdef_0123456g ", 16),
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
