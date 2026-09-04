package mask

import (
	"slices"
	"strings"
	"testing"
)

// The Sentry auth token pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. A hexadecimal body is 0123456789abcdef four times
// over, which is the sixty-four characters thirty-two random bytes come to. An
// organization token's payload is 0123456789abcdefghijklmnopqrstuv, which is
// thirty-two characters and so is a multiple of base64's group, and its secret
// is 0123456789abcdefghijklmnopqrstuvwxyzABCDEFG, which is the forty-three
// characters thirty-two random bytes come to in base64 without padding.

func Test_SentryAuthToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a user token on its own",
			src:  "sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 71}},
		},
		{
			name: "a user token in an environment assignment",
			src:  "SENTRY_AUTH_TOKEN=sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{18, 89}},
		},
		{
			name: "a user application token",
			src:  "sntrya_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 71}},
		},
		{
			name: "an internal integration token",
			src:  "sntryi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 71}},
		},
		{
			name: "an organization token on its own",
			src:  "sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: []Span{{0, 83}},
		},
		{
			// The payload carries its padding, where the secret is written
			// without any: Sentry strips it there and sentry-cli reads the
			// secret with a codec admitting none. One padding character and two
			// are both what base64 can call for.
			name: "an organization token whose payload closes with one padding character",
			src:  "sntrys_0123456789abcdefghijklmnopqrstu=_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: []Span{{0, 83}},
		},
		{
			name: "an organization token whose payload closes with two",
			src:  "sntrys_0123456789abcdefghijklmnopqrst==_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: []Span{{0, 83}},
		},
		{
			// The alphabet is the standard base64 one and not base64url, so the
			// two characters that tell them apart are + and /. Both stand in the
			// tokens Sentry, sentry-cli and gitleaks publish.
			name: "a plus and a slash in each segment",
			src:  "sntrys_0123456789abcdefghijklmnopqrs+/v_0123456789abcdefghijklmnopqrstuvwxyzABCDE+/",
			want: []Span{{0, 83}},
		},
		{
			// The counts are read exactly, so what follows the last character
			// of a body is not part of the token and stays in the text.
			name: "a hexadecimal run longer than a body is a token and what follows it",
			src:  "sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefa",
			want: []Span{{0, 71}},
		},
		{
			name: "a base64 run longer than a secret is a token and what follows it",
			src:  "sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH",
			want: []Span{{0, 83}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefsntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: []Span{{0, 71}, {71, 154}},
		},
		{
			// A payload closing with sntrys hands the separator behind it to a
			// second candidate, whose own payload is then the secret of the
			// first. A scan resuming past a match would step over that token and
			// leave it in the output whole. The spans overlap, which a Masker
			// resolves into one.
			name: "an organization token beginning inside the payload of another",
			src:  "sntrys_0123456789abcdef0123456789sntrys_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: []Span{{0, 83}, {33, 128}},
		},
		{
			// The same nesting across the two shapes: a payload closing with
			// sntryu opens a candidate whose body is hexadecimal, and the first
			// forty-three characters of that body are the secret of the token
			// it stands inside.
			name: "a user token beginning inside the payload of an organization token",
			src:  "sntrys_0123456789abcdef0123456789sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 83}, {33, 104}},
		},
		{
			// The shortest a payload can be written: one whole group of four,
			// no padding. A floor demanding thirty-two or more characters, or
			// eight or more, would pass every other case in this file but
			// locate nothing here.
			name: "an organization token whose payload is one group of four",
			src:  "sntrys_0123_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: []Span{{0, 55}},
		},
		{
			// The same floor, written with two padding characters closing the
			// one group.
			name: "an organization token whose payload closes with two padding characters and is otherwise the shortest one can be",
			src:  "sntrys_01==_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: []Span{{0, 55}},
		},
		{
			// The base64 of an actual Sentry payload object — naming the
			// organization, the url and the region url — rather than a
			// payload shortened for readability. A cap between forty-five and
			// a hundred and twenty-four characters would pass every other
			// case here and locate nothing in this one.
			name: "an organization token whose payload is the base64 of a payload object",
			src:  "sntrys_eyJpYXQiOjE3MDAwMDAwMDAsInVybCI6Imh0dHBzOi8vc2VudHJ5LmlvIiwicmVnaW9uX3VybCI6Imh0dHBzOi8vdXMuc2VudHJ5LmlvIiwib3JnIjoiYWNtZSJ9_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: []Span{{0, 175}},
		},
		{
			// A hexadecimal run one character longer than an internal
			// integration body, which the exact count reads as the token and
			// the character after it — driven for sntryi_ rather than only
			// for sntryu_.
			name: "a hexadecimal run longer than an internal integration body",
			src:  "sntryi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefa",
			want: []Span{{0, 71}},
		},
		{
			// Two organization tokens with nothing between them. Unlike a
			// hexadecimal body, a payload's own alphabet holds every letter
			// standing in front of it, so the first token's secret does not
			// stop the run on its own; the exact count is what cuts it where
			// the second token's prefix begins.
			name: "two organization tokens with nothing between them",
			src:  "sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGsntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: []Span{{0, 83}, {83, 166}},
		},
		{
			// A token immediately against a multi-byte rune on both sides, of
			// each of the two shapes.
			name: "a user token between japanese",
			src:  "トークンはsntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefです",
			want: []Span{{15, 86}},
		},
		{
			name: "an organization token between japanese",
			src:  "トークンはsntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGです",
			want: []Span{{15, 98}},
		},
		{
			name: "a user token against an invalid byte",
			src:  "\xffsntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\xff",
			want: []Span{{1, 72}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SentryAuthToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SentryAuthToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a user prefix alone",
			src:  "sntryu_",
		},
		{
			name: "an organization prefix alone",
			src:  "sntrys_",
		},
		{
			name: "the opening with no kind or separator behind it",
			src:  "sntry",
		},
		{
			// Sixty-three characters where the pattern asks for sixty-four,
			// which is what a line cut to a column limit leaves.
			name: "a hexadecimal body one character short",
			src:  "sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// Uppercase is not admitted: secrets.token_hex writes none.
			name: "a hexadecimal body written in uppercase",
			src:  "sntryu_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			// g ends the run of hexadecimal, so the count is never reached.
			name: "a letter past f in a hexadecimal body",
			src:  "sntryu_0123456789abcdefg123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a hexadecimal body broken by a hyphen",
			src:  "sntryu_0123456789abcdef-123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The character naming the kind is one of four. t is not one of
			// them, and sentry-cli's own tests carry it as a wrong prefix.
			name: "a kind the enumeration does not name",
			src:  "sntryt_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The kinds are read case-sensitively: the opening is written in
			// the case Sentry writes it, and the character naming the kind
			// carries no case of its own to fold either.
			name: "an uppercase kind character behind a lowercase opening",
			src:  "sntryU_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "an uppercase organization kind",
			src:  "sntryS_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			// The separator standing where the kind belongs, so the byte the
			// scan branches on names neither a hexadecimal kind nor the
			// organization one.
			name: "the separator where the kind belongs",
			src:  "sntry__0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The forbidden byte at the very first character of a hexadecimal
			// body, with the rest of the shape otherwise a whole token.
			name: "a letter past f at the first character of a hexadecimal body",
			src:  "sntryu_g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// And at the first character of an organization secret.
			name: "a hyphen at the first character of an organization secret",
			src:  "sntrys_0123456789abcdefghijklmnopqrstuv_-123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			// A user application token, driven at the same boundary the user
			// token above is driven at.
			name: "a user application token with a body one character short",
			src:  "sntrya_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "an internal integration token with a letter past f in its body",
			src:  "sntryi_0123456789abcdefg123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The word the environment variable is spelled with carries an e
			// the anchor does not.
			name: "the vendor's name written in full where the anchor belongs",
			src:  "sentry_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "an uppercase anchor",
			src:  "SNTRYU_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a hyphen where the prefix carries its separator",
			src:  "sntryu-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// sentry-cli rejects this one under the name missing_payload: a
			// payload of no characters is no payload.
			name: "an organization token with no payload",
			src:  "sntrys__0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			// Thirty-one characters, which base64 cannot have written: the
			// length of a payload, padding included, is a multiple of four.
			name: "an organization payload that is not a multiple of base64's group",
			src:  "sntrys_0123456789abcdefghijklmnopqrstu_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			// Thirty-two characters and one of padding behind them, which is
			// thirty-three and so is not one either.
			name: "an organization payload padded past the group",
			src:  "sntrys_0123456789abcdefghijklmnopqrstuv=_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			// Base64 calls for at most two padding characters.
			name: "an organization payload closing with three",
			src:  "sntrys_0123456789abcdefghijklmnopqrs===_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			// Padding stands where a payload ends and nowhere else, so what
			// follows it here is not the separator the candidate wants.
			name: "padding inside an organization payload",
			src:  "sntrys_0123456789abcdefghijklmn==qrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			name: "an organization secret one character short",
			src:  "sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEF",
		},
		{
			// The secret is written without padding: Sentry strips it and
			// sentry-cli reads the secret with a codec that admits none.
			name: "padding where an organization secret ends",
			src:  "sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEF=",
		},
		{
			// A third underscore, which sentry-cli rejects: the separator
			// belongs to neither segment, so a secret carrying one is no secret.
			name: "a third underscore inside an organization secret",
			src:  "sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrs_uvwxyzABCDEFG",
		},
		{
			// The alphabet is the standard base64 one, so the two characters
			// base64url writes in place of + and / are outside it and end a run
			// where they stand.
			name: "a hyphen inside an organization secret",
			src:  "sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrs-uvwxyzABCDEFG",
		},
		{
			name: "an organization token with no separator between its segments",
			src:  "sntrys_0123456789abcdefghijklmnopqrstuv0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			name: "an organization token broken by a space",
			src:  "sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghij nopqrstuvwxyzABCDEFG",
		},
		{
			name: "a token broken by a line break",
			src:  "sntryu_0123456789abcdef\n123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// The format Sentry minted before it prefixed its tokens, which is
			// this shape with nothing in front of it. It is a SHA-256's shape as
			// well, which is why it is not read.
			name: "a token of the old format, which carries no prefix",
			src:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
		{
			// A base64 payload carries no underscore, so it hands the letters of
			// the anchor nowhere to close however long it runs.
			name: "a base64 payload carrying the letters of the anchor",
			src:  "sntryu0123456789abcdefghijklmnopqrstuvsntrys0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "a jwt",
			src:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SentryAuthToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_SentryAuthToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "SENTRY_AUTH_TOKEN=sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "SENTRY_AUTH_TOKEN=***********************************************************************",
		},
		{
			// How a token reaches the API, and how it reaches a log line that
			// echoed the header.
			name: "a bearer token header",
			src:  "Authorization: Bearer sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "Authorization: Bearer ***********************************************************************",
		},
		{
			// The organization token as sentry-cli is handed one, which is what
			// a release step in a CI log carries.
			name: "an organization token on a command line",
			src:  "sentry-cli --auth-token sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG releases new 1.0.0",
			want: "sentry-cli --auth-token *********************************************************************************** releases new 1.0.0",
		},
		{
			name: "json",
			src:  `{"token":"sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`,
			want: `{"token":"***********************************************************************"}`,
		},
		{
			name: "twice",
			src:  "sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: "*********************************************************************** ***********************************************************************************",
		},
		{
			// The two spans are merged, so the token that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a token beginning inside the token before it",
			src:  "sntrys_0123456789abcdef0123456789sntrys_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: "********************************************************************************************************************************",
		},
	}

	m := New(WithPatterns(SentryAuthToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SentryAuthToken_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the token through whole. The first of them is also
	// what the tightening the Slack and Stripe scans take would cost here,
	// which builtin_sentry_auth_token.go weighs against what it would buy.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "xsntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "x***********************************************************************",
		},
		{
			name: "underscore before",
			src:  "SENTRY_AUTH_TOKEN_sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "SENTRY_AUTH_TOKEN_***********************************************************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this token
			// rather than trim it; without one the sixty-four characters Sentry
			// issued are redacted and the one written after them, which is part
			// of no credential, stays in the text.
			name: "a character of the alphabet after",
			src:  "sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefa",
			want: "***********************************************************************a",
		},
	}

	m := New(WithPatterns(SentryAuthToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SentryAuthToken_leavesWhatFollowsAlone(t *testing.T) {
	// A token is as many characters as its kind is written to and no more, so
	// what is written after one stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the token is sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.",
			want: "the token is ***********************************************************************.",
		},
		{
			name: "quoted",
			src:  `"sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"`,
			want: `"***********************************************************************************"`,
		},
		{
			// The hyphen belongs to neither alphabet, so it ends the reading
			// wherever it stands rather than being drawn into a body.
			name: "dashed word",
			src:  "sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef-suffix",
			want: "***********************************************************************-suffix",
		},
		{
			// The one forbidden character a scan reading the secret with
			// padding admitted would have swallowed: a whole organization
			// token with the padding character written straight after it.
			name: "padding written after a whole organization token",
			src:  "sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG=",
			want: "***********************************************************************************=",
		},
	}

	m := New(WithPatterns(SentryAuthToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SentryAuthToken_aDigestBehindThePrefix(t *testing.T) {
	// The one collision this format leaves. A hexadecimal body is thirty-two
	// random bytes written in hexadecimal, which is a SHA-256 digest's shape
	// exactly, so a digest written behind one of the three prefixes is a token
	// to this scan.
	//
	// It is redacted rather than spared, and nothing could be done about it that
	// would not cost a credential: such a run is a token's format exactly, so a
	// scan declining it would decline every token Sentry happened to write in
	// the digits and the letters through f alone. What keeps the collision rare
	// is the seven characters in front of it, which no digest carries and no
	// word is spelled with. A SHA-1 is left alone, at forty characters
	// twenty-four short of the count, and so is a digest written behind a hyphen
	// rather than the separator.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sha-256 behind the prefix",
			src:  "sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "***********************************************************************",
		},
		{
			name: "a sha-1 behind it, which is too short to be a body",
			src:  "sntryu_0123456789abcdef0123456789abcdef01234567",
			want: "sntryu_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a sha-256 behind a hyphen",
			src:  "sntryu-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "sntryu-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a sha-256 on its own",
			src:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	m := New(WithPatterns(SentryAuthToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

// Test_SentryAuthToken_retain holds the second return of Find to a literal
// offset, on the two shapes builtin_scan.go names: a piece of a prefix
// standing at the end of the input, and a candidate the end of the input cut
// short.
func Test_SentryAuthToken_retain(t *testing.T) {
	tests := []struct {
		name       string
		src        string
		wantRetain int
	}{
		{
			// The last six characters are "sntryu", a piece of the
			// seven-character prefix "sntryu_" cut short by the end of the
			// input.
			name:       "a piece of a prefix standing at the end of the input",
			src:        "token sntryu",
			wantRetain: 6,
		},
		{
			// A whole hexadecimal prefix with a body too short to reach the
			// count, standing at the end of the input. More characters
			// arriving could still complete the token, so the candidate is
			// unsettled from its own start.
			name:       "a hexadecimal candidate the end of the input cut short",
			src:        "sntryu_0123456789abcdef",
			wantRetain: 0,
		},
		{
			// An organization prefix whose payload the end of the input cut
			// short: no separator has arrived yet, so more characters could
			// still complete the payload and the count behind it.
			name:       "an organization candidate cut short inside its payload",
			src:        "sntrys_0123456789",
			wantRetain: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := SentryAuthToken().Find(tt.src)
			if len(got) != 0 {
				t.Fatalf("Find(%q) located %v, want no span", tt.src, got)
			}
			if retain != tt.wantRetain {
				t.Errorf("Find(%q) retain = %d, want %d", tt.src, retain, tt.wantRetain)
			}
		})
	}
}

func Test_sentryAuthTokenKinds(t *testing.T) {
	// The characters naming a kind are what the enumeration Sentry keeps
	// differs in, and the scan branches on them. A character naming two kinds
	// would make one of the two branches unreachable, and the case above
	// pinning a hexadecimal body would say nothing about the kind it names.
	if sentryAuthTokenHexKinds == "" {
		t.Fatal("no kind carries a hexadecimal body, so the scan locates only organization tokens")
	}
	if strings.IndexByte(sentryAuthTokenHexKinds, sentryAuthTokenOrgKind) >= 0 {
		t.Errorf("the organization kind %q is named among the hexadecimal ones %q", sentryAuthTokenOrgKind, sentryAuthTokenHexKinds)
	}
	for i := range len(sentryAuthTokenHexKinds) {
		if strings.IndexByte(sentryAuthTokenHexKinds[i+1:], sentryAuthTokenHexKinds[i]) >= 0 {
			t.Errorf("the hexadecimal kinds %q name %q twice", sentryAuthTokenHexKinds, sentryAuthTokenHexKinds[i])
		}
	}

	// Every prefix Sentry's enumeration names is seven characters — sntryu_,
	// sntrys_, sntrya_ and sntryi_ — and the scan reads the kind and the
	// separator by counting back two and one from the body it works out from
	// that number. So the number is restated here as the vendor's rather than
	// derived from the declarations the scan derives it from, which would agree
	// with itself whatever the prefix had become.
	const documented = 7
	if sentryAuthTokenPrefixChars != documented {
		t.Errorf("a prefix is read as %d characters, Sentry writes %d", sentryAuthTokenPrefixChars, documented)
	}
	if got := len(sentryAuthTokenOpening) + len("_") + 1; got != documented {
		t.Errorf("the opening, one character of kind and the separator come to %d, Sentry writes %d", got, documented)
	}
}

// Test_sentryAuthTokenAnchor holds the opening to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_sentryAuthTokenAnchor(t *testing.T) {
	if sentryAuthTokenAnchorIndex >= len(sentryAuthTokenOpening) {
		t.Fatalf("the anchor stands at %d, the opening is %d characters", sentryAuthTokenAnchorIndex, len(sentryAuthTokenOpening))
	}
	if c := sentryAuthTokenOpening[sentryAuthTokenAnchorIndex]; c != sentryAuthTokenAnchor {
		t.Errorf("the opening carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(sentryAuthTokenAnchor))
	}
}

func Test_sentryAuthTokenHexTokenChars(t *testing.T) {
	// Sentry stores these tokens in a column declared at seventy-one
	// characters, which is the seven of a prefix and the sixty-four of a body.
	// It is the one place the vendor writes the whole of the length down, and
	// the two counts here are only as good as their total agreeing with it.
	const documented = 71
	if got := sentryAuthTokenPrefixChars + sentryAuthTokenHexChars; got != documented {
		t.Errorf("a token with a hexadecimal body is read as %d characters, Sentry stores %d", got, documented)
	}
}

func Test_sentryAuthTokenSeparator_runsDoNotOverlap(t *testing.T) {
	// The scan walks the payload run behind every organization candidate and
	// keeps no cursor over it, where a scan whose prefix closes on a character
	// its own body admits has to keep one. What makes the cursor unnecessary
	// is that two candidates can never read the same run: a candidate asks for
	// the separator seven characters in, no payload and no secret may be
	// written with it, so the run of an earlier candidate has already ended
	// there and the later candidate's run begins past it. Were the separator a
	// character a payload admits, a run dense in prefixes would be walked once
	// for every candidate in it and the scan would cost time quadratic in the
	// length of such a line.
	if isSentryAuthTokenBase64Byte(sentryAuthTokenSeparator) {
		t.Errorf("the separator %q belongs to the alphabet a payload is written in, so two candidates can read the same run", sentryAuthTokenSeparator)
	}
	if sentryAuthTokenSeparator == sentryAuthTokenPadding {
		t.Errorf("the separator %q is what a payload closes with, so a payload could not end where the separator stands", sentryAuthTokenSeparator)
	}

	// The other side of the same character. The scan resumes one byte past the
	// start of a candidate because a token can begin inside the payload of the
	// one before it, and that holds only while the alphabet holds the letters
	// the prefix is written with: a payload closing with the opening and a kind
	// leaves the separator of the next token standing directly behind it. A
	// prefix written entirely outside the alphabet would make the two
	// impossible to nest, and the cases above pinning the nesting would stand
	// for nothing.
	for i := range len(sentryAuthTokenOpening) {
		if c := sentryAuthTokenOpening[i]; !isSentryAuthTokenBase64Byte(c) {
			t.Errorf("the opening holds %q, which no payload may be written with", c)
		}
	}
	for i := range len(sentryAuthTokenHexKinds) {
		if c := sentryAuthTokenHexKinds[i]; !isSentryAuthTokenBase64Byte(c) {
			t.Errorf("the kind %q is a character no payload may be written with", c)
		}
	}
	if !isSentryAuthTokenBase64Byte(sentryAuthTokenOrgKind) {
		t.Errorf("the organization kind %q is a character no payload may be written with", sentryAuthTokenOrgKind)
	}
}

func Test_sentryAuthTokenAlphabets(t *testing.T) {
	// The two byte tests, stated over every byte rather than by example. The
	// hexadecimal one is what secrets.token_hex writes and admits no uppercase;
	// the base64 one is the standard alphabet and not the base64url one, so the
	// two characters that differ are + and / rather than - and _.
	for c := range 256 {
		b := byte(c)

		wantHex := '0' <= b && b <= '9' || 'a' <= b && b <= 'f'
		if got := isSentryAuthTokenHexByte(b); got != wantHex {
			t.Errorf("isSentryAuthTokenHexByte(%q) = %v, want %v", b, got, wantHex)
		}

		wantBase64 := '0' <= b && b <= '9' ||
			'A' <= b && b <= 'Z' ||
			'a' <= b && b <= 'z' ||
			b == '+' || b == '/'
		if got := isSentryAuthTokenBase64Byte(b); got != wantBase64 {
			t.Errorf("isSentryAuthTokenBase64Byte(%q) = %v, want %v", b, got, wantBase64)
		}

		// The one relation between this alphabet and the base64url one the rest
		// of the package reads: they differ in exactly the two characters, and
		// the underscore being outside this one is what the scan's want of a
		// cursor rests on.
		if isBase64URLByte(b) != wantBase64 && b != '-' && b != '_' && b != '+' && b != '/' {
			t.Errorf("the two alphabets differ at %q, which is neither of the two characters that tell them apart", b)
		}
	}
}

func Test_SentryAuthToken_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a line dense in prefixes
	// holds a candidate for every five characters it has. The one thing a
	// candidate reads that is a walk over the rest of the input rather than a
	// bounded test is where its payload run ends, and repeating that walk at
	// every candidate would cost time quadratic in the length of the line. The
	// bound here is far above a linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every seventy-one bytes where they are densest, because a
	// sample has to carry a whole body to be one. The crowding a line can
	// actually carry stays here.
	sources := map[string]string{
		// Candidates as close together as the anchor allows, none of them with
		// a body: every one reaches the body of the loop and every one is
		// rejected.
		"a candidate every seven characters": strings.Repeat("sntrys_", 300000),
		// Organization payloads written into one another, each candidate
		// beginning inside the payload of the one before it, so every one of
		// them walks a run.
		"a candidate beginning inside every payload": strings.Repeat("sntrys_0123456789abcdef0123456789sntrys", 50000),
		// One candidate whose payload is the whole line, which is the walk over
		// a run reading the length of the input and finding no separator at the
		// end of it.
		"a payload that runs the length of the line": "sntrys_" + strings.Repeat("a", 1800000),
		// The same line with the separator and a secret behind it, which is the
		// walk finding a token.
		"a payload that runs the length of the line and closes": "sntrys_" + strings.Repeat("a", 1800000) + "_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		// The letters of the anchor written over and over with no separator
		// among them, which is the search for the anchor reading a whole line
		// and finding no candidate at all.
		"the letters of the anchor with no separator": strings.Repeat("sntry", 400000),
	}

	checkScanIsLinear(t, SentryAuthToken(), sources)
}

// referenceSentryAuthTokenAt reports where a Sentry auth token written at start
// ends, and whether one is written there at all. It is the statement of what the
// scan in builtin_sentry_auth_token.go locates, kept here so that the scan can
// be held to it, and it reads one position and stops.
//
// The opening, the characters naming a kind, the two counts, the separator, the
// alphabets and the padding rule are spelled again rather than built from
// sentryAuthTokenOpening, sentryAuthTokenHexKinds, sentryAuthTokenOrgKind,
// sentryAuthTokenHexChars, sentryAuthTokenSecretChars,
// sentryAuthTokenSeparator, isSentryAuthTokenHexByte and
// isSentryAuthTokenBase64Byte. A reference sharing those declarations could not
// disagree with the scan about them, and it is exactly that disagreement the
// fuzz target below is for: the two have to be changed together or reported
// apart.
//
// The payload is read as base64 writes it — whole groups of four, the last of
// them able to close with one padding character or two — rather than as a run
// and a length divisible by four, which is how the scan reads the same rule.
// That is the one place the two are written differently on purpose: a reference
// restating the modulus would agree with the scan by construction wherever the
// scan had the modulus wrong.
//
// It is written out rather than built on a regular expression, and neither the
// counts nor the repetition is why. Both counts are exact, so the machine an
// engine builds for a candidate is bounded, and the group of four repeated
// without limit is a loop rather than a width. What costs an expression here is
// that the alphabet a payload is written in holds every letter the opening is
// written in, so a run of them is a candidate at every byte, and a reference
// asking at every byte hands the engine the whole of the rest of the input at
// each of them. Over an input the mutator had grown, that leaves
// FuzzSentryAuthToken_matchesReference running for three seconds of its thirty
// and reporting no executions at all for the rest. The walks below read a byte
// at a time, and a candidate that is not one stops on the character that says
// so.
func referenceSentryAuthTokenAt(src string, start int) (int, bool) {
	if !strings.HasPrefix(src[start:], "sntry") {
		return 0, false
	}
	prefix := start + len("sntry")
	if prefix+2 > len(src) || src[prefix+1] != '_' {
		return 0, false
	}
	body := prefix + 2

	switch kind := src[prefix]; kind {
	case 'u', 'a', 'i':
		end := body + 64
		if end > len(src) {
			return 0, false
		}
		for i := body; i < end; i++ {
			if !referenceSentryHexByte(src[i]) {
				return 0, false
			}
		}
		return end, true
	case 's':
		payload, ok := referenceSentryPayloadEnd(src, body)
		if !ok {
			return 0, false
		}
		secret := payload + 1 // the separator the payload closed against
		end := secret + 43
		if end > len(src) {
			return 0, false
		}
		for i := secret; i < end; i++ {
			if !referenceSentryBase64Byte(src[i]) {
				return 0, false
			}
		}
		return end, true
	}
	return 0, false
}

// referenceSentryPayloadEnd returns where the payload beginning at body ends,
// and whether one is written there: whole groups of four, then a last group of
// four, of three and one padding character, or of two and two, with the
// separator standing behind it.
//
// It walks the groups rather than dividing, which is the one rule this file
// states differently from the scan on purpose. A group that cannot be the last
// one is a full group and the walk goes on past it; a group that is neither is
// where a payload stops being one.
func referenceSentryPayloadEnd(src string, body int) (int, bool) {
	for i := body; ; i += 4 {
		if end, ok := referenceSentryLastGroupEnd(src, i); ok && end < len(src) && src[end] == '_' {
			return end, true
		}
		for j := i; j < i+4; j++ {
			if j >= len(src) || !referenceSentryBase64Byte(src[j]) {
				return 0, false
			}
		}
	}
}

// referenceSentryLastGroupEnd returns where the group beginning at i ends when
// it is the last one of a payload, taking the three shapes in the order an
// alternation would try them: four characters, three and one padding character,
// two and two.
func referenceSentryLastGroupEnd(src string, i int) (int, bool) {
	run := 0
	for run < 4 && i+run < len(src) && referenceSentryBase64Byte(src[i+run]) {
		run++
	}
	switch {
	case run == 4:
		return i + 4, true
	case run == 3 && i+4 <= len(src) && src[i+3] == '=':
		return i + 4, true
	case run == 2 && i+4 <= len(src) && src[i+2] == '=' && src[i+3] == '=':
		return i + 4, true
	}
	return 0, false
}

// referenceSentryHexByte reports whether c may appear in the body of a token
// carrying one, which is what token_hex writes: the digits and the lowercase
// letters through f.
func referenceSentryHexByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f'
}

// referenceSentryBase64Byte reports whether c may appear in the payload or the
// secret of an organization token, which is the base64 alphabet of RFC 4648
// without its padding: + and / where base64url writes - and _.
func referenceSentryBase64Byte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z' ||
		c == '+' || c == '/'
}

// referenceSentryAuthTokenFind locates tokens the plain way: every position in
// turn, with nothing remembered between them.
//
// Asking at every position is what a reference must do here, and the shorter way
// of resuming past a match is the wrong one. A token can begin inside one: the
// alphabet an organization token's segments are written in holds every letter
// the opening is written in and every character naming a kind, and the separator
// behind them is the one such a token already carries, so a payload closing with
// sntrys or sntryu opens a candidate a search resuming past the match would
// never go on to try. The scan finds both and reports the two spans overlapping
// for a Masker to resolve, so the reference must ask about both.
func referenceSentryAuthTokenFind(src string) []Span {
	var spans []Span
	for start := range len(src) {
		if end, ok := referenceSentryAuthTokenAt(src, start); ok {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
}

// FuzzSentryAuthToken_matchesReference guards the hand-written scan: the anchor
// it searches for, the characters naming a kind, the two counts it reads behind
// a prefix, the separator, the padding it admits, the alphabets it reads the
// two bodies in and the byte it resumes at may none of them change which tokens
// are located.
func FuzzSentryAuthToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("SENTRY_AUTH_TOKEN=sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("sntrya_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("sntryi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("sntryt_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")  // a kind the enumeration does not name
	f.Add("sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")   // a hexadecimal body one short
	f.Add("sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefa") // and a run longer than one
	f.Add("sntryu_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")  // uppercase, which token_hex writes none of
	f.Add("sntryu_0123456789abcdefg123456789abcdef0123456789abcdef0123456789abcdef")  // a letter past f
	f.Add("sntryu-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")  // a hyphen where the separator belongs
	f.Add("sentry_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")  // the vendor's name in full
	f.Add("sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
	f.Add("sntrys_0123456789abcdefghijklmnopqrstu=_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")  // one padding character
	f.Add("sntrys_0123456789abcdefghijklmnopqrst==_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")  // two
	f.Add("sntrys_0123456789abcdefghijklmnopqrs===_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")  // three, which base64 never calls for
	f.Add("sntrys_0123456789abcdefghijklmnopqrstuv=_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG") // padded past the group
	f.Add("sntrys_0123456789abcdefghijklmnopqrstu_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")   // a payload that is not a multiple of four
	f.Add("sntrys_0123456789abcdefghijklmn==qrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")  // padding inside a payload
	f.Add("sntrys__0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")                                  // no payload at all
	f.Add("sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEF")   // a secret one short
	f.Add("sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH") // and a run longer than one
	f.Add("sntrys_0123456789abcdefghijklmnopqrs+/v_0123456789abcdefghijklmnopqrstuvwxyzABCDE+/")  // + and /, which tell this alphabet from base64url
	f.Add("sntrys_0123456789abcdefghijklmnopqrs-_v_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")  // - and _, which base64url writes in their place
	f.Add("sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrs_uvwxyzABCDEFG")  // a third underscore
	// A token beginning inside the payload of the one before it, in both
	// shapes, which a scan resuming past a match steps over.
	f.Add("sntrys_0123456789abcdef0123456789sntrys_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
	f.Add("sntrys_0123456789abcdef0123456789sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// Two tokens with nothing between them, which is the same text without the
	// overlap.
	f.Add("sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefsntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
	// Candidate positions crowded as close as they can be, a run of separators,
	// and a run of padding, which is where the length of a payload is decided.
	f.Add(strings.Repeat("sntrys_", 16))
	f.Add(strings.Repeat("sntrys_", 16) + "0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
	f.Add(strings.Repeat("sntry", 32))
	f.Add(strings.Repeat("_", 128))
	f.Add("sntrys_" + strings.Repeat("=", 64))
	// The old format, which carries no prefix and is not read, and a JWT, whose
	// segments are base64url where these are base64.
	f.Add("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef")

	fuzzAgainstReference(f, SentryAuthToken().Find, referenceSentryAuthTokenFind)
}

// sentryAuthTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func sentryAuthTokenFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the anchor, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="uploading source maps" url=https://sentry.io/api/0/organizations/acme/releases/ `
	user := "sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	org := "sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The anchor is five characters, so a run of them holds a candidate
			// for every five it has. Each of these is turned away by the one
			// comparison the separator's position costs, which is the cheapest
			// this scan declines a candidate for.
			name:  "candidates that are not values",
			src:   strings.Repeat("sntry", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: a whole prefix, so the body is
			// walked before a count or a character turns the candidate away.
			// Every payload here is read once and no run is read twice, which
			// is what the scan's want of a cursor rests on.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEF ", 16),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "token=" + user,
			spans: 1,
		},
		{
			name:  "one organization token",
			src:   line + "token=" + org,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "token=" + user,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"token="+user+"\n", 32),
			spans: 32,
		},
	}
}
