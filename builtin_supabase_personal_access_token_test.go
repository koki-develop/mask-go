package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Supabase personal access token pattern: what it locates and what it leaves
// alone, written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a set
// of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. The body is 0123456789abcdef written twice and then
// as far as 7, which is the forty characters the vendor's own expression asks
// for, and it is written in lowercase because that expression admits nothing
// else. With the prefix in front it comes to forty-four characters, and with the
// marker of an OAuth issued token as well to fifty.

func Test_SupabasePersonalAccessToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "sbp_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}},
		},
		{
			name: "a token in an environment assignment",
			src:  "SUPABASE_ACCESS_TOKEN=sbp_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{22, 66}},
		},
		{
			// The optional group of the vendor's own expression: the same forty
			// characters behind six more of prefix, issued to an OAuth
			// application in a user's name and sent in the same header.
			name: "a token issued through oauth",
			src:  "sbp_oauth_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 50}},
		},
		{
			// The count is read exactly, so what follows the forty-fourth
			// character is not part of the token and stays in the text.
			name: "a body run longer than the count is a token and what follows it",
			src:  "sbp_0123456789abcdef0123456789abcdef012345678",
			want: []Span{{0, 44}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "sbp_0123456789abcdef0123456789abcdef01234567sbp_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}, {44, 88}},
		},
		{
			name: "an oauth token written straight after a personal one",
			src:  "sbp_0123456789abcdef0123456789abcdef01234567sbp_oauth_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}, {44, 94}},
		},
		{
			// The candidate this scan resumes a byte along for. The prefix at
			// the front of the input opens a candidate whose body would have to
			// begin with the letter of the second prefix, which no body is
			// written with; the token is the one standing four characters in,
			// and a scan stepping over what it declined would never reach it.
			name: "a prefix in front of a token",
			src:  "sbp_sbp_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{4, 48}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SupabasePersonalAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SupabasePersonalAccessToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "sbp_",
		},
		{
			name: "the prefix and the marker with no body behind them",
			src:  "sbp_oauth_",
		},
		{
			// Thirty-nine where the pattern asks for forty, which is what the
			// vendor's own tests reject on both forms.
			name: "a body one character short",
			src:  "sbp_0123456789abcdef0123456789abcdef0123456",
		},
		{
			name: "an oauth body one character short",
			src:  "sbp_oauth_0123456789abcdef0123456789abcdef0123456",
		},
		{
			// The alphabet is lowercase hexadecimal alone, and the vendor's
			// validator refuses an uppercase token with a test named for
			// refusing one.
			name: "an uppercase body",
			src:  "sbp_0123456789ABCDEF0123456789ABCDEF01234567",
		},
		{
			name: "an uppercase oauth body",
			src:  "sbp_oauth_0123456789ABCDEF0123456789ABCDEF01234567",
		},
		{
			// The letters a body may carry stop at f, which is what turns away
			// the run betterleaks needs an entropy floor to hold back.
			name: "a letter past f in the body",
			src:  "sbp_0123456789abcdefg123456789abcdef01234567",
		},
		{
			name: "a body of lowercase letters alone",
			src:  "sbp_abcdefghijklmnopqrstuvwxyzabcdefghijklmn",
		},
		{
			// Neither character base64url adds beyond the digits and the
			// letters is admitted, and the underscore is what the prefix itself
			// closes with.
			name: "an underscore inside the body",
			src:  "sbp_0123456789abcdef_123456789abcdef01234567",
		},
		{
			name: "a hyphen inside the body",
			src:  "sbp_0123456789abcdef-123456789abcdef01234567",
		},
		{
			name: "a token broken by a space",
			src:  "sbp_0123456789abcdef 123456789abcdef01234567",
		},
		{
			name: "a token broken by a line break",
			src:  "sbp_0123456789abcdef\n123456789abcdef01234567",
		},
		{
			name: "a hyphen where the prefix carries its underscore",
			src:  "sbp-0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "the prefix without its closing underscore",
			src:  "sbp0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "an uppercase prefix",
			src:  "SBP_0123456789abcdef0123456789abcdef01234567",
		},
		{
			// The marker is read whole or not at all: what stands behind an
			// incomplete one is the letter it opens with, which no body carries.
			name: "the marker without its closing underscore",
			src:  "sbp_oauth0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "an uppercase marker",
			src:  "sbp_OAUTH_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "the marker written twice",
			src:  "sbp_oauth_oauth_0123456789abcdef0123456789abcdef01234567",
		},
		{
			// Forty-four characters of the right shape opening with something
			// else. The prefix is the whole of the anchor.
			name: "a value of the right shape opening with no prefix",
			src:  "xxx_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// No word is spelled sbp, so no snake_case name reaches the prefix
			// however it is written.
			name: "a snake_case name whose segment is nearly the prefix",
			src:  "sb_0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SupabasePersonalAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_SupabasePersonalAccessToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "SUPABASE_ACCESS_TOKEN=sbp_0123456789abcdef0123456789abcdef01234567",
			want: "SUPABASE_ACCESS_TOKEN=********************************************",
		},
		{
			// How a token reaches the Management API, and how it reaches a log
			// line that echoed the header.
			name: "a bearer token header",
			src:  "Authorization: Bearer sbp_0123456789abcdef0123456789abcdef01234567",
			want: "Authorization: Bearer ********************************************",
		},
		{
			// The command the vendor's own documentation prints for a
			// non-interactive login.
			name: "a command line",
			src:  "supabase login --token sbp_0123456789abcdef0123456789abcdef01234567",
			want: "supabase login --token ********************************************",
		},
		{
			name: "a token in a curl invocation",
			src:  "curl -H 'Authorization: Bearer sbp_0123456789abcdef0123456789abcdef01234567' https://api.supabase.com/v1/projects",
			want: "curl -H 'Authorization: Bearer ********************************************' https://api.supabase.com/v1/projects",
		},
		{
			name: "an oauth token in a token exchange response",
			src:  `{"access_token":"sbp_oauth_0123456789abcdef0123456789abcdef01234567","token_type":"Bearer"}`,
			want: `{"access_token":"**************************************************","token_type":"Bearer"}`,
		},
		{
			name: "twice",
			src:  "sbp_0123456789abcdef0123456789abcdef01234567 sbp_oauth_0123456789abcdef0123456789abcdef01234567",
			want: "******************************************** **************************************************",
		},
	}

	m := New(WithPatterns(SupabasePersonalAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SupabasePersonalAccessToken_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the token through whole. The first of them is also
	// what the tightening the Slack and Stripe scans take would cost here, which
	// builtin_supabase_personal_access_token.go weighs against what it would buy
	// — which, since no word closes on sbp, is nothing.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "xsbp_0123456789abcdef0123456789abcdef01234567",
			want: "x********************************************",
		},
		{
			name: "underscore before",
			src:  "SUPABASE_TOKEN_sbp_0123456789abcdef0123456789abcdef01234567",
			want: "SUPABASE_TOKEN_********************************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this token
			// rather than trim it; without one the forty-four characters
			// Supabase issued are redacted and the one written after them, which
			// is part of no credential, stays in the text.
			name: "a character of the body's class after",
			src:  "sbp_0123456789abcdef0123456789abcdef012345678",
			want: "********************************************8",
		},
	}

	m := New(WithPatterns(SupabasePersonalAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SupabasePersonalAccessToken_leavesWhatFollowsAlone(t *testing.T) {
	// A token is forty-four characters and no more, so what is written after one
	// stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the token is sbp_0123456789abcdef0123456789abcdef01234567.",
			want: "the token is ********************************************.",
		},
		{
			name: "quoted",
			src:  `"sbp_0123456789abcdef0123456789abcdef01234567"`,
			want: `"********************************************"`,
		},
		{
			// The hyphen belongs to no body, so a hyphenated word written
			// against a token is left where it stands.
			name: "dashed word",
			src:  "sbp_0123456789abcdef0123456789abcdef01234567-suffix",
			want: "********************************************-suffix",
		},
		{
			// The underscore belongs to no body either, however much of the
			// format is written with one: the count is what ends a token, so an
			// underscored word against one is left where it stands as a
			// hyphenated one is.
			name: "underscored word",
			src:  "sbp_0123456789abcdef0123456789abcdef01234567_tail",
			want: "********************************************_tail",
		},
		{
			// A letter past f is not a body character, so a word written
			// against a token is not read into it.
			name: "word written against a token",
			src:  "sbp_0123456789abcdef0123456789abcdef01234567suffix",
			want: "********************************************suffix",
		},
	}

	m := New(WithPatterns(SupabasePersonalAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SupabasePersonalAccessToken_noTokenBeginsInsideAnother(t *testing.T) {
	// The claim builtin_supabase_personal_access_token.go makes that only the
	// Stripe scan makes beside it: the spans of this pattern never overlap one
	// another. It rests on one character. The letter the prefix opens with is
	// written nowhere else in a token — the marker does not carry it and no body
	// may — so the anchor stands at a token's first character and at no other,
	// and a candidate found inside a span is not a thing this scan can be handed.
	//
	// That is what makes the byte the scan resumes at a choice rather than a
	// necessity for a candidate that became a token, and it is what the
	// paragraph on two tokens written together rests on. Neither is a claim one
	// input can state, so it is stated of the format first and then driven.
	if isSupabasePersonalAccessTokenSecretByte(supabasePersonalAccessTokenPrefix[0]) {
		t.Errorf("the prefix opens with %q, which a body may be written with, so a token can hold a prefix of its own",
			supabasePersonalAccessTokenPrefix[0])
	}
	if strings.IndexByte(supabasePersonalAccessTokenOAuthMarker, supabasePersonalAccessTokenPrefix[0]) >= 0 {
		t.Errorf("the marker holds %q, which the prefix opens with, so an oauth token can hold a prefix of its own",
			supabasePersonalAccessTokenPrefix[0])
	}

	// And driven, with every way one token can be written against another: at
	// the end of a body, where a body begins, and one character short of a body
	// so that the outer candidate is declined and the inner is all there is.
	body := "0123456789abcdef0123456789abcdef01234567"
	prefixes := []string{
		supabasePersonalAccessTokenPrefix,
		supabasePersonalAccessTokenPrefix + supabasePersonalAccessTokenOAuthMarker,
	}
	p := SupabasePersonalAccessToken()

	for _, outer := range prefixes {
		for _, inner := range prefixes {
			for _, src := range []string{
				outer + body + inner + body,
				outer + inner + body,
				outer + body[:len(body)-1] + inner + body,
				outer + body + "_" + inner + body,
			} {
				spans := p.Find(src)
				for i, got := range spans {
					if i > 0 && got.Start < spans[i-1].End {
						t.Errorf("Find(%q) = %v, which holds two values overlapping", src, spans)
						break
					}
				}
			}
		}
	}
}

func Test_SupabasePersonalAccessToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision every prefix in this package leaves, and the one this format
	// pays for where the Grafana one rules it out. There the character
	// thirty-two past the prefix has to be the underscore dividing a secret from
	// its checksum and no digest holds one; here there is nothing behind the
	// prefix but the run, and forty lowercase hexadecimal characters are a SHA-1
	// as readily as a token.
	//
	// Redacting one is right for the reason the count is read at all: the prefix
	// and forty lowercase hexadecimal digits are the vendor's format exactly, so
	// nothing is left in the text to tell the two apart, and declining the run
	// would decline every token Supabase ever issued. What the count does still
	// rule out is the digest of another width — an MD5 is thirty-two where a
	// token asks for forty — and a SHA-256 is read as the token its first forty
	// characters are with the rest left where it was written, which is the trade
	// every exact count here makes.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a sha-1 behind the prefix",
			src:  "sbp_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}},
		},
		{
			name: "a sha-256 behind the prefix",
			src:  "sbp_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 44}},
		},
		{
			name: "an md5 behind the prefix",
			src:  "sbp_0123456789abcdef0123456789abcdef",
		},
		{
			// A digest carries no underscore, so it holds no prefix to be found
			// at however long it runs.
			name: "a digest on its own",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a digest in a commit line",
			src:  "commit 0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SupabasePersonalAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SupabasePersonalAccessToken_theOtherSupabaseCredentials(t *testing.T) {
	// The credentials Supabase issues beside a personal access token, none of
	// which this pattern reads. The project API keys open with sb_publishable_
	// and sb_secret_, and builtin_supabase_personal_access_token.go says why
	// they are declined: nothing published states what stands behind either
	// prefix, and the rules written against them put the count in different
	// places, most of them behind an entropy floor doing the work it cannot. The
	// anon and service_role keys those replaced are JWTs, which JWT in
	// builtin_jwt.go locates as what they are — this pattern finding nothing in
	// one is the whole of what it has to do about them.
	//
	// The decisions are pinned here so that reading sb_secret_ is a change
	// somebody argues for rather than one somebody notices afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a project secret key",
			src:  "sb_secret_0123456789abcdef0123456789abcdef012",
		},
		{
			name: "a project secret key in an environment assignment",
			src:  "SUPABASE_SECRET_KEY=sb_secret_0123456789abcdef0123456789abcdef012",
		},
		{
			name: "a project publishable key",
			src:  "sb_publishable_0123456789abcdef0123456789abcd",
		},
		{
			name: "an anon key of the format the project keys replaced",
			src:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SupabasePersonalAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_supabasePersonalAccessTokenPrefix(t *testing.T) {
	// The two things the prefix is doing beyond naming the format. Its last
	// character belongs to no body, so a body begins where a prefix ends and
	// nowhere else; its first belongs to no body either, which is what
	// Test_SupabasePersonalAccessToken_noTokenBeginsInsideAnother rests on. A
	// prefix built any other way would leave both of those claims standing for
	// nothing, which is not a failure anything else here reports.
	if supabasePersonalAccessTokenPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	if c := supabasePersonalAccessTokenPrefix[len(supabasePersonalAccessTokenPrefix)-1]; isSupabasePersonalAccessTokenSecretByte(c) {
		t.Errorf("the prefix closes with %q, which a body is written with", c)
	}
	if c := supabasePersonalAccessTokenPrefix[0]; isSupabasePersonalAccessTokenSecretByte(c) {
		t.Errorf("the prefix opens with %q, which a body is written with", c)
	}
}

func Test_supabasePersonalAccessTokenOAuthMarker(t *testing.T) {
	// The marker is read greedily: a candidate carrying it is read as the longer
	// form and never as the shorter one afterwards. That is only sound while the
	// two readings cannot both apply, and what makes them exclusive is the
	// marker's first character — where the shorter reading needs a character of
	// the body's alphabet, the marker puts one that is not.
	if supabasePersonalAccessTokenOAuthMarker == "" {
		t.Fatal("the marker is empty, so the two forms are the same and the reading is not greedy at all")
	}
	if c := supabasePersonalAccessTokenOAuthMarker[0]; isSupabasePersonalAccessTokenSecretByte(c) {
		t.Errorf("the marker opens with %q, which a body is written with, so a candidate could be read both ways", c)
	}

	// And it closes with a character no body carries, so the body of an oauth
	// token begins where the marker ends as the body of a personal one begins
	// where the prefix does.
	if c := supabasePersonalAccessTokenOAuthMarker[len(supabasePersonalAccessTokenOAuthMarker)-1]; isSupabasePersonalAccessTokenSecretByte(c) {
		t.Errorf("the marker closes with %q, which a body is written with", c)
	}
}

func Test_supabasePersonalAccessTokenChars(t *testing.T) {
	// Forty is the count in the vendor's own expression, and the length of the
	// example the Management API introduction prints: four hexadecimal
	// characters, thirty-two masked and four more. Forty-four and fifty are what
	// it comes to behind the prefix and behind the prefix and the marker, which
	// is what the two constants the scan reads must still be.
	const documentedBody = 4 + 32 + 4
	if supabasePersonalAccessTokenSecretChars != documentedBody {
		t.Errorf("a body is read as %d characters, the documented example is %d", supabasePersonalAccessTokenSecretChars, documentedBody)
	}
	if want := 44; supabasePersonalAccessTokenChars != want {
		t.Errorf("a token is read as %d characters, want %d", supabasePersonalAccessTokenChars, want)
	}
	if want := 50; supabasePersonalAccessTokenOAuthChars != want {
		t.Errorf("an oauth token is read as %d characters, want %d", supabasePersonalAccessTokenOAuthChars, want)
	}
}

func Test_isSupabasePersonalAccessTokenSecretByte(t *testing.T) {
	// The lowercase hexadecimal digits and nothing else, stated over every byte
	// rather than by example. Uppercase is not admitted, where the Grafana
	// checksum admits it, for the reason
	// builtin_supabase_personal_access_token.go weighs.
	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9' || 'a' <= b && b <= 'f'
		if got := isSupabasePersonalAccessTokenSecretByte(b); got != want {
			t.Errorf("isSupabasePersonalAccessTokenSecretByte(%q) = %v, want %v", b, got, want)
		}
	}
}

func Test_isSupabasePersonalAccessTokenSecret(t *testing.T) {
	// The count and the character class together, stated over every byte rather
	// than by example.
	body := strings.Repeat("a", supabasePersonalAccessTokenSecretChars)

	if !isSupabasePersonalAccessTokenSecret(body) {
		t.Errorf("isSupabasePersonalAccessTokenSecret(%q) = false, want a run of %d characters to be one", body, supabasePersonalAccessTokenSecretChars)
	}
	for _, s := range []string{body[:len(body)-1], body + "a"} {
		if isSupabasePersonalAccessTokenSecret(s) {
			t.Errorf("isSupabasePersonalAccessTokenSecret(%q) = true, want only %d characters to be one", s, supabasePersonalAccessTokenSecretChars)
		}
	}

	for i := range supabasePersonalAccessTokenSecretChars {
		for c := range 256 {
			b := byte(c)
			src := body[:i] + string([]byte{b}) + body[i+1:]

			want := isSupabasePersonalAccessTokenSecretByte(b)
			if got := isSupabasePersonalAccessTokenSecret(src); got != want {
				t.Errorf("isSupabasePersonalAccessTokenSecret(%q) = %v with %q at %d, want %v", src, got, b, i, want)
			}
		}
	}
}

// referenceSupabasePersonalAccessToken is the expression the scan in
// builtin_supabase_personal_access_token.go reads by hand: the statement of what
// a Supabase personal access token is, kept here so that the scan can be held to
// it.
//
// The prefix, the marker, the count and the character class are spelled again
// rather than built from supabasePersonalAccessTokenPrefix,
// supabasePersonalAccessTokenOAuthMarker,
// supabasePersonalAccessTokenSecretChars and
// isSupabasePersonalAccessTokenSecretByte. A reference sharing those
// declarations could not disagree with the scan about them, and it is exactly
// that disagreement the fuzz target below is for: the two have to be changed
// together or reported apart.
//
// The counted repetition here is exact, so the machine an engine builds for a
// candidate is forty states wide and read once, and the literal in front of it
// is the one both forms open with, which is what an engine searches the text
// for. That is what lets this reference be an expression at all, where the
// Anthropic one is written out for a floor spelled as a counted repetition and
// the Notion one for an alternation of two literals sharing no character.
//
// The optional group is where the expression and the scan state the grammar
// differently, and they still cannot disagree about what they locate. An engine
// takes the group greedily and falls back to the empty branch where the forty
// characters behind it do not follow; the scan takes the marker wherever it
// stands and never tries the shorter reading. The two coincide because the
// marker opens with a character no body is written with, so the branch the scan
// does not try is one that cannot match — which is what
// Test_supabasePersonalAccessTokenOAuthMarker holds and what this target would
// report were it to stop being true.
var referenceSupabasePersonalAccessToken = regexp.MustCompile(`sbp_(?:oauth_)?[0-9a-f]{40}`)

// referenceSupabasePersonalAccessTokenFind locates tokens the plain way: the
// leftmost match of the expression above, then the leftmost one beginning after
// that match's first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex resumes past a match, and here that would report the same
// spans: no token is written inside another, so nothing stands between the end
// of a match and the next candidate. It is written this way all the same,
// because it is the scan's own resumption and a reference restating the scan's
// rules is what the target compares. As in the AWS, Google, SendGrid, Notion and
// Grafana references, asking at every byte costs this one nothing beyond a
// constant: every candidate reads at most fifty characters, here as in the scan,
// so neither has a run to walk and there is no cursor for either to be wrong
// about.
func referenceSupabasePersonalAccessTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceSupabasePersonalAccessToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzSupabasePersonalAccessToken_matchesReference guards the hand-written scan:
// the prefix it searches for, the marker it reads behind that prefix, the count
// it reads behind either of them, the character class it reads them in and the
// byte it resumes at may none of them change which tokens are located.
func FuzzSupabasePersonalAccessToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("SUPABASE_ACCESS_TOKEN=sbp_0123456789abcdef0123456789abcdef01234567")
	f.Add("sbp_oauth_0123456789abcdef0123456789abcdef01234567")       // the oauth form
	f.Add("sbp_0123456789abcdef0123456789abcdef0123456")              // a body one short
	f.Add("sbp_0123456789abcdef0123456789abcdef012345678")            // and a run longer than one
	f.Add("sbp_oauth_0123456789abcdef0123456789abcdef0123456")        // an oauth body one short
	f.Add("sbp_0123456789ABCDEF0123456789ABCDEF01234567")             // an uppercase body
	f.Add("sbp_0123456789abcdefg123456789abcdef01234567")             // a letter past f
	f.Add("sbp_0123456789abcdef_123456789abcdef01234567")             // an underscore inside the body
	f.Add("sbp_0123456789abcdef-123456789abcdef01234567")             // and a hyphen
	f.Add("sbp-0123456789abcdef0123456789abcdef01234567")             // a hyphen where the prefix carries its underscore
	f.Add("SBP_0123456789abcdef0123456789abcdef01234567")             // an uppercase prefix
	f.Add("sbp_oauth0123456789abcdef0123456789abcdef01234567")        // the marker without its underscore
	f.Add("sbp_OAUTH_0123456789abcdef0123456789abcdef01234567")       // an uppercase marker
	f.Add("sbp_oauth_oauth_0123456789abcdef0123456789abcdef01234567") // the marker twice
	f.Add("sbp_0123456789abcdef\n123456789abcdef01234567")
	f.Add("xsbp_0123456789abcdef0123456789abcdef01234567")
	// A digest behind the prefix, which is a token's format exactly, and one
	// long enough that the count is all that ends the match.
	f.Add("sbp_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("sbp_0123456789abcdef0123456789abcdef")
	// A prefix in front of a token, which a scan stepping over what it declined
	// would never reach, and two tokens with nothing between them.
	f.Add("sbp_sbp_0123456789abcdef0123456789abcdef01234567")
	f.Add("sbp_0123456789abcdef0123456789abcdef01234567sbp_0123456789abcdef0123456789abcdef01234567")
	f.Add("sbp_0123456789abcdef0123456789abcdef01234567sbp_oauth_0123456789abcdef0123456789abcdef01234567")
	// Candidate positions crowded as close as they can be, with and without the
	// marker, and a run of the character both close on.
	f.Add(strings.Repeat("sbp_", 32))
	f.Add(strings.Repeat("sbp_oauth_", 32))
	f.Add(strings.Repeat("sbp_", 32) + "0123456789abcdef0123456789abcdef01234567")
	f.Add(strings.Repeat("sbp_0123456789abcdef0123456789abcdef01234567", 8))
	f.Add(strings.Repeat("_", 128))
	// The Supabase credentials this pattern declines to read.
	f.Add("sb_secret_0123456789abcdef0123456789abcdef012")
	f.Add("sb_publishable_0123456789abcdef0123456789abcd")

	fuzzAgainstReference(f, SupabasePersonalAccessToken().Find, referenceSupabasePersonalAccessTokenFind)
}

// supabasePersonalAccessTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func supabasePersonalAccessTokenFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.supabase.com/v1/projects `
	token := "sbp_0123456789abcdef0123456789abcdef01234567"
	oauth := "sbp_oauth_0123456789abcdef0123456789abcdef01234567"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is four characters, so a run of them holds a candidate
			// for every four it has. Each is turned away by the first byte the
			// body is read at, which is the cheapest this scan declines a
			// candidate for.
			name:  "candidates that are not values",
			src:   strings.Repeat("sbp_", 512),
			spans: 0,
		},
		{
			// The same crowding with the marker to read first, which is what a
			// candidate pays before its body is looked at.
			name:  "candidates carrying the marker",
			src:   strings.Repeat("sbp_oauth_", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: a run of the right alphabet up to
			// its last character, so the whole of the body is walked before the
			// candidate is turned away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("sbp_0123456789abcdef0123456789abcdef0123456g ", 16),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "token=" + token,
			spans: 1,
		},
		{
			name:  "one value carrying the marker",
			src:   line + "token=" + oauth,
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
