package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The PlanetScale token pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. A body is forty-three base64url characters,
// written here as 0123456789abcdef twice over and eleven more, and the three
// prefixes bring a token to fifty-four, fifty-six and sixty-four. Where a case
// turns on the wider alphabet, the run is written with the uppercase letters,
// the hyphen or the underscore among it and stays forty-three characters long.

func Test_PlanetScaleToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a service token",
			src:  "pscale_tkn_0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 54}},
		},
		{
			name: "a service token in an environment assignment",
			src:  "PLANETSCALE_SERVICE_TOKEN=pscale_tkn_0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{26, 80}},
		},
		{
			name: "an oauth access token",
			src:  "pscale_oauth_0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 56}},
		},
		{
			name: "an oauth refresh token",
			src:  "pscale_oauth_refresh_0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 64}},
		},
		{
			// The body is base64url, so the letters of both cases, the digits,
			// the hyphen and the underscore all stand in one.
			name: "a body written with the uppercase letters",
			src:  "pscale_tkn_0123456789abcdefABCDEF0123456789abcdefABCDE",
			want: []Span{{0, 54}},
		},
		{
			name: "a body carrying a hyphen and an underscore",
			src:  "pscale_tkn_0123456789abcdef-0123456789abcdef_012345678",
			want: []Span{{0, 54}},
		},
		{
			// The count is read exactly, so what follows the last character of
			// the body is not part of the token and stays in the text.
			name: "a run longer than the count is a token and what follows it",
			src:  "pscale_tkn_0123456789abcdef0123456789abcdef0123456789a0",
			want: []Span{{0, 54}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "pscale_tkn_0123456789abcdef0123456789abcdef0123456789apscale_oauth_0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 54}, {54, 110}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PlanetScaleToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PlanetScaleToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the opening alone",
			src:  "pscale_",
		},
		{
			name: "prefix alone",
			src:  "pscale_tkn_",
		},
		{
			name: "a body one character short",
			src:  "pscale_tkn_0123456789abcdef0123456789abcdef0123456789",
		},
		{
			name: "an uppercase prefix",
			src:  "PSCALE_TKN_0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			// The equals sign is base64's padding, which the compact encoding
			// is defined without, and two of the three rulesets reading this
			// format admit it.
			name: "an equals sign in the body",
			src:  "pscale_tkn_0123456789abcdef=123456789abcdef0123456789a",
		},
		{
			// And the dot, which belongs to no encoding at all and which the
			// same two admit.
			name: "a dot in the body",
			src:  "pscale_tkn_0123456789abcdef.123456789abcdef0123456789a",
		},
		{
			name: "a body broken by a space",
			src:  "pscale_tkn_0123456789abcdef 123456789abcdef0123456789a",
		},
		{
			name: "a body broken by a line break",
			src:  "pscale_tkn_0123456789abcdef\n123456789abcdef0123456789a",
		},
		{
			name: "the kind without the underscore that closes it",
			src:  "pscale_tkn0123456789abcdef0123456789abcdef0123456789ab",
		},
		{
			name: "a hyphen where the opening carries its underscore",
			src:  "pscale-tkn-0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			// A kind PlanetScale writes no token for. pscale_api_ is what its
			// CLI names a Postgres role by, so it is a string this opening
			// reaches and the kind turns away.
			name: "the opening with a kind no token is written with",
			src:  "pscale_api_0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			// A body of the right count and the right class behind something
			// else. The prefix is the whole of the anchor.
			name: "a value of the right shape opening with no prefix",
			src:  "xxxxxx_tkn_0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// A line carrying the byte the scan searches for several times
			// over, none of them with an opening behind it.
			name: "the anchor as it is written in prose",
			src:  "the api prints a payload the proxy passes on to the app",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PlanetScaleToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PlanetScaleToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			// The name PlanetScale's own CLI reads a service token out of,
			// beside the identifier the token is kept under — which is twelve
			// characters carrying no opening, and stays in the text.
			name: "the environment the cli reads a service token from",
			src:  "PLANETSCALE_SERVICE_TOKEN_ID=ihk9lqudel8z PLANETSCALE_SERVICE_TOKEN=pscale_tkn_0123456789abcdef0123456789abcdef0123456789a",
			want: "PLANETSCALE_SERVICE_TOKEN_ID=ihk9lqudel8z PLANETSCALE_SERVICE_TOKEN=******************************************************",
		},
		{
			// How an OAuth token reaches the API, and how it reaches a log line
			// that echoed the header.
			name: "the bearer header",
			src:  "Authorization: Bearer pscale_oauth_0123456789abcdef0123456789abcdef0123456789a",
			want: "Authorization: Bearer ********************************************************",
		},
		{
			name: "the response the oauth flow returns",
			src:  `{"access_token":"pscale_oauth_0123456789abcdef0123456789abcdef0123456789a","token_type":"Bearer","refresh_token":"pscale_oauth_refresh_0123456789abcdef0123456789abcdef0123456789a"}`,
			want: `{"access_token":"********************************************************","token_type":"Bearer","refresh_token":"****************************************************************"}`,
		},
		{
			name: "a command line",
			src:  "curl -H 'Authorization: Bearer pscale_tkn_0123456789abcdef0123456789abcdef0123456789a' https://api.planetscale.com/v1/organizations",
			want: "curl -H 'Authorization: Bearer ******************************************************' https://api.planetscale.com/v1/organizations",
		},
	}

	m := New(WithPatterns(PlanetScaleToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PlanetScaleToken_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the token through whole. The first two are what the
	// demand would cost.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "xpscale_tkn_0123456789abcdef0123456789abcdef0123456789a",
			want: "x******************************************************",
		},
		{
			name: "underscore before",
			src:  "PLANETSCALE_SERVICE_TOKEN_pscale_tkn_0123456789abcdef0123456789abcdef0123456789a",
			want: "PLANETSCALE_SERVICE_TOKEN_******************************************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this token
			// rather than trim it; without one the fifty-four characters
			// PlanetScale issued are redacted and the one written after them,
			// which is part of no credential, stays in the text.
			name: "a character of the body's class after",
			src:  "pscale_tkn_0123456789abcdef0123456789abcdef0123456789a0",
			want: "******************************************************0",
		},
	}

	m := New(WithPatterns(PlanetScaleToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PlanetScaleToken_leavesWhatFollowsAlone(t *testing.T) {
	// A service token is fifty-four characters and no more, so what is written
	// after one stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the token is pscale_tkn_0123456789abcdef0123456789abcdef0123456789a.",
			want: "the token is ******************************************************.",
		},
		{
			name: "quoted",
			src:  `"pscale_tkn_0123456789abcdef0123456789abcdef0123456789a"`,
			want: `"******************************************************"`,
		},
		{
			name: "dashed word",
			src:  "pscale_tkn_0123456789abcdef0123456789abcdef0123456789a-suffix",
			want: "******************************************************-suffix",
		},
		{
			name: "underscored word",
			src:  "pscale_tkn_0123456789abcdef0123456789abcdef0123456789a_tail",
			want: "******************************************************_tail",
		},
		{
			// The count has already ended the token, so a word written straight
			// against one comes through.
			name: "a word written against a token",
			src:  "pscale_tkn_0123456789abcdef0123456789abcdef0123456789asuffix",
			want: "******************************************************suffix",
		},
	}

	m := New(WithPatterns(PlanetScaleToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PlanetScaleToken_theRefreshKindCarriesTheAccessTokenOpening(t *testing.T) {
	// The corner builtin_planetscale_token.go argues. Everything between
	// pscale_oauth_ and a refresh token's body — refresh_ — is written in the
	// body's own alphabet, so a whole refresh token is also the access token's
	// prefix with forty-three characters behind it, and both readings are true
	// of the same text.
	//
	// The scan tries a kind before any kind that is an opening of it, so the
	// refresh token is reported once at sixty-four characters rather than as that
	// span and the fifty-six character one inside it. Where the longer reading
	// fails the shorter is taken all the same: a refresh opening with thirty-five
	// characters behind it is an access token's shape exactly.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a whole refresh token is one span and not two",
			src:  "pscale_oauth_refresh_0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 64}},
		},
		{
			name: "a refresh prefix with an access token's body behind it",
			src:  "pscale_oauth_refresh_0123456789abcdef0123456789abcdef012",
			want: []Span{{0, 56}},
		},
		{
			name: "a refresh prefix with a body too short for either reading",
			src:  "pscale_oauth_refresh_0123456789abcdef0123456789abcdef01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PlanetScaleToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PlanetScaleToken_holdsARefreshTokenTheInputCutShort(t *testing.T) {
	// The other half of the order the kinds are tried in, which no span above
	// reports. A refresh token the end of the input cut short holds a whole
	// access token in front of the cut, so a scan taking that access token and
	// settling the text behind it would have a stream write out fifty-six
	// characters of redaction with the last eight characters of the refresh
	// token beside it.
	//
	// What the scan reports instead is the span it has and the start of the
	// value as the place the input stops being settled, which holds a Writer
	// until the rest arrives. The two cases are the same text cut and whole.
	whole := "pscale_oauth_refresh_0123456789abcdef0123456789abcdef0123456789a"
	cut := whole[:len(whole)-1]

	spans, retain := PlanetScaleToken().Find(cut)
	if want := []Span{{0, 56}}; !slices.Equal(spans, want) {
		t.Errorf("Find(%q) = %v, want %v", cut, spans, want)
	}
	if retain != 0 {
		t.Errorf("Find(%q) settled from %d, want 0", cut, retain)
	}

	m := New(WithPatterns(PlanetScaleToken()))
	var out strings.Builder
	w := NewWriter(&out, m)
	if _, err := w.Write([]byte(cut)); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if _, err := w.Write([]byte(whole[len(whole)-1:])); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if got, want := out.String(), strings.Repeat("*", len(whole)); got != want {
		t.Errorf("a refresh token written in two pieces came out %q, want %q", got, want)
	}
}

func Test_PlanetScaleToken_aTokenBeginningInsideAnother(t *testing.T) {
	// What advancing rather than consuming the match has to find here, and it is
	// unbounded rather than narrow: every character of an opening is written in
	// the body's alphabet, so a whole prefix can stand anywhere inside a body.
	//
	// A scan consuming its match would resume past the outer token and leave the
	// inner one in the output whole. The two spans overlap, which a Masker
	// resolves into one, so the redaction reaches from the first character to
	// the last.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// A prefix written at the first character of a body. The outer
			// candidate's body runs on through it, so both are tokens.
			name: "a token opening at the first character of a body",
			src:  "pscale_tkn_pscale_tkn_0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 54}, {11, 65}},
		},
		{
			// And one written far enough along that the outer body runs out
			// before it, so only the inner token stands.
			name: "a token opening past the end of the body around it",
			src:  "pscale_tkn_0123456789abcdef0123456789abcdef0123456789apscale_tkn_0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 54}, {54, 108}},
		},
	}

	m := New(WithPatterns(PlanetScaleToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PlanetScaleToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Fatalf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
			if got, want := m.Mask(tt.src), strings.Repeat("*", len(tt.src)); got != want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, want)
			}
		})
	}
}

func Test_PlanetScaleToken_theDatabasePasswordIsNotRead(t *testing.T) {
	// PlanetScale's database password opens pscale_pw_ and carries the same
	// forty-three characters, so the grammar would cost one entry in the kinds.
	// What it does not have is a term: PlanetScale calls it a password wherever
	// it names it — the CLI's password subcommand, the API's plain_text
	// password, the connection strings its tutorials print — and never a token,
	// so no term of the vendor's covers a password and the three kinds together.
	//
	// It is turned away at the kind, which is written down here so that reading
	// it is a change somebody argues for rather than one somebody notices
	// afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a database password on its own",
			src:  "pscale_pw_0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a database password in the connection string it is written into",
			src:  "mysql://0123456789abcd:pscale_pw_0123456789abcdef0123456789abcdef0123456789a@aws.connect.psdb.cloud/main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PlanetScaleToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PlanetScaleToken_aHyphenInTheBody(t *testing.T) {
	// The one part of this alphabet no published value shows. Four values of this
	// width are published between PlanetScale's API reference and trufflehog's
	// tests, two of them carrying an underscore and none of them a hyphen —
	// which forty-three base64url characters give about one run in fifteen, so
	// it is what the values would look like either way.
	//
	// The class is read as the whole of base64url because the count says a body
	// is thirty-two bytes in that encoding, and declining the hyphen would
	// decline about half of every token issued. What admitting it costs is a run
	// of the same alphabet with a hyphen in it, which is opaque either way.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a hyphen in a service token's body",
			src:  "pscale_tkn_0123456789abcdef-0123456789abcdef0123456789",
			want: []Span{{0, 54}},
		},
		{
			name: "a hyphen at the last character of a body",
			src:  "pscale_tkn_0123456789abcdef0123456789abcdef0123456789-",
			want: []Span{{0, 54}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PlanetScaleToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PlanetScaleToken_aBase64URLRunBehindTheOpening(t *testing.T) {
	// The collision every prefix in this package leaves is whatever its own
	// alphabet is written straight behind it, and here that alphabet is the one
	// a JWT segment, a web push key and a routable payload are written in. So a
	// prefix and forty-three characters of an encoded blob is a token character
	// for character, and the whole of it is redacted.
	//
	// That is the answer rather than a fault in it: the vendor's format is that
	// prefix and that many of those characters, and no part of it is left for a
	// blob to fail, so a scan declining this would decline every token
	// PlanetScale issues. A run shorter than the count is turned away by the
	// count, and a run with no prefix in front of it holds nothing to be found
	// at.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a base64url run of the count behind the prefix",
			src:  "pscale_tkn_eyJhbGciOiJIUzI1NiJ90123456789abcdef0123456",
			want: []Span{{0, 54}},
		},
		{
			name: "a base64url run shorter than the count",
			src:  "pscale_tkn_eyJhbGciOiJIUzI1NiJ90123456789abcdef",
		},
		{
			name: "a base64url run with no prefix in front of it",
			src:  "eyJhbGciOiJIUzI1NiJ90123456789abcdef0123456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PlanetScaleToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PlanetScaleToken_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor and can keep none: a run of the body's alphabet
	// may hold an opening at any of its characters, so no two candidates can be
	// told apart by where the run before them ended. What holds it linear is the
	// count being a count — a candidate reads at most sixty-four bytes and stops
	// — and these are the inputs that would find that wrong.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// whole body apiece and so hold a candidate every fifty-four bytes at their
	// densest. The crowding a line can actually carry stays here.
	sources := map[string]string{
		// The anchor at every byte, each turned away by the second character of
		// the opening, which is the cheapest this scan declines anything.
		"the anchor at every byte": strings.Repeat("p", 2000000),
		// A whole opening every eight characters, each turned away at the kind.
		"an opening every eight characters": strings.Repeat("pscale_ ", 250000),
		// A whole prefix every eleven characters, each of which reads
		// forty-three characters of body and reports a span.
		"a prefix every eleven characters": strings.Repeat("pscale_tkn_", 180000),
		// The same crowding with a whole token at each candidate.
		"a token every fifty-four characters": strings.Repeat("pscale_tkn_0123456789abcdef0123456789abcdef0123456789a", 37000),
		// One candidate whose body is the whole line. The count stops it at
		// forty-three characters; a scan reading the run would read two
		// mebibytes.
		"a base64url run the length of the line": "pscale_tkn_" + strings.Repeat("a", 2000000),
		// The same run with no prefix in front of it, so no candidate is found
		// in it at all.
		"a base64url run with no prefix": strings.Repeat("a", 2000000),
	}

	m := New(WithPatterns(PlanetScaleToken()))
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

// Test_planetScaleTokenOpening holds the opening to being written in the body's
// own alphabet, which is what several sentences in
// builtin_planetscale_token.go rest on: that a token can begin anywhere inside
// another, that the scan can keep no cursor, and that the byte it searches for
// had to be chosen on the text around a token rather than on the body.
//
// It is held rather than assumed so that those sentences are a measurement. An
// opening carrying one character outside base64url would make all three of them
// wrong at once, and nothing else here would report it: the cases above would
// go on passing, since what they drive is an opening that still stands where it
// is written.
func Test_planetScaleTokenOpening(t *testing.T) {
	if len(planetScaleTokenOpening) == 0 {
		t.Fatal("the opening is empty, so every position in the input is a candidate")
	}
	for i := range len(planetScaleTokenOpening) {
		if c := planetScaleTokenOpening[i]; !isBase64URLByte(c) {
			t.Errorf("the opening %q carries %q, which no body is written with — a run of the body's alphabet can no longer hold one", planetScaleTokenOpening, c)
		}
	}
}

// Test_planetScaleTokenKinds holds the kinds to the rule the scan reads them
// under: a kind is tried before any kind that is an opening of it.
//
// That is what leaves oauth_refresh_ in front of oauth_, and it decides two
// things no case in this file could report on its own. A refresh token taken as
// the access token inside it would be reported at fifty-six characters rather
// than sixty-four, which the cases above do drive; and a refresh token the end
// of the input cut short would be settled behind the access token in front of
// the cut, which Test_PlanetScaleToken_holdsARefreshTokenTheInputCutShort
// drives. The rule is held here rather than the arrangement, so a kind added
// tomorrow is held to the same thing.
func Test_planetScaleTokenKinds(t *testing.T) {
	if len(planetScaleTokenKinds) == 0 {
		t.Fatal("the pattern carries no kind, so it locates nothing")
	}
	for i, kind := range planetScaleTokenKinds {
		if kind == "" {
			t.Errorf("the kind at %d is empty, so the opening alone opens a candidate", i)
		}
		for j, later := range planetScaleTokenKinds[i+1:] {
			if later == kind {
				t.Errorf("the kind %q is written twice, at %d and %d", kind, i, i+1+j)
			}
			if strings.HasPrefix(later, kind) {
				t.Errorf("the kind %q stands in front of %q, which it is an opening of, so the longer one is never reached", kind, later)
			}
		}
	}
}

// Test_planetScaleTokenAnchor holds every prefix the scan can match to carrying
// the byte the scan searches the input for at the index it reads a candidate
// back from. builtin_scan.go says why that is held here rather than left to the
// targets: a kind added to planetScaleTokenKinds whose prefix carried the
// anchor somewhere else would be located nowhere, and nothing that was passing
// would stop passing.
func Test_planetScaleTokenAnchor(t *testing.T) {
	if len(planetScaleTokenPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for _, p := range planetScaleTokenPrefixes {
		if planetScaleTokenAnchorIndex >= len(p) {
			t.Errorf("the anchor stands at %d, the prefix %q is %d characters", planetScaleTokenAnchorIndex, p, len(p))
			continue
		}
		if c := p[planetScaleTokenAnchorIndex]; c != planetScaleTokenAnchor {
			t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", p, c, byte(planetScaleTokenAnchor))
		}
	}
}

// Test_planetScaleTokenChars holds the arithmetic to the widths
// PlanetScaleToken's own documentation promises, and every prefix to being one
// of the three it names.
//
// What it holds is the documentation rather than the scan. The scan never
// states a whole token: it reads the body from where a kind ends, so a kind of
// another length would be located correctly and nothing would go wrong. What
// would go wrong is the sentence on PlanetScaleToken promising fifty-four,
// fifty-six and sixty-four characters, and the spans every case in this file is
// written with.
func Test_planetScaleTokenChars(t *testing.T) {
	const documentedBodyChars = 43
	documented := map[string]int{
		"pscale_tkn_":           54,
		"pscale_oauth_":         56,
		"pscale_oauth_refresh_": 64,
	}

	if planetScaleTokenBodyChars != documentedBodyChars {
		t.Errorf("a body is read as %d characters, the documentation promises %d", planetScaleTokenBodyChars, documentedBodyChars)
	}
	if len(planetScaleTokenPrefixes) != len(documented) {
		t.Errorf("the scan reads %d prefixes, the documentation names %d", len(planetScaleTokenPrefixes), len(documented))
	}
	for _, p := range planetScaleTokenPrefixes {
		chars, ok := documented[p]
		if !ok {
			t.Errorf("the prefix %q is read by the scan and named in no sentence of the documentation", p)
			continue
		}
		if got := len(p) + planetScaleTokenBodyChars; got != chars {
			t.Errorf("a token opening %q is read as %d characters, the documentation promises %d", p, got, chars)
		}
	}
}

// referencePlanetScaleToken is the expression the scan in
// builtin_planetscale_token.go reads by hand: the statement of what a
// PlanetScale token is, kept here so that the scan can be held to it.
//
// The opening, the three kinds, the count and the character class are spelled
// again rather than built from the declarations beside the scan. A reference
// sharing those could not disagree with the scan about them, and it is exactly
// that disagreement the fuzz target below is for: the two have to be changed
// together or reported apart.
//
// The alternation is written with oauth_refresh in front of oauth, which is the
// same rule the scan's kinds are ordered by and is spelled here for the same
// reason as everything else: an engine prefers the first branch that lets the
// whole match succeed, so the order decides whether a refresh token is reported
// at sixty-four characters or at the fifty-six inside it, and whether a refresh
// prefix with a shorter body falls back to the access token's reading.
//
// The repetition is exact, so the machine an engine builds for a candidate is
// forty-three states wide and is read once, where a floor spelled as a counted
// repetition would cost a machine as wide as the floor at every candidate. What
// an engine searches the text for is the seven character literal the expression
// opens with — every character of which a body is written with, so a run of the
// body's alphabet is a place the search stops, and what keeps that cheap is the
// literal being seven characters rather than one.
var referencePlanetScaleToken = regexp.MustCompile(`pscale_(?:oauth_refresh|oauth|tkn)_[0-9A-Za-z_-]{43}`)

// referencePlanetScaleTokenFind locates tokens the plain way: the leftmost
// match of the expression above, then the leftmost one beginning after that
// match's first byte, over and over, with nothing remembered between them.
//
// Asking at every byte is what the scan does too, and it is not written here to
// restate that. A reference is written to know nothing its scan claims, and
// where a token may begin is one of the things the scan claims — so this one
// starts afresh a byte along whether or not a token can be written inside
// another, and the fuzz target below is what holds the two to the same answer.
func referencePlanetScaleTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referencePlanetScaleToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzPlanetScaleToken_matchesReference guards the hand-written scan: the byte
// it searches for, the opening it reads back from that byte, the kinds it tries
// behind the opening and the order it tries them in, the count it reads and the
// character class it reads it in may none of them change which tokens are
// located.
func FuzzPlanetScaleToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("PLANETSCALE_SERVICE_TOKEN=pscale_tkn_0123456789abcdef0123456789abcdef0123456789a")
	f.Add("pscale_oauth_0123456789abcdef0123456789abcdef0123456789a")                         // the two kinds the oauth flow returns
	f.Add("pscale_oauth_refresh_0123456789abcdef0123456789abcdef0123456789a")                 //
	f.Add("pscale_oauth_refresh_0123456789abcdef0123456789abcdef012")                         // a refresh prefix with an access token's body
	f.Add("pscale_oauth_refresh_0123456789abcdef0123456789abcdef01")                          // and one shorter than either reading
	f.Add("pscale_pw_0123456789abcdef0123456789abcdef0123456789a")                            // the database password, which is no token
	f.Add("pscale_api_0123456789abcdef0123456789abcdef0123456789a")                           // the opening a postgres role is named by
	f.Add("pscale_tkn_0123456789abcdef0123456789abcdef0123456789")                            // a body one short
	f.Add("pscale_tkn_0123456789abcdef0123456789abcdef0123456789a0")                          // and a run longer than one
	f.Add("pscale_tkn_0123456789abcdefABCDEF0123456789abcdefABCDE")                           // the uppercase half of the alphabet
	f.Add("pscale_tkn_0123456789abcdef-0123456789abcdef_012345678")                           // the hyphen and the underscore
	f.Add("pscale_tkn_0123456789abcdef=123456789abcdef0123456789a")                           // the padding character, which is no body's
	f.Add("pscale_tkn_0123456789abcdef.123456789abcdef0123456789a")                           // and the dot
	f.Add("PSCALE_TKN_0123456789abcdef0123456789abcdef0123456789a")                           // an uppercase prefix
	f.Add("pscale-tkn-0123456789abcdef0123456789abcdef0123456789a")                           // hyphens where the underscores stand
	f.Add("pscale_tkn0123456789abcdef0123456789abcdef0123456789ab")                           // the kind without the underscore closing it
	f.Add("pscale_tkn_0123456789abcdef\n123456789abcdef0123456789a")                          // a token a line break breaks
	f.Add("xxxxxx_tkn_0123456789abcdef0123456789abcdef0123456789a")                           // the right shape with no opening
	f.Add("xpscale_tkn_0123456789abcdef0123456789abcdef0123456789a")                          // written against a letter
	f.Add("PLANETSCALE_SERVICE_TOKEN_pscale_tkn_0123456789abcdef0123456789abcdef0123456789a") // and against a name
	f.Add("pscale_tkn_eyJhbGciOiJIUzI1NiJ90123456789abcdef0123456")                           // an encoded blob behind the prefix
	// A token beginning inside another, which is what advancing rather than
	// consuming the match has to find, and two written with nothing between them.
	f.Add("pscale_tkn_pscale_tkn_0123456789abcdef0123456789abcdef0123456789a")
	f.Add("pscale_tkn_0123456789abcdef0123456789abcdef0123456789apscale_oauth_0123456789abcdef0123456789abcdef0123456789a")
	// Candidate positions crowded as close as they can be: the anchor at every
	// byte, the opening over and over, the whole prefix over and over, and a
	// base64url run with no prefix in front of it.
	f.Add(strings.Repeat("p", 128))
	f.Add(strings.Repeat("pscale_", 32))
	f.Add(strings.Repeat("pscale_tkn_", 32))
	f.Add(strings.Repeat("0123456789abcdef", 8))

	fuzzAgainstReference(f, PlanetScaleToken().Find, referencePlanetScaleTokenFind)
}

// planetScaleTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func planetScaleTokenFindBenchmarks() []benchmarkCase {
	// The line carries the byte the scan searches for four times, once in a word
	// of the message and three times in the vendor's own API path, and none of
	// them opens a candidate. What it times is that search and the four reads
	// that turn those positions away, which is what this pattern costs a caller
	// whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.planetscale.com/v1/organizations `
	token := "pscale_tkn_0123456789abcdef0123456789abcdef0123456789a"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The opening written over and over with a space behind it, so a
			// candidate stands at every eighth byte and every one of them is
			// turned away at the kind. That is the cheapest this scan declines a
			// candidate whose opening is whole.
			name:  "candidates that are not values",
			src:   strings.Repeat("pscale_ ", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: forty-two characters of the body
			// walked before its last one turns the candidate away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("pscale_tkn_0123456789abcdef0123456789abcdef0123456789! ", 16),
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
