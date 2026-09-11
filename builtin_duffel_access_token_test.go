package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Duffel access token pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. The run they are built from opens on
// 0123456789abcdef and carries on through the alphabet to z, then back to 0,
// which comes to the forty-three characters a body is. Where a case is about
// one position of the body rather than about the count, that position is
// rewritten and the rest of the run is left standing, so the body is still
// forty-three characters.

func Test_DuffelAccessToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a live token on its own",
			src:  "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: []Span{{0, 55}},
		},
		{
			name: "a test token on its own",
			src:  "duffel_test_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: []Span{{0, 55}},
		},
		{
			name: "a token in an environment assignment",
			src:  "DUFFEL_ACCESS_TOKEN=duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: []Span{{20, 75}},
		},
		{
			// The alphabet holds the letters of both cases, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "duffel_test_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
			want: []Span{{0, 55}},
		},
		{
			// The count is exact and the span ends at it, so a forty-fourth
			// character of the alphabet is a character written after the token
			// rather than part of one.
			name: "a run longer than the count",
			src:  "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz01234567",
			want: []Span{{0, 55}},
		},
		{
			name: "the two modes separated by a space",
			src:  "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456 duffel_test_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
			want: []Span{{0, 55}, {56, 111}},
		},
		{
			// The count ends the first token where the second opens, so the two
			// spans meet rather than overlapping.
			name: "two tokens with nothing between them",
			src:  "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456duffel_test_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: []Span{{0, 55}, {55, 110}},
		},
		{
			// A token immediately preceded by a digit, by a hyphen, and by a
			// multi-byte rune, and followed by one. The pattern reads no word
			// boundary either side of a match.
			name: "a digit before",
			src:  "9duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: []Span{{1, 56}},
		},
		{
			name: "a hyphen before",
			src:  "build-duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: []Span{{6, 61}},
		},
		{
			name: "between japanese",
			src:  "トークンはduffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456です",
			want: []Span{{15, 70}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DuffelAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DuffelAccessToken_theAlphabetAtItsEnds(t *testing.T) {
	// The base64url alphabet at each of its ends, written at the first
	// character of a body and at the last. A body built from the ordered run
	// reaches none of these by itself: the run opens on a digit and closes on
	// one, so the hyphen, the underscore, the last letter of either case and
	// the last digit are each written into a position of their own here.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a body opening on a hyphen",
			src:  "duffel_live_-123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: []Span{{0, 55}},
		},
		{
			name: "a body closing on a hyphen",
			src:  "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz012345-",
			want: []Span{{0, 55}},
		},
		{
			name: "a body opening on an underscore",
			src:  "duffel_live__123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: []Span{{0, 55}},
		},
		{
			name: "a body closing on an underscore",
			src:  "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz012345_",
			want: []Span{{0, 55}},
		},
		{
			name: "a body opening on the last letter of the alphabet",
			src:  "duffel_live_z123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: []Span{{0, 55}},
		},
		{
			name: "a body closing on the last letter of the alphabet",
			src:  "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz012345z",
			want: []Span{{0, 55}},
		},
		{
			name: "a body opening on the last capital of the alphabet",
			src:  "duffel_live_Z123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: []Span{{0, 55}},
		},
		{
			name: "a body closing on the last capital of the alphabet",
			src:  "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz012345Z",
			want: []Span{{0, 55}},
		},
		{
			name: "a body opening on the first capital of the alphabet",
			src:  "duffel_live_A123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: []Span{{0, 55}},
		},
		{
			name: "a body closing on the last digit",
			src:  "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123459",
			want: []Span{{0, 55}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DuffelAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DuffelAccessToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "duffel_live_",
		},
		{
			name: "the opening alone",
			src:  "duffel_",
		},
		{
			// Forty-two characters where the pattern asks for forty-three. This
			// is the shape a line cut to a column limit leaves.
			name: "a body one character too short",
			src:  "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz012345",
		},
		{
			// The characters just outside each end of the alphabet, written at
			// the first position of a body, in the middle of one and at the
			// last, with the rest of the run standing so that only the one
			// character decides it. The colon follows the digits, the at sign
			// comes before the capitals, the bracket follows them, the backtick
			// comes before the lowercase letters, the brace follows them and
			// the caret comes before the underscore.
			name: "a colon at the first character of a body",
			src:  "duffel_live_:123456789abcdefghijklmnopqrstuvwxyz0123456",
		},
		{
			name: "a backtick at the first character of a body",
			src:  "duffel_live_`123456789abcdefghijklmnopqrstuvwxyz0123456",
		},
		{
			name: "an at sign at the last character of a body",
			src:  "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz012345@",
		},
		{
			name: "a brace at the last character of a body",
			src:  "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz012345{",
		},
		{
			name: "a bracket in the middle of a body",
			src:  "duffel_live_0123456789abcdefghijklmnop[rstuvwxyz0123456",
		},
		{
			name: "a caret in the middle of a body",
			src:  "duffel_live_0123456789abcdefghijklmnop^rstuvwxyz0123456",
		},
		{
			// The two characters standard base64 writes where base64url writes
			// the hyphen and the underscore. Neither is in the alphabet, so a
			// body carrying one is no body.
			name: "a plus sign in the middle of a body",
			src:  "duffel_live_0123456789abcdefghijklmnop+rstuvwxyz0123456",
		},
		{
			name: "a slash in the middle of a body",
			src:  "duffel_live_0123456789abcdefghijklmnop/rstuvwxyz0123456",
		},
		{
			name: "a dot at the first character of a body",
			src:  "duffel_live_.123456789abcdefghijklmnopqrstuvwxyz0123456",
		},
		{
			name: "a dot in the middle of a body",
			src:  "duffel_live_0123456789abcdefghijklmnop.rstuvwxyz0123456",
		},
		{
			name: "a dot at the last character of a body",
			src:  "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz012345.",
		},
		{
			name: "a space in the body",
			src:  "duffel_live_0123456789abcdefghijklmnop rstuvwxyz0123456",
		},
		{
			name: "a body broken by a line break",
			src:  "duffel_live_0123456789abcdefghijklmnop\nrstuvwxyz0123456",
		},
		{
			name: "an uppercase prefix",
			src:  "DUFFEL_LIVE_0123456789abcdefghijklmnopqrstuvwxyz0123456",
		},
		{
			// A prefix whose letters are neither all lowercase nor all
			// uppercase, which a scan comparing case-insensitively or
			// lower-casing before comparing would pass.
			name: "a prefix in the case the vendor's own name is written in",
			src:  "Duffel_Live_0123456789abcdefghijklmnopqrstuvwxyz0123456",
		},
		{
			name: "a mode written in capitals",
			src:  "duffel_LIVE_0123456789abcdefghijklmnopqrstuvwxyz0123456",
		},
		{
			// The prefix is written with the underscores Duffel divides it by,
			// not with the hyphens a delimiter is elsewhere.
			name: "hyphens where the prefix carries underscores",
			src:  "duffel-live-0123456789abcdefghijklmnopqrstuvwxyz0123456",
		},
		{
			name: "the opening without its underscore",
			src:  "duffellive_0123456789abcdefghijklmnopqrstuvwxyz0123456",
		},
		{
			name: "the mode without the underscore that closes it",
			src:  "duffel_live0123456789abcdefghijklmnopqrstuvwxyz0123456",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// the whole of what tells this format from any other run of the
			// alphabet.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdefghijklmnopqrstuvwxyz0123456",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DuffelAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DuffelAccessToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "DUFFEL_ACCESS_TOKEN=duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: "DUFFEL_ACCESS_TOKEN=*******************************************************",
		},
		{
			// The header the Duffel API is called with.
			name: "a bearer authorization header",
			src:  "Authorization: Bearer duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: "Authorization: Bearer *******************************************************",
		},
		{
			name: "json",
			src:  `{"access_token":"duffel_test_0123456789abcdefghijklmnopqrstuvwxyz0123456"}`,
			want: `{"access_token":"*******************************************************"}`,
		},
		{
			name: "a command line",
			src:  `curl -H "Authorization: Bearer duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456" https://api.duffel.com/air/orders`,
			want: `curl -H "Authorization: Bearer *******************************************************" https://api.duffel.com/air/orders`,
		},
		{
			name: "a configuration environment block",
			src:  `"env": {"DUFFEL_ACCESS_TOKEN": "duffel_test_0123456789abcdefghijklmnopqrstuvwxyz0123456"}`,
			want: `"env": {"DUFFEL_ACCESS_TOKEN": "*******************************************************"}`,
		},
		{
			name: "both modes on one line",
			src:  "live=duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456 test=duffel_test_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: "live=******************************************************* test=*******************************************************",
		},
	}

	m := New(WithPatterns(DuffelAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DuffelAccessToken_theModesDuffelWrites(t *testing.T) {
	// The two modes are read by name rather than as any word standing where a
	// mode stands, and these are what that decides. Duffel writes its own name
	// in front of a word in several places of its own API, and a scan reading
	// duffel_ and any word would open a candidate at each of them — the fourth
	// case is what that reading would locate whole.
	//
	// What the decision wagers is the mode Duffel has not written yet, and the
	// third case is that wager: a mode nothing states is a mode this scan does
	// not read, and the token carrying it stays in the text. The cases move with
	// duffelAccessTokenModes, so reading another one is a decision taken rather
	// than a widening nobody noticed.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "the live mode",
			src:  "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: "*******************************************************",
		},
		{
			name: "the test mode",
			src:  "duffel_test_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: "*******************************************************",
		},
		{
			name: "a mode no duffel page writes",
			src:  "duffel_prod_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: "duffel_prod_0123456789abcdefghijklmnopqrstuvwxyz0123456",
		},
		{
			// The rate source Duffel's Stays API returns, with a run of the
			// alphabet behind it. A scan reading any word where a mode stands
			// would locate this whole.
			name: "a stays rate source with a body behind it",
			src:  "duffel_hotel_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: "duffel_hotel_0123456789abcdefghijklmnopqrstuvwxyz0123456",
		},
		{
			name: "the rate source as the stays response writes it",
			src:  `{"source":"duffel_hotel_group_rewards"}`,
			want: `{"source":"duffel_hotel_group_rewards"}`,
		},
		{
			name: "the user agent duffel's own client library sends",
			src:  "User-Agent: Duffel/v2 duffel_api_javascript/4.9.0",
			want: "User-Agent: Duffel/v2 duffel_api_javascript/4.9.0",
		},
		{
			name: "a field of the identity response",
			src:  `{"is_duffel_links_enabled":true}`,
			want: `{"is_duffel_links_enabled":true}`,
		},
	}

	m := New(WithPatterns(DuffelAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DuffelAccessToken_aTokenBeginningInsideAnother(t *testing.T) {
	// Every character of a prefix belongs to the alphabet a body is written in,
	// so a prefix can stand inside the body of the token before it. The scan
	// steps one byte past the start of a candidate rather than past its end, so
	// both are located; a scan consuming its match would step over the second
	// and leave it in the output whole.
	//
	// The second case is the other half: the candidate stepped over is one the
	// body test rejected, so a scan resuming past a match it never made would
	// lose the token four characters in as surely as one resuming past a match
	// it did.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token beginning inside the token before it",
			src:  "duffel_test_duffel_test_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: []Span{{0, 55}, {12, 67}},
		},
		{
			name: "a token inside a candidate the body turned away",
			src:  "duffel_test_.duffel_test_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: []Span{{13, 68}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DuffelAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DuffelAccessToken_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the token through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xduffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: "x*******************************************************",
		},
		{
			name: "underscore before",
			src:  "DUFFEL_ACCESS_TOKEN_duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			want: "DUFFEL_ACCESS_TOKEN_*******************************************************",
		},
	}

	m := New(WithPatterns(DuffelAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DuffelAccessToken_leavesWhatFollowsAlone(t *testing.T) {
	// The near side of reading the count exactly rather than as a floor. A
	// token ends at its fifty-fifth character whatever is written against it,
	// so a forty-fourth character of the alphabet stays in the text — which is
	// what a word boundary behind the match would drop the whole token over.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the token is duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456.",
			want: "the token is *******************************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export DUFFEL_ACCESS_TOKEN="duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456"`,
			want: `export DUFFEL_ACCESS_TOKEN="*******************************************************"`,
		},
		{
			name: "a word written against the token",
			src:  "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456suffix",
			want: "*******************************************************suffix",
		},
		{
			name: "a hyphenated word written against the token",
			src:  "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456-suffix",
			want: "*******************************************************-suffix",
		},
		{
			name: "an underscored word written against the token",
			src:  "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456_suffix",
			want: "*******************************************************_suffix",
		},
	}

	m := New(WithPatterns(DuffelAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DuffelAccessToken_cutShortOfTheCount(t *testing.T) {
	// What the exact count costs, held to being left in the text rather than
	// redacted. A line cut to a column limit partway through a token leaves a
	// prefix and a body short of the count, and the characters written before
	// the cut come through whole.
	//
	// The cases move with the scan: one of them starting to be located means
	// the count moved, and that is a decision to be taken rather than noticed
	// afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a token one character short of the count",
			src:  "DUFFEL_ACCESS_TOKEN=duffel_live_0123456789abcdefghijklmnopqrstuvwxyz012345",
		},
		{
			name: "a token cut off at its prefix",
			src:  "DUFFEL_ACCESS_TOKEN=duffel_live_",
		},
	}

	m := New(WithPatterns(DuffelAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_DuffelAccessToken_insideAnOpaqueRun(t *testing.T) {
	// What base64url costs. Hexadecimal, base62, standard base64 and base32
	// write no underscore, so an identifier, a certificate body or an embedded
	// image carries no candidate at however long it runs; base64url writes
	// every character of both prefixes, and there a chance prefix with the
	// count behind it is redacted along with the twelve characters in front of
	// it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "the prefix inside a longer run of base64url",
			src:  "payload=zzzzduffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456zzzz",
			want: "payload=zzzz*******************************************************zzzz",
		},
		{
			name: "the prefix where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzduffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456zzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz*******************************************************zzzz",
		},
		{
			name: "a certificate body in standard base64",
			src:  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0123456789abcdef+/0123456789abcdef",
			want: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0123456789abcdef+/0123456789abcdef",
		},
	}

	m := New(WithPatterns(DuffelAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DuffelAccessToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_duffel_access_token.go names, held to the answer it
	// gives rather than to the one a reader might want. The hexadecimal digits
	// are base64url and a digest carries nothing that ends a run, so a digest of
	// at least forty-three characters written behind a prefix is a token to this
	// scan. Declining it would mean declining every token Duffel issues, since
	// the format is that prefix and that many of those characters and nothing is
	// left over for a digest to fail.
	//
	// The count is what holds either side of it. A SHA-256 is longer than a body
	// and the first forty-three of it go with the prefix while the rest stays; a
	// SHA-1, an MD5 and a UUID are each short of one, and a digest with nothing
	// in front of it opens no candidate at all. The UUID is here because its
	// hyphens are in the alphabet, so nothing inside one ends the body either —
	// what turns it away is the thirty-six characters it comes to.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sha256 behind the prefix",
			src:  "duffel_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "*******************************************************bcdef0123456789abcdef",
		},
		{
			name: "a sha1 behind the prefix, three characters short of a body",
			src:  "duffel_live_0123456789abcdef0123456789abcdef01234567",
			want: "duffel_live_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "an md5 behind the prefix",
			src:  "duffel_live_0123456789abcdef0123456789abcdef",
			want: "duffel_live_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a uuid behind the prefix",
			src:  "duffel_live_01234567-89ab-cdef-0123-456789abcdef",
			want: "duffel_live_01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "a sha256 with no prefix in front of it",
			src:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	m := New(WithPatterns(DuffelAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DuffelAccessToken_holdsATokenTheInputCutShort(t *testing.T) {
	// The second return of Find, held to a literal offset on the two shapes
	// builtin_scan.go names: a piece of a prefix standing at the end of the
	// input, and a candidate the end of the input cut short.
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
			src:    "duffel_li",
			retain: 0,
		},
		{
			name:   "a piece of the prefix behind prose",
			src:    "the token starts with duffel_li",
			retain: len("the token starts with "),
		},
		{
			// A whole prefix and a body the input cuts short before the count
			// is met. The candidate could still become a token were the input
			// longer, so what is unsettled reaches back to where it opened.
			name:   "a body the input cuts short of the count",
			src:    "duffel_live_0123456789abcdef",
			retain: 0,
		},
		{
			// A mode the scan does not read, long enough for the mode test to
			// be reached and rejected. Settled to the end says the mode was
			// read and turned away rather than cut short.
			name:   "a mode no duffel page writes, with a body behind it",
			src:    "duffel_prod_0123456789abcdefghijklmnopqrstuvwxyz0123456",
			retain: len("duffel_prod_0123456789abcdefghijklmnopqrstuvwxyz0123456"),
		},
		{
			// The same mode cut short by the end of the input, which settles no
			// further back than it does. A candidate opens on a prefix, and no
			// piece of duffel_prod is a piece of either prefix, so the mode is
			// no more unsettled here than it was above — what holds the tail is
			// the trailing d alone, which opens one.
			name:   "a mode no duffel page writes, cut short at a byte a prefix opens with",
			src:    "duffel_prod",
			retain: len("duffel_pro"),
		},
		{
			// And the same text a character shorter, where the byte at the end
			// opens no piece of either prefix and nothing is held at all.
			name:   "a mode no duffel page writes, cut short at a byte no prefix carries",
			src:    "duffel_pro",
			retain: len("duffel_pro"),
		},
		{
			// A whole token with more text after it, ending in a byte that
			// opens no piece of either prefix, so nothing at the end of the
			// input is left unsettled.
			name:   "a whole token followed by settled text",
			src:    "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456 tail",
			want:   []Span{{0, 55}},
			retain: len("duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456 tail"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := DuffelAccessToken().Find(tt.src)
			if retain != tt.retain {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, retain, tt.retain)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

// Test_duffelAccessTokenPrefixes holds the claim the scan's resumption rests
// on: every character of a prefix is one a body may be written with, so a
// prefix can stand anywhere inside a body and a token can begin inside the one
// before it. A scan consuming its match would step over such a token; this scan
// steps one byte along instead, and Test_DuffelAccessToken_aTokenBeginningInsideAnother
// drives what that finds.
//
// It is stated over the declarations rather than by a case, because the case
// that would state it in full is a body made of nothing but prefixes — a value
// carrying none of the ordered characters a value written into this repository
// is built from.
func Test_duffelAccessTokenPrefixes(t *testing.T) {
	if len(duffelAccessTokenPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for _, prefix := range duffelAccessTokenPrefixes {
		for i := range len(prefix) {
			if c := prefix[i]; !isBase64URLByte(c) {
				t.Errorf("the prefix %q holds %q at %d, which a body may not be written with, so no token can begin there", prefix, c, i)
			}
		}
	}
}

// Test_duffelAccessTokenModes holds every mode to the width the scan reads it
// at. The scan finds the separator by counting from the opening, so a mode of
// another width is one whose prefix is never matched — and nothing else reports
// it, since a prefix no candidate opens on locates nothing and every case here
// goes on passing.
func Test_duffelAccessTokenModes(t *testing.T) {
	if len(duffelAccessTokenModes) == 0 {
		t.Fatal("the pattern reads no mode, so it locates nothing")
	}
	for _, mode := range duffelAccessTokenModes {
		if len(mode) != duffelAccessTokenModeChars {
			t.Errorf("the mode %q is %d characters, where the scan reads %d", mode, len(mode), duffelAccessTokenModeChars)
		}
	}
}

// Test_duffelAccessTokenAnchor holds every prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_duffelAccessTokenAnchor(t *testing.T) {
	if len(duffelAccessTokenPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so there is no candidate to reason about")
	}
	for _, prefix := range duffelAccessTokenPrefixes {
		if duffelAccessTokenAnchorIndex >= len(prefix) {
			t.Fatalf("the anchor stands at %d, the prefix %q is %d characters", duffelAccessTokenAnchorIndex, prefix, len(prefix))
		}
		if c := prefix[duffelAccessTokenAnchorIndex]; c != duffelAccessTokenAnchor {
			t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", prefix, c, byte(duffelAccessTokenAnchor))
		}
	}
}

// Test_duffelAccessTokenFindBenchmarks_lineTheAnchorWasChosenAgainst holds the
// line the benchmarks are written on to the counts the rationale reads the
// anchor choice off. The counts are the whole of the evidence for searching on
// the u rather than on any other byte of the opening, and nothing else reports
// them: a word added to that line falsifies the sentence in silence, since every
// benchmark goes on timing whatever the line became.
func Test_duffelAccessTokenFindBenchmarks_lineTheAnchorWasChosenAgainst(t *testing.T) {
	var line string
	for _, c := range duffelAccessTokenFindBenchmarks() {
		if c.name == "no value" {
			line = c.src
		}
	}
	if line == "" {
		t.Fatal(`no benchmark case named "no value", so the line the anchor was chosen against is not here to count`)
	}

	for _, tt := range []struct {
		c    byte
		want int
	}{
		{'d', 10},
		{'f', 9},
		{'e', 12},
		{'l', 4},
		{'_', 4},
		{duffelAccessTokenAnchor, 2},
	} {
		if got := strings.Count(line, string([]byte{tt.c})); got != tt.want {
			t.Errorf("the line carries %q %d times, the rationale reads the anchor off %d", tt.c, got, tt.want)
		}
	}
}

// Test_duffelAccessTokenChars holds the counts to the numbers the rationale
// reads them as: forty-three is the count both rules that read this format
// state and the width thirty-two bytes encode to, twelve is the prefix a body is
// read from, and fifty-five is the two together.
func Test_duffelAccessTokenChars(t *testing.T) {
	if duffelAccessTokenBodyChars != 43 {
		t.Errorf("a body is read as %d characters, the rationale says forty-three", duffelAccessTokenBodyChars)
	}
	for _, prefix := range duffelAccessTokenPrefixes {
		if len(prefix) != duffelAccessTokenPrefixChars {
			t.Errorf("the prefix %q is %d characters, the scan reads a body from %d", prefix, len(prefix), duffelAccessTokenPrefixChars)
		}
	}
	if duffelAccessTokenPrefixChars != 12 {
		t.Errorf("a prefix is read as %d characters, the rationale says twelve", duffelAccessTokenPrefixChars)
	}
	if want := duffelAccessTokenPrefixChars + duffelAccessTokenBodyChars; duffelAccessTokenChars != want {
		t.Errorf("a token is read as %d characters, the prefix and the body come to %d", duffelAccessTokenChars, want)
	}
	if duffelAccessTokenChars != 55 {
		t.Errorf("a token is read as %d characters, the rationale says fifty-five", duffelAccessTokenChars)
	}
}

func Test_isDuffelAccessTokenBody(t *testing.T) {
	// The count and the alphabet together, stated over every byte rather than
	// by example: a body is exactly duffelAccessTokenBodyChars characters and
	// each of them base64url.
	body := strings.Repeat("a", duffelAccessTokenBodyChars)

	if !isDuffelAccessTokenBody(body) {
		t.Errorf("isDuffelAccessTokenBody(%q) = false, want a body of %d characters to be one", body, duffelAccessTokenBodyChars)
	}
	for _, s := range []string{body[:len(body)-1], body + "a"} {
		if isDuffelAccessTokenBody(s) {
			t.Errorf("isDuffelAccessTokenBody(%q) = true, want only %d characters to be a body", s, duffelAccessTokenBodyChars)
		}
	}

	for c := range 256 {
		b := byte(c)
		src := body[:len(body)-1] + string([]byte{b})
		if got, want := isDuffelAccessTokenBody(src), isBase64URLByte(b); got != want {
			t.Errorf("isDuffelAccessTokenBody(%q) = %v with %q in it, want %v", src, got, b, want)
		}
	}
}

func Test_opensDuffelAccessTokenMode(t *testing.T) {
	// The mode and the separator that closes it, read in one place. A mode with
	// nothing behind it is no prefix, and a mode the scan does not read is no
	// prefix however the text carries on.
	for _, mode := range duffelAccessTokenModes {
		if !opensDuffelAccessTokenMode(mode + "_body") {
			t.Errorf("opensDuffelAccessTokenMode(%q) = false, want a mode with its separator to open one", mode+"_body")
		}
		if opensDuffelAccessTokenMode(mode) {
			t.Errorf("opensDuffelAccessTokenMode(%q) = true, want a mode with no separator behind it to open none", mode)
		}
		if opensDuffelAccessTokenMode(mode + "x_body") {
			t.Errorf("opensDuffelAccessTokenMode(%q) = true, want the separator to be read at the width the scan counts to", mode+"x_body")
		}
	}
	for _, s := range []string{"prod_body", "hote_body", "api__body", ""} {
		if opensDuffelAccessTokenMode(s) {
			t.Errorf("opensDuffelAccessTokenMode(%q) = true, want a mode the scan does not read to open none", s)
		}
	}
}

// referenceDuffelAccessToken is the expression the scan in
// builtin_duffel_access_token.go reads by hand: the statement of what a Duffel
// access token is, kept here so that the scan can be held to it.
//
// The opening, the modes, the separator, the count and the alphabet are spelled
// again rather than built from duffelAccessTokenOpening, duffelAccessTokenModes,
// duffelAccessTokenBodyChars and isBase64URLByte. A reference sharing those
// declarations could not disagree with the scan about them, and it is exactly
// that disagreement the fuzz target below is for: the two have to be changed
// together or reported apart.
var referenceDuffelAccessToken = regexp.MustCompile(`duffel_(live|test)_[0-9A-Za-z_-]{43}`)

// referenceDuffelAccessTokenFind locates tokens the plain way: the leftmost
// match of the expression above, then the leftmost one beginning after that
// match's first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a token can begin inside one: every character of
// a prefix is written in the alphabet a body is, so a body holding a prefix
// holds a token the engine would never go on to try. The scan finds both and
// reports the two spans overlapping for a Masker to resolve, so the reference
// must ask about both.
//
// Resuming a byte along costs this one nothing beyond a constant: every
// candidate reads at most fifty-five characters, here as in the scan, so neither
// has a run to walk and there is no cursor for either to be wrong about.
//
// It is built on an expression rather than written out, and the exact count is
// what allows that. A floor spelled as a counted repetition costs an engine a
// machine as wide as the floor at every candidate, which is what has starved
// targets of executions; an exact count is read once and stops. The seven
// character literal in front of the alternation is what the engine searches the
// text for, so a line holding no prefix is skipped rather than walked.
func referenceDuffelAccessTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceDuffelAccessToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzDuffelAccessToken_matchesReference guards the hand-written scan: the
// prefixes it searches for, the modes it reads between them, the count it holds
// a body to, the alphabet it reads that body in and the byte it resumes at may
// none of them change which tokens are located.
func FuzzDuffelAccessToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("DUFFEL_ACCESS_TOKEN=duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456")
	f.Add("Authorization: Bearer duffel_test_0123456789abcdefghijklmnopqrstuvwxyz0123456")
	f.Add("duffel_live_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456")  // a body written in capitals
	f.Add("duffel_live_0123456789abcdefghijklmnopqrstuvwxyz012345")   // one short of a body
	f.Add("duffel_live_0123456789abcdefghijklmnopqrstuvwxyz01234567") // and a run longer than one
	f.Add("duffel_live_-123456789abcdefghijklmnopqrstuvwxyz0123456")  // a body opening on a hyphen
	f.Add("duffel_live_0123456789abcdefghijklmnopqrstuvwxyz012345_")  // and one closing on an underscore
	f.Add("duffel_live_0123456789abcdefghijklmnop+rstuvwxyz0123456")  // a plus sign ends a body
	f.Add("duffel_live_0123456789abcdefghijklmnop.rstuvwxyz0123456")  // a dot, likewise
	f.Add("DUFFEL_LIVE_0123456789abcdefghijklmnopqrstuvwxyz0123456")  // an uppercase prefix
	f.Add("duffel-live-0123456789abcdefghijklmnopqrstuvwxyz0123456")  // hyphens where the prefix carries underscores
	f.Add("duffellive_0123456789abcdefghijklmnopqrstuvwxyz0123456")   // the opening without its underscore
	f.Add("duffel_prod_0123456789abcdefghijklmnopqrstuvwxyz0123456")  // a mode no Duffel page writes
	f.Add("duffel_hotel_0123456789abcdefghijklmnopqrstuvwxyz0123456") // a rate source with a body behind it
	f.Add(`{"source":"duffel_hotel_group_rewards"}`)                  // the rate source as Duffel writes it
	f.Add("User-Agent: Duffel/v2 duffel_api_javascript/4.9.0")        // the user agent its own library sends
	f.Add("duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456 duffel_test_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456")
	f.Add("duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456duffel_test_0123456789abcdefghijklmnopqrstuvwxyz0123456")
	// A token beginning inside another, and one inside a candidate the body
	// turned away.
	f.Add("duffel_test_duffel_test_0123456789abcdefghijklmnopqrstuvwxyz0123456")
	f.Add("duffel_test_.duffel_test_0123456789abcdefghijklmnopqrstuvwxyz0123456")
	// Candidate positions crowded as close as they can be, with no body for any
	// of them, and tokens written one against the next so that every candidate
	// has one.
	f.Add(strings.Repeat("duffel_live_", 16))
	f.Add(strings.Repeat("duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456", 4))
	// The digests either side of the count, behind the prefix and bare.
	f.Add("duffel_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("duffel_live_0123456789abcdef0123456789abcdef01234567")
	f.Add("duffel_live_01234567-89ab-cdef-0123-456789abcdef")
	f.Add("0123456789abcdefghijklmnopqrstuvwxyz0123456")
	// The prefix written inside a run of base64url, which is the over-match the
	// pattern admits.
	f.Add("payload=zzzzduffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456zzzz")

	fuzzAgainstReference(f, DuffelAccessToken().Find, referenceDuffelAccessTokenFind)
}

// duffelAccessTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func duffelAccessTokenFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no token. The vendor's own host name and the words its
	// records are written in are here because they are what a line about Duffel
	// carries, and they are what the anchor was chosen against: the offer and
	// the order spell the f, the d and the e several times over, where the u
	// stands only in the host name and in url.
	line := `time=2026-08-17T00:00:00Z level=info msg="order created" order_id=ord_0123456789abcdef offer_id=off_0123456789abcdef url=https://api.duffel.com/air/orders `
	token := "duffel_live_0123456789abcdefghijklmnopqrstuvwxyz0123456"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The other side of passing over the underscore: a body of JSON
			// written in snake_case stops a scan anchored there at every field
			// name, where this one walks past them.
			name:  "underscores that open no candidate",
			src:   strings.Repeat(`{"order_id":"ord_0123456789abcdef","offer_id":"off_0123456789abcdef","booking_reference":"0123AB"}`, 2),
			spans: 0,
		},
		{
			// A candidate every fifty-five characters, each of them rejected by
			// the last character of its body. This is the dearest a candidate
			// can be turned away: the whole count is read before the answer
			// comes. A prefix repeated on its own would not do, for the reason
			// Test_duffelAccessTokenPrefixes states — every character of a
			// prefix is in the alphabet, so a line of them is a line of tokens
			// rather than of rejected candidates.
			name:  "candidates that are not values",
			src:   strings.Repeat("duffel_live_0123456789abcdefghijklmnopqrstuvwxyz012345.", 32),
			spans: 0,
		},
		{
			// Tokens written one against the next, so that every candidate is a
			// token and the count is read in full at each of them.
			name:  "tokens written one against the next",
			src:   strings.Repeat(token, 128),
			spans: 128,
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
