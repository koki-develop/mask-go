package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Databricks personal access token pattern: what it locates and what it
// leaves alone, written out case by case, and the reference its scan is held
// to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a set
// of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. A body is thirty-two hexadecimal characters,
// written here as 0123456789abcdef twice over, which with the prefix in front
// comes to thirty-six characters and with the tail some tokens carry to
// thirty-eight.

func Test_DatabricksPersonalAccessToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "dapi0123456789abcdef0123456789abcdef",
			want: []Span{{0, 36}},
		},
		{
			name: "a token in an environment assignment",
			src:  "DATABRICKS_TOKEN=dapi0123456789abcdef0123456789abcdef",
			want: []Span{{17, 53}},
		},
		{
			name: "a token carrying the tail some are written with",
			src:  "dapi0123456789abcdef0123456789abcdef-2",
			want: []Span{{0, 38}},
		},
		{
			// The count is read exactly, so what follows the thirty-sixth
			// character is not part of the token and stays in the text.
			name: "a run longer than the count is a token and what follows it",
			src:  "dapi0123456789abcdef0123456789abcdef0",
			want: []Span{{0, 36}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "dapi0123456789abcdef0123456789abcdefdapi0123456789abcdef0123456789abcdef",
			want: []Span{{0, 36}, {36, 72}},
		},
		{
			// The prefix written twice over. The p of the second closes the
			// body of the candidate the first opens, since it is no character a
			// body is written with, so the token is the one the second opens.
			name: "a prefix in front of a token",
			src:  "dapidapi0123456789abcdef0123456789abcdef",
			want: []Span{{4, 40}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksPersonalAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DatabricksPersonalAccessToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "dapi",
		},
		{
			name: "a body one character short",
			src:  "dapi0123456789abcdef0123456789abcde",
		},
		{
			name: "a body broken by a space",
			src:  "dapi0123456789abcdef 123456789abcdef",
		},
		{
			name: "a hyphen in the body",
			src:  "dapi0123456789abcdef-123456789abcdef",
		},
		{
			name: "an underscore in the body",
			src:  "dapi0123456789abcdef_123456789abcdef",
		},
		{
			name: "a letter outside hexadecimal in the body",
			src:  "dapi0123456789abcdefg123456789abcdef",
		},
		{
			// The case the environment variable holding a token is spelled in,
			// which is one reason the prefix is read in a single case.
			name: "an uppercase prefix",
			src:  "DAPI0123456789abcdef0123456789abcdef",
		},
		{
			name: "the prefix without its closing letter",
			src:  "dap0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a hyphen inside the prefix",
			src:  "da-pi0123456789abcdef0123456789abcdef",
		},
		{
			name: "a title case prefix",
			src:  "Dapi0123456789abcdef0123456789abcdef",
		},
		{
			name: "one uppercase character in the prefix",
			src:  "dapI0123456789abcdef0123456789abcdef",
		},
		{
			// A character the body alphabet forbids standing immediately
			// behind the prefix, at the first character of the body, rather
			// than in the middle of it where the existing cases above break
			// the run.
			name: "a letter outside hexadecimal at the first character of the body",
			src:  "dapig123456789abcdef0123456789abcdef0",
		},
		{
			name: "a hyphen at the first character of the body",
			src:  "dapi-123456789abcdef0123456789abcdef0",
		},
		{
			name: "an uppercase letter at the first character of the body",
			src:  "dapiA123456789abcdef0123456789abcdef0",
		},
		{
			// The OAuth client secret Databricks issues a service principal,
			// which carries a prefix of its own and no dapi to be found at.
			name: "an oauth client secret",
			src:  "dose0123456789abcdef0123456789abcdef",
		},
		{
			name: "a body of the right shape opening with no prefix",
			src:  "xxxx0123456789abcdef0123456789abcdef",
		},
		{
			name: "a digest with no prefix",
			src:  "md5=0123456789abcdef0123456789abcdef",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "a log line",
			src:  `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://dbc-01234567-89ab.cloud.databricks.com/api/2.0/clusters/list`,
		},
		{
			name: "the workspace host a token authenticates against",
			src:  "DATABRICKS_HOST=https://dbc-01234567-89ab.cloud.databricks.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksPersonalAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DatabricksPersonalAccessToken_inContext(t *testing.T) {
	// The places a token is written, which are the places Databricks' own
	// documentation puts one: the environment the SDKs read it from, the
	// profile the CLI writes it to, the bearer header a request carries it in,
	// the property a JDBC connection takes it as and the field the token
	// endpoint returns it in.
	const token = "dapi0123456789abcdef0123456789abcdef"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token in an environment assignment",
			src:  "DATABRICKS_TOKEN=" + token,
			want: []Span{{17, 17 + len(token)}},
		},
		{
			name: "a token in the profile the cli writes",
			src:  "[DEFAULT]\nhost = https://dbc-01234567-89ab.cloud.databricks.com\ntoken = " + token,
			want: []Span{{72, 72 + len(token)}},
		},
		{
			name: "a token in a bearer token header",
			src:  "Authorization: Bearer " + token,
			want: []Span{{22, 22 + len(token)}},
		},
		{
			name: "a token on a command line",
			src:  "databricks configure --token " + token,
			want: []Span{{29, 29 + len(token)}},
		},
		{
			name: "a token in a jdbc connection string",
			src:  "jdbc:databricks://dbc-01234567-89ab.cloud.databricks.com:443/default;PWD=" + token,
			want: []Span{{73, 73 + len(token)}},
		},
		{
			name: "a token in the json the token endpoint returns",
			src:  `{"token_value":"` + token + `"}`,
			want: []Span{{16, 16 + len(token)}},
		},
		{
			name: "a token at the end of a sentence",
			src:  "the token is " + token + ".",
			want: []Span{{13, 13 + len(token)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksPersonalAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DatabricksPersonalAccessToken_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match. A word boundary in front
	// would drop the whole match rather than trim it wherever a token is
	// written against a word character, and one behind it would drop a token
	// followed by a letter or a digit.
	const token = "dapi0123456789abcdef0123456789abcdef"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token after an underscore",
			src:  "DATABRICKS_TOKEN_" + token,
			want: []Span{{17, 17 + len(token)}},
		},
		{
			name: "a token after a letter",
			src:  "x" + token,
			want: []Span{{1, 1 + len(token)}},
		},
		{
			name: "a word written against a token",
			src:  token + "suffix",
			want: []Span{{0, len(token)}},
		},
		{
			// The hyphen a tail opens with, followed by a letter rather than a
			// digit, so no tail stands here and the token ends where its body
			// does.
			name: "a hyphenated word written against a token",
			src:  token + "-suffix",
			want: []Span{{0, len(token)}},
		},
		{
			// A digit and a hyphen written immediately in front of the
			// prefix, rather than the letter and the underscore driven above.
			name: "a token after a digit",
			src:  "9" + token,
			want: []Span{{1, 1 + len(token)}},
		},
		{
			name: "a token after a hyphen",
			src:  "-" + token,
			want: []Span{{1, 1 + len(token)}},
		},
		{
			// A multi-byte rune flush against the token on both sides, with
			// no space between them.
			name: "a multi-byte rune flush against the token on both sides",
			src:  "日本語" + token + "日本語",
			want: []Span{{9, 9 + len(token)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksPersonalAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DatabricksPersonalAccessToken_theTail(t *testing.T) {
	// The hyphen and the digit behind a body, which is the one part of this
	// format no vendor writes down. It is read as one digit, so a longer number
	// written there is a tail and what follows it, exactly as a longer run of
	// the body alphabet is a body and what follows it.
	const token = "dapi0123456789abcdef0123456789abcdef"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token with the tail",
			src:  token + "-2",
			want: []Span{{0, 38}},
		},
		{
			name: "a token with a hyphen and nothing behind it",
			src:  token + "-",
			want: []Span{{0, 36}},
		},
		{
			name: "a token with a hyphen and a letter behind it",
			src:  token + "-a",
			want: []Span{{0, 36}},
		},
		{
			name: "a tail of two digits is a tail and a digit",
			src:  token + "-23",
			want: []Span{{0, 38}},
		},
		{
			name: "a date written against a token",
			src:  token + "-2026-01-01",
			want: []Span{{0, 38}},
		},
		{
			name: "a token with the tail in an environment assignment",
			src:  "DATABRICKS_TOKEN=" + token + "-2",
			want: []Span{{17, 55}},
		},
		{
			// The two ends of the tail digit's own class, rather than the 2
			// every other case here carries.
			name: "a tail digit at the bottom of its class",
			src:  token + "-0",
			want: []Span{{0, 38}},
		},
		{
			name: "a tail digit at the top of its class",
			src:  token + "-9",
			want: []Span{{0, 38}},
		},
		{
			// A run longer than the body's own count with a tail written
			// behind that longer run. The extra character belongs to the run
			// rather than to the body the count reads, so the hyphen does not
			// stand where a tail is read from and the run and its tail stay
			// in the text.
			name: "a run longer than the body's count with a tail behind it",
			src:  token + "0-2",
			want: []Span{{0, 36}},
		},
		{
			// Two tokens each carrying the tail, written with nothing between
			// them.
			name: "two tagged tokens with nothing between them",
			src:  token + "-2" + token + "-2",
			want: []Span{{0, 38}, {38, 76}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksPersonalAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DatabricksPersonalAccessToken_anUppercaseBody(t *testing.T) {
	// The alphabet is lowercase hexadecimal, which is what every ruleset
	// written against tokens somebody held reads and what a hexadecimal encoder
	// settles once for all of its output. Admitting the other case is the
	// widening the rationale declines, and these are the cases that would move
	// if it were taken.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "an uppercase body",
			src:  "dapi0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "a body mixing the two cases",
			src:  "dapi0123456789ABCDEF0123456789abcdef",
		},
		{
			name: "one uppercase character in a body",
			src:  "dapi0123456789abcdef0123456789abcdeF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksPersonalAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DatabricksPersonalAccessToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision this format leaves. Thirty-two lowercase hexadecimal
	// characters behind the prefix is the vendor's format exactly, and an MD5
	// is thirty-two of them, so the prefix written straight in front of one is a
	// token character for character. A longer digest is redacted for thirty-six
	// characters with the rest left in the text, and a digest on its own carries
	// no prefix and reaches nothing.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an md5 behind the prefix",
			src:  "dapi0123456789abcdef0123456789abcdef",
			want: []Span{{0, 36}},
		},
		{
			name: "a sha-1 behind the prefix",
			src:  "dapi0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 36}},
		},
		{
			name: "a sha-256 behind the prefix",
			src:  "dapi0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 36}},
		},
		{
			// A UUID is thirty-two hexadecimal characters divided by hyphens,
			// and a hyphen is no character a body is written with.
			name: "a uuid behind the prefix",
			src:  "dapi01234567-89ab-cdef-0123-456789abcdef",
			want: nil,
		},
		{
			name: "an md5 on its own",
			src:  "md5=0123456789abcdef0123456789abcdef",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksPersonalAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DatabricksPersonalAccessToken_aTokenInsideAToken(t *testing.T) {
	// A token can be written inside another, which is why the scan resumes a
	// byte past the start of a candidate rather than past the candidate. The p a
	// candidate is read back from stands two characters into a prefix and
	// nowhere else in a token, so the positions inside one that open a candidate
	// are those where that p falls past the end of the span: the last two
	// characters of a body, reached where the text carries on with the rest of a
	// prefix. The spans overlap there, which Masker.locate resolves.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// A body closing on da, with the pi that completes the prefix
			// written after the token that body closes.
			name: "a token beginning two characters from the end of another",
			src:  "dapi0123456789abcdef0123456789abcddapi0123456789abcdef0123456789abcdef",
			want: []Span{{0, 36}, {34, 70}},
		},
		{
			// A body closing on d, with the api that completes the prefix
			// written after the token.
			name: "a token beginning at the last character of another",
			src:  "dapi0123456789abcdef0123456789abcdedapi0123456789abcdef0123456789abcdef",
			want: []Span{{0, 36}, {35, 71}},
		},
		{
			// The same opening with nothing behind it long enough to be a body,
			// so the token in front of it is the one there is.
			name: "a body closing on da that opens no token",
			src:  "dapi0123456789abcdef0123456789abcddapi0123456789",
			want: []Span{{0, 36}},
		},
		{
			// The prefix written where a body would have to hold it. The p it
			// carries is no character a body may hold, so the candidate in front
			// of it ends there and the token is the one that prefix opens.
			name: "a prefix written where a body would stand",
			src:  "dapi0123456789abcdapi0123456789abcdef0123456789abcdef",
			want: []Span{{17, 53}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "dapi0123456789abcdef0123456789abcdefdapi0123456789abcdef0123456789abcdef",
			want: []Span{{0, 36}, {36, 72}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksPersonalAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DatabricksPersonalAccessToken_settlesNothingAboutAnOpenTail(t *testing.T) {
	// Where a token ends is not settled by the token: the two characters that
	// would widen the span stand behind it, so a scan handed the body as the
	// last of its input, or handed the hyphen with nothing behind it, reports
	// the span it has and holds from the start of the value. What every
	// built-in owes about that offset is driven over the samples and over
	// generated text in builtins_test.go and fuzz_test.go; what is written out
	// here is which inputs of this format leave the tail open, since nothing
	// else names them.
	const token = "dapi0123456789abcdef0123456789abcdef"

	tests := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "a body reaching the end of the input",
			src:  token,
			want: 0,
		},
		{
			name: "a hyphen reaching the end of the input",
			src:  token + "-",
			want: 0,
		},
		{
			name: "a tail reaching the end of the input, which is whole",
			src:  token + "-2",
			want: len(token) + 2,
		},
		{
			name: "a character that opens no tail, which settles the token",
			src:  token + " ",
			want: len(token) + 1,
		},
		{
			name: "a hyphen and a letter, which settle the token",
			src:  token + "-a",
			want: len(token) + 2,
		},
		{
			name: "a token held from its own start rather than from further back",
			src:  "DATABRICKS_TOKEN=" + token,
			want: 17,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, got := DatabricksPersonalAccessToken().Find(tt.src); got != tt.want {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, got, tt.want)
			}
		})
	}
}

// Test_DatabricksPersonalAccessToken_scanIsLinear drives the crowding this
// scan is most exposed to: the prefix carries two characters of its own body
// alphabet, d and a, so a run built from the prefix repeated crowds candidates
// close together, and the scan reads a fixed count at each rather than keeping
// a cursor, so nothing here is expected to cost more than that count times the
// number of candidates.
func Test_DatabricksPersonalAccessToken_scanIsLinear(t *testing.T) {
	checkScanIsLinear(t, DatabricksPersonalAccessToken(), map[string]string{
		"a prefix every four characters":      strings.Repeat("dapi", 500000),
		"an anchor with no prefix behind it":  strings.Repeat("p", 2000000),
		"a hexadecimal run with no prefix":    strings.Repeat("0123456789abcdef", 125000),
		"a token every thirty-six characters": strings.Repeat("dapi0123456789abcdef0123456789abcdef", 55000),
	})
}

func Test_databricksPersonalAccessTokenPrefix(t *testing.T) {
	// The prefix is the whole of what tells this format from text, and two of
	// its four characters stand outside the alphabet a body is written in. That
	// is what makes the search cheap on a line of digests — a run of the body
	// alphabet opens no candidate however long it runs — and it is what bounds
	// where a token may begin inside another, which the count below is of.
	if got := databricksPersonalAccessTokenPrefix; got != "dapi" {
		t.Errorf("databricksPersonalAccessTokenPrefix = %q, want %q", got, "dapi")
	}
	outside := 0
	for i := range len(databricksPersonalAccessTokenPrefix) {
		if !isDatabricksPersonalAccessTokenBodyByte(databricksPersonalAccessTokenPrefix[i]) {
			outside++
		}
	}
	if want := 2; outside != want {
		t.Errorf("%d character(s) of the prefix stand outside the body alphabet, want %d", outside, want)
	}

	// Where a token may begin inside another, counted out of the declarations
	// that decide it rather than claimed in prose. A candidate is found at the
	// anchor and read back from it, and the only anchor a token carries is the
	// one in its own prefix, so a position inside a span opens a candidate only
	// where the anchor reading it back falls past the end of the span. A prefix
	// lengthened, an anchor moved or a count changed moves the number, and
	// nothing else here would report it; a body admitting the anchor byte would
	// move it as well, and that is what the walk above turns away.
	inside := 0
	for p := 1; p < databricksPersonalAccessTokenChars; p++ {
		if p+databricksPersonalAccessTokenAnchorIndex >= databricksPersonalAccessTokenChars {
			inside++
		}
	}
	if want := 2; inside != want {
		t.Errorf("%d position(s) inside a token can open a candidate, want %d", inside, want)
	}

	// The hyphen a tail opens with is no character a body is written with, which
	// is what decides the count above before the tail is read at all.
	if isDatabricksPersonalAccessTokenBodyByte(databricksPersonalAccessTokenSuffixSeparator) {
		t.Errorf("the tail opens on %q, which a body may be written with",
			databricksPersonalAccessTokenSuffixSeparator)
	}

	// And no position inside a token carrying the tail opens a candidate at
	// all: the two characters at that distance from the end of one are the
	// hyphen and the digit, and neither is the byte a candidate is found at nor
	// the byte a prefix opens with. Both bytes are asked of every character a
	// tail may hold rather than of the two written out here, so that a tail
	// widened is a tail this reports on.
	for c := range 256 {
		b := byte(c)
		if b != databricksPersonalAccessTokenSuffixSeparator && !isDatabricksPersonalAccessTokenSuffixDigit(b) {
			continue
		}
		if b == databricksPersonalAccessTokenAnchor {
			t.Errorf("a tail can carry the anchor %q, so a candidate is found inside a token that has one", b)
		}
		if b == databricksPersonalAccessTokenPrefix[0] {
			t.Errorf("a tail can carry %q, which a prefix opens with, so a candidate can open inside a token that has one", b)
		}
	}
}

func Test_databricksPersonalAccessTokenAnchor(t *testing.T) {
	// The byte the scan searches for stands at the index it reads a candidate
	// back from. A prefix or an index changed without the other leaves the scan
	// opening candidates nowhere near where a token begins, and what such a scan
	// finds is nothing at all rather than something wrong.
	if got := databricksPersonalAccessTokenPrefix[databricksPersonalAccessTokenAnchorIndex]; got != databricksPersonalAccessTokenAnchor {
		t.Errorf("databricksPersonalAccessTokenPrefix[%d] = %q, want the anchor %q",
			databricksPersonalAccessTokenAnchorIndex, got, databricksPersonalAccessTokenAnchor)
	}

	// What the anchor costs, counted rather than claimed in prose: it stands
	// once in the prefix, so a line of tokens stops the search once a token, and
	// nowhere in a body, so a digest of any length stops it not at all. The d
	// and the a are the characters that would not do, and they are the reason
	// this one is worth counting: both are written in the body alphabet.
	if n := strings.Count(databricksPersonalAccessTokenPrefix, string(databricksPersonalAccessTokenAnchor)); n != 1 {
		t.Errorf("the anchor stands %d times in %q, want 1", n, databricksPersonalAccessTokenPrefix)
	}
	if isDatabricksPersonalAccessTokenBodyByte(databricksPersonalAccessTokenAnchor) {
		t.Errorf("the anchor %q is a character a body may be written with", databricksPersonalAccessTokenAnchor)
	}
}

func Test_databricksPersonalAccessTokenChars(t *testing.T) {
	// The prefix and the 128-bit key written behind it. Four characters and
	// thirty-two make a token of thirty-six, and the tail brings one to
	// thirty-eight.
	if got := len(databricksPersonalAccessTokenPrefix); got != 4 {
		t.Errorf("len(databricksPersonalAccessTokenPrefix) = %d, want 4", got)
	}
	if got := databricksPersonalAccessTokenBodyChars; got != 32 {
		t.Errorf("databricksPersonalAccessTokenBodyChars = %d, want 32", got)
	}
	if got := databricksPersonalAccessTokenChars; got != 36 {
		t.Errorf("databricksPersonalAccessTokenChars = %d, want 36", got)
	}
	if got := databricksPersonalAccessTokenSuffixedChars; got != 38 {
		t.Errorf("databricksPersonalAccessTokenSuffixedChars = %d, want 38", got)
	}
}

// referenceDatabricksPersonalAccessToken is the grammar as a regular
// expression: the prefix Databricks writes a token with, the count of a
// 128-bit key written in hexadecimal, the lowercase alphabet that count is read
// in, and the hyphen and digit some tokens carry behind it. Every part of it is
// spelled again rather than read from the scan, so that the two can disagree
// and the target below report it.
//
// It is built on an expression rather than written out because the count is
// exact, so an engine reads its machine once and stops, and because the opening
// is a literal an engine can search the text for rather than a class it would
// have to walk its machine at every byte for.
var referenceDatabricksPersonalAccessToken = regexp.MustCompile(`dapi[0-9a-f]{32}(?:-[0-9])?`)

// referenceDatabricksPersonalAccessTokenFind locates tokens the plain way: the
// leftmost match of the expression above, then the leftmost one beginning after
// that match's first byte, over and over, with nothing remembered between them.
//
// Asking at every byte rather than resuming past a match is what the scan does
// and is what a token written inside another needs: a body may close on the
// characters a prefix opens with, so a match can begin two characters from the
// end of the one before it, and resuming past the first would lose it.
func referenceDatabricksPersonalAccessTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceDatabricksPersonalAccessToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzDatabricksPersonalAccessToken_matchesReference guards the hand-written
// scan: the prefix it searches for, the case it reads that prefix and its body
// in, the count it reads behind the prefix, the tail it reads behind the count
// and the byte it resumes at may none of them change which tokens are located.
func FuzzDatabricksPersonalAccessToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("DATABRICKS_TOKEN=dapi0123456789abcdef0123456789abcdef")
	f.Add("dapi0123456789abcdef0123456789abcde")   // a body one character short
	f.Add("dapi0123456789abcdef0123456789abcdef0") // and a run one longer
	f.Add("dapi0123456789abcdef 123456789abcdef")  // a body broken by a space
	f.Add("dapi0123456789abcdef-123456789abcdef")  // a hyphen in the body
	f.Add("dapi0123456789abcdef_123456789abcdef")  // an underscore in the body
	f.Add("dapi0123456789abcdefg123456789abcdef")  // a letter outside hexadecimal
	f.Add("dapi0123456789abcdef\n123456789abcdef")
	f.Add("dapi0123456789ABCDEF0123456789ABCDEF") // an uppercase body
	f.Add("dapi0123456789abcdef0123456789abcdeF") // one uppercase character in one
	f.Add("DAPI0123456789abcdef0123456789abcdef") // an uppercase prefix
	f.Add("dap0123456789abcdef0123456789abcdef01")
	f.Add("xdapi0123456789abcdef0123456789abcdef")
	// The tail: whole, cut short, followed by a letter, and followed by more
	// digits than one.
	f.Add("dapi0123456789abcdef0123456789abcdef-2")
	f.Add("dapi0123456789abcdef0123456789abcdef-")
	f.Add("dapi0123456789abcdef0123456789abcdef-a")
	f.Add("dapi0123456789abcdef0123456789abcdef-23")
	f.Add("dapi0123456789abcdef0123456789abcdef-2026-01-01")
	// The other Databricks credential this pattern locates nothing in, a digest
	// behind the prefix, which it locates a token in, and a UUID, which it does
	// not.
	f.Add("dose0123456789abcdef0123456789abcdef")
	f.Add("dapi0123456789abcdef0123456789abcdef01234567")
	f.Add("dapi01234567-89ab-cdef-0123-456789abcdef")
	// A prefix written where a body would have to hold it, two tokens with
	// nothing between them, and candidate positions crowded as close as they can
	// be.
	f.Add("dapidapi0123456789abcdef0123456789abcdef")
	f.Add("dapi0123456789abcdapi0123456789abcdef0123456789abcdef")
	// A token beginning at each of the last two characters of another's body,
	// which a scan resuming past a match would lose.
	f.Add("dapi0123456789abcdef0123456789abcddapi0123456789abcdef0123456789abcdef")
	f.Add("dapi0123456789abcdef0123456789abcdedapi0123456789abcdef0123456789abcdef")
	f.Add("dapi0123456789abcdef0123456789abcdefdapi0123456789abcdef0123456789abcdef")
	f.Add(strings.Repeat("dapi", 64))
	f.Add(strings.Repeat("dapi", 64) + "0123456789abcdef0123456789abcdef")
	f.Add(strings.Repeat("dapi0123456789abcdef0123456789abcdef", 8))
	f.Add(strings.Repeat("p", 128))
	f.Add(strings.Repeat("0123456789abcdef", 8))

	fuzzAgainstReference(f, DatabricksPersonalAccessToken().Find, referenceDatabricksPersonalAccessTokenFind)
}

// databricksPersonalAccessTokenFindBenchmarks is what this scan is timed on.
// The builtinPatterns entry for the pattern names it, and BenchmarkBuiltins
// times every case it holds under the pattern's own name, so that a built-in
// cannot arrive without a benchmark. Every case is held to the count it states
// under a plain go test as well, which is what a benchmark nobody has run yet
// cannot be.
func databricksPersonalAccessTokenFindBenchmarks() []benchmarkCase {
	// The line the anchor is chosen against: the p stands three times on it
	// where the i stands seven, and the d and the a — the two characters of the
	// prefix a body may also be written with — stand three times and six. What
	// the line times is the search for the anchor, which is most of what this
	// pattern costs a caller whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://dbc-01234567-89ab.cloud.databricks.com/api/2.0/clusters/list `
	token := "dapi0123456789abcdef0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is four characters carrying the anchor once, so a run
			// of them stops the search once every four characters and each stop
			// reads a body that fails on its third character, which is the p of
			// the prefix beginning a byte later.
			name:  "candidates that are not values",
			src:   strings.Repeat("dapi", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads a prefix, which is the cheapest a candidate
			// is declined for at all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("p", 4096),
			spans: 0,
		},
		{
			// The other way a candidate fails: a body of the right alphabet up
			// to its last character, so the whole of it is walked before the
			// candidate is turned away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("dapi0123456789abcdef0123456789abcde. ", 16),
			spans: 0,
		},
		{
			// A run of the alphabet a body is read in, carrying no anchor at
			// all, which is what the search walks a digest of.
			name:  "a run of the body alphabet",
			src:   strings.Repeat("0123456789abcdef", 256),
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
