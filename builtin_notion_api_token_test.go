package mask

import (
	"slices"
	"strings"
	"testing"
)

// The Notion API token pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. A current token is ntn_ and the forty-six
// characters 0123456789abcdef0123456789abcdef0123456789abcd; a token of the
// format Notion issued until September 2024 is secret_ and the forty-three
// characters 0123456789abcdef0123456789abcdef0123456789a. Neither body is an
// abbreviation, and both come to the fifty characters the two published shapes
// agree on.

func Test_NotionAPIToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "ntn_0123456789abcdef0123456789abcdef0123456789abcd",
			want: []Span{{0, 50}},
		},
		{
			name: "a token of the format issued until september 2024",
			src:  "secret_0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 50}},
		},
		{
			name: "a token in an environment assignment",
			src:  "NOTION_TOKEN=ntn_0123456789abcdef0123456789abcdef0123456789abcd",
			want: []Span{{13, 63}},
		},
		{
			// base62 is the letters of both cases and the digits, so a body is
			// a body in either case. Only the prefix is fixed in case.
			name: "a body written in capitals",
			src:  "ntn_0123456789ABCDEF0123456789ABCDEF0123456789ABCD",
			want: []Span{{0, 50}},
		},
		{
			// The count is read exactly, so what follows the fiftieth character
			// is not part of the token and stays in the text.
			name: "an alphabet run longer than the body is a token and what follows it",
			src:  "ntn_0123456789abcdef0123456789abcdef0123456789abcd0",
			want: []Span{{0, 50}},
		},
		{
			// Neither token is inside the other, and nothing separates them.
			name: "two tokens with nothing between them",
			src:  "ntn_0123456789abcdef0123456789abcdef0123456789abcdntn_0123456789abcdef0123456789abcdef0123456789abcd",
			want: []Span{{0, 50}, {50, 100}},
		},
		{
			name: "a token of each format on one line",
			src:  "ntn_0123456789abcdef0123456789abcdef0123456789abcd secret_0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 50}, {51, 101}},
		},
		{
			// A body closing with ntn hands the underscore written after the
			// token to a candidate beginning three characters before that token
			// ends. The underscore it is found by stands past the first token,
			// so the scan reaches it; the spans overlap, which a Masker
			// resolves into one.
			name: "a token beginning inside the token before it",
			src:  "ntn_0123456789abcdef0123456789abcdef0123456789antn_0123456789abcdef0123456789abcdef0123456789abcd",
			want: []Span{{0, 50}, {47, 97}},
		},
		{
			// The same six characters in, which is what the longer prefix
			// costs.
			name: "a token of the older format beginning inside the one before it",
			src:  "secret_0123456789abcdef0123456789abcdef01234secret_0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 50}, {44, 94}},
		},
		{
			// base62 is the letters of both cases and the digits behind either
			// prefix, and the main table above pins it for ntn_ alone: this is
			// the same claim for the older format.
			name: "an older-format body written in capitals",
			src:  "secret_0123456789ABCDEF0123456789ABCDEF0123456789A",
			want: []Span{{0, 50}},
		},
		{
			// The newer prefix's own underscore stands where a body of the
			// older prefix would be reading its fifth character, so a whole
			// ntn_ token can open right where a secret_ candidate has already
			// been declined for carrying an underscore too soon — the two
			// prefixes crowded together rather than one nested in the other.
			name: "the newer prefix in front of an older-format token",
			src:  "ntn_secret_0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{4, 54}},
		},
		{
			name: "the older prefix in front of a newer-format token",
			src:  "secret_ntn_0123456789abcdef0123456789abcdef0123456789abcd",
			want: []Span{{7, 57}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := NotionAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NotionAPIToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "ntn_",
		},
		{
			name: "the older prefix alone",
			src:  "secret_",
		},
		{
			name: "a body one character too short",
			src:  "ntn_0123456789abcdef0123456789abcdef0123456789abc",
		},
		{
			name: "a body of the older format one character too short",
			src:  "secret_0123456789abcdef0123456789abcdef0123456789",
		},
		{
			// The hyphen belongs to base64url and not to base62, so it ends a
			// body where it stands.
			name: "a hyphen inside the body",
			src:  "ntn_0123456789abcdef0123-456789abcdef0123456789abc",
		},
		{
			// And the underscore, which is the character a candidate is found
			// by: a second one inside a body ends it, and opens no candidate of
			// its own, since neither prefix stands in front of it.
			name: "a further underscore inside the body",
			src:  "ntn_0123456789abcdef0123_456789abcdef0123456789abc",
		},
		{
			name: "a body broken by a space",
			src:  "ntn_0123456789abcdef0123 456789abcdef0123456789abc",
		},
		{
			name: "a body broken by a line break",
			src:  "ntn_0123456789abcdef0123\n456789abcdef0123456789abc",
		},
		{
			name: "an uppercase prefix",
			src:  "NTN_0123456789abcdef0123456789abcdef0123456789abcd",
		},
		{
			name: "an uppercase older prefix",
			src:  "SECRET_0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a hyphen where the prefix carries its underscore",
			src:  "ntn-0123456789abcdef0123456789abcdef0123456789abcd",
		},
		{
			name: "a hyphen where the older prefix carries its underscore",
			src:  "secret-0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			// The prefix is the whole of the anchor: fifty characters of the
			// right shape opening with something else are nothing.
			name: "a run of the right length opening with no prefix",
			src:  "xyz_0123456789abcdef0123456789abcdef0123456789abcd",
		},
		{
			name: "a run of the right length with no prefix at all",
			src:  "0123456789abcdef0123456789abcdef0123456789abcd",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// Forty hexadecimal characters, and no underscore anywhere in
			// them, so nothing to be found at.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a jwt",
			src:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
		},
		{
			// The environment a Notion client is configured through is written
			// in snake_case, and every underscore in it is followed by a word
			// far short of a body.
			name: "an environment variable name",
			src:  "NOTION_API_KEY=",
		},
		{
			// The three run-enders pinned inside an ntn_ body above hold the
			// same way behind the older prefix, since neither prefix's
			// alphabet differs.
			name: "a hyphen inside an older-format body",
			src:  "secret_0123456789abcdef0123-456789abcdef0123456789",
		},
		{
			name: "a further underscore inside an older-format body",
			src:  "secret_0123456789abcdef0123_456789abcdef0123456789",
		},
		{
			name: "an older-format body broken by a space",
			src:  "secret_0123456789abcdef0123 456789abcdef0123456789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := NotionAPIToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_NotionAPIToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "NOTION_TOKEN=ntn_0123456789abcdef0123456789abcdef0123456789abcd",
			want: "NOTION_TOKEN=**************************************************",
		},
		{
			// How a token reaches the API, and how it reaches a log line that
			// echoed the header.
			name: "a bearer token header",
			src:  "Authorization: Bearer ntn_0123456789abcdef0123456789abcdef0123456789abcd",
			want: "Authorization: Bearer **************************************************",
		},
		{
			name: "json",
			src:  `{"access_token":"ntn_0123456789abcdef0123456789abcdef0123456789abcd","token_type":"bearer"}`,
			want: `{"access_token":"**************************************************","token_type":"bearer"}`,
		},
		{
			name: "a token of the older format in an assignment",
			src:  "NOTION_TOKEN=secret_0123456789abcdef0123456789abcdef0123456789a",
			want: "NOTION_TOKEN=**************************************************",
		},
		{
			name: "one of each",
			src:  "ntn_0123456789abcdef0123456789abcdef0123456789abcd secret_0123456789abcdef0123456789abcdef0123456789a",
			want: "************************************************** **************************************************",
		},
		{
			// The two spans are merged, so the token that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a token beginning inside the token before it",
			src:  "ntn_0123456789abcdef0123456789abcdef0123456789antn_0123456789abcdef0123456789abcdef0123456789abcd",
			want: "*************************************************************************************************",
		},
		{
			name: "a token of the older format beginning inside the one before it",
			src:  "secret_0123456789abcdef0123456789abcdef01234secret_0123456789abcdef0123456789abcdef0123456789a",
			want: "**********************************************************************************************",
		},
	}

	m := New(WithPatterns(NotionAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NotionAPIToken_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the token through whole. The first two are also
	// what the tightening the Slack and Stripe scans take would cost here,
	// which builtin_notion_api_token.go weighs against what it would buy.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "xntn_0123456789abcdef0123456789abcdef0123456789abcd",
			want: "x**************************************************",
		},
		{
			name: "underscore before",
			src:  "NOTION_TOKEN_ntn_0123456789abcdef0123456789abcdef0123456789abcd",
			want: "NOTION_TOKEN_**************************************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this token
			// rather than trim it; without one the fifty characters Notion
			// issued are redacted and the one written after them, which is part
			// of no credential, stays in the text.
			name: "a character of the alphabet after",
			src:  "ntn_0123456789abcdef0123456789abcdef0123456789abcd0",
			want: "**************************************************0",
		},
		{
			name: "letter before an older-format token",
			src:  "xsecret_0123456789abcdef0123456789abcdef0123456789a",
			want: "x**************************************************",
		},
		{
			// A multi-byte rune is no word character, but it is worth pinning
			// beside the ASCII cases above: no boundary is asked of it either.
			name: "a multi-byte rune before and after",
			src:  "日本語ntn_0123456789abcdef0123456789abcdef0123456789abcd日本語",
			want: "日本語**************************************************日本語",
		},
		{
			name: "an invalid utf-8 byte before",
			src:  "\xffntn_0123456789abcdef0123456789abcdef0123456789abcd",
			want: "\xff**************************************************",
		},
	}

	m := New(WithPatterns(NotionAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NotionAPIToken_leavesWhatFollowsAlone(t *testing.T) {
	// A token is fifty characters and no more, so what is written after one
	// stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the token is ntn_0123456789abcdef0123456789abcdef0123456789abcd.",
			want: "the token is **************************************************.",
		},
		{
			name: "quoted",
			src:  `"ntn_0123456789abcdef0123456789abcdef0123456789abcd"`,
			want: `"**************************************************"`,
		},
		{
			// The hyphen belongs to no body, so a hyphenated word written
			// against a token is left where it stands rather than read as more
			// of the body — which is what tells this pattern from the OpenAI
			// and Anthropic ones, whose bodies are base64url.
			name: "dashed word",
			src:  "ntn_0123456789abcdef0123456789abcdef0123456789abcd-suffix",
			want: "**************************************************-suffix",
		},
		{
			name: "underscored word",
			src:  "ntn_0123456789abcdef0123456789abcdef0123456789abcd_suffix",
			want: "**************************************************_suffix",
		},
		{
			name: "sentence, older format",
			src:  "the token is secret_0123456789abcdef0123456789abcdef0123456789a.",
			want: "the token is **************************************************.",
		},
		{
			name: "dashed word, older format",
			src:  "secret_0123456789abcdef0123456789abcdef0123456789a-suffix",
			want: "**************************************************-suffix",
		},
		{
			name: "underscored word, older format",
			src:  "secret_0123456789abcdef0123456789abcdef0123456789a_suffix",
			want: "**************************************************_suffix",
		},
	}

	m := New(WithPatterns(NotionAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NotionAPIToken_wordClosingOnThePrefix(t *testing.T) {
	// What this pattern redacts that nobody issued, and the one place the text
	// taken is text somebody wrote. secret_ closes an ordinary name —
	// client_secret_, app_secret_ and webhook_secret_ are all that shape — so
	// where forty-three unbroken letters and digits are spliced straight onto
	// one, the name is redacted from its secret onward.
	//
	// They are held to being redacted rather than to being spared. What keeps
	// such a name out of a span in an ordinary file is the character that
	// follows it there, which is =, a colon and a space, or a quote, and none
	// of those is a character a body is written with. The tightening on offer
	// in front would not help: it admits the underscore, which is what every
	// one of these names carries in front of the prefix.
	// builtin_notion_api_token.go weighs both.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a name closing on the older prefix with a value spliced onto it",
			src:  "client_secret_0123456789abcdef0123456789abcdef0123456789a",
			want: "client_**************************************************",
		},
		{
			name: "the same name with the value written where a file would write it",
			src:  "client_secret=0123456789abcdef0123456789abcdef0123456789a",
			want: "client_secret=0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a name closing on the older prefix with a value of another length",
			src:  "client_secret_0123456789abcdef0123456789abcdef0123456789",
			want: "client_secret_0123456789abcdef0123456789abcdef0123456789",
		},
	}

	m := New(WithPatterns(NotionAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NotionAPIToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision either prefix leaves. Hexadecimal digits are base62 and a
	// digest carries nothing that ends a run, so a SHA-256 written behind a
	// prefix reaches both counts and the first fifty characters are redacted,
	// with the rest of the digest left in the text — which is what the count
	// being a count leaves behind, where the npm scan reading a floor would
	// take the digest whole. A SHA-1 is forty characters and an MD5
	// thirty-two, and neither reaches either count.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sha256 behind the prefix",
			src:  "ntn_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "**************************************************ef0123456789abcdef",
		},
		{
			name: "a sha256 behind the older prefix",
			src:  "secret_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "**************************************************bcdef0123456789abcdef",
		},
		{
			name: "a sha1 behind the prefix, six characters short of a body",
			src:  "ntn_0123456789abcdef0123456789abcdef01234567",
			want: "ntn_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a sha1 behind the older prefix, three characters short of a body",
			src:  "secret_0123456789abcdef0123456789abcdef01234567",
			want: "secret_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "an md5 behind the prefix",
			src:  "ntn_0123456789abcdef0123456789abcdef",
			want: "ntn_0123456789abcdef0123456789abcdef",
		},
	}

	m := New(WithPatterns(NotionAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NotionAPIToken_holdsATokenTheInputCutShort(t *testing.T) {
	// What Find's second return settles. builtin_scan.go and the rationale in
	// builtin_notion_api_token.go give two shapes: a piece of a prefix
	// standing at the end of the input, and a candidate the end of the input
	// cut short. Everything else is settled to the end of the input, since
	// nothing there could still become a token.
	tests := []struct {
		name   string
		src    string
		retain int
	}{
		{
			// Neither prefix, nor a piece of one, stands anywhere in the text,
			// so the whole of it is settled.
			name:   "no credential at all",
			src:    "there is no credential in this sentence",
			retain: len("there is no credential in this sentence"),
		},
		{
			// The candidate is found by the underscore its own prefix closes
			// with, so a body one character short of a whole ntn_ token, with
			// nothing after it, ends in a candidate the input cut short: the
			// prefix and the forty-five characters that follow are held.
			name:   "a candidate the input cut short of the count",
			src:    "xxx ntn_0123456789abcdef0123456789abcdef0123456789abc",
			retain: 4,
		},
		{
			// A body cut short by fewer characters still leaves the same
			// candidate open.
			name:   "a shorter candidate the input cut short of the count",
			src:    "xxx ntn_0123456789",
			retain: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, retain := NotionAPIToken().Find(tt.src); retain != tt.retain {
				t.Errorf("Find(%q) retain = %d, want %d", tt.src, retain, tt.retain)
			}
		})
	}
}

func Test_NotionAPIToken_scanIsLinear(t *testing.T) {
	// The scan keeps no cursor, so what has to be bounded is the work a single
	// candidate does rather than work repeated across candidates: it reads at
	// most fifty bytes and stops. A line dense in anchors holds a candidate at
	// every underscore, and the bound here is far above a linear scan and far
	// below a quadratic one.
	sources := map[string]string{
		// An anchor at every byte, none of them opening a candidate at all,
		// which is the cheapest way a position is declined.
		"an anchor every byte": strings.Repeat("_", 2000000),
		// A candidate at every four characters, none with a body long
		// enough to be one.
		"a candidate every four characters": strings.Repeat("ntn_", 500000),
		// A candidate at every seven characters, under the longer prefix.
		"a candidate every seven characters": strings.Repeat("secret_", 300000),
		// One candidate whose body is the whole line, which is the walk
		// finding no token because the run never closes on a count of
		// exactly fifty.
		"a body that runs the length of the line": "ntn_" + strings.Repeat("a", 1800000),
		// A token beginning inside every token before it, so every candidate
		// the scan opens is a token and none of the walks is wasted.
		"a token beginning inside every token": strings.Repeat("ntn_0123456789abcdef0123456789abcdef0123456789abcd", 40000),
	}

	checkScanIsLinear(t, NotionAPIToken(), sources)
}

func Test_NotionAPIToken_spansAreAscending(t *testing.T) {
	// A candidate is read backwards from the underscore it was found by, so the
	// spans come out in the order of their anchors rather than of their starts,
	// and the two agree only because no prefix carries the anchor anywhere but
	// at its last character — the argument builtin_notion_api_token.go sets
	// out. Nothing else here would report a disagreement as itself: the
	// reference below is compared span for span, so it would fail on the order
	// without saying that the order was what failed.
	srcs := []string{
		"ntn_0123456789abcdef0123456789abcdef0123456789abcd secret_0123456789abcdef0123456789abcdef0123456789a",
		"secret_0123456789abcdef0123456789abcdef0123456789a ntn_0123456789abcdef0123456789abcdef0123456789abcd",
		"ntn_0123456789abcdef0123456789abcdef0123456789antn_0123456789abcdef0123456789abcdef0123456789abcd",
		"secret_0123456789abcdef0123456789abcdef01234secret_0123456789abcdef0123456789abcdef0123456789a",
		"ntn_secret_0123456789abcdef0123456789abcdef0123456789a",
		"secret_ntn_0123456789abcdef0123456789abcdef0123456789abcd",
		strings.Repeat("ntn_", 64),
		strings.Repeat("secret_", 64),
		strings.Repeat("_", 128),
		strings.Repeat("ntn_secret_", 32),
	}

	for _, src := range srcs {
		spans, _ := NotionAPIToken().Find(src)
		for i := 1; i < len(spans); i++ {
			if spans[i].Start < spans[i-1].Start {
				t.Errorf("Find(%q) reported %v after %v", src, spans[i], spans[i-1])
			}
		}
	}
}

func Test_notionAPITokenPrefixes(t *testing.T) {
	// The scan searches for the character a prefix closes with and reads the
	// prefix backwards from it, and three properties of this table are what
	// make that safe. Nothing else here reports the loss of any of them: a
	// prefix carrying the anchor twice would put a candidate somewhere the
	// ordering argument does not reach, one that is the suffix of another would
	// make the order of the table decide which is read, and a prefix carrying
	// something no body is written with would quietly end the nesting the cases
	// above pin.
	if len(notionAPITokenPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}

	for _, prefix := range notionAPITokenPrefixes {
		t.Run(prefix, func(t *testing.T) {
			if prefix == "" {
				t.Fatal("the table holds an empty prefix")
			}
			if c := prefix[len(prefix)-1]; c != notionAPITokenAnchor {
				t.Errorf("the prefix closes with %q, want the anchor %q", c, byte(notionAPITokenAnchor))
			}
			for i := range len(prefix) - 1 {
				if c := prefix[i]; c == notionAPITokenAnchor {
					t.Errorf("the prefix carries the anchor at %d as well as at its end", i)
				} else if !isBase62Byte(c) {
					t.Errorf("the prefix holds %q, which no body may be written with", c)
				}
			}
			if len(prefix) >= notionAPITokenChars {
				t.Errorf("the prefix is %d characters, leaving no body inside the %d a token is", len(prefix), notionAPITokenChars)
			}
		})
	}

	for i, prefix := range notionAPITokenPrefixes {
		for j, other := range notionAPITokenPrefixes {
			if i != j && strings.HasSuffix(other, prefix) {
				t.Errorf("%q closes with %q, so which of the two is read depends on the order of the table", other, prefix)
			}
		}
	}

	// The anchor ends a body where it stands, which is what makes a candidate
	// findable by its own underscore and what keeps a body from carrying one.
	if isBase62Byte(notionAPITokenAnchor) {
		t.Errorf("the anchor %q belongs to the alphabet a body is written in", byte(notionAPITokenAnchor))
	}
}

func Test_notionAPITokenChars(t *testing.T) {
	// Fifty is what both published shapes come to, and it is the whole of what
	// this pattern reads a length by: the body behind a prefix is whatever is
	// left of it. So each prefix is held to leaving behind it the count the
	// rulesets reading that prefix state — forty-six for the one Notion issues
	// today, forty-three for the one before it — and a prefix added without a
	// count named here is reported rather than silently given whatever fifty
	// leaves.
	const documented = 50
	if notionAPITokenChars != documented {
		t.Errorf("a token is read as %d characters, both published shapes come to %d", notionAPITokenChars, documented)
	}

	bodies := map[string]int{
		"ntn_":    46,
		"secret_": 43,
	}
	for _, prefix := range notionAPITokenPrefixes {
		want, ok := bodies[prefix]
		if !ok {
			t.Errorf("the table carries the prefix %q, which no count here is stated for", prefix)
			continue
		}
		if got := notionAPITokenChars - len(prefix); got != want {
			t.Errorf("%q leaves a body of %d characters, the rulesets reading it state %d", prefix, got, want)
		}
	}
	if len(bodies) != len(notionAPITokenPrefixes) {
		t.Errorf("%d count(s) are stated here for %d prefix(es)", len(bodies), len(notionAPITokenPrefixes))
	}
}

func Test_isNotionAPITokenBody(t *testing.T) {
	// The alphabet, stated over every byte rather than by example. The length
	// is not checked here and is not meant to be: the caller cuts the body to
	// what the count leaves, so a shorter string is answered for on its
	// characters alone.
	body := strings.Repeat("a", notionAPITokenChars-len("ntn_"))
	if !isNotionAPITokenBody(body) {
		t.Errorf("isNotionAPITokenBody(%q) = false, want a run of the alphabet to be one", body)
	}

	for i := range len(body) {
		for c := range 256 {
			b := byte(c)
			src := body[:i] + string([]byte{b}) + body[i+1:]
			if got, want := isNotionAPITokenBody(src), isBase62Byte(b); got != want {
				t.Errorf("isNotionAPITokenBody(%q) = %v with %q at %d, want %v", src, got, b, i, want)
			}
		}
	}
}

// referenceNotionAPITokenFind locates tokens the plain way: every position in
// turn, each prefix tried at it, and the characters behind whichever one stands
// there counted off against that prefix's own count, with nothing remembered
// between candidates.
//
// Both prefixes, both counts and the alphabet are spelled again here rather
// than shared with the scan. A reference reading notionAPITokenPrefixes,
// notionAPITokenChars and isBase62Byte could not disagree with it about them,
// and it is exactly that disagreement the fuzz target below is for: the two
// have to be changed together or reported apart. The counts are spelled as a
// count a body where the scan spells one total and subtracts a prefix, so that
// the subtraction is something the two can disagree about too.
//
// Every position is a starting point in its own right, a match included,
// because the characters in front of either prefix's underscore belong to the
// alphabet a body is written in: a body closing with ntn or with secret opens a
// token beginning inside the match before it. The scan finds both and reports
// the two spans overlapping for a Masker to resolve, so the reference must ask
// about both.
//
// It is written out rather than built on a regular expression, for a reason of
// its own. The grammar states compactly as
// ntn_[0-9A-Za-z]{46}|secret_[0-9A-Za-z]{43}, and it is the alternation rather
// than either count that costs: an expression with one literal in front of it
// is scanned for by searching the text for that literal, and two literals
// leave the engine walking its machine at every byte instead. Measured on a
// mebibyte of alphanumerics holding no token at all, the alternation costs
// seventeen milliseconds where either half of it alone costs fourteen
// microseconds — a thousandfold, on the text a fuzzer spends its time in — and
// the mutator reaches inputs of that size, which left this target running at
// speed for fifteen seconds and then at nothing at all for the rest of its
// run.
//
// What is below has neither problem, and does not pay for it the way the
// Anthropic reference does. Both counts are counts, so a position reads at most
// fifty bytes and stops: there is no run to walk again at the next position,
// nothing quadratic to keep the seeds small around, and the walk is linear in
// the length of the input as the scan is.
func referenceNotionAPITokenFind(src string) []Span {
	prefixes := [...]struct {
		prefix    string
		bodyChars int
	}{
		{"secret_", 43},
		{"ntn_", 46},
	}
	body := func(c byte) bool {
		return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
	}

	var spans []Span
	for start := range len(src) {
		for _, p := range prefixes {
			if !strings.HasPrefix(src[start:], p.prefix) {
				continue
			}
			from := start + len(p.prefix)
			end := from + p.bodyChars
			if end > len(src) {
				continue
			}
			ok := true
			for i := from; i < end; i++ {
				if !body(src[i]) {
					ok = false
					break
				}
			}
			if ok {
				spans = append(spans, Span{Start: start, End: end})
			}
		}
	}
	return spans
}

// FuzzNotionAPIToken_matchesReference guards the hand-written scan: the anchor
// it searches for, the prefixes it reads backwards from that anchor, the count
// it holds a token to, the alphabet it reads a body in and the byte it resumes
// at may none of them change which tokens are located.
func FuzzNotionAPIToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("NOTION_TOKEN=ntn_0123456789abcdef0123456789abcdef0123456789abcd")
	f.Add("secret_0123456789abcdef0123456789abcdef0123456789a")
	f.Add("ntn_0123456789ABCDEF0123456789ABCDEF0123456789ABCD")                   // a body written in capitals
	f.Add("ntn_0123456789abcdef0123456789abcdef0123456789abc")                    // a body one short
	f.Add("ntn_0123456789abcdef0123456789abcdef0123456789abcd0")                  // and a run longer than one
	f.Add("secret_0123456789abcdef0123456789abcdef0123456789")                    // the older body one short
	f.Add("ntn_0123456789abcdef0123-456789abcdef0123456789abc")                   // a hyphen inside a body
	f.Add("ntn_0123456789abcdef0123_456789abcdef0123456789abc")                   // and a further underscore
	f.Add("ntn-0123456789abcdef0123456789abcdef0123456789abcd")                   // a hyphen where the prefix carries its underscore
	f.Add("NTN_0123456789abcdef0123456789abcdef0123456789abcd")                   // an uppercase prefix
	f.Add("xyz_0123456789abcdef0123456789abcdef0123456789abcd")                   // a run of the right length behind another underscore
	f.Add("client_secret_0123456789abcdef0123456789abcdef0123456789a")            // a name closing on the older prefix
	f.Add("ntn_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") // a digest long enough to be a body
	f.Add("ntn_0123456789abcdef0123456789abcdef01234567")                         // and one that is not
	// A token beginning inside the match before it, which a scan resuming past
	// a match steps over, and two tokens with nothing between them, which is
	// the same text without the overlap.
	f.Add("ntn_0123456789abcdef0123456789abcdef0123456789antn_0123456789abcdef0123456789abcdef0123456789abcd")
	f.Add("secret_0123456789abcdef0123456789abcdef01234secret_0123456789abcdef0123456789abcdef0123456789a")
	f.Add("ntn_0123456789abcdef0123456789abcdef0123456789abcdntn_0123456789abcdef0123456789abcdef0123456789abcd")
	f.Add("ntn_0123456789abcdef0123456789abcdef0123456789abcd secret_0123456789abcdef0123456789abcdef0123456789a")
	// The two prefixes crowded together, where a later anchor is closest to
	// opening an earlier candidate, and a run of anchors, which is where a
	// prefix read backwards past the start of the input is decided.
	f.Add("ntn_secret_0123456789abcdef0123456789abcdef0123456789a")
	f.Add("secret_ntn_0123456789abcdef0123456789abcdef0123456789abcd")
	f.Add(strings.Repeat("ntn_", 32))
	f.Add(strings.Repeat("secret_", 32))
	f.Add(strings.Repeat("ntn_secret_", 16))
	f.Add(strings.Repeat("_", 128))
	f.Add("_" + "0123456789abcdef0123456789abcdef0123456789abcd")
	// A JWT, whose signature is written in an alphabet holding the underscore a
	// candidate is found by, and the same with a token written into it.
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.ntn_0123456789abcdef0123456789abcdef0123456789abcd")

	fuzzAgainstReference(f, NotionAPIToken().Find, referenceNotionAPITokenFind)
}

// notionAPITokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func notionAPITokenFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line carries the anchor, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.notion.com/v1/pages `
	token := "ntn_0123456789abcdef0123456789abcdef0123456789abcd"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The anchor is one byte, so text written in snake_case carries it
			// often, and each one costs the prefix table and nothing else. This
			// is the cheapest way a candidate position is declined and the one
			// an environment file or a log of field names reaches.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("field_", 512),
			spans: 0,
		},
		{
			// A candidate at every anchor, each turned away on the fourth byte
			// of its body by the underscore of the next prefix.
			name:  "candidates that are not values",
			src:   strings.Repeat("ntn_", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: a body of the alphabet one
			// character short of the count, so the whole of it is walked before
			// the character that ends it turns the candidate away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("ntn_0123456789abcdef0123456789abcdef0123456789abc ", 16),
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
