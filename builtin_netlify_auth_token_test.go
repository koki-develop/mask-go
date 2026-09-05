package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Netlify authentication token pattern: what it locates and what it leaves
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
// 0123456789abcdefghijklmnopqrstuvwxyz, is thirty-six characters and so is a
// whole body — the shortest the scan reads, since the count is a floor, so a
// body shortened for readability would leave a case holding no token at all.
// It is written in lowercase where the case does not matter and in uppercase
// where the case is what a case is about: base62 holds the letters of both, so
// either spelling is a body.

func Test_NetlifyAuthToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a personal access token on its own",
			src:  "nfp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			name: "a netlify cli token",
			src:  "nfc_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			name: "an oauth access token",
			src:  "nfo_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			name: "an app.netlify.com token",
			src:  "nfu_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			name: "a build token",
			src:  "nfb_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			name: "a token in an environment assignment",
			src:  "NETLIFY_AUTH_TOKEN=nfp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{19, 59}},
		},
		{
			// base62 holds the letters of both cases, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "nfp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			want: []Span{{0, 40}},
		},
		{
			// The count is a floor and the span reaches the end of the run, so
			// a run longer than the shortest body is a token to the end of it
			// rather than a token and a character left over.
			name: "a run longer than the shortest body",
			src:  "nfp_0123456789abcdefghijklmnopqrstuvwxyz0",
			want: []Span{{0, 41}},
		},
		{
			name: "two tokens of different kinds separated by a space",
			src:  "nfp_0123456789abcdefghijklmnopqrstuvwxyz nfb_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			want: []Span{{0, 40}, {41, 81}},
		},
		{
			// The three characters in front of the underscore belong to the
			// alphabet a body is written in, so a body may close with a prefix
			// stripped of its underscore and the underscore of the next token
			// stand directly behind it. The second token begins three
			// characters before the first one ends, and a scan resuming past a
			// match would step over it. The spans overlap, which a Masker
			// resolves into one.
			name: "a token beginning inside the token before it",
			src:  "nfp_0123456789abcdefghijklmnopqrstuvwnfp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}, {37, 77}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := NetlifyAuthToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NetlifyAuthToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "nfp_",
		},
		{
			// Thirty-five characters where the pattern asks for thirty-six.
			// This is the shape a line cut to a column limit leaves, and the
			// characters in front of the cut stay in the text: the far side of
			// reading a floor, which builtin_netlify_auth_token.go weighs.
			name: "a body one character too short",
			src:  "nfp_0123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			// The hyphen and the underscore are base64url characters and no
			// base62 ones, so either ends a body where the run behind it is
			// too short to be one.
			name: "a body carrying a hyphen",
			src:  "nfp_0123456789abcdef-ghijklmnopqrstuvwxyz",
		},
		{
			name: "a body carrying an underscore",
			src:  "nfp_0123456789abcdef_ghijklmnopqrstuvwxyz",
		},
		{
			// The character between the opening and the underscore names one of
			// the five kinds Netlify issues, and an s names none of them —
			// which is what a name opening nfs_ rests on.
			name: "a character naming no kind",
			src:  "nfs_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "an uppercase prefix",
			src:  "NFP_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			// The prefix closes with an underscore, so a hyphen written in its
			// place opens no candidate at all.
			name: "a hyphen where the prefix carries an underscore",
			src:  "nfp-0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "one character of the opening",
			src:  "nxp_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "a space in the body",
			src:  "nfp_0123456789abcdef ghijklmnopqrstuvwxyz",
		},
		{
			name: "a dot in the body",
			src:  "nfp_0123456789abcdef.ghijklmnopqrstuvwxyz",
		},
		{
			name: "a body broken by a line break",
			src:  "nfp_0123456789abcdef\nghijklmnopqrstuvwxyz",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// the whole of the anchor, so a run long enough is not a token
			// without it.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			// The format Netlify issued before this one: no prefix and nothing
			// of its own to be recognised by, so the only thing left to locate
			// one by is the word Netlify standing near it, which is a rule
			// about the text around a value rather than about the value.
			name: "a token of the format netlify issued before this one",
			src:  "NETLIFY_AUTH_TOKEN=0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
		},
		{
			// Unicode normalization code is written in snake_case names opening
			// nfc_, which carries a prefix. What turns them away is the count:
			// the next underscore of such a name ends the run long before
			// thirty-six characters of it have been read.
			name: "a name unicode normalization code is written with",
			src:  "nfc_normalized = nfc_normalize(nfc_quick_check(input_string))",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// Forty hexadecimal characters. A digest carries no underscore, so
			// it holds no prefix to be found at however long it runs.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
		{
			// The character between the opening and the underscore has to
			// name one of the five kinds, and an uppercase letter names none
			// of them: the prefix is read in the one case Netlify writes it.
			name: "the kind letter uppercased",
			src:  "nfP_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "a digit naming no kind",
			src:  "nf1_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			// The kind character is the underscore itself, which is written
			// nowhere Netlify names a kind by.
			name: "an underscore naming no kind",
			src:  "nf__0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "a hyphen naming no kind",
			src:  "nf-_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			// The three-character opening with no kind character between it
			// and the underscore at all -- the shape the announcement's own
			// division would leave were the kind character optional, which it
			// is not.
			name: "the opening and the underscore with no kind between them",
			src:  "nf_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			// A hyphen immediately behind the prefix, with a full
			// thirty-six-character run behind it. The run does not begin
			// until past the hyphen, so it is one character short of a body
			// however far it runs.
			name: "a hyphen at the first character of the body",
			src:  "nfp_-0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "an underscore at the first character of the body",
			src:  "nfp__0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			// A plus and a slash are base64 characters and not base62 ones,
			// so either ends a body exactly as the hyphen and the underscore
			// do.
			name: "a plus in the body",
			src:  "nfp_0123456789abcdef+ghijklmnopqrstuvwxyz",
		},
		{
			name: "a slash in the body",
			src:  "nfp_0123456789abcdef/ghijklmnopqrstuvwxyz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := NetlifyAuthToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_NetlifyAuthToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "NETLIFY_AUTH_TOKEN=nfp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "NETLIFY_AUTH_TOKEN=****************************************",
		},
		{
			// The file the Netlify CLI stores the token it logged in with.
			name: "a config.json field",
			src:  `{"userId":"0123","users":{"0123":{"auth":{"token":"nfc_0123456789abcdefghijklmnopqrstuvwxyz"}}}}`,
			want: `{"userId":"0123","users":{"0123":{"auth":{"token":"****************************************"}}}}`,
		},
		{
			// The header a request to the Netlify API carries a token in.
			name: "an authorization header",
			src:  "Authorization: Bearer nfp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "Authorization: Bearer ****************************************",
		},
		{
			name: "a command line",
			src:  "netlify deploy --prod --auth nfp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "netlify deploy --prod --auth ****************************************",
		},
		{
			name: "twice",
			src:  "nfp_0123456789abcdefghijklmnopqrstuvwxyz nfo_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			want: "**************************************** ****************************************",
		},
		{
			// The two spans are merged, so the token that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a token beginning inside the token before it",
			src:  "nfp_0123456789abcdefghijklmnopqrstuvwnfp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "*****************************************************************************",
		},
	}

	m := New(WithPatterns(NetlifyAuthToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NetlifyAuthToken_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the token through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xnfp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "x****************************************",
		},
		{
			name: "underscore before",
			src:  "NETLIFY_TOKEN_nfp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "NETLIFY_TOKEN_****************************************",
		},
		{
			// A multi-byte rune is no word character, but it is worth pinning
			// beside the two above: nothing about a boundary is asked of it
			// either, in front or behind.
			name: "a multi-byte rune before and after",
			src:  "日本語nfp_0123456789abcdefghijklmnopqrstuvwxyz日本語",
			want: "日本語****************************************日本語",
		},
		{
			name: "an invalid utf-8 byte before",
			src:  "\xffnfp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "\xff****************************************",
		},
	}

	m := New(WithPatterns(NetlifyAuthToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NetlifyAuthToken_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a floor rather than a count. Where a token ends
	// is where its alphabet stops, so a letter or a digit written straight
	// against a token is redacted with it — which is what buys a token of a
	// length Netlify has not published being located whole. The alphabet is
	// base62 and not base64url, so the two characters that separate them, the
	// hyphen and the underscore, end a token here.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the token is nfp_0123456789abcdefghijklmnopqrstuvwxyz.",
			want: "the token is ****************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export NETLIFY_AUTH_TOKEN="nfp_0123456789abcdefghijklmnopqrstuvwxyz"`,
			want: `export NETLIFY_AUTH_TOKEN="****************************************"`,
		},
		{
			name: "a word against the token",
			src:  "nfp_0123456789abcdefghijklmnopqrstuvwxyzsuffix",
			want: "**********************************************",
		},
		{
			name: "a dashed word against the token",
			src:  "nfp_0123456789abcdefghijklmnopqrstuvwxyz-suffix",
			want: "****************************************-suffix",
		},
		{
			name: "an underscored word against the token",
			src:  "nfp_0123456789abcdefghijklmnopqrstuvwxyz_suffix",
			want: "****************************************_suffix",
		},
		{
			// Base64 padding is neither base62 nor a character that closes a
			// prefix, so it ends the run exactly as a hyphen or an underscore
			// would and is left in the text behind the token.
			name: "base64 padding against the token",
			src:  "nfp_0123456789abcdefghijklmnopqrstuvwxyz==",
			want: "****************************************==",
		},
	}

	m := New(WithPatterns(NetlifyAuthToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NetlifyAuthToken_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than
	// redacted. A line cut to a column limit partway through a token leaves a
	// prefix and a body too short to be one, and the random characters written
	// before the cut come through whole.
	//
	// It is the price of reading a count the rules state rather than one Netlify
	// states.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a token one character short of the floor",
			src:  "NETLIFY_AUTH_TOKEN=nfp_0123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			name: "a token cut off at its prefix",
			src:  "NETLIFY_AUTH_TOKEN=nfp_",
		},
	}

	m := New(WithPatterns(NetlifyAuthToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_NetlifyAuthToken_holdsATokenTheInputCutShort(t *testing.T) {
	// What Find's second return settles. builtin_scan.go and the rationale in
	// builtin_netlify_auth_token.go give two shapes: a piece of a prefix
	// standing at the end of the input, and a candidate the end of the input
	// cut short. Everything else is settled to the end of the input, since
	// nothing there could still become a token.
	tests := []struct {
		name   string
		src    string
		retain int
	}{
		{
			// No prefix and no piece of one anywhere in the text, so the whole
			// of it is settled.
			name:   "no credential at all",
			src:    "there is no credential in this sentence",
			retain: len("there is no credential in this sentence"),
		},
		{
			// The last two characters of the input are a piece of every
			// prefix at once, so what comes next could still complete one:
			// the text from there on is held.
			name:   "a piece of the opening at the end of the input",
			src:    "xxx nf",
			retain: 4,
		},
		{
			// A candidate whose body has not reached the floor, with the run
			// carrying on to the end of the input. What comes next either
			// carries the run on to a token or ends it, so this candidate's
			// start is held rather than settled.
			name:   "a candidate the input cut short of the floor",
			src:    "xxx nfp_0123456789abcdef",
			retain: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, retain := NetlifyAuthToken().Find(tt.src); retain != tt.retain {
				t.Errorf("Find(%q) retain = %d, want %d", tt.src, retain, tt.retain)
			}
		})
	}
}

func Test_NetlifyAuthToken_anUnderscoreInTheBody(t *testing.T) {
	// The other side of reading the body in base62 rather than in an alphabet
	// holding the underscore, held to being left in the text.
	// builtin_netlify_auth_token.go argues why the narrow reading is the right
	// one; what it risks is here. Were Netlify writing bodies that carry an
	// underscore, the run would end at that character and a token whose first
	// thirty-six were not all base62 would come through whole.
	//
	// The cases move with the alphabet: one of them starting to be redacted
	// means the body was widened, and that is a decision to be taken rather
	// than noticed afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "an underscore early in the body",
			src:  "NETLIFY_AUTH_TOKEN=nfp_0123_56789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "an underscore one character short of the floor",
			src:  "NETLIFY_AUTH_TOKEN=nfp_0123456789abcdefghijklmnopqrstuvwxy_z",
		},
	}

	m := New(WithPatterns(NetlifyAuthToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_NetlifyAuthToken_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix carries an
	// underscore, which standard base64 writes nowhere, so only a base64url
	// encoding can hold one; where thirty-six base62 characters follow,
	// everything from the prefix to the end of that run is redacted.
	//
	// The cases are held to being redacted rather than to being spared. What is
	// taken is a stretch of a value already opaque to a reader, and the run is a
	// token's format exactly: nothing is left in the text to tell the two apart,
	// so a pattern letting it through would let a real token through with it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "inside a base64url payload",
			src:  "payload=zzzznfp_0123456789abcdefghijklmnopqrstuvwxyzzzzz",
			want: "payload=zzzz********************************************",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the
			// Netlify pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzznfp_0123456789abcdefghijklmnopqrstuvwxyzzzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz********************************************",
		},
	}

	m := New(WithPatterns(NetlifyAuthToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NetlifyAuthToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_netlify_auth_token.go names, held to the answer it
	// gives rather than to the one a reader might want. Hexadecimal digits are
	// base62 and a digest carries nothing that ends a run, so a digest of forty
	// characters or more written behind a prefix is a token's format exactly and
	// is redacted. Declining it would mean declining every token Netlify wrote
	// in the digits alone, which is the whole credential against a cache key.
	//
	// The two below it are where the floor and the prefix each hold: an MD5 is
	// four characters short of a body, and a hyphen is no character a prefix
	// carries.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sha1 behind the prefix",
			src:  "nfp_0123456789abcdef0123456789abcdef01234567",
			want: "********************************************",
		},
		{
			name: "a sha256 in a cache key",
			src:  "key: nfp_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "key: ********************************************************************",
		},
		{
			name: "an md5 behind the prefix, four characters short of a body",
			src:  "nfp_0123456789abcdef0123456789abcdef",
			want: "nfp_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a sha1 behind a hyphen rather than the prefix",
			src:  "nfp-0123456789abcdef0123456789abcdef01234567",
			want: "nfp-0123456789abcdef0123456789abcdef01234567",
		},
	}

	m := New(WithPatterns(NetlifyAuthToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_netlifyAuthTokenOpening(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a token
	// can begin inside the one before it, and that holds only while the
	// characters in front of the underscore are ones a body may be written
	// with. Here they are the opening and the character naming the kind: a body
	// closing with those three leaves the underscore of the next token standing
	// directly behind it. An opening written outside the alphabet would make the
	// two impossible to nest, and the case above pinning the nesting would stand
	// for nothing — which is not a failure anything else here reports.
	if netlifyAuthTokenOpening == "" {
		t.Fatal("the pattern carries no opening, so it locates nothing")
	}
	for i := range len(netlifyAuthTokenOpening) {
		if c := netlifyAuthTokenOpening[i]; !isBase62Byte(c) {
			t.Errorf("the opening holds %q, which no body may be written with", c)
		}
	}
}

func Test_netlifyAuthTokenKinds(t *testing.T) {
	// The characters naming a kind, held to naming no character twice and to
	// being ones a body may be written with. A character repeated would build
	// two prefixes the same, which costs the tail of the input a comparison it
	// can never need; one outside the alphabet would part the nesting the scan
	// resumes a byte along for from the grammar that makes it possible.
	if netlifyAuthTokenKinds == "" {
		t.Fatal("the pattern names no kind, so it locates nothing")
	}

	// The count builtin_netlify_auth_token.go states in prose, held here so that
	// a kind added fails where the sentence naming the number can be found.
	if got, want := len(netlifyAuthTokenKinds), 5; got != want {
		t.Errorf("the table names %d kind(s) and builtin_netlify_auth_token.go says %d", got, want)
	}
	seen := map[byte]bool{}
	for i := range len(netlifyAuthTokenKinds) {
		c := netlifyAuthTokenKinds[i]
		if seen[c] {
			t.Errorf("the kinds name %q twice", c)
		}
		seen[c] = true
		if !isBase62Byte(c) {
			t.Errorf("the kinds name %q, which no body may be written with", c)
		}
	}
}

// Test_netlifyAuthTokenAnchor holds every prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from, and to
// the width the scan reads a body from. builtin_scan.go says why that is held
// here rather than left to the targets.
func Test_netlifyAuthTokenAnchor(t *testing.T) {
	if len(netlifyAuthTokenPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for _, p := range netlifyAuthTokenPrefixes {
		if len(p) != netlifyAuthTokenPrefixChars {
			t.Errorf("the prefix %q is %d characters where the scan reads a body %d in", p, len(p), netlifyAuthTokenPrefixChars)
			continue
		}
		if c := p[netlifyAuthTokenAnchorIndex]; c != netlifyAuthTokenAnchor {
			t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", p, c, byte(netlifyAuthTokenAnchor))
		}
	}
}

func Test_netlifyAuthTokenPrefixes_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over
	// it, where a scan whose prefix closes on a character its own body admits
	// has to keep one. What makes the cursor unnecessary is that two candidates
	// can never read the same run: a candidate asks for the last character of a
	// prefix four characters in, no body may be written with it, so the run of
	// an earlier candidate has already ended there and the later candidate's run
	// begins past it. Were that character one a body admits, a run dense in
	// prefixes would be walked once for every candidate in it and the scan would
	// cost time quadratic in the length of such a line.
	if len(netlifyAuthTokenPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so there is no candidate to reason about")
	}
	for _, p := range netlifyAuthTokenPrefixes {
		if c := p[len(p)-1]; isBase62Byte(c) {
			t.Errorf("the prefix %q closes with %q, which a body may be written with, so two candidates can read the same run", p, c)
		}
	}
}

func Test_NetlifyAuthToken_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a line dense in prefixes
	// holds a candidate for every four characters it has. The one thing a
	// candidate reads that is a walk over the rest of the input rather than a
	// bounded test is where its run ends, and repeating that walk at every
	// candidate would cost time quadratic in the length of the line. The bound
	// here is far above a linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every thirty-seven bytes where they are densest, because a
	// sample has to carry a whole body to be one. The crowding a line can
	// actually carry, a candidate every four bytes, stays here.
	sources := map[string]string{
		// Candidates as close together as a prefix allows, none of them with a
		// run long enough to be a body: every one reaches the body of the loop
		// and every one is rejected.
		"a candidate every four characters": strings.Repeat("nfp_", 500000),
		// Tokens written into one another, each beginning three characters
		// before the one in front of it ends, so every candidate is a token and
		// every one of them walks a run.
		"a token beginning inside every token": strings.Repeat("nfp_0123456789abcdefghijklmnopqrstuvw", 50000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a token.
		"a body that runs the length of the line": "nfp_" + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("a_", 900000),
		// An opening and an anchor with no character naming a kind between
		// them, which is the candidate that costs a whole opening to decline.
		"an opening that names no kind": strings.Repeat("nfs_", 500000),
		// And the opening's own letters with no anchor among them, which is the
		// walk reading a whole line and stopping nowhere in it.
		"the letters of the opening with no anchor": strings.Repeat("nf", 900000),
	}

	checkScanIsLinear(t, NetlifyAuthToken(), sources)
}

// referenceNetlifyAuthToken is the expression the scan in
// builtin_netlify_auth_token.go reads by hand: the statement of what a Netlify
// authentication token is, kept here so that the scan can be held to it.
//
// The opening, the kinds, the separator, the floor and the alphabet are spelled
// again rather than built from netlifyAuthTokenOpening, netlifyAuthTokenKinds,
// netlifyAuthTokenAnchor, netlifyAuthTokenBodyChars and isBase62Byte. A
// reference sharing those declarations could not disagree with the scan about
// them, and it is exactly that disagreement the fuzz target below is for: the
// two have to be changed together or reported apart.
//
// The floor is written as a counted repetition, which costs an engine a machine
// as wide as the floor at every candidate. It costs nothing here, and for the
// reason the scan needs no cursor: candidates cannot crowd inside one run, so
// no input makes an engine walk the same run more than once. The opening is a
// literal in front of the grammar besides, which is what an engine searches the
// text for.
var referenceNetlifyAuthToken = regexp.MustCompile(`nf[pcoub]_[0-9A-Za-z]{36,}`)

// referenceNetlifyAuthTokenFind locates tokens the plain way: the leftmost
// match of the expression above, then the leftmost one beginning after that
// match's first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a token can begin inside one: the three
// characters in front of the underscore are written in the alphabet a body is,
// so a body closing with them holds the start of the token behind it. The scan
// finds both and reports the two spans overlapping for a Masker to resolve, so
// the reference must ask about both.
func referenceNetlifyAuthTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceNetlifyAuthToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzNetlifyAuthToken_matchesReference guards the hand-written scan: the
// opening it searches back from, the kinds it admits between that opening and
// the underscore, the floor it holds a body to, the alphabet it reads that body
// in and the byte it resumes at may none of them change which tokens are
// located.
func FuzzNetlifyAuthToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("NETLIFY_AUTH_TOKEN=nfp_0123456789abcdefghijklmnopqrstuvwxyz")
	f.Add("nfc_0123456789abcdefghijklmnopqrstuvwxyz")
	f.Add("nfo_0123456789abcdefghijklmnopqrstuvwxyz")
	f.Add("nfu_0123456789abcdefghijklmnopqrstuvwxyz")
	f.Add("nfb_0123456789abcdefghijklmnopqrstuvwxyz")
	f.Add("nfs_0123456789abcdefghijklmnopqrstuvwxyz") // a character naming no kind
	f.Add("nfp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	f.Add("nfp_0123456789abcdefghijklmnopqrstuvwxy")   // one short of a body
	f.Add("nfp_0123456789abcdefghijklmnopqrstuvwxyz0") // and a run longer than one
	f.Add("nfp_0123456789abcdef-ghijklmnopqrstuvwxyz") // a hyphen, which base64url admits and base62 does not
	f.Add("nfp_0123456789abcdef_ghijklmnopqrstuvwxyz") // an underscore, likewise
	f.Add("nfp_0123456789abcdef.ghijklmnopqrstuvwxyz") // a dot ends the body
	f.Add("NFP_0123456789abcdefghijklmnopqrstuvwxyz")  // an uppercase prefix
	f.Add("nfp-0123456789abcdefghijklmnopqrstuvwxyz")  // a hyphen where the prefix carries an underscore
	f.Add("nfp_0123456789abcdefghijklmnopqrstuvwxyz-suffix")
	f.Add("nfp_0123456789abcdefghijklmnopqrstuvwxyz_suffix")
	f.Add("nfp_0123456789abcdefghijklmnopqrstuvwxyz\nnfb_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	// A token beginning inside the match before it, which a scan resuming past
	// a match steps over, and two tokens with nothing between them.
	f.Add("nfp_0123456789abcdefghijklmnopqrstuvwnfp_0123456789abcdefghijklmnopqrstuvwxyz")
	f.Add("nfp_0123456789abcdefghijklmnopqrstuvwxyznfo_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	// Candidate positions crowded as close as they can be, with no run long
	// enough for any of them, and tokens written into one another so that every
	// candidate has one.
	f.Add(strings.Repeat("nfp_", 16))
	f.Add(strings.Repeat("nfp_0123456789abcdefghijklmnopqrstuvw", 4))
	// A digest written behind the prefix, which is a token's format exactly, and
	// one four characters short of a body.
	f.Add("nfp_0123456789abcdef0123456789abcdef01234567")
	f.Add("key: nfp_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("nfp_0123456789abcdef0123456789abcdef")
	// Names Unicode normalization code is written with, which carry a prefix and
	// which only the floor turns away.
	f.Add("nfc_normalized = nfc_normalize(nfc_quick_check(input_string))")
	// The prefix written inside a run of base64url, which is the over-match the
	// pattern admits.
	f.Add("payload=zzzznfp_0123456789abcdefghijklmnopqrstuvwxyzzzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzznfp_0123456789abcdefghijklmnopqrstuvwxyzzzzz")

	fuzzAgainstReference(f, NetlifyAuthToken().Find, referenceNetlifyAuthTokenFind)
}

// netlifyAuthTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func netlifyAuthTokenFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens a prefix, so what the line times is the
	// search for the underscore — which is most of what this pattern costs a
	// caller whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="deploying a site" url=https://api.netlify.com/api/v1/sites `
	token := "nfp_0123456789abcdefghijklmnopqrstuvwxyz"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every four characters with no run long enough behind
			// any of them: each reaches the body of the loop and none becomes a
			// token. What it times is the walk over a run being started and
			// stopped, once per candidate and no more.
			name:  "candidates that are not values",
			src:   strings.Repeat("nfp_", 128),
			spans: 0,
		},
		{
			// The same crowding with a character naming no kind, which is the
			// candidate declined by the one byte read after the opening.
			name:  "candidates naming no kind",
			src:   strings.Repeat("nfs_", 128),
			spans: 0,
		},
		{
			// Tokens written into one another, each beginning three characters
			// before the one in front of it ends. This is what the scan gets
			// away with keeping no cursor for: the runs the candidates read
			// follow one another rather than overlapping. The three characters
			// at the end are what closes the body of the last of them, which
			// otherwise has only the run it was written with.
			name:  "tokens written into one another",
			src:   strings.Repeat("nfp_0123456789abcdefghijklmnopqrstuvw", 128) + "xyz",
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
