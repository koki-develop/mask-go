package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Paddle API key pattern: what it locates and what it leaves alone, written
// out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The keys written out below are made only of ordered characters: valid in
// shape, obviously not real. The run 0123456789abcdef serves for all three
// segments — once and ten characters over for the twenty-six of the first,
// once and six over for the twenty-two of the second, and three characters of
// it for the third — and with the sixteen character prefix in front and the two
// separators between, a key comes to sixty-nine.

func Test_PaddleAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a live api key",
			src:  "pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012",
			want: []Span{{0, 69}},
		},
		{
			name: "a live api key in an environment assignment",
			src:  "PADDLE_API_KEY=pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012",
			want: []Span{{15, 84}},
		},
		{
			name: "a sandbox api key",
			src:  "pdl_sdbx_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012",
			want: []Span{{0, 69}},
		},
		{
			// The two segments behind the first are read in base62, which is
			// the class the vendor's expression spells for each of them.
			name: "the last two segments written in capitals",
			src:  "pdl_live_apikey_0123456789abcdef0123456789_0123456789ABCDEF012345_01A",
			want: []Span{{0, 69}},
		},
		{
			name: "two keys with nothing between them",
			src:  "pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012pdl_sdbx_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012",
			want: []Span{{0, 69}, {69, 138}},
		},
		{
			// A key beginning sixty-two characters into another, which is the
			// one shape the scan's step at a candidate is for: the second
			// segment closes on pdl, the separator in front of the third stands
			// behind them, the third reads liv and the text carrying on from
			// the key writes the rest of a prefix.
			// Test_PaddleAPIKey_aKeyBeginningInsideAnother is what counts the
			// positions this can happen at.
			name: "a key beginning inside the key before it",
			src:  "pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012",
			want: []Span{{0, 69}, {62, 131}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PaddleAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PaddleAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a prefix alone",
			src:  "pdl_live_apikey_",
		},
		{
			name: "a first segment one character short",
			src:  "pdl_live_apikey_0123456789abcdef012345678_0123456789abcdef012345_012",
		},
		{
			name: "a first segment one character long",
			src:  "pdl_live_apikey_0123456789abcdef01234567890_0123456789abcdef012345_012",
		},
		{
			name: "a second segment one character short",
			src:  "pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef01234_012",
		},
		{
			name: "a third segment one character short",
			src:  "pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_01",
		},
		{
			// The first segment is read in the lowercase letters and the
			// digits, which is the class the vendor's expression spells for it.
			name: "an uppercase letter in the first segment",
			src:  "pdl_live_apikey_0123456789ABCDEF0123456789_0123456789abcdef012345_012",
		},
		{
			name: "an uppercase prefix",
			src:  "PDL_LIVE_APIKEY_0123456789abcdef0123456789_0123456789abcdef012345_012",
		},
		{
			// The environment the client-side token is written with, which is
			// no environment an API key carries: Paddle writes live or sdbx and
			// nothing else.
			name: "an environment paddle does not publish",
			src:  "pdl_test_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012",
		},
		{
			name: "hyphens where the separators stand",
			src:  "pdl_live_apikey_0123456789abcdef0123456789-0123456789abcdef012345-012",
		},
		{
			name: "the first separator missing",
			src:  "pdl_live_apikey_0123456789abcdef01234567890123456789abcdef0123456_012",
		},
		{
			name: "the second separator missing",
			src:  "pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef0123450123",
		},
		{
			name: "a first segment broken by a space",
			src:  "pdl_live_apikey_0123456789abcdef 123456789_0123456789abcdef012345_012",
		},
		{
			name: "a second segment broken by a line break",
			src:  "pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef\n12345_012",
		},
		{
			name: "a hyphen inside the second segment",
			src:  "pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef-12345_012",
		},
		{
			// The right counts and the right classes behind an opening that is
			// not this vendor's. The prefix is the whole of the anchor.
			name: "a value of the right shape opening with no prefix",
			src:  "xxx_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// A line carrying the byte the scan searches for several times
			// over, none of them with a prefix in front of it.
			name: "the anchor as it is written in prose",
			src:  "the key the worker keeps in a bucket is checked by nobody",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PaddleAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PaddleAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "PADDLE_API_KEY=pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012",
			want: "PADDLE_API_KEY=*********************************************************************",
		},
		{
			// How a key reaches the API, and how it reaches a log line that
			// echoed the header.
			name: "the bearer authorization header a request carries it in",
			src:  "Authorization: Bearer pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012",
			want: "Authorization: Bearer *********************************************************************",
		},
		{
			name: "a command line",
			src:  "curl -H 'Authorization: Bearer pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012' https://api.paddle.com/transactions",
			want: "curl -H 'Authorization: Bearer *********************************************************************' https://api.paddle.com/transactions",
		},
		{
			name: "a json body",
			src:  `{"apiKey":"pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012"}`,
			want: `{"apiKey":"*********************************************************************"}`,
		},
		{
			// The key of each environment as a deployment is configured with
			// them, which is where two of them arrive together.
			name: "the keys of both environments in one configuration",
			src:  "PADDLE_API_KEY=pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012\nPADDLE_SANDBOX_API_KEY=pdl_sdbx_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012",
			want: "PADDLE_API_KEY=*********************************************************************\nPADDLE_SANDBOX_API_KEY=*********************************************************************",
		},
	}

	m := New(WithPatterns(PaddleAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PaddleAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the key through whole. The first two are what the
	// demand in front would cost, and the third what the demand behind it
	// would.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "xpdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012",
			want: "x*********************************************************************",
		},
		{
			name: "underscore before",
			src:  "PADDLE_API_KEY_pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012",
			want: "PADDLE_API_KEY_*********************************************************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this key rather
			// than trim it; without one the sixty-nine characters Paddle issued
			// are redacted and the one written after them, which is part of no
			// credential, stays in the text.
			name: "a character of the third segment's class after",
			src:  "pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_0123",
			want: "*********************************************************************3",
		},
	}

	m := New(WithPatterns(PaddleAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PaddleAPIKey_leavesWhatFollowsAlone(t *testing.T) {
	// A key is sixty-nine characters and no more, so what is written after one
	// stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the key is pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012.",
			want: "the key is *********************************************************************.",
		},
		{
			name: "quoted",
			src:  `"pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012"`,
			want: `"*********************************************************************"`,
		},
		{
			name: "dashed word",
			src:  "pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012-suffix",
			want: "*********************************************************************-suffix",
		},
		{
			// A word written straight against a key comes through: the counts
			// have already ended the key, and a letter ends nothing here.
			name: "a word written against a key",
			src:  "pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012suffix",
			want: "*********************************************************************suffix",
		},
	}

	m := New(WithPatterns(PaddleAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PaddleAPIKey_aKeyBeginningInsideAnother(t *testing.T) {
	// Where a key may begin inside another, counted out of the declarations
	// that decide it rather than claimed in prose. A key opens on a prefix
	// carrying three underscores, at its fourth, ninth and sixteenth character,
	// and the underscores a key holds stand at five places: the three of its
	// own prefix and the two dividing its segments. So a position inside a key
	// opens one only where each of those three falls on an underscore of the
	// key it stands in or past the end of it, where the text carrying on is
	// free to write anything.
	//
	// That leaves four positions, and they divide in two. One is sixty-two
	// characters in, where the separator in front of the third segment stands
	// where a prefix's fourth character has to — the case the table at the top
	// of this file writes out. The other three are the last three characters of
	// a key, where the whole of the prefix but its first characters is written
	// by whatever follows. A prefix lengthened or a count changed moves the
	// number, and nothing else here would report it.
	prefixUnderscores := []int{
		len(paddleAPIKeyOpening) - 1,
		len(paddleAPIKeyOpening) + paddleAPIKeyEnvironmentChars,
		paddleAPIKeyPrefixChars - 1,
	}
	keyUnderscores := map[int]bool{
		paddleAPIKeyPrefixChars + paddleAPIKeyFirstSeparatorIndex:  true,
		paddleAPIKeyPrefixChars + paddleAPIKeySecondSeparatorIndex: true,
	}
	for _, k := range prefixUnderscores {
		keyUnderscores[k] = true
	}

	inside := 0
	for p := 1; p < paddleAPIKeyChars; p++ {
		opens := true
		for _, k := range prefixUnderscores {
			if p+k < paddleAPIKeyChars && !keyUnderscores[p+k] {
				opens = false
				break
			}
		}
		if opens {
			inside++
		}
	}
	if want := 4; inside != want {
		t.Errorf("%d position(s) inside a key can open one, want %d", inside, want)
	}

	// And what the scan does with the one of them a key can be written whole
	// at: both keys are located, the spans overlap, and Masker.locate resolves
	// them into one redaction that leaves neither key to be found.
	src := "pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012"
	want := []Span{{0, 69}, {62, 131}}
	if got, _ := PaddleAPIKey().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}

	m := New(WithPatterns(PaddleAPIKey()))
	if got, wanted := m.Mask(src), strings.Repeat("*", len(src)); got != wanted {
		t.Errorf("Mask(%q) = %q, want %q", src, got, wanted)
	}
}

func Test_PaddleAPIKey_aFirstSegmentOutsideCrockfordsAlphabet(t *testing.T) {
	// The tightening builtin_paddle_api_key.go declines. Twenty-six lowercase
	// characters holding neither i, l, o nor u is what a ULID is written in, and
	// the first segment of the key Paddle publishes carries none of the four —
	// but the expression it publishes admits the whole lowercase alphabet, and
	// a class narrowed on the values somebody was shown would locate nothing at
	// all the day a key arrived carrying one of the four.
	//
	// So a first segment carrying all four is a key here, and the whole of it
	// is located.
	src := "pdl_live_apikey_0123456789abcdefilou012345_0123456789abcdef012345_012"
	want := []Span{{0, 69}}
	if got, _ := PaddleAPIKey().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}
}

func Test_PaddleAPIKey_theWebhookSecretKey(t *testing.T) {
	// The other credential Paddle writes with the pdl_ opening. Its own
	// component list says apikey_ is what differentiates an API key from
	// anything else written that way, and the secret key a notification
	// destination is verified by is written pdl_ntfset_ instead.
	//
	// Nothing Paddle publishes states a length or an alphabet for it — there is
	// one example and no grammar — so it is left in the output, and reading it
	// would take a pattern built on whatever Paddle comes to state. The
	// decision is written down here so that it is one somebody argues for
	// rather than one somebody notices afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a webhook secret key",
			src:  "pdl_ntfset_0123456789abcdef0123456789_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a webhook secret key in an environment assignment",
			src:  "PADDLE_WEBHOOK_SECRET_KEY=pdl_ntfset_0123456789abcdef0123456789_0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PaddleAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PaddleAPIKey_theKeyFormatItReplaced(t *testing.T) {
	// The keys Paddle issued before 6 May 2025, which it calls legacy keys and
	// states continue to work without disruption. They are live credentials and
	// this pattern locates none of them: Paddle describes one as a random
	// string of fifty characters holding only lowercase letters and digits, so
	// there is no prefix to search for and nothing to read but a length over an
	// alphabet — the loose grammar this package declines rather than the
	// unlucky one, since fifty lowercase characters are a digest written out,
	// an encoded payload, or an identifier some other vendor assigns.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a legacy key",
			src:  "0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a legacy key in an environment assignment",
			src:  "PADDLE_API_KEY=0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a legacy key in the header a request carries it in",
			src:  "Authorization: Bearer 0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PaddleAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PaddleAPIKey_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor, and what holds it linear is the counts being
	// counts: a candidate reads at most sixty-nine bytes and stops. These are
	// the inputs that would find it wrong here — a line that is nothing but
	// prefixes, a line that is nothing but keys, and two runs as long as the
	// line, one of the alphabet a segment is written in and one of the byte the
	// search stops at.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// whole key apiece and so hold a candidate every sixty-nine bytes at their
	// densest. The crowding a line can actually carry, a candidate every
	// sixteen, stays here.
	sources := map[string]string{
		// A candidate every sixteen characters, each turned away where the
		// separator between its first two segments would stand, which is the
		// cheapest this scan declines a candidate whose prefix is whole.
		"a candidate every sixteen characters": strings.Repeat("pdl_live_apikey_", 128000),
		// The same crowding with a whole key at each candidate, so every one of
		// them reads fifty-three characters and reports a span.
		"a key every sixty-nine characters": strings.Repeat("pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012", 20000),
		// A candidate walked to its last character before the third segment's
		// alphabet turns it away, which is the most a rejected candidate can
		// cost.
		"a candidate walked to its last character": strings.Repeat("pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_01! ", 20000),
		// One candidate whose segments are the whole line. The counts stop it
		// at fifty-three characters; a scan reading the run would read two
		// mebibytes.
		"a lowercase run the length of the line": "pdl_live_apikey_" + strings.Repeat("a", 2000000),
		// The byte the search stops at, written the length of the line with no
		// prefix anywhere in it. Every position is one the search reports and
		// the byte twelve characters in front of it turns away.
		"a run of the anchor the length of the line": strings.Repeat("k", 2000000),
	}

	checkScanIsLinear(t, PaddleAPIKey(), sources)
}

func Test_paddleAPIKeyPrefixes(t *testing.T) {
	// What the scan needs of the prefixes, which nothing else here reports: a
	// prefix nothing locates simply locates nothing, and the cases above would
	// go on passing for the environment that still works.
	//
	// Every prefix is one length, which is what lets a candidate be read back
	// from one index, and every one carries the anchor at that index. An
	// environment written to another length, or a marker that moved the anchor,
	// would leave the scan opening candidates nowhere near where a key begins.
	if len(paddleAPIKeyPrefixes) != len(paddleAPIKeyEnvironments) {
		t.Errorf("%d prefix(es) for %d environment(s)", len(paddleAPIKeyPrefixes), len(paddleAPIKeyEnvironments))
	}
	for _, env := range paddleAPIKeyEnvironments {
		if len(env) != paddleAPIKeyEnvironmentChars {
			t.Errorf("the environment %q is %d characters, want %d", env, len(env), paddleAPIKeyEnvironmentChars)
		}
	}
	for _, prefix := range paddleAPIKeyPrefixes {
		if len(prefix) != paddleAPIKeyPrefixChars {
			t.Errorf("the prefix %q is %d characters, want %d", prefix, len(prefix), paddleAPIKeyPrefixChars)
		}
		if prefix[0] != paddleAPIKeyOpening[0] {
			t.Errorf("the prefix %q opens with %q, where the scan tests for %q",
				prefix, prefix[0], paddleAPIKeyOpening[0])
		}
		if got := prefix[paddleAPIKeyAnchorIndex]; got != paddleAPIKeyAnchor {
			t.Errorf("%q[%d] = %q, want the anchor %q", prefix, paddleAPIKeyAnchorIndex, got, paddleAPIKeyAnchor)
		}
		// Where the anchor is fixed it stands once, which is what this counts.
		// Where it is not is the segments: base62 holds the k, so a key may
		// carry it as many times again, and each of those stops the search for
		// the one comparison against the byte twelve characters in front of it.
		if n := strings.Count(prefix, string(paddleAPIKeyAnchor)); n != 1 {
			t.Errorf("the anchor stands %d times in %q, want 1", n, prefix)
		}
	}

	// And what the separator needs to be: a character no segment holds, so that
	// a run of either alphabet can never carry one and the counts either side
	// of it are readable at all.
	if isBase62Byte(paddleAPIKeySeparator) || isPaddleAPIKeyFirstSegmentByte(paddleAPIKeySeparator) {
		t.Errorf("the separator %q is a character a segment may be written with", byte(paddleAPIKeySeparator))
	}
}

func Test_paddleAPIKeyChars(t *testing.T) {
	// The arithmetic held to what Paddle's own API keys page states: the three
	// counts its expression asks for, and the sixty-nine characters and five
	// underscores it writes a key is. The key built here is built from the
	// declarations the scan reads, so a count changed anywhere moves it.
	const (
		documentedFirstSegmentChars  = 26
		documentedSecondSegmentChars = 22
		documentedThirdSegmentChars  = 3
		documentedChars              = 69
		documentedUnderscores        = 5
	)

	if paddleAPIKeyFirstSegmentChars != documentedFirstSegmentChars {
		t.Errorf("the first segment is read as %d characters, the expression states %d",
			paddleAPIKeyFirstSegmentChars, documentedFirstSegmentChars)
	}
	if paddleAPIKeySecondSegmentChars != documentedSecondSegmentChars {
		t.Errorf("the second segment is read as %d characters, the expression states %d",
			paddleAPIKeySecondSegmentChars, documentedSecondSegmentChars)
	}
	if paddleAPIKeyThirdSegmentChars != documentedThirdSegmentChars {
		t.Errorf("the third segment is read as %d characters, the expression states %d",
			paddleAPIKeyThirdSegmentChars, documentedThirdSegmentChars)
	}

	key := paddleAPIKeyPrefixes[0] +
		strings.Repeat("a", paddleAPIKeyFirstSegmentChars) + string(paddleAPIKeySeparator) +
		strings.Repeat("a", paddleAPIKeySecondSegmentChars) + string(paddleAPIKeySeparator) +
		strings.Repeat("a", paddleAPIKeyThirdSegmentChars)
	if len(key) != documentedChars {
		t.Errorf("a key is built to %d characters, the page states %d", len(key), documentedChars)
	}
	if n := strings.Count(key, string(paddleAPIKeySeparator)); n != documentedUnderscores {
		t.Errorf("a key carries %d underscores, the page states %d", n, documentedUnderscores)
	}
	if paddleAPIKeyChars != len(key) {
		t.Errorf("paddleAPIKeyChars = %d, where a key built from the parts is %d", paddleAPIKeyChars, len(key))
	}
}

// referencePaddleAPIKey is the expression the scan in builtin_paddle_api_key.go
// reads by hand: the statement of what a Paddle API key is, kept here so that
// the scan can be held to it.
//
// It is the expression Paddle publishes to validate a key with, its anchors
// taken off, and it is spelled out again rather than built from the
// declarations beside the scan. A reference sharing those could not disagree
// with the scan about them, and it is exactly that disagreement the fuzz target
// below is for: the two have to be changed together or reported apart.
//
// All three repetitions are exact, so the machine an engine builds for a
// candidate is read once and stops, where a floor spelled as a counted
// repetition would cost a machine as wide as the floor at every candidate. What
// an engine searches the text for is the four character literal in front of the
// alternation, which closes on the underscore no segment is written with — so a
// run of a segment's alphabet, which is where candidates would otherwise crowd,
// holds no position for the engine to walk its machine at.
var referencePaddleAPIKey = regexp.MustCompile(`pdl_(live|sdbx)_apikey_[a-z0-9]{26}_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{3}`)

// referencePaddleAPIKeyFind locates keys the plain way: the leftmost match of
// the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// Asking at every byte rather than resuming past a match is what the scan does
// and is what a key written inside another needs: a second segment may close on
// the characters an opening begins with, so a match can begin sixty-two
// characters into the one in front of it, and resuming past the first would
// lose it.
func referencePaddleAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referencePaddleAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzPaddleAPIKey_matchesReference guards the hand-written scan: the byte it
// searches for, the prefixes it reads back from that byte, the environments it
// admits, the two separators, the three counts it reads and the classes it
// reads them in may none of them change which keys are located.
func FuzzPaddleAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("PADDLE_API_KEY=pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012")
	f.Add("pdl_sdbx_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012")  // the sandbox environment
	f.Add("pdl_live_apikey_0123456789abcdef0123456789_0123456789ABCDEF012345_01A")  // capitals in the last two segments
	f.Add("pdl_live_apikey_0123456789ABCDEF0123456789_0123456789abcdef012345_012")  // and a capital in the first, which is no key
	f.Add("pdl_live_apikey_0123456789abcdefilou012345_0123456789abcdef012345_012")  // a first segment outside Crockford's alphabet
	f.Add("pdl_test_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012")  // an environment Paddle does not publish
	f.Add("PDL_LIVE_APIKEY_0123456789abcdef0123456789_0123456789abcdef012345_012")  // an uppercase prefix
	f.Add("xxx_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012")  // the right shape with no opening
	f.Add("pdl_live_apikey_0123456789abcdef012345678_0123456789abcdef012345_012")   // a first segment one short
	f.Add("pdl_live_apikey_0123456789abcdef01234567890_0123456789abcdef012345_012") // and one long
	f.Add("pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef01234_012")   // a second segment one short
	f.Add("pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_01")   // a third segment one short
	f.Add("pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_0123") // and a run longer than one
	f.Add("pdl_live_apikey_0123456789abcdef0123456789-0123456789abcdef012345-012")  // hyphens where the separators stand
	f.Add("pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef\n12345_012") // a key a line break breaks
	f.Add("pdl_ntfset_0123456789abcdef0123456789_0123456789abcdef0123456789abcdef") // a webhook secret key
	f.Add("PADDLE_API_KEY=0123456789abcdef0123456789abcdef0123456789abcdef01")      // a legacy key
	f.Add("xpdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012") // written against a letter
	f.Add("pdl_live_apikey_")                                                       // a prefix alone
	// A key beginning inside another, and two keys with nothing between them,
	// which is what advancing rather than consuming the match has to find.
	f.Add("pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012")
	f.Add("pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012pdl_sdbx_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012")
	// Candidate positions crowded as close as they can be, a lowercase run with
	// no prefix in front of it, and a run of the byte the search stops at.
	f.Add(strings.Repeat("pdl_live_apikey_", 32))
	f.Add(strings.Repeat("pdl_live_apikey_", 32) + strings.Repeat("0123456789abcdef", 4))
	f.Add(strings.Repeat("k", 128))

	fuzzAgainstReference(f, PaddleAPIKey().Find, referencePaddleAPIKeyFind)
}

// paddleAPIKeyFindBenchmarks is what this scan is timed on. The builtinPatterns
// entry for the pattern names it, and BenchmarkBuiltins times every case it
// holds under the pattern's own name, so that a built-in cannot arrive without
// a benchmark. Every case is held to the count it states under a plain go test
// as well, which is what a benchmark nobody has run yet cannot be.
func paddleAPIKeyFindBenchmarks() []benchmarkCase {
	// The line carries the byte the scan searches for not at all, where the p
	// stands four times, the l six and the a seven — the count that made the k
	// the byte to search for.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.paddle.com/transactions status=200 `
	key := "pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_012"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix written over and over, so a candidate stands at every
			// sixteenth byte and every one of them is turned away where the
			// separator between its first two segments would stand. That is the
			// cheapest this scan declines a candidate whose prefix is whole.
			name:  "candidates that are not values",
			src:   strings.Repeat("pdl_live_apikey_", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: both separators found and the
			// segments walked to their last character before it turns the
			// candidate away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("pdl_live_apikey_0123456789abcdef0123456789_0123456789abcdef012345_01! ", 16),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "key=" + key,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "key=" + key,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"key="+key+"\n", 32),
			spans: 32,
		},
	}
}
