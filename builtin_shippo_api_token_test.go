package mask

import (
	"slices"
	"strings"
	"testing"
)

// The Shippo API token pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. The run they are built from, 0123456789abcdef, is
// sixteen characters, so a body is that run twice over and half of it again —
// the shortest body the scan reads, since the count is a floor, so a body
// shortened for readability would leave a case holding no token at all. It is
// written in lowercase where the case does not matter and in uppercase where
// the case is what a case is about: a body is hexadecimal of either case, so
// either spelling is a body.

func Test_ShippoAPIToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a live token on its own",
			src:  "shippo_live_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 52}},
		},
		{
			name: "a test token on its own",
			src:  "shippo_test_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 52}},
		},
		{
			name: "a token in an environment assignment",
			src:  "SHIPPO_API_TOKEN=shippo_live_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{17, 69}},
		},
		{
			// A body is hexadecimal in either case, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "shippo_live_0123456789ABCDEF0123456789ABCDEF01234567",
			want: []Span{{0, 52}},
		},
		{
			// The count is a floor and the span reaches the end of the run, so
			// a run longer than the shortest body is a token to the end of it
			// rather than a token and a character left over.
			name: "a run longer than the shortest body",
			src:  "shippo_live_0123456789abcdef0123456789abcdef012345670",
			want: []Span{{0, 53}},
		},
		{
			name: "the two modes separated by a space",
			src:  "shippo_live_0123456789abcdef0123456789abcdef01234567 shippo_test_0123456789ABCDEF0123456789ABCDEF01234567",
			want: []Span{{0, 52}, {53, 105}},
		},
		{
			// The opening is written in no hexadecimal character, so the body
			// of the first token ends at the s of the second and the two spans
			// meet rather than overlapping.
			name: "two tokens with nothing between them",
			src:  "shippo_live_0123456789abcdef0123456789abcdef01234567shippo_test_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 52}, {52, 104}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ShippoAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ShippoAPIToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "shippo_live_",
		},
		{
			name: "the opening alone",
			src:  "shippo_",
		},
		{
			// Thirty-nine characters where the pattern asks for forty. This is
			// the shape a line cut to a column limit leaves, and the characters
			// in front of the cut stay in the text: the far side of reading a
			// floor, which builtin_shippo_api_token.go weighs.
			name: "a body one character too short",
			src:  "shippo_live_0123456789abcdef0123456789abcdef0123456",
		},
		{
			// The placeholder Shippo's own authentication example writes where
			// a token goes.
			name: "the placeholder the documentation writes",
			src:  "Authorization: ShippoToken shippo_test_token",
		},
		{
			// A body is hexadecimal, so a letter past f ends the run — and what
			// stands in front of that letter here is thirty-two characters,
			// short of the floor.
			name: "a body carrying a letter past f",
			src:  "shippo_live_0123456789abcdef0123456789abcdefg1234567",
		},
		{
			name: "a body carrying a hyphen",
			src:  "shippo_live_0123456789abcdef0123456789abcdef-1234567",
		},
		{
			name: "a body carrying an underscore",
			src:  "shippo_live_0123456789abcdef0123456789abcdef_1234567",
		},
		{
			name: "a space in the body",
			src:  "shippo_live_0123456789abcdef0123456789abcdef 1234567",
		},
		{
			name: "a body broken by a line break",
			src:  "shippo_live_0123456789abcdef0123456789abcdef\n1234567",
		},
		{
			name: "an uppercase prefix",
			src:  "SHIPPO_LIVE_0123456789abcdef0123456789abcdef01234567",
		},
		{
			// The prefix is written with the underscores Shippo divides it by,
			// not with the hyphens a delimiter is elsewhere.
			name: "hyphens where the prefix carries underscores",
			src:  "shippo-live-0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "the opening without its underscore",
			src:  "shippolive_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "the mode without the underscore that closes it",
			src:  "shippo_live0123456789abcdef0123456789abcdef01234567",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// the whole of what tells this format from a digest.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ShippoAPIToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_ShippoAPIToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "SHIPPO_API_TOKEN=shippo_live_0123456789abcdef0123456789abcdef01234567",
			want: "SHIPPO_API_TOKEN=****************************************************",
		},
		{
			// The header the Shippo API is called with, which carries the
			// scheme ShippoToken rather than Bearer.
			name: "a shippotoken authorization header",
			src:  "Authorization: ShippoToken shippo_live_0123456789abcdef0123456789abcdef01234567",
			want: "Authorization: ShippoToken ****************************************************",
		},
		{
			name: "json",
			src:  `{"token":"shippo_test_0123456789abcdef0123456789abcdef01234567"}`,
			want: `{"token":"****************************************************"}`,
		},
		{
			name: "a command line",
			src:  `curl -H "Authorization: ShippoToken shippo_live_0123456789abcdef0123456789abcdef01234567" https://api.goshippo.com/shipments/`,
			want: `curl -H "Authorization: ShippoToken ****************************************************" https://api.goshippo.com/shipments/`,
		},
		{
			name: "a configuration environment block",
			src:  `"env": {"SHIPPO_API_TOKEN": "shippo_test_0123456789abcdef0123456789abcdef01234567"}`,
			want: `"env": {"SHIPPO_API_TOKEN": "****************************************************"}`,
		},
		{
			name: "both modes on one line",
			src:  "live=shippo_live_0123456789abcdef0123456789abcdef01234567 test=shippo_test_0123456789abcdef0123456789abcdef01234567",
			want: "live=**************************************************** test=****************************************************",
		},
	}

	m := New(WithPatterns(ShippoAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ShippoAPIToken_theModesShippoWrites(t *testing.T) {
	// The two modes are read by name rather than as any word standing where a
	// mode stands, and these are what that decides. Shippo writes the vendor's
	// own name in front of a word elsewhere — the account id its carrier-account
	// response carries for a carrier it provides is shippo_ups_account — so a
	// scan reading shippo_ and any word would open a candidate there.
	//
	// What the decision wagers is the mode Shippo has not written yet, and the
	// third case is that wager: a mode nothing states is a mode this scan does
	// not read, and the token carrying it stays in the text whole. The cases
	// move with shippoAPITokenModes, so reading another one is a decision taken
	// rather than a widening nobody noticed.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "the live mode",
			src:  "shippo_live_0123456789abcdef0123456789abcdef01234567",
			want: "****************************************************",
		},
		{
			name: "the test mode",
			src:  "shippo_test_0123456789abcdef0123456789abcdef01234567",
			want: "****************************************************",
		},
		{
			name: "a mode no shippo page writes",
			src:  "shippo_prod_0123456789abcdef0123456789abcdef01234567",
			want: "shippo_prod_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a carrier account id written with the vendor name",
			src:  `"account_id":"shippo_ups_account"`,
			want: `"account_id":"shippo_ups_account"`,
		},
	}

	m := New(WithPatterns(ShippoAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ShippoAPIToken_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the token through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xshippo_live_0123456789abcdef0123456789abcdef01234567",
			want: "x****************************************************",
		},
		{
			name: "underscore before",
			src:  "SHIPPO_API_TOKEN_shippo_live_0123456789abcdef0123456789abcdef01234567",
			want: "SHIPPO_API_TOKEN_****************************************************",
		},
	}

	m := New(WithPatterns(ShippoAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ShippoAPIToken_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a floor rather than a count. Where a token ends
	// is where its alphabet stops, so a hexadecimal character written straight
	// against a token is redacted with it — which is what buys a token of a
	// length nobody has published being located whole. A letter past f, a
	// hyphen and an underscore end it instead.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the token is shippo_live_0123456789abcdef0123456789abcdef01234567.",
			want: "the token is ****************************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export SHIPPO_API_TOKEN="shippo_live_0123456789abcdef0123456789abcdef01234567"`,
			want: `export SHIPPO_API_TOKEN="****************************************************"`,
		},
		{
			name: "a hexadecimal word against the token",
			src:  "shippo_live_0123456789abcdef0123456789abcdef01234567deadbeef",
			want: "************************************************************",
		},
		{
			name: "a word past f against the token",
			src:  "shippo_live_0123456789abcdef0123456789abcdef01234567suffix",
			want: "****************************************************suffix",
		},
		{
			name: "a dashed word against the token",
			src:  "shippo_live_0123456789abcdef0123456789abcdef01234567-suffix",
			want: "****************************************************-suffix",
		},
		{
			name: "an underscored word against the token",
			src:  "shippo_live_0123456789abcdef0123456789abcdef01234567_suffix",
			want: "****************************************************_suffix",
		},
	}

	m := New(WithPatterns(ShippoAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ShippoAPIToken_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than
	// redacted. A line cut to a column limit partway through a token leaves a
	// prefix and a body too short to be one, and the random characters written
	// before the cut come through whole.
	//
	// It is the price of reading a count no Shippo page states, and the cases
	// move with the scan: one of them starting to be located means the floor
	// moved, and that is a decision to be taken rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a token one character short of the floor",
			src:  "SHIPPO_API_TOKEN=shippo_live_0123456789abcdef0123456789abcdef0123456",
		},
		{
			name: "a token cut off at its prefix",
			src:  "SHIPPO_API_TOKEN=shippo_live_",
		},
	}

	m := New(WithPatterns(ShippoAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_ShippoAPIToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_shippo_api_token.go names, held to the answer it
	// gives rather than to the one a reader might want. A SHA-1 is forty
	// hexadecimal characters exactly, which is a body exactly, so a prefix and
	// a SHA-1 is a token to this scan. Declining it would mean declining every
	// token Shippo issues, since the format is that prefix and that many of
	// those characters and nothing is left over for a digest to fail.
	//
	// A longer digest goes with it rather than being cut at the fortieth
	// character, because the count is a floor and the span reaches the end of
	// the run. The two below are where the floor and the prefix each hold: an
	// MD5 is eight characters short of a body, and a digest with nothing in
	// front of it opens no candidate at all.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sha1 behind the prefix",
			src:  "shippo_live_0123456789abcdef0123456789abcdef01234567",
			want: "****************************************************",
		},
		{
			name: "a sha256 behind the prefix, redacted to the end of the run",
			src:  "shippo_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "****************************************************************************",
		},
		{
			name: "an uppercase sha1 in a cache key",
			src:  "key: shippo_test_0123456789ABCDEF0123456789ABCDEF01234567",
			want: "key: ****************************************************",
		},
		{
			name: "an md5 behind the prefix, eight characters short of a body",
			src:  "shippo_live_0123456789abcdef0123456789abcdef",
			want: "shippo_live_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a sha1 with no prefix in front of it",
			src:  "0123456789abcdef0123456789abcdef01234567",
			want: "0123456789abcdef0123456789abcdef01234567",
		},
	}

	m := New(WithPatterns(ShippoAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ShippoAPIToken_noTokenBeginsInsideAnother(t *testing.T) {
	// The claim builtin_shippo_api_token.go makes: no token of this format can
	// begin inside another. Everything a span covers past the prefix is a
	// hexadecimal digit and the opening is written in none of them, so no
	// position inside a body opens one; and no prefix carries the opening again
	// past its own first character, so no position inside a prefix does either.
	//
	// The claim is stated rather than used — the scan takes the default step of
	// one byte along, which locates a token beginning inside another wherever
	// one could — so what holds it is the two readings below and the shape that
	// would carry it if either were false.
	for _, prefix := range shippoAPITokenPrefixes {
		for i := 1; i < len(prefix); i++ {
			if strings.HasPrefix(prefix[i:], shippoAPITokenOpening) {
				t.Errorf("the prefix %q carries the opening again at %d, so a token can begin inside another prefix", prefix, i)
			}
		}
	}
	for i := range len(shippoAPITokenOpening) {
		if c := shippoAPITokenOpening[i]; isShippoAPITokenBodyByte(c) {
			t.Errorf("the opening %q carries %q at %d, which a body is written with", shippoAPITokenOpening, c, i)
		}
	}

	src := "shippo_live_0123456789abcdef0123456789abcdef01234567shippo_test_0123456789abcdef0123456789abcdef01234567"
	want := []Span{{0, 52}, {52, 104}}
	if got, _ := ShippoAPIToken().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}
}

// Test_shippoAPITokenModes holds every mode to the width the scan reads it at.
// The scan finds the separator by counting from the opening, so a mode of
// another width is one whose prefix is never matched — and nothing else reports
// it, since a prefix no candidate opens on locates nothing and every case here
// goes on passing.
func Test_shippoAPITokenModes(t *testing.T) {
	if len(shippoAPITokenModes) == 0 {
		t.Fatal("the pattern reads no mode, so it locates nothing")
	}
	for _, mode := range shippoAPITokenModes {
		if len(mode) != shippoAPITokenModeChars {
			t.Errorf("the mode %q is %d characters, where the scan reads %d", mode, len(mode), shippoAPITokenModeChars)
		}
	}
}

func Test_shippoAPITokenPrefixes_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over
	// it. What makes the cursor unnecessary is that two candidates can never
	// read the same run: a candidate asks for the last character of a prefix
	// directly in front of its body, no body may be written with it, so an
	// earlier candidate's run has already ended there. Were that character one
	// a body admits, a run dense in prefixes would be walked once per candidate
	// in it and the scan would cost time quadratic in the length of such a
	// line.
	if len(shippoAPITokenPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so there is no candidate to reason about")
	}
	for _, prefix := range shippoAPITokenPrefixes {
		if c := prefix[len(prefix)-1]; isShippoAPITokenBodyByte(c) {
			t.Errorf("the prefix %q closes with %q, which a body may be written with, so two candidates can read the same run", prefix, c)
		}
	}
}

// Test_shippoAPITokenAnchor holds every prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_shippoAPITokenAnchor(t *testing.T) {
	for _, prefix := range shippoAPITokenPrefixes {
		if shippoAPITokenAnchorIndex >= len(prefix) {
			t.Fatalf("the anchor stands at %d, the prefix %q is %d characters", shippoAPITokenAnchorIndex, prefix, len(prefix))
		}
		if c := prefix[shippoAPITokenAnchorIndex]; c != shippoAPITokenAnchor {
			t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", prefix, c, byte(shippoAPITokenAnchor))
		}
	}
}

func Test_ShippoAPIToken_scanIsLinear(t *testing.T) {
	// A line dense in prefixes holds a candidate for every twelve characters it
	// has. The one thing a candidate reads that is a walk over the rest of the
	// input rather than a bounded test is where its run ends, and repeating
	// that walk at every candidate would cost time quadratic in the length of
	// the line. The bound here is far above a linear scan and far below a
	// quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every fifty-two bytes where they are densest, because a sample
	// has to carry a whole body to be one. The crowding a line can actually
	// carry, a candidate every twelve bytes, stays here.
	sources := map[string]string{
		// Candidates as close together as the prefix allows, none of them with
		// a run long enough to be a body: every one reaches the body of the
		// loop and every one is rejected.
		"a candidate every twelve characters": strings.Repeat("shippo_live_", 150000),
		// Tokens written one against the next, so that every candidate is a
		// token and every one of them walks a run.
		"tokens written one against the next": strings.Repeat("shippo_live_0123456789abcdef0123456789abcdef01234567", 34000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a token.
		"a body that runs the length of the line": "shippo_live_" + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing in front of it that opens the
		// opening, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("a_", 900000),
		// And the letters of the opening with no anchor among them, which is
		// the walk reading a whole line and stopping nowhere in it.
		"the letters of the opening with no anchor": strings.Repeat("shippo", 300000),
	}

	checkScanIsLinear(t, ShippoAPIToken(), sources)
}

// referenceShippoAPITokenFind locates tokens the plain way: every position in
// turn, each prefix tried at it and the body walked to the end of its run, with
// no cursor and nothing remembered between candidates. The prefixes, the floor
// and the character class are spelled again here rather than shared with the
// scan. A reference reading shippoAPITokenPrefixes, shippoAPITokenBodyChars and
// isShippoAPITokenBodyByte could not disagree with it about them, and it is
// exactly that disagreement the fuzz target below is for: the two have to be
// changed together or reported apart.
//
// Every position is asked about, a match included, rather than resuming past
// one. No token of this format can begin inside another — the opening is
// written in no character a body is — but that is a thing the scan claims, and
// a reference is written to know nothing its scan claims.
//
// It is written out rather than built on a regular expression, and the floor is
// why, though not because the expression was measured too slow to fuzz with.
// The grammar states compactly as shippo_(live|test)_[0-9A-Fa-f]{40,}, and a
// counted repetition is what an engine has the least room to skip: behind this
// one the machine is forty states wide and is walked again at every candidate,
// which is the shape that has starved targets of executions. Driven from that
// expression this target held around eighty thousand executions a second over
// three quarters of a minute and the mutator found no input that starved it,
// where the walk below held around a hundred and ten thousand; both were
// measured. So the expression is affordable on the inputs that were reached and
// the walk is cheaper on them, and what settles it is that the walk cannot have
// the hazard at all.
func referenceShippoAPITokenFind(src string) []Span {
	const bodyChars = 40
	prefixes := []string{"shippo_live_", "shippo_test_"}

	body := func(c byte) bool {
		return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
	}

	var spans []Span
	for start := range len(src) {
		for _, prefix := range prefixes {
			if !strings.HasPrefix(src[start:], prefix) {
				continue
			}

			at := start + len(prefix)
			end := at
			for end < len(src) && body(src[end]) {
				end++
			}
			if end-at < bodyChars {
				continue
			}
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
}

// FuzzShippoAPIToken_matchesReference guards the hand-written scan: the
// prefixes it searches for, the modes it reads between them, the floor it holds
// a body to, the alphabet it reads that body in and the byte it resumes at may
// none of them change which tokens are located.
func FuzzShippoAPIToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("SHIPPO_API_TOKEN=shippo_live_0123456789abcdef0123456789abcdef01234567")
	f.Add("Authorization: ShippoToken shippo_test_0123456789abcdef0123456789abcdef01234567")
	f.Add("shippo_live_0123456789ABCDEF0123456789ABCDEF01234567")         // a body written in capitals
	f.Add("shippo_live_0123456789abcdef0123456789abcdef0123456")          // one short of a body
	f.Add("shippo_live_0123456789abcdef0123456789abcdef012345670")        // and a run longer than one
	f.Add("shippo_live_0123456789abcdef0123456789abcdefg1234567")         // a letter past f ends the body
	f.Add("shippo_live_0123456789abcdef0123456789abcdef-1234567")         // a hyphen, likewise
	f.Add("shippo_live_0123456789abcdef0123456789abcdef_1234567")         // an underscore, likewise
	f.Add("SHIPPO_LIVE_0123456789abcdef0123456789abcdef01234567")         // an uppercase prefix
	f.Add("shippo-live-0123456789abcdef0123456789abcdef01234567")         // hyphens where the prefix carries underscores
	f.Add("shippolive_0123456789abcdef0123456789abcdef01234567")          // the opening without its underscore
	f.Add("shippo_prod_0123456789abcdef0123456789abcdef01234567")         // a mode no Shippo page writes
	f.Add("shippo_live_0123456789abcdef0123456789abcdef01234567_suffix")  // a word the underscore keeps out of the span
	f.Add("shippo_live_0123456789abcdef0123456789abcdef01234567deadbeef") // and one the alphabet takes into it
	f.Add("Authorization: ShippoToken shippo_test_token")                 // the placeholder the documentation writes
	f.Add(`"account_id":"shippo_ups_account"`)                            // an account id Shippo writes with the vendor name
	f.Add("shippo_live_0123456789abcdef0123456789abcdef01234567 shippo_test_0123456789ABCDEF0123456789ABCDEF01234567")
	f.Add("shippo_live_0123456789abcdef0123456789abcdef01234567shippo_test_0123456789abcdef0123456789abcdef01234567")
	// Candidate positions crowded as close as they can be, with no run long
	// enough for any of them, and tokens written one against the next so that
	// every candidate has one.
	f.Add(strings.Repeat("shippo_live_", 16))
	f.Add(strings.Repeat("shippo_live_0123456789abcdef0123456789abcdef01234567", 4))
	// The digests either side of the floor, behind the prefix and bare.
	f.Add("shippo_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("shippo_live_0123456789abcdef0123456789abcdef")
	f.Add("0123456789abcdef0123456789abcdef01234567")
	// The prefix written inside a run of base64url, which is the over-match the
	// pattern admits.
	f.Add("payload=zzzzshippo_live_0123456789abcdef0123456789abcdef01234567zzzz")

	fuzzAgainstReference(f, ShippoAPIToken().Find, referenceShippoAPITokenFind)
}

// shippoAPITokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func shippoAPITokenFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no token. The vendor's own host name is written here
	// because it is what a line about Shippo carries: it opens no candidate,
	// since the character behind shippo is the dot of a host name and not the
	// underscore of a prefix.
	line := `time=2026-08-17T00:00:00Z level=info msg="label purchased" object_id=0123456789abcdef0123456789abcdef carrier=usps url=https://api.goshippo.com/transactions/ `
	token := "shippo_live_0123456789abcdef0123456789abcdef01234567"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The other side of anchoring on the underscore: a body of JSON
			// written in snake_case stops the search at every field name, and
			// each of those positions is turned away by the one byte read back
			// for the opening.
			name:  "underscores that open no candidate",
			src:   strings.Repeat(`{"object_id":"0123456789abcdef","carrier_account":"0123456789abcdef","tracking_number":"9405511899223197428490"}`, 2),
			spans: 0,
		},
		{
			// A candidate every twelve characters with no run behind any of
			// them: each reaches the body of the loop and none becomes a token.
			// What it times is the mode being read and the walk over a run
			// being started and stopped, once per candidate and no more.
			name:  "candidates that are not values",
			src:   strings.Repeat("shippo_live_", 128),
			spans: 0,
		},
		{
			// Tokens written one against the next. This is what the scan gets
			// away with keeping no cursor for: the runs the candidates read
			// follow one another rather than overlapping.
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
