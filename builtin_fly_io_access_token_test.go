package mask

import (
	"slices"
	"strings"
	"testing"
)

// The Fly.io access token pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. A body is the ordered run written four times over,
// which is the sixty-four characters the floor asks for; with the four
// characters of the v2 prefix that comes to sixty-eight, and with the five of a
// v1 one to sixty-nine. A real body is longer and carries the MessagePack
// encoding of a macaroon, which nothing here needs to be: what the scan reads
// is the alphabet, the padding and the count.

const (
	flyIOAccessTokenBody  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	flyIOAccessTokenValue = "fm2_" + flyIOAccessTokenBody
)

func Test_FlyIOAccessToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  flyIOAccessTokenValue,
			want: []Span{{0, 68}},
		},
		{
			name: "a token in an environment assignment",
			src:  "FLY_API_TOKEN=" + flyIOAccessTokenValue,
			want: []Span{{14, 82}},
		},
		{
			// The two labels format.go admits alongside the v2 one, decoded
			// there by the same call and read here by the same walk.
			name: "a v1 permission token",
			src:  "fm1r_" + flyIOAccessTokenBody,
			want: []Span{{0, 69}},
		},
		{
			name: "a v1 discharge token",
			src:  "fm1a_" + flyIOAccessTokenBody,
			want: []Span{{0, 69}},
		},
		{
			// The header a permission token and the discharge answering its
			// third-party caveat travel in together, which is what the vendor
			// hands a user as one access token.
			name: "a permission token and its discharge",
			src:  "FlyV1 " + flyIOAccessTokenValue + ",fm1a_" + flyIOAccessTokenBody,
			want: []Span{{6, 74}, {75, 144}},
		},
		{
			// The scheme a token is sent under stands in front of the value and
			// says nothing about whether one stands there, so the scan reads
			// none of it and the span opens at the prefix.
			name: "a token under the FlyV1 scheme",
			src:  "Authorization: FlyV1 " + flyIOAccessTokenValue,
			want: []Span{{21, 89}},
		},
		{
			// The count is a floor, so a run carrying on past the sixty-fourth
			// character is redacted to the end of that run.
			name: "a body longer than the floor",
			src:  "fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123",
			want: []Span{{0, 72}},
		},
		{
			// The two characters that tell the standard alphabet from the
			// base64url one the rest of this package reads.
			name: "a body carrying a plus and a slash",
			src:  "fm2_0123456789abcde+0123456789abcde/0123456789abcdef0123456789abcdef",
			want: []Span{{0, 68}},
		},
		{
			name: "a body closing with one padding character",
			src:  "fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde=",
			want: []Span{{0, 68}},
		},
		{
			name: "a body closing with two",
			src:  "fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd==",
			want: []Span{{0, 68}},
		},
		{
			// The header form: superfly/macaroon joins several tokens with
			// commas, each carrying its own prefix. The comma belongs to
			// neither the alphabet nor the padding, so each body ends where the
			// next token begins.
			name: "two tokens joined by a comma",
			src:  flyIOAccessTokenValue + "," + flyIOAccessTokenValue,
			want: []Span{{0, 68}, {69, 137}},
		},
		{
			// A body is written in an alphabet every character of a label
			// belongs to, so the run of the token in front carries on into the
			// prefix of the token behind it and stops at that prefix's
			// underscore.
			name: "a token written against another",
			src:  flyIOAccessTokenValue + flyIOAccessTokenValue,
			want: []Span{{0, 71}, {68, 136}},
		},
		{
			// The alphabet holds uppercase letters as well as lowercase, and a
			// body mixing the two is read exactly as one holding either alone.
			name: "a body carrying uppercase letters",
			src:  "fm2_0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 68}},
		},
		{
			// A body of uppercase letters alone, holding the alphabet's upper
			// half without any of its lower half beside it.
			name: "a body of uppercase letters alone",
			src:  "fm2_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 68}},
		},
		{
			// The whole standard base64 alphabet in order, sixty-four
			// characters exactly: the uppercase letters from A to Z, the
			// lowercase letters from a to z, the digits from 0 to 9, and the
			// two characters, + and /, that tell this alphabet from base64url.
			name: "a body of the whole base64 alphabet in order",
			src:  "fm2_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
			want: []Span{{0, 68}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := FlyIOAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_FlyIOAccessToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the prefix alone",
			src:  "fm2_",
		},
		{
			name: "a body one character short of the floor",
			src:  "fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// Padding counts toward the floor, and base64 asks for no more than
			// two characters of it, so a third leaves the body one short.
			name: "a body padded past what base64 asks for",
			src:  "fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc===",
		},
		{
			// Padding stands where a body ends and nowhere else, so a body
			// carrying it in the middle ends there.
			name: "padding inside a body",
			src:  "fm2_0123456789abcdef0123456789abcd==0123456789abcdef0123456789abcdef",
		},
		{
			name: "the prefix without its underscore",
			src:  "fm20123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a hyphen where the prefix closes",
			src:  "fm2-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "an uppercase label",
			src:  "FM2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a body broken by a space",
			src:  "fm2_0123456789abcde 0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The two characters base64url writes where this alphabet writes
			// plus and slash. The underscore is the one the whole scan rests on
			// a body not carrying: it ends the run where it stands, and what is
			// written in front of it spells no label.
			name: "a body broken by a hyphen",
			src:  "fm2_0123456789abcde-0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a body broken by an underscore",
			src:  "fm2_0123456789abcde_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a body broken by a dot",
			src:  "fm2_0123456789abcde.0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := FlyIOAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_FlyIOAccessToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "FLY_API_TOKEN=fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "FLY_API_TOKEN=********************************************************************",
		},
		{
			name: "quoted",
			src:  `"fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`,
			want: `"********************************************************************"`,
		},
		{
			// The header a token is sent under.
			name: "header",
			src:  "Authorization: FlyV1 fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "Authorization: FlyV1 ********************************************************************",
		},
		{
			name: "json",
			src:  `{"token":"fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`,
			want: `{"token":"********************************************************************"}`,
		},
		{
			name: "twice",
			src:  "fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "******************************************************************** ********************************************************************",
		},
	}

	m := New(WithPatterns(FlyIOAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_FlyIOAccessToken_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, kept as a decision on the record. A line cut to a
	// column limit partway through a token leaves the prefix and a body too
	// short to be one, and nothing is located: the characters written before
	// the cut stay in the output. Reading the floor lower to reach them would
	// widen what the pattern fires on for every input there is, which is the
	// trade the rationale weighs.
	for i := range len(flyIOAccessTokenBody) {
		src := "fm2_" + flyIOAccessTokenBody[:i]
		if got, _ := FlyIOAccessToken().Find(src); len(got) != 0 {
			t.Errorf("Find(%q) = %v, want no span for a body of %d characters", src, got, i)
		}
	}
	if got, _ := FlyIOAccessToken().Find(flyIOAccessTokenValue); len(got) != 1 {
		t.Errorf("Find(%q) = %v, want the one span the floor admits", flyIOAccessTokenValue, got)
	}
}

func Test_FlyIOAccessToken_theLabelThatIsNotRead(t *testing.T) {
	// superfly/macaroon's format.go names four labels and this scan reads three.
	// What divides them is the arm of Parse each falls in: fm1r, fm1a and fm2
	// share the one that decodes, so the alphabet and the count are stated for
	// all three, where fo1 is the arm that skips without decoding anything and
	// no source of the vendor's says what stands behind it. A body of the shape
	// this scan reads is written behind it here, so that a label admitted by
	// accident is a failure rather than a widening nobody notices.
	src := "fo1_" + flyIOAccessTokenBody
	if got, _ := FlyIOAccessToken().Find(src); len(got) != 0 {
		t.Errorf("Find(%q) = %v, want no span", src, got)
	}
}

func Test_FlyIOAccessToken_aTokenAgainstAnother(t *testing.T) {
	// Why the scan resumes a byte along rather than consuming its match. Every
	// character in front of the separator belongs to the alphabet a body is
	// written in, so a body may close with them and hand the underscore behind
	// it to a token of its own. A scan consuming the first match would resume
	// past that underscore and leave the second token in the output whole.
	src := flyIOAccessTokenValue + flyIOAccessTokenValue
	want := []Span{{0, 71}, {68, 136}}
	if got, _ := FlyIOAccessToken().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}

	// The spans overlap, and what a caller sees is the one redaction a Masker
	// resolves them into: neither token is left in the output.
	m := New(WithPatterns(FlyIOAccessToken()), WithRedactor(Fixed("[REDACTED]")))
	if got, want := m.Mask(src), "[REDACTED]"; got != want {
		t.Errorf("Mask(%q) = %q, want %q", src, got, want)
	}
}

func Test_FlyIOAccessToken_aBase64URLPayload(t *testing.T) {
	// What this pattern over-matches on, pinned. base64url is the one encoding
	// in ordinary use carrying the underscore, so a payload written in it can
	// hold a whole prefix; what it then has to carry for the run behind that
	// prefix to be redacted is sixty-four characters drawn from the sixty-two
	// its alphabet shares with this one. Such a payload is a value already
	// opaque to a reader, and declining it would mean declining every token of
	// the same shape.
	src := "eyJzdWIiOiJhYmNfm2_" + flyIOAccessTokenBody
	want := []Span{{15, 83}}
	if got, _ := FlyIOAccessToken().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}
}

func Test_flyIOAccessTokenPrefixes(t *testing.T) {
	// Three things the scan rests on, stated over the prefixes rather than by
	// example.
	//
	// Every prefix closes on the byte the scan searches the input for, which is
	// what makes a candidate readable back from a search that stops there. One
	// that did not would open no candidate anywhere, and nothing else would
	// report it: a scan reports spans rather than the positions it looked at,
	// so a label nothing finds and a label nothing matches look alike.
	for _, p := range flyIOAccessTokenPrefixes {
		if c := p[len(p)-1]; c != flyIOAccessTokenSeparator {
			t.Errorf("the prefix %q closes on %q, where the scan searches for %q", p, c, byte(flyIOAccessTokenSeparator))
		}
	}

	// Every character of a label belongs to the alphabet a body is written in,
	// which is what lets one token begin inside another and is why the cases
	// above pinning that nesting stand for something.
	for _, l := range flyIOAccessTokenLabels {
		for i := range len(l) {
			if c := l[i]; !isFlyIOAccessTokenBase64Byte(c) {
				t.Errorf("the label %q holds %q, which no body may be written with", l, c)
			}
		}
	}

	// No two labels close on the same character, which is what lets the walk
	// take the first prefix that matches rather than weighing the rest: two
	// that did could both close at one separator, and which of them the walk
	// reported would be the order of the table.
	last := map[byte]string{}
	for _, l := range flyIOAccessTokenLabels {
		c := l[len(l)-1]
		if other, ok := last[c]; ok {
			t.Errorf("the labels %q and %q both close on %q, so both can close at one separator", other, l, c)
		}
		last[c] = l
	}
}

func Test_flyIOAccessTokenPrefixes_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over
	// it, where a scan whose prefix closes on a character its own body admits
	// has to keep one. What makes the cursor unnecessary is that two candidates
	// can never read the same run: a candidate asks for the underscore at the
	// end of its label, no body and no padding may be written with it, so the
	// run of an earlier candidate has already ended there and the later
	// candidate's run begins past it. Were it a character a body admits, a run
	// dense in prefixes would be walked once for every candidate in it and the
	// scan would cost time quadratic in the length of such a line.
	if isFlyIOAccessTokenBase64Byte(flyIOAccessTokenSeparator) {
		t.Errorf("the separator %q belongs to the alphabet a body is written in, so two candidates can read the same run", byte(flyIOAccessTokenSeparator))
	}
	if flyIOAccessTokenSeparator == flyIOAccessTokenPadding {
		t.Errorf("the separator %q is what a body closes with, so a body could not end where the separator stands", byte(flyIOAccessTokenSeparator))
	}
}

func Test_flyIOAccessTokenAlphabet(t *testing.T) {
	// The byte test stated over every byte rather than by example. It is the
	// standard alphabet of RFC 4648 and not the base64url one, so the two
	// characters that differ are + and / rather than - and _. The padding
	// character is outside it and is counted separately, since it may stand
	// only where a body ends.
	for c := range 256 {
		b := byte(c)

		want := '0' <= b && b <= '9' ||
			'A' <= b && b <= 'Z' ||
			'a' <= b && b <= 'z' ||
			b == '+' || b == '/'
		if got := isFlyIOAccessTokenBase64Byte(b); got != want {
			t.Errorf("isFlyIOAccessTokenBase64Byte(%q) = %v, want %v", b, got, want)
		}
	}

	if isFlyIOAccessTokenBase64Byte(flyIOAccessTokenPadding) {
		t.Errorf("the padding character %q belongs to the alphabet, so a body could not be told from its padding", byte(flyIOAccessTokenPadding))
	}
}

func Test_FlyIOAccessToken_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a line dense in prefixes
	// holds a candidate for every four characters it has. The one thing a
	// candidate reads that is a walk over the rest of the input rather than a
	// bounded test is where its run ends, and repeating that walk at every
	// candidate would cost time quadratic in the length of the line. The bound
	// here is far above a linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every sixty-eight bytes where they are densest, because a
	// sample has to carry a whole body to be one. The crowding a line can
	// actually carry stays here.
	sources := map[string]string{
		// Candidates as close together as the prefix allows, none of them with
		// a body: every one reaches the body of the loop and every one is
		// rejected by the floor.
		"a candidate every four characters": strings.Repeat("fm2_", 500000),
		// The same at the other length a prefix comes in, which is the walk
		// trying every prefix at a separator none of them closes at.
		"a candidate every five characters": strings.Repeat("fm1r_", 400000),
		// Bodies written into one another, each candidate beginning three
		// characters before the end of the one before it, so every one of them
		// walks a run.
		"a candidate beginning inside every body": strings.Repeat("fm2_0123456789abcdef0123456789fm2", 60000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding the end of it.
		"a body that runs the length of the line": "fm2_" + strings.Repeat("a", 1800000),
		// The characters of the prefix with no underscore among them, which is
		// the search for the anchor reading a whole line and finding no
		// candidate at all.
		"the prefix without its separator": strings.Repeat("fm2", 600000),
		// A run of padding, which is where the length of a body is decided.
		"a run of padding": "fm2_" + strings.Repeat("=", 1800000),
	}

	checkScanIsLinear(t, FlyIOAccessToken(), sources)
}

// referenceFlyIOAccessTokenAt reports where a Fly.io access token written at
// start ends, and whether one is written there at all. It is the statement of
// what the scan in builtin_fly_io_access_token.go locates, kept here so that
// the scan can be held to it, and it reads one position and stops.
//
// The labels, the count, the alphabet and the padding rule are spelled again
// rather than built from flyIOAccessTokenLabels, flyIOAccessTokenSeparator,
// flyIOAccessTokenBodyChars, isFlyIOAccessTokenBase64Byte,
// flyIOAccessTokenPadding and flyIOAccessTokenPaddingMax, so that the two can
// disagree and the target below report it. The labels are asked about in turn
// rather than read back from a separator, which is the scan's arrangement and
// not the rule: what the rule says is that a token opens with one of them.
//
// It is written out rather than built on an expression, and what decides that
// is the shape of the rule rather than the cost of running it. The floor is a
// count over the run and the padding together, so an expression saying it needs
// one branch for each number of padding characters a body may close with, each
// carrying a floor of its own — three counts to keep in step where the walk has
// one, and three places for a change to the floor to be applied twice.
func referenceFlyIOAccessTokenAt(src string, start int) (int, bool) {
	var body int
	switch {
	case strings.HasPrefix(src[start:], "fm2_"):
		body = start + len("fm2_")
	case strings.HasPrefix(src[start:], "fm1r_"):
		body = start + len("fm1r_")
	case strings.HasPrefix(src[start:], "fm1a_"):
		body = start + len("fm1a_")
	default:
		return 0, false
	}

	i := body
	for i < len(src) && referenceFlyIOBase64Byte(src[i]) {
		i++
	}
	for pad := 0; pad < 2 && i < len(src) && src[i] == '='; pad++ {
		i++
	}
	if i-body < 64 {
		return 0, false
	}
	return i, true
}

// referenceFlyIOBase64Byte reports whether c belongs to the standard base64
// alphabet, spelled out again for the reason the reference above gives.
func referenceFlyIOBase64Byte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z' ||
		c == '+' || c == '/'
}

// referenceFlyIOAccessTokenFind locates tokens the plain way: every position in
// src is asked whether one is written there, and the answer at one position is
// read without regard to any other.
//
// Every position rather than resuming past a match, because a token can begin
// inside the body of the one in front of it: every character of every label
// belongs to the alphabet a body is written in.
func referenceFlyIOAccessTokenFind(src string) []Span {
	var spans []Span
	for start := range len(src) {
		if end, ok := referenceFlyIOAccessTokenAt(src, start); ok {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
}

// FuzzFlyIOAccessToken_matchesReference holds the scan to the reference above
// on generated input. The seeds are the shapes the scan decides something at:
// the prefix and the labels beside it, the floor from either side, the
// alphabet against the base64url one, the padding at every count it admits, and
// a token beginning inside another. Neither the prefix, the floor, the alphabet
// nor the padding may change which tokens are located without this reporting
// it.
func FuzzFlyIOAccessToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("FLY_API_TOKEN=fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("Authorization: FlyV1 fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")                 // a body one short of the floor
	f.Add("fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0")               // and a run longer than it
	f.Add("fm2_0123456789abcde+0123456789abcde/0123456789abcdef0123456789abcdef")                // + and /, which tell this alphabet from base64url
	f.Add("fm2_0123456789abcde-0123456789abcde_0123456789abcdef0123456789abcdef")                // - and _, which base64url writes in their place
	f.Add("fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde=")                // one padding character
	f.Add("fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd==")                // two
	f.Add("fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc===")                // three, which base64 never calls for
	f.Add("fm2_0123456789abcdef0123456789abcd==0123456789abcdef0123456789abcdef")                // padding inside a body
	f.Add("fm20123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")                 // the label with no separator
	f.Add("fm2-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")                // a hyphen where the separator belongs
	f.Add("FM2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")                // an uppercase label
	f.Add("fm1r_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")               // the two v1 labels Parse decodes beside fm2
	f.Add("fm1a_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")               //
	f.Add("fm1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")                // a v1 label with no character naming its kind
	f.Add("fm1x_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")               // a kind no label names
	f.Add("fo1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")                // the label Parse skips without decoding
	f.Add("eyJzdWIiOiJhYmNfm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") // a base64url payload holding a prefix
	// A token beginning inside the body of the one before it, which a scan
	// resuming past a match steps over, and the same two with nothing between
	// them.
	f.Add("fm2_0123456789abcdef0123456789abcdef0123456789abcdeffm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// Candidate positions crowded as close as they can be, a run of separators,
	// and a run of padding, which is where the length of a body is decided.
	f.Add(strings.Repeat("fm2_", 24))
	f.Add(strings.Repeat("fm1a_", 24))
	f.Add(strings.Repeat("fm2_", 24) + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add(strings.Repeat("fm2", 32))
	f.Add(strings.Repeat("_", 128))
	f.Add("fm2_" + strings.Repeat("=", 64))
	// A JWT, whose segments are base64url where this body is base64, and a
	// digest, which carries nothing a prefix could be found in.
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
	f.Add("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	fuzzAgainstReference(f, FlyIOAccessToken().Find, referenceFlyIOAccessTokenFind)
}

// flyIOAccessTokenFindBenchmarks is what this scan is timed on. The cases are
// the ordinary line, the two ways a candidate fails, and the lines a token
// stands in.
func flyIOAccessTokenFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line carries the underscore the scan searches for,
	// so what the line times is that search — which is most of what this
	// pattern costs a caller whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="deploying app" url=https://api.machines.dev/v1/apps/acme/machines `
	token := "fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A prefix is four characters here, so a run of them holds a
			// candidate for every four it has, and the run behind each one is
			// the three characters of the next label before the separator ends
			// it. That is the floor turning a candidate away after the shortest
			// body walk there is.
			name:  "candidates that are not values",
			src:   strings.Repeat("fm2_", 512),
			spans: 0,
		},
		{
			// A separator no prefix closes at, which is every prefix tried and
			// every one turned away by the byte a label opens with.
			name:  "separators that open no candidate",
			src:   strings.Repeat("a_b_c_d_", 256),
			spans: 0,
		},
		{
			// The same rejection at the other end of the walk: a run one
			// character short of the floor, so the body is read to its last
			// character before the count turns it away. Every run here is read
			// once and none is read twice, which is what the scan's want of a
			// cursor rests on.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("fm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde ", 16),
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
