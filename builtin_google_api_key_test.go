package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Google API key pattern: what it locates and what it leaves alone, written
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
// shape, obviously not real. The run they are built from,
// 0123456789abcdefghijklmnopqrstuvwxy, is thirty-five characters and so is a
// whole body.

func Test_GoogleAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "AIza0123456789abcdefghijklmnopqrstuvwxy",
			want: []Span{{0, 39}},
		},
		{
			name: "a key in an environment assignment",
			src:  "GOOGLE_API_KEY=AIza0123456789abcdefghijklmnopqrstuvwxy",
			want: []Span{{15, 54}},
		},
		{
			// The hyphen and the underscore are base64url characters, and
			// Google's own example key carries one of each.
			name: "a body carrying a hyphen and an underscore",
			src:  "AIza0123456789abcdef-hijklmnopqrstuvwx_",
			want: []Span{{0, 39}},
		},
		{
			// Every key Google shows is thirty-nine characters, so the
			// thirty-five behind the prefix are read as a count and not a
			// floor: what follows the thirty-ninth is not part of the key and
			// stays in the text.
			name: "an alphabet run longer than a key is a key and what follows it",
			src:  "AIza0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 39}},
		},
		{
			// Neither key is inside the other, and nothing separates them.
			name: "two keys with nothing between them",
			src:  "AIza0123456789abcdefghijklmnopqrstuvwxyAIza0123456789abcdefghijklmnopqrstuvwxy",
			want: []Span{{0, 39}, {39, 78}},
		},
		{
			// The prefix is written in the alphabet a body is, so a key can
			// begin inside the span of the one before it, and a scan resuming
			// past a match would step over it and leave a whole key in the
			// output. The spans overlap, which a Masker resolves into one.
			name: "a key beginning inside the key before it",
			src:  "AIzaAIza0123456789abcdefghijklmnopqrstuvwxy",
			want: []Span{{0, 39}, {4, 43}},
		},
		{
			// The hyphen and the underscore are written in the middle of a
			// body elsewhere in this file; these are the two straight behind
			// the prefix, the position adjacent to it.
			name: "a hyphen at the first character of the body",
			src:  "AIza-0123456789abcdefghijklmnopqrstuvwx",
			want: []Span{{0, 39}},
		},
		{
			name: "an underscore at the first character of the body",
			src:  "AIza_0123456789abcdefghijklmnopqrstuvwx",
			want: []Span{{0, 39}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := GoogleAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GoogleAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "AIza",
		},
		{
			// Thirty-eight characters where the pattern asks for thirty-nine.
			name: "body one character too short",
			src:  "AIza0123456789abcdefghijklmnopqrstuvwx",
		},
		{
			name: "a dot in the body",
			src:  "AIza0123456789abcdef.hijklmnopqrstuvwxy",
		},
		{
			name: "a plus where the body would be",
			src:  "AIza+123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			// Standard base64 rather than base64url: the two characters
			// base64url writes as - and _ are + and /, and neither belongs to
			// the alphabet a body is read in.
			name: "a slash in the body",
			src:  "AIza0123456789abcdef/hijklmnopqrstuvwx+",
		},
		{
			// The slash alone, at each of the three positions the class is
			// tested at: the middle of the body, straight behind the prefix,
			// and the last character.
			name: "a slash alone in the middle of the body",
			src:  "AIza0123456789abcdef/hijklmnopqrstuvwxy",
		},
		{
			name: "a slash alone at the first character of the body",
			src:  "AIza/123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			name: "a slash alone at the last character of the body",
			src:  "AIza0123456789abcdefghijklmnopqrstuvwx/",
		},
		{
			// Base64's padding character, which appears in no test or corpus
			// case elsewhere in this pattern.
			name: "an equals sign in the middle of the body",
			src:  "AIza0123456789abcdef=hijklmnopqrstuvwxy",
		},
		{
			name: "an equals sign at the first character of the body",
			src:  "AIza=123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			name: "an equals sign at the last character of the body",
			src:  "AIza0123456789abcdefghijklmnopqrstuvwx=",
		},
		{
			name: "a body broken by a tab",
			src:  "AIza0123456789abcdef\thijklmnopqrstuvwxy",
		},
		{
			name: "a body broken by a carriage return",
			src:  "AIza0123456789abcdef\rhijklmnopqrstuvwxy",
		},
		{
			name: "a body broken by a space",
			src:  "AIza0123456789abcdef hijklmnopqrstuvwxy",
		},
		{
			name: "a body broken by a line break",
			src:  "AIza0123456789abcdef\nhijklmnopqrstuvwxy",
		},
		{
			name: "a lowercase prefix",
			src:  "aiza0123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			name: "an uppercase prefix",
			src:  "AIZA0123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			// A single letter of the prefix miscased, rather than the whole of
			// it: each of the other three positions on its own.
			name: "the second character of the prefix in capitals",
			src:  "AIZa0123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			name: "the first two characters of the prefix reversed in case",
			src:  "AiZa0123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			name: "the whole prefix lowercase but the last character",
			src:  "aIza0123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			name: "the last character of the prefix in capitals",
			src:  "AIzA0123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			// The prefix is four characters and all four are read. Google
			// documents no other, and a run opening with three of them is not
			// one.
			name: "three characters of the prefix",
			src:  "AIzb0123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			// Thirty-nine base64url characters that open with something else.
			// The prefix is the whole of the anchor, so a run of the right
			// length is not a key without it.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdefghijklmnopqrstuvwxyzABC",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// Forty hexadecimal characters. A digest carries no uppercase
			// letter among lowercase ones, so it holds no prefix to be found
			// at.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := GoogleAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_GoogleAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "GOOGLE_API_KEY=AIza0123456789abcdefghijklmnopqrstuvwxy",
			want: "GOOGLE_API_KEY=***************************************",
		},
		{
			name: "quoted",
			src:  `"AIza0123456789abcdefghijklmnopqrstuvwxy"`,
			want: `"***************************************"`,
		},
		{
			name: "json",
			src:  `{"apiKey":"AIza0123456789abcdefghijklmnopqrstuvwxy"}`,
			want: `{"apiKey":"***************************************"}`,
		},
		{
			// The query parameter Google's own documentation shows a key
			// passed in. An ampersand ends the run, so the parameter after it
			// stays in the text.
			name: "a query parameter",
			src:  "https://maps.googleapis.com/maps/api/geocode/json?key=AIza0123456789abcdefghijklmnopqrstuvwxy&address=Tokyo",
			want: "https://maps.googleapis.com/maps/api/geocode/json?key=***************************************&address=Tokyo",
		},
		{
			name: "twice",
			src:  "AIza0123456789abcdefghijklmnopqrstuvwxy AIza0123456789abcdef-hijklmnopqrstuvwx_",
			want: "*************************************** ***************************************",
		},
		{
			// The two spans are merged, so the key that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a key beginning inside the key before it",
			src:  "AIzaAIza0123456789abcdefghijklmnopqrstuvwxy",
			want: "*******************************************",
		},
	}

	m := New(WithPatterns(GoogleAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GoogleAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xAIza0123456789abcdefghijklmnopqrstuvwxy",
			want: "x***************************************",
		},
		{
			name: "underscore before",
			src:  "GOOGLE_API_KEY_AIza0123456789abcdefghijklmnopqrstuvwxy",
			want: "GOOGLE_API_KEY_***************************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this key
			// rather than trim it; without one the thirty-nine characters
			// Google issued are redacted and the one written after them,
			// which is part of no credential, stays in the text.
			name: "a character of the alphabet after",
			src:  "AIza0123456789abcdefghijklmnopqrstuvwxyz",
			want: "***************************************z",
		},
	}

	m := New(WithPatterns(GoogleAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GoogleAPIKey_leavesWhatFollowsAlone(t *testing.T) {
	// A key carries no character the base64url alphabet does not, so ordinary
	// punctuation ends one and nothing written after it joins it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "host",
			src:  "host=AIza0123456789abcdefghijklmnopqrstuvwxy.example.com",
			want: "host=***************************************.example.com",
		},
		{
			name: "sentence",
			src:  "the key is AIza0123456789abcdefghijklmnopqrstuvwxy.",
			want: "the key is ***************************************.",
		},
		{
			// The hyphen is a body character, so what follows a key across one
			// is read as a body and the count is what ends the key rather than
			// the hyphen.
			name: "dashed word",
			src:  "AIza0123456789abcdefghijklmnopqrstuvwxy-suffix",
			want: "***************************************-suffix",
		},
		{
			// A multi-byte rune written against the key on both sides.
			// Neither its UTF-8 encoding nor a byte of it belongs to the
			// prefix or the body's alphabet, so the key keeps its span
			// exactly as it does against a single-byte character.
			name: "a multi-byte rune before and after",
			src:  "日本語AIza0123456789abcdefghijklmnopqrstuvwxy日本語",
			want: "日本語***************************************日本語",
		},
	}

	m := New(WithPatterns(GoogleAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GoogleAPIKey_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix is four
	// characters of an alphabet of sixty-four, so a long enough base64 value
	// carries it, and where the thirty-five behind it are in the alphabet too,
	// those thirty-nine are redacted.
	//
	// They are held to being redacted rather than to being spared. Nothing in
	// the text tells such a run from a key — they are the same thirty-nine
	// bytes — so a scan that let these through would let a real key through
	// with them, which builtin_google_api_key.go sets out. What the table is
	// for is that the cases move with the scan: one of them ceasing to be
	// located means the grammar changed, and that is a decision to be taken
	// rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "inside a base64url payload",
			src:  "payload=zzzzAIza0123456789abcdefghijklmnopqrstuvwxyzzzz",
			want: "payload=zzzz***************************************zzzz",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the
			// Google pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.AIza0123456789abcdefghijklmnopqrstuvwxy",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.***************************************",
		},
	}

	m := New(WithPatterns(GoogleAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

// Test_GoogleAPIKey_holdsATokenTheInputCutShort states, with a literal
// number, what the second return of Find settles: a piece of the prefix
// standing at the end of the input, a candidate the end of the input cut
// short, and a whole match with nothing left unsettled behind it.
func Test_GoogleAPIKey_holdsATokenTheInputCutShort(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		want   []Span
		retain int
	}{
		{
			// A piece of the prefix stands at the end of the input: it
			// could still grow into "AIza" with one more byte, so nothing
			// behind where it opens is settled.
			name:   "a piece of the prefix at the end of the input",
			src:    "the key starts with AIz",
			retain: len("the key starts with "),
		},
		{
			// A whole prefix and a body the input cuts short before the
			// count is met.
			name:   "a body the input cuts short of the count",
			src:    "AIza0123456789abcdefghij",
			retain: 0,
		},
		{
			// A whole key with more text after it, ending in a byte that
			// opens no piece of the prefix, so nothing at the end of the
			// input is left unsettled.
			name:   "a whole key followed by settled text",
			src:    "AIza0123456789abcdefghijklmnopqrstuvwxy tail",
			want:   []Span{{0, 39}},
			retain: len("AIza0123456789abcdefghijklmnopqrstuvwxy tail"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := GoogleAPIKey().Find(tt.src)
			if retain != tt.retain {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, retain, tt.retain)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_googleAPIKeyPrefix(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a key can
	// begin inside the body of the one before it, and that holds only while
	// every character of the prefix is one a body may be written in. A prefix
	// carrying a character outside the alphabet would make the two impossible
	// to nest, and the case above pinning the nesting would stand for nothing —
	// which is not a failure anything else here reports.
	if googleAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for i := range len(googleAPIKeyPrefix) {
		if c := googleAPIKeyPrefix[i]; !isBase64URLByte(c) {
			t.Errorf("the prefix holds %q, which no body may be written with", c)
		}
	}
}

// Test_googleAPIKeyAnchor holds the prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_googleAPIKeyAnchor(t *testing.T) {
	if googleAPIKeyAnchorIndex >= len(googleAPIKeyPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", googleAPIKeyAnchorIndex, len(googleAPIKeyPrefix))
	}
	if c := googleAPIKeyPrefix[googleAPIKeyAnchorIndex]; c != googleAPIKeyAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(googleAPIKeyAnchor))
	}
}

func Test_isGoogleAPIKeyBody(t *testing.T) {
	// The count and the alphabet together, stated over every byte rather than
	// by example: a body is exactly googleAPIKeyBodyChars characters and each
	// of them base64url.
	body := strings.Repeat("a", googleAPIKeyBodyChars)

	if !isGoogleAPIKeyBody(body) {
		t.Errorf("isGoogleAPIKeyBody(%q) = false, want a body of %d characters to be one", body, googleAPIKeyBodyChars)
	}
	for _, s := range []string{body[:len(body)-1], body + "a"} {
		if isGoogleAPIKeyBody(s) {
			t.Errorf("isGoogleAPIKeyBody(%q) = true, want only %d characters to be a body", s, googleAPIKeyBodyChars)
		}
	}

	for c := range 256 {
		b := byte(c)
		src := body[:len(body)-1] + string([]byte{b})
		if got, want := isGoogleAPIKeyBody(src), isBase64URLByte(b); got != want {
			t.Errorf("isGoogleAPIKeyBody(%q) = %v with %q in it, want %v", src, got, b, want)
		}
	}
}

// referenceGoogleAPIKey is the expression the scan in builtin_google_api_key.go
// reads by hand: the statement of what a Google API key is, kept here so that
// the scan can be held to it.
//
// The prefix, the count and the alphabet are spelled again rather than built
// from googleAPIKeyPrefix, googleAPIKeyBodyChars and isBase64URLByte. A
// reference sharing those declarations could not disagree with the scan about
// them, and it is exactly that disagreement the fuzz target below is for: the
// two have to be changed together or reported apart.
var referenceGoogleAPIKey = regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)

// referenceGoogleAPIKeyFind locates keys the plain way: the leftmost match of
// the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a key can begin inside one: the prefix is
// written in the alphabet a body is, so AIzaAIza... holds a key the engine
// would never go on to try. The scan finds both and reports the two spans
// overlapping for a Masker to resolve, so the reference must ask about both.
//
// Resuming a byte along costs this one nothing beyond a constant, where a
// reference reading a body to the end of its run pays for it: every candidate
// reads at most thirty-nine characters, here as in the scan, so neither has a
// run to walk and there is no cursor for either to be wrong about.
func referenceGoogleAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceGoogleAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzGoogleAPIKey_matchesReference guards the hand-written scan: the prefix it
// searches for, the count it reads behind that prefix, the alphabet it reads it
// in and the byte it resumes at may none of them change which keys are located.
func FuzzGoogleAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("GOOGLE_API_KEY=AIza0123456789abcdefghijklmnopqrstuvwxy")
	f.Add("AIza0123456789abcdef-hijklmnopqrstuvwx_")  // a hyphen and an underscore in the body
	f.Add("AIza0123456789abcdefghijklmnopqrstuvwx")   // one short of a key
	f.Add("AIza0123456789abcdefghijklmnopqrstuvwxyz") // and a run longer than one
	f.Add("aiza0123456789abcdefghijklmnopqrstuvwxy")  // a lowercase prefix
	f.Add("AIZA0123456789abcdefghijklmnopqrstuvwxy")  // an uppercase one
	f.Add("AIzb0123456789abcdefghijklmnopqrstuvwxy")  // three characters of one
	f.Add("AIza0123456789abcdef+hijklmnopqrstuvwx/")  // standard base64 rather than base64url
	f.Add("AIza0123456789abcdef.hijklmnopqrstuvwxy")  // a dot ends the body
	f.Add("AIza0123456789abcdefghijklmnopqrstuvwxy.next")
	f.Add("AIza0123456789abcdefghijklmnopqrstuvwxy\nAIza0123456789abcdefghijklmnopqrstuvwxy")
	// A key beginning inside the match before it, which a scan resuming past a
	// match steps over, and two keys with nothing between them, which is the
	// same text without the overlap.
	f.Add("AIzaAIza0123456789abcdefghijklmnopqrstuvwxy")
	f.Add("AIza0123456789abcdefghijklmnopqrstuvwxyAIza0123456789abcdefghijklmnopqrstuvwxy")
	f.Add(strings.Repeat("AIzaAIza", 8))
	// Candidate positions crowded as close as they can be: every fourth byte in
	// the first, and a run that is a body to every candidate in it.
	f.Add(strings.Repeat("AIza", 32))
	f.Add(strings.Repeat("AIza", 32) + "!")
	// The prefix written inside a run of the alphabet, which is the over-match
	// the pattern admits, and the same run one character short of admitting it.
	f.Add("zzzzAIza0123456789abcdefghijklmnopqrstuvwxyzzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.AIza0123456789abcdefghijklmnopqrstuvwxy")

	fuzzAgainstReference(f, GoogleAPIKey().Find, referenceGoogleAPIKeyFind)
}

// googleAPIKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under
// a plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func googleAPIKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling the Maps API" url=https://maps.googleapis.com/maps/api/geocode/json `
	key := "AIza0123456789abcdefghijklmnopqrstuvwxy"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is four characters a body is written with, so a run
			// can hold a candidate for every four it has. Here each of them
			// reads the body as far as the character that is not one, which
			// stands where the run ends: the crowding this pattern admits,
			// with no value at the end of any of it.
			name:  "candidates that are not values",
			src:   strings.Repeat("AIzaAIzaAIzaAIzaAIzaAIzaAIzaAIza.", 16),
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
