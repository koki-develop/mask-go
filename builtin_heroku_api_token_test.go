package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Heroku API token pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. A body in the shape Heroku writes a token in now
// is sixty base64url characters, which is 0123456789abcdef three times over and
// twelve more, so with the prefix in front a token is sixty-five. A body in the
// shape it wrote one in until 23 April 2025 is a UUID, the same run cut into
// the groups 8-4-4-4-12, so such a token is forty-one.

func Test_HerokuAPIToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{0, 65}},
		},
		{
			name: "a token in an environment assignment",
			src:  "HEROKU_API_KEY=HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{15, 80}},
		},
		{
			name: "a token in the header the platform api reads it from",
			src:  "Authorization: Bearer HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{22, 87}},
		},
		{
			name: "a token in the shape written until the length changed",
			src:  "HRKU-01234567-89ab-cdef-0123-456789abcdef",
			want: []Span{{0, 41}},
		},
		{
			// The counts are read exactly, so what follows the last character
			// of a token is not part of it and stays in the text.
			name: "a body run longer than the count is a token and what follows it",
			src:  "HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
			want: []Span{{0, 65}},
		},
		{
			// Neither token is inside the other, and nothing separates them.
			name: "two tokens with nothing between them",
			src:  "HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abHRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{0, 65}, {65, 130}},
		},
		{
			name: "a token of each shape on one line",
			src:  "new=HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab old=HRKU-01234567-89ab-cdef-0123-456789abcdef",
			want: []Span{{4, 69}, {74, 115}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HerokuAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HerokuAPIToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "HRKU-",
		},
		{
			name: "a body one character short",
			src:  "HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a body carrying a space",
			src:  "HRKU-0123456789abcdef 123456789abcdef0123456789abcdef0123456789ab",
		},
		{
			name: "a body carrying a dot",
			src:  "HRKU-0123456789abcdef.123456789abcdef0123456789abcdef0123456789ab",
		},
		{
			name: "a body carrying an equals sign",
			src:  "HRKU-0123456789abcdef=123456789abcdef0123456789abcdef0123456789ab",
		},
		{
			name: "a lowercase prefix",
			src:  "hrku-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
		},
		{
			name: "the prefix without the hyphen closing it",
			src:  "HRKU0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
		},
		{
			name: "an underscore where the prefix closes",
			src:  "HRKU_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
		},
		{
			name: "the prefix without one of its letters",
			src:  "HRU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
		},
		{
			name: "a body of the right length opening with no prefix",
			src:  "xxxxx0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
		},
		{
			// The separators of a UUID stand at fixed places, which is the
			// whole of what tells that shape from any other thirty-six
			// characters written behind the prefix.
			name: "a uuid whose separators stand elsewhere",
			src:  "HRKU-0123456-789ab-cdef-0123-456789abcdef",
		},
		{
			name: "a uuid with a group past hexadecimal",
			src:  "HRKU-0123456g-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "a uuid one character short",
			src:  "HRKU-01234567-89ab-cdef-0123-456789abcde",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HerokuAPIToken().Find(tt.src); got != nil {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_HerokuAPIToken_inContext(t *testing.T) {
	// The places a token is written: the environment variable the CLI and every
	// tool around it read one from, the header the Platform API takes it in, the
	// file the CLI stores it in, and the command lines and responses that pass
	// it along.
	const token = "HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"

	tests := []struct {
		name  string
		src   string
		start int
	}{
		{
			name:  "a token in a dotenv line",
			src:   "HEROKU_API_KEY=" + token,
			start: 15,
		},
		{
			name:  "a token in the authorization header",
			src:   "Authorization: Bearer " + token,
			start: 22,
		},
		{
			name:  "a token on a curl command line",
			src:   `curl -H "Authorization: Bearer ` + token + `" https://api.heroku.com/apps`,
			start: 31,
		},
		{
			name:  "a token in the netrc entry the cli writes",
			src:   "machine api.heroku.com\n  login me@example.com\n  password " + token,
			start: 57,
		},
		{
			name:  "a token in the json an authorization returns",
			src:   `{"access_token":"` + token + `","expires_in":28799,"token_type":"Bearer"}`,
			start: 17,
		},
		{
			name:  "a token in what the cli prints on creating an authorization",
			src:   "Token:       " + token,
			start: 13,
		},
		{
			name:  "a token at the end of a sentence",
			src:   "the token is " + token + ".",
			start: 13,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := []Span{{tt.start, tt.start + len(token)}}
			if got, _ := HerokuAPIToken().Find(tt.src); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, want)
			}
		})
	}
}

func Test_HerokuAPIToken_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match. A word boundary in front
	// would drop the whole match rather than trim it wherever a token is
	// written against a word character, and one behind it would drop a token
	// followed by a character of the body's own alphabet. Both rulesets reading
	// this format open on one, and both close on something.
	const token = "HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"

	tests := []struct {
		name  string
		src   string
		start int
	}{
		{
			name:  "a token after an underscore",
			src:   "HEROKU_API_KEY_" + token,
			start: 15,
		},
		{
			name:  "a token after a letter",
			src:   "x" + token,
			start: 1,
		},
		{
			name:  "a word written against a token",
			src:   token + "-suffix",
			start: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := []Span{{tt.start, tt.start + len(token)}}
			if got, _ := HerokuAPIToken().Find(tt.src); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, want)
			}
		})
	}
}

func Test_HerokuAPIToken_leavesWhatFollowsAlone(t *testing.T) {
	// A token is sixty-five characters, or forty-one in the shorter shape, and
	// no more — so what is written after one stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the token is HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.",
			want: "the token is *****************************************************************.",
		},
		{
			name: "quoted",
			src:  `"HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"`,
			want: `"*****************************************************************"`,
		},
		{
			// A character the alphabet does admit: the count is what ends a
			// token, so the two digits stay in the text rather than joining it.
			name: "digits written against a token",
			src:  "HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
			want: "*****************************************************************cd",
		},
		{
			// And the shorter shape, where what follows is a hexadecimal
			// character the longer reading would have taken had there been
			// enough of them.
			name: "a digit written against a token of the shorter shape",
			src:  "HRKU-01234567-89ab-cdef-0123-456789abcdef0",
			want: "*****************************************0",
		},
	}

	m := New(WithPatterns(HerokuAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HerokuAPIToken_theUUIDReadingInsideTheLongerOne(t *testing.T) {
	// The corner builtin_heroku_api_token.go argues. A UUID is written in
	// base64url, so a whole token of the shorter shape stands at the front of
	// any longer one whose first thirty-six characters happen to fall that way,
	// and both readings are then true of the same text.
	//
	// The scan walks the longer reading first, so such a token is reported once
	// at sixty-five characters rather than as that span and the forty-one
	// character one inside it. Where the longer reading fails the shorter is
	// taken all the same.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token whose body opens on a uuid is one span and not two",
			src:  "HRKU-01234567-89ab-cdef-0123-456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 65}},
		},
		{
			name: "a uuid with too few characters behind it for the longer reading",
			src:  "HRKU-01234567-89ab-cdef-0123-456789abcdef0123",
			want: []Span{{0, 41}},
		},
		{
			name: "a body too short for either reading",
			src:  "HRKU-01234567-89ab-cdef-0123-45678",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HerokuAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HerokuAPIToken_holdsATokenTheInputCutShort(t *testing.T) {
	// The other half of the order the two readings are walked in, which no span
	// above reports. A token of the longer shape whose body opens on a UUID
	// holds a whole token of the shorter shape in front of the cut, so a scan
	// taking that shorter one and settling the text behind it would have a
	// stream write out forty-one characters of redaction with the last
	// twenty-four characters of a live token beside them.
	//
	// What the scan reports instead is the span it has and the start of the
	// value as the place the input stops being settled, which holds a Writer
	// until the rest arrives. The two cases are the same text cut and whole.
	whole := "HRKU-01234567-89ab-cdef-0123-456789abcdef0123456789abcdef01234567"
	cut := whole[:len(whole)-1]

	spans, retain := HerokuAPIToken().Find(cut)
	if want := []Span{{0, 41}}; !slices.Equal(spans, want) {
		t.Errorf("Find(%q) = %v, want %v", cut, spans, want)
	}
	if retain != 0 {
		t.Errorf("Find(%q) settled from %d, want 0", cut, retain)
	}

	m := New(WithPatterns(HerokuAPIToken()))
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
		t.Errorf("a token written in two pieces came out %q, want %q", got, want)
	}
}

func Test_HerokuAPIToken_aTokenBeginningInsideAnother(t *testing.T) {
	// What advancing rather than consuming the match has to find here, and it
	// is unbounded rather than narrow: every character of the prefix is written
	// in the body's alphabet, so a whole prefix can stand anywhere inside a
	// body.
	//
	// A scan consuming its match would resume past the outer token and leave
	// the inner one in the output whole. The two spans overlap, which a Masker
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
			src:  "HRKU-HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{0, 65}, {5, 70}},
		},
		{
			// And one written far enough along that the outer body runs out
			// before it, so only the inner token stands.
			name: "a token opening past the end of the body around it",
			src:  "HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abHRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{0, 65}, {65, 130}},
		},
	}

	m := New(WithPatterns(HerokuAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HerokuAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Fatalf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
			if got, want := m.Mask(tt.src), strings.Repeat("*", len(tt.src)); got != want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, want)
			}
		})
	}
}

func Test_HerokuAPIToken_aBodyOpeningPastTheRulesets(t *testing.T) {
	// The tightening builtin_heroku_api_token.go declines. Both rulesets
	// reading this format ask for AA at the front of a body — gitleaks reads it
	// as part of the expression, trufflehog pre-filters its input on the
	// literal HRKU-AA — and Heroku states the prefix and the length without
	// stating those two characters.
	//
	// A body opening on them is located, and so is a body opening on anything
	// else. Being wrong about the two would locate nothing at all, where being
	// wrong about the alphabet locates a token with a character too many.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a body opening on the two characters the rulesets ask for",
			src:  "HRKU-AA0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			want: []Span{{0, 65}},
		},
		{
			name: "a body opening on anything else",
			src:  "HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{0, 65}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HerokuAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HerokuAPIToken_aKebabCaseRunBehindThePrefix(t *testing.T) {
	// What this alphabet reaches that a base62 body would not. The hyphen is a
	// body character, so a run of hyphenated words is never broken and sixty of
	// them behind the prefix are a body character for character.
	//
	// It is redacted, and what holds it back is only the four capitals in
	// front, which spell no word and which no kebab-case name written by a tool
	// begins with. Narrowing the alphabet to rule it out would decline every
	// token whose body fell with a hyphen in it, which is most of them.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a hyphenated run long enough to be a body",
			src:  "HRKU-alpha-bravo-charlie-delta-echo-foxtrot-golf-hotel-india-juliet",
			want: []Span{{0, 65}},
		},
		{
			name: "a hyphenated run the count stops short of",
			src:  "HRKU-alpha-bravo-charlie-delta-echo-foxtrot-golf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HerokuAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HerokuAPIToken_theCredentialsWithNoPrefix(t *testing.T) {
	// The two shapes Heroku's own pages print with nothing in front of them,
	// both left in the output whole. The refresh token handed out beside an
	// access token is a bare UUID — the OAuth page prints the pair in one
	// response, the access token prefixed and the refresh token not. The forty
	// hexadecimal characters are the example the authentication page writes its
	// netrc entry with, which is neither shape on record; what the CLI stores
	// in that field today is the OAuth token the changelogs prefixed, and
	// Test_HerokuAPIToken_inContext locates one there.
	//
	// Neither carries the anchor the whole of this pattern rests on, and what
	// is left of each is a shape this package may not read: a UUID is an
	// identifier written in URLs and dashboards by design, and forty
	// hexadecimal characters are a SHA-1.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a refresh token beside an access token",
			src:  `{"refresh_token":"01234567-89ab-cdef-0123-456789abcdef"}`,
		},
		{
			name: "the older shape the netrc example is written in",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HerokuAPIToken().Find(tt.src); got != nil {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_HerokuAPIToken_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor and can keep none: a run of the body's alphabet
	// may hold a prefix at any of its characters, so no two candidates can be
	// told apart by where the run before them ended. What holds it linear is
	// the counts being counts — a candidate reads at most sixty bytes and stops
	// — and these are the inputs that would find that wrong.
	//
	// The generic guard in builtins_test.go repeats the samples, the densest of
	// which holds two candidates five bytes apart. The crowding a whole line
	// can carry stays here.
	sources := map[string]string{
		// The anchor at every byte, each turned away by the second character of
		// the prefix, which is the cheapest this scan declines anything.
		"the anchor at every byte": strings.Repeat("H", 2000000),
		// A whole prefix every six characters, each turned away by the space
		// standing where its body would open.
		"a prefix every six characters": strings.Repeat("HRKU- ", 330000),
		// A whole prefix every five characters, with nothing between them, so
		// every candidate reads sixty characters of body and most report a
		// span.
		"a prefix every five characters": strings.Repeat("HRKU-", 400000),
		// One candidate whose body is the whole line. The count stops it at
		// sixty characters; a scan reading the run would read two mebibytes.
		"a base64url run the length of the line": "HRKU-" + strings.Repeat("a", 2000000),
		// The same run with no prefix in front of it, so no candidate is found
		// in it at all.
		"a base64url run with no prefix": strings.Repeat("a", 2000000),
	}

	checkScanIsLinear(t, HerokuAPIToken(), sources)
}

// Test_herokuAPITokenPrefix holds the prefix to being written in the body's own
// alphabet, which is what several sentences in builtin_heroku_api_token.go rest
// on: that a token can begin anywhere inside another, that the scan can keep no
// cursor, and that the byte it searches for had to be chosen on the text around
// a token rather than on the body.
//
// It is held rather than assumed so that those sentences are a measurement. A
// prefix carrying one character outside base64url would make all three of them
// wrong at once, and nothing else here would report it: the cases above would
// go on passing, since what they drive is a prefix that still stands where it
// is written.
func Test_herokuAPITokenPrefix(t *testing.T) {
	if len(herokuAPITokenPrefix) == 0 {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for i := range len(herokuAPITokenPrefix) {
		if c := herokuAPITokenPrefix[i]; !isBase64URLByte(c) {
			t.Errorf("the prefix %q carries %q, which no body is written with — a run of the body's alphabet can no longer hold one", herokuAPITokenPrefix, c)
		}
	}
}

// Test_herokuAPITokenAnchor holds the prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_herokuAPITokenAnchor(t *testing.T) {
	if herokuAPITokenAnchorIndex >= len(herokuAPITokenPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", herokuAPITokenAnchorIndex, len(herokuAPITokenPrefix))
	}
	if c := herokuAPITokenPrefix[herokuAPITokenAnchorIndex]; c != herokuAPITokenAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(herokuAPITokenAnchor))
	}

	// What the anchor costs, held rather than claimed in prose. It stands once
	// in the prefix, so a run of prefixes stops the search once a prefix; and
	// it is not the character the prefix closes with, which is what every ISO
	// timestamp, every UUID and every kebab-case name is written with.
	if n := strings.Count(herokuAPITokenPrefix, string(herokuAPITokenAnchor)); n != 1 {
		t.Errorf("the anchor stands %d times in %q, want 1", n, herokuAPITokenPrefix)
	}
	if closing := herokuAPITokenPrefix[len(herokuAPITokenPrefix)-1]; herokuAPITokenAnchor == closing {
		t.Errorf("the anchor is the character the prefix closes with, %q, which ordinary text is written with", closing)
	}
}

// Test_herokuAPITokenChars holds the arithmetic to the two lengths Heroku
// states, and the groups of a UUID to coming to the count the scan cuts by.
//
// The counts are the vendor's own: the OAuth page states sixty-five characters
// in a sentence, and the changelog of 23 April 2025 states the forty-one a
// token was before it. What would go wrong without this is the documentation on
// HerokuAPIToken promising those two widths, and the spans every case in this
// file is written with.
func Test_herokuAPITokenChars(t *testing.T) {
	if got := len(herokuAPITokenPrefix); got != 5 {
		t.Errorf("len(herokuAPITokenPrefix) = %d, want 5", got)
	}
	if got := herokuAPITokenBodyChars; got != 60 {
		t.Errorf("herokuAPITokenBodyChars = %d, want 60", got)
	}
	if got := herokuAPITokenChars; got != 65 {
		t.Errorf("herokuAPITokenChars = %d, want the 65 Heroku states", got)
	}
	if got := herokuAPITokenUUIDBodyChars; got != 36 {
		t.Errorf("herokuAPITokenUUIDBodyChars = %d, want 36", got)
	}
	if got := herokuAPITokenUUIDChars; got != 41 {
		t.Errorf("herokuAPITokenUUIDChars = %d, want the 41 Heroku states", got)
	}

	// The groups and the separators between them are what the shorter reading
	// walks; the count above is what the scan cuts by before walking it. The
	// two are written apart and would go on passing everything above if they
	// came apart, since a walk over a string of the wrong length simply reads
	// what it was handed.
	chars := len(herokuAPITokenUUIDGroups) - 1
	for _, width := range herokuAPITokenUUIDGroups {
		chars += width
	}
	if chars != herokuAPITokenUUIDBodyChars {
		t.Errorf("the groups come to %d characters, the scan cuts %d", chars, herokuAPITokenUUIDBodyChars)
	}
}

func Test_isHerokuAPITokenBody(t *testing.T) {
	// The count and the character class together, stated over every byte rather
	// than by example.
	body := strings.Repeat("a", herokuAPITokenBodyChars)

	if !isHerokuAPITokenBody(body) {
		t.Errorf("isHerokuAPITokenBody(%q) = false, want a body of %d characters to be one", body, herokuAPITokenBodyChars)
	}
	for _, s := range []string{body[:len(body)-1], body + "a"} {
		if isHerokuAPITokenBody(s) {
			t.Errorf("isHerokuAPITokenBody(%q) = true, want only %d characters to be a body", s, herokuAPITokenBodyChars)
		}
	}

	for i := range herokuAPITokenBodyChars {
		for c := range 256 {
			b := byte(c)
			src := body[:i] + string([]byte{b}) + body[i+1:]
			if got, want := isHerokuAPITokenBody(src), isBase64URLByte(b); got != want {
				t.Errorf("isHerokuAPITokenBody(%q) = %v with %q at %d, want %v", src, got, b, i, want)
			}
		}
	}
}

func Test_isHerokuAPITokenUUIDBody(t *testing.T) {
	// The layout and the character class together, stated over every byte
	// rather than by example: a separator stands where the groups put one and
	// hexadecimal everywhere else.
	const body = "01234567-89ab-cdef-0123-456789abcdef"

	if !isHerokuAPITokenUUIDBody(body) {
		t.Errorf("isHerokuAPITokenUUIDBody(%q) = false, want a uuid to be one", body)
	}
	for _, s := range []string{body[:len(body)-1], body + "0"} {
		if isHerokuAPITokenUUIDBody(s) {
			t.Errorf("isHerokuAPITokenUUIDBody(%q) = true, want only %d characters to be one", s, herokuAPITokenUUIDBodyChars)
		}
	}

	separators := map[int]bool{}
	at := 0
	for g, width := range herokuAPITokenUUIDGroups {
		if g > 0 {
			separators[at] = true
			at++
		}
		at += width
	}

	for i := range len(body) {
		for c := range 256 {
			b := byte(c)
			src := body[:i] + string([]byte{b}) + body[i+1:]
			want := isHerokuAPITokenUUIDByte(b)
			if separators[i] {
				want = b == herokuAPITokenUUIDSeparator
			}
			if got := isHerokuAPITokenUUIDBody(src); got != want {
				t.Errorf("isHerokuAPITokenUUIDBody(%q) = %v with %q at %d, want %v", src, got, b, i, want)
			}
		}
	}
}

func Test_isHerokuAPITokenUUIDByte(t *testing.T) {
	// The hexadecimal digits of either case and nothing else, stated over every
	// byte rather than by example. Heroku prints these lowercase; reading the
	// other case as well is what builtin_heroku_api_token.go weighs.
	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9' || 'A' <= b && b <= 'F' || 'a' <= b && b <= 'f'
		if got := isHerokuAPITokenUUIDByte(b); got != want {
			t.Errorf("isHerokuAPITokenUUIDByte(%q) = %v, want %v", b, got, want)
		}
	}
}

// referenceHerokuAPIToken is the expression the scan in
// builtin_heroku_api_token.go reads by hand: the statement of what a Heroku API
// token is, kept here so that the scan can be held to it.
//
// The prefix, both readings, both counts and both character classes are spelled
// again rather than built from the declarations beside the scan. A reference
// sharing those could not disagree with the scan about them, and it is exactly
// that disagreement the fuzz target below is for: the two have to be changed
// together or reported apart.
//
// The alternation is written with the sixty characters in front of the UUID,
// which is the order the scan walks its two readings in and is spelled here for
// the same reason as everything else: an engine prefers the first branch that
// lets the whole match succeed, so the order decides whether a token whose body
// opens on a UUID is reported at sixty-five characters or at the forty-one
// inside it, and whether a UUID with too little behind it falls back to the
// shorter reading.
//
// Both repetitions are exact, so the machine an engine builds for a candidate
// is read once and stops, where a floor spelled as a counted repetition would
// cost a machine as wide as the floor at every candidate. What an engine
// searches the text for is the five character literal the expression opens with
// — every character of which a body is written with, so a run of the body's
// alphabet is a place the search stops, and what keeps that cheap is the
// literal being five characters rather than one.
var referenceHerokuAPIToken = regexp.MustCompile(`HRKU-(?:[0-9A-Za-z_-]{60}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`)

// referenceHerokuAPITokenFind locates tokens the plain way: the leftmost match
// of the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// Asking at every byte rather than resuming past a match is what the scan does,
// and here it is what finds anything at all past the first token: every
// character of the prefix is written in the body's alphabet, so a token can
// begin anywhere inside another.
func referenceHerokuAPITokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceHerokuAPIToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzHerokuAPIToken_matchesReference guards the hand-written scan: the prefix
// it searches for, the case it reads that prefix in, the two counts it reads
// behind it, the alphabets it reads them in, the order it walks the two
// readings in and the byte it resumes at may none of them change which tokens
// are located.
func FuzzHerokuAPIToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("HEROKU_API_KEY=HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab")
	f.Add("HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789a")  // a body one short
	f.Add("HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab") // and exact
	f.Add("HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd")
	f.Add("HRKU-0123456789abcdef 123456789abcdef0123456789abcdef0123456789ab")
	f.Add("HRKU-0123456789abcdef.123456789abcdef0123456789abcdef0123456789ab")
	f.Add("HRKU-0123456789abcdef\n123456789abcdef0123456789abcdef0123456789ab")
	f.Add("hrku-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab") // a lowercase prefix
	f.Add("HRKU0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc") // no hyphen closing it
	f.Add("HRKU_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab") // an underscore closing it
	f.Add("xHRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab")
	// The body both rulesets ask for, which this scan does not.
	f.Add("HRKU-AA0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	// The shorter reading, and the corner where it stands inside the longer one.
	f.Add("HRKU-01234567-89ab-cdef-0123-456789abcdef")
	f.Add("HRKU-01234567-89ab-cdef-0123-456789abcdef0123")
	f.Add("HRKU-01234567-89ab-cdef-0123-456789abcdef0123456789abcdef01234567")
	f.Add("HRKU-01234567-89AB-CDEF-0123-456789ABCDEF")
	f.Add("HRKU-0123456-789ab-cdef-0123-456789abcdef")
	f.Add("HRKU-0123456g-89ab-cdef-0123-456789abcdef")
	f.Add("HRKU-01234567-89ab-cdef-0123-456789abcde")
	// The credentials with no prefix, and the run a hyphenated name is.
	f.Add(`{"refresh_token":"01234567-89ab-cdef-0123-456789abcdef"}`)
	f.Add("0123456789abcdef0123456789abcdef01234567")
	f.Add("HRKU-alpha-bravo-charlie-delta-echo-foxtrot-golf-hotel-india-juliet")
	// A prefix in front of a token, two tokens with nothing between them, and
	// candidate positions crowded as close as they can be.
	f.Add("HRKU-HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab")
	f.Add("HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abHRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab")
	f.Add(strings.Repeat("HRKU-", 64))
	f.Add(strings.Repeat("HRKU- ", 64))
	f.Add(strings.Repeat("HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab", 4))
	f.Add(strings.Repeat("-", 128))
	f.Add(strings.Repeat("H", 128))
	f.Add(`time=2026-08-17T00:00:00Z level=info msg="deploying release" app=acme-web`)

	fuzzAgainstReference(f, HerokuAPIToken().Find, referenceHerokuAPITokenFind)
}

// herokuAPITokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func herokuAPITokenFindBenchmarks() []benchmarkCase {
	// The line the anchor is chosen against. Not one of the four letters the
	// prefix is written with stands on it, which is what four capitals in a row
	// buys and is why the search stops here only where the text is uppercase;
	// the hyphen the prefix closes with stands four times, twice in the
	// timestamp and once in each writing of the application's own name, and is
	// the byte not to anchor on for that reason.
	line := `time=2026-08-17T00:00:00Z level=info msg="deploying release" app=acme-web url=https://api.heroku.com/apps/acme-web/dynos `
	token := "HRKU-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A whole prefix every six characters, each turned away by the
			// space standing where its body would open — which is the cheapest
			// this scan declines a candidate once the prefix has been read.
			name:  "candidates that are not values",
			src:   strings.Repeat("HRKU- ", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads a prefix, since the character behind each
			// is the anchor rather than the R. That is one comparison a stop,
			// and the cheapest a stop is answered for at all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("H", 4096),
			spans: 0,
		},
		{
			// The way a candidate is walked furthest without becoming a value:
			// a body of the right length whose last character is a space, so
			// the whole of it is walked before either reading is turned away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("HRKU-0123456789abcdef0123456789abcdef0123456789abcdef012345678 ", 16),
			spans: 0,
		},
		{
			// A base64url run carrying no character of the prefix at all, which
			// is what a digest and an identifier are written in, so the search
			// walks the whole of it in one pass.
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
