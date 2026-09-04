package mask

import (
	"encoding/hex"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The SonarQube token pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. The run they are built from,
// 0123456789abcdef0123456789abcdef01234567, is forty characters and so is a
// whole body.

func Test_SonarQubeToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a user token",
			src:  "squ_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}},
		},
		{
			name: "a global analysis token",
			src:  "sqa_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}},
		},
		{
			name: "a project analysis token",
			src:  "sqp_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}},
		},
		{
			name: "a project badge token",
			src:  "sqb_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}},
		},
		{
			name: "a token in an environment assignment",
			src:  "SONAR_TOKEN=squ_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{12, 56}},
		},
		{
			// The forty behind the prefix are read as a count and not a floor:
			// what follows the forty-fourth character is not part of the token
			// and stays in the text.
			name: "a hexadecimal run longer than a token is a token and what follows it",
			src:  "squ_0123456789abcdef0123456789abcdef012345678",
			want: []Span{{0, 44}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "squ_0123456789abcdef0123456789abcdef01234567sqa_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}, {44, 88}},
		},
		{
			// The same shape as the squ_ case above, driven against another
			// kind: the forty-first character is not part of the token and
			// stays in the text.
			name: "a hexadecimal run longer than a token is a token and what follows it, for another kind",
			src:  "sqa_0123456789abcdef0123456789abcdef012345678",
			want: []Span{{0, 44}},
		},
		{
			// A multi-byte rune is neither hexadecimal nor the underscore a
			// prefix closes with, so it opens a candidate in front of a token
			// exactly as an ASCII byte would.
			name: "a token after a multi-byte rune",
			src:  "日本語squ_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{9, 53}},
		},
		{
			// And it ends the body behind one: none of its bytes are lowercase
			// hexadecimal.
			name: "a token before a multi-byte rune",
			src:  "squ_0123456789abcdef0123456789abcdef01234567日本語",
			want: []Span{{0, 44}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SonarQubeToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SonarQubeToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "squ_",
		},
		{
			// Thirty-nine characters where the pattern asks for forty.
			name: "body one character too short",
			src:  "squ_0123456789abcdef0123456789abcdef0123456",
		},
		{
			name: "a letter outside hexadecimal in the body",
			src:  "squ_0123456789abcdefg123456789abcdef01234567",
		},
		{
			name: "an uppercase body",
			src:  "squ_0123456789ABCDEF0123456789abcdef01234567",
		},
		{
			name: "a hyphen in the body",
			src:  "squ_0123456789abcdef-123456789abcdef01234567",
		},
		{
			name: "a body broken by a space",
			src:  "squ_0123456789abcdef 123456789abcdef01234567",
		},
		{
			name: "a body broken by a line break",
			src:  "squ_0123456789abcdef\n123456789abcdef01234567",
		},
		{
			name: "an uppercase prefix",
			src:  "SQU_0123456789abcdef0123456789abcdef01234567",
		},
		{
			// A character naming no kind SonarQube writes.
			name: "a prefix naming another kind",
			src:  "sqx_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "the prefix without the character naming the kind",
			src:  "sq_0123456789abcdef0123456789abcdef012345678",
		},
		{
			name: "a hyphen where the prefix carries its underscore",
			src:  "squ-0123456789abcdef0123456789abcdef01234567",
		},
		{
			// Forty hexadecimal characters that open with something else. The
			// prefix is the whole of the anchor, so a run of the right length
			// is not a token without it.
			name: "a run of the right length opening with no prefix",
			src:  "xxx_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// A commit hash is the body without the prefix in front of it.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
		{
			// The character the prefix itself closes with, standing inside the
			// forty rather than in front of them: it is outside lowercase
			// hexadecimal wherever it stands.
			name: "an underscore inside the body",
			src:  "squ_0123456789abcdef_123456789abcdef01234567",
		},
		{
			name: "an uppercase prefix naming another kind",
			src:  "SQB_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a prefix with only its first letter uppercase",
			src:  "Squ_0123456789abcdef0123456789abcdef01234567",
		},
		{
			// The alphabet a body is read in ends at the boundary wherever it
			// stands, not only in the middle of the forty: an uppercase
			// hexadecimal digit at the very first character ends the reading
			// exactly as one further in does.
			name: "an uppercase hexadecimal character at the start of the body",
			src:  "squ_A123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "an uppercase hexadecimal character at the end of the body",
			src:  "squ_0123456789abcdef0123456789abcdef0123456F",
		},
		{
			name: "a letter outside hexadecimal at the start of the body",
			src:  "squ_g123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a letter outside hexadecimal at the end of the body",
			src:  "squ_0123456789abcdef0123456789abcdef0123456z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SonarQubeToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_SonarQubeToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "SONAR_TOKEN=squ_0123456789abcdef0123456789abcdef01234567",
			want: "SONAR_TOKEN=********************************************",
		},
		{
			// The property an analysis is handed its token in.
			name: "an analysis property",
			src:  "sonar-scanner -Dsonar.token=sqp_0123456789abcdef0123456789abcdef01234567",
			want: "sonar-scanner -Dsonar.token=********************************************",
		},
		{
			name: "quoted",
			src:  `"squ_0123456789abcdef0123456789abcdef01234567"`,
			want: `"********************************************"`,
		},
		{
			name: "json",
			src:  `{"token":"sqa_0123456789abcdef0123456789abcdef01234567"}`,
			want: `{"token":"********************************************"}`,
		},
		{
			// The URL a badge is rendered from, which is where a badge token is
			// written.
			name: "a badge url",
			src:  "https://sonarqube.example.com/api/project_badges/measure?project=my-project&metric=alert_status&token=sqb_0123456789abcdef0123456789abcdef01234567",
			want: "https://sonarqube.example.com/api/project_badges/measure?project=my-project&metric=alert_status&token=********************************************",
		},
		{
			name: "twice",
			src:  "squ_0123456789abcdef0123456789abcdef01234567 sqp_0123456789abcdef0123456789abcdef01234567",
			want: "******************************************** ********************************************",
		},
	}

	m := New(WithPatterns(SonarQubeToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SonarQubeToken_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the token through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xsqu_0123456789abcdef0123456789abcdef01234567",
			want: "x********************************************",
		},
		{
			name: "underscore before",
			src:  "SONAR_TOKEN_squ_0123456789abcdef0123456789abcdef01234567",
			want: "SONAR_TOKEN_********************************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this token
			// rather than trim it; without one the forty-four characters
			// SonarQube issued are redacted and the one written after them,
			// which is part of no credential, stays in the text.
			name: "a hexadecimal character after",
			src:  "squ_0123456789abcdef0123456789abcdef012345678",
			want: "********************************************8",
		},
	}

	m := New(WithPatterns(SonarQubeToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SonarQubeToken_leavesWhatFollowsAlone(t *testing.T) {
	// A body carries no character outside lowercase hexadecimal, so ordinary
	// punctuation ends a token and nothing written after it joins it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "host",
			src:  "token=squ_0123456789abcdef0123456789abcdef01234567@sonarqube.example.com",
			want: "token=********************************************@sonarqube.example.com",
		},
		{
			name: "sentence",
			src:  "the token is squ_0123456789abcdef0123456789abcdef01234567.",
			want: "the token is ********************************************.",
		},
		{
			name: "hyphenated word",
			src:  "squ_0123456789abcdef0123456789abcdef01234567-suffix",
			want: "********************************************-suffix",
		},
	}

	m := New(WithPatterns(SonarQubeToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SonarQubeToken_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. Every character of a prefix
	// belongs to base64url, so a payload written in that alphabet can spell one,
	// and where forty hexadecimal characters follow it those forty-four are
	// redacted.
	//
	// They are held to being redacted rather than to being spared. Nothing in
	// the text tells such a run from a token — they are the same forty-four
	// bytes — so a scan that let these through would let a real token through
	// with them, which builtin_sonarqube_token.go sets out. What the table is
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
			src:  "payload=zzzzsqu_0123456789abcdef0123456789abcdef01234567zzzz",
			want: "payload=zzzz********************************************zzzz",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the
			// SonarQube pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.squ_0123456789abcdef0123456789abcdef01234567",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.********************************************",
		},
	}

	m := New(WithPatterns(SonarQubeToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SonarQubeToken_theScopedOrganizationTokenPrefix(t *testing.T) {
	// The prefix SonarQube Cloud identifies a scoped organization token by,
	// which this scan does not read: the rationale beside the scan says what is
	// missing, which is a width. The width the one ruleset reading the format
	// asks for is written out here, and the width of every other kind beside
	// it, so that reading the prefix is a change somebody argues for rather
	// than one somebody notices afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the width the ruleset asks for",
			src:  "sqco_0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "the width the other kinds are written to",
			src:  "sqco_0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SonarQubeToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_SonarQubeToken_theShapeItReplaced(t *testing.T) {
	// The shape a token took before SonarQube wrote a prefix in front of one:
	// forty hexadecimal characters with nothing to recognise them by but the
	// property name beside them, which is the shape the rationale beside the
	// scan declines to read. A pattern reading it would redact every commit
	// hash a caller passes through.
	src := "sonar.login=0123456789abcdef0123456789abcdef01234567"

	if got, _ := SonarQubeToken().Find(src); len(got) != 0 {
		t.Errorf("Find(%q) = %v, want no span", src, got)
	}
}

// Test_SonarQubeToken_noTokenBeginsInsideAnother holds the claim that a
// matched token's forty-four characters can never carry the start of a second
// token's prefix. Every prefix opens on 's' and then 'q', and a body admits
// neither byte — isSonarQubeTokenBodyByte reads lowercase hexadecimal alone —
// so the forty characters behind a matched prefix hold no 's' for a second
// prefix to open on, and the matched prefix's own four characters carry the
// one 's' and the one 'q' the span has, both already spent on the match
// itself. Nothing this scan locates can begin inside a span it already
// reported, so no case here needs to spell out a nested pair that cannot be
// written.
func Test_SonarQubeToken_noTokenBeginsInsideAnother(t *testing.T) {
	if isSonarQubeTokenBodyByte('s') {
		t.Error("a body admits 's', so a second prefix could open inside one")
	}
	if isSonarQubeTokenBodyByte('q') {
		t.Error("a body admits 'q', so a second prefix could open inside one")
	}
}

func Test_SonarQubeToken_settlesACandidateTheInputCutShort(t *testing.T) {
	// What Find's second result reports on an input ending inside a candidate:
	// a candidate's own start where a prefix stands with too little of a body
	// behind it, or where only a piece of a prefix stands. Prose with no
	// opening at all settles the whole input.
	tests := []struct {
		name   string
		src    string
		retain int
	}{
		{
			// The prefix is whole and the body behind it, seventeen
			// characters, is short of the forty the count asks for.
			name:   "a candidate the input cut short",
			src:    "log line token=squ_0123456789abcdef",
			retain: 15,
		},
		{
			// The text ends inside the prefix itself, which might still
			// complete to squ_.
			name:   "a piece of the prefix",
			src:    "log line with squ",
			retain: 14,
		},
		{
			// No anchor stands anywhere in this text, so the search never
			// opens a candidate and the whole input is settled.
			name:   "prose with no prefix at all",
			src:    "log line with nothing",
			retain: len("log line with nothing"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, retain := SonarQubeToken().Find(tt.src)
			if retain != tt.retain {
				t.Errorf("Find(%q) retain = %d, want %d", tt.src, retain, tt.retain)
			}
		})
	}
}

// Test_sonarQubeTokenPrefixes holds every prefix to the parts it is built from:
// the opening SonarQube's generator writes, one character naming the kind, and
// the separator, which stands once and closes it.
//
// The parts are what the table is written as, so what this catches is a kind
// added with a character of its own in it — a separator, or a second character
// naming the kind — which would leave the anchor standing at another index and
// the scan reading a candidate back from the wrong place.
func Test_sonarQubeTokenPrefixes(t *testing.T) {
	if len(sonarQubeTokenPrefixes) != len(sonarQubeTokenKinds) {
		t.Fatalf("%d prefixes are built from %d kinds", len(sonarQubeTokenPrefixes), len(sonarQubeTokenKinds))
	}
	for i, p := range sonarQubeTokenPrefixes {
		if len(p) != sonarQubeTokenPrefixChars {
			t.Errorf("the prefix %q is %d characters, the scan reads %d", p, len(p), sonarQubeTokenPrefixChars)
		}
		if want := sonarQubeTokenOpening + sonarQubeTokenKinds[i] + string(sonarQubeTokenSeparator); p != want {
			t.Errorf("the prefix %q is not %q, which its parts come to", p, want)
		}
		if got := strings.Count(p, string(sonarQubeTokenSeparator)); got != 1 {
			t.Errorf("the prefix %q carries %d separators, want the one that closes it", p, got)
		}
		if !opensSonarQubeToken(p + strings.Repeat("0", sonarQubeTokenBodyChars)) {
			t.Errorf("a token written with the prefix %q opens no candidate", p)
		}
	}
	if opensSonarQubeToken(sonarQubeTokenPrefixes[0][:sonarQubeTokenPrefixChars-1]) {
		t.Error("a prefix the end of the input cut short opens a candidate, which the tail is what holds the input back for")
	}
}

// Test_sonarQubeTokenAnchor holds the prefixes to carrying the byte the scan
// searches the input for at the index it reads a candidate back from, and holds
// that byte to being one no body may carry. builtin_scan.go says why the first
// is held here rather than left to the targets; the second is what keeps a
// hexadecimal run from stopping the search, which is the rationale's reason for
// searching this byte rather than the separator.
func Test_sonarQubeTokenAnchor(t *testing.T) {
	if isSonarQubeTokenBodyByte(sonarQubeTokenAnchor) {
		t.Errorf("the scan searches for %q, which a body may be written with, so every body stops the search", byte(sonarQubeTokenAnchor))
	}
	for _, p := range sonarQubeTokenPrefixes {
		if sonarQubeTokenAnchorIndex >= len(p) {
			t.Fatalf("the anchor stands at %d, the prefix %q is %d characters", sonarQubeTokenAnchorIndex, p, len(p))
		}
		if c := p[sonarQubeTokenAnchorIndex]; c != sonarQubeTokenAnchor {
			t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", p, c, byte(sonarQubeTokenAnchor))
		}
	}
}

// Test_sonarQubeTokenChars holds the counts to the arithmetic the rationale
// reads them as: a body is the width twenty bytes come to in hexadecimal, and a
// token is that with a prefix in front. The widths either side of twenty are
// checked as well, since it is those that make forty the width of one whole
// number of bytes and no other.
func Test_sonarQubeTokenChars(t *testing.T) {
	if got := hex.EncodedLen(20); got != sonarQubeTokenBodyChars {
		t.Errorf("twenty bytes encode to %d characters, the body is read as %d", got, sonarQubeTokenBodyChars)
	}
	for _, n := range []int{19, 21} {
		if got := hex.EncodedLen(n); got == sonarQubeTokenBodyChars {
			t.Errorf("%d bytes encode to %d characters as well, so the count names no one width", n, got)
		}
	}
	if want := sonarQubeTokenPrefixChars + sonarQubeTokenBodyChars; sonarQubeTokenChars != want {
		t.Errorf("a token is read as %d characters, the prefix and the body come to %d", sonarQubeTokenChars, want)
	}
	if sonarQubeTokenChars != 44 {
		t.Errorf("a token is read as %d characters, the rationale says forty-four", sonarQubeTokenChars)
	}
}

func Test_isSonarQubeTokenBody(t *testing.T) {
	// The count and the alphabet together, stated over every byte rather than
	// by example: a body is exactly sonarQubeTokenBodyChars characters and each
	// of them a lowercase hexadecimal digit.
	body := strings.Repeat("a", sonarQubeTokenBodyChars)

	if !isSonarQubeTokenBody(body) {
		t.Errorf("isSonarQubeTokenBody(%q) = false, want a body of %d characters to be one", body, sonarQubeTokenBodyChars)
	}
	for _, s := range []string{body[:len(body)-1], body + "a"} {
		if isSonarQubeTokenBody(s) {
			t.Errorf("isSonarQubeTokenBody(%q) = true, want only %d characters to be a body", s, sonarQubeTokenBodyChars)
		}
	}

	for c := range 256 {
		b := byte(c)
		src := body[:len(body)-1] + string([]byte{b})
		want := '0' <= b && b <= '9' || 'a' <= b && b <= 'f'
		if got := isSonarQubeTokenBody(src); got != want {
			t.Errorf("isSonarQubeTokenBody(%q) = %v with %q in it, want %v", src, got, b, want)
		}
	}
}

// referenceSonarQubeToken is the expression the scan in
// builtin_sonarqube_token.go reads by hand: the statement of what a SonarQube
// token is, kept here so that the scan can be held to it.
//
// The prefixes, the count and the alphabet are spelled again rather than built
// from sonarQubeTokenPrefixes, sonarQubeTokenBodyChars and
// isSonarQubeTokenBodyByte. A reference sharing those declarations could not
// disagree with the scan about them, and it is exactly that disagreement the
// fuzz target below is for: the two have to be changed together or reported
// apart.
var referenceSonarQubeToken = regexp.MustCompile(`sq[uabp]_[0-9a-f]{40}`)

// referenceSonarQubeTokenFind locates tokens the plain way: the leftmost match
// of the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// It asks at every byte rather than resuming past a match, which is what
// FindAllStringIndex would do. That a token cannot be written inside another is
// a claim the scan makes, and a reference is written knowing nothing the scan
// claims; asking at every byte costs this one a constant, since every candidate
// reads at most forty-four characters and neither implementation has a run to
// walk.
func referenceSonarQubeTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceSonarQubeToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzSonarQubeToken_matchesReference guards the hand-written scan: the
// prefixes it searches for, the count it reads behind them, the alphabet it
// reads it in and the byte it resumes at may none of them change which tokens
// are located.
func FuzzSonarQubeToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("SONAR_TOKEN=squ_0123456789abcdef0123456789abcdef01234567")
	f.Add("sonar-scanner -Dsonar.token=sqp_0123456789abcdef0123456789abcdef01234567")
	f.Add("sqa_0123456789abcdef0123456789abcdef01234567")   // a global analysis token
	f.Add("sqb_0123456789abcdef0123456789abcdef01234567")   // a project badge token
	f.Add("squ_0123456789abcdef0123456789abcdef0123456")    // one short of a token
	f.Add("squ_0123456789abcdef0123456789abcdef012345678")  // and a run longer than one
	f.Add("SQU_0123456789abcdef0123456789abcdef01234567")   // an uppercase prefix
	f.Add("squ_0123456789ABCDEF0123456789abcdef01234567")   // an uppercase body
	f.Add("sqx_0123456789abcdef0123456789abcdef01234567")   // a character naming no kind
	f.Add("squ-0123456789abcdef0123456789abcdef01234567")   // a hyphen where it carries its underscore
	f.Add("sq_0123456789abcdef0123456789abcdef012345678")   // the character naming the kind left out
	f.Add("sqco_0123456789abcdef0123456789abcdef01234567")  // the prefix of a scoped organization token
	f.Add("sonar.login=0123456789abcdef0123456789abcdef01") // the shape a token took before the prefixes
	f.Add("squ_0123456789abcdefg123456789abcdef01234567")   // a letter outside hexadecimal in the body
	f.Add("squ_0123456789abcdef 123456789abcdef01234567")   // a space ends the body
	f.Add("squ_0123456789abcdef0123456789abcdef01234567.next")
	f.Add("squ_0123456789abcdef0123456789abcdef01234567\nsqa_0123456789abcdef0123456789abcdef01234567")
	// Two tokens with nothing between them, and a prefix written where a body
	// would stand.
	f.Add("squ_0123456789abcdef0123456789abcdef01234567sqa_0123456789abcdef0123456789abcdef01234567")
	f.Add("squ_squ_0123456789abcdef0123456789abcdef01234567")
	f.Add(strings.Repeat("squ_", 16))
	// Candidate positions crowded as close as they can be: every fourth byte in
	// the first, and a hexadecimal run behind each of them in the second.
	f.Add(strings.Repeat("squ_", 32) + "0123456789abcdef0123456789abcdef01234567")
	f.Add(strings.Repeat("squ_0123456789abcdef0123456789abcdef012345", 8))
	// The prefix written inside a run of the alphabet a prefix belongs to,
	// which is the over-match the pattern admits, and the same run where a JWT
	// signature stands.
	f.Add("payload=zzzzsqu_0123456789abcdef0123456789abcdef01234567zzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.squ_0123456789abcdef0123456789abcdef01234567")

	fuzzAgainstReference(f, SonarQubeToken().Find, referenceSonarQubeTokenFind)
}

// sonarQubeTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func sonarQubeTokenFindBenchmarks() []benchmarkCase {
	// The vendor's own host name carries the byte the scan searches for, so
	// this line is the shape that costs the search most while holding no token:
	// one candidate opened and turned away on the character in front of it.
	line := `time=2026-08-17T00:00:00Z level=info msg="analysis finished" url=https://sonarqube.example.com/dashboard?id=my-project `
	token := "squ_0123456789abcdef0123456789abcdef01234567"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A prefix at every candidate, each of them one short of a body:
			// the scan reads thirty-nine hexadecimal characters and is turned
			// away by the character standing where the fortieth would.
			name:  "candidates that are not values",
			src:   strings.Repeat("squ_0123456789abcdef0123456789abcdef0123456.", 16),
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
