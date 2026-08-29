package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Dynatrace token pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a set
// of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. Both portions are written in uppercase letters and
// digits, so the run 0123456789ABCDEF serves for both — once and a half over for
// the twenty-four of the public identifier, four times over for the sixty-four
// of the secret — and with the six character prefix and the two full stops in
// front that comes to ninety-six.

func Test_DynatraceToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an api token",
			src:  "dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 96}},
		},
		{
			name: "an api token in an environment assignment",
			src:  "DT_API_TOKEN=dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{13, 109}},
		},
		{
			// The prefix Dynatrace's account pages print, which authorizes
			// changes to an account over SCIM.
			name: "an account api token",
			src:  "dt0s01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 96}},
		},
		{
			// The prefix a platform token carries, the last entry of the table
			// Dynatrace publishes.
			name: "a platform token",
			src:  "dt0s16.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 96}},
		},
		{
			// What reading the letter and the digits rather than a table of
			// prefixes buys, and what it costs. The prefix Dynatrace's OAuth
			// page prints stands nowhere in the table its token page keeps, and
			// is located here; so is a prefix nobody has published, which is the
			// same wager the vendor's own expression makes.
			name: "a prefix the published table does not list",
			src:  "dt0s17.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 96}},
		},
		{
			name: "a prefix dynatrace has not published at all",
			src:  "dt0x99.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 96}},
		},
		{
			// The vendor's expression admits the letter in either case, where
			// every prefix it prints is lowercase.
			name: "an uppercase letter naming the type",
			src:  "dt0C01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 96}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEFdt0s16.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 96}, {96, 192}},
		},
		{
			// A candidate whose public portion opens with a prefix of its own.
			// The outer one is turned away where its separator would stand, and
			// the inner token is found where it is written.
			name: "a candidate whose public portion opens with a prefix",
			src:  "dt0c01.dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{7, 103}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DynatraceToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DynatraceToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "dt0c01.",
		},
		{
			name: "a public portion one character short",
			src:  "dt0c01.0123456789ABCDEF0123456.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "a public portion one character long",
			src:  "dt0c01.0123456789ABCDEF012345678.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "a secret one character short",
			src:  "dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDE",
		},
		{
			// Both portions are read in uppercase alone, which is the class the
			// vendor's own expression spells for each of them.
			name: "a lowercase public portion",
			src:  "dt0c01.0123456789abcdef01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "a lowercase secret",
			src:  "dt0c01.0123456789ABCDEF01234567.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "an uppercase opening",
			src:  "DT0C01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "a letter where the type carries a digit",
			src:  "dt0cX1.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "a digit where the type carries its letter",
			src:  "dt0101.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "a digit other than the one the opening ends on",
			src:  "dt1c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "hyphens where the separators stand",
			src:  "dt0c01-0123456789ABCDEF01234567-0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "the separator between the portions missing",
			src:  "dt0c01.0123456789ABCDEF012345670123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0",
		},
		{
			name: "a secret broken by a space",
			src:  "dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF 123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "a secret broken by a line break",
			src:  "dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF\n123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "a hyphen inside the public portion",
			src:  "dt0c01.0123456789ABCDEF-1234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			// A body of the right counts and the right class behind something
			// else. The prefix is the whole of the anchor.
			name: "a value of the right shape opening with no prefix",
			src:  "xx0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// A line carrying the byte the scan searches for several times over,
			// none of them with an opening behind it.
			name: "the anchor as it is written in prose",
			src:  "the documented decision to redact the credentials a dashboard displays",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DynatraceToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DynatraceToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "DT_API_TOKEN=dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: "DT_API_TOKEN=************************************************************************************************",
		},
		{
			// How a token reaches the API, and how it reaches a log line that
			// echoed the header.
			name: "the header a request carries it in",
			src:  "Authorization: Api-Token dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: "Authorization: Api-Token ************************************************************************************************",
		},
		{
			name: "a command line",
			src:  "curl -H 'Authorization: Api-Token dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF' https://abc12345.live.dynatrace.com/api/v2/metrics",
			want: "curl -H 'Authorization: Api-Token ************************************************************************************************' https://abc12345.live.dynatrace.com/api/v2/metrics",
		},
		{
			// The two tokens an operator's chart is configured with, which is
			// where two of them arrive together.
			name: "the values a deployment is configured with",
			src:  "  apiToken: dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF\n  paasToken: dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: "  apiToken: ************************************************************************************************\n  paasToken: ************************************************************************************************",
		},
		{
			name: "a json body",
			src:  `{"token":"dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"}`,
			want: `{"token":"************************************************************************************************"}`,
		},
	}

	m := New(WithPatterns(DynatraceToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DynatraceToken_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the token through whole. The first two are what the
	// demand would cost, and both noseyparker and kingfisher ask for it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "xdt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: "x************************************************************************************************",
		},
		{
			name: "underscore before",
			src:  "DT_API_TOKEN_dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: "DT_API_TOKEN_************************************************************************************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this token
			// rather than trim it; without one the ninety-six characters
			// Dynatrace issued are redacted and the one written after them,
			// which is part of no credential, stays in the text.
			name: "a character of the secret's class after",
			src:  "dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0",
			want: "************************************************************************************************0",
		},
	}

	m := New(WithPatterns(DynatraceToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DynatraceToken_leavesWhatFollowsAlone(t *testing.T) {
	// A token is ninety-six characters and no more, so what is written after one
	// stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the token is dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF.",
			want: "the token is ************************************************************************************************.",
		},
		{
			name: "quoted",
			src:  `"dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"`,
			want: `"************************************************************************************************"`,
		},
		{
			name: "dashed word",
			src:  "dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF-suffix",
			want: "************************************************************************************************-suffix",
		},
		{
			// A lowercase letter ends nothing here — the count has already
			// ended the token — so a word written straight against one comes
			// through.
			name: "a word written against a token",
			src:  "dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEFsuffix",
			want: "************************************************************************************************suffix",
		},
	}

	m := New(WithPatterns(DynatraceToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DynatraceToken_noTokenBeginsInsideAnother(t *testing.T) {
	// The claim builtin_dynatrace_token.go makes: the spans of this pattern
	// never overlap one another. Everything a span covers past the prefix is an
	// uppercase letter, a digit or a full stop, and the two letters an opening
	// starts with are lowercase, so no position inside a body opens a candidate;
	// inside a prefix the letter naming the type could be a d, but a digit
	// stands where the t would have to.
	//
	// It is not a claim one input can state, so a whole token is written into
	// every position of another here — at each character of its prefix, at each
	// character of either portion and against either end — with nothing, a
	// secret and a second token behind it in turn. What is asserted is only that
	// no two spans overlap; where the tokens fall is what the table at the top
	// of this file is for.
	secret := "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	token := "dt0c01.0123456789ABCDEF01234567." + secret
	p := DynatraceToken()

	for i := range len(token) + 1 {
		for _, tail := range []string{"", secret, token} {
			src := token[:i] + token + token[i:] + tail
			spans, _ := p.Find(src)
			for j, got := range spans {
				if j > 0 && got.Start < spans[j-1].End {
					t.Errorf("Find(%q) = %v, which holds two values overlapping", src, spans)
					break
				}
			}
		}
	}
}

func Test_DynatraceToken_theTokenIdentifierIsNoValue(t *testing.T) {
	// Dynatrace names the prefix and the public portion together the token
	// identifier, and states that it can be safely displayed in the UI and used
	// for logging purposes. So a caller keeping a log by one is keeping it by
	// something the vendor published for that purpose, and redacting it would
	// take away the one part of a token they are meant to have.
	//
	// What the scan asks for past the identifier is the separator and the
	// sixty-four characters of the secret, so an identifier standing on its own
	// — however it is written, and whatever is written after it that is not a
	// secret — is located nowhere.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "an identifier on its own",
			src:  "dt0c01.0123456789ABCDEF01234567",
		},
		{
			name: "an identifier in a log line",
			src:  "time=2026-08-17T00:00:00Z level=info msg=\"token used\" token=dt0c01.0123456789ABCDEF01234567",
		},
		{
			name: "an identifier with the separator behind it and no secret",
			src:  "dt0c01.0123456789ABCDEF01234567.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DynatraceToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DynatraceToken_aPublicPortionShorterThanTheCount(t *testing.T) {
	// The one credential of this vendor's that reading the vendor's own count
	// leaves in the output, which builtin_dynatrace_token.go weighs. Dynatrace
	// prints an OAuth client identifier as dt0s17.ABCDE123, whose public portion
	// is eight characters rather than twenty-four, and kingfisher reads a three
	// part credential built on one by relaxing that count to a range of eight to
	// a hundred and twenty-eight.
	//
	// Neither bound of that range is a number Dynatrace states anywhere, where
	// the twenty-four the scan reads is one it writes in prose and again in the
	// expression it publishes. The decision is written down here so that reading
	// the client secret is a change somebody argues for rather than one somebody
	// notices afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a client secret whose public portion is eight characters",
			src:  "dt0s02.0123ABCD.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "the client identifier the oauth page prints",
			src:  "client_id=dt0s17.0123ABCD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DynatraceToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DynatraceToken_theTokenFormatItReplaced(t *testing.T) {
	// Dynatrace enabled this format by default in version 1.210 and states that
	// all existing tokens of the old format remain valid, so tokens of that
	// format are live credentials. What it does not state anywhere is their
	// shape: no prefix to search for and no count to read, which leaves nothing
	// to write a pattern from but a guess at a length over an alphabet — the
	// loose grammar this package declines rather than the unlucky one.
	//
	// The inputs below therefore stand for the class rather than for anything
	// published: a value carrying no prefix at all, written where a token is
	// written. Nothing is located in either.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a value with no prefix in an environment assignment",
			src:  "DT_API_TOKEN=0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "a value with no prefix in the header a request carries it in",
			src:  "Authorization: Api-Token 0123456789ABCDEF0123456789ABCDEF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DynatraceToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DynatraceToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision every prefix in this package leaves is a digest written
	// behind it, and this format rules it out twice over rather than paying for
	// it. A digest carries no full stop, so the prefix and the sixty-four
	// characters of a SHA-256 hold nothing at the twenty-fifth character but
	// more of the digest; and a digest is written in lowercase hexadecimal,
	// where both portions here are uppercase.
	//
	// The second case is that digest upper-cased, which is turned away by the
	// separator alone, and the third is a digest with no prefix in front of it,
	// which holds nothing to be found at.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a sha-256 behind the prefix",
			src:  "dt0c01.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "an uppercase sha-256 behind the prefix",
			src:  "dt0c01.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "a sha-256 on its own",
			src:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DynatraceToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DynatraceToken_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor, and what holds it linear is the counts being
	// counts: a candidate reads at most ninety-six bytes and stops. These are the
	// inputs that would find it wrong here — a line that is nothing but openings,
	// a line that is nothing but tokens, and a single uppercase run as long as
	// the line, which is where a scan reading a run instead of a count would show
	// itself.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// whole token apiece and so hold a candidate every ninety-six bytes at their
	// densest. The crowding a line can actually carry, a candidate every seven,
	// stays here.
	sources := map[string]string{
		// A candidate every seven characters, each turned away where its
		// separator would stand, which is the cheapest this scan declines a
		// candidate whose opening is whole.
		"a candidate every seven characters": strings.Repeat("dt0c01.", 300000),
		// The same crowding with a whole token at each candidate, so every one of
		// them reads eighty-nine characters and reports a span.
		"a token every ninety-six characters": strings.Repeat("dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", 20000),
		// A candidate walked to its last character before the secret's class
		// turns it away, which is the most a rejected candidate can cost.
		"a candidate walked to its last character": strings.Repeat("dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEz ", 20000),
		// One candidate whose portions are the whole line. The counts stop it at
		// eighty-nine characters; a scan reading the run would read two mebibytes.
		"an uppercase run the length of the line": "dt0c01." + strings.Repeat("A", 2000000),
		// The same run with no opening in front of it, so no candidate is found
		// in it at all.
		"an uppercase run with no opening": strings.Repeat("A", 2000000),
	}

	checkScanIsLinear(t, DynatraceToken(), sources)
}

func Test_dynatraceTokenOpening(t *testing.T) {
	// What the scan needs of the opening, which nothing else here reports: an
	// opening nothing locates simply locates nothing, and the cases above would
	// go on passing for the opening that still works.
	//
	// Its first character is what caps how far a token reaches into another. It
	// is written in neither portion's alphabet, so no candidate can open inside
	// the body of a token and the spans of this pattern never overlap.
	// Test_DynatraceToken_noTokenBeginsInsideAnother drives that.
	if len(dynatraceTokenOpening) == 0 {
		t.Fatal("the opening is empty, so every byte of the input opens a candidate")
	}
	if c := dynatraceTokenOpening[0]; isDynatraceTokenByte(c) {
		t.Errorf("the opening %q begins with %q, which a portion is written with", dynatraceTokenOpening, c)
	}

	// And what the separator needs to be: a character neither portion holds, so
	// that a run of that alphabet can never hold one and the counts either side
	// of it are readable at all.
	if isDynatraceTokenByte(dynatraceTokenSeparator) {
		t.Errorf("the separator %q is a character a portion is written with", byte(dynatraceTokenSeparator))
	}
}

// Test_dynatraceTokenAnchor holds the byte the scan searches the input for to
// being the one byte an opening may begin with, so that stepping through the
// anchors reaches every candidate there is.
//
// builtin_scan.go says why that is held here rather than left to the targets: an
// opening widened at its first character — a second vendor prefix admitted, a
// case relaxed — would be located nowhere, and nothing that was passing would
// stop passing.
func Test_dynatraceTokenAnchor(t *testing.T) {
	if !dynatraceTokenOpeningByteAt(0, dynatraceTokenAnchor) {
		t.Fatalf("no opening begins with %q, where the scan searches for it", byte(dynatraceTokenAnchor))
	}
	for c := range 256 {
		if byte(c) == dynatraceTokenAnchor {
			continue
		}
		if dynatraceTokenOpeningByteAt(0, byte(c)) {
			t.Errorf("an opening may begin with %q, which the scan never stops at", byte(c))
		}
	}
}

// Test_dynatraceTokenChars holds the arithmetic to the numbers Dynatrace's own
// token page states: the twenty-four characters of the public identifier, the
// sixty-four of the secret, and the six a prefix comes to in every prefix that
// page prints.
//
// What it holds is the documentation rather than the scan. The scan never states
// a whole token twice: it reads each portion from where the one in front of it
// ended, so counts of other sizes would be located correctly and nothing would
// go wrong. What would go wrong is the sentence on DynatraceToken promising
// ninety-six characters, and the spans every case in this file is written with.
func Test_dynatraceTokenChars(t *testing.T) {
	const (
		documentedPrefixChars = 6
		documentedPublicChars = 24
		documentedSecretChars = 64
		documentedChars       = 96
	)

	if dynatraceTokenPrefixChars != documentedPrefixChars {
		t.Errorf("a prefix is read as %d characters, the documentation prints %d", dynatraceTokenPrefixChars, documentedPrefixChars)
	}
	if dynatraceTokenPublicChars != documentedPublicChars {
		t.Errorf("a public portion is read as %d characters, the documentation states %d", dynatraceTokenPublicChars, documentedPublicChars)
	}
	if dynatraceTokenSecretChars != documentedSecretChars {
		t.Errorf("a secret is read as %d characters, the documentation states %d", dynatraceTokenSecretChars, documentedSecretChars)
	}
	if dynatraceTokenChars != documentedChars {
		t.Errorf("a token is read as %d characters, which the three above come to as %d", dynatraceTokenChars, documentedChars)
	}
}

// referenceDynatraceToken is the expression the scan in
// builtin_dynatrace_token.go reads by hand: the statement of what a Dynatrace
// token is, kept here so that the scan can be held to it.
//
// It is the expression Dynatrace publishes to look for tokens with, and it is
// spelled out again rather than built from the declarations beside the scan. A
// reference sharing those could not disagree with the scan about them, and it is
// exactly that disagreement the fuzz target below is for: the two have to be
// changed together or reported apart.
//
// Both repetitions are exact, so the machine an engine builds for a candidate is
// read once and stops, where a floor spelled as a counted repetition would cost
// a machine as wide as the floor at every candidate. What an engine searches the
// text for is the three character literal the expression opens with, whose
// letters are written in neither portion — so a run of the portions' alphabet,
// which is where candidates would otherwise crowd, holds no position for the
// engine to walk its machine at.
var referenceDynatraceToken = regexp.MustCompile(`dt0[a-zA-Z][0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}`)

// referenceDynatraceTokenFind locates tokens the plain way: the leftmost match
// of the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// Asking at every byte is what the scan does too, and it is not written here to
// restate that. A reference is written to know nothing its scan claims, and that
// no token begins inside another is one of the things the scan claims — so this
// one starts afresh a byte along regardless, and the fuzz target below is what
// holds the two to the same answer.
func referenceDynatraceTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceDynatraceToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzDynatraceToken_matchesReference guards the hand-written scan: the byte it
// searches for, the opening it reads back from that byte, the letter and digits
// naming the type, the two separators, the counts it reads and the character
// class it reads them in may none of them change which tokens are located.
func FuzzDynatraceToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("DT_API_TOKEN=dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
	f.Add("dt0s01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")  // the account api token
	f.Add("dt0s16.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")  // the platform token
	f.Add("dt0s17.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")  // a prefix the published table leaves out
	f.Add("dt0x99.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")  // one nobody publishes at all
	f.Add("dt0C01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")  // an uppercase letter naming the type
	f.Add("dt0101.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")  // a digit where that letter belongs
	f.Add("dt0cX1.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")  // a letter where a digit belongs
	f.Add("DT0C01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")  // an uppercase opening
	f.Add("dt0c01.0123456789ABCDEF0123456.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")   // a public portion one short
	f.Add("dt0c01.0123456789ABCDEF012345678.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF") // and one long
	f.Add("dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDE")   // a secret one short
	f.Add("dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0") // and a run longer than one
	f.Add("dt0c01.0123456789abcdef01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")  // a lowercase public portion
	f.Add("dt0c01.0123456789ABCDEF01234567.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")  // a lowercase secret
	f.Add("dt0c01-0123456789ABCDEF01234567-0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")  // hyphens where the separators stand
	f.Add("dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF\n123456789ABCDEF0123456789ABCDEF0123456789ABCDEF") // a token a line break breaks
	f.Add("xx0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")  // the right shape with no opening
	f.Add("xdt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF") // written against a letter
	f.Add("dt0c01.0123456789ABCDEF01234567")                                                                   // the token identifier alone
	f.Add("dt0s02.0123ABCD.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")                  // an oauth client secret
	f.Add("dt0c01.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")                           // a sha-256 behind the prefix
	f.Add("DT_API_TOKEN=0123456789ABCDEF0123456789ABCDEF")                                                     // a value with no prefix
	// A prefix written where a portion would stand, and two tokens with nothing
	// between them, which is what advancing rather than consuming the match has
	// to find.
	f.Add("dt0c01.dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
	f.Add("dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEFdt0s16.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
	// Candidate positions crowded as close as they can be, and an uppercase run
	// with no opening in front of it.
	f.Add(strings.Repeat("dt0c01.", 32))
	f.Add(strings.Repeat("dt0c01.", 32) + strings.Repeat("0123456789ABCDEF", 4))
	f.Add(strings.Repeat("0123456789ABCDEF", 16))

	fuzzAgainstReference(f, DynatraceToken().Find, referenceDynatraceTokenFind)
}

// dynatraceTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func dynatraceTokenFindBenchmarks() []benchmarkCase {
	// The line carries the byte the scan searches for once, in the vendor's own
	// host name, and it opens no candidate. It carries three full stops, five
	// t's and eight 0's, which are the other three bytes standing at a fixed
	// index of every opening — the count that made the d the byte to search for.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://abc12345.live.dynatrace.com/api/v2/metrics `
	token := "dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The opening written over and over, so a candidate stands at every
			// seventh byte and every one of them is turned away where its
			// separator would stand. That is the cheapest this scan declines a
			// candidate whose opening is whole.
			name:  "candidates that are not values",
			src:   strings.Repeat("dt0c01.", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: eighty-eight characters of the
			// body walked before its last one turns the candidate away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("dt0c01.0123456789ABCDEF01234567.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEz ", 16),
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
