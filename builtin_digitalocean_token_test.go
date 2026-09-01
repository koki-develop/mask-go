package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The DigitalOcean token pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. A body is sixty-four lowercase hexadecimal
// characters, written here as 0123456789abcdef four times over, and with a
// seven character prefix in front of it that comes to seventy-one. Where a case
// turns on what a body may close on, its last character is written as a d
// instead.

func Test_DigitalOceanToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a personal access token",
			src:  "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 71}},
		},
		{
			name: "a personal access token in an environment assignment",
			src:  "DIGITALOCEAN_TOKEN=dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{19, 90}},
		},
		{
			name: "an oauth access token",
			src:  "doo_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 71}},
		},
		{
			name: "an oauth refresh token",
			src:  "dor_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 71}},
		},
		{
			// The count is read exactly, so what follows the seventy-first
			// character is not part of the token and stays in the text.
			name: "a run longer than the count is a token and what follows it",
			src:  "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
			want: []Span{{0, 71}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefdoo_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 71}, {71, 142}},
		},
		{
			// A candidate whose body opens with a prefix of its own. The outer
			// one is turned away at the second character of its body, which is
			// the o of the inner opening and no character a body is written
			// with; the inner token is found where it stands.
			name: "a candidate whose body opens with a prefix",
			src:  "dop_v1_dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{7, 78}},
		},
		{
			// The one shape a word boundary in front would turn away. No word
			// is spelled dop, doo or dor, so what can reach the prefix is a
			// snake_case name whose last segment is those three characters —
			// which the tightening on offer admits anyway, since it admits the
			// underscore.
			name: "a snake_case name closing on the opening and a kind",
			src:  "cloud_dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{6, 77}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DigitalOceanToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DigitalOceanToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "dop_v1_",
		},
		{
			name: "a body one character short",
			src:  "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// The body is read in lowercase alone, so the case an environment
			// variable's name is written in is no token however the body is.
			name: "an uppercase body",
			src:  "dop_v1_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "an uppercase prefix",
			src:  "DOP_V1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// A letter past f, which is what separates a body from the base62
			// and base64url runs the prefix could otherwise be found inside.
			name: "a letter past f in the body",
			src:  "dop_v1_0123456789abcdefg123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a body broken by a space",
			src:  "dop_v1_0123456789abcdef 123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a body broken by a line break",
			src:  "dop_v1_0123456789abcdef\n123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a hyphen inside the body",
			src:  "dop_v1_0123456789abcdef-123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "an underscore inside the body",
			src:  "dop_v1_0123456789abcdef_123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "hyphens where the version carries its underscores",
			src:  "dop-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The version is part of the prefix rather than a number the scan
			// reads, so the format that follows this one is a format somebody
			// adds a prefix for.
			name: "a version digitalocean has not written",
			src:  "dop_v2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "the version without the underscore that opens it",
			src:  "dopv1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
		},
		{
			// A body of the right count and the right class behind something
			// else. The prefix is the whole of the anchor.
			name: "a value of the right shape opening with no prefix",
			src:  "xxx_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// A line carrying the byte the scan searches for several times over,
			// none of them with an opening in front of it.
			name: "the anchor as it is written in prose",
			src:  "every version of every token this vendor issues carries a prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DigitalOceanToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DigitalOceanToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "DIGITALOCEAN_TOKEN=dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "DIGITALOCEAN_TOKEN=***********************************************************************",
		},
		{
			// How a token reaches the API, and how it reaches a log line that
			// echoed the header.
			name: "the bearer header",
			src:  "Authorization: Bearer dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "Authorization: Bearer ***********************************************************************",
		},
		{
			// The response the OAuth flow reads a token and its refresh token
			// out of, which is where two of the three kinds arrive together.
			name: "the response the oauth flow returns",
			src:  `{"access_token":"doo_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","refresh_token":"dor_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`,
			want: `{"access_token":"***********************************************************************","refresh_token":"***********************************************************************"}`,
		},
		{
			name: "the file doctl writes a token into",
			src:  "access-token: dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "access-token: ***********************************************************************",
		},
		{
			name: "a command line",
			src:  "curl -H 'Authorization: Bearer dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' https://api.digitalocean.com/v2/account",
			want: "curl -H 'Authorization: Bearer ***********************************************************************' https://api.digitalocean.com/v2/account",
		},
	}

	m := New(WithPatterns(DigitalOceanToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DigitalOceanToken_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the token through whole. The first two are what the
	// demand would cost.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "xdop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "x***********************************************************************",
		},
		{
			name: "underscore before",
			src:  "DIGITALOCEAN_TOKEN_dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "DIGITALOCEAN_TOKEN_***********************************************************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this token
			// rather than trim it; without one the seventy-one characters
			// DigitalOcean issued are redacted and the one written after them,
			// which is part of no credential, stays in the text.
			name: "a character of the body's class after",
			src:  "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
			want: "***********************************************************************0",
		},
	}

	m := New(WithPatterns(DigitalOceanToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DigitalOceanToken_leavesWhatFollowsAlone(t *testing.T) {
	// A token is seventy-one characters and no more, so what is written after
	// one stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the token is dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.",
			want: "the token is ***********************************************************************.",
		},
		{
			name: "quoted",
			src:  `"dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`,
			want: `"***********************************************************************"`,
		},
		{
			name: "dashed word",
			src:  "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef-suffix",
			want: "***********************************************************************-suffix",
		},
		{
			name: "underscored word",
			src:  "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef_tail",
			want: "***********************************************************************_tail",
		},
		{
			// A letter past f ends nothing here — the count has already ended
			// the token — so a word written straight against one comes through.
			name: "a word written against a token",
			src:  "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefsuffix",
			want: "***********************************************************************suffix",
		},
	}

	m := New(WithPatterns(DigitalOceanToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DigitalOceanToken_aTokenBeginningInsideAnother(t *testing.T) {
	// The claim builtin_digitalocean_token.go makes about advancing rather than
	// consuming the match, and the one position it leaves. The two letters a
	// prefix opens with cannot both fall inside a body, because the o is no
	// hexadecimal character; and no character of a prefix past its first is a d,
	// so no prefix can be found inside another prefix either. What is left is a
	// body closing on a d, with the o, the kind and the version written past the
	// end of the token that d belongs to.
	//
	// A scan consuming its match would resume past the first token and leave the
	// second in the output whole. The two spans overlap by that one character,
	// which a Masker resolves into one, so the redaction reaches from the first
	// character to the last.
	src := "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdedop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	want := []Span{{0, 71}, {70, 141}}

	if got, _ := DigitalOceanToken().Find(src); !slices.Equal(got, want) {
		t.Fatalf("Find(%q) = %v, want %v", src, got, want)
	}
	m := New(WithPatterns(DigitalOceanToken()))
	if got, want := m.Mask(src), strings.Repeat("*", len(src)); got != want {
		t.Errorf("Mask(%q) = %q, want %q", src, got, want)
	}
}

func Test_DigitalOceanToken_aWordEndingInAKind(t *testing.T) {
	// What declining the word boundary in front costs, which
	// builtin_digitalocean_token.go weighs. The kind naming an OAuth access
	// token closes voodoo and hoodoo, so such a word with a version segment and
	// sixty-four hexadecimal characters behind it is a candidate from its fourth
	// character on, and the boundary four of the five published rulesets ask for
	// would turn it away.
	//
	// It is redacted from that fourth character, leaving the three in front of it
	// in the text. On the other side of the trade is a token written straight
	// against a letter or an underscore, which the same demand would drop whole
	// rather than trim, and Test_DigitalOceanToken_nextToWordCharacters drives
	// that.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a word closing on the oauth kind",
			src:  "voodoo_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{3, 74}},
		},
		{
			name: "another word closing on it",
			src:  "hoodoo_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{3, 74}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DigitalOceanToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DigitalOceanToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision a prefix invites is a digest written behind it, and this
	// format pays it rather than ruling it out — more squarely than most, since
	// a SHA-256 is sixty-four lowercase hexadecimal characters and a body is
	// exactly that. So the prefix and a SHA-256 is a token with nothing left
	// over to tell the two apart, which is what builtin_digitalocean_token.go
	// weighs: a scan declining it would decline every token DigitalOcean issues.
	//
	// The digests shorter than the count are turned away by the count, and a
	// digest with no prefix in front of it holds nothing to be found at.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a sha-256 behind the prefix",
			src:  "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 71}},
		},
		{
			name: "a sha-1 behind the prefix",
			src:  "dop_v1_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "an md5 behind the prefix",
			src:  "dop_v1_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a sha-256 on its own",
			src:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DigitalOceanToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DigitalOceanToken_theTokenFormatItReplaced(t *testing.T) {
	// The token DigitalOcean issued before the prefixes arrived, which doctl
	// still accepts under legacyTokenLength: sixty-four characters with nothing
	// in front of them, lowercase hexadecimal in every value its own tests are
	// written from. That is a SHA-256's format exactly, so a pattern reading it
	// would redact every git object id, every digest in a lock file and every
	// cache key a caller passes through — the loose grammar this package
	// declines rather than the unlucky one.
	//
	// Such tokens were not revoked when the prefixes arrived, so what this
	// decision costs is a live credential left in the output whole. It is
	// written down here so that reading it is a change somebody argues for
	// rather than one somebody notices afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a legacy token on its own",
			src:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a legacy token in an environment assignment",
			src:  "DIGITALOCEAN_TOKEN=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DigitalOceanToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DigitalOceanToken_theShapeTheDocumentationPrints(t *testing.T) {
	// The two tokens the OAuth reference page prints are seventy-one characters
	// apiece, which is what makes them worth reading for the width, and both
	// carry EXAMPLE written over the front of the body. Those are uppercase
	// letters no hexadecimal string holds, so neither printed string is located
	// and neither was ever a value.
	//
	// A reader auditing this scan against that page meets both, so the shape is
	// pinned here rather than left for them to come across. The count is met and
	// the class is what turns it away.
	src := "dop_v1_EXAMPLE789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if len(src) != 71 {
		t.Fatalf("the case is %d characters, a token is 71", len(src))
	}
	if got, _ := DigitalOceanToken().Find(src); len(got) != 0 {
		t.Errorf("Find(%q) = %v, want no span", src, got)
	}
}

func Test_DigitalOceanToken_aKindDigitalOceanNamesNoPrefixFor(t *testing.T) {
	// GitHub's secret scanning partner list, which DigitalOcean joined when this
	// format shipped, names a DigitalOcean System Token beside the three kinds
	// the announcement lists. DigitalOcean documents no such credential and no
	// published ruleset reads one, so there is no prefix to write and nothing to
	// read behind it, and this scan locates none of the letters somebody might
	// guess at.
	//
	// The three cases below are the s such a token's name suggests and two
	// letters beside it, each written where a kind stands with a whole body
	// behind. Reading one is a one character change to isDigitalOceanTokenKind
	// on the day the format is published.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the letter the system token's name suggests",
			src:  "dos_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a letter of the body's own class",
			src:  "dob_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a letter nothing suggests",
			src:  "dox_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DigitalOceanToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DigitalOceanToken_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor, and what holds it linear is the count being a
	// count: a candidate reads at most seventy-one bytes and stops. These are the
	// inputs that would find it wrong here — a line that is nothing but prefixes,
	// a line that is nothing but tokens, and a single hexadecimal run as long as
	// the line, which is where a scan reading a run instead of a count would show
	// itself.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// whole body apiece and so hold a candidate every seventy-one bytes at their
	// densest. The crowding a line can actually carry, a candidate every seven,
	// stays here.
	sources := map[string]string{
		// A candidate every seven characters, each turned away at the second
		// character of its body, which is the o the next opening carries and no
		// character a body is written with.
		"a candidate every seven characters": strings.Repeat("dop_v1_", 300000),
		// The same crowding with a whole token at each candidate, so every one of
		// them reads sixty-four characters and reports a span.
		"a token every seventy-one characters": strings.Repeat("dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 30000),
		// A candidate walked to its last character before the body's class turns
		// it away, which is the most a rejected candidate can cost.
		"a candidate walked to its last character": strings.Repeat("dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg ", 30000),
		// One candidate whose body is the whole line. The count stops it at
		// sixty-four characters; a scan reading the run would read two mebibytes.
		"a hexadecimal run the length of the line": "dop_v1_" + strings.Repeat("a", 2000000),
		// The same run with no prefix in front of it, so no candidate is found in
		// it at all.
		"a hexadecimal run with no prefix": strings.Repeat("a", 2000000),
	}

	checkScanIsLinear(t, DigitalOceanToken(), sources)
}

func Test_digitalOceanTokenOpening(t *testing.T) {
	// What the scan needs of the opening, which nothing else here reports: an
	// opening nothing locates simply locates nothing, and the cases above would
	// go on passing for the opening that still works.
	//
	// Its second character is what caps how far a token reaches into another. It
	// is no character a body is written with, so the two letters cannot both
	// fall inside a body and the deepest a prefix can begin is the last
	// character of the body in front of it.
	// Test_DigitalOceanToken_aTokenBeginningInsideAnother drives that one
	// position. The first character is asked nothing here: it is hexadecimal, and
	// being so is exactly what leaves that one position rather than none.
	if len(digitalOceanTokenOpening) < 2 {
		t.Fatalf("the opening is %q, which is too short to bound anything", digitalOceanTokenOpening)
	}
	if c := digitalOceanTokenOpening[1]; isDigitalOceanTokenBodyByte(c) {
		t.Errorf("the opening %q carries %q at its second character, which a body is written with", digitalOceanTokenOpening, c)
	}

	// And what the version needs to be: a character no body holds at either end,
	// so that a run of the body's alphabet can never hold a prefix. That is not
	// what bounds this scan, but it is what a count relaxed to a floor would fall
	// back on.
	if len(digitalOceanTokenVersion) < 2 {
		t.Fatalf("the version is %q, which carries no separator at either end", digitalOceanTokenVersion)
	}
	if c := digitalOceanTokenVersion[0]; isDigitalOceanTokenBodyByte(c) {
		t.Errorf("the version %q opens with %q, which a body is written with", digitalOceanTokenVersion, c)
	}
	if c := digitalOceanTokenVersion[len(digitalOceanTokenVersion)-1]; isDigitalOceanTokenBodyByte(c) {
		t.Errorf("the version %q closes with %q, which a body is written with", digitalOceanTokenVersion, c)
	}
}

// Test_digitalOceanTokenAnchor holds every prefix the scan can match to carrying
// the byte the scan searches the input for at the index it reads a candidate
// back from. builtin_scan.go says why that is held here rather than left to the
// targets: a kind added to isDigitalOceanTokenKind whose prefix carried the
// anchor somewhere else would be located nowhere, and nothing that was passing
// would stop passing.
func Test_digitalOceanTokenAnchor(t *testing.T) {
	if len(digitalOceanTokenPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for _, p := range digitalOceanTokenPrefixes {
		if digitalOceanTokenAnchorIndex >= len(p) {
			t.Errorf("the anchor stands at %d, the prefix %q is %d characters", digitalOceanTokenAnchorIndex, p, len(p))
			continue
		}
		if c := p[digitalOceanTokenAnchorIndex]; c != digitalOceanTokenAnchor {
			t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", p, c, byte(digitalOceanTokenAnchor))
		}
	}
}

// Test_digitalOceanTokenChars holds the arithmetic to the two numbers
// DigitalOcean's own code states: the seventy-one characters doctl accepts, and
// the seven a prefix comes to, whose difference is the body.
//
// What it holds is the documentation rather than the scan. The scan never states
// a whole token: it reads the body from where the prefix ends, so a prefix of
// another length would be located correctly and nothing would go wrong. What
// would go wrong is the sentence on DigitalOceanToken promising seventy-one
// characters, and the spans every case in this file is written with.
func Test_digitalOceanTokenChars(t *testing.T) {
	const (
		documentedPrefixChars = 7
		documentedChars       = 71
	)

	if digitalOceanTokenPrefixChars != documentedPrefixChars {
		t.Errorf("a prefix is read as %d characters, the documentation promises %d", digitalOceanTokenPrefixChars, documentedPrefixChars)
	}
	if digitalOceanTokenChars != documentedChars {
		t.Errorf("a token is read as %d characters, the documentation promises %d", digitalOceanTokenChars, documentedChars)
	}
	for _, p := range digitalOceanTokenPrefixes {
		if len(p) != documentedPrefixChars {
			t.Errorf("the prefix %q is %d characters, the documentation promises %d", p, len(p), documentedPrefixChars)
		}
	}
}

// referenceDigitalOceanToken is the expression the scan in
// builtin_digitalocean_token.go reads by hand: the statement of what a
// DigitalOcean token is, kept here so that the scan can be held to it.
//
// The opening, the three kinds, the version, the count and the character class
// are spelled again rather than built from the declarations beside the scan. A
// reference sharing those could not disagree with the scan about them, and it is
// exactly that disagreement the fuzz target below is for: the two have to be
// changed together or reported apart.
//
// The repetition is exact, so the machine an engine builds for a candidate is
// sixty-four states wide and is read once, where a floor spelled as a counted
// repetition would cost a machine as wide as the floor at every candidate. What
// an engine searches the text for is the two character literal the expression
// opens with, and its second character is written in no body — so a run of the
// body's alphabet, which is where candidates would otherwise crowd, holds no
// position for the engine to walk its machine at.
var referenceDigitalOceanToken = regexp.MustCompile(`do[por]_v1_[0-9a-f]{64}`)

// referenceDigitalOceanTokenFind locates tokens the plain way: the leftmost
// match of the expression above, then the leftmost one beginning after that
// match's first byte, over and over, with nothing remembered between them.
//
// Asking at every byte is what the scan does too, and it is not written here to
// restate that. A reference is written to know nothing its scan claims, and
// where a token may begin is one of the things the scan claims — so this one
// starts afresh a byte along whether or not a token can be written inside
// another, and the fuzz target below is what holds the two to the same answer.
func referenceDigitalOceanTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceDigitalOceanToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzDigitalOceanToken_matchesReference guards the hand-written scan: the byte
// it searches for, the opening and the kinds it reads back from that byte, the
// version behind them, the count it reads and the character class it reads it in
// may none of them change which tokens are located.
func FuzzDigitalOceanToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("DIGITALOCEAN_TOKEN=dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("doo_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")             // the oauth kinds
	f.Add("dor_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")             //
	f.Add("dos_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")             // a kind with no prefix published
	f.Add("dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")              // a body one short
	f.Add("dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0")            // and a run longer than one
	f.Add("dop_v1_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")             // an uppercase body
	f.Add("DOP_V1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")             // an uppercase prefix
	f.Add("dop_v1_0123456789abcdefg123456789abcdef0123456789abcdef0123456789abcdef")             // a letter past f
	f.Add("dop_v1_0123456789abcdef-123456789abcdef0123456789abcdef0123456789abcdef")             // a hyphen inside the body
	f.Add("dop_v1_0123456789abcdef_123456789abcdef0123456789abcdef0123456789abcdef")             // and an underscore
	f.Add("dop_v1_0123456789abcdef\n123456789abcdef0123456789abcdef0123456789abcdef")            // a token a line break breaks
	f.Add("dop-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")             // hyphens where the underscores stand
	f.Add("dop_v2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")             // a version nobody writes
	f.Add("dopv1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0")             // the version without its opening
	f.Add("xxx_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")             // the right shape with no prefix
	f.Add("xdop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")            // written against a letter
	f.Add("cloud_dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")       // and against a name
	f.Add("dop_v1_EXAMPLE789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")             // the shape the documentation prints
	f.Add("dop_v1_0123456789abcdef0123456789abcdef01234567")                                     // a sha-1 behind the prefix
	f.Add("dop_v1_0123456789abcdef0123456789abcdef")                                             // an md5
	f.Add("DIGITALOCEAN_TOKEN=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") // the format this one replaced
	f.Add("dop_v1_dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")      // a prefix where a body could hold one
	f.Add("voodoo_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")          // a word closing on a kind
	// A token beginning inside another, which is what advancing rather than
	// consuming the match has to find, and two written with nothing between them.
	f.Add("dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdedop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefdoo_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// Candidate positions crowded as close as they can be, and a hexadecimal run
	// with no prefix in front of it.
	f.Add(strings.Repeat("dop_v1_", 32))
	f.Add(strings.Repeat("dop_v1_", 32) + strings.Repeat("0123456789abcdef", 4))
	f.Add(strings.Repeat("0123456789abcdef", 16))

	fuzzAgainstReference(f, DigitalOceanToken().Find, referenceDigitalOceanTokenFind)
}

// digitalOceanTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func digitalOceanTokenFindBenchmarks() []benchmarkCase {
	// The line carries the byte the scan searches for twice, once in a word of
	// the message and once in the version segment of the vendor's own API path,
	// and neither opens a candidate. What it times is that search and the two
	// reads that turn those positions away, which is what this pattern costs a
	// caller whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.digitalocean.com/v2/account `
	token := "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix written over and over, so a candidate stands at every
			// seventh byte and every one of them is turned away at the second
			// character of its body, which is the o of the next opening. That is
			// the cheapest this scan declines a candidate whose prefix is whole.
			name:  "candidates that are not values",
			src:   strings.Repeat("dop_v1_", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: sixty-three characters of the body
			// walked before its last one turns the candidate away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg ", 16),
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
