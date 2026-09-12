package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Axiom API token pattern: what it locates and what it leaves alone, written
// out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a set
// of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. The run they are built from is 0123456789abcdef
// carried round again, laid into the groups of a UUID as
// 01234567-89ab-cdef-0123-456789abcdef. Where a case is about the ends of the
// alphabet or about a character the body excludes, the character at that
// position is the only one that moves. The cases of
// Test_AxiomAPIToken_anyVersionAndVariant part from the run at the two positions
// a UUID writes its version and its variant, which a run of ordered characters
// cannot state.

func Test_AxiomAPIToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// The run opens on the first digit and closes on the last lowercase
			// letter of the alphabet, so this case carries both ends of hexadecimal
			// at the ends of a body already.
			name: "a token on its own",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcdef",
			want: []Span{{0, 41}},
		},
		{
			name: "a token in an environment assignment",
			src:  "AXIOM_TOKEN=xaat-01234567-89ab-cdef-0123-456789abcdef",
			want: []Span{{12, 53}},
		},
		{
			// Hexadecimal is read in either case, and every other case in this file
			// writes its body in lowercase alone.
			name: "a body written in capitals",
			src:  "xaat-01234567-89AB-CDEF-0123-456789ABCDEF",
			want: []Span{{0, 41}},
		},
		{
			name: "a body written in both cases at once",
			src:  "xaat-01234567-89Ab-cDeF-0123-456789abcdef",
			want: []Span{{0, 41}},
		},
		{
			// The alphabet at the top of its lowercase range, at the first
			// character of a body.
			name: "a body opening on the last lowercase letter of the alphabet",
			src:  "xaat-f1234567-89ab-cdef-0123-456789abcdef",
			want: []Span{{0, 41}},
		},
		{
			// The capitals at both ends at once: A is the first of them and F the
			// last hexadecimal admits.
			name: "a body opening on the first capital and closing on the last",
			src:  "xaat-A1234567-89ab-cdef-0123-456789abcdeF",
			want: []Span{{0, 41}},
		},
		{
			name: "a body opening on the last capital hexadecimal admits",
			src:  "xaat-F1234567-89ab-cdef-0123-456789abcdef",
			want: []Span{{0, 41}},
		},
		{
			// The first of the lowercase letters at one end and the first of the
			// capitals at the other, which are the two ends no other case here
			// writes.
			name: "a body opening on the first lowercase letter and closing on the first capital",
			src:  "xaat-a1234567-89ab-cdef-0123-456789abcdeA",
			want: []Span{{0, 41}},
		},
		{
			// The digits are the bottom of the alphabet: 0 is the first of them and
			// 9 the last.
			name: "a body opening on the last digit and closing on the first lowercase letter",
			src:  "xaat-91234567-89ab-cdef-0123-456789abcdea",
			want: []Span{{0, 41}},
		},
		{
			name: "a body closing on the first digit",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcde0",
			want: []Span{{0, 41}},
		},
		{
			name: "a body closing on the last digit",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcde9",
			want: []Span{{0, 41}},
		},
		{
			// The thirty-six behind the prefix are a layout and not a floor: what
			// follows the forty-first character is not part of the token and stays
			// in the text.
			name: "a hexadecimal run longer than a body is a token and what follows it",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcdef0",
			want: []Span{{0, 41}},
		},
		{
			// The prefix written twice opens a candidate at the first, whose body
			// carries the x of the second and so is no body; the token stands five
			// characters along, inside the forty-one bytes that candidate reached
			// over. Test_AxiomAPIToken_aTokenInsideARejectedCandidate states what a
			// scan consuming its candidate would lose here.
			name: "a token inside a candidate the body turned away",
			src:  "xaat-xaat-01234567-89ab-cdef-0123-456789abcdef",
			want: []Span{{5, 46}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcdefxaat-01234567-89AB-CDEF-0123-456789ABCDEF",
			want: []Span{{0, 41}, {41, 82}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AxiomAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AxiomAPIToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "xaat-",
		},
		{
			// Thirty-five characters where the layout asks for thirty-six. The
			// input ends there, so what declines this is the scan cutting by a
			// count it cannot reach rather than anything the body walk read: the
			// case below is the same body with the walk let run.
			name: "body one character too short at the end of the input",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcde",
		},
		{
			// The same body with text behind it, which puts the shortfall on the
			// other side of the scan's length guard. The case above ends inside
			// the candidate, so it is declined without a byte of the body being
			// read; here the forty-one characters are all there to read, and
			// what turns the candidate away is the layout finding a space where
			// a group belongs. The guard and the walk are two rejections, and a
			// body one character short meets whichever the text hands it.
			name: "body one character too short with text behind it",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcde tail",
		},
		{
			// The layout rather than the count: thirty-six characters of
			// hexadecimal and separators, with a separator missing from the front
			// of the body and a digit made up at the back.
			name: "a separator missing from the body",
			src:  "xaat-0123456789ab-cdef-0123-456789abcdef0",
		},
		{
			// A hexadecimal digit standing where each of the separators belongs,
			// the body still thirty-six characters and every one of them in the
			// alphabet. The layout alone declines these, so a walk that stopped
			// reading it at any one separator would locate a token here.
			name: "a hexadecimal digit where the first separator stands",
			src:  "xaat-01234567089ab-cdef-0123-456789abcdef",
		},
		{
			name: "a hexadecimal digit where the second separator stands",
			src:  "xaat-01234567-89ab0cdef-0123-456789abcdef",
		},
		{
			name: "a hexadecimal digit where the third separator stands",
			src:  "xaat-01234567-89ab-cdef00123-456789abcdef",
		},
		{
			name: "a hexadecimal digit where the fourth separator stands",
			src:  "xaat-01234567-89ab-cdef-01230456789abcdef",
		},
		{
			name: "a separator where the body carries a hexadecimal digit",
			src:  "xaat--1234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "a separator at the last character of the body",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcde-",
		},
		{
			name: "a separator too many in the body",
			src:  "xaat-0123456--89ab-cdef-0123-456789abcdef",
		},
		{
			// The six characters standing immediately outside the three ranges
			// hexadecimal is made of, each written where a body opens. / and :
			// fence the digits, @ and G the capitals, ` and g the lowercase
			// letters.
			name: "the character below the digits where the body opens",
			src:  "xaat-/1234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "the character above the digits where the body opens",
			src:  "xaat-:1234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "the character below the capitals where the body opens",
			src:  "xaat-@1234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "the character above the capitals where the body opens",
			src:  "xaat-G1234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "the character below the lowercase letters where the body opens",
			src:  "xaat-`1234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "the character above the lowercase letters where the body opens",
			src:  "xaat-g1234567-89ab-cdef-0123-456789abcdef",
		},
		{
			// The same six at the other end of a body.
			name: "the character below the digits where the body closes",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcde/",
		},
		{
			name: "the character above the digits where the body closes",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcde:",
		},
		{
			name: "the character below the capitals where the body closes",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcde@",
		},
		{
			name: "the character above the capitals where the body closes",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcdeG",
		},
		{
			name: "the character below the lowercase letters where the body closes",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcde`",
		},
		{
			name: "the character above the lowercase letters where the body closes",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcdeg",
		},
		{
			// And inside each of the groups the twelve cases above do not reach,
			// where the same rejection has to hold. The groups are walked rather
			// than their widths added up, so a group left unread would decline
			// nothing written in it — and a group read at one end alone would
			// decline nothing written in the middle of it, which is what the
			// first and the last of these are for: those two are the wide groups,
			// and the cases above reach each of them at one end only.
			name: "a character outside the alphabet inside the first group",
			src:  "xaat-0123z567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "a character outside the alphabet in the second group",
			src:  "xaat-01234567-89zb-cdef-0123-456789abcdef",
		},
		{
			name: "a character outside the alphabet in the third group",
			src:  "xaat-01234567-89ab-cdgf-0123-456789abcdef",
		},
		{
			name: "a character outside the alphabet in the fourth group",
			src:  "xaat-01234567-89ab-cdef-01z3-456789abcdef",
		},
		{
			name: "a character outside the alphabet inside the fifth group",
			src:  "xaat-01234567-89ab-cdef-0123-4567z9abcdef",
		},
		{
			name: "an underscore in the body",
			src:  "xaat-01234567-89ab_cdef-0123-456789abcdef",
		},
		{
			name: "a body broken by a space",
			src:  "xaat-01234567-89ab-cdef-0123 456789abcdef",
		},
		{
			name: "a body broken by a line break",
			src:  "xaat-01234567-89ab-cdef-0123\n456789abcdef",
		},
		{
			name: "an uppercase prefix",
			src:  "XAAT-01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			// One letter of the prefix in the other case, rather than the whole of
			// it.
			name: "the prefix with its first letter capitalized",
			src:  "Xaat-01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "an underscore where the prefix carries its hyphen",
			src:  "xaat_01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "the prefix without the hyphen that closes it",
			src:  "xaat01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			// A run of the right shape that opens with something else. The prefix
			// is the whole of the anchor, so a UUID is not a token without it.
			name: "a run of the right length opening with no prefix",
			src:  "xxxx-01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// Forty hexadecimal characters. A digest carries no separator, so it
			// answers the layout nowhere however long it runs.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
		{
			// The separators of a timestamp stand at their own places rather than
			// at a UUID's, and there is no prefix in front of them either way.
			name: "an iso timestamp",
			src:  "2026-08-17T00:00:00Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AxiomAPIToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_AxiomAPIToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "AXIOM_TOKEN=xaat-01234567-89ab-cdef-0123-456789abcdef",
			want: "AXIOM_TOKEN=*****************************************",
		},
		{
			name: "quoted",
			src:  `"xaat-01234567-89ab-cdef-0123-456789abcdef"`,
			want: `"*****************************************"`,
		},
		{
			// The field the response that provisions an organization writes a
			// token of this kind into.
			name: "json",
			src:  `{"token":"xaat-01234567-89ab-cdef-0123-456789abcdef"}`,
			want: `{"token":"*****************************************"}`,
		},
		{
			// The header Axiom's own API reference calls its endpoints with.
			name: "the bearer authorization header",
			src:  "Authorization: Bearer xaat-01234567-89ab-cdef-0123-456789abcdef",
			want: "Authorization: Bearer *****************************************",
		},
		{
			// What the SDK guides pass a token of this kind to.
			name: "a client initialization",
			src:  `axiom.SetToken("xaat-01234567-89ab-cdef-0123-456789abcdef")`,
			want: `axiom.SetToken("*****************************************")`,
		},
		{
			name: "twice",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcdef xaat-01234567-89AB-CDEF-0123-456789ABCDEF",
			want: "***************************************** *****************************************",
		},
	}

	m := New(WithPatterns(AxiomAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AxiomAPIToken_aTokenInsideARejectedCandidate(t *testing.T) {
	// The half of "advance, never consume" this format can reach. The prefix
	// written twice opens a candidate at the first, whose body carries the x of
	// the second and so is no body at all; the token stands five characters
	// along, inside the forty-one bytes that candidate read over. A scan stepping
	// past its own candidate would leave it in the output whole.
	//
	// The other half — one token opening inside another — cannot happen here.
	// Inside a body: a body is hexadecimal and the separator alone while the
	// prefix carries two characters of neither. Inside a prefix: no proper suffix
	// of the prefix opens a prefix of its own. Test_axiomAPITokenPrefix measures
	// both, so the sentence is a measurement rather than a hope.
	src := "xaat-xaat-01234567-89ab-cdef-0123-456789abcdef"

	want := []Span{{5, 46}}
	if got, _ := AxiomAPIToken().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}

	m := New(WithPatterns(AxiomAPIToken()))
	if got, want := m.Mask(src), "xaat-"+strings.Repeat("*", 41); got != want {
		t.Errorf("Mask(%q) = %q, want %q", src, got, want)
	}
}

func Test_AxiomAPIToken_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches but
	// drop them, letting the token through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "zxaat-01234567-89ab-cdef-0123-456789abcdef",
			want: "z*****************************************",
		},
		{
			name: "underscore before",
			src:  "AXIOM_TOKEN_xaat-01234567-89ab-cdef-0123-456789abcdef",
			want: "AXIOM_TOKEN_*****************************************",
		},
		{
			// The far side of the same choice, and the one that costs something. A
			// boundary behind the match would drop this token rather than trim it;
			// without one the forty-one characters Axiom issued are redacted and
			// the one written after them, which is part of no credential, stays in
			// the text.
			name: "a hexadecimal character after",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcdef0",
			want: "*****************************************0",
		},
		{
			// A multi-byte rune written against the token on both sides. Neither
			// UTF-8 encoding shares a byte with the prefix or the body's alphabet,
			// so the token keeps its span exactly as it does against a single-byte
			// character.
			name: "a multi-byte rune before and after",
			src:  "鍵はxaat-01234567-89ab-cdef-0123-456789abcdefです",
			want: "鍵は*****************************************です",
		},
	}

	m := New(WithPatterns(AxiomAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AxiomAPIToken_leavesWhatFollowsAlone(t *testing.T) {
	// The layout ends a token at its forty-first character, so whatever is
	// written after one stays in the text whether the body's alphabet admits it
	// or not.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "host",
			src:  "host=xaat-01234567-89ab-cdef-0123-456789abcdef.example.com",
			want: "host=*****************************************.example.com",
		},
		{
			name: "sentence",
			src:  "the token is xaat-01234567-89ab-cdef-0123-456789abcdef.",
			want: "the token is *****************************************.",
		},
		{
			name: "underscored word",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcdef_suffix",
			want: "*****************************************_suffix",
		},
		{
			// A hyphen is a character a body is written with, and it still stays in
			// the text: the layout has been answered by the time it is read.
			name: "dashed word",
			src:  "xaat-01234567-89ab-cdef-0123-456789abcdef-suffix",
			want: "*****************************************-suffix",
		},
	}

	m := New(WithPatterns(AxiomAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AxiomAPIToken_anyVersionAndVariant(t *testing.T) {
	// The tightening this scan declines. A UUID carries a version at the first
	// character of its third group and a variant at the first of its fourth, and
	// the one whole token Axiom prints is of this kind and is version 4 with the
	// variant that goes with it. Neither nibble is read: nothing of Axiom's
	// states a version, so demanding one would be read off a value somebody was
	// shown rather than off the format, and being wrong about it locates nothing
	// at all.
	//
	// These carry no ordered run at the two positions, since the run cannot state
	// a nibble.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the version and variant of a random uuid",
			src:  "xaat-01234567-89ab-4def-8123-456789abcdef",
		},
		{
			name: "a version and variant of zero",
			src:  "xaat-01234567-89ab-0def-0123-456789abcdef",
		},
		{
			name: "a version and variant no uuid specification defines",
			src:  "xaat-01234567-89ab-fdef-f123-456789abcdef",
		},
	}

	want := []Span{{0, 41}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AxiomAPIToken().Find(tt.src); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, want)
			}
		})
	}
}

func Test_AxiomAPIToken_thePersonalAccessToken(t *testing.T) {
	// The other kind Axiom issues, which this scan does not read: a personal
	// access token, written xapt- and the same UUID behind it. The rationale
	// beside the scan says what separates the two — such a token performs every
	// action its holder can perform where this one carries only the privileges it
	// was created with — which puts the two under separate switches rather than
	// under this one widened to cover both.
	//
	// What the table is for is the decision: a value below ceasing to be declined
	// is a change somebody argues for rather than one somebody notices afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a personal access token",
			src:  "xapt-01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "a personal access token in an environment assignment",
			src:  "AXIOM_TOKEN=xapt-01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "a personal access token in the bearer authorization header",
			src:  "Authorization: Bearer xapt-01234567-89ab-cdef-0123-456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AxiomAPIToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_AxiomAPIToken_aBareUUID(t *testing.T) {
	// A UUID with nothing in front of it is not read and cannot be. It is the
	// shape an identifier is written in — a request id, an organization's claim
	// link, a row key — and a pattern in this package may not be anchored on one:
	// a grammar that admits a value carrying meaning to a reader when a tighter
	// grammar was available is the grammar this package declines. The prefix is
	// what makes the tighter one available here, so what is left without it stays
	// in the text.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a uuid on its own",
			src:  "01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "a request id",
			src:  "request_id=01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "a uuid in a query string",
			src:  "https://app.axiom.co/axiom-abcd/claim?token=01234567-89ab-cdef-0123-456789abcdef",
		},
	}

	m := New(WithPatterns(AxiomAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want it left alone", tt.src, got)
			}
		})
	}
}

// Test_AxiomAPIToken_holdsATokenTheInputCutShort states, with a literal number,
// what the second return of Find settles: a piece of the prefix standing at the
// end of the input, a candidate the end of the input cut short, and a whole
// match with nothing left unsettled behind it.
func Test_AxiomAPIToken_holdsATokenTheInputCutShort(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		want   []Span
		retain int
	}{
		{
			// A piece of the prefix stands at the very end of the input, so
			// nothing behind where it opens is settled.
			name:   "a piece of the prefix at the end of the input",
			src:    "xaat",
			retain: 0,
		},
		{
			name:   "a piece of the prefix behind prose",
			src:    "the token starts with xaat",
			retain: len("the token starts with "),
		},
		{
			// A whole prefix and a body the input cuts short. The candidate could
			// still become a token were the input longer, so what is unsettled
			// reaches back to where the candidate opened.
			name:   "a body the input cuts short",
			src:    "xaat-01234567-89ab",
			retain: 0,
		},
		{
			name:   "a body one character short of the layout",
			src:    "xaat-01234567-89ab-cdef-0123-456789abcde",
			retain: 0,
		},
		{
			// A candidate the input cut short whose bytes already break the
			// layout: a hexadecimal digit stands where the first separator
			// belongs, so no text carrying on from here could make this a token.
			// It is held from its own start all the same, which is the rule
			// against reading what is written of a truncated candidate — a scan
			// that worked out this one was hopeless would be keeping a second
			// grammar, of the halves, beside the first and free to disagree with
			// it. The cases above end inside a candidate that is still well
			// formed, so none of them can tell the two apart.
			name:   "a candidate the input cut short that the layout already broke",
			src:    "xaat-01234567089ab",
			retain: 0,
		},
		{
			// The same body written long enough for the layout to be read and
			// rejected. Settled to the end says the body test decided it; the case
			// above settles at the candidate instead, since the input runs out
			// before the layout is read and the scan gives up on it rather than
			// reading what is written of it.
			name:   "a candidate the body turned away, read to the end",
			src:    "xaat-01234567-89ab-cdef-0123-456789abcde. tail",
			retain: len("xaat-01234567-89ab-cdef-0123-456789abcde. tail"),
		},
		{
			// A whole token with more text after it, ending in a byte that opens no
			// piece of the prefix, so nothing at the end of the input is left
			// unsettled.
			name:   "a whole token followed by settled text",
			src:    "xaat-01234567-89ab-cdef-0123-456789abcdef tail",
			want:   []Span{{0, 41}},
			retain: len("xaat-01234567-89ab-cdef-0123-456789abcdef tail"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := AxiomAPIToken().Find(tt.src)
			if retain != tt.retain {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, retain, tt.retain)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

// Test_axiomAPITokenPrefix counts the characters of the prefix that no body may
// be written with, which is the claim the scan's account of itself rests on and
// which nothing else here reaches. A body is hexadecimal and the separator and
// nothing besides, so a prefix holding a character of neither cannot stand
// inside one — which is what keeps a token from opening inside another and what
// keeps the spans this pattern reports from ever overlapping.
//
// The count is asserted rather than its being merely more than none, because two
// is the number the rationale beside the scan writes down, and a prefix changed
// without that sentence being changed with it is what this catches. It is one
// fewer than the other half of this format has, the a this prefix writes twice
// being a character a body admits.
func Test_axiomAPITokenPrefix(t *testing.T) {
	if axiomAPITokenPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}

	outside := 0
	for i := range len(axiomAPITokenPrefix) {
		c := axiomAPITokenPrefix[i]
		if !isAxiomTokenHexByte(c) && c != axiomTokenSeparator {
			outside++
		}
	}
	if outside == 0 {
		t.Fatal("every character of the prefix is one a body may be written with, so a token can open inside another")
	}
	if outside != 2 {
		t.Errorf("%d characters of the prefix are ones no body admits, the rationale says two", outside)
	}

	// The other half, and the one the rationale declines to rest on: the prefix
	// closes on a character a body is written with, so nothing here may be
	// argued from a prefix closing outside the body's alphabet — a search does
	// stop inside a body at this character, and what keeps it from mattering is
	// that the scan searches for a different one.
	if c := axiomAPITokenPrefix[len(axiomAPITokenPrefix)-1]; c != axiomTokenSeparator {
		t.Errorf("the prefix closes on %q, where the rationale reads it as closing on the separator a body carries", c)
	}

	// And the leg the count above does not reach. A token beginning inside
	// another begins either in its body, which the count rules out, or in the
	// prefix in front of that body — and a token beginning at the nth character
	// of a prefix would need the rest of that prefix to open a prefix of its
	// own. No proper suffix of this one does, which is what leaves the body the
	// only place left to rule out.
	//
	// Nothing else reaches it: a prefix that grew a border would leave every
	// case in this file passing and the sentence beside the scan false, since
	// what such a prefix costs is two spans overlapping, which the cases here
	// have no shape to report.
	for k := 1; k < len(axiomAPITokenPrefix); k++ {
		if strings.HasPrefix(axiomAPITokenPrefix, axiomAPITokenPrefix[k:]) {
			t.Errorf("%q is both a suffix and a prefix of %q, so a token can open %d characters into another", axiomAPITokenPrefix[k:], axiomAPITokenPrefix, k)
		}
	}
}

// Test_axiomAPITokenAnchor holds the prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
//
// The second assertion is what the rationale's account of the choice rests on,
// and nothing else reaches it: an anchor moved to the a or to the hyphen leaves
// the scan correct and every case in this file passing, while a search resuming
// into a body would then stop about once in sixteen characters of it, or at
// every separator of every UUID, rather than running to the end without
// stopping.
func Test_axiomAPITokenAnchor(t *testing.T) {
	if axiomAPITokenAnchorIndex >= len(axiomAPITokenPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", axiomAPITokenAnchorIndex, len(axiomAPITokenPrefix))
	}
	if c := axiomAPITokenPrefix[axiomAPITokenAnchorIndex]; c != axiomAPITokenAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(axiomAPITokenAnchor))
	}
	if isAxiomTokenHexByte(axiomAPITokenAnchor) || axiomAPITokenAnchor == axiomTokenSeparator {
		t.Errorf("the scan searches for %q, which a body may be written with, so a search resumes inside one", byte(axiomAPITokenAnchor))
	}
}

// Test_axiomAPITokenFindBenchmarks_lineTheAnchorWasChosenAgainst holds the line
// the benchmarks are written on to the counts the rationale reads the anchor
// choice off. The counts are the whole of the evidence for searching on the x
// rather than on one of the other three, and nothing else reports them: a word
// added to that line with an x in it falsifies the sentence in silence, since
// every benchmark goes on timing whatever the line became.
func Test_axiomAPITokenFindBenchmarks_lineTheAnchorWasChosenAgainst(t *testing.T) {
	var line string
	for _, c := range axiomAPITokenFindBenchmarks() {
		if c.name == "no value" {
			line = c.src
		}
	}
	if line == "" {
		t.Fatal(`no benchmark case named "no value", so the line the anchor was chosen against is not here to count`)
	}

	for _, tt := range []struct {
		c    byte
		want int
	}{
		{axiomAPITokenAnchor, 1},
		{'a', 9},
		{'t', 11},
		{'-', 3},
	} {
		if got := strings.Count(line, string([]byte{tt.c})); got != tt.want {
			t.Errorf("the line carries %q %d times, the rationale reads the anchor off %d", tt.c, got, tt.want)
		}
	}
}

// Test_axiomAPITokenChars holds this half's count to the number the rationale
// reads it as: a token is the prefix and the body both halves share, which comes
// to forty-one. What the body itself is held to is the other half's, where it is
// declared.
//
// The sum is not asserted here, because the constant is that sum: recomputing it
// would compare an expression with itself and report nothing. Forty-one is the
// number the rationale writes down, and it is the one thing about this count
// that a change to either part could falsify.
func Test_axiomAPITokenChars(t *testing.T) {
	if axiomAPITokenChars != 41 {
		t.Errorf("a token is read as %d characters, the rationale says forty-one", axiomAPITokenChars)
	}
}

// referenceAxiomAPIToken is the expression the scan in builtin_axiom_api_token.go
// reads by hand: the statement of what an Axiom API token is, kept here so that
// the scan can be held to it.
//
// The prefix, the groups, the separators and the character class are spelled
// again rather than built from axiomAPITokenPrefix, axiomTokenGroups,
// axiomTokenSeparator and isAxiomTokenHexByte. A reference sharing those
// declarations could not disagree with the scan about them, and it is exactly
// that disagreement the fuzz target below is for: the two have to be changed
// together or reported apart.
var referenceAxiomAPIToken = regexp.MustCompile(`xaat-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}`)

// referenceAxiomAPITokenFind locates tokens the plain way: the leftmost match of
// the expression above, then the leftmost one beginning after that match's first
// byte, over and over, with nothing remembered between them.
//
// It asks at every byte rather than resuming past a match. A token cannot begin
// inside another here, so FindAllStringIndex would report the same spans — and
// it is not used all the same, because a reference is written to know nothing
// its scan claims, and that tokens cannot nest is a thing the scan claims.
//
// Resuming a byte along costs this one nothing beyond a constant: every
// candidate reads at most forty-one characters, here as in the scan, so neither
// has a run to walk and there is no cursor for either to be wrong about.
func referenceAxiomAPITokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceAxiomAPIToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzAxiomAPIToken_matchesReference guards the hand-written scan: the prefix it
// searches for, the layout it reads behind that prefix, the alphabet it reads
// the groups in and the byte it resumes at may none of them change which tokens
// are located.
func FuzzAxiomAPIToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("AXIOM_TOKEN=xaat-01234567-89ab-cdef-0123-456789abcdef")
	f.Add("Authorization: Bearer xaat-01234567-89ab-cdef-0123-456789abcdef")
	f.Add("xaat-01234567-89AB-CDEF-0123-456789ABCDEF")  // a body written in capitals
	f.Add("xaat-01234567-89ab-cdef-0123-456789abcde")   // one short of a token
	f.Add("xaat-01234567-89ab-cdef-0123-456789abcdef0") // and a run longer than one
	f.Add("XAAT-01234567-89ab-cdef-0123-456789abcdef")  // an uppercase prefix
	f.Add("xaat_01234567-89ab-cdef-0123-456789abcdef")  // an underscore where it carries its hyphen
	f.Add("xaat01234567-89ab-cdef-0123-456789abcdef")   // the hyphen that closes it left out
	f.Add("xaat-0123456789ab-cdef-0123-456789abcdef0")  // a separator missing from the body
	f.Add("xaat--1234567-89ab-cdef-0123-456789abcdef")  // a separator where a group opens
	f.Add("xaat-0123456--89ab-cdef-0123-456789abcdef")  // a separator too many
	// A hexadecimal digit standing where each of the separators belongs, which is
	// the layout alone declining a body the count and the alphabet both answer.
	f.Add("xaat-01234567089ab-cdef-0123-456789abcdef")
	f.Add("xaat-01234567-89ab0cdef-0123-456789abcdef")
	f.Add("xaat-01234567-89ab-cdef00123-456789abcdef")
	f.Add("xaat-01234567-89ab-cdef-01230456789abcdef")
	f.Add("xaat-g1234567-89ab-cdef-0123-456789abcdef")   // outside the alphabet where a body opens
	f.Add("xaat-01234567-89ab-cdef-0123-456789abcdeg")   // and where it closes
	f.Add("xaat-01234567-89ab-cdef-0123 456789abcdef")   // a space breaks the body
	f.Add("xaat-01234567-89ab-cdef-0123\n456789abcdef")  // and a line break
	f.Add("xapt-01234567-89ab-cdef-0123-456789abcdef")   // the other kind Axiom issues
	f.Add("01234567-89ab-cdef-0123-456789abcdef")        // a UUID with nothing in front of it
	f.Add("xaat-01234567-89ab-4def-8123-456789abcdef")   // the version and variant of a random UUID
	f.Add("xaat-01234567-89ab-cdef-0123-456789abcdef.")  // a token against a full stop
	f.Add("2026-08-17T00:00:00Z 0123456789abcdef012345") // separators and hexadecimal carrying no prefix
	// A token inside a candidate the body turned away, which a scan consuming its
	// own reach would step over, and two tokens with nothing between them.
	f.Add("xaat-xaat-01234567-89ab-cdef-0123-456789abcdef")
	f.Add("xaat-01234567-89ab-cdef-0123-456789abcdefxaat-01234567-89AB-CDEF-0123-456789ABCDEF")
	f.Add(strings.Repeat("xaat-", 8))
	// Candidate positions crowded as close as they can be: every fifth byte in
	// the first, and a run that reaches the layout at none of them.
	f.Add(strings.Repeat("xaat-", 32))
	f.Add(strings.Repeat("xaat-", 32) + "!")
	f.Add(strings.Repeat("xaat-01234567-89ab-cdef-0123-456789abcde.", 8))

	fuzzAgainstReference(f, AxiomAPIToken().Find, referenceAxiomAPITokenFind)
}

// axiomAPITokenFindBenchmarks is what this scan is timed on. The builtinPatterns
// entry for the pattern names it, and BenchmarkBuiltins times every case it
// holds under the pattern's own name, so that a built-in cannot arrive without a
// benchmark. Every case is held to the count it states under a plain go test as
// well, which is what a benchmark nobody has run yet cannot be.
func axiomAPITokenFindBenchmarks() []benchmarkCase {
	// The vendor's own host carries the only x on this line, so it is what the
	// anchor was chosen against: the t stands eleven times on it, the a nine and
	// the hyphen three, where the x stands once and the line costs the search one
	// pass and one candidate, turned away by the second character of the prefix.
	line := `time=2026-08-17T00:00:00Z level=info msg="query completed" dataset=http-logs url=https://api.axiom.co/v1/datasets/_apl?format=legacy `
	token := "xaat-01234567-89ab-cdef-0123-456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate at every forty-first byte, each of them reading the whole
			// layout before the last character turns it away. That is the most a
			// candidate can cost this scan without becoming a token, and there is
			// no value at the end of any of it.
			name:  "candidates that are not values",
			src:   strings.Repeat("xaat-01234567-89ab-cdef-0123-456789abcde.", 16),
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
