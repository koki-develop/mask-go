package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Sourcegraph access token pattern: what it locates and what it leaves
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
// shape, obviously not real. A value is forty hexadecimal characters, which is
// 0123456789abcdef twice over and eight more, so with the prefix in front a
// token is forty-four; the identifier a licensed instance writes is the run
// once, which brings a token to sixty-one, and the word a development instance
// writes brings it to fifty. Where a case is about the alphabet, it carries the
// same ordered characters spelled uppercase or carried on past f instead.

func Test_SourcegraphAccessToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token carrying no identifier",
			src:  "sgp_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}},
		},
		{
			name: "a token carrying the identifier a licensed instance writes",
			src:  "sgp_0123456789abcdef_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 61}},
		},
		{
			name: "a token carrying the identifier a development instance writes",
			src:  "sgp_local_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 50}},
		},
		{
			name: "a token in an environment assignment",
			src:  "SRC_ACCESS_TOKEN=sgp_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{17, 61}},
		},
		{
			name: "a token in the header the graphql api reads it from",
			src:  "Authorization: token sgp_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{21, 65}},
		},
		{
			// The count is read exactly, so what follows the fortieth character
			// of a value is not part of the token and stays in the text.
			name: "a value run longer than the count is a token and what follows it",
			src:  "sgp_0123456789abcdef0123456789abcdef012345670",
			want: []Span{{0, 44}},
		},
		{
			// The same, behind an identifier.
			name: "a value run longer than the count behind an identifier",
			src:  "sgp_0123456789abcdef_0123456789abcdef0123456789abcdef012345670",
			want: []Span{{0, 61}},
		},
		{
			// Neither token is inside the other, and nothing separates them.
			name: "two tokens with nothing between them",
			src:  "sgp_0123456789abcdef0123456789abcdef01234567sgp_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}, {44, 88}},
		},
		{
			name: "a token of each form written together",
			src:  "sgp_0123456789abcdef0123456789abcdef01234567sgp_local_0123456789abcdef0123456789abcdef01234567sgp_0123456789abcdef_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}, {44, 94}, {94, 155}},
		},
		{
			// A chain of three rather than a pair, so the resumption past a
			// candidate that failed is driven twice over on the same text
			// rather than once.
			name: "three tokens with nothing between them",
			src:  "sgp_0123456789abcdef0123456789abcdef01234567sgp_0123456789abcdef0123456789abcdef01234567sgp_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}, {44, 88}, {88, 132}},
		},
		{
			// The candidate the scan resuming a byte along is for. The first
			// prefix opens a candidate whose identifier would begin with the s
			// of the second, which no identifier may hold; the whole token
			// stands at the second. A scan resuming past the length the first
			// candidate hoped for would step over it.
			name: "a prefix written in front of a token",
			src:  "sgp_sgp_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{4, 48}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SourcegraphAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SourcegraphAccessToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "sgp_",
		},
		{
			name: "a value one character short",
			src:  "sgp_0123456789abcdef0123456789abcdef0123456",
		},
		{
			name: "a value one character short behind an identifier",
			src:  "sgp_0123456789abcdef_0123456789abcdef0123456789abcdef0123456",
		},
		{
			// The local form one character short of its own total length. The
			// separator behind the word local reads fine, so the value is read
			// from there; thirty-nine hexadecimal characters and the end of the
			// input follow, which is a candidate the input cuts short rather
			// than one the text itself rules out, and Find reports no span
			// either way.
			name: "a value one character short behind the local identifier",
			src:  "sgp_local_0123456789abcdef0123456789abcdef0123456",
		},
		{
			// A character outside the alphabet at the very first position of a
			// value rather than in its middle: the identifier reading is never
			// reached, since the byte behind the prefix settles a local reading
			// only for a letter l, and the walk for either hexadecimal reading
			// fails on its first character.
			name: "a forbidden character at the start of a value",
			src:  "sgp_.123456789abcdef0123456789abcdef01234567",
		},
		{
			// The same character at the value's last position rather than its
			// first: thirty-nine hexadecimal characters read fine and the walk
			// fails on the fortieth.
			name: "a forbidden character at the end of a value",
			src:  "sgp_0123456789abcdef0123456789abcdef0123456.",
		},
		{
			// A character outside the alphabet at the identifier's first
			// position: the hexadecimal identifier reading fails on its first
			// character, and the fallback reading of the whole run as a value
			// fails on the same byte.
			name: "a forbidden character at the start of an identifier",
			src:  "sgp_.123456789abcdef_0123456789abcdef0123456789abcdef01234567",
		},
		{
			// The same character at the identifier's last position: fifteen
			// hexadecimal characters read fine and the identifier walk fails on
			// the sixteenth, which is also where the fallback value walk fails.
			name: "a forbidden character at the end of an identifier",
			src:  "sgp_0123456789abcde._0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a value carrying a space",
			src:  "sgp_0123456789abcdef 123456789abcdef01234567",
		},
		{
			name: "a value carrying a hyphen",
			src:  "sgp_0123456789abcdef-123456789abcdef01234567",
		},
		{
			name: "a value carrying a dot",
			src:  "sgp_0123456789abcdef.123456789abcdef01234567",
		},
		{
			name: "a value carrying a letter past f",
			src:  "sgp_0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "an uppercase prefix",
			src:  "SGP_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "the prefix without the underscore closing it",
			src:  "sgp0123456789abcdef0123456789abcdef012345678",
		},
		{
			name: "a hyphen where the prefix closes",
			src:  "sgp-0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "the prefix without its middle letter",
			src:  "sp_0123456789abcdef0123456789abcdef01234567",
		},
		{
			// The prefix the vendor's parser accepts in place of this one and
			// nothing the vendor runs ever writes.
			name: "the prefix with an h behind it",
			src:  "sgph_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a value of the right length opening with no prefix",
			src:  "xxxx0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "an identifier with no separator behind it",
			src:  "sgp_local0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "the word of the local identifier written uppercase",
			src:  "sgp_LOCAL_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "the word of the local identifier written in mixed case",
			src:  "sgp_locaL_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "an identifier a character short",
			src:  "sgp_0123456789abcde_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "an identifier carrying a letter past f",
			src:  "sgp_0123456789abcdeg_0123456789abcdef0123456789abcdef01234567",
		},
		{
			// The instance identifier is not verified by the vendor, so this
			// value still authenticates; the grammar read here is the one the
			// vendor's own scanners are given, and a word is neither of the two
			// identifiers it names.
			name: "an identifier of neither shape",
			src:  "sgp_instance_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SourcegraphAccessToken().Find(tt.src); got != nil {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_SourcegraphAccessToken_inContext(t *testing.T) {
	// The places a token is written: the environment the src CLI reads one
	// from, the header the GraphQL API takes it in, the configuration file the
	// CLI reads beside that environment and the command lines that pass it
	// along.
	const token = "sgp_0123456789abcdef0123456789abcdef01234567"

	tests := []struct {
		name  string
		src   string
		start int
	}{
		{
			name:  "a token in a dotenv line",
			src:   "SRC_ACCESS_TOKEN=" + token,
			start: 17,
		},
		{
			name:  "a token in the authorization header",
			src:   "Authorization: token " + token,
			start: 21,
		},
		{
			name:  "a token on a curl command line",
			src:   `curl -H "Authorization: token ` + token + `" https://sourcegraph.example.com/.api/graphql`,
			start: 30,
		},
		{
			name:  "a token in the configuration file the cli reads",
			src:   `{"endpoint":"https://sourcegraph.example.com","accessToken":"` + token + `"}`,
			start: 61,
		},
		{
			name:  "a token on a command line the cli reads its environment from",
			src:   "SRC_ENDPOINT=https://sourcegraph.example.com SRC_ACCESS_TOKEN=" + token + " src search foo",
			start: 62,
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
			if got, _ := SourcegraphAccessToken().Find(tt.src); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, want)
			}
		})
	}
}

func Test_SourcegraphAccessToken_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match. A word boundary in front
	// would drop the whole match rather than trim it wherever a token is
	// written against a word character, and one behind it would drop a token
	// followed by a character of the value's own alphabet.
	const token = "sgp_0123456789abcdef0123456789abcdef01234567"

	tests := []struct {
		name  string
		src   string
		start int
	}{
		{
			name:  "a token after an underscore",
			src:   "SRC_ACCESS_TOKEN_" + token,
			start: 17,
		},
		{
			name:  "a token after a letter",
			src:   "x" + token,
			start: 1,
		},
		{
			name:  "a word written against a token",
			src:   token + "suffix",
			start: 0,
		},
		{
			name:  "a hyphenated word written against a token",
			src:   token + "-suffix",
			start: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := []Span{{tt.start, tt.start + len(token)}}
			if got, _ := SourcegraphAccessToken().Find(tt.src); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, want)
			}
		})
	}
}

func Test_SourcegraphAccessToken_leavesWhatFollowsAlone(t *testing.T) {
	// A token is forty-four, fifty or sixty-one characters and no more, so what
	// is written after one stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the token is sgp_0123456789abcdef0123456789abcdef01234567.",
			want: "the token is ********************************************.",
		},
		{
			name: "quoted",
			src:  `"sgp_0123456789abcdef0123456789abcdef01234567"`,
			want: `"********************************************"`,
		},
		{
			// The underscore belongs to no value however much the prefix and
			// the separator are written with one, so a word written against a
			// token is left where it stands.
			name: "an underscored word",
			src:  "sgp_0123456789abcdef0123456789abcdef01234567_suffix",
			want: "********************************************_suffix",
		},
		{
			// A letter past f is no value character either, so an ordinary word
			// written against a token survives it whole.
			name: "a word past f",
			src:  "sgp_0123456789abcdef0123456789abcdef01234567suffix",
			want: "********************************************suffix",
		},
		{
			// And a character the alphabet does admit: the count is what ends a
			// token, so the digit stays in the text rather than joining it.
			name: "a digit written against a token",
			src:  "sgp_0123456789abcdef0123456789abcdef012345678",
			want: "********************************************8",
		},
		{
			name: "a digit written against a token carrying an identifier",
			src:  "sgp_0123456789abcdef_0123456789abcdef0123456789abcdef012345678",
			want: "*************************************************************8",
		},
		{
			name: "a digit written against a token carrying the local identifier",
			src:  "sgp_local_0123456789abcdef0123456789abcdef012345678",
			want: "**************************************************8",
		},
	}

	m := New(WithPatterns(SourcegraphAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SourcegraphAccessToken_anUppercaseBody(t *testing.T) {
	// The alphabet decision builtin_sourcegraph_access_token.go argues: the
	// class is hexadecimal in either case, where the Pulumi and Supabase bodies
	// beside it are read lowercase alone. Sourcegraph's own expression and its
	// own parser are both written [a-fA-F0-9], so an uppercased token is one
	// the vendor authenticates — and the generator writes lowercase, which
	// makes these the values nothing mints and everything accepts.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an uppercase value",
			src:  "sgp_0123456789ABCDEF0123456789ABCDEF01234567",
			want: []Span{{0, 44}},
		},
		{
			name: "one uppercase character in a value",
			src:  "sgp_0123456789abcdef0123456789abcdef0123456F",
			want: []Span{{0, 44}},
		},
		{
			name: "an uppercase identifier",
			src:  "sgp_0123456789ABCDEF_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 61}},
		},
		{
			name: "an uppercase character at the start of a value",
			src:  "sgp_F0123456789abcdef0123456789abcdef0123456",
			want: []Span{{0, 44}},
		},
		{
			name: "an uppercase character in the middle of a value",
			src:  "sgp_0123456789abcdef0123A56789abcdef01234567",
			want: []Span{{0, 44}},
		},
		{
			// The earliest position an uppercase character can stand in an
			// identifier: the ten characters in front of it are digits, which
			// carry no case.
			name: "an uppercase character at the start of an identifier",
			src:  "sgp_0123456789Abcdef_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 61}},
		},
		{
			name: "an uppercase character in the middle of an identifier",
			src:  "sgp_0123456789abcDef_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 61}},
		},
		{
			name: "an uppercase character at the end of an identifier",
			src:  "sgp_0123456789abcdeF_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 61}},
		},
		{
			// Case mixed throughout both the identifier and the value, rather
			// than uppercased as a block or at a single character.
			name: "a token mixing case throughout",
			src:  "sgp_0123456789abcdef_0123456789AbCdEf0123456789aBcDeF01234567",
			want: []Span{{0, 61}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SourcegraphAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SourcegraphAccessToken_aBareBody(t *testing.T) {
	// The one decision here that is not the vendor's. Sourcegraph documents a
	// third version of this token, forty hexadecimal characters with nothing in
	// front of them, and still authenticates it. Reading it would mean redacting
	// every git commit name and every SHA-1 written into a log, which is the
	// grammar the gate in .claude/rules/builtin-patterns.md rules out, so the
	// prefix is required and these are the values that pass through.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a bare value",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a commit written into a log line",
			src:  "checked out 0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a value assigned to the name the cli reads it from",
			src:  "SRC_ACCESS_TOKEN=0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SourcegraphAccessToken().Find(tt.src); got != nil {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_SourcegraphAccessToken_theReadingsAreExclusive(t *testing.T) {
	// The claim builtin_sourcegraph_access_token.go rests the single pass over
	// a candidate on: at most one of the three readings can apply, so the scan
	// takes the one it lands in rather than trying a shorter one after a longer
	// one failed.
	//
	// The word opens with a letter no hexadecimal identifier and no value is
	// written with, which divides it from the other two; the character sixteen
	// along divides those two from each other, being the separator where a
	// token carries an identifier and a seventeenth character of the value
	// where it does not. The last case is what a seventeenth of an identifier
	// would have been: neither reading holds, and nothing is located.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a word behind the prefix is the local form",
			src:  "sgp_local_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 50}},
		},
		{
			name: "a separator sixteen characters along is the identified form",
			src:  "sgp_0123456789abcdef_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 61}},
		},
		{
			name: "a hexadecimal character sixteen along is the form carrying no identifier",
			src:  "sgp_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}},
		},
		{
			name: "a separator seventeen characters along is neither",
			src:  "sgp_0123456789abcdef0_0123456789abcdef0123456789abcdef01234567",
			want: nil,
		},
		{
			// A value forty characters long divided from what follows by a
			// separator is the form carrying no identifier: the separator is
			// what would have divided a sixteen character identifier, and this
			// run is not one.
			name: "a value with a separator behind it",
			src:  "sgp_0123456789abcdef0123456789abcdef01234567_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SourcegraphAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SourcegraphAccessToken_noTokenBeginsInsideAnother(t *testing.T) {
	// The claim builtin_sourcegraph_access_token.go makes: the spans of this
	// pattern never overlap one another. Everything a span covers past the
	// prefix is a hexadecimal character, a separator or a letter of the word
	// local, and the prefix opens with an s that neither of the two characters
	// behind it is, that the separator is not, that the word does not carry and
	// that no value may hold — so no position inside a span opens a prefix.
	//
	// It is not a claim one input can state, so a whole token is written into
	// every position of another here — at each character of its prefix, at each
	// character of its body and against either end — with nothing, a value and a
	// second token behind it in turn, for each of the three forms against each
	// of the three. What is asserted is only that no two spans overlap; where
	// the tokens fall is what the table at the top of this file is for.
	value := strings.Repeat("0123456789abcdef", 2) + "01234567"
	forms := []string{
		"sgp_" + value,
		"sgp_0123456789abcdef_" + value,
		"sgp_local_" + value,
	}
	p := SourcegraphAccessToken()

	for _, outer := range forms {
		for _, inner := range forms {
			for i := range len(outer) + 1 {
				for _, tail := range []string{"", value, inner} {
					src := outer[:i] + inner + outer[i:] + tail
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
	}
}

func Test_SourcegraphAccessToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision this format pays for rather than ruling out. Everything
	// behind the prefix is one class and a digest is written in it, so the
	// count is the whole of what tells the two apart: an MD5 is thirty-two
	// characters and is turned away, a SHA-1 is forty and is a token's format
	// character for character, and a SHA-256 is sixty-four, of which the first
	// forty are a value.
	//
	// The prefix is what holds the collision to text somebody wrote sgp_ in
	// front of, and it is why the version of this token carrying no prefix is
	// declined — Test_SourcegraphAccessToken_aBareBody is that half.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an md5 behind the prefix",
			src:  "sgp_0123456789abcdef0123456789abcdef",
			want: nil,
		},
		{
			name: "a uuid behind the prefix",
			src:  "sgp_01234567-89ab-cdef-0123-456789abcdef",
			want: nil,
		},
		{
			name: "a sha-1 behind the prefix",
			src:  "sgp_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}},
		},
		{
			name: "a sha-256 behind the prefix",
			src:  "sgp_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 44}},
		},
		{
			name: "the prefix in front of a digest in a path",
			src:  "assets/sgp_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.png",
			want: []Span{{7, 51}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SourcegraphAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SourcegraphAccessToken_nextToNonASCII(t *testing.T) {
	// There is no boundary on either side of a match, and a multi-byte rune is
	// no exception: the prefix opens with a byte no such rune's encoding holds,
	// and a value's alphabet holds none of the continuation bytes such an
	// encoding is written in either.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// 日本語 is three runes of three bytes each, so the token begins at
			// byte nine.
			name: "a token after japanese text",
			src:  "日本語sgp_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{9, 53}},
		},
		{
			name: "a token before japanese text",
			src:  "sgp_local_0123456789abcdef0123456789abcdef01234567日本語",
			want: []Span{{0, 50}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SourcegraphAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SourcegraphAccessToken_settlesACandidateTheInputCutShort(t *testing.T) {
	// What the scan settles where the input ends inside a candidate rather than
	// after one: the candidate's own start, whichever of the three readings the
	// text in front of the cut was heading towards.
	tests := []struct {
		name   string
		src    string
		retain int
	}{
		{
			// The prefix and a whole identifier stand, but the value behind the
			// separator is sixteen characters where forty are asked for: the walk
			// runs out of input inside the value, so the whole candidate,
			// starting at the prefix, is unsettled.
			name:   "the input ends inside the value behind an identifier",
			src:    "token=sgp_0123456789abcdef_0123456789abcdef",
			retain: 6,
		},
		{
			// The input ends inside the prefix itself: "sgp" is a proper prefix
			// of "sgp_", so the candidate it might open is held back from its
			// own first byte.
			name:   "the input ends inside the prefix",
			src:    "token=sgp",
			retain: 6,
		},
		{
			// No suffix of this input is the start of the prefix — the third
			// character asked for is p and this one is q — so nothing here is
			// held back at all.
			name:   "the input ends on a byte the prefix could never continue",
			src:    "token=sgq",
			retain: 9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, retain := SourcegraphAccessToken().Find(tt.src); retain != tt.retain {
				t.Errorf("Find(%q) retain = %d, want %d", tt.src, retain, tt.retain)
			}
		})
	}
}

func Test_sourcegraphAccessTokenPrefix(t *testing.T) {
	// Two things about the prefix are load-bearing, and neither shows anywhere
	// else.
	//
	// It opens with a character no value is written with, one it carries
	// nowhere else and one the word of the local identifier does not hold. That
	// is the whole of the claim that no token can begin inside another, which
	// Test_SourcegraphAccessToken_noTokenBeginsInsideAnother drives and which a
	// prefix built any other way would make false without failing there — the
	// drive would pass on a pattern whose spans do overlap somewhere it does
	// not reach.
	//
	// And it closes with a character no value is written with, so a run of
	// value characters can never hold the prefix and every body begins where
	// such a run begins. That is not what bounds the scan — the counts are —
	// but it is what a count relaxed to a floor would have to fall back on,
	// which is why it is held to here rather than worked out then.
	if sourcegraphAccessTokenPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}

	opening := sourcegraphAccessTokenPrefix[0]
	if isSourcegraphAccessTokenHexByte(opening) {
		t.Errorf("the prefix opens with %q, which a value may be written with", opening)
	}
	if i := strings.IndexByte(sourcegraphAccessTokenPrefix[1:], opening); i >= 0 {
		t.Errorf("the prefix carries %q again at %d, so a prefix can open inside one", opening, i+1)
	}
	if i := strings.IndexByte(sourcegraphAccessTokenLocalIdentifier, opening); i >= 0 {
		t.Errorf("the local identifier carries %q at %d, so a prefix can open inside one", opening, i)
	}
	if c := sourcegraphAccessTokenPrefix[len(sourcegraphAccessTokenPrefix)-1]; isSourcegraphAccessTokenHexByte(c) {
		t.Errorf("the prefix closes with %q, which a value may be written with", c)
	}
}

// Test_sourcegraphAccessTokenAnchor holds the prefix to carrying the byte the
// scan searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_sourcegraphAccessTokenAnchor(t *testing.T) {
	if sourcegraphAccessTokenAnchorIndex >= len(sourcegraphAccessTokenPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", sourcegraphAccessTokenAnchorIndex, len(sourcegraphAccessTokenPrefix))
	}
	if c := sourcegraphAccessTokenPrefix[sourcegraphAccessTokenAnchorIndex]; c != sourcegraphAccessTokenAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(sourcegraphAccessTokenAnchor))
	}

	// What the anchor costs, counted rather than claimed in prose. It stands
	// once in the prefix and not at all in the word of the local identifier, so
	// a run of prefixes stops the search once a prefix; and it is no character
	// a value is written with, so a digest stops it not once however long it
	// runs. The three letters in front of it are what the vendor's own name,
	// its host names and its paths are spelled with, which is what it is chosen
	// against.
	if n := strings.Count(sourcegraphAccessTokenPrefix, string(sourcegraphAccessTokenAnchor)); n != 1 {
		t.Errorf("the anchor stands %d times in %q, want 1", n, sourcegraphAccessTokenPrefix)
	}
	if n := strings.Count(sourcegraphAccessTokenLocalIdentifier, string(sourcegraphAccessTokenAnchor)); n != 0 {
		t.Errorf("the anchor stands %d times in %q, want 0", n, sourcegraphAccessTokenLocalIdentifier)
	}
	if isSourcegraphAccessTokenHexByte(sourcegraphAccessTokenAnchor) {
		t.Errorf("the anchor is %q, which a value may be written with", byte(sourcegraphAccessTokenAnchor))
	}
}

func Test_sourcegraphAccessTokenLocalIdentifier(t *testing.T) {
	// What the word has to be for the reading of a candidate to be settled by
	// one byte: it opens with a character no hexadecimal identifier and no
	// value is written with, so a candidate carrying it has a letter where
	// either other reading needs a digit.
	//
	// The separator is not part of it. A token carrying this identifier writes
	// one behind the word exactly as a token carrying a hexadecimal identifier
	// does, and keeping the two declarations apart is what lets the scan read
	// the separator in one place for both.
	if sourcegraphAccessTokenLocalIdentifier == "" {
		t.Fatal("the local identifier is empty, so every candidate carries one")
	}
	if c := sourcegraphAccessTokenLocalIdentifier[0]; isSourcegraphAccessTokenHexByte(c) {
		t.Errorf("the local identifier opens with %q, which a hexadecimal identifier may open with", c)
	}
	if got := strings.ToLower(sourcegraphAccessTokenLocalIdentifier); got != sourcegraphAccessTokenLocalIdentifier {
		t.Errorf("the local identifier is %q, and the generator writes it %q", sourcegraphAccessTokenLocalIdentifier, got)
	}
}

func Test_sourcegraphAccessTokenChars(t *testing.T) {
	// The prefix Sourcegraph documents, the two identifiers it writes and the
	// count of a value. The three lengths they make between them — forty-four,
	// fifty and sixty-one — are pinned by the spans the table at the top of
	// this file writes out against the scan.
	if got := len(sourcegraphAccessTokenPrefix); got != 4 {
		t.Errorf("len(sourcegraphAccessTokenPrefix) = %d, want 4", got)
	}
	if got := len(sourcegraphAccessTokenLocalIdentifier); got != 5 {
		t.Errorf("len(sourcegraphAccessTokenLocalIdentifier) = %d, want 5", got)
	}
	if got := sourcegraphAccessTokenIdentifierChars; got != 16 {
		t.Errorf("sourcegraphAccessTokenIdentifierChars = %d, want 16", got)
	}
	if got := sourcegraphAccessTokenValueChars; got != 40 {
		t.Errorf("sourcegraphAccessTokenValueChars = %d, want 40", got)
	}
}

func Test_isSourcegraphAccessTokenHexByte(t *testing.T) {
	// The hexadecimal digits of either case and nothing else, stated over every
	// byte rather than by example. The uppercase half is admitted, which
	// builtin_sourcegraph_access_token.go weighs against the two hexadecimal
	// bodies beside it that decline it.
	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9' || 'a' <= b && b <= 'f' || 'A' <= b && b <= 'F'
		if got := isSourcegraphAccessTokenHexByte(b); got != want {
			t.Errorf("isSourcegraphAccessTokenHexByte(%q) = %v, want %v", b, got, want)
		}
	}
}

func Test_sourcegraphAccessTokenHexEnd(t *testing.T) {
	// The walk the identifier and the value are both read by, and the reason it
	// answers with two booleans rather than one: a walk that stopped because
	// the text said so has settled the candidate, and a walk that stopped
	// because the input ran out has not.
	tests := []struct {
		name string
		src  string
		i    int
		n    int
		end  int
		ok   bool
		cut  bool
	}{
		{
			name: "the count standing where it is asked for",
			src:  "0123456789abcdef",
			i:    0,
			n:    16,
			end:  16,
			ok:   true,
		},
		{
			name: "more than the count is the count and what follows it",
			src:  "0123456789abcdef0",
			i:    0,
			n:    16,
			end:  16,
			ok:   true,
		},
		{
			name: "a character outside the alphabet settles the walk",
			src:  "0123456789abcdeg",
			i:    0,
			n:    16,
			end:  0,
			ok:   false,
		},
		{
			name: "the end of the input does not",
			src:  "0123456789abcde",
			i:    0,
			n:    16,
			end:  0,
			ok:   false,
			cut:  true,
		},
		{
			name: "a character outside the alphabet in front of the end settles it",
			src:  "0123456789abcdeg",
			i:    0,
			n:    32,
			end:  0,
			ok:   false,
		},
		{
			name: "a walk beginning at the end of the input",
			src:  "0123456789abcdef",
			i:    16,
			n:    16,
			end:  0,
			ok:   false,
			cut:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			end, ok, cut := sourcegraphAccessTokenHexEnd(tt.src, tt.i, tt.n)
			if end != tt.end || ok != tt.ok || cut != tt.cut {
				t.Errorf("sourcegraphAccessTokenHexEnd(%q, %d, %d) = (%d, %v, %v), want (%d, %v, %v)",
					tt.src, tt.i, tt.n, end, ok, cut, tt.end, tt.ok, tt.cut)
			}
		})
	}
}

// referenceSourcegraphAccessToken is the expression the scan in
// builtin_sourcegraph_access_token.go reads by hand: the statement of what a
// Sourcegraph access token is, kept here so that the scan can be held to it.
// It is the vendor's own expression for the two versions that carry the prefix,
// written as one alternation rather than as the two rows the secret formats
// page divides them into.
//
// The prefix, the identifiers, the counts and the character class are spelled
// again rather than built from sourcegraphAccessTokenPrefix,
// sourcegraphAccessTokenLocalIdentifier, sourcegraphAccessTokenIdentifierChars,
// sourcegraphAccessTokenValueChars and isSourcegraphAccessTokenHexByte. A
// reference sharing those declarations could not disagree with the scan about
// them, and it is exactly that disagreement the fuzz target below is for: the
// two have to be changed together or reported apart.
//
// The counted repetitions here are exact, so the machine an engine builds for a
// candidate is read once and stops, and the prefix in front of them is one
// literal, which is what an engine searches the text for. That is what lets
// this reference be an expression at all, where the Anthropic one is written
// out for a floor spelled as a counted repetition and the Notion one for an
// alternation of two literals.
var referenceSourcegraphAccessToken = regexp.MustCompile(`sgp_(?:[0-9a-fA-F]{16}_|local_)?[0-9a-fA-F]{40}`)

// referenceSourcegraphAccessTokenFind locates tokens the plain way: the
// leftmost match of the expression above, then the leftmost one beginning after
// that match's first byte, over and over, with nothing remembered between them.
//
// Asking at every byte rather than resuming past a match is what the scan does.
// No token can be written inside another here, which the scan claims and
// builtin_sourcegraph_access_token.go argues, and a reference is written to
// know nothing its scan claims — so the reference asks anyway, and the target
// below is what holds the claim to being true rather than assumed on both
// sides.
func referenceSourcegraphAccessTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceSourcegraphAccessToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzSourcegraphAccessToken_matchesReference guards the hand-written scan: the
// prefix it searches for, the case it reads that prefix in, the two identifiers
// it reads behind it, the counts it reads them and the value against, the
// alphabet it reads those counts in and the byte it resumes at may none of them
// change which tokens are located.
func FuzzSourcegraphAccessToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("SRC_ACCESS_TOKEN=sgp_0123456789abcdef0123456789abcdef01234567")
	f.Add("sgp_0123456789abcdef_0123456789abcdef0123456789abcdef01234567")
	f.Add("sgp_local_0123456789abcdef0123456789abcdef01234567")
	f.Add("sgp_0123456789abcdef0123456789abcdef012345")    // a value two short
	f.Add("sgp_0123456789abcdef0123456789abcdef0123456")   // and one short
	f.Add("sgp_0123456789abcdef0123456789abcdef012345678") // and one long
	f.Add("sgp_0123456789abcdef 123456789abcdef01234567")
	f.Add("sgp_0123456789abcdef-123456789abcdef01234567")
	f.Add("sgp_0123456789abcdef\n123456789abcdef01234567")
	f.Add("sgp_0123456789ABCDEF0123456789ABCDEF01234567") // an uppercase value
	f.Add("sgp_0123456789abcdefghijklmnopqrstuvwxyz0123") // letters past f
	f.Add("SGP_0123456789abcdef0123456789abcdef01234567") // an uppercase prefix
	f.Add("sgp0123456789abcdef0123456789abcdef012345678") // no underscore closing it
	f.Add("sgp-0123456789abcdef0123456789abcdef01234567") // a hyphen closing it
	f.Add("sgph_0123456789abcdef0123456789abcdef01234567")
	f.Add("xsgp_0123456789abcdef0123456789abcdef01234567")
	// The identifiers either side of what is read: one character short, one
	// character long, the word in the wrong case, the word with no separator
	// behind it and a word that is neither.
	f.Add("sgp_0123456789abcde_0123456789abcdef0123456789abcdef01234567")
	f.Add("sgp_0123456789abcdef0_0123456789abcdef0123456789abcdef01234567")
	f.Add("sgp_LOCAL_0123456789abcdef0123456789abcdef01234567")
	f.Add("sgp_locaL_0123456789abcdef0123456789abcdef01234567")
	f.Add("sgp_local0123456789abcdef0123456789abcdef01234567")
	f.Add("sgp_instance_0123456789abcdef0123456789abcdef01234567")
	f.Add("sgp_local_local_0123456789abcdef0123456789abcdef01234567")
	f.Add("sgp_0123456789abcdef0123456789abcdef01234567_0123456789abcdef0123456789abcdef01234567")
	// The digests and the UUID the count and the alphabet are read against, and
	// the version of this token that carries no prefix at all.
	f.Add("sgp_0123456789abcdef0123456789abcdef")
	f.Add("sgp_01234567-89ab-cdef-0123-456789abcdef")
	f.Add("sgp_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("0123456789abcdef0123456789abcdef01234567")
	// A prefix in front of a token, tokens with nothing between them, and
	// candidate positions crowded as close as they can be.
	f.Add("sgp_sgp_0123456789abcdef0123456789abcdef01234567")
	f.Add("sgp_0123456789abcdef0123456789abcdef01234567sgp_0123456789abcdef0123456789abcdef01234567")
	f.Add("sgp_0123456789abcdef0123456789abcdef01234567sgp_local_0123456789abcdef0123456789abcdef01234567")
	f.Add(strings.Repeat("sgp_", 64))
	f.Add(strings.Repeat("sgp_", 64) + "0123456789abcdef0123456789abcdef01234567")
	f.Add(strings.Repeat("sgp_local_", 64) + "0123456789abcdef0123456789abcdef01234567")
	f.Add(strings.Repeat("sgp_0123456789abcdef_0123456789abcdef0123456789abcdef01234567", 4))
	f.Add(strings.Repeat("_", 128))
	f.Add(strings.Repeat("0123456789abcdef_", 128))
	f.Add("src login https://sourcegraph.example.com")

	fuzzAgainstReference(f, SourcegraphAccessToken().Find, referenceSourcegraphAccessTokenFind)
}

// sourcegraphAccessTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func sourcegraphAccessTokenFindBenchmarks() []benchmarkCase {
	// The line the anchor is chosen against: the s stands five times on it, the
	// g four and the p four, where the underscore stands once. The word
	// Sourcegraph's own host name is spelled with carries one of each letter,
	// which is what the three of them cost and the underscore does not. Nothing
	// on it opens the prefix, so what the line times is the search for the
	// anchor, which is most of what this pattern costs a caller whose text
	// holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="fetching repository" host=sourcegraph.example.com repo_name=github.com/acme/website `
	token := "sgp_0123456789abcdef0123456789abcdef01234567"
	identified := "sgp_0123456789abcdef_0123456789abcdef0123456789abcdef01234567"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is four characters carrying the anchor once, so a run
			// of them holds a candidate for every four it has. Each is turned
			// away by the first byte of the body it never had, since the s
			// opening the next prefix is neither the letter the word opens with
			// nor a character an identifier may hold — which is the cheapest
			// this scan declines a candidate for once the prefix has been read.
			name:  "candidates that are not values",
			src:   strings.Repeat("sgp_", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads a prefix, since what stands three
			// characters in front of each is the anchor rather than the s.
			// That is one comparison a stop, and the cheapest a stop is
			// answered for at all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("_", 4096),
			spans: 0,
		},
		{
			// The way a candidate carrying no identifier is walked furthest: a
			// value of the right length whose last character is a letter past
			// f, so the whole of it is walked before the candidate is turned
			// away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("sgp_0123456789abcdef0123456789abcdef0123456g ", 16),
			spans: 0,
		},
		{
			// And the way a candidate carrying one is: an identifier and a
			// separator read whole and a value walked to its last character,
			// which is the most bytes any candidate of this scan reads.
			name:  "candidates walked past an identifier",
			src:   strings.Repeat("sgp_0123456789abcdef_0123456789abcdef0123456789abcdef0123456g ", 16),
			spans: 0,
		},
		{
			// A hexadecimal run, which is what a digest and an identifier are
			// written in and carries no character of the prefix at all, so the
			// search walks the whole of it in one pass.
			name:  "a run of the value alphabet",
			src:   strings.Repeat("0123456789abcdef", 256),
			spans: 0,
		},
		{
			// The same run broken by the anchor every sixteen characters, which
			// is the shape a line of identifiers is: every break stops the
			// search, and the byte in front of each is a hexadecimal character
			// rather than the s.
			name:  "a run of the value alphabet broken by anchors",
			src:   strings.Repeat("0123456789abcdef_", 256),
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
		{
			name:  "many values carrying an identifier",
			src:   strings.Repeat(line+"token="+identified+"\n", 32),
			spans: 32,
		},
	}
}
