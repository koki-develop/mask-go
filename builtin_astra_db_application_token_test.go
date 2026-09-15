package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Astra DB application token pattern: what it locates and what it leaves
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
// shape, obviously not real. The client identifier is the run 0123456789
// carried on through the alphabet to twenty-four characters,
// 0123456789abcdefghijklmn, and the secret is the same run to sixty-four, which
// runs to z and starts the alphabet again,
// 0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr.
//
// Where a case turns on a character the run does not put there, the half writes
// that character and carries the run everywhere else: the ones carrying the
// hyphen and the underscore base64url adds to base62, and the ones carrying a
// character the alphabet leaves out. A half opening and closing on an end of
// the alphabet writes that end at both of its ends and carries the run between
// them, which is the run shortened by two rather than shifted along:
// .betterleaks.toml says why a value written here has to carry the run where a
// body begins.
//
// The bodies in Test_AstraDBApplicationToken_aPlaceholderBody are built from no
// run at all, being a single repeated digit, which is what makes them
// placeholders.

func Test_AstraDBApplicationToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			want: []Span{{0, 97}},
		},
		{
			name: "a token in an environment assignment",
			src:  "ASTRA_DB_APPLICATION_TOKEN=AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			want: []Span{{27, 124}},
		},
		{
			// The two characters base64url adds to base62, in the middle of a
			// half where nothing else could be reading them.
			name: "a hyphen in the identifier and an underscore in the secret",
			src:  "AstraCS:0123456789ab-defghijklmn:0123456789abcdefghijklmnopqrstuv_xyz0123456789abcdefghijklmnopqr",
			want: []Span{{0, 97}},
		},
		{
			name: "an underscore in the identifier and a hyphen in the secret",
			src:  "AstraCS:0123456789ab_defghijklmn:0123456789abcdefghijklmnopqrstuv-xyz0123456789abcdefghijklmnopqr",
			want: []Span{{0, 97}},
		},
		{
			// The alphabet has eight ends — 0, 9, A, Z, a, z, the hyphen and
			// the underscore — and each is a character a half may open or close
			// on. The run stands on one of the eight and no more, at the first
			// character of either half, so each case here writes one end at all
			// four of the places a half begins or closes and carries the run
			// between them.
			name: "halves opening and closing on the first digit",
			src:  "AstraCS:00123456789abcdefghijkl0:00123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop0",
			want: []Span{{0, 97}},
		},
		{
			name: "halves opening and closing on the last digit",
			src:  "AstraCS:90123456789abcdefghijkl9:90123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop9",
			want: []Span{{0, 97}},
		},
		{
			name: "halves opening and closing on the first uppercase letter",
			src:  "AstraCS:A0123456789abcdefghijklA:A0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopA",
			want: []Span{{0, 97}},
		},
		{
			name: "halves opening and closing on the last uppercase letter",
			src:  "AstraCS:Z0123456789abcdefghijklZ:Z0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopZ",
			want: []Span{{0, 97}},
		},
		{
			name: "halves opening and closing on the first lowercase letter",
			src:  "AstraCS:a0123456789abcdefghijkla:a0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopa",
			want: []Span{{0, 97}},
		},
		{
			name: "halves opening and closing on the last lowercase letter",
			src:  "AstraCS:z0123456789abcdefghijklz:z0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopz",
			want: []Span{{0, 97}},
		},
		{
			name: "halves opening and closing on the hyphen",
			src:  "AstraCS:-0123456789abcdefghijkl-:-0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop-",
			want: []Span{{0, 97}},
		},
		{
			name: "halves opening and closing on the underscore",
			src:  "AstraCS:_0123456789abcdefghijkl_:_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop_",
			want: []Span{{0, 97}},
		},
		{
			// The counts are read exactly, so a character of the alphabet
			// written against a token is a character after the token rather
			// than part of it.
			name: "a run longer than the count",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrs",
			want: []Span{{0, 97}},
		},
		{
			// The prefix carries the colon a body may not, so the candidate
			// opening at the front of this text reads the second prefix where a
			// divider belongs and is turned away, and the token behind it is
			// found at its own prefix.
			name: "a token behind a prefix that opens no token",
			src:  "AstraCS:AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			want: []Span{{8, 105}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrAstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			want: []Span{{0, 97}, {97, 194}},
		},
		{
			name: "two tokens separated by a space",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			want: []Span{{0, 97}, {98, 195}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AstraDBApplicationToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AstraDBApplicationToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "AstraCS:",
		},
		{
			// The bytes just outside the alphabet's six range ends, which is
			// where a bound written one too wide would show. Each stands in a
			// token of the right counts and divider, so a half admitting it
			// would be located and the case would fail rather than merely stop
			// stating anything. The identifier and the secret are two slices of
			// one body, so each byte is written at both ends and the middle of
			// each of them: an index cut one short in one of the two would
			// leave the other reading correctly.
			name: "the byte before the first digit where the identifier opens",
			src:  "AstraCS:/123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the first digit in the identifier",
			src:  "AstraCS:0123456789ab/defghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the first digit where the identifier closes",
			src:  "AstraCS:0123456789abcdefghijklm/:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the first digit where the secret opens",
			src:  "AstraCS:0123456789abcdefghijklmn:/123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the first digit in the secret",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuv/xyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the first digit where the secret closes",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq/",
		},
		{
			// The byte past the last digit is the divider itself, so these are
			// also what says a half may carry none of its own: the candidate
			// keeps the divider it needs at the offset the counts put it and is
			// turned away by the character written beside it.
			name: "the byte past the last digit where the identifier opens",
			src:  "AstraCS::123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte past the last digit in the identifier",
			src:  "AstraCS:0123456789ab:defghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte past the last digit where the identifier closes",
			src:  "AstraCS:0123456789abcdefghijklm::0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte past the last digit where the secret opens",
			src:  "AstraCS:0123456789abcdefghijklmn::123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte past the last digit in the secret",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuv:xyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte past the last digit where the secret closes",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq:",
		},
		{
			name: "the byte before the first uppercase letter where the identifier opens",
			src:  "AstraCS:@123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the first uppercase letter in the identifier",
			src:  "AstraCS:0123456789ab@defghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the first uppercase letter where the identifier closes",
			src:  "AstraCS:0123456789abcdefghijklm@:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the first uppercase letter where the secret opens",
			src:  "AstraCS:0123456789abcdefghijklmn:@123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the first uppercase letter in the secret",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuv@xyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the first uppercase letter where the secret closes",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq@",
		},
		{
			name: "the byte past the last uppercase letter where the identifier opens",
			src:  "AstraCS:[123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte past the last uppercase letter in the identifier",
			src:  "AstraCS:0123456789ab[defghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte past the last uppercase letter where the identifier closes",
			src:  "AstraCS:0123456789abcdefghijklm[:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte past the last uppercase letter where the secret opens",
			src:  "AstraCS:0123456789abcdefghijklmn:[123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte past the last uppercase letter in the secret",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuv[xyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte past the last uppercase letter where the secret closes",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq[",
		},
		{
			name: "the byte before the first lowercase letter where the identifier opens",
			src:  "AstraCS:`123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the first lowercase letter in the identifier",
			src:  "AstraCS:0123456789ab`defghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the first lowercase letter where the identifier closes",
			src:  "AstraCS:0123456789abcdefghijklm`:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the first lowercase letter where the secret opens",
			src:  "AstraCS:0123456789abcdefghijklmn:`123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the first lowercase letter in the secret",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuv`xyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the first lowercase letter where the secret closes",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq`",
		},
		{
			name: "the byte past the last lowercase letter where the identifier opens",
			src:  "AstraCS:{123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte past the last lowercase letter in the identifier",
			src:  "AstraCS:0123456789ab{defghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte past the last lowercase letter where the identifier closes",
			src:  "AstraCS:0123456789abcdefghijklm{:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte past the last lowercase letter where the secret opens",
			src:  "AstraCS:0123456789abcdefghijklmn:{123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte past the last lowercase letter in the secret",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuv{xyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte past the last lowercase letter where the secret closes",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq{",
		},
		{
			// The hyphen and the underscore are the other two ends of the
			// alphabet, and neither is the end of a range: each is a comparison
			// against one character, so what goes wrong there is a character
			// written in place of the one named rather than a bound one too
			// wide. The bytes either side of each are what says the comparison
			// is the character it names, and they get one case in each half
			// rather than the six above — where a half a byte is written in
			// matters, since the two are two slices of one body, where a
			// position inside a half does not, the walk being the same at every
			// character of one. Three of the four stand here; the fourth, the
			// byte past the underscore, is the byte before the first lowercase
			// letter and is driven at all six positions above.
			name: "the byte past the hyphen where the identifier opens",
			src:  "AstraCS:.123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte past the hyphen in the secret",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuv.xyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the hyphen where the identifier closes",
			src:  "AstraCS:0123456789abcdefghijklm,:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the hyphen where the secret opens",
			src:  "AstraCS:0123456789abcdefghijklmn:,123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the underscore in the identifier",
			src:  "AstraCS:0123456789ab^defghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the byte before the underscore where the secret closes",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq^",
		},
		{
			// The two characters standard base64 adds that base64url does not,
			// which are what the rationale stops the widening short of. The
			// solidus is the third and is driven at all six positions above,
			// being the byte in front of the first digit.
			name: "a plus where the identifier opens",
			src:  "AstraCS:+123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "a plus where the secret closes",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq+",
		},
		{
			name: "an equals sign where the identifier closes",
			src:  "AstraCS:0123456789abcdefghijklm=:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "an equals sign where the secret opens",
			src:  "AstraCS:0123456789abcdefghijklmn:=123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			// The counts are what put the divider where the scan reads it, so
			// an identifier of any other width moves it and nothing stands
			// there. The short one is followed by a space, which is what makes
			// it a token the text turned away rather than one the end of the
			// input cut short.
			name: "an identifier one character short of the count",
			src:  "AstraCS:0123456789abcdefghijklm:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr ",
		},
		{
			name: "an identifier one character past the count",
			src:  "AstraCS:0123456789abcdefghijklmno:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "a character of the alphabet where the divider stands",
			src:  "AstraCS:0123456789abcdefghijklmn00123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "a secret one character short of the count",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq ",
		},
		{
			// The prefix is read as DataStax writes it, and it is the whole of
			// what tells a token from two runs written against a colon.
			name: "a lowercase prefix",
			src:  "astracs:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "an uppercase prefix",
			src:  "ASTRACS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "one character of the prefix",
			src:  "AstraGS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "a hyphen where the prefix closes on its colon",
			src:  "AstraCS-0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the body of a token with no prefix in front of it",
			src:  "0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "a space in the identifier",
			src:  "AstraCS:0123456789ab defghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "a token broken by a line break",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuv\nxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AstraDBApplicationToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_AstraDBApplicationToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "ASTRA_DB_APPLICATION_TOKEN=AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			want: "ASTRA_DB_APPLICATION_TOKEN=*************************************************************************************************",
		},
		{
			name: "a token on the command line the cli takes one on",
			src:  "astra db list --token AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			want: "astra db list --token *************************************************************************************************",
		},
		{
			name: "a token in a bearer header",
			src:  "Authorization: Bearer AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			want: "Authorization: Bearer *************************************************************************************************",
		},
		{
			name: "a token in json",
			src:  `{"token":"AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr"}`,
			want: `{"token":"*************************************************************************************************"}`,
		},
		{
			name: "a token in a container environment",
			src:  "docker run -e ASTRA_DB_APPLICATION_TOKEN=AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr app",
			want: "docker run -e ASTRA_DB_APPLICATION_TOKEN=************************************************************************************************* app",
		},
		{
			name: "twice",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			want: "************************************************************************************************* *************************************************************************************************",
		},
	}

	m := New(WithPatterns(AstraDBApplicationToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AstraDBApplicationToken_nextToWordCharacters(t *testing.T) {
	// Nothing is asked of the character either side of a token. A boundary in
	// front would drop rather than trim the match wherever a token is written
	// against a word character, and the counts being exact are what leave
	// whatever follows a token in the text.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xAstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			want: "x*************************************************************************************************",
		},
		{
			name: "underscore before",
			src:  "ASTRA_DB_APPLICATION_TOKEN_AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			want: "ASTRA_DB_APPLICATION_TOKEN_*************************************************************************************************",
		},
		{
			name: "a character of the alphabet after",
			src:  "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrs",
			want: "*************************************************************************************************s",
		},
		{
			// A multi-byte rune is no word character, but it is worth pinning
			// beside the two above: nothing about a boundary is asked of it
			// either, in front or behind.
			name: "a multi-byte rune before and after",
			src:  "日本語AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr日本語",
			want: "日本語*************************************************************************************************日本語",
		},
		{
			name: "an invalid utf-8 byte before",
			src:  "\xffAstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			want: "\xff*************************************************************************************************",
		},
	}

	m := New(WithPatterns(AstraDBApplicationToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AstraDBApplicationToken_aPlaceholderBody(t *testing.T) {
	// What this pattern over-matches on, held to being redacted rather than
	// spared. A page of documentation writing the prefix and two runs of one
	// repeated character is a token's format character for character, and
	// nothing is left in the text to tell the two apart. Declining it would
	// mean declining every real token of the same shape, since a scan cannot
	// read who minted a run.
	//
	// These halves are one repeated character, which no ordered run can state.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "halves of zeroes",
			src:  "ASTRA_DB_APPLICATION_TOKEN=AstraCS:000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000",
			want: "ASTRA_DB_APPLICATION_TOKEN=*************************************************************************************************",
		},
		{
			name: "halves of ones",
			src:  "ASTRA_DB_APPLICATION_TOKEN=AstraCS:111111111111111111111111:1111111111111111111111111111111111111111111111111111111111111111",
			want: "ASTRA_DB_APPLICATION_TOKEN=*************************************************************************************************",
		},
	}

	m := New(WithPatterns(AstraDBApplicationToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AstraDBApplicationToken_theHalvesThatCarryNoPrefix(t *testing.T) {
	// The live credentials this pattern leaves in the output, held to being
	// left there rather than quietly forgotten.
	// builtin_astra_db_application_token.go weighs the decline; this is what it
	// costs.
	//
	// DataStax issues a client identifier and a secret as well as the token
	// that bundles them, and either half written on its own carries no opening
	// at all. Twenty-four characters of this alphabet are a word of an
	// identifier and sixty-four are any encoded blob, so a pattern reading one
	// would redact text a reader has every reason to see.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a client identifier on its own",
			src:  "clientId=0123456789abcdefghijklmn",
		},
		{
			name: "a secret on its own",
			src:  "secret=0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
		},
		{
			name: "the pair written as two fields",
			src:  `{"clientId":"0123456789abcdefghijklmn","secret":"0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr"}`,
		},
	}

	m := New(WithPatterns(AstraDBApplicationToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_AstraDBApplicationToken_aTokenBeginningInsideAnother(t *testing.T) {
	// The input the default step is load-bearing on, rather than merely
	// correct. A half carries no colon, so the only colon a second candidate
	// can open against inside the first is the divider, and what stands in
	// front of the divider here is the prefix: a candidate opens seventeen
	// characters into the identifier.
	//
	// The outer candidate is no token — it reads its own divider where the
	// inner prefix closes, and the colon that then falls inside its secret
	// turns it away — so the token this text holds is the inner one, and a scan
	// consuming its match would have stepped over it.
	//
	// The identifier's last seven characters are the prefix and the run stands
	// in front of them, which is the one place a half here is written from
	// anything but the run alone.
	src := "AstraCS:0123456789abcdefgAstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr"
	want := []Span{{25, 122}}

	if got, _ := AstraDBApplicationToken().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}
}

func Test_AstraDBApplicationToken_holdsATokenTheInputCutShort(t *testing.T) {
	// What Find's second return settles. builtin_scan.go and the rationale in
	// builtin_astra_db_application_token.go give two shapes: a piece of the
	// prefix standing at the end of the input, and a candidate the end of the
	// input cut short. Everything else is settled to the end of the input: the
	// counts are exact and no boundary is asked behind a match, so a candidate
	// that fits inside the input is decided by the text and nothing arriving
	// later can change it.
	//
	// A span being settled is not the same as the text it stands in being
	// settled, and the last case here is where the two part. A candidate can
	// open inside another, so a token reported whole at the front of the input
	// can still leave everything from that inner candidate on unsettled — which
	// is the second shape again rather than a third of its own.
	tests := []struct {
		name   string
		src    string
		retain int
	}{
		{
			// No prefix and no piece of one anywhere in the text, so the whole
			// of it is settled.
			name:   "no credential at all",
			src:    "there is no credential in this sentence",
			retain: len("there is no credential in this sentence"),
		},
		{
			// The last five characters of the input are a piece of the prefix,
			// so what comes next could still complete it: the text from there
			// on is held.
			name:   "a piece of the prefix at the end of the input",
			src:    "xxx Astra",
			retain: 4,
		},
		{
			// A candidate whose body the end of the input cut short. What comes
			// next may carry it to the counts and the divider, so the
			// candidate's start is held rather than settled.
			name:   "a candidate the input cut short",
			src:    "xxx AstraCS:0123456789",
			retain: 4,
		},
		{
			// The same candidate one character short of the count, which is the
			// last offset the end of the input can still decide.
			name:   "a candidate one character short of the count",
			src:    "xxx AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq",
			retain: 4,
		},
		{
			// A whole token, with nothing behind it that could widen the span.
			// The counts are exact, so the token is reported and the input is
			// settled to the end.
			name:   "a whole token at the end of the input",
			src:    "xxx AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			retain: len("xxx AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr"),
		},
		{
			// A candidate rejected by the text rather than by the end of it: an
			// identifier a character too long moves the divider off the offset
			// the counts put it at, so nothing arriving behind it could make a
			// token of this and the whole input is settled.
			name:   "a candidate the text turned away",
			src:    "xxx AstraCS:0123456789abcdefghijklmno:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			retain: len("xxx AstraCS:0123456789abcdefghijklmno:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr"),
		},
		{
			// A whole token whose identifier closes on the prefix, so a second
			// candidate opens twenty-five characters into it and the end of the
			// input cuts that one short. The token is reported and the text
			// from the inner candidate on is held: what more text could still
			// carry that candidate to is a token the redaction of this one
			// would have written over.
			name:   "a candidate the input cut short inside a whole token",
			src:    "AstraCS:0123456789abcdefgAstraCS:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			retain: 25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, retain := AstraDBApplicationToken().Find(tt.src); retain != tt.retain {
				t.Errorf("Find(%q) retain = %d, want %d", tt.src, retain, tt.retain)
			}
		})
	}
}

// Test_astraDBApplicationTokenAnchor holds the prefix to carrying the byte the
// scan searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_astraDBApplicationTokenAnchor(t *testing.T) {
	if len(astraDBApplicationTokenPrefix) <= astraDBApplicationTokenAnchorIndex {
		t.Fatalf("the prefix %q is %d characters where the scan reads its anchor at %d", astraDBApplicationTokenPrefix, len(astraDBApplicationTokenPrefix), astraDBApplicationTokenAnchorIndex)
	}
	if c := astraDBApplicationTokenPrefix[astraDBApplicationTokenAnchorIndex]; c != astraDBApplicationTokenAnchor {
		t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", astraDBApplicationTokenPrefix, c, byte(astraDBApplicationTokenAnchor))
	}
}

// Test_astraDBApplicationTokenChars holds the prefix, the two counts and the
// divider between the halves to the length the Astra CLI states a token has and
// refuses one for not having. The parts are what the scan reads and the total
// is what the vendor wrote down, so a count edited here without the total
// moving is a count that has parted from the format with nothing else to report
// it.
func Test_astraDBApplicationTokenChars(t *testing.T) {
	if got := len(astraDBApplicationTokenPrefix) + astraDBApplicationTokenClientIDChars + 1 + astraDBApplicationTokenSecretChars; got != 97 {
		t.Errorf("the prefix, the halves and the divider come to %d characters where the vendor states 97", got)
	}
	if astraDBApplicationTokenChars != 97 {
		t.Errorf("the scan reads a token of %d characters where the vendor states 97", astraDBApplicationTokenChars)
	}
}

// Test_astraDBApplicationTokenDivider holds the divider to being a character
// neither half can carry. Were it one of the alphabet, the offset the scan
// finds it at would say nothing — a candidate would keep whatever character
// stood there and the counts alone would decide it — and the rationale's
// sentence about a run of the alphabet carrying no colon would be wrong with
// nothing else reporting it.
func Test_astraDBApplicationTokenDivider(t *testing.T) {
	if isAstraDBApplicationTokenRun(string(byte(astraDBApplicationTokenDivider))) {
		t.Errorf("the divider %q belongs to the alphabet the halves are read in, so a half could carry one", byte(astraDBApplicationTokenDivider))
	}
	if c := astraDBApplicationTokenPrefix[len(astraDBApplicationTokenPrefix)-1]; c != astraDBApplicationTokenDivider {
		t.Errorf("the prefix closes on %q where the divider is %q, so no prefix can be read as closing a body", c, byte(astraDBApplicationTokenDivider))
	}
}

// Test_astraDBApplicationTokenFindBenchmarks_lineTheAnchorWasChosenAgainst
// holds the line the benchmarks are written on to the counts the rationale
// reads the anchor choice off. Those counts are the whole of the evidence for
// searching on the C rather than on one of the other seven bytes of the prefix,
// and nothing else reports them: a word added to that line with a C in it
// falsifies the sentence in silence, since every benchmark goes on timing
// whatever the line became.
func Test_astraDBApplicationTokenFindBenchmarks_lineTheAnchorWasChosenAgainst(t *testing.T) {
	var line string
	for _, c := range astraDBApplicationTokenFindBenchmarks() {
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
		{astraDBApplicationTokenAnchor, 0},
		{'A', 1},
		{'S', 1},
		{'s', 10},
		{'t', 9},
		{'r', 3},
		{'a', 7},
		{astraDBApplicationTokenDivider, 2},
	} {
		if got := strings.Count(line, string([]byte{tt.c})); got != tt.want {
			t.Errorf("the line carries %q %d times, the rationale reads the anchor off %d", tt.c, got, tt.want)
		}
	}
}

func Test_AstraDBApplicationToken_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a line dense in prefixes
	// holds a candidate for every character it has. What keeps that linear is
	// the counts being counts: a candidate reads at most ninety-seven bytes and
	// stops, whatever stands behind it. The bound here is far above a linear
	// scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every ninety-seven bytes where they are densest, because a
	// sample has to carry a whole token to be one. The crowding a line can
	// actually carry stays here.
	sources := map[string]string{
		// Candidates as close together as a whole prefix allows, none of them
		// with a body behind it: every one reaches the walk over the body and
		// every one is turned away at the divider.
		"a candidate every eight characters": strings.Repeat("AstraCS:", 240000),
		// Tokens written one against the next, so every candidate is a token
		// and every one of them walks both halves whole.
		"a token against every token": strings.Repeat("AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr", 20000),
		// An anchor at every other byte with nothing in front of it that opens
		// a prefix, which is the cheapest way a position is declined: the
		// prefix read back and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("aC", 900000),
		// One token and then a run of the body's own alphabet the length of the
		// line. The anchor belongs to that alphabet, so this is the shape the
		// rationale says the choice costs: the search stops about once in
		// sixty-four characters and is turned away by one comparison each time.
		"a run of the alphabet the length of the line": "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr" + strings.Repeat("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 30000),
		// The divided shape this scan reads, written over and over with no
		// prefix among it, which is a line dense in the layout and holding no
		// anchor at all.
		"a divided run every ninety characters": strings.Repeat("0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr ", 20000),
		// And the prefix's own characters with the anchor taken out, which is
		// the search reading a whole line and stopping nowhere in it.
		"the prefix with its anchor taken out": strings.Repeat("AstraS:", 270000),
	}

	checkScanIsLinear(t, AstraDBApplicationToken(), sources)
}

// referenceAstraDBApplicationToken is the expression the scan in
// builtin_astra_db_application_token.go reads by hand: the statement of what an
// Astra DB application token is, kept here so that the scan can be held to it.
//
// The prefix, the two counts, the divider between the halves and the character
// class are spelled again rather than built from
// astraDBApplicationTokenPrefix, astraDBApplicationTokenClientIDChars,
// astraDBApplicationTokenSecretChars, astraDBApplicationTokenDivider and
// isAstraDBApplicationTokenRun. A reference sharing those declarations could
// not disagree with the scan about them, and it is exactly that disagreement
// the fuzz target below is for: the two have to be changed together or reported
// apart.
//
// Both repetitions are exact, so the machine an engine builds is read once and
// stops rather than being as wide as a floor at every candidate. The prefix is
// an eight-character literal in front of the grammar besides, closing on a
// character no half can carry, so an engine searching the text for that literal
// finds it nowhere in a run of the alphabet.
var referenceAstraDBApplicationToken = regexp.MustCompile(`AstraCS:[0-9A-Za-z_-]{24}:[0-9A-Za-z_-]{64}`)

// referenceAstraDBApplicationTokenFind locates tokens the plain way: the
// leftmost match of the expression above, then the leftmost one beginning after
// that match's first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this. It resumes past a
// match, and the scan it checks resumes one byte along — so a reference written
// that way would agree with the scan only while no token can begin inside
// another, which is a thing the scan claims and a reference may take nothing on
// trust.
func referenceAstraDBApplicationTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceAstraDBApplicationToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzAstraDBApplicationToken_matchesReference guards the hand-written scan:
// the prefix it searches back from, the counts it cuts the halves by, the
// divider it reads between them, the alphabet it walks them in and the byte it
// resumes at may none of them change which tokens are located.
func FuzzAstraDBApplicationToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("ASTRA_DB_APPLICATION_TOKEN=AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	// The two characters base64url adds to base62, in each half.
	f.Add("AstraCS:0123456789ab-defghijklmn:0123456789abcdefghijklmnopqrstuv_xyz0123456789abcdefghijklmnopqr")
	f.Add("AstraCS:0123456789ab_defghijklmn:0123456789abcdefghijklmnopqrstuv-xyz0123456789abcdefghijklmnopqr")
	// The ends of the alphabet at all four places a half begins or closes.
	f.Add("AstraCS:00123456789abcdefghijkl0:00123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop0")
	f.Add("AstraCS:90123456789abcdefghijkl9:90123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop9")
	f.Add("AstraCS:A0123456789abcdefghijklA:A0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopA")
	f.Add("AstraCS:Z0123456789abcdefghijklZ:Z0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopZ")
	f.Add("AstraCS:a0123456789abcdefghijkla:a0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopa")
	f.Add("AstraCS:z0123456789abcdefghijklz:z0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopz")
	f.Add("AstraCS:-0123456789abcdefghijkl-:-0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop-")
	f.Add("AstraCS:_0123456789abcdefghijkl_:_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop_")
	// The bytes just outside those ends, at each end and the middle of each
	// half, which is where a bound written one too wide would show.
	f.Add("AstraCS:/123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("AstraCS:0123456789abcdefghijklm/:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("AstraCS:0123456789abcdefghijklmn:/123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq/")
	f.Add("AstraCS:0123456789ab@defghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("AstraCS:0123456789abcdefghijklm[:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("AstraCS:0123456789abcdefghijklmn:`123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuv{xyz0123456789abcdefghijklmnopqr")
	// The counts and the divider they put in place.
	f.Add("AstraCS:0123456789abcdefghijklm:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr ")
	f.Add("AstraCS:0123456789abcdefghijklmno:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("AstraCS:0123456789abcdefghijklmn00123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq ")
	f.Add("AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrs")
	f.Add("AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuv:xyz0123456789abcdefghijklmnopqr")
	// The prefix written otherwise, and the body with none in front of it.
	f.Add("astracs:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("ASTRACS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("AstraGS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("AstraCS-0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	// A prefix in front of a token, where the divider of the first candidate
	// falls on the second prefix.
	f.Add("AstraCS:AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	// An identifier closing on the prefix, which is the one place a candidate
	// can open inside another: whole, and cut short by the end of the input.
	f.Add("AstraCS:0123456789abcdefgAstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("AstraCS:0123456789abcdefgAstraCS:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	// The bytes either side of the hyphen and the underscore, and the two
	// characters standard base64 adds that base64url does not.
	f.Add("AstraCS:.123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("AstraCS:0123456789abcdefghijklm,:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("AstraCS:0123456789ab^defghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("AstraCS:+123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("AstraCS:0123456789abcdefghijklmn:=123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	// The placeholder a page of documentation writes, which this pattern
	// redacts.
	f.Add("ASTRA_DB_APPLICATION_TOKEN=AstraCS:000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000")
	// Tokens written against word characters at either end, which no boundary
	// is asked of.
	f.Add("xAstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("ASTRA_DB_APPLICATION_TOKEN_AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	// Candidate positions crowded as close as they can be, with no body behind
	// any of them, and tokens written one against the next.
	f.Add(strings.Repeat("AstraCS:", 16))
	f.Add(strings.Repeat("aC", 16))
	f.Add(strings.Repeat("AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr", 4))
	f.Add("AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr\nAstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	// Candidates the end of the input cuts short in each of the places it can,
	// and one the text turned away.
	f.Add("xxx Astra")
	f.Add("xxx AstraCS:0123456789")
	f.Add("xxx AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq")
	f.Add("xxx AstraCS:0123456789abcdefghijklmno:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")

	fuzzAgainstReference(f, AstraDBApplicationToken().Find, referenceAstraDBApplicationTokenFind)
}

// astraDBApplicationTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func astraDBApplicationTokenFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens a prefix, so what the line times is the
	// search for the anchor — which is most of what this pattern costs a caller
	// whose text holds no token. It is the line the rationale's count of the
	// eight characters a prefix is written with is taken over.
	line := `time=2026-09-14T00:00:00Z level=info msg="Astra DB request finished" method=POST path=/api/rest/v2/keyspaces/default_keyspace status=200 `
	token := "AstraCS:0123456789abcdefghijklmn:0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A whole prefix every eight characters with no body behind any of
			// them: each reaches the walk over the body and each is turned away
			// at the divider.
			name:  "candidates that are not values",
			src:   strings.Repeat("AstraCS:", 128),
			spans: 0,
		},
		{
			// The same crowding one step earlier: an anchor at every other byte
			// with nothing in front of it that opens a prefix, so each
			// candidate is declined by the comparison of the prefix.
			name:  "candidates declined at their prefix",
			src:   strings.Repeat("aC", 128),
			spans: 0,
		},
		{
			// A run of the body's own alphabet, which the anchor belongs to, so
			// the search stops in it about once in sixty-four characters. This
			// is what the rationale says the choice of anchor costs.
			name:  "a run of the alphabet holding no prefix",
			src:   strings.Repeat("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 8),
			spans: 0,
		},
		{
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
