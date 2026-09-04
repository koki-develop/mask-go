package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Databricks OAuth client secret pattern: what it locates and what it
// leaves alone, written out case by case, and the reference its scan is held
// to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a set
// of tests apiece.
//
// The secrets written out below are made only of ordered characters: valid in
// shape, obviously not real. A body is thirty-two hexadecimal characters,
// written here as 0123456789abcdef twice over, which with the prefix in front
// comes to thirty-six characters. Where a case turns on what a body may close
// on, it closes one on d instead.

func Test_DatabricksOAuthClientSecret(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a secret on its own",
			src:  "dose0123456789abcdef0123456789abcdef",
			want: []Span{{0, 36}},
		},
		{
			name: "a secret in an environment assignment",
			src:  "DATABRICKS_CLIENT_SECRET=dose0123456789abcdef0123456789abcdef",
			want: []Span{{25, 61}},
		},
		{
			// The count is read exactly, so what follows the thirty-sixth
			// character is not part of the secret and stays in the text.
			name: "a run longer than the count is a secret and what follows it",
			src:  "dose0123456789abcdef0123456789abcdef0",
			want: []Span{{0, 36}},
		},
		{
			name: "two secrets with nothing between them",
			src:  "dose0123456789abcdef0123456789abcdefdose0123456789abcdef0123456789abcdef",
			want: []Span{{0, 36}, {36, 72}},
		},
		{
			// The prefix written twice over. The o of the second closes the
			// body of the candidate the first opens, since it is no character a
			// body is written with, so the secret is the one the second opens.
			name: "a prefix in front of a secret",
			src:  "dosedose0123456789abcdef0123456789abcdef",
			want: []Span{{4, 40}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksOAuthClientSecret().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DatabricksOAuthClientSecret_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "dose",
		},
		{
			name: "a body one character short",
			src:  "dose0123456789abcdef0123456789abcde",
		},
		{
			name: "a body broken by a space",
			src:  "dose0123456789abcdef 123456789abcdef",
		},
		{
			name: "a letter outside hexadecimal in the body",
			src:  "dose0123456789abcdefg123456789abcdef",
		},
		{
			// The case the environment variable holding a secret is spelled in,
			// which is one reason the prefix is read in a single case.
			name: "an uppercase prefix",
			src:  "DOSE0123456789abcdef0123456789abcdef",
		},
		{
			name: "the prefix without its closing letter",
			src:  "dos0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a hyphen inside the prefix",
			src:  "do-se0123456789abcdef0123456789abcdef",
		},
		{
			// The personal access token Databricks issues, which carries a
			// prefix of its own and no dose to be found at.
			name: "a personal access token",
			src:  "dapi0123456789abcdef0123456789abcdef",
		},
		{
			name: "a body of the right shape opening with no prefix",
			src:  "xxxx0123456789abcdef0123456789abcdef",
		},
		{
			name: "a digest with no prefix",
			src:  "md5=0123456789abcdef0123456789abcdef",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "a log line",
			src:  `time=2026-08-17T00:00:00Z level=info msg="requesting a token" url=https://dbc-01234567-89ab.cloud.databricks.com/oidc/v1/token`,
		},
		{
			name: "the workspace host a secret authenticates against",
			src:  "DATABRICKS_HOST=https://dbc-01234567-89ab.cloud.databricks.com",
		},
		{
			// The client ID a secret is written beside, which is a UUID and
			// carries no prefix.
			name: "the client id a secret stands with",
			src:  "DATABRICKS_CLIENT_ID=01234567-89ab-cdef-0123-456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksOAuthClientSecret().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DatabricksOAuthClientSecret_inContext(t *testing.T) {
	// The places a secret is written, which are the places Databricks' own
	// documentation puts one: the environment the SDKs read it from, the
	// profile the CLI writes it to, the body of the token request it is
	// exchanged in, the command line that request may be made from, the
	// property a JDBC connection takes it as and the field the account API
	// returns it in.
	const secret = "dose0123456789abcdef0123456789abcdef"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a secret in an environment assignment",
			src:  "DATABRICKS_CLIENT_SECRET=" + secret,
			want: []Span{{25, 25 + len(secret)}},
		},
		{
			name: "a secret in the profile the cli writes",
			src:  "[DEFAULT]\nhost = https://dbc-01234567-89ab.cloud.databricks.com\nclient_secret = " + secret,
			want: []Span{{80, 80 + len(secret)}},
		},
		{
			name: "a secret in the body of a token request",
			src:  "grant_type=client_credentials&scope=all-apis&client_secret=" + secret,
			want: []Span{{59, 59 + len(secret)}},
		},
		{
			name: "a secret on a command line",
			src:  "curl -X POST -d client_id=01234567-89ab-cdef-0123-456789abcdef -d client_secret=" + secret + " https://dbc-01234567-89ab.cloud.databricks.com/oidc/v1/token",
			want: []Span{{80, 80 + len(secret)}},
		},
		{
			name: "a secret in a jdbc connection string",
			src:  "jdbc:databricks://dbc-01234567-89ab.cloud.databricks.com:443/default;OAuth2Secret=" + secret,
			want: []Span{{82, 82 + len(secret)}},
		},
		{
			name: "a secret in the json the account api returns",
			src:  `{"secret":"` + secret + `"}`,
			want: []Span{{11, 11 + len(secret)}},
		},
		{
			name: "a secret at the end of a sentence",
			src:  "the secret is " + secret + ".",
			want: []Span{{14, 14 + len(secret)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksOAuthClientSecret().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DatabricksOAuthClientSecret_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match. A word boundary in front
	// would drop the whole match rather than trim it wherever a secret is
	// written against a word character, and one behind it would drop a secret
	// followed by a letter or a digit.
	const secret = "dose0123456789abcdef0123456789abcdef"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a secret after an underscore",
			src:  "DATABRICKS_CLIENT_SECRET_" + secret,
			want: []Span{{25, 25 + len(secret)}},
		},
		{
			name: "a secret after a letter",
			src:  "x" + secret,
			want: []Span{{1, 1 + len(secret)}},
		},
		{
			name: "a word written against a secret",
			src:  secret + "suffix",
			want: []Span{{0, len(secret)}},
		},
		{
			name: "a hyphenated word written against a secret",
			src:  secret + "-suffix",
			want: []Span{{0, len(secret)}},
		},
		{
			name: "a digit written against a secret",
			src:  secret + "2",
			want: []Span{{0, len(secret)}},
		},
		{
			// A multi-byte rune flush against the secret on both sides, with
			// no space between them.
			name: "a multi-byte rune flush against the secret on both sides",
			src:  "日本語" + secret + "日本語",
			want: []Span{{9, 9 + len(secret)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksOAuthClientSecret().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DatabricksOAuthClientSecret_aTitleCasePrefix(t *testing.T) {
	// The prefix is read in the one case Databricks' own scanner and every
	// partner's documentation writes it in. Only the wholly uppercase spelling
	// is driven elsewhere in this file; a prefix capitalised in part is driven
	// here.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a title case prefix",
			src:  "Dose0123456789abcdef0123456789abcdef",
		},
		{
			name: "one uppercase character in the prefix",
			src:  "doSe0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksOAuthClientSecret().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DatabricksOAuthClientSecret_aBodyOfOneClassAlone(t *testing.T) {
	// Every body written elsewhere in this file is the ordered run
	// 0123456789abcdef, which carries both digits and hexadecimal letters at
	// once. A body of one class alone is asserted nowhere, so each is written
	// out here.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a body of digits alone",
			src:  "dose01234567890123456789012345678901",
			want: []Span{{0, 36}},
		},
		{
			name: "a body of hexadecimal letters alone",
			src:  "doseabcdefabcdefabcdefabcdefabcdefab",
			want: []Span{{0, 36}},
		},
		{
			name: "a body of one repeated character",
			src:  "dose" + strings.Repeat("a", 32),
			want: []Span{{0, 36}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksOAuthClientSecret().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DatabricksOAuthClientSecret_anUppercaseBody(t *testing.T) {
	// The alphabet is lowercase hexadecimal. A hexadecimal encoder settles the
	// case once for all of its output rather than varying it between secrets,
	// so admitting the other case would widen the net for a credential neither
	// Databricks nor a ruleset states, and these are the cases that would move
	// if it were taken.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "an uppercase body",
			src:  "dose0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "a body mixing the two cases",
			src:  "dose0123456789ABCDEF0123456789abcdef",
		},
		{
			name: "one uppercase character in a body",
			src:  "dose0123456789abcdef0123456789abcdeF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksOAuthClientSecret().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DatabricksOAuthClientSecret_aWiderAlphabet(t *testing.T) {
	// The widening the pattern's own file declines: a body read as any
	// thirty-two of the letters, the digits, the underscore, the dot and the
	// hyphen rather than as thirty-two hexadecimal characters. These are the
	// inputs that would move if it were taken, and the last of them is why it
	// is not — the prefix is a word, so a hyphenated phrase reaches the count
	// as readily as a secret does.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a dot in the body",
			src:  "dose0123456789abcdef.123456789abcdef",
		},
		{
			name: "a hyphen in the body",
			src:  "dose0123456789abcdef-123456789abcdef",
		},
		{
			name: "an underscore in the body",
			src:  "dose0123456789abcdef_123456789abcdef",
		},
		{
			name: "a body of letters outside hexadecimal",
			src:  "doseghijklmnopqrstuvwxyzghijklmnopqrs",
		},
		{
			name: "a hyphenated phrase reaching the count",
			src:  "dose-response-curve-analysis-2024-v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksOAuthClientSecret().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DatabricksOAuthClientSecret_aDigestBehindThePrefix(t *testing.T) {
	// The collision this format leaves. Thirty-two lowercase hexadecimal
	// characters behind the prefix is the vendor's format exactly, and an MD5
	// is thirty-two of them, so the prefix written straight in front of one is a
	// secret character for character. A longer digest is redacted for thirty-six
	// characters with the rest left in the text, and a digest on its own carries
	// no prefix and reaches nothing.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an md5 behind the prefix",
			src:  "dose0123456789abcdef0123456789abcdef",
			want: []Span{{0, 36}},
		},
		{
			name: "a sha-1 behind the prefix",
			src:  "dose0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 36}},
		},
		{
			name: "a sha-256 behind the prefix",
			src:  "dose0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 36}},
		},
		{
			// A UUID is thirty-two hexadecimal characters divided by hyphens,
			// and a hyphen is no character a body is written with.
			name: "a uuid behind the prefix",
			src:  "dose01234567-89ab-cdef-0123-456789abcdef",
			want: nil,
		},
		{
			name: "an md5 on its own",
			src:  "md5=0123456789abcdef0123456789abcdef",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksOAuthClientSecret().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DatabricksOAuthClientSecret_aSecretInsideASecret(t *testing.T) {
	// A secret can be written inside another, which is why the scan resumes a
	// byte past the start of a candidate rather than past the candidate. The s a
	// candidate is read back from stands two characters into a prefix and
	// nowhere else in a secret, so the positions inside one that could open a
	// candidate are the last two characters of a body — and the o rules out the
	// earlier of those two, since a candidate opening there would write the o as
	// the last character of the body it stands in and no body holds one. What is
	// left is a secret beginning at the last character of another, where the
	// spans overlap and Masker.locate resolves them.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// A body closing on d, with the ose that completes the prefix
			// written after the secret that body closes.
			name: "a secret beginning at the last character of another",
			src:  "dose0123456789abcdef0123456789abcdedose0123456789abcdef0123456789abcdef",
			want: []Span{{0, 36}, {35, 71}},
		},
		{
			// The same opening with nothing behind it long enough to be a body,
			// so the secret in front of it is the one there is.
			name: "a body closing on d that opens no secret",
			src:  "dose0123456789abcdef0123456789abcdedose0123456789",
			want: []Span{{0, 36}},
		},
		{
			// The position the o rules out. A prefix written two characters from
			// where a body would end puts that o where the body's last character
			// would stand, which ends the candidate in front of it, so the
			// secret is the one that prefix opens.
			name: "a prefix written two characters from the end of a body",
			src:  "dose0123456789abcdef0123456789abcddose0123456789abcdef0123456789abcdef",
			want: []Span{{34, 70}},
		},
		{
			// The prefix written where a body would hold it further back. The o
			// it carries is no character a body may hold, so the candidate in
			// front of it ends there and the secret is the one that prefix
			// opens.
			name: "a prefix written where a body would stand",
			src:  "dose0123456789abcdose0123456789abcdef0123456789abcdef",
			want: []Span{{17, 53}},
		},
		{
			name: "two secrets with nothing between them",
			src:  "dose0123456789abcdef0123456789abcdefdose0123456789abcdef0123456789abcdef",
			want: []Span{{0, 36}, {36, 72}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DatabricksOAuthClientSecret().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DatabricksOAuthClientSecret_settlesAWholeSecret(t *testing.T) {
	// Nothing is read behind the count, so a secret reaching the end of the
	// input is finished and settles as it stands — with one exception the
	// prefix puts there. A body may close on the character a prefix opens with,
	// and a d standing last is a piece of a prefix, so what is held back is that
	// one character rather than the secret in front of it. What every built-in
	// owes about that offset is driven over the samples and over generated text
	// in builtins_test.go and fuzz_test.go; what is written out here is which
	// inputs of this format hold anything back at all, since nothing else names
	// them.
	const secret = "dose0123456789abcdef0123456789abcdef"

	tests := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "a secret reaching the end of the input",
			src:  secret,
			want: len(secret),
		},
		{
			name: "a secret whose last character opens a prefix",
			src:  "dose0123456789abcdef0123456789abcded",
			want: 35,
		},
		{
			name: "a secret followed by a character that opens nothing",
			src:  secret + " ",
			want: len(secret) + 1,
		},
		{
			name: "a body the end of the input cut short",
			src:  "dose0123456789abcdef",
			want: 0,
		},
		{
			name: "the prefix the end of the input cut short",
			src:  "dos",
			want: 0,
		},
		{
			name: "a body cut short held from its own start rather than from further back",
			src:  "DATABRICKS_CLIENT_SECRET=dose0123456789abcdef",
			want: 25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, got := DatabricksOAuthClientSecret().Find(tt.src); got != tt.want {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, got, tt.want)
			}
		})
	}
}

// Test_DatabricksOAuthClientSecret_scanIsLinear drives the crowding this scan
// is most exposed to: the prefix carries two characters of its own body
// alphabet, d and e, so a run built from the prefix repeated crowds candidates
// close together, and the scan reads a fixed count at each rather than keeping
// a cursor, so nothing here is expected to cost more than that count times the
// number of candidates.
func Test_DatabricksOAuthClientSecret_scanIsLinear(t *testing.T) {
	checkScanIsLinear(t, DatabricksOAuthClientSecret(), map[string]string{
		"a prefix every four characters":       strings.Repeat("dose", 500000),
		"an anchor with no prefix behind it":   strings.Repeat("s", 2000000),
		"a hexadecimal run with no prefix":     strings.Repeat("0123456789abcdef", 125000),
		"a secret every thirty-six characters": strings.Repeat("dose0123456789abcdef0123456789abcdef", 55000),
	})
}

func Test_databricksOAuthClientSecretPrefix(t *testing.T) {
	// The prefix is the whole of what tells this format from text, and two of
	// its four characters stand outside the alphabet a body is written in. That
	// is what makes the search cheap on a line of digests — a run of the body
	// alphabet opens no candidate however long it runs — and it is what bounds
	// where a secret may begin inside another, which the count below is of.
	if got := databricksOAuthClientSecretPrefix; got != "dose" {
		t.Errorf("databricksOAuthClientSecretPrefix = %q, want %q", got, "dose")
	}
	outside := 0
	for i := range len(databricksOAuthClientSecretPrefix) {
		if !isDatabricksOAuthClientSecretBodyByte(databricksOAuthClientSecretPrefix[i]) {
			outside++
		}
	}
	if want := 2; outside != want {
		t.Errorf("%d character(s) of the prefix stand outside the body alphabet, want %d", outside, want)
	}

	// Where a secret may begin inside another, counted out of the declarations
	// that decide it rather than claimed in prose. Two things have to hold at a
	// position for a candidate to open there. The anchor reading it back must
	// fall past the end of the span, since the only anchor a secret carries is
	// the one in its own prefix; and every character of the prefix that lands
	// inside the span must be one a body may hold, since those characters are
	// the body's as well. The second is what leaves one position rather than
	// two. A prefix lengthened, an anchor moved, a count changed or a body
	// admitting another character moves the number, and nothing else here would
	// report it.
	inside := 0
	for p := 1; p < databricksOAuthClientSecretChars; p++ {
		if p+databricksOAuthClientSecretAnchorIndex < databricksOAuthClientSecretChars {
			continue
		}
		holds := true
		for i := 0; i < len(databricksOAuthClientSecretPrefix) && p+i < databricksOAuthClientSecretChars; i++ {
			if !isDatabricksOAuthClientSecretBodyByte(databricksOAuthClientSecretPrefix[i]) {
				holds = false
			}
		}
		if holds {
			inside++
		}
	}
	if want := 1; inside != want {
		t.Errorf("%d position(s) inside a secret can open a candidate, want %d", inside, want)
	}
}

func Test_databricksOAuthClientSecretAnchor(t *testing.T) {
	// The byte the scan searches for stands at the index it reads a candidate
	// back from. A prefix or an index changed without the other leaves the scan
	// opening candidates nowhere near where a secret begins, and what such a
	// scan finds is nothing at all rather than something wrong.
	if got := databricksOAuthClientSecretPrefix[databricksOAuthClientSecretAnchorIndex]; got != databricksOAuthClientSecretAnchor {
		t.Errorf("databricksOAuthClientSecretPrefix[%d] = %q, want the anchor %q",
			databricksOAuthClientSecretAnchorIndex, got, databricksOAuthClientSecretAnchor)
	}

	// What the anchor costs, counted rather than claimed in prose: it stands
	// once in the prefix, so a line of secrets stops the search once a secret,
	// and nowhere in a body, so a digest of any length stops it not at all. The
	// d and the e are the characters that would not do, and they are the reason
	// this one is worth counting: both are written in the body alphabet.
	if n := strings.Count(databricksOAuthClientSecretPrefix, string(databricksOAuthClientSecretAnchor)); n != 1 {
		t.Errorf("the anchor stands %d times in %q, want 1", n, databricksOAuthClientSecretPrefix)
	}
	if isDatabricksOAuthClientSecretBodyByte(databricksOAuthClientSecretAnchor) {
		t.Errorf("the anchor %q is a character a body may be written with", databricksOAuthClientSecretAnchor)
	}
}

func Test_databricksOAuthClientSecretChars(t *testing.T) {
	// The prefix and the thirty-two characters written behind it. Four
	// characters and thirty-two make a secret of thirty-six, and nothing is
	// read behind that.
	if got := len(databricksOAuthClientSecretPrefix); got != 4 {
		t.Errorf("len(databricksOAuthClientSecretPrefix) = %d, want 4", got)
	}
	if got := databricksOAuthClientSecretBodyChars; got != 32 {
		t.Errorf("databricksOAuthClientSecretBodyChars = %d, want 32", got)
	}
	if got := databricksOAuthClientSecretChars; got != 36 {
		t.Errorf("databricksOAuthClientSecretChars = %d, want 36", got)
	}
}

// referenceDatabricksOAuthClientSecret is the grammar as a regular expression:
// the prefix Databricks writes a secret with, the count read behind it and the
// lowercase alphabet that count is read in. Every part of it is spelled again
// rather than read from the scan, so that the two can disagree and the target
// below report it.
//
// It is built on an expression rather than written out because the count is
// exact, so an engine reads its machine once and stops, and because the opening
// is a literal an engine can search the text for rather than a class it would
// have to walk its machine at every byte for.
var referenceDatabricksOAuthClientSecret = regexp.MustCompile(`dose[0-9a-f]{32}`)

// referenceDatabricksOAuthClientSecretFind locates secrets the plain way: the
// leftmost match of the expression above, then the leftmost one beginning after
// that match's first byte, over and over, with nothing remembered between them.
//
// Asking at every byte rather than resuming past a match is what the scan does
// and is what a secret written inside another needs: a body may close on the
// character a prefix opens with, so a match can begin at the last character of
// the one before it, and resuming past the first would lose it.
func referenceDatabricksOAuthClientSecretFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceDatabricksOAuthClientSecret.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzDatabricksOAuthClientSecret_matchesReference guards the hand-written
// scan: the prefix it searches for, the case it reads that prefix and its body
// in, the count it reads behind the prefix and the byte it resumes at may none
// of them change which secrets are located.
func FuzzDatabricksOAuthClientSecret_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("DATABRICKS_CLIENT_SECRET=dose0123456789abcdef0123456789abcdef")
	f.Add("dose0123456789abcdef0123456789abcde")   // a body one character short
	f.Add("dose0123456789abcdef0123456789abcdef0") // and a run one longer
	f.Add("dose0123456789abcdef 123456789abcdef")  // a body broken by a space
	f.Add("dose0123456789abcdef.123456789abcdef")  // a dot in the body
	f.Add("dose0123456789abcdef-123456789abcdef")  // a hyphen in the body
	f.Add("dose0123456789abcdef_123456789abcdef")  // an underscore in the body
	f.Add("dose0123456789abcdefg123456789abcdef")  // a letter outside hexadecimal
	f.Add("dose0123456789abcdef\n123456789abcdef")
	f.Add("dose-response-curve-analysis-2024-v1") // a hyphenated phrase of the count
	f.Add("dose0123456789ABCDEF0123456789ABCDEF") // an uppercase body
	f.Add("dose0123456789abcdef0123456789abcdeF") // one uppercase character in one
	f.Add("DOSE0123456789abcdef0123456789abcdef") // an uppercase prefix
	f.Add("dos0123456789abcdef0123456789abcdef01")
	f.Add("xdose0123456789abcdef0123456789abcdef")
	// The other Databricks credential this pattern locates nothing in, a digest
	// behind the prefix, which it locates a secret in, and a UUID, which it does
	// not.
	f.Add("dapi0123456789abcdef0123456789abcdef")
	f.Add("dose0123456789abcdef0123456789abcdef01234567")
	f.Add("dose01234567-89ab-cdef-0123-456789abcdef")
	// A prefix written where a body would have to hold it, two secrets with
	// nothing between them, and candidate positions crowded as close as they can
	// be.
	f.Add("dosedose0123456789abcdef0123456789abcdef")
	f.Add("dose0123456789abcdose0123456789abcdef0123456789abcdef")
	f.Add("dose0123456789abcdef0123456789abcddose0123456789abcdef0123456789abcdef")
	// A secret beginning at the last character of another, which a scan resuming
	// past a match would lose.
	f.Add("dose0123456789abcdef0123456789abcdedose0123456789abcdef0123456789abcdef")
	f.Add("dose0123456789abcdef0123456789abcdefdose0123456789abcdef0123456789abcdef")
	f.Add(strings.Repeat("dose", 64))
	f.Add(strings.Repeat("dose", 64) + "0123456789abcdef0123456789abcdef")
	f.Add(strings.Repeat("dose0123456789abcdef0123456789abcdef", 8))
	f.Add(strings.Repeat("s", 128))
	f.Add(strings.Repeat("0123456789abcdef", 8))

	fuzzAgainstReference(f, DatabricksOAuthClientSecret().Find, referenceDatabricksOAuthClientSecretFind)
}

// databricksOAuthClientSecretFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func databricksOAuthClientSecretFindBenchmarks() []benchmarkCase {
	// The line the anchor is chosen against: the s stands four times on it
	// where the o stands six, and the d and the e — the two characters of the
	// prefix a body may also be written with — stand four times and seven. What
	// the line times is the search for the anchor, which is most of what this
	// pattern costs a caller whose text holds no secret.
	line := `time=2026-08-17T00:00:00Z level=info msg="requesting a token" url=https://dbc-01234567-89ab.cloud.databricks.com/oidc/v1/token `
	secret := "dose0123456789abcdef0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is four characters carrying the anchor once, so a run
			// of them stops the search once every four characters and each stop
			// reads a body that fails on its second character, which is the o of
			// the prefix beginning a byte later.
			name:  "candidates that are not values",
			src:   strings.Repeat("dose", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads a prefix, which is the cheapest a candidate
			// is declined for at all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("s", 4096),
			spans: 0,
		},
		{
			// The other way a candidate fails: a body of the right alphabet up
			// to its last character, so the whole of it is walked before the
			// candidate is turned away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("dose0123456789abcdef0123456789abcde. ", 16),
			spans: 0,
		},
		{
			// A run of the alphabet a body is read in, carrying no anchor at
			// all, which is what the search walks a digest of.
			name:  "a run of the body alphabet",
			src:   strings.Repeat("0123456789abcdef", 256),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "client_secret=" + secret,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "client_secret=" + secret,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"client_secret="+secret+"\n", 32),
			spans: 32,
		},
	}
}
