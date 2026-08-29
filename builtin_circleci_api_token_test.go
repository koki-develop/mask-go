package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The CircleCI API token pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. The middle is twenty-two letters and digits,
// written here as 0123456789abcdef with 012345 behind it; the tail is forty
// hexadecimal characters, the same run twice over with 01234567 behind it. With
// a prefix in front and the separator between, a token comes to seventy
// characters.

func Test_CircleCIAPIToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a personal api token on its own",
			src:  "CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 70}},
		},
		{
			name: "a project api token on its own",
			src:  "CCIPRJ_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 70}},
		},
		{
			name: "a token in an environment assignment",
			src:  "CIRCLE_TOKEN=CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{13, 83}},
		},
		{
			// The counts are read exactly, so what follows the seventieth
			// character is not part of the token and stays in the text.
			name: "a tail longer than the count is a token and what follows it",
			src:  "CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef0123456789",
			want: []Span{{0, 70}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567CCIPRJ_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 70}, {70, 140}},
		},
		{
			// The tail is read as hexadecimal of either case, because the
			// changelog says hex and says nothing about which case it is
			// rendered in.
			name: "an uppercase tail",
			src:  "CCIPAT_0123456789abcdef012345_0123456789ABCDEF0123456789ABCDEF01234567",
			want: []Span{{0, 70}},
		},
		{
			// The middle is read in the letters of both cases with the digits,
			// which is wider than the base58 the changelog names. The narrower
			// class the rationale declines leaves out O, I and l, so it would
			// leave this token in the output whole.
			name: "a middle carrying the letters base58 leaves out",
			src:  "CCIPAT_0123456789abcdefOIl012_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 70}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CircleCIAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CircleCIAPIToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a prefix alone",
			src:  "CCIPAT_",
		},
		{
			name: "a middle one character short",
			src:  "CCIPAT_0123456789abcdef01234_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a middle one character long",
			src:  "CCIPAT_0123456789abcdef0123456_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a tail one character short",
			src:  "CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef0123456",
		},
		{
			name: "a middle broken by a space",
			src:  "CCIPAT_0123456789abcdef 12345_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a hyphen in the middle",
			src:  "CCIPAT_0123456789abcdef-12345_0123456789abcdef0123456789abcdef01234567",
		},
		{
			// The middle is base62, which leaves the underscore out, so a
			// separator written inside it is no token.
			name: "an underscore in the middle",
			src:  "CCIPAT_0123456789abcdef_12345_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a letter outside hexadecimal in the tail",
			src:  "CCIPAT_0123456789abcdef012345_0123456789abcdeg0123456789abcdef01234567",
		},
		{
			name: "the separator missing between the middle and the tail",
			src:  "CCIPAT_0123456789abcdef0123450123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a hyphen where the middle and the tail are divided",
			src:  "CCIPAT_0123456789abcdef012345-0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a lowercase prefix",
			src:  "ccipat_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a kind the vendor writes no token with",
			src:  "CCIORG_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "the prefix without its closing underscore",
			src:  "CCIPAT0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a hyphen where the prefix closes",
			src:  "CCIPAT-0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a body of the right shape opening with no prefix",
			src:  "XXXXXX_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "a log line",
			src:  `time=2026-08-29T00:00:00Z level=info msg="calling api" url=https://circleci.com/api/v2/me`,
		},
		{
			// The environment CircleCI exports, every variable of which is
			// written CIRCLE_ something — an opening the byte tested before the
			// prefixes does not turn away.
			name: "the environment a job runs with",
			src:  "CIRCLE_PROJECT_REPONAME=web CIRCLE_BRANCH=main CIRCLE_BUILD_NUM=4213",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CircleCIAPIToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_CircleCIAPIToken_inContext(t *testing.T) {
	// The places a token is written, which are the places CircleCI's own
	// documentation puts one: the environment the CLI reads it from, the header
	// the API authenticates with, the query a status badge carries it in, and
	// the configuration file the CLI writes.
	const token = "CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token in a dotenv line",
			src:  "CIRCLECI_CLI_TOKEN=" + token,
			want: []Span{{19, 19 + len(token)}},
		},
		{
			name: "a token in the header the api authenticates with",
			src:  "Circle-Token: " + token,
			want: []Span{{14, 14 + len(token)}},
		},
		{
			name: "a token on a curl command line",
			src:  `curl -H "Circle-Token: ` + token + `" https://circleci.com/api/v2/me`,
			want: []Span{{23, 23 + len(token)}},
		},
		{
			// A project token, which is what a status badge for a private
			// project carries and so is written where anyone can read it.
			name: "a project token in the query a status badge carries",
			src:  "https://circleci.com/gh/acme/web.svg?style=svg&circle-token=CCIPRJ_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{60, 130}},
		},
		{
			name: "a token in the configuration file the cli writes",
			src:  "token: " + token,
			want: []Span{{7, 7 + len(token)}},
		},
		{
			name: "a token in json",
			src:  `{"token":"` + token + `"}`,
			want: []Span{{10, 10 + len(token)}},
		},
		{
			name: "a token at the end of a sentence",
			src:  "the token is " + token + ".",
			want: []Span{{13, 13 + len(token)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CircleCIAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CircleCIAPIToken_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match. A word boundary in front
	// would drop the whole match rather than trim it wherever a token is
	// written against a word character, and one behind it would drop a token
	// followed by a letter or a digit.
	const token = "CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token after an underscore",
			src:  "CIRCLE_TOKEN_" + token,
			want: []Span{{13, 13 + len(token)}},
		},
		{
			name: "a token after a letter",
			src:  "x" + token,
			want: []Span{{1, 1 + len(token)}},
		},
		{
			name: "a word written against a token",
			src:  token + "suffix",
			want: []Span{{0, len(token)}},
		},
		{
			name: "a hyphenated word written against a token",
			src:  token + "-suffix",
			want: []Span{{0, len(token)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CircleCIAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CircleCIAPIToken_aTokenInsideAToken(t *testing.T) {
	// A token can begin inside another, which is why the scan resumes a byte
	// past the start of a candidate rather than past the candidate. The
	// underscore a candidate is read back from has to stand past the end of the
	// token it begins inside, and a prefix opens on C, C and then I where a tail
	// admits no I, so the two positions are the last two characters of a tail.
	// Test_circleCIAPITokenPrefixes counts them; the first two cases here drive
	// them, with the rest of the prefix written after the token whose tail
	// closes on its opening.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token beginning at the second last character of another",
			src:  "CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef012345CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 70}, {68, 138}},
		},
		{
			name: "a token beginning at the last character of another",
			src:  "CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef0123456CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 70}, {69, 139}},
		},
		{
			// The same tail with nothing behind it long enough to be a token,
			// so the token in front of it is the one there is.
			name: "a tail closing on the opening of a prefix that opens no token",
			src:  "CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef012345CCIPAT_0123456789",
			want: []Span{{0, 70}},
		},
		{
			// The separator dividing a middle from a tail reads a candidate
			// back into the middle, and such a candidate would need a second
			// separator inside a tail, where none may stand. So the token here
			// is the one the written prefix opens.
			name: "a prefix written where a middle would hold it",
			src:  "CCIPAT_0123456789abcdefCCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{23, 93}},
		},
		{
			name: "a prefix in front of a token",
			src:  "CCIPAT_CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{7, 77}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CircleCIAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CircleCIAPIToken_theOlderFormat(t *testing.T) {
	// The token CircleCI issued before it put a prefix on one is forty
	// hexadecimal characters and nothing else, and the changelog announcing the
	// prefixes left those working. It is a credential this pattern does not
	// locate: the value says nothing about itself, so what would locate it is
	// the name it is assigned to, which is a grammar this pattern's name does
	// not cover.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the older format in an environment assignment",
			src:  "CIRCLE_TOKEN=0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "the older format in the header the api authenticates with",
			src:  "Circle-Token: 0123456789abcdef0123456789abcdef01234567",
		},
		{
			// Everything behind the prefix of a token, which closes on the
			// older format exactly. The prefix is the whole of what tells one
			// from any other forty hexadecimal characters.
			name: "the body of a token without the prefix in front of it",
			src:  "0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CircleCIAPIToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_circleCIAPITokenPrefixes(t *testing.T) {
	// The prefixes are built from the opening, the kinds and the separator
	// rather than written out, so what is held here is what those parts come to
	// and the two things the scan rests on: every prefix is the same width, and
	// each closes on a character no run behind it is written with.
	want := []string{"CCIPAT_", "CCIPRJ_"}
	if !slices.Equal(circleCIAPITokenPrefixes, want) {
		t.Errorf("circleCIAPITokenPrefixes = %q, want %q", circleCIAPITokenPrefixes, want)
	}

	for _, p := range circleCIAPITokenPrefixes {
		if len(p) != circleCIAPITokenPrefixChars {
			t.Errorf("len(%q) = %d, want %d", p, len(p), circleCIAPITokenPrefixChars)
			continue
		}

		// The byte the scan searches for stands at the index it reads a
		// candidate back from, in every prefix. A prefix or an index changed
		// without the other leaves the scan opening candidates nowhere near
		// where a token begins, and what such a scan finds is nothing at all
		// rather than something wrong.
		if got := p[circleCIAPITokenAnchorIndex]; got != circleCIAPITokenAnchor {
			t.Errorf("%q[%d] = %q, want the anchor %q",
				p, circleCIAPITokenAnchorIndex, got, circleCIAPITokenAnchor)
		}

		// What the anchor costs, counted rather than claimed in prose: it
		// stands once in a prefix, so a run of prefixes stops the search once
		// apiece.
		if n := strings.Count(p, string(circleCIAPITokenAnchor)); n != 1 {
			t.Errorf("the anchor stands %d times in %q, want 1", n, p)
		}
	}

	// The anchor belongs to neither run behind a prefix, which is what makes
	// the search cheap over a payload — a run of either alphabet opens no
	// candidate however long it runs — and what bounds where a token may begin
	// inside another.
	if isBase62Byte(circleCIAPITokenAnchor) {
		t.Errorf("the anchor %q is a character a middle may be written with", circleCIAPITokenAnchor)
	}
	if isCircleCIAPITokenHexByte(circleCIAPITokenAnchor) {
		t.Errorf("the anchor %q is a character a tail may be written with", circleCIAPITokenAnchor)
	}

	// Where a token may begin inside another, counted out of the declarations
	// that decide it rather than claimed in prose. A position inside a token
	// begins one where every index the two tokens both reach admits some byte
	// under both of them; the indices past the end of the outer token are
	// whatever the text carries on with and constrain nothing. A count changed,
	// an alphabet widened or a kind added moves the number, and nothing else
	// here would report it.
	inside := 0
	for p := 1; p < circleCIAPITokenChars; p++ {
		shared := true
		for i := 0; p+i < circleCIAPITokenChars && shared; i++ {
			shared = false
			for c := range 256 {
				if circleCIAPITokenAdmitsAt(p+i, byte(c)) && circleCIAPITokenAdmitsAt(i, byte(c)) {
					shared = true
					break
				}
			}
		}
		if shared {
			inside++
		}
	}
	if want := 2; inside != want {
		t.Errorf("%d position(s) inside a token can begin another, want %d", inside, want)
	}
}

// circleCIAPITokenAdmitsAt reports whether c may stand at index i of a token,
// read out of the declarations the scan is written with rather than out of a
// second grammar written beside them.
func circleCIAPITokenAdmitsAt(i int, c byte) bool {
	switch {
	case i < circleCIAPITokenAnchorIndex:
		return slices.ContainsFunc(circleCIAPITokenPrefixes, func(p string) bool { return p[i] == c })
	case i == circleCIAPITokenAnchorIndex, i == circleCIAPITokenPrefixChars+circleCIAPITokenMiddleChars:
		return c == circleCIAPITokenSeparator
	case i < circleCIAPITokenPrefixChars+circleCIAPITokenMiddleChars:
		return isBase62Byte(c)
	default:
		return isCircleCIAPITokenHexByte(c)
	}
}

func Test_circleCIAPITokenChars(t *testing.T) {
	// The prefix, the middle a base58 UUID comes to, the separator and the
	// forty hexadecimal characters the changelog names. Seven, twenty-two, one
	// and forty make a token of seventy.
	if got := circleCIAPITokenPrefixChars; got != 7 {
		t.Errorf("circleCIAPITokenPrefixChars = %d, want 7", got)
	}
	if got := circleCIAPITokenMiddleChars; got != 22 {
		t.Errorf("circleCIAPITokenMiddleChars = %d, want 22", got)
	}
	if got := circleCIAPITokenTailChars; got != 40 {
		t.Errorf("circleCIAPITokenTailChars = %d, want 40", got)
	}
	if got := circleCIAPITokenChars; got != 70 {
		t.Errorf("circleCIAPITokenChars = %d, want 70", got)
	}

	// The token every case above is written from, held to that width so that a
	// count changed here is a count the cases stop agreeing with.
	const token = "CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567"
	if got := len(token); got != circleCIAPITokenChars {
		t.Errorf("len(%q) = %d, want %d", token, got, circleCIAPITokenChars)
	}
}

// referenceCircleCIAPIToken is the grammar as a regular expression: the two
// prefixes CircleCI writes a token with, the counts either side of the second
// separator and the alphabets those counts are read in. Every part of it is
// spelled again rather than read from the scan, so that the two can disagree and
// the target below report it.
//
// It is built on an expression rather than written out because both counts are
// exact, so an engine reads its machine once and stops, and because the two
// prefixes share the literal CCIP — an engine searches the text for that and
// walks its machine only where it stands, rather than at every byte as it would
// for an alternation whose branches share no opening.
var referenceCircleCIAPIToken = regexp.MustCompile(`CCI(?:PAT|PRJ)_[0-9A-Za-z]{22}_[0-9A-Fa-f]{40}`)

// referenceCircleCIAPITokenFind locates tokens the plain way: the leftmost match
// of the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// Asking at every byte rather than resuming past a match is what the scan does
// and is what a token written inside another needs: a tail may close on the
// characters a prefix opens with, so a match can begin sixty-eight characters
// into the one before it, and resuming past the first would lose it.
func referenceCircleCIAPITokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceCircleCIAPIToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzCircleCIAPIToken_matchesReference guards the hand-written scan: the
// prefixes it searches for, the case it reads them in, the counts it reads
// either side of the separator, the alphabets it reads those counts in and the
// byte it resumes at may none of them change which tokens are located.
func FuzzCircleCIAPIToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("CIRCLE_TOKEN=CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567")
	f.Add("CCIPRJ_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567")
	// The lengths either side of each count, and the alphabets either side of
	// each class.
	f.Add("CCIPAT_0123456789abcdef01234_0123456789abcdef0123456789abcdef01234567")
	f.Add("CCIPAT_0123456789abcdef0123456_0123456789abcdef0123456789abcdef01234567")
	f.Add("CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef0123456")
	f.Add("CCIPAT_0123456789abcdef012345_01234567890abcdef0123456789abcdef01234567")
	f.Add("CCIPAT_0123456789abcdef012345_0123456789ABCDEF0123456789ABCDEF01234567")
	f.Add("CCIPAT_0123456789abcdefOIl012_0123456789abcdef0123456789abcdef01234567")
	f.Add("CCIPAT_0123456789abcdef-12345_0123456789abcdef0123456789abcdef01234567")
	f.Add("CCIPAT_0123456789abcdef_12345_0123456789abcdef0123456789abcdef01234567")
	f.Add("CCIPAT_0123456789abcdef 12345_0123456789abcdef0123456789abcdef01234567")
	f.Add("CCIPAT_0123456789abcdef\n12345_0123456789abcdef0123456789abcdef01234567")
	f.Add("CCIPAT_0123456789abcdef012345_0123456789abcdeg0123456789abcdef01234567")
	f.Add("CCIPAT_0123456789abcdef012345-0123456789abcdef0123456789abcdef01234567")
	// The prefix written in the other case, without its separator, and with a
	// kind the vendor writes no token with.
	f.Add("ccipat_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567")
	f.Add("CCIPAT0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567")
	f.Add("CCIORG_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567")
	f.Add("xCCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567")
	// The older format, which carries no prefix, and the environment CircleCI
	// exports, whose variables open the way a prefix does.
	f.Add("CIRCLE_TOKEN=0123456789abcdef0123456789abcdef01234567")
	f.Add("CIRCLE_PROJECT_REPONAME=web CIRCLE_BRANCH=main CIRCLE_BUILD_NUM=4213")
	// A prefix written where a middle would hold it, a prefix in front of a
	// token, and two tokens with nothing between them.
	f.Add("CCIPAT_0123456789abcdefCCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567")
	f.Add("CCIPAT_CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567")
	f.Add("CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567CCIPRJ_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567")
	// A token beginning at each of the last two characters of another's tail,
	// which a scan resuming past a match would lose.
	f.Add("CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef012345CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567")
	f.Add("CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef0123456CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567")
	f.Add(strings.Repeat("CCIPAT_", 64))
	f.Add(strings.Repeat("CCIPAT_", 64) + "0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567")
	f.Add(strings.Repeat("CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567", 8))
	f.Add(strings.Repeat("_", 128))
	f.Add(strings.Repeat("C", 128))
	f.Add(strings.Repeat("CIRCLE_", 64))

	fuzzAgainstReference(f, CircleCIAPIToken().Find, referenceCircleCIAPITokenFind)
}

// circleCIAPITokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func circleCIAPITokenFindBenchmarks() []benchmarkCase {
	// The line the anchor is chosen against, which is the environment CircleCI
	// exports: the underscore stands four times on it where the P — the rarest
	// of the other bytes standing at a fixed index in both prefixes — stands
	// twice. What the line times is the search for the anchor together with the
	// stops CIRCLE_ costs, which is most of what this pattern costs a caller
	// whose text holds no token.
	line := "CIRCLE_PROJECT_REPONAME=web CIRCLE_BRANCH=main CIRCLE_SHA1=0123456789abcdef0123456789abcdef01234567 "
	token := "CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef01234567"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// CIRCLE_ is seven characters closing on an underscore with a C six
			// characters in front, which is a prefix's shape exactly, so every
			// one of these stops pays the comparison of a seven-byte string
			// rather than the one byte that turns the rest away.
			name:  "openings the byte test does not turn away",
			src:   strings.Repeat("CIRCLE_", 512),
			spans: 0,
		},
		{
			// A run of prefixes: each stops the search once, reads back a
			// prefix that matches, and is turned away by the separator the body
			// is asked for at a fixed offset.
			name:  "candidates that are not values",
			src:   strings.Repeat("CCIPAT_", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads a prefix, which is the cheapest a
			// candidate is declined for at all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("_", 4096),
			spans: 0,
		},
		{
			// The other way a candidate fails: a body of the right shape up to
			// its last character, so the whole of it is walked before the
			// candidate is turned away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("CCIPAT_0123456789abcdef012345_0123456789abcdef0123456789abcdef0123456. ", 16),
			spans: 0,
		},
		{
			// A run of the alphabet a middle is read in, carrying no anchor at
			// all, which is what the search walks a payload of.
			name:  "a run of the middle alphabet",
			src:   strings.Repeat("0123456789abcdef", 256),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "CIRCLE_TOKEN=" + token,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "CIRCLE_TOKEN=" + token,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"CIRCLE_TOKEN="+token+"\n", 32),
			spans: 32,
		},
	}
}
