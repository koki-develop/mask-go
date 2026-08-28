package mask

import (
	"slices"
	"strings"
	"testing"
)

// The crates.io token pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. A body is the run 0123456789abcdef written twice,
// which is the thirty-two characters either form carries, so an API token comes
// to thirty-five characters and a Trusted Publishing token to thirty-nine.

func Test_CratesIOToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an API token on its own",
			src:  "cio0123456789abcdef0123456789abcdef",
			want: []Span{{0, 35}},
		},
		{
			name: "a Trusted Publishing token on its own",
			src:  "cio_tp_0123456789abcdef0123456789abcdef",
			want: []Span{{0, 39}},
		},
		{
			name: "an API token in an environment assignment",
			src:  "CARGO_REGISTRY_TOKEN=cio0123456789abcdef0123456789abcdef",
			want: []Span{{21, 56}},
		},
		{
			name: "an uppercase body",
			src:  "cio0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 35}},
		},
		{
			name: "a body of letters alone",
			src:  "cioabcdefghijklmnopqrstuvwxyzabcdef",
			want: []Span{{0, 35}},
		},
		{
			name: "a body of digits alone",
			src:  "cio01234567890123456789012345678901",
			want: []Span{{0, 35}},
		},
		{
			// The counts are read exactly, so what follows the last character
			// of a token is not part of it and stays in the text.
			name: "a run longer than the count is a token and what follows it",
			src:  "cio0123456789abcdef0123456789abcdef0",
			want: []Span{{0, 35}},
		},
		{
			name: "a longer run behind the Trusted Publishing prefix",
			src:  "cio_tp_0123456789abcdef0123456789abcdef0",
			want: []Span{{0, 39}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "cio0123456789abcdef0123456789abcdefcio0123456789abcdef0123456789abcdef",
			want: []Span{{0, 35}, {35, 70}},
		},
		{
			name: "the two forms written together",
			src:  "cio0123456789abcdef0123456789abcdef cio_tp_0123456789abcdef0123456789abcdef",
			want: []Span{{0, 35}, {36, 75}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CratesIOToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CratesIOToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the opening alone",
			src:  "cio",
		},
		{
			name: "the Trusted Publishing prefix alone",
			src:  "cio_tp_",
		},
		{
			name: "an API body one character short",
			src:  "cio0123456789abcdef0123456789abcde",
		},
		{
			name: "a Trusted Publishing body one character short",
			src:  "cio_tp_0123456789abcdef0123456789abcde",
		},
		{
			name: "a hyphen in the body",
			src:  "cio0123456789abcdef-123456789abcdef",
		},
		{
			name: "an underscore in the body",
			src:  "cio0123456789abcdef_123456789abcdef",
		},
		{
			name: "a body broken by a space",
			src:  "cio0123456789abcdef 123456789abcdef",
		},
		{
			name: "a body broken by a dot",
			src:  "cio0123456789abcdef.123456789abcdef",
		},
		{
			name: "an uppercase opening",
			src:  "CIO0123456789abcdef0123456789abcdef",
		},
		{
			// The infix is what the longer form is read by, and every
			// character of it is asked for.
			name: "the Trusted Publishing infix without its closing underscore",
			src:  "cio_tp0123456789abcdef0123456789abcdef",
		},
		{
			name: "a hyphen where the infix opens",
			src:  "cio-tp-0123456789abcdef0123456789abcdef",
		},
		{
			name: "an underscore behind the opening that begins no infix",
			src:  "cio_0123456789abcdef0123456789abcdef",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "a log line",
			src:  `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://crates.io/api/v1/crates`,
		},
		{
			name: "the line cargo writes while publishing",
			src:  "    Uploading my-crate v0.1.0 (/home/runner/work/my-crate/my-crate)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CratesIOToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_CratesIOToken_inContext(t *testing.T) {
	// The places a token is written, which are the places crates.io and cargo
	// put one: the credentials file cargo login stores it in, the environment
	// variable CI hands it through, the header the API reads it from and the
	// response the Trusted Publishing exchange returns it in.
	const api = "cio0123456789abcdef0123456789abcdef"
	const tp = "cio_tp_0123456789abcdef0123456789abcdef"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token in the credentials file",
			src:  `token = "` + api + `"`,
			want: []Span{{9, 9 + len(api)}},
		},
		{
			name: "a token on a cargo login command line",
			src:  "cargo login " + api,
			want: []Span{{12, 12 + len(api)}},
		},
		{
			name: "a token in an environment assignment",
			src:  "CARGO_REGISTRY_TOKEN=" + api,
			want: []Span{{21, 21 + len(api)}},
		},
		{
			name: "a token in an authorization header",
			src:  "Authorization: " + api,
			want: []Span{{15, 15 + len(api)}},
		},
		{
			name: "a Trusted Publishing token in the response that mints it",
			src:  `{"token":"` + tp + `","expires_at":"2026-08-17T00:30:00Z"}`,
			want: []Span{{10, 10 + len(tp)}},
		},
		{
			name: "a Trusted Publishing token in a workflow output",
			src:  "token: " + tp,
			want: []Span{{7, 7 + len(tp)}},
		},
		{
			name: "a token at the end of a sentence",
			src:  "the token is " + api + ".",
			want: []Span{{13, 13 + len(api)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CratesIOToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CratesIOToken_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match, where all three published
	// rules reading this prefix ask for both. A word boundary in front would
	// drop the whole match rather than trim it wherever a token is written
	// against a word character, and one behind it would drop a token followed
	// by a letter or a digit.
	const api = "cio0123456789abcdef0123456789abcdef"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token after an underscore",
			src:  "CARGO_REGISTRY_TOKEN_" + api,
			want: []Span{{21, 21 + len(api)}},
		},
		{
			name: "a token after a letter",
			src:  "x" + api,
			want: []Span{{1, 1 + len(api)}},
		},
		{
			name: "a word written against a token",
			src:  api + "suffix",
			want: []Span{{0, len(api)}},
		},
		{
			name: "a hyphenated word written against a token",
			src:  api + "-suffix",
			want: []Span{{0, len(api)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CratesIOToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CratesIOToken_aTokenInsideAnother(t *testing.T) {
	// A token can be written inside another, which is why the scan resumes a
	// byte past the start of a candidate rather than past the candidate. The
	// alphabet a body is drawn from holds every character of the opening, so a
	// body may spell it and open a candidate that reads on past the end of the
	// token it stands in. The spans overlap where it does, which Masker.locate
	// resolves.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an API token beginning inside another",
			src:  "ciocio0123456789abcdef0123456789abcdef",
			want: []Span{{0, 35}, {3, 38}},
		},
		{
			name: "an API token beginning inside a Trusted Publishing token",
			src:  "cio_tp_0123456789abcdef0123456cio0123456789abcdef0123456789abcdef",
			want: []Span{{0, 39}, {30, 65}},
		},
		{
			name: "an opening inside a body that opens no token",
			src:  "ciocio0123456789abcdef0123456789abcde",
			want: []Span{{0, 35}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CratesIOToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CratesIOToken_theTwoFormsCannotBothStand(t *testing.T) {
	// What lets one walk read either form: the infix opens with a character no
	// body is written with, so a candidate carrying it is no API token at
	// whatever length it runs and the scan has nothing to fall back to when the
	// longer form fails. crates.io makes the same observation where it declares
	// the longer prefix — the regular tokens are what its comment calls the
	// ones that use no underscore.
	if c := cratesIOTrustedPublishingInfix[0]; isBase62Byte(c) {
		t.Errorf("the infix opens with %q, which a body may be written with, so a candidate carrying the infix could be read as an API token as well", c)
	}

	// So a Trusted Publishing token reports the one span of thirty-nine
	// characters, and never a shorter one taken from the same opening.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a Trusted Publishing token reports its own span alone",
			src:  "cio_tp_0123456789abcdef0123456789abcdef",
			want: []Span{{0, 39}},
		},
		{
			// The longer form failing leaves nothing behind: thirty-two
			// characters of the alphabet do stand behind the opening here, but
			// the first of them is the infix's underscore.
			name: "a Trusted Publishing body one character short is no API token",
			src:  "cio_tp_0123456789abcdef0123456789abcde",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CratesIOToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CratesIOToken_aTrustedPublishingTokenWithAWrongChecksum(t *testing.T) {
	// The last character of such a token stands for the XOR of the thirty-one
	// in front of it, folded into the same sixty-two, and this scan does not do
	// the arithmetic — builtin_crates_io_token.go weighs what that costs and
	// buys. The body below is the run 0123456789abcdef written twice; the
	// character crates.io would have written at the end of it is o, and the f
	// standing there is redacted all the same.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a body whose last character is not the checksum of the rest",
			src:  "cio_tp_0123456789abcdef0123456789abcdef",
			want: []Span{{0, 39}},
		},
		{
			name: "the same body with the checksum crates.io would write",
			src:  "cio_tp_0123456789abcdef0123456789abcdeo",
			want: []Span{{0, 39}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CratesIOToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CratesIOToken_aRunOfTheAlphabetAroundTheOpening(t *testing.T) {
	// The collision this format leaves, and the ones it does not. Three
	// lowercase letters with nothing to close them can stand inside a run of
	// the body's own alphabet, and thirty-two characters of that alphabet
	// behind them is the vendor's format exactly, so nothing is left in the
	// text to tell such a run from a token.
	//
	// Lowercase base32 is the encoding the opening stands most often in, since
	// every character it writes is a character a body may hold, and the address
	// below is the case that reaches a caller: fifty-six characters of it, with
	// thirty-five of them redacted.
	//
	// What is out of reach: a digest, since neither the i nor the o is a
	// hexadecimal digit; a word, since no word carries thirty-two unbroken
	// letters and digits behind those three; and the longer form in every
	// encoding here, since none of them writes an underscore at all.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an opening inside a longer run of the alphabet",
			src:  "Zciocio0123456789abcdef0123456789abcdefZ",
			want: []Span{{1, 36}, {4, 39}},
		},
		{
			name: "an opening inside a lowercase base32 address",
			src:  "abcdefghijciodefghijklmnopqrstuvwxyz234567abcdefghijklmn.onion",
			want: []Span{{10, 45}},
		},
		{
			name: "a base62 run holding no opening",
			src:  "abcdefghijklmnopqrstuvwxyz0123456789abcdefghij",
		},
		{
			name: "a SHA-256 digest",
			src:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a standard base64 payload, which carries no opening",
			src:  "payload=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsbpublishable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CratesIOToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CratesIOToken_aBodyWithNoPrefix(t *testing.T) {
	// The value crates.io issued before the prefix existed is not read.
	// HashedToken::parse rejects a string that does not open with the prefix,
	// so a token carrying none authenticates nothing; and thirty-two characters
	// of letters and digits with nothing in front of them is the shape of every
	// identifier, cache key and content hash a caller passes through.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a body of the right length with no opening",
			src:  "0123456789abcdef0123456789abcdef",
		},
		{
			name: "a body of the right length behind another word",
			src:  "token=0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CratesIOToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_cratesIOTokenOpening(t *testing.T) {
	// The opening is TOKEN_PREFIX, and it is the first characters of the
	// Trusted Publishing prefix as well, which is what lets one search find a
	// candidate of either form.
	if got := cratesIOTokenOpening; got != "cio" {
		t.Errorf("cratesIOTokenOpening = %q, want %q", got, "cio")
	}
	if got := cratesIOTrustedPublishingPrefix; got != "cio_tp_" {
		t.Errorf("cratesIOTrustedPublishingPrefix = %q, want %q", got, "cio_tp_")
	}
	if !strings.HasPrefix(cratesIOTrustedPublishingPrefix, cratesIOTokenOpening) {
		t.Errorf("%q does not open with %q, so one search cannot find both forms",
			cratesIOTrustedPublishingPrefix, cratesIOTokenOpening)
	}
}

func Test_cratesIOTokenAnchor(t *testing.T) {
	// The byte the scan searches for stands at the index it reads a candidate
	// back from, in every opening this pattern can match. A prefix or an index
	// changed without the other leaves the scan opening candidates nowhere near
	// where a token begins, and what such a scan finds is nothing at all rather
	// than something wrong.
	for _, prefix := range cratesIOTokenPrefixes {
		if got := prefix[cratesIOTokenAnchorIndex]; got != cratesIOTokenAnchor {
			t.Errorf("%q[%d] = %q, want the anchor %q",
				prefix, cratesIOTokenAnchorIndex, got, cratesIOTokenAnchor)
		}

		// What the anchor costs, counted rather than claimed in prose: it
		// stands once in each opening, so a candidate stops the search once
		// however it ends. An opening rewritten to carry it twice would stop
		// the search twice for one candidate.
		if n := strings.Count(prefix, string(cratesIOTokenAnchor)); n != 1 {
			t.Errorf("the anchor stands %d times in %q, want 1", n, prefix)
		}
	}
}

func Test_cratesIOTokenChars(t *testing.T) {
	// The two counts, each the argument a generator is called with, and the
	// two totals they come to.
	if got := cratesIOAPITokenBodyChars; got != 32 {
		t.Errorf("cratesIOAPITokenBodyChars = %d, want 32", got)
	}
	if got := cratesIOTrustedPublishingBodyChars; got != 32 {
		t.Errorf("cratesIOTrustedPublishingBodyChars = %d, want 32", got)
	}
	if got := cratesIOAPITokenChars; got != 35 {
		t.Errorf("cratesIOAPITokenChars = %d, want 35", got)
	}
	if got := cratesIOTrustedPublishingTokenChars; got != 39 {
		t.Errorf("cratesIOTrustedPublishingTokenChars = %d, want 39", got)
	}
}

// referenceCratesIOTokenAt reports where a crates.io token written at start
// ends, and whether one is written there at all. It is the statement of what
// the scan in builtin_crates_io_token.go locates, kept here so that the scan
// can be held to it, and it reads one position and stops.
//
// The two forms are tried in turn and neither is told about the other. They
// cannot both be written at one position — the infix opens with a character no
// body carries — but that is a claim the scan makes, and a reference is written
// to know nothing its scan claims.
//
// It is written out rather than built on a regular expression, which is the
// choice the layout leaves open and which the openings here settle. Both
// counts are exact, so a counted repetition would cost an engine nothing; what
// costs is the opening being written in the same alphabet as the body behind
// it. Every position of a run of that alphabet is then a candidate, an engine
// hands the machine the rest of the input at each of them, and the cost is
// quadratic in the length of the run: over cio written over and over, an
// expression takes this reference from a hundred and sixty microseconds at a
// kibibyte to twelve milliseconds at sixteen, and leaves
// FuzzCratesIOToken_matchesReference reporting no executions at all for the
// last two-thirds of its run. The walks below read a byte at a time and stop at
// the count, which is fifty microseconds and four hundred over the same two
// inputs.
//
// The prefixes, the counts and the alphabet are written out here rather than
// read from the scan. Reading them would move this with whatever the scan was
// changed to, and the fuzz target below would then hold a rule against itself;
// Test_references_shareNoDeclarationWithTheScans is what keeps the two apart.
func referenceCratesIOTokenAt(src string, start int) (int, bool) {
	if end, ok := referenceCratesIOTrustedPublishingTokenAt(src, start); ok {
		return end, true
	}
	return referenceCratesIOAPITokenAt(src, start)
}

// referenceCratesIOAPITokenAt reads cio and the thirty-two characters of the
// alphabet behind it, which is TOKEN_LENGTH characters of what crates.io draws
// from rand's Alphanumeric.
func referenceCratesIOAPITokenAt(src string, start int) (int, bool) {
	if !strings.HasPrefix(src[start:], "cio") {
		return 0, false
	}
	body := start + 3
	end := body + 32
	if end > len(src) {
		return 0, false
	}
	for i := body; i < end; i++ {
		if !referenceCratesIOTokenBodyByte(src[i]) {
			return 0, false
		}
	}
	return end, true
}

// referenceCratesIOTrustedPublishingTokenAt reads cio_tp_ and the thirty-two
// characters behind it: AccessToken::RAW_LENGTH characters of the alphabet and
// the one character of checksum written after them, which is read as a
// character of the alphabet and not verified.
func referenceCratesIOTrustedPublishingTokenAt(src string, start int) (int, bool) {
	if !strings.HasPrefix(src[start:], "cio_tp_") {
		return 0, false
	}
	body := start + 7
	end := body + 31 + 1
	if end > len(src) {
		return 0, false
	}
	for i := body; i < end; i++ {
		if !referenceCratesIOTokenBodyByte(src[i]) {
			return 0, false
		}
	}
	return end, true
}

// referenceCratesIOTokenBodyByte reports whether c is a character a body is
// written with: the letters of both cases and the digits, which is what rand
// documents Alphanumeric as sampling from.
func referenceCratesIOTokenBodyByte(c byte) bool {
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
}

// referenceCratesIOTokenFind locates tokens the plain way: every position in
// turn, with nothing remembered between them. It is the control flow of the
// scan with the grammar above in place of the byte tests the scan reads it
// with.
//
// Asking at every position rather than resuming past a match is what the scan
// does and is what a token written inside another needs: a body may spell the
// opening, so a token can begin three characters into the one before it and
// resuming past the first would lose it.
func referenceCratesIOTokenFind(src string) []Span {
	var spans []Span
	for start := range len(src) {
		if end, ok := referenceCratesIOTokenAt(src, start); ok {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
}

// FuzzCratesIOToken_matchesReference guards the hand-written scan: the opening
// it searches for, the infix it reads the longer form by, the counts it reads
// behind each prefix, the alphabet it reads them in and the byte it resumes at
// may none of them change which tokens are located.
func FuzzCratesIOToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("CARGO_REGISTRY_TOKEN=cio0123456789abcdef0123456789abcdef")
	f.Add("cio_tp_0123456789abcdef0123456789abcdef")
	f.Add("cio0123456789abcdef0123456789abcde")   // a body one character short
	f.Add("cio0123456789abcdef0123456789abcdef0") // and a run one longer
	f.Add("cio_tp_0123456789abcdef0123456789abcde")
	f.Add("cio_tp_0123456789abcdef0123456789abcdef0")
	f.Add("cio0123456789ABCDEF0123456789ABCDEF")  // an uppercase body
	f.Add("cio0123456789abcdef-123456789abcdef")  // a hyphen in the body
	f.Add("cio0123456789abcdef_123456789abcdef")  // an underscore in the body
	f.Add("cio0123456789abcdef.123456789abcdef")  // a character outside the alphabet
	f.Add("cio0123456789abcdef\n123456789abcdef") // and a line break
	f.Add("CIO0123456789abcdef0123456789abcdef")  // an uppercase opening
	f.Add("cio_tp0123456789abcdef0123456789abcdef")
	f.Add("cio-tp-0123456789abcdef0123456789abcdef")
	f.Add("cio_0123456789abcdef0123456789abcdef")
	f.Add("xcio0123456789abcdef0123456789abcdef")
	// A token written inside another, which a scan resuming past a match would
	// lose, and two tokens with nothing between them.
	f.Add("ciocio0123456789abcdef0123456789abcdef")
	f.Add("cio_tp_0123456789abcdef0123456cio0123456789abcdef0123456789abcdef")
	f.Add("cio0123456789abcdef0123456789abcdefcio0123456789abcdef0123456789abcdef")
	// Candidate positions crowded as close as they can be, and runs of the
	// bytes the search stops at and the infix is written with.
	f.Add(strings.Repeat("cio", 64))
	f.Add(strings.Repeat("cio_", 64))
	f.Add(strings.Repeat("cio_tp_", 64))
	f.Add(strings.Repeat("c", 128))
	f.Add(strings.Repeat("_", 128))
	f.Add(strings.Repeat("cio0123456789abcdef0123456789abcdef", 8))
	// A digest and a base64 payload, which carry no opening between them.
	f.Add("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAcio")

	fuzzAgainstReference(f, CratesIOToken().Find, referenceCratesIOTokenFind)
}

// cratesIOTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func cratesIOTokenFindBenchmarks() []benchmarkCase {
	// The line the anchor is weighed against, and the one text here where the c
	// is not the rarest of the three characters the opening is written with:
	// the vendor's own name is spelled with one and the path behind it repeats
	// it, so the c stands three times here against the o's two. That is why the
	// choice is argued against cargo's output and this package's other lines as
	// well as against this one.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://crates.io/api/v1/crates `
	api := "cio0123456789abcdef0123456789abcdef"
	tp := "cio_tp_0123456789abcdef0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// Candidates as close together as they can be without becoming
			// tokens: the opening every four characters, each turned away by
			// the first character of the body it never had.
			name:  "candidates that are not values",
			src:   strings.Repeat("cio_", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads an opening, which is the cheapest a
			// candidate is declined for at all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("c", 4096),
			spans: 0,
		},
		{
			// The other way a candidate fails: a body of the right alphabet up
			// to its last character, so the whole of it is walked before the
			// candidate is turned away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("cio0123456789abcdef0123456789abcde. ", 16),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "token=" + api,
			spans: 1,
		},
		{
			// The longer form, which is read by four characters more before
			// the same body walk.
			name:  "one value in the longer form",
			src:   line + "token=" + tp,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "token=" + api,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"token="+api+"\n", 32),
			spans: 32,
		},
	}
}
