package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Resend API key pattern: what it locates and what it leaves alone, written
// out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a set
// of tests apiece.
//
// The keys written out below are made only of ordered characters: valid in
// shape, obviously not real. The first segment is eight letters and digits,
// written here as 01234567, and the second is twenty-four, written as
// 0123456789abcdef with 01234567 behind it; with the prefix and the separator
// between them that comes to the thirty-six characters the key Resend publishes
// is.

func Test_ResendAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "re_01234567_0123456789abcdef01234567",
			want: []Span{{0, 36}},
		},
		{
			name: "a key in an environment assignment",
			src:  "RESEND_API_KEY=re_01234567_0123456789abcdef01234567",
			want: []Span{{15, 51}},
		},
		{
			// The counts are read exactly, so what follows the thirty-sixth
			// character is not part of the key and stays in the text.
			name: "a run longer than the count is a key and what follows it",
			src:  "re_01234567_0123456789abcdef012345678",
			want: []Span{{0, 36}},
		},
		{
			name: "two keys with nothing between them",
			src:  "re_01234567_0123456789abcdef01234567re_01234567_0123456789abcdef01234567",
			want: []Span{{0, 36}, {36, 72}},
		},
		{
			// The alphabet is the letters of both cases with the digits, which
			// is what the expression Resend redacts its own fixtures with
			// spells out, so the segments written out here carry both.
			name: "an uppercase second segment",
			src:  "re_01234567_0123456789ABCDEF01234567",
			want: []Span{{0, 36}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ResendAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ResendAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "re_",
		},
		{
			name: "a first segment one character short",
			src:  "re_0123456_0123456789abcdef01234567",
		},
		{
			// The separator then stands where a ninth character of the first
			// segment is, which no run can be at once.
			name: "a first segment one character long",
			src:  "re_012345678_0123456789abcdef01234567",
		},
		{
			name: "a second segment one character short",
			src:  "re_01234567_0123456789abcdef0123456",
		},
		{
			name: "a second segment broken by a space",
			src:  "re_01234567_0123456789abcdef 1234567",
		},
		{
			name: "a hyphen in the second segment",
			src:  "re_01234567_0123456789abcdef-1234567",
		},
		{
			// The character the prefix closes with and the segments divide on,
			// which is the one the whole scan rests on a segment not carrying.
			name: "an underscore in the second segment",
			src:  "re_01234567_0123456789abcdef_1234567",
		},
		{
			name: "a character outside the alphabet in the second segment",
			src:  "re_01234567_0123456789abcdef.1234567",
		},
		{
			// The prefix is read in the one case Resend writes it.
			name: "an uppercase prefix",
			src:  "RE_01234567_0123456789abcdef01234567",
		},
		{
			name: "the prefix without its closing underscore",
			src:  "re01234567_0123456789abcdef012345678",
		},
		{
			name: "a hyphen where the prefix closes",
			src:  "re-01234567_0123456789abcdef01234567",
		},
		{
			name: "a hyphen where the segments divide",
			src:  "re_01234567-0123456789abcdef01234567",
		},
		{
			// The other credential Resend hands out, which carries a prefix of
			// its own and no re_ to be found at.
			name: "a webhook signing secret",
			src:  "whsec_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a body of the right shape opening with no prefix",
			src:  "xxx01234567_0123456789abcdef01234567",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "a log line",
			src:  `time=2026-08-17T00:00:00Z level=info msg="sending email" url=https://api.resend.com/emails`,
		},
		{
			name: "a resend environment variable holding a host name",
			src:  "RESEND_BASE_URL=https://api.resend.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ResendAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_ResendAPIKey_inContext(t *testing.T) {
	// The places a key is written, which are the places Resend's own
	// documentation puts one: the environment its client libraries read it
	// from, the argument they take it as, the bearer header a request carries
	// it in and the command line a curl example writes that header on.
	const key = "re_01234567_0123456789abcdef01234567"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key in a dotenv line",
			src:  "RESEND_API_KEY=" + key,
			want: []Span{{15, 15 + len(key)}},
		},
		{
			name: "a key in a node argument",
			src:  `const resend = new Resend("` + key + `");`,
			want: []Span{{27, 27 + len(key)}},
		},
		{
			name: "a key in a bearer token header",
			src:  "Authorization: Bearer " + key,
			want: []Span{{22, 22 + len(key)}},
		},
		{
			name: "a key on a command line",
			src:  `curl -H "Authorization: Bearer ` + key + `" https://api.resend.com/emails`,
			want: []Span{{31, 31 + len(key)}},
		},
		{
			name: "a key in a json body",
			src:  `{"token":"` + key + `"}`,
			want: []Span{{10, 10 + len(key)}},
		},
		{
			name: "a key at the end of a sentence",
			src:  "the key is " + key + ".",
			want: []Span{{11, 11 + len(key)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ResendAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ResendAPIKey_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match. A word boundary in front
	// would drop the whole match rather than trim it wherever a key is written
	// against a word character, and one behind it would drop a key followed by
	// a letter or a digit.
	const key = "re_01234567_0123456789abcdef01234567"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key after an underscore",
			src:  "RESEND_API_KEY_" + key,
			want: []Span{{15, 15 + len(key)}},
		},
		{
			name: "a key after a letter",
			src:  "x" + key,
			want: []Span{{1, 1 + len(key)}},
		},
		{
			name: "a word written against a key",
			src:  key + "suffix",
			want: []Span{{0, len(key)}},
		},
		{
			name: "a hyphenated word written against a key",
			src:  key + "-suffix",
			want: []Span{{0, len(key)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ResendAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ResendAPIKey_aKeyInsideAKey(t *testing.T) {
	// A key can be written inside another, which is why the scan resumes a byte
	// past the start of a candidate rather than past the candidate. Three
	// positions inside a span open a candidate — Test_resendAPIKeyPrefix counts
	// them — and the two that can become a key are the last two characters of
	// the second segment, from which the underscore reading them back stands
	// past the end of the span. The spans overlap there, which Masker.locate
	// resolves.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// A second segment closing on re, with the underscore that reads it
			// back written after the key that segment closes.
			name: "a key beginning at the end of another",
			src:  "re_01234567_0123456789abcdef012345re_01234567_0123456789abcdef01234567",
			want: []Span{{0, 36}, {34, 70}},
		},
		{
			// The same opening with nothing behind it long enough to be a
			// second segment, so the key in front of it is the one there is.
			name: "a second segment closing on re that opens no key",
			src:  "re_01234567_0123456789abcdef012345re_01234567_0123",
			want: []Span{{0, 36}},
		},
		{
			// The other of the two positions: a second segment closing on r,
			// with the e and the underscore written after the key.
			name: "a key beginning at the last character of another",
			src:  "re_01234567_0123456789abcdef0123456re_01234567_0123456789abcdef01234567",
			want: []Span{{0, 36}, {35, 71}},
		},
		{
			// The third position, which is the separator's. A candidate opens
			// where a first segment closes on re, and its own separator would
			// have to stand eight characters further on — inside the second
			// segment of the key it begins in, which is written in an alphabet
			// holding no underscore. So it is a candidate that can never become
			// a key.
			name: "a candidate opening at the separator of another key",
			src:  "re_012345re_0123456789abcdef01234567 and more text",
			want: []Span{{0, 36}},
		},
		{
			// The prefix written where a first segment would have to hold it.
			// The underscore it closes with stands where that segment's ninth
			// character is, so the candidate in front of it ends there and the
			// key is the one that prefix opens.
			name: "a prefix written where a segment would stand",
			src:  "re_01234re_01234567_0123456789abcdef01234567",
			want: []Span{{8, 44}},
		},
		{
			name: "a prefix in front of a key",
			src:  "re_re_01234567_0123456789abcdef01234567",
			want: []Span{{3, 39}},
		},
		{
			name: "two keys with nothing between them",
			src:  "re_01234567_0123456789abcdef01234567re_01234567_0123456789abcdef01234567",
			want: []Span{{0, 36}, {36, 72}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ResendAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ResendAPIKey_theShapesWrittenByAccident(t *testing.T) {
	// The two shapes text reaches this format by. base64url is the one alphabet
	// in ordinary use carrying the underscore, so a payload written in it can
	// hold a prefix and a separator where hexadecimal and standard base64 hold
	// neither. A snake-cased identifier is the other, and it needs segments of
	// exactly eight and exactly twenty-four characters — the second of which is
	// what a digest or an encoded field is written as rather than what a word
	// is. Where either is written there is nothing left in the text to tell it
	// from a key.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "the prefix inside a longer base64url run",
			src:  "payload=zzzzre_01234567_0123456789abcdef01234567zzzz",
			want: []Span{{12, 48}},
		},
		{
			name: "the prefix where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.re_01234567_0123456789abcdef01234567",
			want: []Span{{40, 76}},
		},
		{
			// Standard base64 writes the plus and the slash where base64url
			// writes the hyphen and the underscore, so a payload written in it
			// holds no separator to be found at however long it runs.
			name: "a standard base64 payload, which carries no underscore",
			src:  "payload=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAre0123456789abcdef",
			want: nil,
		},
		{
			// The identifier of the two counts, re_ being a prefix a name can
			// open with and compiled being eight characters.
			name: "a snake cased identifier of the two counts",
			src:  "re_compiled_0123456789abcdef01234567",
			want: []Span{{0, 36}},
		},
		{
			// A word of the wrong length in the first segment reaches nothing,
			// which is what keeps the shape above rare.
			name: "a snake cased identifier of other counts",
			src:  "re_compile_0123456789abcdef01234567",
			want: nil,
		},
		{
			// A digest carries no underscore, so one written straight behind
			// the prefix is turned away where the separator should stand.
			name: "a sha-1 behind the prefix",
			src:  "re_0123456789abcdef0123456789abcdef01234567",
			want: nil,
		},
		{
			// What a digest can do is stand as the second segment, which needs
			// the first segment and the separator written in front of it.
			name: "a sha-1 where the second segment stands",
			src:  "re_01234567_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 36}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ResendAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_resendAPIKeyPrefix(t *testing.T) {
	// The prefix is the whole of what tells this format from text, and it
	// closes on the character the two segments divide on. That is what makes
	// the search cheap on a line holding no key — a run of a segment opens no
	// candidate however long it runs — and it is what bounds where a key may
	// begin inside another, which the count below is of.
	if got := resendAPIKeyPrefix; got != "re_" {
		t.Errorf("resendAPIKeyPrefix = %q, want %q", got, "re_")
	}
	for i := range len(resendAPIKeyPrefix) {
		c := resendAPIKeyPrefix[i]
		if i == len(resendAPIKeyPrefix)-1 {
			if isBase62Byte(c) {
				t.Errorf("the prefix closes on %q, which a segment may be written with", c)
			}
			continue
		}
		if !isBase62Byte(c) {
			t.Errorf("the prefix carries %q at index %d, which a segment may not be written with", c, i)
		}
	}
	if isBase62Byte(resendAPIKeySeparator) {
		t.Errorf("the separator %q is a character a segment may be written with", resendAPIKeySeparator)
	}

	// Where a key may begin inside another, counted out of the declarations
	// that decide it rather than claimed in prose. A candidate opens where the
	// whole prefix stands, and the underscores a span holds are the prefix's
	// and the separator's, so a position inside a span opens one where either
	// of those falls at the anchor's index past it, or where the anchor falls
	// past the end of the span. What that leaves is the position two characters
	// in front of the separator and each of the last two characters of a key,
	// the second pair being what the scan resuming a byte along exists to
	// reach. A prefix
	// lengthened or a count changed moves the number, and nothing else here
	// would report it; a segment admitting the underscore would move it as
	// well, and that is what the walk above turns away.
	inside := 0
	for p := 1; p < resendAPIKeyChars; p++ {
		anchor := p + resendAPIKeyAnchorIndex
		if anchor >= resendAPIKeyChars ||
			anchor == len(resendAPIKeyPrefix)-1 ||
			anchor == len(resendAPIKeyPrefix)+resendAPIKeyIDChars {
			inside++
		}
	}
	if want := 3; inside != want {
		t.Errorf("%d position(s) inside a key can open a candidate, want %d", inside, want)
	}
}

func Test_resendAPIKeyAnchor(t *testing.T) {
	// The byte the scan searches for stands at the index it reads a candidate
	// back from. A prefix or an index changed without the other leaves the scan
	// opening candidates nowhere near where a key begins, and what such a scan
	// finds is nothing at all rather than something wrong.
	if got := resendAPIKeyPrefix[resendAPIKeyAnchorIndex]; got != resendAPIKeyAnchor {
		t.Errorf("resendAPIKeyPrefix[%d] = %q, want the anchor %q",
			resendAPIKeyAnchorIndex, got, resendAPIKeyAnchor)
	}

	// What the anchor costs, counted rather than claimed in prose: it stands
	// once in the prefix and once again as the separator, so a line of keys
	// stops the search twice a key, and nowhere in a segment, so a run of one
	// stops it not at all.
	if n := strings.Count(resendAPIKeyPrefix, string(resendAPIKeyAnchor)); n != 1 {
		t.Errorf("the anchor stands %d times in %q, want 1", n, resendAPIKeyPrefix)
	}
	if resendAPIKeySeparator != resendAPIKeyAnchor {
		t.Errorf("the separator %q is not the anchor %q, so a key stops the search once rather than twice",
			resendAPIKeySeparator, resendAPIKeyAnchor)
	}
	if isBase62Byte(resendAPIKeyAnchor) {
		t.Errorf("the anchor %q is a character a segment may be written with", resendAPIKeyAnchor)
	}
}

func Test_resendAPIKeyChars(t *testing.T) {
	// The prefix Resend writes a key with, and the two counts its own
	// expression asks for either side of the separator.
	if got := len(resendAPIKeyPrefix); got != 3 {
		t.Errorf("len(resendAPIKeyPrefix) = %d, want 3", got)
	}
	if got := resendAPIKeyIDChars; got != 8 {
		t.Errorf("resendAPIKeyIDChars = %d, want 8", got)
	}
	if got := resendAPIKeySecretChars; got != 24 {
		t.Errorf("resendAPIKeySecretChars = %d, want 24", got)
	}
	if got := resendAPIKeyChars; got != 36 {
		t.Errorf("resendAPIKeyChars = %d, want 36", got)
	}
}

// referenceResendAPIKey is the grammar as a regular expression: the prefix
// Resend writes a key with, the two counts its own expression asks for, the
// separator between them and the letters and digits those counts are read in.
// Every part of it is spelled again rather than read from the scan, so that the
// two can disagree and the target below report it.
//
// It is built on an expression rather than written out because both counts are
// exact, so an engine reads its machine once and stops, and because the opening
// is a literal an engine can search the text for rather than a class it would
// have to walk its machine at every byte for.
var referenceResendAPIKey = regexp.MustCompile(`re_[0-9A-Za-z]{8}_[0-9A-Za-z]{24}`)

// referenceResendAPIKeyFind locates keys the plain way: the leftmost match of
// the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// Asking at every byte rather than resuming past a match is what the scan does
// and is what a key written inside another needs: a second segment may close on
// the characters a prefix opens with, so a match can begin thirty-four
// characters into the one before it, and resuming past the first would lose it.
func referenceResendAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceResendAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzResendAPIKey_matchesReference guards the hand-written scan: the prefix it
// searches for, the case it reads that prefix in, the two counts it reads
// behind it, the separator it asks for between them, the alphabet it reads
// those counts in and the byte it resumes at may none of them change which keys
// are located.
func FuzzResendAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("RESEND_API_KEY=re_01234567_0123456789abcdef01234567")
	f.Add("re_0123456_0123456789abcdef01234567")   // a first segment one character short
	f.Add("re_012345678_0123456789abcdef01234567") // and one character long
	f.Add("re_01234567_0123456789abcdef0123456")   // a second segment one character short
	f.Add("re_01234567_0123456789abcdef012345678") // and a run one longer than a key
	f.Add("re_01234567_0123456789abcdef 1234567")  // a second segment broken by a space
	f.Add("re_01234567_0123456789abcdef-1234567")  // a hyphen in the second segment
	f.Add("re_01234567_0123456789abcdef_1234567")  // an underscore in the second segment
	f.Add("re_01234567_0123456789abcdef.1234567")  // a character outside the alphabet
	f.Add("re_01234567_0123456789abcdef\n01234567")
	f.Add("re_01234567_0123456789ABCDEF01234567") // an uppercase second segment
	f.Add("RE_01234567_0123456789abcdef01234567") // an uppercase prefix
	f.Add("re-01234567_0123456789abcdef01234567") // a hyphen where the prefix closes
	f.Add("re_01234567-0123456789abcdef01234567") // a hyphen where the segments divide
	f.Add("re01234567_0123456789abcdef012345678") // the prefix without its underscore
	f.Add("xre_01234567_0123456789abcdef01234567")
	// The other Resend credential, which this pattern locates nothing in, and a
	// digest either side of the separator.
	f.Add("whsec_0123456789abcdef0123456789abcdef")
	f.Add("re_0123456789abcdef0123456789abcdef01234567")
	f.Add("re_01234567_0123456789abcdef0123456789abcdef01234567")
	// The prefix inside base64url text, which is the alphabet that can hold it,
	// and the snake-cased identifier of the two counts.
	f.Add("payload=zzzzre_01234567_0123456789abcdef01234567zzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.re_01234567_0123456789abcdef01234567")
	f.Add("re_compiled_0123456789abcdef01234567")
	// A prefix written where a segment would have to hold it, two keys with
	// nothing between them, and candidate positions crowded as close as they
	// can be.
	f.Add("re_re_01234567_0123456789abcdef01234567")
	f.Add("re_01234re_01234567_0123456789abcdef01234567")
	f.Add("re_01234567_0123456789abcdef01234567re_01234567_0123456789abcdef01234567")
	// A key beginning at each of the last two characters of another's second
	// segment, which a scan resuming past a match would lose, and a candidate
	// opening at a separator, which no key can begin at.
	f.Add("re_01234567_0123456789abcdef012345re_01234567_0123456789abcdef01234567")
	f.Add("re_01234567_0123456789abcdef0123456re_01234567_0123456789abcdef01234567")
	f.Add("re_012345re_0123456789abcdef01234567 and more text")
	f.Add(strings.Repeat("re_", 64))
	f.Add(strings.Repeat("re_", 64) + "01234567_0123456789abcdef01234567")
	f.Add(strings.Repeat("re_01234567_0123456789abcdef01234567", 8))
	f.Add(strings.Repeat("_", 128))
	f.Add(strings.Repeat("e", 128))

	fuzzAgainstReference(f, ResendAPIKey().Find, referenceResendAPIKeyFind)
}

// resendAPIKeyFindBenchmarks is what this scan is timed on. The builtinPatterns
// entry for the pattern names it, and BenchmarkBuiltins times every case it
// holds under the pattern's own name, so that a built-in cannot arrive without
// a benchmark. Every case is held to the count it states under a plain go test
// as well, which is what a benchmark nobody has run yet cannot be.
func resendAPIKeyFindBenchmarks() []benchmarkCase {
	// The line the anchor is chosen against: the underscore the prefix closes
	// with stands not once on it, where the e stands eight times and the r
	// twice. What the line times is the search for the anchor, which is most of
	// what this pattern costs a caller whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="sending email" url=https://api.resend.com/emails `
	key := "re_01234567_0123456789abcdef01234567"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is three characters carrying the anchor once, so a run
			// of them stops the search once every three characters and each
			// stop reads a first segment that fails on its third character,
			// which is the underscore the prefix beginning a byte later closes
			// with.
			name:  "candidates that are not values",
			src:   strings.Repeat("re_", 512),
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
			// The other way a candidate fails: both segments of the right
			// alphabet up to the last character of the second, so the whole of
			// a candidate is walked before it is turned away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("re_01234567_0123456789abcdef0123456. ", 16),
			spans: 0,
		},
		{
			// A run of the alphabet a segment is read in, carrying no anchor at
			// all, which is what the search walks a payload of.
			name:  "a run of the body alphabet",
			src:   strings.Repeat("0123456789abcdef", 256),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "api_key=" + key,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "api_key=" + key,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"api_key="+key+"\n", 32),
			spans: 32,
		},
	}
}
