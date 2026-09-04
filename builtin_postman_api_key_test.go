package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Postman API key pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The keys written out below are made only of ordered characters: valid in
// shape, obviously not real. A body is twenty-four characters, a hyphen and
// thirty-four more, which with the prefix in front comes to sixty-four. The
// key the cases are written around carries 0123456789abcdef01234567 and
// 0123456789abcdef0123456789abcdef01; where a case is about the alphabet or
// the case a body is written in, it carries the same ordered characters
// spelled out that far or spelled uppercase instead.

func Test_PostmanAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01",
			want: []Span{{0, 64}},
		},
		{
			name: "a key in an environment assignment",
			src:  "POSTMAN_API_KEY=PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01",
			want: []Span{{16, 80}},
		},
		{
			name: "a key in the header the api reads it from",
			src:  "X-API-Key: PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01",
			want: []Span{{11, 75}},
		},
		{
			// The counts are read exactly, so what follows the sixty-fourth
			// character is not part of the key and stays in the text.
			name: "a run longer than the second count is a key and what follows it",
			src:  "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef012",
			want: []Span{{0, 64}},
		},
		{
			name: "two keys with nothing between them",
			src:  "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01",
			want: []Span{{0, 64}, {64, 128}},
		},
		{
			// Every key the rulesets carry in their corpora is written in
			// lowercase hexadecimal, and nothing Postman publishes says a key
			// must be.
			name: "an uppercase body",
			src:  "PMAK-0123456789ABCDEF01234567-0123456789ABCDEF0123456789ABCDEF01",
			want: []Span{{0, 64}},
		},
		{
			// The key the narrower of the two alphabets would leave in the
			// output whole: letters past f in both segments.
			name: "a body carrying letters past f",
			src:  "PMAK-0123456789abcdefghijklmn-0123456789abcdefghijklmnopqrstuvwx",
			want: []Span{{0, 64}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PostmanAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PostmanAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "PMAK-",
		},
		{
			name: "a first segment one character short",
			src:  "PMAK-0123456789abcdef0123456-0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a first segment one character long",
			src:  "PMAK-0123456789abcdef012345678-0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a second segment one character short",
			src:  "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0",
		},
		{
			name: "the two segments written with no separator between them",
			src:  "PMAK-0123456789abcdef012345670123456789abcdef0123456789abcdef01",
		},
		{
			name: "an underscore where the separator stands",
			src:  "PMAK-0123456789abcdef01234567_0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a dot where the separator stands",
			src:  "PMAK-0123456789abcdef01234567.0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a space in the first segment",
			src:  "PMAK-0123456789abcdef 1234567-0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a dot in the second segment",
			src:  "PMAK-0123456789abcdef01234567-0123456789abcdef.123456789abcdef01",
		},
		{
			name: "a second hyphen in the second segment",
			src:  "PMAK-0123456789abcdef01234567-0123456789abcdef-123456789abcdef01",
		},
		{
			// A hyphen at an ordinary position of the first segment, with the
			// rest of the key otherwise valid — the shape that would catch a
			// first segment read too widely, since the separator's own
			// position moves with it.
			name: "a hyphen in the first segment",
			src:  "PMAK-0123456789ab-def01234567-0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a hyphen at the last character of the second segment",
			src:  "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0-",
		},
		{
			name: "an underscore in the first segment",
			src:  "PMAK-0123456789abcdef_1234567-0123456789abcdef0123456789abcdef01",
		},
		{
			name: "an underscore in the second segment",
			src:  "PMAK-0123456789abcdef01234567-0123456789abcdef_123456789abcdef01",
		},
		{
			name: "a dot in the first segment",
			src:  "PMAK-0123456789abcdef.1234567-0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a space in the second segment",
			src:  "PMAK-0123456789abcdef01234567-0123456789abcdef 123456789abcdef01",
		},
		{
			// An invalid UTF-8 byte inside the second segment. It belongs to
			// no encoding at all, so it ends the read exactly as the dot and
			// the space do.
			name: "an invalid byte in the second segment",
			src:  "PMAK-0123456789abcdef01234567-0123456789abcdef\xff123456789abcdef01",
		},
		{
			name: "a lowercase prefix",
			src:  "pmak-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01",
		},
		{
			name: "the prefix without its closing hyphen",
			src:  "PMAK0123456789abcdef01234567-0123456789abcdef0123456789abcdef01",
		},
		{
			name: "an underscore where the prefix closes",
			src:  "PMAK_0123456789abcdef01234567-0123456789abcdef0123456789abcdef01",
		},
		{
			// The collection access key, which Postman calls by another name
			// and writes behind another prefix.
			name: "a collection access key",
			src:  "PMAT-0123456789abcdef0123456789",
		},
		{
			name: "a body of the right shape opening with no prefix",
			src:  "0123456789abcdef01234567-0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a uuid",
			src:  "01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "a log line",
			src:  `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.getpostman.com/me`,
		},
		{
			name: "the environment variable holding a key, with nothing behind it",
			src:  "POSTMAN_API_KEY=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PostmanAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PostmanAPIKey_inContext(t *testing.T) {
	// The places a key is written: the header the API reads it from, the
	// environment the tooling takes it out of, the command line it is passed
	// on and the body of a request that carries it.
	const key = "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key in a dotenv line",
			src:  "POSTMAN_API_KEY=" + key,
			want: []Span{{16, 16 + len(key)}},
		},
		{
			name: "a key in the api key header",
			src:  "X-API-Key: " + key,
			want: []Span{{11, 11 + len(key)}},
		},
		{
			name: "a key on a curl command line",
			src:  `curl -H "X-API-Key: ` + key + `" https://api.getpostman.com/me`,
			want: []Span{{20, 20 + len(key)}},
		},
		{
			name: "a key in a json body",
			src:  `{"apiKey":"` + key + `"}`,
			want: []Span{{11, 11 + len(key)}},
		},
		{
			name: "a key on a postman cli command line",
			src:  "postman login --with-api-key " + key,
			want: []Span{{29, 29 + len(key)}},
		},
		{
			name: "a key at the end of a sentence",
			src:  "the key is " + key + ".",
			want: []Span{{11, 11 + len(key)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PostmanAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PostmanAPIKey_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match. A word boundary in front
	// would drop the whole match rather than trim it wherever a key is written
	// against a word character, and one behind it would drop a key followed by
	// a letter or a digit.
	const key = "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key after an underscore",
			src:  "POSTMAN_API_KEY_" + key,
			want: []Span{{16, 16 + len(key)}},
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
		{
			// A multi-byte rune written straight against a key with no ASCII
			// byte between the two, on either side.
			name: "a key after a multi-byte rune",
			src:  "日本語" + key,
			want: []Span{{9, 9 + len(key)}},
		},
		{
			name: "a key before a multi-byte rune",
			src:  key + "日本語",
			want: []Span{{0, len(key)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PostmanAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PostmanAPIKey_aKeyBeginningInsideAnother(t *testing.T) {
	// A key can be written inside another, which is why the scan resumes a
	// byte past the start of a candidate rather than past the candidate. The
	// alphabet a body is read in holds every letter the prefix is written
	// with, so a body may spell PMAK; what it may not hold is the hyphen the
	// prefix closes with, so a candidate opening inside a key either borrows
	// the key's own separator or reaches past the key's end for a hyphen. The
	// first of those cannot close, and the second is the four positions the
	// cases here drive. The spans overlap, which Masker.locate resolves.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// A second segment closing on PMAK, with the hyphen that reads it
			// back written after the key that segment closes.
			name: "a key beginning four characters from the end of another",
			src:  "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdPMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01",
			want: []Span{{0, 64}, {60, 124}},
		},
		{
			// The other end of the same range: a second segment closing on P,
			// with MAK- written after the key it closes.
			name: "a key beginning at the last character of another",
			src:  "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01",
			want: []Span{{0, 64}, {63, 127}},
		},
		{
			// The same opening with nothing behind it long enough to be a
			// body, so the key in front of it is the one there is.
			name: "a segment closing on PMAK that opens no key",
			src:  "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdPMAK-0123456789",
			want: []Span{{0, 64}},
		},
		{
			// The one position inside a key from which the prefix stands
			// whole: a first segment closing on PMAK, whose candidate borrows
			// the key's own separator and then needs a second hyphen
			// twenty-five characters further on, where the key's second
			// segment stands.
			name: "a first segment closing on PMAK opens a candidate that cannot close",
			src:  "PMAK-0123456789abcdef0123PMAK-0123456789abcdef0123456789abcdef01",
			want: []Span{{0, 64}},
		},
		{
			// The prefix written where a body would have to hold it. The
			// hyphen it closes with is no character a body may carry, so the
			// candidate in front of it is turned away and the key is the one
			// that prefix opens.
			name: "a prefix written where a body would stand",
			src:  "PMAK-0123456789abcPMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01",
			want: []Span{{18, 82}},
		},
		{
			name: "a prefix in front of a key",
			src:  "PMAK-PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01",
			want: []Span{{5, 69}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PostmanAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PostmanAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision a prefix leaves where everything behind it is one class,
	// which this format does not leave. A body is two runs of exact length
	// divided by a character neither run may carry, and no digest is
	// twenty-four or thirty-four characters wide or holds a hyphen at all, so
	// a digest written behind the prefix reaches nothing. A UUID carries four
	// hyphens and none of them falls where this format needs one.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an md5 behind the prefix",
			src:  "PMAK-0123456789abcdef0123456789abcdef",
			want: nil,
		},
		{
			name: "a sha-1 behind the prefix",
			src:  "PMAK-0123456789abcdef0123456789abcdef01234567",
			want: nil,
		},
		{
			name: "a sha-256 behind the prefix",
			src:  "PMAK-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: nil,
		},
		{
			name: "a uuid behind the prefix",
			src:  "PMAK-01234567-89ab-cdef-0123-456789abcdef",
			want: nil,
		},
		{
			// The same characters divided the way this format divides them,
			// which is a key's shape exactly and is redacted for that reason.
			name: "hexadecimal behind the prefix, divided at the twenty-fifth character",
			src:  "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01",
			want: []Span{{0, 64}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PostmanAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PostmanAPIKey_settlesAWholeKey(t *testing.T) {
	// A key of exactly the right counts standing at the very end of the input
	// closes on its own counts rather than on a run, so nothing arriving
	// after it can turn it into something else, and the whole input is
	// settled.
	src := "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01"

	spans, retain := PostmanAPIKey().Find(src)
	if want := []Span{{0, 64}}; !slices.Equal(spans, want) {
		t.Errorf("Find(%q) = %v, want %v", src, spans, want)
	}
	if retain != len(src) {
		t.Errorf("Find(%q) settled %d of %d, want the whole of it", src, retain, len(src))
	}
}

func Test_PostmanAPIKey_holdsAKeyTheInputCutShort(t *testing.T) {
	// The other side of the same decision. A candidate one character short of
	// the second segment's count is not a key, but more text could still
	// complete it, so the scan holds the candidate open from its own start
	// rather than reporting the whole input settled.
	src := "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0"

	spans, retain := PostmanAPIKey().Find(src)
	if len(spans) != 0 {
		t.Errorf("Find(%q) = %v, want no span", src, spans)
	}
	if retain != 0 {
		t.Errorf("Find(%q) settled from %d, want 0", src, retain)
	}
}

func Test_postmanAPIKeyPrefix(t *testing.T) {
	// The prefix is the whole of what tells this format from text, and it
	// closes on a character no body is written with. That is what turns away a
	// candidate whose body opens with a prefix of its own, and it is what
	// bounds where a key may begin inside another, which the counts below are
	// of.
	if got := postmanAPIKeyPrefix; got != "PMAK-" {
		t.Errorf("postmanAPIKeyPrefix = %q, want %q", got, "PMAK-")
	}
	for i := range len(postmanAPIKeyPrefix) {
		c := postmanAPIKeyPrefix[i]
		if i == len(postmanAPIKeyPrefix)-1 {
			if isBase62Byte(c) {
				t.Errorf("the prefix closes on %q, which a body may be written with", c)
			}
			continue
		}
		if !isBase62Byte(c) {
			t.Errorf("the prefix carries %q at index %d, which a body may not be written with", c, i)
		}
	}
	if got := postmanAPIKeyPrefix[len(postmanAPIKeyPrefix)-1]; got != postmanAPIKeySeparator {
		t.Errorf("the prefix closes on %q, want the separator %q", got, postmanAPIKeySeparator)
	}

	// Where a key may begin inside another, counted out of the declarations
	// that decide it rather than claimed in prose. A candidate opens where the
	// whole prefix stands, and the character that prefix closes with is one no
	// body carries, so a position inside a key opens a candidate only where
	// that character falls past the end of the key or on the one separator the
	// key itself holds. A count changed, the prefix lengthened or a body
	// admitting the hyphen would each move these numbers, and nothing else
	// here would report it.
	separator := len(postmanAPIKeyPrefix) + postmanAPIKeyFirstChars
	straddling := 0
	var borrowing []int
	for p := 1; p < postmanAPIKeyChars; p++ {
		closes := p + len(postmanAPIKeyPrefix) - 1
		switch {
		case closes >= postmanAPIKeyChars:
			straddling++
		case closes == separator:
			borrowing = append(borrowing, p)
		}
	}
	if want := 4; straddling != want {
		t.Errorf("%d position(s) inside a key reach a hyphen past its end, want %d", straddling, want)
	}
	if want := []int{25}; !slices.Equal(borrowing, want) {
		t.Errorf("position(s) inside a key borrowing its separator = %v, want %v", borrowing, want)
	}

	// And why the borrowing one closes no key: the separator its own body
	// would need stands where the key's second segment does, which is a
	// character the alphabet admits and the separator is not.
	if second := borrowing[0] + len(postmanAPIKeyPrefix) + postmanAPIKeyFirstChars; second <= separator || second >= postmanAPIKeyChars {
		t.Errorf("a candidate at %d needs its separator at %d, which is not inside the second segment",
			borrowing[0], second)
	}
}

func Test_postmanAPIKeyAnchor(t *testing.T) {
	// The byte the scan searches for stands at the index it reads a candidate
	// back from. A prefix or an index changed without the other leaves the
	// scan opening candidates nowhere near where a key begins, and what such a
	// scan finds is nothing at all rather than something wrong.
	if got := postmanAPIKeyPrefix[postmanAPIKeyAnchorIndex]; got != postmanAPIKeyAnchor {
		t.Errorf("postmanAPIKeyPrefix[%d] = %q, want the anchor %q",
			postmanAPIKeyAnchorIndex, got, postmanAPIKeyAnchor)
	}

	// What the anchor costs, counted rather than claimed in prose: it stands
	// once in the prefix, so a line of keys stops the search once a key. It is
	// a character a body may carry, which is what separates this scan from one
	// anchored outside its own alphabet — a run of the alphabet stops the
	// search wherever it spells this letter, and each stop is one byte
	// compared and resumed from. What is bought with that is not being
	// anchored on the separator, which every date and every hyphenated word is
	// written with.
	if n := strings.Count(postmanAPIKeyPrefix, string(postmanAPIKeyAnchor)); n != 1 {
		t.Errorf("the anchor stands %d times in %q, want 1", n, postmanAPIKeyPrefix)
	}
	if postmanAPIKeyAnchor == postmanAPIKeySeparator {
		t.Errorf("the anchor is the separator %q, which ordinary text is written with", postmanAPIKeySeparator)
	}
}

func Test_postmanAPIKeyChars(t *testing.T) {
	// The prefix and the two segments every ruleset that reads this format
	// asks for. Five characters, twenty-four, a separator and thirty-four make
	// a key of sixty-four.
	if got := len(postmanAPIKeyPrefix); got != 5 {
		t.Errorf("len(postmanAPIKeyPrefix) = %d, want 5", got)
	}
	if got := postmanAPIKeyFirstChars; got != 24 {
		t.Errorf("postmanAPIKeyFirstChars = %d, want 24", got)
	}
	if got := postmanAPIKeySecondChars; got != 34 {
		t.Errorf("postmanAPIKeySecondChars = %d, want 34", got)
	}
	if got := postmanAPIKeyBodyChars; got != 59 {
		t.Errorf("postmanAPIKeyBodyChars = %d, want 59", got)
	}
	if got := postmanAPIKeyChars; got != 64 {
		t.Errorf("postmanAPIKeyChars = %d, want 64", got)
	}
}

// referencePostmanAPIKey is the grammar as a regular expression: the prefix
// every published key opens with, the two counts every ruleset reading this
// format asks for, the hyphen between them and the letters and digits the
// counts are read in. Every part of it is spelled again rather than read from
// the scan, so that the two can disagree and the target below report it.
//
// It is built on an expression rather than written out because both counts are
// exact, so an engine reads its machine once and stops, and because the opening
// is a literal an engine can search the text for rather than a class it would
// have to walk its machine at every byte for.
var referencePostmanAPIKey = regexp.MustCompile(`PMAK-[0-9A-Za-z]{24}-[0-9A-Za-z]{34}`)

// referencePostmanAPIKeyFind locates keys the plain way: the leftmost match of
// the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// Asking at every byte rather than resuming past a match is what the scan does
// and is what a key written inside another needs: a body may close on the
// letters a prefix opens with, so a match can begin at any of the last four
// characters of the one before it, and resuming past the first would lose it.
func referencePostmanAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referencePostmanAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzPostmanAPIKey_matchesReference guards the hand-written scan: the prefix
// it searches for, the case it reads that prefix in, the two counts it reads
// behind it, the separator it asks for between them, the alphabet it reads
// them in and the byte it resumes at may none of them change which keys are
// located.
func FuzzPostmanAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("POSTMAN_API_KEY=PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01")
	f.Add("PMAK-0123456789abcdef0123456-0123456789abcdef0123456789abcdef01")     // a first segment one short
	f.Add("PMAK-0123456789abcdef012345678-0123456789abcdef0123456789abcdef01")   // and one long
	f.Add("PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0")     // a second segment one short
	f.Add("PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef012")   // and one long
	f.Add("PMAK-0123456789abcdef012345670123456789abcdef0123456789abcdef01")     // no separator at all
	f.Add("PMAK-0123456789abcdef01234567_0123456789abcdef0123456789abcdef01")    // an underscore for one
	f.Add("PMAK-0123456789abcdef 1234567-0123456789abcdef0123456789abcdef01")    // a space in the first segment
	f.Add("PMAK-0123456789abcdef01234567-0123456789abcdef.123456789abcdef01")    // a dot in the second
	f.Add("PMAK-0123456789abcdef01234567-0123456789abcdef-123456789abcdef01")    // a second hyphen in it
	f.Add("PMAK-0123456789ab-def01234567-0123456789abcdef0123456789abcdef01")    // a hyphen in the first segment
	f.Add("PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0-")    // a hyphen at the last character of the second
	f.Add("PMAK-0123456789abcdef_1234567-0123456789abcdef0123456789abcdef01")    // an underscore in the first segment
	f.Add("PMAK-0123456789abcdef01234567-0123456789abcdef_123456789abcdef01")    // an underscore in the second
	f.Add("PMAK-0123456789abcdef.1234567-0123456789abcdef0123456789abcdef01")    // a dot in the first segment
	f.Add("PMAK-0123456789abcdef01234567-0123456789abcdef 123456789abcdef01")    // a space in the second segment
	f.Add("PMAK-0123456789abcdef01234567-0123456789abcdef\xff123456789abcdef01") // an invalid byte in the second segment
	f.Add("日本語PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01") // a key after a multi-byte rune
	f.Add("PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01日本語") // and before one
	f.Add("PMAK-0123456789abcdef01234567-0123456789abcdef\n123456789abcdef01")
	f.Add("PMAK-0123456789ABCDEF01234567-0123456789ABCDEF0123456789ABCDEF01") // an uppercase body
	f.Add("PMAK-0123456789abcdefghijklmn-0123456789abcdefghijklmnopqrstuvwx") // letters past f
	f.Add("pmak-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01") // a lowercase prefix
	f.Add("PMAK0123456789abcdef01234567-0123456789abcdef0123456789abcdef01")  // no hyphen closing it
	f.Add("PMAK_0123456789abcdef01234567-0123456789abcdef0123456789abcdef01") // an underscore closing it
	f.Add("xPMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01")
	// The other Postman credential, which this pattern locates nothing in, and
	// the digests and the UUID a body's shape turns away.
	f.Add("PMAT-0123456789abcdef0123456789")
	f.Add("PMAK-0123456789abcdef0123456789abcdef")
	f.Add("PMAK-0123456789abcdef0123456789abcdef01234567")
	f.Add("PMAK-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("PMAK-01234567-89ab-cdef-0123-456789abcdef")
	// A prefix written where a body would have to hold it, two keys with
	// nothing between them, and candidate positions crowded as close as they
	// can be.
	f.Add("PMAK-PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01")
	f.Add("PMAK-0123456789abcPMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01")
	f.Add("PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01")
	// A key beginning at each end of the four positions another leaves it, and
	// the one position inside a key whose candidate borrows the key's own
	// separator and closes nothing.
	f.Add("PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdPMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01")
	f.Add("PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01")
	f.Add("PMAK-0123456789abcdef0123PMAK-0123456789abcdef0123456789abcdef01")
	f.Add(strings.Repeat("PMAK-", 64))
	f.Add(strings.Repeat("PMAK-", 64) + "0123456789abcdef01234567-0123456789abcdef0123456789abcdef01")
	f.Add(strings.Repeat("PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01", 4))
	f.Add(strings.Repeat("-", 128))
	f.Add(strings.Repeat("K", 128))

	fuzzAgainstReference(f, PostmanAPIKey().Find, referencePostmanAPIKeyFind)
}

// postmanAPIKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under
// a plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func postmanAPIKeyFindBenchmarks() []benchmarkCase {
	// The line the anchor is chosen against: the hyphen the prefix closes with
	// stands twice on it, the P twice and the A once, where the K stands not
	// once. What the line times is the search for the anchor, which is most of
	// what this pattern costs a caller whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="POST /collections" url=https://api.getpostman.com/me Accept=application/json agent=PostmanRuntime/7.42.0 `
	key := "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is five characters carrying the anchor once, so a run
			// of them stops the search once every five characters and each
			// stop reads a body whose separator is where a prefix's hyphen
			// falls and whose fifth character is that same hyphen, which the
			// alphabet does not admit.
			name:  "candidates that are not values",
			src:   strings.Repeat("PMAK-", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads a prefix, which is the cheapest a
			// candidate is declined for at all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("K", 4096),
			spans: 0,
		},
		{
			// The way a candidate is walked furthest: a body of the right
			// alphabet with the separator in the right place, failing on the
			// last character of its second segment.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0. ", 16),
			spans: 0,
		},
		{
			// A hexadecimal run, which is what a digest and an identifier are
			// written in and carries no anchor at all, so the search walks the
			// whole of it in one pass.
			name:  "a run of the body alphabet",
			src:   strings.Repeat("0123456789abcdef", 256),
			spans: 0,
		},
		{
			// The alphabet a body is read in reaches the anchor, so a run of
			// the wider class stops the search once a block where a
			// hexadecimal one stops it not at all. Each stop is turned away by
			// the byte the prefix opens with, which is the cheapest a
			// candidate is declined for once the search has found something.
			name:  "a run of the body alphabet carrying the anchor",
			src:   strings.Repeat("0123456789ABCDEFGHIJKLMNOPQRSTUV", 128),
			spans: 0,
		},
		{
			// What the separator is compared before either segment is walked:
			// a whole prefix with a run of the alphabet behind it, where the
			// twenty-fifth character of the body is one of that run rather
			// than the hyphen. One comparison turns each of these away, where
			// walking the first segment would cost twenty-four.
			name:  "candidates turned away by the separator",
			src:   strings.Repeat("PMAK-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab. ", 16),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "key=" + key,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "key=" + key,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"key="+key+"\n", 32),
			spans: 32,
		},
	}
}
