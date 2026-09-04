package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The age secret key pattern: what it locates and what it leaves alone, written
// out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The keys written out below are made only of ordered characters: valid in
// shape, obviously not real. The run they are built from is 023456789ACDEF,
// which is the ordered run 0123456789ABCDEF with the two characters the Bech32
// alphabet leaves out taken away, repeated to the fifty-eight a body is.

func Test_AgeSecretKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an x25519 secret key",
			src:  "AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
			want: []Span{{0, 74}},
		},
		{
			name: "a hybrid secret key",
			src:  "AGE-SECRET-KEY-PQ-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
			want: []Span{{0, 77}},
		},
		{
			name: "a secret key in an environment assignment",
			src:  "AGE_SECRET_KEY=AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
			want: []Span{{15, 89}},
		},
		{
			// The count behind the prefix is exact, so what follows the
			// fifty-eighth character of the body is not part of the key and
			// stays in the text.
			name: "an alphabet run longer than a key is a key and what follows it",
			src:  "AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF0234",
			want: []Span{{0, 74}},
		},
		{
			// Nothing separates them, and a boundary behind the match would
			// drop the first rather than trim it.
			name: "two keys with nothing between them",
			src:  "AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
			want: []Span{{0, 74}, {74, 148}},
		},
		{
			name: "a key of each kind on one line",
			src:  "AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02 AGE-SECRET-KEY-PQ-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
			want: []Span{{0, 74}, {75, 152}},
		},
		{
			// The count behind the prefix is exact for the hybrid kind as well,
			// so a run longer than a hybrid key is a key and what follows it,
			// exactly as it is for the shorter prefix above.
			name: "a hybrid alphabet run longer than a key is a key and what follows it",
			src:  "AGE-SECRET-KEY-PQ-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF0234",
			want: []Span{{0, 77}},
		},
		{
			// A body that opens on the run every other case here uses and then
			// carries on through the letters that run never reaches. Bech32
			// leaves out 1 and B, so the run written into a body is
			// 023456789ACDEF; QPZRYXGTVWSJNKHMUL is what the alphabet holds
			// besides, which no other case in this file puts in front of the
			// scan.
			name: "a body carrying the letters the run never reaches",
			src:  "AGE-SECRET-KEY-1023456789ACDEFQPZRYXGTVWSJNKHMULQPZRYXGTVWSJNKHMULQPZRYXGT",
			want: []Span{{0, 74}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AgeSecretKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AgeSecretKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "AGE-SECRET-KEY-1",
		},
		{
			name: "the human-readable part without the separator behind it",
			src:  "AGE-SECRET-KEY-023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
		},
		{
			name: "body one character short",
			src:  "AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF0",
		},
		{
			name: "a hybrid body one character short",
			src:  "AGE-SECRET-KEY-PQ-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF0",
		},
		{
			// Bech32 admits an all-lowercase spelling of any string, and age
			// writes and reads a secret key in uppercase alone.
			name: "a key written in lowercase",
			src:  "age-secret-key-1023456789acdef023456789acdef023456789acdef023456789acdef02",
		},
		{
			name: "a lowercase body under an uppercase prefix",
			src:  "AGE-SECRET-KEY-1023456789acdef023456789acdef023456789acdef023456789acdef02",
		},
		{
			// The four characters Bech32 leaves out of its alphabet, one case
			// apiece: the separator, and the three letters.
			name: "the separator in the body",
			src:  "AGE-SECRET-KEY-1123456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
		},
		{
			name: "the letter B, which the alphabet leaves out",
			src:  "AGE-SECRET-KEY-10B3456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
		},
		{
			name: "the letter I, which the alphabet leaves out",
			src:  "AGE-SECRET-KEY-10I3456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
		},
		{
			name: "the letter O, which the alphabet leaves out",
			src:  "AGE-SECRET-KEY-10O3456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
		},
		{
			name: "a hyphen in the body",
			src:  "AGE-SECRET-KEY-10-3456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
		},
		{
			// The public half of the same key pair, which age prints above the
			// key in an identity file and a caller publishes.
			name: "the recipient the key decrypts for",
			src:  "age1023456789acdef023456789acdef023456789acdef023456789acdef02",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "prose in capitals",
			src:  "THERE IS NO CREDENTIAL IN THIS SENTENCE",
		},
		{
			// The hybrid kind is read in the same one case as the shorter
			// prefix, and nowhere else: age dispatches on the uppercase prefix
			// before it decodes anything, so a lowercase spelling of it is one
			// nothing of age's writes or reads.
			name: "a hybrid key written in lowercase",
			src:  "age-secret-key-pq-1023456789acdef023456789acdef023456789acdef023456789acdef02",
		},
		{
			// The separator Bech32 divides the human-readable part from the
			// data by is what closes the hybrid prefix, and without it the scan
			// never finishes reading a kind.
			name: "the hybrid prefix without the separator behind it",
			src:  "AGE-SECRET-KEY-PQ-023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
		},
		{
			name: "the hybrid prefix without its hyphen",
			src:  "AGE-SECRET-KEY-PQ1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
		},
		{
			// The fifty-eighth character of the body, the last one the count
			// reads, standing outside the alphabet. A scan checking only the
			// characters in front of it would still call this a key.
			name: "a character outside the alphabet at the last position of the body",
			src:  "AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF0B",
		},
		{
			name: "a lowercase letter at the last position of the body",
			src:  "AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF0f",
		},
		{
			// The separator standing one character short of where it would
			// close a second candidate's human-readable part, deep inside a
			// body rather than at the position the prefix reads it from.
			name: "the separator near the end of the body",
			src:  "AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF12",
		},
		{
			// The alphabet and the case are both age's, so a body that is
			// otherwise uppercase and carries one lowercase letter is no key,
			// exactly as a body written wholly in lowercase is not.
			name: "a body carrying one lowercase character",
			src:  "AGE-SECRET-KEY-1023456789ACDEF023456789aCDEF023456789ACDEF023456789ACDEF02",
		},
		{
			// An uppercase base32 blob, which is the nearest ordinary text
			// comes to this alphabet without naming a key at all.
			name: "an uppercase base32 blob",
			src:  "MZXW6YTBOI======MZXW6YTBOI======MZXW6YTBOI======MZXW6YTBOI======",
		},
		{
			// A kind naming nothing age issues, standing where PQ would.
			name: "a kind this pattern was never told about",
			src:  "BUILD_ID=AGE-SECRET-KEY-BUILD-1023456789ACDEF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AgeSecretKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_AgeSecretKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "AGE_SECRET_KEY=AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
			want: "AGE_SECRET_KEY=**************************************************************************",
		},
		{
			name: "quoted",
			src:  `"AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02"`,
			want: `"**************************************************************************"`,
		},
		{
			// What age-keygen writes: the recipient in a comment above the key,
			// which is published and stays in the text, and the key under it.
			name: "an identity file",
			src:  "# created: 2026-08-17T00:00:00Z\n# public key: age1023456789acdef023456789acdef023456789acdef023456789acdef02\nAGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02\n",
			want: "# created: 2026-08-17T00:00:00Z\n# public key: age1023456789acdef023456789acdef023456789acdef023456789acdef02\n**************************************************************************\n",
		},
		{
			name: "the command line that reads one",
			src:  "echo AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02 | age -d -i - secrets.age",
			want: "echo ************************************************************************** | age -d -i - secrets.age",
		},
		{
			name: "a key of each kind",
			src:  "AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02 AGE-SECRET-KEY-PQ-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
			want: "************************************************************************** *****************************************************************************",
		},
		{
			// The hybrid kind written in the shapes the shorter prefix is
			// exercised in above: an assignment, quoted, and a field of a json
			// log line.
			name: "a hybrid key in an environment assignment",
			src:  "SOPS_AGE_KEY=AGE-SECRET-KEY-PQ-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
			want: "SOPS_AGE_KEY=*****************************************************************************",
		},
		{
			name: "a hybrid key quoted",
			src:  `"AGE-SECRET-KEY-PQ-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02"`,
			want: `"*****************************************************************************"`,
		},
		{
			name: "a hybrid key in a json field",
			src:  `{"identity":"AGE-SECRET-KEY-PQ-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02"}`,
			want: `{"identity":"*****************************************************************************"}`,
		},
	}

	m := New(WithPatterns(AgeSecretKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AgeSecretKey_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xAGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
			want: "x**************************************************************************",
		},
		{
			name: "underscore before",
			src:  "AGE_SECRET_KEY_AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
			want: "AGE_SECRET_KEY_**************************************************************************",
		},
		{
			name: "underscore after",
			src:  "AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02_x",
			want: "**************************************************************************_x",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this key
			// rather than trim it; without one the key is redacted and the two
			// characters written after it, which are part of no key, stay in
			// the text.
			name: "a character of the alphabet after",
			src:  "AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF0234",
			want: "**************************************************************************34",
		},
		{
			// A multi-byte rune written flush against a key on both sides, with
			// no space between them. Everywhere else in this file a rune of
			// that kind stands a space away from the key.
			name: "a multi-byte rune flush against the key on both sides",
			src:  "日本語AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02日本語",
			want: "日本語**************************************************************************日本語",
		},
	}

	m := New(WithPatterns(AgeSecretKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AgeSecretKey_leavesWhatFollowsAlone(t *testing.T) {
	// A key carries no punctuation at all, so nothing written after one joins
	// it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "path",
			src:  "key=AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02 file=/etc/age/keys.txt",
			want: "key=************************************************************************** file=/etc/age/keys.txt",
		},
		{
			name: "sentence",
			src:  "the key is AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02.",
			want: "the key is **************************************************************************.",
		},
	}

	m := New(WithPatterns(AgeSecretKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

// Test_AgeSecretKey_settlesWhatTheInputCutShort holds Find's second return to
// the offset in front of which nothing further back can still become a key,
// which is either a piece of a prefix standing at the end of the input or a
// candidate the end of the input cut short. What every built-in owes about
// that offset over generated text and over the samples is driven in
// builtins_test.go and fuzz_test.go; what is written out here is which inputs
// of this pattern's own shape hold anything back, since nothing else names
// them.
func Test_AgeSecretKey_settlesWhatTheInputCutShort(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want int
	}{
		{
			// The human-readable part alone, which is a piece of every prefix
			// this pattern reads and stands at the very start of the input.
			name: "the human-readable part alone",
			src:  "AGE-SECRET-KEY-",
			want: 0,
		},
		{
			name: "the hybrid kind without its separator",
			src:  "AGE-SECRET-KEY-PQ",
			want: 0,
		},
		{
			// A whole prefix at the end of the input with no body behind it:
			// the candidate it opens is cut short by the end of the input, and
			// what is held back is the whole of it rather than the prose in
			// front.
			name: "a whole prefix at the end of the input",
			src:  "nothing here yet AGE-SECRET-KEY-1",
			want: 17,
		},
		{
			// A body the end of the input cut short, held back from its own
			// start rather than from further back.
			name: "a body the end of the input cut short",
			src:  "AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF",
			want: 0,
		},
		{
			// A whole key reaching the end of the input. Nothing is read
			// behind the count, and the key's own alphabet carries none of the
			// bytes a prefix is written with, so nothing is held back.
			name: "a whole key reaching the end of the input",
			src:  "AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02",
			want: 74,
		},
		{
			// The same key with a character behind it that opens no prefix of
			// its own, so the whole of the input settles.
			name: "a whole key followed by a character that opens no prefix",
			src:  "AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02 ",
			want: 75,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, got := AgeSecretKey().Find(tt.src); got != tt.want {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, got, tt.want)
			}
		})
	}
}

// Test_AgeSecretKey_scanIsLinear drives the crowding this scan is most exposed
// to: the anchor stands once in every prefix, so a prefix repeated end to end
// holds a candidate for every sixteen (or nineteen, for the hybrid kind) bytes
// of the line, and the scan reads a fixed count at each rather than keeping a
// cursor, so nothing here is expected to cost more than that count times the
// number of candidates.
func Test_AgeSecretKey_scanIsLinear(t *testing.T) {
	checkScanIsLinear(t, AgeSecretKey(), map[string]string{
		"a prefix every sixteen characters":         strings.Repeat("AGE-SECRET-KEY-1", 200000),
		"a hybrid prefix every nineteen characters": strings.Repeat("AGE-SECRET-KEY-PQ-1", 200000),
		"one body running the length of the line":   "AGE-SECRET-KEY-1" + strings.Repeat("0", 1800000),
		"the anchor byte with no prefix behind it":  strings.Repeat("Y", 300000),
	})
}

func Test_ageSecretKeyPrefixes(t *testing.T) {
	// The scan reads a candidate back from a fixed index and then compares the
	// prefixes standing there, so a prefix that opened on something other than
	// the human-readable part, or closed on something other than the
	// separator, is one it never finishes reading. Neither shows as a failing
	// case: the pattern would quietly stop locating that kind of key. Which
	// byte the scan searches the input for is Test_ageSecretKeyAnchor's to
	// hold.
	if len(ageSecretKeyPrefixes) != len(ageSecretKeyKinds) {
		t.Fatalf("%d prefixes for %d kinds, so a kind opens no candidate",
			len(ageSecretKeyPrefixes), len(ageSecretKeyKinds))
	}
	for _, prefix := range ageSecretKeyPrefixes {
		t.Run(prefix, func(t *testing.T) {
			if !strings.HasPrefix(prefix, "AGE-SECRET-KEY-") {
				t.Errorf("the prefix does not open with the human-readable part age writes")
			}
			if !strings.HasSuffix(prefix, "1") {
				t.Errorf("the prefix does not close with the separator, so the body would be read from inside it")
			}
		})
	}
}

// Test_ageSecretKeyAnchor holds every prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from. One
// search serves every kind only while every kind spells that byte there, and a
// kind that did not would be one no candidate is ever found at.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_ageSecretKeyAnchor(t *testing.T) {
	for _, prefix := range ageSecretKeyPrefixes {
		t.Run(prefix, func(t *testing.T) {
			if ageSecretKeyAnchorIndex >= len(prefix) {
				t.Fatalf("the anchor stands at %d, the prefix is %d characters", ageSecretKeyAnchorIndex, len(prefix))
			}
			if c := prefix[ageSecretKeyAnchorIndex]; c != ageSecretKeyAnchor {
				t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it",
					c, byte(ageSecretKeyAnchor))
			}
		})
	}
}

func Test_isAgeSecretKeyByte(t *testing.T) {
	// The alphabet is stated over every byte rather than by example, and
	// against the character set BIP173 writes out rather than against the
	// ranges the scan reads it by: the two spellings are what hold each other,
	// as the reference below holds the grammar around them.
	const charset = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"

	for c := range 256 {
		b := byte(c)
		want := strings.IndexByte(charset, b) >= 0
		if got := isAgeSecretKeyByte(b); got != want {
			t.Errorf("isAgeSecretKeyByte(%q) = %v, want %v", b, got, want)
		}
	}

	// And the four characters the alphabet is short of are the four BIP173
	// names, which is what makes thirty-two of it.
	if len(charset) != 32 {
		t.Errorf("the character set is %d characters, Bech32 writes five bits to one", len(charset))
	}
	for _, c := range []byte{'1', 'B', 'I', 'O'} {
		if isAgeSecretKeyByte(c) {
			t.Errorf("isAgeSecretKeyByte(%q) = true, want the character Bech32 leaves out", c)
		}
	}
}

// referenceAgeSecretKey is the expression the scan in builtin_age_secret_key.go
// reads by hand: the statement of what a secret key is, kept here so that the
// scan can be held to it.
//
// The prefixes, the count and the alphabet are spelled again rather than built
// from ageSecretKeyPrefixes, ageSecretKeyBodyChars and isAgeSecretKeyByte. A
// reference sharing those declarations could not disagree with the scan about
// them, and it is exactly that disagreement the fuzz target below is for: the
// two have to be changed together or reported apart.
//
// The count is exact rather than a floor, which is what keeps this cheap enough
// to fuzz with: an engine reads a machine as wide as an exact count once and
// stops, where a floor costs it that machine at every candidate. The literal in
// front carries a hyphen, which no body is written with, so no run of the
// alphabet holds a second candidate for the engine to walk.
var referenceAgeSecretKey = regexp.MustCompile(`AGE-SECRET-KEY-(?:PQ-)?1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`)

// referenceAgeSecretKeyFind locates keys the plain way: the leftmost match of
// the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// It asks at every byte rather than resuming past a match, as every reference
// here does. That a key cannot begin inside another — the human-readable part
// carries hyphens, and a body is written without them — is a thing the scan
// claims, and a reference is written knowing nothing the scan claims.
func referenceAgeSecretKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceAgeSecretKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzAgeSecretKey_matchesReference guards the hand-written scan: the byte it
// searches for, the kinds it admits, the count it reads behind them, the
// alphabet it reads them in and the byte it resumes at may none of them change
// which keys are located.
func FuzzAgeSecretKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("AGE_SECRET_KEY=AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02")
	f.Add("AGE-SECRET-KEY-PQ-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02")
	f.Add("AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF0")    // one short of a key
	f.Add("AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF0234") // and a run longer than one
	f.Add("age-secret-key-1023456789acdef023456789acdef023456789acdef023456789acdef02")   // a key written in lowercase
	f.Add("AGE-SECRET-KEY-1123456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02")   // the separator in the body
	f.Add("AGE-SECRET-KEY-10B3456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02")   // a letter outside the alphabet
	f.Add("AGE-SECRET-KEY-10-3456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02")   // a hyphen in the body
	f.Add("age1023456789acdef023456789acdef023456789acdef023456789acdef02")               // the recipient rather than the key
	f.Add("AGE-SECRET-KEY-")                                                              // the human-readable part alone
	f.Add("AGE-SECRET-KEY-PQ-")
	f.Add("AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02\nAGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02")
	// Two keys with nothing between them, and the two kinds against one
	// another, where a scan resuming past a match would step over the second.
	f.Add("AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02AGE-SECRET-KEY-PQ-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02")
	// Candidate positions crowded as close as they can be: an anchor at every
	// fifteenth byte in the first, a run that is a body to every candidate in
	// the second, and a prefix at every byte of the third.
	f.Add(strings.Repeat("AGE-SECRET-KEY-1", 8))
	f.Add(strings.Repeat("AGE-SECRET-KEY-1", 8) + strings.Repeat("0", 64))
	f.Add(strings.Repeat("Y", 64))

	fuzzAgainstReference(f, AgeSecretKey().Find, referenceAgeSecretKeyFind)
}

// ageSecretKeyFindBenchmarks is what this scan is timed on. The builtinPatterns
// entry for the pattern names it, and BenchmarkBuiltins times every case it
// holds under the pattern's own name, so that a built-in cannot arrive without
// a benchmark. Every case is held to the count it states under a plain go test
// as well, which is what a benchmark nobody has run yet cannot be.
func ageSecretKeyFindBenchmarks() []benchmarkCase {
	// The line carries the capitals a log line about age has anyway — the name
	// of the file being decrypted and the variable the key is read from —
	// because they are what a scan searching for one of the commoner letters
	// of the human-readable part would have stopped at. The counts the anchor
	// was chosen on are this line's, and builtin_age_secret_key.go names them.
	line := `time=2026-08-17T00:00:00Z level=info msg="decrypting SECRETS.TAR.AGE" AGE_SECRET_KEY_FILE=/etc/age/keys.txt `
	key := "AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02"
	hybrid := "AGE-SECRET-KEY-PQ-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDEF02"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A prefix written out and a body one character short of the
			// count: the candidate standing at each prefix reads all
			// fifty-eight body positions and is turned away by the last of
			// them, which is the most a candidate can cost here. This scan
			// keeps no cursor and needs none — a fixed count bounds what a
			// candidate reads — and this is the input that would show the
			// bound gone.
			name:  "candidates that are not values",
			src:   strings.Repeat("AGE-SECRET-KEY-1023456789ACDEF023456789ACDEF023456789ACDEF023456789ACDE-", 32),
			spans: 0,
		},
		{
			// Values as close together as they can stand, and the two kinds
			// alternating, so both walks over the prefixes are timed.
			name:  "values with nothing between them",
			src:   strings.Repeat(key+hybrid, 16),
			spans: 32,
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
