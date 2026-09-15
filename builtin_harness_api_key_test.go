package mask

import (
	"slices"
	"strings"
	"testing"
)

// The Harness API key pattern: what it locates and what it leaves alone, written
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
// shape, obviously not real. Each of the three parts opens on 0123456789abcdef
// and carries on through the alphabet — twenty-two characters for the account
// identifier, twenty-four for the token identifier and twenty for the secret,
// which with the prefix and the two separators comes to seventy-two. Where a
// case turns on what a part may open or close on, the character at that end is
// written differently and the rest of the run is left where it was.

// A whole key of each kind, for the cases that turn on something other than the
// shape of one, and the three parts they are built from.
const (
	harnessAPIKeyTestAccount = "0123456789abcdefghijkl"
	harnessAPIKeyTestToken   = "0123456789abcdefghijklmn"
	harnessAPIKeyTestSecret  = "0123456789abcdefghij"

	harnessAPIKeyTestKey = "pat." + harnessAPIKeyTestAccount + "." + harnessAPIKeyTestToken + "." + harnessAPIKeyTestSecret
	harnessAPIKeyTestSAT = "sat." + harnessAPIKeyTestAccount + "." + harnessAPIKeyTestToken + "." + harnessAPIKeyTestSecret
)

func Test_HarnessAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a personal access token",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij",
			want: []Span{{0, 72}},
		},
		{
			name: "a service account token",
			src:  "sat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij",
			want: []Span{{0, 72}},
		},
		{
			name: "a key in an environment assignment",
			src:  "HARNESS_API_KEY=pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij",
			want: []Span{{16, 88}},
		},
		{
			// The letters of the other case, which every part is written in and
			// which a value built from an ordered run reaches nowhere else.
			name: "an uppercase body",
			src:  "pat.0123456789ABCDEFGHIJKL.0123456789ABCDEFGHIJKLMN.0123456789ABCDEFGHIJ",
			want: []Span{{0, 72}},
		},
		{
			// The account identifier is read in base64url, so the two characters
			// that alphabet adds to the letters and the digits stand in it — at
			// its first character, its last and in the middle.
			name: "a hyphen at the first character of the account identifier",
			src:  "pat.-123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij",
			want: []Span{{0, 72}},
		},
		{
			name: "a hyphen at the last character of the account identifier",
			src:  "pat.0123456789abcdefghijk-.0123456789abcdefghijklmn.0123456789abcdefghij",
			want: []Span{{0, 72}},
		},
		{
			name: "a hyphen in the middle of the account identifier",
			src:  "pat.0123456789ab-defghijkl.0123456789abcdefghijklmn.0123456789abcdefghij",
			want: []Span{{0, 72}},
		},
		{
			name: "an underscore at the first character of the account identifier",
			src:  "pat._123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij",
			want: []Span{{0, 72}},
		},
		{
			name: "an underscore at the last character of the account identifier",
			src:  "pat.0123456789abcdefghijk_.0123456789abcdefghijklmn.0123456789abcdefghij",
			want: []Span{{0, 72}},
		},
		{
			name: "an underscore in the middle of the account identifier",
			src:  "pat.0123456789ab_defghijkl.0123456789abcdefghijklmn.0123456789abcdefghij",
			want: []Span{{0, 72}},
		},
		{
			// The last letter of the alphabet at the first and the last character
			// of each of the three parts, which an ordered run never reaches at
			// either end.
			name: "every part opening and closing on the last letter of the alphabet",
			src:  "pat.z123456789abcdefghijkz.z123456789abcdefghijklmz.z123456789abcdefghiz",
			want: []Span{{0, 72}},
		},
		{
			// And the first digit of it at the same six places.
			name: "every part opening and closing on the first digit of the alphabet",
			src:  "pat.0123456789abcdefghijk0.0123456789abcdefghijklm0.0123456789abcdefghi0",
			want: []Span{{0, 72}},
		},
		{
			// The secret is read as a floor, so a run longer than twenty
			// characters is one key and the whole of the run is redacted.
			name: "a secret longer than the floor",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghijklmn",
			want: []Span{{0, 76}},
		},
		{
			// The secret is read to the end of its run, and the three letters
			// the next key opens with are written in the run's own alphabet — so
			// the first span reaches the full stop that closes the second key's
			// prefix rather than stopping at the seventy-second character. The
			// two spans overlap and Masker.locate resolves them, which
			// Test_HarnessAPIKey_overlappingSpansMergeIntoOneRedaction drives.
			name: "two keys with nothing between them",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghijsat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij",
			want: []Span{{0, 75}, {72, 144}},
		},
		{
			name: "two keys separated by a space",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij sat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij",
			want: []Span{{0, 72}, {73, 145}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HarnessAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HarnessAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a prefix alone",
			src:  "pat.",
		},
		{
			name: "the identifiers with no secret behind them",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.",
		},
		{
			name: "an account identifier one character short",
			src:  "pat.0123456789abcdefghijk.0123456789abcdefghijklmn.0123456789abcdefghij",
		},
		{
			// One character longer than the count, which the separator is what
			// reports: the twenty-third character behind the prefix is a
			// character of the identifier's alphabet rather than the full stop.
			name: "an account identifier one character longer",
			src:  "pat.0123456789abcdefghijklm.0123456789abcdefghijklmn.0123456789abcdefghij",
		},
		{
			name: "a token identifier one character short",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklm.0123456789abcdefghij",
		},
		{
			name: "a token identifier one character longer",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmno.0123456789abcdefghij",
		},
		{
			name: "a secret one character short of the floor",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghi",
		},
		{
			// The token identifier is read in base62, which leaves out the two
			// characters base64url adds. Either of them ends the reading wherever
			// it stands.
			name: "a hyphen at the first character of the token identifier",
			src:  "pat.0123456789abcdefghijkl.-123456789abcdefghijklmn.0123456789abcdefghij",
		},
		{
			name: "a hyphen at the last character of the token identifier",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklm-.0123456789abcdefghij",
		},
		{
			name: "a hyphen in the middle of the token identifier",
			src:  "pat.0123456789abcdefghijkl.0123456789ab-defghijklmn.0123456789abcdefghij",
		},
		{
			name: "an underscore at the first character of the token identifier",
			src:  "pat.0123456789abcdefghijkl._123456789abcdefghijklmn.0123456789abcdefghij",
		},
		{
			name: "an underscore at the last character of the token identifier",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklm_.0123456789abcdefghij",
		},
		{
			name: "an underscore in the middle of the token identifier",
			src:  "pat.0123456789abcdefghijkl.0123456789ab_defghijklmn.0123456789abcdefghij",
		},
		{
			// The secret is read in base62 as well, and there the two characters
			// base64url adds end the run rather than the reading: what is left in
			// front of one is a run short of the floor.
			name: "a hyphen at the first character of the secret",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.-123456789abcdefghij",
		},
		{
			name: "a hyphen at the last character of the secret",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghi-",
		},
		{
			name: "a hyphen in the middle of the secret",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789ab-defghij",
		},
		{
			name: "an underscore at the first character of the secret",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn._123456789abcdefghij",
		},
		{
			name: "an underscore at the last character of the secret",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghi_",
		},
		{
			name: "an underscore in the middle of the secret",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789ab_defghij",
		},
		{
			// A character outside base64url at the ends of the account
			// identifier and inside it. The plus sign is what standard base64
			// writes where base64url writes the hyphen, so it is the character
			// nearest the alphabet that the alphabet leaves out.
			name: "a plus sign at the first character of the account identifier",
			src:  "pat.+123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij",
		},
		{
			name: "a plus sign at the last character of the account identifier",
			src:  "pat.0123456789abcdefghijk+.0123456789abcdefghijklmn.0123456789abcdefghij",
		},
		{
			name: "a plus sign in the middle of the account identifier",
			src:  "pat.0123456789ab+defghijkl.0123456789abcdefghijklmn.0123456789abcdefghij",
		},
		{
			name: "a full stop inside the account identifier",
			src:  "pat.0123456789ab.defghijkl.0123456789abcdefghijklmn.0123456789abcdefghij",
		},
		{
			name: "a full stop inside the token identifier",
			src:  "pat.0123456789abcdefghijkl.0123456789ab.defghijklmn.0123456789abcdefghij",
		},
		{
			name: "no separator between the identifiers",
			src:  "pat.0123456789abcdefghijkl0123456789abcdefghijklmn.0123456789abcdefghijkl",
		},
		{
			name: "no separator between the token identifier and the secret",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn0123456789abcdefghij",
		},
		{
			name: "a hyphen where the first separator stands",
			src:  "pat.0123456789abcdefghijkl-0123456789abcdefghijklmn.0123456789abcdefghij",
		},
		{
			name: "an underscore where the second separator stands",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn_0123456789abcdefghij",
		},
		{
			name: "a space at the first character of the account identifier",
			src:  "pat. 123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij",
		},
		{
			name: "a secret broken by a space",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789ab defghij",
		},
		{
			name: "a secret broken by a line break",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789ab\ndefghij",
		},
		{
			name: "an uppercase prefix",
			src:  "PAT.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij",
		},
		{
			// The three letters without the full stop behind them, which is the
			// Airtable prefix rather than this one.
			name: "the prefix without its separator",
			src:  "pat0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij",
		},
		{
			// A kind Harness writes nowhere. Its own code names pat and sat and
			// no others, so three letters and a full stop are a prefix only for
			// those two.
			name: "a kind harness does not issue",
			src:  "xat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij",
		},
		{
			name: "a body of the right shape with no prefix in front of it",
			src:  "0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// A line carrying the byte the scan searches for several times over,
			// none of them with a prefix in front of it.
			name: "the anchor as it is written in prose",
			src:  "the key is rotated. the old one stops working. nothing else changes.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HarnessAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_HarnessAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "HARNESS_API_KEY=" + harnessAPIKeyTestKey,
			want: "HARNESS_API_KEY=" + strings.Repeat("*", 72),
		},
		{
			// The header Harness sends a key in, which is how one reaches the API
			// and how it reaches a log line that echoed the request.
			name: "the api key header",
			src:  "x-api-key: " + harnessAPIKeyTestKey,
			want: "x-api-key: " + strings.Repeat("*", 72),
		},
		{
			name: "a command line",
			src:  `curl -H "x-api-key: ` + harnessAPIKeyTestKey + `" https://app.harness.io/v1/orgs`,
			want: `curl -H "x-api-key: ` + strings.Repeat("*", 72) + `" https://app.harness.io/v1/orgs`,
		},
		{
			name: "a json body",
			src:  `{"apiKey":"` + harnessAPIKeyTestSAT + `"}`,
			want: `{"apiKey":"` + strings.Repeat("*", 72) + `"}`,
		},
	}

	m := New(WithPatterns(HarnessAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HarnessAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the key through whole. Two of the three rules
	// stating this format ask for nothing either side; trufflehog asks for one
	// at both ends and for the vendor's name in the text in front besides.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "x" + harnessAPIKeyTestKey,
			want: "x" + strings.Repeat("*", 72),
		},
		{
			name: "underscore before",
			src:  "HARNESS_API_KEY_" + harnessAPIKeyTestKey,
			want: "HARNESS_API_KEY_" + strings.Repeat("*", 72),
		},
		{
			name: "a digit before",
			src:  "9" + harnessAPIKeyTestKey,
			want: "9" + strings.Repeat("*", 72),
		},
		{
			name: "a full stop before",
			src:  "." + harnessAPIKeyTestKey,
			want: "." + strings.Repeat("*", 72),
		},
		{
			// A multi-byte rune written against the key on both sides. Neither
			// UTF-8 encoding shares a byte with a prefix or with either
			// alphabet, so the key keeps its span exactly as it does against a
			// single-byte character.
			name: "a multi-byte rune before and after",
			src:  "日本語" + harnessAPIKeyTestKey + "日本語",
			want: "日本語" + strings.Repeat("*", 72) + "日本語",
		},
	}

	m := New(WithPatterns(HarnessAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HarnessAPIKey_aSecretLongerThanTheFloor(t *testing.T) {
	// The near side of reading the last count as a floor, which
	// builtin_harness_api_key.go weighs against reading it exactly. A secret
	// wider than twenty characters is redacted whole rather than to the count,
	// and what pays for that is the character of the secret's own alphabet
	// written straight behind a key, which belongs to no credential and is
	// redacted with it.
	//
	// The two cannot be told apart from the text: a run of twenty-one is either
	// a key whose secret is wider than the rules that state this format
	// observed, or a key of twenty with a character written against it, and
	// nothing in the run says which.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "one character past the floor",
			src:  harnessAPIKeyTestKey + "k",
			want: strings.Repeat("*", 73),
		},
		{
			name: "a secret half as wide again",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghijklmnopqrst",
			want: strings.Repeat("*", 82),
		},
		{
			// What ends the run ends the key, so a character of neither alphabet
			// written behind a secret stays in the text.
			name: "a character of neither alphabet behind the secret",
			src:  harnessAPIKeyTestKey + "-suffix",
			want: strings.Repeat("*", 72) + "-suffix",
		},
		{
			name: "a quoted key",
			src:  `"` + harnessAPIKeyTestKey + `"`,
			want: `"` + strings.Repeat("*", 72) + `"`,
		},
		{
			name: "a key closing a sentence",
			src:  "the key is " + harnessAPIKeyTestKey + ".",
			want: "the key is " + strings.Repeat("*", 72) + ".",
		},
	}

	m := New(WithPatterns(HarnessAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HarnessAPIKey_cutShortOfTheFloor(t *testing.T) {
	// The far side of the same decision. A floor gives up on the run that never
	// reaches it, so a key cut short — a line trimmed to a column limit partway
	// through one, a secret broken across a wrap — leaves a prefix, two whole
	// identifiers and a run too short to be a secret, and nothing is located.
	//
	// Each case writes text behind the candidate, so that the floor is what
	// reports the rejection rather than the end of the input. What says the walk
	// ran is the second return: the input is settled to its end, where the same
	// value with nothing behind it settles where the candidate opened.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a secret one character short of the floor",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghi and the line carries on",
		},
		{
			name: "a secret half the floor",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789 and the line carries on",
		},
		{
			name: "the identifiers with no secret behind them",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn. and the line carries on",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := HarnessAPIKey().Find(tt.src)
			if len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
			if retain != len(tt.src) {
				t.Errorf("Find(%q) settled %d, want %d — the run was not read", tt.src, retain, len(tt.src))
			}
		})
	}
}

func Test_HarnessAPIKey_aKeyBeginningInsideAnother(t *testing.T) {
	// The claim builtin_harness_api_key.go makes about what advancing rather
	// than consuming the match finds here. A key carries a full stop at three
	// places, so a candidate opens inside one wherever the three characters in
	// front of a stop spell a prefix — at the twenty-third character of a key,
	// where the account identifier ends in pat or sat, and at the forty-eighth,
	// where the token identifier does.
	//
	// Only the second of the two can go on to be a key, and both are driven
	// here. A candidate opening twenty-three characters in wants its own first
	// stop where the token identifier is still being written, and a token
	// identifier holds none, so it is turned away and the key around it keeps
	// its own span; a candidate opening forty-eight characters in wants its
	// stops where the secret's run and what follows it are written, and there
	// the text below gives it them. The spans overlap in the second case, and a
	// scan consuming its match would report the first and step over the second.
	//
	// Each case writes text behind the candidates, so that the grammar reports
	// the rejection rather than the end of the input: the second return says the
	// walk ran.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// The account identifier closes on the three letters a prefix opens
			// with, so a candidate stands at the twenty-fourth character of the
			// key. It is no key and nothing of it reaches the output.
			name: "a candidate opening in the account identifier is no key",
			src:  "pat.0123456789abcdefghipat.0123456789abcdefghijklmn.0123456789abcdefghij tail",
			want: []Span{{0, 72}},
		},
		{
			// The token identifier closes on them instead, so the candidate
			// stands at the forty-ninth character, where its own identifiers are
			// the secret of the key around it and the text written behind that.
			name: "a candidate opening in the token identifier is a key",
			src:  "pat.0123456789abcdefghijkl.0123456789abcdefghijkpat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij tail",
			want: []Span{{0, 74}, {48, 120}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := HarnessAPIKey().Find(tt.src)
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
			if retain != len(tt.src) {
				t.Errorf("Find(%q) settled %d, want %d — the grammar was not read", tt.src, retain, len(tt.src))
			}
		})
	}
}

func Test_HarnessAPIKey_overlappingSpansMergeIntoOneRedaction(t *testing.T) {
	// The two ways this scan reports overlapping spans, through Mask rather
	// than Find: a key beginning inside another, and two keys written with
	// nothing between them, where the first secret's run reaches into the
	// second key's prefix. Either way Masker.locate resolves the pair into one
	// redaction and the text either side of it comes through untouched.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a key beginning inside another",
			src:  "key=pat.0123456789abcdefghijkl.0123456789abcdefghijkpat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij tail",
			want: "key=" + strings.Repeat("*", 120) + " tail",
		},
		{
			name: "two keys with nothing between them",
			src:  "key=" + harnessAPIKeyTestKey + harnessAPIKeyTestSAT + " tail",
			want: "key=" + strings.Repeat("*", 144) + " tail",
		},
	}

	m := New(WithPatterns(HarnessAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HarnessAPIKey_aDottedName(t *testing.T) {
	// The prefix is three letters and a full stop, which is how a great many
	// ordinary names are written: pat is where compat, compatibility and a
	// package path written through them all end, and sat opens a word of its
	// own. What turns those away is the layout behind the prefix — exactly
	// twenty-two characters, a stop, exactly twenty-four, a stop and twenty more
	// — and none of these reaches it.
	//
	// Each case writes text behind the candidate, so that the grammar is what
	// reports the rejection rather than the end of the input. What says the walk
	// ran is the second return.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a package path",
			src:  "org.example.compat.legacy.ClientAdapter was loaded from the shaded jar",
		},
		{
			name: "a module path in an import",
			src:  "import org.example.compat.shim as compat and then carry on with the rest of it",
		},
		{
			name: "a field access in a stack trace",
			src:  "at com.example.compat.Bridge.invoke(Bridge.java:118) and eleven frames below it",
		},
		{
			name: "a sentence closing on the three letters",
			src:  "the change is backwards compat. the release note says so and nothing else in the file changed",
		},
		{
			// The closest a name comes: the first count met exactly and the
			// second one character short, so the walk reaches the last character
			// of the token identifier before the grammar reports it.
			name: "a dotted name with the first count met",
			src:  "compat.0123456789abcdefghijkl.0123456789abcdefghijklm.0123456789abcdefghij and the line carries on",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := HarnessAPIKey().Find(tt.src)
			if len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
			if retain != len(tt.src) {
				t.Errorf("Find(%q) settled %d, want %d — the grammar was not read", tt.src, retain, len(tt.src))
			}
		})
	}
}

func Test_HarnessAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision a prefix ordinarily invites is a digest written behind it,
	// and the counts here turn one away rather than pay for it: an MD5 is
	// thirty-two characters, a SHA-1 forty and a SHA-256 sixty-four, and neither
	// identifier is written to any of those widths. A digest carries no full
	// stop besides, so none of them divides where a key does.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "an md5 behind the prefix",
			src:  "pat.0123456789abcdef0123456789abcdef and the line carries on",
		},
		{
			name: "a sha-1 behind the prefix",
			src:  "pat.0123456789abcdef0123456789abcdef01234567 and the line carries on",
		},
		{
			name: "a sha-256 behind the prefix",
			src:  "pat.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef and the line carries on",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := HarnessAPIKey().Find(tt.src)
			if len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
			if retain != len(tt.src) {
				t.Errorf("Find(%q) settled %d, want %d — the grammar was not read", tt.src, retain, len(tt.src))
			}
		})
	}
}

func Test_HarnessAPIKey_anAirtableToken(t *testing.T) {
	// The pair builtin_harness_api_key.go names. The Airtable personal access
	// token opens on the same three letters, and no value of either format is a
	// value of the other — but the shared letters do reach candidates and spans,
	// and both directions are driven here.
	const (
		airtable = "pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		// The same token with its identifier closing on the three letters a
		// prefix opens with, which is what puts a candidate of this scan inside
		// an Airtable token: the candidate opens fourteen characters in and its
		// own first stop is the one Airtable writes at the eighteenth.
		airtableClosingOnAPrefix = "pat0123456789apat.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)

	t.Run("an airtable token holds no harness key", func(t *testing.T) {
		if got, _ := HarnessAPIKey().Find(airtable); len(got) != 0 {
			t.Errorf("Find(%q) = %v, want no span", airtable, got)
		}
	})

	t.Run("nor one whose identifier closes on a prefix", func(t *testing.T) {
		// The candidate opens here where it cannot in the case above. What
		// turns it away is the secret: sixty-four hexadecimal characters carry
		// no stop where this grammar wants its second, twenty-two characters
		// past the first.
		if got, _ := HarnessAPIKey().Find(airtableClosingOnAPrefix); len(got) != 0 {
			t.Errorf("Find(%q) = %v, want no span", airtableClosingOnAPrefix, got)
		}
		if got, _ := AirtablePersonalAccessToken().Find(airtableClosingOnAPrefix); len(got) != 1 {
			t.Errorf("Find(%q) = %v, want the airtable token located", airtableClosingOnAPrefix, got)
		}
	})

	t.Run("a harness key holds no airtable token", func(t *testing.T) {
		if got, _ := AirtablePersonalAccessToken().Find(harnessAPIKeyTestKey); len(got) != 0 {
			t.Errorf("Find(%q) = %v, want no span", harnessAPIKeyTestKey, got)
		}
	})

	t.Run("the two written apart are two redactions", func(t *testing.T) {
		src := airtable + " " + harnessAPIKeyTestKey
		want := strings.Repeat("*", 82) + " " + strings.Repeat("*", 72)

		m := New(WithPatterns(AirtablePersonalAccessToken(), HarnessAPIKey()))
		if got := m.Mask(src); got != want {
			t.Errorf("Mask(%q) = %q, want %q", src, got, want)
		}
	})

	t.Run("an airtable token behind a key is taken into the key's span", func(t *testing.T) {
		// The other direction: this secret's run reads on through the Airtable
		// identifier and stops at that token's own separator, so the two spans
		// overlap and Masker.locate makes them one redaction. Neither
		// credential survives it; what the reader loses is which of the two the
		// redaction is attributed to.
		src := harnessAPIKeyTestKey + airtable
		want := []Span{{0, 89}}

		if got, _ := HarnessAPIKey().Find(src); !slices.Equal(got, want) {
			t.Errorf("Find(%q) = %v, want %v", src, got, want)
		}

		m := New(WithPatterns(AirtablePersonalAccessToken(), HarnessAPIKey()))
		if got, wantMasked := m.Mask(src), strings.Repeat("*", len(src)); got != wantMasked {
			t.Errorf("Mask(%q) = %q, want %q", src, got, wantMasked)
		}
	})
}

// Test_HarnessAPIKey_holdsAKeyTheInputCutShort states, with a literal number,
// what the second return of Find settles on the shapes
// builtin_harness_api_key.go's rationale on settling names: a piece of a prefix
// standing at the end of the input, a candidate the end of the input cut short,
// a secret whose run the end of the input may still lengthen, and a whole match
// with nothing left unsettled behind it.
func Test_HarnessAPIKey_holdsAKeyTheInputCutShort(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		want   []Span
		retain int
	}{
		{
			// A piece of a prefix stands at the very end of the input: it could
			// still grow into "pat." with one more byte, so nothing behind where
			// it opens is settled.
			name:   "a piece of a prefix at the end of the input",
			src:    "pat",
			retain: 0,
		},
		{
			// The same piece with prose in front of it, so what is unsettled is
			// only the piece itself rather than the whole input.
			name:   "a piece of a prefix behind prose",
			src:    "the key starts with pat",
			retain: len("the key starts with "),
		},
		{
			// A whole prefix and identifiers the input cuts short before the
			// counts are met. The candidate could still become a key were the
			// input longer, so what is unsettled reaches back to where the
			// candidate opened rather than to the byte the input stopped at.
			name:   "identifiers the input cuts short of the counts",
			src:    "pat.0123456789abcdefghijkl.0123456789abc",
			retain: 0,
		},
		{
			// The same, with a candidate that had already failed: the first
			// character of its account identifier is a plus sign, so no text
			// carrying on from here could have made it a key. The scan settles
			// where the candidate opened all the same, which is the decision
			// builtin_scan.go argues.
			name:   "identifiers the input cuts short, already carrying a character no part holds",
			src:    "pat.+123456789abcdefghijkl.0123456789abc",
			retain: 0,
		},
		{
			// A whole key at the end of the input. The secret is read as a floor
			// and the run reaches the end, so what comes next could lengthen the
			// span: the key is reported and the text from where it opened is
			// held back all the same.
			name:   "a whole key at the end of the input",
			src:    harnessAPIKeyTestKey,
			want:   []Span{{0, 72}},
			retain: 0,
		},
		{
			// A run already past the floor, with the same answer for the same
			// reason: what the floor has settled is whether there is a key here,
			// never where it ends.
			name:   "a secret past the floor at the end of the input",
			src:    harnessAPIKeyTestKey + "k",
			want:   []Span{{0, 73}},
			retain: 0,
		},
		{
			// A whole key with more text after it, ending in a byte that opens
			// no piece of a prefix, so nothing at the end of the input is left
			// unsettled — the key found is reported and the input is settled to
			// its end.
			name:   "a whole key followed by settled text",
			src:    harnessAPIKeyTestKey + " tail",
			want:   []Span{{0, 72}},
			retain: 77,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := HarnessAPIKey().Find(tt.src)
			if retain != tt.retain {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, retain, tt.retain)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HarnessAPIKey_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor over the secret's run, and what holds it linear
	// is the separator: a secret begins one byte past a full stop and no part of
	// a key is written with one, so a run ends before the next candidate's
	// secret begins and no two candidates read the same run. These are the
	// inputs that would find that wrong.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// whole key apiece and so hold a candidate every seventy-two bytes at their
	// densest. The crowding a line can actually carry stays here.
	sources := map[string]string{
		// A candidate at every fourth byte, each turned away at the first
		// separator it asks for: the twenty-third character behind the prefix is
		// a t rather than a full stop.
		"a candidate every four characters": strings.Repeat("pat.", 400000),
		// The densest crowding a key can be written at, and the worst case for
		// the run walk. Each unit is forty-eight bytes and its token identifier
		// closes on the three letters of the next prefix, so a candidate opens
		// every forty-eight bytes, reads its identifiers whole and walks a
		// twenty-two character run — which clears the floor, so every one of
		// them reports a span as well.
		"a candidate every forty-eight characters": strings.Repeat("pat.0123456789abcdefghijkl.0123456789abcdefghijk", 30000),
		// One candidate whose secret is the whole of the line, which is the run
		// a scan reading it more than once would read again at every candidate.
		"a secret the length of the line": "pat.0123456789abcdefghijkl.0123456789abcdefghijklmn." + strings.Repeat("a", 2000000),
		// The same run with no prefix in front of it, so no candidate is found
		// in it at all.
		"a base62 run with no prefix": strings.Repeat("a", 2000000),
	}

	checkScanIsLinear(t, HarnessAPIKey(), sources)
}

// Test_harnessAPIKeyAnchor holds the byte the scan searches the input for to
// standing at the index every prefix carries it at, and to being a character no
// part of a key is written with.
//
// The first half is what builtin_scan.go asks of every anchor: a prefix carrying
// it somewhere else is a prefix no candidate is ever found at, and nothing that
// was passing would stop passing. The second is what the argument that no two
// candidates read one run rests on, which
// Test_harnessAPIKeySeparator_runsDoNotOverlap states in full.
func Test_harnessAPIKeyAnchor(t *testing.T) {
	for _, prefix := range harnessAPIKeyPrefixes {
		if harnessAPIKeyAnchorIndex >= len(prefix) {
			t.Fatalf("the anchor stands at %d, the prefix %q is %d characters", harnessAPIKeyAnchorIndex, prefix, len(prefix))
		}
		if c := prefix[harnessAPIKeyAnchorIndex]; c != harnessAPIKeyAnchor {
			t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", prefix, c, byte(harnessAPIKeyAnchor))
		}
		if n := strings.Count(prefix, string(rune(harnessAPIKeyAnchor))); n != 1 {
			t.Errorf("the prefix %q carries the anchor %q %d times, so a candidate can open inside one", prefix, byte(harnessAPIKeyAnchor), n)
		}
	}
}

// Test_harnessAPIKeyKinds holds the kinds to what the scan takes for granted
// about them: that each is the same width, that the prefix built from one closes
// on the separator, and that no two of them stand at one position.
//
// The last is what lets harnessAPIKeyOpens return at the first prefix that
// matches. Two kinds sharing a first character would still be told apart by the
// rest of them at this width, but a kind added later that was a piece of another
// would not, and the scan would then read the shorter of the two and locate a
// key whose account identifier began one character early.
func Test_harnessAPIKeyKinds(t *testing.T) {
	for _, kind := range harnessAPIKeyKinds {
		if len(kind) != harnessAPIKeyKindChars {
			t.Errorf("the kind %q is %d characters, the scan reads every one of them as %d", kind, len(kind), harnessAPIKeyKindChars)
		}
	}

	seen := make(map[string]bool, len(harnessAPIKeyPrefixes))
	for _, prefix := range harnessAPIKeyPrefixes {
		if len(prefix) != harnessAPIKeyPrefixChars {
			t.Errorf("the prefix %q is %d characters, the scan reads every one of them as %d", prefix, len(prefix), harnessAPIKeyPrefixChars)
		}
		if prefix[len(prefix)-1] != harnessAPIKeySeparator {
			t.Errorf("the prefix %q does not close on the separator %q, so the run guarantee does not hold for it", prefix, byte(harnessAPIKeySeparator))
		}
		if seen[prefix] {
			t.Errorf("the prefix %q is written twice", prefix)
		}
		seen[prefix] = true
	}

	for _, prefix := range harnessAPIKeyPrefixes {
		for _, other := range harnessAPIKeyPrefixes {
			if prefix != other && strings.HasPrefix(prefix, other) {
				t.Errorf("the prefix %q opens with %q, so the two stand at one position and the scan reads whichever it tries first", prefix, other)
			}
		}
	}
}

// Test_harnessAPIKeySeparator_runsDoNotOverlap holds the character the scan's
// linearity rests on: the separator belongs to neither class a part of a key is
// written in.
//
// That is what leaves a secret's run beginning where a run of its alphabet
// begins. A candidate behind this one writes a separator one byte in front of
// its own secret, and that separator ends this candidate's run — so the two read
// runs that do not overlap, and a line dense in prefixes costs the scan one pass
// rather than one per candidate. Test_HarnessAPIKey_scanIsLinear drives the
// inputs that would find it wrong.
func Test_harnessAPIKeySeparator_runsDoNotOverlap(t *testing.T) {
	if isBase62Byte(harnessAPIKeySeparator) {
		t.Errorf("the separator %q is a character the token identifier and the secret are written with, so two candidates can read one run", byte(harnessAPIKeySeparator))
	}
	if isBase64URLByte(harnessAPIKeySeparator) {
		t.Errorf("the separator %q is a character the account identifier is written with, so it ends no identifier", byte(harnessAPIKeySeparator))
	}
}

// Test_harnessAPIKeyChars holds the arithmetic to the numbers this pattern's
// documentation states: the four characters of a prefix, the twenty-two of the
// account identifier, the twenty-four of the token identifier, the twenty the
// secret is held to and the seventy-two a key comes to at that floor.
//
// What it holds is the documentation rather than the scan. The scan never states
// a whole key: it reads each part from where the one in front of it ended, so a
// prefix of another width would be located correctly and nothing would go wrong.
// What would go wrong is the sentence on HarnessAPIKey promising those counts,
// and the spans every case in this file is written with.
func Test_harnessAPIKeyChars(t *testing.T) {
	const (
		documentedPrefixChars  = 4
		documentedAccountChars = 22
		documentedTokenChars   = 24
		documentedSecretChars  = 20
		documentedChars        = 72
	)

	if harnessAPIKeyPrefixChars != documentedPrefixChars {
		t.Errorf("a prefix is read as %d characters, the documentation promises %d", harnessAPIKeyPrefixChars, documentedPrefixChars)
	}
	if harnessAPIKeyAccountChars != documentedAccountChars {
		t.Errorf("the account identifier is read as %d characters, the documentation promises %d", harnessAPIKeyAccountChars, documentedAccountChars)
	}
	if harnessAPIKeyTokenChars != documentedTokenChars {
		t.Errorf("the token identifier is read as %d characters, the documentation promises %d", harnessAPIKeyTokenChars, documentedTokenChars)
	}
	if harnessAPIKeySecretChars != documentedSecretChars {
		t.Errorf("the secret is held to %d characters, the documentation promises %d", harnessAPIKeySecretChars, documentedSecretChars)
	}
	if harnessAPIKeyChars != documentedChars {
		t.Errorf("the shortest key is read as %d characters, the documentation promises %d", harnessAPIKeyChars, documentedChars)
	}
}

// Test_harnessAPIKeyFindBenchmarks_lineTheAnchorWasChosenAgainst holds the line
// these benchmarks are written on to the counts the choice of anchor was read
// off: the full stop stands twice, both times in the vendor's own host name,
// where the two letters every prefix shares stand far more often.
func Test_harnessAPIKeyFindBenchmarks_lineTheAnchorWasChosenAgainst(t *testing.T) {
	line := harnessAPIKeyFindBenchmarks()[0].src

	counts := map[byte]int{'.': 2, 'a': 4, 't': 3}
	for c, want := range counts {
		if got := strings.Count(line, string(c)); got != want {
			t.Errorf("the line carries %q %d times, where the choice of anchor was read off %d", c, got, want)
		}
	}
}

// referenceHarnessAPIKeyAt reports where a Harness API key written at start
// ends, and whether one is written there at all. It is the statement of what the
// scan in builtin_harness_api_key.go locates, kept here so that the scan can be
// held to it, and it reads one position and stops.
//
// The prefixes, the three counts, the separator and both character classes are
// written out here rather than read from the scan. Reading them would move this
// with whatever the scan was changed to, and the fuzz target below would then
// hold a rule against itself; Test_references_shareNoDeclarationWithTheScans is
// what keeps the two apart.
//
// It is written out rather than built on a regular expression, and the floor is
// what settles that: a counted repetition with a floor costs an engine a machine
// as wide as the floor at every candidate, which builtin-patterns.md names as one
// of the two shapes that have made an expression too slow to fuzz with, and the
// input this reference is asked at every byte of can crowd candidates every four
// bytes. Measured over a cleaned fuzz cache at the thirty seconds CI gives a
// target, the expression
// `(?:pat|sat)\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{20,}` asked the
// same way reached 583,548 executions against the walks below at 2,443,209 — a
// quarter of the rate, and falling rather than holding: the expression's last
// three seconds ran at 2,941 executions a second against the 16,400 it managed
// up to twenty-four, where the walks hold their rate for the whole thirty.
func referenceHarnessAPIKeyAt(src string, start int) (int, bool) {
	if !strings.HasPrefix(src[start:], "pat.") && !strings.HasPrefix(src[start:], "sat.") {
		return 0, false
	}

	account := start + 4
	accountEnd := account + 22
	token := accountEnd + 1
	tokenEnd := token + 24
	secret := tokenEnd + 1
	if secret > len(src) {
		return 0, false
	}

	for i := account; i < accountEnd; i++ {
		if !referenceHarnessAPIKeyAccountByte(src[i]) {
			return 0, false
		}
	}
	if src[accountEnd] != '.' {
		return 0, false
	}
	for i := token; i < tokenEnd; i++ {
		if !referenceHarnessAPIKeySecretByte(src[i]) {
			return 0, false
		}
	}
	if src[tokenEnd] != '.' {
		return 0, false
	}

	end := secret
	for end < len(src) && referenceHarnessAPIKeySecretByte(src[end]) {
		end++
	}
	if end-secret < 20 {
		return 0, false
	}
	return end, true
}

// referenceHarnessAPIKeyAccountByte reports whether c is a character the account
// identifier is written with: the base64url alphabet of RFC 4648.
func referenceHarnessAPIKeyAccountByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z' ||
		c == '-' || c == '_'
}

// referenceHarnessAPIKeySecretByte reports whether c is a character the token
// identifier and the secret are written with: the letters of both cases and the
// digits, and neither of the two base64url adds to those.
func referenceHarnessAPIKeySecretByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z'
}

// referenceHarnessAPIKeyFind locates keys the plain way: every position in turn,
// with nothing remembered between them. It is the control flow of the scan with
// the grammar above in place of the byte tests the scan reads it with.
//
// Asking at every position is what the scan does too, and it is not written here
// to restate that. A reference is written to know nothing its scan claims, and
// where a key may begin is one of the things the scan claims — so this one asks
// at every byte all the same, and the fuzz target below is what holds the two to
// the same answer.
func referenceHarnessAPIKeyFind(src string) []Span {
	var spans []Span
	for i := range len(src) {
		if end, ok := referenceHarnessAPIKeyAt(src, i); ok {
			spans = append(spans, Span{Start: i, End: end})
		}
	}
	return spans
}

// FuzzHarnessAPIKey_matchesReference guards the hand-written scan: the byte it
// searches for, the prefixes it reads forward from that byte, the two counts it
// reads exactly, the floor it holds the secret to, the separators between them
// and the two character classes may none of them change which keys are located.
func FuzzHarnessAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("HARNESS_API_KEY=pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij")
	f.Add("sat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij")
	f.Add("pat.0123456789abcdefghij.0123456789abcdefghijklmn.0123456789abcdefghij")             // an account identifier one short
	f.Add("pat.0123456789abcdefghijklm.0123456789abcdefghijklmn.0123456789abcdefghij")          // and one long
	f.Add("pat.0123456789abcdefghijkl.0123456789abcdefghijklm.0123456789abcdefghij")            // a token identifier one short
	f.Add("pat.0123456789abcdefghijkl.0123456789abcdefghijklmno.0123456789abcdefghij")          // and one long
	f.Add("pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghi")            // a secret one short of the floor
	f.Add("pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghijk")          // and one past it
	f.Add("pat.-123456789abcdefghijk_.0123456789abcdefghijklmn.0123456789abcdefghij")           // the two characters base64url adds, in the account identifier
	f.Add("pat.0123456789abcdefghijkl.-123456789abcdefghijklm_.0123456789abcdefghij")           // and where the token identifier admits neither
	f.Add("pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.-123456789abcdefghi_")           // and where the secret admits neither
	f.Add("pat.+123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij")           // a character outside base64url
	f.Add("pat.0123456789ABCDEFGHIJKL.0123456789ABCDEFGHIJKLMN.0123456789ABCDEFGHIJ")           // an uppercase body
	f.Add("PAT.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij")           // an uppercase prefix
	f.Add("xat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij")           // a kind nobody issues
	f.Add("pat0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij")            // the prefix without its separator
	f.Add("pat.0123456789abcdefghijkl0123456789abcdefghijklmn.0123456789abcdefghijkl")          // no separator between the identifiers
	f.Add("pat.0123456789abcdefghijkl.0123456789abcdefghijklmn0123456789abcdefghij")            // and none in front of the secret
	f.Add("pat.0123456789ab.defghijkl.0123456789abcdefghijklmn.0123456789abcdefghij")           // a separator standing where none does
	f.Add("pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789ab\ndefghij")          // a secret a line break breaks
	f.Add("xpat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij")          // written against a letter
	f.Add("compat.0123456789abcdefghijkl.0123456789abcdefghijklm.0123456789abcdefghij")         // and behind a word closing on the three letters
	f.Add("pat.0123456789abcdef0123456789abcdef and the line carries on")                       // an md5 behind the prefix
	f.Add("org.example.compat.legacy.ClientAdapter was loaded from the shaded jar")             // a package path
	f.Add("the change is backwards compat. the release note says so")                           // and a sentence closing on the three letters
	f.Add("pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") // an airtable token, which opens on the same three letters
	// A key beginning inside another, and two keys written with nothing between
	// them, which is what advancing rather than consuming the match has to find.
	f.Add("pat.0123456789abcdefghijkl.0123456789abcdefghijkpat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij tail")
	f.Add("pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghijsat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789abcdefghij")
	// Candidate positions crowded as close as they can be, and a base62 run with
	// no prefix in front of it.
	f.Add(strings.Repeat("pat.", 32))
	f.Add(strings.Repeat("pat.0123456789abcdefghijkl.0123456789abcdefghijk", 8))
	f.Add(strings.Repeat("0123456789abcdef", 16))
	// The pieces of a prefix the end of the input can cut short.
	f.Add("the key starts with pat")
	f.Add("pat.0123456789abcdefghijkl.0123456789abc")

	fuzzAgainstReference(f, HarnessAPIKey().Find, referenceHarnessAPIKeyFind)
}

// harnessAPIKeyFindBenchmarks is what this scan is timed on. The builtinPatterns
// entry for the pattern names it, and BenchmarkBuiltins times every case it
// holds under the pattern's own name, so that a built-in cannot arrive without a
// benchmark. Every case is held to the count it states under a plain go test as
// well, which is what a benchmark nobody has run yet cannot be.
func harnessAPIKeyFindBenchmarks() []benchmarkCase {
	// The line carries the byte the scan searches for twice, both times in the
	// vendor's own host name, and neither opens a candidate. The two letters
	// every prefix shares stand four and three times over the same line, which
	// is what the full stop was chosen against.
	// Test_harnessAPIKeyFindBenchmarks_lineTheAnchorWasChosenAgainst holds it to
	// those counts.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://app.harness.io/v1/orgs `
	key := harnessAPIKeyTestKey

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A prefix written over and over, so a candidate stands at every
			// fourth byte and every one of them is turned away at the first
			// separator it asks for. That is the cheapest this scan declines a
			// candidate whose prefix is whole.
			name:  "candidates that are not values",
			src:   strings.Repeat("pat.", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: both identifiers walked whole
			// before the floor turns the candidate away.
			name:  "candidates walked past their identifiers",
			src:   strings.Repeat("pat.0123456789abcdefghijkl.0123456789abcdefghijklmn.0123456789 ", 16),
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
