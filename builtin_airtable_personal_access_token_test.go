package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Airtable personal access token pattern: what it locates and what it
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
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. The rest of an identifier is fourteen characters,
// written here as the front of 0123456789abcdef; the secret behind the dot is
// sixty-four hexadecimal characters, written as that run four times over. With
// the prefix in front a token comes to eighty-two characters. Where a case
// turns on what an identifier may hold, it holds the prefix itself instead.

func Test_AirtablePersonalAccessToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 82}},
		},
		{
			name: "a token in an environment assignment",
			src:  "AIRTABLE_API_KEY=pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{17, 99}},
		},
		{
			name: "an identifier of letters and digits in both cases",
			src:  "patABCDEFghij0123.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 82}},
		},
		{
			// The counts are read exactly, so what follows the eighty-second
			// character is not part of the token and stays in the text.
			name: "a run longer than the count is a token and what follows it",
			src:  "pat0123456789abcd.01234567890123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 82}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefpat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 82}, {82, 164}},
		},
		{
			// The prefix written twice over. The dot the first candidate wants
			// falls three characters short of the one written, so the token is
			// the one the second prefix opens.
			name: "a prefix in front of a token",
			src:  "patpat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{3, 85}},
		},
		{
			// The four-part shape a chained digest or another OAuth-style
			// string takes: a token, a dot, and another sixty-four hexadecimal
			// characters. The count is read exactly, so the second run is not
			// part of the token and stays in the text.
			name: "a token followed by a dot and another sixty-four hexadecimal characters",
			src:  "pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 82}},
		},
		{
			// An identifier drawn from the letters the ordered run used
			// elsewhere in this file never reaches.
			name: "an identifier drawn from the far end of the alphabet",
			src:  "patZYXWVUzyxwvu98.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 82}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AirtablePersonalAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AirtablePersonalAccessToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "pat",
		},
		{
			name: "an identifier with no secret behind it",
			src:  "pat0123456789abcd",
		},
		{
			name: "an identifier one character short",
			src:  "pat0123456789abc.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "an identifier one character long",
			src:  "pat0123456789abcde.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a secret one character short",
			src:  "pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "a hyphen where the separator belongs",
			src:  "pat0123456789abcd-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "no separator at all",
			src:  "pat0123456789abcd00123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a second separator inside the secret",
			src:  "pat0123456789abcd.0123456789abcdef0123456789abcdef.123456789abcdef0123456789abcdef",
		},
		{
			name: "a hyphen in the identifier",
			src:  "pat0123456789-bcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "an underscore in the identifier",
			src:  "pat0123456789_bcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a letter outside hexadecimal in the secret",
			src:  "pat0123456789abcd.0123456789abcdefg123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a hyphen in the secret",
			src:  "pat0123456789abcd.0123456789abcdef-123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a space in the secret",
			src:  "pat0123456789abcd.0123456789abcdef 123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The case the environment variable holding a token is spelled in,
			// which is one reason the prefix is read in a single case.
			name: "an uppercase prefix",
			src:  "PAT0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "the prefix without its closing letter",
			src:  "pa0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a body of the right shape opening with no prefix",
			src:  "xyz0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The identifier Airtable keeps a token under, written without the
			// secret it is a prefix of.
			name: "an identifier of another kind",
			src:  "usr0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a sha-256 with no identifier in front of it",
			src:  "sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "prose opening on the prefix",
			src:  "the patch is on the path to the patient pattern",
		},
		{
			name: "a log line",
			src:  `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.airtable.com/v0/meta/whoami`,
		},
		{
			// A dot standing one character early, with the identifier's own
			// characters carrying on behind it. This is what separates a scan
			// reading the separator at a fixed position from one searching for
			// it anywhere in the identifier.
			name: "a dot one character early with more identifier-shaped text behind it",
			src:  "pat012345.789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a space inside the identifier",
			src:  "pat0123456789 bcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The character straight behind the dot standing outside
			// hexadecimal, so the secret's own alphabet is broken at its very
			// first byte rather than in the middle where every other case here
			// breaks it.
			name: "a character outside hexadecimal at the first character of the secret",
			src:  "pat0123456789abcd.g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a secret broken by a carriage return and a line feed",
			src:  "pat0123456789abcd.0123456789abcdef\r\n123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AirtablePersonalAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_AirtablePersonalAccessToken_inContext(t *testing.T) {
	// The places a token is written. The environment variable and the bearer
	// header are Airtable's own: its JavaScript client reads a token out of
	// AIRTABLE_API_KEY and sends it as "Authorization: Bearer", and its README
	// writes the export. The rest are the shapes any credential is carried in.
	const token = "pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token in the environment assignment the client reads",
			src:  "AIRTABLE_API_KEY=" + token,
			want: []Span{{17, 17 + len(token)}},
		},
		{
			name: "a token in a bearer token header",
			src:  "Authorization: Bearer " + token,
			want: []Span{{22, 22 + len(token)}},
		},
		{
			name: "a token on a command line",
			src:  "curl -H 'Authorization: Bearer " + token + "' https://api.airtable.com/v0/meta/whoami",
			want: []Span{{31, 31 + len(token)}},
		},
		{
			name: "a token in json",
			src:  `{"personalAccessToken":"` + token + `"}`,
			want: []Span{{24, 24 + len(token)}},
		},
		{
			name: "a token in a log line",
			src:  `time=2026-08-17T00:00:00Z level=info msg="calling api" token=` + token,
			want: []Span{{61, 61 + len(token)}},
		},
		{
			name: "a token at the end of a sentence",
			src:  "the token is " + token + ".",
			want: []Span{{13, 13 + len(token)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AirtablePersonalAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AirtablePersonalAccessToken_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match. A word boundary in front
	// would drop the whole match rather than trim it wherever a token is
	// written against a word character, and one behind it would drop a token
	// followed by a letter or a digit.
	const token = "pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token after an underscore",
			src:  "AIRTABLE_PERSONAL_ACCESS_TOKEN_" + token,
			want: []Span{{31, 31 + len(token)}},
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
			name: "a hexadecimal character written against a token",
			src:  token + "0",
			want: []Span{{0, len(token)}},
		},
		{
			name: "a token after a dot",
			src:  "airtable." + token,
			want: []Span{{9, 9 + len(token)}},
		},
		{
			// A multi-byte rune standing flush against the token on both
			// sides, with no space between them.
			name: "a multi-byte rune flush against the token on both sides",
			src:  "日本語" + token + "日本語",
			want: []Span{{9, 9 + len(token)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AirtablePersonalAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AirtablePersonalAccessToken_anUppercaseSecret(t *testing.T) {
	// The secret is read in lowercase hexadecimal, which is what every ruleset
	// reading this format reads, what every published token carries and what a
	// hexadecimal encoder settles once for all of its output. Admitting the
	// other case is the widening the rationale declines, and these are the cases
	// that would move if it were taken. The identifier is a separate question
	// and is read in both cases, which the last case here is of.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an uppercase secret",
			src:  "pat0123456789abcd.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: nil,
		},
		{
			name: "a secret mixing the two cases",
			src:  "pat0123456789abcd.0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef",
			want: nil,
		},
		{
			name: "one uppercase character in a secret",
			src:  "pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeF",
			want: nil,
		},
		{
			name: "an uppercase identifier, which is read",
			src:  "patABCDEFGHIJKLMN.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 82}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AirtablePersonalAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AirtablePersonalAccessToken_aDigestBehindAnIdentifier(t *testing.T) {
	// The collision this format leaves. Sixty-four lowercase hexadecimal
	// characters behind a seventeen character word and a dot is the vendor's
	// format exactly, and a SHA-256 is sixty-four of them, so a word of that
	// length in front of one is a token character for character. The shorter
	// digests are not secrets at any length, and a digest with no word in front
	// of it carries no prefix and reaches nothing.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a word of sixteen characters in front of a sha-256",
			src:  "patchnotes123456.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: nil,
		},
		{
			name: "a sha-256 behind a word of exactly seventeen characters",
			src:  "patchnotes1234567.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 82}},
		},
		{
			name: "a sha-1 behind a word of exactly seventeen characters",
			src:  "patchnotes1234567.0123456789abcdef0123456789abcdef01234567",
			want: nil,
		},
		{
			name: "an md5 behind a word of exactly seventeen characters",
			src:  "patchnotes1234567.0123456789abcdef0123456789abcdef",
			want: nil,
		},
		{
			// A UUID is thirty-two hexadecimal characters divided by hyphens,
			// and a hyphen is no character a secret is written with.
			name: "a uuid behind a word of exactly seventeen characters",
			src:  "patchnotes1234567.01234567-89ab-cdef-0123-456789abcdef",
			want: nil,
		},
		{
			name: "a sha-256 on its own",
			src:  "sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AirtablePersonalAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AirtablePersonalAccessToken_noTokenBeginsInsideAnother(t *testing.T) {
	// The claim builtin_airtable_personal_access_token.go makes: the spans of
	// this pattern never overlap one another. A token holds one separator, at
	// its eighteenth character, and everything behind that separator is
	// hexadecimal — an alphabet holding neither the p nor the t of the prefix.
	// So a second token beginning inside this one would want a separator
	// seventeen characters along and find hexadecimal, or would have to open on
	// a p the secret cannot hold.
	//
	// It is not a claim one input can state, so a whole token is written into
	// every position of another here — at each character of its prefix, of its
	// identifier and of its secret, and against either end — with nothing, a
	// secret and a second token behind it in turn. The identifier carries the
	// prefix itself, so the positions inside a span that could open a candidate
	// at all are the ones driven. What is asserted is only that no two spans
	// overlap; where the tokens fall is what the table at the top of this file
	// is for.
	secret := strings.Repeat("0123456789abcdef", 4)
	token := airtablePersonalAccessTokenPrefix + "pat0123456789a" + "." + secret
	p := AirtablePersonalAccessToken()

	for i := range len(token) + 1 {
		for _, tail := range []string{"", secret, token} {
			src := token[:i] + token + token[i:] + tail
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

func Test_AirtablePersonalAccessToken_aPrefixInsideAnIdentifier(t *testing.T) {
	// The identifier is written in an alphabet that holds every character of
	// the prefix, so a candidate opens inside one. What closes that candidate
	// is the separator it wants: seventeen characters past a p standing in an
	// identifier is the secret, and the secret is hexadecimal.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an identifier opening on the prefix",
			src:  "patpat0123456789a.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 82}},
		},
		{
			name: "an identifier closing on the prefix",
			src:  "pat0123456789apat.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 82}},
		},
		{
			name: "a token whose identifier opens on the prefix, written after another",
			src:  "pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefpatpat0123456789a.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 82}, {82, 164}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AirtablePersonalAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

// Test_AirtablePersonalAccessToken_settlesWhatTheInputCutShort holds Find's
// second return to the offset in front of which nothing further back can
// still become a token, which is either a piece of the prefix standing at the
// end of the input or a candidate the end of the input cut short. What every
// built-in owes about that offset over generated text and over the samples is
// driven in builtins_test.go and fuzz_test.go; what is written out here is
// which inputs of this pattern's own shape hold anything back, since nothing
// else names them.
func Test_AirtablePersonalAccessToken_settlesWhatTheInputCutShort(t *testing.T) {
	const token = "pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tests := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "the prefix alone",
			src:  "pat",
			want: 0,
		},
		{
			// An identifier complete but with no separator or secret behind
			// it, held back from its own start rather than from further back.
			name: "an identifier with nothing behind it",
			src:  "pat0123456789abcd",
			want: 0,
		},
		{
			name: "a secret the end of the input cut short",
			src:  "pat0123456789abcd.0123456789abcdef",
			want: 0,
		},
		{
			// A token reaching the end of the input. Nothing is read behind
			// either count, and the alphabets carry none of the bytes the
			// prefix is written with, so nothing is held back.
			name: "a whole token reaching the end of the input",
			src:  token,
			want: len(token),
		},
		{
			name: "a whole token followed by a character that opens no prefix",
			src:  token + " ",
			want: len(token) + 1,
		},
		{
			// The candidate cut short by the end of the input, held back from
			// its own start rather than from the prose in front of it.
			name: "a candidate cut short held from its own start rather than further back",
			src:  "AIRTABLE_API_KEY=pat0123456789abcd",
			want: 17,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, got := AirtablePersonalAccessToken().Find(tt.src); got != tt.want {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, got, tt.want)
			}
		})
	}
}

// Test_AirtablePersonalAccessToken_scanIsLinear drives the crowding this scan
// is most exposed to: the anchor is the p the prefix opens with, and it stands
// nowhere else in either alphabet the format is read in, so a run of either one
// holds no candidate at all. What does hold a candidate at every three bytes is
// the prefix itself repeated, and the scan reads a fixed count at each rather
// than keeping a cursor, so nothing here is expected to cost more than that
// count times the number of candidates.
func Test_AirtablePersonalAccessToken_scanIsLinear(t *testing.T) {
	checkScanIsLinear(t, AirtablePersonalAccessToken(), map[string]string{
		"a prefix every three characters":           strings.Repeat("pat", 700000),
		"an anchor with no prefix behind it":        strings.Repeat("p", 3000000),
		"a run of the secret alphabet":              strings.Repeat("0123456789abcdef", 200000),
		"candidates walked to their last character": strings.Repeat("pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde ", 30000),
	})
}

func Test_airtablePersonalAccessTokenPrefix(t *testing.T) {
	// The prefix is the three letters an Airtable identifier of this kind opens
	// with, and two of the three stand outside the alphabet the secret is
	// written in. That is what a run of hexadecimal opening no candidate rests
	// on, and it is half of the claim that no token begins inside another,
	// which Test_AirtablePersonalAccessToken_noTokenBeginsInsideAnother drives
	// and which a prefix built any other way would make false without failing
	// there.
	if got := airtablePersonalAccessTokenPrefix; got != "pat" {
		t.Errorf("airtablePersonalAccessTokenPrefix = %q, want %q", got, "pat")
	}
	outside := 0
	for i := range len(airtablePersonalAccessTokenPrefix) {
		if !isAirtablePersonalAccessTokenSecretByte(airtablePersonalAccessTokenPrefix[i]) {
			outside++
		}
	}
	if want := 2; outside != want {
		t.Errorf("%d character(s) of the prefix stand outside the secret alphabet, want %d", outside, want)
	}

	// The other half of the claim: the separator belongs to neither alphabet,
	// so a token holds exactly one and it stands at one index. A separator a
	// secret could hold would put a second one inside a span and open a
	// position for a token to begin at.
	if isBase62Byte(airtablePersonalAccessTokenSeparator) {
		t.Errorf("the separator %q is a character an identifier may be written with",
			airtablePersonalAccessTokenSeparator)
	}
	if isAirtablePersonalAccessTokenSecretByte(airtablePersonalAccessTokenSeparator) {
		t.Errorf("the separator %q is a character a secret may be written with",
			airtablePersonalAccessTokenSeparator)
	}

	// Every character of the prefix is one an identifier may hold, which is why
	// a candidate opens inside one and why the scan advances a byte rather than
	// a match. Test_AirtablePersonalAccessToken_aPrefixInsideAnIdentifier
	// drives what happens there.
	for i := range len(airtablePersonalAccessTokenPrefix) {
		if !isBase62Byte(airtablePersonalAccessTokenPrefix[i]) {
			t.Errorf("the prefix carries %q, which an identifier may not hold",
				airtablePersonalAccessTokenPrefix[i])
		}
	}
}

func Test_airtablePersonalAccessTokenAnchor(t *testing.T) {
	// The byte the scan searches for stands at the index it reads a candidate
	// back from. A prefix or an index changed without the other leaves the scan
	// opening candidates nowhere near where a token begins, and what such a scan
	// finds is nothing at all rather than something wrong.
	if got := airtablePersonalAccessTokenPrefix[airtablePersonalAccessTokenAnchorIndex]; got != airtablePersonalAccessTokenAnchor {
		t.Errorf("airtablePersonalAccessTokenPrefix[%d] = %q, want the anchor %q",
			airtablePersonalAccessTokenAnchorIndex, got, airtablePersonalAccessTokenAnchor)
	}

	// What the anchor costs, counted rather than claimed in prose: it stands
	// once in the prefix, so a line of tokens stops the search once a token, and
	// nowhere in a secret, so a digest of any length stops it not at all. The a
	// is the character that would not do, and it is the reason this one is worth
	// counting: it is written in the secret's alphabet.
	if n := strings.Count(airtablePersonalAccessTokenPrefix, string(airtablePersonalAccessTokenAnchor)); n != 1 {
		t.Errorf("the anchor stands %d times in %q, want 1", n, airtablePersonalAccessTokenPrefix)
	}
	if isAirtablePersonalAccessTokenSecretByte(airtablePersonalAccessTokenAnchor) {
		t.Errorf("the anchor %q is a character a secret may be written with", airtablePersonalAccessTokenAnchor)
	}
}

func Test_airtablePersonalAccessTokenChars(t *testing.T) {
	// The three letters, the fourteen characters that finish the identifier,
	// the separator and the sixty-four of the secret. The first two are the
	// seventeen characters every Airtable ID is written to, which is what makes
	// the fourteen readable at all, and the whole comes to eighty-two.
	if got := len(airtablePersonalAccessTokenPrefix); got != 3 {
		t.Errorf("len(airtablePersonalAccessTokenPrefix) = %d, want 3", got)
	}
	if got := airtablePersonalAccessTokenIDChars; got != 14 {
		t.Errorf("airtablePersonalAccessTokenIDChars = %d, want 14", got)
	}
	if got := len(airtablePersonalAccessTokenPrefix) + airtablePersonalAccessTokenIDChars; got != 17 {
		t.Errorf("an identifier is %d characters, want 17", got)
	}
	if got := airtablePersonalAccessTokenSecretChars; got != 64 {
		t.Errorf("airtablePersonalAccessTokenSecretChars = %d, want 64", got)
	}
	if got := airtablePersonalAccessTokenBodyChars; got != 79 {
		t.Errorf("airtablePersonalAccessTokenBodyChars = %d, want 79", got)
	}
	if got := airtablePersonalAccessTokenChars; got != 82 {
		t.Errorf("airtablePersonalAccessTokenChars = %d, want 82", got)
	}
}

// referenceAirtablePersonalAccessToken is the grammar as a regular expression:
// the three letters an identifier of this kind opens with, the fourteen
// characters and the alphabet that finish it, the separator, and the count and
// the lowercase alphabet of the secret behind it. Every part of it is spelled
// again rather than read from the scan, so that the two can disagree and the
// target below report it.
//
// It is built on an expression rather than written out because both counts are
// exact, so an engine reads its machine once and stops, and because the opening
// is a literal an engine can search the text for rather than a class it would
// have to walk its machine at every byte for.
var referenceAirtablePersonalAccessToken = regexp.MustCompile(`pat[0-9A-Za-z]{14}\.[0-9a-f]{64}`)

// referenceAirtablePersonalAccessTokenFind locates tokens the plain way: the
// leftmost match of the expression above, then the leftmost one beginning after
// that match's first byte, over and over, with nothing remembered between them.
//
// Asking at every byte rather than resuming past a match is what the scan does.
// No token can be written inside another here, which the rationale beside the
// scan argues, and asking at every byte is kept anyway: a reference is written
// to know nothing its scan claims, and that is a thing the scan claims.
func referenceAirtablePersonalAccessTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceAirtablePersonalAccessToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzAirtablePersonalAccessToken_matchesReference guards the hand-written
// scan: the prefix it searches for, the case it reads that prefix and either
// half in, the counts it reads on either side of the separator, the separator
// itself and the byte it resumes at may none of them change which tokens are
// located.
func FuzzAirtablePersonalAccessToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("AIRTABLE_API_KEY=pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// The counts either side of the separator, one short and one long apiece.
	f.Add("pat0123456789abc.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("pat0123456789abcde.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	f.Add("pat0123456789abcd.01234567890123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// The separator: missing, replaced, and written a second time.
	f.Add("pat0123456789abcd00123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("pat0123456789abcd-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("pat0123456789abcd.0123456789abcdef0123456789abcdef.123456789abcdef0123456789abcdef")
	// The alphabets: the identifier in both cases, the secret out of hexadecimal
	// and in the other case.
	f.Add("patABCDEFghij0123.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("pat0123456789_bcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("pat0123456789abcd.0123456789abcdefg123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("pat0123456789abcd.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
	f.Add("pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeF")
	f.Add("pat0123456789abcd.0123456789abcdef 123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("pat0123456789abcd.0123456789abcdef\n123456789abcdef0123456789abcdef0123456789abcdef")
	// The prefix: uppercase, cut short, and written where no candidate opens.
	f.Add("PAT0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("pa0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("xyz0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("usr0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// A word of prose opening on the prefix, and a digest with nothing in front
	// of it.
	f.Add("the patch is on the path to the patient pattern")
	f.Add("patchnotes1234567.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("patchnotes1234567.01234567-89ab-cdef-0123-456789abcdef")
	// Candidates crowded as close as they can be: the prefix in front of a
	// token, an identifier carrying the prefix, and two tokens with nothing
	// between them.
	f.Add("patpat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("patpat0123456789a.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("pat0123456789apat.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefpat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add(strings.Repeat("pat", 64))
	f.Add(strings.Repeat("pat", 64) + "0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add(strings.Repeat("pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 4))
	f.Add(strings.Repeat("p", 128))
	f.Add(strings.Repeat("0123456789abcdef", 8))

	fuzzAgainstReference(f, AirtablePersonalAccessToken().Find, referenceAirtablePersonalAccessTokenFind)
}

// airtablePersonalAccessTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func airtablePersonalAccessTokenFindBenchmarks() []benchmarkCase {
	// The line the anchor is chosen against: the p stands three times on it
	// where the t stands five and the a — the one character of the prefix a
	// secret may also be written with — stands seven. What the line times is the
	// search for the anchor, which is most of what this pattern costs a caller
	// whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.airtable.com/v0/meta/whoami `
	token := "pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is three characters carrying the anchor once, so a run
			// of them stops the search once every three characters and each stop
			// reads an identifier that runs into the p of the prefix three
			// characters later, where the separator is wanted fourteen further
			// on.
			name:  "candidates that are not values",
			src:   strings.Repeat("pat", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads a prefix, which is the cheapest a candidate
			// is declined for at all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("p", 4096),
			spans: 0,
		},
		{
			// The separator is tested before either run is walked, so a
			// candidate whose seventeenth character is not one is turned away by
			// a single comparison however long the run behind it is.
			name:  "candidates turned away at the separator",
			src:   strings.Repeat("pat0123456789abcde0123456789abcdef0123456789abcdef ", 16),
			spans: 0,
		},
		{
			// The other way a candidate fails: both halves of the right
			// alphabet up to the last character of the secret, so the whole of
			// it is walked before the candidate is turned away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde. ", 16),
			spans: 0,
		},
		{
			// A run of the alphabet a secret is read in, carrying no anchor at
			// all, which is what the search walks a digest of.
			name:  "a run of the secret alphabet",
			src:   strings.Repeat("0123456789abcdef", 256),
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
