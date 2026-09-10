package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Polar organization access token pattern: what it locates and what it
// leaves alone, written out case by case, and the reference its scan is held
// to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. The run they are built from,
// 0123456789abcdefghijklmnopqrstuvwxyz, is thirty-six characters, so a body is
// that run and seven characters more.

// polarOrganizationAccessTokenTestBody is the body every case here is written
// with unless it says otherwise: the ordered run, and the run again as far as
// the forty-three characters a body is.
const polarOrganizationAccessTokenTestBody = "0123456789abcdefghijklmnopqrstuvwxyz0123456"

func Test_PolarOrganizationAccessToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "polar_oat_" + polarOrganizationAccessTokenTestBody,
			want: []Span{{0, 53}},
		},
		{
			name: "a token in an environment assignment",
			src:  "POLAR_ACCESS_TOKEN=polar_oat_" + polarOrganizationAccessTokenTestBody,
			want: []Span{{19, 72}},
		},
		{
			// The upper half of the alphabet, which the run leaves untouched:
			// base62 reads every letter of both cases, and a body written in
			// capitals is a body.
			name: "a body of uppercase letters",
			src:  "polar_oat_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
			want: []Span{{0, 53}},
		},
		{
			// The run opens a body on a digit and closes it on one. Here the
			// letters stand at both ends instead, which is the alphabet driven
			// at the first character of a body and at the last rather than in
			// the middle.
			name: "a body opening and closing on a lowercase letter",
			src:  "polar_oat_abcdefghijklmnopqrstuvwxyz0123456789abcdefg",
			want: []Span{{0, 53}},
		},
		{
			name: "a body opening and closing on an uppercase letter",
			src:  "polar_oat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFG",
			want: []Span{{0, 53}},
		},
		{
			// The last character of two of the three ranges base62 is, which
			// the runs above reach at neither end of a body: the digits
			// descending open this one on a nine and an ascending run closes it
			// on a capital Z. The third range's last character stands at both
			// ends of the repeated body in
			// Test_PolarOrganizationAccessToken_theChecksumIsNotVerified.
			name: "a body opening on the last digit and closing on the last capital",
			src:  "polar_oat_9876543210abcdefghijklmnopqrstuvwxyzTUVWXYZ",
			want: []Span{{0, 53}},
		},
		{
			// The forty-three behind the prefix are read as a count and not a
			// floor: what follows the fifty-third character is not part of the
			// token and stays in the text.
			name: "an alphabet run longer than a token is a token and what follows it",
			src:  "polar_oat_" + polarOrganizationAccessTokenTestBody + "7",
			want: []Span{{0, 53}},
		},
		{
			// Neither token is inside the other, and nothing separates them.
			name: "two tokens with nothing between them",
			src:  "polar_oat_" + polarOrganizationAccessTokenTestBody + "polar_oat_" + polarOrganizationAccessTokenTestBody,
			want: []Span{{0, 53}, {53, 106}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PolarOrganizationAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PolarOrganizationAccessToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "polar_oat_",
		},
		{
			// Forty-two characters where the pattern asks for forty-three.
			name: "body one character too short",
			src:  "polar_oat_0123456789abcdefghijklmnopqrstuvwxyz012345",
		},
		{
			name: "an underscore at the first character of the body",
			src:  "polar_oat__123456789abcdefghijklmnopqrstuvwxyz0123456",
		},
		{
			name: "an underscore at the last character of the body",
			src:  "polar_oat_0123456789abcdefghijklmnopqrstuvwxyz012345_",
		},
		{
			// base64url writes the hyphen and the underscore where base62
			// writes nothing, so a body carrying either is no body.
			name: "a hyphen in the middle of the body",
			src:  "polar_oat_0123456789abcdefghij-lmnopqrstuvwxyz0123456",
		},
		{
			name: "a hyphen at the last character of the body",
			src:  "polar_oat_0123456789abcdefghijklmnopqrstuvwxyz012345-",
		},
		{
			name: "a dot in the middle of the body",
			src:  "polar_oat_0123456789abcdefghij.lmnopqrstuvwxyz0123456",
		},
		{
			name: "a dot at the last character of the body",
			src:  "polar_oat_0123456789abcdefghijklmnopqrstuvwxyz012345.",
		},
		{
			name: "a plus at the first character of the body",
			src:  "polar_oat_+123456789abcdefghijklmnopqrstuvwxyz0123456",
		},
		{
			// The bytes standing directly outside the three ranges base62 is,
			// written where the alphabet is read: the slash below the digits,
			// the colon above them, the at sign below the capitals, the
			// bracket above them, the backquote below the lowercase letters and
			// the brace above them. A body opens on the first three and closes
			// on the second three, so both ends of every range are driven.
			name: "the byte below the digits at the first character of the body",
			src:  "polar_oat_/123456789abcdefghijklmnopqrstuvwxyz0123456",
		},
		{
			name: "the byte below the capitals at the first character of the body",
			src:  "polar_oat_@123456789abcdefghijklmnopqrstuvwxyz0123456",
		},
		{
			name: "the byte below the lowercase letters at the first character of the body",
			src:  "polar_oat_`123456789abcdefghijklmnopqrstuvwxyz0123456",
		},
		{
			name: "the byte above the digits at the last character of the body",
			src:  "polar_oat_0123456789abcdefghijklmnopqrstuvwxyz012345:",
		},
		{
			name: "the byte above the capitals at the last character of the body",
			src:  "polar_oat_0123456789abcdefghijklmnopqrstuvwxyz012345[",
		},
		{
			name: "the byte above the lowercase letters at the last character of the body",
			src:  "polar_oat_0123456789abcdefghijklmnopqrstuvwxyz012345{",
		},
		{
			name: "a space at the last character of the body",
			src:  "polar_oat_0123456789abcdefghijklmnopqrstuvwxyz012345 ",
		},
		{
			name: "a body broken by a space",
			src:  "polar_oat_0123456789abcdefghij lmnopqrstuvwxyz0123456",
		},
		{
			name: "a body broken by a line break",
			src:  "polar_oat_0123456789abcdefghij\nlmnopqrstuvwxyz0123456",
		},
		{
			name: "an uppercase prefix",
			src:  "POLAR_OAT_" + polarOrganizationAccessTokenTestBody,
		},
		{
			// One letter of the prefix in the other case, rather than the whole
			// of it.
			name: "the vendor with one letter capitalized",
			src:  "Polar_oat_" + polarOrganizationAccessTokenTestBody,
		},
		{
			name: "the kind with one letter capitalized",
			src:  "polar_Oat_" + polarOrganizationAccessTokenTestBody,
		},
		{
			name: "hyphens where the prefix carries its underscores",
			src:  "polar-oat-" + polarOrganizationAccessTokenTestBody,
		},
		{
			name: "the prefix without the underscore that closes it",
			src:  "polar_oat" + polarOrganizationAccessTokenTestBody + "7",
		},
		{
			name: "the prefix without the underscore in the middle of it",
			src:  "polaroat_" + polarOrganizationAccessTokenTestBody + "7",
		},
		{
			// Fifty-three characters of the alphabet that open with something
			// else. The prefix is the whole of the anchor, so a run of the
			// right length is not a token without it.
			name: "a run of the right length opening with no prefix",
			src:  "xxxxx_xxx_" + polarOrganizationAccessTokenTestBody,
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// Forty hexadecimal characters. A digest carries no underscore, so
			// it holds no prefix to be found at.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PolarOrganizationAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PolarOrganizationAccessToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "POLAR_ACCESS_TOKEN=polar_oat_" + polarOrganizationAccessTokenTestBody,
			want: "POLAR_ACCESS_TOKEN=" + strings.Repeat("*", 53),
		},
		{
			name: "quoted",
			src:  `"polar_oat_` + polarOrganizationAccessTokenTestBody + `"`,
			want: `"` + strings.Repeat("*", 53) + `"`,
		},
		{
			name: "json",
			src:  `{"accessToken":"polar_oat_` + polarOrganizationAccessTokenTestBody + `"}`,
			want: `{"accessToken":"` + strings.Repeat("*", 53) + `"}`,
		},
		{
			// The header Polar's own API reference writes a request with.
			name: "the authorization header",
			src:  "Authorization: Bearer polar_oat_" + polarOrganizationAccessTokenTestBody,
			want: "Authorization: Bearer " + strings.Repeat("*", 53),
		},
		{
			name: "twice",
			src:  "polar_oat_" + polarOrganizationAccessTokenTestBody + " polar_oat_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
			want: strings.Repeat("*", 53) + " " + strings.Repeat("*", 53),
		},
	}

	m := New(WithPatterns(PolarOrganizationAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PolarOrganizationAccessToken_aTokenInsideAToken(t *testing.T) {
	// A token can be written inside another, in the last five characters of a
	// body and nowhere else, which is why the scan resumes a byte past the
	// start of a candidate rather than past the candidate. The five letters the
	// prefix opens with are letters a body may hold and the underscore behind
	// them is not, so an opening inside a token needs that underscore to fall
	// past the token's end. The spans overlap where it happens, and
	// Masker.locate resolves them.
	//
	// Every one of the five is driven here, since which of them a scan reaches
	// is decided by where it resumes, and they run from the furthest a candidate
	// can open inside another to the nearest. The two cases behind them are what
	// bounds the five on either side: an opening one character further in, and
	// one of the five with no body behind it.
	run := "0123456789abcdefghijklmnopqrstuvwxyz"
	body := polarOrganizationAccessTokenTestBody

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// A body closing on the whole of what the prefix opens with, so the
			// next token begins five characters from the end of this one, which
			// is the furthest inside another that one can.
			name: "a token beginning five characters from the end of another",
			src:  "polar_oat_" + run + "01polar" + "_oat_" + body,
			want: []Span{{0, 53}, {48, 101}},
		},
		{
			name: "a token beginning four characters from the end of another",
			src:  "polar_oat_" + run + "012pola" + "r_oat_" + body,
			want: []Span{{0, 53}, {49, 102}},
		},
		{
			name: "a token beginning three characters from the end of another",
			src:  "polar_oat_" + run + "0123pol" + "ar_oat_" + body,
			want: []Span{{0, 53}, {50, 103}},
		},
		{
			name: "a token beginning two characters from the end of another",
			src:  "polar_oat_" + run + "01234po" + "lar_oat_" + body,
			want: []Span{{0, 53}, {51, 104}},
		},
		{
			// The nearest of the five: a body closing on the one letter the
			// prefix opens with, and the rest of that prefix written behind the
			// token.
			name: "a token beginning at the last character of another",
			src:  "polar_oat_" + run + "012345p" + "olar_oat_" + body,
			want: []Span{{0, 53}, {52, 105}},
		},
		{
			// One character further in than the five reach, which is what
			// bounds them: the underscore such an opening needs falls at the
			// last character of what would be the body in front of it, and no
			// body carries one. So the text in front is no token, and what
			// stands here is the one token the opening began rather than two
			// tokens overlapping.
			name: "an opening one character further in than the five reach",
			src:  "polar_oat_" + run + "0" + "polar" + "_oat_" + body,
			want: []Span{{47, 100}},
		},
		{
			// The furthest of the five again, with nothing behind the opening
			// long enough to be a body, so the token it stands inside is the
			// one there is.
			name: "an opening at the end of a token with no body behind it",
			src:  "polar_oat_" + run + "01polar" + "_oat_0123456789",
			want: []Span{{0, 53}},
		},
	}

	m := New(WithPatterns(PolarOrganizationAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PolarOrganizationAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
			// The overlapping spans are redacted as one, which is what a caller
			// sees of the two.
			want := tt.src[:tt.want[0].Start] +
				strings.Repeat("*", tt.want[len(tt.want)-1].End-tt.want[0].Start) +
				tt.src[tt.want[len(tt.want)-1].End:]
			if got := m.Mask(tt.src); got != want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, want)
			}
		})
	}
}

func Test_PolarOrganizationAccessToken_aTokenBehindAFailedCandidate(t *testing.T) {
	// The other shape the scan's step is for: the candidate that failed. The
	// prefix written twice carries a token at its second prefix, and a scan
	// resuming past the fifty-three its first candidate hoped for would step
	// over it.
	src := "polar_oat_polar_oat_" + polarOrganizationAccessTokenTestBody

	want := []Span{{10, 63}}
	if got, _ := PolarOrganizationAccessToken().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}

	m := New(WithPatterns(PolarOrganizationAccessToken()))
	if got, want := m.Mask(src), "polar_oat_"+strings.Repeat("*", 53); got != want {
		t.Errorf("Mask(%q) = %q, want %q", src, got, want)
	}
}

func Test_PolarOrganizationAccessToken_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the token through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xpolar_oat_" + polarOrganizationAccessTokenTestBody,
			want: "x" + strings.Repeat("*", 53),
		},
		{
			name: "underscore before",
			src:  "POLAR_ACCESS_TOKEN_polar_oat_" + polarOrganizationAccessTokenTestBody,
			want: "POLAR_ACCESS_TOKEN_" + strings.Repeat("*", 53),
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this token
			// rather than trim it; without one the fifty-three characters Polar
			// issued are redacted and the one written after them, which is part
			// of no credential, stays in the text.
			name: "a character of the alphabet after",
			src:  "polar_oat_" + polarOrganizationAccessTokenTestBody + "7",
			want: strings.Repeat("*", 53) + "7",
		},
		{
			// A multi-byte rune written against the token on both sides.
			// Neither UTF-8 encoding shares a byte with the prefix or the
			// body's alphabet, so the token keeps its span exactly as it does
			// against a single-byte character.
			name: "a multi-byte rune before and after",
			src:  "日本語polar_oat_" + polarOrganizationAccessTokenTestBody + "日本語",
			want: "日本語" + strings.Repeat("*", 53) + "日本語",
		},
	}

	m := New(WithPatterns(PolarOrganizationAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PolarOrganizationAccessToken_leavesWhatFollowsAlone(t *testing.T) {
	// A token carries neither the hyphen nor the underscore, so ordinary
	// punctuation ends one and nothing written after it joins it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the token is polar_oat_" + polarOrganizationAccessTokenTestBody + ".",
			want: "the token is " + strings.Repeat("*", 53) + ".",
		},
		{
			name: "dashed word",
			src:  "polar_oat_" + polarOrganizationAccessTokenTestBody + "-suffix",
			want: strings.Repeat("*", 53) + "-suffix",
		},
		{
			name: "snake_case word",
			src:  "polar_oat_" + polarOrganizationAccessTokenTestBody + "_suffix",
			want: strings.Repeat("*", 53) + "_suffix",
		},
	}

	m := New(WithPatterns(PolarOrganizationAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PolarOrganizationAccessToken_theChecksumIsNotVerified(t *testing.T) {
	// Six of the forty-three are a base62 CRC32 over the thirty-seven in front
	// of them, and the scan reads them as six characters of the alphabet and
	// nothing more. Every body below fails that checksum — the ordered run is
	// no CRC32 of itself — and every one of them is redacted, which is what a
	// caller wants of a token mistyped, cut short and pasted back together, or
	// rewritten by an editor that took it for a word.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the ordered run",
			src:  "polar_oat_" + polarOrganizationAccessTokenTestBody,
		},
		{
			name: "a body of one repeated character",
			src:  "polar_oat_" + strings.Repeat("z", 43),
		},
		{
			name: "a body of zeros",
			src:  "polar_oat_" + strings.Repeat("0", 43),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := []Span{{0, 53}}
			if got, _ := PolarOrganizationAccessToken().Find(tt.src); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, want)
			}
		})
	}
}

func Test_PolarOrganizationAccessToken_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix is ten
	// characters of an alphabet of sixty-four, so a base64url value long enough
	// to spell it carries a candidate, and where the forty-three behind it are
	// letters and digits, those fifty-three are redacted.
	//
	// They are held to being redacted rather than to being spared. Nothing in
	// the text tells such a run from a token — they are the same fifty-three
	// bytes — so a scan that let these through would let a real token through
	// with them, which builtin_polar_organization_access_token.go sets out.
	// What the table is for is that the cases move with the scan: one of them
	// ceasing to be located means the grammar changed, and that is a decision
	// to be taken rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "inside a base64url payload",
			src:  "payload=zzzzpolar_oat_" + polarOrganizationAccessTokenTestBody + "zzzz",
			want: "payload=zzzz" + strings.Repeat("*", 53) + "zzzz",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the Polar
			// pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.polar_oat_" + polarOrganizationAccessTokenTestBody,
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ." + strings.Repeat("*", 53),
		},
	}

	m := New(WithPatterns(PolarOrganizationAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PolarOrganizationAccessToken_theOtherPrefixesTheGeneratorWrites(t *testing.T) {
	// Prefixes Polar writes behind the same generator that this scan does not
	// read: the rationale beside the scan says why, which is that each of them
	// is a credential of its own rather than a width this pattern is missing.
	// The two here are the ones the published ruleset that scan cites carries
	// rules of its own for, and the body is written at the one count every one
	// of these is minted at — so reading a prefix is a change somebody argues
	// for rather than one somebody notices afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a personal access token",
			src:  "POLAR_ACCESS_TOKEN=polar_pat_" + polarOrganizationAccessTokenTestBody,
		},
		{
			// The OAuth2 access token, which an application acting for a person
			// carries. Its kind divides again into the subject it was issued
			// for, so the prefix is longer by two characters than the others
			// here and the body behind it is the same.
			name: "an oauth access token issued for an organization",
			src:  "Authorization: Bearer polar_at_o_" + polarOrganizationAccessTokenTestBody,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PolarOrganizationAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

// Test_PolarOrganizationAccessToken_holdsATokenTheInputCutShort states, with a
// literal number, what the second return of Find settles: a piece of the prefix
// standing at the end of the input, a candidate the end of the input cut short,
// and a whole match with nothing left unsettled behind it.
func Test_PolarOrganizationAccessToken_holdsATokenTheInputCutShort(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		want   []Span
		retain int
	}{
		{
			// A piece of the prefix stands at the very end of the input, so
			// nothing behind where it opens is settled.
			name:   "a piece of the prefix at the end of the input",
			src:    "polar_oat",
			retain: 0,
		},
		{
			name:   "a piece of the prefix behind prose",
			src:    "the token starts with polar_oat",
			retain: len("the token starts with "),
		},
		{
			// A whole prefix and a body the input cuts short before the count
			// is met. The candidate could still become a token were the input
			// longer, so what is unsettled reaches back to where the candidate
			// opened.
			name:   "a body the input cuts short of the count",
			src:    "polar_oat_0123456789abcdef",
			retain: 0,
		},
		{
			// A whole token with more text after it, ending in a byte that
			// opens no piece of the prefix, so nothing at the end of the input
			// is left unsettled.
			name:   "a whole token followed by settled text",
			src:    "polar_oat_" + polarOrganizationAccessTokenTestBody + " tail",
			want:   []Span{{0, 53}},
			retain: 58,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := PolarOrganizationAccessToken().Find(tt.src)
			if retain != tt.retain {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, retain, tt.retain)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_polarOrganizationAccessTokenPrefix(t *testing.T) {
	// The prefix is the whole of what tells this format from a run of letters
	// and digits. It closes on a character no body is written with, which is
	// what makes the search cheap over a run of a body — a body opens no
	// candidate however long it runs — and every character in front of that one
	// is either a letter a body may hold or the same character again.
	if got := polarOrganizationAccessTokenPrefix; got != "polar_oat_" {
		t.Errorf("polarOrganizationAccessTokenPrefix = %q, want %q", got, "polar_oat_")
	}
	for i := range len(polarOrganizationAccessTokenPrefix) {
		c := polarOrganizationAccessTokenPrefix[i]
		if i == len(polarOrganizationAccessTokenPrefix)-1 {
			if isBase62Byte(c) {
				t.Errorf("the prefix closes on %q, which a body may be written with", c)
			}
			continue
		}
		if !isBase62Byte(c) && c != polarOrganizationAccessTokenAnchor {
			t.Errorf("the prefix carries %q at index %d, which is neither a character a body may hold nor the byte the scan searches for", c, i)
		}
	}

	// Where a token may begin inside another, counted out of the declarations
	// that decide it rather than claimed in prose. A candidate opens where the
	// whole prefix stands, and the first character of that prefix no body may
	// carry has to fall past the end of the span it opens inside, since a body
	// carries no such character anywhere. What that leaves is the last five
	// characters of a body, which is what the scan resuming a byte along exists
	// to reach and what
	// Test_PolarOrganizationAccessToken_aTokenInsideAToken drives. A prefix
	// lengthened, that character moved or a count changed moves the number, and
	// nothing else here would report it.
	first := -1
	for i := range len(polarOrganizationAccessTokenPrefix) {
		if !isBase62Byte(polarOrganizationAccessTokenPrefix[i]) {
			first = i
			break
		}
	}
	if first < 0 {
		t.Fatal("every character of the prefix is one a body may hold, so a token may begin anywhere inside another")
	}
	inside := 0
	for p := 1; p < polarOrganizationAccessTokenChars; p++ {
		if p+first >= polarOrganizationAccessTokenChars {
			inside++
		}
	}
	if want := 5; inside != want {
		t.Errorf("%d position(s) inside a token can open a candidate, want %d", inside, want)
	}
}

// Test_polarOrganizationAccessTokenAnchor holds the prefix to carrying the byte
// the scan searches the input for at the index it reads a candidate back from,
// and counts what that byte costs. builtin_scan.go says why the index is held
// here rather than left to the targets.
func Test_polarOrganizationAccessTokenAnchor(t *testing.T) {
	if polarOrganizationAccessTokenAnchorIndex >= len(polarOrganizationAccessTokenPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", polarOrganizationAccessTokenAnchorIndex, len(polarOrganizationAccessTokenPrefix))
	}
	if c := polarOrganizationAccessTokenPrefix[polarOrganizationAccessTokenAnchorIndex]; c != polarOrganizationAccessTokenAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(polarOrganizationAccessTokenAnchor))
	}

	// What the anchor costs, counted rather than claimed in prose: it stands
	// twice in the prefix, so the search stops twice at every prefix and the
	// rationale accounts for the stop that opens no candidate, and nowhere in a
	// body, so a run of one stops it not at all.
	if n := strings.Count(polarOrganizationAccessTokenPrefix, string(rune(polarOrganizationAccessTokenAnchor))); n != 2 {
		t.Errorf("the anchor stands %d times in %q, want 2", n, polarOrganizationAccessTokenPrefix)
	}
	if isBase62Byte(polarOrganizationAccessTokenAnchor) {
		t.Errorf("the scan searches for %q, which a body may hold, so a candidate is read back at every one of them in an opaque run", byte(polarOrganizationAccessTokenAnchor))
	}
}

// Test_polarOrganizationAccessTokenChars holds the counts to the arithmetic the
// rationale reads them as: a body is the thirty-seven characters the generator
// draws and the six its base62 checksum is padded to, and a token is that with
// the prefix in front.
func Test_polarOrganizationAccessTokenChars(t *testing.T) {
	if polarOrganizationAccessTokenSecretChars != 37 {
		t.Errorf("the secret is read as %d characters, the generator draws thirty-seven", polarOrganizationAccessTokenSecretChars)
	}
	if polarOrganizationAccessTokenChecksumChars != 6 {
		t.Errorf("the checksum is read as %d characters, the generator pads it to six", polarOrganizationAccessTokenChecksumChars)
	}
	if want := polarOrganizationAccessTokenSecretChars + polarOrganizationAccessTokenChecksumChars; polarOrganizationAccessTokenBodyChars != want {
		t.Errorf("a body is read as %d characters, the secret and the checksum come to %d", polarOrganizationAccessTokenBodyChars, want)
	}
	if want := len(polarOrganizationAccessTokenPrefix) + polarOrganizationAccessTokenBodyChars; polarOrganizationAccessTokenChars != want {
		t.Errorf("a token is read as %d characters, the prefix and the body come to %d", polarOrganizationAccessTokenChars, want)
	}
	if polarOrganizationAccessTokenChars != 53 {
		t.Errorf("a token is read as %d characters, the rationale says fifty-three", polarOrganizationAccessTokenChars)
	}
}

func Test_isPolarOrganizationAccessTokenBody(t *testing.T) {
	// The count and the alphabet together, stated over every byte rather than
	// by example: a body is exactly polarOrganizationAccessTokenBodyChars
	// characters and each of them a letter or a digit.
	body := strings.Repeat("a", polarOrganizationAccessTokenBodyChars)

	if !isPolarOrganizationAccessTokenBody(body) {
		t.Errorf("isPolarOrganizationAccessTokenBody(%q) = false, want a body of %d characters to be one", body, polarOrganizationAccessTokenBodyChars)
	}
	for _, s := range []string{body[:len(body)-1], body + "a"} {
		if isPolarOrganizationAccessTokenBody(s) {
			t.Errorf("isPolarOrganizationAccessTokenBody(%q) = true, want only %d characters to be a body", s, polarOrganizationAccessTokenBodyChars)
		}
	}

	for c := range 256 {
		b := byte(c)
		for _, at := range []int{0, len(body) - 1} {
			src := body[:at] + string([]byte{b}) + body[at+1:]
			if got, want := isPolarOrganizationAccessTokenBody(src), isBase62Byte(b); got != want {
				t.Errorf("isPolarOrganizationAccessTokenBody(%q) = %v with %q at %d, want %v", src, got, b, at, want)
			}
		}
	}
}

// referencePolarOrganizationAccessToken is the expression the scan in
// builtin_polar_organization_access_token.go reads by hand: the statement of
// what a Polar organization access token is, kept here so that the scan can be
// held to it.
//
// The prefix, the count and the alphabet are spelled again rather than built
// from polarOrganizationAccessTokenPrefix,
// polarOrganizationAccessTokenBodyChars and isBase62Byte. A reference sharing
// those declarations could not disagree with the scan about them, and it is
// exactly that disagreement the fuzz target below is for: the two have to be
// changed together or reported apart.
var referencePolarOrganizationAccessToken = regexp.MustCompile(`polar_oat_[0-9A-Za-z]{43}`)

// referencePolarOrganizationAccessTokenFind locates tokens the plain way: the
// leftmost match of the expression above, then the leftmost one beginning after
// that match's first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a token can begin inside one: the five letters
// the prefix opens with are letters a body is written with, so a body closing
// on polar with the rest of a prefix behind it holds a token the engine would
// never go on to try. The scan finds both and reports the two spans
// overlapping for a Masker to resolve, so the reference must ask about both.
//
// Resuming a byte along costs this one nothing beyond a constant: every
// candidate reads at most fifty-three characters, here as in the scan, so
// neither has a run to walk and there is no cursor for either to be wrong
// about.
func referencePolarOrganizationAccessTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referencePolarOrganizationAccessToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzPolarOrganizationAccessToken_matchesReference guards the hand-written
// scan: the prefix it searches for, the count it reads behind that prefix, the
// alphabet it reads it in and the byte it resumes at may none of them change
// which tokens are located.
func FuzzPolarOrganizationAccessToken_matchesReference(f *testing.F) {
	body := polarOrganizationAccessTokenTestBody

	f.Add("nothing to see here")
	f.Add("POLAR_ACCESS_TOKEN=polar_oat_" + body)
	f.Add("Authorization: Bearer polar_oat_" + body)
	f.Add("polar_oat_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456") // a body in capitals
	f.Add("polar_oat_" + body[:len(body)-1])                       // one short of a token
	f.Add("polar_oat_" + body + "7")                               // and a run longer than one
	f.Add("POLAR_OAT_" + body)                                     // an uppercase prefix
	f.Add("polar-oat-" + body)                                     // hyphens where it carries underscores
	f.Add("polar_oat" + body + "7")                                // the underscore that closes it left out
	f.Add("polar_pat_" + body)                                     // the prefix of a personal access token
	f.Add("polar_at_o_" + body)                                    // and of an oauth access token
	f.Add("polar_oat_0123456789abcdefghij-lmnopqrstuvwxyz0123456") // a hyphen ends the body
	f.Add("polar_oat_0123456789abcdefghij_lmnopqrstuvwxyz0123456") // and an underscore
	f.Add("polar_oat_0123456789abcdefghij.lmnopqrstuvwxyz0123456") // and a dot
	f.Add("polar_oat_0123456789abcdefghij lmnopqrstuvwxyz0123456") // and a space
	f.Add("polar_oat_" + body + ".next")
	f.Add("polar_oat_" + body + "\npolar_oat_" + body)
	// A whole token behind a candidate that failed, which a scan resuming past
	// the length it hoped for steps over, and two tokens with nothing between
	// them.
	f.Add("polar_oat_polar_oat_" + body)
	f.Add("polar_oat_" + body + "polar_oat_" + body)
	// A token beginning inside another, at the furthest and the nearest of the
	// five positions one can, and the opening one character further in than
	// those five reach.
	f.Add("polar_oat_0123456789abcdefghijklmnopqrstuvwxyz01polar_oat_" + body)
	f.Add("polar_oat_0123456789abcdefghijklmnopqrstuvwxyz012345polar_oat_" + body)
	f.Add("polar_oat_0123456789abcdefghijklmnopqrstuvwxyz0polar_oat_" + body)
	f.Add(strings.Repeat("polar_oat_", 8))
	// Candidate positions crowded as close as they can be: every tenth byte in
	// the first, and a run behind each of them that is read to the count before
	// it fails.
	f.Add(strings.Repeat("polar_oat_", 32))
	f.Add(strings.Repeat("polar_oat_"+strings.Repeat("z", 42)+".", 16))
	// The prefix written inside a run of the alphabet, which is the over-match
	// the pattern admits, and the same run where a JWT signature stands.
	f.Add("payload=zzzzpolar_oat_" + body + "zzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.polar_oat_" + body)

	fuzzAgainstReference(f, PolarOrganizationAccessToken().Find, referencePolarOrganizationAccessTokenFind)
}

// polarOrganizationAccessTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func polarOrganizationAccessTokenFindBenchmarks() []benchmarkCase {
	// The record a caller of this API keeps: the vendor's own host name, which
	// carries the five characters a prefix opens with, and a snake_case field,
	// which carries the byte the scan searches for. That underscore is the one
	// candidate this line opens, turned away on the character in front of it,
	// and Test_polarOrganizationAccessTokenFindBenchmarks_theLineOpensOne
	// counts it rather than leaving it to this sentence.
	line := `time=2026-08-17T00:00:00Z level=info msg="creating a checkout" organization_id=1dbfc517 url=https://api.polar.sh/v1/checkouts `
	token := "polar_oat_" + polarOrganizationAccessTokenTestBody

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A unit here is the ten character prefix, a run one character
			// short of a body, and a character no body may hold — fifty-three
			// bytes, so a candidate opens every fifty-three. Each of them walks
			// the whole run before that last character turns it away, which is
			// the crowding this pattern admits with no value at the end of any
			// of it. A run of the count itself would make every unit a value
			// and the case its own opposite.
			name:  "candidates that are not values",
			src:   strings.Repeat("polar_oat_"+strings.Repeat("z", 42)+".", 16),
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

// Test_polarOrganizationAccessTokenFindBenchmarks_theLineOpensOne holds the
// line the benchmarks above are written on to carrying the byte the scan
// searches for once, which is what the comment beside that line claims and
// what the case is worth timing for.
//
// Test_builtins_benchmarkCasesHoldTheirValues holds the case to locating
// nothing, and a line carrying a dozen underscores would satisfy that
// identically while timing a search that stops a dozen times. The two together
// are what makes the case the shape it says it is.
func Test_polarOrganizationAccessTokenFindBenchmarks_theLineOpensOne(t *testing.T) {
	const name = "no value"

	i := slices.IndexFunc(polarOrganizationAccessTokenFindBenchmarks(), func(c benchmarkCase) bool {
		return c.name == name
	})
	if i < 0 {
		t.Fatalf("no benchmark case named %q, so the line the comment describes is written nowhere", name)
	}
	line := polarOrganizationAccessTokenFindBenchmarks()[i].src
	if n := strings.Count(line, string(rune(polarOrganizationAccessTokenAnchor))); n != 1 {
		t.Errorf("the line opens %d candidate(s), the comment beside it says one", n)
	}
}
