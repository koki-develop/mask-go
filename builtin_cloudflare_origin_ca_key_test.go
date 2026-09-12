package mask

import (
	"slices"
	"strings"
	"testing"
)

// The Cloudflare Origin CA key pattern: what it locates and what it leaves
// alone, written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a set
// of tests apiece.
//
// The keys written out below are made only of ordered characters: valid in
// shape, obviously not real. The first run is 0123456789abcdef and eight
// characters of it again, which is the twenty-four the format is written to; the
// second is that run nine times over and two characters more, which is a hundred
// and forty-six; and with the prefix and the separator between them that comes
// to a hundred and seventy-six. Where a case turns on what a run may open or
// close on, the character at that end is written differently and the rest of the
// run is left where it was.

func Test_CloudflareOriginCAKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
			want: []Span{{0, 176}},
		},
		{
			name: "a key in an environment assignment",
			src:  "CLOUDFLARE_ORIGIN_CA_KEY=v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
			want: []Span{{25, 201}},
		},
		{
			// The last character of the body's alphabet at the first and the
			// last character of both runs, which a value built from an ordered
			// run never reaches at either end.
			name: "both runs opening and closing on the last letter of the alphabet",
			src:  "v1.0-f123456789abcdef0123456f-f123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0f",
			want: []Span{{0, 176}},
		},
		{
			// And the first character of it at the same four places.
			name: "both runs opening and closing on the first digit of the alphabet",
			src:  "v1.0-0123456789abcdef01234560-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00",
			want: []Span{{0, 176}},
		},
		{
			// Both counts are read exactly, so what follows the hundred and
			// seventy-sixth character is not part of the key and stays in the
			// text.
			name: "a second run longer than the count is a key and what follows it",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef010",
			want: []Span{{0, 176}},
		},
		{
			name: "two keys with nothing between them",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef23",
			want: []Span{{0, 176}, {176, 352}},
		},
		{
			name: "two keys separated by a space",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01 v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef23",
			want: []Span{{0, 176}, {177, 353}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CloudflareOriginCAKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CloudflareOriginCAKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "v1.0-",
		},
		{
			name: "a first run one character short",
			src:  "v1.0-0123456789abcdef0123456-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			// One character longer than the count, which the separator is what
			// reports: the twenty-fifth character behind the prefix is a
			// hexadecimal digit rather than the hyphen.
			name: "a first run one character longer",
			src:  "v1.0-0123456789abcdef012345678-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a second run one character short",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
		},
		{
			// The body is read in lowercase alone, so the case an environment
			// variable's name is written in is no key however the counts fall.
			name: "an uppercase body",
			src:  "v1.0-0123456789ABCDEF01234567-0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01",
		},
		{
			name: "a letter past f at the first character of the first run",
			src:  "v1.0-g123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a letter past f at the last character of the first run",
			src:  "v1.0-0123456789abcdef0123456g-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a letter past f in the middle of the first run",
			src:  "v1.0-0123456789abgdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a letter past f at the first character of the second run",
			src:  "v1.0-0123456789abcdef01234567-g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a letter past f at the last character of the second run",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0g",
		},
		{
			name: "a letter past f in the middle of the second run",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345678gabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			// The separator at the ends of the two runs rather than inside
			// one. It is the character the body excludes that a body also
			// carries, so where it may not stand is what has to be written
			// out: the first and the last character of either run.
			name: "the separator at the first character of the first run",
			src:  "v1.0--123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "the separator at the last character of the first run",
			src:  "v1.0-0123456789abcdef0123456--0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "the separator at the first character of the second run",
			src:  "v1.0-0123456789abcdef01234567--123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "the separator at the last character of the second run",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0-",
		},
		{
			// The three edges of the alphabet a letter past f does not reach:
			// the character in front of a, the one behind 9 and the one in
			// front of 0.
			name: "the character before a at the first character of the first run",
			src:  "v1.0-`123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "the character after 9 in the middle of the first run",
			src:  "v1.0-01234:6789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "the character before 0 at the last character of the second run",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0/",
		},
		{
			name: "an underscore where the separator stands",
			src:  "v1.0-0123456789abcdef01234567_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a hexadecimal digit where the separator stands",
			src:  "v1.0-0123456789abcdef0123456700123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "the two runs written with no separator between them",
			src:  "v1.0-0123456789abcdef012345670123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			// The separator stands at one place and no other, so a second one
			// written inside the second run ends the reading there.
			name: "a second separator inside the second run",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01234567-9abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a space at the first character of the first run",
			src:  "v1.0- 123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a second run broken by a space",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01234567 9abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a second run broken by a line break",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01234567\n9abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "an uppercase prefix",
			src:  "V1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "the prefix without the full stop",
			src:  "v10-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "an underscore where the prefix carries its hyphen",
			src:  "v1.0_0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			// The version is part of the prefix rather than a number the scan
			// reads, so the format that follows this one is a format somebody
			// writes a prefix for.
			name: "a major version cloudflare has not written",
			src:  "v2.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a minor version cloudflare has not written",
			src:  "v1.1-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			// A body of the right counts and the right class behind something
			// else. The prefix is the whole of the anchor.
			name: "a body of the right shape opening with no prefix",
			src:  "x1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a body with no prefix in front of it at all",
			src:  "0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// A line carrying the byte the scan searches for several times
			// over, none of them with a prefix behind it.
			name: "the anchor as it is written in prose",
			src:  "every version of every key this vendor revokes leaves the others valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CloudflareOriginCAKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_CloudflareOriginCAKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "CLOUDFLARE_ORIGIN_CA_KEY=v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
			want: "CLOUDFLARE_ORIGIN_CA_KEY=" + strings.Repeat("*", 176),
		},
		{
			// The header Cloudflare sends one in, which is the whole of how a
			// key reaches the Origin CA API and how it reaches a log line that
			// echoed the request.
			name: "the service key header",
			src:  "X-Auth-User-Service-Key: v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
			want: "X-Auth-User-Service-Key: " + strings.Repeat("*", 176),
		},
		{
			name: "a command line",
			src:  `curl -H "X-Auth-User-Service-Key: v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01" https://api.cloudflare.com/client/v4/certificates`,
			want: `curl -H "X-Auth-User-Service-Key: ` + strings.Repeat("*", 176) + `" https://api.cloudflare.com/client/v4/certificates`,
		},
		{
			name: "a json body",
			src:  `{"service_key":"v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01"}`,
			want: `{"service_key":"` + strings.Repeat("*", 176) + `"}`,
		},
	}

	m := New(WithPatterns(CloudflareOriginCAKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CloudflareOriginCAKey_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the key through whole. The first two are what the
	// demand would cost, and both rulesets that spell this format's two counts
	// make it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "xv1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
			want: "x" + strings.Repeat("*", 176),
		},
		{
			name: "underscore before",
			src:  "CLOUDFLARE_ORIGIN_CA_KEY_v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
			want: "CLOUDFLARE_ORIGIN_CA_KEY_" + strings.Repeat("*", 176),
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this key rather
			// than trim it; without one the hundred and seventy-six characters
			// Cloudflare issued are redacted and the one written after them,
			// which is part of no credential, stays in the text.
			name: "a character of the body's class after",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef010",
			want: strings.Repeat("*", 176) + "0",
		},
		{
			name: "a digit before",
			src:  "9v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
			want: "9" + strings.Repeat("*", 176),
		},
		{
			name: "a hyphen before",
			src:  "-v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
			want: "-" + strings.Repeat("*", 176),
		},
		{
			// A multi-byte rune written against the key on both sides. Neither
			// UTF-8 encoding shares a byte with the prefix or the body's
			// alphabet, so the key keeps its span exactly as it does against a
			// single-byte character.
			name: "a multi-byte rune before and after",
			src:  "日本語v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01日本語",
			want: "日本語" + strings.Repeat("*", 176) + "日本語",
		},
	}

	m := New(WithPatterns(CloudflareOriginCAKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CloudflareOriginCAKey_leavesWhatFollowsAlone(t *testing.T) {
	// A key is a hundred and seventy-six characters and no more, so what is
	// written after one stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the key is v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01.",
			want: "the key is " + strings.Repeat("*", 176) + ".",
		},
		{
			name: "quoted",
			src:  `"v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01"`,
			want: `"` + strings.Repeat("*", 176) + `"`,
		},
		{
			name: "dashed word",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01-suffix",
			want: strings.Repeat("*", 176) + "-suffix",
		},
		{
			// A letter past f ends nothing here — the count has already ended
			// the key — so a word written straight against one comes through.
			name: "a word written against a key",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01suffix",
			want: strings.Repeat("*", 176) + "suffix",
		},
	}

	m := New(WithPatterns(CloudflareOriginCAKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CloudflareOriginCAKey_noKeyBeginsInsideAnother(t *testing.T) {
	// The claim builtin_cloudflare_origin_ca_key.go makes about what advancing
	// rather than consuming the match finds here, which is nothing. The byte the
	// scan searches for opens the prefix and stands nowhere else in a key — no
	// run is written with it and the rest of the prefix is not — so the search
	// stops at no position inside a key it has located.
	//
	// What that comes to is spans that never overlap: two keys written with
	// nothing between them are two separate redactions, and a whole key written
	// inside the body of a candidate is located where it stands while the
	// candidate around it is turned away.
	// Test_cloudflareOriginCAKeyAnchor holds the character the claim rests on.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "two keys with nothing between them",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef23",
			want: []Span{{0, 176}, {176, 352}},
		},
		{
			// A candidate whose body opens with a prefix of its own. The outer
			// one is turned away at the first character of its first run, which
			// is the v the inner prefix opens with and no character a run is
			// written with; the key inside it is found where it stands.
			name: "a candidate whose body opens with a prefix",
			src:  "v1.0-v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
			want: []Span{{5, 181}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CloudflareOriginCAKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CloudflareOriginCAKey_aVersionString(t *testing.T) {
	// The prefix is the one part of this format Cloudflare states, and it is
	// also how a pre-release version is written. So the shapes that reach it are
	// ordinary text rather than anything credential-shaped, and these are the
	// ones a repository writes.
	//
	// What turns all four away is the count, before any of the body is read: a
	// version string carries nowhere near the hundred and seventy-one characters
	// a key has behind its prefix, and the fourth case is a hundred and seventy
	// of them, one short. So none of these holds the body walk to anything, and
	// they are written out for the shapes rather than for the rejection.
	// Test_CloudflareOriginCAKey_rejectedByTheBodyRatherThanByTheEndOfTheInput
	// is where a version string is written into a line long enough for the walk
	// to run and the grammar to be what reports it.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a pre-release version",
			src:  "v1.0-beta",
		},
		{
			name: "a release candidate",
			src:  "v1.0-rc1",
		},
		{
			name: "the output of git describe",
			src:  "v1.0-12-g0123abc",
		},
		{
			// The same shape with the counts nearly met, which is what a
			// version string could not reach and a truncated key could: the
			// first run is right and the second is one character short.
			name: "a version string with a body one character short",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CloudflareOriginCAKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_CloudflareOriginCAKey_rejectedByTheBodyRatherThanByTheEndOfTheInput(t *testing.T) {
	// A candidate shorter than a key is turned away twice over, and the two are
	// not the same rejection. The scan reaches the body only where a hundred
	// and seventy-one characters stand behind the prefix; short of that it
	// reports the candidate and reads nothing of it, which is what
	// Test_CloudflareOriginCAKey_holdsAKeyTheInputCutShort states. So a case
	// that stops at the end of its own input leaves the counts and the
	// separator untested: a scan reading no body at all would pass it.
	//
	// Each case here writes text behind the candidate, which is the only
	// arrangement where the body walk runs and the grammar is what reports the
	// rejection. What says the walk ran is the second return: the input is
	// settled to its end, where the same value with nothing behind it settles
	// where the candidate opened.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a first run one character short",
			src:  "v1.0-0123456789abcdef0123456-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01 and the line carries on",
		},
		{
			name: "a second run one character short",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0 and the line carries on",
		},
		{
			name: "the two runs written with no separator between them",
			src:  "v1.0-0123456789abcdef012345670123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01 and the line carries on",
		},
		{
			// The version string the rationale names, written as a changelog
			// writes one rather than on a line of its own. The candidate opens
			// at the v, the first two characters of its body are the b and the
			// e of beta and both are hexadecimal, and what ends the reading is
			// the t behind them.
			name: "a pre-release version in a line longer than a key",
			src:  "v1.0-beta, cut from the release branch, and the changelog note written beside it runs on well past a hundred and seventy-six characters, so what ends the reading here is the body and not the end of the input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := CloudflareOriginCAKey().Find(tt.src)
			if len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
			if retain != len(tt.src) {
				t.Errorf("Find(%q) settled %d, want %d — the body was not read", tt.src, retain, len(tt.src))
			}
		})
	}
}

func Test_CloudflareOriginCAKey_aWordEndingInTheAnchor(t *testing.T) {
	// What declining the word boundary in front costs, which
	// builtin_cloudflare_origin_ca_key.go weighs. A word closing on a v with a
	// whole key written behind it is a candidate from that v on, and the
	// boundary both rulesets spelling this format ask for would turn it away.
	//
	// It is redacted from that v, leaving the letters in front of it in the
	// text. On the other side of the trade is a key written straight against a
	// letter or an underscore, which the same demand would drop whole rather
	// than trim, and Test_CloudflareOriginCAKey_nextToWordCharacters drives
	// that.
	src := "rev1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01"
	want := []Span{{2, 178}}

	if got, _ := CloudflareOriginCAKey().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}
}

func Test_CloudflareOriginCAKey_aWiderAlphabet(t *testing.T) {
	// The widening on offer, declined on what it would admit rather than on who
	// wrote it. trufflehog reads a hundred and seventy-one characters of the
	// letters of either case, the digits and the hyphen behind the prefix, where
	// the two rulesets spelling the split read lowercase hexadecimal in two runs
	// divided by one hyphen at one place.
	//
	// Each case below is located by the wider reading and by nothing here. It is
	// pinned so that taking the wider class is a change somebody argues for
	// rather than one somebody notices afterwards: what it would draw in behind
	// a version string is a hundred and seventy-one characters of ordinary
	// base62 text.
	tests := []struct {
		name string
		src  string
	}{
		{
			// The run here is the letters past f with the v taken out — g to z
			// less the one character a prefix opens with — so that the body
			// carries no second candidate and the case is about the alphabet
			// alone. Both runs are still written to their counts.
			name: "a body of letters past f",
			src:  "v1.0-ghijklmnopqrstuwxyzghijk-ghijklmnopqrstuwxyzghijklmnopqrstuwxyzghijklmnopqrstuwxyzghijklmnopqrstuwxyzghijklmnopqrstuwxyzghijklmnopqrstuwxyzghijklmnopqrstuwxyzghijklmnopqrs",
		},
		{
			name: "an uppercase body",
			src:  "v1.0-0123456789ABCDEF01234567-0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01",
		},
		{
			name: "a hyphen standing where no separator does",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01234567-9abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CloudflareOriginCAKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_CloudflareOriginCAKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision a prefix ordinarily invites is a digest written behind it,
	// and the counts here turn one away rather than pay for it: an MD5 is
	// thirty-two characters, a SHA-1 forty, a SHA-256 sixty-four and a SHA-512 a
	// hundred and twenty-eight, and neither run is written to any of those
	// widths. That is what builtin_cloudflare_origin_ca_key.go weighs the exact
	// counts against a floor on, so the shapes a floor would have admitted are
	// written out here.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a sha-256 where the second run stands",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a sha-512 where the second run stands",
			src:  "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a sha-1 where the first run stands",
			src:  "v1.0-0123456789abcdef0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CloudflareOriginCAKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_CloudflareOriginCAKey_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor, and what holds it linear is the counts being
	// counts: a candidate reads at most a hundred and seventy-six bytes and
	// stops. These are the inputs that would find it wrong here — a line that is
	// nothing but prefixes, a line that is nothing but keys, and a single
	// hexadecimal run as long as the line, which is where a scan reading a run
	// instead of a count would show itself.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// whole body apiece and so hold a candidate every hundred and seventy-six
	// bytes at their densest. The crowding a line can actually carry, a
	// candidate every five, stays here.
	sources := map[string]string{
		// A candidate every five characters, each turned away at the first
		// character of its first run, which is the v the next prefix opens with
		// and no character a run is written with.
		"a candidate every five characters": strings.Repeat("v1.0-", 300000),
		// The same crowding with a whole key at each candidate, so every one of
		// them reads a hundred and seventy-one characters and reports a span.
		"a key every hundred and seventy-six characters": strings.Repeat("v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01", 12000),
		// A candidate walked to its last character before the body's class turns
		// it away, which is the most a rejected candidate can cost.
		"a candidate walked to its last character": strings.Repeat("v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0g ", 12000),
		// One candidate whose run is the whole line. The separator is what stops
		// it, twenty-five bytes in, where a scan reading the run to its end
		// would read two mebibytes before deciding anything.
		"a hexadecimal run the length of the line": "v1.0-" + strings.Repeat("a", 2000000),
		// The same run with no prefix in front of it, so no candidate is found
		// in it at all.
		"a hexadecimal run with no prefix": strings.Repeat("a", 2000000),
	}

	checkScanIsLinear(t, CloudflareOriginCAKey(), sources)
}

// Test_CloudflareOriginCAKey_holdsAKeyTheInputCutShort states, with a literal
// number, what the second return of Find settles on the three shapes
// builtin_cloudflare_origin_ca_key.go's rationale on settling names: a prefix
// standing at the end of the input, a candidate the end of the input cut short,
// and a whole match with nothing left unsettled behind it.
func Test_CloudflareOriginCAKey_holdsAKeyTheInputCutShort(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		want   []Span
		retain int
	}{
		{
			// A piece of the prefix stands at the very end of the input: it
			// could still grow into "v1.0-" with one more byte, so nothing
			// behind where it opens is settled.
			name:   "a piece of the prefix at the end of the input",
			src:    "v1.0",
			retain: 0,
		},
		{
			// The same piece with prose in front of it, so what is unsettled is
			// only the piece itself rather than the whole input.
			name:   "a piece of the prefix behind prose",
			src:    "the key starts with v1.0",
			retain: len("the key starts with "),
		},
		{
			// A whole prefix and a body the input cuts short before the counts
			// are met. The candidate could still become a key were the input
			// longer, so what is unsettled reaches back to where the candidate
			// opened rather than to the byte the input stopped at.
			name:   "a body the input cuts short of the count",
			src:    "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			retain: 0,
		},
		{
			// The same, with a candidate that had already failed: the first
			// character of its first run is a letter past f, so no text
			// carrying on from here could have made it a key. The scan settles
			// where the candidate opened all the same, which is the decision
			// builtin_scan.go argues — reading what is written of a truncated
			// candidate would cost a second grammar, and a few bytes at the end
			// of a write are not worth one.
			name:   "a body the input cuts short, already carrying a character no run holds",
			src:    "v1.0-g123456789abcdef01234567-0123456789ab",
			retain: 0,
		},
		{
			// A whole key with more text after it, ending in a byte that opens
			// no piece of the prefix, so nothing at the end of the input is left
			// unsettled — the key found is reported and the input is settled to
			// its end.
			name:   "a whole key followed by settled text",
			src:    "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01 tail",
			want:   []Span{{0, 176}},
			retain: 181,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := CloudflareOriginCAKey().Find(tt.src)
			if retain != tt.retain {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, retain, tt.retain)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

// Test_cloudflareOriginCAKeyAnchor holds the byte the scan searches the input
// for to standing where the scan reads a candidate back from, and to standing
// nowhere else in a key at all.
//
// The first half is what builtin_scan.go asks of every anchor: a prefix carrying
// it somewhere else is a prefix no candidate is ever found at, and nothing that
// was passing would stop passing.
//
// The second half is what Test_CloudflareOriginCAKey_noKeyBeginsInsideAnother
// rests on. A key is the prefix, two runs of the body's alphabet and the
// separator between them, so an anchor written in none of those but the prefix's
// own first character stands once in a key and the search can stop nowhere
// inside one.
func Test_cloudflareOriginCAKeyAnchor(t *testing.T) {
	p := cloudflareOriginCAKeyPrefix
	if cloudflareOriginCAKeyAnchorIndex >= len(p) {
		t.Fatalf("the anchor stands at %d, the prefix %q is %d characters", cloudflareOriginCAKeyAnchorIndex, p, len(p))
	}
	if c := p[cloudflareOriginCAKeyAnchorIndex]; c != cloudflareOriginCAKeyAnchor {
		t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", p, c, byte(cloudflareOriginCAKeyAnchor))
	}
	if n := strings.Count(p, string(rune(cloudflareOriginCAKeyAnchor))); n != 1 {
		t.Errorf("the prefix %q carries the anchor %q %d times, so a candidate can open inside one", p, byte(cloudflareOriginCAKeyAnchor), n)
	}
	if isCloudflareOriginCAKeyByte(cloudflareOriginCAKeyAnchor) {
		t.Errorf("the anchor %q is a character a run is written with, so a candidate can open inside a body", byte(cloudflareOriginCAKeyAnchor))
	}
	if cloudflareOriginCAKeyAnchor == cloudflareOriginCAKeySeparator {
		t.Errorf("the anchor %q is the separator, so a candidate can open where the two runs divide", byte(cloudflareOriginCAKeyAnchor))
	}
}

// Test_cloudflareOriginCAKeyChars holds the arithmetic to the numbers this
// pattern's documentation states: the five characters of the prefix, the
// twenty-four of the first run, the hundred and forty-six of the second and the
// hundred and seventy-six a key comes to.
//
// What it holds is the documentation rather than the scan. The scan never states
// a whole key: it reads the body from where the prefix ends, so a prefix of
// another length would be located correctly and nothing would go wrong. What
// would go wrong is the sentence on CloudflareOriginCAKey promising a hundred
// and seventy-six characters, and the spans every case in this file is written
// with.
func Test_cloudflareOriginCAKeyChars(t *testing.T) {
	const (
		documentedPrefixChars    = 5
		documentedFirstRunChars  = 24
		documentedSecondRunChars = 146
		documentedChars          = 176
	)

	if len(cloudflareOriginCAKeyPrefix) != documentedPrefixChars {
		t.Errorf("the prefix %q is %d characters, the documentation promises %d", cloudflareOriginCAKeyPrefix, len(cloudflareOriginCAKeyPrefix), documentedPrefixChars)
	}
	if cloudflareOriginCAKeyFirstRunChars != documentedFirstRunChars {
		t.Errorf("the first run is read as %d characters, the documentation promises %d", cloudflareOriginCAKeyFirstRunChars, documentedFirstRunChars)
	}
	if cloudflareOriginCAKeySecondRunChars != documentedSecondRunChars {
		t.Errorf("the second run is read as %d characters, the documentation promises %d", cloudflareOriginCAKeySecondRunChars, documentedSecondRunChars)
	}
	if cloudflareOriginCAKeyChars != documentedChars {
		t.Errorf("a key is read as %d characters, the documentation promises %d", cloudflareOriginCAKeyChars, documentedChars)
	}
}

// referenceCloudflareOriginCAKeyAt reports where a Cloudflare Origin CA key
// written at start ends, and whether one is written there at all. It is the
// statement of what the scan in builtin_cloudflare_origin_ca_key.go locates,
// kept here so that the scan can be held to it, and it reads one position and
// stops.
//
// The prefix, both counts, the separator and the character class are written out
// here rather than read from the scan. Reading them would move this with
// whatever the scan was changed to, and the fuzz target below would then hold a
// rule against itself; Test_references_shareNoDeclarationWithTheScans is what
// keeps the two apart.
//
// It is written out rather than built on a regular expression, which is the
// choice the layout leaves open and which the second count settles. Both counts
// are exact, so neither costs an engine the machine-as-wide-as-the-floor a
// counted floor would; what costs is how wide the second of them is. A hundred
// and forty-six unrolls into a program long enough that an input reaching into
// it is slow to run, and the engine's minimizer re-runs one input until its
// budget is out — sixty seconds of it by default, against the thirty seconds CI
// gives a target. Measured over a cleaned fuzz cache at that thirty, the
// expression left FuzzCloudflareOriginCAKey_matchesReference reporting no
// executions at all for the last eighteen seconds and 578,626 executions in all;
// the walks below hold their rate for the whole thirty and reach 2,254,738. The
// scan is not what stalls: CloudflareAPIKey, whose counts are forty and eight,
// sustains its rate over the same thirty seconds on an expression.
func referenceCloudflareOriginCAKeyAt(src string, start int) (int, bool) {
	if !strings.HasPrefix(src[start:], "v1.0-") {
		return 0, false
	}
	body := start + 5
	separator := body + 24
	end := separator + 1 + 146
	if end > len(src) {
		return 0, false
	}
	for i := body; i < separator; i++ {
		if !referenceCloudflareOriginCAKeyByte(src[i]) {
			return 0, false
		}
	}
	if src[separator] != '-' {
		return 0, false
	}
	for i := separator + 1; i < end; i++ {
		if !referenceCloudflareOriginCAKeyByte(src[i]) {
			return 0, false
		}
	}
	return end, true
}

// referenceCloudflareOriginCAKeyByte reports whether c is a character a run is
// written with: a lowercase hexadecimal digit.
func referenceCloudflareOriginCAKeyByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f'
}

// referenceCloudflareOriginCAKeyFind locates keys the plain way: every position
// in turn, with nothing remembered between them. It is the control flow of the
// scan with the grammar above in place of the byte tests the scan reads it with.
//
// Asking at every position is what the scan does too, and it is not written here
// to restate that. A reference is written to know nothing its scan claims, and
// that no key can begin inside another is one of the things the scan claims — so
// this one asks at every byte all the same, and the fuzz target below is what
// holds the two to the same answer.
func referenceCloudflareOriginCAKeyFind(src string) []Span {
	var spans []Span
	for i := range len(src) {
		if end, ok := referenceCloudflareOriginCAKeyAt(src, i); ok {
			spans = append(spans, Span{Start: i, End: end})
		}
	}
	return spans
}

// FuzzCloudflareOriginCAKey_matchesReference guards the hand-written scan: the
// byte it searches for, the prefix it reads forward from that byte, the two
// counts it reads, the separator between them and the character class it reads
// them in may none of them change which keys are located.
func FuzzCloudflareOriginCAKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("CLOUDFLARE_ORIGIN_CA_KEY=v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")
	f.Add("v1.0-0123456789abcdef0123456-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")    // a first run one short
	f.Add("v1.0-0123456789abcdef012345678-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")  // and one long
	f.Add("v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0")    // a second run one short
	f.Add("v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef010")  // and one long
	f.Add("v1.0-0123456789ABCDEF01234567-0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01")   // an uppercase body
	f.Add("V1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")   // an uppercase prefix
	f.Add("v1.0-0123456789abgdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")   // a letter past f in the first run
	f.Add("v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345678gabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")   // and in the second
	f.Add("v1.0-0123456789abcdef01234567_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")   // an underscore where the separator stands
	f.Add("v1.0-0123456789abcdef012345670123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")    // and no separator at all
	f.Add("v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01234567-9abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")   // a second separator inside the second run
	f.Add("v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01234567\n9abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")  // a key a line break breaks
	f.Add("v2.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")   // a version nobody writes
	f.Add("x1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")   // the right shape with no prefix
	f.Add("xv1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")  // written against a letter
	f.Add("rev1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01") // and behind a word closing on the anchor
	f.Add("v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")                                                                                     // a sha-256 where the second run stands
	f.Add("v1.0-beta")                                                                                                                                                                          // the prefix as a version string writes it
	f.Add("v1.0-12-g0123abc")                                                                                                                                                                   //
	// The same rejections with text behind them, where the body is what reports
	// them rather than the end of the input.
	f.Add("v1.0-0123456789abcdef0123456-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01 and the line carries on")
	f.Add("v1.0-beta, cut from the release branch, and the changelog note written beside it runs on well past a hundred and seventy-six characters, so what ends the reading here is the body and not the end of the input")
	// The separator written where no separator stands: the ends of either run.
	f.Add("v1.0--123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")
	f.Add("v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0-")
	// A prefix where a body could hold one, and two keys written with nothing
	// between them, which is what advancing rather than consuming the match has
	// to find.
	f.Add("v1.0-v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")
	f.Add("v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef23")
	// Candidate positions crowded as close as they can be, and a hexadecimal run
	// with no prefix in front of it.
	f.Add(strings.Repeat("v1.0-", 32))
	f.Add(strings.Repeat("v1.0-", 32) + strings.Repeat("0123456789abcdef", 11))
	f.Add(strings.Repeat("0123456789abcdef", 16))

	fuzzAgainstReference(f, CloudflareOriginCAKey().Find, referenceCloudflareOriginCAKeyFind)
}

// cloudflareOriginCAKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func cloudflareOriginCAKeyFindBenchmarks() []benchmarkCase {
	// The line carries the byte the scan searches for twice, once in a word of
	// the message and once in the version segment of the vendor's own API path,
	// and neither opens a candidate. What it times is that search and the two
	// reads that turn those positions away, which is what this pattern costs a
	// caller whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.cloudflare.com/client/v4/certificates `
	key := "v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix written over and over, so a candidate stands at every
			// fifth byte and every one of them is turned away at the first
			// character of its first run, which is the v the next prefix opens
			// with. That is the cheapest this scan declines a candidate whose
			// prefix is whole.
			name:  "candidates that are not values",
			src:   strings.Repeat("v1.0-", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: a hundred and seventy characters
			// of the body walked before its last one turns the candidate away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("v1.0-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0g ", 16),
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
