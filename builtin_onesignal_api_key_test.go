package mask

import (
	"slices"
	"strings"
	"testing"
)

// The OneSignal API key pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. The run they are built from is
// 234567abcdefghijklmnopqrstuvwxyz, which is the ordered run
// 0123456789abcdefghijklmnopqrstuvwxyz with the four digits the alphabet leaves
// out taken away, repeated to the hundred and three characters a body is at its
// shortest. Where a case turns on a character standing at one end of a body or
// just outside the alphabet, that character is written in and the rest of the
// run is left as it was.

func Test_OneSignalAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an app key",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
			want: []Span{{0, 113}},
		},
		{
			name: "an organization key",
			src:  "os_v2_org_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
			want: []Span{{0, 113}},
		},
		{
			name: "a key in an environment assignment",
			src:  "ONESIGNAL_APP_API_KEY=os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
			want: []Span{{22, 135}},
		},
		{
			// The count is a floor, so a run longer than the shortest body is
			// one longer key rather than a key and what follows it.
			name: "a body longer than the shortest one",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567ab",
			want: []Span{{0, 114}},
		},
		{
			name: "a body opening and closing on the first letter of the alphabet",
			src:  "os_v2_app_a34567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
			want: []Span{{0, 113}},
		},
		{
			name: "a body opening and closing on the last letter of the alphabet",
			src:  "os_v2_app_z34567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567z",
			want: []Span{{0, 113}},
		},
		{
			name: "a body opening and closing on the lowest digit",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345672",
			want: []Span{{0, 113}},
		},
		{
			name: "a body opening and closing on the highest digit",
			src:  "os_v2_app_734567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345677",
			want: []Span{{0, 113}},
		},
		{
			name: "a key of each scope on one line",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a os_v2_org_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
			want: []Span{{0, 113}, {114, 227}},
		},
		{
			// The two characters the opening begins with belong to the alphabet a
			// body is written in, so the run of the first key carries on into the
			// second key's opening and stops at its first underscore. The second
			// key is found at its own prefix, and the spans overlap for
			// Masker.locate to resolve.
			name: "a key written straight against the key in front of it",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567aos_v2_org_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
			want: []Span{{0, 115}, {113, 226}},
		},
		{
			// The hexadecimal digits this alphabet leaves out are what keeps a
			// digest from being a body, and a run wide enough to reach the floor
			// before it writes one of them is located. A hundred and twenty-eight
			// hexadecimal characters is a sha512, and this one writes its first
			// excluded digit at the hundred and ninth.
			name: "a hexadecimal run whose first excluded digit stands past the floor",
			src:  "os_v2_app_234567abcdef234567abcdef234567abcdef234567abcdef234567abcdef234567abcdef234567abcdef234567abcdef234567abcdef0123456789abcdef0123",
			want: []Span{{0, 118}},
		},
		{
			// The run ends where the alphabet stops, so the digit is no part of
			// the key.
			name: "a key closing on a character the alphabet leaves out",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a0",
			want: []Span{{0, 113}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := OneSignalAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OneSignalAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "os_v2_app_",
		},
		{
			name: "a body one character short of the floor",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567",
		},
		{
			name: "the opening with no scope behind it",
			src:  "os_v2_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
		},
		{
			name: "a scope this pattern was never told about",
			src:  "os_v2_usr_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
		},
		{
			name: "the prefix without the separator it closes with",
			src:  "os_v2_app234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
		},
		{
			name: "an uppercase prefix",
			src:  "OS_V2_APP_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
		},
		{
			// The alphabet is read in the lowercase the example and the rule stating
			// this format are both written in, so the letters here end the run at
			// once and the six digits in front of them are the whole of the body.
			name: "a body written in capitals",
			src:  "os_v2_app_234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567A",
		},
		{
			name: "the digit 1 at the first character of the body",
			src:  "os_v2_app_134567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
		},
		{
			// The last character the floor reads, standing outside the alphabet. A
			// scan checking only the characters in front of it would still call this
			// a key.
			name: "the digit 8 at the last character of the body",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345678",
		},
		{
			name: "the digit 0 inside the body",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklm0opqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
		},
		{
			name: "the digit 9 inside the body",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklm9opqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
		},
		{
			// The bytes on either side of the letter half of the alphabet, at
			// either end of a body: 0x60 one below a, and 0x7b one above z. A
			// range test written a character wide at either end would admit one
			// of them and still turn a capital away.
			name: "the byte just below the first letter at the first character of the body",
			src:  "os_v2_app_`34567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
		},
		{
			name: "the byte just above the last letter at the last character of the body",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567{",
		},
		{
			name: "a capital at the last character of the body",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567A",
		},
		{
			name: "a capital inside the body",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmAopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
		},
		{
			name: "a hyphen inside the body",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklm-opqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
		},
		{
			name: "an underscore inside the body",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklm_opqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
		},
		{
			name: "a run of the right length with no prefix in front of it",
			src:  "234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "the version the prefix carries written in prose",
			src:  "GET /api/v2/apps returned 200 for os_v2 clients",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := OneSignalAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_OneSignalAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "an environment assignment",
			src:  "ONESIGNAL_APP_API_KEY=os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
			want: "ONESIGNAL_APP_API_KEY=*****************************************************************************************************************",
		},
		{
			name: "the header OneSignal takes a key in",
			src:  "Authorization: Key os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
			want: "Authorization: Key *****************************************************************************************************************",
		},
		{
			name: "a key in json",
			src:  "{\"api_key\":\"os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a\"}",
			want: "{\"api_key\":\"*****************************************************************************************************************\"}",
		},
		{
			name: "a key on a command line",
			src:  "curl -H \"Authorization: Key os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a\" https://api.onesignal.com/notifications",
			want: "curl -H \"Authorization: Key *****************************************************************************************************************\" https://api.onesignal.com/notifications",
		},
		{
			name: "a key of each scope",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a os_v2_org_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
			want: "***************************************************************************************************************** *****************************************************************************************************************",
		},
	}

	m := New(WithPatterns(OneSignalAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OneSignalAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xos_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
			want: "x*****************************************************************************************************************",
		},
		{
			name: "underscore before",
			src:  "ONESIGNAL_KEY_os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
			want: "ONESIGNAL_KEY_*****************************************************************************************************************",
		},
		{
			name: "underscore after",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a_x",
			want: "*****************************************************************************************************************_x",
		},
		{
			// The far side of the same choice, and the one that costs something. A
			// boundary behind the match would drop this key rather than trim it;
			// without one the two characters written after it are redacted with the
			// key, the count being a floor read to the end of the run.
			name: "a character of the alphabet after",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567aab",
			want: "*******************************************************************************************************************",
		},
		{
			// A multi-byte rune written flush against a key on both sides, with no
			// space between them.
			name: "a multi-byte rune flush against the key on both sides",
			src:  "日本語os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a日本語",
			want: "日本語*****************************************************************************************************************日本語",
		},
	}

	m := New(WithPatterns(OneSignalAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OneSignalAPIKey_reachesTheEndOfTheRun(t *testing.T) {
	// The count is a floor, so a key is redacted from its prefix to wherever
	// the alphabet stops. What ends a run is what a body may not be written
	// with, and the characters an identifier is joined by are the ones worth
	// writing out: the underscore and the hyphen end a run, and so do the four
	// digits the alphabet leaves out.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a word written straight against a key",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567asuffix",
			want: "***********************************************************************************************************************",
		},
		{
			name: "an underscored word against a key",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a_suffix",
			want: "*****************************************************************************************************************_suffix",
		},
		{
			name: "a hyphenated word against a key",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a-suffix",
			want: "*****************************************************************************************************************-suffix",
		},
		{
			name: "a digit the alphabet leaves out against a key",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a0123",
			want: "*****************************************************************************************************************0123",
		},
		{
			name: "a capital against a key",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567aABC",
			want: "*****************************************************************************************************************ABC",
		},
		{
			name: "the byte just below the first letter against a key",
			src:  "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a`suffix",
			want: "*****************************************************************************************************************`suffix",
		},
	}

	m := New(WithPatterns(OneSignalAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OneSignalAPIKey_cutShortOfTheFloor(t *testing.T) {
	// What reading the count as a floor costs: a key shorter than the floor is
	// located nowhere, so a line cut to a column limit partway through one
	// leaves the characters written before the cut in the text. The floor is
	// what buys the other side of it, a key longer than the shortest being
	// redacted whole rather than cut short.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a body one character short of the floor",
			src:  "ONESIGNAL_APP_API_KEY=os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567",
		},
		{
			name: "a key cut off at its prefix",
			src:  "ONESIGNAL_APP_API_KEY=os_v2_app_",
		},
		{
			name: "a key cut off inside its prefix",
			src:  "ONESIGNAL_APP_API_KEY=os_v2_a",
		},
	}

	m := New(WithPatterns(OneSignalAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_OneSignalAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// A digest written behind the prefix is not the collision it is for a scan
	// reading base62. Four of the sixteen hexadecimal digits — 0, 1, 8 and 9 —
	// are ones this alphabet leaves out, so a run of a digest ends at the first
	// of them it writes, and each of the three below writes one at its opening.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a sha1 written behind the prefix",
			src:  "os_v2_app_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a sha256 written behind the prefix",
			src:  "os_v2_app_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a sha512 written behind the prefix, longer than the floor",
			src:  "os_v2_app_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	m := New(WithPatterns(OneSignalAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

// Test_OneSignalAPIKey_settlesWhatTheInputCutShort holds Find's second return
// to the offset in front of which nothing further back can still become a key,
// which is either a piece of a prefix standing at the end of the input or a
// candidate the end of the input cut short. What every built-in owes about
// that offset over generated text and over the samples is driven in
// builtins_test.go and fuzz_test.go; what is written out here is which inputs
// of this pattern's own shape hold anything back, since nothing else names
// them.
func Test_OneSignalAPIKey_settlesWhatTheInputCutShort(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "the opening alone, which is a piece of every prefix",
			src:  "see os_v2_",
			want: 4,
		},
		{
			name: "a scope without the separator behind it",
			src:  "see os_v2_app",
			want: 4,
		},
		{
			// The candidate it opens is cut short by the end of the input, and what
			// is held back is the whole of it rather than the prose in front.
			name: "a whole prefix at the end of the input",
			src:  "nothing here yet os_v2_app_",
			want: 17,
		},
		{
			name: "a body the end of the input cut short",
			src:  "see os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567",
			want: 4,
		},
		{
			// The floor is met and the run reaches the end of the input, so the key
			// is located and nothing behind its prefix is settled all the same: a
			// character still to come would carry the run on and lengthen the span.
			// The answer is not monotone in how much of a key has arrived, and
			// stream.go keeps the further of the two.
			name: "a whole key reaching the end of the input",
			src:  "see os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a",
			want: 4,
		},
		{
			name: "a whole key followed by a character that ends the run",
			src:  "see os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a ",
			want: 118,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, got := OneSignalAPIKey().Find(tt.src); got != tt.want {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OneSignalAPIKey_holdsAKeyTheInputCutShort(t *testing.T) {
	// The other half of what the offset above is for: a key arriving in two
	// writes is in neither of them, and a stream that released the first piece
	// would write the front of a key out in the clear.
	whole := "see os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a"
	cut := whole[:len(whole)-1] // one character short of the floor

	spans, retain := OneSignalAPIKey().Find(cut)
	if len(spans) != 0 {
		t.Errorf("Find(%q) = %v, want no span", cut, spans)
	}
	if want := 4; retain != want {
		t.Errorf("Find(%q) settled from %d, want %d", cut, retain, want)
	}

	m := New(WithPatterns(OneSignalAPIKey()))
	var out strings.Builder
	w := NewWriter(&out, m)
	if _, err := w.Write([]byte(cut)); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if _, err := w.Write([]byte(whole[len(whole)-1:])); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if got, want := out.String(), "see "+strings.Repeat("*", len(whole)-4); got != want {
		t.Errorf("a key written in two pieces came out %q, want %q", got, want)
	}
}

func Test_oneSignalAPIKeyPrefixes(t *testing.T) {
	// The scan reads a candidate back from a fixed index and then compares the
	// prefixes standing there, so a prefix that opened on something other than
	// the opening every key carries, or closed on something other than the
	// separator, is one it never finishes reading. Neither shows as a failing
	// case: the pattern would quietly stop locating that scope. Which byte the
	// scan searches the input for is Test_oneSignalAPIKeyAnchor's to hold.
	if len(oneSignalAPIKeyPrefixes) != len(oneSignalAPIKeyScopes) {
		t.Fatalf("%d prefixes for %d scopes, so a scope opens no candidate",
			len(oneSignalAPIKeyPrefixes), len(oneSignalAPIKeyScopes))
	}
	for _, prefix := range oneSignalAPIKeyPrefixes {
		t.Run(prefix, func(t *testing.T) {
			if !strings.HasPrefix(prefix, "os_v2_") {
				t.Errorf("the prefix does not open with what OneSignal writes every key with")
			}
			if !strings.HasSuffix(prefix, "_") {
				t.Errorf("the prefix does not close with the separator, so the body would be read from inside it")
			}
		})
	}
}

// Test_oneSignalAPIKeyAnchor holds every prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from. One
// search serves every scope only while every scope spells that byte there, and
// a scope that did not would be one no candidate is ever found at.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_oneSignalAPIKeyAnchor(t *testing.T) {
	for _, prefix := range oneSignalAPIKeyPrefixes {
		t.Run(prefix, func(t *testing.T) {
			if oneSignalAPIKeyAnchorIndex >= len(prefix) {
				t.Fatalf("the anchor stands at %d, the prefix is %d characters", oneSignalAPIKeyAnchorIndex, len(prefix))
			}
			if c := prefix[oneSignalAPIKeyAnchorIndex]; c != oneSignalAPIKeyAnchor {
				t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it",
					c, byte(oneSignalAPIKeyAnchor))
			}
		})
	}
}

func Test_oneSignalAPIKeyPrefixes_standAtNoOnePosition(t *testing.T) {
	// oneSignalAPIKeyPrefixLen reports the first prefix that matches, which is
	// the right answer only while no two of them can stand at one position. A
	// scope added later that opens on the whole of one already here — apps
	// behind app — would be read as the shorter prefix, and the body would then
	// begin inside the longer one rather than behind it. The tail takes the
	// longest match instead, so the scan and what a stream settles by would
	// disagree about the same text, which nothing else here reports.
	for i, a := range oneSignalAPIKeyPrefixes {
		for j, b := range oneSignalAPIKeyPrefixes {
			if i == j {
				continue
			}
			if strings.HasPrefix(b, a) {
				t.Errorf("%q stands at the start of %q, so a candidate opening %q is read as the shorter of the two", a, b, b)
			}
		}
	}
}

func Test_oneSignalAPIKeyPrefixes_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over
	// it, where a scan whose prefix closes on a character its own body admits
	// has to keep one. What makes the cursor unnecessary is that two candidates
	// can never read the same run: a candidate asks for that character at the
	// end of its prefix, no body may be written with it, so the run of an
	// earlier candidate has already ended there and the later candidate's body
	// begins past it. Were that character one a body admits, a run dense in
	// prefixes would be walked once for every candidate in it and the scan
	// would cost time quadratic in the length of such a line.
	for _, prefix := range oneSignalAPIKeyPrefixes {
		t.Run(prefix, func(t *testing.T) {
			if prefix == "" {
				t.Fatal("the scope carries no prefix, so there is no candidate to reason about")
			}
			if c := prefix[len(prefix)-1]; isOneSignalAPIKeyByte(c) {
				t.Errorf("the prefix closes with %q, which a body may be written with, so two candidates can read the same run", c)
			}
		})
	}
}

func Test_isOneSignalAPIKeyByte(t *testing.T) {
	// The alphabet is stated over every byte rather than by example, and against
	// the character set RFC 4648 writes out — in the lowercase a key is written
	// in — rather than against the ranges the scan reads it by: the two
	// spellings are what hold each other, as the reference below holds the
	// grammar around them.
	const charset = "abcdefghijklmnopqrstuvwxyz234567"

	for c := range 256 {
		b := byte(c)
		want := strings.IndexByte(charset, b) >= 0
		if got := isOneSignalAPIKeyByte(b); got != want {
			t.Errorf("isOneSignalAPIKeyByte(%q) = %v, want %v", b, got, want)
		}
	}

	// And the alphabet is thirty-two characters, which is what writing five
	// bits to one means.
	if len(charset) != 32 {
		t.Errorf("the character set is %d characters, base32 writes five bits to one", len(charset))
	}
	for _, c := range []byte{'0', '1', '8', '9'} {
		if isOneSignalAPIKeyByte(c) {
			t.Errorf("isOneSignalAPIKeyByte(%q) = true, want the digit base32 leaves out", c)
		}
	}
}

// Test_OneSignalAPIKey_scanIsLinear drives the crowding this scan is most
// exposed to. Rejecting a candidate resumes one byte along, so a line dense in
// prefixes holds a candidate for every ten characters it has. The one thing a
// candidate reads that is a walk over the rest of the input rather than a
// bounded test is where its run ends, and repeating that walk at every
// candidate would cost time quadratic in the length of the line.
func Test_OneSignalAPIKey_scanIsLinear(t *testing.T) {
	checkScanIsLinear(t, OneSignalAPIKey(), map[string]string{
		// Candidates as close together as a prefix allows, none of them with a
		// run long enough to be a body: every one reaches the body of the loop
		// and every one is rejected.
		"a candidate every ten characters": strings.Repeat("os_v2_app_", 200000),
		// The same with the two scopes alternating, so both comparisons are
		// walked at every candidate.
		"the two scopes alternating": strings.Repeat("os_v2_app_os_v2_org_", 100000),
		// One candidate whose body is the whole line, which is the walk over a
		// run this scan means to pay for once.
		"one body running the length of the line": "os_v2_app_" + strings.Repeat("a", 1800000),
		// The anchor byte with nothing behind it, which is the search stopping
		// at every byte of the line and reading a candidate back from none.
		"the anchor byte with no prefix behind it": strings.Repeat("v", 300000),
	})
}

// referenceOneSignalAPIKeyAt reports where a OneSignal API key written at start
// ends, and whether one is written there at all. It is the statement of what the
// scan in builtin_onesignal_api_key.go locates, kept here so that the scan can be
// held to it, and it reads one position and stops.
//
// The prefixes, the floor and the alphabet are written out here rather than read
// from oneSignalAPIKeyPrefixes, oneSignalAPIKeyBodyChars and
// isOneSignalAPIKeyByte. Reading them would move this with whatever the scan was
// changed to, and the fuzz target below would then hold a rule against itself;
// Test_references_shareNoDeclarationWithTheScans is what keeps the two apart.
//
// It is written out rather than built on a regular expression, which is the
// choice the layout leaves open and which the floor settles. A floor spelled as
// a counted repetition unrolls into a program as wide as the floor, an input
// reaching into it is slow to run, and the engine's minimizer re-runs one input
// until its budget is out — sixty seconds of it by default, against the thirty
// seconds CI gives a target. Measured over a cleaned fuzz cache at that thirty,
// the expression left FuzzOneSignalAPIKey_matchesReference reporting no
// executions at all for the last fifteen seconds and 307,377 executions in all;
// the walks below hold their rate for the whole thirty and reach 1,172,103.
func referenceOneSignalAPIKeyAt(src string, start int) (int, bool) {
	if !strings.HasPrefix(src[start:], "os_v2_app_") && !strings.HasPrefix(src[start:], "os_v2_org_") {
		return 0, false
	}
	body := start + 10
	end := body
	for end < len(src) && referenceOneSignalAPIKeyByte(src[end]) {
		end++
	}
	if end-body < 103 {
		return 0, false
	}
	return end, true
}

// referenceOneSignalAPIKeyByte reports whether c is a character a body is written
// with: a lowercase letter or one of the six digits base32 admits.
func referenceOneSignalAPIKeyByte(c byte) bool {
	return 'a' <= c && c <= 'z' || '2' <= c && c <= '7'
}

// referenceOneSignalAPIKeyFind locates keys the plain way: every position in
// turn, with nothing remembered between them. It is the control flow of the scan
// with the grammar above in place of the byte tests the scan reads it with.
//
// Asking at every position is what the scan does too, and it is not written here
// to restate that. A reference is written to know nothing its scan claims, and
// that a key can begin inside another — the two letters an opening starts with
// are ones a body is written with — is one of the things the scan claims.
func referenceOneSignalAPIKeyFind(src string) []Span {
	var spans []Span
	for i := range len(src) {
		if end, ok := referenceOneSignalAPIKeyAt(src, i); ok {
			spans = append(spans, Span{Start: i, End: end})
		}
	}
	return spans
}

// FuzzOneSignalAPIKey_matchesReference guards the hand-written scan: the byte
// it searches for, the scopes it admits, the floor it holds a body to, the
// alphabet it reads that body in and the byte it resumes at may none of them
// change which keys are located.
func FuzzOneSignalAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("ONESIGNAL_APP_API_KEY=os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a")
	f.Add("os_v2_org_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a")
	f.Add("os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567")   // one short of a body
	f.Add("os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567ab") // and a run longer than one
	f.Add("os_v2_app_234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567A")  // a body written in capitals
	f.Add("os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklm0opqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a")  // a digit the alphabet leaves out
	f.Add("os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklm-opqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a")  // a hyphen, which ends the run
	f.Add("os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklm_opqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a")  // an underscore, likewise
	f.Add("os_v2_usr_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a")  // a scope this pattern was never told about
	f.Add("os_v2_")                                                                                                             // the opening alone
	f.Add("os_v2_app_")
	// A hexadecimal run behind the prefix, which is the shape the alphabet
	// decides: the first writes an excluded digit at its opening and the second
	// reaches the floor before it writes one.
	f.Add("os_v2_app_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("os_v2_app_234567abcdef234567abcdef234567abcdef234567abcdef234567abcdef234567abcdef234567abcdef234567abcdef234567abcdef0123456789abcdef0123")
	// Two keys with nothing between them, where the run of the first carries
	// on into the opening of the second and a scan resuming past a match would
	// step over it.
	f.Add("os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567aos_v2_org_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a")
	f.Add("os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a os_v2_org_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a")
	// Candidate positions crowded as close as they can be: a prefix at every
	// tenth byte in the first, a run that is a body to every candidate in the
	// second, and the anchor at every byte of the third.
	f.Add(strings.Repeat("os_v2_app_", 8))
	f.Add(strings.Repeat("os_v2_app_", 8) + strings.Repeat("a", 128))
	f.Add(strings.Repeat("v", 64))

	fuzzAgainstReference(f, OneSignalAPIKey().Find, referenceOneSignalAPIKeyFind)
}

// oneSignalAPIKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under
// a plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func oneSignalAPIKeyFindBenchmarks() []benchmarkCase {
	// The line carries the snake_case field names a log line about a OneSignal
	// request has anyway, because they are what a scan searching for the
	// underscore of the prefix would have stopped at. The counts the anchor was
	// chosen on are this line's, and builtin_onesignal_api_key.go names them.
	line := `time=2026-08-17T00:00:00Z level=info msg="POST /notifications" app_id=01234567-89ab-cdef-0123-456789abcdef target_channel=push included_segments=subscribed_users `
	key := "os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a"
	org := "os_v2_org_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567a"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A prefix written out and a body one character short of the floor:
			// the candidate at each prefix walks its whole run and is turned away
			// by its width, which is the most a candidate can cost here. A hyphen
			// closes each run, since a prefix written straight against a body
			// carries that run two characters into its opening and so past the
			// floor. This is the input that would show the run guarantee gone.
			name:  "candidates that are not values",
			src:   strings.Repeat("os_v2_app_234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567-", 8),
			spans: 0,
		},
		{
			// Values as close together as they can stand, the two scopes
			// alternating, so both comparisons are walked at every candidate.
			// Each run carries on into the opening of the key behind it, so every
			// span but the last overlaps the next.
			name:  "values with nothing between them",
			src:   strings.Repeat(key+org, 8),
			spans: 16,
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
