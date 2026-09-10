package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Dub API key pattern: what it locates and what it leaves alone, written
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
// shape, obviously not real. The run they are built from is
// 0123456789abcdefghijklmn, which is the sixteen characters of
// 0123456789abcdef carried on through the alphabet to twenty-four, a whole
// body. Where a case is about the ends of the alphabet rather than about the
// count, the run is shortened by however many characters the case writes at
// one end or the other.

func Test_DubAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "dub_0123456789abcdefghijklmn",
			want: []Span{{0, 28}},
		},
		{
			name: "a key in an environment assignment",
			src:  "DUB_API_KEY=dub_0123456789abcdefghijklmn",
			want: []Span{{12, 40}},
		},
		{
			// base62 reads the letters of both cases, and every other case in
			// this file writes its body in lowercase alone.
			name: "a body written in capitals",
			src:  "dub_0123456789ABCDEFGHIJKLMN",
			want: []Span{{0, 28}},
		},
		{
			// The alphabet at the top of its range, at the first character of a
			// body: z is the last character base62 admits.
			name: "a body opening on the last letter of the alphabet",
			src:  "dub_z0123456789abcdefghijklm",
			want: []Span{{0, 28}},
		},
		{
			// The same character at the other end of a body, where the count
			// ends the key rather than the alphabet.
			name: "a body closing on the last letter of the alphabet",
			src:  "dub_0123456789abcdefghijklmz",
			want: []Span{{0, 28}},
		},
		{
			// The capitals at both ends at once: A is the first of them and Z
			// the last.
			name: "a body opening on the first capital and closing on the last",
			src:  "dub_A0123456789abcdefghijklZ",
			want: []Span{{0, 28}},
		},
		{
			// The digits are the bottom of the alphabet, and 9 is the last of
			// them.
			name: "a body closing on the last digit",
			src:  "dub_0123456789abcdefghijklm9",
			want: []Span{{0, 28}},
		},
		{
			// The twenty-four behind the prefix are read as a count and not a
			// floor: what follows the twenty-eighth character is not part of
			// the key and stays in the text.
			name: "an alphabet run longer than a key is a key and what follows it",
			src:  "dub_0123456789abcdefghijklmno",
			want: []Span{{0, 28}},
		},
		{
			// The prefix written twice opens a candidate at the first, whose
			// body carries the underscore of the second and so is no body; the
			// key stands four characters along, inside the twenty-eight bytes
			// that candidate reached over. This is the half of "advance, never
			// consume" that a scan stepping past a failed candidate would lose,
			// where Test_DubAPIKey_aKeyBeginningInsideAnother is the half where
			// both candidates become keys.
			name: "a key inside a candidate the body turned away",
			src:  "dub_dub_0123456789abcdefghijklmn",
			want: []Span{{4, 32}},
		},
		{
			// Neither key is inside the other, and nothing separates them.
			name: "two keys with nothing between them",
			src:  "dub_0123456789abcdefghijklmndub_0123456789ABCDEFGHIJKLMN",
			want: []Span{{0, 28}, {28, 56}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DubAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DubAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "dub_",
		},
		{
			// Twenty-three characters where the pattern asks for twenty-four.
			name: "body one character too short",
			src:  "dub_0123456789abcdefghijklm",
		},
		{
			name: "a hyphen in the body",
			src:  "dub_0123456789-bcdefghijklmn",
		},
		{
			name: "an underscore in the body",
			src:  "dub_0123456789_bcdefghijklmn",
		},
		{
			// The two characters above stand in the middle of a body. These
			// two stand at its first character, where a body opens.
			name: "a hyphen straight behind the prefix",
			src:  "dub_-123456789abcdefghijklmn",
		},
		{
			name: "an underscore straight behind the prefix",
			src:  "dub__123456789abcdefghijklmn",
		},
		{
			// And these at its last character, straight in front of where the
			// count ends the key, where the same rejection has to hold.
			name: "a hyphen at the last character of the body",
			src:  "dub_0123456789abcdefghijklm-",
		},
		{
			name: "an underscore at the last character of the body",
			src:  "dub_0123456789abcdefghijklm_",
		},
		{
			name: "a dot at the last character of the body",
			src:  "dub_0123456789abcdefghijklm.",
		},
		{
			name: "a space at the last character of the body",
			src:  "dub_0123456789abcdefghijklm ",
		},
		{
			// The six characters standing immediately outside the three ranges
			// base62 is made of, each written where a body opens. / and : fence
			// the digits, @ and [ the capitals, ` and { the lowercase letters.
			name: "the character below the digits where the body opens",
			src:  "dub_/123456789abcdefghijklmn",
		},
		{
			name: "the character above the digits where the body opens",
			src:  "dub_:123456789abcdefghijklmn",
		},
		{
			name: "the character below the capitals where the body opens",
			src:  "dub_@123456789abcdefghijklmn",
		},
		{
			name: "the character above the capitals where the body opens",
			src:  "dub_[123456789abcdefghijklmn",
		},
		{
			name: "the character below the lowercase letters where the body opens",
			src:  "dub_`123456789abcdefghijklmn",
		},
		{
			name: "the character above the lowercase letters where the body opens",
			src:  "dub_{123456789abcdefghijklmn",
		},
		{
			// The same six at the other end of a body.
			name: "the character below the digits where the body closes",
			src:  "dub_0123456789abcdefghijklm/",
		},
		{
			name: "the character above the digits where the body closes",
			src:  "dub_0123456789abcdefghijklm:",
		},
		{
			name: "the character below the capitals where the body closes",
			src:  "dub_0123456789abcdefghijklm@",
		},
		{
			name: "the character above the capitals where the body closes",
			src:  "dub_0123456789abcdefghijklm[",
		},
		{
			name: "the character below the lowercase letters where the body closes",
			src:  "dub_0123456789abcdefghijklm`",
		},
		{
			name: "the character above the lowercase letters where the body closes",
			src:  "dub_0123456789abcdefghijklm{",
		},
		{
			name: "a body broken by a space",
			src:  "dub_0123456789abcdef ghijklmn",
		},
		{
			name: "a body broken by a line break",
			src:  "dub_0123456789abcdef\nghijklmn",
		},
		{
			name: "an uppercase prefix",
			src:  "DUB_0123456789abcdefghijklmn",
		},
		{
			// One letter of the prefix in the other case, rather than the whole
			// of it.
			name: "the prefix with its first letter capitalized",
			src:  "Dub_0123456789abcdefghijklmn",
		},
		{
			name: "a hyphen where the prefix carries its underscore",
			src:  "dub-0123456789abcdefghijklmn",
		},
		{
			name: "the prefix without the underscore that closes it",
			src:  "dub0123456789abcdefghijklmno",
		},
		{
			// Twenty-eight base62 characters that open with something else. The
			// prefix is the whole of the anchor, so a run of the right length is
			// not a key without it.
			name: "a run of the right length opening with no prefix",
			src:  "xxx_0123456789abcdefghijklmn",
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
		{
			// A snake_case name whose segment closes on the three letters the
			// prefix opens with. The next segment of such a name runs out at
			// its own underscore long before the twenty-fourth character.
			// Test_DubAPIKey_holdsAKeyTheInputCutShort writes the same name out
			// at a length that reaches the body test, which is where the
			// underscore does the rejecting rather than the end of the input.
			name: "a name whose segment closes on the prefix",
			src:  "overdub_gain_factor = 2",
		},
		{
			// A certificate body, which is standard base64 rather than
			// base64url: the two characters that encoding writes where
			// base64url writes the hyphen and the underscore are + and /, so a
			// run of it holds no prefix to be found at however long it goes on.
			name: "a certificate body in standard base64",
			src:  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0123456789abcdef+/0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DubAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DubAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "DUB_API_KEY=dub_0123456789abcdefghijklmn",
			want: "DUB_API_KEY=****************************",
		},
		{
			name: "quoted",
			src:  `"dub_0123456789abcdefghijklmn"`,
			want: `"****************************"`,
		},
		{
			name: "json",
			src:  `{"token":"dub_0123456789abcdefghijklmn"}`,
			want: `{"token":"****************************"}`,
		},
		{
			// The header Dub's own reference calls the API with.
			name: "the bearer authorization header",
			src:  "Authorization: Bearer dub_0123456789abcdefghijklmn",
			want: "Authorization: Bearer ****************************",
		},
		{
			name: "a command line",
			src:  `curl -H "Authorization: Bearer dub_0123456789abcdefghijklmn" https://api.dub.co/links`,
			want: `curl -H "Authorization: Bearer ****************************" https://api.dub.co/links`,
		},
		{
			name: "twice",
			src:  "dub_0123456789abcdefghijklmn dub_0123456789ABCDEFGHIJKLMN",
			want: "**************************** ****************************",
		},
	}

	m := New(WithPatterns(DubAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DubAPIKey_aKeyBeginningInsideAnother(t *testing.T) {
	// The three letters the prefix opens with belong to the alphabet a body is
	// written in, so a body may close with dub and the underscore of the next
	// key stand directly behind it. The second key begins three characters
	// before the first one ends. A scan resuming past its match would step over
	// it and leave it in the output whole; the two spans overlap and a Masker
	// resolves them into one.
	src := "dub_0123456789abcdefghijkdub_0123456789abcdefghijklmn"

	want := []Span{{0, 28}, {25, 53}}
	if got, _ := DubAPIKey().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}

	m := New(WithPatterns(DubAPIKey()))
	if got, want := m.Mask(src), strings.Repeat("*", len(src)); got != want {
		t.Errorf("Mask(%q) = %q, want %q", src, got, want)
	}
}

func Test_DubAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xdub_0123456789abcdefghijklmn",
			want: "x****************************",
		},
		{
			name: "underscore before",
			src:  "DUB_API_KEY_dub_0123456789abcdefghijklmn",
			want: "DUB_API_KEY_****************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this key rather
			// than trim it; without one the twenty-eight characters Dub issued
			// are redacted and the one written after them, which is part of no
			// credential, stays in the text.
			name: "a character of the alphabet after",
			src:  "dub_0123456789abcdefghijklmno",
			want: "****************************o",
		},
		{
			// A multi-byte rune written against the key on both sides. Neither
			// UTF-8 encoding shares a byte with the prefix or the body's
			// alphabet, so the key keeps its span exactly as it does against a
			// single-byte character.
			name: "a multi-byte rune before and after",
			src:  "鍵はdub_0123456789abcdefghijklmnです",
			want: "鍵は****************************です",
		},
	}

	m := New(WithPatterns(DubAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DubAPIKey_leavesWhatFollowsAlone(t *testing.T) {
	// The count ends a key at its twenty-eighth character, so whatever is
	// written after one stays in the text whether the alphabet admits it or
	// not.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "host",
			src:  "host=dub_0123456789abcdefghijklmn.example.com",
			want: "host=****************************.example.com",
		},
		{
			name: "sentence",
			src:  "the key is dub_0123456789abcdefghijklmn.",
			want: "the key is ****************************.",
		},
		{
			name: "underscored word",
			src:  "dub_0123456789abcdefghijklmn_suffix",
			want: "****************************_suffix",
		},
		{
			name: "dashed word",
			src:  "dub_0123456789abcdefghijklmn-suffix",
			want: "****************************-suffix",
		},
	}

	m := New(WithPatterns(DubAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DubAPIKey_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix closes with an
	// underscore, which hexadecimal and standard base64 write nowhere, so only
	// a base64url encoding can spell it — and where twenty-four characters of
	// the letters and digits follow, those twenty-eight are redacted.
	//
	// They are held to being redacted rather than to being spared. Nothing in
	// the text tells such a run from a key — they are the same twenty-eight
	// bytes — so a scan that let these through would let a real key through
	// with them, which builtin_dub_api_key.go sets out. What the table is for is
	// that the cases move with the scan: one of them ceasing to be located means
	// the grammar changed, and that is a decision to be taken rather than
	// noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "inside a base64url payload",
			src:  "payload=zzzzdub_0123456789abcdefghijklmnzzzz",
			want: "payload=zzzz****************************zzzz",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the Dub
			// pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzdub_0123456789abcdefghijklmnzzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz****************************zzzz",
		},
	}

	m := New(WithPatterns(DubAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DubAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// The over-match that takes a value a reader had a use for. Hexadecimal
	// digits are base62 and a digest carries nothing that ends a run, so every
	// digest written behind the prefix is at least as long as the count: the
	// first twenty-four characters of one are redacted with the prefix and the
	// rest of the digest stays in the text.
	//
	// The last two cases are what holds either side of it: a run of sixteen is
	// eight characters short of a body, and a hyphen is no character the prefix
	// carries.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "an md5 behind the prefix",
			src:  "dub_0123456789abcdef0123456789abcdef",
			want: "****************************89abcdef",
		},
		{
			name: "a sha1 behind the prefix in a cache key",
			src:  "key: dub_0123456789abcdef0123456789abcdef01234567",
			want: "key: ****************************89abcdef01234567",
		},
		{
			name: "a sha256 behind the prefix",
			src:  "dub_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "****************************89abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a run of sixteen behind the prefix, eight characters short of a body",
			src:  "dub_0123456789abcdef",
			want: "dub_0123456789abcdef",
		},
		{
			name: "an md5 behind a hyphen rather than the prefix",
			src:  "dub-0123456789abcdef0123456789abcdef",
			want: "dub-0123456789abcdef0123456789abcdef",
		},
	}

	m := New(WithPatterns(DubAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DubAPIKey_theOtherPrefixes(t *testing.T) {
	// The kinds Dub writes behind the same four characters that this scan does
	// not read: the rationale beside the scan says what separates each of them
	// from an API key. Each names its kind and closes that name with an
	// underscore, so the twenty-four characters read behind dub_ run into a
	// character no body admits.
	//
	// The table is the kinds Dub writes today rather than a closed set — a kind
	// added tomorrow is turned away by the same underscore without being written
	// here. What it is for is the decision: a value below ceasing to be declined
	// is a change somebody argues for rather than one somebody notices
	// afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a publishable key",
			src:  "dub_pk_0123456789abcdefghijklmn",
		},
		{
			// A public embed token, whose body is a ULID written in Crockford's
			// base32 rather than in the alphabet a key's body is: the run it is
			// built from is the uppercase one with I, L, O and U taken out,
			// which that encoding leaves no room for.
			name: "a public embed token",
			src:  "dub_embed_0123456789ABCDEFGHJKMNPQRS",
		},
		{
			name: "an oauth client id",
			src:  "dub_app_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "an oauth client secret",
			src:  "dub_app_secret_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
		},
		{
			name: "an oauth access token",
			src:  "dub_access_token_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DubAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

// Test_DubAPIKey_holdsAKeyTheInputCutShort states, with a literal number, what
// the second return of Find settles: a piece of the prefix standing at the end
// of the input, a candidate the end of the input cut short, and a whole match
// with nothing left unsettled behind it.
func Test_DubAPIKey_holdsAKeyTheInputCutShort(t *testing.T) {
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
			src:    "dub",
			retain: 0,
		},
		{
			name:   "a piece of the prefix behind prose",
			src:    "the key starts with dub",
			retain: len("the key starts with "),
		},
		{
			// A whole prefix and a body the input cuts short before the count
			// is met. The candidate could still become a key were the input
			// longer, so what is unsettled reaches back to where the candidate
			// opened.
			name:   "a body the input cuts short of the count",
			src:    "dub_0123456789abcdef",
			retain: 0,
		},
		{
			// The snake_case name the rationale says the underscore turns away,
			// written long enough for the body test to be reached. Settled to
			// the end says the name was read and rejected; the short form of
			// the same name settles at the candidate instead, since the input
			// runs out before the count and the scan gives up on it rather than
			// reading what is written of it. Only the long form tells the
			// underscore's rejection from that truncation, which is why the
			// number is stated here rather than left to the case in
			// Test_DubAPIKey_noMatch.
			name:   "a snake_case name long enough to be rejected rather than cut short",
			src:    "overdub_gain_factor_in_the_mixdown_settings = 2",
			retain: len("overdub_gain_factor_in_the_mixdown_settings = 2"),
		},
		{
			name:   "the same name cut short of the count",
			src:    "overdub_gain_factor",
			retain: len("over"),
		},
		{
			// A whole key with more text after it, ending in a byte that opens
			// no piece of the prefix, so nothing at the end of the input is
			// left unsettled.
			name:   "a whole key followed by settled text",
			src:    "dub_0123456789abcdefghijklmn tail",
			want:   []Span{{0, 28}},
			retain: len("dub_0123456789abcdefghijklmn tail"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := DubAPIKey().Find(tt.src)
			if retain != tt.retain {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, retain, tt.retain)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_dubAPIKeyPrefix(t *testing.T) {
	// Two claims the scan rests on, neither of which anything else here would
	// report. The scan resumes one byte past the start of a candidate because a
	// key can begin three characters before the end of the one before it, and
	// that holds only while the letters the prefix opens with are ones a body
	// may be written in. It stops searching inside a body, and turns away the
	// other kinds Dub writes, only while the character the prefix closes with
	// is one no body admits.
	if dubAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for i := range len(dubAPIKeyPrefix) - 1 {
		if c := dubAPIKeyPrefix[i]; !isBase62Byte(c) {
			t.Errorf("the prefix holds %q where a body's alphabet is asked for, so no key can begin inside another", c)
		}
	}
	if c := dubAPIKeyPrefix[len(dubAPIKeyPrefix)-1]; isBase62Byte(c) {
		t.Errorf("the prefix closes on %q, which a body may be written with", c)
	}
}

// Test_dubAPIKeyAnchor holds the prefix to carrying the byte the scan searches
// the input for at the index it reads a candidate back from. builtin_scan.go
// says why that is held here rather than left to the targets.
//
// The second assertion is what the rationale's account of the choice rests on,
// and nothing else reaches it: an anchor moved to one of the three letters
// leaves the scan correct and every case in this file passing, while a search
// resuming into a body stops at that letter about once in sixty-two characters
// rather than running to the end of the body without stopping.
func Test_dubAPIKeyAnchor(t *testing.T) {
	if dubAPIKeyAnchorIndex >= len(dubAPIKeyPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", dubAPIKeyAnchorIndex, len(dubAPIKeyPrefix))
	}
	if c := dubAPIKeyPrefix[dubAPIKeyAnchorIndex]; c != dubAPIKeyAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(dubAPIKeyAnchor))
	}
	if isBase62Byte(dubAPIKeyAnchor) {
		t.Errorf("the scan searches for %q, which a body may be written with, so a search resumes inside one", byte(dubAPIKeyAnchor))
	}
}

// Test_dubAPIKeyFindBenchmarks_lineTheAnchorWasChosenAgainst holds the line the
// benchmarks are written on to the counts the rationale reads the anchor choice
// off. The counts are the whole of the evidence for searching on the underscore
// rather than on one of the three letters, and nothing else reports them: a
// word added to that line with an underscore in it — a log field written
// snake_case, say — falsifies the sentence in silence, since every benchmark
// goes on timing whatever the line became.
func Test_dubAPIKeyFindBenchmarks_lineTheAnchorWasChosenAgainst(t *testing.T) {
	var line string
	for _, c := range dubAPIKeyFindBenchmarks() {
		if c.name == "no value" {
			line = c.src
		}
	}
	if line == "" {
		t.Fatal(`no benchmark case named "no value", so the line the anchor was chosen against is not here to count`)
	}

	for _, tt := range []struct {
		c    byte
		want int
	}{
		{'d', 4},
		{'u', 3},
		{'b', 2},
		{dubAPIKeyAnchor, 0},
	} {
		if got := strings.Count(line, string([]byte{tt.c})); got != tt.want {
			t.Errorf("the line carries %q %d times, the rationale reads the anchor off %d", tt.c, got, tt.want)
		}
	}
}

// Test_dubAPIKeyChars holds the counts to the numbers the rationale reads them
// as: twenty-four is the length Dub's own generator is called with, and a key
// is that with the prefix in front.
func Test_dubAPIKeyChars(t *testing.T) {
	if dubAPIKeyBodyChars != 24 {
		t.Errorf("a body is read as %d characters, the rationale says twenty-four", dubAPIKeyBodyChars)
	}
	if want := len(dubAPIKeyPrefix) + dubAPIKeyBodyChars; dubAPIKeyChars != want {
		t.Errorf("a key is read as %d characters, the prefix and the body come to %d", dubAPIKeyChars, want)
	}
	if dubAPIKeyChars != 28 {
		t.Errorf("a key is read as %d characters, the rationale says twenty-eight", dubAPIKeyChars)
	}
}

func Test_isDubAPIKeyBody(t *testing.T) {
	// The count and the alphabet together, stated over every byte rather than
	// by example: a body is exactly dubAPIKeyBodyChars characters and each of
	// them base62.
	body := strings.Repeat("a", dubAPIKeyBodyChars)

	if !isDubAPIKeyBody(body) {
		t.Errorf("isDubAPIKeyBody(%q) = false, want a body of %d characters to be one", body, dubAPIKeyBodyChars)
	}
	for _, s := range []string{body[:len(body)-1], body + "a"} {
		if isDubAPIKeyBody(s) {
			t.Errorf("isDubAPIKeyBody(%q) = true, want only %d characters to be a body", s, dubAPIKeyBodyChars)
		}
	}

	for c := range 256 {
		b := byte(c)
		src := body[:len(body)-1] + string([]byte{b})
		if got, want := isDubAPIKeyBody(src), isBase62Byte(b); got != want {
			t.Errorf("isDubAPIKeyBody(%q) = %v with %q in it, want %v", src, got, b, want)
		}
	}
}

// referenceDubAPIKey is the expression the scan in builtin_dub_api_key.go reads
// by hand: the statement of what a Dub API key is, kept here so that the scan
// can be held to it.
//
// The prefix, the count and the alphabet are spelled again rather than built
// from dubAPIKeyPrefix, dubAPIKeyBodyChars and isBase62Byte. A reference
// sharing those declarations could not disagree with the scan about them, and
// it is exactly that disagreement the fuzz target below is for: the two have to
// be changed together or reported apart.
var referenceDubAPIKey = regexp.MustCompile(`dub_[0-9A-Za-z]{24}`)

// referenceDubAPIKeyFind locates keys the plain way: the leftmost match of the
// expression above, then the leftmost one beginning after that match's first
// byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a key can begin inside one: the three letters
// the prefix opens with are written in the alphabet a body is, so a body
// closing on dub with an underscore behind it holds a key the engine would
// never go on to try. The scan finds both and reports the two spans
// overlapping for a Masker to resolve, so the reference must ask about both.
//
// Resuming a byte along costs this one nothing beyond a constant, where a
// reference reading a body to the end of its run pays for it: every candidate
// reads at most twenty-eight characters, here as in the scan, so neither has a
// run to walk and there is no cursor for either to be wrong about.
func referenceDubAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceDubAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzDubAPIKey_matchesReference guards the hand-written scan: the prefix it
// searches for, the count it reads behind that prefix, the alphabet it reads it
// in and the byte it resumes at may none of them change which keys are located.
func FuzzDubAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("DUB_API_KEY=dub_0123456789abcdefghijklmn")
	f.Add("Authorization: Bearer dub_0123456789abcdefghijklmn")
	f.Add("dub_0123456789ABCDEFGHIJKLMN")    // a body written in capitals
	f.Add("dub_0123456789abcdefghijklm")     // one short of a key
	f.Add("dub_0123456789abcdefghijklmno")   // and a run longer than one
	f.Add("DUB_0123456789abcdefghijklmn")    // an uppercase prefix
	f.Add("dub-0123456789abcdefghijklmn")    // a hyphen where it carries its underscore
	f.Add("dub0123456789abcdefghijklmno")    // the underscore that closes it left out
	f.Add("dub_0123456789-bcdefghijklmn")    // a hyphen in the body
	f.Add("dub_0123456789_bcdefghijklmn")    // and an underscore
	f.Add("dub_0123456789abcdef ghijklmn")   // a space breaks the body
	f.Add("dub_0123456789abcdef\nghijklmn")  // and a line break
	f.Add("dub_pk_0123456789abcdefghijklmn") // the prefix of a publishable key
	f.Add("dub_access_token_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("dub_0123456789abcdefghijklmn.next")
	f.Add("dub_0123456789abcdefghijklmn\ndub_0123456789ABCDEFGHIJKLMN")
	// A key beginning inside the match before it, which a scan resuming past a
	// match steps over; a key inside a candidate the body turned away, which is
	// the same step taken over a match that was never made; and two keys with
	// nothing between them, which is the first text without the overlap.
	f.Add("dub_0123456789abcdefghijkdub_0123456789abcdefghijklmn")
	f.Add("dub_dub_0123456789abcdefghijklmn")
	f.Add("dub_0123456789abcdefghijklmndub_0123456789ABCDEFGHIJKLMN")
	f.Add(strings.Repeat("dub_", 8))
	// Candidate positions crowded as close as they can be: every fourth byte in
	// the first, and a run that is a body to every candidate in it.
	f.Add(strings.Repeat("dub_", 32))
	f.Add(strings.Repeat("dub_", 32) + "!")
	// The prefix written inside a run of the alphabet, which is the over-match
	// the pattern admits, and a digest written behind it.
	f.Add("payload=zzzzdub_0123456789abcdefghijklmnzzzz")
	f.Add("dub_0123456789abcdef0123456789abcdef01234567")
	// The two encodings that carry no candidate at all, and a snake_case name
	// long enough for the body test to decide it.
	f.Add("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0123456789abcdef+/0123456789abcdef")
	f.Add("overdub_gain_factor_in_the_mixdown_settings = 2")

	fuzzAgainstReference(f, DubAPIKey().Find, referenceDubAPIKeyFind)
}

// dubAPIKeyFindBenchmarks is what this scan is timed on. The builtinPatterns
// entry for the pattern names it, and BenchmarkBuiltins times every case it
// holds under the pattern's own name, so that a built-in cannot arrive without
// a benchmark. Every case is held to the count it states under a plain go test
// as well, which is what a benchmark nobody has run yet cannot be.
func dubAPIKeyFindBenchmarks() []benchmarkCase {
	// The vendor's own host and short domain carry the letters of the prefix
	// twice over, so this line is what the anchor was chosen against: the d
	// stands four times on it, the u three and the b twice, where the
	// underscore the scan searches for stands not at all and the line costs the
	// search one pass and no candidate.
	line := `time=2026-08-17T00:00:00Z level=info msg="created a short link" domain=dub.sh url=https://api.dub.co/links `
	key := "dub_0123456789abcdefghijklmn"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate at every twenty-eighth byte, each of them reading the
			// whole count before the last character turns it away. That is the
			// most a candidate can cost this scan without becoming a key, and
			// there is no value at the end of any of it.
			name:  "candidates that are not values",
			src:   strings.Repeat("dub_0123456789abcdefghijklm.", 16),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "token=" + key,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "token=" + key,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"token="+key+"\n", 32),
			spans: 32,
		},
	}
}
