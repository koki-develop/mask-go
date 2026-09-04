package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Groq API key pattern: what it locates and what it leaves alone, written
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
// shape, obviously not real. The run they are built from,
// 0123456789abcdefghijklmnopqrstuvwxyz, is thirty-six characters, so a body
// carries it and fourteen characters more — the shortest body the scan reads,
// since the count is a floor, so a body shortened for readability would leave a
// case holding no key at all. It is written in lowercase where the case does
// not matter and in uppercase where the case is what a case is about: base62
// holds the letters of both, so either spelling is a body.

func Test_GroqAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
			want: []Span{{0, 54}},
		},
		{
			name: "a key in an environment assignment",
			src:  "GROQ_API_KEY=gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
			want: []Span{{13, 67}},
		},
		{
			// base62 holds the letters of both cases, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "gsk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD",
			want: []Span{{0, 54}},
		},
		{
			// The count is a floor and the span reaches the end of the run, so
			// a run longer than the shortest body is a key to the end of it
			// rather than a key and a character left over.
			name: "a run longer than the shortest body",
			src:  "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcde",
			want: []Span{{0, 55}},
		},
		{
			// The length every published key actually has: fifty-two
			// characters behind the prefix, fifty-six altogether. This is the
			// one length nobody wagers by, sitting strictly between the floor
			// and the runs the cases above and below drive.
			name: "a key at the length every published key has",
			src:  "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdef",
			want: []Span{{0, 56}},
		},
		{
			name: "two keys separated by a space",
			src:  "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd gsk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD",
			want: []Span{{0, 54}, {55, 109}},
		},
		{
			// The three letters the prefix opens with belong to the alphabet a
			// body is written in, so a body may close with gsk and the
			// underscore of the next key stand directly behind it. The second
			// key begins three characters before the first one ends, and a scan
			// resuming past a match would step over it. The spans overlap,
			// which a Masker resolves into one.
			name: "a key beginning inside the key before it",
			src:  "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789agsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
			want: []Span{{0, 54}, {51, 105}},
		},
		{
			// Two keys with nothing at all between them. The first body reads
			// three characters into the second key's prefix and stops at the
			// underscore behind them, so the spans overlap here as well.
			name: "two keys with nothing between them",
			src:  "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdgsk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD",
			want: []Span{{0, 57}, {54, 108}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := GroqAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GroqAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "gsk_",
		},
		{
			// Forty-nine characters where the pattern asks for fifty. This is
			// the shape a line cut to a column limit leaves, and the characters
			// in front of the cut stay in the text: the far side of reading a
			// floor, which builtin_groq_api_key.go weighs.
			name: "a body one character too short",
			src:  "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abc",
		},
		{
			// The hyphen and the underscore are base64url characters and no
			// base62 ones, so either ends a body where the run behind it is
			// too short to be one.
			name: "a body carrying a hyphen",
			src:  "gsk_0123456789abcdefghij-lmnopqrstuvwxyz0123456789abcd",
		},
		{
			name: "a body carrying an underscore",
			src:  "gsk_0123456789abcdefghij_lmnopqrstuvwxyz0123456789abcd",
		},
		{
			// A plus and a slash, the two characters standard base64 writes
			// that base62 does not carry at all, driven at the same middle
			// position as the hyphen and the underscore above.
			name: "a body carrying a plus",
			src:  "gsk_0123456789abcdefghij+lmnopqrstuvwxyz0123456789abcd",
		},
		{
			name: "a body carrying a slash",
			src:  "gsk_0123456789abcdefghij/lmnopqrstuvwxyz0123456789abcd",
		},
		{
			// The excluded characters above all stand in the middle of a
			// body. These three stand straight behind the prefix, with a full
			// run of the alphabet behind them — the run is still too short to
			// be a body, because it never gets to begin.
			name: "a hyphen straight behind the prefix",
			src:  "gsk_-0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
		},
		{
			name: "an underscore straight behind the prefix",
			src:  "gsk__0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
		},
		{
			name: "a dot straight behind the prefix",
			src:  "gsk_.0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
		},
		{
			name: "an uppercase prefix",
			src:  "GSK_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
		},
		{
			// The prefix is written with the underscore Groq closes it with,
			// not with the hyphen a delimiter is elsewhere.
			name: "a hyphen where the prefix carries an underscore",
			src:  "gsk-0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
		},
		{
			// The prefix closes with an underscore, so a body written straight
			// against the three letters is no body.
			name: "the prefix without its closing underscore",
			src:  "gsk0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
		},
		{
			name: "a space in the body",
			src:  "gsk_0123456789abcdefghij lmnopqrstuvwxyz0123456789abcd",
		},
		{
			name: "a dot in the body",
			src:  "gsk_0123456789abcdefghij.lmnopqrstuvwxyz0123456789abcd",
		},
		{
			name: "a body broken by a line break",
			src:  "gsk_0123456789abcdefghij\nlmnopqrstuvwxyz0123456789abcd",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// most of the anchor, so a run long enough is not a key without it.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// Forty hexadecimal characters. A digest carries no underscore, so
			// it holds no prefix to be found at however long it runs.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := GroqAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_GroqAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "GROQ_API_KEY=gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
			want: "GROQ_API_KEY=******************************************************",
		},
		{
			// The header Groq's OpenAI-compatible endpoints are called with.
			name: "a bearer authorization header",
			src:  "Authorization: Bearer gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
			want: "Authorization: Bearer ******************************************************",
		},
		{
			name: "json",
			src:  `{"apiKey":"gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd"}`,
			want: `{"apiKey":"******************************************************"}`,
		},
		{
			name: "a command line",
			src:  `curl -H "Authorization: Bearer gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd" https://api.groq.com/openai/v1/chat/completions`,
			want: `curl -H "Authorization: Bearer ******************************************************" https://api.groq.com/openai/v1/chat/completions`,
		},
		{
			// The environment block a client is configured with.
			name: "a configuration environment block",
			src:  `"env": {"GROQ_API_KEY": "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd"}`,
			want: `"env": {"GROQ_API_KEY": "******************************************************"}`,
		},
		{
			name: "twice",
			src:  "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd gsk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD",
			want: "****************************************************** ******************************************************",
		},
		{
			// The two spans are merged, so the key that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a key beginning inside the key before it",
			src:  "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789agsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
			want: "*********************************************************************************************************",
		},
	}

	m := New(WithPatterns(GroqAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GroqAPIKey_theMarkerThePublishedKeysCarry(t *testing.T) {
	// The eight characters every published key carries at the twenty-first
	// character of its body, held to deciding nothing. builtin_groq_api_key.go
	// weighs reading them and declines: no vendor source and no published rule
	// states them, and a marker read wrong locates nothing at all.
	//
	// The cases drive both sides of that, so a scan that started reading the
	// marker would fail on the second rather than pass quietly. What the first
	// shows is that carrying it changes nothing; what the second shows is the
	// key of the same shape without it, which is what declining the marker
	// buys and what reading it would leave in the output whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a key carrying the marker",
			src:  "gsk_0123456789abcdefghijWGdyb3FYklmnopqrstuvwxyz012345",
			want: "******************************************************",
		},
		{
			name: "a key of the same shape carrying no marker",
			src:  "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
			want: "******************************************************",
		},
	}

	m := New(WithPatterns(GroqAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GroqAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xgsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
			want: "x******************************************************",
		},
		{
			name: "underscore before",
			src:  "GROQ_API_KEY_gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
			want: "GROQ_API_KEY_******************************************************",
		},
		{
			// The third class of word character neither of the two above
			// is: a bare digit immediately in front of the prefix.
			name: "digit before",
			src:  "0gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
			want: "0******************************************************",
		},
	}

	m := New(WithPatterns(GroqAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GroqAPIKey_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a floor rather than a count. Where a key ends is
	// where its alphabet stops, so a letter or a digit written straight against
	// a key is redacted with it — which is what buys a key of a length neither
	// Groq nor a ruleset states being located whole. The alphabet is base62 and
	// not base64url, so the two characters that separate them, the hyphen and
	// the underscore, end a key here.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the key is gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd.",
			want: "the key is ******************************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export GROQ_API_KEY="gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd"`,
			want: `export GROQ_API_KEY="******************************************************"`,
		},
		{
			name: "a word against the key",
			src:  "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdsuffix",
			want: "************************************************************",
		},
		{
			name: "a dashed word against the key",
			src:  "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd-suffix",
			want: "******************************************************-suffix",
		},
		{
			name: "an underscored word against the key",
			src:  "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd_suffix",
			want: "******************************************************_suffix",
		},
		{
			// The two characters standard base64 adds beyond base62 also
			// end a run, exactly as the hyphen and the underscore do.
			name: "a plus against the key",
			src:  "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd+AAA",
			want: "******************************************************+AAA",
		},
		{
			// A multi-byte rune written immediately against the key.
			// Neither its UTF-8 encoding nor a byte of it belongs to the
			// alphabet a body is read in, so the run stops there exactly
			// as it does against a single-byte character.
			name: "a multi-byte rune against the key",
			src:  "日本語gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd日本語",
			want: "日本語******************************************************日本語",
		},
	}

	m := New(WithPatterns(GroqAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GroqAPIKey_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than
	// redacted. A line cut to a column limit partway through a key leaves a
	// prefix and a body too short to be one, and the random characters written
	// before the cut come through whole.
	//
	// It is the price of reading a count no Groq page states, and the cases
	// move with the scan: one of them starting to be located means the floor
	// moved, and that is a decision to be taken rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a key one character short of the floor",
			src:  "GROQ_API_KEY=gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abc",
		},
		{
			name: "a key cut off at its prefix",
			src:  "GROQ_API_KEY=gsk_",
		},
	}

	m := New(WithPatterns(GroqAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_GroqAPIKey_nameClosingOnThePrefix(t *testing.T) {
	// The over-match builtin_groq_api_key.go declines to rule out, held to the
	// answer it gives rather than to the one a reader might want. A snake_case
	// name whose segment closes on gsk carries a whole prefix, and where fifty
	// unbroken characters of the alphabet follow one, everything from the gsk
	// onward is redacted and only the syllable in front of it stays.
	//
	// The tightening that would rule this out is the demand that no letter and
	// no digit stand in front of a prefix. It is declined because it would
	// reject the key written inside another, whose prefix stands against the
	// last letter of the body in front of it — the last case below, which the
	// demand would leave in the output with its body whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a name closing on the prefix with a body behind it",
			src:  "debugsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
			want: "debu******************************************************",
		},
		{
			name: "a name closing on the prefix with a short segment behind it",
			src:  "debugsk_level=1 debugsk_host=localhost",
			want: "debugsk_level=1 debugsk_host=localhost",
		},
		{
			name: "a key written inside another, which the demand would reject",
			src:  "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789agsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
			want: "*********************************************************************************************************",
		},
	}

	m := New(WithPatterns(GroqAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GroqAPIKey_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix closes with an
	// underscore, which standard base64 writes nowhere, so only a base64url
	// encoding can hold one — and where fifty base62 characters follow,
	// everything from the prefix to the end of that run is redacted.
	//
	// The cases are held to being redacted rather than to being spared. What is
	// taken is a stretch of a value already opaque to a reader, and the run is
	// a key's format exactly: nothing is left in the text to tell the two
	// apart, so a pattern letting it through would let a real key through with
	// it. What the cases are for is that they move with the scan: one of them
	// ceasing to be located means the grammar changed, and that is a decision
	// to be taken rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "inside a base64url payload",
			src:  "payload=zzzzgsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdzzzz",
			want: "payload=zzzz**********************************************************",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the Groq
			// pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzgsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdzzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz**********************************************************",
		},
	}

	m := New(WithPatterns(GroqAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GroqAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_groq_api_key.go names, held to the answer it gives
	// rather than to the one a reader might want. Hexadecimal digits are base62
	// and a digest carries nothing that ends a run, so a digest of fifty
	// characters or more written behind the prefix is a key's format exactly
	// and is redacted. Declining it would mean declining every key Groq wrote
	// in the digits alone, which is the whole credential against a cache key.
	//
	// The two below it are where the floor and the prefix each hold: a SHA-1 is
	// ten characters short of a body and an MD5 eighteen, and a hyphen is no
	// character the prefix carries. The cases move with the scan, so a change
	// to either shows up here as a decision rather than as something the next
	// reader discovers.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sha256 behind the prefix",
			src:  "gsk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "********************************************************************",
		},
		{
			name: "a sha256 in a cache key",
			src:  "key: gsk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "key: ********************************************************************",
		},
		{
			name: "a sha1 behind the prefix, ten characters short of a body",
			src:  "gsk_0123456789abcdef0123456789abcdef01234567",
			want: "gsk_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "an md5 behind the prefix",
			src:  "gsk_0123456789abcdef0123456789abcdef",
			want: "gsk_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a sha256 behind a hyphen rather than the prefix",
			src:  "gsk-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "gsk-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	m := New(WithPatterns(GroqAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

// Test_GroqAPIKey_holdsATokenTheInputCutShort states, with a literal number,
// what the second return of Find settles: a piece of the prefix standing at
// the end of the input, a candidate the end of the input cut short before the
// floor is reached, and a whole match with nothing left unsettled behind it.
func Test_GroqAPIKey_holdsATokenTheInputCutShort(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		want   []Span
		retain int
	}{
		{
			// A piece of the prefix stands at the end of the input: it
			// could still grow into "gsk_" with one more byte, so nothing
			// behind where it opens is settled.
			name:   "a piece of the prefix at the end of the input",
			src:    "the key starts with gsk",
			retain: len("the key starts with "),
		},
		{
			// A whole prefix and a run the input cuts short before the
			// floor is met. The run also reaches the end of the input, so
			// more of it could still arrive, and what is unsettled reaches
			// back to where the candidate opened.
			name:   "a run the input cuts short of the floor",
			src:    "gsk_0123456789abcdefghij",
			retain: 0,
		},
		{
			// A whole key with more text after it, ending in a byte that
			// opens no piece of the prefix, so nothing at the end of the
			// input is left unsettled.
			name:   "a whole key followed by settled text",
			src:    "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd tail",
			want:   []Span{{0, 54}},
			retain: len("gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd tail"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := GroqAPIKey().Find(tt.src)
			if retain != tt.retain {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, retain, tt.retain)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_groqAPIKeyPrefix(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a key can
	// begin inside the one before it, and that holds only while the prefix
	// opens with characters a body may be written with. Here it is the three in
	// front of the underscore: a body closing with gsk leaves the underscore of
	// the next key standing directly behind it. A prefix opening with a
	// character outside the alphabet would make the two impossible to nest, and
	// the cases above pinning the nesting would stand for nothing — which is
	// not a failure anything else here reports.
	if groqAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	if c := groqAPIKeyPrefix[0]; !isBase62Byte(c) {
		t.Errorf("the prefix opens with %q, which no body may be written with, so no key can begin inside another", c)
	}
}

func Test_groqAPIKeyPrefix_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over
	// it, where a scan whose prefix closes on a character its own body admits
	// has to keep one. What makes the cursor unnecessary is that two candidates
	// can never read the same run: a candidate asks for the last character of
	// the prefix directly in front of its body, no body may be written with it,
	// so the run of an earlier candidate has already ended there and the later
	// candidate's run begins past it. Were that character one a body admits, a
	// run dense in prefixes would be walked once for every candidate in it and
	// the scan would cost time quadratic in the length of such a line.
	if groqAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so there is no candidate to reason about")
	}
	if c := groqAPIKeyPrefix[len(groqAPIKeyPrefix)-1]; isBase62Byte(c) {
		t.Errorf("the prefix closes with %q, which a body may be written with, so two candidates can read the same run", c)
	}
}

// Test_groqAPIKeyAnchor holds the prefix to carrying the byte the scan searches
// the input for at the index it reads a candidate back from. builtin_scan.go
// says why that is held here rather than left to the targets.
func Test_groqAPIKeyAnchor(t *testing.T) {
	if groqAPIKeyAnchorIndex >= len(groqAPIKeyPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", groqAPIKeyAnchorIndex, len(groqAPIKeyPrefix))
	}
	if c := groqAPIKeyPrefix[groqAPIKeyAnchorIndex]; c != groqAPIKeyAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(groqAPIKeyAnchor))
	}
}

func Test_GroqAPIKey_scanIsLinear(t *testing.T) {
	// A line dense in prefixes holds a candidate for every four characters it
	// has. The one thing a candidate reads that is a walk over the rest of the
	// input rather than a bounded test is where its run ends, and repeating
	// that walk at every candidate would cost time quadratic in the length of
	// the line. The bound here is far above a linear scan and far below a
	// quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every fifty-one bytes where they are densest, because a sample
	// has to carry a whole body to be one. The crowding a line can actually
	// carry, a candidate every four bytes, stays here.
	sources := map[string]string{
		// Candidates as close together as the prefix allows, none of them with
		// a run long enough to be a body: every one reaches the body of the
		// loop and every one is rejected.
		"a candidate every four characters": strings.Repeat("gsk_", 250000),
		// Keys written into one another, each beginning three characters before
		// the one in front of it ends, so every candidate is a key and every
		// one of them walks a run.
		"a key beginning inside every key": strings.Repeat("gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789a", 35000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a key.
		"a body that runs the length of the line": "gsk_" + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("a_", 900000),
		// And the prefix's own letters with no anchor among them, which is the
		// walk reading a whole line and stopping nowhere in it.
		"the letters of the prefix with no anchor": strings.Repeat("gsk", 600000),
	}

	checkScanIsLinear(t, GroqAPIKey(), sources)
}

// referenceGroqAPIKey is the expression the scan in builtin_groq_api_key.go
// reads by hand: the statement of what a Groq API key is, kept here so that the
// scan can be held to it.
//
// The prefix, the floor and the alphabet are spelled again rather than built
// from groqAPIKeyPrefix, groqAPIKeyBodyChars and isBase62Byte. A reference
// sharing those declarations could not disagree with the scan about them, and
// it is exactly that disagreement the fuzz target below is for: the two have to
// be changed together or reported apart.
//
// The floor is written as a counted repetition, which is what a reference is
// otherwise written out by hand to avoid. It costs nothing here, and for the
// reason the scan needs no cursor: candidates cannot crowd inside one run, so
// no input makes an engine walk the same run more than once.
var referenceGroqAPIKey = regexp.MustCompile(`gsk_[0-9A-Za-z]{50,}`)

// referenceGroqAPIKeyFind locates keys the plain way: the leftmost match of the
// expression above, then the leftmost one beginning after that match's first
// byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a key can begin inside one: the three letters
// the prefix opens with are written in the alphabet a body is, so a body
// closing with gsk holds the start of the key behind it. The scan finds both
// and reports the two spans overlapping for a Masker to resolve, so the
// reference must ask about both.
func referenceGroqAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceGroqAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzGroqAPIKey_matchesReference guards the hand-written scan: the prefix it
// searches for, the floor it holds a body to, the alphabet it reads that body
// in and the byte it resumes at may none of them change which keys are located.
func FuzzGroqAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("GROQ_API_KEY=gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd")
	f.Add("gsk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD")
	f.Add("gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abc")   // one short of a body
	f.Add("gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcde") // and a run longer than one
	f.Add("gsk_0123456789abcdefghij-lmnopqrstuvwxyz0123456789abcd")  // a hyphen, which base64url admits and base62 does not
	f.Add("gsk_0123456789abcdefghij_lmnopqrstuvwxyz0123456789abcd")  // an underscore, likewise
	f.Add("gsk_0123456789abcdefghij.lmnopqrstuvwxyz0123456789abcd")  // a dot ends the body
	f.Add("GSK_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd")  // an uppercase prefix
	f.Add("gsk-0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd")  // a hyphen where the prefix carries an underscore
	f.Add("gsk0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd")   // the prefix without its closing underscore
	f.Add("gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd-suffix")
	f.Add("gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd_suffix")
	f.Add("gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd\ngsk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD")
	// A key beginning inside the match before it, which a scan resuming past a
	// match steps over, and two keys with nothing between them.
	f.Add("gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789agsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd")
	f.Add("gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdgsk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD")
	// Candidate positions crowded as close as they can be, with no run long
	// enough for any of them, and keys written into one another so that every
	// candidate has one.
	f.Add(strings.Repeat("gsk_", 16))
	f.Add(strings.Repeat("gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789a", 4))
	// A digest written behind the prefix, which is a key's format exactly, and
	// the two that fall short of the floor.
	f.Add("gsk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("gsk_0123456789abcdef0123456789abcdef01234567")
	f.Add("gsk_0123456789abcdef0123456789abcdef")
	// A snake_case name whose segment closes on the three letters the prefix
	// opens with, with a body behind it and with a segment too short to be one.
	f.Add("debugsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd")
	f.Add("debugsk_level=1 debugsk_host=localhost")
	// The eight characters every published key carries inside its body, which
	// this scan reads as body and nothing more.
	f.Add("gsk_0123456789abcdefghijWGdyb3FYklmnopqrstuvwxyz012345")
	// The prefix written inside a run of base64url, which is the over-match the
	// pattern admits.
	f.Add("payload=zzzzgsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdzzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzgsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdzzzz")

	fuzzAgainstReference(f, GroqAPIKey().Find, referenceGroqAPIKeyFind)
}

// groqAPIKeyFindBenchmarks is what this scan is timed on. The builtinPatterns
// entry for the pattern names it, and BenchmarkBuiltins times every case it
// holds under the pattern's own name, so that a built-in cannot arrive without
// a benchmark. Every case is held to the count it states under a plain go test
// as well, which is what a benchmark nobody has run yet cannot be.
func groqAPIKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="completion finished" tokens=512 url=https://api.groq.com/openai/v1/chat/completions `
	key := "gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every four characters with no run long enough behind
			// any of them: each reaches the body of the loop and none becomes a
			// key. What it times is the walk over a run being started and
			// stopped, once per candidate and no more.
			name:  "candidates that are not values",
			src:   strings.Repeat("gsk_", 128),
			spans: 0,
		},
		{
			// Keys written into one another, each beginning three characters
			// before the one in front of it ends. This is what the scan gets
			// away with keeping no cursor for: the runs the candidates read
			// follow one another rather than overlapping. The three characters
			// at the end are what closes the body of the last of them, which
			// otherwise has only the run it was written with.
			name:  "keys written into one another",
			src:   strings.Repeat("gsk_0123456789abcdefghijklmnopqrstuvwxyz0123456789a", 128) + "gsk",
			spans: 128,
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
