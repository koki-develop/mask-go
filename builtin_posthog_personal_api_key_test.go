package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The PostHog personal API key pattern: what it locates and what it leaves
// alone, written out case by case, and the reference its scan is held to.
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
// carries it and five characters more — the shortest body the scan reads, since
// the count is a floor, so a body shortened for readability would leave a case
// holding no key at all. It is written in lowercase where the case does not
// matter and in uppercase where the case is what a case is about: base62 holds
// the letters of both, so either spelling is a body.

func Test_PostHogPersonalAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "phx_0123456789abcdefghijklmnopqrstuvwxyz01234",
			want: []Span{{0, 45}},
		},
		{
			name: "a key in an environment assignment",
			src:  "POSTHOG_PERSONAL_API_KEY=phx_0123456789abcdefghijklmnopqrstuvwxyz01234",
			want: []Span{{25, 70}},
		},
		{
			// base62 holds the letters of both cases, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "phx_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
			want: []Span{{0, 45}},
		},
		{
			// The count is a floor and the span reaches the end of the run, so
			// a run longer than the shortest body is a key to the end of it
			// rather than a key and a character left over. This is the length a
			// key minted today is written at.
			name: "a run of the length a key is minted at today",
			src:  "phx_0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
			want: []Span{{0, 52}},
		},
		{
			name: "two keys separated by a space",
			src:  "phx_0123456789abcdefghijklmnopqrstuvwxyz01234 phx_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
			want: []Span{{0, 45}, {46, 91}},
		},
		{
			// The three letters the prefix opens with belong to the alphabet a
			// body is written in, so a body may close with phx and the
			// underscore of the next key stand directly behind it. The second
			// key begins three characters before the first one ends, and a scan
			// resuming past a match would step over it. The spans overlap,
			// which a Masker resolves into one.
			name: "a key beginning inside the key before it",
			src:  "phx_0123456789abcdefghijklmnopqrstuvwxyz01phx_0123456789abcdefghijklmnopqrstuvwxyz01234",
			want: []Span{{0, 45}, {42, 87}},
		},
		{
			// Two keys with nothing at all between them. The first body reads
			// three characters into the second key's prefix and stops at the
			// underscore behind them, so the spans overlap here as well.
			name: "two keys with nothing between them",
			src:  "phx_0123456789abcdefghijklmnopqrstuvwxyz01234phx_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
			want: []Span{{0, 48}, {45, 90}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PostHogPersonalAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PostHogPersonalAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "phx_",
		},
		{
			// Forty characters where the pattern asks for forty-one. This is
			// the shape a line cut to a column limit leaves, and the characters
			// in front of the cut stay in the text: the far side of reading a
			// floor, which builtin_posthog_personal_api_key.go weighs.
			name: "a body one character too short",
			src:  "phx_0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			// The hyphen and the underscore are base64url characters and no
			// base62 ones, so either ends a body where the run behind it is
			// too short to be one.
			name: "a body carrying a hyphen",
			src:  "phx_0123456789abcdefghij-lmnopqrstuvwxyz01234",
		},
		{
			name: "a body carrying an underscore",
			src:  "phx_0123456789abcdefghij_lmnopqrstuvwxyz01234",
		},
		{
			name: "an uppercase prefix",
			src:  "PHX_0123456789abcdefghijklmnopqrstuvwxyz01234",
		},
		{
			// The prefix is written with the underscore PostHog closes it with,
			// not with the hyphen a delimiter is elsewhere.
			name: "a hyphen where the prefix carries an underscore",
			src:  "phx-0123456789abcdefghijklmnopqrstuvwxyz01234",
		},
		{
			// The prefix closes with an underscore, so a body written straight
			// against the three letters is no body.
			name: "the prefix without its closing underscore",
			src:  "phx0123456789abcdefghijklmnopqrstuvwxyz01234",
		},
		{
			name: "a space in the body",
			src:  "phx_0123456789abcdefghij lmnopqrstuvwxyz01234",
		},
		{
			name: "a dot in the body",
			src:  "phx_0123456789abcdefghij.lmnopqrstuvwxyz01234",
		},
		{
			name: "a body broken by a line break",
			src:  "phx_0123456789abcdefghij\nlmnopqrstuvwxyz01234",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// most of the anchor, so a run long enough is not a key without it.
			// It is also the shape of the keys PostHog issued before it wrote a
			// prefix on any of them, which this pattern cannot locate.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdefghijklmnopqrstuvwxyz01234",
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
		{
			// An invalid UTF-8 byte inside the run. It belongs to no encoding
			// at all, so it ends the run exactly where a space or a dot does.
			name: "an invalid byte in the run",
			src:  "phx_0123456789abcdefghijklmnopqrstuvwxyz\xff1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PostHogPersonalAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PostHogPersonalAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "POSTHOG_PERSONAL_API_KEY=phx_0123456789abcdefghijklmnopqrstuvwxyz01234",
			want: "POSTHOG_PERSONAL_API_KEY=*********************************************",
		},
		{
			// The header PostHog's private endpoints are called with.
			name: "a bearer authorization header",
			src:  "Authorization: Bearer phx_0123456789abcdefghijklmnopqrstuvwxyz01234",
			want: "Authorization: Bearer *********************************************",
		},
		{
			name: "json",
			src:  `{"personal_api_key":"phx_0123456789abcdefghijklmnopqrstuvwxyz01234"}`,
			want: `{"personal_api_key":"*********************************************"}`,
		},
		{
			name: "a command line",
			src:  `curl -H "Authorization: Bearer phx_0123456789abcdefghijklmnopqrstuvwxyz01234" https://us.i.posthog.com/api/projects/1/query/`,
			want: `curl -H "Authorization: Bearer *********************************************" https://us.i.posthog.com/api/projects/1/query/`,
		},
		{
			name: "a configuration environment block",
			src:  `"env": {"POSTHOG_PERSONAL_API_KEY": "phx_0123456789abcdefghijklmnopqrstuvwxyz01234"}`,
			want: `"env": {"POSTHOG_PERSONAL_API_KEY": "*********************************************"}`,
		},
		{
			name: "twice",
			src:  "phx_0123456789abcdefghijklmnopqrstuvwxyz01234 phx_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
			want: "********************************************* *********************************************",
		},
		{
			// The two spans are merged, so the key that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a key beginning inside the key before it",
			src:  "phx_0123456789abcdefghijklmnopqrstuvwxyz01phx_0123456789abcdefghijklmnopqrstuvwxyz01234",
			want: "***************************************************************************************",
		},
	}

	m := New(WithPatterns(PostHogPersonalAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PostHogPersonalAPIKey_theSiblingPrefixes(t *testing.T) {
	// The four other prefixes PostHog writes with the same two letters, held to
	// being left alone. Each is a credential of its own and none of them is
	// this one: the project API token is published by design, and the rest are
	// values PostHog gives other names to.
	//
	// What separates them from a key here is the single character behind the
	// ph, so the cases are the whole boundary the pattern draws. One of them
	// starting to be located means the prefix widened, and that is a decision to
	// be taken rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a project api token",
			src:  "phc_0123456789abcdefghijklmnopqrstuvwxyz01234",
		},
		{
			name: "a project secret api key",
			src:  "phs_0123456789abcdefghijklmnopqrstuvwxyz01234",
		},
		{
			name: "an oauth access token",
			src:  "pha_0123456789abcdefghijklmnopqrstuvwxyz01234",
		},
		{
			name: "an oauth refresh token",
			src:  "phr_0123456789abcdefghijklmnopqrstuvwxyz01234",
		},
	}

	m := New(WithPatterns(PostHogPersonalAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_PostHogPersonalAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xphx_0123456789abcdefghijklmnopqrstuvwxyz01234",
			want: "x*********************************************",
		},
		{
			name: "underscore before",
			src:  "POSTHOG_PERSONAL_API_KEY_phx_0123456789abcdefghijklmnopqrstuvwxyz01234",
			want: "POSTHOG_PERSONAL_API_KEY_*********************************************",
		},
		{
			name: "digit before",
			src:  "0phx_0123456789abcdefghijklmnopqrstuvwxyz01234",
			want: "0*********************************************",
		},
		{
			// The byte that ends a run standing immediately in front of the
			// prefix rather than only behind a whole word.
			name: "hyphen before",
			src:  "key-phx_0123456789abcdefghijklmnopqrstuvwxyz01234",
			want: "key-*********************************************",
		},
		{
			name: "a multi-byte rune before",
			src:  "日本語phx_0123456789abcdefghijklmnopqrstuvwxyz01234",
			want: "日本語*********************************************",
		},
	}

	m := New(WithPatterns(PostHogPersonalAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PostHogPersonalAPIKey_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a floor rather than a count. Where a key ends is
	// where its alphabet stops, so a letter or a digit written straight against
	// a key is redacted with it — which is what buys a key of a length PostHog
	// has not minted yet being located whole. The alphabet is base62 and not
	// base64url, so the two characters that separate them, the hyphen and the
	// underscore, end a key here.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the key is phx_0123456789abcdefghijklmnopqrstuvwxyz01234.",
			want: "the key is *********************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export POSTHOG_PERSONAL_API_KEY="phx_0123456789abcdefghijklmnopqrstuvwxyz01234"`,
			want: `export POSTHOG_PERSONAL_API_KEY="*********************************************"`,
		},
		{
			name: "a word against the key",
			src:  "phx_0123456789abcdefghijklmnopqrstuvwxyz01234suffix",
			want: "***************************************************",
		},
		{
			name: "a dashed word against the key",
			src:  "phx_0123456789abcdefghijklmnopqrstuvwxyz01234-suffix",
			want: "*********************************************-suffix",
		},
		{
			name: "an underscored word against the key",
			src:  "phx_0123456789abcdefghijklmnopqrstuvwxyz01234_suffix",
			want: "*********************************************_suffix",
		},
		{
			// A multi-byte rune stands outside base62 either way, so it ends
			// the run exactly where an ordinary word boundary does and
			// nothing of it is drawn into the redaction.
			name: "a multi-byte rune after the key",
			src:  "phx_0123456789abcdefghijklmnopqrstuvwxyz01234日本語",
			want: "*********************************************日本語",
		},
	}

	m := New(WithPatterns(PostHogPersonalAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PostHogPersonalAPIKey_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than
	// redacted. A line cut to a column limit partway through a key leaves a
	// prefix and a body too short to be one, and the random characters written
	// before the cut come through whole.
	//
	// It is the price of a floor set below the shortest body PostHog has
	// minted, and the cases move with the scan: one of them starting to be
	// located means the floor moved, and that is a decision to be taken rather
	// than noticed afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a key one character short of the floor",
			src:  "POSTHOG_PERSONAL_API_KEY=phx_0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "a key cut off at its prefix",
			src:  "POSTHOG_PERSONAL_API_KEY=phx_",
		},
		{
			// A run at exactly the floor's boundary, ended by a hyphen with
			// more text carrying on behind it — the floor and the alphabet
			// boundary reached together rather than one at a time.
			name: "a run of forty ended by a hyphen",
			src:  "phx_0123456789abcdefghijklmnopqrstuvwxyz0123-suffix",
		},
		{
			name: "a run of forty ended by an underscore",
			src:  "phx_0123456789abcdefghijklmnopqrstuvwxyz0123_suffix",
		},
	}

	m := New(WithPatterns(PostHogPersonalAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_PostHogPersonalAPIKey_theAlphabetIsWiderThanTodaysKeys(t *testing.T) {
	// The alphabet, held to the wider of the two PostHog has written a body in.
	// A key minted today is base57 — base62 with the five characters a reader
	// confuses, 0, 1, O, I and l, taken out of it — and every key minted before
	// that is base62, so a scan reading the narrower alphabet would turn away an
	// older key wherever one of the five stands in its body, which is nearly all
	// of them. The case below is what such a narrowing would lose.
	//
	// There is no case for a body written without the five, because base57 is
	// base62 with characters taken away rather than an alphabet of its own —
	// such a body is read by the same character test as any other, and a case
	// for it would hold nothing the cases above do not already hold.
	src := "phx_0123456789abcdefghijklmnopqrstuvwxyz01OIl"
	want := "*********************************************"

	m := New(WithPatterns(PostHogPersonalAPIKey()))
	if got := m.Mask(src); got != want {
		t.Errorf("Mask(%q) = %q, want %q", src, got, want)
	}
}

func Test_PostHogPersonalAPIKey_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix closes with an
	// underscore, which standard base64 writes nowhere, so only a base64url
	// encoding can hold one — and where forty-one base62 characters follow,
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
			src:  "payload=zzzzphx_0123456789abcdefghijklmnopqrstuvwxyz01234zzzz",
			want: "payload=zzzz*************************************************",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the
			// PostHog pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzphx_0123456789abcdefghijklmnopqrstuvwxyz01234zzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz*************************************************",
		},
	}

	m := New(WithPatterns(PostHogPersonalAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PostHogPersonalAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_posthog_personal_api_key.go names, held to the
	// answer it gives rather than to the one a reader might want. Hexadecimal
	// digits are base62 and a digest carries nothing that ends a run, so a
	// digest of forty-one characters or more written behind the prefix is a
	// key's format exactly and is redacted. Declining it would mean declining
	// every key PostHog wrote in the digits alone, which is a whole credential
	// against a cache key.
	//
	// The two below it are where the floor and the prefix each hold: a git SHA
	// is one character short of a body and an MD5 nine, and a hyphen is no
	// character the prefix carries. The cases move with the scan, so a change to
	// either shows up here as a decision rather than as something the next
	// reader discovers.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sha256 behind the prefix",
			src:  "phx_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "********************************************************************",
		},
		{
			name: "a sha256 in a cache key",
			src:  "key: phx_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "key: ********************************************************************",
		},
		{
			name: "a git sha behind the prefix, one character short of a body",
			src:  "phx_0123456789abcdef0123456789abcdef01234567",
			want: "phx_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "an md5 behind the prefix",
			src:  "phx_0123456789abcdef0123456789abcdef",
			want: "phx_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a sha256 behind a hyphen rather than the prefix",
			src:  "phx-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "phx-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	m := New(WithPatterns(PostHogPersonalAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PostHogPersonalAPIKey_settlesNothingAboutAnOpenRun(t *testing.T) {
	// A key standing at the very end of the input closes no run: more text
	// could still carry it on, so the scan holds the candidate open from its
	// own start rather than reporting the input settled up to the span it
	// already found.
	src := "phx_0123456789abcdefghijklmnopqrstuvwxyz01234"

	spans, retain := PostHogPersonalAPIKey().Find(src)
	if want := []Span{{0, 45}}; !slices.Equal(spans, want) {
		t.Errorf("Find(%q) = %v, want %v", src, spans, want)
	}
	if retain != 0 {
		t.Errorf("Find(%q) settled from %d, want 0", src, retain)
	}
}

func Test_PostHogPersonalAPIKey_settlesOnceTheRunCloses(t *testing.T) {
	// The other side of the same decision. A period does not belong to the
	// alphabet a body is written in, so it closes the run behind the key: no
	// text arriving after it can widen what was already found, and the whole
	// of the input is settled.
	src := "the key is phx_0123456789abcdefghijklmnopqrstuvwxyz01234."

	spans, retain := PostHogPersonalAPIKey().Find(src)
	if want := []Span{{11, 56}}; !slices.Equal(spans, want) {
		t.Errorf("Find(%q) = %v, want %v", src, spans, want)
	}
	if retain != len(src) {
		t.Errorf("Find(%q) settled %d of %d, want the whole of it", src, retain, len(src))
	}
}

func Test_postHogPersonalAPIKeyPrefix(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a key can
	// begin inside the one before it, and that holds only while the prefix
	// opens with characters a body may be written with. Here it is the three in
	// front of the underscore: a body closing with phx leaves the underscore of
	// the next key standing directly behind it. A prefix opening with a
	// character outside the alphabet would make the two impossible to nest, and
	// the cases above pinning the nesting would stand for nothing — which is
	// not a failure anything else here reports.
	if postHogPersonalAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	if c := postHogPersonalAPIKeyPrefix[0]; !isBase62Byte(c) {
		t.Errorf("the prefix opens with %q, which no body may be written with, so no key can begin inside another", c)
	}
}

func Test_postHogPersonalAPIKeyPrefix_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over
	// it, where a scan whose prefix closes on a character its own body admits
	// has to keep one. What makes the cursor unnecessary is that two candidates
	// can never read the same run: a candidate asks for the last character of
	// the prefix directly in front of its body, no body may be written with it,
	// so the run of an earlier candidate has already ended there and the later
	// candidate's run begins past it. Were that character one a body admits, a
	// run dense in prefixes would be walked once for every candidate in it and
	// the scan would cost time quadratic in the length of such a line.
	if postHogPersonalAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so there is no candidate to reason about")
	}
	if c := postHogPersonalAPIKeyPrefix[len(postHogPersonalAPIKeyPrefix)-1]; isBase62Byte(c) {
		t.Errorf("the prefix closes with %q, which a body may be written with, so two candidates can read the same run", c)
	}
}

// Test_postHogPersonalAPIKeyAnchor holds the prefix to carrying the byte the
// scan searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_postHogPersonalAPIKeyAnchor(t *testing.T) {
	if postHogPersonalAPIKeyAnchorIndex >= len(postHogPersonalAPIKeyPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", postHogPersonalAPIKeyAnchorIndex, len(postHogPersonalAPIKeyPrefix))
	}
	if c := postHogPersonalAPIKeyPrefix[postHogPersonalAPIKeyAnchorIndex]; c != postHogPersonalAPIKeyAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(postHogPersonalAPIKeyAnchor))
	}
}

func Test_PostHogPersonalAPIKey_scanIsLinear(t *testing.T) {
	// A line dense in prefixes holds a candidate for every four characters it
	// has. The one thing a candidate reads that is a walk over the rest of the
	// input rather than a bounded test is where its run ends, and repeating
	// that walk at every candidate would cost time quadratic in the length of
	// the line. The bound here is far above a linear scan and far below a
	// quadratic one.
	//
	// The generic guard in builtins_test.go repeats every sample and every
	// sample cut in half, and the shortest unit that leaves is twenty-two bytes,
	// so it crowds candidates no closer than one every twenty-two. The crowding
	// a line can actually carry, a candidate every four bytes, stays here.
	sources := map[string]string{
		// Candidates as close together as the prefix allows, none of them with
		// a run long enough to be a body: every one reaches the body of the
		// loop and every one is rejected.
		"a candidate every four characters": strings.Repeat("phx_", 250000),
		// Keys written into one another, each beginning three characters before
		// the one in front of it ends, so every candidate is a key and every
		// one of them walks a run.
		"a key beginning inside every key": strings.Repeat("phx_0123456789abcdefghijklmnopqrstuvwxyz01", 40000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a key.
		"a body that runs the length of the line": "phx_" + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("a_", 900000),
		// The sibling prefixes, which carry the anchor and the byte the scan
		// tests in front of it, so each is declined by the comparison of the
		// whole prefix — the most a position costs before any run is walked.
		"a sibling prefix every four characters": strings.Repeat("phc_", 250000),
		// And the prefix's own letters with no anchor among them, which is the
		// walk reading a whole line and stopping nowhere in it.
		"the letters of the prefix with no anchor": strings.Repeat("phx", 600000),
	}

	checkScanIsLinear(t, PostHogPersonalAPIKey(), sources)
}

// referencePostHogPersonalAPIKey is the expression the scan in
// builtin_posthog_personal_api_key.go reads by hand: the statement of what a
// PostHog personal API key is, kept here so that the scan can be held to it.
//
// The prefix, the floor and the alphabet are spelled again rather than built
// from postHogPersonalAPIKeyPrefix, postHogPersonalAPIKeyBodyChars and
// isBase62Byte. A reference sharing those declarations could not disagree with
// the scan about them, and it is exactly that disagreement the fuzz target
// below is for: the two have to be changed together or reported apart.
//
// The floor is written as a counted repetition, which is what a reference is
// otherwise written out by hand to avoid. It costs nothing here, and for the
// reason the scan needs no cursor: candidates cannot crowd inside one run, so
// no input makes an engine walk the same run more than once.
var referencePostHogPersonalAPIKey = regexp.MustCompile(`phx_[0-9A-Za-z]{41,}`)

// referencePostHogPersonalAPIKeyFind locates keys the plain way: the leftmost
// match of the expression above, then the leftmost one beginning after that
// match's first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a key can begin inside one: the three letters
// the prefix opens with are written in the alphabet a body is, so a body
// closing with phx holds the start of the key behind it. The scan finds both
// and reports the two spans overlapping for a Masker to resolve, so the
// reference must ask about both.
func referencePostHogPersonalAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referencePostHogPersonalAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzPostHogPersonalAPIKey_matchesReference guards the hand-written scan: the
// prefix it searches for, the floor it holds a body to, the alphabet it reads
// that body in and the byte it resumes at may none of them change which keys
// are located.
func FuzzPostHogPersonalAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("POSTHOG_PERSONAL_API_KEY=phx_0123456789abcdefghijklmnopqrstuvwxyz01234")
	f.Add("phx_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01234")
	f.Add("phx_0123456789abcdefghijklmnopqrstuvwxyz0123")         // one short of a body
	f.Add("phx_0123456789abcdefghijklmnopqrstuvwxyz0123456789ab") // the length a key is minted at today
	f.Add("phx_0123456789abcdefghij-lmnopqrstuvwxyz01234")        // a hyphen, which base64url admits and base62 does not
	f.Add("phx_0123456789abcdefghij_lmnopqrstuvwxyz01234")        // an underscore, likewise
	f.Add("phx_0123456789abcdefghij.lmnopqrstuvwxyz01234")        // a dot ends the body
	f.Add("PHX_0123456789abcdefghijklmnopqrstuvwxyz01234")        // an uppercase prefix
	f.Add("phx-0123456789abcdefghijklmnopqrstuvwxyz01234")        // a hyphen where the prefix carries an underscore
	f.Add("phx0123456789abcdefghijklmnopqrstuvwxyz01234")         // the prefix without its closing underscore
	f.Add("phx_0123456789abcdefghijklmnopqrstuvwxyz0123-suffix")  // a run of forty ended by a hyphen, with text carrying on
	f.Add("phx_0123456789abcdefghijklmnopqrstuvwxyz0123_suffix")  // and by an underscore
	f.Add("0phx_0123456789abcdefghijklmnopqrstuvwxyz01234")       // a digit before the prefix
	f.Add("key-phx_0123456789abcdefghijklmnopqrstuvwxyz01234")    // a hyphen before the prefix
	f.Add("日本語phx_0123456789abcdefghijklmnopqrstuvwxyz01234")     // a multi-byte rune before the key
	f.Add("phx_0123456789abcdefghijklmnopqrstuvwxyz01234日本語")     // and after it
	f.Add("phx_0123456789abcdefghijklmnopqrstuvwxyz\xff1234")     // an invalid byte in the run
	f.Add("phx_0123456789abcdefghijklmnopqrstuvwxyz01234-suffix")
	f.Add("phx_0123456789abcdefghijklmnopqrstuvwxyz01234_suffix")
	f.Add("phx_0123456789abcdefghijklmnopqrstuvwxyz01234\nphx_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01234")
	// A key beginning inside the match before it, which a scan resuming past a
	// match steps over, and two keys with nothing between them.
	f.Add("phx_0123456789abcdefghijklmnopqrstuvwxyz01phx_0123456789abcdefghijklmnopqrstuvwxyz01234")
	f.Add("phx_0123456789abcdefghijklmnopqrstuvwxyz01234phx_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01234")
	// Candidate positions crowded as close as they can be, with no run long
	// enough for any of them, and keys written into one another so that every
	// candidate has one.
	f.Add(strings.Repeat("phx_", 16))
	f.Add(strings.Repeat("phx_0123456789abcdefghijklmnopqrstuvwxyz01", 4))
	// The four sibling prefixes, which carry the anchor and the byte tested in
	// front of it and are none of them this credential.
	f.Add("phc_0123456789abcdefghijklmnopqrstuvwxyz01234")
	f.Add("phs_0123456789abcdefghijklmnopqrstuvwxyz01234")
	f.Add("pha_0123456789abcdefghijklmnopqrstuvwxyz01234")
	f.Add("phr_0123456789abcdefghijklmnopqrstuvwxyz01234")
	// A body carrying the five characters base57 leaves out, which is what a key
	// minted before base57 may hold and a narrower alphabet would turn away.
	f.Add("phx_0123456789abcdefghijklmnopqrstuvwxyz01OIl")
	// A digest written behind the prefix, which is a key's format exactly, and
	// the two that fall short of the floor.
	f.Add("phx_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("phx_0123456789abcdef0123456789abcdef01234567")
	f.Add("phx_0123456789abcdef0123456789abcdef")
	// The prefix written inside a run of base64url, which is the over-match the
	// pattern admits.
	f.Add("payload=zzzzphx_0123456789abcdefghijklmnopqrstuvwxyz01234zzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzphx_0123456789abcdefghijklmnopqrstuvwxyz01234zzzz")

	fuzzAgainstReference(f, PostHogPersonalAPIKey().Find, referencePostHogPersonalAPIKeyFind)
}

// postHogPersonalAPIKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func postHogPersonalAPIKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no key. It is also the line the choice of anchor is
	// argued on: the p stands six times and the h twice, where neither the x
	// nor the underscore stands at all.
	line := `time=2026-08-17T00:00:00Z level=info msg="capture accepted" events=512 url=https://us.i.posthog.com/api/projects/1/query/ `
	key := "phx_0123456789abcdefghijklmnopqrstuvwxyz01234"

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
			src:   strings.Repeat("phx_", 128),
			spans: 0,
		},
		{
			// The sibling prefixes as close together as they go. Each carries
			// the anchor and the byte tested in front of it, so each is declined
			// by the comparison of the whole prefix, which is what the choice of
			// anchor pays for. It is the case above that costs more: a candidate
			// opening a whole prefix goes on to walk a run.
			name:  "sibling prefixes",
			src:   strings.Repeat("phc_", 128),
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
			src:   strings.Repeat("phx_0123456789abcdefghijklmnopqrstuvwxyz01", 128) + "phx",
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
