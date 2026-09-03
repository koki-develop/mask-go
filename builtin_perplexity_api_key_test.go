package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Perplexity API key pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. The run they are built from,
// 0123456789abcdefghijklmnopqrstuvwxyz, is thirty-six characters, so a body
// carries it and twelve characters more — the shortest body the scan reads,
// since the count is a floor, so a body shortened for readability would leave a
// case holding no key at all. It is written in lowercase where the case does
// not matter and in uppercase where the case is what a case is about: base62
// holds the letters of both, so either spelling is a body.

func Test_PerplexityAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
			want: []Span{{0, 53}},
		},
		{
			name: "a key in an environment assignment",
			src:  "PERPLEXITY_API_KEY=pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
			want: []Span{{19, 72}},
		},
		{
			// base62 holds the letters of both cases, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "pplx-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AB",
			want: []Span{{0, 53}},
		},
		{
			// The count is a floor and the span reaches the end of the run, so
			// a run longer than the shortest body is a key to the end of it
			// rather than a key and a character left over.
			name: "a run longer than the shortest body",
			src:  "pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789abc",
			want: []Span{{0, 54}},
		},
		{
			name: "two keys separated by a space",
			src:  "pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab pplx-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AB",
			want: []Span{{0, 53}, {54, 107}},
		},
		{
			// The four letters the prefix opens with belong to the alphabet a
			// body is written in, so a body may close with pplx and the hyphen
			// of the next key stand directly behind it. The second key begins
			// four characters before the first one ends, and a scan resuming
			// past a match would step over it. The spans overlap, which a
			// Masker resolves into one.
			name: "a key beginning inside the key before it",
			src:  "pplx-0123456789abcdefghijklmnopqrstuvwxyz01234567pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
			want: []Span{{0, 53}, {49, 102}},
		},
		{
			// Two keys with nothing at all between them. The first body reads
			// four characters into the second key's prefix and stops at the
			// hyphen behind them, so the spans overlap here as well.
			name: "two keys with nothing between them",
			src:  "pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789abpplx-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AB",
			want: []Span{{0, 57}, {53, 106}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PerplexityAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PerplexityAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "pplx-",
		},
		{
			// Forty-seven characters where the pattern asks for forty-eight.
			// This is the shape a line cut to a column limit leaves, and the
			// characters in front of the cut stay in the text: the far side of
			// reading a floor, which builtin_perplexity_api_key.go weighs.
			name: "a body one character too short",
			src:  "pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789a",
		},
		{
			// The hyphen and the underscore are base64url characters and no
			// base62 ones, so either ends a body where the run behind it is
			// too short to be one.
			name: "a body carrying a hyphen",
			src:  "pplx-0123456789abcdefghij-lmnopqrstuvwxyz0123456789ab",
		},
		{
			name: "a body carrying an underscore",
			src:  "pplx-0123456789abcdefghij_lmnopqrstuvwxyz0123456789ab",
		},
		{
			name: "an uppercase prefix",
			src:  "PPLX-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
		},
		{
			// The four letters capitalised the way Perplexity's own MCP server
			// writes them in a header name of its own.
			name: "the prefix capitalised as a header name writes it",
			src:  "Pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
		},
		{
			// The prefix is written with the hyphen Perplexity closes it with,
			// not with the underscore a delimiter is elsewhere.
			name: "an underscore where the prefix carries a hyphen",
			src:  "pplx_0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
		},
		{
			// The prefix closes with a hyphen, so a body written straight
			// against the four letters is no body.
			name: "the prefix without its closing hyphen",
			src:  "pplx0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
		},
		{
			name: "a space in the body",
			src:  "pplx-0123456789abcdefghij lmnopqrstuvwxyz0123456789ab",
		},
		{
			name: "a dot in the body",
			src:  "pplx-0123456789abcdefghij.lmnopqrstuvwxyz0123456789ab",
		},
		{
			name: "a body broken by a line break",
			src:  "pplx-0123456789abcdefghij\nlmnopqrstuvwxyz0123456789ab",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// most of the anchor, so a run long enough is not a key without it.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// Forty hexadecimal characters. A digest carries no hyphen, so it
			// holds no prefix to be found at however long it runs.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PerplexityAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PerplexityAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "PERPLEXITY_API_KEY=pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
			want: "PERPLEXITY_API_KEY=*****************************************************",
		},
		{
			// The header the Sonar API is called with.
			name: "a bearer authorization header",
			src:  "Authorization: Bearer pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
			want: "Authorization: Bearer *****************************************************",
		},
		{
			// The field the endpoint that issues a key hands it back in.
			name: "the json a generated key is returned in",
			src:  `{"auth_token":"pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab","token_name":"Production API Key"}`,
			want: `{"auth_token":"*****************************************************","token_name":"Production API Key"}`,
		},
		{
			name: "a command line",
			src:  `curl -H "Authorization: Bearer pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab" https://api.perplexity.ai/chat/completions`,
			want: `curl -H "Authorization: Bearer *****************************************************" https://api.perplexity.ai/chat/completions`,
		},
		{
			// The environment block the MCP server is configured with.
			name: "a configuration environment block",
			src:  `"env": {"PERPLEXITY_API_KEY": "pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab"}`,
			want: `"env": {"PERPLEXITY_API_KEY": "*****************************************************"}`,
		},
		{
			name: "twice",
			src:  "pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab pplx-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AB",
			want: "***************************************************** *****************************************************",
		},
		{
			// The two spans are merged, so the key that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a key beginning inside the key before it",
			src:  "pplx-0123456789abcdefghijklmnopqrstuvwxyz01234567pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
			want: "******************************************************************************************************",
		},
	}

	m := New(WithPatterns(PerplexityAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PerplexityAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xpplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
			want: "x*****************************************************",
		},
		{
			name: "underscore before",
			src:  "PERPLEXITY_API_KEY_pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
			want: "PERPLEXITY_API_KEY_*****************************************************",
		},
	}

	m := New(WithPatterns(PerplexityAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PerplexityAPIKey_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a floor rather than a count. Where a key ends is
	// where its alphabet stops, so a letter or a digit written straight against
	// a key is redacted with it — which is what buys a key of a length neither
	// Perplexity nor a published rule states being located whole. The alphabet
	// is base62 and not base64url, so the two characters that separate them,
	// the hyphen and the underscore, end a key here.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the key is pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab.",
			want: "the key is *****************************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export PERPLEXITY_API_KEY="pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab"`,
			want: `export PERPLEXITY_API_KEY="*****************************************************"`,
		},
		{
			name: "a word against the key",
			src:  "pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789absuffix",
			want: "***********************************************************",
		},
		{
			name: "a dashed word against the key",
			src:  "pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab-suffix",
			want: "*****************************************************-suffix",
		},
		{
			name: "an underscored word against the key",
			src:  "pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab_suffix",
			want: "*****************************************************_suffix",
		},
	}

	m := New(WithPatterns(PerplexityAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PerplexityAPIKey_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than
	// redacted. A line cut to a column limit partway through a key leaves a
	// prefix and a body too short to be one, and the random characters written
	// before the cut come through whole.
	//
	// It is the price of reading a count no Perplexity page states, and the
	// cases move with the scan: one of them starting to be located means the
	// floor moved, and that is a decision to be taken rather than noticed
	// afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a key one character short of the floor",
			src:  "PERPLEXITY_API_KEY=pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789a",
		},
		{
			name: "a key cut off at its prefix",
			src:  "PERPLEXITY_API_KEY=pplx-",
		},
	}

	m := New(WithPatterns(PerplexityAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_PerplexityAPIKey_noEntropyFloor(t *testing.T) {
	// The entropy floor both published rules carry, held to deciding nothing.
	// builtin_perplexity_api_key.go weighs reading one and declines: this
	// library redacts rather than reports, so a value declined is a credential
	// written out in full, and nothing about the format says a key of
	// repetitive characters cannot be issued.
	//
	// The body of one repeated letter is the case, since it is the one shape
	// the ordered run the keys here are otherwise built from cannot state: that
	// run carries more entropy than either rule asks for, so a scan that
	// started reading one would go on locating those keys and only this case
	// would report it.
	src := "pplx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	want := "*****************************************************"

	m := New(WithPatterns(PerplexityAPIKey()))
	if got := m.Mask(src); got != want {
		t.Errorf("Mask(%q) = %q, want %q", src, got, want)
	}
}

func Test_PerplexityAPIKey_theVendorsOwnNames(t *testing.T) {
	// Perplexity names its own products with the prefix it issues keys under,
	// so the text most likely to be written near a key carries a whole prefix.
	// Every name below but the last is located nowhere, and what turns each of
	// them away is the floor: the segment behind the prefix is broken by a
	// character no body admits long before forty-eight of them have stood.
	//
	// The last case is what that leaves admitted, and it is stated rather than
	// hidden: a name whose segment does run forty-eight unbroken characters of
	// the alphabet is a key's format exactly, and nothing is left in the text
	// to tell the two apart.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "the name the api was announced under",
			src:  "using pplx-api for search",
			want: "using pplx-api for search",
		},
		{
			name: "the embedding model names",
			src:  `{"model":"pplx-embed-v1-0"} {"model":"pplx-embed-context-v1-0"}`,
			want: `{"model":"pplx-embed-v1-0"} {"model":"pplx-embed-context-v1-0"}`,
		},
		{
			name: "the command line and the file it ships as",
			src:  "pplx-cli installs pplx-aarch64-apple-darwin.bin",
			want: "pplx-cli installs pplx-aarch64-apple-darwin.bin",
		},
		{
			name: "the name the mcp server sends as its source",
			src:  `"X-Source": "pplx-mcp-server"`,
			want: `"X-Source": "pplx-mcp-server"`,
		},
		{
			name: "the name the search sdk sends as its own",
			src:  `"User-Agent": "pplx-srch-sdk-python/1.0.0"`,
			want: `"User-Agent": "pplx-srch-sdk-python/1.0.0"`,
		},
		{
			name: "a name whose segment runs the length of a body",
			src:  `{"model":"pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab"}`,
			want: `{"model":"*****************************************************"}`,
		},
	}

	m := New(WithPatterns(PerplexityAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PerplexityAPIKey_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix closes with a
	// hyphen, which standard base64 writes nowhere, so only a base64url
	// encoding can hold one — and where forty-eight base62 characters follow,
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
			src:  "payload=zzzzpplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789abzzzz",
			want: "payload=zzzz*********************************************************",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the
			// Perplexity pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzpplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789abzzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz*********************************************************",
		},
	}

	m := New(WithPatterns(PerplexityAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PerplexityAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_perplexity_api_key.go names, held to the answer it
	// gives rather than to the one a reader might want. Hexadecimal digits are
	// base62 and a digest carries nothing that ends a run, so a digest of
	// forty-eight characters or more written behind the prefix is a key's
	// format exactly and is redacted. Declining it would mean declining every
	// key Perplexity wrote in the digits alone, which is the whole credential
	// rather than the end of one.
	//
	// The two below it are where the floor and the prefix each hold: a SHA-1 is
	// eight characters short of a body and an MD5 sixteen, and an underscore is
	// no character the prefix carries. The cases move with the scan, so a
	// change to either shows up here as a decision rather than as something the
	// next reader discovers.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sha256 behind the prefix",
			src:  "pplx-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "*********************************************************************",
		},
		{
			name: "a sha256 in a cache key",
			src:  "key: pplx-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "key: *********************************************************************",
		},
		{
			name: "a sha1 behind the prefix, eight characters short of a body",
			src:  "pplx-0123456789abcdef0123456789abcdef01234567",
			want: "pplx-0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "an md5 behind the prefix",
			src:  "pplx-0123456789abcdef0123456789abcdef",
			want: "pplx-0123456789abcdef0123456789abcdef",
		},
		{
			name: "a sha256 behind an underscore rather than the prefix",
			src:  "pplx_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "pplx_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	m := New(WithPatterns(PerplexityAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_perplexityAPIKeyPrefix(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a key can
	// begin inside the one before it, and that holds only while the prefix
	// opens with characters a body may be written with. Here it is the four in
	// front of the hyphen: a body closing with pplx leaves the hyphen of the
	// next key standing directly behind it. A prefix opening with a character
	// outside the alphabet would make the two impossible to nest, and the cases
	// above pinning the nesting would stand for nothing — which is not a
	// failure anything else here reports.
	if perplexityAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	if c := perplexityAPIKeyPrefix[0]; !isBase62Byte(c) {
		t.Errorf("the prefix opens with %q, which no body may be written with, so no key can begin inside another", c)
	}
}

func Test_perplexityAPIKeyPrefix_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over
	// it, where a scan whose prefix closes on a character its own body admits
	// has to keep one. What makes the cursor unnecessary is that two candidates
	// can never read the same run: a candidate asks for the last character of
	// the prefix directly in front of its body, no body may be written with it,
	// so the run of an earlier candidate has already ended there and the later
	// candidate's run begins past it. Were that character one a body admits, a
	// run dense in prefixes would be walked once for every candidate in it and
	// the scan would cost time quadratic in the length of such a line.
	if perplexityAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so there is no candidate to reason about")
	}
	if c := perplexityAPIKeyPrefix[len(perplexityAPIKeyPrefix)-1]; isBase62Byte(c) {
		t.Errorf("the prefix closes with %q, which a body may be written with, so two candidates can read the same run", c)
	}
}

// Test_perplexityAPIKeyAnchor holds the prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_perplexityAPIKeyAnchor(t *testing.T) {
	if perplexityAPIKeyAnchorIndex >= len(perplexityAPIKeyPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", perplexityAPIKeyAnchorIndex, len(perplexityAPIKeyPrefix))
	}
	if c := perplexityAPIKeyPrefix[perplexityAPIKeyAnchorIndex]; c != perplexityAPIKeyAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(perplexityAPIKeyAnchor))
	}
}

func Test_PerplexityAPIKey_scanIsLinear(t *testing.T) {
	// A line dense in prefixes holds a candidate for every five characters it
	// has. The one thing a candidate reads that is a walk over the rest of the
	// input rather than a bounded test is where its run ends, and repeating
	// that walk at every candidate would cost time quadratic in the length of
	// the line. The bound here is far above a linear scan and far below a
	// quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every fifty-three bytes where they are densest, because a
	// sample has to carry a whole body to be one. The crowding a line can
	// actually carry, a candidate every five bytes, stays here.
	sources := map[string]string{
		// Candidates as close together as the prefix allows, none of them with
		// a run long enough to be a body: every one reaches the body of the
		// loop and every one is rejected.
		"a candidate every five characters": strings.Repeat("pplx-", 250000),
		// Keys written into one another, each beginning four characters before
		// the one in front of it ends, so every candidate is a key and every
		// one of them walks a run.
		"a key beginning inside every key": strings.Repeat("pplx-0123456789abcdefghijklmnopqrstuvwxyz01234567", 35000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a key.
		"a body that runs the length of the line": "pplx-" + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: three bytes
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("ax", 900000),
		// And the prefix's own letters with no anchor among them, which is the
		// walk reading a whole line and stopping nowhere in it.
		"the letters of the prefix with no anchor": strings.Repeat("ppl", 600000),
	}

	checkScanIsLinear(t, PerplexityAPIKey(), sources)
}

// referencePerplexityAPIKey is the expression the scan in
// builtin_perplexity_api_key.go reads by hand: the statement of what a
// Perplexity API key is, kept here so that the scan can be held to it.
//
// The prefix, the floor and the alphabet are spelled again rather than built
// from perplexityAPIKeyPrefix, perplexityAPIKeyBodyChars and isBase62Byte. A
// reference sharing those declarations could not disagree with the scan about
// them, and it is exactly that disagreement the fuzz target below is for: the
// two have to be changed together or reported apart.
//
// The floor is written as a counted repetition, which is what a reference is
// otherwise written out by hand to avoid. It costs nothing here, and for the
// reason the scan needs no cursor: candidates cannot crowd inside one run, so
// no input makes an engine walk the same run more than once.
var referencePerplexityAPIKey = regexp.MustCompile(`pplx-[0-9A-Za-z]{48,}`)

// referencePerplexityAPIKeyFind locates keys the plain way: the leftmost match
// of the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a key can begin inside one: the four letters the
// prefix opens with are written in the alphabet a body is, so a body closing
// with pplx holds the start of the key behind it. The scan finds both and
// reports the two spans overlapping for a Masker to resolve, so the reference
// must ask about both.
func referencePerplexityAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referencePerplexityAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzPerplexityAPIKey_matchesReference guards the hand-written scan: the
// prefix it searches for, the floor it holds a body to, the alphabet it reads
// that body in and the byte it resumes at may none of them change which keys
// are located.
func FuzzPerplexityAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("PERPLEXITY_API_KEY=pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab")
	f.Add("pplx-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AB")
	f.Add("pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789a")   // one short of a body
	f.Add("pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789abc") // and a run longer than one
	f.Add("pplx-0123456789abcdefghij-lmnopqrstuvwxyz0123456789ab")  // a hyphen, which base64url admits and base62 does not
	f.Add("pplx-0123456789abcdefghij_lmnopqrstuvwxyz0123456789ab")  // an underscore, likewise
	f.Add("pplx-0123456789abcdefghij.lmnopqrstuvwxyz0123456789ab")  // a dot ends the body
	f.Add("PPLX-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab")  // an uppercase prefix
	f.Add("Pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab")  // the capitalisation a header name of the vendor's carries
	f.Add("pplx_0123456789abcdefghijklmnopqrstuvwxyz0123456789ab")  // an underscore where the prefix carries a hyphen
	f.Add("pplx0123456789abcdefghijklmnopqrstuvwxyz0123456789ab")   // the prefix without its closing hyphen
	f.Add("pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab-suffix")
	f.Add("pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab_suffix")
	f.Add("pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab\npplx-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AB")
	// A key beginning inside the match before it, which a scan resuming past a
	// match steps over, and two keys with nothing between them.
	f.Add("pplx-0123456789abcdefghijklmnopqrstuvwxyz01234567pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab")
	f.Add("pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789abpplx-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AB")
	// Candidate positions crowded as close as they can be, with no run long
	// enough for any of them, and keys written into one another so that every
	// candidate has one.
	f.Add(strings.Repeat("pplx-", 16))
	f.Add(strings.Repeat("pplx-0123456789abcdefghijklmnopqrstuvwxyz01234567", 4))
	// A digest written behind the prefix, which is a key's format exactly, and
	// the two that fall short of the floor.
	f.Add("pplx-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("pplx-0123456789abcdef0123456789abcdef01234567")
	f.Add("pplx-0123456789abcdef0123456789abcdef")
	// The names Perplexity gives its own products, which carry a whole prefix
	// and no body, and one whose segment runs the length of a body.
	f.Add("using pplx-api for search")
	f.Add(`{"model":"pplx-embed-v1-0"} {"model":"pplx-embed-context-v1-0"}`)
	f.Add("pplx-cli installs pplx-aarch64-apple-darwin.bin")
	f.Add(`"User-Agent": "pplx-srch-sdk-python/1.0.0"`)
	f.Add(`{"model":"pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab"}`)
	// The prefix written inside a run of base64url, which is the over-match the
	// pattern admits.
	f.Add("payload=zzzzpplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789abzzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzpplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789abzzzz")

	fuzzAgainstReference(f, PerplexityAPIKey().Find, referencePerplexityAPIKeyFind)
}

// perplexityAPIKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func perplexityAPIKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no key. It is also the line the rationale counts the
	// prefix's own bytes over to settle which of them the search is made for.
	line := `time=2026-08-17T00:00:00Z level=info msg="completion finished" tokens=512 url=https://api.perplexity.ai/chat/completions `
	key := "pplx-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every five characters with no run long enough behind
			// any of them: each reaches the body of the loop and none becomes a
			// key. What it times is the walk over a run being started and
			// stopped, once per candidate and no more.
			name:  "candidates that are not values",
			src:   strings.Repeat("pplx-", 128),
			spans: 0,
		},
		{
			// Keys written into one another, each beginning four characters
			// before the one in front of it ends. This is what the scan gets
			// away with keeping no cursor for: the runs the candidates read
			// follow one another rather than overlapping. The four characters
			// at the end are what closes the body of the last of them, which
			// otherwise has only the run it was written with.
			name:  "keys written into one another",
			src:   strings.Repeat("pplx-0123456789abcdefghijklmnopqrstuvwxyz01234567", 128) + "pplx",
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
