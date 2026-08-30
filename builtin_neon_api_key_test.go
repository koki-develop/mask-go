package mask

import (
	"slices"
	"strings"
	"testing"
)

// The Neon API key pattern: what it locates and what it leaves alone, written
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
// shape, obviously not real. The run they are built from, 0123456789abcdef, is
// sixteen characters, so a body is that run four times over — the shortest body
// the scan reads, since the count is a floor, so a body shortened for
// readability would leave a case holding no key at all. It is written in
// lowercase where the case does not matter and in uppercase where the case is
// what a case is about: base62 holds the letters of both, so either spelling is
// a body.

func Test_NeonAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 69}},
		},
		{
			name: "a key in an environment assignment",
			src:  "NEON_API_KEY=napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{13, 82}},
		},
		{
			// base62 holds the letters of both cases, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "napi_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 69}},
		},
		{
			// The count is a floor and the span reaches the end of the run, so
			// a run longer than the shortest body is a key to the end of it
			// rather than a key and a character left over.
			name: "a run longer than the shortest body",
			src:  "napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
			want: []Span{{0, 70}},
		},
		{
			name: "two keys separated by a space",
			src:  "napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef napi_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 69}, {70, 139}},
		},
		{
			// The four letters the prefix opens with belong to the alphabet a
			// body is written in, so a body may close with napi and the
			// underscore of the next key stand directly behind it. The second
			// key begins four characters before the first one ends, and a scan
			// resuming past a match would step over it. The spans overlap,
			// which a Masker resolves into one.
			name: "a key beginning inside the key before it",
			src:  "napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abnapi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 69}, {65, 134}},
		},
		{
			// Two keys with nothing at all between them. The first body reads
			// four characters into the second key's prefix and stops at the
			// underscore behind them, so the spans overlap here as well.
			name: "two keys with nothing between them",
			src:  "napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefnapi_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 73}, {69, 138}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := NeonAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NeonAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "napi_",
		},
		{
			// Sixty-three characters where the pattern asks for sixty-four.
			// This is the shape a line cut to a column limit leaves, and the
			// characters in front of the cut stay in the text: the far side of
			// reading a floor, which builtin_neon_api_key.go weighs.
			name: "a body one character too short",
			src:  "napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// The hyphen and the underscore are base64url characters and no
			// base62 ones, so either ends a body where the run behind it is
			// too short to be one.
			name: "a body carrying a hyphen",
			src:  "napi_0123456789abcdef0123456789abcdef-123456789abcdef0123456789abcdef",
		},
		{
			name: "a body carrying an underscore",
			src:  "napi_0123456789abcdef0123456789abcdef_123456789abcdef0123456789abcdef",
		},
		{
			name: "an uppercase prefix",
			src:  "NAPI_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The prefix is written with the underscore Neon closes it with,
			// not with the hyphen a delimiter is elsewhere.
			name: "a hyphen where the prefix carries an underscore",
			src:  "napi-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The prefix closes with an underscore, so a body written straight
			// against the four letters is no body.
			name: "the prefix without its closing underscore",
			src:  "napi0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a space in the body",
			src:  "napi_0123456789abcdef0123456789abcdef 123456789abcdef0123456789abcdef",
		},
		{
			name: "a dot in the body",
			src:  "napi_0123456789abcdef0123456789abcdef.123456789abcdef0123456789abcdef",
		},
		{
			name: "a body broken by a line break",
			src:  "napi_0123456789abcdef0123456789abcdef\n123456789abcdef0123456789abcdef",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// most of the anchor, so a run long enough is not a key without it.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
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
			if got, _ := NeonAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_NeonAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "NEON_API_KEY=napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "NEON_API_KEY=*********************************************************************",
		},
		{
			// The header the Neon API is called with.
			name: "a bearer authorization header",
			src:  "Authorization: Bearer napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "Authorization: Bearer *********************************************************************",
		},
		{
			name: "json",
			src:  `{"key":"napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`,
			want: `{"key":"*********************************************************************"}`,
		},
		{
			name: "a command line",
			src:  `curl -H "Authorization: Bearer napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" https://console.neon.tech/api/v2/projects`,
			want: `curl -H "Authorization: Bearer *********************************************************************" https://console.neon.tech/api/v2/projects`,
		},
		{
			// The environment block the Neon CLI is configured with.
			name: "a configuration environment block",
			src:  `"env": {"NEON_API_KEY": "napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`,
			want: `"env": {"NEON_API_KEY": "*********************************************************************"}`,
		},
		{
			name: "twice",
			src:  "napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef napi_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: "********************************************************************* *********************************************************************",
		},
		{
			// The two spans are merged, so the key that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a key beginning inside the key before it",
			src:  "napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abnapi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "**************************************************************************************************************************************",
		},
	}

	m := New(WithPatterns(NeonAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NeonAPIKey_theResponseExamplePrefixes(t *testing.T) {
	// The three spellings Neon's create-response examples write where a key
	// goes, held to being left in the text, and the same body behind napi_ held
	// to being redacted. builtin_neon_api_key.go argues why those three are
	// placeholders and this scan reads napi_ alone; the cases are what makes a
	// change of mind about it a decision rather than a widening nobody noticed.
	//
	// The personal spelling stands first because it is the one the argument
	// turns on: it is provably no prefix a key carries, which is what licenses
	// reading the other two the same way. Left unpinned, a later widening that
	// read it would leave the two below still passing.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "the personal response example spelling",
			src:  "neon_api_key_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "neon_api_key_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "the organization response example spelling",
			src:  "neon_org_key_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "neon_org_key_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "the project-scoped response example spelling",
			src:  "neon_project_key_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "neon_project_key_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "the same body behind the prefix the changelog states",
			src:  "napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "*********************************************************************",
		},
	}

	m := New(WithPatterns(NeonAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NeonAPIKey_theNodeAPINamesThatCarryThePrefix(t *testing.T) {
	// Node-API writes its names with this prefix, so a source file of a native
	// addon carries napi_ on nearly every line. What keeps them out of a span
	// is the floor and the alphabet together: a name is snake_case, so the
	// underscore after its next word ends the run long before the sixty-fourth
	// character.
	//
	// The last case is where that stops holding — a name whose segment closes
	// on napi with sixty-four unbroken characters behind it is a key's format
	// exactly, and everything from the napi onward is redacted.
	// builtin_neon_api_key.go weighs the tightening that would rule it out and
	// says why it is declined.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a node-api type",
			src:  "napi_value result;",
			want: "napi_value result;",
		},
		{
			name: "a node-api status",
			src:  "napi_status status = napi_ok;",
			want: "napi_status status = napi_ok;",
		},
		{
			name: "a node-api call",
			src:  "napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &result);",
			want: "napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &result);",
		},
		{
			name: "a name closing on the prefix with a body behind it",
			src:  "sonapi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "so*********************************************************************",
		},
	}

	m := New(WithPatterns(NeonAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NeonAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xnapi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "x*********************************************************************",
		},
		{
			name: "underscore before",
			src:  "NEON_API_KEY_napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "NEON_API_KEY_*********************************************************************",
		},
	}

	m := New(WithPatterns(NeonAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NeonAPIKey_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a floor rather than a count. Where a key ends is
	// where its alphabet stops, so a letter or a digit written straight against
	// a key is redacted with it — which is what buys a key of a length nobody
	// has published being located whole. The alphabet is base62 and not
	// base64url, so the two characters that separate them, the hyphen and the
	// underscore, end a key here.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the key is napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.",
			want: "the key is *********************************************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export NEON_API_KEY="napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`,
			want: `export NEON_API_KEY="*********************************************************************"`,
		},
		{
			name: "a word against the key",
			src:  "napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefsuffix",
			want: "***************************************************************************",
		},
		{
			name: "a dashed word against the key",
			src:  "napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef-suffix",
			want: "*********************************************************************-suffix",
		},
		{
			name: "an underscored word against the key",
			src:  "napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef_suffix",
			want: "*********************************************************************_suffix",
		},
	}

	m := New(WithPatterns(NeonAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NeonAPIKey_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than
	// redacted. A line cut to a column limit partway through a key leaves a
	// prefix and a body too short to be one, and the random characters written
	// before the cut come through whole.
	//
	// It is the price of reading a count no Neon page states in a unit a string
	// carries, and the cases move with the scan: one of them starting to be
	// located means the floor moved, and that is a decision to be taken rather
	// than noticed afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a key one character short of the floor",
			src:  "NEON_API_KEY=napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "a key cut off at its prefix",
			src:  "NEON_API_KEY=napi_",
		},
	}

	m := New(WithPatterns(NeonAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_NeonAPIKey_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix closes with an
	// underscore, which standard base64 writes nowhere, so only a base64url
	// encoding can hold one — and where sixty-four base62 characters follow,
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
			src:  "payload=zzzznapi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefzzzz",
			want: "payload=zzzz*************************************************************************",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the Neon
			// pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzznapi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefzzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz*************************************************************************",
		},
	}

	m := New(WithPatterns(NeonAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NeonAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_neon_api_key.go names, held to the answer it gives
	// rather than to the one a reader might want. Hexadecimal digits are base62
	// and a digest carries nothing that ends a run, so a SHA-256 written behind
	// the prefix is exactly the sixty-four characters a body is and is
	// redacted. Declining it would mean declining every key Neon wrote in the
	// digits alone, which is the whole credential against a cache key.
	//
	// The two below it are where the floor and the prefix each hold: a SHA-1 is
	// twenty-four characters short of a body and an MD5 thirty-two, and a
	// hyphen is no character the prefix carries. The cases move with the scan,
	// so a change to either shows up here as a decision rather than as
	// something the next reader discovers.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sha256 behind the prefix",
			src:  "napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "*********************************************************************",
		},
		{
			name: "a sha256 in a cache key",
			src:  "key: napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "key: *********************************************************************",
		},
		{
			name: "a sha1 behind the prefix, twenty-four characters short of a body",
			src:  "napi_0123456789abcdef0123456789abcdef01234567",
			want: "napi_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "an md5 behind the prefix",
			src:  "napi_0123456789abcdef0123456789abcdef",
			want: "napi_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a sha256 behind a hyphen rather than the prefix",
			src:  "napi-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "napi-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	m := New(WithPatterns(NeonAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_neonAPIKeyPrefix(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a key can
	// begin inside the one before it, and that holds only while the prefix
	// opens in the alphabet a body is written in. A prefix opening with a
	// character outside it would make the two impossible to nest, and the cases
	// above pinning the nesting would stand for nothing — which is not a
	// failure anything else here reports.
	if neonAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	if c := neonAPIKeyPrefix[0]; !isBase62Byte(c) {
		t.Errorf("the prefix opens with %q, which no body may be written with, so no key can begin inside another", c)
	}
}

func Test_neonAPIKeyPrefix_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over
	// it. What makes the cursor unnecessary is that two candidates can never
	// read the same run: a candidate asks for the last character of the prefix
	// directly in front of its body, no body may be written with it, so an
	// earlier candidate's run has already ended there. Were that character one
	// a body admits, a run dense in prefixes would be walked once per candidate
	// in it and the scan would cost time quadratic in the length of such a line.
	if neonAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so there is no candidate to reason about")
	}
	if c := neonAPIKeyPrefix[len(neonAPIKeyPrefix)-1]; isBase62Byte(c) {
		t.Errorf("the prefix closes with %q, which a body may be written with, so two candidates can read the same run", c)
	}
}

// Test_neonAPIKeyAnchor holds the prefix to carrying the byte the scan searches
// the input for at the index it reads a candidate back from. builtin_scan.go
// says why that is held here rather than left to the targets.
func Test_neonAPIKeyAnchor(t *testing.T) {
	if neonAPIKeyAnchorIndex >= len(neonAPIKeyPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", neonAPIKeyAnchorIndex, len(neonAPIKeyPrefix))
	}
	if c := neonAPIKeyPrefix[neonAPIKeyAnchorIndex]; c != neonAPIKeyAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(neonAPIKeyAnchor))
	}
}

func Test_NeonAPIKey_scanIsLinear(t *testing.T) {
	// A line dense in prefixes holds a candidate for every five characters it
	// has. The one thing a candidate reads that is a walk over the rest of the
	// input rather than a bounded test is where its run ends, and repeating
	// that walk at every candidate would cost time quadratic in the length of
	// the line. The bound here is far above a linear scan and far below a
	// quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every sixty-five bytes where they are densest, because a sample
	// has to carry a whole body to be one. The crowding a line can actually
	// carry, a candidate every five bytes, stays here.
	sources := map[string]string{
		// Candidates as close together as the prefix allows, none of them with
		// a run long enough to be a body: every one reaches the body of the
		// loop and every one is rejected.
		"a candidate every five characters": strings.Repeat("napi_", 250000),
		// Keys written into one another, each beginning four characters before
		// the one in front of it ends, so every candidate is a key and every
		// one of them walks a run.
		"a key beginning inside every key": strings.Repeat("napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab", 20000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a key.
		"a body that runs the length of the line": "napi_" + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("a_", 900000),
		// And the prefix's own letters with no anchor among them, which is the
		// walk reading a whole line and stopping nowhere in it.
		"the letters of the prefix with no anchor": strings.Repeat("napi", 450000),
	}

	checkScanIsLinear(t, NeonAPIKey(), sources)
}

// referenceNeonAPIKeyFind locates keys the plain way: every position in turn,
// the prefix tried at it and the body walked to the end of its run, with no
// cursor and nothing remembered between candidates. The prefix, the floor and
// the character class are spelled again here rather than shared with the scan.
// A reference reading neonAPIKeyPrefix, neonAPIKeyBodyChars and isBase62Byte
// could not disagree with it about them, and it is exactly that disagreement
// the fuzz target below is for: the two have to be changed together or reported
// apart.
//
// Every position is a starting point in its own right, a match included,
// because the prefix opens in the alphabet a body is written in:
// napi_...abnapi_... holds a key beginning inside the match before it. The scan
// finds both and reports the two spans overlapping for a Masker to resolve, so
// the reference must ask about both.
//
// It is written out rather than built on a regular expression, and the floor is
// why. The grammar states compactly as napi_[0-9A-Za-z]{64,}, but a counted
// repetition is what an engine has the least room to skip, and behind this one
// the machine is sixty-four states wide. Driven from that expression the target
// stopped reaching executions at all partway into every run — six seconds into
// the shortest of them, fifteen into the longest — and reached none for the
// rest of it, where the walk below holds twenty-odd thousand a second for as
// long as it is given. The input the mutator finds that on is not one that can
// be written down here: over text crafted from the prefix, a run of it or a
// body repeated to two megabytes, the expression costs a handful of times what
// the walk does and no more. Both were measured.
//
// The walk reads every position rather than the anchors a search finds, which
// is the work the scan is spared and all of it: the cost stays linear in the
// length of the input for the reason the scan needs no cursor. The underscore
// the prefix closes with is written in no body, so the run one candidate reads
// has ended before the next candidate's body begins, and no two of them read
// the same run however dense in prefixes the text is.
func referenceNeonAPIKeyFind(src string) []Span {
	const (
		prefix    = "napi_"
		bodyChars = 64
	)

	body := func(c byte) bool {
		return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
	}

	var spans []Span
	for start := range len(src) {
		if !strings.HasPrefix(src[start:], prefix) {
			continue
		}

		at := start + len(prefix)
		end := at
		for end < len(src) && body(src[end]) {
			end++
		}
		if end-at < bodyChars {
			continue
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return spans
}

// FuzzNeonAPIKey_matchesReference guards the hand-written scan: the prefix it
// searches for, the floor it holds a body to, the alphabet it reads that body
// in and the byte it resumes at may none of them change which keys are located.
func FuzzNeonAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("NEON_API_KEY=napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("napi_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
	f.Add("napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")   // one short of a body
	f.Add("napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0") // and a run longer than one
	f.Add("napi_0123456789abcdef0123456789abcdef-123456789abcdef0123456789abcdef")  // a hyphen, which base64url admits and base62 does not
	f.Add("napi_0123456789abcdef0123456789abcdef_123456789abcdef0123456789abcdef")  // an underscore, likewise
	f.Add("napi_0123456789abcdef0123456789abcdef.123456789abcdef0123456789abcdef")  // a dot ends the body
	f.Add("NAPI_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")  // an uppercase prefix
	f.Add("napi-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")  // a hyphen where the prefix carries an underscore
	f.Add("napi0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")   // the prefix without its closing underscore
	f.Add("napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef-suffix")
	f.Add("napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef_suffix")
	f.Add("napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\nnapi_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
	// A key beginning inside the match before it, which a scan resuming past a
	// match steps over, and two keys with nothing between them.
	f.Add("napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abnapi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefnapi_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
	// Candidate positions crowded as close as they can be, with no run long
	// enough for any of them, and keys written into one another so that every
	// candidate has one.
	f.Add(strings.Repeat("napi_", 16))
	f.Add(strings.Repeat("napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab", 4))
	// The two digests that fall short of the floor. A SHA-256 written behind
	// the prefix is the case above: it is exactly the sixty-four characters a
	// body is.
	f.Add("napi_0123456789abcdef0123456789abcdef01234567")
	f.Add("napi_0123456789abcdef0123456789abcdef")
	// The names Node-API exports, which write this prefix on nearly every line
	// of a native addon, and a snake_case name whose segment closes on napi
	// with a body behind it.
	f.Add("napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &result);")
	f.Add("napi_status status = napi_ok;")
	f.Add("sonapi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// The prefixes the documentation's response examples write in place of a
	// key, which the scan reads as no prefix at all.
	f.Add("neon_api_key_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("neon_org_key_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("neon_project_key_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// The prefix written inside a run of base64url, which is the over-match the
	// pattern admits.
	f.Add("payload=zzzznapi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefzzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzznapi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefzzzz")

	fuzzAgainstReference(f, NeonAPIKey().Find, referenceNeonAPIKeyFind)
}

// neonAPIKeyFindBenchmarks is what this scan is timed on. The builtinPatterns
// entry for the pattern names it, and BenchmarkBuiltins times every case it
// holds under the pattern's own name, so that a built-in cannot arrive without
// a benchmark. Every case is held to the count it states under a plain go test
// as well, which is what a benchmark nobody has run yet cannot be.
func neonAPIKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="branch created" project=misty-pine-12345678 url=https://console.neon.tech/api/v2/projects `
	key := "napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

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
			src:   strings.Repeat("napi_", 128),
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
			src:   strings.Repeat("napi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab", 128) + "napi",
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
