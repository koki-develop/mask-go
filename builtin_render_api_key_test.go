package mask

import (
	"slices"
	"strings"
	"testing"
)

// The Render API key pattern: what it locates and what it leaves alone, written
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
// sixteen characters, so a body is that run and twelve characters of it again —
// the shortest body the scan reads, since the count is a floor, so a body
// shortened for readability would leave a case holding no key at all. It is
// written in lowercase where the case does not matter and in uppercase where
// the case is what a case is about: base62 holds the letters of both, so either
// spelling is a body.

func Test_RenderAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "rnd_0123456789abcdef0123456789ab",
			want: []Span{{0, 32}},
		},
		{
			name: "a key in an environment assignment",
			src:  "RENDER_API_KEY=rnd_0123456789abcdef0123456789ab",
			want: []Span{{15, 47}},
		},
		{
			// base62 holds the letters of both cases, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "rnd_0123456789ABCDEF0123456789AB",
			want: []Span{{0, 32}},
		},
		{
			// The count is a floor and the span reaches the end of the run, so
			// a run longer than the shortest body is a key to the end of it
			// rather than a key and a character left over.
			name: "a run longer than the shortest body",
			src:  "rnd_0123456789abcdef0123456789abc",
			want: []Span{{0, 33}},
		},
		{
			name: "two keys separated by a space",
			src:  "rnd_0123456789abcdef0123456789ab rnd_0123456789ABCDEF0123456789AB",
			want: []Span{{0, 32}, {33, 65}},
		},
		{
			// The three letters the prefix opens with belong to the alphabet a
			// body is written in, so a body may close with rnd and the
			// underscore of the next key stand directly behind it. The second
			// key begins three characters before the first one ends, and a scan
			// resuming past a match would step over it. The spans overlap, which
			// a Masker resolves into one.
			name: "a key beginning inside the key before it",
			src:  "rnd_0123456789abcdef0123456789rnd_0123456789abcdef0123456789ab",
			want: []Span{{0, 33}, {30, 62}},
		},
		{
			// Two keys with nothing at all between them. The first body reads
			// three characters into the second key's prefix and stops at the
			// underscore behind them, so the spans overlap here as well.
			name: "two keys with nothing between them",
			src:  "rnd_0123456789abcdef0123456789abrnd_0123456789ABCDEF0123456789AB",
			want: []Span{{0, 35}, {32, 64}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := RenderAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_RenderAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "rnd_",
		},
		{
			// Twenty-seven characters where the pattern asks for twenty-eight.
			// This is the shape a line cut to a column limit leaves, and the
			// characters in front of the cut stay in the text: the far side of
			// reading a floor, which builtin_render_api_key.go weighs.
			name: "a body one character too short",
			src:  "rnd_0123456789abcdef0123456789a",
		},
		{
			// The hyphen and the underscore are base64url characters and no
			// base62 ones, so either ends a body where the run behind it is too
			// short to be one.
			name: "a body carrying a hyphen",
			src:  "rnd_0123456789abcdef-123456789ab",
		},
		{
			name: "a body carrying an underscore",
			src:  "rnd_0123456789abcdef_123456789ab",
		},
		{
			name: "an uppercase prefix",
			src:  "RND_0123456789abcdef0123456789ab",
		},
		{
			// The prefix is written with the underscore Render closes it with,
			// not with the hyphen a delimiter is elsewhere.
			name: "a hyphen where the prefix carries an underscore",
			src:  "rnd-0123456789abcdef0123456789ab",
		},
		{
			// The prefix closes with an underscore, so a body written straight
			// against the three letters is no body.
			name: "the prefix without its closing underscore",
			src:  "rnd0123456789abcdef0123456789ab",
		},
		{
			name: "a space in the body",
			src:  "rnd_0123456789abcdef 123456789ab",
		},
		{
			name: "a dot in the body",
			src:  "rnd_0123456789abcdef.123456789ab",
		},
		{
			name: "a body broken by a line break",
			src:  "rnd_0123456789abcdef\n123456789ab",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// most of the anchor, so a run long enough is not a key without it.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdef0123456789ab",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// A run of the alphabet as long as a body, written where a random
			// number generator seeds itself. A digest carries no underscore, so
			// it holds no prefix to be found at however long it runs.
			name: "a digest with no prefix in front of it",
			src:  "seed=0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := RenderAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_RenderAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "RENDER_API_KEY=rnd_0123456789abcdef0123456789ab",
			want: "RENDER_API_KEY=********************************",
		},
		{
			// The header the Render API is called with.
			name: "a bearer authorization header",
			src:  "Authorization: Bearer rnd_0123456789abcdef0123456789ab",
			want: "Authorization: Bearer ********************************",
		},
		{
			name: "json",
			src:  `{"key":"rnd_0123456789abcdef0123456789ab"}`,
			want: `{"key":"********************************"}`,
		},
		{
			name: "a command line",
			src:  `curl -H "Authorization: Bearer rnd_0123456789abcdef0123456789ab" https://api.render.com/v1/services`,
			want: `curl -H "Authorization: Bearer ********************************" https://api.render.com/v1/services`,
		},
		{
			// The environment block the Render CLI is configured with.
			name: "a configuration environment block",
			src:  `"env": {"RENDER_API_KEY": "rnd_0123456789abcdef0123456789ab"}`,
			want: `"env": {"RENDER_API_KEY": "********************************"}`,
		},
		{
			name: "twice",
			src:  "rnd_0123456789abcdef0123456789ab rnd_0123456789ABCDEF0123456789AB",
			want: "******************************** ********************************",
		},
		{
			// The two spans are merged, so the key that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a key beginning inside the key before it",
			src:  "rnd_0123456789abcdef0123456789rnd_0123456789abcdef0123456789ab",
			want: "**************************************************************",
		},
	}

	m := New(WithPatterns(RenderAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_RenderAPIKey_theRandomNamesThatCarryThePrefix(t *testing.T) {
	// rnd is how ordinary code abbreviates random, so a simulation or a game
	// carries this prefix wherever it names its generator. What keeps those
	// names out of a span is the floor and the alphabet together: a name is
	// snake_case, so the underscore after its next word ends the run long before
	// the twenty-eighth character. The shouted spelling is turned away by the
	// case of the prefix instead, which is what buys the whole of a line of
	// configuration.
	//
	// The last case is where that stops holding — a name whose segment closes on
	// rnd with twenty-eight unbroken characters behind it is a key's format
	// exactly, and everything from the rnd onward is redacted.
	// builtin_render_api_key.go weighs the tightening that would rule it out and
	// says why it is declined.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a generator state",
			src:  "rnd_state = rnd_seed(rnd_next(seed));",
			want: "rnd_state = rnd_seed(rnd_next(seed));",
		},
		{
			name: "a shouted constant",
			src:  "if (rnd_value > RND_MAX / 2) { }",
			want: "if (rnd_value > RND_MAX / 2) { }",
		},
		{
			name: "a name closing on the prefix with a body behind it",
			src:  "seedrnd_0123456789abcdef0123456789ab",
			want: "seed********************************",
		},
	}

	m := New(WithPatterns(RenderAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_RenderAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xrnd_0123456789abcdef0123456789ab",
			want: "x********************************",
		},
		{
			name: "underscore before",
			src:  "RENDER_API_KEY_rnd_0123456789abcdef0123456789ab",
			want: "RENDER_API_KEY_********************************",
		},
	}

	m := New(WithPatterns(RenderAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_RenderAPIKey_reachesTheEndOfTheRun(t *testing.T) {
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
			src:  "the key is rnd_0123456789abcdef0123456789ab.",
			want: "the key is ********************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export RENDER_API_KEY="rnd_0123456789abcdef0123456789ab"`,
			want: `export RENDER_API_KEY="********************************"`,
		},
		{
			name: "a word against the key",
			src:  "rnd_0123456789abcdef0123456789absuffix",
			want: "**************************************",
		},
		{
			name: "a dashed word against the key",
			src:  "rnd_0123456789abcdef0123456789ab-suffix",
			want: "********************************-suffix",
		},
		{
			name: "an underscored word against the key",
			src:  "rnd_0123456789abcdef0123456789ab_suffix",
			want: "********************************_suffix",
		},
	}

	m := New(WithPatterns(RenderAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_RenderAPIKey_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than redacted.
	// A line cut to a column limit partway through a key leaves a prefix and a
	// body too short to be one, and the random characters written before the cut
	// come through whole.
	//
	// It is the price of reading a count Render has never written down, and the
	// cases move with the scan: one of them starting to be located means the
	// floor moved, and that is a decision to be taken rather than noticed
	// afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a key one character short of the floor",
			src:  "RENDER_API_KEY=rnd_0123456789abcdef0123456789a",
		},
		{
			name: "a key cut off at its prefix",
			src:  "RENDER_API_KEY=rnd_",
		},
	}

	m := New(WithPatterns(RenderAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_RenderAPIKey_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix closes with an
	// underscore, which standard base64 writes nowhere, so only a base64url
	// encoding can hold one — and where twenty-eight base62 characters follow,
	// everything from the prefix to the end of that run is redacted.
	//
	// The cases are held to being redacted rather than to being spared. What is
	// taken is a stretch of a value already opaque to a reader, and the run is a
	// key's format exactly: nothing is left in the text to tell the two apart,
	// so a pattern letting it through would let a real key through with it. What
	// the cases are for is that they move with the scan: one of them ceasing to
	// be located means the grammar changed, and that is a decision to be taken
	// rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "inside a base64url payload",
			src:  "payload=zzzzrnd_0123456789abcdef0123456789abzzzz",
			want: "payload=zzzz************************************",
		},
		{
			// The same run written where a JWT signature stands. The JWT pattern
			// is not enabled here, so what the case states is the Render
			// pattern's own reading of it: the dot in front of the signature
			// ends the run of the segment before, and the prefix inside the
			// signature is read from there to the end of the run it opens.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzrnd_0123456789abcdef0123456789abzzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz************************************",
		},
	}

	m := New(WithPatterns(RenderAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_RenderAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_render_api_key.go names, held to the answer it gives
	// rather than to the one a reader might want. Hexadecimal digits are base62
	// and a digest carries nothing that ends a run, so a digest written behind
	// the prefix runs past the floor and is redacted whole — an MD5 at
	// thirty-two characters, a SHA-1 at forty and a SHA-256 at sixty-four alike.
	// Declining them would mean declining every key Render wrote in the digits
	// alone, which is the whole credential against a cache key.
	//
	// The two below them are where the floor and the prefix each hold: a run of
	// sixteen is twelve characters short of a body, and a hyphen is no character
	// the prefix carries. The cases move with the scan, so a change to either
	// shows up here as a decision rather than as something the next reader
	// discovers.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "an md5 behind the prefix",
			src:  "rnd_0123456789abcdef0123456789abcdef",
			want: "************************************",
		},
		{
			name: "a sha1 behind the prefix in a cache key",
			src:  "key: rnd_0123456789abcdef0123456789abcdef01234567",
			want: "key: ********************************************",
		},
		{
			name: "a sha256 behind the prefix",
			src:  "rnd_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "********************************************************************",
		},
		{
			name: "a run of sixteen behind the prefix, twelve characters short of a body",
			src:  "rnd_0123456789abcdef",
			want: "rnd_0123456789abcdef",
		},
		{
			name: "an md5 behind a hyphen rather than the prefix",
			src:  "rnd-0123456789abcdef0123456789abcdef",
			want: "rnd-0123456789abcdef0123456789abcdef",
		},
	}

	m := New(WithPatterns(RenderAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_renderAPIKeyPrefix(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a key can
	// begin inside the one before it, and that holds only while the characters
	// in front of the underscore are ones a body may be written with: a body
	// closing with those three leaves the underscore of the next key standing
	// directly behind it. One of them written outside the alphabet would make
	// the two impossible to nest, and the cases above pinning the nesting would
	// stand for nothing — which is not a failure anything else here reports.
	if renderAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for i := range len(renderAPIKeyPrefix) - 1 {
		if c := renderAPIKeyPrefix[i]; !isBase62Byte(c) {
			t.Errorf("the prefix holds %q, which no body may be written with, so no key can begin inside another", c)
		}
	}
}

func Test_renderAPIKeyPrefix_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over it.
	// What makes the cursor unnecessary is that two candidates can never read
	// the same run: a candidate asks for the last character of the prefix
	// directly in front of its body, no body may be written with it, so an
	// earlier candidate's run has already ended there. Were that character one a
	// body admits, a run dense in prefixes would be walked once per candidate in
	// it and the scan would cost time quadratic in the length of such a line.
	if renderAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so there is no candidate to reason about")
	}
	if c := renderAPIKeyPrefix[len(renderAPIKeyPrefix)-1]; isBase62Byte(c) {
		t.Errorf("the prefix closes with %q, which a body may be written with, so two candidates can read the same run", c)
	}
}

// Test_renderAPIKeyAnchor holds the prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_renderAPIKeyAnchor(t *testing.T) {
	if renderAPIKeyAnchorIndex >= len(renderAPIKeyPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", renderAPIKeyAnchorIndex, len(renderAPIKeyPrefix))
	}
	if c := renderAPIKeyPrefix[renderAPIKeyAnchorIndex]; c != renderAPIKeyAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(renderAPIKeyAnchor))
	}
}

func Test_RenderAPIKey_scanIsLinear(t *testing.T) {
	// A line dense in prefixes holds a candidate for every four characters it
	// has. The one thing a candidate reads that is a walk over the rest of the
	// input rather than a bounded test is where its run ends, and repeating that
	// walk at every candidate would cost time quadratic in the length of the
	// line. The bound here is far above a linear scan and far below a quadratic
	// one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every thirty bytes where they are densest, because a sample has
	// to carry a whole body to be one. The crowding a line can actually carry, a
	// candidate every four bytes, stays here.
	sources := map[string]string{
		// Candidates as close together as the prefix allows, none of them with a
		// run long enough to be a body: every one reaches the body of the loop
		// and every one is rejected.
		"a candidate every four characters": strings.Repeat("rnd_", 250000),
		// Keys written into one another, each beginning three characters before
		// the one in front of it ends, so every candidate is a key and every one
		// of them walks a run.
		"a key beginning inside every key": strings.Repeat("rnd_0123456789abcdef0123456789", 40000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a key.
		"a body that runs the length of the line": "rnd_" + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: one byte read
		// and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("a_", 900000),
		// And the prefix's own letters with no anchor among them, which is the
		// walk reading a whole line and stopping nowhere in it.
		"the letters of the prefix with no anchor": strings.Repeat("rnd", 600000),
	}

	checkScanIsLinear(t, RenderAPIKey(), sources)
}

// referenceRenderAPIKeyFind locates keys the plain way: every position in turn,
// the prefix tried at it and the body walked to the end of its run, with no
// cursor and nothing remembered between candidates. The prefix, the floor and
// the character class are spelled again here rather than shared with the scan.
// A reference reading renderAPIKeyPrefix, renderAPIKeyBodyChars and
// isBase62Byte could not disagree with it about them, and it is exactly that
// disagreement the fuzz target below is for: the two have to be changed
// together or reported apart.
//
// Every position is a starting point in its own right, a match included,
// because the prefix opens in the alphabet a body is written in:
// rnd_...rnd_... holds a key beginning inside the match before it. The scan
// finds both and reports the two spans overlapping for a Masker to resolve, so
// the reference must ask about both.
//
// It is written out rather than built on a regular expression, and what decides
// that is what the expression costs this target. The grammar states compactly as
// rnd_[0-9A-Za-z]{28,}, whose counted repetition leaves an engine a machine
// twenty-eight states wide to walk at every candidate, and a line dense in
// prefixes hands it one candidate every four characters. Driven from that
// expression the target held between a half and two thirds of the executions the
// walk holds over a run of the same length; both were measured, and neither
// starved. So the expression is affordable here and is declined for what it
// costs rather than for what it would break.
//
// The walk reads every position rather than the anchors a search finds, which is
// the work the scan is spared and all of it: the cost stays linear in the length
// of the input for the reason the scan needs no cursor. The underscore the
// prefix closes with is written in no body, so the run one candidate reads has
// ended before the next candidate's body begins, and no two of them read the
// same run however dense in prefixes the text is.
func referenceRenderAPIKeyFind(src string) []Span {
	const (
		prefix    = "rnd_"
		bodyChars = 28
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

// FuzzRenderAPIKey_matchesReference guards the hand-written scan: the prefix it
// searches for, the floor it holds a body to, the alphabet it reads that body in
// and the byte it resumes at may none of them change which keys are located.
func FuzzRenderAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("RENDER_API_KEY=rnd_0123456789abcdef0123456789ab")
	f.Add("rnd_0123456789ABCDEF0123456789AB")
	f.Add("rnd_0123456789abcdef0123456789a")   // one short of a body
	f.Add("rnd_0123456789abcdef0123456789abc") // and a run longer than one
	f.Add("rnd_0123456789abcdef-123456789ab")  // a hyphen, which base64url admits and base62 does not
	f.Add("rnd_0123456789abcdef_123456789ab")  // an underscore, likewise
	f.Add("rnd_0123456789abcdef.123456789ab")  // a dot ends the body
	f.Add("RND_0123456789abcdef0123456789ab")  // an uppercase prefix
	f.Add("rnd-0123456789abcdef0123456789ab")  // a hyphen where the prefix carries an underscore
	f.Add("rnd0123456789abcdef0123456789ab")   // the prefix without its closing underscore
	f.Add("rnd_0123456789abcdef0123456789ab-suffix")
	f.Add("rnd_0123456789abcdef0123456789ab_suffix")
	f.Add("rnd_0123456789abcdef0123456789ab\nrnd_0123456789ABCDEF0123456789AB")
	// A key beginning inside the match before it, which a scan resuming past a
	// match steps over, and two keys with nothing between them.
	f.Add("rnd_0123456789abcdef0123456789rnd_0123456789abcdef0123456789ab")
	f.Add("rnd_0123456789abcdef0123456789abrnd_0123456789ABCDEF0123456789AB")
	// Candidate positions crowded as close as they can be, with no run long
	// enough for any of them, and keys written into one another so that every
	// candidate has one.
	f.Add(strings.Repeat("rnd_", 16))
	f.Add(strings.Repeat("rnd_0123456789abcdef0123456789", 4))
	// The digests that run past the floor behind the prefix, and the run that
	// falls short of it.
	f.Add("rnd_0123456789abcdef0123456789abcdef")
	f.Add("rnd_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("rnd_0123456789abcdef")
	// The names ordinary code writes with this prefix where it abbreviates
	// random, and a name whose segment closes on rnd with a body behind it.
	f.Add("rnd_state = rnd_seed(rnd_next(seed));")
	f.Add("if (rnd_value > RND_MAX / 2) { }")
	f.Add("seedrnd_0123456789abcdef0123456789ab")
	// The prefix written inside a run of base64url, which is the over-match the
	// pattern admits.
	f.Add("payload=zzzzrnd_0123456789abcdef0123456789abzzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzrnd_0123456789abcdef0123456789abzzzz")

	fuzzAgainstReference(f, RenderAPIKey().Find, referenceRenderAPIKeyFind)
}

// renderAPIKeyFindBenchmarks is what this scan is timed on. The builtinPatterns
// entry for the pattern names it, and BenchmarkBuiltins times every case it
// holds under the pattern's own name, so that a built-in cannot arrive without a
// benchmark. Every case is held to the count it states under a plain go test as
// well, which is what a benchmark nobody has run yet cannot be.
func renderAPIKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="deploy live" service=srv-0123456789abcdefghij url=https://api.render.com/v1/services `
	key := "rnd_0123456789abcdef0123456789ab"

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
			src:   strings.Repeat("rnd_", 128),
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
			src:   strings.Repeat("rnd_0123456789abcdef0123456789", 128) + "rnd",
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
