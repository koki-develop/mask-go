package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Linear API key pattern: what it locates and what it leaves alone, written
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
// carries it and four characters more — the shortest body the scan reads, since
// the count is a floor, so a body shortened for readability would leave a case
// holding no key at all. It is written in lowercase where the case does not
// matter and in uppercase where the case is what a case is about: base62 holds
// the letters of both, so either spelling is a body.

func Test_LinearAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{0, 48}},
		},
		{
			name: "a key in an environment assignment",
			src:  "LINEAR_API_KEY=lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{15, 63}},
		},
		{
			// base62 holds the letters of both cases, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "lin_api_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
			want: []Span{{0, 48}},
		},
		{
			// The count is a floor and the span reaches the end of the run, so
			// a run longer than the shortest body is a key to the end of it
			// rather than a key and a character left over.
			name: "a run longer than the shortest body",
			src:  "lin_api_0123456789abcdefghijklmnopqrstuvwxyz01234",
			want: []Span{{0, 49}},
		},
		{
			name: "two keys separated by a space",
			src:  "lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123 lin_api_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
			want: []Span{{0, 48}, {49, 97}},
		},
		{
			// The three letters the prefix opens with belong to the alphabet a
			// body is written in, so a body may close with lin and the
			// underscore of the next key stand directly behind it. The second
			// key begins three characters before the first one ends, and a scan
			// resuming past a match would step over it. The spans overlap,
			// which a Masker resolves into one.
			name: "a key beginning inside the key before it",
			src:  "lin_api_0123456789abcdefghijklmnopqrstuvwxyz0lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{0, 48}, {45, 93}},
		},
		{
			// Two keys with nothing at all between them. The first body reads
			// three characters into the second key's prefix and stops at the
			// underscore behind them, so the spans overlap here as well.
			name: "two keys with nothing between them",
			src:  "lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123lin_api_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
			want: []Span{{0, 51}, {48, 96}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := LinearAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LinearAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "lin_api_",
		},
		{
			// Thirty-nine characters where the pattern asks for forty. This is
			// the shape a line cut to a column limit leaves, and the characters
			// in front of the cut stay in the text: the far side of reading a
			// floor, which builtin_linear_api_key.go weighs.
			name: "a body one character too short",
			src:  "lin_api_0123456789abcdefghijklmnopqrstuvwxyz012",
		},
		{
			// The hyphen and the underscore are base64url characters and no
			// base62 ones, so either ends a body where the run behind it is
			// too short to be one.
			name: "a body carrying a hyphen",
			src:  "lin_api_0123456789abcdefghij-lmnopqrstuvwxyz0123",
		},
		{
			name: "a body carrying an underscore",
			src:  "lin_api_0123456789abcdefghij_lmnopqrstuvwxyz0123",
		},
		{
			name: "an uppercase prefix",
			src:  "LIN_API_0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			// The prefix is written with the underscore Linear separates its
			// segments by, not with the hyphen a delimiter is elsewhere.
			name: "hyphens where the prefix carries underscores",
			src:  "lin-api-0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			// The prefix closes with an underscore, so a body written straight
			// against api is no body.
			name: "the prefix without its closing underscore",
			src:  "lin_api0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			// The middle segment is read literally rather than as any lowercase
			// word between the underscores, which is what the Stripe scan
			// decided about its own mode segment and for the same reason: three
			// letters and two underscores are not an anchor.
			name: "another word where the prefix carries api",
			src:  "lin_key_0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "a space in the body",
			src:  "lin_api_0123456789abcdefghij lmnopqrstuvwxyz0123",
		},
		{
			name: "a dot in the body",
			src:  "lin_api_0123456789abcdefghij.lmnopqrstuvwxyz0123",
		},
		{
			name: "a body broken by a line break",
			src:  "lin_api_0123456789abcdefghij\nlmnopqrstuvwxyz0123",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// most of the anchor, so a run long enough is not a key without it.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			// A snake_case name whose segment closes on the three letters the
			// prefix opens with. The prefix is there; what turns the name away
			// is the floor, which the next underscore of such a name ends long
			// before.
			name: "a snake case name closing on the prefix",
			src:  "berlin_api_key=1 dublin_api_host=localhost",
		},
		{
			// The unprefixed token Linear's OAuth page still prints, which is a
			// SHA-256 digest's shape exactly.
			name: "sixty-four hexadecimal characters",
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
			if got, _ := LinearAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_LinearAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "LINEAR_API_KEY=lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: "LINEAR_API_KEY=************************************************",
		},
		{
			// The header Linear's own documentation asks for, which carries the
			// key with no Bearer in front of it.
			name: "an authorization header",
			src:  "Authorization: lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: "Authorization: ************************************************",
		},
		{
			name: "json",
			src:  `{"apiKey":"lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123"}`,
			want: `{"apiKey":"************************************************"}`,
		},
		{
			name: "a command line",
			src:  `curl -H "Authorization: lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123" https://api.linear.app/graphql`,
			want: `curl -H "Authorization: ************************************************" https://api.linear.app/graphql`,
		},
		{
			// The environment block a client is configured with.
			name: "a configuration environment block",
			src:  `"env": {"LINEAR_API_KEY": "lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123"}`,
			want: `"env": {"LINEAR_API_KEY": "************************************************"}`,
		},
		{
			name: "twice",
			src:  "lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123 lin_api_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
			want: "************************************************ ************************************************",
		},
		{
			// The two spans are merged, so the key that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a key beginning inside the key before it",
			src:  "lin_api_0123456789abcdefghijklmnopqrstuvwxyz0lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: "*********************************************************************************************",
		},
	}

	m := New(WithPatterns(LinearAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LinearAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xlin_api_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: "x************************************************",
		},
		{
			name: "underscore before",
			src:  "LINEAR_API_KEY_lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: "LINEAR_API_KEY_************************************************",
		},
	}

	m := New(WithPatterns(LinearAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LinearAPIKey_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a floor rather than a count. Where a key ends is
	// where its alphabet stops, so a letter or a digit written straight against
	// a key is redacted with it — which is what buys a key of a length nobody
	// has published being located whole. The alphabet is base62 and not
	// base64url, so the two characters that separate them, the hyphen and the
	// underscore, end a key here where they would carry one on in the OpenAI
	// and Anthropic scans.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the key is lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123.",
			want: "the key is ************************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export LINEAR_API_KEY="lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123"`,
			want: `export LINEAR_API_KEY="************************************************"`,
		},
		{
			name: "a word against the key",
			src:  "lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123suffix",
			want: "******************************************************",
		},
		{
			name: "a dashed word against the key",
			src:  "lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123-suffix",
			want: "************************************************-suffix",
		},
		{
			name: "an underscored word against the key",
			src:  "lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123_suffix",
			want: "************************************************_suffix",
		},
	}

	m := New(WithPatterns(LinearAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LinearAPIKey_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than
	// redacted. A line cut to a column limit partway through a key leaves a
	// prefix and a body too short to be one, and the random characters written
	// before the cut come through whole.
	//
	// It is the price of reading a count no Linear page states, and the cases
	// move with the scan: one of them starting to be located means the floor
	// moved, and that is a decision to be taken rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a key one character short of the floor",
			src:  "LINEAR_API_KEY=lin_api_0123456789abcdefghijklmnopqrstuvwxyz012",
		},
		{
			name: "a key cut off at its prefix",
			src:  "LINEAR_API_KEY=lin_api_",
		},
	}

	m := New(WithPatterns(LinearAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_LinearAPIKey_wordClosingOnThePrefix(t *testing.T) {
	// The over-match builtin_linear_api_key.go declines to rule out, held to
	// the answer it gives rather than to the one a reader might want. The three
	// letters the prefix opens with close ordinary words, so berlin_api_ and
	// dublin_api_ are whole prefixes inside snake_case names; where forty
	// unbroken characters of the alphabet follow one, everything from the lin
	// onward is redacted and only the syllable in front of it stays.
	//
	// The tightening that would rule this out is the demand the Slack and
	// Stripe scans make, that no letter and no digit stand in front of a
	// prefix. It is declined because it would reject the key written inside
	// another, whose prefix stands against the last letter of the body in front
	// of it — the last case below, which the demand would leave in the output
	// with its body whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a word closing on the prefix with a body behind it",
			src:  "berlin_api_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: "ber************************************************",
		},
		{
			name: "a word closing on the prefix with a short segment behind it",
			src:  "dublin_api_key=1",
			want: "dublin_api_key=1",
		},
		{
			name: "a key written inside another, which the demand would reject",
			src:  "lin_api_0123456789abcdefghijklmnopqrstuvwxyz0lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: "*********************************************************************************************",
		},
	}

	m := New(WithPatterns(LinearAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LinearAPIKey_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix carries two
	// underscores, which standard base64 writes nowhere, so only a base64url
	// encoding can hold one — and there eight characters of an alphabet of
	// sixty-four stand where the prefix stands about once in two hundred and
	// eighty million million characters. Where forty base62 characters follow,
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
			src:  "payload=zzzzlin_api_0123456789abcdefghijklmnopqrstuvwxyz0123zzzz",
			want: "payload=zzzz****************************************************",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the
			// Linear pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzlin_api_0123456789abcdefghijklmnopqrstuvwxyz0123zzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz****************************************************",
		},
	}

	m := New(WithPatterns(LinearAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LinearAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_linear_api_key.go names, held to the answer it
	// gives rather than to the one a reader might want. Hexadecimal digits are
	// base62 and a digest carries nothing that ends a run, so a digest of forty
	// characters or more written behind the prefix is a key's format exactly
	// and is redacted. Declining it would mean declining every key Linear wrote
	// in the digits alone, which is the whole credential against a cache key.
	//
	// The two below it are where the floor and the prefix each hold: an MD5 is
	// eight characters short of a body, and a hyphen is no character the prefix
	// carries. The cases move with the scan, so a change to either shows up
	// here as a decision rather than as something the next reader discovers.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sha1 behind the prefix",
			src:  "lin_api_0123456789abcdef0123456789abcdef01234567",
			want: "************************************************",
		},
		{
			name: "a sha256 in a cache key",
			src:  "key: lin_api_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "key: ************************************************************************",
		},
		{
			name: "an md5 behind the prefix, eight characters short of a body",
			src:  "lin_api_0123456789abcdef0123456789abcdef",
			want: "lin_api_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a sha1 behind hyphens rather than the prefix",
			src:  "lin-api-0123456789abcdef0123456789abcdef01234567",
			want: "lin-api-0123456789abcdef0123456789abcdef01234567",
		},
	}

	m := New(WithPatterns(LinearAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LinearAPIKey_theOtherPrefix(t *testing.T) {
	// The prefix this pattern does not read, held to being left in the text.
	// Linear's changelog names lin_oauth_ beside lin_api_ and names nothing
	// else about it, and builtin_linear_api_key.go weighs reading a body
	// nobody has published against leaving an OAuth access token whole.
	//
	// The case is here so that the decision moves with the scan: a body
	// invented for the second prefix would start locating this, and that is a
	// change to be argued for rather than one to be noticed afterwards. The
	// second case is the same prefix with the one thing a reader could mistake
	// for the first written into it, and it is left alone as well.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "an oauth access token",
			src:  "lin_oauth_0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "an oauth access token in an environment assignment",
			src:  "LINEAR_OAUTH_TOKEN=lin_oauth_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	m := New(WithPatterns(LinearAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_linearAPIKeyPrefix(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a key can
	// begin inside the one before it, and that holds only while the prefix
	// opens with characters a body may be written with. Here it is the three in
	// front of the first underscore: a body closing with lin leaves the
	// underscore of the next key standing directly behind it. A prefix opening
	// with a character outside the alphabet would make the two impossible to
	// nest, and the cases above pinning the nesting would stand for nothing —
	// which is not a failure anything else here reports.
	if linearAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	if c := linearAPIKeyPrefix[0]; !isBase62Byte(c) {
		t.Errorf("the prefix opens with %q, which no body may be written with, so no key can begin inside another", c)
	}
}

func Test_linearAPIKeyPrefix_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over
	// it, where a scan whose prefix closes on a character its own body admits
	// has to keep one. What makes the cursor unnecessary is that two
	// candidates can never read the same run: a candidate asks for the last
	// character of the prefix directly in front of its body, no body may be
	// written with it, so the run of an earlier candidate has already ended
	// there and the later candidate's run begins past it. Were that character
	// one a body admits, a run dense in prefixes would be walked once for
	// every candidate in it and the scan would cost time quadratic in the
	// length of such a line.
	if linearAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so there is no candidate to reason about")
	}
	if c := linearAPIKeyPrefix[len(linearAPIKeyPrefix)-1]; isBase62Byte(c) {
		t.Errorf("the prefix closes with %q, which a body may be written with, so two candidates can read the same run", c)
	}
}

// Test_linearAPIKeyAnchor holds the prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from, and to
// the one thing the scan's resume rests on. builtin_scan.go says why the first
// is held here rather than left to the targets.
//
// The resume is the second. A candidate that carries the prefix resumes at its
// body rather than a byte along, which steps over the positions inside the
// prefix, and that is sound only while no key can begin at one of them. The
// prefix carries the character it opens with nowhere else, so none can.
func Test_linearAPIKeyAnchor(t *testing.T) {
	if linearAPIKeyAnchorIndex >= len(linearAPIKeyPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", linearAPIKeyAnchorIndex, len(linearAPIKeyPrefix))
	}
	if c := linearAPIKeyPrefix[linearAPIKeyAnchorIndex]; c != linearAPIKeyAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(linearAPIKeyAnchor))
	}
	if i := strings.IndexByte(linearAPIKeyPrefix[1:], linearAPIKeyPrefix[0]); i >= 0 {
		t.Errorf("the prefix carries %q again at %d, so a key can begin inside one and the resume at the body steps over it",
			linearAPIKeyPrefix[0], i+1)
	}
}

func Test_LinearAPIKey_scanIsLinear(t *testing.T) {
	// A line dense in prefixes holds a candidate for every eight characters it
	// has, whether the scan resumes one byte along or at the body of the
	// candidate it just read — the second only skips positions no key can begin
	// at. The one thing a candidate reads that is a walk over the rest of the
	// input rather than a bounded test is where its run ends, and repeating
	// that walk at every candidate would cost time quadratic in the length of
	// the line. The bound here is far above a linear scan and far below a
	// quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every forty-five bytes where they are densest, because a sample
	// has to carry a whole body to be one. The crowding a line can actually
	// carry, a candidate every eight bytes, stays here.
	sources := map[string]string{
		// Candidates as close together as the prefix allows, none of them with
		// a run long enough to be a body: every one reaches the body of the
		// loop and every one is rejected.
		"a candidate every eight characters": strings.Repeat("lin_api_", 250000),
		// Keys written into one another, each beginning three characters before
		// the one in front of it ends, so every candidate is a key and every
		// one of them walks a run.
		"a key beginning inside every key": strings.Repeat("lin_api_0123456789abcdefghijklmnopqrstuvwxyz0", 40000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a key.
		"a body that runs the length of the line": "lin_api_" + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("a_", 900000),
		// And the prefix's own letters with no anchor among them, which is the
		// walk reading a whole line and stopping nowhere in it.
		"the letters of the prefix with no anchor": strings.Repeat("linapi", 300000),
	}

	checkScanIsLinear(t, LinearAPIKey(), sources)
}

// referenceLinearAPIKey is the expression the scan in
// builtin_linear_api_key.go reads by hand: the statement of what a Linear API
// key is, kept here so that the scan can be held to it.
//
// The prefix, the floor and the alphabet are spelled again rather than built
// from linearAPIKeyPrefix, linearAPIKeyBodyChars and isBase62Byte. A reference
// sharing those declarations could not disagree with the scan about them, and
// it is exactly that disagreement the fuzz target below is for: the two have to
// be changed together or reported apart.
//
// The floor is written as a counted repetition, which is what the Anthropic
// reference is written out by hand to avoid. It costs nothing here, and for the
// reason the scan needs no cursor: candidates cannot crowd inside one run, so
// no input makes an engine walk the same run more than once.
var referenceLinearAPIKey = regexp.MustCompile(`lin_api_[0-9A-Za-z]{40,}`)

// referenceLinearAPIKeyFind locates keys the plain way: the leftmost match of
// the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a key can begin inside one: the three letters
// the prefix opens with are written in the alphabet a body is, so a body
// closing with lin holds the start of the key behind it. The scan finds both
// and reports the two spans overlapping for a Masker to resolve, so the
// reference must ask about both.
func referenceLinearAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceLinearAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzLinearAPIKey_matchesReference guards the hand-written scan: the prefix it
// searches for, the floor it holds a body to, the alphabet it reads that body
// in and the byte it resumes at may none of them change which keys are located.
func FuzzLinearAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("LINEAR_API_KEY=lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123")
	f.Add("lin_api_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123")
	f.Add("lin_api_0123456789abcdefghijklmnopqrstuvwxyz012")   // one short of a body
	f.Add("lin_api_0123456789abcdefghijklmnopqrstuvwxyz01234") // and a run longer than one
	f.Add("lin_api_0123456789abcdefghij-lmnopqrstuvwxyz0123")  // a hyphen, which base64url admits and base62 does not
	f.Add("lin_api_0123456789abcdefghij_lmnopqrstuvwxyz0123")  // an underscore, likewise
	f.Add("lin_api_0123456789abcdefghij.lmnopqrstuvwxyz0123")  // a dot ends the body
	f.Add("LIN_API_0123456789abcdefghijklmnopqrstuvwxyz0123")  // an uppercase prefix
	f.Add("lin-api-0123456789abcdefghijklmnopqrstuvwxyz0123")  // hyphens where the prefix carries underscores
	f.Add("lin_api0123456789abcdefghijklmnopqrstuvwxyz0123")   // the prefix without its closing underscore
	f.Add("lin_key_0123456789abcdefghijklmnopqrstuvwxyz0123")  // another word where the prefix carries api
	f.Add("lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123-suffix")
	f.Add("lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123_suffix")
	f.Add("lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123\nlin_api_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123")
	// A key beginning inside the match before it, which a scan resuming past a
	// match steps over, and two keys with nothing between them.
	f.Add("lin_api_0123456789abcdefghijklmnopqrstuvwxyz0lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123")
	f.Add("lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123lin_api_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123")
	// Candidate positions crowded as close as they can be, with no run long
	// enough for any of them, and keys written into one another so that every
	// candidate has one.
	f.Add(strings.Repeat("lin_api_", 16))
	f.Add(strings.Repeat("lin_api_0123456789abcdefghijklmnopqrstuvwxyz0", 4))
	// A digest written behind the prefix, which is a key's format exactly, and
	// one eight characters short of a body.
	f.Add("lin_api_0123456789abcdef0123456789abcdef01234567")
	f.Add("key: lin_api_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("lin_api_0123456789abcdef0123456789abcdef")
	// A snake_case name closing on the three letters the prefix opens with,
	// with a body behind it and with a segment too short to be one.
	f.Add("berlin_api_0123456789abcdefghijklmnopqrstuvwxyz0123")
	f.Add("berlin_api_key=1 dublin_api_host=localhost")
	// The prefix Linear names beside this one and this pattern does not read.
	f.Add("lin_oauth_0123456789abcdefghijklmnopqrstuvwxyz0123")
	f.Add("LINEAR_OAUTH_TOKEN=lin_oauth_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// The prefix written inside a run of base64url, which is the over-match the
	// pattern admits.
	f.Add("payload=zzzzlin_api_0123456789abcdefghijklmnopqrstuvwxyz0123zzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzlin_api_0123456789abcdefghijklmnopqrstuvwxyz0123zzzz")

	fuzzAgainstReference(f, LinearAPIKey().Find, referenceLinearAPIKeyFind)
}

// linearAPIKeyFindBenchmarks is what this scan is timed on. The builtinPatterns
// entry for the pattern names it, and BenchmarkBuiltins times every case it
// holds under the pattern's own name, so that a built-in cannot arrive without
// a benchmark. Every case is held to the count it states under a plain go test
// as well, which is what a benchmark nobody has run yet cannot be.
func linearAPIKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="creating an issue" url=https://api.linear.app/graphql `
	key := "lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every eight characters with no run long enough behind
			// any of them: each reaches the body of the loop and none becomes a
			// key. What it times is the walk over a run being started and
			// stopped, once per candidate and no more.
			name:  "candidates that are not values",
			src:   strings.Repeat("lin_api_", 128),
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
			src:   strings.Repeat("lin_api_0123456789abcdefghijklmnopqrstuvwxyz0", 128) + "lin",
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
