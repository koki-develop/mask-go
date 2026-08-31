package mask

import (
	"slices"
	"strings"
	"testing"
)

// The Anthropic API key pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. The run they are built from, 0123456789abcdef, is
// written out until the body is ninety-five characters, which is the shortest
// the scan reads — a floor, unlike the runs the OpenAI cases stand in for, so a
// body shortened for readability would leave a case holding no key at all.

func Test_AnthropicAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a console key on its own",
			src:  "sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{0, 108}},
		},
		{
			name: "a console key in an environment assignment",
			src:  "ANTHROPIC_API_KEY=sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{18, 126}},
		},
		{
			name: "an admin api key",
			src:  "sk-ant-admin01-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{0, 110}},
		},
		{
			// The token claude setup-token mints, which Anthropic writes with
			// a kind of its own and otherwise exactly as it writes a key.
			name: "an oauth access token",
			src:  "sk-ant-oat01-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{0, 108}},
		},
		{
			// A session key is written sid01 and sid02 both. The version is
			// read as part of the kind rather than recognised, so the one
			// added later is located like the one it was added beside.
			name: "a session key of the version added beside sid01",
			src:  "sk-ant-sid02-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{0, 108}},
		},
		{
			name: "a kind the scan carries no name for",
			src:  "sk-ant-zzz99-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{0, 108}},
		},
		{
			// The hyphen and the underscore are base64url characters, and both
			// rulesets stating a shape admit them in a body.
			name: "a body carrying a hyphen and an underscore",
			src:  "sk-ant-api03-0123456789abcdef-123456789abcdef_123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{0, 108}},
		},
		{
			// The count is a floor and the span reaches the end of the run, so
			// a run longer than the shortest body is a key to the end of it
			// rather than a key and a character left over.
			name: "a run longer than the shortest body",
			src:  "sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdez",
			want: []Span{{0, 109}},
		},
		{
			name: "two keys separated by a space",
			src:  "sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde sk-ant-admin01-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{0, 108}, {109, 219}},
		},
		{
			// The prefix is written in the alphabet a body is, so a key can
			// begin inside the span of the one before it, and a scan resuming
			// past a match would step over it. The spans overlap, which a
			// Masker resolves into one.
			name: "a key beginning inside the key before it",
			src:  "sk-ant-a-sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{0, 117}, {9, 117}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AnthropicAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AnthropicAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "sk-ant-",
		},
		{
			name: "a prefix and a kind with no body behind them",
			src:  "sk-ant-api03-",
		},
		{
			// Ninety-four characters where the pattern asks for ninety-five.
			// This is the shape a line cut to a column limit leaves, and the
			// characters in front of the cut stay in the text: the far side of
			// reading a floor, which builtin_anthropic_api_key.go weighs.
			name: "a body one character too short",
			src:  "sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		},
		{
			// A body long enough with no kind and no separator in front of it.
			// The kind is read to the first hyphen behind the prefix, and here
			// the run holds none at all.
			name: "no kind between the prefix and the body",
			src:  "sk-ant-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "an uppercase kind",
			src:  "sk-ant-API03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// The kind is closed by a hyphen, which is what divides it from a
			// body that may carry hyphens of its own. An underscore in that
			// place divides nothing.
			name: "an underscore where the kind is closed by a hyphen",
			src:  "sk-ant-api03_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "an uppercase prefix",
			src:  "SK-ANT-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// The prefix is seven characters and all seven are read.
			name: "an underscore where the prefix carries a hyphen",
			src:  "sk_ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "six characters of the prefix",
			src:  "sk-anx-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "a space in the body",
			src:  "sk-ant-api03-0123456789abcdef0123456789abcdef012345 789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "a dot in the body",
			src:  "sk-ant-api03-0123456789abcdef0123456789abcdef012345.789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// Standard base64 rather than base64url: the two characters
			// base64url writes as - and _ are + and /, and neither belongs to
			// the alphabet a body is read in.
			name: "a plus in the body",
			src:  "sk-ant-api03-0123456789abcdef0123456789abcdef012345+789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "a slash in the body",
			src:  "sk-ant-api03-0123456789abcdef0123456789abcdef012345/789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "a body broken by a line break",
			src:  "sk-ant-api03-0123456789abcdef0123456789abcdef012345\n789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// the whole of the anchor, so a run long enough is not a key
			// without it.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// The prefix carries two hyphens, so it stands inside ordinary
			// kebab-case text: task-ant- holds it three characters in. What
			// turns this away is the count the body is held to, which is the
			// work the floor does besides stating what Anthropic issues.
			name: "a hyphenated word carrying the prefix",
			src:  "the task-ant-colony-optimization-benchmark-suite was reviewed",
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
			if got, _ := AnthropicAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_AnthropicAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "ANTHROPIC_API_KEY=sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: "ANTHROPIC_API_KEY=************************************************************************************************************",
		},
		{
			name: "quoted",
			src:  `"sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"`,
			want: `"************************************************************************************************************"`,
		},
		{
			name: "json",
			src:  `{"apiKey":"sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"}`,
			want: `{"apiKey":"************************************************************************************************************"}`,
		},
		{
			// The header the Claude API takes a key in.
			name: "an x-api-key header",
			src:  "x-api-key: sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: "x-api-key: ************************************************************************************************************",
		},
		{
			name: "a command line",
			src:  "curl -H 'x-api-key: sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde' https://api.anthropic.com/v1/messages",
			want: "curl -H 'x-api-key: ************************************************************************************************************' https://api.anthropic.com/v1/messages",
		},
		{
			name: "twice",
			src:  "sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde sk-ant-admin01-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: "************************************************************************************************************ **************************************************************************************************************",
		},
		{
			// The two spans are merged, so the key that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a key beginning inside the key before it",
			src:  "sk-ant-a-sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: "*********************************************************************************************************************",
		},
	}

	m := New(WithPatterns(AnthropicAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AnthropicAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xsk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: "x************************************************************************************************************",
		},
		{
			name: "underscore before",
			src:  "ANTHROPIC_API_KEY_sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: "ANTHROPIC_API_KEY_************************************************************************************************************",
		},
	}

	m := New(WithPatterns(AnthropicAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AnthropicAPIKey_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a floor rather than a count. Where a key ends is
	// where its alphabet stops, so ordinary punctuation ends one and nothing
	// written after it joins it — but a character of the key's own alphabet
	// written straight against a key is redacted with the key, which is what
	// buys a key of a length neither Anthropic nor a ruleset states being
	// located whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the key is sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde.",
			want: "the key is ************************************************************************************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export ANTHROPIC_API_KEY="sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"`,
			want: `export ANTHROPIC_API_KEY="************************************************************************************************************"`,
		},
		{
			// The hyphen is a body character, so a hyphenated word written
			// against a key is read as more of the run and redacted with it.
			name: "a dashed word against the key",
			src:  "sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde-suffix",
			want: "*******************************************************************************************************************",
		},
		{
			name: "a word against the key",
			src:  "sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdesuffix",
			want: "******************************************************************************************************************",
		},
	}

	m := New(WithPatterns(AnthropicAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AnthropicAPIKey_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than
	// redacted. A line cut to a column limit partway through a key leaves a
	// prefix, a kind and a body too short to be one, and the random characters
	// written before the cut come through whole.
	//
	// It is the one thing this scan gives up that the OpenAI scan beside it
	// does not, and it is the price of a grammar with nothing but length to
	// tell a credential from a hyphenated identifier. The cases move with the
	// scan: one of them starting to be located means the floor moved, and that
	// is a decision to be taken rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a key one character short of the floor",
			src:  "ANTHROPIC_API_KEY=sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		},
		{
			name: "a key cut off at its kind",
			src:  "ANTHROPIC_API_KEY=sk-ant-api03",
		},
	}

	m := New(WithPatterns(AnthropicAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_AnthropicAPIKey_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix is seven
	// characters of an alphabet of sixty-four, so a long enough base64url value
	// carries it, and where a kind, a separator and ninety-five characters
	// follow inside the same run, everything from the prefix to the end of that
	// run is redacted.
	//
	// The cases are held to being redacted rather than to being spared. What
	// is taken is a stretch of a value already opaque to a reader, and the
	// only tightening on offer is the table of kind names;
	// builtin_anthropic_api_key.go sets out why this scan does not read it.
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
			src:  "payload=zzzzsk-ant-a-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdezzzz",
			want: "payload=zzzz************************************************************************************************************",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the
			// Anthropic pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzsk-ant-a-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdezzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz************************************************************************************************************",
		},
	}

	m := New(WithPatterns(AnthropicAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_anthropicAPIKeyPrefix(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a key can
	// begin inside the body of the one before it, and that holds only while
	// every character of the prefix is one a body may be written in. A prefix
	// carrying a character outside the alphabet would make the two impossible
	// to nest, and the case above pinning the nesting would stand for nothing —
	// which is not a failure anything else here reports.
	if anthropicAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for i := range len(anthropicAPIKeyPrefix) {
		if c := anthropicAPIKeyPrefix[i]; !isBase64URLByte(c) {
			t.Errorf("the prefix holds %q, which no body may be written with", c)
		}
	}
}

// Test_anthropicAPIKeyAnchor holds the prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_anthropicAPIKeyAnchor(t *testing.T) {
	if anthropicAPIKeyAnchorIndex >= len(anthropicAPIKeyPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", anthropicAPIKeyAnchorIndex, len(anthropicAPIKeyPrefix))
	}
	if c := anthropicAPIKeyPrefix[anthropicAPIKeyAnchorIndex]; c != anthropicAPIKeyAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(anthropicAPIKeyAnchor))
	}
}

func Test_anthropicAPIKeyPrefix_bodyNeverMovesBack(t *testing.T) {
	// The scan keeps one run cursor for every candidate and reuses it wherever
	// a body begins inside the run already read. That is sound only while a
	// body never begins in front of the body of the candidate before it: were
	// one to, the cursor would answer for a stretch of run it had never looked
	// at, and a key there would be missed rather than mislocated. The walk over
	// a kind is bounded by the same thing — it stops at the first character no
	// kind may hold — and without it a line dense in prefixes would be walked
	// once for every candidate in it.
	//
	// Both rest on one character: the last of the prefix, which no kind may be
	// written with. A later candidate carries it, an earlier candidate's kind
	// carries nothing like it, so the later candidate cannot begin before that
	// kind has ended. Everything else about the two follows, which is why this
	// is what is checked rather than the pair of consequences.
	if anthropicAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so there is no candidate to reason about")
	}
	if c := anthropicAPIKeyPrefix[len(anthropicAPIKeyPrefix)-1]; isAnthropicAPIKeyKindByte(c) {
		t.Errorf("the prefix closes with %q, which a kind may be written with, so a candidate can begin inside the kind of the one before it", c)
	}
}

func Test_anthropicAPIKeySeparator(t *testing.T) {
	// The separator divides the kind from the body, so it has to be a character
	// a kind cannot hold — otherwise the walk over a kind would run straight
	// through it and no candidate would ever have a body — and one a body can,
	// since a body carries hyphens of its own and only the first behind the
	// prefix divides the two.
	if isAnthropicAPIKeyKindByte(anthropicAPIKeySeparator) {
		t.Errorf("the separator %q is a character a kind may be written with, so nothing closes a kind", anthropicAPIKeySeparator)
	}
	if !isBase64URLByte(anthropicAPIKeySeparator) {
		t.Errorf("the separator %q is no character a body may be written with", anthropicAPIKeySeparator)
	}
}

func Test_isAnthropicAPIKeyKindByte(t *testing.T) {
	// The alphabet a kind is written in, stated over every byte rather than by
	// example: the lowercase letters and the digits, and neither the hyphen nor
	// the underscore a body admits.
	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9' || 'a' <= b && b <= 'z'
		if got := isAnthropicAPIKeyKindByte(b); got != want {
			t.Errorf("isAnthropicAPIKeyKindByte(%q) = %v, want %v", b, got, want)
		}
	}
}

func Test_anthropicAPIKeyBodyAt(t *testing.T) {
	// Where a body begins, and where the scan is told there is none. The count
	// the body then runs to is the scan's to measure against the run, so what
	// is stated here is only the division the prefix and the kind make.
	tests := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "a kind of one character",
			src:  "sk-ant-a-body",
			want: 9,
		},
		{
			name: "a kind carrying digits",
			src:  "sk-ant-api03-body",
			want: 13,
		},
		{
			name: "a body opening with a hyphen of its own",
			src:  "sk-ant-a--body",
			want: 9,
		},
		{
			name: "no kind at all",
			src:  "sk-ant--body",
			want: -1,
		},
		{
			name: "a kind closed by nothing",
			src:  "sk-ant-api03",
			want: -1,
		},
		{
			name: "a kind closed by an underscore",
			src:  "sk-ant-api03_body",
			want: -1,
		},
		{
			name: "a kind carrying an uppercase letter",
			src:  "sk-ant-Api03-body",
			want: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := anthropicAPIKeyBodyAt(tt.src, 0); got != tt.want {
				t.Errorf("anthropicAPIKeyBodyAt(%q, 0) = %d, want %d", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AnthropicAPIKey_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a run dense in prefixes
	// holds a candidate for every nine characters it has. Two things a
	// candidate reads are walks over the rest of the input rather than bounded
	// tests — where its run ends, and where its kind ends — and repeating
	// either at every candidate costs time quadratic in the length of the line.
	// The bound here is far above a linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every fifty-eight bytes where they are densest, because a
	// sample has to carry a whole body to be one. The crowding a run can
	// actually carry, a candidate every nine bytes, stays here.
	sources := map[string]string{
		// One run, a candidate every nine characters, and every one of them a
		// key reaching the end of it: the run cursor is walked once and read
		// two hundred thousand times.
		"a candidate every nine characters in one run": strings.Repeat("sk-ant-a-", 200000),
		// The same crowding with every run ended before a body can begin, so
		// every candidate is rejected and the cursor is moved at each of them.
		"a candidate every nine characters, none with a run": strings.Repeat("sk-ant-a-.", 200000),
		// A kind longer than the distance between candidates, so the walks over
		// two kinds would overlap were either repeated.
		"a long kind at every candidate": strings.Repeat("sk-ant-aaaaaaaaaa-", 100000),
		// One candidate whose kind is never closed, which is the walk over a
		// kind reading the whole line and finding nothing.
		"a kind that runs the length of the line": "sk-ant-" + strings.Repeat("a", 1800000),
		// One candidate whose body is the whole line, which is the walk over a
		// run doing the same and finding a key.
		"a body that runs the length of the line": "sk-ant-a-" + strings.Repeat("a", 1800000),
	}

	checkScanIsLinear(t, AnthropicAPIKey(), sources)
}

// referenceAnthropicAPIKeyFind locates keys the plain way: every position in
// turn, the prefix tried at it, the kind behind that walked to its end and the
// body walked to the end of its run, with no cursor and nothing remembered
// between candidates. The prefix, the separator, the floor and the two
// character classes are spelled again here rather than shared with the scan. A
// reference reading those declarations could not disagree with it about them,
// and it is exactly that disagreement the fuzz target below is for: the two
// have to be changed together or reported apart.
//
// Every position is a starting point in its own right, a match included,
// because the prefix is written in the alphabet a body is: sk-ant-a-sk-ant-...
// holds a key beginning inside the match before it. The scan finds both and
// reports the two spans overlapping for a Masker to resolve, so the reference
// must ask about both.
//
// It is written out rather than built on a regular expression, for a reason of
// its own: the grammar states compactly as
// sk-ant-[0-9a-z]+-[0-9A-Za-z_-]{95,}, but a counted repetition is what an
// engine has the least room to skip, and greedy repetition behind one makes it
// re-walk the run at every candidate through a machine ninety-five states
// wide. Measured on sk-ant-a- written over and over, that expression costs
// thirteen seconds on a hundred and fifteen kilobytes where the walks below
// cost a third of one — and the mutator reaches such an input within seconds,
// which left the fuzz target wedged on it for the rest of its run and buying
// almost no fuzzing at all.
//
// Walking the run at every position is what the cursor saves the scan from, so
// this still costs time quadratic in the length of a run the prefix can be
// written inside: a third of a second against a hundred microseconds in the
// scan, at that size. That is the price of a reference with no cursor to be
// wrong about, and the reason the seeds below keep such a run under two hundred
// bytes rather than inviting the mutator to grow it. Test_builtins_scanIsLinear
// and Test_AnthropicAPIKey_scanIsLinear are where the cost the scan pays is
// held down.
func referenceAnthropicAPIKeyFind(src string) []Span {
	const (
		prefix    = "sk-ant-"
		separator = '-'
		bodyChars = 95
	)

	kind := func(c byte) bool { return '0' <= c && c <= '9' || 'a' <= c && c <= 'z' }
	body := func(c byte) bool {
		return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || c == '-' || c == '_'
	}

	var spans []Span
	for start := range len(src) {
		if !strings.HasPrefix(src[start:], prefix) {
			continue
		}

		from := start + len(prefix)
		i := from
		for i < len(src) && kind(src[i]) {
			i++
		}
		if i == from || i == len(src) || src[i] != separator {
			continue
		}

		at := i + 1
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

// FuzzAnthropicAPIKey_matchesReference guards the hand-written scan: the prefix
// it searches for, the alphabet it reads a kind in, the separator it asks that
// kind to be closed by, the floor it holds a body to, the alphabet it reads
// that body in, the run it remembers between candidates and the byte it resumes
// at may none of them change which keys are located.
func FuzzAnthropicAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("ANTHROPIC_API_KEY=sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	f.Add("sk-ant-admin01-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	f.Add("sk-ant-oat01-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	f.Add("sk-ant-sid02-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	f.Add("sk-ant-zzz99-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")  // a kind the scan carries no name for
	f.Add("sk-ant-api03-0123456789abcdef-123456789abcdef_123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")  // a hyphen and an underscore in the body
	f.Add("sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd")   // one short of a body
	f.Add("sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdez") // and a run longer than one
	f.Add("sk-ant-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")        // no kind between the prefix and the body
	f.Add("sk-ant-API03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")  // an uppercase kind
	f.Add("sk-ant-api03_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")  // an underscore where the kind is closed by a hyphen
	f.Add("SK-ANT-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")  // an uppercase prefix
	f.Add("sk_ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")  // an underscore where the prefix carries a hyphen
	f.Add("sk-ant-api03-0123456789abcdef0123456789abcdef012345+789abcdef0123456789abcdef0123456789abcdef0123456789abcde")  // standard base64 rather than base64url
	f.Add("sk-ant-api03-0123456789abcdef0123456789abcdef012345.789abcdef0123456789abcdef0123456789abcdef0123456789abcde")  // a dot ends the body
	f.Add("sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde-suffix")
	f.Add("sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde\nsk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	// A key beginning inside the match before it, which a scan resuming past a
	// match steps over, and two keys with nothing between them.
	f.Add("sk-ant-a-sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	f.Add("sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdesk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	// Candidate positions crowded as close as they can be: a body long enough
	// for all of them, a body long enough for none, and a kind that is never
	// closed.
	f.Add(strings.Repeat("sk-ant-a-", 8) + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	f.Add(strings.Repeat("sk-ant-a-.", 12))
	f.Add("sk-ant-" + strings.Repeat("a", 96))
	f.Add(strings.Repeat("sk-ant-aaaaaaaaaa-", 8))
	// A hyphenated word carrying the prefix, which only the floor turns away.
	f.Add("the task-ant-colony-optimization-benchmark-suite was reviewed")
	// The prefix written inside a run of the alphabet, which is the over-match
	// the pattern admits.
	f.Add("payload=zzzzsk-ant-a-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdezzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzsk-ant-a-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdezzzz")

	fuzzAgainstReference(f, AnthropicAPIKey().Find, referenceAnthropicAPIKeyFind)
}

// anthropicAPIKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func anthropicAPIKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling the messages API" url=https://api.anthropic.com/v1/messages `
	key := "sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every nine characters with every run ended before a
			// body can begin: each of them reaches the body of the loop and
			// none becomes a key. What it times is the walk over a kind and the
			// run cursor being moved, once per candidate and no more.
			name:  "candidates that are not values",
			src:   strings.Repeat("sk-ant-a-.", 128),
			spans: 0,
		},
		{
			// The same crowding inside one run long enough for every candidate,
			// so each locates a key and every span reaches the same place. This
			// is what the run cursor exists for: without it the run is read
			// once per candidate.
			name:  "candidates crowded in one run",
			src:   strings.Repeat("sk-ant-a-", 128) + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
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
