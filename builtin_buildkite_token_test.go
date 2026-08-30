package mask

import (
	"slices"
	"strings"
	"testing"
)

// The Buildkite token pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. The run they are built from,
// 0123456789abcdef0123456789abcdef01234567, is forty characters and so is a
// whole token body — the shortest the scan reads, since the count is a floor,
// so a body shortened for readability would leave a case holding no token at
// all. It is written in lowercase where the case does not matter and in
// uppercase where the case is what a case is about: base64url holds the letters
// of both, so either spelling is a body.

const (
	buildkiteBody      = "0123456789abcdef0123456789abcdef01234567"
	buildkiteUpperBody = "0123456789ABCDEF0123456789ABCDEF01234567"
)

func Test_BuildkiteToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an api access token",
			src:  "bkua_" + buildkiteBody,
			want: []Span{{0, 45}},
		},
		{
			name: "an agent session token",
			src:  "bkaa_" + buildkiteBody,
			want: []Span{{0, 45}},
		},
		{
			name: "an agent job token",
			src:  "bkaj_" + buildkiteBody,
			want: []Span{{0, 45}},
		},
		{
			name: "an unclustered agent token",
			src:  "bkar_" + buildkiteBody,
			want: []Span{{0, 45}},
		},
		{
			name: "an agent token",
			src:  "bkct_" + buildkiteBody,
			want: []Span{{0, 45}},
		},
		{
			name: "a registry token",
			src:  "bkpt_" + buildkiteBody,
			want: []Span{{0, 45}},
		},
		{
			name: "a portal secret",
			src:  "bkps_" + buildkiteBody,
			want: []Span{{0, 45}},
		},
		{
			name: "a token exchange token",
			src:  "bktx_" + buildkiteBody,
			want: []Span{{0, 45}},
		},
		{
			// The two kinds whose acronym is three characters, so the
			// separator stands one byte further along than it does above.
			name: "a portal token",
			src:  "bkpat_" + buildkiteBody,
			want: []Span{{0, 46}},
		},
		{
			name: "a job acquisition token",
			src:  "bkjat_" + buildkiteBody,
			want: []Span{{0, 46}},
		},
		{
			name: "a token in an environment assignment",
			src:  "BUILDKITE_API_TOKEN=bkua_" + buildkiteBody,
			want: []Span{{20, 65}},
		},
		{
			// base64url holds the letters of both cases, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "bkua_" + buildkiteUpperBody,
			want: []Span{{0, 45}},
		},
		{
			// The hyphen and the underscore are what separate base64url from
			// base62, and both belong to a body here: betterleaks admits them
			// behind seven of the ten prefixes. A body carrying one runs
			// through it rather than ending at it.
			name: "a body carrying a hyphen",
			src:  "bkua_0123456789abcdef-0123456789abcdef01234567",
			want: []Span{{0, 46}},
		},
		{
			name: "a body carrying an underscore",
			src:  "bkua_0123456789abcdef_0123456789abcdef01234567",
			want: []Span{{0, 46}},
		},
		{
			// The count is a floor and the span reaches the end of the run, so
			// a run longer than the shortest body is a token to the end of it
			// rather than a token and a character left over.
			name: "a run longer than the shortest body",
			src:  "bkua_" + buildkiteBody + "0",
			want: []Span{{0, 46}},
		},
		{
			name: "two tokens separated by a space",
			src:  "bkua_" + buildkiteBody + " bkct_" + buildkiteUpperBody,
			want: []Span{{0, 45}, {46, 91}},
		},
		{
			// A prefix is written in the alphabet a body is, the underscore
			// closing it included, so a whole prefix can stand inside a body.
			// The second token begins five characters into the first and both
			// bodies run to the same place, so the two spans overlap and a
			// scan resuming past a match would step over the second.
			name: "a token beginning inside the token before it",
			src:  "bkua_bkct_" + buildkiteBody,
			want: []Span{{0, 50}, {5, 50}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := BuildkiteToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_BuildkiteToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "bkua_",
		},
		{
			// Thirty-nine characters where the pattern asks for forty. This is
			// the shape a line cut to a column limit leaves, and the characters
			// in front of the cut stay in the text: the far side of reading a
			// floor, which builtin_buildkite_token.go weighs.
			name: "a body one character too short",
			src:  "bkua_0123456789abcdef0123456789abcdef0123456",
		},
		{
			name: "an uppercase prefix",
			src:  "BKUA_" + buildkiteBody,
		},
		{
			// The prefix closes with an underscore, so a hyphen written in its
			// place opens no candidate at all.
			name: "a hyphen where the prefix carries an underscore",
			src:  "bkua-" + buildkiteBody,
		},
		{
			name: "an acronym Buildkite names no token with",
			src:  "bkzz_" + buildkiteBody,
		},
		{
			// A character written into an acronym moves the separator off both
			// depths a kind may close at, so the position opens nothing.
			name: "a character written into an acronym",
			src:  "bkuaa_" + buildkiteBody,
		},
		{
			name: "the opening with no acronym behind it",
			src:  "bk_" + buildkiteBody,
		},
		{
			name: "a space in the body",
			src:  "bkua_0123456789abcdef 0123456789abcdef01234567",
		},
		{
			// The dot belongs to neither base64url nor the text a body is read
			// as, and it is what an ordinary sentence and an ordinary path are
			// broken by, so it ends a body where a hyphen and an underscore
			// carry one on.
			name: "a dot in the body",
			src:  "bkua_0123456789abcdef.0123456789abcdef01234567",
		},
		{
			name: "a body broken by a line break",
			src:  "bkua_0123456789abcdef\n0123456789abcdef01234567",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// the whole of the anchor, so a run long enough is not a token
			// without it.
			name: "a run of the right length opening with no prefix",
			src:  buildkiteBody,
		},
		{
			// The value standing in the URL of a pipeline trigger. Buildkite
			// neither calls it a token nor lists it among them, so its acronym
			// is in no prefix here and the URL comes through whole.
			name: "the value in a pipeline trigger url",
			src:  "https://webhook.buildkite.com/deliver/bktr_0123456789ab",
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
			if got, _ := BuildkiteToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_BuildkiteToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "BUILDKITE_API_TOKEN=bkua_" + buildkiteBody,
			want: "BUILDKITE_API_TOKEN=" + strings.Repeat("*", 45),
		},
		{
			// The header a request to the REST and GraphQL APIs carries a token
			// in.
			name: "an authorization header",
			src:  "Authorization: Bearer bkua_" + buildkiteBody,
			want: "Authorization: Bearer " + strings.Repeat("*", 45),
		},
		{
			name: "json",
			src:  `{"access_token":"bktx_` + buildkiteBody + `"}`,
			want: `{"access_token":"` + strings.Repeat("*", 45) + `"}`,
		},
		{
			// The agent configuration file, whose own name carries the letters
			// the opening is written with.
			name: "an agent configuration line",
			src:  `token="bkct_` + buildkiteBody + `"`,
			want: `token="` + strings.Repeat("*", 45) + `"`,
		},
		{
			name: "a command line",
			src:  "buildkite-agent start --token bkct_" + buildkiteBody,
			want: "buildkite-agent start --token " + strings.Repeat("*", 45),
		},
		{
			name: "twice",
			src:  "bkua_" + buildkiteBody + " bkct_" + buildkiteUpperBody,
			want: strings.Repeat("*", 45) + " " + strings.Repeat("*", 45),
		},
		{
			// The two spans are merged, so the token that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a token beginning inside the token before it",
			src:  "bkua_bkct_" + buildkiteBody,
			want: strings.Repeat("*", 50),
		},
	}

	m := New(WithPatterns(BuildkiteToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_BuildkiteToken_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the token through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xbkua_" + buildkiteBody,
			want: "x" + strings.Repeat("*", 45),
		},
		{
			name: "underscore before",
			src:  "BUILDKITE_API_TOKEN_bkua_" + buildkiteBody,
			want: "BUILDKITE_API_TOKEN_" + strings.Repeat("*", 45),
		},
	}

	m := New(WithPatterns(BuildkiteToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_BuildkiteToken_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a floor rather than a count. Where a token ends
	// is where its alphabet stops, so a character of base64url written straight
	// against a token is redacted with it — which is what buys a token of a
	// length Buildkite has not published being located whole. The hyphen and
	// the underscore belong to that alphabet, so a hyphenated or underscored
	// word written against a token goes with it; a space and a dot do not.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the token is bkua_" + buildkiteBody + ".",
			want: "the token is " + strings.Repeat("*", 45) + ".",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export BUILDKITE_API_TOKEN="bkua_` + buildkiteBody + `"`,
			want: `export BUILDKITE_API_TOKEN="` + strings.Repeat("*", 45) + `"`,
		},
		{
			name: "a word against the token",
			src:  "bkua_" + buildkiteBody + "suffix",
			want: strings.Repeat("*", 51),
		},
		{
			name: "a dashed word against the token",
			src:  "bkua_" + buildkiteBody + "-suffix",
			want: strings.Repeat("*", 52),
		},
		{
			name: "an underscored word against the token",
			src:  "bkua_" + buildkiteBody + "_suffix",
			want: strings.Repeat("*", 52),
		},
	}

	m := New(WithPatterns(BuildkiteToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_BuildkiteToken_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than
	// redacted. The first two are what a floor costs anywhere: a line cut to a
	// column limit partway through a token leaves a prefix and a body too short
	// to be one, and the random characters written before the cut come through
	// whole.
	//
	// The third is this pattern's own. None of the counts a ruleset states is
	// Buildkite's, two of the ten kinds have no count from any source, and one
	// floor is read for all ten — so a kind written shorter than forty would be
	// located nowhere rather than located short. The cases move with the scan:
	// one of them starting to be located means the floor moved, and that is a
	// decision to be taken rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a token one character short of the floor",
			src:  "BUILDKITE_API_TOKEN=bkua_0123456789abcdef0123456789abcdef0123456",
		},
		{
			name: "a token cut off at its prefix",
			src:  "BUILDKITE_API_TOKEN=bkua_",
		},
		{
			name: "a whole body of thirty-two characters",
			src:  "BUILDKITE_API_TOKEN=bkua_0123456789abcdef0123456789abcdef",
		},
	}

	m := New(WithPatterns(BuildkiteToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_BuildkiteToken_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. A prefix carries an
	// underscore, which standard base64 writes nowhere, so only a base64url
	// encoding can hold one — and there the five characters of a prefix stand
	// about once in a hundred and thirty million characters. The run from such
	// a prefix to the end of the encoding is then redacted.
	//
	// The cases are held to being redacted rather than to being spared. What is
	// taken is a stretch of a value already opaque to a reader, and the run is a
	// token's format exactly: nothing is left in the text to tell the two apart,
	// so a pattern letting it through would let a real token through with it.
	// What the cases are for is that they move with the scan: one of them
	// ceasing to be located means the grammar changed, and that is a decision to
	// be taken rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "inside a base64url payload",
			src:  "payload=zzzzbkua_" + buildkiteBody + "zzzz",
			want: "payload=zzzz" + strings.Repeat("*", 49),
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the
			// Buildkite pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzbkua_" + buildkiteBody + "zzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz" + strings.Repeat("*", 49),
		},
	}

	m := New(WithPatterns(BuildkiteToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_BuildkiteToken_anIdentifierBehindThePrefix(t *testing.T) {
	// The residue builtin_buildkite_token.go names, held to the answer it gives
	// rather than to the one a reader might want. The alphabet holds the
	// underscore and the hyphen, so snake_case and kebab-case run through it
	// unbroken: a name opening with one of these prefixes and carrying forty
	// more characters of the alphabet is a token's format exactly and is
	// redacted. Raising the floor is what would rule it out, and forty is the
	// shortest body any source attests, so a higher one would turn a real API
	// access token away.
	//
	// The two below them are where the floor and the alphabet each hold: a
	// shorter name is left alone, and a dotted one is broken by the dot long
	// before forty characters of it have been read.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a snake case name long enough to reach the floor",
			src:  "bkct_agent_token_for_the_production_cluster_east",
			want: strings.Repeat("*", 48),
		},
		{
			name: "a kebab case name long enough to reach the floor",
			src:  "bkct_agent-token-for-the-production-cluster-east",
			want: strings.Repeat("*", 48),
		},
		{
			name: "a shorter name behind the prefix",
			src:  "bkct_agent_token_for_production",
			want: "bkct_agent_token_for_production",
		},
		{
			name: "a dotted name behind the prefix",
			src:  "bkct_agent.token.for.the.production.cluster.east",
			want: "bkct_agent.token.for.the.production.cluster.east",
		},
	}

	m := New(WithPatterns(BuildkiteToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_buildkiteTokenKinds(t *testing.T) {
	// The table the prefixes are built from, held to the two things the walk
	// over it takes for granted.
	//
	// No acronym may be written twice, or a candidate would be read against the
	// same rule twice over. And every character of one belongs to the alphabet
	// a body is written in but is not the separator, which is two arguments in
	// one line. The walk takes the first entry that fits and no second one can
	// fit beside it, because a longer acronym carries a character of its own
	// where a shorter one wants the separator — which holds only while no
	// acronym is written with the separator. And a prefix stands inside a body,
	// which is what the case pinning one token inside another rests on — which
	// holds only while every character of one is a character a body may carry.
	// Neither is a failure anything else here reports.
	if len(buildkiteTokenKinds) == 0 {
		t.Fatal("the pattern names no kind, so it locates nothing")
	}
	for i, kind := range buildkiteTokenKinds {
		if kind == "" {
			t.Errorf("the table holds an empty acronym at %d", i)
			continue
		}
		if slices.Index(buildkiteTokenKinds, kind) != i {
			t.Errorf("the acronym %q is written twice", kind)
		}
		for k := range len(kind) {
			switch c := kind[k]; {
			case c == buildkiteTokenSeparator:
				t.Errorf("the acronym %q holds the separator, so two acronyms can fit at one position", kind)
			case !isBase64URLByte(c):
				t.Errorf("the acronym %q holds %q, which no body may be written with", kind, c)
			}
		}
	}
}

func Test_buildkiteTokenKinds_bodyNeverMovesBack(t *testing.T) {
	// The scan works the end of a run out once and reuses it wherever a body
	// begins inside the run already read, which is sound only while a body
	// never begins in front of the body of the candidate before it. A candidate
	// stands at least one byte further along than the last and its body stands
	// its own acronym's length behind that, so the body moves back exactly
	// where an acronym is more than one character shorter than another. Two
	// characters against three is the widest gap this table has; an acronym of
	// five written beside one of two would have the cursor hand a candidate the
	// end of a run its own body never stood in, and the span would reach past
	// where that body's run ends.
	if len(buildkiteTokenKinds) == 0 {
		t.Fatal("the pattern names no kind, so there is no candidate to reason about")
	}
	shortest, longest := len(buildkiteTokenKinds[0]), len(buildkiteTokenKinds[0])
	for _, kind := range buildkiteTokenKinds {
		shortest = min(shortest, len(kind))
		longest = max(longest, len(kind))
	}
	if longest-shortest > 1 {
		t.Errorf("the acronyms run from %d characters to %d, so a body can begin in front of the one before it", shortest, longest)
	}
}

// Test_buildkiteTokenAnchor holds every prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from, and the
// opening to the two characters the scan reads it as. builtin_scan.go says why
// the first is held here rather than left to the targets; the second is what
// lets the scan compare one byte at a candidate, the anchor being the other. An
// opening of three characters would leave the middle one unread, and every
// position carrying its first character and the rest of a prefix would open a
// candidate.
func Test_buildkiteTokenAnchor(t *testing.T) {
	if len(buildkiteTokenOpening) != 2 {
		t.Errorf("the opening is %d characters, where the scan reads one byte of it against the one the anchor read", len(buildkiteTokenOpening))
	}
	for _, prefix := range buildkiteTokenPrefixes {
		if buildkiteTokenAnchorIndex >= len(prefix) {
			t.Errorf("the anchor stands at %d, %q is %d characters", buildkiteTokenAnchorIndex, prefix, len(prefix))
			continue
		}
		if c := prefix[buildkiteTokenAnchorIndex]; c != buildkiteTokenAnchor {
			t.Errorf("%q carries %q where the scan searches for %q, so no candidate is ever found at it", prefix, c, byte(buildkiteTokenAnchor))
		}
	}
}

func Test_BuildkiteToken_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a line dense in prefixes
	// holds a candidate for every five characters it has. The one thing a
	// candidate reads that is a walk over the rest of the input rather than a
	// bounded test is where its run ends, and repeating that walk at every
	// candidate would cost time quadratic in the length of the line. The bound
	// here is far above a linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every forty-five bytes where they are densest, because a sample
	// has to carry a whole body to be one. The crowding a line can actually
	// carry, a candidate every five bytes inside one run, stays here.
	sources := map[string]string{
		// Candidates as close together as the prefix allows, all of them inside
		// one run, since the underscore a prefix closes with belongs to the
		// alphabet a body is read in. This is what the run cursor exists for:
		// without it the run is read once per candidate.
		"a candidate every five characters in one run": strings.Repeat("bkua_", 400000),
		// The same crowding with every run ended before a body can begin, so
		// each candidate reaches the body of the loop and none becomes a token.
		"candidates with no run behind them": strings.Repeat("bkua_.", 300000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a token.
		"a body that runs the length of the line": "bkua_" + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("ak", 900000),
		// And the prefix's own letters with no anchor among them, which is the
		// walk reading a whole line and stopping nowhere in it.
		"the letters of a prefix with no anchor": strings.Repeat("bua_", 450000),
	}

	checkScanIsLinear(t, BuildkiteToken(), sources)
}

// referenceBuildkiteTokenFind locates tokens the plain way: every position in
// turn, the opening tried at it, every acronym tried behind that and the body
// walked to the end of its run, with no cursor and nothing remembered between
// candidates. The opening, the acronyms, the separator, the floor and the
// character class are spelled again here rather than shared with the scan. A
// reference reading those declarations could not disagree with it about them,
// and it is exactly that disagreement the fuzz target below is for: the two
// have to be changed together or reported apart.
//
// Every position is a starting point in its own right, a match included,
// because a prefix is written in the alphabet a body is: bkua_bkct_ holds a
// token beginning inside the match before it. The scan finds both and reports
// the two spans overlapping for a Masker to resolve, so the reference must ask
// about both.
//
// Every acronym is tried where the scan stops at the first that fits. At most
// one can fit — a longer acronym carries a character of its own where a shorter
// one wants the separator — and asking about all of them is what leaves that
// claim something to fail on rather than something the reference takes from the
// scan.
//
// It is written out rather than built on a regular expression, for the reason
// the Anthropic reference beside it gives: the grammar states compactly as
// bk(?:…)_[0-9A-Za-z_-]{40,}, but a counted repetition is what an engine has
// the least room to skip, and greedy repetition behind one makes it re-walk the
// run at every candidate through a machine forty states wide — on bkua_ written
// over and over, which is one run and not a run apiece, and which the mutator
// reaches within seconds.
//
// Walking the run at every position is what the cursor saves the scan from, so
// this still costs time quadratic in the length of a run a prefix can be
// written inside. That is the price of a reference with no cursor to be wrong
// about, and the reason the seeds below keep such a run under two hundred bytes
// rather than inviting the mutator to grow it. Test_builtins_scanIsLinear and
// Test_BuildkiteToken_scanIsLinear are where the cost the scan pays is held
// down.
func referenceBuildkiteTokenFind(src string) []Span {
	const (
		opening   = "bk"
		separator = '_'
		bodyChars = 40
	)
	kinds := []string{"ua", "aa", "aj", "ar", "ct", "pt", "ps", "tx", "pat", "jat"}

	body := func(c byte) bool {
		return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || c == '-' || c == '_'
	}

	var spans []Span
	for start := range len(src) {
		if !strings.HasPrefix(src[start:], opening) {
			continue
		}
		for _, kind := range kinds {
			at := start + len(opening) + len(kind)
			if at >= len(src) || src[at] != separator || src[start+len(opening):at] != kind {
				continue
			}

			from := at + 1
			end := from
			for end < len(src) && body(src[end]) {
				end++
			}
			if end-from < bodyChars {
				continue
			}
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
}

// FuzzBuildkiteToken_matchesReference guards the hand-written scan: the opening
// it searches for, the acronyms it reads behind it, the floor it holds a body
// to, the alphabet it reads that body in, the run it remembers between
// candidates and the byte it resumes at may none of them change which tokens
// are located.
func FuzzBuildkiteToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("BUILDKITE_API_TOKEN=bkua_" + buildkiteBody)
	f.Add("bkua_" + buildkiteUpperBody)
	// One of every kind, so that both lengths of acronym are driven.
	f.Add("bkaa_" + buildkiteBody)
	f.Add("bkaj_" + buildkiteBody)
	f.Add("bkar_" + buildkiteBody)
	f.Add("bkct_" + buildkiteBody)
	f.Add("bkpt_" + buildkiteBody)
	f.Add("bkps_" + buildkiteBody)
	f.Add("bktx_" + buildkiteBody)
	f.Add("bkpat_" + buildkiteBody)
	f.Add("bkjat_" + buildkiteBody)
	f.Add("bkua_0123456789abcdef0123456789abcdef0123456")   // one short of a body
	f.Add("bkua_" + buildkiteBody + "0")                    // and a run longer than one
	f.Add("bkua_0123456789abcdef-0123456789abcdef01234567") // a hyphen, which the body admits
	f.Add("bkua_0123456789abcdef_0123456789abcdef01234567") // an underscore, likewise
	f.Add("bkua_0123456789abcdef.0123456789abcdef01234567") // a dot, which ends the body
	f.Add("BKUA_" + buildkiteBody)                          // an uppercase prefix
	f.Add("bkua-" + buildkiteBody)                          // a hyphen where the prefix carries an underscore
	f.Add("bkzz_" + buildkiteBody)                          // an acronym Buildkite names no token with
	f.Add("bkuaa_" + buildkiteBody)                         // a character written into an acronym
	f.Add("bk_" + buildkiteBody)                            // the opening with no acronym behind it
	f.Add("bkua_" + buildkiteBody + "-suffix")
	f.Add("bkua_" + buildkiteBody + "_suffix")
	f.Add("bkua_" + buildkiteBody + "\nbkct_" + buildkiteUpperBody)
	// A token beginning inside the match before it, which a scan resuming past
	// a match steps over, and two tokens with nothing between them.
	f.Add("bkua_bkct_" + buildkiteBody)
	f.Add("bkua_" + buildkiteBody + "bkct_" + buildkiteUpperBody)
	// Candidate positions crowded as close as they can be, inside one run and
	// with every run ended before a body can begin. Both are kept short: the
	// reference walks the run at every position, so a long one is what wedges
	// the target rather than what fuzzes it.
	f.Add(strings.Repeat("bkua_", 16))
	f.Add(strings.Repeat("bkua_.", 16))
	// A digest written behind the prefix, which is a token's format exactly,
	// and a snake_case name long enough to reach the floor.
	f.Add("bkua_0123456789abcdef0123456789abcdef01234567")
	f.Add("bkct_agent_token_for_the_production_cluster_east")
	// The value in a pipeline trigger URL, whose acronym is in no prefix here.
	f.Add("https://webhook.buildkite.com/deliver/bktr_0123456789ab")
	// The prefix written inside a run of base64url, which is the over-match the
	// pattern admits.
	f.Add("payload=zzzzbkua_" + buildkiteBody + "zzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzbkua_" + buildkiteBody + "zzzz")

	fuzzAgainstReference(f, BuildkiteToken().Find, referenceBuildkiteTokenFind)
}

// buildkiteTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func buildkiteTokenFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens a prefix, so what the line times is the
	// search for the anchor — which is most of what this pattern costs a caller
	// whose text holds no token. It is the line the anchor was chosen on: the b
	// stands six times on it against the k's one.
	line := `time=2026-08-17T00:00:00Z level=info msg="build finished" org=acme pipeline=web build=1234 url=https://buildkite.com/acme/web/builds/1234 `
	token := "bkua_" + buildkiteBody

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every six characters with every run ended before a
			// body can begin: each of them reaches the body of the loop and
			// none becomes a token. What it times is the run cursor being
			// moved, once per candidate and no more.
			name:  "candidates that are not values",
			src:   strings.Repeat("bkua_.", 128),
			spans: 0,
		},
		{
			// The same crowding inside one run long enough for every candidate,
			// so each locates a token and every span reaches the same place.
			// This is what the run cursor exists for: without it the run is
			// read once per candidate.
			name:  "candidates crowded in one run",
			src:   strings.Repeat("bkua_", 128) + buildkiteBody,
			spans: 128,
		},
		{
			name:  "one value",
			src:   line + "token=" + token,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "token=" + token,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"token="+token+"\n", 32),
			spans: 32,
		},
	}
}
