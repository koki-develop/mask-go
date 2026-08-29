package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The npm access token pattern: what it locates and what it leaves alone,
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
// 0123456789abcdefghijklmnopqrstuvwxyz, is thirty-six characters and so is a
// whole body — the shortest the scan reads, since the count is a floor, so a
// body shortened for readability would leave a case holding no token at all.
// It is written in lowercase where the case does not matter and in uppercase
// where the case is what a case is about: base62 holds the letters of both, so
// either spelling is a body.

func Test_NPMAccessToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "npm_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			name: "a token in an environment assignment",
			src:  "NPM_TOKEN=npm_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{10, 50}},
		},
		{
			// base62 holds the letters of both cases, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "npm_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			want: []Span{{0, 40}},
		},
		{
			// The count is a floor and the span reaches the end of the run, so
			// a run longer than the shortest body is a token to the end of it
			// rather than a token and a character left over.
			name: "a run longer than the shortest body",
			src:  "npm_0123456789abcdefghijklmnopqrstuvwxyz0",
			want: []Span{{0, 41}},
		},
		{
			name: "two tokens separated by a space",
			src:  "npm_0123456789abcdefghijklmnopqrstuvwxyz npm_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			want: []Span{{0, 40}, {41, 81}},
		},
		{
			// The three letters the prefix opens with belong to the alphabet a
			// body is written in, so a body may close with npm and the
			// underscore of the next token stand directly behind it. The
			// second token begins three characters before the first one ends,
			// and a scan resuming past a match would step over it. The spans
			// overlap, which a Masker resolves into one.
			name: "a token beginning inside the token before it",
			src:  "npm_0123456789abcdefghijklmnopqrstuvwnpm_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}, {37, 77}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := NPMAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NPMAccessToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "npm_",
		},
		{
			// Thirty-five characters where the pattern asks for thirty-six.
			// This is the shape a line cut to a column limit leaves, and the
			// characters in front of the cut stay in the text: the far side of
			// reading a floor, which builtin_npm_access_token.go weighs.
			name: "a body one character too short",
			src:  "npm_0123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			// The hyphen and the underscore are base64url characters and no
			// base62 ones, so either ends a body where the run behind it is
			// too short to be one.
			name: "a body carrying a hyphen",
			src:  "npm_0123456789abcdef-ghijklmnopqrstuvwxyz",
		},
		{
			name: "a body carrying an underscore",
			src:  "npm_0123456789abcdef_ghijklmnopqrstuvwxyz",
		},
		{
			name: "an uppercase prefix",
			src:  "NPM_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			// The prefix closes with an underscore, so a hyphen written in its
			// place opens no candidate at all.
			name: "a hyphen where the prefix carries an underscore",
			src:  "npm-0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "two characters of the prefix",
			src:  "nxm_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "a space in the body",
			src:  "npm_0123456789abcdef ghijklmnopqrstuvwxyz",
		},
		{
			name: "a dot in the body",
			src:  "npm_0123456789abcdef.ghijklmnopqrstuvwxyz",
		},
		{
			name: "a body broken by a line break",
			src:  "npm_0123456789abcdef\nghijklmnopqrstuvwxyz",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// the whole of the anchor, so a run long enough is not a token
			// without it.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			// The format this one replaced: a bare UUID, with hyphens where a
			// body carries none and no prefix in front of it. npm revoked the
			// last of them, and nothing in such a string says which registry
			// it was for.
			name: "a token of the uuid format npm issued before this one",
			src:  "0123456789ab-cdef-0123-4567-89abcdef0123",
		},
		{
			// The environment npm exports to a lifecycle script is written in
			// snake_case, so it carries the prefix. What turns it away is the
			// count: the next underscore of such a name ends the run long
			// before thirty-six characters of it have been read.
			name: "an environment variable npm sets for a script",
			src:  "npm_package_version=1.0.0 npm_lifecycle_event=prepublishOnly",
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
			if got, _ := NPMAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_NPMAccessToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "NPM_TOKEN=npm_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "NPM_TOKEN=****************************************",
		},
		{
			// The file the npm CLI reads a token from.
			name: "an npmrc line",
			src:  "//registry.npmjs.org/:_authToken=npm_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "//registry.npmjs.org/:_authToken=****************************************",
		},
		{
			name: "json",
			src:  `{"token":"npm_0123456789abcdefghijklmnopqrstuvwxyz"}`,
			want: `{"token":"****************************************"}`,
		},
		{
			// The header a request to the registry carries a token in.
			name: "an authorization header",
			src:  "Authorization: Bearer npm_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "Authorization: Bearer ****************************************",
		},
		{
			name: "a command line",
			src:  "npm config set //registry.npmjs.org/:_authToken npm_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "npm config set //registry.npmjs.org/:_authToken ****************************************",
		},
		{
			name: "twice",
			src:  "npm_0123456789abcdefghijklmnopqrstuvwxyz npm_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			want: "**************************************** ****************************************",
		},
		{
			// The two spans are merged, so the token that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a token beginning inside the token before it",
			src:  "npm_0123456789abcdefghijklmnopqrstuvwnpm_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "*****************************************************************************",
		},
	}

	m := New(WithPatterns(NPMAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NPMAccessToken_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the token through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xnpm_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "x****************************************",
		},
		{
			name: "underscore before",
			src:  "NPM_TOKEN_npm_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "NPM_TOKEN_****************************************",
		},
	}

	m := New(WithPatterns(NPMAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NPMAccessToken_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a floor rather than a count. Where a token ends
	// is where its alphabet stops, so a letter or a digit written straight
	// against a token is redacted with it — which is what buys a token of a
	// length nobody has published being located whole. The alphabet is base62
	// and not base64url, so the two characters that separate them, the hyphen
	// and the underscore, end a token here where they would carry one on in the
	// OpenAI and Anthropic scans.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the token is npm_0123456789abcdefghijklmnopqrstuvwxyz.",
			want: "the token is ****************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export NPM_TOKEN="npm_0123456789abcdefghijklmnopqrstuvwxyz"`,
			want: `export NPM_TOKEN="****************************************"`,
		},
		{
			name: "a word against the token",
			src:  "npm_0123456789abcdefghijklmnopqrstuvwxyzsuffix",
			want: "**********************************************",
		},
		{
			name: "a dashed word against the token",
			src:  "npm_0123456789abcdefghijklmnopqrstuvwxyz-suffix",
			want: "****************************************-suffix",
		},
		{
			name: "an underscored word against the token",
			src:  "npm_0123456789abcdefghijklmnopqrstuvwxyz_suffix",
			want: "****************************************_suffix",
		},
	}

	m := New(WithPatterns(NPMAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NPMAccessToken_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than
	// redacted. A line cut to a column limit partway through a token leaves a
	// prefix and a body too short to be one, and the random characters written
	// before the cut come through whole.
	//
	// It is the price of reading a count npm derives rather than states, and
	// the cases move with the scan: one of them starting to be located means
	// the floor moved, and that is a decision to be taken rather than noticed
	// afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a token one character short of the floor",
			src:  "NPM_TOKEN=npm_0123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			name: "a token cut off at its prefix",
			src:  "NPM_TOKEN=npm_",
		},
	}

	m := New(WithPatterns(NPMAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_NPMAccessToken_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix carries an
	// underscore, which standard base64 writes nowhere, so only a base64url
	// encoding can hold one — and there four characters of an alphabet of
	// sixty-four stand where the prefix stands about once in seventeen million
	// characters. Where thirty-six base62 characters follow, everything from
	// the prefix to the end of that run is redacted.
	//
	// The cases are held to being redacted rather than to being spared. What is
	// taken is a stretch of a value already opaque to a reader, and the run is
	// a token's format exactly: nothing is left in the text to tell the two
	// apart, so a pattern letting it through would let a real token through
	// with it. What the cases are for is that they move with the scan: one of
	// them ceasing to be located means the grammar changed, and that is a
	// decision to be taken rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "inside a base64url payload",
			src:  "payload=zzzznpm_0123456789abcdefghijklmnopqrstuvwxyzzzzz",
			want: "payload=zzzz********************************************",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the npm
			// pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzznpm_0123456789abcdefghijklmnopqrstuvwxyzzzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz********************************************",
		},
	}

	m := New(WithPatterns(NPMAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NPMAccessToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_npm_access_token.go names, held to the answer it gives
	// rather than to the one a reader might want. Hexadecimal digits are base62
	// and a digest carries nothing that ends a run, so a digest of forty
	// characters or more written behind the prefix is a token's format exactly
	// and is redacted — a cache key built from npm_ and the hash of a lock file
	// among them. Declining it would mean declining every token npm wrote in
	// the digits alone, which is the whole credential against a cache key.
	//
	// The two below it are where the floor and the prefix each hold: an MD5 is
	// four characters short of a body, and a hyphen is no character the prefix
	// carries. The cases move with the scan, so a change to either shows up
	// here as a decision rather than as something the next reader discovers.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sha1 behind the prefix",
			src:  "npm_0123456789abcdef0123456789abcdef01234567",
			want: "********************************************",
		},
		{
			name: "a sha256 in a cache key",
			src:  "key: npm_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "key: ********************************************************************",
		},
		{
			name: "an md5 behind the prefix, four characters short of a body",
			src:  "npm_0123456789abcdef0123456789abcdef",
			want: "npm_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a sha1 behind a hyphen rather than the prefix",
			src:  "npm-0123456789abcdef0123456789abcdef01234567",
			want: "npm-0123456789abcdef0123456789abcdef01234567",
		},
	}

	m := New(WithPatterns(NPMAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_npmAccessTokenPrefix(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a token
	// can begin inside the one before it, and that holds only while the prefix
	// carries characters a body may be written with. Here it is the three in
	// front of the underscore: a body closing with npm leaves the underscore of
	// the next token standing directly behind it. A prefix written entirely
	// outside the alphabet would make the two impossible to nest, and the case
	// above pinning the nesting would stand for nothing — which is not a
	// failure anything else here reports.
	if npmAccessTokenPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for i := range len(npmAccessTokenPrefix) - 1 {
		if c := npmAccessTokenPrefix[i]; !isBase62Byte(c) {
			t.Errorf("the prefix holds %q in front of its last character, which no body may be written with", c)
		}
	}
}

// Test_npmAccessTokenAnchor holds the prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_npmAccessTokenAnchor(t *testing.T) {
	if npmAccessTokenAnchorIndex >= len(npmAccessTokenPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", npmAccessTokenAnchorIndex, len(npmAccessTokenPrefix))
	}
	if c := npmAccessTokenPrefix[npmAccessTokenAnchorIndex]; c != npmAccessTokenAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(npmAccessTokenAnchor))
	}
}

func Test_npmAccessTokenPrefix_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over
	// it, where a scan whose prefix closes on a character its own body admits
	// has to keep one. What makes the cursor unnecessary is that two
	// candidates can never read the same run: a candidate asks for the last
	// character of the prefix four characters in, no body may be written with
	// it, so the run of an earlier candidate has already ended there and the
	// later candidate's run begins past it. Were that character one a body
	// admits, a run dense in prefixes would be walked once for every candidate
	// in it and the scan would cost time quadratic in the length of such a
	// line.
	if npmAccessTokenPrefix == "" {
		t.Fatal("the pattern carries no prefix, so there is no candidate to reason about")
	}
	if c := npmAccessTokenPrefix[len(npmAccessTokenPrefix)-1]; isBase62Byte(c) {
		t.Errorf("the prefix closes with %q, which a body may be written with, so two candidates can read the same run", c)
	}
}

func Test_NPMAccessToken_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a line dense in prefixes
	// holds a candidate for every four characters it has. The one thing a
	// candidate reads that is a walk over the rest of the input rather than a
	// bounded test is where its run ends, and repeating that walk at every
	// candidate would cost time quadratic in the length of the line. The bound
	// here is far above a linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every thirty-seven bytes where they are densest, because a
	// sample has to carry a whole body to be one. The crowding a line can
	// actually carry, a candidate every four bytes, stays here.
	sources := map[string]string{
		// Candidates as close together as the prefix allows, none of them with
		// a run long enough to be a body: every one reaches the body of the
		// loop and every one is rejected.
		"a candidate every four characters": strings.Repeat("npm_", 500000),
		// Tokens written into one another, each beginning three characters
		// before the one in front of it ends, so every candidate is a token and
		// every one of them walks a run.
		"a token beginning inside every token": strings.Repeat("npm_0123456789abcdefghijklmnopqrstuvw", 50000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a token.
		"a body that runs the length of the line": "npm_" + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("a_", 900000),
		// And the prefix's own letters with no anchor among them, which is the
		// walk reading a whole line and stopping nowhere in it.
		"the letters of the prefix with no anchor": strings.Repeat("npm", 600000),
	}

	checkScanIsLinear(t, NPMAccessToken(), sources)
}

// referenceNPMAccessToken is the expression the scan in
// builtin_npm_access_token.go reads by hand: the statement of what an npm
// access token is, kept here so that the scan can be held to it.
//
// The prefix, the floor and the alphabet are spelled again rather than built
// from npmAccessTokenPrefix, npmAccessTokenBodyChars and isBase62Byte. A
// reference sharing those declarations could not disagree with the scan about
// them, and it is exactly that disagreement the fuzz target below is for: the
// two have to be changed together or reported apart.
//
// The floor is written as a counted repetition, which is what the Anthropic
// reference beside this one is written out by hand to avoid. It costs nothing
// here, and for the reason the scan needs no cursor: candidates cannot crowd
// inside one run, so no input makes an engine walk the same run more than once.
var referenceNPMAccessToken = regexp.MustCompile(`npm_[0-9A-Za-z]{36,}`)

// referenceNPMAccessTokenFind locates tokens the plain way: the leftmost match
// of the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a token can begin inside one: the three letters
// the prefix opens with are written in the alphabet a body is, so a body
// closing with npm holds the start of the token behind it. The scan finds both
// and reports the two spans overlapping for a Masker to resolve, so the
// reference must ask about both.
func referenceNPMAccessTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceNPMAccessToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzNPMAccessToken_matchesReference guards the hand-written scan: the prefix
// it searches for, the floor it holds a body to, the alphabet it reads that
// body in and the byte it resumes at may none of them change which tokens are
// located.
func FuzzNPMAccessToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("NPM_TOKEN=npm_0123456789abcdefghijklmnopqrstuvwxyz")
	f.Add("npm_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	f.Add("npm_0123456789abcdefghijklmnopqrstuvwxy")   // one short of a body
	f.Add("npm_0123456789abcdefghijklmnopqrstuvwxyz0") // and a run longer than one
	f.Add("npm_0123456789abcdef-ghijklmnopqrstuvwxyz") // a hyphen, which base64url admits and base62 does not
	f.Add("npm_0123456789abcdef_ghijklmnopqrstuvwxyz") // an underscore, likewise
	f.Add("npm_0123456789abcdef.ghijklmnopqrstuvwxyz") // a dot ends the body
	f.Add("NPM_0123456789abcdefghijklmnopqrstuvwxyz")  // an uppercase prefix
	f.Add("npm-0123456789abcdefghijklmnopqrstuvwxyz")  // a hyphen where the prefix carries an underscore
	f.Add("npm_0123456789abcdefghijklmnopqrstuvwxyz-suffix")
	f.Add("npm_0123456789abcdefghijklmnopqrstuvwxyz_suffix")
	f.Add("npm_0123456789abcdefghijklmnopqrstuvwxyz\nnpm_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	// A token beginning inside the match before it, which a scan resuming past
	// a match steps over, and two tokens with nothing between them.
	f.Add("npm_0123456789abcdefghijklmnopqrstuvwnpm_0123456789abcdefghijklmnopqrstuvwxyz")
	f.Add("npm_0123456789abcdefghijklmnopqrstuvwxyznpm_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	// Candidate positions crowded as close as they can be, with no run long
	// enough for any of them, and tokens written into one another so that every
	// candidate has one.
	f.Add(strings.Repeat("npm_", 16))
	f.Add(strings.Repeat("npm_0123456789abcdefghijklmnopqrstuvw", 4))
	// A digest written behind the prefix, which is a token's format exactly, and
	// one four characters short of a body.
	f.Add("npm_0123456789abcdef0123456789abcdef01234567")
	f.Add("key: npm_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("npm_0123456789abcdef0123456789abcdef")
	// The environment npm exports to a lifecycle script, which carries the
	// prefix and which only the floor turns away.
	f.Add("npm_package_version=1.0.0 npm_lifecycle_event=prepublishOnly")
	// The prefix written inside a run of base64url, which is the over-match the
	// pattern admits.
	f.Add("payload=zzzznpm_0123456789abcdefghijklmnopqrstuvwxyzzzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzznpm_0123456789abcdefghijklmnopqrstuvwxyzzzzz")

	fuzzAgainstReference(f, NPMAccessToken().Find, referenceNPMAccessTokenFind)
}

// npmAccessTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func npmAccessTokenFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="fetching a package" url=https://registry.npmjs.org/left-pad `
	token := "npm_0123456789abcdefghijklmnopqrstuvwxyz"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every four characters with no run long enough behind
			// any of them: each reaches the body of the loop and none becomes a
			// token. What it times is the walk over a run being started and
			// stopped, once per candidate and no more.
			name:  "candidates that are not values",
			src:   strings.Repeat("npm_", 128),
			spans: 0,
		},
		{
			// Tokens written into one another, each beginning three characters
			// before the one in front of it ends. This is what the scan gets
			// away with keeping no cursor for: the runs the candidates read
			// follow one another rather than overlapping. The three characters
			// at the end are what closes the body of the last of them, which
			// otherwise has only the run it was written with.
			name:  "tokens written into one another",
			src:   strings.Repeat("npm_0123456789abcdefghijklmnopqrstuvw", 128) + "xyz",
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
