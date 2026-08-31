package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Ory API key pattern: what it locates and what it leaves alone, written
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
// sixteen characters, so a body is that run twice over — the shortest body the
// scan reads, since the count is a floor, so a body shortened for readability
// would leave a case holding no key at all. It is written in lowercase where
// the case does not matter and in uppercase where the case is what a case is
// about: base62 holds the letters of both, so either spelling is a body.

func Test_OryAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "ory_pat_0123456789abcdef0123456789abcdef",
			want: []Span{{0, 40}},
		},
		{
			name: "a key in an environment assignment",
			src:  "ORY_API_KEY=ory_pat_0123456789abcdef0123456789abcdef",
			want: []Span{{12, 52}},
		},
		{
			// base62 holds the letters of both cases, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "ory_pat_0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 40}},
		},
		{
			// The count is a floor and the span reaches the end of the run, so
			// a run longer than the shortest body is a key to the end of it
			// rather than a key and a character left over.
			name: "a run longer than the shortest body",
			src:  "ory_pat_0123456789abcdef0123456789abcdef0",
			want: []Span{{0, 41}},
		},
		{
			name: "two keys separated by a space",
			src:  "ory_pat_0123456789abcdef0123456789abcdef ory_wak_0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 40}, {41, 81}},
		},
		{
			// The three letters the opening is made of belong to the alphabet a
			// body is written in, so a body may close with ory and the
			// underscore of the next key stand directly behind it. The second
			// key begins three characters before the first one ends, and a scan
			// resuming past a match would step over it. The spans overlap,
			// which a Masker resolves into one.
			name: "a key beginning inside the key before it",
			src:  "ory_pat_0123456789abcdef0123456789abcdefory_pat_0123456789abcdef0123456789abcdef",
			want: []Span{{0, 43}, {40, 80}},
		},
		{
			// Two keys with nothing at all between them. The first body reads
			// three characters into the second key's opening and stops at the
			// underscore behind them, so the spans overlap here as well.
			name: "two keys of different kinds with nothing between them",
			src:  "ory_pat_0123456789abcdef0123456789abcdefory_apikey_0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 43}, {40, 83}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := OryAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OryAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "ory_pat_",
		},
		{
			// Thirty-one characters where the pattern asks for thirty-two. This
			// is the shape a line cut to a column limit leaves, and the
			// characters in front of the cut stay in the text: the far side of
			// reading a floor, which builtin_ory_api_key.go weighs.
			name: "a body one character too short",
			src:  "ory_pat_0123456789abcdef0123456789abcde",
		},
		{
			// The hyphen and the underscore are base64url characters and no
			// base62 ones, so either ends a body where the run behind it is
			// too short to be one.
			name: "a body carrying a hyphen",
			src:  "ory_pat_0123456789abcdef-123456789abcdef",
		},
		{
			name: "a body carrying an underscore",
			src:  "ory_pat_0123456789abcdef_123456789abcdef",
		},
		{
			name: "an uppercase prefix",
			src:  "ORY_PAT_0123456789abcdef0123456789abcdef",
		},
		{
			// The prefix is written with the underscores Ory divides it by, not
			// with the hyphen a delimiter is elsewhere.
			name: "hyphens where the prefix carries underscores",
			src:  "ory-pat-0123456789abcdef0123456789abcdef",
		},
		{
			// The word naming the kind has to be closed by the second
			// underscore, so a body written straight against it is no body.
			name: "the prefix without its closing underscore",
			src:  "ory_pat0123456789abcdef0123456789abcdef",
		},
		{
			name: "the opening without a word naming a kind",
			src:  "ory_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a word no key is issued with where the kind stands",
			src:  "ory_key_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a space in the body",
			src:  "ory_pat_0123456789abcdef 123456789abcdef",
		},
		{
			name: "a dot in the body",
			src:  "ory_pat_0123456789abcdef.123456789abcdef",
		},
		{
			name: "a body broken by a line break",
			src:  "ory_pat_0123456789abcdef\n123456789abcdef",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// most of the anchor, so a run long enough is not a key without it.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdef0123456789abcdef",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := OryAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_OryAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "ORY_API_KEY=ory_pat_0123456789abcdef0123456789abcdef",
			want: "ORY_API_KEY=****************************************",
		},
		{
			// The header an Ory admin API is called with.
			name: "a bearer authorization header",
			src:  "Authorization: Bearer ory_pat_0123456789abcdef0123456789abcdef",
			want: "Authorization: Bearer ****************************************",
		},
		{
			name: "json",
			src:  `{"value":"ory_apikey_0123456789abcdef0123456789abcdef"}`,
			want: `{"value":"*******************************************"}`,
		},
		{
			name: "a command line",
			src:  `curl -H "Authorization: Bearer ory_pat_0123456789abcdef0123456789abcdef" https://practical-swirles-01234567.projects.oryapis.com/admin/identities`,
			want: `curl -H "Authorization: Bearer ****************************************" https://practical-swirles-01234567.projects.oryapis.com/admin/identities`,
		},
		{
			// The environment block the Ory CLI is configured with.
			name: "a configuration environment block",
			src:  `"env": {"ORY_WORKSPACE_API_KEY": "ory_wak_0123456789abcdef0123456789abcdef"}`,
			want: `"env": {"ORY_WORKSPACE_API_KEY": "****************************************"}`,
		},
		{
			name: "twice",
			src:  "ory_pat_0123456789abcdef0123456789abcdef ory_wak_0123456789ABCDEF0123456789ABCDEF",
			want: "**************************************** ****************************************",
		},
		{
			// The two spans are merged, so the key that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a key beginning inside the key before it",
			src:  "ory_pat_0123456789abcdef0123456789abcdefory_pat_0123456789abcdef0123456789abcdef",
			want: "********************************************************************************",
		},
	}

	m := New(WithPatterns(OryAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OryAPIKey_theThreePrefixes(t *testing.T) {
	// The three prefixes Ory lists under Ory Network API keys, each with the
	// same body behind it. Only ory_pat_ has been published with a whole key,
	// and builtin_ory_api_key.go argues why the other two are read at the same
	// length and in the same alphabet; the cases are what makes a change of
	// mind about that a decision rather than a widening nobody noticed.
	//
	// The workspace prefix stands with the two project ones so that the reach
	// of the pattern is written down: a caller enabling it redacts what reaches
	// a project and what reaches the whole workspace, and dropping either would
	// leave these cases failing rather than passing quietly.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "the project prefix a whole key has been published with",
			src:  "ory_pat_0123456789abcdef0123456789abcdef",
			want: "****************************************",
		},
		{
			name: "the other project prefix",
			src:  "ory_apikey_0123456789abcdef0123456789abcdef",
			want: "*******************************************",
		},
		{
			name: "the workspace prefix",
			src:  "ory_wak_0123456789abcdef0123456789abcdef",
			want: "****************************************",
		},
	}

	m := New(WithPatterns(OryAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OryAPIKey_theOtherOryPrefixes(t *testing.T) {
	// The prefixes Ory writes on the credentials that are not API keys, held to
	// being left in the text. They stand under headings of their own on the
	// same page and are a different credential under a different term of Ory's,
	// which builtin_ory_api_key.go weighs; the cases keep the reach of this
	// pattern from drifting into them unnoticed.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "an oauth2 access token prefix",
			src:  "ory_at_0123456789abcdef0123456789abcdef",
		},
		{
			name: "an oauth2 refresh token prefix",
			src:  "ory_rt_0123456789abcdef0123456789abcdef",
		},
		{
			name: "an oauth2 authorization code prefix",
			src:  "ory_ac_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a session token prefix",
			src:  "ory_st_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a session cookie prefix",
			src:  "ory_session_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a logout token prefix",
			src:  "ory_lo_0123456789abcdef0123456789abcdef",
		},
	}

	m := New(WithPatterns(OryAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_OryAPIKey_theSnakeCaseNamesThatCarryTheOpening(t *testing.T) {
	// English has a shelf of words closing on ory, so ordinary snake_case code
	// carries the opening and the underscore behind it. Two things turn those
	// away: the word naming the kind, which the second underscore has to stand
	// directly behind, and the floor, which the next underscore of such a name
	// ends the run long before.
	//
	// The last case is where that stops holding — a name whose segments spell a
	// whole prefix with thirty-two unbroken characters behind it is a key's
	// format exactly, and everything from the ory onward is redacted.
	// builtin_ory_api_key.go weighs the tightening that would rule it out and
	// says why it is declined.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a name whose next segment merely opens like a kind",
			src:  "repository_pattern = None",
			want: "repository_pattern = None",
		},
		{
			name: "a name whose next segment opens like another kind",
			src:  "memory_wakeup_timer = 30",
			want: "memory_wakeup_timer = 30",
		},
		{
			name: "a name spelling a whole prefix with segments behind it",
			src:  "inventory_pat_index_by_id",
			want: "inventory_pat_index_by_id",
		},
		{
			name: "a name spelling a whole prefix with a body behind it",
			src:  "memory_pat_0123456789abcdef0123456789abcdef",
			want: "mem****************************************",
		},
	}

	m := New(WithPatterns(OryAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OryAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xory_pat_0123456789abcdef0123456789abcdef",
			want: "x****************************************",
		},
		{
			name: "underscore before",
			src:  "ORY_API_KEY_ory_pat_0123456789abcdef0123456789abcdef",
			want: "ORY_API_KEY_****************************************",
		},
	}

	m := New(WithPatterns(OryAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OryAPIKey_reachesTheEndOfTheRun(t *testing.T) {
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
			src:  "the key is ory_pat_0123456789abcdef0123456789abcdef.",
			want: "the key is ****************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export ORY_API_KEY="ory_pat_0123456789abcdef0123456789abcdef"`,
			want: `export ORY_API_KEY="****************************************"`,
		},
		{
			name: "a word against the key",
			src:  "ory_pat_0123456789abcdef0123456789abcdefsuffix",
			want: "**********************************************",
		},
		{
			name: "a dashed word against the key",
			src:  "ory_pat_0123456789abcdef0123456789abcdef-suffix",
			want: "****************************************-suffix",
		},
		{
			name: "an underscored word against the key",
			src:  "ory_pat_0123456789abcdef0123456789abcdef_suffix",
			want: "****************************************_suffix",
		},
	}

	m := New(WithPatterns(OryAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OryAPIKey_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than
	// redacted. A line cut to a column limit partway through a key leaves a
	// prefix and a body too short to be one, and the random characters written
	// before the cut come through whole.
	//
	// It is the price of reading a count no Ory page states, and the cases move
	// with the scan: one of them starting to be located means the floor moved,
	// and that is a decision to be taken rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a key one character short of the floor",
			src:  "ORY_API_KEY=ory_pat_0123456789abcdef0123456789abcde",
		},
		{
			name: "a key cut off at its prefix",
			src:  "ORY_API_KEY=ory_pat_",
		},
		{
			name: "a key cut off inside the word naming its kind",
			src:  "ORY_API_KEY=ory_apike",
		},
	}

	m := New(WithPatterns(OryAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_OryAPIKey_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix carries two
	// underscores, which standard base64 writes nowhere, so only a base64url
	// encoding can hold one — and where thirty-two base62 characters follow,
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
			src:  "payload=zzzzory_pat_0123456789abcdef0123456789abcdefzzzz",
			want: "payload=zzzz********************************************",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the Ory
			// pattern's own reading of it.
			name: "where a signature stands",
			src:  "****************************************************************************",
			want: "****************************************************************************",
		},
	}

	m := New(WithPatterns(OryAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OryAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_ory_api_key.go names, held to the answer it gives
	// rather than to the one a reader might want. Hexadecimal digits are base62
	// and a digest carries nothing that ends a run, so an MD5 written behind a
	// prefix is exactly the thirty-two characters a body is and is redacted, as
	// the longer digests are. Declining them would mean declining every key Ory
	// wrote in the digits alone, which is the whole credential against a cache
	// key.
	//
	// The two below are where the floor and the prefix each hold: a digest of
	// twenty-four characters falls short of a body, and a hyphen is no
	// character the prefix carries. The cases move with the scan, so a change to
	// either shows up here as a decision rather than as something the next
	// reader discovers.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "an md5 behind the prefix",
			src:  "ory_pat_0123456789abcdef0123456789abcdef",
			want: "****************************************",
		},
		{
			name: "a sha1 behind the prefix in a cache key",
			src:  "key: ory_pat_0123456789abcdef0123456789abcdef01234567",
			want: "key: ************************************************",
		},
		{
			name: "a digest of twenty-four characters, eight short of a body",
			src:  "ory_pat_0123456789abcdef01234567",
			want: "ory_pat_0123456789abcdef01234567",
		},
		{
			name: "an md5 behind a hyphen rather than the prefix",
			src:  "ory-pat-0123456789abcdef0123456789abcdef",
			want: "ory-pat-0123456789abcdef0123456789abcdef",
		},
	}

	m := New(WithPatterns(OryAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_oryAPIKeyOpening(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a key can
	// begin inside the one before it, and that holds only while the opening is
	// written in the alphabet a body is. An opening carrying a character
	// outside it would make the two impossible to nest, and the cases above
	// pinning the nesting would stand for nothing — which is not a failure
	// anything else here reports.
	if oryAPIKeyOpening == "" {
		t.Fatal("the pattern carries no opening, so it locates nothing")
	}
	for i := range len(oryAPIKeyOpening) {
		if c := oryAPIKeyOpening[i]; !isBase62Byte(c) {
			t.Errorf("the opening carries %q, which no body may be written with, so no key can begin inside another", c)
		}
	}
}

func Test_oryAPIKeyKinds(t *testing.T) {
	// The scan stops at the first word it matches rather than trying the rest,
	// which is right only while at most one of them can stand at a position:
	// the words open on three different bytes, so a word that matched and was
	// not closed by the separator rules the others out as well. Were two of
	// them to share a first byte, or one to be written inside another, a key of
	// the kind tried second would go unlocated and nothing else here would
	// report it.
	if len(oryAPIKeyKinds) == 0 {
		t.Fatal("the pattern names no kind, so it locates nothing")
	}
	for _, kind := range oryAPIKeyKinds {
		if kind == "" {
			t.Fatal("a kind is empty, so its prefix is the opening and the separators alone")
		}
		for i := range len(kind) {
			if c := kind[i]; !isBase62Byte(c) {
				t.Errorf("the kind %q carries %q, which the separator would then not divide from a body", kind, c)
			}
		}
	}
	for i, kind := range oryAPIKeyKinds {
		for _, other := range oryAPIKeyKinds[i+1:] {
			if kind[0] == other[0] {
				t.Errorf("the kinds %q and %q open on the same byte, so the scan cannot stop at the first of them it matches", kind, other)
			}
		}
	}
}

func Test_oryAPIKeyPrefixes_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over
	// it. What makes the cursor unnecessary is that two candidates can never
	// read the same run: a candidate asks for the last character of its prefix
	// directly in front of its body, no body may be written with it, so an
	// earlier candidate's run has already ended there. Were that character one
	// a body admits, a run dense in prefixes would be walked once per candidate
	// in it and the scan would cost time quadratic in the length of such a line.
	if len(oryAPIKeyPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so there is no candidate to reason about")
	}
	for _, p := range oryAPIKeyPrefixes {
		if c := p[len(p)-1]; isBase62Byte(c) {
			t.Errorf("the prefix %q closes with %q, which a body may be written with, so two candidates can read the same run", p, c)
		}
	}
}

// Test_oryAPIKeyAnchor holds every prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_oryAPIKeyAnchor(t *testing.T) {
	for _, p := range oryAPIKeyPrefixes {
		if oryAPIKeyAnchorIndex >= len(p) {
			t.Errorf("the anchor stands at %d, the prefix %q is %d characters", oryAPIKeyAnchorIndex, p, len(p))
			continue
		}
		if c := p[oryAPIKeyAnchorIndex]; c != oryAPIKeyAnchor {
			t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", p, c, byte(oryAPIKeyAnchor))
		}
	}
}

func Test_OryAPIKey_scanIsLinear(t *testing.T) {
	// A line dense in prefixes holds a candidate for every four characters it
	// has. The one thing a candidate reads that is a walk over the rest of the
	// input rather than a bounded test is where its run ends, and repeating
	// that walk at every candidate would cost time quadratic in the length of
	// the line. The bound here is far above a linear scan and far below a
	// quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every forty bytes where they are densest, because a sample has
	// to carry a whole body to be one. The crowding a line can actually carry,
	// a candidate every four bytes, stays here.
	sources := map[string]string{
		// Candidates as close together as the opening allows, none of them
		// carrying a word that names a kind: every one reaches the loop over
		// the kinds and every one is rejected there.
		"a candidate every four characters": strings.Repeat("ory_", 250000),
		// Whole prefixes as close together as they go, none of them with a run
		// long enough to be a body: every one reaches the walk over a run and
		// every one is rejected behind it.
		"a prefix every eight characters": strings.Repeat("ory_pat_", 125000),
		// Keys written into one another, each beginning three characters before
		// the one in front of it ends, so every candidate is a key and every one
		// of them walks a run.
		"a key beginning inside every key": strings.Repeat("ory_pat_0123456789abcdef0123456789abcdef", 25000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a key.
		"a body that runs the length of the line": "ory_pat_" + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("a_", 900000),
		// And the letters of the opening with no anchor among them, which is
		// the walk reading a whole line and stopping nowhere in it.
		"the letters of the opening with no anchor": strings.Repeat("ory", 600000),
	}

	checkScanIsLinear(t, OryAPIKey(), sources)
}

// referenceOryAPIKey is the expression the scan in builtin_ory_api_key.go reads
// by hand: the statement of what an Ory Network API key is, kept here so that
// the scan can be held to it.
//
// The opening, the kinds, the separator, the floor and the alphabet are spelled
// again rather than built from oryAPIKeyOpening, oryAPIKeyKinds,
// oryAPIKeySeparator, oryAPIKeyBodyChars and isBase62Byte. A reference sharing
// those declarations could not disagree with the scan about them, and it is
// exactly that disagreement the fuzz target below is for: the two have to be
// changed together or reported apart.
//
// The floor is written as a counted repetition, which costs an engine a machine
// as wide as the floor at every candidate. It costs nothing here, and for the
// reason the scan needs no cursor: a body opens directly behind an underscore
// and holds none, so candidates cannot crowd inside one run and no input makes
// an engine walk the same run more than once. The opening and the separator
// behind it are a literal in front of the grammar besides, shared by all three
// alternatives, which is what an engine searches the text for.
var referenceOryAPIKey = regexp.MustCompile(`ory_(?:pat|apikey|wak)_[0-9A-Za-z]{32,}`)

// referenceOryAPIKeyFind locates keys the plain way: the leftmost match of the
// expression above, then the leftmost one beginning after that match's first
// byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a key can begin inside one: the three letters of
// the opening are written in the alphabet a body is, so a body closing with
// them holds the start of the key behind it. The scan finds both and reports
// the two spans overlapping for a Masker to resolve, so the reference must ask
// about both.
func referenceOryAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceOryAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzOryAPIKey_matchesReference guards the hand-written scan: the opening it
// searches back from, the words it admits between that opening and the second
// separator, the floor it holds a body to, the alphabet it reads that body in
// and the byte it resumes at may none of them change which keys are located.
func FuzzOryAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("ORY_API_KEY=ory_pat_0123456789abcdef0123456789abcdef")
	f.Add("ory_apikey_0123456789abcdef0123456789abcdef")
	f.Add("ory_wak_0123456789ABCDEF0123456789ABCDEF")
	f.Add("ory_pat_0123456789abcdef0123456789abcde")   // one short of a body
	f.Add("ory_pat_0123456789abcdef0123456789abcdef0") // and a run longer than one
	f.Add("ory_pat_0123456789abcdef-123456789abcdef")  // a hyphen, which base64url admits and base62 does not
	f.Add("ory_pat_0123456789abcdef_123456789abcdef")  // an underscore, likewise
	f.Add("ory_pat_0123456789abcdef.123456789abcdef")  // a dot ends the body
	f.Add("ORY_PAT_0123456789abcdef0123456789abcdef")  // an uppercase prefix
	f.Add("ory-pat-0123456789abcdef0123456789abcdef")  // hyphens where the prefix carries underscores
	f.Add("ory_pat0123456789abcdef0123456789abcdef")   // the prefix without its closing underscore
	f.Add("ory_0123456789abcdef0123456789abcdef")      // the opening with no word naming a kind
	f.Add("ory_key_0123456789abcdef0123456789abcdef")  // a word no key is issued with
	f.Add("ory_pat_0123456789abcdef0123456789abcdef-suffix")
	f.Add("ory_pat_0123456789abcdef0123456789abcdef_suffix")
	f.Add("ory_pat_0123456789abcdef0123456789abcdef\nory_wak_0123456789ABCDEF0123456789ABCDEF")
	// A key beginning inside the match before it, and two keys of different
	// kinds with nothing between them.
	f.Add("ory_pat_0123456789abcdef0123456789abcdefory_pat_0123456789abcdef0123456789abcdef")
	f.Add("ory_pat_0123456789abcdef0123456789abcdefory_apikey_0123456789ABCDEF0123456789ABCDEF")
	// Candidate positions crowded as close as they can be, with no word naming
	// a kind and with no run long enough for any of them, and keys written into
	// one another so that every candidate has one.
	f.Add(strings.Repeat("ory_", 16))
	f.Add(strings.Repeat("ory_pat_", 16))
	f.Add(strings.Repeat("ory_pat_0123456789abcdef0123456789abcdef", 4))
	// The digest that falls short of the floor. An MD5 written behind a prefix
	// is the case above: it is exactly the thirty-two characters a body is.
	f.Add("ory_pat_0123456789abcdef01234567")
	f.Add("key: ory_pat_0123456789abcdef0123456789abcdef01234567")
	// The prefixes Ory writes on the credentials that are not API keys.
	f.Add("ory_at_0123456789abcdef0123456789abcdef")
	f.Add("ory_rt_0123456789abcdef0123456789abcdef")
	f.Add("ory_session_0123456789abcdef0123456789abcdef")
	// Snake_case names closing on the opening, which ordinary code carries, and
	// one whose segments spell a whole prefix with a body behind it.
	f.Add("repository_pattern = None")
	f.Add("memory_wakeup_timer = 30")
	f.Add("inventory_pat_index_by_id")
	f.Add("memory_pat_0123456789abcdef0123456789abcdef")
	// The prefix written inside a run of base64url, which is the over-match the
	// pattern admits.
	f.Add("payload=zzzzory_pat_0123456789abcdef0123456789abcdefzzzz")
	f.Add("****************************************************************************")

	fuzzAgainstReference(f, OryAPIKey().Find, referenceOryAPIKeyFind)
}

// oryAPIKeyFindBenchmarks is what this scan is timed on. The builtinPatterns
// entry for the pattern names it, and BenchmarkBuiltins times every case it
// holds under the pattern's own name, so that a built-in cannot arrive without
// a benchmark. Every case is held to the count it states under a plain go test
// as well, which is what a benchmark nobody has run yet cannot be.
func oryAPIKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens a prefix, so what the line times is the
	// search for the underscore behind the opening — which is most of what this
	// pattern costs a caller whose text holds no key. The line carries the
	// letters of the opening in the host name and in the words around it, which
	// is what the anchor is chosen against.
	line := `time=2026-08-17T00:00:00Z level=info msg="identity created" project=romantic-hill-01234567 url=https://practical-swirles-89abcdef.projects.oryapis.com/admin/identities `
	key := "ory_pat_0123456789abcdef0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every four characters with no word naming a kind
			// behind any of them: each reaches the loop over the kinds and none
			// gets past it. What it times is the cheapest rejection a candidate
			// that opened correctly can have.
			name:  "candidates that are not values",
			src:   strings.Repeat("ory_", 128),
			spans: 0,
		},
		{
			// Whole prefixes with nothing behind them, which is the same
			// rejection one step further along: every one reaches the walk over
			// a run and every one is turned away by the floor.
			name:  "prefixes with no body",
			src:   strings.Repeat("ory_pat_", 128),
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
			src:   strings.Repeat("ory_pat_0123456789abcdef0123456789abcdef", 128) + "ory",
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
