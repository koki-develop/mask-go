package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The LangSmith API key pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. A first run opens on 0123456789abcdef and carries
// on through the alphabet to thirty-two characters, which is the shortest one
// the scan reads, since the count is a floor and a run shortened for
// readability would leave a case holding no key at all. Carrying on rather than
// writing those sixteen twice is what states the alphabet: a first run reaching
// past f is what a scan reading hexadecimal would locate nothing of. The run
// joined to it is the first ten of those characters. Both are spelled in
// lowercase where the case does not matter and in uppercase where the case is
// what a case is about: base62 holds the letters of both, so either spelling is
// a run.
//
// Test_LangSmithAPIKey_aDigestBehindThePrefix is where a body is written in
// hexadecimal instead, and the alphabet is what those cases are about: a digest
// is one class of characters and this pattern reads it as a first run.

func Test_LangSmithAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789",
			want: []Span{{0, 51}},
		},
		{
			name: "a key in an environment assignment",
			src:  "LANGSMITH_API_KEY=lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789",
			want: []Span{{18, 69}},
		},
		{
			// base62 holds the letters of both cases, so runs written in
			// capitals are runs.
			name: "runs written in capitals",
			src:  "lsv2_sk_0123456789ABCDEFGHIJKLMNOPQRSTUV_0123456789",
			want: []Span{{0, 51}},
		},
		{
			// The count is a floor, so a first run longer than the shortest one
			// is a key to the end of what is joined to it rather than a key and
			// a character left over.
			name: "a first run longer than the shortest one",
			src:  "lsv2_pt_0123456789abcdefghijklmnopqrstuvw_0123456789",
			want: []Span{{0, 52}},
		},
		{
			name: "two keys separated by a space",
			src:  "lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789 lsv2_sk_0123456789ABCDEFGHIJKLMNOPQRSTUV_0123456789",
			want: []Span{{0, 51}, {52, 103}},
		},
		{
			// A key written into the run another key's tail is: the second one
			// opens where the first one's last run reaches, so the first span
			// covers the second key whole and the second begins inside it. A
			// scan resuming past a match would step over the second key
			// altogether. The spans overlap, which a Masker resolves into one.
			name: "a key written into the tail of the key before it",
			src:  "lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789",
			want: []Span{{0, 102}, {51, 102}},
		},
		{
			// And a key beginning inside the first run of the one before it,
			// which is what the four characters of the opening being base62
			// makes possible: the first key's first run closes with lsv2 and
			// the underscore of the second key's prefix stands directly behind
			// it.
			name: "a key beginning inside the first run of the key before it",
			src:  "lsv2_pt_0123456789abcdefghijklmnopqrlsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789",
			want: []Span{{0, 87}, {36, 87}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := LangSmithAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LangSmithAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "lsv2_pt_",
		},
		{
			// Thirty-one characters where the pattern asks for thirty-two. This
			// is the shape a line cut to a column limit leaves, and the
			// characters in front of the cut stay in the text: the far side of
			// reading a floor, which builtin_langsmith_api_key.go weighs.
			name: "a first run one character too short",
			src:  "lsv2_pt_0123456789abcdefghijklmnopqrstu",
		},
		{
			// The hyphen is a base64url character and no base62 one, so it ends
			// a run where what stands in front of it is too short to be a first
			// run.
			name: "a first run carrying a hyphen",
			src:  "lsv2_pt_0123456789abcdef-hijklmnopqrstuv",
		},
		{
			// The underscore joins a run to the one in front of it, and the
			// floor is asked of the first alone: sixteen characters and then
			// fifteen more is no key, where thirty-two and then ten is one.
			name: "the floor divided across two runs",
			src:  "lsv2_pt_0123456789abcdef_hijklmnopqrstuv",
		},
		{
			name: "an uppercase prefix",
			src:  "LSV2_PT_0123456789abcdefghijklmnopqrstuv_0123456789",
		},
		{
			// The prefix is written with the underscores LangSmith divides it
			// by, not with the hyphen a delimiter is elsewhere.
			name: "hyphens where the prefix carries underscores",
			src:  "lsv2-pt-0123456789abcdefghijklmnopqrstuv-0123456789",
		},
		{
			// The word naming the kind has to be closed by the second
			// underscore, so a run written straight against it is no run.
			name: "the prefix without its closing underscore",
			src:  "lsv2_pt0123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "the opening without a word naming a kind",
			src:  "lsv2_0123456789abcdefghijklmnopqrstuv",
		},
		{
			// A word opening on the byte a kind opens on, which is where the
			// loop over the kinds reads past the first character.
			name: "a word no key is issued with where the kind stands",
			src:  "lsv2_st_0123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "a space in the first run",
			src:  "lsv2_pt_0123456789abcdef hijklmnopqrstuv",
		},
		{
			name: "a dot in the first run",
			src:  "lsv2_pt_0123456789abcdef.hijklmnopqrstuv",
		},
		{
			name: "a first run broken by a line break",
			src:  "lsv2_pt_0123456789abcdef\nhijklmnopqrstuv",
		},
		{
			// Runs of the right shape opening with no prefix. The prefix is
			// most of the anchor, so runs long enough are no key without it.
			name: "runs of the right shape opening with no prefix",
			src:  "0123456789abcdefghijklmnopqrstuv_0123456789",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := LangSmithAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_LangSmithAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "LANGSMITH_API_KEY=lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789",
			want: "LANGSMITH_API_KEY=***************************************************",
		},
		{
			// The header the LangSmith API is called with.
			name: "an api key header",
			src:  "x-api-key: lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789",
			want: "x-api-key: ***************************************************",
		},
		{
			name: "json",
			src:  `{"api_key":"lsv2_sk_0123456789abcdefghijklmnopqrstuv_0123456789"}`,
			want: `{"api_key":"***************************************************"}`,
		},
		{
			name: "a command line",
			src:  `curl -H "x-api-key: lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789" https://api.smith.langchain.com/api/v1/runs`,
			want: `curl -H "x-api-key: ***************************************************" https://api.smith.langchain.com/api/v1/runs`,
		},
		{
			// The environment block a traced service is configured with.
			name: "a configuration environment block",
			src:  `"env": {"LANGSMITH_API_KEY": "lsv2_sk_0123456789abcdefghijklmnopqrstuv_0123456789"}`,
			want: `"env": {"LANGSMITH_API_KEY": "***************************************************"}`,
		},
		{
			name: "twice",
			src:  "lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789 lsv2_sk_0123456789ABCDEFGHIJKLMNOPQRSTUV_0123456789",
			want: "*************************************************** ***************************************************",
		},
		{
			// The two spans are merged, so the key written into the tail of the
			// one before it leaves nothing of itself behind.
			name: "a key written into the tail of the key before it",
			src:  "lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789",
			want: "******************************************************************************************************",
		},
	}

	m := New(WithPatterns(LangSmithAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LangSmithAPIKey_theTwoPrefixes(t *testing.T) {
	// The two prefixes LangSmith names: lsv2_pt_, which a personal access token
	// carries, and lsv2_sk_, which a service key carries. Both are read with
	// the same body, and builtin_langsmith_api_key.go argues why they are one
	// pattern rather than two; the cases are what makes a change of mind about
	// either a decision rather than a widening nobody noticed.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "the prefix a personal access token carries",
			src:  "lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789",
			want: "***************************************************",
		},
		{
			name: "the prefix a service key carries",
			src:  "lsv2_sk_0123456789abcdefghijklmnopqrstuv_0123456789",
			want: "***************************************************",
		},
	}

	m := New(WithPatterns(LangSmithAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LangSmithAPIKey_theLegacyPrefix(t *testing.T) {
	// The prefix LangSmith issued keys under before these, held to being left
	// in the text. Support for it ended and v2 tracing rejects a key carrying
	// it, so what reading it would locate authenticates nothing;
	// builtin_langsmith_api_key.go weighs that against what two letters of
	// anchor would draw in.
	//
	// The two ways of being wrong about it fail differently, which is what this
	// case is for. Reading the prefix is caught here: the first case below
	// stops passing. Leaving out a prefix LangSmith does issue keys under is
	// caught by nothing — a prefix no key carries opens no candidate, so the
	// scan locates nothing, and nothing anywhere fails for a pattern that
	// located nothing.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "the prefix the keys before these carry",
			src:  "LANGCHAIN_API_KEY=ls__0123456789abcdefghijklmnopqrstuv",
			want: "LANGCHAIN_API_KEY=ls__0123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "the same body behind a prefix in use",
			src:  "LANGCHAIN_API_KEY=lsv2_pt_0123456789abcdefghijklmnopqrstuv",
			want: "LANGCHAIN_API_KEY=****************************************",
		},
	}

	m := New(WithPatterns(LangSmithAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LangSmithAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xlsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789",
			want: "x***************************************************",
		},
		{
			name: "underscore before",
			src:  "LANGSMITH_API_KEY_lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789",
			want: "LANGSMITH_API_KEY_***************************************************",
		},
	}

	m := New(WithPatterns(LangSmithAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LangSmithAPIKey_reachesTheEndOfTheRuns(t *testing.T) {
	// What reading the tail costs. A key is written in more than one run, so
	// the span goes on for as long as an underscore joins another run to the
	// last — which buys the tail of every key being redacted with it, and costs
	// the name written against a key in that same shape being redacted too.
	//
	// The last two cases are where it stops. A run has to carry at least one
	// character, so a second underscore ends a body where it stands, and the
	// hyphen belongs to no run at all.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the key is lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789.",
			want: "the key is ***************************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export LANGSMITH_API_KEY="lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789"`,
			want: `export LANGSMITH_API_KEY="***************************************************"`,
		},
		{
			name: "a word against the key",
			src:  "lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789suffix",
			want: "*********************************************************",
		},
		{
			name: "an underscored word against the key",
			src:  "lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789_suffix",
			want: "**********************************************************",
		},
		{
			name: "a second underscore against the key",
			src:  "lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789__suffix",
			want: "***************************************************__suffix",
		},
		{
			name: "a dashed word against the key",
			src:  "lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789-suffix",
			want: "***************************************************-suffix",
		},
	}

	m := New(WithPatterns(LangSmithAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LangSmithAPIKey_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than
	// redacted. A line cut to a column limit partway through a key leaves a
	// prefix and a run too short to be a first run, and the characters written
	// before the cut come through whole.
	//
	// It is the price of a count read as a floor, and the cases move with the
	// scan: one of them starting to be located means the floor moved, and that
	// is a decision to be taken rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a key one character short of the floor",
			src:  "LANGSMITH_API_KEY=lsv2_pt_0123456789abcdefghijklmnopqrstu",
		},
		{
			name: "a key cut off at its prefix",
			src:  "LANGSMITH_API_KEY=lsv2_pt_",
		},
		{
			name: "a key cut off inside the word naming its kind",
			src:  "LANGSMITH_API_KEY=lsv2_p",
		},
	}

	m := New(WithPatterns(LangSmithAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_LangSmithAPIKey_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix carries two
	// underscores, which standard base64 writes nowhere, so only a base64url
	// encoding can hold one — and where thirty-two base62 characters follow,
	// everything from the prefix to the end of the runs behind it is redacted.
	//
	// The cases are held to being redacted rather than to being spared. What is
	// taken is a stretch of a value already opaque to a reader, and the runs are
	// a key's shape exactly: nothing is left in the text to tell the two apart,
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
			src:  "payload=zzzzlsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789zzzz",
			want: "payload=zzzz*******************************************************",
		},
		{
			// The same runs written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the
			// LangSmith pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzlsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789zzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz*******************************************************",
		},
	}

	m := New(WithPatterns(LangSmithAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LangSmithAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_langsmith_api_key.go names, held to the answer it
	// gives rather than to the one a reader might want. Hexadecimal digits are
	// base62 and a digest carries nothing that ends a run, so an MD5 written
	// behind a prefix is exactly the thirty-two characters a first run is and is
	// redacted, as the longer digests are. Declining them would mean declining
	// every key LangSmith wrote in the digits and the first six letters alone,
	// which is the whole credential against a cache key.
	//
	// The bodies here are the ordered run written twice rather than carried on
	// through the alphabet, because a digest is what the cases are about and a
	// digest is hexadecimal.
	//
	// The two below are where the floor and the prefix each hold: a digest of
	// twenty-four characters falls short of a first run, and a hyphen is no
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
			src:  "lsv2_pt_0123456789abcdef0123456789abcdef",
			want: "****************************************",
		},
		{
			name: "a sha1 behind the prefix in a cache key",
			src:  "key: lsv2_pt_0123456789abcdef0123456789abcdef01234567",
			want: "key: ************************************************",
		},
		{
			name: "a digest of twenty-four characters, eight short of a first run",
			src:  "lsv2_pt_0123456789abcdef01234567",
			want: "lsv2_pt_0123456789abcdef01234567",
		},
		{
			name: "an md5 behind a hyphen rather than the prefix",
			src:  "lsv2-pt-0123456789abcdef0123456789abcdef",
			want: "lsv2-pt-0123456789abcdef0123456789abcdef",
		},
	}

	m := New(WithPatterns(LangSmithAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_langSmithAPIKeyOpening(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a key can
	// begin inside the one before it, and that holds only while the opening is
	// written in the alphabet a run is. An opening carrying a character outside
	// it would make the two impossible to nest, and the cases above pinning the
	// nesting would stand for nothing — which is not a failure anything else
	// here reports.
	if langSmithAPIKeyOpening == "" {
		t.Fatal("the pattern carries no opening, so it locates nothing")
	}
	for i := range len(langSmithAPIKeyOpening) {
		if c := langSmithAPIKeyOpening[i]; !isBase62Byte(c) {
			t.Errorf("the opening carries %q, which no run may be written with, so no key can begin inside another", c)
		}
	}
}

func Test_langSmithAPIKeyKinds(t *testing.T) {
	// The scan stops at the first word it matches rather than trying the rest,
	// which is right only while at most one of them can stand at a position.
	// Two words stand at one only where one is written inside the other from
	// its start, so nesting is what would lose a key: the word matched first
	// ends the search, and the kind it hid goes unlocated with nothing here to
	// report it.
	//
	// That is the first of the two checks below, and it is asked of every
	// ordered pair rather than of each pair once, since which of two nested
	// words is reached first is the order of the table and nothing holds that.
	//
	// The second asks for more. Words opening on different bytes cannot nest,
	// so it rules the nesting out again and buys the byte the loop turns a word
	// away on besides.
	if len(langSmithAPIKeyKinds) == 0 {
		t.Fatal("the pattern names no kind, so it locates nothing")
	}

	// The count builtin_langsmith_api_key.go states in prose, held here so that
	// a kind added fails where the sentence naming the number can be found.
	if got, want := len(langSmithAPIKeyKinds), 2; got != want {
		t.Errorf("the table names %d kind(s) and builtin_langsmith_api_key.go says %d", got, want)
	}
	for _, kind := range langSmithAPIKeyKinds {
		if kind == "" {
			t.Fatal("a kind is empty, so its prefix is the opening and the separators alone")
		}
		for i := range len(kind) {
			if c := kind[i]; !isBase62Byte(c) {
				t.Errorf("the kind %q carries %q, which the separator would then not divide from a body", kind, c)
			}
		}
	}
	for i, kind := range langSmithAPIKeyKinds {
		for j, other := range langSmithAPIKeyKinds {
			if i == j {
				continue
			}
			// The one that decides whether a key is located at all.
			if strings.HasPrefix(other, kind) {
				t.Errorf("the kind %q opens %q, so a key of the second kind is located nowhere: the loop matches the first, finds no separator behind it and gives up on the candidate", kind, other)
			}
		}
		for _, other := range langSmithAPIKeyKinds[i+1:] {
			// And the one that decides what a position costs.
			if kind[0] == other[0] {
				t.Errorf("the kinds %q and %q open on the same byte, so the loop no longer turns a word away on one", kind, other)
			}
		}
	}
}

func Test_langSmithAPIKeyPrefixes_bodyNeverMovesBack(t *testing.T) {
	// The scan keeps a cursor over the runs behind a body and reuses it
	// wherever a body opens in front of where those runs ended. That is sound
	// only while a body never opens in front of the body of the candidate
	// before it: were one to, the cursor would answer for a stretch of text it
	// had never looked at, and a key there would be mislocated rather than
	// missed.
	//
	// It rests on one character: the last of the prefix, which no run is
	// written with. A body opens directly behind it, so every body opens where
	// a run opens, and bodies therefore follow one another in the order their
	// candidates are found. Were that character one a run admits, a body could
	// open inside the run of the candidate before it — and a line dense in
	// prefixes would be walked once for every candidate in it besides.
	if len(langSmithAPIKeyPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so there is no candidate to reason about")
	}
	for _, p := range langSmithAPIKeyPrefixes {
		if c := p[len(p)-1]; isBase62Byte(c) {
			t.Errorf("the prefix %q closes with %q, which a run may be written with, so a body can open inside the body of the candidate before it", p, c)
		}
	}
}

// Test_langSmithAPIKeyAnchor holds every prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_langSmithAPIKeyAnchor(t *testing.T) {
	for _, p := range langSmithAPIKeyPrefixes {
		if langSmithAPIKeyAnchorIndex >= len(p) {
			t.Errorf("the anchor stands at %d, the prefix %q is %d characters", langSmithAPIKeyAnchorIndex, p, len(p))
			continue
		}
		if c := p[langSmithAPIKeyAnchorIndex]; c != langSmithAPIKeyAnchor {
			t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", p, c, byte(langSmithAPIKeyAnchor))
		}
	}
}

func Test_LangSmithAPIKey_scanIsLinear(t *testing.T) {
	// A line dense in prefixes holds a candidate for every five characters it
	// has, and the runs a body is made of are joined by the character a prefix
	// closes with — so a line of keys written against one another is one stretch
	// of text that every candidate in it reads to the end of. Walking it at
	// every candidate would cost time quadratic in the length of the line, and
	// the cursor is what keeps it to one walk. The bound here is far above a
	// linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every fifty bytes where they are densest, because a sample has
	// to carry a whole key to be one. The crowding a line can actually carry
	// stays here.
	sources := map[string]string{
		// Candidates as close together as the opening allows, none of them
		// carrying a word that names a kind: every one reaches the loop over
		// the kinds and every one is rejected there.
		"a candidate every five characters": strings.Repeat("lsv2_", 200000),
		// Whole prefixes as close together as they go, none of them with a run
		// long enough to be a first run: every one reaches the walk over a run
		// and every one is rejected behind it.
		"a prefix every eight characters": strings.Repeat("lsv2_pt_", 125000),
		// Keys joined to one another by the character their own runs are joined
		// by. Every candidate is a key, every one of them reads runs that reach
		// the end of the line, and this is the input the cursor is for.
		"keys joined by an underscore": strings.Repeat("lsv2_pt_0123456789abcdefghijklmnopqrstuv_", 25000),
		// The same crowding reached the other way: each key written straight
		// against the one in front of it, so every candidate begins inside the
		// tail of the one before it.
		"a key written into the tail of every key": strings.Repeat("lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789", 20000),
		// One candidate whose first run is the whole line, which is the walk
		// over a run reading the length of the input and finding a key.
		"a first run that runs the length of the line": "lsv2_pt_" + strings.Repeat("a", 1800000),
		// One candidate whose runs are as short as runs go, which is the walk
		// over the tail stopping and resuming for every character of the line.
		"runs of one character the length of the line": "lsv2_pt_" + strings.Repeat("a", 32) + strings.Repeat("_a", 900000),
		// An anchor every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("a_", 900000),
		// And the characters of the opening with no anchor among them, which is
		// the walk reading a whole line and stopping nowhere in it.
		"the characters of the opening with no anchor": strings.Repeat("lsv2", 450000),
	}

	checkScanIsLinear(t, LangSmithAPIKey(), sources)
}

// referenceLangSmithAPIKey is the expression the scan in
// builtin_langsmith_api_key.go reads by hand: the statement of what a LangSmith
// API key is, kept here so that the scan can be held to it.
//
// The opening, the kinds, the separator, the floor and the alphabet are spelled
// again rather than built from langSmithAPIKeyOpening, langSmithAPIKeyKinds,
// langSmithAPIKeySeparator, langSmithAPIKeyBodyChars and isBase62Byte. A
// reference sharing those declarations could not disagree with the scan about
// them, and it is exactly that disagreement the fuzz target below is for: the
// two have to be changed together or reported apart.
//
// The floor is written as a counted repetition, which costs an engine a machine
// as wide as the floor at every candidate, and that is not what this expression
// costs: measured against a line of keys joined by the separator, taking the
// floor out changes nothing. What does cost is the tail. Every match runs to
// the end of such a line, since the separator joining two runs is the one a
// prefix closes with, so a reference asking at every byte reads the rest of the
// line once for every key in it — eighty kilobytes of that takes the expression
// seconds where the scan beside it takes a fraction of a millisecond, and it is
// the grammar rather than the engine, since a walk written by hand would read
// the same text as many times.
//
// What keeps that off the target is how much a fuzzer writes. The seeds below
// crowd the candidates as close as they go and are hundreds of bytes, where the
// cost begins to show in tens of thousands.
var referenceLangSmithAPIKey = regexp.MustCompile(`lsv2_(?:pt|sk)_[0-9A-Za-z]{32,}(?:_[0-9A-Za-z]+)*`)

// referenceLangSmithAPIKeyFind locates keys the plain way: the leftmost match
// of the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a key can begin inside one: the four characters
// of the opening are written in the alphabet a run is, and the separator that
// joins two runs is the one a prefix closes with, so a key stands inside the
// one in front of it both ways. The scan finds both and reports the two spans
// overlapping for a Masker to resolve, so the reference must ask about both.
func referenceLangSmithAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceLangSmithAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzLangSmithAPIKey_matchesReference guards the hand-written scan: the
// opening it searches back from, the words it admits between that opening and
// the second separator, the floor it holds a first run to, the alphabet it
// reads the runs in, the cursor it carries between candidates and the byte it
// resumes at may none of them change which keys are located.
func FuzzLangSmithAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("LANGSMITH_API_KEY=lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789")
	f.Add("lsv2_sk_0123456789ABCDEFGHIJKLMNOPQRSTUV_0123456789")
	f.Add("lsv2_pt_0123456789abcdefghijklmnopqrstu")     // one short of a first run
	f.Add("lsv2_pt_0123456789abcdefghijklmnopqrstuvw_0") // and a first run longer than one
	f.Add("lsv2_pt_0123456789abcdef-hijklmnopqrstuv")    // a hyphen, which base64url admits and base62 does not
	f.Add("lsv2_pt_0123456789abcdef_hijklmnopqrstuv")    // the floor divided across two runs
	f.Add("lsv2_pt_0123456789abcdef.hijklmnopqrstuv")    // a dot ends a run
	f.Add("LSV2_PT_0123456789abcdefghijklmnopqrstuv")    // an uppercase prefix
	f.Add("lsv2-pt-0123456789abcdefghijklmnopqrstuv")    // hyphens where the prefix carries underscores
	f.Add("lsv2_pt0123456789abcdefghijklmnopqrstuv")     // the prefix without its closing underscore
	f.Add("lsv2_0123456789abcdefghijklmnopqrstuv")       // the opening with no word naming a kind
	f.Add("lsv2_st_0123456789abcdefghijklmnopqrstuv")    // a word no key is issued with, opening on a kind's byte
	f.Add("lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789suffix")
	f.Add("lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789_suffix")
	f.Add("lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789__suffix")
	f.Add("lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789-suffix")
	f.Add("lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789\nlsv2_sk_0123456789ABCDEFGHIJKLMNOPQRSTUV_0123456789")
	// A key written into the tail of the one before it, and one beginning
	// inside the first run of the one before it.
	f.Add("lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789")
	f.Add("lsv2_pt_0123456789abcdefghijklmnopqrlsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789")
	// Candidate positions crowded as close as they can be, with no word naming
	// a kind and with no run long enough for any of them, and keys joined by
	// the separator so that every candidate reads the runs of every key behind
	// it.
	f.Add(strings.Repeat("lsv2_", 16))
	f.Add(strings.Repeat("lsv2_pt_", 16))
	f.Add(strings.Repeat("lsv2_pt_0123456789abcdefghijklmnopqrstuv_", 4))
	// The digest, whose class is what a first run reaches past. An MD5 written
	// behind a prefix is exactly the thirty-two characters a first run is, and
	// one of twenty-four falls short of the floor.
	f.Add("lsv2_pt_0123456789abcdef01234567")
	f.Add("lsv2_pt_0123456789abcdef0123456789abcdef")
	f.Add("key: lsv2_pt_0123456789abcdef0123456789abcdef01234567")
	// The prefix LangSmith issued keys under before these, which the scan does
	// not read.
	f.Add("ls__0123456789abcdefghijklmnopqrstuv")
	// Snake_case names carrying the separator the search stops at.
	f.Add("run_id = None")
	f.Add("trace_id_lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789")
	// The prefix written inside a run of base64url, which is the over-match the
	// pattern admits.
	f.Add("payload=zzzzlsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789zzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzlsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789zzzz")

	fuzzAgainstReference(f, LangSmithAPIKey().Find, referenceLangSmithAPIKeyFind)
}

// langSmithAPIKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func langSmithAPIKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens a prefix, so what the line times is the
	// search for the underscore behind the opening — which is most of what this
	// pattern costs a caller whose text holds no key. The line carries the
	// characters of the opening in the host name and in the words around it,
	// and the separator in the field names, which is what the anchor is chosen
	// against.
	line := `time=2026-08-17T00:00:00Z level=info msg="run created" run_id=0123456789abcdef trace_id=0123456789abcdef url=https://api.smith.langchain.com/api/v1/runs `
	key := "lsv2_pt_0123456789abcdefghijklmnopqrstuv_0123456789"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every five characters with no word naming a kind
			// behind any of them: each reaches the loop over the kinds and none
			// gets past it. What it times is the cheapest rejection a candidate
			// that opened correctly can have.
			name:  "candidates that are not values",
			src:   strings.Repeat("lsv2_", 128),
			spans: 0,
		},
		{
			// Whole prefixes with nothing behind them, which is the same
			// rejection one step further along: every one reaches the walk over
			// a run and every one is turned away by the floor.
			name:  "prefixes with no body",
			src:   strings.Repeat("lsv2_pt_", 128),
			spans: 0,
		},
		{
			// Keys joined to one another by the character their own runs are
			// joined by, so every candidate reads runs reaching the end of the
			// line. This is what the cursor is for, and what times it.
			name:  "keys joined by an underscore",
			src:   strings.Repeat("lsv2_pt_0123456789abcdefghijklmnopqrstuv_", 128),
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
