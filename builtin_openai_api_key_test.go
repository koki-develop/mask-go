package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The OpenAI API key pattern: what it locates and what it leaves alone, written
// out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The keys written out below are made only of ordered characters around the
// marker: valid in shape, obviously not real. The run they are built from,
// 0123456789abcdef, stands in for the seventy-four or fifty-eight random
// characters a real key carries on either side of T3BlbkFJ, or the twenty an
// older one does — the scan reads those as runs rather than to a count, so
// sixteen states the grammar as well as seventy-four would and leaves a case
// short enough to read.

func Test_OpenAIAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a project key on its own",
			src:  "sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef",
			want: []Span{{0, 48}},
		},
		{
			name: "a project key in an environment assignment",
			src:  "OPENAI_API_KEY=sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef",
			want: []Span{{15, 63}},
		},
		{
			name: "a service account key",
			src:  "sk-svcacct-0123456789abcdefT3BlbkFJ0123456789abcdef",
			want: []Span{{0, 51}},
		},
		{
			name: "an admin api key",
			src:  "sk-admin-0123456789abcdefT3BlbkFJ0123456789abcdef",
			want: []Span{{0, 49}},
		},
		{
			// The kind of key issued before projects existed, which carries no
			// name of a kind between the prefix and the run at all.
			name: "a user key with no kind behind the prefix",
			src:  "sk-0123456789abcdefT3BlbkFJ0123456789abcdef",
			want: []Span{{0, 43}},
		},
		{
			// The prefix a kind names itself with is read as the opening of the
			// run rather than as a table of prefixes, so a kind the scan was
			// never told about is located like any other.
			name: "a kind the scan carries no name for",
			src:  "sk-service-0123456789abcdefT3BlbkFJ0123456789abcdef",
			want: []Span{{0, 51}},
		},
		{
			name: "the older kind written with a placeholder for the organization",
			src:  "sk-None-0123456789abcdefT3BlbkFJ0123456789abcdef",
			want: []Span{{0, 48}},
		},
		{
			// The hyphen and the underscore are base64url characters, and the
			// keys published carry both between the letters and digits of a
			// run.
			name: "runs carrying a hyphen and an underscore",
			src:  "sk-proj-0123456789abcdef-0123456789abcdef_T3BlbkFJ0123456789abcdef",
			want: []Span{{0, 66}},
		},
		{
			// The run is read to its end rather than to a count, so a key of
			// any length is located whole. Here the run in front of the marker
			// is three times the one behind it.
			name: "runs of unequal length",
			src:  "sk-proj-0123456789abcdef0123456789abcdef0123456789abcdefT3BlbkFJ0123456789abcdef",
			want: []Span{{0, 80}},
		},
		{
			// A line cut just past the marker still carries every random
			// character in front of it, and those are as much of the key as
			// the ones that were cut.
			name: "a key cut off at the marker",
			src:  "sk-proj-0123456789abcdefT3BlbkFJ",
			want: []Span{{0, 32}},
		},
		{
			name: "two keys separated by a space",
			src:  "sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef sk-admin-0123456789abcdefT3BlbkFJ0123456789abcdef",
			want: []Span{{0, 48}, {49, 98}},
		},
		{
			// The prefix is written in the alphabet a run is, so a key can
			// begin inside the span of the one before it, and a scan resuming
			// past a match would step over it. The spans overlap, which a
			// Masker resolves into one.
			name: "a key beginning inside the key before it",
			src:  "sk-sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef",
			want: []Span{{0, 51}, {3, 51}},
		},
		{
			// Two whole keys with nothing at all between them. Every character
			// of both keys belongs to the run alphabet, so the second key's
			// prefix stands inside the run the first one closes on, and the
			// scan reports both: the first reaching over the second entirely,
			// the second beginning where its own prefix stands.
			name: "two whole keys with nothing between them",
			src:  "sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdefsk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef",
			want: []Span{{0, 96}, {48, 96}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := OpenAIAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OpenAIAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "sk-",
		},
		{
			name: "a prefix and a run carrying no marker",
			src:  "sk-proj-0123456789abcdef0123456789abcdef",
		},
		{
			name: "the marker with no prefix in front of it",
			src:  "0123456789abcdefT3BlbkFJ0123456789abcdef",
		},
		{
			// Seven of the marker's eight characters. The whole of it is read,
			// so a run carrying part of it carries none.
			name: "seven characters of the marker",
			src:  "sk-proj-0123456789abcdefT3BlbkF0123456789abcdef",
		},
		{
			name: "a marker in the wrong case",
			src:  "sk-proj-0123456789abcdeft3blbkfj0123456789abcdef",
		},
		{
			// The run in front of the marker is what carries the prefix to it.
			// A space, a dot or a quote ends that run, so the marker then
			// stands in a run of its own with no prefix in it.
			name: "a space between the prefix and the marker",
			src:  "sk-proj-0123456789abcdef T3BlbkFJ0123456789abcdef",
		},
		{
			name: "a dot between the prefix and the marker",
			src:  "sk-proj-0123456789abcdef.T3BlbkFJ0123456789abcdef",
		},
		{
			// Standard base64 rather than base64url: the two characters
			// base64url writes as - and _ are + and /, and neither belongs to
			// the alphabet a run is read in, so neither carries the prefix to
			// the marker.
			name: "a plus between the prefix and the marker",
			src:  "sk-proj-0123456789abcdef+T3BlbkFJ0123456789abcdef",
		},
		{
			name: "a slash between the prefix and the marker",
			src:  "sk-proj-0123456789abcdef/T3BlbkFJ0123456789abcdef",
		},
		{
			name: "a line break between the prefix and the marker",
			src:  "sk-proj-0123456789abcdef\nT3BlbkFJ0123456789abcdef",
		},
		{
			name: "an uppercase prefix",
			src:  "SK-proj-0123456789abcdefT3BlbkFJ0123456789abcdef",
		},
		{
			// The prefix is three characters and all three are read. An
			// underscore where the hyphen is is not one.
			name: "an underscore where the prefix carries a hyphen",
			src:  "sk_proj-0123456789abcdefT3BlbkFJ0123456789abcdef",
		},
		{
			// The marker stands behind the prefix, never in front of it: the
			// run is searched from the prefix on.
			name: "the marker in front of the prefix",
			src:  "T3BlbkFJ0123456789abcdefsk-0123456789abcdef",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// A hyphenated word carries the prefix and no marker, which is the
			// whole of what turns it away.
			name: "a hyphenated word carrying the prefix",
			src:  "the task-list and the risk-register were both reviewed",
		},
		{
			// Forty hexadecimal characters. A digest carries no hyphen, so it
			// holds no prefix to be found at, and neither T nor J is a
			// hexadecimal digit, so it holds no marker either.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := OpenAIAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_OpenAIAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "OPENAI_API_KEY=sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef",
			want: "OPENAI_API_KEY=************************************************",
		},
		{
			name: "quoted",
			src:  `"sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef"`,
			want: `"************************************************"`,
		},
		{
			name: "json",
			src:  `{"apiKey":"sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef"}`,
			want: `{"apiKey":"************************************************"}`,
		},
		{
			// The header the OpenAI API takes a key in.
			name: "an authorization header",
			src:  "Authorization: Bearer sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef",
			want: "Authorization: Bearer ************************************************",
		},
		{
			name: "a command line",
			src:  "curl -H 'Authorization: Bearer sk-admin-0123456789abcdefT3BlbkFJ0123456789abcdef' https://api.openai.com/v1/organization/projects",
			want: "curl -H 'Authorization: Bearer *************************************************' https://api.openai.com/v1/organization/projects",
		},
		{
			name: "twice",
			src:  "sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef sk-svcacct-0123456789abcdefT3BlbkFJ0123456789abcdef",
			want: "************************************************ ***************************************************",
		},
		{
			// The two spans are merged, so the key that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a key beginning inside the key before it",
			src:  "sk-sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef",
			want: "***************************************************",
		},
	}

	m := New(WithPatterns(OpenAIAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OpenAIAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xsk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef",
			want: "x************************************************",
		},
		{
			name: "underscore before",
			src:  "OPENAI_API_KEY_sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef",
			want: "OPENAI_API_KEY_************************************************",
		},
	}

	m := New(WithPatterns(OpenAIAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OpenAIAPIKey_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a run rather than a count. Where a key ends is
	// where its alphabet stops, so ordinary punctuation ends one and nothing
	// written after it joins it — but a character of the key's own alphabet
	// written straight against a key is redacted with the key, which is what
	// buys a key of a length neither OpenAI nor a ruleset states being located
	// whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the key is sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef.",
			want: "the key is ************************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export OPENAI_API_KEY="sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef"`,
			want: `export OPENAI_API_KEY="************************************************"`,
		},
		{
			// The hyphen is a run character, so a hyphenated word written
			// against a key is read as more of the run and redacted with it.
			name: "a dashed word against the key",
			src:  "sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef-suffix",
			want: "*******************************************************",
		},
		{
			name: "a word against the key",
			src:  "sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdefsuffix",
			want: "******************************************************",
		},
	}

	m := New(WithPatterns(OpenAIAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OpenAIAPIKey_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The marker is the base64
	// encoding of OpenAI, so a base64url encoding of bytes holding that word at
	// a position divisible by three carries it; where such an encoding also
	// carries the prefix in front of it, the run from that prefix to the end of
	// the encoding is redacted.
	//
	// The cases are held to being redacted rather than to being spared. What
	// is taken is a stretch of a value already opaque to a reader, and the
	// only tightening on offer is a count; builtin_openai_api_key.go sets out
	// why this scan does not read one. What the table is for is that the cases
	// move with the scan: one of them ceasing to be located means the grammar
	// changed, and that is a decision to be taken rather than noticed
	// afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "inside a base64url payload",
			src:  "payload=zzzzsk-zzzzT3BlbkFJzzzz",
			want: "payload=zzzz*******************",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the
			// OpenAI pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzsk-zzzzT3BlbkFJzzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz*******************",
		},
	}

	m := New(WithPatterns(OpenAIAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OpenAIAPIKey_settlesNothingAboutAnOpenRun(t *testing.T) {
	// A key standing at the very end of the input closes no run: the next byte
	// could carry the run on, and a longer run could still fail to carry a
	// marker where this one already found one, or carry one where it did not.
	// So the scan reports the candidate it has found and holds the answer open
	// from its own start, not from the end of the span it already located.
	src := "sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef"

	spans, retain := OpenAIAPIKey().Find(src)
	if want := []Span{{0, 48}}; !slices.Equal(spans, want) {
		t.Errorf("Find(%q) = %v, want %v", src, spans, want)
	}
	if retain != 0 {
		t.Errorf("Find(%q) settled from %d, want 0", src, retain)
	}
}

func Test_OpenAIAPIKey_settlesOnceTheRunCloses(t *testing.T) {
	// The other side of the same decision. A period does not belong to the
	// alphabet a run is written in, so it closes the run behind the key: no
	// text arriving after it can widen or narrow what was already found, and
	// the whole of the input is settled.
	src := "the key is sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef."

	spans, retain := OpenAIAPIKey().Find(src)
	if want := []Span{{11, 59}}; !slices.Equal(spans, want) {
		t.Errorf("Find(%q) = %v, want %v", src, spans, want)
	}
	if retain != len(src) {
		t.Errorf("Find(%q) settled %d of %d, want the whole of it", src, retain, len(src))
	}
}

func Test_openAIAPIKeyPrefix(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a key can
	// begin inside the run of the one before it, and that holds only while
	// every character of the prefix is one a run may be written in. A prefix
	// carrying a character outside the alphabet would make the two impossible
	// to nest, and the case above pinning the nesting would stand for nothing —
	// which is not a failure anything else here reports.
	if openAIAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for i := range len(openAIAPIKeyPrefix) {
		if c := openAIAPIKeyPrefix[i]; !isBase64URLByte(c) {
			t.Errorf("the prefix holds %q, which no run may be written with", c)
		}
	}
}

// Test_openAIAPIKeyAnchor holds the prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_openAIAPIKeyAnchor(t *testing.T) {
	if openAIAPIKeyAnchorIndex >= len(openAIAPIKeyPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", openAIAPIKeyAnchorIndex, len(openAIAPIKeyPrefix))
	}
	if c := openAIAPIKeyPrefix[openAIAPIKeyAnchorIndex]; c != openAIAPIKeyAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(openAIAPIKeyAnchor))
	}
}

func Test_openAIAPIKeyMarker(t *testing.T) {
	// The marker stands inside the run rather than dividing it, which is what
	// lets the scan settle the whole grammar by asking where the marker ends
	// against where the run does. A marker carrying a character outside the
	// alphabet would end every run in front of itself, and the scan would then
	// locate nothing at all.
	if openAIAPIKeyMarker == "" {
		t.Fatal("the pattern carries no marker, so its prefix alone would locate keys")
	}
	for i := range len(openAIAPIKeyMarker) {
		if c := openAIAPIKeyMarker[i]; !isBase64URLByte(c) {
			t.Errorf("the marker holds %q, which no run may be written with", c)
		}
	}

	// What the eight characters are: the base64 encoding of the vendor's name,
	// which is why they are in the key rather than in front of it.
	if got := base64URLOf("OpenAI"); got != openAIAPIKeyMarker {
		t.Errorf("the marker is %q, the base64 encoding of OpenAI is %q", openAIAPIKeyMarker, got)
	}
}

// base64URLOf encodes s the way the marker is encoded, spelled out here rather
// than taken from encoding/base64 so that the claim about what the marker is
// can be read from the test that makes it.
func base64URLOf(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	var b strings.Builder
	for i := 0; i+3 <= len(s); i += 3 {
		n := int(s[i])<<16 | int(s[i+1])<<8 | int(s[i+2])
		for shift := 18; shift >= 0; shift -= 6 {
			b.WriteByte(alphabet[n>>shift&0x3f])
		}
	}
	return b.String()
}

func Test_OpenAIAPIKey_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a run dense in prefixes
	// holds a candidate for every three characters it has. Two things a
	// candidate needs are searches over the rest of the input rather than
	// bounded tests — where its run ends, and where the marker behind it stands
	// — and working either out again at every candidate costs time quadratic in
	// the length of the line. The bound here is far above a linear scan and far
	// below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// marker in every repetition and so never make a candidate search far. The
	// inputs crafted against what this scan remembers stay here.
	sources := map[string]string{
		// One run, a candidate every three characters, and the marker only at
		// the very end: every candidate that reused nothing would search the
		// whole line for it.
		"a marker only at the end of a long run": strings.Repeat("sk-", 300000) + "T3BlbkFJx",
		// The same crowding with no marker anywhere, which the search made
		// before the loop turns away without reaching a candidate at all.
		"no marker anywhere": strings.Repeat("sk-", 300000),
		// A run that ends before the marker does, so every candidate is
		// rejected after a search that found something too far away.
		"a marker past the end of every run": strings.Repeat("sk-.", 250000) + "T3BlbkFJx",
		// Runs and markers alternating, so the remembered marker is passed
		// again and again and each candidate searches afresh.
		"a marker in every run": strings.Repeat("sk-.T3BlbkFJ.", 80000),
		// Every candidate locates a key here, so the spans are as many as the
		// prefixes and each of them reaches the end of the same run.
		"a key at every candidate": strings.Repeat("sk-T3BlbkFJ", 100000),
	}

	checkScanIsLinear(t, OpenAIAPIKey(), sources)
}

// referenceOpenAIAPIKey is the expression the scan in
// builtin_openai_api_key.go reads by hand: the statement of what an OpenAI API
// key is, kept here so that the scan can be held to it.
//
// The prefix, the marker and the alphabet are spelled again rather than built
// from openAIAPIKeyPrefix, openAIAPIKeyMarker and isBase64URLByte. A reference
// sharing those declarations could not disagree with the scan about them, and
// it is exactly that disagreement the fuzz target below is for: the two have to
// be changed together or reported apart.
//
// Both runs are greedy and both may be empty, which is the grammar the scan
// reads: the run behind the marker is what carries the match to the end of the
// run it stands in, and the one in front of it is what carries the prefix to
// the marker. Where a run holds the marker twice, greediness takes the later of
// them and the scan takes the earlier — the match ends in the same place either
// way, since what ends it is where the alphabet stops.
var referenceOpenAIAPIKey = regexp.MustCompile(`sk-[0-9A-Za-z_-]*T3BlbkFJ[0-9A-Za-z_-]*`)

// referenceOpenAIAPIKeyFind locates keys the plain way: the leftmost match of
// the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a key can begin inside one: the prefix is
// written in the alphabet a run is, so sk-sk-proj-... holds a key the engine
// would never go on to try. The scan finds both and reports the two spans
// overlapping for a Masker to resolve, so the reference must ask about both.
//
// Resuming a byte along costs this one more than a constant, where a reference
// reading a bounded count pays nothing: a match reads its run to the end, so a
// run dense in prefixes is read once for every candidate in it. That is what
// the reference is for — the scan remembers the run and the marker across
// candidates and the reference remembers nothing, so the two agreeing is the
// statement that the remembering is sound.
func referenceOpenAIAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceOpenAIAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzOpenAIAPIKey_matchesReference guards the hand-written scan: the prefix it
// searches for, the marker it asks a run to carry, the alphabet it reads that
// run in, the run and marker it remembers between candidates and the byte it
// resumes at may none of them change which keys are located.
func FuzzOpenAIAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("OPENAI_API_KEY=sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef")
	f.Add("sk-svcacct-0123456789abcdefT3BlbkFJ0123456789abcdef")
	f.Add("sk-admin-0123456789abcdefT3BlbkFJ0123456789abcdef")
	f.Add("sk-0123456789abcdefT3BlbkFJ0123456789abcdef")         // no kind behind the prefix
	f.Add("sk-service-0123456789abcdefT3BlbkFJ0123456789abcdef") // a kind the scan carries no name for
	f.Add("sk-proj-0123456789abcdef-0123456789abcdef_T3BlbkFJ0123456789abcdef")
	f.Add("sk-proj-0123456789abcdefT3BlbkFJ")                        // cut off at the marker
	f.Add("sk-proj-0123456789abcdefT3BlbkF0123456789abcdef")         // seven characters of the marker
	f.Add("sk-proj-0123456789abcdeft3blbkfj0123456789abcdef")        // the marker in the wrong case
	f.Add("sk-proj-0123456789abcdef.T3BlbkFJ0123456789abcdef")       // a dot ends the run in front of the marker
	f.Add("sk-proj-0123456789abcdef+T3BlbkFJ0123456789abcdef")       // standard base64 rather than base64url
	f.Add("T3BlbkFJ0123456789abcdefsk-0123456789abcdef")             // the marker in front of the prefix
	f.Add("sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef-suffix") // the run reaches over what is written against it
	f.Add("sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef\nsk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef")
	// A key beginning inside the match before it, which a scan resuming past a
	// match steps over, and a run carrying the marker twice, where the scan
	// takes the first and the reference's greediness takes the second.
	f.Add("sk-sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef")
	// Two whole keys with nothing at all between them, so the second key's
	// prefix stands inside the run the first one closes on.
	f.Add("sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdefsk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef")
	f.Add("sk-T3BlbkFJT3BlbkFJ0123456789abcdef")
	f.Add("sk-T3BlbkFJ")
	// Candidate positions crowded as close as they can be: every third byte,
	// with the marker at the end of the run, nowhere at all, and in every run.
	f.Add(strings.Repeat("sk-", 32) + "T3BlbkFJx")
	f.Add(strings.Repeat("sk-", 32))
	f.Add(strings.Repeat("sk-.T3BlbkFJ.", 8))
	f.Add(strings.Repeat("sk-T3BlbkFJ", 8))
	// The prefix and the marker written inside a run of the alphabet, which is
	// the over-match the pattern admits.
	f.Add("payload=zzzzsk-zzzzT3BlbkFJzzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzsk-zzzzT3BlbkFJzzzz")

	fuzzAgainstReference(f, OpenAIAPIKey().Find, referenceOpenAIAPIKeyFind)
}

// openAIAPIKeyFindBenchmarks is what this scan is timed on. The builtinPatterns
// entry for the pattern names it, and BenchmarkBuiltins times every case it
// holds under the pattern's own name, so that a built-in cannot arrive without
// a benchmark. Every case is held to the count it states under a plain go test
// as well, which is what a benchmark nobody has run yet cannot be.
func openAIAPIKeyFindBenchmarks() []benchmarkCase {
	// An ordinary line carries no marker, so what it times is the search for
	// one and the return behind it — which is the whole of what this pattern
	// costs a caller whose text holds no key, however many hyphenated words the
	// line ends in sk-.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling the responses API" url=https://api.openai.com/v1/responses `
	key := "sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// One run that is nothing but prefixes, with the marker written
			// past the end of it: a candidate every three characters, every
			// one of them reaching the body of the loop and none of them
			// becoming a key. What it times is the two cursors doing their
			// work, since every candidate here would otherwise read the rest
			// of the line twice over.
			name:  "candidates that are not values",
			src:   strings.Repeat("sk-", 512) + ".T3BlbkFJ",
			spans: 0,
		},
		{
			// A marker in every run rather than one for the whole line, which
			// is what makes the remembered marker be passed and searched for
			// again at each candidate instead of being reused.
			name:  "a marker in every run",
			src:   strings.Repeat("sk-.T3BlbkFJ.", 128),
			spans: 0,
		},
		{
			// The same crowding with a marker at the end, so every candidate
			// locates a key and every span reaches the same place.
			name:  "candidates crowded in front of one marker",
			src:   strings.Repeat("sk-", 512) + "T3BlbkFJ0123456789abcdef",
			spans: 512,
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
