package mask

import (
	"slices"
	"strings"
	"testing"
)

// The xAI API key pattern: what it locates and what it leaves alone, written
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
// shape, obviously not real. A body is at least eighty letters and digits,
// written here as 0123456789abcdef five times over, which with the prefix in
// front comes to the eighty-four characters the key xAI prints whole is, and
// with the management infix behind that prefix to the ninety osv-scalibr reads
// a management key at.

func Test_XAIAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 84}},
		},
		{
			name: "a key in an environment assignment",
			src:  "XAI_API_KEY=xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{12, 96}},
		},
		{
			// The count is a floor and the span reaches to the end of the run,
			// so a character written against a key is redacted with it.
			name: "a run longer than the floor is one key to the end of it",
			src:  "xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
			want: []Span{{0, 85}},
		},
		{
			name: "a management key on its own",
			src:  "xai-token-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 90}},
		},
		{
			// The alphabet is the letters of both cases with the digits, which
			// is what every key xAI, osv-scalibr and kingfisher carry is
			// spelled in, so the bodies written out here carry both.
			name: "an uppercase body",
			src:  "xai-0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 84}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := XAIAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_XAIAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "xai-",
		},
		{
			// The far side of reading the count as a floor: a key a column
			// limit cut short is a body too short to be one, and nothing is
			// located.
			name: "a body one character short of the floor",
			src:  "xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "a body broken by a space",
			src:  "xai-0123456789abcdef0123456789abcdef 123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The character the prefix closes with, which the two rulesets
			// reading a range admit in a body and this scan does not.
			name: "a hyphen in the body",
			src:  "xai-0123456789abcdef0123456789abcdef-123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The character trufflehog admits besides.
			name: "an underscore in the body",
			src:  "xai-0123456789abcdef0123456789abcdef_123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a character outside the alphabet in the body",
			src:  "xai-0123456789abcdef0123456789abcdef.123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The prefix is read in the one case xAI writes it, where
			// betterleaks reads it without regard to case.
			name: "an uppercase prefix",
			src:  "XAI-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "the prefix without its closing hyphen",
			src:  "xai0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "an underscore where the prefix closes",
			src:  "xai_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a body of the right shape opening with no prefix",
			src:  "zzz-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The prefix as xAI's own repositories are named, where the word
			// behind the hyphen is seventy or more characters short of a body.
			name: "the prefix in a repository name",
			src:  "https://github.com/xai-org/xai-cookbook",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "a log line",
			src:  `time=2026-08-17T00:00:00Z level=info msg="creating chat completion" url=https://api.x.ai/v1/chat/completions`,
		},
		{
			name: "an xai environment variable holding a host name",
			src:  "XAI_API_BASE_URL=https://api.x.ai/v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := XAIAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_XAIAPIKey_inContext(t *testing.T) {
	// The places a key is written, which are the places xAI's own documentation
	// puts one: the environment its client libraries read it from, the argument
	// they take it as, the bearer header a request carries it in and the
	// command line a curl example writes that header on.
	const key = "xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key in a dotenv line",
			src:  "XAI_API_KEY=" + key,
			want: []Span{{12, 12 + len(key)}},
		},
		{
			name: "a key in a python argument",
			src:  `Client(api_key="` + key + `")`,
			want: []Span{{16, 16 + len(key)}},
		},
		{
			name: "a key in a bearer token header",
			src:  "Authorization: Bearer " + key,
			want: []Span{{22, 22 + len(key)}},
		},
		{
			name: "a key on a command line",
			src:  `curl -H "Authorization: Bearer ` + key + `" https://api.x.ai/v1/chat/completions`,
			want: []Span{{31, 31 + len(key)}},
		},
		{
			name: "a key in a json body",
			src:  `{"apiKey":"` + key + `"}`,
			want: []Span{{11, 11 + len(key)}},
		},
		{
			name: "a key at the end of a sentence",
			src:  "the key is " + key + ".",
			want: []Span{{11, 11 + len(key)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := XAIAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_XAIAPIKey_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match. A word boundary in front
	// would drop the whole match rather than trim it wherever a key is written
	// against a word character. One behind would drop rather than trim as well,
	// and where it were asked decides what it drops. Asked behind the count, it
	// drops the key a letter, a digit or an underscore is written against. Asked
	// behind that run, it drops the key an underscore is written against and
	// nothing else, the underscore being the one word character no body admits.
	const key = "xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key after an underscore",
			src:  "XAI_API_KEY_" + key,
			want: []Span{{12, 12 + len(key)}},
		},
		{
			name: "a key after a letter",
			src:  "x" + key,
			want: []Span{{1, 1 + len(key)}},
		},
		{
			// What the span reaching to the end of the run costs: the word is
			// redacted with the key rather than left in the text.
			name: "a word written against a key",
			src:  key + "suffix",
			want: []Span{{0, len(key) + 6}},
		},
		{
			name: "a hyphenated word written against a key",
			src:  key + "-suffix",
			want: []Span{{0, len(key)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := XAIAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_XAIAPIKey_aKeyInsideAKey(t *testing.T) {
	// A key can be written inside another, which is why the scan resumes a byte
	// past the start of a candidate rather than past the candidate: the three
	// characters the prefix opens with belong to the alphabet a body is written
	// in, so a body may close with xai and the hyphen opening the next key
	// stand directly behind it. The spans overlap there, which Masker.locate
	// resolves.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// The first span runs through the second key's xai to the hyphen
			// that ends the run, so it reaches three characters past where the
			// second key begins.
			name: "a key beginning at the end of another",
			src:  "xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefxai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 87}, {84, 168}},
		},
		{
			// A body closing on xai with nothing behind the hyphen long enough
			// to be a body, so the key in front of it is the one there is.
			name: "a body closing on xai that opens no key",
			src:  "xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcxai-0123456789",
			want: []Span{{0, 84}},
		},
		{
			// The prefix written where a body would have to hold it. The hyphen
			// it closes with is no character a body may carry, so the candidate
			// in front of it ends there far short of the floor and the key is
			// the one that prefix opens.
			name: "a prefix written where a body would stand",
			src:  "xai-0123456789abcxai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{17, 101}},
		},
		{
			name: "a prefix in front of a key",
			src:  "xai-xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{4, 88}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := XAIAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_XAIAPIKey_aManagementKey(t *testing.T) {
	// The key an account manages its other keys with, which xAI prints only
	// redacted and osv-scalibr reads as xai-token- and eighty letters and
	// digits. The infix closes on the hyphen a body ends at, so it is read
	// where it stands and the body begins past it, and where it does not stand
	// the characters spelling it are a body like any other.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a management key in an environment assignment",
			src:  "XAI_MANAGEMENT_KEY=xai-token-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{19, 109}},
		},
		{
			// The floor is the body's, so the infix buys the candidate nothing:
			// seventy-nine characters behind it are no more a key than
			// seventy-nine behind the prefix alone.
			name: "a management body one character short of the floor",
			src:  "xai-token-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: nil,
		},
		{
			// Without the hyphen that closes it there is no infix, and the
			// characters spelling it open a body of the ordinary kind.
			name: "the infix without its hyphen is a body",
			src:  "xai-token0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 84}},
		},
		{
			// The infix is read in the one case osv-scalibr reads it, as the
			// prefix in front of it is.
			name: "an uppercase infix",
			src:  "xai-TOKEN-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: nil,
		},
		{
			// At most one infix is read, so the second is a body that runs out
			// at its own hyphen five characters in.
			name: "the infix written twice",
			src:  "xai-token-token-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := XAIAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_XAIAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision this format leaves. Eighty letters and digits behind the
	// prefix is the shape every key xAI and the rulesets carry is, so a run of
	// hexadecimal that long written there is indistinguishable from a key and
	// is redacted. A SHA-256 is sixteen characters short of the floor and
	// reaches nothing; two of them written together are past it. A digest on
	// its own carries no prefix and reaches nothing whatever its length.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a sha-256 behind the prefix",
			src:  "xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: nil,
		},
		{
			name: "two sha-256s behind the prefix",
			src:  "xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 132}},
		},
		{
			name: "a sha-1 behind the prefix",
			src:  "xai-0123456789abcdef0123456789abcdef01234567",
			want: nil,
		},
		{
			name: "a sha-256 on its own",
			src:  "sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := XAIAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_XAIAPIKey_aBodyBelowTheEntropyFloors(t *testing.T) {
	// The demands two of the rulesets make beyond the grammar, which this scan
	// declines: kingfisher drops a body below an entropy of 3.8 or carrying
	// fewer than two digits, and betterleaks filters on an entropy of its own.
	// A body is random, so what a floor turns away is the key whose characters
	// happened to fall in a way that reads as ordinary — and a redaction
	// library may not leave one in the output for that.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a body of eighty zeros",
			src:  "xai-" + strings.Repeat("0", 80),
			want: []Span{{0, 84}},
		},
		{
			name: "a body carrying no digit at all",
			src:  "xai-" + strings.Repeat("a", 80),
			want: []Span{{0, 84}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := XAIAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_xaiAPIKeyOpenings(t *testing.T) {
	// Both openings close on a character no body may be written with, and
	// everything the scan rests on comes from that. It is what makes the search
	// cheap on a line holding no key — a run of a body opens no candidate
	// however long it runs. It is what keeps two candidates from ever reading
	// the same run, since a candidate's body begins directly behind that
	// character and the run of an earlier candidate has already ended there,
	// which is what lets the scan walk a body of any length with no cursor to
	// be wrong about. And it is what keeps the two openings from being read at
	// one candidate: a body beginning at the prefix of a key carrying the infix
	// runs out at the infix's own closing character. Were that character one a
	// body admits, a run dense in openings would be walked once for every
	// candidate in it and the scan would cost time quadratic in the length of
	// such a line.
	//
	// The prefix's first three characters are written in the alphabet a body
	// is, which is what lets a key begin inside another and is why the scan
	// resumes a byte along.
	if got := xaiAPIKeyPrefix; got != "xai-" {
		t.Errorf("xaiAPIKeyPrefix = %q, want %q", got, "xai-")
	}
	if got := xaiAPIKeyManagementInfix; got != "token-" {
		t.Errorf("xaiAPIKeyManagementInfix = %q, want %q", got, "token-")
	}

	for _, opening := range []string{xaiAPIKeyPrefix, xaiAPIKeyManagementInfix} {
		if opening == "" {
			t.Fatal("an opening is empty, so there is no candidate to reason about")
		}
		if c := opening[len(opening)-1]; isBase62Byte(c) {
			t.Errorf("%q closes with %q, which a body may be written with, so two candidates can read the same run", opening, c)
		}
	}

	for i := range len(xaiAPIKeyPrefix) - 1 {
		if c := xaiAPIKeyPrefix[i]; !isBase62Byte(c) {
			t.Errorf("the prefix carries %q at index %d, which a body may not be written with", c, i)
		}
	}
}

func Test_xaiAPIKeyAnchor(t *testing.T) {
	// The byte the scan searches for stands at the index it reads a candidate
	// back from. A prefix or an index changed without the other leaves the scan
	// opening candidates nowhere near where a key begins, and what such a scan
	// finds is nothing at all rather than something wrong.
	if got := xaiAPIKeyPrefix[xaiAPIKeyAnchorIndex]; got != xaiAPIKeyAnchor {
		t.Errorf("xaiAPIKeyPrefix[%d] = %q, want the anchor %q",
			xaiAPIKeyAnchorIndex, got, xaiAPIKeyAnchor)
	}

	// What the anchor costs, counted rather than claimed in prose: it stands
	// once in the prefix and nowhere in the infix, so a line of keys of either
	// kind stops the search once a key.
	if n := strings.Count(xaiAPIKeyPrefix, string(xaiAPIKeyAnchor)); n != 1 {
		t.Errorf("the anchor stands %d times in %q, want 1", n, xaiAPIKeyPrefix)
	}
	if n := strings.Count(xaiAPIKeyManagementInfix, string(xaiAPIKeyAnchor)); n != 0 {
		t.Errorf("the anchor stands %d times in %q, want 0", n, xaiAPIKeyManagementInfix)
	}
}

func Test_xaiAPIKeyBodyChars(t *testing.T) {
	// The prefix xAI writes a key with, the infix that says a key is the kind
	// an account manages its other keys with, and what the eighty-four
	// characters of the key xAI prints whole leave behind that prefix — which
	// is what the ninety osv-scalibr reads a management key at leave behind the
	// two openings together.
	if got := len(xaiAPIKeyPrefix); got != 4 {
		t.Errorf("len(xaiAPIKeyPrefix) = %d, want 4", got)
	}
	if got := len(xaiAPIKeyPrefix) + len(xaiAPIKeyManagementInfix); got != 10 {
		t.Errorf("the management opening is %d characters, want 10", got)
	}
	if got := xaiAPIKeyBodyChars; got != 80 {
		t.Errorf("xaiAPIKeyBodyChars = %d, want 80", got)
	}
}

func Test_XAIAPIKey_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a line dense in prefixes
	// holds a candidate for every four characters it has. The one thing a
	// candidate reads that is a walk over the rest of the input rather than a
	// bounded test is where its run ends, and repeating that walk at every
	// candidate would cost time quadratic in the length of the line. The bound
	// here is far above a linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every eighty-four bytes where they are densest, because a
	// sample has to carry a whole body to be one. The crowding a line can
	// actually carry, a candidate every four bytes, stays here.
	sources := map[string]string{
		// Candidates as close together as the prefix allows, none of them with
		// a run long enough to be a body: every one reaches the body of the
		// loop and every one is rejected.
		"a candidate every four characters": strings.Repeat("xai-", 500000),
		// Keys written into one another, each beginning three characters before
		// the one in front of it ends, so every candidate is a key and every one
		// of them walks a run.
		"a key beginning inside every key": strings.Repeat("xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 20000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a key.
		"a body that runs the length of the line": "xai-" + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing behind it that opens a
		// prefix, which is the cheapest way a position is declined: the prefix
		// compared and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("x ", 900000),
		// And the rest of the prefix with no anchor among it, which is the walk
		// reading a whole line and stopping nowhere in it.
		"the rest of the prefix with no anchor": strings.Repeat("ai-", 600000),
		// The management opening as close together as it allows, every
		// candidate reading the infix and then a run that ends at the next
		// opening's own hyphen.
		"a management candidate every ten characters": strings.Repeat("xai-token-", 200000),
	}

	checkScanIsLinear(t, XAIAPIKey(), sources)
}

// referenceXAIAPIKeyFind locates keys the plain way: every position in turn,
// the prefix tried at it, the infix read where it stands behind that prefix and
// the body walked to the end of its run, with nothing remembered between
// candidates. The prefix, the infix, the floor and the character class are
// spelled again here rather than shared with the scan. A reference reading
// those declarations could not disagree with it about them, and it is exactly
// that disagreement the fuzz target below is for: the two have to be changed
// together or reported apart.
//
// Every position is a starting point in its own right, a match included,
// because the three characters the prefix opens with are written in the
// alphabet a body is: a body closing with xai holds the start of the key behind
// it. The scan finds both and reports the two spans overlapping for a Masker to
// resolve, so the reference must ask about both.
//
// The body behind the infix is read first and the body behind the prefix alone
// is what it falls back to, which is a reading of the grammar rather than a
// claim about it: both are asked at every candidate, so a reference that had
// the fallback wrong would be reported by the target rather than agreeing with
// the scan by construction.
//
// It is written out rather than built on a regular expression, for the reason
// the Anthropic reference beside it is. The grammar states compactly as
// xai-(?:token-)?[0-9A-Za-z]{80,}, but a counted repetition is what an engine
// has the least room to skip, and greedy repetition behind one makes it re-walk
// the run at every candidate through a machine eighty states wide. Measured,
// that expression cost a hundred and twenty milliseconds on four kilobytes of
// one run behind the infix, which the mutator reaches within seconds and which
// left the target reporting no executions at all for most of its run. The walks
// below cost microseconds on the same input, and the seeds are kept small
// besides rather than inviting the mutator to grow one.
func referenceXAIAPIKeyFind(src string) []Span {
	const (
		prefix    = "xai-"
		infix     = "token-"
		bodyChars = 80
	)

	body := func(c byte) bool {
		return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
	}

	// bodyEnd walks the run beginning at i and reports where it ends and
	// whether it is long enough to be a body.
	bodyEnd := func(i int) (int, bool) {
		end := i
		for end < len(src) && body(src[end]) {
			end++
		}
		return end, end-i >= bodyChars
	}

	var spans []Span
	for start := range len(src) {
		if !strings.HasPrefix(src[start:], prefix) {
			continue
		}

		at := start + len(prefix)
		if strings.HasPrefix(src[at:], infix) {
			if end, ok := bodyEnd(at + len(infix)); ok {
				spans = append(spans, Span{Start: start, End: end})
				continue
			}
		}
		if end, ok := bodyEnd(at); ok {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
}

// FuzzXAIAPIKey_matchesReference guards the hand-written scan: the openings it
// searches for, the case it reads them in, the floor it holds a body to, the
// alphabet it reads that body in and the byte it resumes at may none of them
// change which keys are located.
func FuzzXAIAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("XAI_API_KEY=xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")   // a body one character short
	f.Add("xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0") // and a run one longer
	f.Add("xai-0123456789abcdef0123456789abcdef 123456789abcdef0123456789abcdef0123456789abcdef")  // a body broken by a space
	f.Add("xai-0123456789abcdef0123456789abcdef-123456789abcdef0123456789abcdef0123456789abcdef")  // a hyphen in the body
	f.Add("xai-0123456789abcdef0123456789abcdef_123456789abcdef0123456789abcdef0123456789abcdef")  // an underscore in the body
	f.Add("xai-0123456789abcdef0123456789abcdef.123456789abcdef0123456789abcdef0123456789abcdef")  // a character outside the alphabet
	f.Add("xai-0123456789abcdef0123456789abcdef\n123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("xai-0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF") // an uppercase body
	f.Add("XAI-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") // an uppercase prefix
	f.Add("xai_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") // an underscore where the prefix closes
	f.Add("xai0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")  // the prefix without its hyphen
	f.Add("xxai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// The prefix as xAI's own repositories are named, and a digest behind it at
	// either side of the floor.
	f.Add("https://github.com/xai-org/xai-cookbook")
	f.Add("xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// A prefix written where a body would have to hold it, a prefix in front of
	// a key, and candidate positions crowded as close as they can be.
	f.Add("xai-xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("xai-0123456789abcxai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// A key beginning three characters before another ends, which a scan
	// resuming past a match would lose, and a body closing on xai with nothing
	// behind the hyphen long enough to be one.
	f.Add("xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefxai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcxai-0123456789")
	f.Add(strings.Repeat("xai-", 32))
	f.Add(strings.Repeat("xai-", 16) + strings.Repeat("0123456789abcdef", 5))
	f.Add(strings.Repeat("x", 128))
	f.Add(strings.Repeat("-", 128))
	// The management form, and the ways the infix is not one: a body one
	// character short behind it, the characters spelling it without the hyphen
	// that closes it, an uppercase spelling and a second infix where a body
	// would stand.
	f.Add("xai-token-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("xai-token-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	f.Add("xai-token0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789a")
	f.Add("xai-TOKEN-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("xai-token-token-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("xai-token-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefxai-token-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add(strings.Repeat("xai-token-", 16))

	fuzzAgainstReference(f, XAIAPIKey().Find, referenceXAIAPIKeyFind)
}

// xaiAPIKeyFindBenchmarks is what this scan is timed on. The builtinPatterns
// entry for the pattern names it, and BenchmarkBuiltins times every case it
// holds under the pattern's own name, so that a built-in cannot arrive without
// a benchmark. Every case is held to the count it states under a plain go test
// as well, which is what a benchmark nobody has run yet cannot be.
func xaiAPIKeyFindBenchmarks() []benchmarkCase {
	// The line the anchor is chosen against: the x the prefix opens with stands
	// once on it, where the hyphen stands twice, the a five times and the i
	// seven. What the line times is the search for the anchor, which is most of
	// what this pattern costs a caller whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="creating chat completion" url=https://api.x.ai/v1/chat/completions `
	key := "xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is four characters carrying the anchor once, so a run
			// of them stops the search once every four characters and each stop
			// reads a run that ends at the hyphen the prefix beginning a byte
			// later closes with, far short of the floor.
			name:  "candidates that are not values",
			src:   strings.Repeat("xai-", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads a prefix, which is the cheapest a
			// candidate is declined for at all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("x", 4096),
			spans: 0,
		},
		{
			// The other way a candidate fails: a body of the right alphabet up
			// to one character short of the floor, so the whole of it is walked
			// before the candidate is turned away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("xai-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde. ", 16),
			spans: 0,
		},
		{
			// A run of the alphabet a body is read in, which carries the anchor
			// about once every sixty-two characters and is what this scan pays
			// for anchoring on a character a body may hold.
			name:  "a run of the body alphabet",
			src:   strings.Repeat("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 64),
			spans: 0,
		},
		{
			// The infix compared at every candidate that carried the prefix,
			// and a run that ends at the next opening's own hyphen.
			name:  "management candidates that are not values",
			src:   strings.Repeat("xai-token-", 512),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "key=" + key,
			spans: 1,
		},
		{
			name:  "one management value",
			src:   line + "key=xai-token-" + key[4:],
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
