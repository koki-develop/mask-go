package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Replicate API token pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a set
// of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. A body is thirty-seven letters and digits, written
// here as 0123456789abcdef twice and then 01234, which with the prefix in front
// comes to the forty characters Replicate states a token is.

func Test_ReplicateAPIToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "r8_0123456789abcdef0123456789abcdef01234",
			want: []Span{{0, 40}},
		},
		{
			name: "a token in an environment assignment",
			src:  "REPLICATE_API_TOKEN=r8_0123456789abcdef0123456789abcdef01234",
			want: []Span{{20, 60}},
		},
		{
			// The count is read exactly, so what follows the fortieth character
			// is not part of the token and stays in the text.
			name: "a run longer than the count is a token and what follows it",
			src:  "r8_0123456789abcdef0123456789abcdef012345",
			want: []Span{{0, 40}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "r8_0123456789abcdef0123456789abcdef01234r8_0123456789abcdef0123456789abcdef01234",
			want: []Span{{0, 40}, {40, 80}},
		},
		{
			// The alphabet is the letters of both cases with the digits, which
			// is what the tokens kingfisher publishes as its examples are
			// spelled in, so the bodies written out here carry both.
			name: "an uppercase body",
			src:  "r8_0123456789ABCDEF0123456789ABCDEF01234",
			want: []Span{{0, 40}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ReplicateAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ReplicateAPIToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "r8_",
		},
		{
			name: "a body one character short",
			src:  "r8_0123456789abcdef0123456789abcdef0123",
		},
		{
			name: "a body broken by a space",
			src:  "r8_0123456789abcdef 123456789abcdef01234",
		},
		{
			name: "a hyphen in the body",
			src:  "r8_0123456789abcdef-123456789abcdef01234",
		},
		{
			// The character trufflehog admits and this scan does not, which is
			// the one the prefix closes with.
			name: "an underscore in the body",
			src:  "r8_0123456789abcdef_123456789abcdef01234",
		},
		{
			name: "a character outside the alphabet in the body",
			src:  "r8_0123456789abcdef.123456789abcdef01234",
		},
		{
			// The prefix is read in the one case Replicate writes it, where
			// betterleaks reads it without regard to case.
			name: "an uppercase prefix",
			src:  "R8_0123456789abcdef0123456789abcdef01234",
		},
		{
			name: "the prefix without its closing underscore",
			src:  "r80123456789abcdef0123456789abcdef012345",
		},
		{
			name: "a hyphen where the prefix closes",
			src:  "r8-0123456789abcdef0123456789abcdef01234",
		},
		{
			// The webhook signing secret Replicate hands a handler, which
			// carries a prefix of its own and no r8_ to be found at.
			name: "a webhook signing secret",
			src:  "whsec_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a body of the right shape opening with no prefix",
			src:  "xxx0123456789abcdef0123456789abcdef01234",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "a log line",
			src:  `time=2026-08-17T00:00:00Z level=info msg="creating prediction" url=https://api.replicate.com/v1/predictions`,
		},
		{
			name: "a replicate environment variable holding a host name",
			src:  "REPLICATE_API_BASE_URL=https://api.replicate.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ReplicateAPIToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_ReplicateAPIToken_inContext(t *testing.T) {
	// The places a token is written, which are the places Replicate's own
	// documentation puts one: the environment its client libraries read it
	// from, the argument they take it as, the bearer header a request carries
	// it in and the command line a curl example writes that header on.
	const token = "r8_0123456789abcdef0123456789abcdef01234"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token in a dotenv line",
			src:  "REPLICATE_API_TOKEN=" + token,
			want: []Span{{20, 20 + len(token)}},
		},
		{
			name: "a token in a python argument",
			src:  `replicate.Client(api_token="` + token + `")`,
			want: []Span{{28, 28 + len(token)}},
		},
		{
			name: "a token in a bearer token header",
			src:  "Authorization: Bearer " + token,
			want: []Span{{22, 22 + len(token)}},
		},
		{
			name: "a token on a command line",
			src:  `curl -H "Authorization: Bearer ` + token + `" https://api.replicate.com/v1/account`,
			want: []Span{{31, 31 + len(token)}},
		},
		{
			name: "a token in a json body",
			src:  `{"api_token":"` + token + `"}`,
			want: []Span{{14, 14 + len(token)}},
		},
		{
			name: "a token at the end of a sentence",
			src:  "the token is " + token + ".",
			want: []Span{{13, 13 + len(token)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ReplicateAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ReplicateAPIToken_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match. A word boundary in front
	// would drop the whole match rather than trim it wherever a token is
	// written against a word character, and one behind it would drop a token
	// followed by a letter or a digit.
	const token = "r8_0123456789abcdef0123456789abcdef01234"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token after an underscore",
			src:  "REPLICATE_API_TOKEN_" + token,
			want: []Span{{20, 20 + len(token)}},
		},
		{
			name: "a token after a letter",
			src:  "x" + token,
			want: []Span{{1, 1 + len(token)}},
		},
		{
			name: "a word written against a token",
			src:  token + "suffix",
			want: []Span{{0, len(token)}},
		},
		{
			name: "a hyphenated word written against a token",
			src:  token + "-suffix",
			want: []Span{{0, len(token)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ReplicateAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ReplicateAPIToken_aTokenInsideAToken(t *testing.T) {
	// A token can be written inside another, which is why the scan resumes a
	// byte past the start of a candidate rather than past the candidate: the
	// underscore a candidate is read back from stands past the end of the token
	// it begins inside, so a body closing on r8 opens one thirty-eight
	// characters in. The spans overlap there, which Masker.locate resolves.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// A body closing on r8, with the underscore that reads it back
			// written after the token that body closes.
			name: "a token beginning at the end of another",
			src:  "r8_0123456789abcdef0123456789abcdef012r8_0123456789abcdef0123456789abcdef01234",
			want: []Span{{0, 40}, {38, 78}},
		},
		{
			// The same opening with nothing behind it long enough to be a body,
			// so the token in front of it is the one there is.
			name: "a body closing on r8 that opens no token",
			src:  "r8_0123456789abcdef0123456789abcdef012r8_0123456789",
			want: []Span{{0, 40}},
		},
		{
			// The other of the two positions: a body closing on r, with the 8
			// and the underscore written after the token.
			name: "a token beginning at the last character of another",
			src:  "r8_0123456789abcdef0123456789abcdef0123r8_0123456789abcdef0123456789abcdef01234",
			want: []Span{{0, 40}, {39, 79}},
		},
		{
			// The prefix written where a body would have to hold it. The
			// underscore it closes with is no character a body may carry, so
			// the candidate in front of it ends there and the token is the one
			// that prefix opens.
			name: "a prefix written where a body would stand",
			src:  "r8_0123456789abcr8_0123456789abcdef0123456789abcdef01234",
			want: []Span{{16, 56}},
		},
		{
			name: "a prefix in front of a token",
			src:  "r8_r8_0123456789abcdef0123456789abcdef01234",
			want: []Span{{3, 43}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "r8_0123456789abcdef0123456789abcdef01234r8_0123456789abcdef0123456789abcdef01234",
			want: []Span{{0, 40}, {40, 80}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ReplicateAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ReplicateAPIToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision this format leaves. Thirty-seven letters and digits behind
	// the prefix is the vendor's format exactly, so a digest written there is
	// indistinguishable from a token and is redacted for thirty-seven of its
	// characters. A digest on its own carries no prefix and reaches nothing.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a sha-1 behind the prefix",
			src:  "r8_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 40}},
		},
		{
			name: "a sha-256 behind the prefix",
			src:  "r8_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 40}},
		},
		{
			// An MD5 is thirty-two characters, which is five short of a body.
			name: "an md5 behind the prefix",
			src:  "r8_0123456789abcdef0123456789abcdef",
			want: nil,
		},
		{
			name: "a sha-1 on its own",
			src:  "sha1=0123456789abcdef0123456789abcdef01234567",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ReplicateAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ReplicateAPIToken_thePrefixInsideBase64URL(t *testing.T) {
	// The other text this format is written by accident. base64url holds the
	// underscore where hexadecimal and standard base64 do not, so a payload
	// written in it carries the prefix where those cannot, and where the
	// thirty-seven behind it are letters and digits alone those forty are a
	// token's format exactly.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "the prefix inside a longer base64url run",
			src:  "payload=zzzzr8_0123456789abcdef0123456789abcdef01234zzzz",
			want: []Span{{12, 52}},
		},
		{
			name: "the prefix where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.r8_0123456789abcdef0123456789abcdef01234",
			want: []Span{{40, 80}},
		},
		{
			// Standard base64 writes the plus and the slash where base64url
			// writes the hyphen and the underscore, so a payload written in it
			// holds no prefix to be found at however long it runs.
			name: "a standard base64 payload, which carries no underscore",
			src:  "payload=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr80123456789abcdef",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ReplicateAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_replicateAPITokenPrefix(t *testing.T) {
	// The prefix is the whole of what tells this format from text, and it
	// closes on a character no body is written with. That is what makes the
	// search cheap on a line holding no token — a run of a body opens no
	// candidate however long it runs — and it is what bounds where a token may
	// begin inside another, which the count below is of.
	if got := replicateAPITokenPrefix; got != "r8_" {
		t.Errorf("replicateAPITokenPrefix = %q, want %q", got, "r8_")
	}
	for i := range len(replicateAPITokenPrefix) {
		c := replicateAPITokenPrefix[i]
		if i == len(replicateAPITokenPrefix)-1 {
			if isBase62Byte(c) {
				t.Errorf("the prefix closes on %q, which a body may be written with", c)
			}
			continue
		}
		if !isBase62Byte(c) {
			t.Errorf("the prefix carries %q at index %d, which a body may not be written with", c, i)
		}
	}

	// Where a token may begin inside another, counted out of the declarations
	// that decide it rather than claimed in prose. A candidate opens where the
	// whole prefix stands, and the underscore that prefix closes with is no
	// character a body carries, so a position inside a span opens one only
	// where that underscore falls past the end of the span. What that leaves is
	// the last two characters of a body, which is what the scan resuming a byte
	// along exists to reach. A prefix lengthened or a count changed moves the
	// number, and nothing else here would report it; a body admitting the
	// underscore would move it as well, and that is what the walk above turns
	// away.
	inside := 0
	for p := 1; p < replicateAPITokenChars; p++ {
		if p+len(replicateAPITokenPrefix)-1 >= replicateAPITokenChars {
			inside++
		}
	}
	if want := 2; inside != want {
		t.Errorf("%d position(s) inside a token can open a candidate, want %d", inside, want)
	}
}

func Test_replicateAPITokenAnchor(t *testing.T) {
	// The byte the scan searches for stands at the index it reads a candidate
	// back from. A prefix or an index changed without the other leaves the scan
	// opening candidates nowhere near where a token begins, and what such a
	// scan finds is nothing at all rather than something wrong.
	if got := replicateAPITokenPrefix[replicateAPITokenAnchorIndex]; got != replicateAPITokenAnchor {
		t.Errorf("replicateAPITokenPrefix[%d] = %q, want the anchor %q",
			replicateAPITokenAnchorIndex, got, replicateAPITokenAnchor)
	}

	// What the anchor costs, counted rather than claimed in prose: it stands
	// once in the prefix, so a line of tokens stops the search once a token,
	// and nowhere in a body, so a run of one stops it not at all.
	if n := strings.Count(replicateAPITokenPrefix, string(replicateAPITokenAnchor)); n != 1 {
		t.Errorf("the anchor stands %d times in %q, want 1", n, replicateAPITokenPrefix)
	}
	if isBase62Byte(replicateAPITokenAnchor) {
		t.Errorf("the anchor %q is a character a body may be written with", replicateAPITokenAnchor)
	}
}

func Test_replicateAPITokenChars(t *testing.T) {
	// The prefix Replicate says a token always opens with, and what the forty
	// characters it says a token is leave behind that prefix.
	if got := len(replicateAPITokenPrefix); got != 3 {
		t.Errorf("len(replicateAPITokenPrefix) = %d, want 3", got)
	}
	if got := replicateAPITokenBodyChars; got != 37 {
		t.Errorf("replicateAPITokenBodyChars = %d, want 37", got)
	}
	if got := replicateAPITokenChars; got != 40 {
		t.Errorf("replicateAPITokenChars = %d, want 40", got)
	}
}

// referenceReplicateAPIToken is the grammar as a regular expression: the prefix
// Replicate writes a token with, the count its stated length leaves behind that
// prefix and the letters and digits that count is read in. Every part of it is
// spelled again rather than read from the scan, so that the two can disagree
// and the target below report it.
//
// It is built on an expression rather than written out because the count is
// exact, so an engine reads its machine once and stops, and because the opening
// is a literal an engine can search the text for rather than a class it would
// have to walk its machine at every byte for.
var referenceReplicateAPIToken = regexp.MustCompile(`r8_[0-9A-Za-z]{37}`)

// referenceReplicateAPITokenFind locates tokens the plain way: the leftmost
// match of the expression above, then the leftmost one beginning after that
// match's first byte, over and over, with nothing remembered between them.
//
// Asking at every byte rather than resuming past a match is what the scan does
// and is what a token written inside another needs: a body may close on the
// characters a prefix opens with, so a match can begin thirty-eight characters
// into the one before it, and resuming past the first would lose it.
func referenceReplicateAPITokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceReplicateAPIToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzReplicateAPIToken_matchesReference guards the hand-written scan: the
// prefix it searches for, the case it reads that prefix in, the count it reads
// behind it, the alphabet it reads that count in and the byte it resumes at may
// none of them change which tokens are located.
func FuzzReplicateAPIToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("REPLICATE_API_TOKEN=r8_0123456789abcdef0123456789abcdef01234")
	f.Add("r8_0123456789abcdef0123456789abcdef0123")   // a body one character short
	f.Add("r8_0123456789abcdef0123456789abcdef012345") // and a run one longer
	f.Add("r8_0123456789abcdef 123456789abcdef01234")  // a body broken by a space
	f.Add("r8_0123456789abcdef-123456789abcdef01234")  // a hyphen in the body
	f.Add("r8_0123456789abcdef_123456789abcdef01234")  // an underscore in the body
	f.Add("r8_0123456789abcdef.123456789abcdef01234")  // a character outside the alphabet
	f.Add("r8_0123456789abcdef\n123456789abcdef01234")
	f.Add("r8_0123456789ABCDEF0123456789ABCDEF01234") // an uppercase body
	f.Add("R8_0123456789abcdef0123456789abcdef01234") // an uppercase prefix
	f.Add("r8-0123456789abcdef0123456789abcdef01234") // a hyphen where the prefix closes
	f.Add("r80123456789abcdef0123456789abcdef012345") // the prefix without its underscore
	f.Add("xr8_0123456789abcdef0123456789abcdef01234")
	// The other Replicate credential, which this pattern locates nothing in,
	// and a digest behind the prefix, which it locates a token in.
	f.Add("whsec_0123456789abcdef0123456789abcdef")
	f.Add("r8_0123456789abcdef0123456789abcdef01234567")
	// The prefix inside base64url text, which is the alphabet that can hold it.
	f.Add("payload=zzzzr8_0123456789abcdef0123456789abcdef01234zzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.r8_0123456789abcdef0123456789abcdef01234")
	// A prefix written where a body would have to hold it, two tokens with
	// nothing between them, and candidate positions crowded as close as they
	// can be.
	f.Add("r8_r8_0123456789abcdef0123456789abcdef01234")
	f.Add("r8_0123456789abcr8_0123456789abcdef0123456789abcdef01234")
	// A token beginning at each of the last two characters of another's body,
	// which a scan resuming past a match would lose, and the same characters a
	// byte further in, where the underscore falls inside the body and neither
	// token stands.
	f.Add("r8_0123456789abcdef0123456789abcdef012r8_0123456789abcdef0123456789abcdef01234")
	f.Add("r8_0123456789abcdef0123456789abcdef0123r8_0123456789abcdef0123456789abcdef01234")
	f.Add("r8_0123456789abcdef0123456789abcder8_80123456789abcdef0123456789abcdef01234")
	f.Add("r8_0123456789abcdef0123456789abcdef01234r8_0123456789abcdef0123456789abcdef01234")
	f.Add(strings.Repeat("r8_", 64))
	f.Add(strings.Repeat("r8_", 64) + "0123456789abcdef0123456789abcdef01234")
	f.Add(strings.Repeat("r8_0123456789abcdef0123456789abcdef01234", 8))
	f.Add(strings.Repeat("_", 128))
	f.Add(strings.Repeat("8", 128))

	fuzzAgainstReference(f, ReplicateAPIToken().Find, referenceReplicateAPITokenFind)
}

// replicateAPITokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func replicateAPITokenFindBenchmarks() []benchmarkCase {
	// The line the anchor is chosen against: the underscore the prefix closes
	// with stands not once on it, where the r stands five times and the 8 once.
	// What the line times is the search for the anchor, which is most of what
	// this pattern costs a caller whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="creating prediction" url=https://api.replicate.com/v1/predictions `
	token := "r8_0123456789abcdef0123456789abcdef01234"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is three characters carrying the anchor once, so a run
			// of them stops the search once every three characters and each
			// stop reads a body that fails on its third character, which is the
			// underscore the prefix beginning a byte later closes with.
			name:  "candidates that are not values",
			src:   strings.Repeat("r8_", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads a prefix, which is the cheapest a
			// candidate is declined for at all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("_", 4096),
			spans: 0,
		},
		{
			// The other way a candidate fails: a body of the right alphabet up
			// to its last character, so the whole of it is walked before the
			// candidate is turned away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("r8_0123456789abcdef0123456789abcdef0123. ", 16),
			spans: 0,
		},
		{
			// A run of the alphabet a body is read in, carrying no anchor at
			// all, which is what the search walks a payload of.
			name:  "a run of the body alphabet",
			src:   strings.Repeat("0123456789abcdef", 256),
			spans: 0,
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
