package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The AWS access key ID pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. The uppercase run they are built from,
// 0123456789ABCDEF, is sixteen characters and so is a whole body — and it
// carries 0, 1, 8 and 9, which the base32 alphabet issued keys are reported to
// be drawn from does not. Every key below is therefore one the scan locates
// and, if that report is right, no generator would produce: the alphabet
// decision in builtin_aws_access_key_id.go stated by the data rather than only
// in a comment.

func Test_AWSAccessKeyID(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a long term access key id",
			src:  "AKIA0123456789ABCDEF",
			want: []Span{{0, 20}},
		},
		{
			name: "a temporary access key id",
			src:  "ASIA0123456789ABCDEF",
			want: []Span{{0, 20}},
		},
		{
			name: "an access key id in an environment assignment",
			src:  "AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF",
			want: []Span{{18, 38}},
		},
		{
			// Every access key ID AWS shows is twenty characters, so the
			// sixteen behind the prefix are read as a count and not a floor:
			// what follows the twentieth is not part of the key and stays in
			// the text. The four characters left here belong to no
			// credential.
			name: "an alphabet run longer than a key is a key and what follows it",
			src:  "AKIA0123456789ABCDEFGHIJ",
			want: []Span{{0, 20}},
		},
		{
			// Neither key is inside the other, and nothing separates them.
			name: "two keys with nothing between them",
			src:  "AKIA0123456789ABCDEFASIA0123456789ABCDEF",
			want: []Span{{0, 20}, {20, 40}},
		},
		{
			// The two prefixes overlap: the A that closes ASIA is the A that
			// opens AKIA three characters along. So a key begins inside the
			// span of the one before it, and a scan resuming past a match
			// would step over it and leave a whole key in the output. The
			// spans overlap, which a Masker resolves into one.
			name: "a key beginning inside the key before it",
			src:  "ASIAKIA0123456789ABCDEF",
			want: []Span{{0, 20}, {3, 23}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AWSAccessKeyID().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AWSAccessKeyID_capitalsThatAreNotCredentials(t *testing.T) {
	// Text that is a key's format without being a key. ASIA is an English
	// word where AKIA is not, so a run of twenty unbroken capitals opening
	// with it is redacted whether anyone issued it or not, and these are the
	// runs that fall that way.
	//
	// They are held to being redacted rather than to being spared. Nothing in
	// the text tells them from a key — they are the same twenty bytes — so a
	// scan that let these through would let a real key through with them,
	// which builtin_aws_access_key_id.go sets out. What the table is for is
	// that the cases move with the scan: one of them ceasing to be located
	// means the grammar changed, and that is a decision to be taken rather
	// than noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a word of exactly twenty capitals",
			src:  "ASIAPACIFICSOUTHEAST",
			want: "********************",
		},
		{
			// Longer than a key, so the count leaves the tail behind rather
			// than taking the whole word.
			name: "a word of more than twenty capitals",
			src:  "ASIANELEPHANTCONSERVATION",
			want: "********************ATION",
		},
		{
			name: "capitals under the other prefix, which is no word",
			src:  "AKIAPACIFICSOUTHEAST",
			want: "********************",
		},
	}

	m := New(WithPatterns(AWSAccessKeyID()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AWSAccessKeyID_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "AKIA",
		},
		{
			// Nineteen characters where the pattern asks for twenty.
			name: "body one character too short",
			src:  "AKIA0123456789ABCDE",
		},
		{
			name: "lowercase body",
			src:  "AKIA0123456789abcdef",
		},
		{
			name: "lowercase prefix",
			src:  "akia0123456789ABCDEF",
		},
		{
			// AROA names a role. It is a unique identifier rather than a
			// credential, and the pattern admits the two prefixes AWS
			// documents for an access key ID and no others.
			name: "a unique identifier prefix that is not an access key id",
			src:  "AROA0123456789ABCDEF",
		},
		{
			// ABIA is a service bearer token and ACCA a context-specific
			// credential. Both are credentials and both are left alone: AWS
			// documents no shape for either beyond the prefix.
			name: "a credential prefix with no documented shape",
			src:  "ABIA0123456789ABCDEF",
		},
		{
			name: "the other credential prefix with no documented shape",
			src:  "ACCA0123456789ABCDEF",
		},
		{
			name: "an underscore in the body",
			src:  "AKIA0123456789ABCDE_",
		},
		{
			name: "a hyphen in the body",
			src:  "AKIA-123456789ABCDEF",
		},
		{
			name: "twenty uppercase characters that open with no prefix",
			src:  "ABCDEFGHIJKLMNOPQRST",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "prose in capitals",
			src:  "THERE IS NO CREDENTIAL IN THIS SENTENCE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AWSAccessKeyID().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_AWSAccessKeyID_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF",
			want: "AWS_ACCESS_KEY_ID=********************",
		},
		{
			name: "quoted",
			src:  `"AKIA0123456789ABCDEF"`,
			want: `"********************"`,
		},
		{
			name: "json",
			src:  `{"AccessKeyId":"ASIA0123456789ABCDEF"}`,
			want: `{"AccessKeyId":"********************"}`,
		},
		{
			name: "twice",
			src:  "AKIA0123456789ABCDEF ASIA0123456789ABCDEF",
			want: "******************** ********************",
		},
		{
			// The two spans are merged, so the key that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a key beginning inside the key before it",
			src:  "ASIAKIA0123456789ABCDEF",
			want: "***********************",
		},
	}

	m := New(WithPatterns(AWSAccessKeyID()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AWSAccessKeyID_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xAKIA0123456789ABCDEF",
			want: "x********************",
		},
		{
			name: "underscore before",
			src:  "AWS_ACCESS_KEY_ID_AKIA0123456789ABCDEF",
			want: "AWS_ACCESS_KEY_ID_********************",
		},
		{
			name: "underscore after",
			src:  "AKIA0123456789ABCDEF_x",
			want: "********************_x",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this key
			// rather than trim it; without one the twenty characters AWS
			// issued are redacted and the four written after them, which are
			// part of no credential, stay in the text.
			name: "uppercase after",
			src:  "AKIA0123456789ABCDEFGHIJ",
			want: "********************GHIJ",
		},
	}

	m := New(WithPatterns(AWSAccessKeyID()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AWSAccessKeyID_leavesWhatFollowsAlone(t *testing.T) {
	// A key carries no punctuation at all, so nothing written after one joins
	// it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "host",
			src:  "host=AKIA0123456789ABCDEF.example.com",
			want: "host=********************.example.com",
		},
		{
			name: "dashed word",
			src:  "AKIA0123456789ABCDEF-SUFFIX",
			want: "********************-SUFFIX",
		},
		{
			name: "sentence",
			src:  "the key is AKIA0123456789ABCDEF.",
			want: "the key is ********************.",
		},
	}

	m := New(WithPatterns(AWSAccessKeyID()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_awsAccessKeyIDPrefixes(t *testing.T) {
	// The scan reads a fixed number of characters from every candidate and
	// tests the byte a prefix opens with before it reads any of them, so a
	// prefix of another length is one the scan reads the wrong number of
	// characters behind and a prefix opening with another byte is one it turns
	// away unread. Neither shows as a failing case: the pattern would quietly
	// stop locating that kind of key. Which byte the scan searches the input
	// for is Test_awsAccessKeyIDAnchor's to hold.
	if len(awsAccessKeyIDPrefixes) == 0 {
		t.Fatal("no prefix is documented, so the pattern locates nothing")
	}
	for _, prefix := range awsAccessKeyIDPrefixes {
		t.Run(prefix, func(t *testing.T) {
			if len(prefix) != awsAccessKeyIDPrefixChars {
				t.Errorf("the prefix is %d characters, the scan reads %d", len(prefix), awsAccessKeyIDPrefixChars)
			}
			if prefix == "" || prefix[0] != awsAccessKeyIDFirstByte {
				t.Errorf("the prefix does not open with %q, which is what a candidate is read back to", awsAccessKeyIDFirstByte)
			}
		})
	}
}

// Test_awsAccessKeyIDAnchor holds every prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from. One
// search serves both prefixes only while both spell that byte there, and a
// prefix that did not would be one no candidate is ever found at.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_awsAccessKeyIDAnchor(t *testing.T) {
	for _, prefix := range awsAccessKeyIDPrefixes {
		t.Run(prefix, func(t *testing.T) {
			if awsAccessKeyIDAnchorIndex >= len(prefix) {
				t.Fatalf("the anchor stands at %d, the prefix is %d characters", awsAccessKeyIDAnchorIndex, len(prefix))
			}
			if c := prefix[awsAccessKeyIDAnchorIndex]; c != awsAccessKeyIDAnchor {
				t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it",
					c, byte(awsAccessKeyIDAnchor))
			}
		})
	}
}

func Test_isAWSAccessKeyIDByte(t *testing.T) {
	// The alphabet is what the pattern is widest on, so it is stated over
	// every byte rather than by example. It admits every character AWS has
	// shown in a key and no more: issued keys are reported to be narrower
	// still — base32, which holds no 0, 1, 8 or 9 — but that report is not
	// AWS's, and the lowercase half is left out because no key AWS has
	// published carries one.
	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9' || 'A' <= b && b <= 'Z'
		if got := isAWSAccessKeyIDByte(b); got != want {
			t.Errorf("isAWSAccessKeyIDByte(%q) = %v, want %v", b, got, want)
		}
	}

	// And the four digits base32 leaves out are in, which is the whole of what
	// separates this alphabet from the one issued keys are reported to use.
	for _, c := range []byte{'0', '1', '8', '9'} {
		if !isAWSAccessKeyIDByte(c) {
			t.Errorf("isAWSAccessKeyIDByte(%q) = false, want every character AWS has shown rather than base32", c)
		}
	}
}

// referenceAWSAccessKeyID is the expression the scan in
// builtin_aws_access_key_id.go reads by hand: the statement of what an access
// key ID is, kept here so that the scan can be held to it.
//
// The prefixes and the count are spelled again rather than built from
// awsAccessKeyIDPrefixes and awsAccessKeyIDBodyChars. A reference sharing those
// declarations could not disagree with the scan about them, and it is exactly
// that disagreement the fuzz target below is for: the two have to be changed
// together or reported apart.
var referenceAWSAccessKeyID = regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`)

// referenceAWSAccessKeyIDFind locates keys the plain way: the leftmost match of
// the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a key can begin inside one: the A that closes
// ASIA opens AKIA three characters along, so ASIAKIA... holds a key the engine
// would never go on to try. The scan finds both and reports the two spans
// overlapping for a Masker to resolve, so the reference must ask about both.
//
// Unlike the GitHub reference, resuming a byte along costs this one nothing
// beyond a constant: every candidate reads at most twenty characters, here as
// in the scan, so neither has a run to walk and there is no cursor for either
// to be wrong about.
func referenceAWSAccessKeyIDFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceAWSAccessKeyID.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzAWSAccessKeyID_matchesReference guards the hand-written scan: the byte it
// searches for, the prefixes it admits, the count it reads behind them, the
// alphabet it reads them in and the byte it resumes at may none of them change
// which keys are located.
func FuzzAWSAccessKeyID_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF")
	f.Add("ASIA0123456789ABCDEF")
	f.Add("AKIA0123456789ABCDE")       // one short of a key
	f.Add("AKIA0123456789ABCDEFGHIJ")  // and a run longer than one
	f.Add("AKIA0123456789abcdef")      // a lowercase body
	f.Add("akia0123456789ABCDEF")      // a lowercase prefix
	f.Add("AKIA-123456789ABCDEF")      // a character outside the alphabet
	f.Add("AROA0123456789ABCDEF")      // a unique identifier rather than a key
	f.Add("ABIA0123456789ABCDEF")      // a credential with no documented shape
	f.Add("ACCA0123456789ABCDEF")      // and the other one
	f.Add("A3TX0123456789ABCDEF")      // the legacy shape gitleaks carries, which AWS does not document
	f.Add("ABCDEFGHIJKLMNOPQRST")      // twenty uppercase characters opening with no prefix
	f.Add("AKIA0123456789ABCDEF.next") // punctuation ends a key
	f.Add("AKIA0123456789ABCDEF\nAKIA0123456789ABCDEF")
	// A key beginning inside the match before it, which a scan resuming past a
	// match steps over, and two keys with nothing between them, which is the
	// same text without the overlap.
	f.Add("ASIAKIA0123456789ABCDEF")
	f.Add("AKIA0123456789ABCDEFASIA0123456789ABCDEF")
	f.Add(strings.Repeat("ASIAKIA", 8))
	// Candidate positions crowded as close as they can be: every byte in the
	// first, every fourth in the second, and a run that is a body to every
	// candidate in it.
	f.Add(strings.Repeat("A", 64))
	f.Add(strings.Repeat("AKIA", 16))
	f.Add(strings.Repeat("AKIA", 16) + "!")

	fuzzAgainstReference(f, AWSAccessKeyID().Find, referenceAWSAccessKeyIDFind)
}

// awsAccessKeyIDFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under
// a plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func awsAccessKeyIDFindBenchmarks() []benchmarkCase {
	// The line carries the capitals a log line has anyway — the name of the
	// call and the region — because they are what a scan searching for the
	// letter a prefix opens with would have stopped at. The I the scan does
	// search for stands in none of them, so what the line times is the walk
	// alone, and the difference between the two is what the anchor bought.
	line := `time=2026-08-17T00:00:00Z level=info msg="AssumeRole" region=AP-NORTHEAST-1 `
	key := "AKIA0123456789ABCDEF"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A prefix written out and a body one character short of the
			// count: the candidate standing at each prefix reads all sixteen
			// body positions and is turned away by the last of them, which is
			// the most a candidate can cost here. The two capitals behind it
			// are turned away at the prefix without a body character being
			// read at all. This scan keeps no cursor and needs none — a fixed
			// count bounds what a candidate reads — and this is the input that
			// would show the bound gone.
			name:  "candidates that are not values",
			src:   strings.Repeat("AKIA0123456789ABCDE-", 32),
			spans: 0,
		},
		{
			// The prefixes overlapping one another, which is a key beginning
			// three characters inside the one before it: most of these
			// candidates become values, and the spans they report overlap.
			name:  "values crowded in one run",
			src:   strings.Repeat("ASIAKIA", 32),
			spans: 59,
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
