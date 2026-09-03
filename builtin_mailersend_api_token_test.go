package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The MailerSend API token pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. The body they are built from,
// 0123456789abcdefghijklmnopqrst, is thirty characters, which is the shortest
// body the scan reads, since the count is a floor — so a body shortened for
// readability would leave a case holding no token at all. It is written in
// lowercase where the case does not matter and in uppercase where the case is
// what a case is about: base62 holds the letters of both, so either spelling is
// a body.

func Test_MailerSendAPIToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "mlsn.0123456789abcdefghijklmnopqrst",
			want: []Span{{0, 35}},
		},
		{
			name: "a token in an environment assignment",
			src:  "MAILERSEND_API_TOKEN=mlsn.0123456789abcdefghijklmnopqrst",
			want: []Span{{21, 56}},
		},
		{
			// base62 holds the letters of both cases, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "mlsn.0123456789ABCDEFGHIJKLMNOPQRST",
			want: []Span{{0, 35}},
		},
		{
			// The count is a floor and the span reaches the end of the run, so
			// a run longer than the shortest body is a token to the end of it
			// rather than a token and six characters left over.
			name: "a run longer than the shortest body",
			src:  "mlsn.0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 41}},
		},
		{
			name: "two tokens separated by a space",
			src:  "mlsn.0123456789abcdefghijklmnopqrst mlsn.0123456789ABCDEFGHIJKLMNOPQRST",
			want: []Span{{0, 35}, {36, 71}},
		},
		{
			// The four letters the prefix opens with belong to the alphabet a
			// body is written in, so a body may close with mlsn and the dot of
			// the next token stand directly behind it. Written with nothing
			// between them the second token begins four characters before the
			// first one ends, and a scan resuming past a match would step over
			// it. The spans overlap, which a Masker resolves into one.
			name: "two tokens with nothing between them",
			src:  "mlsn.0123456789abcdefghijklmnopqrstmlsn.0123456789ABCDEFGHIJKLMNOPQRST",
			want: []Span{{0, 39}, {35, 70}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := MailerSendAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_MailerSendAPIToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "mlsn.",
		},
		{
			// Twenty-nine characters where the pattern asks for thirty. This is
			// the shape a line cut to a column limit leaves, and the characters
			// in front of the cut stay in the text: the far side of reading a
			// floor, which builtin_mailersend_api_token.go weighs.
			name: "a body one character too short",
			src:  "mlsn.0123456789abcdefghijklmnopqrs",
		},
		{
			// The hyphen and the underscore are base64url characters and no
			// base62 ones, so either ends a body where the run behind it is
			// too short to be one.
			name: "a body carrying a hyphen",
			src:  "mlsn.0123456789abcdefghij-lmnopqrst",
		},
		{
			name: "a body carrying an underscore",
			src:  "mlsn.0123456789abcdefghij_lmnopqrst",
		},
		{
			name: "an uppercase prefix",
			src:  "MLSN.0123456789abcdefghijklmnopqrst",
		},
		{
			// The prefix is written with the dot MailerSend closes it with, not
			// with the underscore a delimiter is elsewhere.
			name: "an underscore where the prefix carries a dot",
			src:  "mlsn_0123456789abcdefghijklmnopqrst",
		},
		{
			// The prefix closes with a dot, so a body written straight against
			// the four letters is no body.
			name: "the prefix without its closing dot",
			src:  "mlsn0123456789abcdefghijklmnopqrst",
		},
		{
			name: "a space in the body",
			src:  "mlsn.0123456789abcdefghij lmnopqrst",
		},
		{
			// The dot is what the prefix closes with and no character a body is
			// written in, so one inside a body ends it.
			name: "a dot in the body",
			src:  "mlsn.0123456789abcdefghij.lmnopqrst",
		},
		{
			name: "a body broken by a line break",
			src:  "mlsn.0123456789abcdefghij\nlmnopqrst",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// most of the anchor, so a run long enough is not a token without
			// it.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdefghijklmnopqrst",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// A digest carries no dot, so it holds no prefix to be found at
			// however long it runs.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := MailerSendAPIToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_MailerSendAPIToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "MAILERSEND_API_TOKEN=mlsn.0123456789abcdefghijklmnopqrst",
			want: "MAILERSEND_API_TOKEN=***********************************",
		},
		{
			// The header every call to the MailerSend API carries.
			name: "a bearer authorization header",
			src:  "Authorization: Bearer mlsn.0123456789abcdefghijklmnopqrst",
			want: "Authorization: Bearer ***********************************",
		},
		{
			name: "json",
			src:  `{"accessToken":"mlsn.0123456789abcdefghijklmnopqrst"}`,
			want: `{"accessToken":"***********************************"}`,
		},
		{
			name: "a command line",
			src:  `curl -H "Authorization: Bearer mlsn.0123456789abcdefghijklmnopqrst" https://api.mailersend.com/v1/email`,
			want: `curl -H "Authorization: Bearer ***********************************" https://api.mailersend.com/v1/email`,
		},
		{
			name: "a configuration environment block",
			src:  `"env": {"MAILERSEND_API_TOKEN": "mlsn.0123456789abcdefghijklmnopqrst"}`,
			want: `"env": {"MAILERSEND_API_TOKEN": "***********************************"}`,
		},
		{
			name: "twice",
			src:  "mlsn.0123456789abcdefghijklmnopqrst mlsn.0123456789ABCDEFGHIJKLMNOPQRST",
			want: "*********************************** ***********************************",
		},
		{
			// The two spans are merged, so the token that begins inside the one
			// before it leaves nothing of itself behind.
			name: "two tokens with nothing between them",
			src:  "mlsn.0123456789abcdefghijklmnopqrstmlsn.0123456789ABCDEFGHIJKLMNOPQRST",
			want: "**********************************************************************",
		},
	}

	m := New(WithPatterns(MailerSendAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_MailerSendAPIToken_theCredentialsWithAnotherShape(t *testing.T) {
	// Two other MailerSend credentials, held to being left alone. Neither is an
	// API token written the way this pattern reads one, and what separates them
	// is the prefix in both cases.
	//
	// The SMTP password is written mssp. and no source states a shape for what
	// stands behind it, so the four letters in front of the dot are the whole
	// of what tells it from the token here. The other is the API token
	// MailerSend issued before it wrote a prefix on any of them, which its own
	// Firebase extension still gives eyJ and a row of asterisks as the example
	// of one: a JOSE-shaped value carrying no prefix for this scan to find.
	//
	// The cases move with the scan: either of them starting to be located means
	// the prefix widened, and that is a decision to be taken rather than noticed
	// afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "an smtp password",
			src:  "mssp.0123456789abcdefghijklmnopqrst",
		},
		{
			name: "a token of the shape MailerSend issued before it wrote a prefix",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
		},
	}

	m := New(WithPatterns(MailerSendAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_MailerSendAPIToken_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the token through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xmlsn.0123456789abcdefghijklmnopqrst",
			want: "x***********************************",
		},
		{
			name: "underscore before",
			src:  "MAILERSEND_API_TOKEN_mlsn.0123456789abcdefghijklmnopqrst",
			want: "MAILERSEND_API_TOKEN_***********************************",
		},
	}

	m := New(WithPatterns(MailerSendAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_MailerSendAPIToken_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a floor rather than a count. Where a token ends is
	// where its alphabet stops, so a letter or a digit written straight against
	// a token is redacted with it — which is what buys a token of a length
	// MailerSend has not minted yet being located whole. The alphabet is base62
	// and not base64url, so the two characters that separate them, the hyphen
	// and the underscore, end a token here, and so does the dot the prefix
	// itself closes with.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the token is mlsn.0123456789abcdefghijklmnopqrst.",
			want: "the token is ***********************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export MAILERSEND_API_TOKEN="mlsn.0123456789abcdefghijklmnopqrst"`,
			want: `export MAILERSEND_API_TOKEN="***********************************"`,
		},
		{
			name: "a word against the token",
			src:  "mlsn.0123456789abcdefghijklmnopqrstsuffix",
			want: "*****************************************",
		},
		{
			name: "a dashed word against the token",
			src:  "mlsn.0123456789abcdefghijklmnopqrst-suffix",
			want: "***********************************-suffix",
		},
		{
			name: "an underscored word against the token",
			src:  "mlsn.0123456789abcdefghijklmnopqrst_suffix",
			want: "***********************************_suffix",
		},
	}

	m := New(WithPatterns(MailerSendAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_MailerSendAPIToken_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than
	// redacted. A line cut to a column limit partway through a token leaves a
	// prefix and a body too short to be one, and the random characters written
	// before the cut come through whole.
	//
	// Thirty is where the one source that states a length puts the shortest
	// body, so the cases move with the scan: one of them starting to be located
	// means the floor moved, and that is a decision to be taken rather than
	// noticed afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a token one character short of the floor",
			src:  "MAILERSEND_API_TOKEN=mlsn.0123456789abcdefghijklmnopqrs",
		},
		{
			name: "a token cut off at its prefix",
			src:  "MAILERSEND_API_TOKEN=mlsn.",
		},
	}

	m := New(WithPatterns(MailerSendAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_MailerSendAPIToken_theShapesWrittenByAccident(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix closes with a
	// dot, which neither base64url nor standard base64 writes, so no encoded
	// payload can carry it inside itself however long it runs — and what is
	// left are the two shapes below.
	//
	// One is the boundary between two dotted segments: a JOSE payload whose
	// encoding happens to close on mlsn, with thirty base62 characters opening
	// the segment behind it. The other is a host name, where a dot stands in
	// front of every label and a label of thirty unbroken letters and digits is
	// this format exactly.
	//
	// The cases are held to being redacted rather than to being spared. Nothing
	// is left in the text to tell either from a token, so a pattern letting them
	// through would let a real token through with them. What the cases are for
	// is that they move with the scan: one of them ceasing to be located means
	// the grammar changed, and that is a decision to be taken rather than
	// noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			// The JWT pattern is not enabled here, so what the case states is
			// this pattern's own reading of the text.
			name: "a jose payload closing on the letters of the prefix",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQmlsn.0123456789abcdefghijklmnopqrst",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ***********************************",
		},
		{
			name: "a label of a host name",
			src:  "curl https://mlsn.0123456789abcdefghijklmnopqrst.example.com/",
			want: "curl https://***********************************.example.com/",
		},
	}

	m := New(WithPatterns(MailerSendAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_MailerSendAPIToken_aBodyOfFewCharacters(t *testing.T) {
	// Where this pattern is wider than the source its floor came from, held to
	// the answer builtin_mailersend_api_token.go argues for. betterleaks drops a
	// match whose body falls below an entropy of three and a half, so the body
	// below is no finding there and is a token here: a scan is deciding what to
	// keep out of a log rather than what to put in a report, and the two do not
	// want the same clause.
	//
	// The body carries no ordered run, since ten each of three characters is
	// what it is about.
	src := "mlsn.aaaaaaaaaabbbbbbbbbbcccccccccc"
	want := "***********************************"

	m := New(WithPatterns(MailerSendAPIToken()))
	if got := m.Mask(src); got != want {
		t.Errorf("Mask(%q) = %q, want %q", src, got, want)
	}
}

func Test_MailerSendAPIToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_mailersend_api_token.go names, held to the answer it
	// gives rather than to the one a reader might want. The floor sits below the
	// length of every common digest: hexadecimal digits are base62 and a digest
	// carries nothing that ends a run, so the prefix and an MD5, a git SHA or a
	// SHA-256 are a token's format exactly and all three are redacted.
	// Declining them would mean declining every token MailerSend happened to
	// write in the digits alone.
	//
	// What holds the other side of it is the prefix: a digest standing behind a
	// hyphen, or behind nothing at all, carries no dot for a candidate to be
	// found at.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "an md5 behind the prefix",
			src:  "mlsn.0123456789abcdef0123456789abcdef",
			want: "*************************************",
		},
		{
			name: "a git sha behind the prefix",
			src:  "mlsn.0123456789abcdef0123456789abcdef01234567",
			want: "*********************************************",
		},
		{
			name: "a sha256 in a cache key",
			src:  "key: mlsn.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "key: *********************************************************************",
		},
		{
			name: "a sha256 behind a hyphen rather than the prefix",
			src:  "mlsn-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "mlsn-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a digest with no prefix in front of it",
			src:  "sha1=0123456789abcdef0123456789abcdef01234567",
			want: "sha1=0123456789abcdef0123456789abcdef01234567",
		},
	}

	m := New(WithPatterns(MailerSendAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_mailerSendAPITokenPrefix(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a token
	// can begin inside the one before it, and that holds only while the prefix
	// opens with characters a body may be written with. Here it is the four in
	// front of the dot: a body closing with mlsn leaves the dot of the next
	// token standing directly behind it. A prefix opening with a character
	// outside the alphabet would make the two impossible to nest, and the cases
	// above pinning the nesting would stand for nothing — which is not a failure
	// anything else here reports.
	if mailerSendAPITokenPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	if c := mailerSendAPITokenPrefix[0]; !isBase62Byte(c) {
		t.Errorf("the prefix opens with %q, which no body may be written with, so no token can begin inside another", c)
	}
}

func Test_mailerSendAPITokenPrefix_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over
	// it, where a scan whose prefix closes on a character its own body admits
	// has to keep one. What makes the cursor unnecessary is that two candidates
	// can never read the same run: a candidate asks for the last character of
	// the prefix directly in front of its body, no body may be written with it,
	// so the run of an earlier candidate has already ended there and the later
	// candidate's run begins past it. Were that character one a body admits, a
	// run dense in prefixes would be walked once for every candidate in it and
	// the scan would cost time quadratic in the length of such a line.
	if mailerSendAPITokenPrefix == "" {
		t.Fatal("the pattern carries no prefix, so there is no candidate to reason about")
	}
	if c := mailerSendAPITokenPrefix[len(mailerSendAPITokenPrefix)-1]; isBase62Byte(c) {
		t.Errorf("the prefix closes with %q, which a body may be written with, so two candidates can read the same run", c)
	}
}

// Test_mailerSendAPITokenAnchor holds the prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_mailerSendAPITokenAnchor(t *testing.T) {
	if mailerSendAPITokenAnchorIndex >= len(mailerSendAPITokenPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", mailerSendAPITokenAnchorIndex, len(mailerSendAPITokenPrefix))
	}
	if c := mailerSendAPITokenPrefix[mailerSendAPITokenAnchorIndex]; c != mailerSendAPITokenAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(mailerSendAPITokenAnchor))
	}
}

func Test_MailerSendAPIToken_scanIsLinear(t *testing.T) {
	// A line dense in prefixes holds a candidate for every five characters it
	// has. The one thing a candidate reads that is a walk over the rest of the
	// input rather than a bounded test is where its run ends, and repeating that
	// walk at every candidate would cost time quadratic in the length of the
	// line. The bound here is far above a linear scan and far below a quadratic
	// one.
	//
	// The generic guard in builtins_test.go repeats every sample and every
	// sample cut in half, and the shortest unit that leaves is seventeen bytes,
	// so it crowds candidates no closer than one every seventeen. The crowding a
	// line can actually carry, a candidate every five bytes, stays here.
	sources := map[string]string{
		// Candidates as close together as the prefix allows, none of them with
		// a run long enough to be a body: every one reaches the body of the
		// loop and every one is rejected.
		"a candidate every five characters": strings.Repeat("mlsn.", 200000),
		// Tokens written into one another, each beginning four characters
		// before the one in front of it ends, so every candidate is a token and
		// every one of them walks a run.
		"a token beginning inside every token": strings.Repeat("mlsn.0123456789abcdefghijklmnop", 32000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a token.
		"a body that runs the length of the line": "mlsn." + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("a.", 900000),
		// The prefix MailerSend writes an SMTP password with, which carries the
		// anchor and the byte the scan tests in front of it, so each is declined
		// by the comparison of the whole prefix — the most a position costs
		// before any run is walked.
		"an smtp password prefix every five characters": strings.Repeat("mssp.", 200000),
		// And the prefix's own letters with no anchor among them, which is the
		// walk reading a whole line and stopping nowhere in it.
		"the letters of the prefix with no anchor": strings.Repeat("mlsn", 450000),
	}

	checkScanIsLinear(t, MailerSendAPIToken(), sources)
}

// referenceMailerSendAPIToken is the expression the scan in
// builtin_mailersend_api_token.go reads by hand: the statement of what a
// MailerSend API token is, kept here so that the scan can be held to it.
//
// The prefix, the floor and the alphabet are spelled again rather than built
// from mailerSendAPITokenPrefix, mailerSendAPITokenBodyChars and isBase62Byte.
// A reference sharing those declarations could not disagree with the scan about
// them, and it is exactly that disagreement the fuzz target below is for: the
// two have to be changed together or reported apart.
//
// The floor is written as a counted repetition, which is what a reference is
// otherwise written out by hand to avoid. It costs nothing here, and for the
// reason the scan needs no cursor: candidates cannot crowd inside one run, so
// no input makes an engine walk the same run more than once.
var referenceMailerSendAPIToken = regexp.MustCompile(`mlsn\.[0-9A-Za-z]{30,}`)

// referenceMailerSendAPITokenFind locates tokens the plain way: the leftmost
// match of the expression above, then the leftmost one beginning after that
// match's first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a token can begin inside one: the four letters
// the prefix opens with are written in the alphabet a body is, so a body
// closing with mlsn holds the start of the token behind it. The scan finds both
// and reports the two spans overlapping for a Masker to resolve, so the
// reference must ask about both.
func referenceMailerSendAPITokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceMailerSendAPIToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzMailerSendAPIToken_matchesReference guards the hand-written scan: the
// prefix it searches for, the floor it holds a body to, the alphabet it reads
// that body in and the byte it resumes at may none of them change which tokens
// are located.
func FuzzMailerSendAPIToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("MAILERSEND_API_TOKEN=mlsn.0123456789abcdefghijklmnopqrst")
	f.Add("mlsn.0123456789ABCDEFGHIJKLMNOPQRST")
	f.Add("mlsn.0123456789abcdefghijklmnopqrs")        // one short of a body
	f.Add("mlsn.0123456789abcdefghijklmnopqrstuvwxyz") // a run longer than the floor
	f.Add("mlsn.0123456789abcdefghij-lmnopqrst")       // a hyphen, which base64url admits and base62 does not
	f.Add("mlsn.0123456789abcdefghij_lmnopqrst")       // an underscore, likewise
	f.Add("mlsn.0123456789abcdefghij.lmnopqrst")       // a dot ends the body
	f.Add("MLSN.0123456789abcdefghijklmnopqrst")       // an uppercase prefix
	f.Add("mlsn_0123456789abcdefghijklmnopqrst")       // an underscore where the prefix carries a dot
	f.Add("mlsn0123456789abcdefghijklmnopqrst")        // the prefix without its closing dot
	f.Add("mlsn.0123456789abcdefghijklmnopqrst-suffix")
	f.Add("mlsn.0123456789abcdefghijklmnopqrst_suffix")
	f.Add("mlsn.0123456789abcdefghijklmnopqrst\nmlsn.0123456789ABCDEFGHIJKLMNOPQRST")
	// Two tokens with nothing between them, where the second begins four
	// characters before the first one ends and a scan resuming past a match
	// would step over it.
	f.Add("mlsn.0123456789abcdefghijklmnopqrstmlsn.0123456789ABCDEFGHIJKLMNOPQRST")
	// Candidate positions crowded as close as they can be, with no run long
	// enough for any of them, and tokens written into one another so that every
	// candidate has one.
	f.Add(strings.Repeat("mlsn.", 16))
	f.Add(strings.Repeat("mlsn.0123456789abcdefghijklmnop", 4))
	// The prefix MailerSend writes an SMTP password with, which carries the
	// anchor and the byte tested in front of it and is not this credential.
	f.Add("mssp.0123456789abcdefghijklmnopqrst")
	// A body of few distinct characters, which the source the floor came from
	// filters on entropy and this scan reads as a token.
	f.Add("mlsn.aaaaaaaaaabbbbbbbbbbcccccccccc")
	// A digest written behind the prefix, which is a token's format exactly.
	f.Add("mlsn.0123456789abcdef0123456789abcdef")
	f.Add("mlsn.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// The two shapes that reach the prefix by accident: a dotted segment
	// boundary and a label of a host name.
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQmlsn.0123456789abcdefghijklmnopqrst")
	f.Add("curl https://mlsn.0123456789abcdefghijklmnopqrst.example.com/")

	fuzzAgainstReference(f, MailerSendAPIToken().Find, referenceMailerSendAPITokenFind)
}

// mailerSendAPITokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func mailerSendAPITokenFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no token. It is also the line the choice of anchor is
	// argued on: the dot stands twice, against three n, four s and six each of
	// m and l.
	line := `time=2026-08-17T00:00:00Z level=info msg="email accepted" recipients=3 url=https://api.mailersend.com/v1/email `
	token := "mlsn.0123456789abcdefghijklmnopqrst"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every five characters with no run long enough behind
			// any of them: each reaches the body of the loop and none becomes a
			// token. What it times is the walk over a run being started and
			// stopped, once per candidate and no more.
			name:  "candidates that are not values",
			src:   strings.Repeat("mlsn.", 128),
			spans: 0,
		},
		{
			// The prefix MailerSend writes an SMTP password with, as close
			// together as it goes. Each carries the anchor and the byte tested
			// in front of it, so each is declined by the comparison of the whole
			// prefix, which is what the choice of anchor pays for. It is the
			// case above that costs more: a candidate opening a whole prefix
			// goes on to walk a run.
			name:  "an smtp password prefix",
			src:   strings.Repeat("mssp.", 128),
			spans: 0,
		},
		{
			// Tokens written into one another, each beginning four characters
			// before the one in front of it ends. This is what the scan gets
			// away with keeping no cursor for: the runs the candidates read
			// follow one another rather than overlapping. The four letters at
			// the end are what closes the body of the last of them, which
			// otherwise has only the run it was written with.
			name:  "tokens written into one another",
			src:   strings.Repeat("mlsn.0123456789abcdefghijklmnop", 128) + "mlsn",
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
