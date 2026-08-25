package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The Stripe webhook signing secret pattern: what it locates and what it leaves
// alone, written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The secrets written out below are made only of the ordered run
// 0123456789abcdef, which no real credential is, written out until it is the
// thirty-two characters the pattern holds a body to. That count is a floor and
// not an abbreviation: a body shortened for readability would leave a case
// holding no secret at all. It is written in lowercase where the case does not
// matter and in uppercase where the case is what a case is about, since base62
// holds the letters of both.

func Test_StripeWebhookSigningSecret(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a secret on its own",
			src:  "whsec_0123456789abcdef0123456789abcdef",
			want: []Span{{0, 38}},
		},
		{
			name: "a secret in an environment assignment",
			src:  "STRIPE_WEBHOOK_SECRET=whsec_0123456789abcdef0123456789abcdef",
			want: []Span{{22, 60}},
		},
		{
			// base62 holds the letters of both cases, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "whsec_0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 38}},
		},
		{
			// The count is a floor and the span reaches the end of the run, so a
			// run longer than the shortest body is a secret to the end of it
			// rather than a secret and a character left over. Twice the floor is
			// the shape Stripe writes into its own example environment file.
			name: "a run longer than the shortest body",
			src:  "whsec_0123456789abcdef0123456789abcdef0",
			want: []Span{{0, 39}},
		},
		{
			name: "a body of twice the floor",
			src:  "whsec_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 70}},
		},
		{
			name: "two secrets separated by a space",
			src:  "whsec_0123456789abcdef0123456789abcdef whsec_0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 38}, {39, 77}},
		},
		{
			// The five letters the prefix opens with belong to the alphabet a
			// body is written in, so a body may close with whsec and the
			// underscore of the next secret stand directly behind it. The second
			// secret begins five characters before the first one ends, and a scan
			// resuming past a match would step over it. The spans overlap, which
			// a Masker resolves into one.
			name: "a secret beginning inside the secret before it",
			src:  "whsec_0123456789abcdef0123456789awhsec_0123456789abcdef0123456789abcdef",
			want: []Span{{0, 38}, {33, 71}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StripeWebhookSigningSecret().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_StripeWebhookSigningSecret_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "whsec_",
		},
		{
			// Thirty-one characters where the pattern asks for thirty-two. This
			// is the shape a line cut to a column limit leaves, and the
			// characters in front of the cut stay in the text: the far side of
			// reading a floor, which
			// builtin_stripe_webhook_signing_secret.go weighs.
			name: "a body one character too short",
			src:  "whsec_0123456789abcdef0123456789abcde",
		},
		{
			// The hyphen and the underscore are base64url characters and no
			// base62 ones, so either ends a body where the run behind it is too
			// short to be one.
			name: "a body carrying a hyphen",
			src:  "whsec_0123456789abcdef-0123456789abcdef",
		},
		{
			name: "a body carrying an underscore",
			src:  "whsec_0123456789abcdef_0123456789abcdef",
		},
		{
			// The two characters standard base64 adds to the alphabet, and the
			// padding character behind them. Stripe's own crash report scrubber
			// reads all three behind this prefix and this scan reads none of
			// them, so each of them ends a body here and what is left in front
			// of it is too short to be one.
			name: "a body carrying a plus",
			src:  "whsec_0123456789abcdef+0123456789abcdef",
		},
		{
			name: "a body carrying a slash",
			src:  "whsec_0123456789abcdef/0123456789abcdef",
		},
		{
			name: "a body carrying the padding character",
			src:  "whsec_0123456789abcdef=0123456789abcdef",
		},
		{
			name: "an uppercase prefix",
			src:  "WHSEC_0123456789abcdef0123456789abcdef",
		},
		{
			// The prefix closes with an underscore, so a hyphen written in its
			// place opens no candidate at all.
			name: "a hyphen where the prefix carries an underscore",
			src:  "whsec-0123456789abcdef0123456789abcdef",
		},
		{
			name: "one character of the prefix wrong",
			src:  "whsex_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a space in the body",
			src:  "whsec_0123456789abcdef 0123456789abcdef",
		},
		{
			name: "a dot in the body",
			src:  "whsec_0123456789abcdef.0123456789abcdef",
		},
		{
			name: "a body broken by a line break",
			src:  "whsec_0123456789abcdef\n0123456789abcdef",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// the whole of the anchor, so a run long enough is not a secret
			// without it.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdef0123456789abcdef",
		},
		{
			// What Stripe writes into its own CLI reference where a secret would
			// stand: fourteen characters, which the floor turns away.
			name: "the placeholder Stripe writes where a secret goes",
			src:  "whsec_abcdefg1234567",
		},
		{
			// A placeholder written in snake_case. The next underscore of such a
			// name ends the run long before thirty-two characters of it have been
			// read.
			name: "a placeholder written in snake_case",
			src:  "STRIPE_WEBHOOK_SECRET=whsec_your_webhook_signing_secret_goes_here",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// Forty hexadecimal characters. A digest carries no underscore, so it
			// holds no prefix to be found at however long it runs.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StripeWebhookSigningSecret().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_StripeWebhookSigningSecret_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "STRIPE_WEBHOOK_SECRET=whsec_0123456789abcdef0123456789abcdef",
			want: "STRIPE_WEBHOOK_SECRET=**************************************",
		},
		{
			// What the CLI prints when it begins forwarding events to a local
			// endpoint.
			name: "the line the stripe cli announces a session with",
			src:  "> Ready! Your webhook signing secret is whsec_0123456789abcdef0123456789abcdef (^C to quit)",
			want: "> Ready! Your webhook signing secret is ************************************** (^C to quit)",
		},
		{
			// The field the v1 webhook endpoint object carries it in.
			name: "json",
			src:  `{"secret":"whsec_0123456789abcdef0123456789abcdef"}`,
			want: `{"secret":"**************************************"}`,
		},
		{
			// And the field the v2 event destination carries it in.
			name: "a signing secret in an event destination",
			src:  `{"webhook_endpoint":{"signing_secret":"whsec_0123456789abcdef0123456789abcdef"}}`,
			want: `{"webhook_endpoint":{"signing_secret":"**************************************"}}`,
		},
		{
			name: "a secret in a source file",
			src:  `const endpointSecret = 'whsec_0123456789abcdef0123456789abcdef';`,
			want: `const endpointSecret = '**************************************';`,
		},
		{
			name: "twice",
			src:  "whsec_0123456789abcdef0123456789abcdef whsec_0123456789ABCDEF0123456789ABCDEF",
			want: "************************************** **************************************",
		},
		{
			// The two spans are merged, so the secret that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a secret beginning inside the secret before it",
			src:  "whsec_0123456789abcdef0123456789awhsec_0123456789abcdef0123456789abcdef",
			want: "***********************************************************************",
		},
	}

	m := New(WithPatterns(StripeWebhookSigningSecret()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_StripeWebhookSigningSecret_nextToWordCharacters(t *testing.T) {
	// The byte in front of the prefix is not read at all, which is what tells
	// this pattern from the Stripe API key patterns beside it. Their demand
	// would drop rather than trim each of these matches, and it would drop the
	// nested and the adjacent secret with them, for the letter or digit every
	// position inside a span past the prefix is.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xwhsec_0123456789abcdef0123456789abcdef",
			want: "x**************************************",
		},
		{
			name: "digit before",
			src:  "1whsec_0123456789abcdef0123456789abcdef",
			want: "1**************************************",
		},
		{
			name: "underscore before",
			src:  "STRIPE_WEBHOOK_SECRET_whsec_0123456789abcdef0123456789abcdef",
			want: "STRIPE_WEBHOOK_SECRET_**************************************",
		},
	}

	m := New(WithPatterns(StripeWebhookSigningSecret()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_StripeWebhookSigningSecret_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a floor rather than a count. Where a secret ends
	// is where its alphabet stops, so a letter or a digit written straight
	// against one is redacted with it — which is what buys a secret of a length
	// nobody has published being located whole. The alphabet is base62, so the
	// hyphen and the underscore end a run rather than carrying it on, and so do
	// the two characters standard base64 adds.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the secret is whsec_0123456789abcdef0123456789abcdef.",
			want: "the secret is **************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export STRIPE_WEBHOOK_SECRET="whsec_0123456789abcdef0123456789abcdef"`,
			want: `export STRIPE_WEBHOOK_SECRET="**************************************"`,
		},
		{
			name: "a word against the secret",
			src:  "whsec_0123456789abcdef0123456789abcdefsuffix",
			want: "********************************************",
		},
		{
			name: "a dashed word against the secret",
			src:  "whsec_0123456789abcdef0123456789abcdef-suffix",
			want: "**************************************-suffix",
		},
		{
			name: "an underscored word against the secret",
			src:  "whsec_0123456789abcdef0123456789abcdef_suffix",
			want: "**************************************_suffix",
		},
		{
			name: "a path written against the secret",
			src:  "whsec_0123456789abcdef0123456789abcdef/webhook",
			want: "**************************************/webhook",
		},
	}

	m := New(WithPatterns(StripeWebhookSigningSecret()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_StripeWebhookSigningSecret_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than redacted.
	// A line cut to a column limit partway through a secret leaves a prefix and
	// a body too short to be one, and the random characters written before the
	// cut come through whole.
	//
	// It is the price of reading a count off the values Stripe has printed
	// rather than one Stripe has stated, and the cases move with the scan: one
	// of them starting to be located means the floor moved, and that is a
	// decision to be taken rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a secret one character short of the floor",
			src:  "STRIPE_WEBHOOK_SECRET=whsec_0123456789abcdef0123456789abcde",
		},
		{
			name: "a secret cut off at its prefix",
			src:  "STRIPE_WEBHOOK_SECRET=whsec_",
		},
	}

	m := New(WithPatterns(StripeWebhookSigningSecret()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_StripeWebhookSigningSecret_aPlaceholderLongEnoughToBeASecret(t *testing.T) {
	// The over-match builtin_stripe_webhook_signing_secret.go names, held to the
	// answer it gives rather than to the one a reader might want. A word
	// somebody wrote where a secret goes is a secret's format exactly once it
	// reaches the floor unbroken, so it is redacted; declining it would mean
	// declining every secret Stripe wrote in the letters alone.
	//
	// The two after it are where the floor and the alphabet hold instead: most
	// placeholders are shorter than thirty-two characters, and one written in
	// snake_case ends at its next underscore however long the whole of it runs.
	// The cases move with the scan, so a change to either shows up here as a
	// decision rather than as something the next reader discovers.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a placeholder of thirty-two unbroken characters",
			src:  "STRIPE_WEBHOOK_SECRET=whsec_replacethiswithyoursigningsecret",
			want: "STRIPE_WEBHOOK_SECRET=**************************************",
		},
		{
			name: "a placeholder short of the floor",
			src:  "STRIPE_WEBHOOK_SECRET=whsec_yoursecret",
			want: "STRIPE_WEBHOOK_SECRET=whsec_yoursecret",
		},
		{
			name: "a placeholder written in snake_case",
			src:  "STRIPE_WEBHOOK_SECRET=whsec_replace_this_with_your_signing_secret",
			want: "STRIPE_WEBHOOK_SECRET=whsec_replace_this_with_your_signing_secret",
		},
	}

	m := New(WithPatterns(StripeWebhookSigningSecret()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_StripeWebhookSigningSecret_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix carries an
	// underscore, which standard base64 writes nowhere, so only a base64url
	// encoding can hold one — and there six characters of an alphabet of
	// sixty-four stand where the prefix stands about once in seventy thousand
	// million characters. Where thirty-two base62 characters follow, everything
	// from the prefix to the end of that run is redacted.
	//
	// The cases are held to being redacted rather than to being spared. What is
	// taken is a stretch of a value already opaque to a reader, and the run is a
	// secret's format exactly: nothing is left in the text to tell the two
	// apart, so a pattern letting it through would let a real secret through
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
			src:  "payload=zzzzwhsec_0123456789abcdef0123456789abcdefzzzz",
			want: "payload=zzzz******************************************",
		},
		{
			// The same run written where a JWT signature stands. The JWT pattern
			// is not enabled here, so what the case states is this pattern's own
			// reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzwhsec_0123456789abcdef0123456789abcdefzzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz******************************************",
		},
	}

	m := New(WithPatterns(StripeWebhookSigningSecret()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_stripeWebhookSigningSecretPrefix(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a secret
	// can begin inside the one before it, and that holds only while the prefix
	// carries characters a body may be written with. Here it is the five in
	// front of the underscore: a body closing with whsec leaves the underscore
	// of the next secret standing directly behind it. A prefix written entirely
	// outside the alphabet would make the two impossible to nest, and the case
	// above pinning the nesting would stand for nothing — which is not a failure
	// anything else here reports.
	if stripeWebhookSigningSecretPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for i := range len(stripeWebhookSigningSecretPrefix) - 1 {
		if c := stripeWebhookSigningSecretPrefix[i]; !isBase62Byte(c) {
			t.Errorf("the prefix holds %q in front of its last character, which no body may be written with", c)
		}
	}
}

// Test_stripeWebhookSigningSecretAnchor holds the prefix to carrying the byte
// the scan searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_stripeWebhookSigningSecretAnchor(t *testing.T) {
	if stripeWebhookSigningSecretAnchorIndex >= len(stripeWebhookSigningSecretPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", stripeWebhookSigningSecretAnchorIndex, len(stripeWebhookSigningSecretPrefix))
	}
	if c := stripeWebhookSigningSecretPrefix[stripeWebhookSigningSecretAnchorIndex]; c != stripeWebhookSigningSecretAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(stripeWebhookSigningSecretAnchor))
	}
}

func Test_stripeWebhookSigningSecretPrefix_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over it,
	// where a scan whose prefix closes on a character its own body admits has to
	// keep one. What makes the cursor unnecessary is that two candidates can
	// never read the same run: a candidate asks for the last character of the
	// prefix six characters in, no body may be written with it, so the run of an
	// earlier candidate has already ended there and the later candidate's run
	// begins past it. Were that character one a body admits, a run dense in
	// prefixes would be walked once for every candidate in it and the scan would
	// cost time quadratic in the length of such a line.
	if stripeWebhookSigningSecretPrefix == "" {
		t.Fatal("the pattern carries no prefix, so there is no candidate to reason about")
	}
	if c := stripeWebhookSigningSecretPrefix[len(stripeWebhookSigningSecretPrefix)-1]; isBase62Byte(c) {
		t.Errorf("the prefix closes with %q, which a body may be written with, so two candidates can read the same run", c)
	}
}

func Test_StripeWebhookSigningSecret_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a line dense in prefixes
	// holds a candidate for every six characters it has. The one thing a
	// candidate reads that is a walk over the rest of the input rather than a
	// bounded test is where its run ends, and repeating that walk at every
	// candidate would cost time quadratic in the length of the line. The bound
	// here is far above a linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every thirty-three bytes where they are densest, because a
	// sample has to carry a whole body to be one. The crowding a line can
	// actually carry, a candidate every six bytes, stays here.
	sources := map[string]string{
		// Candidates as close together as the prefix allows, none of them with a
		// run long enough to be a body: every one reaches the body of the loop
		// and every one is rejected.
		"a candidate every six characters": strings.Repeat("whsec_", 300000),
		// Secrets written into one another, each beginning five characters
		// before the one in front of it ends, so every candidate is a secret and
		// every one of them walks a run.
		"a secret beginning inside every secret": strings.Repeat("whsec_0123456789abcdef0123456789a", 54000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a secret.
		"a body that runs the length of the line": "whsec_" + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("a_", 900000),
		// And the prefix's own letters with no anchor among them, which is the
		// walk reading a whole line and stopping nowhere in it.
		"the letters of the prefix with no anchor": strings.Repeat("whsec", 360000),
	}

	m := New(WithPatterns(StripeWebhookSigningSecret()))
	for name, src := range sources {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_ = m.Mask(src)
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("Mask() of %d bytes took %v", len(src), d)
			}
		})
	}
}

// referenceStripeWebhookSigningSecret is the expression the scan in
// builtin_stripe_webhook_signing_secret.go reads by hand: the statement of what
// a Stripe webhook signing secret is, kept here so that the scan can be held to
// it.
//
// The prefix, the floor and the alphabet are spelled again rather than built
// from stripeWebhookSigningSecretPrefix, stripeWebhookSigningSecretBodyChars
// and isBase62Byte. A reference sharing those declarations could not disagree
// with the scan about them, and it is exactly that disagreement the fuzz target
// below is for: the two have to be changed together or reported apart.
//
// The floor is written as a counted repetition, which is what a reference
// written out by hand avoids. It costs nothing here, and for the reason the
// scan needs no cursor: the run behind a candidate ends at the underscore any
// later prefix opens with, so an engine asking for thirty-two characters at a
// crowded candidate stops inside the six the prefix takes.
var referenceStripeWebhookSigningSecret = regexp.MustCompile(`whsec_[0-9A-Za-z]{32,}`)

// referenceStripeWebhookSigningSecretFind locates secrets the plain way: the
// leftmost match of the expression above, then the leftmost one beginning after
// that match's first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a secret can begin inside one: the five letters
// the prefix opens with are written in the alphabet a body is, so a body
// closing with whsec holds the start of the secret behind it. The scan finds
// both and reports the two spans overlapping for a Masker to resolve, so the
// reference must ask about both.
func referenceStripeWebhookSigningSecretFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceStripeWebhookSigningSecret.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzStripeWebhookSigningSecret_matchesReference guards the hand-written scan:
// the prefix it searches for, the floor it holds a body to, the alphabet it
// reads that body in and the byte it resumes at may none of them change which
// secrets are located.
func FuzzStripeWebhookSigningSecret_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("STRIPE_WEBHOOK_SECRET=whsec_0123456789abcdef0123456789abcdef")
	f.Add("whsec_0123456789ABCDEF0123456789ABCDEF")
	f.Add("whsec_0123456789abcdef0123456789abcde")                                  // one short of a body
	f.Add("whsec_0123456789abcdef0123456789abcdef0")                                // and a run longer than one
	f.Add("whsec_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") // twice the floor
	f.Add("whsec_0123456789abcdef-0123456789abcdef")                                // a hyphen, which base64url admits and base62 does not
	f.Add("whsec_0123456789abcdef_0123456789abcdef")                                // an underscore, likewise
	f.Add("whsec_0123456789abcdef+0123456789abcdef")                                // a plus, which standard base64 adds
	f.Add("whsec_0123456789abcdef/0123456789abcdef")                                // and a slash
	f.Add("whsec_0123456789abcdef=0123456789abcdef")                                // the character standard base64 pads with
	f.Add("whsec_0123456789abcdef0123456789abcdef==")                               // and that character behind a whole body
	f.Add("whsec_0123456789abcdef.0123456789abcdef")                                // a dot ends the body
	f.Add("WHSEC_0123456789abcdef0123456789abcdef")                                 // an uppercase prefix
	f.Add("whsec-0123456789abcdef0123456789abcdef")                                 // a hyphen where the prefix carries an underscore
	f.Add("whsec_0123456789abcdef0123456789abcdef-suffix")
	f.Add("whsec_0123456789abcdef0123456789abcdef_suffix")
	f.Add("whsec_0123456789abcdef0123456789abcdef\nwhsec_0123456789ABCDEF0123456789ABCDEF")
	// A secret beginning inside the match before it, which a scan resuming past
	// a match steps over, and two secrets with nothing between them.
	f.Add("whsec_0123456789abcdef0123456789awhsec_0123456789abcdef0123456789abcdef")
	f.Add("whsec_0123456789abcdef0123456789abcdefwhsec_0123456789ABCDEF0123456789ABCDEF")
	// Candidate positions crowded as close as they can be, with no run long
	// enough for any of them, and secrets written into one another so that every
	// candidate has one.
	f.Add(strings.Repeat("whsec_", 16))
	f.Add(strings.Repeat("whsec_0123456789abcdef0123456789a", 4))
	// The placeholders: the one Stripe writes into its own CLI reference, one
	// long enough to be a secret, and one whose next underscore ends the run.
	f.Add("whsec_abcdefg1234567")
	f.Add("STRIPE_WEBHOOK_SECRET=whsec_replacethiswithyoursigningsecret")
	f.Add("STRIPE_WEBHOOK_SECRET=whsec_replace_this_with_your_signing_secret")
	// The prefix written inside a run of base64url, which is the over-match the
	// pattern admits.
	f.Add("payload=zzzzwhsec_0123456789abcdef0123456789abcdefzzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzwhsec_0123456789abcdef0123456789abcdefzzzz")

	fuzzAgainstReference(f, StripeWebhookSigningSecret().Find, referenceStripeWebhookSigningSecretFind)
}

// stripeWebhookSigningSecretFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func stripeWebhookSigningSecretFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line carries the anchor, so what the line times is
	// the walk looking for it — which is most of what this pattern costs a
	// caller whose text holds no secret.
	line := `time=2026-08-17T00:00:00Z level=info msg="handling an event" url=https://example.com/webhook `
	secret := "whsec_0123456789abcdef0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every six characters with no run long enough behind any
			// of them: each reaches the body of the loop and none becomes a
			// secret. What it times is the walk over a run being started and
			// stopped, once per candidate and no more.
			name:  "candidates that are not values",
			src:   strings.Repeat("whsec_", 128),
			spans: 0,
		},
		{
			// Secrets written into one another, each beginning five characters
			// before the one in front of it ends. This is what the scan gets away
			// with keeping no cursor for: the runs the candidates read follow one
			// another rather than overlapping. The five characters at the end are
			// what closes the body of the last of them, which otherwise has only
			// the run it was written with.
			name:  "secrets written into one another",
			src:   strings.Repeat("whsec_0123456789abcdef0123456789a", 128) + "bcdef",
			spans: 128,
		},
		{
			name:  "one value",
			src:   line + "secret=" + secret,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "secret=" + secret,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"secret="+secret+"\n", 32),
			spans: 32,
		},
	}
}
