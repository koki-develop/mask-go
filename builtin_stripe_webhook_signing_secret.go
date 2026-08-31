package mask

import "strings"

// StripeWebhookSigningSecret locates the signing secrets Stripe issues for a
// webhook endpoint (whsec_): the key a handler computes the HMAC in the
// Stripe-Signature header with, and the one the Stripe CLI prints when it
// begins forwarding events to a local endpoint.
//
// A secret is located wherever it is written, with no word boundary either
// side, and is redacted from its whsec_ to the end of the run it stands in. So
// a secret written against a word character keeps its span, and a character of
// the secret's own alphabet written straight after one is redacted with it.
//
// Its name is "stripe-webhook-signing-secret".
func StripeWebhookSigningSecret() Pattern { return stripeWebhookSigningSecret }

// Webhook signing secret is Stripe's own name for this value, and the boundary
// this pattern stands on is that no term of Stripe's covers it and the API keys
// together. Stripe's table of key types has four rows — the publishable, the
// restricted, the secret and the organization API key — and this is in none of
// them; it is not issued per account but per endpoint, it is rolled from the
// endpoint's own page rather than from the API keys page, and what it
// authenticates runs the other way, Stripe to the reader's server rather than
// the reader's server to Stripe. What those rows are is read by the scans in
// builtin_stripe_secret_key.go and builtin_stripe_publishable_key.go, and this
// is no row of that table.
//
// The name is Stripe's wherever Stripe names the value. The CLI announces a
// session by printing that the reader's webhook signing secret is whsec_ and
// the value; the guide to securing an endpoint tells a reader to get the
// endpoint's signing secret; the field the v2 event destination carries it in
// is spelled signing_secret, and the field the v1 webhook endpoint carries it
// in secret, which is the shorter half of the same term.
//
// What Stripe states about the format is the prefix and nothing else. No page
// gives a length, an alphabet or a checksum, and no ruleset fills the gap
// either: the three that read Stripe's API keys — gitleaks, GitLab's own secret
// detection rules and trufflehog — carry no rule for this prefix at all. GitHub
// lists a Stripe Webhook Signing Secret among the patterns its secret scanning
// carries for a partner, and publishes what it detects rather than the
// expression it detects with. So the alphabet and the count below are read off
// the values Stripe has printed, and off nothing else.
//
// What Stripe shows is three values. The API reference prints the secret of a
// freshly created endpoint, whsec_wRNftLajMZNeslQOP6vEPm4iVx5NlZ6z, and the
// CLI's own documentation of the listen command prints the one a forwarding
// session is given, whsec_oZ8nus9PHnoltEtWZ3pGITZdeHWHoqnL: thirty-two letters
// and digits behind the prefix, twice. The third is a placeholder rather than a
// secret — the environment file of Stripe's own webhook signing example carries
// the prefix and sixty-four zeros — and it is the reason the count below is
// read as a floor rather than as the thirty-two the other two agree on.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the ten digits, which is what both of the secrets Stripe has
// printed are written in and what the placeholder's digits are inside.
//
// A wider alphabet is on offer and is declined, and both sides of that are
// worth writing down, because what a scan reads too narrowly is a credential
// left in the text.
//
// What is on offer is what Stripe's own CLI reads where it scrubs its crash
// reports: the standard base64 alphabet and the padding character behind this
// prefix. That is breadth in a scrubber rather than a statement of the format.
// The same handful of lines reads an API key body as letters, digits and the
// underscore — a character no key Stripe issues carries, and one this package's
// other Stripe scans rely on a body never holding — so what those expressions
// say about an alphabet is that they were written to catch rather than to
// describe. The one other reading anybody has published is an open request
// against trufflehog, which calls the value base64 style and then admits the
// plus without the slash, which is no base64 at all; it is a proposal rather
// than an observation, and no ruleset has taken it up.
//
// What declining costs is a whole credential in the case where the reading is
// wrong. Were Stripe to write one of those characters into a secret, the run
// would end there: with thirty-two base62 characters in front of it the rest of
// the secret stays in the text, and with fewer the secret is located nowhere at
// all. Nothing observed says Stripe does. Both values it has printed are
// base62, the placeholder it writes into its own example is base62, and the
// identifiers and keys it hands out elsewhere are written in letters and digits
// alone.
//
// What admitting them would cost is what settles it, because it is not the
// harmless over-match a prefix this distinctive usually buys. The plus, the
// slash and the hyphen are punctuation a reader reads, and a span reaching the
// end of its run does not stop at them: a secret written in front of a path, a
// query or a hyphenated word would be redacted together with the text after it,
// which was never opaque. A built-in may over-match on what a reader takes
// nothing from, and that would not be one.
//
// Leaving the underscore out is doing more than bounding a span. It is what
// ends a body at the next segment of a snake_case name, so that
// whsec_id_0123456789abcdef0123456789abcdef is a body of two characters rather
// than a secret, and it is what makes every body begin where a run begins,
// which the account of the scan's cost below rests on.
//
// The count is read as a floor and not as a count. A count is read exactly
// where it is most of what tells a value from the text around it; here the
// prefix has already done that, since nothing anybody writes is spelled whsec
// and the underscore behind it has to be there too. What a count would add is
// the chance of being wrong, and being wrong about a count is a secret located
// nowhere: Stripe has printed thirty-two twice and written sixty-four into its
// own example, and a scan asking for thirty-two exactly would locate the first
// thirty-eight characters of the longer shape and leave the rest of it in the
// text.
//
// The floor is thirty-two, the length of both secrets Stripe has printed. What
// it holds back is the placeholder, which is what the prefix is followed by in
// documentation, templates and fixtures far more often than a secret is:
// whsec_abcdefg1234567 is what Stripe writes into the CLI reference where a
// secret would stand, and it is fourteen characters. What the floor costs is
// the secret shorter than it — a line cut to a column limit partway through one
// leaves a prefix and a body too short to be a body, and the random characters
// written before the cut stay in the output. That is the far side of this
// choice, and the cases in builtin_stripe_webhook_signing_secret_test.go pin it
// so that it stays a decision on the record.
//
// There is no boundary on either side of a match. A boundary behind it would
// drop rather than trim, and where it were asked decides what it drops. Asked
// behind the count, it drops the secret a letter, a digit or an underscore is
// written against. Asked behind that run, it drops the secret an underscore is
// written against and nothing else, the underscore being the one word
// character no body admits.
// Test_StripeWebhookSigningSecret_reachesTheEndOfTheRun writes both out.
//
// A boundary in front is a demand the Stripe API key scans do make, and it is
// worth saying why this one does not, because a caller reaching for the vendor
// gets this pattern beside them. What makes the demand worth its cost there is
// a key type an ordinary word can close on — task_ ends in one and network_ in
// the other — so that a snake_case name and a mode would otherwise read as a
// key. Six characters ending in whsec close no word anybody writes, so there is
// no such text for the demand to turn away here.
//
// What it would turn away instead is the base64url embedding below, where a
// character of the encoding stands in front of the prefix: the demand is
// mechanical rather than lexical, asking only that the byte in front be no
// letter and no digit, and it does not ask whether what it turns away was a
// word. That is a tightening on offer and it is declined, because of what the
// same byte costs. Every position a span covers past the prefix is a letter or
// a digit, so the demand would turn away the secret nested in the body of the
// one before it and the second of two written with nothing between them — both
// of which this scan locates and pins. The embedding it would buy off stands
// about once in the two hundred thousand million characters counted below and
// takes text already opaque to a reader; the secrets it would cost are
// redacted today. A credential left whole is the more expensive of the two
// errors, so the byte in front goes unread.
//
// The scan resumes one byte past the start of a candidate whether it became a
// secret or not. The underscore the prefix closes with belongs to no body, but
// the five letters in front of it do, so a body may close with whsec and the
// underscore opening the next secret stand directly behind it: the prefix, a
// body whose last five characters are whsec, then _ and a body of its own is
// two secrets, the second beginning five characters before the first one ends.
// Consuming a match would step over such a secret and leave it in the output
// whole. The two spans then overlap, which a Masker resolves into one.
//
// No cursor is kept over the run, and none is needed. A candidate asks for an
// underscore six characters in and no body may be written with one, so the
// underscore of the next candidate stands no earlier than the byte that ends
// this candidate's run, and the run that candidate reads therefore begins past
// this one. Successive candidates read runs that do not overlap, so reading all
// of them comes to the length of the input.
// Test_stripeWebhookSigningSecretPrefix_runsDoNotOverlap holds the prefix to
// the one character that argument rests on, and
// Test_StripeWebhookSigningSecret_scanIsLinear drives the inputs that would
// find it wrong.
//
// What this pattern over-matches on is the placeholder long enough to reach the
// floor: the prefix and thirty-two unbroken letters and digits of a word
// somebody wrote where a secret goes, as whsec_replacethiswithyoursigningsecret
// is. That is a secret's format exactly — Stripe writes nothing into a secret
// that a written-out word could not hold — so nothing is left in the text to
// read the two apart by, and the tightening on offer is the count, which the
// paragraphs above weigh and which costs a whole credential when it is wrong.
// The short placeholders, which are most of them, are what the floor turns
// away. Test_StripeWebhookSigningSecret_aPlaceholderLongEnoughToBeASecret pins
// both sides of that.
//
// The other thing that reaches a span is the prefix written inside a run that
// nobody meant as one. Standard base64 carries no underscore, so a certificate,
// a PEM body or an embedded image holds no prefix to be found at however long
// it runs, and only a base64url encoding can hold one — there six characters
// drawn from an alphabet of sixty-four stand where the prefix stands about once
// in seventy thousand million characters, and the thirty-two behind one carry
// neither of the two characters base64url adds about four times in ten, so the
// prefix and a body together stand about once in two hundred thousand million
// characters of such an encoding. What is taken there is a stretch of a value
// that was already opaque to a reader.
//
// What reaches a span is never prose, a git SHA or an MD5. A digest carries no
// underscore, so it holds no prefix to be found at however long it runs, and no
// word of prose is spelled whsec_.
//
// referenceStripeWebhookSigningSecret in
// builtin_stripe_webhook_signing_secret_test.go keeps the grammar as a regular
// expression, spelling the prefix, the floor and the alphabet again so that the
// two are changed together, and the fuzz target beside it holds this scan to
// that expression.
var stripeWebhookSigningSecret = NewPattern("stripe-webhook-signing-secret", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := stripeWebhookSigningSecretTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], stripeWebhookSigningSecretAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a secret or not, for
		// the reason the rationale above gives: a body may close with the five
		// letters the prefix opens with, so a secret can begin five characters before
		// the end of the one before it.
		offset = anchor + 1

		if anchor < stripeWebhookSigningSecretAnchorIndex {
			continue
		}
		start := anchor - stripeWebhookSigningSecretAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the few
		// that open a candidate are turned away by one byte where a comparison of
		// the whole prefix is a length and a read.
		if src[start] != stripeWebhookSigningSecretPrefix[0] || !strings.HasPrefix(src[start:], stripeWebhookSigningSecretPrefix) {
			continue
		}

		body := start + len(stripeWebhookSigningSecretPrefix)
		end := base62RunEnd(src, body)
		if end == len(src) {
			// The run reaches the end of the input, so neither where the body
			// ends nor whether it is long enough to be one is settled here:
			// what comes next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if end-body >= stripeWebhookSigningSecretBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// stripeWebhookSigningSecretPrefix is what every secret of this kind opens
	// with, and what the scan reads back from its anchor. Its first five
	// characters belong to the alphabet a body is written in, which is what lets
	// one secret begin inside another and is why the scan resumes a byte along;
	// the underscore closing it does not, which is what keeps two candidates from
	// ever reading the same run. Test_stripeWebhookSigningSecretPrefix holds it
	// to the first and Test_stripeWebhookSigningSecretPrefix_runsDoNotOverlap to
	// the second.
	stripeWebhookSigningSecretPrefix = "whsec_"

	// stripeWebhookSigningSecretAnchor is the byte the scan searches the input
	// for and stripeWebhookSigningSecretAnchorIndex is where it stands in the
	// prefix, so a candidate begins that many bytes in front of what a search
	// reported. builtin_scan.go says why a scan searches for one byte of its
	// prefix rather than for the prefix itself; what makes it this byte is that
	// the five letters in front of it are ordinary ones — over the log line these
	// benchmarks are written on the e stands eight times, the h three and the s
	// twice, where the underscore stands not once. It is the same character the
	// run guarantee rests on, so a candidate found by it is a candidate whose
	// body is the run beginning one byte along.
	stripeWebhookSigningSecretAnchor      = '_'
	stripeWebhookSigningSecretAnchorIndex = 5

	// stripeWebhookSigningSecretBodyChars is the count a body is held to, read
	// as a floor rather than exactly. Thirty-two is the length of both secrets
	// Stripe has printed; the placeholder it writes into its own example is
	// twice that, which is what the rationale above reads the count as a floor
	// for.
	//
	// It is spelled here rather than read from the floor the Stripe API key
	// scans share. That floor is a count of theirs — the shortest body Stripe
	// has printed for a key — and this one is a count of this format's, so the
	// two numbers happening to move together would be a coincidence rather than
	// a rule, and either could be corrected without the other.
	stripeWebhookSigningSecretBodyChars = 32
)

// stripeWebhookSigningSecretTail is what the scan settles the tail of its input
// by. prefixTail (builtin_scan.go) says what that is and why it is built once.
var stripeWebhookSigningSecretTail = newPrefixTail(stripeWebhookSigningSecretPrefix)
