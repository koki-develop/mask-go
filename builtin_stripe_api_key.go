package mask

import "strings"

// StripeAPIKey locates Stripe API keys: the publishable keys a page is
// initialized with (pk_live_, pk_test_), the restricted keys Stripe now asks a
// server to use (rk_live_, rk_test_), the unrestricted secret keys (sk_live_,
// sk_test_) and the organization keys reaching every account under an
// organization (sk_org_).
//
// A key is located wherever it is written, so long as no letter or digit stands
// in front of it, and is redacted from its prefix to the end of the run it
// stands in. So a key written after an underscore, a quote, an equals sign or a
// space keeps its span, and a letter or a digit written straight after a key is
// redacted with it.
//
// Its name is "stripe-api-key".
func StripeAPIKey() Pattern { return stripeAPIKey }

// What Stripe states and what Stripe shows are worth separating here, as they
// were for Slack, GitLab, Google, OpenAI and Anthropic, because on this format
// Stripe states half of it and no more.
//
// What Stripe states is the prefixes, in one table of them on the API keys
// page: pk_ for a publishable key, rk_ for a restricted key and sk_ for a
// secret key, each written with the mode behind it — pk_test_, rk_test_ and
// sk_test_ for a sandbox, pk_live_, rk_live_ and sk_live_ once real payments
// are being taken. The organization keys have a page of their own, which states
// that they are all secret, that all of them carry the prefix sk_org, and that
// there is no rk_org. No page gives a length, an alphabet or a checksum for any
// of them.
//
// What Stripe shows is the sample key it prints in the authentication page's
// own curl command, sk_test_09l3shTSTKHYCzzZZsiLl2vA: twenty-four characters of
// letters and digits behind the prefix. The keys Stripe issues today are
// longer, at ninety-nine, and no Stripe page retires the shorter shape —
// GitLab's ruleset below still carries a rule apiece for it — so both are
// read.
//
// The three rulesets that state a whole shape agree on the alphabet and on
// nothing else. GitLab's own secret detection rules read six of the prefixes
// with exactly ninety-nine letters and digits behind them and two of them with
// exactly twenty-four; gitleaks reads sk_ and rk_ with test, live or prod
// behind them and ten to ninety-nine characters; trufflehog reads sk_, rk_ and
// pk_ in live mode alone with twenty to two hundred and forty-seven. So the
// count is read at two exact values, at a floor of ten and at a floor of
// twenty, by three readings of the same keys.
//
// The mode is what stands between the key type and the body, and this scan
// reads the names Stripe writes rather than reading that there is a name at
// all. That is the opposite of what the OpenAI and Anthropic scans beside it
// decided about their own middle segment, and the reason is what the anchor
// would be left as. There the prefix is sk- or sk-ant-, and what tells a key
// from the text around it is a marker inside the run or ninety-five characters
// of one; here the prefix is two letters and an underscore, and pk_ is what a
// database column is named. A scan reading sk_, pk_ or rk_ and then any
// lowercase word would locate pk_index_0123456789abcdef01234567 and
// task_queue_0123456789abcdef01234567, which are values a reader reads. Pinning
// the mode is what makes the anchor eight characters instead of three, and
// eight is the whole of what this pattern stands on.
//
// What pinning it wagers is a mode Stripe has not written yet, which would then
// be left in the output whole. Three things bound that wager. The first is that
// live and test are not a version but the two halves of Stripe's own model of
// the world, unchanged since the API was published and named in every
// integration built on it. The second is that the wager is already being paid
// once, and is paid in the direction of reading more rather than less:
// gitleaks reads prod beside the two, which Stripe documents nowhere, and it is
// not read here for that reason — a name no vendor page carries is a name this
// file cannot say anything true about. The third is sk_org_, which is the mode
// segment moving, and is read.
//
// The organization key is read in both the shapes it can have. Stripe states
// the prefix sk_org and states that the keys support sandboxes and live mode,
// and does not state where that mode is written; it is either a third segment,
// sk_org_live_ and sk_org_test_, or nowhere in the string. Both are in the
// table, longest first, so whichever Stripe issues is located from the prefix
// to the end of the run. Reading only sk_org_ would, on the three segment
// shape, find a body of four characters where it asks for twenty-four and
// locate nothing at all — and an organization key is the widest credential
// Stripe hands out, so that is the one place a guess costs the most. The two
// readings cannot be confused with one another, because a body is written in an
// alphabet holding no underscore: sk_org_live_ is never sk_org_ and a body
// opening with live.
//
// The alphabet is the letters of both cases and the ten digits, which is what
// all three rulesets admit behind the prefix and what every key anyone has
// published is written in. Neither the hyphen nor the underscore is in it, and
// leaving the underscore out is doing more work here than an alphabet usually
// does: it is what ends a body at the next segment of a snake_case name, so
// that pk_live_id_0123456789abcdef01234567 is a body of two characters rather
// than a key, and it is what makes every body begin at the start of a run,
// which the account of the scan's cost below rests on.
//
// The count is read as a floor and not as a count, which is where this scan
// parts company with the AWS, GitLab and Google ones beside it and stands with
// the OpenAI and Anthropic ones. Those read an exact count because the count is
// most of what tells a value from the text around it. Here the eight characters
// of the prefix have already done that, so a count would buy no discrimination
// it does not have — and a count that is wrong is a key located nowhere. This
// format has already been issued at two lengths, twenty-four and ninety-nine,
// and one of the rulesets above admits two hundred and forty-seven, so a scan
// asking for either published count exactly would leave live credentials of the
// other in the output whole. Read as a floor, a key of any length at or above
// it is located to the end of its run.
//
// The floor is twenty-four, which is the shortest body Stripe itself has
// printed. What it holds back is the placeholder: sk_live_ and pk_test_ are
// written into documentation, templates and test fixtures with a word behind
// them far more often than with a key, and pk_test_yourkeyhere is a body of
// twelve characters that nobody has to redact. Below twenty-four there is
// nothing but such text to gain, since no key anyone has published is shorter
// than that. What the floor costs is the key shorter than it — a line cut to a
// column limit partway through one leaves a prefix and a body too short to be a
// body, and the random characters written before the cut stay in the output.
// That is the far side of this choice, and the cases in
// builtin_stripe_api_key_test.go pin it so that it stays a decision on the
// record.
//
// The byte in front of the prefix may not be a letter or a digit, which of the
// scans beside this one only Slack asks for. The reason is Slack's reason
// exactly: a prefix that can close a word needs something holding it back, and
// two of these three can. task_ and desk_ end in sk_, network_ and benchmark_
// end in rk_, so task_test_, desk_live_, network_live_ and benchmark_test_ each
// carry a whole prefix of this pattern inside an ordinary snake_case name, and
// what follows such a name is a segment of letters and digits — a run id, a
// timestamp and a digest joined, a fixture name — which reaches twenty-four
// characters often enough to matter. gitleaks holds its own Stripe rule to
// exactly this: the false positive it is validated against is task_test_ and
// thirty alphanumerics. Those are values a reader reads, and a tightening was
// available, so a grammar admitting them is one this pattern has no business
// having.
//
// It is not the word boundary a regular expression would write, and the
// difference is the underscore. STRIPE_SECRET_KEY_sk_live_... is how a key
// reaches a log line from a shell, and a \b in front would drop that key rather
// than trim it; so this admits the underscore, and with it the quote, the
// colon, the equals sign, the slash and the space a key is otherwise written
// after. What is left out is the letter and the digit alone, and what that
// costs is a key glued straight onto a word with nothing between them. Where
// such a word is itself inside the body of an earlier key the key is still
// redacted, because a body is read to the end of its run and covers what is
// written inside it; where it is not, a credential written that way is left
// whole, and nothing has been seen written that way.
//
// There is no boundary behind the match, as there is none in any of the scans
// beside this one. One there would drop rather than trim a key whose body runs
// on into the text after it, and since the span already reaches the end of the
// run, that is every key with a letter or a digit written against it.
//
// No key can be written inside another, which of the built-ins beside this
// one the RubyGems, Supabase and OpenRouter patterns can say as well. The
// rest resume a byte past a match because a value can begin inside the span
// of the one in front of it; here none can, and in those three for a reason
// of their own — the letter each prefix opens with stands in a value exactly
// once, at its first character. A key begins only where no letter and no
// digit stands in front of it, and everything a span covers is one or the
// other except the underscores of the prefix — and none of the positions
// those underscores open opens a prefix of its own, since what stands at each
// of them is the rest of a mode or of the organization scope. The body cannot
// open one either: a prefix wants an underscore at its third character, and
// the third character of a body is a letter or a digit like the rest of it.
// So the spans of this pattern never overlap one another.
// Test_StripeAPIKey_noKeyBeginsInsideAnother drives every shape that would
// find that wrong.
//
// The scan resumes one byte past the anchor all the same, and has to: a
// candidate that did not become a key says nothing about the next one, and
// resuming at the start of the candidate would find the same anchor again and
// never advance. One byte past it steps over nothing, since two candidates
// cannot begin one byte apart — the second would want its key type's second
// letter where the first carries the underscore behind its own.
//
// What the spans never overlapping costs is the second of two keys written with
// nothing at all between them. The first is redacted to the end of its run,
// which reaches two characters into the prefix of the second, and the rest of
// that prefix and its whole body are left in the text. Nothing has been seen
// written that way — a list of keys carries a comma, a newline, a quote or an
// underscore between them, and every one of those is a byte a key may be
// written after. It is the same shape the byte in front costs in the other
// direction, and the same shape the Slack scan gives up for the same demand.
//
// The scan keeps no cursor and needs none, which is neither the AWS and Google
// answer nor the JWT, GitHub, GitLab, Slack, OpenAI and Anthropic one. Those
// six keep a run cursor because a prefix written in the run's own alphabet lets
// a run hold a candidate for every few characters it has, and each of them
// would otherwise read that run to its end. No run here can hold two bodies.
// Every prefix closes with an underscore and no body is written with one, so a
// body always begins where a run of body characters begins — and two candidates
// cannot begin one run between them, because the second would need an
// underscore at the character before its body, which is a character inside the
// first body's run and so a letter or a digit. Each run of the input is
// therefore walked by at most one candidate, and the walks add up to a single
// pass. Test_StripeAPIKey_scanIsLinear drives the inputs that would find this
// wrong. The npm scan beside this one reaches the same answer by the same
// argument, its own prefix closing with an underscore no body of its own may
// hold.
//
// The publishable keys are located along with the rest, and Stripe's own page
// says they are safe to expose: a publishable key is embedded in the page it
// initializes, so a reader who has one has taken nothing. They are read here
// because a caller reaching for this pattern is redacting what a log line, a
// crash report or a support ticket carries, and a publishable key is written in
// that text exactly as the other three kinds are, with nothing in the string to
// tell them apart before the mode has been read. Leaving them out would mean
// reading pk_ far enough to decline it, which is the same work, and would mean
// a caller who does want the key in a shared configuration dump redacted has
// nothing to reach for.
//
// What this pattern over-matches on: a prefix standing at the front of a word
// with twenty-four letters and digits behind it. The prefix is eight characters
// carrying two underscores, which narrows this a long way — a base64 payload, a
// certificate or an embedded image writes no underscore at all and holds no
// prefix to be found at however long it runs, and base64url writes one, so a
// prefix stands inside such an encoding about once in three hundred million
// million characters. What is left is text somebody wrote: a snake_case name
// whose first segment is sk, pk or rk, whose second is live, test or org, and
// whose third is twenty-four unbroken letters and digits. A name written
// rk_live_ with a digest behind it is redacted whole. That text is a key's
// format exactly, so there is nothing left to read the two apart by, and the
// tightening on offer is the count — which the paragraphs above weigh and which
// costs a whole credential when it is wrong. The cases in
// builtin_stripe_api_key_test.go pin the over-match so that it stays a decision
// on the record.
//
// What reaches a span is never prose, a git SHA or an MD5. A digest carries no
// underscore, so it holds no prefix to be found at however long it runs, and no
// word of prose is spelled sk_live_. A snake_case identifier can carry a whole
// prefix, as task_test_ does, and what turns that away is the letter in front
// of it.
//
// referenceStripeAPIKeyFind in builtin_stripe_api_key_test.go states the same
// grammar the plain way, spelling the prefixes, the floor and the two character
// classes again so that the two are changed together, and the fuzz target
// beside it holds this scan to that statement.
var stripeAPIKey = NewPattern("stripe-api-key", func(src string) []Span {
	var spans []Span

	for offset := 0; offset < len(src); {
		i := strings.Index(src[offset:], stripeAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes one byte past the anchor whether this candidate
		// became a key or not. It steps over nothing: two candidates cannot
		// begin one byte apart, since the second would want its key type's
		// second letter where this one carries the underscore behind its own.
		// Resuming at the start of the candidate instead would find the same
		// anchor again and never advance.
		offset = anchor + 1

		if anchor < stripeAPIKeyAnchorIndex {
			continue
		}
		start := anchor - stripeAPIKeyAnchorIndex

		// The byte in front comes before the prefix table because it is one
		// comparison where that is up to nine, and every snake_case name whose
		// segment ends in k reaches this line.
		if start > 0 && isStripeAPIKeyWordByte(src[start-1]) {
			continue
		}
		prefix := stripeAPIKeyPrefixAt(src, start)
		if prefix == 0 {
			continue
		}

		body := start + prefix
		end := stripeAPIKeyBodyEnd(src, body)
		if end-body < stripeAPIKeyBodyChars {
			continue
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return spans
})

// stripeAPIKeyPrefixes are the prefixes this pattern reads: the key type Stripe
// documents, the mode behind it, and the organization scope between the two
// where a key carries one.
//
// They are ordered longest first, and here that is a rule rather than the
// courtesy it is in the Slack and GitLab tables. sk_org_ is a prefix of
// sk_org_live_ and of sk_org_test_, so the two of them match wherever it does,
// and the scan takes the first entry that matches: read the other way round, an
// organization key written in the three segment shape would be given a body of
// four characters and located nowhere. Test_stripeAPIKeyPrefixes holds the
// order, and holds every entry to carrying the anchor at the index the scan
// finds a candidate by, to closing with a character no body is written with,
// and to opening with characters a word is made of — which is what lets a
// snake_case name close on a key type, and so what the byte in front of a
// prefix is read for.
var stripeAPIKeyPrefixes = [...]string{
	// Organization keys, if the mode is written as a segment of its own.
	"sk_org_live_",
	"sk_org_test_",
	"sk_live_", // secret keys
	"sk_test_",
	"rk_live_", // restricted keys
	"rk_test_",
	"pk_live_", // publishable keys
	"pk_test_",
	// And the same, if the mode is written nowhere in the string.
	"sk_org_",
}

const (
	// stripeAPIKeyAnchor is what every prefix carries at stripeAPIKeyAnchorIndex
	// and what the scan searches the input for: the letter closing the two
	// character key type, and the underscore behind it. The three key types
	// differ in their first letter and agree in these two, so this is what one
	// search finds all of them by, where a search for the first letter would be
	// three searches or a walk over every s, r and p in the text.
	stripeAPIKeyAnchor      = "k_"
	stripeAPIKeyAnchorIndex = 1

	// stripeAPIKeyBodyChars is the count a body is held to, read as a floor
	// rather than exactly. Twenty-four is the shortest body Stripe has printed
	// in its own documentation; the keys it issues today are far longer, and one
	// ruleset reads them longer still. The rationale above weighs both what a
	// shorter floor would draw in and what a key shorter than this costs.
	stripeAPIKeyBodyChars = 24
)

// stripeAPIKeyPrefixAt returns the length of the prefix beginning at i in src,
// or zero where none does.
func stripeAPIKeyPrefixAt(src string, i int) int {
	for _, prefix := range stripeAPIKeyPrefixes {
		if strings.HasPrefix(src[i:], prefix) {
			return len(prefix)
		}
	}
	return 0
}

// stripeAPIKeyBodyEnd returns where the run of body characters beginning at i
// in src ends, which is len(src) where the run reaches the end of the input.
//
// How long the run then is, is the caller's to measure against the floor. The
// walk is not shared with the base64url one in builtin_scan.go because the
// alphabet is not that one: a body carries neither the hyphen nor the
// underscore, and it is the underscore's absence that ends a body at the next
// segment of a snake_case name.
func stripeAPIKeyBodyEnd(src string, i int) int {
	for i < len(src) && isStripeAPIKeyBodyByte(src[i]) {
		i++
	}
	return i
}

// isStripeAPIKeyBodyByte reports whether c belongs to the alphabet a body is
// written in: the letters of both cases and the ten digits, which is what every
// ruleset admits behind a prefix and what every published key carries.
func isStripeAPIKeyBodyByte(c byte) bool {
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
}

// isStripeAPIKeyWordByte reports whether c is a letter or a digit, which is
// what may not stand in front of a prefix. The underscore is not one of them,
// and is admitted for the reason the rationale above gives.
//
// It holds the same characters as isStripeAPIKeyBodyByte and is written apart
// from it because the two answer different questions: one is the alphabet
// Stripe writes a key in, the other is what a word is made of here. Sharing the
// one function would mean that widening the alphabet — the day a key carries a
// hyphen — silently widened what may close a word in front of a prefix, which
// is a change nothing would report.
func isStripeAPIKeyWordByte(c byte) bool {
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
}
