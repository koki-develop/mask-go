package mask

import (
	"slices"
	"strings"
)

// StripeSecretKey locates the Stripe API keys that must not be exposed: the
// restricted keys Stripe now asks a server to use (rk_live_, rk_test_), the
// unrestricted secret keys (sk_live_, sk_test_) and the organization keys
// reaching every account under an organization (sk_org_).
//
// A key is located wherever it is written, so long as no letter or digit stands
// in front of it, and is redacted from its prefix to the end of the run it
// stands in. So a key written after an underscore, a quote, an equals sign or a
// space keeps its span, and a letter or a digit written straight after a key is
// redacted with it.
//
// Its name is "stripe-secret-key".
func StripeSecretKey() Pattern { return stripeSecretKey }

// Secret is Stripe's word for the three of these together, and it is worth
// saying where it comes from, because Stripe's own table of key types uses it
// for one of them. There the four rows are the publishable API key (pk_), the
// restricted API key (rk_), the secret API key (sk_) and the organization API
// key (sk_org_), and only the third is named secret. What the table divides
// them on is a column of its own — safe to expose — and that column reads yes
// for the publishable key and no for the other three.
//
// Those three are what this pattern locates, and Stripe names the set in three
// places. Its guide to protecting keys is titled for managing secret API keys
// and covers the restricted ones throughout, down to telling a reader to audit
// their source for sk_live_ and rk_live_ in one breath. Its page on
// organization keys says that all organization API keys are secrets. And the
// page the table stands on says that only publishable keys are safe to expose
// outside a backend, and that the reader is responsible for protecting the
// other Stripe API keys, including restricted API keys. So secret is the word
// Stripe reaches for whenever it means these three and not the fourth, and it
// is the word this pattern is named for. StripePublishableKey
// (builtin_stripe_publishable_key.go) is the fourth.
//
// The organization key cannot be sorted into the other two and is not tried:
// Stripe says an organization key is the same as an account level restricted or
// secret key but at the organization level, and that all of them carry the
// sk_org prefix whatever permissions they have. So the string does not say
// which of the two an organization key is, and a boundary drawn between
// restricted and secret would have nowhere to put it. Nothing is lost by that,
// because no caller redacts one of these three and keeps another: they are the
// keys a leak costs something, and Stripe's own guidance rotates any of them on
// exposure without distinguishing them.
//
// What Stripe states and what Stripe shows are worth separating here, as they
// are wherever a vendor names a prefix and leaves the rest to be read off the
// values it issued, because on this format Stripe states half of it and no
// more.
//
// What Stripe states is the prefixes, in that table: rk_ for a restricted key
// and sk_ for a secret key, each written with the mode behind it — rk_test_ and
// sk_test_ for a sandbox, rk_live_ and sk_live_ once real payments are being
// taken. The organization keys have a page of their own, which states that they
// are all secret, that all of them carry the prefix sk_org, and that there is
// no rk_org. No page gives a length, an alphabet or a checksum for any of them.
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
// of one; here the prefix is two letters and an underscore, and a scan reading
// sk_ or rk_ and then any lowercase word would locate task_queue_0123456789 and
// the rest of the snake_case names a reader reads. Pinning the mode is what
// makes the anchor eight characters instead of three, and eight is the whole of
// what this pattern stands on.
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
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the ten digits, which is what all three rulesets admit behind the
// prefix and what every key anyone has published is written in. Neither the
// hyphen nor the underscore is in it, and leaving the underscore out is doing
// more work here than an alphabet usually does: it is what ends a body at the
// next segment of a snake_case name, so that
// sk_live_id_0123456789abcdef01234567 is a body of two characters rather than a
// key, and it is what makes every body begin at the start of a run, which the
// account of the scan's cost below rests on.
//
// The count is read as a floor and not as a count. A count is read exactly
// where it is most of what tells a value from the text around it. Here the
// eight characters of the prefix have already done that, so a count would buy
// no discrimination it does not have — and a count that is wrong is a key
// located nowhere. This format has already been issued at two lengths,
// twenty-four and ninety-nine, and one of the rulesets above admits two
// hundred and forty-seven, so a scan asking for either published count exactly
// would leave live credentials of the other in the output whole. Read as a
// floor, a key of any length at or above it is located to the end of its run.
//
// The floor is twenty-four, which is the shortest body Stripe itself has
// printed. What it holds back is the placeholder: sk_live_ and rk_test_ are
// written into documentation, templates and test fixtures with a word behind
// them far more often than with a key, and sk_test_yourkey is a body of seven
// characters that nobody has to redact. Below twenty-four there is
// nothing but such text to gain, since no key anyone has published is shorter
// than that. What the floor costs is the key shorter than it — a line cut to a
// column limit partway through one leaves a prefix and a body too short to be a
// body, and the random characters written before the cut stay in the output.
// That is the far side of this choice, and the cases in
// builtin_stripe_secret_key_test.go pin it so that it stays a decision on the
// record.
//
// The byte in front of the prefix may not be a letter or a digit, which the
// Slack scan asks for too. The reason is Slack's reason exactly: a prefix that
// can close a word needs something holding it back, and both of these can.
// task_ and desk_ end in sk_, network_ and benchmark_ end in rk_, so
// task_test_, desk_live_, network_live_ and benchmark_test_ each carry a whole
// prefix of this pattern inside an ordinary snake_case name, and what follows
// such a name is a segment of letters and digits — a run id, a timestamp and a
// digest joined, a fixture name — which reaches twenty-four characters often
// enough to matter. gitleaks holds its own Stripe rule to exactly this: the
// false positive it is validated against is task_test_ and thirty
// alphanumerics. Those are values a reader reads, and a tightening was
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
// There is no boundary behind the match. One there would drop rather than
// trim, and where it were asked decides what it drops. Asked behind the count,
// it drops the key a letter, a digit or an underscore is written against.
// Asked behind that run, it drops the key an underscore is written against and
// nothing else, the underscore being the one word character no body admits.
// Test_StripeSecretKey_reachesTheEndOfTheRun writes both keys out.
//
// A key can begin inside the span of the one in front of it, and in a run
// written with nothing between two keys every key after the first does: a body
// is read to the end of its run, so the span in front carries the two
// characters of the next prefix that stand before its underscore. That holds of
// a publishable key written into such a run as well, since the two patterns
// read one body between them. What it costs and what holds it is set out below,
// where the byte in front of a candidate is read.
//
// The scan resumes one byte past the anchor all the same, and has to: a
// candidate that did not become a key says nothing about the next one, and
// resuming at the start of the candidate would find the same anchor again and
// never advance. One byte past it steps over nothing, since two candidates
// cannot begin one byte apart — the second would want its key type's second
// letter where the first carries the underscore behind its own.
//
// A key written against a key is a key, which is what the byte in front is read
// with isStripeKeyBodyRunBefore beside it for. The rule turns away a candidate
// written inside a word, and a body is written in the characters a word is made
// of, so without that every key after the first of a run written with nothing
// between them would be turned away by the body in front of it: the first is
// redacted to the end of its run, which reaches two characters into the
// second's prefix and stops at the underscore behind it, and from the third on
// nothing would reach them at all. What a redaction library may not do is leave
// a key whole, and three written together is all it took.
//
// What tells the two apart is read in front of the candidate and not carried
// along the scan. A cursor remembering where the last key ended would answer
// this at a position from text a window may not hold — the keys Stripe issues
// today are ninety-nine characters behind the prefix, where LookBehind is
// sixty-four — so a stream would release a key the same pattern locates when
// handed the text entire. Test_stripeKeys_locateAMixedRunThroughAWindow is what
// holds the two readings together.
//
// What it costs is that the spans of a run overlap one another, by the two
// characters the run in front reaches into the prefix behind it. A Masker
// merges what overlaps, so a run comes out as one redaction, which is what the
// Stripe webhook signing secret scan beside this one has always done.
// Test_StripeSecretKey_locatesEveryKeyOfARun and
// Test_stripeKeys_locateEveryKeyOfAMixedRun hold every pair of prefixes of both
// halves to leaving no key of a run in the text.
//
// The scan keeps no cursor and needs none, and gets that from the format
// rather than from a bounded count. A scan keeps a run cursor where a prefix
// written in the run's own alphabet lets a run hold a candidate for every few
// characters it has, since each of those candidates would otherwise read that
// run to its end. No run here can hold two bodies. Every prefix closes with an
// underscore and no body is written with one, so a body always begins where a
// run of body characters begins — and two candidates cannot begin one run
// between them, because the second would need an underscore at the character
// before its body, which is a character inside the first body's run and so a
// letter or a digit. Each run of the input is therefore walked by at most one
// candidate, and the walks add up to a single pass.
// Test_StripeSecretKey_scanIsLinear drives the inputs that would find this
// wrong. The npm scan beside this one reaches the same answer by the same
// argument, its own prefix closing with an underscore no body of its own may
// hold.
//
// What this pattern over-matches on: a prefix standing at the front of a word
// with twenty-four letters and digits behind it. The prefix is eight characters
// carrying two underscores, which narrows this a long way — a base64 payload, a
// certificate or an embedded image writes no underscore at all and holds no
// prefix to be found at however long it runs, and base64url writes one, so a
// prefix stands inside such an encoding about once in three hundred million
// million characters. What is left is text somebody wrote: a snake_case name
// whose first segment is sk or rk, whose second is live, test or org, and whose
// third is twenty-four unbroken letters and digits. A name written rk_live_
// with a digest behind it is redacted whole. That text is a key's format
// exactly, so there is nothing left to read the two apart by, and the
// tightening on offer is the count — which the paragraphs above weigh and which
// costs a whole credential when it is wrong. The cases in
// builtin_stripe_secret_key_test.go pin the over-match so that it stays a
// decision on the record.
//
// What reaches a span is never prose, a git SHA or an MD5. A digest carries no
// underscore, so it holds no prefix to be found at however long it runs, and no
// word of prose is spelled sk_live_.
//
// A snake_case identifier can carry a whole prefix, as task_test_ does, and the
// letter in front of it is what turns that away — until stripeKeyRunBeforeChars
// letters and digits stand there unbroken, which is the exemption a run of keys
// is located by and which the byte in front cannot tell from one. So
// task_test_ behind a word of twenty-two characters is redacted where
// task_test_ behind one letter is not. That is the widening the exemption was
// bought with, and it is the same trade the count above is: the alternative is
// a run of keys losing every key after the first, and what a redaction library
// may not do is leave a key whole.
//
// referenceStripeSecretKeyFind in builtin_stripe_secret_key_test.go states the
// same grammar the plain way, spelling the prefixes, the floor and the two
// character classes again so that the two are changed together, and the fuzz
// target beside it holds this scan to that statement.
var stripeSecretKey = NewPattern("stripe-secret-key", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := stripeSecretKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], stripeSecretKeyAnchorByte)
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

		if anchor < stripeSecretKeyAnchorIndex {
			continue
		}
		start := anchor - stripeSecretKeyAnchorIndex

		// The byte in front comes before the prefix table, and every
		// snake_case name whose segment ends in k reaches this line.
		//
		// What it asks is whether this candidate is written inside a word, and
		// a body written against it is no word. isStripeKeyBodyRunBefore is
		// what tells the two apart.
		//
		// What it costs is one comparison, and on a candidate written against
		// a word a walk of up to stripeKeyRunBeforeChars bytes behind it. The
		// walk stops at the byte nearest the candidate rather than at the far
		// end of that window, which is what keeps the shapes it is reached by —
		// a word closing on a key type, a key written against a key — reading a
		// byte or two rather than the whole of it. What a line holding no key
		// pays is the call standing in the loop, which is a few nanoseconds
		// whether or not the walk is ever entered.
		if start > 0 && isStripeKeyWordByte(src[start-1]) && !isStripeKeyBodyRunBefore(src, start) {
			continue
		}
		prefix := stripeSecretKeyPrefixAt(src, start)
		if prefix == 0 {
			continue
		}

		body := start + prefix
		end := base62RunEnd(src, body)
		if end == len(src) {
			// The run reaches the end of the input, so neither where the body
			// ends nor whether it is long enough to be one is settled here:
			// what comes next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if end-body < stripeSecretKeyBodyChars {
			continue
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return spans, retain
})

// stripeSecretKeyPrefixes are the prefixes this pattern reads: the key type
// Stripe documents, the mode behind it, and the organization scope between the
// two where a key carries one.
//
// They are ordered longest first, and here that is a rule rather than the
// courtesy it is in the Slack and GitLab tables. sk_org_ is a prefix of
// sk_org_live_ and of sk_org_test_, so the two of them match wherever it does,
// and the scan takes the first entry that matches: read the other way round, an
// organization key written in the three segment shape would be given a body of
// four characters and located nowhere. Test_stripeSecretKeyPrefixes holds the
// order, and holds every entry to carrying the anchor at the index the scan
// finds a candidate by, to closing with a character no body is written with,
// and to opening with characters a word is made of — which is what lets a
// snake_case name close on a key type, and so what the byte in front of a
// prefix is read for.
var stripeSecretKeyPrefixes = [...]string{
	// Organization keys, if the mode is written as a segment of its own.
	"sk_org_live_",
	"sk_org_test_",
	"sk_live_", // secret keys
	"sk_test_",
	"rk_live_", // restricted keys
	"rk_test_",
	// And the organization key, if the mode is written nowhere in the string.
	"sk_org_",
}

const (
	// stripeSecretKeyAnchor is what every prefix carries at
	// stripeSecretKeyAnchorIndex, and where a candidate is read back from: the
	// letter closing the two character key type, and the underscore behind it.
	// The two key types differ in their first letter and agree in these two, so
	// this is what one search finds both of them by, where a search for the
	// first letter would be two searches or a walk over every s and r in the
	// text.
	stripeSecretKeyAnchor      = "k_"
	stripeSecretKeyAnchorIndex = 1

	// stripeSecretKeyAnchorByte is the byte the scan searches the input for,
	// the one the anchor opens with. A search for the whole anchor would skip
	// along this same byte, so what separates the two is the walk and not
	// where a candidate is found: builtin_scan.go says why the walk is the
	// cheaper of them. The underscore behind it is left to the prefix table
	// below rather than tested by the search.
	//
	// This pattern is the one the choice of byte costs nothing to make. A k
	// closing a snake_case segment is what reaches the loop either way, and
	// over the log line these benchmarks are written on it stands not once.
	stripeSecretKeyAnchorByte = 'k'

	// stripeSecretKeyBodyChars is the count a body is held to, read as a floor
	// rather than exactly. Twenty-four is the shortest body Stripe has printed
	// in its own documentation; the keys it issues today are far longer, and one
	// ruleset reads them longer still. The rationale above weighs both what a
	// shorter floor would draw in and what a key shorter than this costs.
	//
	// The publishable key scan reads this rather than spelling a floor of its
	// own, as it reads isStripeKeyWordByte below, so moving this number moves
	// both halves of Stripe's format together.
	stripeSecretKeyBodyChars = 24
)

// stripeSecretKeyPrefixAt returns the length of the prefix beginning at i in
// src, or zero where none does.
func stripeSecretKeyPrefixAt(src string, i int) int {
	for _, prefix := range stripeSecretKeyPrefixes {
		if strings.HasPrefix(src[i:], prefix) {
			return len(prefix)
		}
	}
	return 0
}

// isStripeKeyWordByte reports whether c is a letter or a digit, which is what
// may not stand in front of a Stripe key's prefix. The underscore is not one of
// them, and is admitted for the reason the rationale above gives.
//
// It is read by the publishable key scan as well, which says so in its own
// file. The two halves of Stripe's key format are one question here — what a
// word is made of in front of a Stripe prefix — and a second copy of the answer
// is one that could come to disagree with this one about a format neither half
// can change alone.
//
// It holds the same characters as isBase62Byte, which is the alphabet a body is
// written in, and is written apart from it because the two answer different
// questions: one is what Stripe writes a key in, the other is what a word is
// made of here. Reading the alphabet for both would mean that widening it — the
// day a key carries a hyphen — silently widened what may close a word in front
// of a prefix, which is a change nothing would report.
func isStripeKeyWordByte(c byte) bool {
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
}

// isStripeKeyBodyRunBefore reports whether the characters a body is written to
// stand in front of i, unbroken and as many of them as the shortest body has.
//
// It is what the byte in front is read with, and what makes a key written
// against a key a key. The rule on that byte turns away a candidate written
// inside a word, and a body is written in the characters a word is made of, so
// without this a run of keys written with nothing between them would lose every
// key after the first: the first is redacted to the end of its run, which
// reaches two characters into the second's prefix and stops at the underscore
// behind it, and from the third on nothing would reach them at all.
//
// What it reads apart is a body from a segment of a name, and the underscore is
// the whole of how. Every prefix of this format closes with one and no body is
// written with one, so a name reaches a key type through an underscore and
// leaves a run of nothing like this length in front of it, where a body leaves
// exactly this. task_test_, topk_live_ and benchmark_rk_ are all turned away
// here as they were before, their runs being broken by the underscore a segment
// ends on.
//
// It reads back stripeKeyRunBeforeChars bytes and no more, which is what keeps
// it inside LookBehind: an answer resting on a whole key in front of it would
// be an answer a window could not reproduce, and a stream would release a key
// the pattern locates only when handed the text entire.
// The run is walked from the candidate backwards rather than from its far end
// forwards, which is the same answer read in the cheaper order. Every byte has
// to be a body byte, so the walk stops at the first that is not, and what turns
// this call away is almost always the text abutting the candidate: a word
// closing on a key type carries a separator or a space a byte or two behind it,
// where the far end of the window is whatever stood twenty-two characters ago
// and is as often a body as not. Walking the other way reads the whole window
// before reaching the byte that decides it.
func isStripeKeyBodyRunBefore(src string, i int) bool {
	if i < stripeKeyRunBeforeChars {
		return false
	}
	for j := i - 1; j >= i-stripeKeyRunBeforeChars; j-- {
		if !isBase62Byte(src[j]) {
			return false
		}
	}
	return true
}

// stripeKeyRunBeforeChars is how long that run has to be.
//
// A key leaves its body behind it, and a body is stripeSecretKeyBodyChars at
// the shortest. Less what the candidate took of it: a candidate may open inside
// the run of the key in front of it, since the characters its own prefix opens
// with before the underscore belong to the alphabet that run is read in, and
// those characters are then the run's rather than in front of it. Every prefix
// of this format opens with two of them, and both halves are read for the head
// because neither may come to ask for a different length than the other.
//
// The floor is read from one half and there is only one to read: the
// publishable keys' floor is that declaration rather than a number of its own,
// which builtin_stripe_publishable_key.go argues, so the two cannot part and a
// minimum over them would be a minimum of one value with itself. What gates
// both scans is this, and what keeps it right for both is that the floor
// underneath it is one declaration and not two.
//
// It is read from the tables rather than written down, so a prefix added with a
// longer head shortens this rather than being missed by it.
var stripeKeyRunBeforeChars = func() int {
	head := 0
	for _, prefix := range slices.Concat(stripeSecretKeyPrefixes[:], stripePublishableKeyPrefixes[:]) {
		head = max(head, strings.IndexByte(prefix, '_'))
	}
	return stripeSecretKeyBodyChars - head
}()

// stripeSecretKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var stripeSecretKeyTail = newPrefixTail(stripeSecretKeyPrefixes[:]...)
