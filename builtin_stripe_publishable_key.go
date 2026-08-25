package mask

import "strings"

// StripePublishableKey locates the Stripe publishable API keys a page is
// initialized with (pk_live_, pk_test_).
//
// A key is located wherever it is written, so long as no letter or digit stands
// in front of it, and is redacted from its prefix to the end of the run it
// stands in. So a key written after an underscore, a quote, an equals sign or a
// space keeps its span, and a letter or a digit written straight after a key is
// redacted with it.
//
// Stripe says a publishable key is safe to expose: it is embedded in the page
// it initializes, so a reader who has one has taken nothing. It is a pattern of
// its own for that reason rather than in spite of it — a caller masking a
// frontend bundle, a browser console log or a bug report has no reason to
// redact a value that belongs there and every reason to keep it, since it says
// which account and which mode the report came from, while a caller masking a
// configuration dump they are about to share may want it gone. Reaching for
// StripeSecretKey (builtin_stripe_secret_key.go) alone is how the first caller
// says so, and reaching for both, or for StripePatterns, is how the second
// does.
//
// Its name is "stripe-publishable-key".
func StripePublishableKey() Pattern { return stripePublishableKey }

// Publishable API key is Stripe's own name for this key, one row of the table
// of key types on its API keys page. That table carries a column reading safe
// to expose, and this is the one row where it reads yes; the restricted, secret
// and organization keys read no and are located by StripeSecretKey. The column
// is what the boundary between the two patterns is drawn on, so a caller
// deciding between them is deciding what Stripe already decided for them.
//
// The grammar is the secret keys' grammar exactly, and
// builtin_stripe_secret_key.go carries the account of it: what Stripe states
// about the format and what it merely shows, why the mode is pinned rather than
// read as any lowercase word, why the count is a floor of twenty-four rather
// than either published length, and what the alphabet leaving the underscore
// out is doing. None of that is repeated here, because none of it is this
// pattern's to decide — the two halves of one vendor format cannot disagree
// about the format, and a second copy of the reasoning is a second thing to
// keep true. What is written here is what this half decides on its own.
//
// The anchor is the key type and the underscore behind it rather than the two
// bytes the secret key scan reads back to. That scan reads two key types, sk_
// and rk_, which agree only in the letter closing them and the underscore
// behind it, so k_ is all one lookup can ask for. Here there is one key
// type, so the anchor can carry the p as well. Three bytes rather than two is a
// test that turns more text away before a candidate is opened at all, and an
// anchor standing at the start of a candidate rather than one byte into it is a
// position the scan can use as it is. It is the same grammar read by a more
// selective search, not a different grammar.
//
// The byte in front of the prefix may not be a letter or a digit, which is the
// demand the secret keys are held to and is read from the same declaration,
// isStripeKeyWordByte in builtin_stripe_secret_key.go. Fewer words close on
// this key type than on those: task_ and desk_ end in sk_, network_ and
// benchmark_ end in rk_, and the English words ending in pk are not ones a
// fixture is named for. What does end in pk is an identifier — topk_ is how the
// top-k operation is spelled in a name — so topk_live_ carries a whole prefix
// of this pattern and is turned away by the letter in front of it exactly as
// task_test_ is.
//
// It would be kept even where it bought nothing, because the two halves of one
// format may not disagree about where a key may begin: a caller reaching for
// both patterns would otherwise get a boundary rule that changed with the key
// type, on the same line, for no reason it could read. What it costs is only a
// key glued straight onto a word with nothing between them.
//
// Sharing the declaration rather than spelling the class again is what keeps
// that true. The rule is one question, asked of one vendor's prefixes, and
// neither half can widen it alone; two copies could come to answer it
// differently and nothing would report the disagreement.
//
// There is no boundary behind the match, as there is none in the scan beside
// this one, and for its reason: the span already reaches the end of the run, so
// a boundary there would drop rather than trim every key with a letter or a
// digit written against it.
//
// No key of this pattern can be written inside another. Every span begins at a
// p that no letter and no digit stands in front of, and everything the span
// covers past the prefix is a letter or a digit, so no position inside one
// opens a candidate that survives the byte in front. The two underscores of the
// prefix open nothing either: what stands at them is the rest of the prefix,
// never a p. Test_StripePublishableKey_noKeyBeginsInsideAnother drives the
// shapes that would find that wrong.
//
// No key of the other half can begin inside one of these either, and none of
// these inside one of those. The byte in front is the whole of the reason.
// Everything a span covers past its prefix is a letter or a digit, so a
// candidate opening there is turned away whichever prefix it carries; a body
// cannot hold pk_ or the anchor of the other scan at all, since an underscore
// ends the run a body is read as; and the positions the two underscores of a
// prefix open carry the rest of that prefix. So a key of either kind written
// straight against another is the case both patterns give up, and a caller
// running both gets no span reaching into another's.
// Test_stripeKeys_neitherKindBeginsInsideTheOther drives every pair of
// prefixes.
//
// The scan resumes one byte past the start of a candidate, which is the
// default and needs no argument beyond the one any scan has: a candidate that
// did not become a key says nothing about the next one. The anchor stands at
// the start of a candidate rather than one byte into it, so a key begins where
// the anchor does and there is no step over anything to justify — where the
// secret key scan, whose anchor stands inside the key type, has to argue for
// the same step.
//
// The scan keeps no cursor and needs none, for the reason the secret key scan
// gives: every prefix closes with an underscore and no body is written with
// one, so a body always begins where a run of body characters begins and no run
// can hold two bodies. Test_StripePublishableKey_scanIsLinear drives the inputs
// that would find this wrong.
//
// What this pattern over-matches on is a snake_case name whose first segment
// ends in pk, whose second is live or test, and whose third is twenty-four
// unbroken letters and digits. That is the format exactly, so there is nothing
// left to read the two apart by; the tightening on offer is the count, which
// costs a whole credential when it is wrong. The prefix is eight characters
// carrying two underscores, so no digest, certificate or base64 payload holds
// one at however long it runs. The cases in
// builtin_stripe_publishable_key_test.go pin the over-match so that it stays a
// decision on the record.
//
// referenceStripePublishableKeyFind in builtin_stripe_publishable_key_test.go
// states the same grammar the plain way, spelling the prefixes, the floor and
// the two character classes again so that the two are changed together, and the
// fuzz target beside it holds this scan to that statement.
var stripePublishableKey = NewPattern("stripe-publishable-key", func(src string) []Span {
	var spans []Span

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], stripePublishableKeyAnchorByte)
		if i < 0 {
			break
		}
		at := offset + i

		// The scan resumes one byte past the start of the candidate whether it
		// became a key or not, which is one byte past where the anchor byte
		// stood. The anchor opens a candidate rather than standing inside one,
		// so this steps over nothing.
		offset = at + 1

		if at < stripePublishableKeyAnchorIndex {
			continue
		}
		start := at - stripePublishableKeyAnchorIndex

		if start > 0 && isStripeKeyWordByte(src[start-1]) {
			continue
		}
		// The byte every prefix opens with is tested before the table is
		// walked, for the reason the byte in front of the candidate is: it is
		// one comparison where that is up to two of eight characters each.
		if src[start] != stripePublishableKeyAnchor[0] {
			continue
		}
		prefix := stripePublishableKeyPrefixAt(src, start)
		if prefix == 0 {
			continue
		}

		body := start + prefix
		end := base62RunEnd(src, body)
		if end-body < stripePublishableKeyBodyChars {
			continue
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return spans
})

// stripePublishableKeyPrefixes are the prefixes this pattern reads: the key
// type Stripe documents and the mode behind it.
//
// Neither is a prefix of the other, so the order they are tried in cannot
// change what is located — unlike stripeSecretKeyPrefixes, where sk_org_
// matching wherever sk_org_live_ does makes the order load-bearing.
// Test_stripePublishableKeyPrefixes holds every entry to opening with the
// anchor, to closing with a character no body is written with, and to opening
// with characters a word is made of, which is what the byte in front of a
// prefix is read for.
var stripePublishableKeyPrefixes = [...]string{
	"pk_live_",
	"pk_test_",
}

const (
	// stripePublishableKeyAnchor is what every prefix opens with: the whole of
	// the key type and the underscore behind it. It stands at the start of a
	// candidate, so where it stands is where a key would begin.
	stripePublishableKeyAnchor = "pk_"

	// stripePublishableKeyAnchorByte is the byte the scan searches the input
	// for and stripePublishableKeyAnchorIndex is where it stands in the anchor,
	// so a candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of what opens a
	// candidate rather than for the whole of it; what makes it this byte is
	// that the p opens page, project, price and half the paths a Stripe log
	// carries — three times over the line these benchmarks are written on —
	// where the k stands once. It is the same byte the secret keys are found
	// by, for the same reason and stated on their own side of the format.
	//
	// The underscore behind it is rarer still on that line — it stands not
	// once — and is passed over all the same: the mode a prefix names closes
	// with one too, so anchoring there would open a second candidate inside
	// every key.
	stripePublishableKeyAnchorByte  = 'k'
	stripePublishableKeyAnchorIndex = 1

	// stripePublishableKeyBodyChars is the count a body is held to, read as a
	// floor rather than exactly. It reads the secret keys' floor rather than
	// spelling a number of its own, because the two are halves of one vendor's
	// format and neither can move the floor alone: a second literal here could
	// come to disagree with the one builtin_stripe_secret_key.go weighs, and a
	// caller running both patterns would get a minimum body that changed with
	// the key type for no reason they could read.
	stripePublishableKeyBodyChars = stripeSecretKeyBodyChars
)

// stripePublishableKeyPrefixAt returns the length of the prefix beginning at i
// in src, or zero where none does.
func stripePublishableKeyPrefixAt(src string, i int) int {
	for _, prefix := range stripePublishableKeyPrefixes {
		if strings.HasPrefix(src[i:], prefix) {
			return len(prefix)
		}
	}
	return 0
}
