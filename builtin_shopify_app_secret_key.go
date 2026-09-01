package mask

import "strings"

// ShopifyAppSecretKey locates the secret half of a Shopify app's client
// credentials: the prefix shpss_ and the thirty-two hexadecimal characters
// behind it — thirty-eight characters altogether.
//
// A key is located wherever it is written, with no word boundary either side,
// and exactly thirty-eight characters of it are. So text of that shape is
// redacted whether or not Shopify issued it. A space, a letter past f or a body
// of the wrong length ends the reading, so text as it is ordinarily written is
// not affected.
//
// Its name is "shopify-app-secret-key".
func ShopifyAppSecretKey() Pattern { return shopifyAppSecretKey }

// The prefix, the width and the count come from the changelog announcing that
// "the length of all newly generated Shopify app secret keys has increased from
// 32 to 38, adding a static prefix of shpss_, to make the secret keys easier to
// identify". That sentence carries the prefix, the six characters it comes to
// and the thirty-two behind it that thirty-eight less a prefix leaves, and it is
// the same sentence in the same shape that the access token changelog carries
// for the other three prefixes.
//
// That is why this scan reads its opening, its separator, its counts and its
// alphabet out of builtin_shopify_access_token.go rather than spelling them
// again. The two changelogs moved the two credentials to one shape, so what is
// borrowed is the half of the format neither of them can change alone; only the
// two characters naming the kind are this pattern's own. A second copy of the
// shared half beside this prefix is a copy that could come to disagree with the
// other while both scans went on passing.
//
// The alphabet is the one part of the grammar Shopify does not state, and the
// published rulesets settle it here as they do for the access token: gitleaks,
// noseyparker and kingfisher all read thirty-two hexadecimal characters behind
// shpss_ without regard to case, and trufflehog's OAuth detector, which reads
// this credential rather than the access token, ships a body written wholly in
// uppercase beside one written wholly in lowercase. So either case is right for
// this credential on the same evidence and for the same reason, which is what
// makes the byte test a shared declaration rather than a coincidence.
//
// This is one pattern and the access token is another, which is a decision about
// the caller rather than about the scanning — the two grammars differ by two
// characters and could trivially have been one scan. Three things separate them.
// A caller has reason to enable one and not the other: an access token is issued
// per shop and reaches a log through the X-Shopify-Access-Token header of every
// request an app makes, where this key is held once by the app's developer, is
// written in a configuration file rather than a request, and is what verifies a
// webhook's HMAC. A caller has reason to tell them apart in the output, and a
// redactor keying on Match.Pattern.Name can only write the distinction a
// boundary hands it: an access token in a log says one shop's session is
// exposed, and this key in a log says every install of the app is. And no term
// Shopify uses covers both — the changelogs name one an access token and the
// other an app secret key, and there is no third word above them — which is what
// settles the boundary on its own.
//
// The name is the changelog's. Shopify has three terms for this credential and
// they are not interchangeable in a redaction: the changelog that introduced the
// prefix calls it an app secret key, the current reference on client credentials
// calls it a client secret and notes that "some tools and documentation call
// these the API key and API secret", and the environment variable Shopify's own
// libraries read it from is SHOPIFY_API_SECRET. App secret key is taken because
// it is the term in the source this scan's grammar is built on, and because the
// other two name the credential by the role it plays in a protocol every vendor
// has one of — a redaction reading "client secret" says nothing about whose. A
// reader auditing this scan against the current reference page will find client
// secret there and should read the two as the same credential.
//
// The reading this scan does behind that prefix — the lowercase prefix against
// the either-case body, the absent word boundaries, the exact count, the byte
// searched for and the step taken at a candidate — is the access token's, and
// that file is where each of them is argued rather than repeated here. One of
// them lands differently: this prefix carries the anchor once where shppa_
// carries it twice, so the cost that choice has does not fall here at all.
//
// The keys Shopify issued before this format are not read, for the reason the
// access token's file gives about the tokens it replaced: such a key was
// thirty-two characters with nothing in front of them, which is a bare digest's
// shape, and the changelog says existing secrets go on working in that form
// until a partner regenerates them.
// Test_ShopifyAppSecretKey_theKeyFormatItReplaced pins the decision.
//
// The scan keeps no cursor and needs none: a candidate reads at most
// thirty-eight bytes and stops, six of prefix and thirty-two of body, which
// bounds what it reads with no state to be wrong about.
//
// referenceShopifyAppSecretKey in builtin_shopify_app_secret_key_test.go keeps
// the grammar as a regular expression, spelling the whole prefix, the count and
// the character class again — including the half this scan borrows, since a
// reference sharing a declaration with the scan it checks could not disagree
// with it and the fuzz target beside it would compare a rule with itself.
var shopifyAppSecretKey = newBuiltin("shopify-app-secret-key", &shopifyAppSecretKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two.
	retain := shopifyAppSecretKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], shopifyCredentialAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not.
		offset = anchor + 1

		if anchor < shopifyCredentialAnchorIndex {
			continue
		}
		start := anchor - shopifyCredentialAnchorIndex

		// The prefix is read in parts, as the access token's three are: the
		// opening, then the two characters naming the kind with the separator
		// behind them. Comparing shopifyAppSecretKeyPrefix whole would read the
		// same six bytes and cost more, since it is built rather than written
		// out and so is a variable the compiler cannot fold into the comparison
		// as it folds the constant opening.
		kind := start + len(shopifyCredentialOpening)
		if !strings.HasPrefix(src[start:], shopifyCredentialOpening) ||
			!opensShopifyAppSecretKeyKind(src[kind:]) {
			continue
		}

		body := start + shopifyCredentialPrefixChars
		end := start + shopifyCredentialChars
		if end > len(src) {
			// The input ends inside this candidate, so the count that is the
			// whole of what tells it from anything else written behind the
			// prefix cannot be taken here.
			retain = min(retain, start)
			continue
		}
		if isShopifyCredentialBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// shopifyAppSecretKeyKind is what stands between the opening and the separator
// in this credential's prefix. It is the whole of what this pattern does not
// share with the access token beside it.
const shopifyAppSecretKeyKind = "ss"

// opensShopifyAppSecretKeyKind reports whether s, which is the text behind the
// opening of a candidate, begins with the kind above and the separator that
// closes a prefix.
//
// It is handed the separator to check as well as the kind for the reason
// opensShopifyAccessTokenKind gives: a kind found with nothing behind it is no
// prefix. The separator is compared first because it is one byte against a fixed
// index and turns away everything the kind would then be compared against.
func opensShopifyAppSecretKeyKind(s string) bool {
	return len(s) > shopifyCredentialKindChars &&
		s[shopifyCredentialKindChars] == shopifyCredentialSeparator &&
		s[:shopifyCredentialKindChars] == shopifyAppSecretKeyKind
}

// shopifyAppSecretKeyPrefix is what a candidate opens with, which the scan
// reads in parts and the tail below needs whole. It is built from the kind above
// and the shared shape of a prefix rather than written out as a literal, so that
// the opening and the separator are stated once for the vendor.
var shopifyAppSecretKeyPrefix = shopifyCredentialPrefix(shopifyAppSecretKeyKind)

// shopifyAppSecretKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var shopifyAppSecretKeyTail = newPrefixTail(shopifyAppSecretKeyPrefix)
