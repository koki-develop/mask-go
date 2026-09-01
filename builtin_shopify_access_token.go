package mask

import (
	"slices"
	"strings"
)

// ShopifyAccessToken locates the access tokens Shopify issues in the format it
// prefixes: the tokens a public app receives for a shop (shpat_), the tokens a
// custom app is given (shpca_) and the tokens a private app was issued and a
// delegate token carries today (shppa_), each with thirty-two hexadecimal
// characters behind it — thirty-eight characters altogether.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly thirty-eight characters of it are. So text of that shape is
// redacted whether or not Shopify issued it. A space, a letter past f or a body
// of the wrong length ends the reading, so text as it is ordinarily written is
// not affected.
//
// Its name is "shopify-access-token".
func ShopifyAccessToken() Pattern { return shopifyAccessToken }

// Shopify calls these tokens opaque and publishes no generator, so the format
// is not read off a writer anybody can run. What states it instead is the
// vendor's own changelog, and it states the whole of it but the alphabet.
//
// The width and the kinds come from the entry announcing that the length of
// newly generated access tokens was increasing from thirty-two to thirty-eight
// characters, "adding a static prefix of shpat_ (for public apps), shpca_ (for
// custom apps), or shppa_ (for legacy private apps)". That is one sentence
// carrying three of the four parts of this grammar: the three prefixes, the six
// characters each of them comes to, and the thirty-two characters behind them
// that thirty-eight less a prefix leaves. The reference page on access tokens
// carries the same shape from the other side, and it is worth reading beside
// the changelog rather than instead of it: it says offline and online access
// tokens "are opaque strings that begin with shpat_" whichever grant produced
// them, and that delegate access tokens begin with shppa_. So the two Shopify
// sources agree on shpat_ and shppa_, the reference page names no third, and
// shpca_ is the changelog's alone.
//
// The two sources also part company over what shppa_ is for, and the scan reads
// the prefix rather than either answer. The changelog calls it the prefix of a
// legacy private app's token; the current page calls it the prefix of a
// delegate access token, which an app mints from its own offline token. Nothing
// here has to settle which: a credential of either description is a credential,
// both are written with the same six characters, and a scan keying on the
// prefix locates them without an opinion about what minted them.
//
// What neither source states is the alphabet a body is written in, and it is
// read off the rulesets and the values instead — the only part of this grammar
// that is. Four published rulesets read this format and all four ask for
// thirty-two hexadecimal characters without regard to case: gitleaks and
// noseyparker spell the class [a-fA-F0-9], trufflehog spells it [0-9A-Fa-f] and
// kingfisher spells it [[:xdigit:]]. Neither the count nor the class is in
// dispute anywhere, and the count they agree on is the one the changelog's
// arithmetic already gave.
//
// The body is therefore read in either case, and the evidence for that is worth
// separating from the agreement above. The token trufflehog ships in its own
// tests for this prefix carries both cases within the one body — uppercase and
// lowercase hexadecimal letters alternating through it — so a scan reading
// lowercase alone would leave that token and every token like it in the output
// whole. A credential missed is the failure this library is for; the uppercase
// digest a wider class draws in behind a prefix is the cost paid for not missing
// one, and Test_ShopifyAccessToken_aDigestBehindThePrefix pins what that cost
// is.
//
// The prefix is read in lowercase alone all the same, and the two readings do
// not pull against each other. A prefix is what a vendor writes; SHPAT_ is what
// an environment variable's name is written as, and a scan admitting it would
// redact the name a caller keeps a log by. Every ruleset but trufflehog reads
// the prefixes case-sensitively, and Test_ShopifyAccessToken_noMatch pins the
// uppercase prefix as text this scan leaves alone.
//
// There is no boundary on either side of a match. A word boundary in front
// would drop the whole match rather than trim it wherever a token is written
// against a word character, as SHOPIFY_ACCESS_TOKEN=shpat_... is not but
// TOKEN_shpat_... is, and one behind it would drop a token followed by a
// character of the body's own alphabet. What may stand either side is held back
// by the character class and the count alone. All four rulesets ask for
// something in front of the match — gitleaks by anchoring nothing but relying
// on its keyword, noseyparker, trufflehog and kingfisher by opening on \b — and
// a token written straight against a letter is one those leave in the text
// where this pattern redacts it.
//
// The count is read exactly rather than as a floor. A run of hexadecimal
// characters longer than thirty-two is not one longer token but a token with
// something written after it, and only the token is redacted. A floor is what a
// scan reads where its vendor states no length; here the vendor states it to the
// character, twice, for two credentials at once.
//
// The byte the scan searches the input for is the p of the opening, two
// characters in. builtin_scan.go says why a scan searches for one byte of its
// opening rather than for the opening itself, and here the three letters of
// that opening are equally absent from every body — none of s, h and p is a
// hexadecimal digit — so a line crowded with tokens opens the same number of
// candidates whichever of them is chosen and the choice falls to ordinary text.
// Over that, p is the rarest of the three by some way: it stands in about two
// characters in a hundred of English against six for either of the others.
//
// What the choice costs is one kind's prefix carrying the byte twice. shppa_
// holds a p at its third character and another at its fourth, so a line
// crowded with delegate tokens opens two candidates a token where a scan
// anchored on the h would open one. The second of them is turned away by a
// single comparison — the character it reads back for the start of the opening
// is the h, not the s — and a line of one kind of token is not what a caller's
// log is, where the letter frequencies above are what decides.
//
// The separator is rarer still on ordinary text and is passed over all the
// same. An underscore is what an environment variable, a snake_case name and a
// log field are written with, so a scan anchored on one opens a candidate on a
// great deal of text to reject it again — and SHOPIFY_API_SECRET= carries three
// of them in front of a value that holds one.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a token or not, which is the default and needs no argument.
// What it finds there is nothing, and the reason is worth stating: no token
// this package reads for Shopify can begin inside another. The opening is three
// letters and not one of them is a hexadecimal digit, so no part of it can fall
// inside a body, and no prefix carries the opening again past its first
// character, so no opening begins inside a prefix either. The second half is
// worth stating that way round rather than as a claim about any one letter:
// shpss_ carries an s twice more behind its opening, and it is the three
// letters together that stand nowhere else.
// Test_ShopifyAccessToken_noTokenBeginsInsideAnother drives the claim. It is
// stated rather than used: the scan still steps one byte along, because the
// default costs nothing worth an optimisation resting on a claim about the
// grammar.
//
// The scan keeps no cursor and needs none: a candidate reads at most
// thirty-eight bytes and stops, which bounds what it reads with no state to be
// wrong about — the guarantee a scan reading a body to the end of its run has
// to buy with a run cursor instead, bought here by the count being a count.
//
// What this pattern over-matches on: thirty-eight characters of the right shape
// that nobody issued. Six characters have to be written, one of them an
// underscore, then exactly thirty-two hexadecimal digits with nothing between
// any of them. Base62, standard base64 and base32 write no underscore at all,
// so an identifier, a certificate, a PEM body or an embedded image carries no
// candidate at however long it runs. Base64url writes every character of a
// prefix, and there the six stand about once in seventy thousand million
// characters, with thirty-two more having then to fall in sixteen of that
// alphabet's sixty-four — which is four raised to the thirty-second against it.
// Outside an encoding what is left is a snake_case name whose first segment is
// spelled shp, a kind and then thirty-two hexadecimal characters.
//
// The collision that is reachable is a digest written behind the prefix, and
// this pattern pays for it rather than ruling it out. An MD5 is thirty-two
// hexadecimal characters exactly, which is a body exactly, so shpat_ and an MD5
// is a token to this scan. There is nothing left in the text to tell the two
// apart — the vendor's format is that prefix and that many of those characters,
// and no part of it is left over for a digest to fail — so a scan declining this
// would decline every token Shopify issues. A longer digest behind the prefix
// is not turned away either, and the exact count is what decides how much of it
// goes: a SHA-1 at forty or a SHA-256 at sixty-four has its first thirty-two
// characters redacted with the prefix in front of them and the rest left in the
// text, because the count stops where a body stops rather than where the run
// does. What the prefix turns away is the bare digest with nothing in front of
// it, which is what keeps every hexadecimal identifier a caller passes through
// out of this.
// Test_ShopifyAccessToken_aDigestBehindThePrefix pins each of those.
//
// What reaches a span is never prose. A token holds one underscore in its first
// six characters and none after, holds no space, and thirty-two unbroken
// hexadecimal characters are longer than anything prose is written in.
//
// The tokens Shopify issued before this format are not read, and reading them
// is what this package exists not to do. Such a token was thirty-two characters
// with nothing in front of them, which the changelog says is the form existing
// tokens go on working in until they are regenerated. That is a bare digest's
// shape exactly: a pattern reading it would redact every MD5, every short cache
// key and every hexadecimal identifier a caller passes through. It is the loose
// grammar this package declines rather than the unlucky one, and
// Test_ShopifyAccessToken_theTokenFormatItReplaced pins the decision so that
// reading it is a change somebody argues for rather than one somebody notices
// afterwards.
//
// A fifth prefix is written about and is not read. shpua_ is named in
// Shopify's community forums as the prefix of tokens belonging to apps of some
// other description, but Shopify documents no such credential, neither
// changelog names it and no published ruleset reads one. A kind guessed at is
// a candidate opened on text neither Shopify nor a ruleset writes; a kind
// stated is one entry added to shopifyAccessTokenKinds below on the day the
// format is published. Test_ShopifyAccessToken_aKindShopifyNamesNoPrefixFor
// pins the decision so that reading one is a change somebody argues for.
//
// referenceShopifyAccessToken in builtin_shopify_access_token_test.go keeps the
// grammar as a regular expression, spelling the opening, the three kinds, the
// separator, the count and the character class again so that the two are changed
// together, and the fuzz target beside it holds this scan to that expression. An
// expression is affordable here: the repetition is exact, so the machine an
// engine builds is read once and stops, and the opening is three letters of
// which none is written in a body, so a run of the body's alphabet holds no
// candidate at all and an engine searching for that literal walks its machine
// almost nowhere.
var shopifyAccessToken = newBuiltin("shopify-access-token", &shopifyAccessTokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := shopifyAccessTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], shopifyCredentialAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not.
		offset = anchor + 1

		if anchor < shopifyCredentialAnchorIndex {
			continue
		}
		start := anchor - shopifyCredentialAnchorIndex

		// The prefix is read in the order it is written: the opening, then the
		// two characters naming the kind with the separator behind them. Every
		// anchor the search stops at reaches this line, and the opening turns
		// all but a few of them away before the kind is looked at.
		kind := start + len(shopifyCredentialOpening)
		if !strings.HasPrefix(src[start:], shopifyCredentialOpening) ||
			!opensShopifyAccessTokenKind(src[kind:]) {
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

// The parts of the format the two Shopify credentials share, which is
// everything but the two characters naming the kind. They are named for the
// vendor rather than for either credential because
// builtin_shopify_app_secret_key.go reads them too: the changelogs moved both
// credentials to this shape in the same words and to the same widths, so it is
// the half of the format neither of them can change alone, and a second copy of
// it beside the other prefix is a copy that could come to disagree with this one
// while both scans went on passing.
const (
	// shopifyCredentialOpening is what every prefix opens with, and what the
	// scan reads back from its anchor.
	//
	// All three of its characters are load-bearing: not one of them is a
	// hexadecimal digit, so no part of the opening can fall inside a body and
	// no credential of this vendor's can begin inside another.
	// Test_shopifyCredentialOpening holds them there.
	shopifyCredentialOpening = "shp"

	// shopifyCredentialSeparator closes every prefix, behind the two characters
	// naming the kind. It is written in no body, so a run of the body's
	// alphabet can hold no prefix and every body begins where such a run begins.
	//
	// That is not what bounds either scan — the count is — but it is what a
	// count relaxed to a floor would have to fall back on, which is why it is
	// stated and held to rather than left to be worked out then.
	shopifyCredentialSeparator = '_'

	// shopifyCredentialKindChars is how many characters name the kind in every
	// prefix, between the opening and the separator.
	shopifyCredentialKindChars = 2

	// shopifyCredentialPrefixChars is the whole of a prefix: the opening, the
	// two characters naming the kind and the separator behind them.
	shopifyCredentialPrefixChars = len(shopifyCredentialOpening) + shopifyCredentialKindChars + 1

	// shopifyCredentialAnchor is the byte both scans search the input for and
	// shopifyCredentialAnchorIndex is where it stands in every prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix rather
	// than for the prefix itself; the rationale above says what made it this
	// byte. Each pattern holds its own prefixes to carrying it at this index, in
	// a test of its own.
	shopifyCredentialAnchor      = 'p'
	shopifyCredentialAnchorIndex = 2

	// shopifyCredentialBodyChars is what stands behind a prefix: thirty-eight
	// characters, which is what both changelogs say a credential grew to, less
	// the six a prefix comes to. Test_shopifyCredentialChars holds the
	// arithmetic to both numbers.
	shopifyCredentialBodyChars = 32

	// shopifyCredentialChars is the whole of a credential, the thirty-eight
	// characters the changelogs state.
	shopifyCredentialChars = shopifyCredentialPrefixChars + shopifyCredentialBodyChars
)

// shopifyAccessTokenKinds is what stands between the opening and the separator
// in the prefix of every token this scan reads: at for the token a public app
// receives for a shop, ca for the token a custom app is given, pa for the token
// Shopify's changelog assigns to a legacy private app and its reference page to
// a delegate access token.
//
// It is the one declaration saying which kinds there are, and
// shopifyAccessTokenPrefixes below reads it rather than writing the prefixes out
// again. builtin_scan.go says why: a table kept beside this is one that can come
// to disagree with it, and what a stream would then do with the kind it had not
// been told about is release the characters a token opens with and redact
// nothing.
var shopifyAccessTokenKinds = []string{"at", "ca", "pa"}

// opensShopifyAccessTokenKind reports whether s, which is the text behind the
// opening of a candidate, begins with one of the kinds above and the separator
// that closes a prefix.
//
// It is handed the separator to check as well as the kind so that the two are
// read in one place: a kind found with nothing behind it is no prefix, and a
// caller left to check the separator for itself is a caller that can forget to.
// The separator is compared first because it is one byte against a fixed index
// and turns away everything the kinds would then be walked for.
func opensShopifyAccessTokenKind(s string) bool {
	if len(s) <= shopifyCredentialKindChars || s[shopifyCredentialKindChars] != shopifyCredentialSeparator {
		return false
	}
	return slices.Contains(shopifyAccessTokenKinds, s[:shopifyCredentialKindChars])
}

// isShopifyCredentialBody reports whether s is everything behind the prefix of a
// Shopify credential: exactly shopifyCredentialBodyChars characters of the
// body's alphabet.
//
// It is named for the vendor rather than for the token because the scan in
// builtin_shopify_app_secret_key.go reads it too, for the reason the shared
// constants above give.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count left to the caller to have cut correctly.
func isShopifyCredentialBody(s string) bool {
	if len(s) != shopifyCredentialBodyChars {
		return false
	}
	for i := range len(s) {
		if !isShopifyCredentialBodyByte(s[i]) {
			return false
		}
	}
	return true
}

// isShopifyCredentialBodyByte reports whether c is a hexadecimal digit of either
// case, which is what every credential this vendor issues is written behind its
// prefix in.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go,
// which hold what more than one scan reads. Two scans read it and both of them
// are Shopify's, which is what a name says here: a hexadecimal class is not one
// class across this package — a whole body is read in either case here and in
// lowercase alone elsewhere, each for the reason its own file gives. A shared
// test named for the class rather than for what reads it would silently be the
// wrong answer for one of them, and would invite the next pattern to read a
// digest with it.
func isShopifyCredentialBodyByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// shopifyCredentialPrefix returns the prefix a Shopify credential of the given
// kind opens with: the opening, the kind and the separator behind it.
//
// Both patterns build their prefixes with it rather than writing them out, so
// that the shape of a prefix is stated once for the vendor and a change to it
// reaches the credentials together, as the changelogs' own change did.
func shopifyCredentialPrefix(kind string) string {
	return shopifyCredentialOpening + kind + string(shopifyCredentialSeparator)
}

// shopifyAccessTokenPrefixes is what a candidate opens with, one entry a kind.
//
// The kinds are read out of shopifyAccessTokenKinds rather than written out
// again, so that a kind admitted there is a kind this knows about.
var shopifyAccessTokenPrefixes = func() []string {
	prefixes := make([]string, 0, len(shopifyAccessTokenKinds))
	for _, kind := range shopifyAccessTokenKinds {
		prefixes = append(prefixes, shopifyCredentialPrefix(kind))
	}
	return prefixes
}()

// shopifyAccessTokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var shopifyAccessTokenTail = newPrefixTail(shopifyAccessTokenPrefixes...)
