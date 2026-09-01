package mask

import "strings"

// DatabricksPersonalAccessToken locates Databricks personal access tokens: the
// prefix dapi and the thirty-two lowercase hexadecimal characters behind it —
// thirty-six characters altogether — followed where one is written by a hyphen
// and one digit, which brings such a token to thirty-eight. One string serves
// the tokens a workspace user creates and the tokens a service principal is
// issued, so nothing in a token says which of the two it authenticates as.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly thirty-six characters of it are, or thirty-eight where the hyphen
// and the digit stand. So text of that shape is redacted whether or not
// Databricks issued it. An uppercase letter, a character outside hexadecimal or
// a run of fewer than thirty-two characters ends the reading, so text as it is
// ordinarily written is not affected. A longer run is a token with something
// written after it, and the token alone is redacted.
//
// Its name is "databricks-personal-access-token".
func DatabricksPersonalAccessToken() Pattern { return databricksPersonalAccessToken }

// Personal access token is Databricks' own name for this string. Its
// documentation keeps a page under that title for the credential a workspace
// user creates, and the same term covers the one a service principal is issued:
// the token endpoint returns both as a token_value, the CLI prompts for a
// "Personal access token" and reports the authentication as "Personal Access
// Token (pat)". That the two are one string with no mark on it to tell them
// apart is why they put no boundary between patterns — a caller cannot act on a
// distinction the value does not carry — and it is why the name is not
// narrowed to the user's half.
//
// What Databricks states about the format stops at the prefix. Its
// documentation writes a token as dapi... wherever it shows one, the SDKs and
// the CLI carry a token as an opaque bearer string, and no length, alphabet or
// checksum appears in any of them.
//
// What states the rest is Microsoft's own classifier for the credential, which
// reads what it calls a hex encoded 128-bit symmetric key and keeps dapi in the
// vocabulary it reads beside one. A 128-bit key written in hexadecimal is
// thirty-two characters, and that is the count below. The page's own worked
// example is a mockup rather than a token — thirty characters, fourteen of them
// outside hexadecimal — so what is read off it is the key it names and not the
// string it prints. It states a character class as well, a-f or A-F with the
// digits, and that is a class for a hexadecimal key of whatever provenance
// rather than a reading of this format.
//
// The rulesets agree on the prefix and on the count, and divide from that class
// on the case: trufflehog reads dapi and thirty-two of [0-9a-f], gitleaks and
// noseyparker the same class, kingfisher the same again with an entropy floor.
// Every one of them was written against tokens somebody held, and lowercase is
// what a hexadecimal encoder settles once for all of its output rather than a
// thing a generator varies between tokens.
//
// So the alphabet is lowercase hexadecimal, and admitting the other case
// beside it is the widening on offer. It is declined on the rulesets rather
// than on the vendor: Databricks itself states no case at all, the classifier
// states both for the reason above, and what four readings of real tokens
// agree on is lowercase. What admitting the other case would buy is a token
// none of those four rules admits; what it would cost is a net cast wider than
// every reading of the format there is.
// Test_DatabricksPersonalAccessToken_anUppercaseBody pins the decision so that
// widening it is a change somebody argues for rather than one somebody notices
// afterwards.
//
// The count is read exactly rather than as a floor. A run longer than
// thirty-two is not one longer token but a token with something written after
// it, and only the token is redacted; running the alphabet out instead would
// swallow whatever was written against the end of one. Databricks states no
// second shape behind this prefix, so reading it exactly turns away nothing a
// range would have caught.
//
// The hyphen and the digit behind the count are the one part of this format no
// vendor writes down, and reading them is a decision rather than a reading.
// Every ruleset above carries them as an optional tail — gitleaks and
// trufflehog as one digit, noseyparker as one or more, kingfisher as one and as
// a form of its own — and all four were written from tokens rather than from a
// specification. What is not in doubt is where the secret is: the thirty-two
// characters are the key, and a scan stopping at them leaves a hyphen and a
// counter in the output rather than any part of one. So the tail is read for
// what the output reads as — a redaction with -2 hanging off it reads as a
// token half taken — and it is read as one digit, which is the tighter of the
// two shapes on offer and the one three of the four rulesets settled on. What
// that costs is the token written against a longer number: a hyphen and four
// digits behind a token leaves three of them in the text, which is the same
// thing a count read exactly leaves behind anywhere else.
// Test_DatabricksPersonalAccessToken_theTail drives both ends of it.
//
// Where a token ends is therefore not settled by the token: a scan handed the
// thirty-sixth character as the last of its input cannot know whether a hyphen
// and a digit follow, and neither can it once the hyphen has arrived alone. So
// the scan reports the span it has and holds from the start of it. What
// that costs a stream is thirty-six characters held to the end of a write
// rather than released with the hyphen still open, and what settling it instead
// would cost is a redaction of thirty-six characters written out with the
// thirty-seventh and thirty-eighth following it unredacted — text a stream
// cannot take back.
//
// There is no boundary on either side of a match. A boundary in front drops
// rather than trims the match wherever a token is written against a word
// character, which is what DATABRICKS_TOKEN_dapi... is; one behind it drops a
// token followed by a letter or a digit, which under an exact count is a token
// with a character written after it. What may stand either side is held back by
// the character class and the count alone. Every ruleset above asks for both
// boundaries, and each of them reads this format under a keyword or an entropy
// floor besides, which are demands on the text around a value and on the
// content of a random body rather than parts of the format.
//
// The byte the scan searches the input for is the p of the prefix, and the
// prefix is read back from it. builtin_scan.go says why a scan searches for one
// byte of its prefix rather than for the prefix itself; what makes it this byte
// is the body behind it. The d and the a are hexadecimal characters, so a
// search for either stops at one byte in sixteen of every digest, every UUID
// and every hash a log carries, and reads a prefix back from each. The p and
// the i are not, so a run of the body alphabet stops the search not once
// however long it runs. Between those two the p is the rarer over text: it
// stands three times against the i's seven on the line these benchmarks are
// written on, a third as often as the i over the conformance corpus, and not at
// all in "there is no credential in this sentence", which this pattern's own
// corpus carries as prose.
//
// That same character bounds where a token may be written inside another,
// without ruling it out. A candidate begins two characters in front of the p it
// is read back from, and the only p a span holds is that of its own prefix — a
// body is hexadecimal and a tail is a hyphen and a digit — so a position inside
// a token opens a candidate only where that p falls past the end of the span.
// What that leaves is the last two characters of a body, and only of a body no
// tail follows: behind a tail the characters at that distance are the hyphen
// and the digit, and neither is the d a prefix opens with nor the p a candidate
// is found at. Test_DatabricksPersonalAccessToken_aTokenInsideAToken drives
// both positions, and Test_databricksPersonalAccessTokenPrefix counts them.
//
// So the scan steps one byte past the start of a candidate, whether that
// candidate became a token or not, which is the default: consuming a match
// would step over a token beginning at the end of it and leave that one in the
// output whole. The two spans overlap where it happens, and Masker.locate
// resolves them.
//
// The scan keeps no cursor and needs none: a candidate reads at most
// thirty-eight bytes and stops, which bounds what it reads with no state to be
// wrong about, and is what rules out a quadratic input.
//
// What this pattern over-matches on is thirty-two lowercase hexadecimal
// characters written behind the prefix, which is the vendor's format exactly,
// and the shape worth stating is the digest: an MD5 is thirty-two hexadecimal
// characters, so dapi written straight in front of one is a token's format
// character for character and the whole of it is redacted. A SHA-1 is forty and
// a SHA-256 sixty-four, so either is redacted for thirty-six with the rest left
// in the text. There is nothing left to tell the two apart — a scan declining
// thirty-two lowercase hexadecimal characters behind this prefix declines every
// token there is — and what has to be written to reach it is the prefix with a
// digest against it and nothing between.
// Test_DatabricksPersonalAccessToken_aDigestBehindThePrefix pins the decision.
//
// A hexadecimal run cannot carry the prefix however long it runs, since neither
// the p nor the i is written in that alphabet, so no digest and no UUID holds
// one partway along. The alphabets that can are the ones that hold letters
// outside hexadecimal: a base62 identifier carries dapi about once in fifteen
// million characters and the thirty-two hexadecimal characters behind it about
// once in seven million million million more, and base64 and base64url are
// wider again. What is taken in any of them is a stretch of a value that was
// already opaque.
//
// What reaches a span is never prose: thirty-two unbroken hexadecimal
// characters behind four letters is longer than anything prose is written in,
// and a word running into the prefix runs the body out at its first character
// outside hexadecimal, which twenty of the twenty-six letters are.
//
// Other credentials Databricks issues are left alone, and the prefix is what
// leaves them. An OAuth client secret is written dose and carries no dapi to be
// found at, which DatabricksOAuthClientSecret is the pattern for; the OAuth
// access and refresh tokens an authorization flow returns are JWTs, which are a
// format of their own. Each is a credential this pattern does not name rather
// than one the scan happens to miss.
//
// referenceDatabricksPersonalAccessTokenFind in
// builtin_databricks_personal_access_token_test.go keeps the grammar as a
// regular expression, spelling the prefix, the count, the alphabet and the tail
// again so that the two are changed together, and the fuzz target beside it
// holds this scan to that expression.
var databricksPersonalAccessToken = newBuiltin("databricks-personal-access-token", &databricksPersonalAccessTokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, a candidate the end of it cut short, or a token whose tail
	// the end of it leaves open. builtin_scan.go states the first two; the
	// third is this format's own and the rationale above argues it.
	retain := databricksPersonalAccessTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], databricksPersonalAccessTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not, for the
		// reason the rationale above gives: a body closing on da or on d can open a
		// token at the last two characters of the one it stands in, and a scan
		// stepping over what it took would leave that one whole.
		offset = anchor + 1

		if anchor < databricksPersonalAccessTokenAnchorIndex {
			continue
		}
		start := anchor - databricksPersonalAccessTokenAnchorIndex

		// The byte the prefix opens with is tested before the prefix is
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != databricksPersonalAccessTokenPrefix[0] || !strings.HasPrefix(src[start:], databricksPersonalAccessTokenPrefix) {
			continue
		}

		body := start + len(databricksPersonalAccessTokenPrefix)
		bodyEnd := start + databricksPersonalAccessTokenChars
		if bodyEnd > len(src) {
			// The input ends inside the body, and the count is the whole of
			// what tells a token from any other run written behind the prefix.
			retain = min(retain, start)
			continue
		}
		if !isDatabricksPersonalAccessTokenBody(src[body:bodyEnd]) {
			continue
		}

		end, open := databricksPersonalAccessTokenEnd(src, start)
		if open {
			// A token stands here and where it ends does not: the tail that
			// would widen the span has not arrived, and nothing written of the
			// token itself says whether it will. The span is reported anyway,
			// since a caller handed the whole of its text is owed it; what is
			// held back is everything from the start of the value, so that a
			// stream reports one span rather than a redaction and the two
			// characters that were about to join it.
			retain = min(retain, start)
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return spans, retain
})

const (
	// databricksPersonalAccessTokenPrefix is what every personal access token
	// opens with, and what the scan reads back from its anchor. Two of its four
	// characters stand outside the alphabet a body is written in, which is what
	// makes the search cheap on a line of digests and what leaves only the end
	// of a body able to open a candidate inside a token;
	// Test_databricksPersonalAccessTokenPrefix holds it to both.
	databricksPersonalAccessTokenPrefix = "dapi"

	// databricksPersonalAccessTokenAnchor is the byte the scan searches the
	// input for and databricksPersonalAccessTokenAnchorIndex is where it stands
	// in the prefix, so a candidate begins that many bytes in front of what a
	// search reported. builtin_scan.go says why a scan searches for one byte of
	// its prefix rather than for the prefix itself; the rationale above says
	// what made it this byte.
	databricksPersonalAccessTokenAnchor      = 'p'
	databricksPersonalAccessTokenAnchorIndex = 2

	// databricksPersonalAccessTokenBodyChars is how many hexadecimal characters
	// stand behind the prefix: a 128-bit key written in that alphabet, which is
	// what the classifier reading this credential names.
	databricksPersonalAccessTokenBodyChars = 32

	// databricksPersonalAccessTokenChars is a token up to the end of its body:
	// the prefix and the count above.
	// Test_databricksPersonalAccessTokenChars holds it to thirty-six.
	databricksPersonalAccessTokenChars = len(databricksPersonalAccessTokenPrefix) + databricksPersonalAccessTokenBodyChars

	// databricksPersonalAccessTokenSuffixSeparator is what divides a token from
	// the digit some carry, and databricksPersonalAccessTokenSuffixChars is the
	// two characters the pair comes to. The separator stands outside the
	// alphabet a body is written in, so a body cannot run into one and the
	// count above is decided before this is read at all.
	databricksPersonalAccessTokenSuffixSeparator = '-'
	databricksPersonalAccessTokenSuffixChars     = 2

	// databricksPersonalAccessTokenSuffixedChars is the whole of a token
	// carrying that digit, and is what the walk below reports the end of one
	// by. Test_databricksPersonalAccessTokenChars holds it to thirty-eight.
	databricksPersonalAccessTokenSuffixedChars = databricksPersonalAccessTokenChars + databricksPersonalAccessTokenSuffixChars
)

// isDatabricksPersonalAccessTokenBody reports whether s is everything behind
// the prefix of a token up to the tail: exactly
// databricksPersonalAccessTokenBodyChars lowercase hexadecimal characters.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count being left to the caller to have cut
// correctly.
func isDatabricksPersonalAccessTokenBody(s string) bool {
	if len(s) != databricksPersonalAccessTokenBodyChars {
		return false
	}
	for i := range len(s) {
		if !isDatabricksPersonalAccessTokenBodyByte(s[i]) {
			return false
		}
	}
	return true
}

// isDatabricksPersonalAccessTokenBodyByte reports whether c is a lowercase
// hexadecimal digit, which is what a body is written in.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go,
// which hold what more than one scan reads. Every hexadecimal run this package
// reads keeps its own test for the reason its own file gives — one admits
// either case where another admits lowercase alone — and a shared test named
// for the class rather than for what reads it would silently be the wrong
// answer for one of them.
func isDatabricksPersonalAccessTokenBodyByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f'
}

// isDatabricksPersonalAccessTokenSuffixDigit reports whether c is the one digit
// a token's tail is written with. It is a decimal digit rather than a
// hexadecimal one: the tail is a counter and not part of the key, and the
// rationale above says what is known of it and what is not.
func isDatabricksPersonalAccessTokenSuffixDigit(c byte) bool {
	return '0' <= c && c <= '9'
}

// databricksPersonalAccessTokenEnd returns where the token beginning at start
// ends, and whether the end of the input is what answered that.
//
// It is handed the start of the token rather than the end of its body so that
// the two lengths a token is written to are the two constants above and are
// read here, rather than one of them being reached by arithmetic the caller
// did.
//
// The two results are one question because only this walk can tell them apart:
// a token the input stops behind and a token nothing follows read the same
// here, and the first of them may still grow by the tail while the second is
// finished. What a scan does with the second answer is settle nothing about the
// value, which is the rationale's own argument and not this helper's.
func databricksPersonalAccessTokenEnd(src string, start int) (end int, open bool) {
	bodyEnd := start + databricksPersonalAccessTokenChars
	if bodyEnd == len(src) {
		return bodyEnd, true
	}
	if src[bodyEnd] != databricksPersonalAccessTokenSuffixSeparator {
		return bodyEnd, false
	}
	if bodyEnd+1 == len(src) {
		return bodyEnd, true
	}
	if !isDatabricksPersonalAccessTokenSuffixDigit(src[bodyEnd+1]) {
		return bodyEnd, false
	}
	return start + databricksPersonalAccessTokenSuffixedChars, false
}

// databricksPersonalAccessTokenTail is what the scan settles the tail of its
// input by, for the piece of a prefix standing at the end of it. prefixTail
// (builtin_scan.go) says what that is and why it is built once; what it does
// not reach — a token whose own tail the end of the input leaves open — is the
// scan's own and is held from the start of the value.
var databricksPersonalAccessTokenTail = newPrefixTail(databricksPersonalAccessTokenPrefix)
