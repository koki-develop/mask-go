package mask

import "strings"

// DatabricksOAuthClientSecret locates Databricks OAuth client secrets: the
// prefix dose and the thirty-two lowercase hexadecimal characters behind it,
// thirty-six characters altogether. One string serves the secret a service
// principal is issued for the machine-to-machine flow and the secret a
// registered OAuth application is given for the user-to-machine one, so nothing
// in a secret says which of the two issued it.
//
// A secret is located wherever it is written, with no word boundary either
// side, and exactly thirty-six characters of it are. So text of that shape is
// redacted whether or not Databricks issued it. An uppercase letter, a
// character outside hexadecimal or a run of fewer than thirty-two characters
// ends the reading, so text as it is ordinarily written is not affected. A
// longer run is a secret with something written after it, and the secret alone
// is redacted.
//
// Its name is "databricks-oauth-client-secret".
func DatabricksOAuthClientSecret() Pattern { return databricksOAuthClientSecret }

// OAuth client secret is Databricks' own name for this string. Its
// documentation names the environment variable the SDKs read it from,
// DATABRICKS_CLIENT_SECRET, a service principal OAuth client secret; the
// account console generates it under a service principal's secrets; and the
// guide Databricks writes for partners registering an OAuth application names
// the same field a client secret there. That one term covers both is why they
// are one pattern rather than two: the value carries no mark saying which flow
// issued it, so a caller cannot act on the distinction a second switch would
// offer.
//
// What Databricks states about the format in its own documentation is nothing
// at all. The value is never shown, and the SDKs, the CLI and the drivers carry
// it as an opaque string with no length, alphabet or checksum stated anywhere.
//
// What states the prefix and the count is Databricks' own secret scanner. The
// Security Analysis Tool ships a detector reading dose and thirty-two
// characters, alongside detectors of the same shape for the other prefixes
// Databricks issues credentials behind. A partner's connector documentation
// writes the secret as dose and thirty-two more characters as well. The two
// agree on the prefix and on the count, and that is the count below.
//
// The alphabet is the one part of this format two readings disagree about, and
// the disagreement is written here because the pattern rests on which of them
// is taken. The Databricks tool reads one body grammar behind every prefix it
// knows, thirty-two characters of a hexadecimal class, and the body behind one
// of those prefixes — dapi, which DatabricksPersonalAccessToken reads — is
// thirty-two hexadecimal characters that four rulesets written against tokens
// somebody held agree on. So the vendor's own scanner describes this body as a
// hexadecimal one. Kingfisher reads it instead as any thirty-two of the
// letters, the digits, the underscore, the dot and the hyphen.
//
// That wider class is the widening on offer, and it is declined on what it
// would admit rather than on who wrote it. dose is a word, and thirty-two
// characters of that class behind a word is a hyphenated phrase of the right
// length as readily as it is a secret: dose-response-curve-analysis-2024-v1 is
// thirty-six characters and no credential. A pattern here redacts for every
// caller of AllBuiltinPatterns, which is not a place to cast a net over text
// that carries meaning when the vendor's own scanner describes a tighter one.
// What declining costs is the whole of the pattern: were Databricks writing
// these bodies in an alphabet hexadecimal has not got, this scan would locate
// none of them.
// Test_DatabricksOAuthClientSecret_aWiderAlphabet pins the decision so that
// taking it is a change somebody argues for rather than one somebody notices
// afterwards.
//
// Lowercase is what the class is read as. A hexadecimal encoder settles the
// case once for all of its output rather than varying it between secrets, so
// what admitting the other case would widen the net for is a secret written in
// a case the vendor's own scanner does not describe.
// Test_DatabricksOAuthClientSecret_anUppercaseBody holds it there.
//
// The count is read exactly rather than as a floor. A run longer than
// thirty-two is not one longer secret but a secret with something written after
// it, and only the secret is redacted; running the alphabet out instead would
// swallow whatever was written against the end of one. No reading of this
// format states a second shape behind the prefix, so reading the count exactly
// turns away nothing a range would have caught.
//
// Nothing is read behind the count. The personal access token beside this one
// carries a hyphen and a digit some tokens are written with, and that tail is
// that format's; neither reading of this one carries anything behind the
// thirty-two characters, so a scan reading one would be reading a shape nobody
// has written down. Where a secret ends is therefore settled by the secret
// itself, which is what leaves this scan with nothing of its own to say about
// the tail of its input.
//
// There is no boundary on either side of a match. A boundary in front drops
// rather than trims the match wherever a secret is written against a word
// character, which is what DATABRICKS_CLIENT_SECRET_dose... is; one behind it
// drops a secret followed by a letter or a digit, which under an exact count is
// a secret with a character written after it. What may stand either side is
// held back by the character class and the count alone.
//
// The byte the scan searches the input for is the s of the prefix, and the
// prefix is read back from it. builtin_scan.go says why a scan searches for one
// byte of its prefix rather than for the prefix itself; what makes it this byte
// is the body behind it. The d and the e are hexadecimal characters, so a
// search for either stops at one byte in sixteen of every digest, every UUID and
// every hash a log carries, and reads a prefix back from each. The o and the s
// are not, so a run of the body alphabet stops the search not once however long
// it runs. Between those two the s is the rarer over the text this library is
// pointed at: it stands four times against the o's six on the line these
// benchmarks are written on and 390 times against 410 over the log lines, JSON
// and command lines the conformance corpus writes text in, and the o is the
// commoner of the two letters in English besides.
//
// That same character bounds where a secret may be written inside another,
// without ruling it out. A candidate begins two characters in front of the s it
// is read back from, and the only s a span holds is that of its own prefix,
// since a body is hexadecimal — so a position inside a secret opens a candidate
// only where that s falls past the end of the span, which is the last two
// characters of a body. The o rules one of those two out again: a candidate
// beginning at the second to last character of a body would write that o as the
// last character of the body it stands in, and no body holds an o. What is left
// is a secret beginning at the last character of another, reached where the
// text carries on with the rest of a prefix.
// Test_DatabricksOAuthClientSecret_aSecretInsideASecret drives that position
// and the one the o rules out, and Test_databricksOAuthClientSecretPrefix
// counts them out of the declarations that decide it.
//
// So the scan steps one byte past the start of a candidate, whether that
// candidate became a secret or not, which is the default: consuming a match
// would step over a secret beginning at the end of it and leave that one in the
// output whole. The two spans overlap where it happens, and Masker.locate
// resolves them.
//
// The scan keeps no cursor and needs none: a candidate reads at most thirty-six
// bytes and stops, which bounds what it reads with no state to be wrong about,
// and is what rules out a quadratic input.
//
// What this pattern over-matches on is thirty-two lowercase hexadecimal
// characters written behind the prefix, which is the vendor's format exactly,
// and the shape worth stating is the digest: an MD5 is thirty-two hexadecimal
// characters, so dose written straight in front of one is a secret's format
// character for character and the whole of it is redacted. A SHA-1 is forty and
// a SHA-256 sixty-four, so either is redacted for thirty-six with the rest left
// in the text. There is nothing left to tell the two apart — a scan declining
// thirty-two lowercase hexadecimal characters behind this prefix declines every
// secret there is — and what has to be written to reach it is the prefix with a
// digest against it and nothing between.
// Test_DatabricksOAuthClientSecret_aDigestBehindThePrefix pins the decision.
//
// A hexadecimal run cannot carry the prefix however long it runs, since neither
// the o nor the s is written in that alphabet, so no digest and no UUID holds
// one partway along. The alphabets that can are the ones that hold letters
// outside hexadecimal: a base62 identifier carries dose about once in fifteen
// million characters and the thirty-two hexadecimal characters behind it about
// once in seven million million million more, and base64 and base64url are
// wider again. What is taken in any of them is a stretch of a value that was
// already opaque.
//
// What reaches a span is never prose: thirty-two unbroken hexadecimal
// characters behind four letters is longer than anything prose is written in,
// and a word running into the prefix runs the body out at its first character
// outside hexadecimal, which twenty of the twenty-six letters are. That is what
// the prefix being a word costs here and all it costs, since the wider class
// declined above is the one that would have made it matter.
//
// referenceDatabricksOAuthClientSecretFind in
// builtin_databricks_oauth_client_secret_test.go keeps the grammar as a regular
// expression, spelling the prefix, the count and the alphabet again so that the
// two are changed together, and the fuzz target beside it holds this scan to
// that expression.
var databricksOAuthClientSecret = newBuiltin("databricks-oauth-client-secret", &databricksOAuthClientSecretTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// states both, and this format adds nothing to them — a secret whole is a
	// secret finished, since nothing behind the count is read.
	retain := databricksOAuthClientSecretTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], databricksOAuthClientSecretAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a secret or not, for
		// the reason the rationale above gives: a body closing on d can open a secret
		// at the last character of the one it stands in, and a scan stepping over
		// what it took would leave that one whole.
		offset = anchor + 1

		if anchor < databricksOAuthClientSecretAnchorIndex {
			continue
		}
		start := anchor - databricksOAuthClientSecretAnchorIndex

		// The byte the prefix opens with is tested before the prefix is
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != databricksOAuthClientSecretPrefix[0] || !strings.HasPrefix(src[start:], databricksOAuthClientSecretPrefix) {
			continue
		}

		body := start + len(databricksOAuthClientSecretPrefix)
		end := start + databricksOAuthClientSecretChars
		if end > len(src) {
			// The input ends inside the body, and the count is the whole of
			// what tells a secret from any other run written behind the prefix.
			retain = min(retain, start)
			continue
		}
		if !isDatabricksOAuthClientSecretBody(src[body:end]) {
			continue
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return spans, retain
})

const (
	// databricksOAuthClientSecretPrefix is what every OAuth client secret opens
	// with, and what the scan reads back from its anchor. Two of its four
	// characters stand outside the alphabet a body is written in, which is what
	// makes the search cheap on a line of digests and what leaves only the end
	// of a body able to open a candidate inside a secret;
	// Test_databricksOAuthClientSecretPrefix holds it to both.
	databricksOAuthClientSecretPrefix = "dose"

	// databricksOAuthClientSecretAnchor is the byte the scan searches the input
	// for and databricksOAuthClientSecretAnchorIndex is where it stands in the
	// prefix, so a candidate begins that many bytes in front of what a search
	// reported. builtin_scan.go says why a scan searches for one byte of its
	// prefix rather than for the prefix itself; the rationale above says what
	// made it this byte.
	databricksOAuthClientSecretAnchor      = 's'
	databricksOAuthClientSecretAnchorIndex = 2

	// databricksOAuthClientSecretBodyChars is how many hexadecimal characters
	// stand behind the prefix, which is the count the scanner Databricks ships
	// reads behind this prefix and the one a partner's documentation writes a
	// secret with.
	databricksOAuthClientSecretBodyChars = 32

	// databricksOAuthClientSecretChars is the whole of a secret: the prefix and
	// the count above. Test_databricksOAuthClientSecretChars holds it to
	// thirty-six.
	databricksOAuthClientSecretChars = len(databricksOAuthClientSecretPrefix) + databricksOAuthClientSecretBodyChars
)

// isDatabricksOAuthClientSecretBody reports whether s is everything behind the
// prefix of a secret: exactly databricksOAuthClientSecretBodyChars lowercase
// hexadecimal characters.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count being left to the caller to have cut
// correctly.
func isDatabricksOAuthClientSecretBody(s string) bool {
	if len(s) != databricksOAuthClientSecretBodyChars {
		return false
	}
	for i := range len(s) {
		if !isDatabricksOAuthClientSecretBodyByte(s[i]) {
			return false
		}
	}
	return true
}

// isDatabricksOAuthClientSecretBodyByte reports whether c is a lowercase
// hexadecimal digit, which is what a body is written in.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go,
// which hold what more than one scan reads. Every hexadecimal run this package
// reads keeps its own test for the reason its own file gives — one admits
// either case where another admits lowercase alone — and a shared test named
// for the class rather than for what reads it would silently be the wrong
// answer for one of them.
func isDatabricksOAuthClientSecretBodyByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f'
}

// databricksOAuthClientSecretTail is what the scan settles the tail of its
// input by, for the piece of a prefix standing at the end of it. prefixTail
// (builtin_scan.go) says what that is and why it is built once. It is the whole
// of what this scan says about the tail beyond the candidate a cut input left
// open: a secret is finished at its thirty-sixth character, so one reaching the
// end of the input settles as it stands.
var databricksOAuthClientSecretTail = newPrefixTail(databricksOAuthClientSecretPrefix)
