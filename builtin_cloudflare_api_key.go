package mask

import "strings"

// CloudflareAPIKey locates Cloudflare API keys: the prefix cfk_, the forty
// characters of the secret behind it and the eight hexadecimal digits of the
// checksum behind that — fifty-two characters. One key carries everything the
// user who holds it can do, over every account and zone they can reach, and
// nothing in it says otherwise.
//
// A key is located wherever it is written, with no word boundary either side,
// and exactly fifty-two characters of it are. So text of that shape is redacted
// whether or not Cloudflare issued it. A space, a hyphen, an underscore behind
// the prefix, a letter past f in the last eight characters or a body of the
// wrong length ends the reading, so text as it is ordinarily written is not
// affected.
//
// Its name is "cloudflare-api-key".
func CloudflareAPIKey() Pattern { return cloudflareAPIKey }

// The name is the term Cloudflare's own two names for this credential share.
// The page on token formats gives the row under cfk_ as the Global API Key; the
// detection entry Cloudflare added to its data loss prevention under the same
// prefix is called a Cloudflare User API Key. Neither wording is the other, and
// what both say is API key — which is also what Cloudflare calls the credential
// on the pages documenting how to get one and what it can do. So the name
// covers the whole of what this scan locates under a term the vendor writes,
// and it is not the narrower of the two names, either of which the vendor could
// drop without the credential changing.
//
// The grammar is read off the same three pages the token scan's is, and they
// give this credential a row apiece alongside the two tokens. The format page
// writes it as the prefix, forty characters and a checksum; the changelog
// adding the detection entries says what the checksum is, a structured prefix
// and a CRC32 checksum suffix, and says the shape is meant to be read with no
// surrounding context at all — no bearer header, no assignment in front of it.
// The Credentials and Secrets table on the page listing the predefined DLP
// profiles divides the body, and is the one page that does: cfk_ followed by
// forty alphanumeric characters and an eight character hex checksum. So the
// prefix, both counts and both character classes are read off what the vendor
// publishes about its own format, and none of the four is read off a value
// somebody was shown.
//
// Everything behind the prefix is the other half of the format the tokens are
// written in, and this scan reads that half rather than spelling it again:
// cloudflareCredentialBodyChars and isCloudflareCredentialBody in
// builtin_cloudflare_api_token.go, where the counts and the two character
// classes are stated once and carry the vendor's name for that reason. The
// format page states them once over all three credentials, so neither pattern
// can move them alone, and a second copy here is a copy that could come to
// disagree while both scans went on passing. What is this pattern's own is the
// prefix, and it is the whole of what separates a key from a token.
//
// The keys issued before the format changed are not read, and cannot be. A key
// then was a lowercase hexadecimal string of thirty-seven to forty-five
// characters with nothing in front of it — no prefix, no checksum, no structure
// of any kind — and a scan anchored on nothing but a run of hexadecimal in that
// range is a scan of every git SHA, every MD5, every SHA-1 and every hex blob a
// log line carries, since forty of those characters is a SHA-1 exactly. It is
// the one thing a pattern in this package may not be. Nothing was revoked when
// the format changed, so such keys are live and are left in the output whole;
// Cloudflare's own profile row declines them in the same words, saying only
// credentials generated after the format update are matched. The prefix is the
// whole of what makes this format readable.
//
// What a candidate is tested against is the whole prefix, four characters
// closing on the underscore. One prefix is what this pattern has, so the whole
// of it is compared at once, where the token scan shares a prefix table between
// two and reads the length it matched. The underscore is what makes the prefix
// rare in the text this library is pointed at: cfk written as a word is not,
// and cfk_ is not written at all outside a snake_case name whose segment is
// spelled that way. Test_cloudflareAPIKeyPrefix holds the prefix to closing on
// a character no body is written with, and to coming to fifty-two characters
// with the body behind it.
//
// There is no boundary on either side of a match. A word boundary in front
// would drop the whole match rather than trim it wherever a key is written
// against a word character, as CLOUDFLARE_API_KEY_cfk_... is, and one behind it
// would drop a key followed by a character of the checksum's own alphabet. What
// may stand either side is held back by the character classes and the two
// counts alone.
//
// The tightening on offer in front is the one the Slack and Stripe scans take:
// to ask that no letter and no digit stand before the prefix. It is declined
// for the AWS scan's reason, and what it would turn away here is narrow enough
// to name. No word is spelled cfk, so what could reach the prefix is a
// snake_case name whose last segment is those three characters — and that test
// admits the underscore, so such a name would pass it unchanged and the
// tightening would not turn it away either. What it would cost is a key written
// straight against a letter, which would then be left in the output whole
// rather than trimmed.
//
// The checksum is read as hexadecimal of either case, and as a shape rather
// than recomputed. Both are the token scan's arguments and are bought here at
// the same price, since it is the same checksum over the same secret: reading
// lowercase alone would be tighter than the vendor's own wording and would
// locate nothing at all the day an encoder wrote one in uppercase, where
// reading either case costs a tail at most; and a key whose secret is intact
// and whose checksum was mistyped, truncated in transit or rewritten by an
// example generator is still a secret somebody can read, where a scan verifying
// the checksum would leave every one of them in the output.
// Test_CloudflareAPIKey_checksumIsNotVerified pins the second of those.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a key or not, and here advancing rather than consuming the
// match is load-bearing rather than a habit. A key can be written inside
// another, and how far in is settled by the prefix in two steps rather than
// chosen. The prefix closes with an underscore and no body is written with one,
// so that underscore has to fall past the first key's last character: the
// overlap is at most the three characters in front of it, and all three land in
// the eight character checksum. Standing in a checksum they then have to be
// hexadecimal, which cfk is not and cf is — so a second key begins at the last
// character of the first, where c alone stands inside it and fk_ is written
// after, or at the character before that, where cf stands inside and k_ is.
// Consuming the first match would step over the second and leave it in the
// output whole. The two spans then overlap, which a Masker resolves into one.
// Test_CloudflareAPIKey_aKeyBeginningInsideAnother drives both positions, and
// what rules out the third is that a value whose checksum held cfk would not be
// a key — which the fuzz target holds against a reference knowing none of
// this.
//
// The scan keeps no cursor and needs none: a candidate reads at most fifty-two
// bytes and stops, which bounds what it reads with no state to be wrong about —
// the guarantee a scan reading a body to the end of its run has to buy with a
// run cursor instead, bought here by the counts being counts.
//
// What this pattern over-matches on: fifty-two characters of the right shape
// that nobody issued. Four characters have to be written, spelling no word and
// closing on an underscore, then exactly forty letters and digits, then exactly
// eight hexadecimal digits, with nothing between any of them. Standard base64
// writes no underscore at all, so a certificate, a PEM body or an embedded
// image carries no candidate at however long it runs; a base64url encoding can
// hold one, and there four characters of an alphabet of sixty-four stand where
// the prefix stands about once in seventeen million characters, with forty-eight
// more having then to carry neither character base64url adds and the last eight
// of them to be hexadecimal. Outside an encoding what is left is a snake_case
// name whose segment is spelled cfk, followed by forty-eight unbroken letters
// and digits.
//
// The collision a prefix leaves where everything behind it is one class is a
// digest written there, and this format pays it rather than ruling it out, for
// the reason the token scan pays it: hexadecimal digits are letters and digits,
// and the last eight characters of a digest are hexadecimal because all of it
// is, so cfk_ and the first forty-eight characters of a SHA-256 are a key to
// this scan and the sixteen left over stay in the text. There is nothing left to
// tell the two apart at that point — the vendor's own format is a prefix and
// forty-eight characters whose last eight are hexadecimal — so a scan declining
// a digest behind this prefix declines the keys whose secret happens to be
// written in the same sixteen characters. A SHA-1 is forty characters and an
// MD5 thirty-two, so neither reaches the count and both are left alone.
// Test_CloudflareAPIKey_aDigestBehindThePrefix pins all three.
//
// What reaches a span is never prose, never a git SHA and never an MD5. A key
// holds an underscore at its fourth character and nowhere else, and holds no
// space.
//
// referenceCloudflareAPIKey in builtin_cloudflare_api_key_test.go keeps the
// grammar as a regular expression, spelling the prefix, both counts and both
// character classes again so that the two are changed together, and the fuzz
// target beside it holds this scan to that expression.
var cloudflareAPIKey = NewPattern("cloudflare-api-key", func(src string) []Span {
	var spans []Span

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], cloudflareAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for the
		// reason the rationale above gives: a checksum closing on cf carries the
		// opening of the prefix, so a key can begin one or two characters before the
		// one in front of it ends. Stepping one byte past the anchor is what leaves
		// the next candidate one byte past this one, which builtin_scan.go sets out.
		offset = anchor + 1

		if anchor < cloudflareAPIKeyAnchorIndex {
			continue
		}
		start := anchor - cloudflareAPIKeyAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != cloudflareAPIKeyPrefix[0] || !strings.HasPrefix(src[start:], cloudflareAPIKeyPrefix) {
			continue
		}

		body := start + len(cloudflareAPIKeyPrefix)
		if end := body + cloudflareCredentialBodyChars; end <= len(src) && isCloudflareCredentialBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
})

// cloudflareAPIKeyPrefix is what a key opens with and what the scan reads back
// from its anchor. It is the whole prefix rather than a part of it, which is
// what one prefix affords and two do not, and it stands at the start of a
// candidate, so what the scan tests is the whole of what opens a key.
//
// Test_cloudflareAPIKeyPrefix holds it to the two things this arrangement
// rests on: that it closes with a character no body is written with, which is
// what turns away a candidate whose body opens with a prefix of its own and
// what caps how far a key reaches into another — the underscore has to fall
// past the first key's last character, so the overlap is at most the three
// characters in front of it; and that it leaves a fifty-two character key with
// the body behind it, which is the count the sentence on CloudflareAPIKey
// promises a caller.
const cloudflareAPIKeyPrefix = "cfk_"

// cloudflareAPIKeyAnchor is the byte the scan searches the input for and
// cloudflareAPIKeyAnchorIndex is where it stands in the prefix, so a candidate
// begins that many bytes in front of what a search reported. builtin_scan.go
// says why a scan searches for one byte of its prefix rather than for the
// prefix itself; what makes it this byte is that the k is the one character of
// cfk_ ordinary text does not carry. Over the log line these benchmarks are
// written on the c stands four times — the word calling, the vendor's own name,
// the com behind it and the client path — and the k not once. The underscore is
// rarer still there and is passed over for the reason the token scan beside
// this one gives: it is
// what an environment variable, a snake_case name and a log field are written
// with, so a scan anchored on it opens a candidate on a great deal of ordinary
// text to reject it again.
const (
	cloudflareAPIKeyAnchor      = 'k'
	cloudflareAPIKeyAnchorIndex = 2
)
