package mask

import "strings"

// OpenRouterAPIKey locates OpenRouter API keys: the prefix sk-or-v1- and the
// sixty-four hexadecimal digits behind it — seventy-three characters
// altogether. One string serves every model OpenRouter routes to and every
// provider behind them, so nothing in a key says what it may be spent on.
//
// A key is located wherever it is written, with no word boundary either side,
// and exactly seventy-three characters of it are. So text of that shape is
// redacted whether or not OpenRouter issued it. A space, a letter past f, or a
// run of fewer than sixty-four hexadecimal digits ends the reading, so text as
// it is ordinarily written is not affected. A longer run is a key with
// something written after it, and the key alone is redacted.
//
// Its name is "openrouter-api-key".
func OpenRouterAPIKey() Pattern { return openRouterAPIKey }

// What OpenRouter states about this format it states by printing a whole key,
// which is more than a vendor page abbreviating a key to its prefix and an
// ellipsis states, and less than a published generator does. The response that
// creates a key is the one place a key is ever shown whole — OpenRouter's own
// documentation says the plaintext value appears there and cannot be read back
// — and the example it carries is sk-or-v1- and sixty-four hexadecimal digits,
// seventy-three characters altogether. Everywhere else the same documentation
// writes the label a key is listed under, sk-or-v1-abc...123, which states the
// prefix and abbreviates the rest.
//
// The rulesets agree, and on this format they agree exactly rather than
// approximately. trufflehog reads sk-or-v1- and sixty-four lowercase
// hexadecimal digits; betterleaks reads the same and drops what falls at or
// below an entropy floor; kingfisher reads the same spelled with a POSIX class
// and matched case-insensitively. No published rule reads a range of lengths, a
// floor on the count, or a second shape behind the same prefix.
//
// GitHub carries it too, as a partner pattern under the token identifier
// openrouter_api_key, with push protection and a validity check. A partner
// pattern is one the vendor wrote and gave to GitHub rather than one somebody
// inferred from published keys, so the agreement above is agreement with
// OpenRouter and not only between readers of the same examples.
//
// The count is therefore read exactly. A scan declines an exact count where
// its vendor states no length, since a count that is wrong there costs the
// whole credential rather than the end of one. The same asymmetry holds here
// and is answered by the prefix rather than by the count: sk-or-v1- carries a
// version, so a key whose shape is not this one is a key whose prefix is not
// this one either. A scan reading sk-or-v1- is already pinned to whatever v1
// means, and the day v2 is issued it locates nothing whether it counted
// sixty-four characters or read a run — so the count adds no staleness the
// prefix does not already have, which is what a prefix carrying no version
// segment cannot say. What an exact count costs is what it costs everywhere: a
// run longer than the count is not one longer key but a key with something
// written after it, and only the key is redacted.
//
// The alphabet is hexadecimal, isOpenRouterAPIKeyBodyByte below, read in either
// case where every published key and two of the three rulesets are lowercase
// alone. It is the Grafana checksum's argument and is bought for the same
// price: the nine characters of the prefix have already decided the match, so
// no text is admitted by the wider class that the narrower one would have
// turned away in practice. What the narrower one would cost is the day
// OpenRouter writes a body in uppercase — the same prefix, and a body a scan
// asking for lowercase alone locates nothing of, leaving every character of a
// live key in the output.
//
// The prefix itself is read in one case, which is a separate decision and the
// Grafana scan's: a prefix is the whole of what tells a format from text, so
// loosening it buys nothing and costs over-matching. It also bounds the
// paragraph above — a key a caller upper-cased whole is one this pattern
// locates nowhere, whatever the body's class admits, and the case named "an
// uppercase prefix" in builtin_openrouter_api_key_test.go pins that.
//
// There is no boundary on either side of a match, and here that is a
// disagreement with all three rulesets rather than with none of them, since
// each of the three writes a word boundary at both ends. A boundary in front
// drops rather than trims the match wherever a key is written against a word
// character, which is what OPENROUTER_API_KEY_sk-or-v1-... is and what a shell
// writes into a log line; one behind it drops a key followed by a hexadecimal
// digit, which under an exact count is a key with a character written after
// it. What may stand either side is held back by the character class and the
// count alone.
//
// The tightening on offer in front is the one the Slack and Stripe scans take:
// to ask that no letter and no digit stand before the prefix. It is declined
// for the AWS scan's reason, and what it would turn away is narrow enough to
// name. No word is spelled sk-or-v1-, and the prefix closes with a hyphen
// rather than with a letter, so a snake_case name cannot reach it at all. What
// can is a hyphenated word whose first segment closes on sk and whose next two
// are or and v1 — risk-or-v1- is the shape, and what has then to follow it is
// sixty-four hexadecimal digits. Against that stands the assignment above,
// which is text people write.
//
// No key can be written inside another, which is what lets this scan resume at
// the body of a candidate rather than a byte past its start. A candidate
// begins where sk-or-v1- begins, and the only s a span covers is the one it
// opens with: the rest of the prefix is k, o, r, v, a digit and three hyphens,
// and a body is hexadecimal, which spells no s either. The 1 of the version is
// the one character of the prefix a body may also be written with, and it
// opens nothing. So the spans of this pattern never overlap one another, and
// Test_OpenRouterAPIKey_noKeyBeginsInsideAnother drives the shapes that would
// find that wrong.
//
// The scan resumes at the body of a candidate whether that candidate became a
// key or not — nine characters along rather than one. It steps over nothing,
// since what those nine characters are is the prefix that has just matched and
// no s stands inside it. Resuming at the start of the candidate instead would
// find the same prefix again and never advance. Resuming past a whole match
// would step over nothing either, by the paragraph above, but it would say
// something the failing candidates cannot: a candidate that is not a key has no
// match to resume past, and reading its sixty-four characters twice is the work
// the body of a candidate is nine characters wide to avoid.
//
// The reference beside this scan is written to know none of that. It starts
// afresh at every byte, so a key nested inside another is one it would find
// and this scan would not, and the fuzz target between them is what holds the
// claim. That is the Stripe reference's arrangement and it is here for the
// Stripe reference's reason. The Supabase and RubyGems references ask at every
// byte too and say a different thing by it — that each restates its scan's own
// resumption rather than a shorter rule agreeing with it — where this one is
// written to restate nothing the scan claims.
//
// The scan keeps no cursor and needs none: a candidate reads at most
// seventy-three bytes and stops, which bounds what it reads with no state to
// be wrong about — the guarantee a scan reading a body to the end of its run
// has to buy with a run cursor instead, bought here by the count being a
// count.
//
// What this pattern over-matches on is one shape and it is worth stating
// plainly: sixty-four hexadecimal digits are a SHA-256, so sk-or-v1- written in
// front of a digest is redacted. That is the collision the Grafana format rules
// out with the underscore dividing its secret from its checksum, and this one
// has nothing to rule it out with — the count is a digest's count exactly. It
// is paid rather than avoided, because there is nothing left to tell the two
// apart: a key OpenRouter issued is sixty-four hexadecimal digits behind this
// prefix, so a scan declining a digest behind this prefix declines every key
// there is. What has to be written to reach it is the nine characters of the
// prefix, spelling no word and closing on a hyphen, and then a digest with
// nothing between them, which is not text anybody writes.
// Test_OpenRouterAPIKey_aDigestBehindThePrefix pins the decision.
//
// What reaches a span is never prose and never a digest on its own. A digest
// carries no hyphen, so it holds no prefix to be found at however long it runs,
// and a key carries a hyphen at its third, sixth and ninth characters and
// nowhere else, and holds no space.
//
// The OpenAI and Anthropic patterns read sk- as well, and neither locates what
// this one does. An OpenAI key is a run carrying the eight characters
// T3BlbkFJ, which hexadecimal cannot spell, and an Anthropic key names its
// kind between sk-ant- and its body. This pattern in turn locates neither of
// theirs, since sixty-four hexadecimal digits are not what either writes
// behind its own prefix. What does reach both is an OpenRouter key written
// straight in front of base64url text carrying the OpenAI marker: the key is
// seventy-three characters and the OpenAI run is everything from the same sk-
// to the end of that text, so the two spans overlap and a Masker resolves them
// into one. The conformance/builtins_together.txt corpus carries the case.
//
// The keys OpenRouter's key management endpoints are authenticated with are not
// read as a format of their own, and nothing published says they are one:
// OpenRouter's documentation names them, sends them in the same bearer header
// and prints none, while the one place it prints a key whole is the response
// that creates an inference key. So what is read is the format OpenRouter
// prints, and a management key sharing it is located by that.
//
// referenceOpenRouterAPIKey in builtin_openrouter_api_key_test.go keeps the
// grammar as a regular expression, spelling the prefix, the count and the
// character class again so that the two are changed together, and the fuzz
// target beside it holds this scan to that expression.
var openRouterAPIKey = NewPattern("openrouter-api-key", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := openRouterAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		// The byte at the resume point is tested before a search is started
		// from it. This scan resumes at the anchor of the next candidate it
		// could not rule out, so on a line of prefixes written one against the
		// next that byte is the anchor itself every time, and a search there is
		// a call into the byte scanner to be told what the comparison already
		// says. Measured on such a line those calls are the whole of what the
		// scan costs; against them this test is one byte read wherever the
		// resume point is not an anchor.
		anchor := offset
		if src[anchor] != openRouterAPIKeyAnchor {
			i := strings.IndexByte(src[anchor+1:], openRouterAPIKeyAnchor)
			if i < 0 {
				break
			}
			anchor += i + 1
		}

		// A candidate that is not one takes the default step, which is all
		// that is owed here: nothing has been read back from the anchor yet,
		// so there is no width to step over and no claim about the grammar to
		// rest a longer step on.
		offset = anchor + 1

		if anchor < openRouterAPIKeyAnchorIndex {
			continue
		}
		start := anchor - openRouterAPIKeyAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != openRouterAPIKeyPrefix[0] || !strings.HasPrefix(src[start:], openRouterAPIKeyPrefix) {
			continue
		}
		body := start + len(openRouterAPIKeyPrefix)

		// A candidate that is one resumes at the body instead, whether it
		// became a key or not, for the reason the rationale above gives: no key
		// begins inside another, and what is stepped over here is the rest of
		// the prefix that has just matched, which carries no s for a second
		// candidate to open at. What the search resumes at is the anchor of a
		// candidate beginning at the body, which is the first one left.
		offset = body + openRouterAPIKeyAnchorIndex

		end := start + openRouterAPIKeyChars
		if end > len(src) {
			// The input ends inside this candidate, so the count that is the
			// whole of what tells it from anything else written behind the
			// prefix cannot be taken here.
			retain = min(retain, start)
			continue
		}
		if isOpenRouterAPIKeyBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// openRouterAPIKeyPrefix is what every key opens with, and what the scan
	// reads back from its anchor. The version it carries is what the rationale
	// above reads the count exactly on the strength of. Two properties of it
	// are what keep one key from being written inside another, and so what let
	// the scan resume at the body rather than a byte along: the s it opens with
	// is no character a body may be written with, so no body opens a candidate,
	// and no second s stands anywhere in it, so no prefix opens inside a
	// prefix. Test_openRouterAPIKeyPrefix holds it to both.
	openRouterAPIKeyPrefix = "sk-or-v1-"

	// openRouterAPIKeyAnchor is the byte the scan searches the input for and
	// openRouterAPIKeyAnchorIndex is where it stands in the prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; what makes it this byte is that the k
	// is the one character of sk-or-v1- ordinary text does not carry. Over the
	// log line these benchmarks are written on the s stands three times, the o
	// five and the hyphen twice, and the k not once. The k stands in the prefix
	// once as well, which is what lets the scan step over the rest of it.
	openRouterAPIKeyAnchor      = 'k'
	openRouterAPIKeyAnchorIndex = 1

	// openRouterAPIKeyBodyChars is how many hexadecimal digits stand behind the
	// prefix. It is read exactly rather than as a floor, for the reason the
	// rationale above gives, and it is the count in the example OpenRouter's own
	// documentation prints and in all three rulesets that read this format.
	openRouterAPIKeyBodyChars = 64

	// openRouterAPIKeyChars is the whole of a key: the prefix and the body.
	// Test_openRouterAPIKeyChars holds it to the seventy-three characters the
	// example OpenRouter prints is.
	openRouterAPIKeyChars = len(openRouterAPIKeyPrefix) + openRouterAPIKeyBodyChars
)

// isOpenRouterAPIKeyBody reports whether s is everything behind the prefix of a
// key: exactly openRouterAPIKeyBodyChars hexadecimal digits.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count left to the caller to have cut correctly.
func isOpenRouterAPIKeyBody(s string) bool {
	if len(s) != openRouterAPIKeyBodyChars {
		return false
	}
	for i := range len(s) {
		if !isOpenRouterAPIKeyBodyByte(s[i]) {
			return false
		}
	}
	return true
}

// isOpenRouterAPIKeyBodyByte reports whether c is a hexadecimal digit, which is
// what a body is written in.
//
// It holds the same characters as isGrafanaServiceAccountTokenChecksumByte and
// is written apart from it, as isStripeKeyWordByte is written apart from
// isBase62Byte and for that reason: the two answer different
// questions. One is the class Grafana writes four bytes of a CRC32 in, the
// other is the alphabet OpenRouter writes a key's body in, and sharing the one
// function would mean that widening either — the day a checksum is encoded some
// other way, or a body admits a character hexadecimal has not got — silently
// widened the other, which is a change nothing would report. Neither belongs in
// builtin_scan.go for the same reason: what is shared there is an alphabet
// several formats are defined over, and hexadecimal is not one thing these two
// formats share but two coincidences of the same sixteen characters.
func isOpenRouterAPIKeyBodyByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'F' ||
		'a' <= c && c <= 'f'
}

// openRouterAPIKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var openRouterAPIKeyTail = newPrefixTail(openRouterAPIKeyPrefix)
