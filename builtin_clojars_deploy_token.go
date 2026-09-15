package mask

import "strings"

// ClojarsDeployToken locates Clojars deploy tokens: the prefix CLOJARS_ and the
// sixty lowercase hexadecimal characters behind it — sixty-eight characters
// altogether. A deploy token stands in for the password of the account that
// created it, so one publishes artifacts as that account.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly sixty-eight characters of it are. So text of that shape is
// redacted whether or not Clojars issued it. An uppercase letter, a character
// outside hexadecimal or a run of fewer than sixty characters ends the reading,
// so text as it is ordinarily written is not affected. A longer run is a token
// with something written after it, and the token alone is redacted.
//
// Its name is "clojars-deploy-token".
func ClojarsDeployToken() Pattern { return clojarsDeployToken }

// Deploy token is Clojars' own name for this string: the wiki page a caller is
// sent to is headed Deploy Tokens, the function that mints one is
// generate-deploy-token, and the table it is written into is deploy_tokens.
// gitleaks calls this an API token, which is a term Clojars itself does not use
// for it, so it is not the name here.
//
// The whole of the grammar is the vendor's own, and it comes from the code that
// issues the credential rather than from anything written about it.
// generate-deploy-token in clojars-web writes CLOJARS_ in front of thirty bytes
// of SecureRandom put through hexadecimalize, which formats each byte as two
// characters and lowercases the result — sixty lowercase hexadecimal characters.
// Beside it stands is-deploy-token?, the vendor's own answer to whether a value
// is token shaped, anchored at both ends and asking for exactly that. So the
// prefix, the alphabet, the case and the count are four things Clojars states
// rather than four things read off values somebody held.
//
// What the rulesets add is corroboration and nothing the grammar rests on.
// gitleaks carries a rule, reading CLOJARS_ and sixty characters of letters and
// digits without regard to case; noseyparker, trufflehog and secretlint carry
// no Clojars rule, and kingfisher reads this format through betterleaks' rule
// rather than one of its own. That rule agrees with the vendor on the count and
// is wider than the vendor in three places: base36 where Clojars writes
// hexadecimal, either case in the body where Clojars lowercases, and either
// case in the prefix, which its (?i) reaches as well. Reading the narrower of
// the two is not a tightening resting on a ruleset's silence: it is the format
// the vendor's own generator writes and its own validator accepts — anchored at
// both ends and case-sensitive — and a value outside it is one Clojars would
// not take as a token. Test_ClojarsDeployToken_aWiderAlphabet,
// Test_ClojarsDeployToken_anUppercaseBody and the lowercase prefix among the
// cases of Test_ClojarsDeployToken_noMatch pin the three of them, so widening
// any is a change somebody argues for.
//
// The count is read exactly rather than as a floor. A run longer than sixty is
// not one longer token but a token with something written after it, and only
// the token is redacted; running the alphabet out instead would swallow
// whatever was written against the end of one. Clojars states no second shape
// behind this prefix, so reading it exactly turns away nothing a range would
// have caught.
//
// There is no boundary on either side of a match. A boundary in front drops
// rather than trims the match wherever a token is written against a word
// character, and a token written straight behind another is one of those: a
// body closes on a hexadecimal digit, so the prefix of the second stands
// against a letter or a digit with nothing between. One behind drops a token
// followed by a letter or a digit, which under an exact count is a token with a
// character written after it. What may stand either side is held back by the
// character class and the count alone.
// Test_ClojarsDeployToken_nextToWordCharacters writes both out.
//
// The byte the scan searches the input for is the J of the prefix, and the
// prefix is read back from it. builtin_scan.go says why a scan searches for one
// byte of its prefix rather than for the prefix itself; what makes it this byte
// is how rarely it is written. None of the eight is a character a body is
// written in, so any of them would leave a run of the body alphabet stopping
// the search not once however long it runs, and the choice between them is
// what an ordinary text costs. The underscore is written in every snake_case
// identifier and every environment variable name; the C, the L, the O, the A,
// the R and the S are the letters a log level, an HTTP method and an acronym
// are spelled in. The J is written in almost none of that.
// Test_clojarsDeployTokenFindBenchmarks_lineTheAnchorWasChosenAgainst holds the
// line these benchmarks are written on to the counts that reasoning rests on.
//
// No token can begin inside another, and where the anchor may stand is what
// settles it. The J is no character a body is written in and it is written once
// in the prefix, so a token carries exactly one, at the fourth character of its
// prefix — which is where the scan reads a candidate back from, and so the only
// candidate a token holds is the token itself.
// Test_clojarsDeployTokenAnchor and Test_clojarsDeployTokenPrefix hold the two
// halves of that, and Test_ClojarsDeployToken_noTokenBeginsInsideAnother drives
// what the scan does with it.
//
// The scan steps one byte past the start of a candidate all the same, whether
// that candidate became a token or not, which is the default and which the
// claim above is no reason to widen: what the step has to reach is a token
// beginning inside a candidate that is no token, as the second CLOJARS_ of
// CLOJARS_CLOJARS_ and a body does.
// Test_ClojarsDeployToken_aPrefixInFrontOfAToken writes that out.
//
// The scan keeps no cursor and needs none: a candidate reads at most sixty-eight
// bytes and stops, which bounds what it reads with no state to be wrong about,
// and is what rules out a quadratic input.
//
// Where a token ends is settled by the token, so the only candidate this scan
// holds on to is one the end of the input cut short, which it reports at the
// candidate's start. It reads nothing in front of a value either: the prefix is
// eight characters and decides on its own whether a token stands somewhere.
//
// What this pattern over-matches on is sixty lowercase hexadecimal characters
// written behind the prefix, which is the vendor's format exactly, and the
// shape worth stating is the digest. No digest in common use is sixty
// hexadecimal characters: an MD5 is thirty-two, a SHA-1 forty, a SHA-224
// fifty-six and a SHA-256 sixty-four. So none of them written behind the prefix
// is a token's length — the first three fall short of the count and locate
// nothing, and a SHA-256 is redacted for sixty with its last four characters
// left in the text. Test_ClojarsDeployToken_aDigestBehindThePrefix pins all
// four. What would have to be written to reach a span at all is the prefix with
// sixty hexadecimal characters against it and nothing between, and there is
// nothing left to tell such a run from a token — a scan declining it would
// decline every real token of the same shape.
//
// What reaches a span is never prose: sixty unbroken hexadecimal characters
// behind seven uppercase letters and an underscore is longer than anything
// prose is written in, and a word running into the prefix runs the body out at
// its first character outside hexadecimal, which twenty of the twenty-six
// letters are.
//
// A hexadecimal run cannot carry the prefix however long it runs, since none of
// its characters is written in that alphabet, so no digest and no UUID holds
// one partway along. Neither can standard base64 or base32, which write no
// underscore; only base64url can, and there the prefix and a body together —
// eight characters fixed out of an alphabet of sixty-four, then sixty drawn
// from the sixteen of those sixty-four that hexadecimal writes — stand about
// once in a number of characters fifty-one digits long. What is taken anywhere
// near that is a stretch of a value that was already opaque.
//
// The other credential Clojars keeps is a password reset code, which this
// pattern does not read and could not: it is forty hexadecimal characters with
// no prefix at all, which is a git SHA and an identifier as much as it is a
// code, and a grammar admitting it is the one AllBuiltinPatterns may not grow.
// Test_ClojarsDeployToken_theCredentialThatCarriesNoPrefix pins the decision.
//
// referenceClojarsDeployTokenFind in builtin_clojars_deploy_token_test.go keeps
// the grammar as a regular expression, spelling the prefix, the count and the
// alphabet again so that the two are changed together, and the fuzz target
// beside it holds this scan to that expression.
var clojarsDeployToken = newBuiltin("clojars-deploy-token", &clojarsDeployTokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// states both, and this scan has no third — a token's length is fixed, so
	// nothing written behind a whole one can widen the span it reports.
	retain := clojarsDeployTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], clojarsDeployTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not,
		// which is the default. The rationale above says what it reaches:
		// a prefix written in front of a prefix leaves the token opening at the
		// second, and a scan stepping over what it read would lose it.
		offset = anchor + 1

		if anchor < clojarsDeployTokenAnchorIndex {
			continue
		}
		start := anchor - clojarsDeployTokenAnchorIndex

		// The byte the prefix opens with is tested before the prefix is
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != clojarsDeployTokenPrefix[0] || !strings.HasPrefix(src[start:], clojarsDeployTokenPrefix) {
			continue
		}

		body := start + len(clojarsDeployTokenPrefix)
		end := start + clojarsDeployTokenChars
		if end > len(src) {
			// The input ends inside the body, and the count is the whole of
			// what tells a token from any other run written behind the prefix.
			retain = min(retain, start)
			continue
		}
		if !isClojarsDeployTokenBody(src[body:end]) {
			continue
		}

		spans = append(spans, Span{Start: start, End: end})
	}
	return spans, retain
})

const (
	// clojarsDeployTokenPrefix is what every deploy token opens with, and what
	// the scan reads back from its anchor. Every one of its characters stands
	// outside the alphabet a body is written in, which is what makes the search
	// cheap on a line of digests and half of what leaves no token able to begin
	// inside another; Test_clojarsDeployTokenPrefix holds it to that.
	clojarsDeployTokenPrefix = "CLOJARS_"

	// clojarsDeployTokenAnchor is the byte the scan searches the input for and
	// clojarsDeployTokenAnchorIndex is where it stands in the prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what made it
	// this byte. Test_clojarsDeployTokenAnchor holds it to standing at that one
	// index and nowhere else in the prefix.
	clojarsDeployTokenAnchor      = 'J'
	clojarsDeployTokenAnchorIndex = 3

	// clojarsDeployTokenBodyChars is how many hexadecimal characters stand
	// behind the prefix: the thirty bytes generate-deploy-token draws from
	// SecureRandom, two characters to a byte.
	clojarsDeployTokenBodyChars = 60

	// clojarsDeployTokenChars is the whole of a token: the prefix and the count
	// above. Test_clojarsDeployTokenChars holds it to sixty-eight.
	clojarsDeployTokenChars = len(clojarsDeployTokenPrefix) + clojarsDeployTokenBodyChars
)

// isClojarsDeployTokenBody reports whether the whole of s is written in the
// alphabet a body is written in.
//
// The count is the caller's rather than this walk's: the scan cuts s between
// the end of the prefix and the whole width of a token, two constants that
// differ by exactly the count, so what reaches here is that many characters and
// the alphabet is all there is left to answer for.
func isClojarsDeployTokenBody(s string) bool {
	for i := range len(s) {
		if !isClojarsDeployTokenBodyByte(s[i]) {
			return false
		}
	}
	return true
}

// isClojarsDeployTokenBodyByte reports whether c is a lowercase hexadecimal
// digit, which is the case hexadecimalize leaves every character of a body in.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go,
// which hold what more than one scan reads. Every hexadecimal run this package
// reads keeps its own test for the reason its own file gives — one admits
// either case where another admits lowercase alone — and a shared test named
// for the class rather than for what reads it would silently be the wrong
// answer for one of them.
func isClojarsDeployTokenBodyByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f'
}

// clojarsDeployTokenTail is what the scan settles the tail of its input by, for
// the piece of a prefix standing at the end of it. prefixTail
// (builtin_scan.go) says what that is and why it is built once.
var clojarsDeployTokenTail = newPrefixTail(clojarsDeployTokenPrefix)
