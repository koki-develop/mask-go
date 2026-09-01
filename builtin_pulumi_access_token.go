package mask

import "strings"

// PulumiAccessToken locates Pulumi access tokens: the prefix pul- and the forty
// lowercase hexadecimal characters behind it — forty-four characters
// altogether. One string serves the token a user creates for themselves, the
// token an organization is issued and the token a team is issued, so nothing in
// a token says which of the three it authenticates as.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly forty-four characters of it are. So text of that shape is
// redacted whether or not Pulumi issued it. A space, an uppercase letter, a
// letter past f or a body of the wrong length ends the reading, so text as it is
// ordinarily written is not affected.
//
// Its name is "pulumi-access-token".
func PulumiAccessToken() Pattern { return pulumiAccessToken }

// Access token is Pulumi's own name for this string, and it is the term that
// covers the whole of what this scan locates. Pulumi Cloud issues three kinds —
// a personal token carrying what its user can do, an organization token
// authenticating as the organization and a team token authenticating as a team
// within one — and its documentation keeps them on one page under that title,
// the environment variable every tool reads one from is PULUMI_ACCESS_TOKEN,
// and the token exchange the CLI's OIDC login goes through asks for a
// requested_token_type of urn:pulumi:token-type:access_token:organization and
// returns it as an AccessToken. The three are one string with the same prefix
// and no mark on it to tell them apart, which is why they put no boundary
// between patterns: a caller cannot act on a distinction the value does not
// carry, and none of them could be enabled without the others.
//
// What Pulumi states about the format is the prefix and nothing else. The post
// announcing the GitHub token scanning partnership says only that tokens
// generated after 28 June 2019 carry pul-; the REST API pages say to send the
// token in an Authorization header and stop there; the CLI stores what it is
// given, sends it as a bearer string and validates no shape, so its own tests
// authenticate with pul-secret-token and pul-test-access-token. No length, no
// alphabet and no checksum appears in any of them, and no whole token is
// printed on any page Pulumi publishes.
//
// What states the rest is the rulesets, and they agree on the count. gitleaks
// reads pul- and forty of [a-f0-9] under an entropy floor; kingfisher reads the
// same class and count, citing gitleaks for it; trufflehog reads pul- and forty
// of [a-z0-9], which is the same count through a wider class. Forty is
// therefore what every rule reading this format asks for, and it is what the
// count below is.
//
// The entropy floors two of them carry — gitleaks at two, kingfisher at 3.3 and
// two digits in the body besides — are not read here. They are demands on how
// the bytes of a random body happened to fall rather than parts of the format,
// and a scan reading one would be deciding whether a value is a credential by
// how ordinary it looks. What declining them costs is the run of the right
// shape whose body is too regular for a generator to have drawn: pul- and forty
// zeros is redacted here and turned away by both floors. What taking one would
// cost is a token whose body fell that way, which nothing but chance rules out
// and which a redaction library may not leave in the output.
// Test_PulumiAccessToken_aBodyBelowTheEntropyFloors pins the decision.
//
// The alphabet is read as lowercase hexadecimal, and the widening on offer is
// trufflehog's class, which admits every lowercase letter besides. It is
// declined. Forty hexadecimal characters are twenty bytes written by a
// hexadecimal encoder, which settles the case once for the whole of its output
// and is the shape a token of that length ordinarily is, where forty
// characters of a thirty-six character alphabet is a width nothing announces.
// The fragments of tokens Pulumi's own pages print are written in hexadecimal
// as well — pul-d2d2… on the pages configuring a deployment runner,
// pul-fa..REDACTED..fa in the post walking through the REST API and pul-abc123
// in the post on property search — where the two placeholders beside them,
// pul-xxx and pul-xxxxxxxx, are written in no alphabet at all. That is
// suggestive rather than decisive, and it points the same way the two rulesets
// do. What the wider class would buy is a token neither Pulumi nor a ruleset
// writes; what it would cost is forty characters of base36 behind a four
// character prefix, which is a net cast wider than the format any published
// rule reads. Test_PulumiAccessToken_aBodyPastHexadecimal pins the decision,
// and Test_PulumiAccessToken_anUppercaseBody pins the other half of the class,
// so that widening either is a change somebody argues for rather than one
// somebody notices afterwards.
//
// The count is read exactly rather than as a floor. A run longer than forty is
// not one longer token but a token with something written after it, and only
// the token is redacted; running the alphabet out instead would swallow
// whatever was written against the end of one. Pulumi states no second shape
// behind this prefix, so reading it exactly turns away nothing a range would
// have caught.
//
// There is no boundary on either side of a match. A boundary in front drops
// rather than trims the match wherever a token is written against a word
// character, which is what PULUMI_ACCESS_TOKEN_pul-... is; one behind it drops
// a token followed by a character of the body's own alphabet, which under an
// exact count is a token with a character written after it. What may stand
// either side is held back by the character class and the count alone. All
// three rulesets ask for both boundaries, and what the one in front buys them
// is weighed with the digest below, which is where it is reachable.
//
// No token can be written inside another, and what this scan rests that on is
// the letter its prefix opens with. Everything a span covers is the four
// characters of the prefix and forty hexadecimal digits, and the p the prefix
// opens with is neither of the two letters behind it in the prefix, is not the
// hyphen closing it and is no character a body may hold. So no position inside
// a span opens a prefix, and the spans of this pattern never overlap one
// another. Test_PulumiAccessToken_noTokenBeginsInsideAnother is what holds the
// claim.
//
// The scan resumes one byte past the start of a candidate all the same, which
// is the default, and what it is for here is the candidate that did not become
// a token rather than the one that did. pul-pul- and forty digits is a
// candidate at the first prefix whose body opens with a p no body may hold, and
// a whole token at the second; a scan resuming past the length the first
// candidate hoped for would step over it.
//
// The scan keeps no cursor and needs none: a candidate reads at most forty-four
// bytes and stops, which bounds what it reads with no state to be wrong about,
// and is what rules out a quadratic input.
//
// The byte the scan searches the input for is the u of the prefix, and the
// prefix is read back from it. builtin_scan.go says why a scan searches for one
// byte of its prefix rather than for the prefix itself; what makes it this byte
// is that none of the four is rare and the choice is between near equals. No
// character of the prefix is written in the body's alphabet, so a hexadecimal
// run stops the search not once whichever is chosen, and each of them stands
// once in the prefix, so a run of prefixes stops it once a prefix. Over the
// conformance corpus the u is the rarest of the three letters by a wide margin,
// standing about three quarters as often as the l and three fifths as often as
// the p, and over the log line these benchmarks are written on the three stand
// within one of each other, the u five times against the l's four and the p's
// six. The hyphen the prefix closes with is rarer again on that one line, and is
// the byte not to anchor on: it is what every ISO timestamp, every UUID and
// every hyphenated word is written with, and it is the commonest of the four
// over the corpus. Anchoring on the p would buy nothing either, since the p is
// what a candidate is read back to and is the byte tested first below, so a scan
// anchored on it pays a comparison of the whole prefix where this one pays one
// byte.
//
// What this pattern over-matches on is forty lowercase hexadecimal characters
// written behind the prefix, which is the format every rule reading it asks
// for, and the shape worth stating is the digest: a SHA-1 is forty hexadecimal
// characters, so pul- written straight in front of one is a token character for
// character and the whole of it is redacted. An MD5 is thirty-two and is turned
// away by the count; a SHA-256 is sixty-four, so with no boundary behind a
// match its first forty characters are a body and the prefix and a SHA-256 is
// redacted for forty-four of its sixty-eight characters, with the twenty-four
// left over staying in the text.
//
// The demand in front of a match that the rulesets write is what makes the
// second of those reachable, and declining it is what this pattern pays. The
// name a content-addressed asset is written under is a word, a hyphen and a
// digest, and where that word ends in the letters pul the digest behind it is
// read as a body — which is the false positive gitleaks carries a case for,
// vipul- and a SHA-256 among them. What the demand would cost is a token
// written straight against a letter or an underscore, which would then be left
// in the output whole rather than trimmed, and PULUMI_ACCESS_TOKEN_pul-... is
// how a token reaches a log line from a shell. A token left whole is the
// failure this library is for, and forty characters of a digest are a value
// that was already opaque, so the demand is declined and
// Test_PulumiAccessToken_aDigestBehindThePrefix pins both halves.
//
// What reaches a span is never prose: forty unbroken hexadecimal characters
// behind three letters and a hyphen is longer than anything prose is written
// in, and a word running into the prefix runs the body out at its first
// character outside hexadecimal, which twenty of the twenty-six letters are.
// A hexadecimal run cannot carry the prefix however long it runs, since none of
// its four characters is written in that alphabet, so no digest and no
// identifier holds one partway along.
//
// The credential exchanged for one of these is not read here: the OIDC ID token
// the CLI hands over is a JWT, which is a format of its own and has a pattern of
// its own. It is a credential this pattern does not name rather than one the
// scan happens to miss.
//
// referencePulumiAccessToken in builtin_pulumi_access_token_test.go keeps the
// grammar as a regular expression, spelling the prefix, the count and the
// character class again so that the two are changed together, and the fuzz
// target beside it holds this scan to that expression.
var pulumiAccessToken = newBuiltin("pulumi-access-token", &pulumiAccessTokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two.
	retain := pulumiAccessTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], pulumiAccessTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not. No
		// token can be written inside another, which the rationale above argues, so
		// what this is for is the candidate that failed: pul-pul- and a body carries
		// a whole token at its second prefix, and resuming past the length this
		// candidate hoped for would step over it.
		offset = anchor + 1

		if anchor < pulumiAccessTokenAnchorIndex {
			continue
		}
		start := anchor - pulumiAccessTokenAnchorIndex

		// The byte the prefix opens with is tested before the prefix is
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != pulumiAccessTokenPrefix[0] || !strings.HasPrefix(src[start:], pulumiAccessTokenPrefix) {
			continue
		}

		body := start + len(pulumiAccessTokenPrefix)
		end := start + pulumiAccessTokenChars
		if end > len(src) {
			// The input ends inside this candidate, so the count that is the
			// whole of what tells it from anything else written behind the
			// prefix cannot be taken here.
			retain = min(retain, start)
			continue
		}
		if isPulumiAccessTokenBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// pulumiAccessTokenPrefix is what every access token opens with, and what
	// the scan reads back from its anchor. It is the one thing Pulumi publishes
	// about this format, and two of its characters are load-bearing.
	//
	// The p it opens with it carries nowhere else and no body may hold, which
	// is the whole of the claim that no token can begin inside another. The
	// hyphen it closes with belongs to no body either, so a run of body
	// characters can never hold the prefix and every body begins where such a
	// run begins — which is not what bounds this scan, since the count is, but
	// is what a count relaxed to a floor would have to fall back on.
	// Test_pulumiAccessTokenPrefix holds the prefix to both.
	pulumiAccessTokenPrefix = "pul-"

	// pulumiAccessTokenAnchor is the byte the scan searches the input for and
	// pulumiAccessTokenAnchorIndex is where it stands in the prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what made it
	// this byte and how close the choice was.
	pulumiAccessTokenAnchor      = 'u'
	pulumiAccessTokenAnchorIndex = 1

	// pulumiAccessTokenBodyChars is how many hexadecimal characters stand
	// behind the prefix: the count every published rule reading this format
	// asks for.
	pulumiAccessTokenBodyChars = 40

	// pulumiAccessTokenChars is the whole of a token, the prefix and the count
	// above. Test_pulumiAccessTokenChars holds it to forty-four.
	pulumiAccessTokenChars = len(pulumiAccessTokenPrefix) + pulumiAccessTokenBodyChars
)

// isPulumiAccessTokenBody reports whether s is everything behind the prefix of a
// token: exactly pulumiAccessTokenBodyChars lowercase hexadecimal characters.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count left to the caller to have cut correctly.
func isPulumiAccessTokenBody(s string) bool {
	if len(s) != pulumiAccessTokenBodyChars {
		return false
	}
	for i := range len(s) {
		if !isPulumiAccessTokenBodyByte(s[i]) {
			return false
		}
	}
	return true
}

// isPulumiAccessTokenBodyByte reports whether c is a lowercase hexadecimal
// digit, which is what a body is written in.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go,
// which hold what more than one scan reads. Every hexadecimal run this package
// reads keeps its own test for the reason its own file gives — one admits
// either case where another admits lowercase alone — and a shared test named
// for the class rather than for what reads it would silently be the wrong
// answer for one of them.
func isPulumiAccessTokenBodyByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f'
}

// pulumiAccessTokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var pulumiAccessTokenTail = newPrefixTail(pulumiAccessTokenPrefix)
