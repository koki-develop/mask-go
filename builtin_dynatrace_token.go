package mask

import "strings"

// DynatraceToken locates the tokens Dynatrace issues in the format it
// publishes: the three characters dt0, one letter and two digits naming the
// token type, then a full stop, the twenty-four characters of the public
// identifier, a second full stop and the sixty-four characters of the secret —
// ninety-six characters altogether.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly ninety-six characters of it are. So text of that shape is
// redacted whether or not Dynatrace issued it. A space, a lowercase letter in
// either portion, a full stop out of place or a portion of the wrong length
// ends the reading, so text as it is ordinarily written is not affected.
//
// Its name is "dynatrace-token".
func DynatraceToken() Pattern { return dynatraceToken }

// Dynatrace states this format itself, and states it as a grammar rather than
// as an example. Its token page divides a token into three components — a
// prefix identifying the token type, a public portion that is a twenty-four
// character public identifier, and a secret portion that is a sixty-four
// character string to be treated like a password — and then publishes the
// expression to look for tokens with, dt0[a-zA-Z]{1}[0-9]{2} and the two
// portions behind full stops, spelled [A-Z0-9]{24} and [A-Z0-9]{64}. That is
// the vendor stating the opening, both alphabets and both counts in one line,
// and the scan below reads exactly it. The page lists masking log files among
// the things it publishes the expression for, which is this library's own
// purpose written into the source it is read from.
//
// The prefix is read as a letter and two digits rather than as a table of
// prefixes, which is what the vendor's expression asks for and what its own
// pages bear out. The token page keeps a table of standard prefixes — dt0s01
// for the API token that authorizes account changes over SCIM, dt0s02, dt0s03
// and dt0s08 for OAuth2 clients, dt0s04 and dt0s09 for chat and identity
// linking, dt0s06 for an OAuth2 refresh token, dt0s16 for a platform token —
// and that table is already short of what Dynatrace writes elsewhere. The
// prefix its API pages carry is dt0c01, and the OAuth page prints a client
// identifier opening dt0s17. A scan reading a table would locate neither, and
// would have to be corrected by every kind Dynatrace adds; one reading the
// letter and the digits locates each of them the day it appears. What that
// costs is a prefix nobody issues — dt0x99 and a body of the right shape is a
// token to this scan — which is the same wager the vendor's own expression
// makes.
//
// The counts are read exactly rather than as floors, for the reason the AWS,
// GitLab and DigitalOcean scans give: a run of the alphabet longer than the
// count is not one longer token but a token with something written after it,
// and only the token is redacted. Neither count is read off a value somebody
// was shown — both are numbers Dynatrace writes in prose and again in its
// expression.
//
// Both portions are read in uppercase and the digits alone, which is the class
// the vendor's expression spells for each of them and the class every token its
// pages print is written in. gitleaks reads both without regard to case and
// leans on an entropy floor of four to hold the result down; that is a wider
// net over a body already decided by two counts and two full stops, and it
// draws in the lowercase shapes — a hexadecimal digest, a base64url payload —
// that the uppercase class turns away without any measurement to make.
//
// The token identifier is left in the text, and deliberately. Dynatrace names
// the prefix and the public portion together the token identifier and states
// that it can be safely displayed in the UI and used for logging purposes, so
// dt0c01 and twenty-four characters is not a value and this scan reports
// nothing for it — a redaction there would take away the one part of a token a
// caller is meant to keep a log by.
// Test_DynatraceToken_theTokenIdentifierIsNoValue pins it.
//
// The OAuth client secret is not read, and it is the one credential of this
// vendor's that this decision leaves in the output. Dynatrace prints a client
// identifier as dt0s17.ABCDE123, whose public portion is eight characters
// rather than twenty-four, and kingfisher reads a three part credential built
// on one — dt0[a-z][0-9]{2}, then eight to a hundred and twenty-eight
// characters, then the sixty-four of a secret — with an example of exactly that
// shape. Neither bound of that range is a number Dynatrace states anywhere: the
// eight and the hundred and twenty-eight are read off the values kingfisher was
// shown, where the twenty-four below is the count the vendor writes twice. A
// floor invented here would loosen the one part of the grammar that says this
// is a token rather than a client credential, and it would cost the fuzz
// target: a floor spelled as a counted repetition builds a machine as wide as
// the floor at every candidate, which is what a reference must not be handed.
// So the client secret is left in the output, and reading it would take a
// grammar of its own built on whatever Dynatrace comes to state about it.
// Test_DynatraceToken_aPublicPortionShorterThanTheCount pins the decision so
// that reading it is a change somebody argues for rather than one somebody
// notices afterwards.
//
// The token format that came before this one is not read either. Dynatrace
// enabled this format by default in version 1.210 and states that all existing
// tokens of the old format remain valid, so those are live credentials; what it
// does not state anywhere is their shape. There is no prefix to search for and
// no count to read, so a pattern for one could only be a guess at a length over
// an alphabet — the loose grammar this package declines rather than the unlucky
// one. Test_DynatraceToken_theTokenFormatItReplaced pins it.
//
// The kinds are one pattern rather than one apiece, which is a decision about
// the caller and not about the scanning. Every kind Dynatrace writes in this
// format carries a sixty-four character secret it says to treat like a
// password, so a caller with reason to redact any of them has the same reason
// for the rest, and nothing a redactor could key on separates them. A switch a
// prefix would be worse than one besides: a caller reaching for this vendor
// would have to know every prefix to redact what it issues, and would be one
// behind on the day the next one shipped — which the prefixes standing outside
// the vendor's own table already show happening. What is left is the name, and
// token is the term Dynatrace uses for the whole of what this locates — its
// page heads the section Token format, keeps a table of Token prefixes and
// offers the expression above to look for tokens. Access token would be the
// narrower term, and a refresh token and a platform token are not ones.
// noseyparker and kingfisher both name their rule for this format Dynatrace
// Token as well.
//
// There is no boundary on either side of a match. A word boundary in front
// would drop the whole match rather than trim it wherever a token is written
// against a word character, as DT_API_TOKEN_dt0c01... is, and one behind it
// would drop a token followed by a character of a portion's own alphabet. What
// may stand either side is held back by the character classes and the counts
// alone. noseyparker and kingfisher both close their expressions in \b either
// side, so a token written against a letter is one they leave in the text.
//
// The byte the scan searches the input for is the d a token opens with, and it
// is chosen twice over. Four bytes stand at a fixed index of every opening —
// the d, the t, the 0 and the full stop behind the prefix — and on the line
// these benchmarks are written on the d stands once against three full stops,
// five t's and eight 0's, since a log line is written in timestamps, host names
// and paths where the other three are what separates one field from the next.
// The second reason is that the d stands first: a search for it stops at every
// position a candidate could begin, including the pieces of an opening the end
// of the input cut short, so the walk that reads an opening is also what says
// where the input stops being settled and no second grammar is kept beside it.
// That is what the scans opening on a literal reach for prefixTail
// (builtin_scan.go) to do; there is no table of literals here to hand it.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a token or not, which is the default and needs no argument.
// What it finds is nothing: no token begins inside another, because the two
// letters an opening starts with are lowercase and neither portion is written
// in lowercase at all, so no candidate opens inside a body — and inside a
// prefix the letter naming the type could be a d, but a digit stands where the
// t would have to.
// Test_DynatraceToken_noTokenBeginsInsideAnother drives it.
//
// The scan keeps no cursor and needs none: a candidate reads at most
// ninety-six bytes and stops, which bounds what it reads with no state to be
// wrong about — the guarantee a scan reading a body to the end of its run has
// to buy with a run cursor instead, bought here by the counts being counts.
//
// What this pattern over-matches on: ninety-six characters of the right shape
// that nobody issued. Three characters spelling no word have to be written,
// then a letter, then two digits, then a full stop, then exactly twenty-four
// uppercase letters and digits, then a second full stop, then exactly
// sixty-four more. The two full stops are what put this out of reach of an
// encoding: base62, standard base64, base64url and base32 write none, so an
// identifier, a certificate, a PEM body or an embedded image carries no
// candidate at however long it runs. What is left is a dotted name written to
// exactly that shape.
//
// The collision a prefix leaves where everything behind it is one class is a
// digest written there, and this format rules it out rather than paying for it.
// A digest carries no full stop, so the prefix and the sixty-four characters of
// a SHA-256 hold nothing at the twenty-fifth character but more of the digest;
// and a digest is written in hexadecimal, which is lowercase in every tool that
// prints one, where both portions here are uppercase.
// Test_DynatraceToken_aDigestBehindThePrefix pins both.
//
// What reaches a span is never prose. A token holds two full stops at fixed
// distances and no space, and eighty-eight unbroken uppercase characters are
// longer than anything prose is written in.
//
// referenceDynatraceToken in builtin_dynatrace_token_test.go keeps the grammar
// as a regular expression, spelling the opening, the letter, the digits, the
// separators, both counts and both character classes again so that the two are
// changed together, and the fuzz target beside it holds this scan to that
// expression. An expression is affordable here: both repetitions are exact, so
// the machine an engine builds is read once and stops, and the literal it
// searches the text for is three lowercase characters neither portion is
// written with, so a run of the alphabet candidates would otherwise crowd in
// holds no position for the engine to walk its machine at.
var dynatraceToken = NewPattern("dynatrace-token", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of an opening standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two, and the walk below answers both — the byte
	// the search stops at is the byte an opening begins with, so a piece of one
	// is reached exactly as a whole one is.
	retain := len(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], dynatraceTokenAnchor)
		if i < 0 {
			break
		}
		start := offset + i

		// The scan resumes one byte past the start of the candidate whether it
		// became a token or not, which is the default.
		offset = start + 1

		opens, cut := opensDynatraceTokenAt(src, start)
		if cut {
			// The end of the input stopped the walk part way through an
			// opening, so nothing here has opened a candidate yet and no text
			// carrying on from it could be decided.
			retain = min(retain, start)
			continue
		}
		if !opens {
			continue
		}

		body := start + dynatraceTokenOpeningChars
		end := start + dynatraceTokenChars
		if end > len(src) {
			// The input ends inside this candidate, so the counts that are the
			// whole of what tells it from anything else written behind the
			// prefix cannot be taken here.
			retain = min(retain, start)
			continue
		}
		if isDynatraceTokenBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// dynatraceTokenOpening is the three characters every prefix opens with,
	// and the whole of what a prefix states literally: the letter and the two
	// digits behind it name the type and are read as classes.
	//
	// Both of its letters are lowercase, and that is load-bearing. Neither
	// portion of a token is written in lowercase, so no candidate can open
	// inside the body of another and the spans of this pattern never overlap.
	// Test_dynatraceTokenOpening holds it there.
	dynatraceTokenOpening = "dt0"

	// dynatraceTokenAnchor is the byte the scan searches the input for. It
	// stands at the first character of every opening, so a candidate begins
	// where a search reported rather than some way in front of it, and a piece
	// of an opening the end of the input cut short is reached the same way a
	// whole one is. builtin_scan.go says why a scan searches for one byte of
	// its opening rather than for the opening itself; the rationale above says
	// what made it this byte. Test_dynatraceTokenAnchor holds it to being the
	// one byte an opening may begin with.
	dynatraceTokenAnchor = 'd'

	// dynatraceTokenTypeChars is what stands behind the opening and names the
	// token type: the one letter and two digits Dynatrace's own expression
	// reads, rather than a table of the prefixes it happens to have published.
	dynatraceTokenTypeChars = 3

	// dynatraceTokenPrefixChars is the whole of a prefix, which is what
	// Dynatrace calls the first of a token's three components.
	dynatraceTokenPrefixChars = len(dynatraceTokenOpening) + dynatraceTokenTypeChars

	// dynatraceTokenSeparator divides the three components. It belongs to
	// neither portion's alphabet, which is what ends the public portion where
	// it stands, what makes the count either side of it readable at all, and
	// what turns away every digest written behind the prefix.
	dynatraceTokenSeparator = '.'

	// dynatraceTokenOpeningChars is the prefix and the separator behind it,
	// which is what a candidate must have whole before anything can decide it.
	dynatraceTokenOpeningChars = dynatraceTokenPrefixChars + 1

	// The counts the two portions are written to, both of them numbers
	// Dynatrace states in prose and again in the expression it publishes: the
	// public identifier the prefix is displayed with, and the secret it says to
	// treat like a password.
	dynatraceTokenPublicChars = 24
	dynatraceTokenSecretChars = 64

	// dynatraceTokenBodyChars is everything behind the opening: the public
	// portion, the separator and the secret portion.
	dynatraceTokenBodyChars = dynatraceTokenPublicChars + 1 + dynatraceTokenSecretChars

	// dynatraceTokenChars is the whole of a token, the ninety-six characters
	// the tokens Dynatrace's own pages print come to.
	// Test_dynatraceTokenChars holds it to that number.
	dynatraceTokenChars = dynatraceTokenOpeningChars + dynatraceTokenBodyChars
)

// dynatraceTokenOpeningByteAt reports whether c may stand at index i of what a
// token opens with: the three characters of the opening, the letter and two
// digits naming the type, and the separator behind them.
//
// It is the one place an opening is stated, which is what lets the scan settle
// the tail of its input from the same grammar it locates values by rather than
// from a table of prefixes kept beside it and free to disagree.
func dynatraceTokenOpeningByteAt(i int, c byte) bool {
	switch {
	case i < len(dynatraceTokenOpening):
		return c == dynatraceTokenOpening[i]
	case i == len(dynatraceTokenOpening):
		// The letter naming the type, in either case. Dynatrace's own
		// expression admits both where every prefix it prints is lowercase, and
		// admitting the uppercase one draws in nothing: the two counts behind
		// it have already decided the match.
		return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
	case i < dynatraceTokenPrefixChars:
		return '0' <= c && c <= '9'
	default:
		return c == dynatraceTokenSeparator
	}
}

// opensDynatraceTokenAt reports whether what a token opens with stands at i in
// src, and whether the end of the input was what answered that.
//
// The second result is what builtin_scan.go asks of a walk that says no: an
// opening the end of the input cut in half opens no candidate, and the text
// from where it began is not settled, where an opening some other byte turned
// away is settled and costs a stream nothing.
func opensDynatraceTokenAt(src string, i int) (ok, cut bool) {
	for k := range dynatraceTokenOpeningChars {
		if i+k == len(src) {
			return false, true
		}
		if !dynatraceTokenOpeningByteAt(k, src[i+k]) {
			return false, false
		}
	}
	return true, false
}

// isDynatraceTokenBody reports whether s is everything behind the opening of a
// token: exactly dynatraceTokenPublicChars characters of the portions'
// alphabet, the separator, and exactly dynatraceTokenSecretChars more.
//
// It is handed the counts as well as the characters so that they are checked in
// one place rather than left to the caller to have cut correctly. The separator
// is tested before either run is walked: a candidate that is not a token is
// usually not one at that character — every digest written behind the prefix is
// turned away there — and one comparison declines it where up to twenty-four
// byte tests would.
func isDynatraceTokenBody(s string) bool {
	if len(s) != dynatraceTokenBodyChars || s[dynatraceTokenPublicChars] != dynatraceTokenSeparator {
		return false
	}
	for i := range dynatraceTokenPublicChars {
		if !isDynatraceTokenByte(s[i]) {
			return false
		}
	}
	for i := dynatraceTokenPublicChars + 1; i < len(s); i++ {
		if !isDynatraceTokenByte(s[i]) {
			return false
		}
	}
	return true
}

// isDynatraceTokenByte reports whether c belongs to the alphabet both portions
// of a token are written in: the uppercase letters and the digits, which is
// what Dynatrace's own expression spells for each of them.
//
// One test for both portions because Dynatrace writes one class for both.
// Lowercase is not admitted: it is what a hexadecimal digest and a base64url
// payload are written in, and no token Dynatrace prints carries any.
func isDynatraceTokenByte(c byte) bool {
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z'
}
