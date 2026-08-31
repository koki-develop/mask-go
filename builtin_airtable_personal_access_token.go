package mask

import "strings"

// AirtablePersonalAccessToken locates Airtable personal access tokens: the
// prefix pat, the fourteen characters that finish the token's identifier, a
// dot, and the sixty-four lowercase hexadecimal characters of the secret behind
// it — eighty-two characters altogether. One string serves every scope a token
// is created with and every base it is granted, so nothing in a token says what
// it may reach.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly eighty-two characters of it are. So text of that shape is
// redacted whether or not Airtable issued it. A space, an identifier of the
// wrong length, a hyphen where the dot belongs or an uppercase letter in the
// secret ends the reading, so text as it is ordinarily written is not affected.
// A longer run is a token with something written after it, and the token alone
// is redacted.
//
// Its name is "airtable-personal-access-token".
func AirtablePersonalAccessToken() Pattern { return airtablePersonalAccessToken }

// Personal access token is Airtable's own name for this string, and the guide
// it keeps under that title is where the one thing Airtable says about the
// format is written. It is not a format: "While personal access tokens are
// prefixed with their ID, they should be otherwise treated as opaque,
// variable-length strings", and then "In particular, do not rely on tokens
// having a particular length or format. Changes to the token format (for newly
// created tokens) are not considered to be breaking changes."
//
// What that rules out is a promise about tomorrow's tokens; what it hands over
// is where today's begin. A token is prefixed with its ID, and an Airtable ID
// is a shape Airtable writes down everywhere else: three letters naming the
// type of thing and fourteen characters of letters and digits behind them. Its
// page on finding IDs prints them for records, fields, tables, bases,
// workspaces and groups — recbtRHd9o7vKZAQr, appeqX9XTkHZNfSbn,
// wsprEhWuZ2PePS6aK — and its audit log reference prints more beside the
// events they belong to, usrL2PNC5o3H4lBEi among them. Every one of them is
// seventeen characters. The three letters here are pat, and the fourteen below
// are the rest of the identifier.
//
// What shows the width of the secret is a whole value of the other credential
// this vendor issues. An OAuth access token is written in four parts, and the
// third of them is base64url; trufflehog publishes two whole ones in its own
// tests, and the third part of either decodes to a JSON object carrying a
// userId and an oauthApplicationId — each of them one of the seventeen
// character identifiers behind its own three letters — an expiresAt written as
// a timestamp, and a secret of exactly sixty-four lowercase hexadecimal
// characters, which is thirty-two bytes written in that alphabet. That is the
// width below, and what makes it worth reading off another credential is that
// it is the same vendor's secret drawn at the same width, rather than a number
// counted off examples of this one.
//
// The rulesets agree on the whole shape and were written from tokens rather
// than from either of those. gitleaks reads \b(pat[[:alnum:]]{14}\.[a-f0-9]{64})\b
// and nothing else; trufflehog reads the same expression behind an airtable
// keyword and verifies what it finds against the API; kingfisher reads
// pat[A-Za-z0-9]{14}\.[a-f0-9]{64} under an entropy floor and a demand for two
// digits, an uppercase letter and a lowercase one. noseyparker reads none of
// it. Between trufflehog's tests and kingfisher's example four whole tokens are
// published, and every one of them is eighty-two characters divided the way the
// three expressions divide it — one of them carrying no digit in its identifier
// at all, which is a token kingfisher's own demand for two would decline.
//
// Both counts are therefore read exactly, and the vendor's sentence about
// length is what the decision has to be weighed against rather than what
// settles it. Airtable reserves the right to issue a different shape and
// writes no such shape down, and what matters is what each half would cost if
// that day came. A secret wider than sixty-four characters is redacted for
// sixty-four with the rest left in the text, which is what an exact count
// costs everywhere. An identifier of some other width is a token this scan
// does not locate at all — the whole credential, left whole — and that is the
// wager. It rests on the identifier being an Airtable ID rather than on the
// examples: the fourteen is the shape Airtable writes every ID of every kind
// in, so a token whose identifier stopped being one would be a change to more
// than this credential. Reading the identifier to the dot instead would spend
// the anchor to buy it, since pat and a dot seventeen characters later is most
// of what tells this format from a word.
//
// The identifier is read in the shared base62 alphabet of builtin_scan.go,
// which is the letters of both cases and the digits, because that is what an
// Airtable ID is written in and not because a run is walked to its end — every
// count here is a count. The secret is read in lowercase hexadecimal, and the
// widening on offer is the other case. It is declined on the values rather than
// on the vendor: Airtable states no alphabet at all, every published token is
// lowercase, the secret carried inside the OAuth access token is lowercase, and
// lowercase is what a hexadecimal encoder settles once for all of its output
// rather than a thing a generator varies between tokens. All three rulesets
// read the lowercase class alone. Test_AirtablePersonalAccessToken_anUppercaseSecret
// pins the decision so that widening it is a change somebody argues for.
//
// The byte test for the secret stays in this file rather than joining the
// shared ones. What is shared in builtin_scan.go is an alphabet a format is
// defined over, and hexadecimal is not that here: the case is this scan's
// reading of what Airtable's encoder emits, argued above and owed the
// cases beside it, so a test named for the class rather than for the reading
// would carry a decision away from the argument for it.
//
// The dot between the identifier and the secret is the one character of the
// format that belongs to neither alphabet, and it is doing most of the work. It
// is what makes the count on either side of it readable at all; it is what
// tells this format from a run of seventy-eight letters and digits, which would
// be a far weaker anchor than three letters and a separator seventeen
// characters along; and it is what leaves no token able to begin inside
// another, which the claim below is.
//
// There is no boundary on either side of a match. A boundary in front drops
// rather than trims the match wherever a token is written against a word
// character, which is what AIRTABLE_PERSONAL_ACCESS_TOKEN_pat... is; one behind
// it drops a token followed by a letter or a digit, which under exact counts is
// a token with a character written after it. What may stand either side is held
// back by the character classes and the two counts alone. gitleaks and
// kingfisher ask for a word boundary at both ends, and trufflehog asks for the
// word airtable in the text in front besides, which is a demand on the text
// around a value rather than a part of the format.
//
// The byte the scan searches the input for is the p the prefix opens with, and
// the prefix is read back from it. builtin_scan.go says why a scan searches for
// one byte of its prefix rather than for the prefix itself. Of the three the
// prefix has, the a is the one that would be worst: it is a hexadecimal
// character, so a search for it stops at one byte in sixteen of every secret,
// every digest and every UUID a log carries. The p and the t are both outside
// that alphabet, so a run of hexadecimal however long stops the search at
// neither; between them the p is the rarer over every text measured. It stands
// three times against the t's five on the line these benchmarks are written on,
// which carries Airtable's own host name and API path, and not at all in "there
// is no credential in this sentence", which this pattern's corpus carries as
// prose; over the log lines, JSON and command lines of text_shapes.txt it
// stands a third as often as either of the others.
//
// No token can be written inside another, which is a claim about the dot. A
// token holds exactly one, at its eighteenth character, and everything behind
// that dot is hexadecimal — an alphabet holding neither the p nor the t of the
// prefix. So a second token beginning inside this one would need its own dot
// seventeen characters along, and there is no dot to be had: every position
// that would put one inside the span lands in the secret, and every position
// far enough along for it to land past the span has to open with a p the secret
// cannot hold. Test_AirtablePersonalAccessToken_noTokenBeginsInsideAnother
// drives it, and Test_airtablePersonalAccessTokenPrefix holds the two
// declarations the claim rests on.
//
// The scan advances one byte past the start of a candidate all the same,
// whether that candidate became a token or not, which is the default and needs
// no argument. What the claim above buys is a reader's confidence that the
// spans do not overlap, not a longer step: the candidate that failed is what a
// longer step would lose, and patpat written in front of an identifier carries
// a whole token at its second prefix.
//
// The scan keeps no cursor and needs none: a candidate reads at most
// eighty-two bytes and stops, which bounds what it reads with no state to be
// wrong about, and is what rules out a quadratic input.
//
// What this pattern over-matches on is a seventeen character word of letters
// and digits opening on pat, with a dot and sixty-four lowercase hexadecimal
// characters behind it. That is the vendor's format exactly, and the shape
// worth stating is the digest: a SHA-256 is sixty-four lowercase hexadecimal
// characters, so a word of that length in front of a dot and one is a token
// character for character and the whole of it is redacted. There is nothing
// left in the string to tell the two apart — a scan declining it would decline
// every token Airtable issues — and what has to be written to reach it is a
// word beginning with the three letters and running to exactly seventeen, then
// the dot, then the digest and nothing between.
// Test_AirtablePersonalAccessToken_aDigestBehindAnIdentifier pins the decision.
//
// What reaches a span is never prose. The English words that open on pat —
// patch, path, patient, pattern — reach a candidate and run out of it at the
// first character that is no letter or digit, and a word long enough to carry
// fourteen more would still have to be followed by a dot and sixty-four
// unbroken hexadecimal characters, which is longer than anything prose is
// written in. A git SHA is forty characters and an MD5 thirty-two, so neither
// is a secret at any length; a digest carries no dot, so none of them holds a
// candidate to be found at.
//
// Other credentials Airtable issues are left alone, and each is one this
// pattern's name does not cover rather than one the scan happens to miss. The
// OAuth access token is written in four parts with .v1. between the first two,
// so its identifier is followed by a dot and a version rather than by a secret,
// and Airtable calls it an OAuth access token where this is a personal access
// token. The user API key that came before both opened on key and carried no
// separator at all — letters and digits and nothing else, which is an
// identifier's shape and no anchor — and Airtable finished deprecating it on 1
// February 2024, since when it reaches nothing.
//
// referenceAirtablePersonalAccessToken in
// builtin_airtable_personal_access_token_test.go keeps the grammar as a regular
// expression, spelling the prefix, the two counts, the separator and both
// alphabets again so that the two are changed together, and the fuzz target
// beside it holds this scan to that expression. An expression is affordable
// here for both of the reasons it can be: the repetitions are exact, so the
// machine an engine builds is read once and stops, and the opening is a literal
// an engine searches the text for rather than a class it would have to walk its
// machine at every byte for.
var airtablePersonalAccessToken = NewPattern("airtable-personal-access-token", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two.
	retain := airtablePersonalAccessTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], airtablePersonalAccessTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not. No
		// token can be written inside another, which the rationale above argues, so
		// what this is for is the candidate that failed: patpat and an identifier
		// carries a whole token at its second prefix, and resuming past the length
		// this candidate hoped for would step over it.
		offset = anchor + 1

		if anchor < airtablePersonalAccessTokenAnchorIndex {
			continue
		}
		start := anchor - airtablePersonalAccessTokenAnchorIndex
		if !strings.HasPrefix(src[start:], airtablePersonalAccessTokenPrefix) {
			continue
		}

		body := start + len(airtablePersonalAccessTokenPrefix)
		end := start + airtablePersonalAccessTokenChars
		if end > len(src) {
			// The input ends inside this candidate, so the counts that are the
			// whole of what tells it from anything else written behind the
			// prefix cannot be taken here.
			retain = min(retain, start)
			continue
		}
		if isAirtablePersonalAccessTokenBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// airtablePersonalAccessTokenPrefix is the three letters an Airtable
	// identifier of this kind opens with, and what the scan reads back from its
	// anchor. Two of them stand outside the alphabet the secret is written in,
	// which is what leaves no token able to begin inside another;
	// Test_airtablePersonalAccessTokenPrefix holds it to that.
	airtablePersonalAccessTokenPrefix = "pat"

	// airtablePersonalAccessTokenAnchor is the byte the scan searches the input
	// for and airtablePersonalAccessTokenAnchorIndex is where it stands in the
	// prefix, so a candidate begins that many bytes in front of what a search
	// reported. builtin_scan.go says why a scan searches for one byte of its
	// prefix rather than for the prefix itself; the rationale above says what
	// made it this byte. Test_airtablePersonalAccessTokenAnchor holds it to
	// standing at this index.
	airtablePersonalAccessTokenAnchor      = 'p'
	airtablePersonalAccessTokenAnchorIndex = 0

	// airtablePersonalAccessTokenSeparator divides the identifier from the
	// secret. It belongs to neither alphabet, which is what ends the identifier
	// where it stands, what makes both counts readable, and what the claim that
	// no token begins inside another rests on.
	airtablePersonalAccessTokenSeparator = '.'

	// airtablePersonalAccessTokenIDChars is what stands between the prefix and
	// the separator: the rest of the token's identifier, which is an Airtable
	// ID and so is fourteen characters behind its three letters.
	airtablePersonalAccessTokenIDChars = 14

	// airtablePersonalAccessTokenSecretChars is the secret behind the
	// separator: thirty-two bytes written in hexadecimal, which is the width
	// the secret inside an Airtable OAuth access token is drawn at.
	airtablePersonalAccessTokenSecretChars = 64

	// airtablePersonalAccessTokenBodyChars is everything behind the prefix: the
	// rest of the identifier, the separator and the secret.
	airtablePersonalAccessTokenBodyChars = airtablePersonalAccessTokenIDChars + 1 + airtablePersonalAccessTokenSecretChars

	// airtablePersonalAccessTokenChars is the whole of a token.
	// Test_airtablePersonalAccessTokenChars holds it to eighty-two, and holds
	// the identifier in front of the separator to the seventeen characters
	// every Airtable ID is written to.
	airtablePersonalAccessTokenChars = len(airtablePersonalAccessTokenPrefix) + airtablePersonalAccessTokenBodyChars
)

// isAirtablePersonalAccessTokenBody reports whether s is everything behind the
// prefix of a token: exactly airtablePersonalAccessTokenIDChars characters of
// the identifier, the separator, and exactly
// airtablePersonalAccessTokenSecretChars characters of the secret.
//
// It is handed the counts as well as the characters so that they are checked in
// one place rather than left to the caller to have cut correctly. The separator
// is tested before either run is walked: a candidate that is not a token is
// usually not one at that character, and one comparison turns it away where up
// to seventy-eight byte tests would.
func isAirtablePersonalAccessTokenBody(s string) bool {
	if len(s) != airtablePersonalAccessTokenBodyChars || s[airtablePersonalAccessTokenIDChars] != airtablePersonalAccessTokenSeparator {
		return false
	}
	for i := range airtablePersonalAccessTokenIDChars {
		if !isBase62Byte(s[i]) {
			return false
		}
	}
	for i := airtablePersonalAccessTokenIDChars + 1; i < len(s); i++ {
		if !isAirtablePersonalAccessTokenSecretByte(s[i]) {
			return false
		}
	}
	return true
}

// isAirtablePersonalAccessTokenSecretByte reports whether c is a lowercase
// hexadecimal digit, which is what the secret behind the separator is written
// in. The rationale above says why the case is read this way and what admitting
// the other one would cost, and why the test stays here rather than joining the
// shared ones in builtin_scan.go.
func isAirtablePersonalAccessTokenSecretByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f'
}

// airtablePersonalAccessTokenTail is what the scan settles the tail of its
// input by. prefixTail (builtin_scan.go) says what that is and why it is built
// once.
var airtablePersonalAccessTokenTail = newPrefixTail(airtablePersonalAccessTokenPrefix)
