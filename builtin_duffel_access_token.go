package mask

import (
	"slices"
	"strings"
)

// DuffelAccessToken locates the access tokens Duffel issues, in either of the
// two modes it issues them for: the prefix duffel_test_ or duffel_live_ and the
// forty-three base64url characters behind it, fifty-five characters altogether.
// A live token searches and books travel and reads the orders, passengers and
// payments of the account it belongs to; a test token reaches that same account
// in test mode. One shape serves both, and it serves a token of either
// permission: a token is created read-only or read-write and nothing in the
// string says which.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly fifty-five characters of it are. So text of that shape is
// redacted whether or not Duffel issued it. A space, a dot, a character outside
// the alphabet or an uppercase prefix ends the reading, so text as it is
// ordinarily written is not affected. A longer run of the alphabet is a token
// with something written after it, and the token alone is redacted.
//
// Its name is "duffel-access-token".
func DuffelAccessToken() Pattern { return duffelAccessToken }

// Access token is Duffel's own term for the whole of what this locates. Its
// guides say that you create an access token in the dashboard, the page on
// making requests sends one as Authorization: Bearer <YOUR_ACCESS_TOKEN>, and
// the client libraries Duffel publishes take it as access_token and read it
// from DUFFEL_ACCESS_TOKEN. The same term covers both modes and both
// permissions: what is chosen beside the token is the mode it reaches and
// whether it is read-only or read-write.
//
// The permission is what a boundary might have been put in for, and the format
// is why it is not. A read-write token books flights and moves money where a
// read-only token only reads, which is a real distinction to route an alert by
// — but Duffel writes the permission nowhere in the string, so no scan can tell
// the two apart and two switches would do one thing.
//
// What Duffel states is the test prefix and stops there. Its getting-started
// guide, its dashboard guide and its test-mode page each say that test tokens
// are easy to recognise: they start with duffel_test_. None of them writes a
// whole token and none gives a length, an alphabet or a checksum. None of them
// writes the live prefix either: what they say of live mode is that a live
// access token reaches resources created in live mode and that it is a separate
// token, and the pages about going live write no prefix at all.
//
// So the live prefix and everything behind both of them is read off the
// rulesets, and two of them state this format. gitleaks reads duffel_test_ or
// duffel_live_ and exactly forty-three characters of the letters of both cases,
// the digits, the hyphen, the underscore and the equals sign; trufflehog reads
// the same two prefixes and exactly forty-three of the same set without the
// equals sign, with a word boundary in front and a character outside the set
// behind.
//
// Two counts the rulesets that state the format, not the rules they state it
// in. betterleaks carries gitleaks' expression and gitleaks' description word
// for word, so it is that rule again; kingfisher carries it a step further
// along, shipping it under betterleaks' own name rather than writing one of its
// own. noseyparker has no Duffel rule at all. So what the forty-three rests on
// is two readings, and for trufflehog nothing published says where its number
// came from.
//
// Reading the live prefix on that footing is the side to be wrong on. Were
// Duffel to write live tokens some other way, this pattern locates none of them
// and a caller is no worse off than with no pattern at all; were the prefix left
// out because no vendor page states it, every production token a caller logs
// stays in the output while the test tokens beside it are redacted. The two
// rulesets agree on it, and the division they name is the division Duffel's own
// pages describe.
//
// The count is read exactly rather than as a floor, and what makes it readable
// as a count is the width itself. A base64url encoding with no padding is one
// character to every six bits, so thirty-two bytes come to forty-three
// characters and no other whole number of bytes does — thirty-one give
// forty-two and thirty-three give forty-four. The body is the width of a fixed
// two hundred and fifty-six bit value, which is a size a token is minted at
// rather than a length it grew to, and both rules state it as a count rather
// than as a bound. A run of the alphabet longer than forty-three is therefore
// not one longer token but a token with something written after it, and a floor
// would swallow what the run went on to hold, which is text belonging to no
// credential.
//
// What an exact count costs is the token cut short of it. A line cut to a column
// limit partway through one leaves a prefix and a body too short to be a body,
// and nothing at all is located: the characters written before the cut stay in
// the output. Test_DuffelAccessToken_cutShortOfTheCount pins that.
//
// The alphabet is base64url, isBase64URLByte in builtin_scan.go: the letters of
// both cases, the digits, the hyphen and the underscore. The equals sign
// gitleaks admits is not read, and the reason is what that character is doing in
// its rule rather than anything about Duffel. gitleaks builds its sample
// alphabets from a small family of helpers, and the class here is one of them
// written out — AlphaNumericExtended, which is the digits, the letters, the
// equals sign, the underscore and the hyphen, sitting between a Short helper
// without the equals sign and a Long one with the slash and the plus as well. It
// is a shelf class picked to be wide enough rather than a claim about what a
// Duffel token holds. The width says the same thing from the other side: padding
// stands only at the end of a length that is a multiple of four, and forty-three
// is not one, so no body of this count can carry an equals sign at all.
//
// The mode is what stands between the opening and the separator, and this scan
// reads the two names Duffel writes rather than reading that there is a name at
// all. Duffel writes its own name in front of a word elsewhere and writes it
// often: duffel_hotel_group and duffel_hotel_group_rewards are rate sources its
// Stays API returns, is_duffel_links_enabled is a field of its identity
// response, and duffel_api_javascript, duffel_api_ruby and duffel_api_python are
// the user agents its own client libraries send. A scan reading duffel_ and any
// word would open a candidate at each of those and at whatever it writes next.
// What pinning the modes wagers is a mode Duffel has not written yet, which
// would then be left in the output whole; against that stands test mode and live
// mode being the whole of the division its documentation draws.
//
// The prefixes are read in the one case Duffel writes them. They are the whole
// of what tells this format from text, so reading them in either case buys
// nothing — DUFFEL_LIVE_ is no form a token is issued in — and costs a candidate
// at every spelling of the environment variable a caller keeps one in.
//
// There is no boundary on either side of a match. One in front would drop the
// whole match rather than trim it wherever a token is written against a word
// character, as DUFFEL_ACCESS_TOKEN_duffel_live_... is. One behind would drop
// rather than trim as well: under an exact count a token written against a
// forty-fourth character of the alphabet is still a token with something after
// it, and a boundary there would locate nothing at all where this scan redacts
// the fifty-five Duffel issued and leaves the character that belongs to no
// credential in the text. Test_DuffelAccessToken_nextToWordCharacters writes
// out what a boundary in front would cost and
// Test_DuffelAccessToken_leavesWhatFollowsAlone what one behind would.
//
// The byte the scan searches the input for is the u of the opening.
// builtin_scan.go says why a scan searches for one byte of its prefix rather
// than for the prefix itself; here every character of the opening stands in a
// base64url run one time in sixty-four, so a run opens the same number of
// candidates whichever byte is chosen and what is left to separate them is how
// often each is written in the text a caller is masking. That text is a travel
// record, and the vendor's vocabulary is what settles it: offer, offers and the
// offer request carry the f, order and identifier carry the d and the e, level
// and url carry the l. The u stands in the vendor's own name and in url and
// almost nowhere else. The underscore is passed over for the reason it usually
// is — a log field, a snake_case name and an environment variable are written
// with it, so a scan anchored there opens a candidate on a great deal of the
// text to reject it again — and here the count says so too, at four against the
// u's two. The line those counts are read off is held by
// Test_duffelAccessTokenFindBenchmarks_lineTheAnchorWasChosenAgainst.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a token or not, which is the default and needs no argument.
// It is load-bearing here rather than merely correct: every character of both
// prefixes belongs to the alphabet a body is written in, so a token can begin
// inside the body of the one before it — a prefix written twice with a body
// behind the second is a token from either of them — and a scan consuming its
// match would step over the second and leave it in the output whole. The two
// spans overlap where it happens, and Masker.locate resolves them.
// Test_DuffelAccessToken_aTokenBeginningInsideAnother drives that, where both
// candidates become tokens; the case named "a token inside a candidate the body
// turned away" drives the other half, where the candidate stepped over is one
// the body test rejected, since a scan may consume a match it never made.
//
// The scan keeps no cursor and needs none: a candidate reads at most fifty-five
// bytes and stops, which bounds what it reads with no state to be wrong about.
// That is what rules out a quadratic input here, and it is what the exact count
// buys beyond the discrimination. A scan reading a body to the end of its run
// would have nothing to divide the runs between candidates by — a prefix closes
// with the underscore and the alphabet admits it — so it would need a cursor
// over the run, and a line dense in prefixes would otherwise be walked once per
// candidate in it.
//
// What this pattern over-matches on: forty-three characters of the alphabet
// written behind one of the two prefixes by something other than Duffel. Twelve
// characters have to be written, two of them underscores, then forty-three more
// with nothing between any of them. Prose holds no such run — a body is longer
// than any word and carries no space or punctuation — and hexadecimal, base62,
// standard base64 and base32 write no underscore at all, so an identifier, a
// certificate body or an embedded image carries no candidate at however long it
// runs. What is left is base64url, which writes every character of both
// prefixes: there the twelve have to fall exactly, halved by there being two
// prefixes, which is about once in two thousand million million million
// characters, and the forty-three behind them are in the alphabet by
// construction. Test_DuffelAccessToken_insideAnOpaqueRun pins it.
//
// The digest is the same over-match taking a value a reader had a use for. The
// hexadecimal digits are base64url and a digest carries nothing that ends a run,
// so a digest of at least forty-three characters written behind a prefix is a
// token to this scan: a SHA-256 at sixty-four is redacted for its first
// forty-three characters and the remaining twenty-one stay in the text. What
// holds either side of it is the count and the prefix — a SHA-1 at forty and an
// MD5 at thirty-two are short of a body, as is the thirty-six characters of a
// UUID, whose hyphens the alphabet reads straight through — and a digest with
// nothing in front of it opens no candidate at all. The tightening that would
// rule the long one out is the demand that the run stop at the count, and it is
// declined for what it costs: a token written against a letter, a digit, a
// hyphen or an underscore answers the count and not the demand, so a scan asking
// for both would locate nothing there and leave every character of a live token
// in the output. Test_DuffelAccessToken_aDigestBehindThePrefix pins each of
// those.
//
// The other credential Duffel issues is not read here and needs no rule of its
// own. A component client key, which authenticates its browser components, is a
// JWT and carries no prefix of Duffel's: it is a value jsonWebToken locates by
// its own format, so a caller masking with the built-ins already redacts one.
//
// referenceDuffelAccessToken in builtin_duffel_access_token_test.go keeps the
// grammar as a regular expression, spelling the opening, the modes, the
// separator, the count and the alphabet again so that the two are changed
// together, and the fuzz target beside it holds this scan to that expression. An
// expression is affordable here: the repetition is exact, so the machine an
// engine builds is read once and stops, and the seven character literal in front
// of the alternation is what an engine searches the text for.
var duffelAccessToken = newBuiltin("duffel-access-token", &duffelAccessTokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two, and this format adds nothing to them — a token
	// whole is a token finished, since nothing behind the count is read.
	retain := duffelAccessTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], duffelAccessTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not,
		// for the reason the rationale above gives: a prefix is written in the
		// alphabet a body is, so a token can begin inside the body of the one
		// before it.
		offset = anchor + 1

		if anchor < duffelAccessTokenAnchorIndex {
			continue
		}
		start := anchor - duffelAccessTokenAnchorIndex

		// The byte the opening begins with is tested before the opening is
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the whole opening is a length and a read.
		if src[start] != duffelAccessTokenOpening[0] ||
			!strings.HasPrefix(src[start:], duffelAccessTokenOpening) {
			continue
		}
		if !opensDuffelAccessTokenMode(src[start+len(duffelAccessTokenOpening):]) {
			continue
		}

		body := start + duffelAccessTokenPrefixChars
		end := start + duffelAccessTokenChars
		if end > len(src) {
			// The input ends inside the body, and the count is the whole of
			// what tells a token from any other run written behind the prefix.
			retain = min(retain, start)
			continue
		}
		if isDuffelAccessTokenBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// duffelAccessTokenOpening is what every prefix opens with, and what the
	// scan reads back from its anchor. The mode naming which of Duffel's two
	// modes a token reaches and the separator closing it stand behind this.
	duffelAccessTokenOpening = "duffel_"

	// duffelAccessTokenSeparator closes a prefix, behind the mode.
	duffelAccessTokenSeparator = '_'

	// duffelAccessTokenModeChars is how many characters name the mode in every
	// prefix, between the opening and the separator. Test_duffelAccessTokenModes
	// holds every mode to it.
	duffelAccessTokenModeChars = 4

	// duffelAccessTokenAnchor is the byte the scan searches the input for and
	// duffelAccessTokenAnchorIndex is where it stands in every prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what made it
	// this byte. Test_duffelAccessTokenAnchor holds it to standing at this
	// index.
	duffelAccessTokenAnchor      = 'u'
	duffelAccessTokenAnchorIndex = 1

	// The counts a token is written to. Forty-three is the count both rules
	// that read this format state, and the width thirty-two bytes encode to;
	// twelve is the prefix the scan reads a body from, and fifty-five is the
	// two together. Test_duffelAccessTokenChars holds the arithmetic to all
	// three.
	duffelAccessTokenBodyChars   = 43
	duffelAccessTokenPrefixChars = len(duffelAccessTokenOpening) + duffelAccessTokenModeChars + 1
	duffelAccessTokenChars       = duffelAccessTokenPrefixChars + duffelAccessTokenBodyChars
)

// duffelAccessTokenModes is what stands between the opening and the separator in
// the prefix of every token this scan reads: live for the mode a booking is made
// in and test for the mode Duffel returns test data in.
//
// It is the one declaration saying which modes there are, and
// duffelAccessTokenPrefixes below reads it rather than writing the prefixes out
// again. builtin_scan.go says why: a table kept beside this is one that can come
// to disagree with it, and what a stream would then do with the mode it had not
// been told about is release the characters a token opens with and redact
// nothing.
var duffelAccessTokenModes = []string{"live", "test"}

// opensDuffelAccessTokenMode reports whether s, which is the text behind the
// opening of a candidate, begins with one of the modes above and the separator
// that closes a prefix.
//
// It is handed the separator to check as well as the mode so that the two are
// read in one place: a mode found with nothing behind it is no prefix, and a
// caller left to check the separator for itself is a caller that can forget to.
// The separator is compared first because it is one byte against a fixed index
// and turns away everything the modes would then be walked for.
func opensDuffelAccessTokenMode(s string) bool {
	if len(s) <= duffelAccessTokenModeChars || s[duffelAccessTokenModeChars] != duffelAccessTokenSeparator {
		return false
	}
	return slices.Contains(duffelAccessTokenModes, s[:duffelAccessTokenModeChars])
}

// isDuffelAccessTokenBody reports whether s is the body of a token: exactly
// duffelAccessTokenBodyChars characters, all of them in the alphabet a body is
// written in.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count being left to the caller to have cut
// correctly.
func isDuffelAccessTokenBody(s string) bool {
	if len(s) != duffelAccessTokenBodyChars {
		return false
	}
	for i := range len(s) {
		if !isBase64URLByte(s[i]) {
			return false
		}
	}
	return true
}

// duffelAccessTokenPrefixes is what a candidate opens with, one entry a mode.
//
// The modes are read out of duffelAccessTokenModes rather than written out
// again, so that a mode admitted there is a mode this knows about.
var duffelAccessTokenPrefixes = func() []string {
	prefixes := make([]string, 0, len(duffelAccessTokenModes))
	for _, mode := range duffelAccessTokenModes {
		prefixes = append(prefixes, duffelAccessTokenOpening+mode+string(duffelAccessTokenSeparator))
	}
	return prefixes
}()

// duffelAccessTokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var duffelAccessTokenTail = newPrefixTail(duffelAccessTokenPrefixes...)
