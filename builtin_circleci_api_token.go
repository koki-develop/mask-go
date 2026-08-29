package mask

import (
	"slices"
	"strings"
)

// CircleCIAPIToken locates CircleCI API tokens: the prefix CCIPAT_ a personal
// API token is written with or the CCIPRJ_ a project API token is written with,
// then twenty-two letters and digits, an underscore, and forty hexadecimal
// characters — seventy characters altogether.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly seventy characters of it are. So text of that shape is redacted
// whether or not CircleCI issued it. A space, a hyphen, a run of other than
// twenty-two letters and digits in front of the second underscore, or a
// character outside hexadecimal behind it, all end the reading, so text as it
// is ordinarily written is not affected. A longer run of hexadecimal is a token
// with something written after it, and the token alone is redacted.
//
// Its name is "circleci-api-token".
func CircleCIAPIToken() Pattern { return circleCIAPIToken }

// API token is CircleCI's own name for the whole of what this locates: its
// documentation keeps one page under that term and divides it into the personal
// API token and the project API token. The two are one pattern here because
// neither of the things that would divide them holds: both
// authenticate and neither is published by design, so a caller has no decision
// to make between them; and the scope a project token carries — status, read
// only or admin — is not written in the string, so a caller telling CCIPRJ_
// from CCIPAT_ in the output would still not be told whether the second one
// could write.
//
// What CircleCI states in prose and what CircleCI shows are worth separating,
// because on this format the prose is one line. The changelog announcing the
// format writes it as CCIPAT_<base58-UUID>_<40-char-hex string> and names
// CCIPRJ_ as what a project token carries in place of the first. It shows one
// token, a personal one, so the shape of a project token rests on that line
// rather than on anything the vendor has written out. Nothing there is a count
// for the middle, and the documentation pages that manage tokens do not
// describe the string at all.
//
// The count of twenty-two is what that line comes to rather than something read
// off the tokens that have been published. A UUID is sixteen bytes, and a
// base58 encoding of a fixed sixteen bytes is ceil(log(2^128)/log(58)) = 22
// characters wide — twenty-one and a fraction, rounded up and padded to the
// width, which is what the base58 encoders written for UUIDs do. The token
// CircleCI writes out is twenty-two characters between its separators.
//
// What an encoder padding to no fixed width would give instead is twenty-one
// characters, which is 58^21 / 2^128 of the tokens there are — about one in
// thirty — and reading the count exactly leaves such a token in the output
// whole. That is the cost the exact count carries, and it is taken because a
// range is a second claim about an encoder nobody has stated anything about,
// where the count above follows from the two words the vendor did write.
//
// The rulesets divide on which prefix they read and agree on both counts.
// Google's osv-scalibr reads CCIPAT_ and CCIPRJ_ alike, with twenty-two letters
// and digits behind either and forty lowercase hexadecimal characters behind
// those; trufflehog reads CCIPAT_ alone, the same twenty-two, and hexadecimal of
// either case; kingfisher reads CCIPAT_ alone, the same twenty-two, and forty
// lowercase letters and digits. None of them reads the middle as anything but
// exactly twenty-two, and osv-scalibr is the one of them that reads a project
// token at all.
//
// The alphabet of the middle is the letters of both cases with the digits,
// isBase62Byte in builtin_scan.go, which is wider than the base58 the changelog
// names. Every base58 alphabet in use — Bitcoin's, Flickr's, Ripple's — is the
// same fifty-eight characters in a different order, the letters and digits less
// 0, O, I and l, so the tightening is available and is four characters wide. It
// is declined on a measurement rather than on the asymmetry alone: GitHub
// carries this format as a partner pattern with push protection, and that
// pattern locates a token whose middle is written with an O, an I and an l.
// Which four characters a base58 alphabet drops is a convention about what a
// reader can tell apart rather than something the encoding needs, and
// implementations differ on it — shortuuid's default drops the 1 as well — so
// the vendor's one word does not pin the class the way the sentence above pins
// the count.
//
// The forty behind the second underscore are read as hexadecimal of either
// case, and this is the one place where what is stated, what is shown and what
// is read pull apart, so the three are worth keeping separate.
//
// Stated: the changelog says a 40-char hex string. Hex names a set of sixteen
// digits and says nothing about the case they are rendered in, and the vendor
// writes nothing else about it anywhere.
//
// Shown: every token anyone has published is lowercase — the one in the
// changelog, and the ones standing in osv-scalibr's tests, kingfisher's and
// trufflehog's. Read: osv-scalibr asks for lowercase, kingfisher for lowercase
// letters and digits, trufflehog for either case. GitHub's partner pattern goes
// with the lowercase ones: it locates the O, the I and the l in a middle, and
// does not locate a tail written in uppercase.
//
// So the tightening is available, and the observation runs against the choice
// made here rather than for it. What decides it is what the tightening could
// buy. The gate a built-in is held to turns on whether a grammar casts a net
// over values that carry meaning, and no reading of these forty characters
// does: the identification is carried by the seven characters of the prefix and
// by the seventy the layout comes to, and a run inside those that happens to be
// written in uppercase is a value a reader can make nothing of either way. The
// narrower class would turn away no text anyone writes, where what it would
// cost, the first time some surface renders a token the other way, is not the
// end of a credential but the whole of it left in the output.
//
// Both counts are read exactly rather than as floors, because running an
// alphabet out to the end of its run would swallow whatever word was written
// against the end of a token.
//
// The prefixes are read in the one case CircleCI writes them. Lowercase ccipat_
// is not a form any token is issued in, and reading either case would open a
// candidate at text nothing about this format reaches.
//
// There is no boundary on either side of a match. A boundary in front drops
// rather than trims the match wherever a token is written against a word
// character, which is what CIRCLE_TOKEN_CCIPAT_... is; one behind it drops a
// token followed by a letter or a digit, which under exact counts is a token
// with a character written after it. What may stand either side is held back by
// the character classes and the counts alone.
//
// The byte the scan searches the input for is the underscore each prefix closes
// with, and the prefix is read back from it. builtin_scan.go says why a scan
// searches for one byte of its prefix rather than for the prefix itself; what
// makes it this byte is the two runs behind it. Neither the twenty-two
// characters nor the forty is written with an underscore — the first is read in
// the base62 alphabet, which leaves it out, and the second in hexadecimal — so
// a payload of either alphabet stops the search only where a separator actually
// stands, however long the payload runs. It is also the last byte of the
// prefix, so every stop has the whole prefix in hand and the reading back needs
// no bound of its own.
//
// It is not the rarest byte the prefix has on every text this scan runs over,
// and the text it is least rare on is CircleCI's own. Of the five bytes
// standing at a fixed index in both prefixes — the two Cs, the I, the P and
// this underscore — the P stands twice on the line these benchmarks are written
// on where the underscore stands four times, because that line is the
// environment CircleCI exports and every variable of it is written CIRCLE_
// something. CIRCLE_ is also the one opening where the byte tested before the
// prefix does not turn a stop away: it is seven characters closing on an
// underscore with a C six characters in front, which is a prefix's shape
// exactly, so each of those stops pays the comparison of a seven-byte string.
//
// A token can begin inside another, and the underscore bounds where. A
// candidate opens six characters in front of one; a span carries underscores at
// two places alone — the one its prefix closes with and the one dividing its
// middle from its tail — and a candidate read back from the second would need a
// third twenty-two characters further along, where a tail admits none. What is
// left is the positions whose underscore falls past the end of the span, and
// the tail narrows those to the last two characters of one: a prefix opens on
// C, C and then I, and the I is no hexadecimal digit, so a tail can carry the
// first two characters of a prefix and no more of it.
// Test_circleCIAPITokenPrefixes counts the positions out of the declarations
// and Test_CircleCIAPIToken_aTokenInsideAToken drives both.
//
// So the scan steps one byte past the start of a candidate, whether that
// candidate became a token or not, which is the default builtin_scan.go sets
// out: consuming a match would step over a token beginning at the end of it and
// leave that one in the output whole. The two spans overlap where it happens,
// and Masker.locate resolves them.
//
// The scan keeps no cursor and needs none: a candidate reads at most sixty-three
// bytes behind its prefix and stops, which bounds what it reads with no state to
// be wrong about, and is what rules out a quadratic input.
//
// What this pattern over-matches on is the vendor's format exactly, and a
// reader loses nothing to it: seventy characters opening on one of two literals
// carry nothing that can be read, so text landing inside the grammar is
// indistinguishable from a token and declining it would mean declining every
// token there is.
//
// The token CircleCI issued before this format is a credential this pattern
// does not locate, and cannot. It is forty hexadecimal characters with nothing
// in front of them, so the value says nothing about itself, and the tokens the
// changelog left working are still in use. What locating them would take is the
// name they are assigned to rather than the value — a different grammar, and
// one this pattern's name does not cover.
//
// referenceCircleCIAPITokenFind in builtin_circleci_api_token_test.go keeps the
// grammar as a regular expression, spelling the prefixes, the counts and the
// alphabets again so that the two are changed together, and the fuzz target
// beside it holds this scan to that expression.
var circleCIAPIToken = NewPattern("circleci-api-token", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := circleCIAPITokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], circleCIAPITokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not,
		// which is the default step and needs no claim about the grammar to
		// rest on. Stepping one byte past the anchor is what leaves the next
		// candidate one byte past this one, which builtin_scan.go sets out.
		offset = anchor + 1

		if anchor < circleCIAPITokenAnchorIndex {
			continue
		}
		start := anchor - circleCIAPITokenAnchorIndex

		// The byte every prefix opens with is tested before the prefixes are
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the prefixes is a length and a read apiece.
		//
		// The whole prefix is in hand at this line: the anchor is the last byte
		// of one, so a search that stopped anchorIndex bytes or more into the
		// input has every byte of the prefix behind it.
		if src[start] != circleCIAPITokenOpening[0] ||
			!isCircleCIAPITokenPrefix(src[start:start+circleCIAPITokenPrefixChars]) {
			continue
		}

		body := start + circleCIAPITokenPrefixChars
		end := start + circleCIAPITokenChars
		if end > len(src) {
			// The input ends inside the body, and the counts behind the prefix
			// are the whole of what tells a token from any other run written
			// there.
			retain = min(retain, start)
			continue
		}
		if isCircleCIAPITokenBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// circleCIAPITokenPrefixes is what a candidate opens with: one entry per kind,
// each of them the opening, the kind and the separator.
//
// They are built from those parts rather than written out, so that the table
// below is the one place a kind is named. A second list is one that can come to
// disagree about which kinds there are, and what a stream would then do with the
// kind it had not been told about is release the characters a token opens with
// and redact nothing.
var circleCIAPITokenPrefixes = func() []string {
	prefixes := make([]string, 0, len(circleCIAPITokenKinds))
	for _, kind := range circleCIAPITokenKinds {
		prefixes = append(prefixes, circleCIAPITokenOpening+kind+string(circleCIAPITokenSeparator))
	}
	return prefixes
}()

// circleCIAPITokenKinds is the kind each prefix names: PAT for the personal API
// token a user creates for themselves, PRJ for the project API token that reads
// and writes one project. They are the same string behind the prefix, which is
// why they are kinds of one pattern rather than two patterns.
var circleCIAPITokenKinds = []string{"PAT", "PRJ"}

const (
	// circleCIAPITokenOpening is what every prefix opens with, and is the byte
	// tested before the prefixes are compared.
	circleCIAPITokenOpening = "CCI"

	// circleCIAPITokenSeparator closes every prefix and divides the middle of a
	// token from its tail. It belongs to neither run behind the prefix, which
	// is what makes the search cheap over a payload and what bounds where a
	// token may begin inside another; Test_circleCIAPITokenPrefixes holds it to
	// standing once in every prefix.
	circleCIAPITokenSeparator = '_'

	// circleCIAPITokenKindChars is how many characters name the kind, and
	// circleCIAPITokenPrefixChars the whole of a prefix: the opening, the kind
	// and the separator.
	circleCIAPITokenKindChars   = 3
	circleCIAPITokenPrefixChars = len(circleCIAPITokenOpening) + circleCIAPITokenKindChars + 1

	// circleCIAPITokenAnchor is the byte the scan searches the input for and
	// circleCIAPITokenAnchorIndex is where it stands in every prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what makes it
	// this byte.
	circleCIAPITokenAnchor      = circleCIAPITokenSeparator
	circleCIAPITokenAnchorIndex = circleCIAPITokenPrefixChars - 1

	// circleCIAPITokenMiddleChars is how many letters and digits carry the
	// encoded UUID, and circleCIAPITokenTailChars how many hexadecimal
	// characters stand behind them. The rationale above says where each count
	// comes from.
	circleCIAPITokenMiddleChars = 22
	circleCIAPITokenTailChars   = 40

	// circleCIAPITokenBodyChars is everything behind the prefix — the middle,
	// the separator and the tail — and circleCIAPITokenChars is the whole of a
	// token. Test_circleCIAPITokenChars holds the second to seventy.
	circleCIAPITokenBodyChars = circleCIAPITokenMiddleChars + 1 + circleCIAPITokenTailChars
	circleCIAPITokenChars     = circleCIAPITokenPrefixChars + circleCIAPITokenBodyChars
)

// isCircleCIAPITokenPrefix reports whether s is a whole prefix: the opening, one
// of the kinds and the separator.
//
// It is handed the width as well as the characters so that the two are checked
// in one place rather than the width being left to the caller to have cut
// correctly.
func isCircleCIAPITokenPrefix(s string) bool {
	if len(s) != circleCIAPITokenPrefixChars {
		return false
	}
	return slices.Contains(circleCIAPITokenPrefixes, s)
}

// isCircleCIAPITokenBody reports whether s is everything behind the prefix of a
// token: circleCIAPITokenMiddleChars letters and digits, the separator, and
// circleCIAPITokenTailChars hexadecimal characters.
//
// It is handed the count as well as the characters for the reason
// isCircleCIAPITokenPrefix gives.
func isCircleCIAPITokenBody(s string) bool {
	if len(s) != circleCIAPITokenBodyChars {
		return false
	}

	// The separator is compared before either run is walked. It stands at a
	// fixed offset, and a candidate that is no token is turned away here by one
	// comparison rather than by twenty-two.
	if s[circleCIAPITokenMiddleChars] != circleCIAPITokenSeparator {
		return false
	}
	for i := range circleCIAPITokenMiddleChars {
		if !isBase62Byte(s[i]) {
			return false
		}
	}
	for i := circleCIAPITokenMiddleChars + 1; i < len(s); i++ {
		if !isCircleCIAPITokenHexByte(s[i]) {
			return false
		}
	}
	return true
}

// isCircleCIAPITokenHexByte reports whether c is a hexadecimal digit of either
// case, which is what the tail of a token is written in.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go,
// which hold what more than one scan reads. Every hexadecimal run this package
// reads keeps its own test for the reason its own file gives — one admits
// either case where another admits lowercase alone — and a shared test named
// for the class rather than for what reads it would silently be the wrong
// answer for one of them.
func isCircleCIAPITokenHexByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// circleCIAPITokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var circleCIAPITokenTail = newPrefixTail(circleCIAPITokenPrefixes...)
