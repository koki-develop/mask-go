package mask

import "strings"

// ReplicateAPIToken locates Replicate API tokens: the prefix r8_ and the
// thirty-seven letters and digits behind it — forty characters altogether. One
// string authenticates every request to Replicate's HTTP API, so nothing in a
// token says what it may be spent on or which of an owner's tokens it is.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly forty characters of it are. So text of that shape is redacted
// whether or not Replicate issued it. A space, a hyphen, an underscore or a run
// of fewer than thirty-seven letters and digits ends the reading, so text as it
// is ordinarily written is not affected. A longer run is a token with something
// written after it, and the token alone is redacted.
//
// Its name is "replicate-api-token".
func ReplicateAPIToken() Pattern { return replicateAPIToken }

// API token is Replicate's own name for this string, the title of the page its
// documentation keeps on it and the term GitHub's partner pattern for the same
// value is filed under. The page names the reasons an owner holds more than one
// — development against staging against production, one project against
// another — and gives each of them the same string with no mark on it to tell
// one from another, which is why those put no boundary between patterns: a
// caller cannot act on a distinction the value does not carry.
//
// What Replicate states about the format is one sentence, and what is unusual
// about it is that it states a whole count and not only a prefix: an API token
// is forty characters and always opens with r8_. The HTTP reference states the
// same count a second way, by printing a token masked to its own length — r8_Hw
// and thirty-five asterisks, which is forty characters. Neither page says what
// alphabet the thirty-seven behind the prefix are written in, and neither do
// the client libraries, which read the token out of the environment and send it
// as a bearer credential without looking at it.
//
// So the count below is the vendor's and the alphabet below is not, and the
// rulesets are where the alphabet comes from. betterleaks reads r8_ and
// thirty-seven letters and digits, matched in either case, with a delimiter
// asked for behind. kingfisher reads the same prefix, count and alphabet, drops
// what falls at or below an entropy floor or carries fewer than three digits,
// and publishes four whole tokens as its examples — each of them forty
// characters, spelled in the letters of both cases with the digits, which is
// what pins the alphabet to something shown rather than only asked for.
// trufflehog reads the same count and admits the hyphen and the underscore
// besides. gitleaks and Google's osv-scalibr read this format not at all.
//
// GitHub carries it as a partner pattern under the token identifier
// replicate_api_token, with push protection and a validity check. A partner
// pattern is one the vendor wrote and gave to GitHub rather than one somebody
// inferred from published tokens, though GitHub publishes what it detects and
// not the expression it detects with.
//
// The alphabet is therefore the letters of both cases with the digits,
// isBase62Byte in builtin_scan.go, and what has to be argued is the one reading
// that is wider. Admitting the hyphen and the underscore casts a net over text
// that carries meaning: r8_ and thirty-seven characters of letters, digits,
// hyphens and underscores is the shape a snake-cased identifier or a hyphenated
// slug reaches, where the same run written in letters and digits alone is not
// something anybody writes. None of the four tokens kingfisher publishes
// carries either character, and the underscore is the one the whole scan below
// rests on besides — it closes the prefix, and a body admitting it would let a
// run of a body open candidates the way a run of prefixes does.
//
// The count is read exactly rather than as a floor. A run longer than
// thirty-seven is not one longer token but a token with something written after
// it, and only the token is redacted; running the alphabet out instead would
// swallow whatever word was written against the end of one. Replicate states no
// second shape behind this prefix, so reading it exactly turns away nothing a
// range would have caught.
//
// The prefix is read in the one case Replicate writes it. A prefix is the whole
// of what tells this format from text, so reading it in either case buys
// nothing — R8_ is no form a token is issued in — and costs a candidate opened
// at every uppercase spelling. betterleaks is the one ruleset that reads it
// without regard to case; the other two read it as Replicate writes it.
//
// There is no boundary on either side of a match, and here that is a
// disagreement with all three rulesets, since each of them writes a boundary in
// front and two of them behind. A boundary in front drops rather than trims the
// match wherever a token is written against a word character, which is what
// REPLICATE_API_TOKEN_r8_... is and what a shell writes into a log line; one
// behind it drops a token followed by a letter or a digit, which under an exact
// count is a token with a character written after it. What may stand either
// side is held back by the character class and the count alone.
//
// The byte the scan searches the input for is the underscore the prefix closes
// with, and the prefix is read back from it. builtin_scan.go says why a scan
// searches for one byte of its prefix rather than for the prefix itself; what
// makes it this byte is the other two. The r opens the vendor's own name and
// its host name, and stands five times on the line these benchmarks are written
// on where the underscore stands not once; the 8 is a digit, so a run of the
// alphabet a body is read in would stop the search about once every sixty-two
// characters however long it ran. The underscore stops it nowhere in a body,
// since that alphabet leaves the character out.
//
// That same character bounds where a token may be written inside another,
// without ruling it out. A candidate begins two characters in front of the
// underscore its prefix closes with, and the one underscore a span holds is
// that of its own prefix, so the positions inside a span that open a candidate
// are the last two characters of the body and no others: from either of those
// the underscore reading them back stands past the end of the span, where
// anywhere earlier it would have to stand inside the body and a body has none.
// A body closing on r8 with an underscore written after it is such a token,
// thirty-eight characters into the one it stands in.
// Test_ReplicateAPIToken_aTokenInsideAToken drives that shape, and
// Test_replicateAPITokenPrefix counts the positions.
//
// So the scan steps one byte past the start of a candidate, whether that
// candidate became a token or not, which is the default: consuming a match
// would step over a token beginning at the end of it and leave that one in the
// output whole. The two spans overlap where it happens, and Masker.locate
// resolves them.
//
// The scan keeps no cursor and needs none: a candidate reads at most
// thirty-seven bytes and stops, which bounds what it reads with no state to be
// wrong about, and is what rules out a quadratic input.
//
// What this pattern over-matches on is thirty-seven letters and digits written
// behind the prefix, which is the vendor's format exactly, and the shape worth
// stating is the digest: a SHA-1 is forty hexadecimal characters and a SHA-256
// sixty-four, so r8_ written in front of either is redacted for thirty-seven of
// them with the rest left in the text. There is nothing left to tell the two
// apart — a scan declining thirty-seven letters and digits behind this prefix
// declines every token there is — and what has to be written to reach it is the
// prefix with a digest against it and nothing between.
// Test_ReplicateAPIToken_aDigestBehindThePrefix pins the decision. An MD5 is
// thirty-two characters and reaches nothing at all, being five short.
//
// The other shape is base64url text, and it is the one the prefix is written by
// accident in. That alphabet holds the underscore where hexadecimal and
// standard base64 do not, so a payload written in it — a JWT signature, the
// routable body some other vendor encodes a credential as — carries r8_ about
// once in the two hundred and sixty thousand characters three bytes of a
// sixty-four character alphabet come to, and where the thirty-seven behind it
// are letters and digits alone those forty are redacted. What is taken there is
// a stretch of a value that was already opaque.
// Test_ReplicateAPIToken_thePrefixInsideBase64URL pins it.
//
// What reaches a span is never prose: the prefix closes on an underscore, which
// no word runs into, and behind it must stand thirty-seven unbroken letters and
// digits.
//
// The webhook signing secret Replicate hands a handler is a credential this
// pattern does not locate, and cannot. It is written whsec_ and a base64 body,
// which carries no r8_ to be found at — a credential this pattern's name does
// not cover rather than one the scan happens to miss.
//
// referenceReplicateAPITokenFind in builtin_replicate_api_token_test.go keeps
// the grammar as a regular expression, spelling the prefix, the count and the
// alphabet again so that the two are changed together, and the fuzz target
// beside it holds this scan to that expression.
var replicateAPIToken = NewPattern("replicate-api-token", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := replicateAPITokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], replicateAPITokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not, for the
		// reason the rationale above gives: a body closing on r8 can open a token
		// thirty-eight characters into the one it stands in, and a scan stepping over
		// what it took would leave that one whole.
		offset = anchor + 1

		if anchor < replicateAPITokenAnchorIndex {
			continue
		}
		start := anchor - replicateAPITokenAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != replicateAPITokenPrefix[0] || !strings.HasPrefix(src[start:], replicateAPITokenPrefix) {
			continue
		}

		body := start + len(replicateAPITokenPrefix)
		end := start + replicateAPITokenChars
		if end > len(src) {
			// The input ends inside the body, and the count is the whole of
			// what tells a token from any other run written behind the prefix.
			retain = min(retain, start)
			continue
		}
		if isReplicateAPITokenBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// replicateAPITokenPrefix is what every API token opens with, and what the
	// scan reads back from its anchor. It closes on a character no body is
	// written with, which is what makes the search cheap on a line holding no
	// token and what bounds where a token may begin inside another;
	// Test_replicateAPITokenPrefix holds it to both.
	replicateAPITokenPrefix = "r8_"

	// replicateAPITokenAnchor is the byte the scan searches the input for and
	// replicateAPITokenAnchorIndex is where it stands in the prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what makes it
	// this byte.
	replicateAPITokenAnchor      = '_'
	replicateAPITokenAnchorIndex = 2

	// replicateAPITokenBodyChars is how many letters and digits stand behind
	// the prefix. It is what the forty characters Replicate states a token is
	// leave once the prefix is taken off, read exactly rather than as a floor
	// for the reason the rationale above gives.
	replicateAPITokenBodyChars = 37

	// replicateAPITokenChars is the whole of a token: the prefix and the body.
	// Test_replicateAPITokenChars holds it to the forty Replicate states.
	replicateAPITokenChars = len(replicateAPITokenPrefix) + replicateAPITokenBodyChars
)

// isReplicateAPITokenBody reports whether s is everything behind the prefix of
// a token: exactly replicateAPITokenBodyChars letters and digits.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count being left to the caller to have cut
// correctly.
func isReplicateAPITokenBody(s string) bool {
	if len(s) != replicateAPITokenBodyChars {
		return false
	}
	for i := range len(s) {
		if !isBase62Byte(s[i]) {
			return false
		}
	}
	return true
}

// replicateAPITokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var replicateAPITokenTail = newPrefixTail(replicateAPITokenPrefix)
