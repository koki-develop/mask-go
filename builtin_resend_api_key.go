package mask

import "strings"

// ResendAPIKey locates Resend API keys: the prefix re_, eight letters and
// digits, an underscore and the twenty-four letters and digits that follow —
// thirty-six characters altogether. One string authenticates every request to
// the Resend API and is the password its SMTP endpoint takes as well, so
// whoever holds one can send mail from the account's verified domains.
//
// A key is located wherever it is written, with no word boundary either side,
// and exactly thirty-six characters of it are. So text of that shape is
// redacted whether or not Resend issued it. A space, a hyphen, a segment of the
// wrong length or an underscore anywhere but the two places one stands ends the
// reading, so text as it is ordinarily written is not affected. A longer run is
// a key with something written after it, and the key alone is redacted.
//
// Its name is "resend-api-key".
func ResendAPIKey() Pattern { return resendAPIKey }

// API key is Resend's own name for this string: the title of the page its
// documentation keeps on it, the object its HTTP reference creates and deletes,
// the variable RESEND_API_KEY its client libraries read, and the field every
// one of those libraries takes as its first argument. An account holds more
// than one — a key per environment, and a key scoped to a single verified
// domain — and each of them is the same string with no mark on it to tell one
// from another, so those put no boundary between patterns: a caller cannot act
// on a distinction the value does not carry. The SMTP endpoint takes the same
// string as its password, which is one more place a key is written rather than
// one more kind of key.
//
// Resend states the format twice, and both statements are the vendor's own. Its
// HTTP reference prints a whole key as the response to creating one —
// re_c1tpEyD8_NKFusih9vKVQknRAQfmFcWCv, which is the prefix, eight characters,
// an underscore and twenty-four more. And its Node client redacts the keys out
// of its own recorded fixtures before writing them to disk, with
// re_[a-zA-Z0-9]{8}_[a-zA-Z0-9]{24} — the counts, the separator and the
// alphabet spelled out by the vendor rather than inferred from what leaked. Two
// further whole keys stand in the fixtures that expression is run over, both of
// that same shape. So the prefix, both counts, the separator and the alphabet
// below are all read off the vendor's own statement of what a key is, and
// nothing here rests on a ruleset: gitleaks, trufflehog and betterleaks read
// this format not at all, the last of them leaving the key Resend publishes in
// the text when handed it.
//
// The alphabet is therefore the letters of both cases with the digits,
// isBase62Byte in builtin_scan.go. What it leaves out is the hyphen and the
// underscore, and the underscore is the one the whole scan below rests on: it
// closes the prefix and it divides the two segments, so it is the character a
// candidate is found by, and a segment admitting it would let the scan read a
// separator where a segment stands.
//
// Both counts are read exactly rather than as floors. A run longer than
// twenty-four is not one longer key but a key with something written after it,
// and only the key is redacted; running the alphabet out instead would swallow
// whatever word was written against the end of one. A first segment longer than
// eight is no key at all, since the separator then stands where a ninth
// character of that segment is. Resend states no second shape behind this
// prefix, so reading both exactly turns away nothing a range would have caught.
//
// The prefix is read in the one case Resend writes it. A prefix is the whole of
// what tells this format from text, so reading it in either case buys nothing —
// RE_ is no form a key is issued in — and costs a candidate opened at every
// uppercase spelling.
//
// There is no boundary on either side of a match. A boundary in front drops
// rather than trims the match wherever a key is written against a word
// character, which is what RESEND_API_KEY_re_... is and what a shell writes
// into a log line; one behind it drops a key followed by a letter or a digit,
// which under exact counts is a key with a character written after it. What may
// stand either side is held back by the character class and the counts alone.
//
// The byte the scan searches the input for is the underscore the prefix closes
// with, and the prefix is read back from it. builtin_scan.go says why a scan
// searches for one byte of its prefix rather than for the prefix itself; what
// makes it this byte is the other two. The r and the e are the two letters the
// vendor's own name, its host name and the word send are spelled with, and
// prose is worse again — over the log line these benchmarks are written on the
// e stands eight times and the r twice, where the underscore stands not once.
// Neither letter is rare in a body either, so a run of the alphabet a segment
// is read in would stop the search on about one character in thirty however
// long it ran, where the underscore stops it nowhere in one.
//
// What the underscore costs is that a key carries a second one, dividing its
// segments, so a line of keys stops the search twice a key rather than once.
// That second stop is answered by a single comparison: what stands two
// characters in front of a separator is a character of the first segment rather
// than the r a prefix opens with.
//
// That same character bounds where a key may be written inside another. A
// candidate begins two characters in front of an underscore, and the two
// underscores a span holds are its prefix's and its separator's, so three
// positions inside a span open a candidate: the one standing two characters in
// front of the separator, and each of the last two characters of the span, from
// which the underscore reading it back stands past the end of it.
//
// The first of the three opens a candidate that can never become a key. Reading
// a candidate back from the separator puts its own separator eight characters
// further on, which is inside the outer key's second segment, and that segment
// is written in an alphabet holding no underscore. So a key beginning inside
// another begins at the last two characters of the second segment and nowhere
// else. Test_resendAPIKeyPrefix counts the three positions out of the
// declarations that decide them, and Test_ResendAPIKey_aKeyInsideAKey drives
// all of them.
//
// So the scan steps one byte past the start of a candidate, whether that
// candidate became a key or not, which is the default: consuming a match would
// step over a key beginning at the end of it and leave that one in the output
// whole. The two spans overlap where it happens, and Masker.locate resolves
// them.
//
// The scan keeps no cursor and needs none: a candidate reads at most
// thirty-three bytes and stops, which bounds what it reads with no state to be
// wrong about, and is what rules out a quadratic input.
//
// What this pattern over-matches on is the vendor's format exactly, and there
// are two shapes text reaches it by. The first is base64url, the one alphabet
// in ordinary use that carries the underscore, so a payload written in it can
// hold a prefix and a separator where hexadecimal and standard base64 hold
// neither; what is taken there is a stretch of a value that was already opaque.
// The second is a snake-cased identifier, and it is the one worth stating: re_
// is a prefix a name can open with, and an identifier written re_, a segment of
// exactly eight characters, an underscore and a segment of exactly twenty-four
// is this format character for character. Twenty-four unbroken letters and digits are what a digest or an
// encoded field is written as rather than what a word is, which is what keeps
// the shape rare — and where one is written there is nothing left in the text
// to tell it from a key, so declining it would mean declining every key Resend
// issues. Test_ResendAPIKey_theShapesWrittenByAccident pins both.
//
// A digest reaches nothing on its own account, and its length has no part in
// that: hexadecimal carries no underscore, so one written behind the prefix is
// turned away where the separator should stand however long it runs. What a
// digest can do is stand as the second segment,
// which needs the first eight characters and the separator written in front of
// it, and then twenty-four of its characters go with them.
//
// The webhook signing secret Resend hands a handler is a credential this
// pattern does not locate, and cannot. It is written whsec_ and a base64 body,
// which carries no re_ to be found at — a credential this pattern's name does
// not cover rather than one the scan happens to miss.
//
// referenceResendAPIKeyFind in builtin_resend_api_key_test.go keeps the grammar
// as a regular expression, spelling the prefix, both counts, the separator and
// the alphabet again so that the two are changed together, and the fuzz target
// beside it holds this scan to that expression.
var resendAPIKey = NewPattern("resend-api-key", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := resendAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], resendAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for the
		// reason the rationale above gives: a second segment closing on re can open a
		// key thirty-four characters into the one it stands in, and a scan stepping
		// over what it took would leave that one whole.
		offset = anchor + 1

		if anchor < resendAPIKeyAnchorIndex {
			continue
		}
		start := anchor - resendAPIKeyAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != resendAPIKeyPrefix[0] || !strings.HasPrefix(src[start:], resendAPIKeyPrefix) {
			continue
		}

		body := start + len(resendAPIKeyPrefix)
		end := start + resendAPIKeyChars
		if end > len(src) {
			// The input ends inside the body, and the counts are the whole of
			// what tells a key from any other run written behind the prefix.
			retain = min(retain, start)
			continue
		}
		if isResendAPIKeyBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// resendAPIKeyPrefix is what every API key opens with, and what the scan
	// reads back from its anchor. It closes on the character that divides the
	// two segments as well, which is what makes the search cheap on a line
	// holding no key and what bounds where a key may begin inside another;
	// Test_resendAPIKeyPrefix holds it to both.
	resendAPIKeyPrefix = "re_"

	// resendAPIKeyAnchor is the byte the scan searches the input for and
	// resendAPIKeyAnchorIndex is where it stands in the prefix, so a candidate
	// begins that many bytes in front of what a search reported. builtin_scan.go
	// says why a scan searches for one byte of its prefix rather than for the
	// prefix itself; the rationale above says what makes it this byte and what
	// it costs.
	resendAPIKeyAnchor      = '_'
	resendAPIKeyAnchorIndex = 2

	// resendAPIKeySeparator divides the two segments. It is the character the
	// prefix closes with as well, which is what makes a key carry two of them.
	resendAPIKeySeparator = '_'

	// resendAPIKeyIDChars is how many letters and digits stand between the
	// prefix and the separator, and resendAPIKeySecretChars how many stand
	// behind the separator. Both are read exactly rather than as floors, for
	// the reason the rationale above gives.
	resendAPIKeyIDChars     = 8
	resendAPIKeySecretChars = 24

	// resendAPIKeyChars is the whole of a key: the prefix, the two segments and
	// the separator between them. Test_resendAPIKeyChars holds it to the
	// thirty-six characters the key Resend publishes is.
	resendAPIKeyChars = len(resendAPIKeyPrefix) + resendAPIKeyIDChars + 1 + resendAPIKeySecretChars
)

// isResendAPIKeyBody reports whether s is everything behind the prefix of a
// key: resendAPIKeyIDChars letters and digits, the separator, and
// resendAPIKeySecretChars letters and digits.
//
// It is handed the counts as well as the characters so that they are checked in
// one place rather than being left to the caller to have cut correctly.
func isResendAPIKeyBody(s string) bool {
	if len(s) != resendAPIKeyIDChars+1+resendAPIKeySecretChars {
		return false
	}
	if s[resendAPIKeyIDChars] != resendAPIKeySeparator {
		return false
	}
	for i := range len(s) {
		if i == resendAPIKeyIDChars {
			continue
		}
		if !isBase62Byte(s[i]) {
			return false
		}
	}
	return true
}

// resendAPIKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var resendAPIKeyTail = newPrefixTail(resendAPIKeyPrefix)
