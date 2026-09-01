package mask

import "strings"

// PaddleAPIKey locates the API keys Paddle issues: the four characters pdl_,
// the environment written as live or sdbx, the eight characters _apikey_, then
// twenty-six lowercase letters and digits, an underscore, twenty-two letters
// and digits, a second underscore and three more — sixty-nine characters
// altogether.
//
// A key is located wherever it is written, with no word boundary either side,
// and exactly sixty-nine characters of it are. So text of that shape is
// redacted whether or not Paddle issued it. A space, an underscore out of
// place, an uppercase letter in the first segment or a segment of the wrong
// length ends the reading, so text as it is ordinarily written is not affected.
//
// Its name is "paddle-api-key".
func PaddleAPIKey() Pattern { return paddleAPIKey }

// Paddle states this format itself, and states it as a grammar rather than as
// an example. Its API keys page divides a key into the parts it is built from —
// pdl_ identifying a Paddle API key, live_ or sdbx_ identifying the
// environment, apikey_ differentiating the key from a client-side token, and a
// twenty-six character alphanumeric string it calls the API key — writes that a
// key is sixty-nine characters in length and always contains five underscores,
// and then publishes the expression a key matches, anchored at both ends:
// pdl_(live|sdbx)_apikey_ and the three segments spelled [a-z\d]{26},
// [a-zA-Z\d]{22} and [a-zA-Z\d]{3} behind it. That is the vendor stating both
// openings, all three alphabets and all three counts in one line, and the scan
// below reads exactly it.
//
// The two environments are one pattern rather than two. A key of either
// authenticates the same API and is written the same way, so a caller with
// reason to redact one has the same reason for the other, and nothing a
// redactor keying on Match.Pattern could act on separates them. GitHub carries
// them as two partner patterns, Paddle API Key under paddle_api_key and Paddle
// Sandbox API Key under paddle_sandbox_api_key, both with push protection; that
// is a division a scanner reports its findings by, not one a caller switches
// on. API key is Paddle's own term for the whole of what this locates — the
// page stating the format is headed Manage API keys, and it is the term the
// component list uses to separate a key from the client-side token that carries
// no pdl_ opening at all.
//
// The counts are read exactly rather than as floors, for the reason the
// Dynatrace scan gives: a run of the alphabet longer than a count is not one
// longer key but a key with something written after it, and only the key is
// redacted. None of the three is read off a value somebody was shown — each is
// a number Paddle writes in the expression it publishes, and the sixty-nine
// they come to with the prefix is a number it writes in prose besides.
//
// The first segment is read in lowercase and the digits, the two behind it in
// base62 — isBase62Byte in builtin_scan.go — which is the class the vendor's
// expression spells for each of them. The tightening on offer in the first
// segment is Crockford's base32: twenty-six lowercase characters carrying
// neither i, l, o nor u is what a ULID is written in, and the first segment of
// the key Paddle publishes carries none of the four, as the same segment of the
// webhook secret key it prints carries none. It is declined because the
// vendor's own expression admits the whole of the lowercase alphabet, and a
// class narrowed on the values somebody was shown locates nothing at all the
// day a key arrives with an l in it — the whole credential rather than the end
// of one. What declining it admits is four more letters in a segment already
// decided by a sixteen character prefix and two counts behind it.
// Test_PaddleAPIKey_aFirstSegmentOutsideCrockfordsAlphabet drives it.
//
// The webhook secret key is the other credential Paddle writes with the pdl_
// opening, and the marker is what turns it away: the vendor prints one as
// pdl_ntfset_ and two segments, which is what its component list says apikey_
// is there to differentiate a key from. Nothing Paddle publishes states a
// length or an alphabet for it — there is one example and no grammar — so
// reading it would take a pattern built on whatever Paddle comes to state.
// Test_PaddleAPIKey_theWebhookSecretKey pins the decision.
//
// The keys issued before 6 May 2025 are not read either, and they are live
// credentials: Paddle calls them legacy keys, states that they continue to work
// without disruption, and describes them as a random string of fifty characters
// holding only lowercase letters and digits. There is no prefix to search for
// and nothing but a length over an alphabet to read, which is the loose grammar
// this package declines rather than the unlucky one — fifty lowercase
// characters is a git SHA written twice over, a base32 payload, or an
// identifier some other vendor assigns.
// Test_PaddleAPIKey_theKeyFormatItReplaced pins it.
//
// The byte the scan searches the input for is the k of the marker, twelve
// characters into every prefix, and the prefix is read back from it.
// builtin_scan.go says why a scan searches for one byte of its prefix rather
// than for the prefix itself; what makes it this byte is that the underscore,
// which the prefix carries three times and which no segment is written with, is
// also the character every environment name and every snake_case field of a
// structured log is written with — PADDLE_API_KEY= carries three of them before
// a key begins. Over the line these benchmarks are written on the k stands not
// at all, where the p stands four times, the l six and the a seven. What it
// costs instead is the k a key's own segments may carry, which base62 admits
// and no underscore could be: each of those stops the search for one comparison
// against the byte twelve characters in front of it.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a key or not, which is the default. It is what a key
// beginning inside another needs, and one can: the three letters the opening
// starts with are lowercase, so a second segment may close on pdl with the
// underscore in front of the third segment behind them, and where the third
// segment reads liv and the text carrying on from the key writes e_apikey_ and
// the segments of one, a whole key begins sixty-two characters into the one in
// front of it. A scan consuming its match would step over that key and leave it
// in the output whole. The two spans overlap where it happens, and
// Masker.locate resolves them.
// Test_PaddleAPIKey_aKeyBeginningInsideAnother drives it.
//
// The scan keeps no cursor and needs none: a candidate reads at most sixty-nine
// bytes and stops, which bounds what it reads with no state to be wrong about —
// the guarantee a scan reading a body to the end of its run has to buy with a
// run cursor instead, bought here by the counts being counts.
//
// What this pattern over-matches on is sixty-nine characters of exactly that
// shape that nobody issued. Sixteen characters spelling the vendor's opening,
// an environment it names and the marker have to be written first, and behind
// them two underscores stand at fixed distances in text that may hold no other:
// base62, standard base64 and base32 write no underscore at all, so an
// identifier, a digest or an encoded payload carries no candidate at however
// long it runs, and base64url writes one wherever the bits fall rather than at
// the twenty-seventh and fiftieth character behind a marker. What is left is
// text written to that shape on purpose.
//
// What reaches a span is never prose, a git SHA or an MD5. Twenty-six unbroken
// characters have to stand behind the marker before the first underscore may
// come, which is longer than an English word and shorter than either digest
// written whole.
//
// referencePaddleAPIKey in builtin_paddle_api_key_test.go keeps the grammar as
// a regular expression, spelling both openings, all three counts and all three
// character classes again so that the two are changed together, and the fuzz
// target beside it holds this scan to that expression. An expression is
// affordable here: all three repetitions are exact, so the machine an engine
// builds for a candidate is read once and stops, and what an engine searches
// the text for is the four character literal in front of the alternation, which
// no segment can hold — the underscore closing it is written in none of them.
var paddleAPIKey = newBuiltin("paddle-api-key", &paddleAPIKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := paddleAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], paddleAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for
		// the reason the rationale above gives: a key can begin sixty-two
		// characters into the one in front of it, and a scan stepping over what
		// it took would leave that one whole.
		offset = anchor + 1

		if anchor < paddleAPIKeyAnchorIndex {
			continue
		}
		start := anchor - paddleAPIKeyAnchorIndex

		// The byte every prefix opens with is tested before the prefixes are
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison against each prefix is a length and a read apiece.
		if src[start] != paddleAPIKeyOpening[0] || !opensPaddleAPIKeyAt(src, start) {
			continue
		}

		body := start + paddleAPIKeyPrefixChars
		end := start + paddleAPIKeyChars
		if end > len(src) {
			// The input ends inside this candidate, so the counts that are the
			// whole of what tells it from anything else written behind a prefix
			// cannot be taken here.
			retain = min(retain, start)
			continue
		}
		if isPaddleAPIKeyBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// paddleAPIKeyOpening is what every prefix opens with, and
	// paddleAPIKeyMarker what closes it. The marker is what separates an API
	// key from the webhook secret key Paddle writes with the same opening,
	// which is the job the vendor's own component list gives it.
	paddleAPIKeyOpening = "pdl_"
	paddleAPIKeyMarker  = "_apikey_"

	// paddleAPIKeyEnvironmentChars is what an environment name is written to.
	// Both of the two are four characters, which is what lets a prefix be one
	// length and a candidate be read back from one index;
	// Test_paddleAPIKeyPrefixes holds every environment to it.
	paddleAPIKeyEnvironmentChars = 4

	// paddleAPIKeyPrefixChars is the whole of a prefix: the opening, the
	// environment and the marker.
	paddleAPIKeyPrefixChars = len(paddleAPIKeyOpening) + paddleAPIKeyEnvironmentChars + len(paddleAPIKeyMarker)

	// paddleAPIKeyAnchor is the byte the scan searches the input for and
	// paddleAPIKeyAnchorIndex is where it stands in every prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what made it
	// this byte. Test_paddleAPIKeyPrefixes holds it to standing there.
	paddleAPIKeyAnchor      = 'k'
	paddleAPIKeyAnchorIndex = 12

	// paddleAPIKeySeparator divides the three segments. It belongs to no
	// segment's alphabet, which is what ends a segment where it stands and what
	// makes the counts either side of it readable at all.
	paddleAPIKeySeparator = '_'

	// The counts the three segments are written to, all three of them numbers
	// Paddle states in the expression it publishes. It names only the first of
	// the three — its component list calls the twenty-six characters the API
	// key — so the names here are positional rather than claims about what a
	// segment holds.
	paddleAPIKeyFirstSegmentChars  = 26
	paddleAPIKeySecondSegmentChars = 22
	paddleAPIKeyThirdSegmentChars  = 3

	// Where the two separators stand in the body, which is everything behind
	// the prefix.
	paddleAPIKeyFirstSeparatorIndex  = paddleAPIKeyFirstSegmentChars
	paddleAPIKeySecondSeparatorIndex = paddleAPIKeyFirstSeparatorIndex + 1 + paddleAPIKeySecondSegmentChars

	// paddleAPIKeyBodyChars is the whole body: the three segments and the two
	// separators between them.
	paddleAPIKeyBodyChars = paddleAPIKeySecondSeparatorIndex + 1 + paddleAPIKeyThirdSegmentChars

	// paddleAPIKeyChars is the whole of a key, the sixty-nine characters Paddle
	// writes a key is. Test_paddleAPIKeyChars holds it to that number and to
	// the five underscores the same page counts.
	paddleAPIKeyChars = paddleAPIKeyPrefixChars + paddleAPIKeyBodyChars
)

// paddleAPIKeyEnvironments is what Paddle writes between the opening and the
// marker: the live environment and the sandbox. They are the alternation its
// own expression spells and no more — a third name would be one Paddle had
// published, and a key written with anything else is nothing this vendor
// issued.
var paddleAPIKeyEnvironments = [...]string{"live", "sdbx"}

// paddleAPIKeyPrefixes is what a candidate opens with, one entry per
// environment.
//
// They are built from the parts rather than written out again, so that an
// environment added to the table above is one both the scan and the tail know
// about. A table of whole prefixes kept beside it is one that can come to
// disagree about which environments there are, and what a stream would then do
// with the environment it had not been told about is release the characters a
// key opens with and redact nothing.
var paddleAPIKeyPrefixes = func() []string {
	prefixes := make([]string, 0, len(paddleAPIKeyEnvironments))
	for _, env := range paddleAPIKeyEnvironments {
		prefixes = append(prefixes, paddleAPIKeyOpening+env+paddleAPIKeyMarker)
	}
	return prefixes
}()

// paddleAPIKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var paddleAPIKeyTail = newPrefixTail(paddleAPIKeyPrefixes...)

// opensPaddleAPIKeyAt reports whether one of the prefixes stands whole at i in
// src.
//
// A prefix the end of the input cut short is not this walk's to report: every
// prefix is a literal, so paddleAPIKeyTail answers for the piece of one
// standing at the end of the input, which is what builtin_scan.go asks of a
// scan opening on literals.
func opensPaddleAPIKeyAt(src string, i int) bool {
	for _, prefix := range paddleAPIKeyPrefixes {
		if strings.HasPrefix(src[i:], prefix) {
			return true
		}
	}
	return false
}

// isPaddleAPIKeyBody reports whether s is everything behind the prefix of a
// key: paddleAPIKeyFirstSegmentChars lowercase letters and digits, the
// separator, paddleAPIKeySecondSegmentChars letters and digits, the separator
// again, and paddleAPIKeyThirdSegmentChars more.
//
// It is handed the counts as well as the characters so that they are checked in
// one place rather than being left to the caller to have cut correctly. Both
// separators are tested before any segment is walked: a candidate that is not a
// key is usually not one at one of those two characters — every digest and
// every encoded payload written behind a prefix is turned away there — and two
// comparisons decline it where up to forty-eight byte tests would.
func isPaddleAPIKeyBody(s string) bool {
	if len(s) != paddleAPIKeyBodyChars {
		return false
	}
	if s[paddleAPIKeyFirstSeparatorIndex] != paddleAPIKeySeparator ||
		s[paddleAPIKeySecondSeparatorIndex] != paddleAPIKeySeparator {
		return false
	}
	for i := range paddleAPIKeyFirstSeparatorIndex {
		if !isPaddleAPIKeyFirstSegmentByte(s[i]) {
			return false
		}
	}
	for i := paddleAPIKeyFirstSeparatorIndex + 1; i < len(s); i++ {
		if i == paddleAPIKeySecondSeparatorIndex {
			continue
		}
		if !isBase62Byte(s[i]) {
			return false
		}
	}
	return true
}

// isPaddleAPIKeyFirstSegmentByte reports whether c belongs to the alphabet the
// first segment is written in: the lowercase letters and the digits, which is
// the class Paddle's expression spells for it.
//
// The two segments behind it are read in base62 instead, which is the wider
// class the same expression spells for each of them. Neither class is narrowed
// nor widened here: both are the vendor's.
func isPaddleAPIKeyFirstSegmentByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'z'
}
