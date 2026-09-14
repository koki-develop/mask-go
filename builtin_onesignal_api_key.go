package mask

import "strings"

// OneSignalAPIKey locates the API keys OneSignal issues: the prefix os_v2_app_
// or os_v2_org_ and the body behind it. Both scopes are located — the app key,
// which sends the messages of one app and reads the users and stats behind it,
// and the organization key, which reaches every app an organization holds and
// the keys themselves.
//
// A key is located wherever it is written, with no word boundary either side,
// and is redacted from its prefix to the end of the run it stands in. So a key
// written against a word character keeps its span, and a character of the key's
// own alphabet written straight after a key is redacted with it.
//
// Its name is "onesignal-api-key".
func OneSignalAPIKey() Pattern { return oneSignalAPIKey }

// API key is OneSignal's own term for the whole of what this locates. The two
// scopes have names of their own — an App API key and an Organization API key —
// and OneSignal writes both under that one term wherever it says what a value
// looks like, which is what the name here is held to. Nothing puts a boundary
// between them: both are secrets authenticating a caller to the same API, so a
// caller has no reason to enable one and not the other, and a redactor keying on
// the name has no decision the scope would answer.
//
// The prefix is what OneSignal states of the format, and it states os_v2_app_ on
// the page that tells a reader where to find a key. The os_v2_org_ prefix comes
// from the one rule stating this format; OneSignal's own pages spell os_v2_app_
// where they say what an Organization API key opens with. Reading the app prefix
// alone is the tightening that rests on that, and it is declined: an organization
// key reaches every app an account holds, what it would cost to miss one is that
// key left in a log whole, and nothing of OneSignal's says the rule is wrong —
// only that no page of OneSignal's repeats it.
//
// The alphabet and the count come from one example of OneSignal's own and one
// rule, and the two agree exactly: a hundred and three characters of a-z2-7,
// which is the base32 alphabet of RFC 4648 in lowercase. The example is the key
// OneSignal writes out whole in its quick start guide, to show what an
// Authorization header carries; the rule is betterleaks', which reads the two
// prefixes and that count. Neither is OneSignal undertaking to keep issuing
// keys of that width — no page of OneSignal's states a length at all — and a
// hundred and three characters is what the alphabet writes sixty-four bytes in,
// which is the only byte count it writes in that many.
//
// The count is read as a floor for that reason. Were OneSignal to lengthen the
// random part, a scan asking for a hundred and three exactly would locate the
// first hundred and three characters of a key and leave the rest of it in the
// output. Read as a floor, a key of any length at or above it is located to the
// end of its run. What the floor costs is the key shorter than it: a line cut to
// a column limit partway through one leaves a prefix and a body too short to be
// a body, and nothing is located.
// Test_OneSignalAPIKey_cutShortOfTheFloor pins that.
//
// The legacy keys OneSignal still accepts are not located. It removed the UI
// that manages them and states no format for them at all, so there is no prefix
// to read one by — and a pattern for what is left would be a net cast over
// values that carry meaning, which is what the gate every built-in is weighed at
// rules out.
//
// There is no boundary on either side of a match, because either one would drop
// a match rather than trim it: in front, wherever a key is written against a
// word character, and behind, wherever a character of the alphabet is written
// against one.
//
// The byte the scan searches the input for is the v of the version both prefixes
// carry, three characters in. builtin_scan.go says why a scan searches for one
// byte of what opens a candidate rather than for the whole of it; what makes it
// this byte is the text these keys are written in. OneSignal's own API is
// snake_case throughout — app_id, target_channel, included_segments — so a line
// about a request it served spells the underscore of the prefix several times
// over, and the digit 2 stands in every timestamp, where the o, the s, the a and
// the p are ordinary letters. Over the log line these benchmarks are written on
// the underscore stands four times and the 2 four, against one v.
//
// No cursor is kept over the run, and none is needed, which is what the
// separator buys. A body begins one byte past the underscore every prefix closes
// with and no body is written with one, so a run read here ends at or before the
// underscore of the next candidate, whose own body begins past it. One run is
// therefore read by one candidate, which is what rules out the quadratic input a
// run dense in prefixes would otherwise be.
// Test_oneSignalAPIKeyPrefixes_runsDoNotOverlap holds the prefixes to the one
// character that argument rests on, and Test_OneSignalAPIKey_scanIsLinear drives
// the inputs that would find it wrong.
//
// What this pattern over-matches on is a hundred and three characters of the
// alphabet standing behind one of those prefixes, which is a key's format
// exactly: there is nothing left in such a run to tell it from a key OneSignal
// issued. The prefix is what makes it rare. Three underscores and a digit are
// nothing prose arrives at, and standard base64 writes no underscore at all, so
// only a base64url encoding can hold one — and there the alphabet costs the rest
// again, a body being a hundred and three characters that are all of them in the
// half of base64url this reads.
//
// A hexadecimal digest behind the prefix is not the collision it is for a scan
// reading base62. Four of the sixteen hexadecimal digits — 0, 1, 8 and 9 — are
// ones this alphabet leaves out, so a run of a digest ends at the first of them
// it writes. A digest narrower than the floor cannot reach it however it was
// written, which covers every digest to a sha384; a wider one reaches it only
// where none of the four stands inside its first hundred and three characters,
// and there the run is redacted.
// Test_OneSignalAPIKey_aDigestBehindThePrefix writes out the digests this
// declines and Test_OneSignalAPIKey the wide run it locates.
//
// referenceOneSignalAPIKeyAt in builtin_onesignal_api_key_test.go states the
// grammar again, spelling the prefixes, the floor and the alphabet so that the
// two are changed together, and the fuzz target beside it holds this scan to
// that statement. It is written out rather than built on an expression, and the
// count is what settles that: the reference says why, and what it measured.
var oneSignalAPIKey = newBuiltin("onesignal-api-key", &oneSignalAPIKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := oneSignalAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], oneSignalAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not,
		// which is the default step builtin_scan.go sets out.
		offset = anchor + 1

		if anchor < oneSignalAPIKeyAnchorIndex {
			continue
		}
		start := anchor - oneSignalAPIKeyAnchorIndex

		prefix := oneSignalAPIKeyPrefixLen(src[start:])
		if prefix == 0 {
			continue
		}

		body := start + prefix
		end := oneSignalAPIKeyRunEnd(src, body)
		if end == len(src) {
			// The run reaches the end of the input, so nothing behind the
			// prefix is settled here: what comes next either carries the run on
			// and lengthens the span, or closes it. That holds whether or not
			// the floor has already been met. What is written of the body is not
			// read before giving up on it, for the reason builtin_scan.go gives.
			retain = min(retain, start)
		}
		if end-body >= oneSignalAPIKeyBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// oneSignalAPIKeyPrefixes is what a candidate opens with, one entry a scope: the
// opening every key carries, what that scope writes behind it, and the separator
// the body stands behind.
//
// They are built from those parts rather than written out, so that a scope added
// to oneSignalAPIKeyScopes is a scope the tail below knows about as well. A table
// written out beside them is one that can come to disagree about which scopes
// there are, and what a stream does with the scope it was not told about is
// release the characters a key opens with.
var oneSignalAPIKeyPrefixes = func() []string {
	prefixes := make([]string, 0, len(oneSignalAPIKeyScopes))
	for _, scope := range oneSignalAPIKeyScopes {
		prefixes = append(prefixes, oneSignalAPIKeyOpening+scope+oneSignalAPIKeySeparator)
	}
	return prefixes
}()

// oneSignalAPIKeyScopes is what each key writes between the opening and the
// separator: app for a key that reaches one app, org for one that reaches every
// app an organization holds.
var oneSignalAPIKeyScopes = [...]string{"app", "org"}

const (
	// oneSignalAPIKeyOpening is what every key opens with, and
	// oneSignalAPIKeySeparator is what every prefix closes with. The separator
	// is the character the run guarantee above rests on, and
	// Test_oneSignalAPIKeyPrefixes_runsDoNotOverlap holds it there.
	oneSignalAPIKeyOpening   = "os_v2_"
	oneSignalAPIKeySeparator = "_"

	// oneSignalAPIKeyBodyChars is the count a body is held to, read as a floor
	// rather than exactly. A hundred and three is what one example of
	// OneSignal's and the one rule stating this format agree on, and no page of
	// OneSignal's states a length at all. The rationale above weighs reading it
	// as a floor.
	oneSignalAPIKeyBodyChars = 103
)

const (
	// oneSignalAPIKeyAnchor is the byte the scan searches the input for and
	// oneSignalAPIKeyAnchorIndex is where it stands in every prefix, so a
	// candidate begins that many bytes in front of what a search reported. The
	// rationale above says what made it this byte.
	//
	// Every prefix carries it at this index, which is what lets one search serve
	// them all: a scope that spelled it elsewhere would be a scope no candidate
	// is ever found at, and Test_oneSignalAPIKeyAnchor reports that.
	oneSignalAPIKeyAnchor      = 'v'
	oneSignalAPIKeyAnchorIndex = 3
)

// oneSignalAPIKeyPrefixLen returns how many bytes of s the prefix standing at
// its start is, and zero where none of them does.
//
// No two prefixes stand at one position, so the first that matches is the only
// one that can. Test_oneSignalAPIKeyPrefixes_standAtNoOnePosition holds that,
// and says what a scope added later would otherwise cost.
func oneSignalAPIKeyPrefixLen(s string) int {
	for _, prefix := range oneSignalAPIKeyPrefixes {
		if strings.HasPrefix(s, prefix) {
			return len(prefix)
		}
	}
	return 0
}

// oneSignalAPIKeyRunEnd returns where the run of body characters beginning at i
// in src ends, which is len(src) where the run reaches the end of the input.
//
// The walk is this scan's own rather than one of the shared ones in
// builtin_scan.go, because the alphabet is: a body is written in thirty-two of
// the sixty-two characters base62 admits, and in neither of the two base64url
// adds to those.
func oneSignalAPIKeyRunEnd(src string, i int) int {
	for i < len(src) && isOneSignalAPIKeyByte(src[i]) {
		i++
	}
	return i
}

// isOneSignalAPIKeyByte reports whether c belongs to the alphabet a body is
// written in: the base32 alphabet of RFC 4648, in the lowercase the example
// OneSignal writes out and the one rule stating this format both read it in.
// The digits it leaves out are 0, 1, 8 and 9, which are the four base32 leaves
// out so that no character of it is taken for another.
func isOneSignalAPIKeyByte(c byte) bool {
	return 'a' <= c && c <= 'z' || '2' <= c && c <= '7'
}

// oneSignalAPIKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var oneSignalAPIKeyTail = newPrefixTail(oneSignalAPIKeyPrefixes...)
