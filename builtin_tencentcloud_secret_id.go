package mask

import "strings"

// TencentCloudSecretID locates Tencent Cloud SecretIds: thirty-six characters
// opening with AKID, which name the account or the sub-user a signed call is
// made as, and sixty-eight opening with the same four, which are what a
// temporary credential carries in that place.
//
// A SecretId is located wherever it is written, with no word boundary either
// side, and exactly as many characters of it are as its own shape comes to. So
// text of either shape is redacted whether or not Tencent Cloud issued it. A
// space, a dot or a run shorter than the count ends the reading, so text as it
// is ordinarily written is not affected. A longer run is a SecretId with
// something written after it, and the SecretId alone is redacted.
//
// Its name is "tencentcloud-secret-id".
func TencentCloudSecretID() Pattern { return tencentCloudSecretID }

// Tencent Cloud states the prefix and nothing else. Its API authentication
// page is where a SecretId is described at all — the value identifying the
// requester, written beside the SecretKey that signs — and the example it
// prints is masked in the middle, so it corroborates no count byte for byte.
// The CAM page on managing access keys, the STS pages on temporary credentials
// and the signature algorithm pages beside them state no length, no alphabet
// and no count. Neither the SDKs nor the CLI validates one: both read a
// SecretId as a string they are handed and nothing more.
//
// So the two counts below rest on the examples Tencent Cloud publishes rather
// than on a sentence of its own, which is the weaker of the two kinds of source
// the rules for these patterns set out, and the same footing
// builtin_aws_access_key_id.go states for its own count. What those examples
// come to is a distribution rather than a format, and the counts are read off
// its two peaks. Over the reference the vendor publishes for its CLI, setting
// aside the values it masks in the open — a bare prefix, a prefix with a
// handful of x behind it, a value with asterisks through its middle — the
// distinct bodies fall on thirty-two characters fourteen times and on
// sixty-four fourteen times, with eighteen more spread from twelve characters
// to forty-seven and no length among those eighteen reaching five.
//
// Those eighteen are read as examples written short rather than as lengths a
// SecretId is issued at, and that reading is the wager this pattern is built
// on. A format issuing bodies across that spread would not leave twenty-eight
// of its forty-six examples on two exact counts; a vendor abbreviating a value
// for a page would leave exactly this, since it already abbreviates in three
// other ways on the same pages. But the reading is a reading, and what it costs
// is a SecretId of another length left in the output whole.
//
// The spread is where that cost is nearest, and it is not far off: the vendor
// prints a body of twenty-eight characters as the example for the SecretId
// field of its own API reference, and this scan leaves it alone.
// Test_TencentCloudSecretID_noMatch carries a body of that length so the
// decision is on the record. The wager is bounded in the other direction too,
// the way a count is: were Tencent Cloud to issue a SecretId longer than these,
// the characters past the count would be left in the output.
//
// A length Tencent Cloud states in words is what these counts give way to, and
// the pages named above are where such a sentence would stand. None of them
// carries one, and the masked example one of them prints is no length either: a
// docs mask may elide rather than stand byte for byte.
//
// The alphabets divide along the same line and are read off the same examples,
// and they rest on firmer ground than the counts do. Not one of the four
// hundred and forty-eight characters the fourteen shorter bodies come to is a
// hyphen or an underscore, which is not a way fourteen draws from base64url
// fall; twelve of the fourteen longer bodies carry one or the other. So the
// shorter body is read in the letters and the digits and the longer in the
// whole of base64url.
//
// The two shapes are one pattern rather than two, which the rules for these
// patterns settle on the caller rather than on the scanning. Neither is
// published by design and neither is the identifier the other is kept under:
// both are written into the same field of a signed request — the SDK's
// credential carries one SecretId whether the call is made with a long-lived
// key or with a temporary one, and its constructor for the second names that
// field a SecretId as well — so a caller with reason to redact one has the same
// reason for the other, and a redactor keying on Match.Pattern has nothing to
// tell them apart by. SecretId is the term Tencent Cloud uses for the whole of
// what this locates, which is what the name is held to. The same decision, for
// the same reasons, puts the long-term and the temporary access key ID of AWS
// under one pattern in the file beside this one.
//
// The longer shape is tried first, and that is load-bearing rather than tidy.
// The shorter body's alphabet is inside the longer one's, so a temporary
// SecretId carrying neither the hyphen nor the underscore in its first
// thirty-two characters opens with the shorter shape exactly. A scan taking the
// shorter reading first would report a span inside such a value and leave the
// thirty-two characters behind it in the text — and, where the end of the input
// cut the longer shape short, would settle the text behind it and let a stream
// write those characters out. So the longer candidate is read first, and where
// the end of the input cuts it short the text is held from the start of the
// candidate whether or not the shorter reading is whole.
//
// What that order costs is the other side of the same reading, and it is a case
// so that reversing the order means arguing with both: a SecretId of the
// shorter shape with any run of base64url written straight
// against it is sixty-four characters of that alphabet behind the prefix, so
// the longer reading takes the value and thirty-two characters of whatever
// followed it. Nothing in the text tells that apart from a temporary SecretId —
// the two are the same sixty-eight bytes — and what is taken with the value is
// opaque either way, where the other order leaves the tail of a real temporary
// SecretId in a log.
// Test_TencentCloudSecretID_theTemporaryShapeOpensWithTheShorterOne drives the
// gain and the cost alike.
//
// There is no boundary on either side of a match. A boundary in front would
// drop rather than trim the match wherever a SecretId is written against a word
// character, which TENCENTCLOUD_SECRET_ID_AKID... is; one behind it would drop
// a SecretId followed by a letter or a digit, which under an exact count is a
// SecretId with a character written after it. What may stand either side is
// held back by the character classes and the counts alone.
//
// The byte the scan searches the input for is the K, one character into the
// prefix. builtin_scan.go says why a scan searches for one byte of its prefix
// rather than for the prefix itself; what makes it this byte is that it is the
// rarest of the four over the text these patterns are driven with. Over the
// shapes the conformance corpus keeps — log lines, JSON, command lines — the K
// stands thirty-eight times where the A stands fifty-five, the D forty-three
// and the I eighty-eight, and a capital A opens the acronyms and the
// capitalised words a log line is full of besides.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a SecretId or not, which is the default and needs no
// argument. Every character of the prefix is written in both body alphabets, so
// a whole prefix can stand anywhere inside a body and a SecretId written inside
// another is located as well as the one around it. The spans overlap and
// Masker.locate resolves them.
// Test_TencentCloudSecretID_aSecretIDBeginningInsideAnother drives it.
//
// That is also why this scan keeps no cursor and can keep none: a run of either
// body alphabet may hold a prefix at any of its characters, so no two
// candidates can be told apart by where the run before them ended. What rules
// out a quadratic input is the counts being counts — a candidate reads at most
// sixty-four bytes and stops, whatever the run behind it runs to.
// Test_TencentCloudSecretID_scanIsLinear drives the inputs that would find that
// wrong.
//
// What this pattern over-matches on is a run of one of those alphabets written
// behind the prefix, which is the shape the examples state and nothing looser.
// The longer shape is the one worth stating: base64url is what an encoded blob
// is written in, so AKID written straight in front of sixty-four characters of
// one is a temporary SecretId character for character and the whole of it is
// redacted. There is nothing left in the text to read the two apart — a scan
// declining it would decline every temporary SecretId issued — and what has to
// be written to reach it is the prefix with such a run against it and nothing
// between. Prose does not reach a span at either count: thirty-two unbroken
// characters behind four more is longer than anything prose is written in, and
// a word running into the prefix runs the body out at its first space or
// punctuation mark.
// Test_TencentCloudSecretID_aBase64URLRunBehindThePrefix pins the decision.
//
// referenceTencentCloudSecretIDFind in builtin_tencentcloud_secret_id_test.go
// keeps the grammar as a regular expression, spelling the prefix, the two
// counts and the character classes again so that the two are changed together,
// and the fuzz target beside it holds this scan to that expression. An
// expression is affordable here for the reason an exact repetition is: the
// machine an engine builds for one is read once and stops. The prefix is a
// four-byte literal an engine searches the text for besides, and it is written
// in the alphabet of both bodies, so a run of either is a position the engine
// stops at — which is what the literal pays for.
//
// The scan declares its prefix to a Masker as a literal and as the tail it
// settles by, which grams (builtin_scan.go) says is the pattern that may be
// passed over and answered for alike. A candidate opens only where the whole
// prefix stands, so a text the filter turns this pattern away on holds no
// candidate and the prefix alone settles what the scan would have.
var tencentCloudSecretID = newBuiltin("tencentcloud-secret-id", &tencentCloudSecretIDTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two, and the rationale above says which candidate
	// is the one held onto here.
	retain := tencentCloudSecretIDTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], tencentCloudSecretIDAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a SecretId or not, for
		// the reason the rationale above gives: every character of the prefix is
		// written in both body alphabets, so a SecretId can begin anywhere inside
		// another and a scan stepping over what it took would leave that one whole.
		offset = anchor + 1

		if anchor < tencentCloudSecretIDAnchorIndex {
			continue
		}
		start := anchor - tencentCloudSecretIDAnchorIndex

		// The prefix is compared before any body is read. Every anchor the
		// search stops at reaches this line, and all but a few of them are
		// turned away here by the three characters around the one already
		// known.
		if !strings.HasPrefix(src[start:], tencentCloudSecretIDPrefix) {
			continue
		}
		body := start + len(tencentCloudSecretIDPrefix)

		// The temporary shape first, whole, for the reason the rationale gives:
		// the shorter shape is its opening, so a scan settling on the shorter
		// one would report a span inside a value and release the rest of it.
		if end := body + tencentCloudSecretIDTemporaryBodyChars; end > len(src) {
			// The input ends inside this candidate, so the count that is the
			// whole of what tells it from anything else written behind the
			// prefix cannot be taken here. What is written of it is not read
			// before giving up on it, which builtin_scan.go argues once for
			// every scan. The shorter shape is tried all the same: it may be
			// whole where this one is not, and the span it reports is one this
			// candidate would widen — which is why the text is held from here
			// either way.
			retain = min(retain, start)
		} else if isTencentCloudSecretIDTemporaryBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
			continue
		}

		if end := body + tencentCloudSecretIDBodyChars; end <= len(src) && isTencentCloudSecretIDBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// tencentCloudSecretIDPrefix is what every SecretId opens with, and what
	// the scan reads back from its anchor. Every character of it is written in
	// both body alphabets, which is what leaves a SecretId able to begin
	// anywhere inside another and why nothing here rests on a separator;
	// Test_tencentCloudSecretIDPrefix holds it to that so the sentence is read
	// as a measurement rather than as an oversight.
	tencentCloudSecretIDPrefix = "AKID"

	// tencentCloudSecretIDAnchor is the byte the scan searches the input for
	// and tencentCloudSecretIDAnchorIndex is where it stands in the prefix, so
	// a candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what made it
	// this byte, which is the text around a SecretId rather than the body.
	// Test_tencentCloudSecretIDAnchor holds it to standing at this index in the
	// prefix.
	tencentCloudSecretIDAnchor      = 'K'
	tencentCloudSecretIDAnchorIndex = 1

	// The counts a SecretId is written to behind the prefix: thirty-two for the
	// one naming an account or a sub-user, sixty-four for the one a temporary
	// credential carries. Both are exact rather than floors, and both rest on
	// the examples the vendor publishes rather than on a length it states,
	// which the rationale above weighs.
	tencentCloudSecretIDBodyChars          = 32
	tencentCloudSecretIDTemporaryBodyChars = 64
)

// tencentCloudSecretIDTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var tencentCloudSecretIDTail = newPrefixTail(tencentCloudSecretIDPrefix)

// isTencentCloudSecretIDBody reports whether s is everything behind the prefix
// of a SecretId naming an account or a sub-user: exactly
// tencentCloudSecretIDBodyChars characters of the letters of both cases and the
// digits.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count being left to the caller to have cut
// correctly.
//
// The alphabet is the shared one in builtin_scan.go rather than a test of this
// scan's own: it is the same base62, and a scan spelling it again here could
// come to disagree with the other scans reading it about what it holds.
func isTencentCloudSecretIDBody(s string) bool {
	if len(s) != tencentCloudSecretIDBodyChars {
		return false
	}
	for i := range len(s) {
		if !isBase62Byte(s[i]) {
			return false
		}
	}
	return true
}

// isTencentCloudSecretIDTemporaryBody reports whether s is everything behind the
// prefix of a temporary SecretId: exactly
// tencentCloudSecretIDTemporaryBodyChars characters of base64url.
//
// The count is checked here for the reason isTencentCloudSecretIDBody gives,
// and the alphabet is the shared one for the same reason: the hyphen and the
// underscore the longer body carries are what base64url holds over base62, and
// this scan is no place to spell that difference a second time.
func isTencentCloudSecretIDTemporaryBody(s string) bool {
	if len(s) != tencentCloudSecretIDTemporaryBodyChars {
		return false
	}
	for i := range len(s) {
		if !isBase64URLByte(s[i]) {
			return false
		}
	}
	return true
}
