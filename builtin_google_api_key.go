package mask

import "strings"

// GoogleAPIKey locates Google API keys: the prefix AIza and thirty-five
// characters behind it. One string serves every Google API that takes a key
// rather than a credentialled principal — Maps, YouTube Data, Firebase, the
// Cloud APIs reaching no private user data, and the Gemini API among them — so
// a key says which project it bills and not which API it was made for.
//
// A key is located wherever it is written, with no word boundary either side,
// and exactly thirty-nine characters of it are. So an unbroken run of
// thirty-nine base64url characters opening with AIza is redacted whether or not
// Google issued it. A space, a dot or a slash ends the run and no word is
// spelled AIza, so text as it is ordinarily written is not affected.
//
// Its name is "google-api-key".
func GoogleAPIKey() Pattern { return googleAPIKey }

// The prefix is what anchors this, with no boundary on either side of the
// match, as in the AWS and GitLab scans beside it. A word boundary in front
// would drop the whole match rather than trim it wherever a key is written
// against a word character, as GOOGLE_API_KEY_AIza... is, and one behind it
// would drop a key followed by a character of the key's own alphabet. What may
// stand either side is held back by the character class alone.
//
// What Google states and what Google shows are worth separating here, as they
// are wherever a vendor names a prefix and leaves the rest of a format to be
// read off the values it issued, because on this format Google states nothing.
//
// The API keys page of the Cloud authentication documentation is the one place
// the string itself is written down, and what it says of it is that a key is
// "an encrypted string", beside one example of one. Sensitive Data Protection
// carries a built-in detector for the same value, GCP_API_KEY, and publishes
// what it detects rather than the expression it detects with. Neither a length
// nor an alphabet nor a checksum appears anywhere in Google's own
// documentation.
//
// What Google shows is that one example, and it is thirty-nine characters: AIza
// and thirty-five more, carrying digits, letters of both cases, a hyphen and an
// underscore between them. Every key published anywhere else is the same
// thirty-nine, and the two rulesets that state a shape state that one —
// gitleaks reads a key as AIza[\w-]{35}, and Microsoft's Purview classifier
// reads it as the prefix AIza and thirty-five letters, digits, hyphens and
// underscores, filed under a keyword set named for a two hundred and ten bit
// symmetric key, which is what thirty-five base64url characters hold.
//
// So thirty-nine is an observation of the examples rather than a documented
// format, and the count below is only as good as that observation. It is the
// same wager the AWS scan beside this one makes and it is bounded the same way:
// were Google to issue a longer key, the characters past the thirty-ninth would
// be left in the output.
//
// The alphabet is the base64url one, isBase64URLByte in builtin_scan.go, which
// is what every statement of the shape admits behind the prefix and what
// Google's own example is written in — that example carries both a hyphen and
// an underscore, so neither is inferred from the rulesets alone.
//
// The count is exact rather than a floor, for the reason the AWS and GitLab
// scans give: a run of the alphabet longer than the count is not one longer key
// but a key with something written after it, and only the key is redacted.
// AIza0123456789abcdefghijklmnopqrstuvwxyz is forty characters and leaves the
// final z in the output, which is part of no credential if the thirty-nine in
// front of it are a key. The alternative, running the alphabet out, would
// redact every character of the run — and that alphabet holds the hyphen and
// the underscore, so it would swallow a hyphenated identifier written after a
// key whole.
//
// The byte the scan searches the input for is the z of AIza, for the reason
// builtin_scan.go gives, and the prefix is read back from it. Searching for
// the four bytes together is the same walk with the A as its anchor, since
// that is the byte strings.Index skips along, and the A is the wrong one of
// the four to stop at: it is the character every capitalised word and every
// acronym in a log line opens with, where the z is one nothing else here is
// written with. Neither costs the other anything on a line that is nothing but
// candidates — AIza carries one of each — so what the choice moves is the
// ordinary line alone.
//
// The scan resumes one byte past the start of a candidate whether it became a
// key or not. The alphabet holds every character the prefix is written in, so
// AIza can stand inside a body and a key can begin inside the span of the one
// before it: AIzaAIza followed by thirty-five characters is two keys, the
// second beginning four characters into the first. Consuming a match would step
// over that key and leave it in the output whole. The two spans then overlap,
// which a Masker resolves into one.
//
// What this pattern over-matches on: thirty-nine characters of the alphabet
// standing inside a longer base64 value. AIza is four characters drawn from an
// alphabet of sixty-four, so a payload written in one — a certificate, an
// embedded image, a JWT signature — carries the prefix about once in seventeen
// million characters, and where the thirty-five behind it are all in the
// alphabet as well, those thirty-nine are redacted. What is taken there is
// thirty-nine characters of a value that was already opaque, and it is a key's
// format exactly: nothing is left in the text to tell the two apart, so a
// pattern letting that run through would let a real key through with it.
//
// The tightening that looks available is the two characters behind the prefix.
// Google's own example is AIzaSy..., as is nearly every key published anywhere,
// so a scan asking for AIzaSy would tell most such runs apart. Google states
// nothing that makes those two characters part of the format, and the corpus
// gitleaks holds its own rule to carries a key written AIzay..., so the
// narrowing would rest on a regularity of the examples rather than on the
// format — and what it would cost, the first time a key is issued without those
// two, is the whole credential. The wider prefix costs thirty-nine characters
// of a blob; the narrower one would cost a key.
//
// What reaches a span is never prose, a git SHA or an MD5. Two of the prefix's
// four characters, the I and the z, are no hexadecimal digit, so a digest holds
// no position to be found at however long it runs; and no word is spelled with
// a capital I behind a capital A and lowercase behind that. The text has to be
// thirty-nine unbroken characters of the alphabet before the question arises at
// all. The tables in builtin_google_api_key_test.go and the corpus beside it
// pin that behaviour so it cannot move unnoticed.
//
// The scan keeps no cursor and needs none: a candidate reads at most
// thirty-nine bytes and stops, four of prefix and thirty-five of body, which
// bounds what it reads with no state to be wrong about.
//
// referenceGoogleAPIKey in builtin_google_api_key_test.go keeps the grammar as
// a regular expression, spelling the prefix, the count and the alphabet again
// so that the two are changed together, and the fuzz target beside it holds
// this scan to that expression. The count is written as an exact repetition
// rather than a floor, which is what keeps the expression cheap enough to fuzz
// with: an engine reads a machine that wide once and stops.
var googleAPIKey = newBuiltin("google-api-key", &googleAPIKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := googleAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], googleAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for the
		// reason the rationale above gives: the prefix is written in the alphabet a
		// body is, so a key can begin inside the body of the one before it.
		offset = anchor + 1

		if anchor < googleAPIKeyAnchorIndex {
			continue
		}
		start := anchor - googleAPIKeyAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != googleAPIKeyPrefix[0] || !strings.HasPrefix(src[start:], googleAPIKeyPrefix) {
			continue
		}

		body := start + len(googleAPIKeyPrefix)
		end := start + googleAPIKeyChars
		if end > len(src) {
			// The input ends inside the body, and the count is the whole of
			// what tells a key from any other run written behind the prefix.
			retain = min(retain, start)
			continue
		}
		if isGoogleAPIKeyBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// googleAPIKeyPrefix is what every key Google has shown opens with, and
	// what the scan reads back from the anchor. Every character of it belongs
	// to the alphabet a body is written in, which is what lets one key be
	// written inside another and is why the scan resumes a byte along;
	// Test_googleAPIKeyPrefix holds it to that.
	googleAPIKeyPrefix = "AIza"

	// googleAPIKeyAnchor is the byte the scan searches the input for and
	// googleAPIKeyAnchorIndex is where it stands in the prefix, so that a
	// candidate begins that many bytes in front of what a search reported. The
	// rationale above says why this character and not the one the prefix opens
	// with.
	googleAPIKeyAnchor      = 'z'
	googleAPIKeyAnchorIndex = 2

	// The counts a key is written to. Every key Google shows is thirty-nine
	// characters and Google states no length of its own, so these are exact
	// rather than floors — on an observation rather than a specification,
	// which the rationale above weighs.
	googleAPIKeyBodyChars = 35
	googleAPIKeyChars     = len(googleAPIKeyPrefix) + googleAPIKeyBodyChars
)

// isGoogleAPIKeyBody reports whether s is the body of a key: exactly
// googleAPIKeyBodyChars characters, all of them in the alphabet a body is
// written in.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count being left to the caller to have cut
// correctly.
func isGoogleAPIKeyBody(s string) bool {
	if len(s) != googleAPIKeyBodyChars {
		return false
	}
	for i := range len(s) {
		if !isBase64URLByte(s[i]) {
			return false
		}
	}
	return true
}

// googleAPIKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var googleAPIKeyTail = newPrefixTail(googleAPIKeyPrefix)
