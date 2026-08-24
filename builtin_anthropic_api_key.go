package mask

import "strings"

// AnthropicAPIKey locates Anthropic API keys: the keys the Claude Console
// issues (sk-ant-api03-) and the keys of the Admin API (sk-ant-admin01-). Both
// are written the same way — the prefix sk-ant-, the name of a kind, a hyphen,
// and a long run of random characters — and it is that shape, rather than the
// two names, that this pattern is anchored on. The OAuth tokens and the session
// keys Anthropic writes the same way are therefore located as well.
//
// A key is located wherever it is written, with no word boundary either side,
// and is redacted from its sk-ant- to the end of the run it stands in. So a key
// written against a word character keeps its span, and a character of the key's
// own alphabet written straight after a key is redacted with it.
//
// Its name is "anthropic-api-key".
func AnthropicAPIKey() Pattern { return anthropicAPIKey }

// What Anthropic states and what Anthropic shows are worth separating here, as
// they are wherever a vendor names a prefix and leaves the rest of a format to
// be read off the values it issued, because on this format Anthropic states
// nothing.
//
// The API documentation gives the header a request carries a key in, x-api-key,
// and the Console page a key is created on. No length, no alphabet and no
// checksum appears anywhere in it. The one place Anthropic writes any of a key
// down is the Admin API: the endpoint reporting a key returns a
// partial_key_hint rather than the key itself, and the example beside it is
// sk-ant-api03-R2D...igAA. That is Anthropic's own statement of the prefix and
// of the two characters a key closes with, and it is the whole of what
// Anthropic publishes.
//
// GitHub lists Anthropic among the partners its secret scanning carries
// patterns for, under three token identifiers — anthropic_api_key,
// anthropic_admin_api_key and anthropic_session_id — and publishes what it
// detects rather than the expressions it detects with.
//
// The two rulesets that state a whole shape agree on one. gitleaks reads a
// Console key as sk-ant-api03- and ninety-three characters of letters, digits,
// the hyphen and the underscore, closed by AA, and an Admin API key as
// sk-ant-admin01- and the same; trufflehog reads both prefixes in one
// expression with the same ninety-three and the same AA. So ninety-five
// characters behind the hyphen, the last two of them AA, is what every
// statement of the shape says — for those two kinds. Nothing states a count for
// the others.
//
// The kind is what stands between the prefix and the body, and this scan reads
// that there is one rather than which one it is. Anthropic writes api03 for a
// Console key, admin01 for an Admin API key, oat01 and ort01 for the OAuth
// access and refresh tokens issued for Claude Code, and sid01 for a session
// key. A table of those names is the tightening on offer and it is the one the
// OpenAI scan beside this one weighs and declines, for the reason that applies
// here twice over: a name carries a version, and Anthropic's versions have
// already moved. A session key is written sk-ant-sid01- and sk-ant-sid02- both,
// and a Console key names itself api03 rather than api01. A scan keyed on the
// names would have gone on finding nothing through each of those, and what it
// would leave in the output is a whole credential. So what is read is one or
// more lowercase letters and digits closed by a hyphen, which is how every kind
// Anthropic has written spells itself.
//
// The alphabet of the body is the base64url one, isBase64URLByte in
// builtin_scan.go: the letters of both cases, the digits, the hyphen and the
// underscore. That is what both rulesets admit behind the prefix. The hyphen
// being in it is why the kind is read to the first hyphen rather than the body
// being read from one — a body may carry hyphens of its own, so only the first
// one behind the prefix divides the two.
//
// The count is read as a floor and not as a count. A count is read exactly
// where it is most of what tells a value from the text around it. Here the
// anchor is doing that work: seven characters of prefix, a kind, a hyphen and
// a run of ninety-five is a far narrower thing than AIza and thirty-five. A
// count read exactly would buy no discrimination it does not already have, and
// a count that is wrong is a key located nowhere — were Anthropic to issue a
// kind whose body is a hundred and twenty characters, a scan asking for
// ninety-five exactly would find nothing and leave a live credential in the
// output whole. Read as a floor, a key of any length at or above it is located
// to the end of its run.
//
// What the floor is for, beyond stating the count that is known, is telling a
// credential from a hyphenated identifier. The prefix carries two hyphens, so
// it stands inside ordinary kebab-case text: task-ant- holds sk-ant- three
// characters in, and desk-ant- does too. Without a floor the phrase behind such
// a prefix would be read as a kind and a body, and a word of prose would be
// redacted. Ninety-five unbroken characters of the alphabet is not a phrase
// anybody writes, which is what turns those away. So the floor cannot simply be
// lowered to admit more: a shorter one buys back the truncated key below and
// lets prose in with it.
//
// What the floor costs is the key shorter than it. A line cut to a column limit
// partway through a key leaves a prefix, a kind and a body too short to be one,
// and nothing is located: the random characters that were written before the
// cut stay in the output. That is the far side of this choice and it is the
// direction the OpenAI scan does not have to take, because a marker inside a
// key says what the key is where here only length can. The cases in
// builtin_anthropic_api_key_test.go pin it so that it stays a decision on the
// record.
//
// The two characters a key closes with are not read. AA closes the ninety-five
// characters behind the hyphen in every key anyone has published, so a scan
// asking for it there is asking for the count exactly, in the one direction
// that costs a credential rather than a tail. Asking for it at the end of the
// run instead would be worse: the span reaches to the end of the run, so a key
// with a character of its own alphabet written against it does not close with
// AA at all, and neither does a key inside a longer blob.
//
// There is no boundary on either side of a match. A boundary in front would
// drop the whole match rather than trim it wherever a key is written against a
// word character, as ANTHROPIC_API_KEY_sk-ant-api03-... is, and one behind it
// would drop a key followed by a character of the key's own alphabet — which,
// since the span already reaches to the end of the run, is every key with
// anything written against it.
//
// The scan resumes one byte past the start of a candidate whether it became a
// key or not. Every character of sk-ant- belongs to the alphabet a body is
// written in, so the prefix can stand inside a body and a key can begin inside
// the span of the one before it. Consuming a match would step over such a key;
// the two spans then overlap, which a Masker resolves into one.
//
// Two things a candidate reads are searches over the rest of the input rather
// than bounded tests, and one character of the prefix is what settles both: the
// hyphen it closes with, which is not a character a kind may be written with.
//
// Where the run ends is remembered, as it is in the OpenAI scan. A run can hold
// a candidate every nine characters — sk-ant-a- written over and over is one
// run, not a run apiece — and each of them reading that run to its end costs
// time quadratic in the length of such a line, so the end is worked out once
// and reused wherever a body begins inside the run already read. That is sound
// while a body never begins in front of the body of the candidate before it,
// and none can: a later candidate carries the closing hyphen somewhere, an
// earlier candidate's kind holds no character like it, so the later candidate
// cannot begin until that kind has ended, and its body stands past that kind's
// body. Test_anthropicAPIKeyPrefix_bodyNeverMovesBack holds the prefix to the
// one thing the argument rests on.
//
// Where the kind ends is not remembered and needs no cursor, for the same
// reason read the other way. The walk stops at the first character no kind may
// hold, and the next candidate carries one two characters before its own body,
// so each walk is bounded by the distance to the next candidate and the walks
// telescope into a single pass over the input.
// Test_AnthropicAPIKey_scanIsLinear drives both.
//
// What this pattern over-matches on: a run of base64url characters carrying
// sk-ant-, a kind, a hyphen and ninety-five more characters. The prefix holds
// two hyphens, which narrows this further than it looks — standard base64
// writes no hyphen at all, so a certificate, a PEM body or an embedded image
// holds no prefix to be found at however long it runs, and only a base64url
// encoding can carry one. In one of those, seven characters drawn from an
// alphabet of sixty-four stand where the prefix stands about once in four
// million million characters, and the run from there to the end of the encoding
// is then redacted. What is taken is a stretch of a value that was already
// opaque to a reader, and the tightening on offer is the table of names weighed
// above, which goes stale and costs a whole credential when it does.
//
// What reaches a span is never prose, a git SHA or an MD5. A digest carries no
// hyphen, so it holds no prefix to be found at, and no word is spelled sk-ant-.
// A hyphenated identifier can carry the prefix, as task-ant- does, and what
// turns it away is the ninety-five unbroken characters of the alphabet the body
// is held to.
//
// referenceAnthropicAPIKeyFind in builtin_anthropic_api_key_test.go states the
// same grammar with no cursor in it, spelling the prefix, the kind, the
// separator, the floor and the alphabet again so that the two are changed
// together, and the fuzz target beside it holds this scan to that statement.
var anthropicAPIKey = NewPattern("anthropic-api-key", func(src string) []Span {
	var spans []Span

	// The run a key is read as is worked out once and remembered, for the
	// reason the rationale above gives. The cursor holds the end of the run the
	// last body was read in, and -1 before there has been one, which every body
	// is past.
	runEnd := -1

	for offset := 0; offset < len(src); {
		i := strings.Index(src[offset:], anthropicAPIKeyPrefix)
		if i < 0 {
			break
		}
		start := offset + i

		// The scan resumes here whether this candidate became a key or not, for
		// the reason the rationale above gives: the prefix is written in the
		// alphabet a body is, so a key can begin inside the body of the one
		// before it.
		offset = start + 1

		body := anthropicAPIKeyBodyAt(src, start)
		if body < 0 {
			continue
		}

		// A body never begins in front of the body of the candidate before it,
		// which the rationale above sets out, so the walk is repeated only
		// where this body is past what was already read.
		if body >= runEnd {
			runEnd = base64URLRunEnd(src, body)
		}
		if runEnd-body < anthropicAPIKeyBodyChars {
			continue
		}
		spans = append(spans, Span{Start: start, End: runEnd})
	}
	return spans
})

const (
	// anthropicAPIKeyPrefix is what every credential Anthropic issues opens
	// with, whichever kind names itself behind it. Every character of it
	// belongs to the alphabet a body is written in, which is what lets one key
	// be written inside another and is why the scan resumes a byte along;
	// Test_anthropicAPIKeyPrefix holds it to that.
	anthropicAPIKeyPrefix = "sk-ant-"

	// anthropicAPIKeySeparator closes the kind and opens the body. It belongs
	// to the body alphabet and not to the one a kind is written in, which is
	// what makes the first of them behind the prefix the one that divides the
	// two. It is also the character the prefix closes with, which is what keeps
	// a body from ever moving back and a walk over a kind from ever being
	// repeated.
	anthropicAPIKeySeparator = '-'

	// anthropicAPIKeyBodyChars is the count a body is held to, read as a floor
	// rather than exactly. Ninety-five is what every published Anthropic
	// credential carries and what both rulesets state; it is also what keeps a
	// hyphenated identifier out, which is why it is not a number that can be
	// lowered on its own. The rationale above weighs both.
	anthropicAPIKeyBodyChars = 95
)

// anthropicAPIKeyBodyAt returns where the body of a candidate opening at start
// begins, or -1 where what stands behind the prefix is not the name of a kind
// closed by a separator.
//
// The kind is read rather than recognised: one or more lowercase letters and
// digits, which is how every kind Anthropic has written spells itself, and no
// list of the names themselves. How long the body then is, is the caller's to
// measure against the run it stands in.
func anthropicAPIKeyBodyAt(src string, start int) int {
	kind := start + len(anthropicAPIKeyPrefix)

	i := kind
	for i < len(src) && isAnthropicAPIKeyKindByte(src[i]) {
		i++
	}
	if i == kind || i == len(src) || src[i] != anthropicAPIKeySeparator {
		return -1
	}
	return i + 1
}

// isAnthropicAPIKeyKindByte reports whether c may appear in the name a kind of
// credential writes between the prefix and its body.
//
// It admits neither the hyphen nor the underscore, which the alphabet a body is
// written in does. The hyphen is what closes the kind, so admitting it would
// leave nothing to divide the two; the underscore is admitted by neither
// Anthropic's own hint nor any kind it has written.
func isAnthropicAPIKeyKindByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'z'
}
