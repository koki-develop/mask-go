package mask

import "strings"

// SendGridAPIKey locates Twilio SendGrid API keys: the prefix SG., the
// twenty-two characters that identify the key, a dot, and the forty-three
// characters of the secret behind it. One string serves every access level
// SendGrid issues — full access, custom access and billing access — so nothing
// in a key says what it is allowed to do.
//
// A key is located wherever it is written, with no word boundary either side,
// and exactly sixty-nine characters of it are. So text of that shape is
// redacted whether or not SendGrid issued it. A space, a hyphen where the dot
// belongs, or a segment of the wrong length ends the reading, so text as it is
// ordinarily written is not affected.
//
// Its name is "sendgrid-api-key".
func SendGridAPIKey() Pattern { return sendGridAPIKey }

// What SendGrid states and what SendGrid shows are worth separating here, as
// they were for Slack, GitLab, Google, OpenAI, Anthropic, Stripe and PyPI. On
// this format the separation comes out the other way round from all seven:
// SendGrid states the one thing none of their vendors states, which is the
// length.
//
// What SendGrid states is that a key is sixty-nine characters, always. The
// support article answering whether a shorter key can be issued says a key is
// always sixty-nine characters, that the length is fixed for every key SendGrid
// generates and that a shorter one cannot be asked for; the API keys page in
// the documentation carries the same number in a warning, that no exception is
// made for third-party infrastructure that cannot hold a key of it. Neither
// page states an alphabet, a per-segment count or a checksum, and nor does the
// API reference beside them.
//
// What SendGrid shows is the shape. The create-key endpoint returns
// {"api_key":"SG.xxxxxxxx.yyyyyyyy","api_key_id":"xxxxxxxx",...}, which says
// three things: a key opens with SG., it is written in two dot-separated parts,
// and the first of them is spelled with the placeholder the api_key_id beside
// it is spelled with — so the front of the string identifies the key and the
// back of it is the secret. SendGrid's own Node client keeps the prefix as a
// constant and warns when a key does not open with it, and checks nothing else
// about the string.
//
// The two counts are what is left, and they are read off the keys published
// rather than off anything SendGrid wrote. GitLab's secret detection ruleset
// carries five example keys for its own SendGrid rule, and every one of them is
// SG. and twenty-two characters, a dot, and forty-three characters —
// sixty-nine altogether, which is the length SendGrid states. Nothing else
// divides sixty-nine that way: the segments are the base64url of sixteen bytes
// and of thirty-two, written without padding, so twenty-two and forty-three are
// what an identifier of one and a secret of the other come to and their total
// is the number SendGrid published.
//
// The three rulesets that state a shape agree with that and with each other on
// everything but how tightly to read it. gitleaks reads SG. and sixty-six
// characters of one class, which is twenty-two, the dot and forty-three
// counted together rather than apart. GitLab reads the same sixty-six. Only
// trufflehog reads the two segments as segments, and reads them as ranges —
// twenty to twenty-four in front and thirty-nine to fifty behind — around a
// test value of its own that is seventy-four characters and so is not a key of
// the length SendGrid states. So the exact shape is what every published key
// carries and what two of the three rulesets total, and the ranges are one
// ruleset's slack around it.
//
// The counts are therefore read exactly, which is where this scan stands with
// the AWS, GitLab and Google ones beside it rather than with the OpenAI,
// Anthropic, Stripe, PyPI and npm ones. Those five decline an exact count —
// three of them reading a floor and the OpenAI and Anthropic ones reading to
// the end of a run — because their vendor states no length, and several of
// them have already issued values at more than one, so a count that is wrong
// there costs the whole credential. Here the vendor states the length itself,
// in a support article whose subject is that it never varies, and the wager on
// an exact count is correspondingly smaller than the one AWS and Google are
// read with — those two are exact on an observation of examples alone. What it
// costs is what it costs there: a segment longer than the count is not one
// longer key but a key with something written after it, and only the key is
// redacted.
//
// The alphabet is the base64url one, isBase64URLByte in builtin_scan.go. Both
// characters that distinguish it from the alphanumerics stand in the keys
// GitLab publishes — two of the five write an underscore into the identifier,
// one of those opening with it, and one writes both a hyphen and an underscore
// into the secret — so neither is inferred from the rulesets. Padding is not
// admitted, and does not arise: twenty-two and forty-three are the unpadded
// lengths, and a padded encoding of the same bytes would be twenty-four and
// forty-four and so would not be sixty-nine characters. gitleaks admits = in
// its class all the same, which is slack of the same kind as trufflehog's
// ranges and is not read here.
//
// The dot between the segments is the one character of the format that is not
// in the alphabet, and it is doing two things. It is what tells this format
// from a single run of sixty-five base64url characters, which would be a far
// weaker anchor; and it is what the prefix closes with, so a key carries the
// character its own prefix ends on twenty-three characters further in. That
// second fact is why a key can begin inside another, which the resumption below
// is about.
//
// There is no boundary on either side of a match, as there is none in any of
// the scans beside this one but the Slack and Stripe ones. A word boundary in
// front would drop the whole match rather than trim it wherever a key is
// written against a word character, as SENDGRID_API_KEY_SG... is, and one
// behind it would drop a key followed by a character of the key's own
// alphabet. What may stand either side is held back by the character classes
// and the two counts alone.
//
// The tightening that is on offer in front is the one the Slack and Stripe
// scans take: to ask that no letter and no digit stand before the prefix. SG.
// can close a word — MSG., NSG., ESG. and PSG. each carry the whole prefix at
// the end of an ordinary identifier — so that test would turn away every
// property chain opening with one of them, which is the whole of what this
// pattern over-matches on. It is not taken, for the reason the AWS scan gives
// for declining a boundary of its own: what it costs is a key written straight
// against a letter or a digit, and that key would then be left in the output
// whole rather than trimmed. Slack and Stripe pay that price because their
// grammars are loose behind the prefix — a floor with no upper bound, and a
// prefix of two letters — so the false positive is reachable enough that
// gitleaks ships one it validates its own Stripe rule against. Here the counts
// are exact on both segments and the dot between them is pinned, so the shape a
// letter in front would rule out is one that also has to carry exactly
// twenty-two characters, then a dot, then forty-three more; and no ruleset
// ships a false positive of that shape. The cases in
// builtin_sendgrid_api_key_test.go pin what is admitted instead of ruled out,
// so that it stays a decision on the record.
//
// The scan resumes one byte past the start of a candidate whether it became a
// key or not. The two letters of the prefix belong to the alphabet a segment is
// written in and the dot behind them is the separator a key already carries, so
// a key whose secret closes with SG opens a candidate two characters before its
// own end: the dot that candidate wants is the one standing after the key, and
// what follows can be a second key's identifier, dot and secret. Consuming a
// match would step over that key and leave it in the output whole. The two
// spans then overlap, which a Masker resolves into one.
//
// The scan keeps no cursor and needs none, as the AWS and Google scans do not
// and for their reason: a candidate reads at most sixty-nine bytes and stops,
// which is the guarantee the JWT, GitHub, GitLab, Slack, OpenAI, Anthropic and
// PyPI scans buy with a run cursor, bought here by the counts being counts.
//
// What this pattern over-matches on: text somebody wrote whose shape is a
// key's exactly. A digest, a base64 payload and a base64url one carry no dot,
// so none of them holds a candidate to be found at however long it runs, since
// neither base64 alphabet writes the dot the prefix closes with. Nor does a
// JWT: the header and the payload of one are JSON, so the bytes each of them
// encodes close with a brace, and base64url turns a final brace into 9, into
// 0, or into fQ, never into SG. The last character in front of a signed
// token's dots is therefore never the G a candidate needs. What is left is an
// identifier or a path whose component closes on SG, followed by exactly
// twenty-two characters of the alphabet, a dot and forty-three more:
// MSG.0123456789abcdef012345.0123456789abcdef0123456789abcdef0123456789a is
// redacted from its SG onward, and the M is what stays. That text is a key's
// format exactly and the counts are already the vendor's own, so there is
// nothing left in the string to read the two apart by.
//
// What reaches a span is never prose, a git SHA or an MD5, and never a
// certificate or an embedded image. A key holds a dot at its third character
// and at its twenty-sixth and nowhere else, and holds no space; no word of
// prose is spelled SG. with sixty-six characters of one run behind it.
//
// referenceSendGridAPIKey in builtin_sendgrid_api_key_test.go keeps the grammar
// as a regular expression, spelling the prefix, the two counts, the separator
// and the alphabet again so that the two are changed together, and the fuzz
// target beside it holds this scan to that expression.
var sendGridAPIKey = NewPattern("sendgrid-api-key", func(src string) []Span {
	var spans []Span

	for offset := 0; offset < len(src); {
		i := strings.Index(src[offset:], sendGridAPIKeyPrefix)
		if i < 0 {
			break
		}
		start := offset + i

		// The scan resumes here whether this candidate became a key or not, for
		// the reason the rationale above gives: the prefix is two characters a
		// segment is written with and the separator a key already carries, so a
		// key can begin two characters before the end of the one before it.
		offset = start + 1

		body := start + len(sendGridAPIKeyPrefix)
		if end := start + sendGridAPIKeyChars; end <= len(src) && isSendGridAPIKeyBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
})

const (
	// sendGridAPIKeyPrefix is what every key opens with, and what the scan
	// searches the input for. It closes with the character the two segments are
	// separated by, which is what lets one key be written inside another and is
	// why the scan resumes a byte along; Test_sendGridAPIKeyPrefix holds it to
	// closing with that character and to carrying nothing but segment
	// characters in front of it.
	sendGridAPIKeyPrefix = "SG."

	// sendGridAPIKeySeparator divides the identifier from the secret. It
	// belongs to no segment, which is what ends a segment where it stands and
	// what makes the count on either side of it readable at all.
	sendGridAPIKeySeparator = '.'

	// The counts a key is written to. Every key published is twenty-two
	// characters of identifier and forty-three of secret, which are the
	// base64url of sixteen bytes and of thirty-two without padding, and which
	// come to the sixty-nine characters SendGrid states a key always is. Unlike
	// the AWS and Google counts these rest on a length the vendor wrote down as
	// well as on the examples, which the rationale above weighs.
	sendGridAPIKeyIDChars     = 22
	sendGridAPIKeySecretChars = 43

	// sendGridAPIKeyBodyChars is everything behind the prefix: the identifier,
	// the separator and the secret.
	sendGridAPIKeyBodyChars = sendGridAPIKeyIDChars + 1 + sendGridAPIKeySecretChars

	// sendGridAPIKeyChars is the whole of a key, and the sixty-nine SendGrid
	// states. Test_sendGridAPIKeyChars holds it to that number, since it is the
	// one part of this grammar the vendor states outright and the counts either
	// side of the separator are only as good as their total agreeing with it.
	sendGridAPIKeyChars = len(sendGridAPIKeyPrefix) + sendGridAPIKeyBodyChars
)

// isSendGridAPIKeyBody reports whether s is everything behind the prefix of a
// key: exactly sendGridAPIKeyIDChars characters of the alphabet, the separator,
// and exactly sendGridAPIKeySecretChars more.
//
// It is handed the counts as well as the characters so that they are checked in
// one place rather than left to the caller to have cut correctly. The separator
// is tested before either run is walked: a candidate that is not a key is
// usually not one at that character, and one comparison turns it away where up
// to sixty-five byte tests would.
func isSendGridAPIKeyBody(s string) bool {
	if len(s) != sendGridAPIKeyBodyChars || s[sendGridAPIKeyIDChars] != sendGridAPIKeySeparator {
		return false
	}
	for i := range sendGridAPIKeyIDChars {
		if !isBase64URLByte(s[i]) {
			return false
		}
	}
	for i := sendGridAPIKeyIDChars + 1; i < len(s); i++ {
		if !isBase64URLByte(s[i]) {
			return false
		}
	}
	return true
}
