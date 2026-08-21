package mask

import "strings"

// SlackToken locates Slack credentials that carry a token prefix: bot tokens
// (xoxb-), user tokens (xoxp-), app-level tokens (xapp-), workflow tokens
// (xwfp-), and the pair token rotation issues — refresh tokens (xoxe-) and the
// rotatable access tokens a xoxe. prefix puts in front of a bot or user token
// (xoxe.xoxb-, xoxe.xoxp-).
//
// Slack documents the prefixes and nothing else: no length, no alphabet, no
// count of the parts a token is written in. So a body is read as the hyphen
// separated segments every Slack token anyone has published is written in, and
// a token is one where some segment is long enough to be the secret such a
// token ends with and carries a letter as every such secret does. A prefix
// written against a letter or a digit opens nothing, which is what keeps an
// identifier ending in one of them from being read as a token.
//
// Its name is "slack-token".
func SlackToken() Pattern { return slackToken }

// What Slack states and what it only shows are worth separating here, because
// they barely overlap and it is the second that the grammar below is built on.
//
// What Slack states is the prefix, in one sentence a token type: "Bot token
// strings begin with xoxb-", and the same for xoxp-, xapp- and xwfp-; the
// token rotation guide adds xoxe- for a refresh token and notes that a
// rotatable access token "now has a new xoxe. prefix" in front of the xoxb- or
// xoxp- it already carried. That is the whole of the format Slack publishes.
// No page gives a length, an alphabet, or how many parts a token has.
//
// What Slack shows, in its own OAuth examples and in every token collected by
// the scanners that hunt them, is a prefix followed by parts joined with
// hyphens: identifiers for the workspace, the app or the token version, and
// then one part which is the secret. The bot token in Slack's own
// oauth.v2.access response is written that way, as the prefix, two identifiers
// of eleven digits and a secret of twenty-four alphanumerics. The parts in
// front of the secret differ by kind and have changed over the years — a bot
// token has carried one identifier and two — and the secret has been written at
// twenty-four characters, at thirty-two, at sixty-four, and at a hundred and
// forty-six or more once rotation wraps a token in base64. What has not changed
// is the shape: alphanumeric parts, hyphens between them, and a secret among
// them.
//
// So the grammar is the prefix, then the run of alphanumerics and hyphens
// behind it, and two demands. Together they are the whole of what keeps this
// pattern off text a reader can read, and neither is enough alone: the hyphen
// is a character prose, identifiers, image tags and branch names are full of,
// so a prefix and a run would redact any of them written after one of these
// five letters.
//
// The first demand is on the run: some segment of it must reach
// slackTokenSecretChars characters and hold a letter. Eighteen unbroken
// alphanumerics with a letter among them are not a word, and text carrying one
// after a Slack prefix is opaque whether or not Slack issued it. Asking for
// the letter is what separates a secret from a nanosecond timestamp or a
// snowflake id, which run to nineteen digits and are values a reader reads:
// xapp-trace-1705311000123456789 is left alone because the long part of it is
// all digits.
//
// What that wagers is a Slack secret with no letter at all, which would then be
// left in the output whole. It is a wager and not a certainty, because Slack
// documents no alphabet — but it is a small one, and smaller than the shape of
// the secrets makes it look: the shortest published secret is twenty-four
// characters of mixed case and digits, where all digits is one chance in
// something like ten to the nineteen, and the narrowest is thirty-two of
// hexadecimal, where it is one in a million and a half. Against that stands
// every eighteen digit identifier written after a prefix, which exists today.
//
// The second demand is on what stands in front: the byte before the prefix may
// not be a letter or a digit. Slack's prefixes are not words, but three of
// these five letters can close one — linuxapp- and nginxapp- end in xapp — and
// behind such an ending an ordinary hyphenated name goes on to carry a git SHA
// or an MD5, which is a run of alphanumerics with letters in it and so the
// whole of what the first demand asks for. Those are values a reader reads,
// and a tightening was available, so a grammar admitting them is one this
// pattern has no business having.
//
// It is not the word boundary a regular expression would write, and the
// difference is the underscore. SLACK_BOT_TOKEN_xoxb-... is how a token
// reaches a log line from a shell, and a \b in front would drop that token
// rather than trim it; so this admits the underscore, and with it the quote,
// the colon, the slash, the equals sign and the space a token is otherwise
// written after. What is left out is the letter and the digit alone, and what
// that costs is a token glued straight onto a word with nothing between them.
// Where such a word is itself inside the body of an earlier token the token is
// still redacted, because a body is read to the end of its run and covers what
// is written inside it; where it is not, a credential written that way is left
// whole, and nothing has been seen written that way.
//
// There is no boundary behind the match, and one there would drop rather than
// trim a token whose body runs on into the text after it. What may follow is
// held back by the character classes alone.
//
// A token written inside another is still reached, because the separator is
// neither a letter nor a digit: the second prefix of xoxb-xoxb-... stands
// against a hyphen and the xoxb- of a xoxe.xoxb- stands against a dot.
//
// The first demand is made of some segment rather than of the last one, which
// is where the secret actually sits, and the difference is the direction the
// pattern fails in. Where the run ends depends on what is written after the
// token: a token followed by a hyphen and a word ends the run past that word.
// Keyed on the last segment, such a token would not be located at all — the
// credential would come through whole because of text beside it. Keyed on some
// segment, text written after a token can only lengthen the run and never take
// a segment out of it, so what follows a token may widen the redaction but can
// never undo it. What that costs is the text a run reaches over:
// xoxb-0123456789ab-0123456789abcdefghijklmn-backup takes -backup with it.
//
// The count is an observation and only as good as the observation. Eighteen is
// below every published Slack secret — the shortest belongs to a retired bot
// token and is nineteen characters — and is the floor the scanners that
// collected those settled on. Slack states no length, so were it to issue a
// token whose every part were shorter than this, that token would be left in
// the output whole. Against that stands what a lower count would cost: at
// twelve, a hyphenated English identifier written after any of these prefixes
// is redacted, letter and all.
//
// The alphabet is the letters of both cases, the ten digits and the hyphen,
// which is every character any published Slack token is written in. The
// prefixes themselves are matched in lowercase only, as Slack writes them: a
// case-insensitive prefix would put XOXO, which is a word and a common one in
// file names, in front of the same run.
//
// The prefixes admitted are the ones Slack documents today, which is what keeps
// every count and character class above keyed on something Slack states rather
// than on other people's readings of issued tokens.
//
// referenceSlackTokenFind in builtin_slack_token_test.go is the plain
// implementation of these rules, spelling the prefixes, the count and the
// character classes again so that the two are changed together, and the fuzz
// target beside it holds this scan to it.
var slackToken = NewPattern("slack-token", func(src string) []Span {
	var spans []Span

	// The run a body is read as is worked out once and remembered. The
	// alphabet holds the letter every prefix opens with, so a prefix can be
	// written inside a body and a run can hold a candidate for every five
	// characters it has — xoxb-xoxb-xoxb- is one run, not three — and each of
	// them reads that same run to its end. Working it out again at every
	// candidate would cost time quadratic in the length of such a line.
	//
	// lastSecret is where the rightmost segment able to be a secret begins, or
	// -1 where the run holds none. Rightmost is what makes it answer for every
	// candidate crowded in the run and not only for the one it was computed
	// at: a candidate's body starts at a segment boundary of this same run, so
	// the run holds a secret at or after that body exactly when the rightmost
	// one does not begin in front of it.
	runEnd := -1
	lastSecret := -1

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], slackTokenFirstByte)
		if i < 0 {
			break
		}
		start := offset + i

		// The scan resumes here whether this candidate became a token or not.
		// A body is read as far as its alphabet runs and that alphabet holds
		// the prefixes, so a body swallows the opening of a token written
		// straight after it — xoxb-xoxb-... is a token beginning inside the
		// span of the one before it — and consuming a match would step over
		// that token and leave it in the output whole. The two spans then
		// overlap, which a Masker resolves into one.
		offset = start + 1

		// The byte test comes before the prefix table because it is one
		// comparison where that is up to seven, and every x in a word reaches
		// this line.
		if start > 0 && isSlackTokenWordByte(src[start-1]) {
			continue
		}
		prefix := slackTokenPrefixAt(src, start)
		if prefix == 0 {
			continue
		}

		// The body of a candidate never begins in front of the body of the
		// one before it, which is what lets a single cursor serve them all.
		// The prefixes are ten characters or five, and the ten character ones
		// hold no candidate start of their own before their fifth character:
		// the only x inside xoxe. is the one at index 2, and no prefix has e
		// as its second character. So a candidate five characters into one of
		// those starts a body exactly where its own would have.
		// Test_slackTokenPrefixes_bodyNeverMovesBack holds the table to that.
		body := start + prefix
		if body >= runEnd {
			runEnd, lastSecret = slackTokenRun(src, body)
		}
		if lastSecret >= body {
			spans = append(spans, Span{Start: start, End: runEnd})
		}
	}
	return spans
})

// slackTokenPrefixes are the prefixes Slack documents, longest first so that a
// rotatable access token is read as the whole of what Slack writes rather than
// as the bot or user token inside it.
//
// The order is a courtesy rather than a rule: no two of these match at the same
// position, because the character that tells a kind apart — the fourth of
// xoxb-, xoxp- and xoxe-, the second of xapp- and xwfp-, the ninth of the two
// behind xoxe. — is inside every one of them. Test_slackTokenPrefixes holds
// them to that, and to opening with the byte the scan searches for and closing
// with the separator a body is written with.
//
// A rotatable access token is located twice over, once at xoxe.xoxb- and once
// at the xoxb- five characters along, and the two spans end together. Both are
// reported and a Masker merges them, which is the same resolution the two
// prefixes of an AWS access key ID need.
var slackTokenPrefixes = [...]string{
	"xoxe.xoxb-",
	"xoxe.xoxp-",
	"xoxb-",
	"xoxp-",
	"xoxe-",
	"xapp-",
	"xwfp-",
}

const (
	// slackTokenFirstByte is the byte every prefix opens with, and the one
	// candidate positions are found by.
	slackTokenFirstByte = 'x'

	// slackTokenSeparator is what a token's parts are joined with, and so
	// what divides a body into segments.
	slackTokenSeparator = '-'

	// slackTokenSecretChars is how long a segment must be, letter included,
	// for the run holding it to be a token. It is a floor and not a count:
	// Slack states no length for any part of a token, and the secrets it has
	// issued have been twenty-four characters, thirty-two, sixty-four and
	// more. The rationale above weighs what a lower one would draw in and what
	// a token shorter than this would cost.
	slackTokenSecretChars = 18
)

// slackTokenPrefixAt returns the length of the prefix beginning at i in src, or
// zero where none does.
func slackTokenPrefixAt(src string, i int) int {
	for _, prefix := range slackTokenPrefixes {
		if strings.HasPrefix(src[i:], prefix) {
			return len(prefix)
		}
	}
	return 0
}

// slackTokenRun reads the run of body characters beginning at body in src,
// returning where it ends and where the rightmost segment able to be a secret
// begins, or -1 where it holds none.
//
// The segments are what the separator divides the run into, an empty one
// between two separators included. What is read of a segment is its length and
// whether it carries a letter: which of them is the secret and which are
// identifiers is not something the bytes say, and Slack has moved a token's
// parts around more than once.
func slackTokenRun(src string, body int) (end, lastSecret int) {
	end, lastSecret = body, -1
	segment, letter := body, false
	for end < len(src) && isSlackTokenByte(src[end]) {
		switch {
		case src[end] == slackTokenSeparator:
			if letter && end-segment >= slackTokenSecretChars {
				lastSecret = segment
			}
			segment, letter = end+1, false
		case isSlackTokenLetterByte(src[end]):
			letter = true
		}
		end++
	}
	if letter && end-segment >= slackTokenSecretChars {
		lastSecret = segment
	}
	return end, lastSecret
}

// isSlackTokenLetterByte reports whether c is one of the letters a segment must
// carry to be a secret. Every secret Slack has published holds several; a part
// of a token written in digits alone is an identifier, a timestamp or an id,
// and is what asking for this leaves in the text.
func isSlackTokenLetterByte(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
}

// isSlackTokenWordByte reports whether c is a letter or a digit, which is what
// may not stand in front of a prefix. The underscore is not one of them, and is
// admitted for the reason the rationale above gives.
func isSlackTokenWordByte(c byte) bool {
	return isSlackTokenLetterByte(c) || '0' <= c && c <= '9'
}

// isSlackTokenByte reports whether c belongs to the alphabet a token body is
// written in: the letters of both cases, the digits and the separator between a
// token's parts. That is every character any published Slack token carries. The
// underscore and the dot are left out — no token holds either, and the dot of a
// rotatable access token stands in front of its prefix rather than in its body.
func isSlackTokenByte(c byte) bool {
	return isSlackTokenWordByte(c) || c == slackTokenSeparator
}
