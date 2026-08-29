package mask

import "strings"

// AWSAccessKeyID locates AWS access key IDs: twenty characters opening with
// AKIA, which AWS gives the long-term key of an IAM user or of the account root
// user, or ASIA, which it gives the temporary credentials AWS STS issues. Those
// are the two prefixes AWS documents for an access key ID, and STS tells the
// two apart by them.
//
// A key is located wherever it is written, with no word boundary either side,
// and exactly twenty characters of it are. So an unbroken run of twenty
// uppercase letters and digits opening with one of the prefixes is redacted
// whether or not AWS issued it, which ASIA, being a word, makes reachable:
// ASIAPACIFICSOUTHEAST is redacted, and ASIANELEPHANTCONSERVATION loses its
// first twenty characters. A space, a hyphen or a lowercase letter ends the
// run, so text as it is ordinarily written is not affected.
//
// Its name is "aws-access-key-id".
func AWSAccessKeyID() Pattern { return awsAccessKeyID }

// The prefix is what anchors these, with no boundary on either side of the
// match. A word boundary in front would drop the whole match rather than trim
// it wherever a key is written against a word character, as
// AWS_ACCESS_KEY_ID_AKIA... is, and one behind it would drop a key followed by
// an uppercase letter or a digit. What may stand either side is held back by
// the character classes alone.
//
// Unlike the GitHub scan beside it, this one counts the characters after the
// prefix rather than running out their alphabet. What that rests on is worth
// separating into what AWS states and what it only shows, because the two do
// not agree and the second is the one being relied on.
//
// What AWS states, in the only place it states a length at all, is the
// AccessKeyId field of the IAM and STS API references: sixteen to a hundred
// and twenty-eight characters matching [\w]+. That is the filter the API puts
// on what a caller may send, not a description of what the service issues —
// it admits lowercase and the underscore, which no key AWS has published
// carries, so a scan reading it as the format would have to widen its alphabet
// to match and would then fire on any sixteen word characters. It is not read
// as the format here.
//
// What AWS shows is twenty characters, without exception, in every access key
// ID in its documentation — AKIAIOSFODNN7EXAMPLE and AKIAI44QH8DHBEXAMPLE on
// the GetAccessKeyInfo page among them — and twenty-one in every unique
// identifier beside them. Twenty is therefore an observation of the examples
// rather than a documented format, and the count below is only as good as that
// observation. The wager is bounded: were AWS to issue a key longer than
// twenty, the characters past the twentieth would be left in the output.
// Against that stands what a floor would cost, which the ASIA paragraph below
// is about, and which bites on text that exists today rather than on text that
// might.
//
// So the sixteen behind the prefix are a count and not a floor, and a longer
// run of the alphabet is not one longer key but a key with something written
// after it. Only the key is redacted, and that costs the tail:
// AKIA0123456789ABCDEFGHIJ leaves GHIJ in the output. Those four characters are
// part of no credential if the twenty in front of them are a key, and the
// alternatives are worse in the direction that matters. Asking for a boundary
// there would leave that key in the output whole; running the alphabet out
// instead would redact every character of the run, which is what makes the ASIA
// below cost a reader a whole word rather than twenty characters of one.
//
// The alphabet is the uppercase letters and the ten digits, which is every
// character AWS has shown in a key. It is wider than what the keys are thought
// to be built from: the characters of a real key are reported to come from the
// base32 alphabet ABCDEFGHIJKLMNOPQRSTUVWXYZ234567, which holds no 0, 1, 8 or
// 9. That report is other people's reading of issued keys, not something AWS
// documents, so it is not what the scan turns on — a scan keyed on it would
// leave a whole key in the output the day one of those four digits appears in
// one, on the strength of a claim AWS never made. Admitting the ten widens
// what is located by nothing a reader can read: what reaches a span either way
// is twenty uppercase characters and digits opening with AKIA or ASIA.
//
// What this pattern over-matches on: ASIA is an English word, and AKIA is not.
// So an unbroken run of twenty uppercase letters and digits that opens with
// those four is redacted whether or not it is a credential: written in capitals
// and unbroken, ASIA PACIFIC SOUTHEAST is exactly twenty characters and is
// redacted whole, and ASIAN ELEPHANT CONSERVATION is longer, so its first
// twenty go and ATION stays. What reaches a span is never prose as a reader
// writes it — a space, a hyphen or a lowercase letter ends the run, so the
// text has to be twenty characters of unbroken capitals before the question
// arises — but it can be a word, which a git SHA or an MD5 cannot. The tables
// in builtin_aws_access_key_id_test.go and the corpus beside it pin that
// behaviour so it cannot move unnoticed.
//
// It is admitted, and not merely tolerated. Twenty unbroken capitals opening
// with ASIA are a key's format exactly, so there is nothing left in the text
// to read them by: a real key and a word written that way are the same twenty
// bytes, and a pattern that let one through would let the other through too.
// Redacting both is the answer that keeps the credential; keeping the word
// would cost the credential. The grammar here is already the format AWS states,
// and tightening it is not on offer.
//
// The two tightenings that look available buy less than they cost. Asking the
// body for at least one digit would tell these apart, and would also drop
// every real key whose sixteen characters happen to be all letters — a share
// large enough to matter under any reading of how a key is generated, and not
// one this file is in a position to put a number on, since AWS documents
// neither the alphabet nor how the characters are drawn. Asking for a boundary
// behind the match would drop ASIANELEPHANTCONSERVATION and leave
// ASIAPACIFICSOUTHEAST, which is twenty characters exactly, so it buys part of
// the case at the price of every key written against a capital.
//
// referenceAWSAccessKeyID in builtin_aws_access_key_id_test.go keeps the
// grammar as a regular expression, spelling the prefixes and the count again so
// that the two are changed together, and the fuzz target beside it holds this
// scan to that expression.
var awsAccessKeyID = NewPattern("aws-access-key-id", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops settling: a piece of a prefix standing at the end
	// of it, or a candidate the end of it cut short, whichever comes first.
	retain := awsAccessKeyIDTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], awsAccessKeyIDAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not. The two
		// prefixes overlap one another: ASIAKIA0123456789ABCDEF holds an AKIA three
		// characters into an ASIA candidate, so a key can begin inside the span of
		// the key before it, and consuming a match would step over that key and leave
		// it in the output whole. The two spans then overlap, which a Masker resolves
		// into one.
		offset = anchor + 1

		if anchor < awsAccessKeyIDAnchorIndex {
			continue
		}
		start := anchor - awsAccessKeyIDAnchorIndex

		// The byte both prefixes open with is tested before the candidate is
		// read. Every anchor the search stops at reaches this line, and all but
		// the few that open a candidate are turned away by one byte where
		// reading the candidate is a length, two prefix comparisons and a walk.
		if src[start] != awsAccessKeyIDFirstByte {
			continue
		}

		end := start + awsAccessKeyIDChars
		if end > len(src) {
			// The input ends inside this candidate, so what it is cannot be
			// decided here: the characters behind the ones written are what
			// tell a key from a capitalised word, and they are not here yet.
			// What is behind the prefix is not looked at before giving up on
			// it either — a candidate this near the end of the input is rare
			// enough that reading it would buy back fewer bytes than the
			// reading costs.
			retain = min(retain, start)
			continue
		}
		if isAWSAccessKeyID(src[start:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// awsAccessKeyIDPrefixes are the two prefixes AWS documents for an access key
// ID: AKIA for a long-term key and ASIA for temporary credentials from AWS STS.
//
// Both are awsAccessKeyIDPrefixChars characters and both open with
// awsAccessKeyIDFirstByte, which Test_awsAccessKeyIDPrefixes holds every entry
// to: a prefix of another length is one the scan never finishes reading.
//
// What decides whether the scan reaches a prefix at all is the anchor below,
// which stands at a fixed index of both and is Test_awsAccessKeyIDAnchor's to
// hold.
var awsAccessKeyIDPrefixes = [...]string{"AKIA", "ASIA"}

const (
	// awsAccessKeyIDFirstByte is the byte every prefix opens with.
	awsAccessKeyIDFirstByte = 'A'

	// awsAccessKeyIDAnchor is the byte the scan searches the input for and
	// awsAccessKeyIDAnchorIndex is where it stands in both prefixes, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; what makes it this byte is that a
	// capital A opens the acronyms and the capitalised words a log line is
	// full of, where the I two characters in stands almost nowhere. Over the
	// line these benchmarks are written on the A stands three times and the I
	// not once, and on a line of nothing but candidates the two prefixes carry
	// two A apiece against one I, so the rarer byte is rarer there as well.
	//
	// It is the one index the two prefixes agree on besides the A, which is
	// what lets one search serve both. A prefix added that spelled its third
	// character differently would be a prefix no candidate is ever found at,
	// which Test_awsAccessKeyIDAnchor reports.
	awsAccessKeyIDAnchor      = 'I'
	awsAccessKeyIDAnchorIndex = 2

	// The counts an access key ID is written to. Every one AWS shows is
	// twenty characters, and AWS states no length of its own, so unlike the
	// GitHub bodies these are exact rather than the shortest seen — on an
	// observation rather than a specification, which the rationale above
	// weighs.
	awsAccessKeyIDPrefixChars = 4
	awsAccessKeyIDBodyChars   = 16
	awsAccessKeyIDChars       = awsAccessKeyIDPrefixChars + awsAccessKeyIDBodyChars
)

// isAWSAccessKeyID reports whether s is an access key ID: exactly
// awsAccessKeyIDChars characters, one of the documented prefixes, and the rest
// of them in the alphabet a body is written in.
//
// It is handed the candidate whole rather than the body alone so that the count
// is checked here and not left to the caller to have cut correctly.
func isAWSAccessKeyID(s string) bool {
	if len(s) != awsAccessKeyIDChars || !opensAWSAccessKeyID(s) {
		return false
	}
	for i := awsAccessKeyIDPrefixChars; i < len(s); i++ {
		if !isAWSAccessKeyIDByte(s[i]) {
			return false
		}
	}
	return true
}

// opensAWSAccessKeyID reports whether s opens with one of the documented
// prefixes.
func opensAWSAccessKeyID(s string) bool {
	for _, prefix := range awsAccessKeyIDPrefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// isAWSAccessKeyIDByte reports whether c belongs to the alphabet the characters
// behind the prefix are written in: the uppercase letters and the digits, which
// is every character AWS has shown in a key. Lowercase is not admitted — no key
// AWS has published carries one, and admitting it would turn every word of
// twenty characters opening with akia into a candidate.
func isAWSAccessKeyIDByte(c byte) bool {
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z'
}

// awsAccessKeyIDTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var awsAccessKeyIDTail = newPrefixTail(awsAccessKeyIDPrefixes[:]...)
