package mask

import "strings"

// PostmanAPIKey locates Postman API keys: the prefix PMAK-, twenty-four
// characters, a hyphen and thirty-four more — sixty-four characters
// altogether. One key carries the whole of the account that created it, over
// every workspace, collection and environment that account can reach, and
// nothing in it says otherwise.
//
// A key is located wherever it is written, with no word boundary either side,
// and exactly sixty-four characters of it are. So text of that shape is
// redacted whether or not Postman issued it. A space, an underscore, a dot, a
// segment of the wrong length or a hyphen standing anywhere but the
// twenty-fifth character behind the prefix ends the reading, so text as it is
// ordinarily written is not affected.
//
// Its name is "postman-api-key".
func PostmanAPIKey() Pattern { return postmanAPIKey }

// API key is Postman's own name for this string. The page documenting how to
// authenticate against the Postman API calls it that, so does the page on
// generating one and so does the administration page on managing them for a
// team, and none of the three has a second name for the credential. There is
// one kind of it: the key is minted for a user, sent in the X-API-Key header,
// and carries whatever that user can do, with no scope, role or expiry written
// into the string to tell one key from another.
//
// What Postman publishes about the format is nothing. The authentication page
// says to send the key in a header and stops there; the page on generating one
// walks through the dialog; the administration page is about revoking and
// rotating; the announcement of the GitHub secret scanning partnership says a
// leaked key is reported and does not say what a key looks like. No example
// key is printed on any of them and no expression appears in any of them,
// which is why the rulesets below that cite a source for this format cite
// those same pages and then write an expression of their own. So the grammar
// here is not the vendor's own statement of its format.
//
// What states it instead is the agreement between the rulesets that detect it
// and the keys that have been published in their test data. On the shape they
// do not divide at all: gitleaks, Google's osv-scalibr, kingfisher and
// noseyparker each read PMAK-, twenty-four characters, a hyphen and
// thirty-four more, and trufflehog reads the same span as fifty-nine
// characters of a class that admits the hyphen. The keys written into their
// corpora agree: every one is the prefix, twenty-four lowercase hexadecimal
// digits, a hyphen and thirty-four more.
//
// The alphabet is where they divide, and it is the one decision here that had
// to be made rather than read. gitleaks and osv-scalibr read hexadecimal;
// noseyparker and kingfisher read the letters of both cases with the digits,
// and kingfisher then holds back what that admits with an entropy floor and a
// demand for two digits. The wider of the two is read here, isBase62Byte in
// builtin_scan.go, and the reason is that the vendor is silent: nothing
// published rules out a key carrying a letter past f, and what the narrower
// class would cost the first time one did is not the end of a credential but
// the whole of it, left in the output with nothing found. The published keys
// are evidence of what has been minted, not of what may be.
//
// The Supabase access token beside this one is the worked precedent for the
// opposite decision, and what separates the two is exactly what is missing
// here. There the vendor's own CLI validates a token against an expression
// that admits lowercase hexadecimal alone, with a unit test named for refusing
// an uppercase one, so a token the narrower class turns away is a token
// Supabase itself would refuse. Postman ships no such check, so reading
// hexadecimal here would be this package guessing at a rule rather than
// reading one.
//
// What the wider class draws in is nothing a reader can read. The hyphen at
// the twenty-fifth character behind the prefix is the whole of why: no run of
// one alphabet carries it, so a body is not a run at all but two runs of exact
// length divided at a fixed place. A digest is the run this shape would
// otherwise be written by accident, and it reaches nothing here — an MD5 is
// thirty-two characters, a SHA-1 forty and a SHA-256 sixty-four, none of them
// is twenty-four or thirty-four, and none of them carries a hyphen to stand
// where this format needs one. A UUID carries four hyphens and is the near
// miss worth naming: they fall at its ninth, fourteenth, nineteenth and
// twenty-fourth characters, one short of the twenty-fifth this format needs,
// and it runs out thirty-six characters in besides.
// Test_PostmanAPIKey_aDigestBehindThePrefix pins both.
//
// The prefix is read in the one case every published key carries and every
// ruleset but kingfisher writes. Reading it in either case would buy nothing:
// PMAK- is not a word, not an environment variable and not a path segment, so
// there is no lowercase spelling of it that anything writes.
//
// The counts are read exactly rather than as floors. A run longer than
// thirty-four behind the second hyphen is not one longer key but a key with
// something written after
// it, and only the key is redacted; running the alphabet out instead would
// swallow whatever was written against the end of one. Nothing states a second
// shape behind this prefix, so reading the counts exactly turns away nothing a
// range would have caught.
//
// There is no boundary on either side of a match, where every ruleset above
// asks for one. A word boundary in front would drop the whole match rather
// than trim it wherever a key is written against a word character, as
// POSTMAN_API_KEY_PMAK-... is, and one behind it would drop a key followed by
// a letter or a digit — which under exact counts is a key with a character
// written after it. What may stand either side is held back by the character
// class, the two counts and the interior hyphen alone.
//
// The tightening on offer in front is the one the Slack and Stripe scans take:
// to ask that no letter and no digit stand before the prefix. It is declined
// for the AWS scan's reason, and what it would turn away here is narrow enough
// to name: a word closing on PMAK, in that case, with a hyphen and a key
// written straight against it. What it would cost is a key written against a
// letter, which would then be left in the output whole rather than trimmed.
//
// The byte the scan searches the input for is the K of the prefix, and the
// prefix is read back from it. builtin_scan.go says why a scan searches for
// one byte of its prefix rather than for the prefix itself; what makes it this
// byte is what the other four are written in. The hyphen the prefix closes
// with is the character a date, a UUID, a kebab-case name and a hyphenated
// word are written with, so a scan anchored on it would open a candidate on a
// great deal of ordinary text to reject it again. Of the four letters, P, M
// and A open the words a log writes in uppercase — the method and the month,
// the Accept and Authorization a header line is named by, the vendor's own
// name in a user agent — where K opens none of them. Over the log line these
// benchmarks are timed against the hyphen stands twice, the P twice and the A
// once, and the K not at all.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a key or not, which is the default. It is load-bearing
// here, because a key can be written inside another and only advancing reaches
// one. The alphabet a body is read in holds every letter the prefix is written
// with, so a body may spell PMAK; what it may not hold is the hyphen the
// prefix closes with, so a candidate opening inside a key has to borrow a
// hyphen the key itself carries or reach past its end for one. A key carries
// one hyphen a candidate could borrow, the one dividing its two segments, and
// a candidate opening there needs a second hyphen twenty-five characters
// further on, where the key's second segment stands — so it opens and cannot
// close. What is left is the four positions at the end of a key from which the
// prefix reaches past it, and a key beginning at any of them is one a scan
// stepping over the match it just took would leave in the output whole. The
// two spans overlap where it happens, and Masker.locate resolves them.
// Test_PostmanAPIKey_aKeyBeginningInsideAnother drives the shape and
// Test_postmanAPIKeyPrefix counts the positions.
//
// The scan keeps no cursor and needs none: a candidate reads at most
// sixty-four bytes and stops, which bounds what it reads with no state to be
// wrong about, and is what rules out a quadratic input.
//
// What this pattern over-matches on is the format itself: twenty-four letters
// and digits, a hyphen and thirty-four more, written behind the prefix with
// nothing between. There is nothing left to tell such text from a key — the
// format is the whole of what a reader has — so declining it would mean
// declining every real key of the same shape. It is never prose that reaches a
// span: the prefix closes on a hyphen no word runs into, and what has to stand
// behind it is fifty-nine unbroken characters whose only hyphen falls on the
// twenty-fifth, which is a line somebody writes on purpose.
//
// The collection access key is left alone, and it is a credential this
// pattern's name does not cover rather than one the scan happens to miss.
// Postman calls it a collection access key and not an API key, it grants
// read-only access to one collection where a key here carries the whole
// account, and a caller has reason to redact the one and not the other. It is
// written PMAT- and carries no PMAK- to be found at, so nothing in this scan
// reaches it.
//
// referencePostmanAPIKeyFind in builtin_postman_api_key_test.go keeps the
// grammar as a regular expression, spelling the prefix, both counts, the
// hyphen between them and the alphabet again so that the two are changed
// together, and the fuzz target beside it holds this scan to that expression.
var postmanAPIKey = NewPattern("postman-api-key", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := postmanAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], postmanAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not,
		// for the reason the rationale above gives: a body may close on the
		// letters the prefix opens with, so a key can begin at any of the last
		// four characters of the one in front of it, and a scan stepping over
		// what it took would leave that one whole. Stepping one byte past the
		// anchor is what leaves the next candidate one byte past this one,
		// which builtin_scan.go sets out.
		offset = anchor + 1

		if anchor < postmanAPIKeyAnchorIndex {
			continue
		}
		start := anchor - postmanAPIKeyAnchorIndex

		// The byte a prefix opens with is tested before the prefix is
		// compared. Every anchor the search stops at reaches this line, and
		// all but the few that open a candidate are turned away by one byte
		// where a comparison of the whole prefix is a length and a read.
		if src[start] != postmanAPIKeyPrefix[0] || !strings.HasPrefix(src[start:], postmanAPIKeyPrefix) {
			continue
		}

		body := start + len(postmanAPIKeyPrefix)
		end := start + postmanAPIKeyChars
		if end > len(src) {
			// The input ends inside the body, and the counts and the hyphen
			// dividing them are the whole of what tells a key from any other
			// run written behind the prefix.
			retain = min(retain, start)
			continue
		}
		if isPostmanAPIKeyBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// postmanAPIKeyPrefix is what every key opens with, and what the scan reads
	// back from its anchor. It closes on a character no body is written with,
	// which is what makes the search cheap on a line holding no key and what
	// bounds where a key may begin inside another;
	// Test_postmanAPIKeyPrefix holds it to both.
	postmanAPIKeyPrefix = "PMAK-"

	// postmanAPIKeyAnchor is the byte the scan searches the input for and
	// postmanAPIKeyAnchorIndex is where it stands in the prefix, so a candidate
	// begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what makes it
	// this byte.
	postmanAPIKeyAnchor      = 'K'
	postmanAPIKeyAnchorIndex = 3

	// postmanAPIKeySeparator is the character dividing the two segments of a
	// body. It is the one character of a body the alphabet does not admit, so
	// testing it is what turns away a run of the alphabet before any of that
	// run is walked.
	postmanAPIKeySeparator = '-'

	// postmanAPIKeyFirstChars and postmanAPIKeySecondChars are how many letters
	// and digits stand either side of the separator. They are the counts every
	// ruleset that reads this format asks for, read exactly rather than as
	// floors for the reason the rationale above gives.
	postmanAPIKeyFirstChars  = 24
	postmanAPIKeySecondChars = 34

	// postmanAPIKeyBodyChars is everything behind the prefix: both segments and
	// the separator between them.
	postmanAPIKeyBodyChars = postmanAPIKeyFirstChars + 1 + postmanAPIKeySecondChars

	// postmanAPIKeyChars is the whole of a key: the prefix and the body.
	// Test_postmanAPIKeyChars holds it to sixty-four.
	postmanAPIKeyChars = len(postmanAPIKeyPrefix) + postmanAPIKeyBodyChars
)

// isPostmanAPIKeyBody reports whether s is everything behind the prefix of a
// key: postmanAPIKeyFirstChars letters and digits, the separator, and
// postmanAPIKeySecondChars more.
//
// It is handed the counts as well as the characters so that they are checked in
// one place rather than being left to the caller to have cut correctly.
//
// The separator is tested before either segment is walked. It is the one
// character of a body the alphabet does not admit, so a run of that alphabet —
// a digest, an identifier, a base62 payload — is turned away by a single
// comparison rather than by twenty-four.
func isPostmanAPIKeyBody(s string) bool {
	if len(s) != postmanAPIKeyBodyChars || s[postmanAPIKeyFirstChars] != postmanAPIKeySeparator {
		return false
	}
	for i := range postmanAPIKeyFirstChars {
		if !isBase62Byte(s[i]) {
			return false
		}
	}
	for i := postmanAPIKeyFirstChars + 1; i < len(s); i++ {
		if !isBase62Byte(s[i]) {
			return false
		}
	}
	return true
}

// postmanAPIKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var postmanAPIKeyTail = newPrefixTail(postmanAPIKeyPrefix)
