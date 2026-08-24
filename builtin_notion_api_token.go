package mask

import "strings"

// NotionAPIToken locates Notion API tokens: the prefix ntn_ and the forty-six
// characters behind it, or the prefix secret_ and the forty-three behind that —
// fifty characters either way. One string serves every kind of token the Public
// API takes, the static token of an internal connection, the OAuth access token
// of a public one and a personal access token alike, so nothing in a token says
// what it authenticates as.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly fifty characters of it are. So text of that shape is redacted
// whether or not Notion issued it. A space, a hyphen, a further underscore or a
// body of the wrong length ends the reading, so text as it is ordinarily
// written is not affected.
//
// Its name is "notion-api-token".
func NotionAPIToken() Pattern { return notionAPIToken }

// What Notion states about this format, it states in order to warn a reader off
// it. The changelog entry announcing the prefix says the format may change over
// time, that a regular expression written to identify or validate a token leads
// to false positives and negatives, and that the string is to be treated as
// opaque and checked by making a request with it. Notion's own JavaScript
// client does that and no more: the token is a string it carries to a header,
// and nothing in it reads a character of one.
//
// So this pattern rests on the tokens published and on the rulesets reading
// them, as the Slack, GitLab, Google, OpenAI, Anthropic, Stripe, PyPI, npm,
// Sentry and Linear ones do — and further on them than any of those, because
// what Notion declines to state is not the length alone but the alphabet, the
// structure, and whether either survives the next change. What is written
// below is therefore written to be wrong cheaply rather than to be exact:
// where a reading could be tighter and the vendor has not underwritten the
// tightening, it is left loose, and the paragraphs on the eleven digits and on
// the over-matching are the two places that choice is paid for.
//
// What Notion does state is the prefix, and why there is one. Public API tokens
// generated from 25 September 2024 open with ntn_ where the ones before them
// opened with secret_, and the reason given is compatibility with secret
// scanners and telling a Notion token apart from the other secrets in a file.
// The tokens carrying the older prefix were not revoked and do not expire of
// themselves: the same entry says they continue to work unchanged and that
// nothing need be done about them. That is why both are read here, and why the
// older is read at all.
//
// The counts are read off the tokens published for each, since the vendor
// states none. gitleaks reads ntn_ and forty-six characters, divided eleven,
// thirty-two and three; kingfisher reads the same forty-six and cites gitleaks
// for them. trufflehog reads secret_ and forty-three, and kingfisher reads
// forty-three as well, each around a published token of its own. GitHub's
// secret scanning lists Notion twice over, as notion_api_token and as
// notion_integration_token, and publishes what it detects rather than the
// expression it detects with — this pattern takes its name from the first of
// the two.
//
// Both counts come to the same fifty characters with the prefix in front, and
// that is what makes either worth reading exactly rather than as a floor: the
// prefix lost three characters when Notion changed it and the body gained
// three, so a token stayed the length it had been. A number reached twice, from
// two formats a vendor rewrote between and from rulesets that did not read it
// off each other, is a different thing from a number read off one set of
// examples — which is what the AWS and Google counts are, and they are read
// exactly too.
//
// The tightening on offer behind ntn_ is the one gitleaks and kingfisher take:
// that the first eleven characters of a body are digits. It is not taken, and
// what it rests on is why. gitleaks carries three tokens, made on the
// integrations page as its author describes, and all three open with the same
// eleven digits, 45647615172, where the twelfth character differs between them
// — 9 in one, 2 in the next, W in the third. Eleven leading digits do not fall
// out of an alphabet of sixty-two by chance, so the run is structure rather
// than coincidence, and the eleven being shared is what says the three came
// from one account. That is the whole of the evidence: it says the run is
// eleven long for that account and says nothing about the next, and an
// identifier is not a clock — nothing published says the number is written to a
// width at all. The refresh token Notion prints in its authorization guide
// opens with thirteen.
//
// What being wrong there costs is the whole credential. A scan asking for
// eleven digits and handed a token whose numeric part is ten or twelve locates
// nothing, and every character of a live token stays in the output. What
// declining it costs is the over-match set out below. The asymmetry is the one
// the OpenAI, Anthropic, Stripe, PyPI, npm and Linear scans read their counts
// loosely for, and it is sharper here than in any of them: a ruleset is
// reporting a finding to somebody who will read it and weigh it, where this
// library is writing over a value nobody will see again.
//
// Reading fifty exactly is a wager of the same kind, and the vendor's warning
// covers it as squarely, so what separates the two is worth writing down. The
// first thing is what each rests on: the eleven digits are three tokens of one
// account, where the fifty is two formats Notion rewrote between and published
// at the same length, so a change that broke it would have to break a number
// Notion has already kept once. The second is what each buys. Declining the
// digits buys back nothing that had to be given up — ntn_ and forty-six letters
// and digits is not text anybody writes — while declining the count would leave
// secret_ and a run, which is client_secret_ and whatever stands behind it, and
// that is a grammar this library cannot have.
//
// Being wrong costs differently as well, and that is the third thing. A token
// longer than fifty is located for its first fifty and the characters past
// them are left in the output, which is what an exact count costs wherever it
// is read and what the AWS, Google, SendGrid and Sentry scans pay too — all
// four read a count rather than a floor; a token shorter than fifty is located
// nowhere, which is the far side of it. The eleven digits have no near side: a
// token whose numeric part is ten characters or twelve is located nowhere at
// any length. The cases in builtin_notion_api_token_test.go pin both sides of
// the count.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the digits. It is what all three rulesets admit behind either
// prefix, and what every token any of them publishes is written in. Neither
// character base64url adds is admitted, and the underscore's absence is
// load-bearing rather than incidental — the whole of the scan below is built on
// it.
//
// The underscore is the one thing the two prefixes have in common, and it
// stands at the end of each: ntn_ carries it fourth, secret_ seventh. That is
// what the scan searches the input for, because there is nothing else the two
// share. A search for the first letter would be two searches over the text, or
// a walk over every n and every s in it, where the letters a prefix is spelled
// with are among the commonest in prose and the character it closes with is
// not.
//
// A candidate is therefore read backwards from its anchor, which no other scan
// here does and which two properties of the table make safe. No prefix carries
// the anchor anywhere but at its last character, so at most one of them stands
// in front of any given underscore; and no prefix is the suffix of another, so
// the order the table is written in decides nothing. Test_notionAPITokenPrefixes
// holds both, and holds every character in front of an anchor to being one a
// body is written with — which is what lets a token be written inside another,
// below.
//
// Reading backwards is also what makes the order of the spans worth an
// argument, where every scan beside this one reports them in the order it walks
// the text. Take two candidates, one at an underscore a and a later one at b,
// and suppose the second began in front of the first. Its start is b+1 less the
// length of its prefix, so beginning earlier than a+1 less the length of the
// first's means b-a is smaller than the second's prefix — which puts a inside
// that prefix and somewhere other than its last character, where no prefix
// carries the anchor. So a later underscore never opens an earlier candidate,
// the spans come out ascending, and the reference below can be compared against
// them span for span.
//
// There is no boundary on either side of a match, as there is none in any of
// the scans beside this one but the Slack and Stripe ones. A word boundary in
// front would drop the whole match rather than trim it wherever a token is
// written against a word character, as NOTION_TOKEN_ntn_... is, and one behind
// it would drop a token followed by a character of the token's own alphabet.
// What may stand either side is held back by the alphabet and the count alone.
//
// The tightening on offer in front is the one the Slack and Stripe scans take,
// to ask that no letter and no digit stand before the prefix. It would buy
// almost nothing here, because that test admits the underscore: client_secret_,
// app_secret_ and webhook_secret_ each close on the whole of the older prefix
// and each carry an underscore in front of it, so every one of them would pass
// the test unchanged. What it would turn away is a letter or a digit written
// directly against a prefix — mysecret_ and the like — and it would cost a
// token written straight after a letter, which is the trade the AWS scan
// declines for the same reason.
//
// The scan advances one byte past the anchor whether the candidate became a
// token or not, and steps over nothing by doing so. That is a weaker claim than
// the one the scans beside this one make when they resume a byte past the start
// of a candidate, and it holds for a different reason: a candidate is found by
// its own underscore, a body carries none, and every underscore in the input is
// looked at in turn.
//
// A token can still be written inside another, and is still found. The
// characters in front of either anchor belong to the alphabet a body is written
// in, so a body closing with ntn hands the underscore written after the token
// to a candidate beginning three characters before that token ends, and a body
// closing with secret does the same six characters before. The underscore such
// a candidate is found by stands past the first token rather than inside it, so
// it is one this scan has not yet passed. The two spans then overlap, which a
// Masker resolves into one.
//
// The scan keeps no cursor and needs none, as the AWS, Google and SendGrid
// scans do not and for their reason: a candidate reads at most fifty bytes and
// stops, which is the guarantee the JWT, GitHub, GitLab, Slack, OpenAI,
// Anthropic and PyPI scans buy with a run cursor, bought here by the count
// being a count. What opens a candidate at all is an underscore, and the input
// holds no more of those than it has characters.
//
// What this pattern over-matches on: fifty characters of the right shape that
// nobody issued. The two prefixes are worth separating here, because only one
// of them draws in text somebody wrote.
//
// Behind ntn_ there is next to nothing. The underscore is what makes that so:
// standard base64 writes none, so a certificate, a PEM body or an embedded
// image carries no prefix to be found at however long it runs, and only a
// base64url encoding can hold one. There four characters of an alphabet of
// sixty-four stand where ntn_ stands about once in seventeen million
// characters, and the forty-six behind one carry neither character base64url
// adds about a quarter of the time, so the two together stand about once in
// seventy million characters of such an encoding. Outside an encoding, a
// snake_case name whose segment closes on ntn is what is left, and it must be
// followed by forty-six unbroken letters and digits.
//
// Behind secret_ the same shape is reachable by writing, because secret_ closes
// an ordinary name: client_secret_, app_secret_ and webhook_secret_ are that
// shape and are written every day. What keeps them out is what follows them in
// a file, which is =, a colon and a space, or a quote — none of them a
// character a body is written with, and any of them ends the reading at once. A
// name is drawn in only where forty-three unbroken letters and digits are
// spliced straight onto it, and a string of that length standing there is a
// secret of some kind whatever issued it: the name in front of it says so. That
// is over-matching on a value already opaque to a reader, which is the standard
// the rest of this pattern's over-matching is held to.
//
// The collision either prefix leaves is a digest written behind it. Hexadecimal
// digits are base62 and a digest carries nothing that ends a run, so secret_
// and the first forty-three characters of a SHA-256 are a token to this scan,
// as ntn_ and the first forty-six are; the twenty-one or eighteen characters
// left over stay in the text, which is what the count being a count leaves
// behind. A SHA-1 is forty characters and an MD5 thirty-two, and neither
// reaches either count, so both are left alone.
// Test_NotionAPIToken_aDigestBehindThePrefix pins all four.
//
// What reaches a span is never prose, never a git SHA and never an MD5. No word
// is spelled ntn_ or secret_ with an unbroken run of letters and digits of the
// right length behind it, and neither digest holds the underscore a candidate
// is found by.
//
// The two Notion credentials this pattern does not read are the refresh token
// and the OAuth client secret. A refresh token opens with nrt_, and nothing
// published pins what follows: the one example Notion prints is forty-nine
// characters where both token forms are fifty, and the one ruleset carrying a
// rule for it reads a range of forty to fifty-five and admits the underscore
// inside the body, which is the slack of a shape nobody has measured. A count
// guessed at there locates part of a token or none of it, and four characters
// of prefix are too little to read fifty-odd of any alphabet by. The client
// secret is listed by GitHub's secret scanning as notion_oauth_client_secret
// and its shape is stated nowhere at all.
//
// referenceNotionAPITokenFind in builtin_notion_api_token_test.go states the
// same grammar the plain way, spelling both prefixes, both counts and the
// alphabet again so that the two are changed together, and the fuzz target
// beside it holds this scan to that statement. It is written out rather than
// built on a regular expression, and its own comment says what an alternation
// of two literals costs an engine and what that cost did to the fuzzing.
var notionAPIToken = NewPattern("notion-api-token", func(src string) []Span {
	var spans []Span

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], notionAPITokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not,
		// for the reason the rationale above gives: a candidate is found by the
		// underscore its own prefix closes with, a body carries none, and a
		// token written inside another is found by an underscore standing past
		// the token it begins inside.
		offset = anchor + 1

		prefix := notionAPITokenPrefixAt(src, anchor)
		if prefix == 0 {
			continue
		}
		start := anchor + 1 - prefix

		if end := start + notionAPITokenChars; end <= len(src) && isNotionAPITokenBody(src[anchor+1:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
})

// notionAPITokenPrefixes are the prefixes this pattern reads: the one Notion
// issues today, and the one it issued until September 2024 and has not revoked.
//
// They are written longest first as a courtesy rather than as a rule, as the
// Slack and GitLab tables are and unlike stripeSecretKeyPrefixes. No two of
// them match at the same anchor: each closes with the anchor and carries it
// nowhere else, and neither is the suffix of the other, so at most one stands
// in front of any underscore whichever order they are tried in.
// Test_notionAPITokenPrefixes holds them to all of that, and to carrying
// nothing in front of the anchor but characters a body is written with — which
// is what lets one token be written inside another.
var notionAPITokenPrefixes = [...]string{
	"secret_", // until 25 September 2024, and still valid
	"ntn_",    // since
}

const (
	// notionAPITokenAnchor is the character every prefix closes with and the
	// one candidate positions are found by. It belongs to no body, which is
	// what makes a candidate's own underscore identify it and so what lets the
	// scan advance past an anchor rather than reason about a run.
	notionAPITokenAnchor = '_'

	// notionAPITokenChars is the whole of a token, prefix included. Fifty is
	// what both published forms come to — ntn_ and forty-six, secret_ and
	// forty-three — and reading the total rather than a count a body is what
	// carries that agreement into the scan. Test_notionAPITokenChars holds the
	// number and holds each prefix to leaving behind it the count its own
	// ruleset states.
	notionAPITokenChars = 50
)

// notionAPITokenPrefixAt returns the length of the prefix closing at the anchor
// standing at i in src, or zero where none does.
//
// It reads backwards, unlike the prefix lookups the Slack, GitLab and Stripe
// scans keep, because what the scan searches for is the character a prefix ends
// on rather than the one it begins with. The bound is checked here rather than
// left to the caller: a prefix longer than the text in front of the anchor is
// the ordinary case near the start of an input, not an error.
func notionAPITokenPrefixAt(src string, i int) int {
	for _, prefix := range notionAPITokenPrefixes {
		if start := i + 1 - len(prefix); start >= 0 && src[start:i+1] == prefix {
			return len(prefix)
		}
	}
	return 0
}

// isNotionAPITokenBody reports whether every character of s belongs to the
// alphabet a body is written in.
//
// The length is the caller's to have cut: a body is whatever is left of the
// fifty characters a token is once its prefix is taken off, so the count lives
// in notionAPITokenChars and in the length of the prefix rather than being
// checked again here.
func isNotionAPITokenBody(s string) bool {
	for i := range len(s) {
		if !isBase62Byte(s[i]) {
			return false
		}
	}
	return true
}
