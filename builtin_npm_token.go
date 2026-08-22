package mask

import "strings"

// NPMToken locates npm access tokens: the prefix npm_ and thirty-six
// characters behind it. One shape serves every token the registry issues in
// this format — the granular access tokens npmjs.com creates today, and the
// classic tokens, read-only, automation and publish alike, created in it until
// npm disabled them — so a token says which registry it authenticates against
// and not what it is allowed to do there.
//
// A token is located wherever it is written, with no word boundary either side,
// and is redacted from its npm_ to the end of the run it stands in. So a token
// written against a word character keeps its span, and a character of the
// token's own alphabet written straight after a token is redacted with it.
//
// Its name is "npm-token".
func NPMToken() Pattern { return npmToken }

// What npm states of this format it states in one place, the announcement of
// it, and states more there than Slack, GitLab, Google, OpenAI and Anthropic
// state of theirs anywhere. A token opens with npm and an underscore behind it,
// where the format before this one was a bare UUID; the random part carries a
// hundred and seventy-eight bits of entropy where that UUID carried a hundred
// and twenty-eight; the last six characters are a CRC32 checksum encoded in
// npm's own base62. And the reason given for all three is that npm matched the
// format GitHub had shipped for its own tokens, which is the format the classic
// alternative of the GitHub scan beside this one reads.
//
// The count follows from those numbers rather than being stated as one.
// Sixty-two characters carry log2(62) bits each, so a hundred and
// seventy-eight bits are thirty random characters, and six more of checksum
// make thirty-six behind the prefix, forty in all. Both rulesets that state a
// shape state that thirty-six exactly: gitleaks reads npm_ and thirty-six
// case-insensitive alphanumerics, trufflehog npm_ and thirty-six of the letters
// of both cases and the digits. GitHub lists npm among the partners its secret
// scanning carries a pattern for, under the token identifier npm_access_token,
// and publishes what it detects rather than the expression it detects with.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the digits, and neither the hyphen nor the underscore base64url
// adds. That is what both rulesets admit behind the prefix and what the
// checksum's own encoding is named for.
//
// The checksum is not verified, as the classic alternative of the GitHub scan
// does not verify the one it carries. npm publishes that the last six
// characters are a CRC32 in "our Base62 implementation" and publishes neither
// the polynomial, nor which bytes are fed to it, nor the order its digits are
// written in. A scan checking the digits would be checking an arithmetic
// reconstructed from outside, and being wrong about it means locating no token
// at all — while what it would buy is nothing a caller wants: the revoked and
// the expired tokens a caller has this library to redact carry checksums that
// verify, so the digits rule none of them out.
//
// The count is read as a floor and not as a count, which is where this scan
// stands with the GitHub one it copies and parts company with the AWS, GitLab
// and Google ones. Those read an exact count because the count is most of what
// tells a value from the text around it, and a run longer than the count is a
// value with something written after it. Here the anchor is doing that work,
// and the thirty-six is a number derived from an entropy figure rather than one
// npm has written down: were npm to lengthen the random part, a scan asking for
// thirty-six exactly would locate the first forty characters of a token and
// leave the rest of it in the output. Read as a floor, a token of any length at
// or above it is located to the end of its run.
//
// What the floor costs is the token shorter than it. A line cut to a column
// limit partway through a token leaves a prefix and a body too short to be one,
// and nothing is located: the random characters written before the cut stay in
// the output. That is the far side of this choice, and the cases in
// builtin_npm_token_test.go pin it so that it stays a decision on the record.
//
// There is no boundary on either side of a match, as there is none in the AWS,
// GitLab, Google, OpenAI and Anthropic scans. A boundary in front would drop
// the whole match rather than trim it wherever a token is written against a
// word character, as NPM_TOKEN_npm_... is, and one behind it would drop a token
// followed by a character of the token's own alphabet — which, since the span
// already reaches to the end of the run, is every token with anything written
// against it.
//
// The scan resumes one byte past the start of a candidate whether it became a
// token or not. The underscore the prefix closes with belongs to no body, but
// the three letters in front of it do, so a body may close with npm and the
// underscore opening the next token stands directly behind it: npm_, a body
// whose last three characters are npm, then _ and a body of its own is two
// tokens, the second beginning three characters before the first one ends.
// Consuming a match would step over such a token and leave it in the output
// whole. The two spans then overlap, which a Masker resolves into one.
//
// No cursor is kept over the run, and none is needed, which is the other thing
// the underscore buys. A candidate asks for an underscore four characters in
// and base62 holds none, so the underscore of the next candidate can be no
// earlier than the byte that ends this run, and the run that candidate reads
// therefore begins past this one. Successive candidates read runs that do not
// overlap, and reading all of them comes to the length of the input — the
// guarantee the classic alternative of the GitHub scan has for the same reason,
// bought without state, where the JWT, GitLab, Slack, OpenAI and Anthropic
// scans have to keep a cursor for want of it.
// Test_npmTokenPrefix_runsDoNotOverlap holds the prefix to the one thing that
// argument rests on, and Test_NPMToken_scanIsLinear drives it.
//
// What this pattern over-matches on: thirty-six characters of base62 behind
// npm_ inside a longer value. The underscore is what makes that rare. Standard
// base64 writes none at all, so a certificate, a PEM body or an embedded image
// carries no prefix to be found at however long it runs, and only a base64url
// encoding can hold one. There four characters drawn from an alphabet of
// sixty-four stand where the prefix stands about once in seventeen million
// characters, and the thirty-six behind one carry neither of the two characters
// base64url adds about three times in ten, so the prefix and a body together
// stand about once in fifty million characters of such an encoding. The run
// from that prefix to the end of the encoding is then redacted, and what is
// taken is a stretch of a value that was already opaque to a reader.
//
// The format npm issued before this one is not read at all, and could not be.
// It was a bare UUID, and a UUID is what a request id, a trace id and a
// correlation id are written as — a grammar admitting one would redact those
// wherever a log line carries them, which is over-matching on values a reader
// reads rather than on values already opaque. There is no anchor to narrow it
// with either: nothing in such a string says npm issued it. npm has revoked the
// last of them, so what is given up is a credential that authenticates nothing.
//
// The collision this format leaves is a digest written behind the prefix. The
// hexadecimal digits are base62 and nothing inside a digest ends a run, so npm_
// and the forty characters of a SHA-1 is a token to this scan, as npm_ and the
// sixty-four of a SHA-256 is — which is the shape a cache key takes where it is
// built from the prefix and the hash of a lock file, as a GitHub Actions key
// written npm_${{ hashFiles('**/package-lock.json') }} is. Those are redacted,
// and nothing could be done about it that would not cost a credential: such a
// run is a token's format exactly, so a scan declining it would decline every
// token npm happened to write in the digits alone. What is taken is a value
// already opaque to a reader, which is the standard the rest of this pattern's
// over-matching is held to, and this is the one place where the value taken is
// one a reader had a use for. An MD5 is left alone, at thirty-two characters
// four short of the floor, and so is any digest written behind a hyphen rather
// than an underscore. Test_NPMToken_aDigestBehindThePrefix pins all four.
//
// What reaches a span is never prose, and never a digest standing on its own. A
// digest carries no underscore, so it holds no prefix to be found at however
// long it runs, and no word is spelled npm_. Ordinary snake_case text carries
// the prefix — the environment variables npm itself exports to a lifecycle
// script, npm_package_ and npm_lifecycle_ among them, are that shape — and what
// turns those away is the thirty-six unbroken characters of the alphabet the
// body is held to, which the next underscore of such a name ends long before.
//
// referenceNPMToken in builtin_npm_token_test.go keeps the grammar as a regular
// expression, spelling the prefix, the floor and the alphabet again so that the
// two are changed together, and the fuzz target beside it holds this scan to
// that expression.
var npmToken = NewPattern("npm-token", func(src string) []Span {
	var spans []Span

	for offset := 0; offset < len(src); {
		i := strings.Index(src[offset:], npmTokenPrefix)
		if i < 0 {
			break
		}
		start := offset + i

		// The scan resumes here whether this candidate became a token or not,
		// for the reason the rationale above gives: a body may close with the
		// three letters the prefix opens with, so a token can begin three
		// characters before the end of the one before it.
		offset = start + 1

		body := start + len(npmTokenPrefix)
		if end := base62RunEnd(src, body); end-body >= npmTokenBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
})

const (
	// npmTokenPrefix is what every token npm issues in this format opens with,
	// and what the scan searches the input for. Its first three characters
	// belong to the alphabet a body is written in, which is what lets one token
	// begin inside another and is why the scan resumes a byte along; the
	// underscore closing it does not, which is what keeps two candidates from
	// ever reading the same run. Test_npmTokenPrefix holds it to the first and
	// Test_npmTokenPrefix_runsDoNotOverlap to the second.
	npmTokenPrefix = "npm_"

	// npmTokenBodyChars is the count a body is held to, read as a floor rather
	// than exactly. Thirty-six is thirty random characters — the hundred and
	// seventy-eight bits npm states, in an alphabet of sixty-two — and the six
	// of checksum behind them, and it is what both rulesets state. The
	// rationale above weighs reading it as a floor.
	npmTokenBodyChars = 36
)
