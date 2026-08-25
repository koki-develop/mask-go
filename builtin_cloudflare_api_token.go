package mask

import "strings"

// CloudflareAPIToken locates Cloudflare API tokens: the prefix cfut_ of a token
// a user owns or cfat_ of one an account owns, the forty characters of the
// secret behind it and the eight hexadecimal digits of the checksum behind
// that — fifty-three characters either way. One string serves every permission
// a token can be scoped to and every account and zone it can be scoped over, so
// nothing in a token says what it is allowed to do.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly fifty-three characters of it are. So text of that shape is
// redacted whether or not Cloudflare issued it. A space, a hyphen, an
// underscore behind the prefix, a letter past f in the last eight characters or
// a body of the wrong length ends the reading, so text as it is ordinarily
// written is not affected.
//
// Its name is "cloudflare-api-token".
func CloudflareAPIToken() Pattern { return cloudflareAPIToken }

// What Cloudflare states about this format it states in order to be scanned
// for, which is the firmest a vendor page can be short of publishing the
// generator. Three pages say it and they say the same thing. The page on token
// formats writes each credential as a prefix, forty characters and a checksum,
// and gives the prefixes as a table: cfk_ for the API key a user holds, cfut_
// for the API token a user owns, cfat_ for the API token an account owns. The
// changelog adding these to Cloudflare's own data loss prevention says what the
// checksum is — a structured prefix and a CRC32 checksum suffix — and says why
// the shape is worth stating at all: the prefix is meant to be detected with no
// surrounding context, no bearer header and no assignment in front of it. The
// Credentials and Secrets table on the page listing Cloudflare's predefined DLP
// profiles then divides the body, and it is the one page that does: each of the
// three rows reads its prefix followed by forty alphanumeric characters and an
// eight character hex checksum. That table is worth naming exactly, because the
// neighbouring page listing the detection entries by name carries the same three
// credentials with a one-line description apiece and no counts at all — a reader
// checking this rationale against that page would find the counts nowhere and
// conclude they were invented. So the prefix, both counts and both character
// classes are read off what the vendor publishes about its own format, and none
// of the four is read off a value somebody was shown.
//
// The two prefixes read here are the two Cloudflare calls tokens. The third,
// cfk_, is the Global API Key, which Cloudflare names a key rather than a token
// throughout, documents on pages of its own and describes as the credential a
// token is to be preferred over. It is read by CloudflareAPIKey
// (builtin_cloudflare_api_key.go) rather than by a third entry in the table
// below, because this pattern is named for what Cloudflare calls an API token
// and reading cfk_ here would leave the name covering less than the scan
// locates. What the two do share is everything behind the prefix, which is why
// the counts and the character classes below are named for the vendor rather
// than for either credential.
//
// The tokens issued before the format changed are not read, and cannot be. A
// token then was forty characters with nothing in front of them — no prefix, no
// checksum, no structure of any kind — and the alphabet is the least of what is
// missing. A scan anchored on nothing but a count of forty draws in a digest, a
// base64url fragment, a path segment and a word of prose alike, whichever
// alphabet it is read in, and it is the one thing a pattern in this package may
// not be. Nothing was revoked when the format changed, so such tokens are live
// and are left in the output whole; Cloudflare's own profile row declines them
// in the same words, saying only credentials generated after the format update
// are matched. The prefix is the whole of what makes this format readable.
//
// The counts are therefore read exactly, both of them. A scan declines an exact
// count where its vendor states no length, since the count is then read off the
// values somebody happened to be shown and being wrong about it costs the whole
// credential rather than the end of one. Here the vendor states both: forty is
// written on the format page and again in the profile row, and eight is what
// that row writes and what four bytes of a CRC32 come to in hexadecimal, which
// is the encoding the changelog names. What an exact count costs is what it
// costs everywhere: a run longer than the count is not one longer token but a
// token with something written after it, and only the token is redacted.
//
// The secret's alphabet is base62, isBase62Byte in builtin_scan.go: the letters
// of both cases and the digits. It is what alphanumeric means in the profile
// row, and it admits neither the hyphen nor the underscore base64url adds. What
// the underscore's absence does here is turn away a candidate whose body opens
// with a prefix of its own: the fifth character of such a body is the underscore
// that inner prefix closes with, and no secret is written with one.
//
// The checksum is read as hexadecimal of either case, where a CRC32 written out
// by an encoder is lowercase and every value published is. Reading lowercase
// alone would be tighter than the vendor's own wording, which says hexadecimal
// and not lowercase hexadecimal, and it would buy little: the eight characters
// stand behind a prefix and a forty character secret that have already decided
// the match. What it would cost is the case where the encoding changed — a
// checksum upper-cased, or written by something else — where a scan asking for
// lowercase locates nothing at all and every character of a live token stays in
// the output. That asymmetry, a reading too narrow costing the whole credential
// where one too wide costs a tail, is the Grafana checksum's argument and is
// bought here at the same price.
//
// The checksum is read as a shape and not verified, though the profile row says
// Cloudflare validates it algorithmically and this scan has what a check would
// need: a checksum written as a suffix is computed from what stands in front of
// it, which a span already covers. It is declined for what
// verifying would throw away. A token whose secret is intact and whose checksum
// was mistyped, truncated in transit or rewritten by an example generator is
// still a secret somebody can read, and a scan verifying the checksum would
// leave every one of them in the output — including the tokens this package's
// own tests are written with, which are built from an ordered run so that they
// are obviously not real. Against that, what verification buys is the last part
// of an over-match that is already close to unreachable: what has to be written
// for this pattern to fire is set out below, and it is not text anybody writes.
// Test_CloudflareAPIToken_checksumIsNotVerified pins the decision.
//
// What the scan searches the input for is the underscore each prefix closes
// with, and the prefix is read back from it. One search over the text serves
// both prefixes where a search for each would be two, and either the opening or
// the closing character could carry it: what settles the choice is how often
// each is written in the text this library is pointed at, for the reason
// builtin_scan.go gives. Over the log line these benchmarks are written on the
// c stands four times — the word calling, this vendor's own name, the client
// path, the com — and the underscore not once. On the line of nothing but cf
// this pattern's own worst case is written from, the c stands at every other
// byte and the underscore nowhere at all.
//
// What the underscore costs is a candidate opened at every environment
// variable, snake_case name and log field, none of which is written with cf.
// Each of those is turned away by the four characters read back, which is one
// comparison; against it stands a stop at every c in the text. The underscore
// is ahead on the ordinary line and far ahead on every crowded one.
//
// Reading backwards asks two things of the table in return. It asks that every
// prefix close on the anchor and carry it nowhere else, so that a candidate is
// read back from the right place, and that all of them be the same length, so
// that one index serves the table. Test_cloudflareAPITokenAnchor holds both:
// a prefix closing on something other than the anchor, or standing a different
// width, is a prefix no candidate is ever found at.
//
// There is no boundary on either side of a match. A word boundary in front
// would drop the whole match rather than trim it wherever a token is written
// against a word character, as CLOUDFLARE_API_TOKEN_cfut_... is, and one behind
// it would drop a token followed by a character of the token's own alphabet.
// What may stand either side is held back by the character classes and the two
// counts alone.
//
// The tightening on offer in front is the one the Slack and Stripe scans take:
// to ask that no letter and no digit stand before the prefix. It is declined
// for the AWS scan's reason, and what it would turn away here is narrow enough
// to name. No word is spelled cfut or cfat, so what could reach a prefix is a
// snake_case name whose last segment is one of those two — and that test admits
// the underscore, so such a name would pass it unchanged and the tightening
// would not turn it away either. What it would cost is a token written straight
// against a letter, which would then be left in the output whole rather than
// trimmed.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a token or not, and here advancing rather than consuming the
// match is load-bearing rather than a habit. A token can be written inside
// another, and how far in is settled by the prefix in two steps rather than
// chosen. Every prefix closes with an underscore and no body is written with
// one, so that underscore has to fall past the first token's last character:
// the overlap is at most the four characters in front of it, and all four land
// in the eight character checksum. Standing in a checksum they then have to be
// hexadecimal, which stops cfut_ at cf and cfat_ at cfa — two characters and
// three. Whatever of the prefix is left over is written straight after the
// token, t_ behind a cfa and ut_ or at_ behind a cf, and forty-eight characters
// behind that complete the second token; a position shallower than a prefix's
// deepest works the same way with more of the prefix falling outside.
// Consuming the first match would step over the second and leave it in the
// output whole. The two spans then overlap, which a Masker resolves into one,
// and Test_CloudflareAPIToken_aTokenBeginningInsideAnother drives each prefix
// at its deepest.
//
// The scan keeps no cursor and needs none: a candidate reads at most fifty-three
// bytes and stops, which bounds what it reads with no state to be wrong about —
// the guarantee a scan reading a body to the end of its run has to buy with a
// run cursor instead, bought here by the counts being counts.
//
// What this pattern over-matches on: fifty-three characters of the right shape
// that nobody issued. Five characters have to be written, spelling no word and
// closing on an underscore, then exactly forty letters and digits, then exactly
// eight hexadecimal digits, with nothing between any of them. Standard base64
// writes no underscore at all, so a certificate, a PEM body or an embedded
// image carries no candidate at however long it runs; a base64url encoding can
// hold one, and there five characters of an alphabet of sixty-four stand where
// a prefix stands about once in five hundred million characters, with
// forty-eight more having then to carry neither character base64url adds and
// the last eight of them to be hexadecimal. Outside an encoding what is left is
// a snake_case name whose segment is spelled cfut or cfat, which is a name
// nobody has written, followed by forty-eight unbroken letters and digits.
//
// The collision a prefix leaves where everything behind it is one class is a
// digest written there, and this format pays it rather than ruling it out.
// Hexadecimal digits are letters and digits, and the last eight characters of a
// digest are hexadecimal because all of it is, so cfut_ and the first
// forty-eight characters of a SHA-256 are a token to this scan and the sixteen
// left over stay in the text. It is paid because there is nothing left to tell
// the two apart at that point: the vendor's own format is a prefix and
// forty-eight characters whose last eight are hexadecimal, so a scan declining
// a digest behind this prefix declines the tokens whose secret happens to be
// written in the same sixteen characters. A SHA-1 is forty characters and an
// MD5 thirty-two, so neither reaches the count and both are left alone.
// Test_CloudflareAPIToken_aDigestBehindThePrefix pins all three.
//
// What reaches a span is never prose, never a git SHA and never an MD5. A token
// holds an underscore at its fifth character and nowhere else, and holds no
// space.
//
// Two Cloudflare formats stand close enough to this one to say where the line
// falls. An Origin CA key opens with v1.0- and carries hyphenated hexadecimal
// runs behind it, which this scan's prefix has nothing to do with. A zone or
// account identifier is thirty-two hexadecimal characters with no prefix at
// all — an MD5's shape exactly, published in dashboards and URLs by design, and
// not a secret. The Global API Key is covered above.
//
// referenceCloudflareAPIToken in builtin_cloudflare_api_token_test.go keeps the
// grammar as a regular expression, spelling both prefixes, both counts and both
// character classes again so that the two are changed together, and the fuzz
// target beside it holds this scan to that expression.
var cloudflareAPIToken = NewPattern("cloudflare-api-token", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := cloudflareAPITokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], cloudflareAPITokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not, for
		// the reason the rationale above gives: a checksum is hexadecimal, so it
		// carries the opening of a prefix and a token can begin as far as three
		// characters before the one in front of it ends. Stepping one byte past the
		// anchor is what leaves the next candidate one byte past this one, which
		// builtin_scan.go sets out.
		offset = anchor + 1

		if anchor < cloudflareAPITokenAnchorIndex {
			continue
		}
		start := anchor - cloudflareAPITokenAnchorIndex

		// The byte every prefix opens with is tested before the table is
		// walked. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where
		// the table is two comparisons.
		if src[start] != cloudflareAPITokenOpening[0] {
			continue
		}
		prefix := cloudflareAPITokenPrefixAt(src, start)
		if prefix == 0 {
			continue
		}

		body := start + prefix
		end := body + cloudflareCredentialBodyChars
		if end > len(src) {
			// The input ends inside the body, so the checksum that tells this
			// candidate from a hexadecimal word is not here yet.
			retain = min(retain, start)
			continue
		}
		if isCloudflareCredentialBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// cloudflareAPITokenPrefixes are the prefixes this pattern reads: the token a
// user owns and the token an account owns, which are the two credentials
// Cloudflare calls API tokens.
//
// Test_cloudflareAPITokenPrefixes holds them to what the scan needs of them:
// that every one opens with the two characters a candidate is read back to,
// without which a prefix is one the scan never reaches; that no one of them
// opens another, so at most one matches at any position and the order they are
// written in decides nothing; and that each leaves a fifty-three character
// token with the body behind it.
var cloudflareAPITokenPrefixes = [...]string{
	"cfut_", // owned by a user
	"cfat_", // owned by an account
}

const (
	// cloudflareAPITokenOpening is what every prefix begins with. Two characters
	// are what the two prefixes share at their start, and the rationale above
	// says why the search is anchored on the underscore each closes with rather
	// than on these.
	cloudflareAPITokenOpening = "cf"

	// cloudflareAPITokenAnchor is the byte the scan searches the input for and
	// cloudflareAPITokenAnchorIndex is where it stands in both prefixes, so a
	// candidate begins that many bytes in front of what a search reported. Both
	// prefixes are five characters, which the fifty-three a token comes to with
	// the body behind it fixes and Test_cloudflareAPITokenPrefixes holds them
	// to, so one index serves the whole table.
	cloudflareAPITokenAnchor      = '_'
	cloudflareAPITokenAnchorIndex = 4

	// The counts a Cloudflare credential is written to, both of them stated by
	// Cloudflare rather than read off a value: forty characters of secret, and
	// the eight hexadecimal digits four bytes of a CRC32 come to. They carry
	// the vendor's name rather than this pattern's because the format page
	// states them once over every credential it lists, so the key scan reads
	// them here rather than spelling a second pair that could come to disagree.
	cloudflareCredentialSecretChars   = 40
	cloudflareCredentialChecksumChars = 8

	// cloudflareCredentialBodyChars is everything behind the prefix: the secret
	// and the checksum, with nothing between them. It is what the format page
	// holds constant across the three credentials it lists, where the prefix in
	// front of it is four characters for one of them and five for the other
	// two, so the scan reads the body from wherever the prefix it matched ends
	// rather than cutting a token to one width. The key scan reads it from the
	// other side of that same sentence.
	//
	// That is the scan alone. A prefix of another length is still a change
	// somebody has to make deliberately, because the sentence on
	// CloudflareAPIToken promises fifty-three characters either way and every
	// span written in the tests is that wide: Test_cloudflareAPITokenPrefixes
	// fails for such a prefix on purpose, and what it is asking for is that the
	// documentation be brought along rather than that the scan be rewritten.
	cloudflareCredentialBodyChars = cloudflareCredentialSecretChars + cloudflareCredentialChecksumChars
)

// cloudflareAPITokenPrefixAt returns the length of the prefix standing at i in
// src, or zero where none does.
//
// It returns the first entry of the table that matches, which is the whole of
// it because no entry opens another — the property
// Test_cloudflareAPITokenPrefixes holds the table to, and without which the
// answer here would depend on the order the entries happen to be written in.
//
// The bound is left to strings.HasPrefix, which reports false for a prefix
// longer than what is left of the input — the ordinary case near the end of a
// candidate found in the last few bytes of a line.
func cloudflareAPITokenPrefixAt(src string, i int) int {
	for _, prefix := range cloudflareAPITokenPrefixes {
		if strings.HasPrefix(src[i:], prefix) {
			return len(prefix)
		}
	}
	return 0
}

// isCloudflareCredentialBody reports whether s is everything behind the prefix
// of a Cloudflare credential: exactly cloudflareCredentialSecretChars
// characters of the secret's alphabet, and exactly
// cloudflareCredentialChecksumChars hexadecimal digits behind them.
//
// It is named for the vendor rather than for the token because the scan in
// builtin_cloudflare_api_key.go reads it too. The body is the half of the
// format neither credential can change alone, and a second copy of it beside
// the key's prefix is a copy that could come to disagree with this one while
// both scans went on passing.
//
// It is handed the counts as well as the characters so that they are checked in
// one place rather than left to the caller to have cut correctly. The secret is
// walked before the checksum because that is where a candidate that is not a
// credential usually stops: the character straight behind a prefix is the one
// most text written this way fails on, and reaching the checksum at all means
// forty letters and digits have already been read.
func isCloudflareCredentialBody(s string) bool {
	if len(s) != cloudflareCredentialBodyChars {
		return false
	}
	for i := range cloudflareCredentialSecretChars {
		if !isBase62Byte(s[i]) {
			return false
		}
	}
	for i := cloudflareCredentialSecretChars; i < len(s); i++ {
		if !isCloudflareCredentialChecksumByte(s[i]) {
			return false
		}
	}
	return true
}

// isCloudflareCredentialChecksumByte reports whether c is a hexadecimal digit,
// which is what the checksum is written in.
//
// Two scans read it and it stays here anyway, where the byte tests in
// builtin_scan.go are what any scan may reach for. The two are the halves of
// one vendor's format and widen together or not at all. Between formats,
// hexadecimal is not one class several are defined over but a coincidence of
// the same sixteen characters: a test named for the class rather than for what
// reads it would make widening one format a change to all of them, which is a
// change nothing would report. Named for the vendor it is one declaration
// exactly where it is one decision.
//
// Either case is admitted where an encoder writes lowercase alone, for the
// reason the rationale above gives.
func isCloudflareCredentialChecksumByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'F' ||
		'a' <= c && c <= 'f'
}

// cloudflareAPITokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var cloudflareAPITokenTail = newPrefixTail(cloudflareAPITokenPrefixes[:]...)
