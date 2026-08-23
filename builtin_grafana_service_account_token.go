package mask

import "strings"

// GrafanaServiceAccountToken locates Grafana service account tokens: the prefix
// glsa_, the thirty-two characters of the secret, an underscore, and the eight
// hexadecimal digits of the checksum behind it — forty-six characters
// altogether. One string serves every service account Grafana issues a token
// for, whatever role it carries and whichever stack it belongs to, so nothing
// in a token says what it is allowed to do.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly forty-six characters of it are. So text of that shape is redacted
// whether or not Grafana issued it. A space, a hyphen where the underscore
// belongs, or a secret of the wrong length ends the reading, so text as it is
// ordinarily written is not affected.
//
// Its name is "grafana-service-account-token".
func GrafanaServiceAccountToken() Pattern { return grafanaServiceAccountToken }

// What Grafana states about this format it states in the code that writes it,
// which no other pattern here can say of its own. Grafana is published under
// AGPL and the generator is pkg/components/satokengen: a prefixed key is the
// two letters gl, a service identifier, an underscore, a secret and an
// underscore and a checksum, the secret is util.GetRandomString(32) and the
// checksum is the CRC32 of everything in front of it, four bytes little-endian,
// written out by encoding/hex. The service identifier a service account token
// carries is the constant "sa". So the prefix, the alphabet, both counts and
// the separator between them are read off the thing that produces them rather
// than off the values it produced, which is what the Slack, GitLab, Google,
// OpenAI, Anthropic, Stripe, PyPI, npm, Sentry, Linear and Notion patterns each
// had to do without.
//
// The documentation agrees and is the second source rather than the first. The
// service account pages print glsa_iNValIdinValiDinvalidinvalidinva_5b582697,
// which is forty-six characters divided the way the generator divides them —
// and whose eight digits are the CRC32 of the thirty-seven characters in front
// of them, so the example is a whole token in every respect but having been
// issued.
//
// The rulesets agree too, and where they differ they are looser rather than
// tighter. gitleaks reads glsa_ and thirty-two alphanumerics, an underscore and
// eight hexadecimal digits of either case; kingfisher reads the same, spelled
// with POSIX classes. trufflehog reads glsa_ and forty-one characters of the
// alphanumerics and the underscore, which is the same total with the division
// inside it left unsaid. No published rule asks for more than the generator
// writes.
//
// Both of the first two match the prefix case-insensitively as well, and this
// scan does not, which is worth setting beside the checksum below because the
// two go opposite ways. The prefix is a literal Grafana declares in two
// constants, gl and sa, and it is the whole of what tells this format from
// text — loosening it buys nothing and costs over-matching, which is what it
// costs gitleaks under its neighbouring rule, where the case-insensitive glc_
// draws in the GLC_ that opens a C function name and the rule ships those as
// known false positives. The checksum's class stands behind a match the prefix
// and the secret have already decided, so widening it draws in nothing further.
//
// The counts are therefore read exactly, which is where this scan stands with
// the AWS, GitLab, Google, SendGrid, Sentry and Notion ones rather than with
// the OpenAI, Anthropic, Stripe, PyPI, npm and Linear ones. Those six decline
// an exact count because their vendor states no length and a count that is
// wrong there costs the whole credential. Here the length is not an observation
// at all: thirty-two is the argument the generator passes and eight is what
// four bytes of hexadecimal come to, so the wager is smaller than the one AWS
// and Google are read with and smaller than the one SendGrid is, since even
// that number was written in prose rather than in code. What an exact count
// costs is what it costs everywhere: a run longer than the count is not one
// longer token but a token with something written after it, and only the token
// is redacted.
//
// The secret's alphabet is base62, isBase62Byte in builtin_scan.go: the letters
// of both cases and the digits. It is the alphanum constant GetRandomString
// draws from, character for character, and it admits neither the hyphen nor the
// underscore base64url adds. The underscore's absence is load-bearing twice
// over — it is what ends the secret where the checksum's separator stands, and
// it is what keeps a digest from ever being read as one.
//
// The checksum is read as hexadecimal of either case, where the generator
// writes it in lowercase alone. Reading lowercase alone would be tighter than
// every published rule on the strength of one call to encoding/hex, and it
// would buy nothing: the eight characters stand behind a prefix and a
// thirty-two character secret that have already decided the match, so no text
// is admitted by the wider class that the narrower one would have turned away
// in practice. What it would cost is the case where that one line changed —
// a checksum upper-cased, or encoded by something else — where a scan asking
// for lowercase locates nothing at all and every character of a live token
// stays in the output. That asymmetry is the one the OpenAI, Anthropic, PyPI,
// npm, Linear and Notion scans read their counts loosely for, and it is bought
// here for one character class rather than for a count.
//
// The checksum is read as a shape and not verified, though Grafana's own Decode
// verifies it and this scan could: the CRC32 is over the prefix and the secret,
// both of which a span already covers. It is declined for what verifying would
// throw away. A token whose secret is intact and whose checksum was mistyped,
// truncated in transit or rewritten by an example generator is still a secret
// somebody can read, and a scan verifying the checksum would leave every one of
// them in the output — including the tokens this package's own tests are
// written with, which are built from an ordered run so that they are obviously
// not real. Against that, what verification buys is the last part of an
// over-match that is already close to unreachable: what has to be written for
// this pattern to fire is set out below, and it is not text anybody writes.
// Test_GrafanaServiceAccountToken_checksumIsNotVerified pins the decision.
//
// The underscore between the secret and the checksum is the one character of
// the format that is not in the secret's alphabet, and it is doing two things.
// It is what tells this format from a run of forty-one alphanumerics, which
// would be a far weaker anchor; and it is the character the prefix itself
// closes with, so a token carries the character its own prefix ends on
// thirty-three characters further in. That second fact is why a token can begin
// inside another, which the resumption below is about.
//
// There is no boundary on either side of a match, as there is none in any of
// the scans beside this one but the Slack and Stripe ones. A word boundary in
// front would drop the whole match rather than trim it wherever a token is
// written against a word character, as GRAFANA_TOKEN_glsa_... is, and one
// behind it would drop a token followed by a character of the token's own
// alphabet. What may stand either side is held back by the character classes
// and the two counts alone.
//
// The tightening on offer in front is the one the Slack and Stripe scans take:
// to ask that no letter and no digit stand before the prefix. It is declined
// for the AWS scan's reason and with less to weigh than any of them, since
// there is nothing here for it to buy. Unlike SG., which closes MSG. and ESG.,
// and unlike lin_api_, which closes berlin_api_, no word is spelled with glsa
// at the end of it, so the shape the demand would turn away is one no ruleset
// has shipped a false positive of. What it would cost is a token written
// straight against a letter, which would then be left in the output whole
// rather than trimmed.
//
// The scan resumes one byte past the start of a candidate whether it became a
// token or not. The four letters of the prefix belong to the alphabet a secret
// is written in and the underscore behind them is the separator a token already
// carries, so a secret whose last four characters are glsa opens a candidate
// four characters before that secret ends and thirteen before the token does:
// the underscore that candidate reads as the end of its prefix is the one
// dividing the first token's secret from its checksum, and the secret it then
// reads is that checksum and the twenty-four characters written after the
// token, with an underscore and eight more behind them. Consuming a match would
// step over that token and leave it in the output whole. The two spans then
// overlap, which a Masker resolves into one.
//
// The scan keeps no cursor and needs none, as the AWS, Google, SendGrid and
// Notion scans do not and for their reason: a candidate reads at most forty-six
// bytes and stops, which is the guarantee the JWT, GitHub, GitLab, Slack,
// OpenAI, Anthropic and PyPI scans buy with a run cursor, bought here by the
// counts being counts.
//
// What this pattern over-matches on: forty-six characters of the right shape
// that nobody issued, and there is little here to reach it by. Four letters
// spelling no word have to be written,
// then an underscore, then exactly thirty-two letters and digits, then a second
// underscore, then exactly eight hexadecimal digits. Standard base64 writes no
// underscore at all, so a certificate, a PEM body or an embedded image carries
// no candidate at however long it runs; a base64url encoding can hold one, and
// there five characters of an alphabet of sixty-four stand where the prefix
// stands about once in a thousand million characters, with the second
// underscore having then to fall exactly thirty-two characters later and eight
// hexadecimal digits to follow it. Outside an encoding what is left is a
// snake_case name whose segment is spelled glsa, which is a name nobody has
// written.
//
// The collision the npm, Linear and Notion prefixes leave is a digest written
// behind one, and this format rules it out rather than paying for it. A digest
// carries no underscore, so glsa_ and the sixty-four characters of a SHA-256
// hold nothing at the thirty-third character but more of the digest, and the
// candidate is turned away by one comparison; a SHA-1 and an MD5 written behind
// the prefix are turned away by that comparison too wherever anything follows
// them, and by the length where nothing does — forty-five characters and
// thirty-seven where a token is forty-six. Where those three scans read a
// digest as a body and say so, this one cannot, and
// Test_GrafanaServiceAccountToken_aDigestBehindThePrefix pins it.
//
// What reaches a span is never prose, never a git SHA and never an MD5. A token
// holds an underscore at its fifth character and at its thirty-eighth and
// nowhere else, and holds no space.
//
// The other credentials Grafana issues are not read, and each is declined for a
// reason of its own.
//
// A Grafana Cloud access policy token opens with glc_ and everything behind it
// is base64 of a JSON object naming the policy, the region and the key. Nothing
// published states its length, and it cannot have one: the object carries the
// token's name, so the encoding is as long as whoever created the token made
// it. The three rulesets reading it read three different ranges — thirty-two to
// four hundred, sixty to a hundred and sixty behind a required eyJ, and forty
// to a hundred and fifty — which is the slack of a shape nobody has measured,
// and two of the three ask for nothing but base64 behind the prefix. A floor
// invented here would be a guess at exactly the part of the grammar that is
// load-bearing, and the alphabet the guess would be read in holds the slash and
// the plus, so a span reaching to the end of a run would take a URL path with
// it. Test_GrafanaServiceAccountToken_theCloudPrefix pins the decision, so that
// reading glc_ is a change somebody argues for rather than one somebody notices
// afterwards.
//
// The API key that service accounts replaced is not read either. It is the
// base64 of a JSON object holding the key, its name and an organization
// identifier, so it opens with eyJrIjoi and runs as long as the name inside it
// — a shape with no prefix of its own outside that eight character opening, no
// stated length, and a body in the same alphabet a JWT's header is written in.
// Grafana's documentation states the format deprecated and replaced by service
// accounts, the keys migrated to service account tokens, and no route serving
// it is left in the source.
//
// The generic form the generator writes is not read beyond glsa_ for a reason
// worth stating, because it is the one place this pattern is narrower than the
// vendor's code. satokengen writes gl and whatever service identifier it is
// handed, and Grafana hands it the slug of an external service account as
// readily as the constant "sa", so tokens with other identifiers exist and are
// the same shape behind their prefix. Reading them would mean anchoring on gl
// and an underscore somewhere in the next few characters, which is two letters
// of anchor where this pattern has five, and the identifiers themselves are not
// enumerable — a slug is whatever the service was named. What is read is the
// one identifier Grafana publishes as a constant.
//
// referenceGrafanaServiceAccountToken in
// builtin_grafana_service_account_token_test.go keeps the grammar as a regular
// expression, spelling the prefix, both counts, the separator and both
// character classes again so that the two are changed together, and the fuzz
// target beside it holds this scan to that expression.
var grafanaServiceAccountToken = NewPattern("grafana-service-account-token", func(src string) []Span {
	var spans []Span

	for offset := 0; offset < len(src); {
		i := strings.Index(src[offset:], grafanaServiceAccountTokenPrefix)
		if i < 0 {
			break
		}
		start := offset + i

		// The scan resumes here whether this candidate became a token or not,
		// for the reason the rationale above gives: the prefix is four
		// characters a secret is written with and the separator a token already
		// carries, so a token can begin four characters before the end of the
		// secret of the one before it.
		offset = start + 1

		body := start + len(grafanaServiceAccountTokenPrefix)
		if end := start + grafanaServiceAccountTokenChars; end <= len(src) && isGrafanaServiceAccountTokenBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
})

const (
	// grafanaServiceAccountTokenPrefix is what every service account token
	// opens with, and what the scan searches the input for. It is the two
	// letters every Grafana prefixed key opens with, the service identifier
	// Grafana declares as a constant for a service account, and the underscore
	// the generator writes behind one — which is the same character the secret
	// is divided from the checksum by, and so is what lets one token be written
	// inside another and why the scan resumes a byte along.
	// Test_grafanaServiceAccountTokenPrefix holds it to closing with that
	// character and to carrying nothing but secret characters in front of it.
	grafanaServiceAccountTokenPrefix = "glsa_"

	// grafanaServiceAccountTokenSeparator divides the secret from the checksum.
	// It belongs to no secret, which is what ends a secret where it stands,
	// what makes the count either side of it readable at all, and what turns
	// away every digest written behind the prefix.
	grafanaServiceAccountTokenSeparator = '_'

	// The counts a token is written to. Thirty-two is the length the generator
	// asks util.GetRandomString for and eight is what the four bytes of a CRC32
	// come to in hexadecimal, so neither is read off an example.
	grafanaServiceAccountTokenSecretChars   = 32
	grafanaServiceAccountTokenChecksumChars = 8

	// grafanaServiceAccountTokenBodyChars is everything behind the prefix: the
	// secret, the separator and the checksum.
	grafanaServiceAccountTokenBodyChars = grafanaServiceAccountTokenSecretChars + 1 + grafanaServiceAccountTokenChecksumChars

	// grafanaServiceAccountTokenChars is the whole of a token, and the
	// forty-six characters the example in Grafana's own documentation is.
	// Test_grafanaServiceAccountTokenChars holds it to that number.
	grafanaServiceAccountTokenChars = len(grafanaServiceAccountTokenPrefix) + grafanaServiceAccountTokenBodyChars
)

// isGrafanaServiceAccountTokenBody reports whether s is everything behind the
// prefix of a token: exactly grafanaServiceAccountTokenSecretChars characters
// of the secret's alphabet, the separator, and exactly
// grafanaServiceAccountTokenChecksumChars hexadecimal digits.
//
// It is handed the counts as well as the characters so that they are checked in
// one place rather than left to the caller to have cut correctly. The separator
// is tested before either run is walked: a candidate that is not a token is
// usually not one at that character — every digest written behind the prefix is
// turned away there — and one comparison declines it where up to forty byte
// tests would.
func isGrafanaServiceAccountTokenBody(s string) bool {
	if len(s) != grafanaServiceAccountTokenBodyChars || s[grafanaServiceAccountTokenSecretChars] != grafanaServiceAccountTokenSeparator {
		return false
	}
	for i := range grafanaServiceAccountTokenSecretChars {
		if !isBase62Byte(s[i]) {
			return false
		}
	}
	for i := grafanaServiceAccountTokenSecretChars + 1; i < len(s); i++ {
		if !isGrafanaServiceAccountTokenChecksumByte(s[i]) {
			return false
		}
	}
	return true
}

// isGrafanaServiceAccountTokenChecksumByte reports whether c is a hexadecimal
// digit, which is what the checksum is written in.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go,
// which hold what more than one scan reads: this is the only scan here reading
// a hexadecimal run, and a shared test named for the class rather than for the
// checksum would invite the next pattern to read a digest with it.
//
// Either case is admitted where the generator writes lowercase alone, for the
// reason the rationale above gives.
func isGrafanaServiceAccountTokenChecksumByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'F' ||
		'a' <= c && c <= 'f'
}
