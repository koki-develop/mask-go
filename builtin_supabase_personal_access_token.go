package mask

import "strings"

// SupabasePersonalAccessToken locates Supabase personal access tokens: the
// prefix sbp_ and the forty lowercase hexadecimal digits behind it, forty-four
// characters altogether, and the token an OAuth application is issued in a
// user's name, which writes oauth_ between the two and so is fifty. One string
// serves the whole of the Management API and carries the privileges of the
// account that created it, so nothing in a token says what it is allowed to do.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly forty-four or fifty characters of it are. So text of that shape is
// redacted whether or not Supabase issued it. A letter past f, an uppercase one,
// or a run of the wrong length ends the reading, so text as it is ordinarily
// written is not affected.
//
// Its name is "supabase-personal-access-token".
func SupabasePersonalAccessToken() Pattern { return supabasePersonalAccessToken }

// What Supabase states about this format it states in the code that reads it.
// The CLI is published under MIT and validates a token before any Management API
// call, against one expression: ^sbp_(oauth_)?[a-f0-9]{40}$. It is written three
// times in that repository and in two languages — apps/cli/src/next/auth/token.ts,
// the legacy path beside it at apps/cli/src/legacy/auth/legacy-access-token.ts,
// and the Go CLI's apps/cli-go/internal/utils/access_token.go — character for
// character the same in all three, which is a stronger statement than one
// declaration would be: the expression has survived a rewrite of the tool around
// it. The unit tests beside the first name each half of it, a token of forty
// lowercase hexadecimal digits and one with oauth_ in front of them accepted,
// thirty-nine and forty-one rejected on both forms, uppercase rejected on both,
// a letter past f rejected, a token with no prefix rejected. So the prefix, the
// alphabet and the count are read off the vendor's own statement of what a token
// is rather than off the tokens it produced.
//
// It is a weaker source than Grafana's generator and a stronger one than an
// example, and it is worth being exact about which. What mints a token is the
// platform API, which is not published, so nothing here has seen a token
// written. What the CLI states instead is what it will accept: every token that
// reaches the Management API through Supabase's own tooling passes that
// expression, and a token that did not would be refused by the vendor before it
// was refused by this scan.
//
// The documentation is the second source and agrees. The Management API
// introduction prints sbp_bdd0 followed by thirty-two bullets and 4f23, which is
// four hexadecimal digits, a masked middle and four more — forty characters
// behind the prefix, divided the way the expression divides them. It states no
// alphabet and no length in prose, and what the CLI prints when it refuses a
// token — that it must be like sbp_0102...1920 — is the shape once more rather
// than a count.
//
// The rulesets agree on the prefix and differ on the alphabet, and where they
// differ they are looser. osv-scalibr reads sbp_ and forty characters of
// [a-f0-9], which is this grammar exactly; kingfisher reads the same class
// spelled as a POSIX one. trufflehog reads sbp_ and forty of [a-z0-9], and
// betterleaks sbp_ and forty of [a-z0-9_-] — both of which admit runs no token
// can be, and betterleaks needs a filter to hold back what its own alphabet lets
// in: the false positive it ships is the prefix and forty lowercase letters,
// which its expression matches and which an entropy floor and a demand for two
// digits then remove. The class read here declines that run by the grammar, on
// the strength of the vendor's own: g is not a hexadecimal digit.
//
// None of the four locates anything at all in the OAuth form, and each misses it
// differently. Three read alphabets the marker's underscore is not in, so the
// character after sbp_ ends the match before it starts. betterleaks admits the
// underscore and would run out six digits early — but every rule it generates
// closes on a quote, a space, a semicolon or the end of the input, and what
// stands six digits early is a hexadecimal digit, so the match is not trimmed
// but declined. What reading the form costs here is nothing: oauth_ is six more
// characters of literal in front of the same forty, so the anchor grows longer
// rather than the alphabet wider, and a token somebody's integration holds is
// redacted instead of being left whole.
//
// That form is read under this name rather than under one of its own for the
// same reason. It is the same credential behind the same prefix, validated by
// the same expression, stored under the same SUPABASE_ACCESS_TOKEN and sent in
// the same Authorization header; what differs is that an OAuth application was
// issued it in the user's name and that it carries the scopes the user approved
// rather than the whole of their account. Splitting it out would be a second
// pattern with a longer prefix and nothing else of its own, and declining it
// would leave a live Management API credential in the output for the sake of a
// word in a name.
//
// The alphabet is lowercase hexadecimal alone, where the Grafana checksum
// beside it is read in either case, and the two decisions are opposite on
// purpose. There the class stands behind a prefix and a thirty-two character
// secret that have already decided the match, so widening it admits no text the
// narrower class would have turned away. Here it is the whole of the body: a
// case admitted is a case admitted at each of forty positions, and the run it
// would draw in — the prefix and forty characters of a mixed-case digest, or of
// a hexadecimal dump written upper — is exactly the text this pattern has to
// stay out of. Against that, what reading lowercase alone risks elsewhere does
// not arise here, because the vendor is not silent about the case: its own
// validator refuses an uppercase token, with a test named for refusing one, so
// an uppercase run is not a token anything would accept.
//
// The count is read exactly, which is what a scan does wherever the vendor
// states the length. Where a vendor states none, a scan reads to the end of the
// run instead and declines an exact count, because a count that is wrong there
// costs the whole credential rather than the end of one; here forty is a count
// in the vendor's own expression with a test either side of it. What an exact
// count costs is what it costs everywhere: a run longer than forty is not one
// longer token but a token with something written after it, and only the token
// is redacted.
//
// There is no boundary on either side of a match, as there is none in any of the
// scans beside this one but the Slack and Stripe ones. A word boundary in front
// would drop the whole match rather than trim it wherever a token is written
// against a word character, as SUPABASE_TOKEN_sbp_... is, and one behind it
// would drop a token followed by a hexadecimal digit.
//
// The tightening on offer in front is the one the Slack and Stripe scans take:
// to ask that no letter and no digit stand before the prefix. It is declined for
// the AWS scan's reason and with as little to weigh as the Grafana scan had.
// Unlike SG., which closes MSG. and ESG., and unlike lin_api_, which closes
// berlin_api_, no word is spelled with sbp at the end of it, so the shape the
// demand would turn away is one no ruleset has shipped a false positive of. What
// it would cost is a token written straight against a letter, which would then
// be left in the output whole rather than trimmed.
//
// The scan resumes one byte past the start of a candidate whether it became a
// token or not, and unlike most of the scans here that is not because a token
// can begin inside the one before it. None can, and the reason is one
// character: the letter the prefix opens with stands in a token exactly once,
// at its first character. The prefix carries one, oauth_ carries none, and a
// body is written in hexadecimal digits, which carry none either — so the
// anchor cannot be found inside a span, and the spans this scan reports never
// overlap one another. That puts it with the Stripe and RubyGems scans and
// nowhere else, and
// Test_SupabasePersonalAccessToken_noTokenBeginsInsideAnother holds the claim.
//
// What the resumption is for is the candidate that failed. sbp_sbp_ opens one
// whose own prefix stands four characters in, and a scan stepping over what it
// declined would lose the token behind it. For a candidate that became a token
// the byte buys nothing and is advanced all the same, because a loop with one
// exit is what the rest of this package is written as and because the cost is a
// search over at most forty-nine bytes that finds nothing.
//
// The two readings of a candidate cannot both apply, which is what lets the scan
// take the marker wherever it stands rather than trying the shorter reading
// after the longer one failed: oauth_ opens with a character no body is written
// with, so a candidate carrying the marker has a letter where the shorter
// reading needs a digit. Test_supabasePersonalAccessTokenOAuthMarker holds it.
//
// The scan keeps no cursor and needs none, as the AWS, Google, SendGrid, Notion
// and Grafana scans do not and for their reason: a candidate reads at most fifty
// bytes and stops, which is the guarantee the JWT, GitHub, GitLab, Slack,
// OpenAI, Anthropic and PyPI scans buy with a run cursor, bought here by the
// count being a count.
//
// What this pattern over-matches on is a digest written behind the prefix, and
// this format pays for that collision where the Grafana one rules it out. There
// the character thirty-two past the prefix has to be the underscore dividing a
// secret from its checksum and no digest holds one; here there is nothing behind
// the prefix but the run, and forty lowercase hexadecimal digits are a SHA-1 as
// readily as a token — a git object name, a blob hash, a commit written into a
// build tag. Redacting one is right for the reason the count is read at all: the
// prefix and forty lowercase hexadecimal digits are the vendor's format exactly,
// there is nothing left in the text to tell the two apart, and declining the run
// would decline every token Supabase ever issued.
//
// What has to be written to reach it is a segment spelled sbp, an underscore,
// and then a digest of exactly that length. A SHA-256 behind the prefix is
// located too, as the first forty of its characters and twenty-four left over,
// which is the same trade every exact count here makes; an MD5 is not, being
// thirty-two where the pattern asks for forty. Outside a name, the alphabet is
// what holds this back: standard base64 writes no underscore at all, so a
// certificate, a PEM body or an embedded image carries no candidate at however
// long it runs, and a base64url encoding puts the four characters of the prefix
// at a position about once in sixteen million, with the forty behind them having
// then to fall in the sixteen characters of an alphabet of sixty-four.
// Test_SupabasePersonalAccessToken_aDigestBehindThePrefix pins all of it.
//
// What reaches a span is never prose and never a word. A token carries an
// underscore at its fourth character, and behind that underscore — or behind the
// tenth, where the marker stands — nothing but the digits and the first six
// letters for forty characters together, with no space anywhere in it.
//
// The other credentials Supabase issues are not read, and each is declined for a
// reason of its own.
//
// The project API keys that replaced the anon and service_role keys open with
// sb_publishable_ and sb_secret_, and nothing published states what stands
// behind either. The announcement and the documentation write them as
// sb_publishable_xxx and sb_secret_xxx, with no length and no alphabet, and the
// rules written against them are guesses at both. Three read sb_secret_ and put
// the count in two different places — exactly thirty-one in one, thirty-one to
// thirty-six in the other two — and two of the three need an entropy floor or a
// demand for upper and lower case behind the count to hold what its alphabet
// lets in, which is what a count nobody can check looks like. sb_publishable_
// has one rule of its own, reading twenty-four to forty, and one more count
// written into a filter for a generic rule rather than into a rule at all. A
// floor invented here would be a guess at exactly the part of the grammar that
// is load-bearing, in an alphabet holding the hyphen and the underscore, and
// the examples those rules are written from divide their thirty-one characters
// with an underscore that no published sentence says is there.
// Test_SupabasePersonalAccessToken_theOtherSupabaseCredentials pins the
// decision, so that reading sb_secret_ is a change somebody argues for rather
// than one somebody notices afterwards.
//
// The anon and service_role keys those replaced need nothing from this pattern.
// They are JWTs signed with the project's secret, carrying the role as a claim,
// and JWT in builtin_jwt.go locates them as what they are; a second pattern
// reading the same string would report a span the first already covers.
//
// referenceSupabasePersonalAccessToken in
// builtin_supabase_personal_access_token_test.go keeps the grammar as a regular
// expression, spelling the prefix, the marker, the count and the character class
// again so that the two are changed together, and the fuzz target beside it
// holds this scan to that expression.
var supabasePersonalAccessToken = NewPattern("supabase-personal-access-token", func(src string) []Span {
	var spans []Span

	for offset := 0; offset < len(src); {
		i := strings.Index(src[offset:], supabasePersonalAccessTokenPrefix)
		if i < 0 {
			break
		}
		start := offset + i

		// The scan resumes here whether this candidate became a token or not.
		// No token is written inside another, so for one that did the byte buys
		// nothing; for one that did not it is what keeps sbp_sbp_ from stepping
		// over the prefix standing four characters in.
		offset = start + 1

		secret := start + len(supabasePersonalAccessTokenPrefix)
		if strings.HasPrefix(src[secret:], supabasePersonalAccessTokenOAuthMarker) {
			secret += len(supabasePersonalAccessTokenOAuthMarker)
		}
		if end := secret + supabasePersonalAccessTokenSecretChars; end <= len(src) && isSupabasePersonalAccessTokenSecret(src[secret:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
})

const (
	// supabasePersonalAccessTokenPrefix is what every token opens with, and what
	// the scan searches the input for. Both forms carry it, so one search finds
	// either. Its first character is the one no body and no marker is written
	// with, which is what keeps a token from being written inside another, and
	// its last is an underscore, which is what keeps a body from beginning
	// anywhere but where a prefix ends.
	// Test_supabasePersonalAccessTokenPrefix holds it to both.
	supabasePersonalAccessTokenPrefix = "sbp_"

	// supabasePersonalAccessTokenOAuthMarker stands between the prefix and the
	// body of a token an OAuth application was issued in a user's name, and is
	// the optional group of the vendor's own expression. It opens with a
	// character no body is written with, so the two readings of a candidate
	// cannot both apply.
	// Test_supabasePersonalAccessTokenOAuthMarker holds it there.
	supabasePersonalAccessTokenOAuthMarker = "oauth_"

	// supabasePersonalAccessTokenSecretChars is what stands behind the prefix,
	// and the count the vendor's expression asks for on both forms.
	supabasePersonalAccessTokenSecretChars = 40

	// supabasePersonalAccessTokenChars is the whole of a personal access token,
	// and supabasePersonalAccessTokenOAuthChars the whole of the form carrying
	// the marker. Test_supabasePersonalAccessTokenChars holds them to those
	// numbers.
	supabasePersonalAccessTokenChars      = len(supabasePersonalAccessTokenPrefix) + supabasePersonalAccessTokenSecretChars
	supabasePersonalAccessTokenOAuthChars = supabasePersonalAccessTokenChars + len(supabasePersonalAccessTokenOAuthMarker)
)

// isSupabasePersonalAccessTokenSecret reports whether s is everything behind the
// prefix of a token: exactly supabasePersonalAccessTokenSecretChars characters
// of the alphabet a body is written in.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than left to the caller to have cut correctly.
func isSupabasePersonalAccessTokenSecret(s string) bool {
	if len(s) != supabasePersonalAccessTokenSecretChars {
		return false
	}
	for i := range len(s) {
		if !isSupabasePersonalAccessTokenSecretByte(s[i]) {
			return false
		}
	}
	return true
}

// isSupabasePersonalAccessTokenSecretByte reports whether c is a lowercase
// hexadecimal digit, which is what a body is written in.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go,
// which hold what more than one scan reads: the Grafana checksum is the only
// other hexadecimal run here and it is read in either case, so a shared test
// would have to be one of the two named for the class rather than for what reads
// it, and the next pattern would reach for whichever it found first.
//
// Uppercase is not admitted, where the Grafana checksum admits it, for the
// reason the rationale above gives: this class is the whole of a body rather
// than eight characters behind a decided match, and the vendor's own validator
// refuses an uppercase token.
func isSupabasePersonalAccessTokenSecretByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f'
}
