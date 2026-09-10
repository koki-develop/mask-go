package mask

import "strings"

// PolarOrganizationAccessToken locates Polar organization access tokens: the
// prefix polar_oat_ and forty-three letters and digits behind it — fifty-three
// characters altogether.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly fifty-three characters of it are. So text of that shape is
// redacted whether or not Polar issued it. A space, a hyphen, an underscore, a
// character outside the alphabet or an uppercase prefix ends the reading, so
// text as it is ordinarily written is not affected. A longer run of letters and
// digits is a token with something written after it, and the token alone is
// redacted.
//
// Its name is "polar-organization-access-token".
func PolarOrganizationAccessToken() Pattern { return polarOrganizationAccessToken }

// Organization access token is Polar's own term for the whole of what this
// locates. The documentation page one is created from is titled "Organization
// Access Tokens", and the authentication section of the API reference names the
// kind that way in the table dividing it from the customer access token a
// browser is handed.
//
// Polar states the prefix twice over. The service that mints one declares
// TOKEN_PREFIX as polar_oat_, and the API reference writes the header a request
// carries as Authorization: Bearer polar_oat_ and a row of x characters. The
// second states no length: seventeen x stand where a body is forty-three, so
// the row elides rather than masks byte for byte and corroborates nothing but
// the prefix.
//
// The count and the alphabet come from the generator itself, which Polar
// publishes. It draws thirty-seven characters from the ASCII letters and the
// digits, takes a CRC32 over them, renders that in base62 and pads it to six
// characters, and writes the three pieces one after another. So a body is
// forty-three characters and every one of them a letter or a digit — the
// vendor's own format rather than a width read off the values somebody
// collected.
//
// betterleaks is the one published ruleset carrying this format, and it reads
// the prefix and twenty to a hundred characters of the letters, the digits, the
// hyphen and the underscore. It corroborates the prefix and nothing else here:
// its body is wider than the generator's on both the count and the alphabet,
// and a rule written wider than a format the vendor publishes is a rule with
// less under it than the format.
//
// The count is read exactly rather than as a floor. Every token is minted at
// the one width, so a run of the alphabet longer than the count is not one
// longer token but a token with something written after it, and a floor would
// swallow what the run went on to hold — text belonging to no credential.
//
// The checksum is read as a width and not verified, though six of the
// forty-three are one and the generator says how it is computed. A token whose
// last six characters do not check is a token all the same: one mistyped into a
// ticket, cut short and pasted back together, or rewritten by an editor that
// normalised what it took for a word. Each of those is a credential a caller
// wants out of the log, and a scan verifying the CRC32 would leave every one of
// them in the output. That is the reading builtin_cloudflare_api_token.go takes
// on a checksum its vendor publishes as well.
// Test_PolarOrganizationAccessToken_theChecksumIsNotVerified pins it.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the digits, and neither the hyphen nor the underscore base64url
// adds. The generator writes the checksum in the same sixty-two characters as
// the secret, so the scan reads the forty-three as one class rather than as
// two.
//
// The prefix is read in the one case Polar writes it. It is the whole of what
// tells this format from a run of letters and digits, so reading it without
// regard to case buys nothing — POLAR_OAT_ is no form a token is issued in —
// and would redact the name an environment variable is kept under.
//
// There is no boundary on either side of a match. One in front would drop the
// whole match rather than trim it wherever a token is written against a word
// character, and POLAR_ACCESS_TOKEN=polar_oat_... is not how a token reaches a
// log line — POLAR_ACCESS_TOKEN_polar_oat_... is, and a shell writes it.
// Test_PolarOrganizationAccessToken_nextToWordCharacters pins the shape that
// pays for it. Behind the match a boundary would drop rather than trim as well:
// a token written against a forty-fourth character of the alphabet would be
// located nowhere, where this scan redacts the fifty-three Polar issued and
// leaves the character that belongs to no credential in the text.
//
// The byte the scan searches the input for is the underscore the prefix closes
// with, and the prefix is read back from it. builtin_scan.go says why a scan
// searches for one byte of its prefix rather than for the prefix itself; what
// makes it this byte is that no body is written with it. The eight letters the
// prefix carries besides are all characters a body may hold, so a scan anchored
// on any of them stops once every sixty-two characters of an opaque run — a
// base64url payload, a digest, a base62 identifier — and reads a candidate back
// at each stop. The underscore stops at none of them. It is the rarest of the
// seven characters the prefix is written with in prose besides: over the line
// these benchmarks are written on its letters stand between three and seven
// times apiece, where the underscore stands once.
//
// The prefix carries two underscores, so the search stops twice at every one of
// them, and the first stop reads a candidate back from four characters in front
// of where the prefix began. Such a candidate is never a prefix itself: it would
// need an r where the prefix it was found in has its p. So it is turned away by
// a comparison rather than by a walk, and that is the whole of what the second
// underscore costs.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a token or not, which is the default and needs no argument.
// It is load-bearing here rather than merely correct, and two shapes need it.
//
// A token can begin inside another, in the last five characters of a body and
// nowhere else. The five letters the prefix opens with are letters a body may
// hold, and the underscore behind them is not, so a candidate opening inside a
// token needs that underscore to fall past the token's end. A body closing on
// polar with _oat_ and a body written after it is a token from either opening,
// the two spans overlap and Masker.locate resolves them.
// Test_PolarOrganizationAccessToken_aTokenInsideAToken drives every one of the
// five, and Test_polarOrganizationAccessTokenPrefix counts them out of the
// declarations that decide it rather than leaving the number to this sentence.
//
// The other shape is the candidate that failed: polar_oat_polar_oat_ and a body
// carries a whole token at its second prefix, and a scan resuming past the
// length its first candidate hoped for would step over it.
// Test_PolarOrganizationAccessToken_aTokenBehindAFailedCandidate drives it.
//
// The scan keeps no cursor and needs none: a candidate reads at most fifty-three
// bytes and stops, which bounds what it reads with no state to be wrong about.
// That is what rules out a quadratic input here.
//
// What this pattern over-matches on: fifty-three characters of the right shape
// that nobody issued. Ten characters have to be written, two of them
// underscores, then exactly forty-three more of the letters and the digits with
// nothing between any of them. Prose holds no such run — a body is longer than
// any word and carries no space or punctuation — and standard base64, base32 and
// hexadecimal write no underscore at all, so an identifier, a certificate body
// or an embedded image carries no candidate at however long it runs. What is
// left is base64url, which writes every character of the prefix: there the ten
// stand about once in a million million million characters, and where they do,
// the forty-three behind them carry neither the hyphen nor the underscore about
// one time in four. That is the collision this pattern pays for, and there is
// nothing in the text to tell such a run from a token — the vendor's format is
// that prefix and that many of those characters, with no part of it left over
// to fail.
// Test_PolarOrganizationAccessToken_insideAnOpaqueRun pins it.
//
// The generator above is the one Polar mints every credential it issues with,
// so the prefix is the whole of what tells any of the others from this one:
// each is polar_, a kind, an underscore and the same forty-three characters. So
// none of the rest is a width this scan is missing.
//
// What keeps them apart is the caller rather than the format. A personal access
// token authenticates a person and an OAuth access token an application acting
// for one, where this authenticates an organization, so a caller has reason to
// switch on one and not the other and a redactor keying on the name has reason
// to tell them apart. Each is a pattern of its own to add under a name of its
// own; a prefix read here instead would leave this pattern locating credentials
// its own name does not cover.
// Test_PolarOrganizationAccessToken_theOtherPrefixesTheGeneratorWrites drives
// the two the ruleset cited above carries rules of its own for, so that reading
// either is a change somebody argues for.
//
// referencePolarOrganizationAccessToken in
// builtin_polar_organization_access_token_test.go keeps the grammar as a regular
// expression, spelling the prefix, the count and the character class again so
// that the two are changed together, and the fuzz target beside it holds this
// scan to that expression. An expression is affordable here for both of the
// reasons it can be: the repetition is exact, so the machine an engine builds is
// read once and stops, and the opening is a ten character literal an engine
// searches the text for rather than a class it would have to walk its machine at
// every byte for.
var polarOrganizationAccessToken = newBuiltin("polar-organization-access-token", &polarOrganizationAccessTokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two.
	retain := polarOrganizationAccessTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], polarOrganizationAccessTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not,
		// for the reason the rationale above gives: the prefix written twice
		// with a body behind it carries a token at its second prefix, which a
		// scan resuming past the length this candidate hoped for would step
		// over.
		offset = anchor + 1

		if anchor < polarOrganizationAccessTokenAnchorIndex {
			continue
		}
		start := anchor - polarOrganizationAccessTokenAnchorIndex

		// The byte the prefix opens with is tested before the prefix is
		// compared. Every anchor the search stops at reaches this line — the
		// underscore the prefix carries in the middle among them — and all but
		// the few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != polarOrganizationAccessTokenPrefix[0] ||
			!strings.HasPrefix(src[start:], polarOrganizationAccessTokenPrefix) {
			continue
		}

		body := start + len(polarOrganizationAccessTokenPrefix)
		end := start + polarOrganizationAccessTokenChars
		if end > len(src) {
			// The input ends inside the body, and the count is the whole of
			// what tells a token from any other run written behind the prefix.
			retain = min(retain, start)
			continue
		}
		if isPolarOrganizationAccessTokenBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// polarOrganizationAccessTokenPrefix is what Polar writes an organization
	// access token with, and what the scan reads back from the anchor. It closes
	// on a character no body is written with, which is what makes the search
	// cheap over a run of a body, and it carries a second one five characters
	// in, which is what bounds where a token may begin inside another.
	// Test_polarOrganizationAccessTokenPrefix holds it to both and counts the
	// positions the second of them leaves.
	polarOrganizationAccessTokenPrefix = "polar_oat_"

	// polarOrganizationAccessTokenAnchor is the byte the scan searches the
	// input for and polarOrganizationAccessTokenAnchorIndex is where it stands
	// in the prefix, so a candidate begins that many bytes in front of what a
	// search reported. builtin_scan.go says why a scan searches for one byte of
	// its prefix rather than for the prefix itself; the rationale above says
	// what made it this byte. Test_polarOrganizationAccessTokenAnchor holds it
	// to standing at this index and to being no character of a body.
	polarOrganizationAccessTokenAnchor      = '_'
	polarOrganizationAccessTokenAnchorIndex = 9

	// The counts a token is written to, which are the generator's own: it draws
	// polarOrganizationAccessTokenSecretChars characters from the letters and
	// the digits and pads the base62 CRC32 over them to
	// polarOrganizationAccessTokenChecksumChars.
	// Test_polarOrganizationAccessTokenChars holds the arithmetic to all four.
	polarOrganizationAccessTokenSecretChars   = 37
	polarOrganizationAccessTokenChecksumChars = 6
	polarOrganizationAccessTokenBodyChars     = polarOrganizationAccessTokenSecretChars + polarOrganizationAccessTokenChecksumChars
	polarOrganizationAccessTokenChars         = len(polarOrganizationAccessTokenPrefix) + polarOrganizationAccessTokenBodyChars
)

// isPolarOrganizationAccessTokenBody reports whether s is the body of a token:
// exactly polarOrganizationAccessTokenBodyChars characters, all of them in the
// alphabet a body is written in.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count being left to the caller to have cut
// correctly.
func isPolarOrganizationAccessTokenBody(s string) bool {
	if len(s) != polarOrganizationAccessTokenBodyChars {
		return false
	}
	for i := range len(s) {
		if !isBase62Byte(s[i]) {
			return false
		}
	}
	return true
}

// polarOrganizationAccessTokenTail is what the scan settles the tail of its
// input by. prefixTail (builtin_scan.go) says what that is and why it is built
// once.
var polarOrganizationAccessTokenTail = newPrefixTail(polarOrganizationAccessTokenPrefix)
