package mask

import "strings"

// SentryAuthToken locates the Sentry auth tokens that carry a token type
// prefix: user auth tokens (sntryu_), user application tokens (sntrya_),
// internal integration tokens (sntryi_) and organization auth tokens (sntrys_).
//
// Two shapes a body is written in are read. Three of the four kinds carry
// thirty-two random bytes written as hexadecimal, which is sixty-four
// characters. The organization token carries a shape of its own: the base64 of
// a JSON payload naming the organization and the region it is served from, an
// underscore, and the base64 of thirty-two random bytes behind it.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly as many characters of it are as the kind is written to. So text
// of that shape is redacted whether or not Sentry issued it. A space, a
// character outside the alphabet, or a body of the wrong length ends the
// reading, so text as it is ordinarily written is not affected.
//
// Its name is "sentry-auth-token".
func SentryAuthToken() Pattern { return sentryAuthToken }

// What Sentry states of this format it states in code rather than in prose,
// and states more there than a vendor naming a prefix and stopping does. The
// prose documentation on auth tokens names the three kinds a reader can create
// and gives no prefix, no length and no alphabet for any of them; everything
// below is read off what Sentry publishes beside it — the server that mints
// the tokens, the command line tool that parses them, and the RFC the
// organization token was designed in.
//
// The prefixes are an enumeration of their own, AuthTokenType in
// src/sentry/types/token.py, whose four members are sntryu_ for a user token,
// sntrya_ for a user application token, sntryi_ for an internal integration
// token and sntrys_ for an organization token, and whose docstring says the
// values "equate to the expected prefix of each of the token types". The member
// with no prefix at all is named there too, for the tokens minted before Sentry
// prefixed them, and what that shape is and why it is not read is the last
// paragraph below.
//
// Three of the four bodies come from one line. generate_token in
// src/sentry/models/apitoken.py is
// f"{token_type}{secrets.token_hex(nbytes=32)}" — the prefix and thirty-two
// random bytes in hexadecimal, which is sixty-four
// characters, lowercase, since that is what token_hex writes. The column those
// tokens are stored in is declared at seventy-one characters, which is the
// seven of a prefix and the sixty-four of a body and says the same number a
// second way. sentry-cli agrees from the other side: it strips the prefix,
// decodes what is left as hexadecimal and asks for thirty-two bytes exactly,
// and its own tests reject sixty-three characters and sixty-five.
//
// Only the user token is minted through that line today; the create call
// branches on the type and reaches it for AuthTokenType.USER alone. The other
// two prefixes are read anyway, because the enumeration is Sentry's own
// statement of what they are, generate_token takes any member of it, and the
// endpoint Sentry runs for GitHub's secret scanning partner program already
// branches on all three. What reading them costs is nothing a reader can read:
// seven characters of prefix and sixty-four of hexadecimal is not text somebody
// wrote.
//
// The organization token is a format with a specification. RFC 0091 in
// getsentry/rfcs writes it as PREFIX_FACTS_SECRET: the facts are "a base64
// encoded JSON string" naming the organization, the URL Sentry is served at and
// the region URL, and the secret is written there as
// b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("="), which
// generate_token in src/sentry/utils/security/orgauthtoken_token.py emits
// verbatim. Thirty-two bytes base64 encoded and stripped of their padding are
// forty-three characters, and that is what the five tokens published in the
// RFC, in gitleaks' rule and in sentry-cli's tests each carry. sentry-cli reads
// the count from the other side as well, decoding the last segment without
// padding and asking for thirty-two bytes; its tests reject forty-two
// characters and forty-four.
//
// The alphabet of both segments is the standard base64 one of RFC 4648 and not
// the base64url alphabet isBase64URLByte in builtin_scan.go holds: Sentry
// writes them with Python's b64encode and sentry-cli reads them with
// data_encoding's BASE64, both of which are the alphabet with + and /. Both of
// those characters stand in the published tokens — one of the secrets carries
// a slash and another two pluses — so neither is inferred. The two characters
// base64url writes in their place are the ones this alphabet leaves out, and
// the underscore among them is what the whole of the reading below rests on.
//
// The payload carries its padding and the secret does not, which is the one
// asymmetry in the format and is written into both ends of it: the secret is
// rstripped where the payload is not, and sentry-cli decodes the payload with a
// codec that demands canonical padding where it decodes the secret with one
// that admits none. So a payload is a multiple of four characters, with at most
// two of them the padding character at the end, and a secret is forty-three
// characters with none. All five published tokens carry a payload that is a
// multiple of four, three of them with padding and two without. The multiple is
// read here rather than left as slack, because it is a property of base64
// itself rather than a count anybody chose: a payload that is not one is a
// payload Sentry could not have written and sentry-cli would refuse to read.
//
// The counts are read exactly. A scan declines an exact count where its vendor
// states no length, since a count that is wrong there costs the whole
// credential rather than the end of one. Here both counts are the width of
// thirty-two random bytes in the encoding the vendor's own minting code names,
// and the vendor's own parser rejects anything either side of them, so there
// is nothing left for a floor to protect against. What it costs is what an
// exact count costs everywhere: a run longer than the count is not one longer
// token but a token with something written after it, and only the token is
// redacted.
//
// There is no boundary on either side of a match. A word boundary in front
// would drop the whole match rather than trim it wherever a token is written
// against a word character, as SENTRY_AUTH_TOKEN_sntryu_... is, and one behind
// it would drop a token followed by a character of the token's own alphabet.
// What may stand either side is held back by the character classes and the
// counts alone.
//
// The tightening the Slack and Stripe scans take — that no letter and no digit
// stand in front of the prefix — would rule out nothing here and is not taken.
// Those two need it because their prefixes are three characters an ordinary
// word closes with, task_ ending in sk_ and network_ in rk_. No word closes on
// sntry, and the environment variable a token is read out of is spelled
// SENTRY_AUTH_TOKEN, with the e this anchor does not carry, so an assignment
// does not itself hold a candidate.
//
// The scan resumes one byte past the start of a candidate whether it became a
// token or not. The alphabet an organization token's payload and secret are
// written in holds every letter the anchor is written in and every character
// naming a kind, and the separator a prefix closes with is the one such a token
// already carries between its two segments — so a payload closing with sntrys
// hands the separator behind it to a second candidate, whose own payload is
// then the secret of the first, and a payload closing with sntryu does the same
// for a candidate whose body is hexadecimal. Consuming a match would step over
// that token and leave it in the output whole. The two spans then overlap,
// which a Masker resolves into one. A hexadecimal body holds none of those
// letters, so nothing begins inside one of those.
//
// The scan keeps no cursor and needs none, which is what the separator buys and
// is the guarantee the Stripe and npm scans reach by the same argument. A
// candidate asks for the separator seven characters in, no body of either shape
// is written with one, and a payload is therefore read from where it begins to
// the separator of the next candidate at the furthest — so two candidates never
// read the same run and reading all of them comes to the length of the input. A
// hexadecimal body reads a bounded count and stops, which is the same guarantee
// bought a second way. Test_sentryAuthTokenSeparator_runsDoNotOverlap holds the
// prefix to the one thing the argument rests on, and
// Test_SentryAuthToken_scanIsLinear drives the inputs that would find it wrong.
//
// What this pattern over-matches on: text somebody wrote whose shape is a
// token's exactly. The anchor is five characters no word is spelled with,
// followed by one of four characters and an underscore, so what has to be
// written before the question arises is sntry, a kind and an underscore. Behind
// a hexadecimal prefix that leaves sixty-four hexadecimal characters, which is
// the shape of a SHA-256 digest — sntryu_ and a digest is redacted, and there
// is nothing left in the string to read it apart from a token by, since a token
// is thirty-two random bytes written the same way. Behind sntrys_ it leaves a
// multiple of four base64 characters, an underscore and forty-three more, which
// is not a shape anything else is written in.
//
// What reaches a span is never prose, a git SHA or an MD5, and never a
// certificate or an embedded image. A digest and a base64 payload carry no
// underscore, so neither holds a prefix to be found at however long it runs,
// and no word of prose is spelled sntry with an underscore two characters
// behind it.
//
// The format Sentry minted before it prefixed its tokens is not read at all,
// and could not be. It is the same thirty-two random bytes in hexadecimal with
// nothing in front of them — the AuthTokenType member with no prefix, and the
// no_prefix case sentry-cli still accepts — so a grammar admitting one would
// admit every SHA-256 digest, which is what a content hash, an image digest and
// a lock file's integrity field are written as. That is over-matching on values
// a reader reads rather than on values already opaque, and there is no anchor
// to narrow it with: nothing in such a string says Sentry issued it.
//
// referenceSentryAuthTokenAt in builtin_sentry_auth_token_test.go states that
// grammar again, spelled out at one position, with the prefixes, the counts,
// the alphabets and the padding rule written afresh so that the two are changed
// together, and the fuzz target beside it holds this scan to it.
var sentryAuthToken = NewPattern("sentry-auth-token", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := sentryAuthTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], sentryAuthTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not, for
		// the reason the rationale above gives: the alphabet an organization token's
		// segments are written in holds the letters of the opening, so a token can
		// begin inside the one before it. Stepping one byte past the anchor is what
		// leaves the next candidate one byte past this one, which builtin_scan.go
		// sets out.
		offset = anchor + 1

		if anchor < sentryAuthTokenAnchorIndex {
			continue
		}
		start := anchor - sentryAuthTokenAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != sentryAuthTokenOpening[0] || !strings.HasPrefix(src[start:], sentryAuthTokenOpening) {
			continue
		}

		body := start + sentryAuthTokenPrefixChars
		if body > len(src) || src[body-1] != sentryAuthTokenSeparator {
			continue
		}

		var (
			end  int
			ok   bool
			open bool
		)
		if kind := src[body-2]; kind == sentryAuthTokenOrgKind {
			end, ok, open = sentryAuthTokenOrgEnd(src, body)
		} else if strings.IndexByte(sentryAuthTokenHexKinds, kind) >= 0 {
			end, ok, open = sentryAuthTokenHexEnd(src, body)
		}
		if open {
			// The input ends inside the body, so the count that tells this
			// candidate from a digest, or the separator that divides a payload
			// from its secret, has not arrived.
			retain = min(retain, start)
		}
		if ok {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// sentryAuthTokenPrefixes is what a candidate opens with, one entry to a kind.
//
// The kinds are read out of the two declarations the scan reads them from
// rather than written out again, so that a kind added to either is a kind this
// knows about: a table of its own is one that can come to disagree with them,
// and what a stream would then do with the kind it had not been told about is
// release the characters a token opens with and redact nothing.
var sentryAuthTokenPrefixes = func() []string {
	kinds := sentryAuthTokenHexKinds + string(sentryAuthTokenOrgKind)
	prefixes := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		prefixes = append(prefixes, sentryAuthTokenOpening+string(kind)+string(sentryAuthTokenSeparator))
	}
	return prefixes
}()

const (
	// sentryAuthTokenOpening is what every prefix opens with, and what the scan
	// reads back from its anchor. The character naming the kind and the
	// separator stand behind it, so a prefix is sentryAuthTokenPrefixChars long
	// whichever kind it names.
	sentryAuthTokenOpening = "sntry"

	// sentryAuthTokenAnchor is the byte the scan searches the input for and
	// sentryAuthTokenAnchorIndex is where it stands in the opening, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of what opens a
	// candidate rather than for the whole of it; what makes it this byte is
	// that sntry is a word with its vowel taken out and the four consonants
	// left are among the commonest there are — over the log line these
	// benchmarks are written on the s stands eight times and the n, the t and
	// the r five each — where the y stands once. The separator closing a
	// prefix is rarer still on that line and is passed over: it stands two
	// characters behind the y, so anchoring there would read a candidate back
	// past the character naming its kind and open one at every underscore of a
	// snake_case name.
	sentryAuthTokenAnchor      = 'y'
	sentryAuthTokenAnchorIndex = len(sentryAuthTokenOpening) - 1

	// sentryAuthTokenSeparator closes every prefix, and divides the payload of
	// an organization token from the secret behind it. It belongs to neither
	// alphabet a body is written in, which is what ends a payload where it
	// stands, what makes the count behind it readable at all, and what keeps
	// two candidates from ever reading the same run.
	// Test_sentryAuthTokenSeparator_runsDoNotOverlap holds it to the last.
	sentryAuthTokenSeparator = '_'

	// sentryAuthTokenPrefixChars is the whole of a prefix: the opening, the one
	// character naming the kind and the separator.
	sentryAuthTokenPrefixChars = len(sentryAuthTokenOpening) + 2

	// The characters naming a kind, which are what the enumeration Sentry keeps
	// differs in. Three of them carry a hexadecimal body — u for a user token,
	// a for a user application token, i for an internal integration token — and
	// the fourth is the organization token, whose body is a payload and a
	// secret. Test_sentryAuthTokenKinds holds the two to naming no character
	// twice.
	sentryAuthTokenHexKinds = "uai"
	sentryAuthTokenOrgKind  = 's'

	// sentryAuthTokenHexChars is what a hexadecimal body is written to:
	// thirty-two random bytes, two characters a byte. It is exact, and
	// sentry-cli rejects a body either side of it.
	sentryAuthTokenHexChars = 64

	// sentryAuthTokenSecretChars is what the secret of an organization token is
	// written to: the same thirty-two random bytes in base64 with the padding
	// stripped, which is forty-three characters. It is exact for the same
	// reason.
	sentryAuthTokenSecretChars = 43

	// sentryAuthTokenPadding is what a payload closes with where its bytes do
	// not fill the last group, and sentryAuthTokenPaddingMax is the most of it
	// base64 can call for. The secret carries none: Sentry strips it there and
	// sentry-cli reads the secret with a codec that admits none.
	sentryAuthTokenPadding    = '='
	sentryAuthTokenPaddingMax = 2

	// sentryAuthTokenPayloadGroup is what the length of a payload, padding
	// included, must be a multiple of. It is base64's own group and not a count
	// anybody chose, which is why the rationale above reads it rather than
	// leaving it as slack.
	sentryAuthTokenPayloadGroup = 4
)

// sentryAuthTokenHexEnd returns where the token whose hexadecimal body begins
// at body in src ends, and whether one is written there.
//
// The count is exact, so the body is read to it and no further: a run longer
// than sentryAuthTokenHexChars is a token and what is written after it.
// It reports whether saying no was the end of the input speaking rather than
// the text: a body the input cut short is one more text may complete, where a
// body carrying a character no body is written with is no body whatever
// follows.
func sentryAuthTokenHexEnd(src string, body int) (int, bool, bool) {
	end := body + sentryAuthTokenHexChars
	if end > len(src) {
		return 0, false, true
	}
	for i := body; i < end; i++ {
		if !isSentryAuthTokenHexByte(src[i]) {
			return 0, false, false
		}
	}
	return end, true, false
}

// sentryAuthTokenOrgEnd returns where the organization token whose payload
// begins at body in src ends, and whether one is written there.
//
// The payload is read as far as the alphabet runs and then over the padding it
// may close with, which is where it ends whatever stands after it: the
// separator belongs to neither, so a payload can no more run past the separator
// it wants than stop short of it. What is asked of the length is base64's own
// group, so a payload Sentry could not have written is turned away before the
// separator is looked for at all.
// It reports whether saying no was the end of the input speaking, as
// sentryAuthTokenHexEnd does. A payload reaching the end of the input is asked
// about before its length is, since a payload that goes on has no length yet:
// what the group rules out is a payload Sentry could not have written, and one
// the input cut short is not that.
func sentryAuthTokenOrgEnd(src string, body int) (int, bool, bool) {
	i := body
	for i < len(src) && isSentryAuthTokenBase64Byte(src[i]) {
		i++
	}
	for pad := 0; pad < sentryAuthTokenPaddingMax && i < len(src) && src[i] == sentryAuthTokenPadding; pad++ {
		i++
	}
	if i == len(src) {
		return 0, false, true
	}
	if n := i - body; n == 0 || n%sentryAuthTokenPayloadGroup != 0 {
		return 0, false, false
	}
	if src[i] != sentryAuthTokenSeparator {
		return 0, false, false
	}

	secret := i + 1
	end := secret + sentryAuthTokenSecretChars
	if end > len(src) {
		return 0, false, true
	}
	for j := secret; j < end; j++ {
		if !isSentryAuthTokenBase64Byte(src[j]) {
			return 0, false, false
		}
	}
	return end, true, false
}

// isSentryAuthTokenHexByte reports whether c may appear in a hexadecimal body:
// a digit or a lowercase letter through f, which is what Python's
// secrets.token_hex writes. Uppercase is not admitted, and admitting it would
// widen the class the one place this pattern already collides with a digest for
// nothing. sentry-cli decodes a body with a permissive codec and so would call
// an uppercased one a token; the server does not, since it authenticates a
// request by the SHA-256 of the string as written, and no digest of an
// uppercased token matches the one it stored. So such a string opens nothing
// and is not a credential to redact.
func isSentryAuthTokenHexByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f'
}

// isSentryAuthTokenBase64Byte reports whether c belongs to the standard base64
// alphabet of RFC 4648, which both segments of an organization token are
// written in. It is not the base64url alphabet isBase64URLByte reads: the two
// characters that differ are + and / here where they are - and _ there, and the
// underscore being outside this alphabet is what the scan's resumption and its
// want of a cursor both rest on. The padding character is not part of it and is
// counted separately, since it may stand only where a payload ends.
func isSentryAuthTokenBase64Byte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z' ||
		c == '+' || c == '/'
}

// sentryAuthTokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var sentryAuthTokenTail = newPrefixTail(sentryAuthTokenPrefixes...)
