package mask

import "strings"

// HerokuAPIToken locates Heroku API tokens: the prefix HRKU- and either the
// sixty base64url characters Heroku writes one with now or the UUID it wrote
// one with before — sixty-five characters or forty-one.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly as many characters of it are as the reading it matched comes to.
// So text of that shape is redacted whether or not Heroku issued it. A space, a
// dot, an equals sign or a run of fewer than sixty characters ends the longer
// reading, and anything but a UUID behind the prefix ends the shorter one, so
// text as it is ordinarily written is not affected. A longer run is a token
// with something written after it, and the token alone is redacted.
//
// Its name is "heroku-api-token".
func HerokuAPIToken() Pattern { return herokuAPIToken }

// Heroku states the prefix and the length outright, which is what the two
// readings below rest on.
//
// The prefix comes from a pair of changelog entries in 2024. The first, of 7
// March, announced that from 1 April Heroku would prefix all newly granted
// OAuth access tokens with HRKU-, and printed a token either side of that
// change: a bare UUID, and the same UUID with the prefix written in front of
// it. The second, of 1 April, says the change is in effect and prints nothing.
// So the prefix is stated twice, and the shape behind it is shown once — a
// UUID, which is what a token had been with nothing at all in front of it. What
// the prefix is for is on the OAuth page rather than in either entry: a
// prefixed token helps identify potentially leaked tokens in code or logs by
// searching for the prefix, which is the vendor asking to be scanned for.
//
// The length comes from the changelog entry of 23 April 2025 and from the OAuth
// page it points at. The entry says the length of new access tokens is
// increasing from forty-one characters to sixty-five, and prints a whole token
// of each; the OAuth page states the result as a sentence, that Heroku OAuth
// access tokens are sixty-five characters long and prefixed with HRKU-. So both
// counts are the vendor's own, written down rather than read off a value
// somebody was shown, and the sixty-five is stated twice.
//
// Both readings are kept because both are live. Heroku wrote the same sentence
// at each change — all current tokens continue to work and remain unchanged
// until they are regenerated — and a token created by heroku
// authorizations:create does not expire, so a token issued before the length
// changed is a credential today. Reading the longer shape alone would leave
// every one of them in the output whole.
//
// What Heroku does not write down is the alphabet of the sixty. The one token
// it prints in the new shape carries an underscore and no hyphen, which is
// consistent with base64url and settles nothing on its own: sixty characters
// drawn from base64url carry no hyphen about two runs in five. The two
// rulesets reading this format both admit the whole of base64url — the letters
// of both cases, the digits, the underscore and the hyphen — and that is what
// is read here, isBase64URLByte in builtin_scan.go. Sixty characters is
// forty-five bytes exactly, which is a width an encoder reaches with no padding
// and is what the count being a multiple of four says about the value behind
// it. Narrowing to the alphabet of the one printed token would decline every
// token whose body happened to fall with a hyphen in it, which is most of them.
//
// The tightening both rulesets take and this scan declines is the two
// characters behind the prefix. gitleaks reads HRKU-AA and fifty-eight more,
// trufflehog reads the same and pre-filters its input on the literal HRKU-AA,
// so both treat the AA as part of the format. The one token Heroku prints opens
// that way too, and twelve zero bits at the front of a body is what a leading
// version byte would look like. It is declined all the same, because Heroku
// states the prefix and the length and does not state those two characters:
// they are read off values somebody was shown, and being wrong about them
// locates nothing at all where being wrong about the alphabet locates a token
// with a character too many. Test_HerokuAPIToken_aBodyOpeningPastTheRulesets
// pins the decision, so that taking the tightening is a change somebody argues
// for.
//
// The UUID reading is the shorter of the two and is read as a UUID rather than
// as thirty-six more characters of base64url. A UUID's four hyphens stand at
// fixed places, which is what tells the shape from any other run of that length
// written behind the prefix, and reading it loosely would admit a great deal
// more for no token gained. Its hexadecimal is read in either case: Heroku
// prints these lowercase and an encoder writing one writes lowercase, but a
// UUID upper-cased on its way through a log is the same credential, and a
// reading too narrow costs the whole of it where one too wide costs nothing but
// a shape nobody issued.
//
// The two readings are one pattern and not two. Neither is published by design,
// both reach the Platform API in the same Bearer header, and nothing a redactor
// could key on separates them: they are one credential written at two lengths
// because Heroku lengthened it. API token is what Heroku calls that credential
// where it is used — the Platform API reference says bearer authentication is
// constructed using an API token, and the CLI authentication page it points at
// uses the same words — so the name covers the whole of what this locates
// without reaching past it.
//
// The longer reading is tried first, and the order is what the scan reports and
// what it settles. A UUID is written in base64url, so a whole token of the
// shorter shape stands at the front of any longer one whose first thirty-six
// characters happen to fall that way, and both readings are then true of the
// same text. Taking the shorter one and stopping would report the span inside
// rather than the span, and worse, would settle the text behind it — a stream
// would write out forty-one characters of redaction with the last twenty-four
// characters of a live token beside them, which is text it cannot take back.
// Where the longer reading fails the shorter is still taken.
// Test_HerokuAPIToken_theUUIDReadingInsideTheLongerOne drives both halves.
//
// There is no boundary on either side of a match. A boundary in front drops
// rather than trims the match wherever a token is written against a word
// character, which is what HEROKU_API_KEY_HRKU-... is; one behind it drops a
// token followed by a character of the body's own alphabet, which under an
// exact count is a token with a character written after it. What may stand
// either side is held back by the character class and the counts alone. Both
// rulesets open on a word boundary, so a token written straight against a
// letter is one they leave in the text where this pattern trims it. Behind the
// match they differ: trufflehog closes on a word boundary as well, where
// gitleaks asks for a backtick, a quote, whitespace, a semicolon, an escaped
// newline or the end of the input — so a token written against a full stop or a
// comma is one gitleaks leaves whole and a word boundary would have taken.
//
// The byte the scan searches the input for is the H the prefix opens with, and
// the prefix is read back from it. builtin_scan.go says why a scan searches for
// one byte of its prefix rather than for the prefix itself. Every character of
// HRKU- is written in base64url, so the body settles nothing here and none of
// the five buys the guarantee a prefix closing outside its own body alphabet
// buys; what is left is the text around a token. The hyphen is the one to pass
// over, for the reason builtin_scan.go gives: it is what every ISO timestamp,
// every UUID and every kebab-case name is written with, and it stands more than
// six times as often as any of the four letters over this library's own corpus.
// Of the letters, the K stands in the KEY and the TOKEN an environment variable
// holding a credential is named with, the U in the URL and the AUTH of a log
// field, and the R in the ERROR a level is written as and the AUTHORIZATION a
// header is named by, where the H opens HTTP and little else a log writes in
// uppercase. Over that corpus the H is the rarest of the four by a wide margin,
// and the search stopping least often is what a scan pays for a line holding no
// token.
//
// Anchoring on the first character of the prefix rather than a later one is
// what leaves a stop costing a comparison of the whole prefix instead of the
// one byte a scan reading its prefix back can test before comparing anything.
// That is the trade the count above pays for, and it was measured either way:
// over this pattern's own benchmark cases the two are within a few per cent of
// one another, and the H is ahead on the inputs that crowd candidates together,
// which is where a stop is answered most often.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a token or not, which is the default and needs no argument.
// What it finds there is unbounded rather than narrow: every character of the
// prefix is written in the body's alphabet, so a whole prefix can stand
// anywhere inside a body, and a token written inside another is located as well
// as the one around it. The spans overlap and Masker.locate resolves them.
// Test_HerokuAPIToken_aTokenBeginningInsideAnother drives it.
//
// That is also why this scan keeps no cursor and can keep none: a run of the
// body's alphabet may hold a prefix at any of its characters, so no two
// candidates can be told apart by where the run before them ended. What rules
// out a quadratic input is the counts being counts — a candidate reads at most
// sixty bytes and stops, whatever the run behind it runs to.
// Test_HerokuAPIToken_scanIsLinear drives the inputs that would find that
// wrong.
//
// What this pattern over-matches on is sixty base64url characters written
// behind the prefix, which is the vendor's format exactly, and the two shapes
// worth stating are both reachable. The first is the encoded blob: base64url is
// what a JWT segment, a web push key and a routable payload are written in, so
// a blob carrying the five characters of the prefix at some position and
// running sixty further is a token character for character. Standard base64
// writes neither character base64url adds, so a certificate, a PEM body or an
// embedded image carries no prefix at however long it runs, and inside a
// base64url encoding five characters of an alphabet of sixty-four stand where
// the prefix stands about once in a thousand million characters.
//
// The second is the one this alphabet has that a base62 body would not: the
// hyphen is a body character, so an unbroken kebab-case run is a body. HRKU-
// written in front of sixty characters of hyphenated words is redacted, and no
// count of unbroken letters rules it out, because a hyphen never ends the run.
// What holds it back is the four capitals in front, which spell no word and
// which no kebab-case name written by a tool begins with.
// Test_HerokuAPIToken_aKebabCaseRunBehindThePrefix pins it.
//
// The refresh token handed out beside an access token is not read, and what
// stops it is that it carries no prefix. The OAuth page prints the pair in one
// response, the access token prefixed and the refresh token not, so the anchor
// the whole of this pattern rests on is absent and what is left is a UUID — an
// identifier written in URLs and dashboards by design, and the shape a pattern
// in this package may not be anchored on. That is a live credential left in the
// output whole, which is stated rather than hidden.
//
// The password the CLI writes into netrc is read, and the page printing it is
// what makes that worth saying. The authentication
// page calls that field an OAuth token, which is the credential the changelogs
// above prefixed, so what the CLI stores today opens with HRKU- and is located
// wherever it is written. The example printed beside that sentence is forty
// hexadecimal characters with nothing in front of them, which is neither shape
// on record and is a SHA-1's shape exactly: a token still written that way is
// not read and cannot be, since a count of forty hexadecimal characters
// anchored on nothing is the one thing a pattern here may not be.
// Test_HerokuAPIToken_theCredentialsWithNoPrefix pins both.
//
// referenceHerokuAPITokenFind in builtin_heroku_api_token_test.go keeps the
// grammar as a regular expression, spelling the prefix, both readings, both
// counts and both character classes again so that the two are changed together,
// and the fuzz target beside it holds this scan to that expression. An
// expression is affordable here for one of the two reasons it usually is: both
// repetitions are exact, so the machine an engine builds is read once and
// stops. The other does not hold — the prefix is written in the alphabet its
// own body is written in, so a run of that alphabet is a position an engine
// stops at — and what pays for it is the prefix being five characters, which an
// engine searches the text for as a literal and finds nowhere in a run that
// does not spell it.
var herokuAPIToken = newBuiltin("heroku-api-token", &herokuAPITokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two. Which candidate is cut short is this format's
	// own question, and the rationale above answers it: the longer reading is
	// walked first so that a token the end of the input cut short is reported
	// as cut short even where the UUID reading inside it is whole.
	retain := herokuAPITokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], herokuAPITokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not, for the
		// reason the rationale above gives: every character of the prefix is written
		// in the body's alphabet, so a token can begin anywhere inside another and a
		// scan stepping over what it took would leave that one whole.
		offset = anchor + 1

		if anchor < herokuAPITokenAnchorIndex {
			continue
		}
		start := anchor - herokuAPITokenAnchorIndex

		// The prefix is compared before either reading is walked. Every anchor
		// the search stops at reaches this line, and all but a few of them are
		// turned away here by the four characters behind the one already known.
		if !strings.HasPrefix(src[start:], herokuAPITokenPrefix) {
			continue
		}
		body := start + len(herokuAPITokenPrefix)

		// The longer reading first. A UUID is written in base64url, so a token
		// of the shorter shape can stand at the front of one of this shape, and
		// taking the shorter one first would report the span inside rather than
		// the span.
		if end := body + herokuAPITokenBodyChars; end > len(src) {
			// The input ends inside this candidate, so the count that is the
			// whole of what tells it from anything else written behind the
			// prefix cannot be taken here. The shorter reading is tried all the
			// same: it may be whole where this one is not, and the span it
			// reports is one this candidate would widen — which is why the text
			// is held from here either way.
			retain = min(retain, start)
		} else if isHerokuAPITokenBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
			continue
		}

		end := body + herokuAPITokenUUIDBodyChars
		if end > len(src) {
			retain = min(retain, start)
			continue
		}
		if isHerokuAPITokenUUIDBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// herokuAPITokenPrefix is what every token opens with, and what the scan
	// reads back from its anchor. Every character of it is written in the
	// body's alphabet, which is what leaves a token able to begin anywhere
	// inside another and why nothing here rests on a separator;
	// Test_herokuAPITokenPrefix holds it to that so the sentence is read as a
	// measurement rather than as an oversight.
	herokuAPITokenPrefix = "HRKU-"

	// herokuAPITokenAnchor is the byte the scan searches the input for and
	// herokuAPITokenAnchorIndex is where it stands in the prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what made it
	// this byte, which is the text around a token rather than the body.
	herokuAPITokenAnchor      = 'H'
	herokuAPITokenAnchorIndex = 0

	// herokuAPITokenBodyChars is how many characters stand behind the prefix in
	// the shape Heroku writes a token in now: sixty, which is what the
	// sixty-five its OAuth page states comes to with the prefix taken off, and
	// what forty-five bytes come to in base64url with no padding.
	herokuAPITokenBodyChars = 60

	// herokuAPITokenChars is the whole of a token in that shape.
	// Test_herokuAPITokenChars holds it to the sixty-five Heroku states.
	herokuAPITokenChars = len(herokuAPITokenPrefix) + herokuAPITokenBodyChars

	// herokuAPITokenUUIDBodyChars is how many characters stand behind the
	// prefix in the shape Heroku wrote a token in until 23 April 2025: the
	// thirty-six of a UUID, written out here as the groups and the separators
	// between them so that the count and the walk below cannot come apart.
	herokuAPITokenUUIDBodyChars = 8 + 1 + 4 + 1 + 4 + 1 + 4 + 1 + 12

	// herokuAPITokenUUIDChars is the whole of a token in that shape.
	// Test_herokuAPITokenChars holds it to the forty-one Heroku states.
	herokuAPITokenUUIDChars = len(herokuAPITokenPrefix) + herokuAPITokenUUIDBodyChars

	// herokuAPITokenUUIDSeparator is what divides the groups of a UUID. It
	// belongs to base64url as much as any character of a body does, which is
	// why the shorter reading is a layout rather than a count: the separators
	// standing at fixed places are the whole of what tells a UUID from
	// thirty-six other characters written behind the prefix.
	herokuAPITokenUUIDSeparator = '-'
)

// herokuAPITokenUUIDGroups are the five groups of hexadecimal a UUID is written
// in, eight characters then three of four then twelve, with a separator between
// each pair. Test_herokuAPITokenChars holds them to coming to
// herokuAPITokenUUIDBodyChars, which is what keeps the walk below and the count
// the scan cuts by from disagreeing.
var herokuAPITokenUUIDGroups = [...]int{8, 4, 4, 4, 12}

// isHerokuAPITokenBody reports whether s is everything behind the prefix of a
// token in the shape Heroku writes one in now: exactly herokuAPITokenBodyChars
// characters of base64url.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count left to the caller to have cut correctly.
func isHerokuAPITokenBody(s string) bool {
	if len(s) != herokuAPITokenBodyChars {
		return false
	}
	for i := range len(s) {
		if !isBase64URLByte(s[i]) {
			return false
		}
	}
	return true
}

// isHerokuAPITokenUUIDBody reports whether s is everything behind the prefix of
// a token in the shape Heroku wrote one in until 23 April 2025: a UUID, which
// is herokuAPITokenUUIDGroups written in hexadecimal with a separator between
// each pair of groups.
//
// The groups are walked rather than the positions of the separators listed,
// because a list of positions is a second statement of the layout that can come
// to disagree with the count the scan cuts by.
func isHerokuAPITokenUUIDBody(s string) bool {
	if len(s) != herokuAPITokenUUIDBodyChars {
		return false
	}
	i := 0
	for g, width := range herokuAPITokenUUIDGroups {
		if g > 0 {
			if s[i] != herokuAPITokenUUIDSeparator {
				return false
			}
			i++
		}
		for range width {
			if !isHerokuAPITokenUUIDByte(s[i]) {
				return false
			}
			i++
		}
	}
	return true
}

// isHerokuAPITokenUUIDByte reports whether c is a hexadecimal digit, which is
// what the groups of a UUID are written in.
//
// Either case is admitted where Heroku prints these lowercase, for the reason
// the rationale above gives: a UUID upper-cased on its way through a log is the
// same credential, and what the wider reading admits besides is a shape nobody
// issued.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go,
// which hold what more than one scan reads. Every hexadecimal run this package
// reads keeps its own test for the reason its own file gives — one admits
// either case where another admits lowercase alone — and a shared test named
// for the class rather than for what reads it would silently be the wrong
// answer for one of them.
func isHerokuAPITokenUUIDByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'F' ||
		'a' <= c && c <= 'f'
}

// herokuAPITokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var herokuAPITokenTail = newPrefixTail(herokuAPITokenPrefix)
