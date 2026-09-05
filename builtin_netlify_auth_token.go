package mask

import "strings"

// NetlifyAuthToken locates the authentication tokens Netlify issues: the
// letters nf, one character naming the kind, an underscore, and thirty-six
// characters behind it. Five kinds are written in that shape — a personal
// access token, a Netlify CLI token, an OAuth access token, an
// app.netlify.com token and a build token — and all five authenticate against
// the same API, so a token says which of them it is and not what it may reach.
//
// A token is located wherever it is written, with no word boundary either side,
// and is redacted from its nf to the end of the run it stands in. So a token
// written against a word character keeps its span, and a character of the
// token's own alphabet written straight after a token is redacted with it.
//
// Its name is "netlify-auth-token".
func NetlifyAuthToken() Pattern { return netlifyAuthToken }

// Netlify states this format in its announcement of it, and states two things
// there: that every authentication token it issues opens with nf and one
// character naming the kind, and that a field holding one needs room for forty
// characters. The five characters naming a kind are named with it —
// p for a personal access token, c for the CLI, o for an OAuth access token, u
// for an app.netlify.com token, b for a build token — and nothing else is. No
// token is shown, whole or masked.
//
// So the opening and the length are Netlify's, and how the forty divides is
// not. The announcement writes a prefix as three characters, nf and the kind,
// which leaves thirty-seven behind it and no separator at all. What is read
// here instead — an underscore closing the prefix and thirty-six characters
// behind it — is read off the rules rather than off the announcement: the
// rules reading this format write the underscore, those of them that state a
// count state thirty-six, and the two together come to the forty Netlify
// published. That is a reading agreeing with a published length and not a
// division Netlify has stated, and a token Netlify or a ruleset writes
// without the underscore is what would send it back.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the digits, and neither the hyphen nor the underscore base64url
// adds. Nothing of Netlify's says so and the rulesets carrying the format do
// not agree with one another about it, so what the choice rests on is the
// format's own shape rather than on which reading is the commoner.
//
// A body admitting the underscore is the reading to rule out, and three things
// rule it out. It is no encoding: the alphabet that adds the underscore to
// base62 is base64url, and base64url adds the hyphen with it, so an alphabet
// holding the one and not the other is neither of the two a token is plausibly
// written in. It would put the separator inside the thing the separator
// divides, leaving a prefix that cannot be read off a token by the character
// Netlify introduced it to be read off by. And it would make the grammar admit
// snake_case text: nf, a kind character and thirty-six word characters is the
// shape of an ordinary identifier, which is a value a reader reads rather than
// one already opaque, and this pattern reaches every caller of
// AllBuiltinPatterns.
//
// What the narrow alphabet costs is a token whose body carried an underscore
// after all. The run would end there, and unless thirty-six characters stood
// in front of it nothing would be located and the whole token would come
// through. That is the risk taken, and it is taken against a certainty on the
// other side: the wide alphabet redacts ordinary identifiers of the right
// length wherever they are written.
// Test_NetlifyAuthToken_anUnderscoreInTheBody pins the risk.
//
// The count is read as a floor and not as a count. Reading it exactly is worth
// it where the count is most of what tells a value from the text around it;
// here the prefix is doing that work, and the thirty-six is a number the rules
// state rather than one Netlify has written down. Were Netlify to lengthen the
// body, a scan asking for thirty-six exactly would locate the first forty
// characters of a token and leave the rest of it in the output.
//
// What the floor costs is the token shorter than it. A line cut to a column
// limit partway through a token leaves a prefix and a body too short to be
// one, and nothing is located: the random characters written before the cut
// stay in the output. Test_NetlifyAuthToken_cutShortOfTheFloor pins that.
//
// The five kinds are one pattern and not five. A caller has no reason to
// redact the token its CLI holds and leave the one its build carries, none of
// the five is published where the others authenticate, and "authentication
// token" is Netlify's own word for all of them — the word its own environment
// variable, NETLIFY_AUTH_TOKEN, is named after. Five switches would mean a
// caller had to know all five to redact what Netlify issues.
//
// There is no boundary on either side of a match. A boundary in front would
// drop the whole match rather than trim it wherever a token is written against
// a word character, as NETLIFY_TOKEN_nfp_... is. One behind would drop rather
// than trim as well, and where it were asked decides what it drops. Asked
// behind the count, it drops the token a letter, a digit or an underscore is
// written against. Asked behind that run, it drops the token an underscore is
// written against and nothing else, the underscore being the one word
// character no body admits. Test_NetlifyAuthToken_reachesTheEndOfTheRun writes
// both tokens out.
//
// The scan resumes one byte past the start of a candidate whether it became a
// token or not. The three characters in front of the underscore belong to the
// alphabet a body is written in, so a body may close with nf and a kind
// character and the underscore opening the next token stand directly behind
// it: a prefix, a body whose last three characters are a prefix without its
// underscore, then _ and a body of its own is two tokens, the second beginning
// three characters before the first one ends. Consuming a match would step over
// such a token and leave it in the output whole. The two spans then overlap,
// which a Masker resolves into one.
//
// No cursor is kept over the run, and none is needed, which is what the
// underscore buys. A candidate asks for an underscore four characters in and
// base62 holds none, so the underscore of the next candidate can be no earlier
// than the byte that ends this run, and the run that candidate reads therefore
// begins past this one. Successive candidates read runs that do not overlap,
// and reading all of them comes to the length of the input — the guarantee a
// scan whose prefix closes on a character its own body admits has to keep a run
// cursor for instead, bought here without state.
// Test_netlifyAuthTokenPrefixes_runsDoNotOverlap holds the prefixes to the one
// thing that argument rests on, and Test_NetlifyAuthToken_scanIsLinear drives
// it.
//
// What this pattern over-matches on: thirty-six characters of base62 behind a
// prefix inside a longer value. The underscore is what makes that rare.
// Standard base64 writes none at all, so a certificate, a PEM body or an
// embedded image carries no prefix to be found at however long it runs, and
// only a base64url encoding can hold one. There a prefix and a body together —
// three fixed characters and one of five out of an alphabet of sixty-four, then
// thirty-six carrying neither of the two characters base64url adds — stand
// about once in ten million characters. The run from that prefix to the end of
// the encoding is then redacted, and what is taken is a stretch of a value that
// was already opaque to a reader.
//
// The format Netlify issued before this one is not read here. It carried no
// prefix and nothing of its own to be recognised by, so the only thing left to
// locate one by is the word Netlify standing near it, which is a rule about the
// text around a value rather than about the value. Netlify has left those
// tokens working, so a caller holding one still has it in the text.
//
// The collision this format leaves is a digest written behind a prefix. The
// hexadecimal digits are base62 and nothing inside a digest ends a run, so a
// prefix and the forty characters of a SHA-1 is a token to this scan, as a
// prefix and the sixty-four of a SHA-256 is. Those are redacted, and nothing
// could be done about it that would not cost a credential: such a run is a
// token's format exactly, so a scan declining it would decline every token
// Netlify happened to write in the digits alone. An MD5 is left alone, at
// thirty-two characters four short of the floor, and so is any digest written
// behind a hyphen rather than an underscore.
// Test_NetlifyAuthToken_aDigestBehindThePrefix pins all four.
//
// Ordinary snake_case code carries the prefix — nfc_ opens the names Unicode
// normalization code is written with — and what turns those away is the
// thirty-six, which the next underscore of such a name ends long before.
//
// referenceNetlifyAuthToken in builtin_netlify_auth_token_test.go keeps the
// grammar as a regular expression, spelling the opening, the kinds, the
// separator, the floor and the alphabet again so that the two are changed
// together, and the fuzz target beside it holds this scan to that expression.
var netlifyAuthToken = newBuiltin("netlify-auth-token", &netlifyAuthTokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := netlifyAuthTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], netlifyAuthTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not, for
		// the reason the rationale above gives: a body may close with the three
		// characters the prefix opens with, so a token can begin three characters
		// before the end of the one before it.
		offset = anchor + 1

		if anchor < netlifyAuthTokenAnchorIndex {
			continue
		}
		start := anchor - netlifyAuthTokenAnchorIndex

		// The byte a prefix opens with is tested before the opening is compared.
		// Every anchor the search stops at reaches this line, and all but the few
		// that open a candidate are turned away by one byte where a comparison of
		// the whole opening is a length and a read.
		if src[start] != netlifyAuthTokenOpening[0] || !strings.HasPrefix(src[start:], netlifyAuthTokenOpening) {
			continue
		}
		if strings.IndexByte(netlifyAuthTokenKinds, src[start+len(netlifyAuthTokenOpening)]) < 0 {
			continue
		}

		body := start + netlifyAuthTokenPrefixChars
		end := base62RunEnd(src, body)
		if end == len(src) {
			// The run reaches the end of the input, so neither where the body ends
			// nor whether it is long enough to be one is settled here: what comes
			// next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if end-body >= netlifyAuthTokenBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// netlifyAuthTokenPrefixes is what a candidate opens with, one entry to a kind.
//
// The kinds are read out of the declaration the scan reads them from rather
// than written out again, so that a kind added there is a kind this knows
// about: a table of its own is one that can come to disagree with it, and what
// a stream would then do with the kind it had not been told about is release
// the characters a token opens with and redact nothing.
var netlifyAuthTokenPrefixes = func() []string {
	prefixes := make([]string, 0, len(netlifyAuthTokenKinds))
	for _, kind := range netlifyAuthTokenKinds {
		prefixes = append(prefixes, netlifyAuthTokenOpening+string(kind)+string(netlifyAuthTokenAnchor))
	}
	return prefixes
}()

const (
	// netlifyAuthTokenOpening is what every prefix opens with, and what the
	// scan reads back from its anchor. The character naming the kind and the
	// underscore closing the prefix stand behind it, so a prefix is
	// netlifyAuthTokenPrefixChars long whichever kind it names. Both its
	// characters belong to the alphabet a body is written in, which is part of
	// what lets one token begin inside another and is why the scan resumes a
	// byte along; Test_netlifyAuthTokenOpening holds them there.
	netlifyAuthTokenOpening = "nf"

	// netlifyAuthTokenAnchor is the byte the scan searches the input for and
	// netlifyAuthTokenAnchorIndex is where it stands in a prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of what opens a
	// candidate rather than for the whole of it; what makes it this byte is
	// that the two letters in front of the kind are ordinary ones — over the
	// log line these benchmarks are written on the n stands three times and the
	// f twice — where the underscore stands not once. It is the same character
	// the run guarantee rests on, so a candidate found by it is a candidate
	// whose body is the run beginning one byte along.
	netlifyAuthTokenAnchor      = '_'
	netlifyAuthTokenAnchorIndex = netlifyAuthTokenPrefixChars - 1

	// netlifyAuthTokenPrefixChars is the whole of a prefix: the opening, the
	// one character naming the kind and the underscore behind it.
	netlifyAuthTokenPrefixChars = len(netlifyAuthTokenOpening) + 2

	// netlifyAuthTokenKinds is the characters naming a kind, which are what the
	// five prefixes Netlify issues differ in: p for a personal access token, c
	// for a Netlify CLI token, o for an OAuth access token, u for an
	// app.netlify.com token, b for a build token. All five carry the same body,
	// so the character is read to tell a prefix from text that merely opens
	// like one and for nothing else. Test_netlifyAuthTokenKinds holds them to
	// naming no character twice and to being characters a prefix can be built
	// from.
	netlifyAuthTokenKinds = "pcoub"

	// netlifyAuthTokenBodyChars is the count a body is held to, read as a floor
	// rather than exactly. Thirty-six is what the rules reading this format
	// state, and with the four characters of a prefix it comes to the forty
	// Netlify publishes — which is a reading agreeing with a published length
	// and not a division Netlify has stated. The rationale above weighs reading
	// it as a floor.
	netlifyAuthTokenBodyChars = 36
)

// netlifyAuthTokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var netlifyAuthTokenTail = newPrefixTail(netlifyAuthTokenPrefixes...)
