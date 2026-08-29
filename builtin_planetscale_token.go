package mask

import "strings"

// PlanetScaleToken locates the tokens PlanetScale issues in the format it
// prefixes: the service token an organization is given (pscale_tkn_), the
// access token an application receives from the OAuth flow (pscale_oauth_) and
// the refresh token handed out beside it (pscale_oauth_refresh_), each with
// forty-three base64url characters behind it — fifty-four, fifty-six and
// sixty-four characters altogether.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly as many characters of it are as its own prefix and the count come
// to. So text of that shape is redacted whether or not PlanetScale issued it. A
// space, a dot, an equals sign or a run of fewer than forty-three characters
// ends the reading, so text as it is ordinarily written is not affected. A
// longer run is a token with something written after it, and the token alone is
// redacted.
//
// Its name is "planetscale-token".
func PlanetScaleToken() Pattern { return planetScaleToken }

// PlanetScale states neither the alphabet nor the count in words. What it gives
// is one opening stated outright and two whole values, which carry the other
// two openings, and the rest of the grammar is read off those values.
//
// The service token's opening is the one stated: the page on authenticating
// the MCP server with one says to copy the token value and that "It starts with
// pscale_tkn_", and to send it as "Authorization: Bearer pscale_tkn_...". The
// page on service tokens beside it is about creating one and assigning it
// permissions, and prints no value. The two OAuth kinds come from the API
// reference's own worked response, which prints an access_token opening
// pscale_oauth_ and a refresh_token opening pscale_oauth_refresh_, both whole
// and both forty-three characters behind their openings. That is the count
// below, and it is read off a printed value rather than off a sentence because
// PlanetScale writes no sentence about it.
//
// Forty-three characters is what thirty-two bytes come to in base64url with no
// padding, and thirty-two bytes is the width a secret is drawn at. So the count
// is not four kinds each settling on the same arbitrary number: it is one
// generator.
//
// The rulesets divide on that. trufflehog reads exactly forty-three characters
// behind pscale_tkn_, verifying what it finds against the API, and reads the
// same forty-three behind the database password's own opening; the two values
// its tests are written from are forty-three apiece. gitleaks reads thirty-two
// to sixty-four characters behind each of pscale_tkn_, pscale_oauth_ and
// pscale_pw_ with an entropy floor, and kingfisher reads the same range behind
// the same three. noseyparker reads none of them. A floor of thirty-two with a
// ceiling of sixty-four is a range drawn around one width by a rule written
// without one; the width is the width, and it is read exactly rather than as a
// floor: a run longer than the count is not one longer token but a token with
// something written after it, and only the token is redacted.
//
// The alphabet is the whole of base64url: the letters of both cases, the
// digits, the underscore and the hyphen. That follows from the width rather
// than from the values, and the values are why it has to. Four values of this
// width are published between PlanetScale's reference and trufflehog's tests —
// the two OAuth kinds, a service token and a database password; two of them
// carry an underscore and none of them carries a hyphen. Forty-three characters
// drawn from base64url carry no hyphen about half the time, so four carrying
// none is about one run in fifteen — likely enough to be what happened, and not
// evidence of an alphabet. trufflehog reads the class without the hyphen and
// would find about half of every token issued if the width means what it says;
// gitleaks and kingfisher admit it. What declining it would cost is that half.
// What admitting it costs is a run of the same alphabet with a hyphen in it,
// which is opaque either way.
// Test_PlanetScaleToken_aHyphenInTheBody pins the decision so that narrowing it
// is a change somebody argues for.
//
// What is declined is what gitleaks and kingfisher admit besides: the equals
// sign and the dot. Neither is written in base64url, the first is the padding
// the compact encoding is defined without and the second belongs to no encoding
// at all, so a run carrying either is no token however long it runs.
//
// The three kinds are one pattern rather than three, which is a decision about
// the caller and not about the scanning. None of them is published by design
// and none is the identifier another is kept under: a service token and an
// OAuth access token reach the same API in the same Bearer header, and a
// refresh token mints fresh ones of the second kind, so a caller with reason to
// redact any of them has the same reason for the rest. Nothing a redactor could
// key on separates them either. Token is the term PlanetScale uses for the
// whole of what this locates — the service tokens page calls the service token
// one and calls what it mints "OAuth tokens", and the reference calls the third
// a refresh token — so the name below covers the three without reaching past
// them.
//
// The database password PlanetScale issues is not read here, and the name is
// why. It opens pscale_pw_ and carries the same forty-three characters, so the
// grammar would cost one entry; what it does not have is a term. PlanetScale
// calls it a password wherever it names it — the CLI's password subcommand, the
// API's plain_text password, the connection strings its tutorials print — and
// never a token, so no term of the vendor's covers a password and the three
// above together, which is what puts a boundary between patterns. This scan
// turns pscale_pw_ away at the kind, and
// Test_PlanetScaleToken_theDatabasePasswordIsNotRead pins that.
//
// The refresh token's opening is written behind the access token's, which is
// this format's one awkward corner and decides both what the scan reports and
// what it settles. Everything between pscale_oauth_ and the refresh token's
// body — refresh_ — is written in the body's own alphabet, so a whole refresh
// token is also pscale_oauth_ with forty-three characters behind it, and both
// readings are true of the same text. The scan tries a kind before any kind
// that is an opening of it and takes the first that yields a token, so a
// refresh token is reported once, at sixty-four characters, rather than as that
// span and the fifty-six character one inside it. Where the longer reading
// fails the shorter is still taken: a refresh opening with thirty-five
// characters behind it is an access token's shape exactly, and is located as
// one.
// Test_PlanetScaleToken_theRefreshKindCarriesTheAccessTokenOpening drives both.
//
// The order the kinds are tried in is what settles the tail as well, and that
// is the half a reader is likelier to change without noticing. An input ending
// inside a refresh token holds a whole access token in front of the cut, so a
// scan that took the access token and stopped would report a span and settle
// the text behind it — and a stream would write out fifty-six characters of
// redaction with the last eight characters of the refresh token beside it,
// which is text it cannot take back. The scan reports the longer candidate as
// cut short even where the shorter one is whole, which holds the stream from
// the start of the value until the rest arrives.
// Test_planetScaleTokenKinds holds the order to trying a kind before any kind
// that is an opening of it.
//
// There is no boundary on either side of a match. A boundary in front drops
// rather than trims the match wherever a token is written against a word
// character, which is what PLANETSCALE_SERVICE_TOKEN_pscale_tkn_... is; one
// behind it drops a token followed by a letter or a digit, which under an exact
// count is a token with a character written after it. What may stand either
// side is held back by the character class and the count alone. Every ruleset
// above asks for something in front of the match: all three open on a word
// boundary. Behind it trufflehog and kingfisher close on one as well, and
// gitleaks closes on a backtick, a quote, whitespace, a semicolon, an escaped
// newline or the end of the input — so a token written against a hyphen or a
// full stop is one gitleaks leaves in the text where this pattern redacts it.
// gitleaks and kingfisher read this format under an entropy floor besides,
// which is a demand on the content of a random body rather than a part of the
// format.
//
// The byte the scan searches the input for is the p the opening opens with, and
// the opening is read back from it. builtin_scan.go says why a scan searches
// for one byte of its opening rather than for the opening itself. What makes
// this one hard to choose is that the body settles nothing: every character of
// pscale_ is written in base64url, so each of the seven stands in a body about
// as often as the next, and none of them buys the guarantee a prefix closing
// outside its own body alphabet buys. What is left is the text around a token,
// and there the p is the rarest letter of the seven over prose and over the
// vendor's own words alike: on the line these benchmarks are written on, which
// carries the vendor's host name and its API path, it stands four times against
// the l's seven, and in the prose sentence this pattern's corpus carries it
// stands not at all where the l stands once. The l is the rarer of the two over
// the log lines, JSON and command lines text_shapes.txt keeps, which is the one
// text measured that runs the other way.
//
// The underscore stands rarer still on several of those and is passed over all
// the same, for the reason builtin_scan.go gives: it is what an environment
// variable, a snake_case name and a log field are written with, so a scan
// anchored on one opens a candidate on a great deal of ordinary text to reject
// it again — and the name PlanetScale's own CLI reads a token out of,
// PLANETSCALE_SERVICE_TOKEN, carries two of them in front of every token
// assigned to it.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a token or not, which is the default and needs no argument.
// What it finds there is unbounded rather than narrow: every character of an
// opening is written in the body's alphabet, so a whole opening can stand
// anywhere inside a body, and a token written inside another is located as well
// as the one around it. The spans overlap and Masker.locate resolves them.
// Test_PlanetScaleToken_aTokenBeginningInsideAnother drives it.
//
// That is also why this scan keeps no cursor and can keep none: a run of the
// body's alphabet may hold an opening at any of its characters, so no two
// candidates can be told apart by where the run before them ended. What rules
// out a quadratic input is the count being a count — a candidate reads at most
// sixty-four bytes and stops, whatever the run behind it runs to.
// Test_PlanetScaleToken_scanIsLinear drives the inputs that would find that
// wrong.
//
// What this pattern over-matches on is forty-three base64url characters written
// behind one of the three openings, which is the vendor's format exactly. The
// shape worth stating is the encoded blob: base64url is what a JWT segment, a
// web push key and a routable payload are written in, so pscale_tkn_ written
// straight in front of forty-three characters of one is a token character for
// character and the whole of it is redacted. There is nothing left to tell the
// two apart — a scan declining it would decline every token PlanetScale issues
// — and what has to be written to reach it is one of the openings with such a
// run against it and nothing between.
// Test_PlanetScaleToken_aBase64URLRunBehindTheOpening pins the decision.
//
// What reaches a span is never prose: forty-three unbroken characters behind
// seven more is longer than anything prose is written in, and a word running
// into an opening runs the body out at its first space or punctuation mark. The
// identifiers PlanetScale writes with
// the same opening are turned away at the kind: pscale_api_ is what its CLI
// names a Postgres role by, and the twelve character identifier a service token
// is kept under carries no opening at all.
//
// referencePlanetScaleTokenFind in builtin_planetscale_token_test.go keeps the
// grammar as a regular expression, spelling the opening, the three kinds, the
// count and the character class again so that the two are changed together, and
// the fuzz target beside it holds this scan to that expression. An expression
// is affordable here for one of the two reasons it usually is: the repetition
// is exact, so the machine an engine builds is read once and stops. The other
// does not hold — the opening is written in the alphabet its own body is
// written in, so a run of that alphabet is a position an engine stops at — and
// what pays for it is the opening being seven characters, which an engine
// searches the text for as a literal and finds nowhere in a run that does not
// spell it.
var planetScaleToken = NewPattern("planetscale-token", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two. Which candidate is cut short is this format's own
	// question, and the rationale above answers it: the kinds are walked whole
	// so that a refresh token the end of the input cut short is reported as cut
	// short even where the access token inside it is finished.
	retain := planetScaleTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], planetScaleTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not, for the
		// reason the rationale above gives: every character of an opening is written
		// in the body's alphabet, so a token can begin anywhere inside another and a
		// scan stepping over what it took would leave that one whole.
		offset = anchor + 1

		if anchor < planetScaleTokenAnchorIndex {
			continue
		}
		start := anchor - planetScaleTokenAnchorIndex

		// The opening is compared before any kind is. Every anchor the search
		// stops at reaches this line, and all but a few of them are turned away
		// here by the six characters behind the one already known.
		if !strings.HasPrefix(src[start:], planetScaleTokenOpening) {
			continue
		}
		kinds := start + len(planetScaleTokenOpening)

		for _, kind := range planetScaleTokenKinds {
			if !strings.HasPrefix(src[kinds:], kind) {
				continue
			}

			body := kinds + len(kind)
			end := body + planetScaleTokenBodyChars
			if end > len(src) {
				// The input ends inside this candidate, so the count that is
				// the whole of what tells it from anything else written behind
				// the prefix cannot be taken here. The kinds behind it are
				// tried all the same: a shorter one may be whole where this one
				// is not, and the span it reports is one this candidate would
				// widen — which is why the text is held from here either way.
				retain = min(retain, start)
				continue
			}
			if !isPlanetScaleTokenBody(src[body:end]) {
				continue
			}
			spans = append(spans, Span{Start: start, End: end})
			break
		}
	}
	return spans, retain
})

const (
	// planetScaleTokenOpening is what every prefix opens with, and what the scan
	// reads back from its anchor. Every character of it is written in the body's
	// alphabet, which is what leaves a token able to begin anywhere inside
	// another and why nothing here rests on a separator;
	// Test_planetScaleTokenOpening holds it to that so the sentence is read as a
	// measurement rather than as an oversight.
	planetScaleTokenOpening = "pscale_"

	// planetScaleTokenAnchor is the byte the scan searches the input for and
	// planetScaleTokenAnchorIndex is where it stands in every prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix rather
	// than for the prefix itself; the rationale above says what made it this
	// byte, which is the text around a token rather than the body.
	// Test_planetScaleTokenAnchor holds it to standing at this index in every
	// prefix the scan can match.
	planetScaleTokenAnchor      = 'p'
	planetScaleTokenAnchorIndex = 0

	// planetScaleTokenBodyChars is how many characters stand behind a prefix:
	// forty-three, which is what thirty-two bytes come to in base64url with no
	// padding, and what each of the four published tokens is written to.
	planetScaleTokenBodyChars = 43
)

// planetScaleTokenKinds is what stands between the opening and the body, one
// entry a kind: tkn_ for the service token an organization is given, and the
// two the OAuth flow returns, oauth_refresh_ for the refresh token and oauth_
// for the access token it mints.
//
// The order is load-bearing rather than tidy. A kind is tried before any kind
// that is an opening of it, which is what leaves oauth_refresh_ in front of
// oauth_: a refresh token is an access token's shape as well, so the shorter
// kind taken first would report the span inside the value instead of the value,
// and would settle the text behind a refresh token the end of the input cut
// short.
// Test_planetScaleTokenKinds holds the order to that rule rather than to this
// arrangement of it, so a kind added tomorrow is held to the same thing.
var planetScaleTokenKinds = []string{"tkn_", "oauth_refresh_", "oauth_"}

// planetScaleTokenPrefixes is what a candidate opens with, one entry a kind:
// the opening with that kind behind it.
//
// The kinds are read out of planetScaleTokenKinds rather than written out
// again, so that a kind the scan reads is a kind the tail below knows about.
// builtin_scan.go says why: a table kept beside that one is one that can come
// to disagree with it, and what a stream would then do with the kind it had not
// been told about is release the characters a token opens with and redact
// nothing.
var planetScaleTokenPrefixes = func() []string {
	prefixes := make([]string, len(planetScaleTokenKinds))
	for i, kind := range planetScaleTokenKinds {
		prefixes[i] = planetScaleTokenOpening + kind
	}
	return prefixes
}()

// planetScaleTokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var planetScaleTokenTail = newPrefixTail(planetScaleTokenPrefixes...)

// isPlanetScaleTokenBody reports whether s is everything behind the prefix of a
// token: exactly planetScaleTokenBodyChars characters of base64url.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count being left to the caller to have cut
// correctly.
//
// The alphabet is the shared one in builtin_scan.go rather than a test of this
// scan's own, because it is the shared alphabet: the count says a body is
// thirty-two bytes written in base64url, so what a body admits is whatever that
// encoding admits, and a scan spelling it again here could come to disagree
// with the other scans reading the same encoding about what that is.
func isPlanetScaleTokenBody(s string) bool {
	if len(s) != planetScaleTokenBodyChars {
		return false
	}
	for i := range len(s) {
		if !isBase64URLByte(s[i]) {
			return false
		}
	}
	return true
}
