package mask

import "strings"

// PyPIAPIToken locates PyPI API tokens: the upload tokens pypi.org issues, the
// ones test.pypi.org issues beside them, and the short-lived ones minted for a
// Trusted Publisher. Every one of them is written the same way — the prefix
// pypi-, and behind it a macaroon serialized into base64url — and it is that
// serialization, rather than the index which issued it, that this pattern is
// anchored on.
//
// A token is located wherever it is written, with no word boundary either side,
// and is redacted from its pypi- to the end of the run it stands in. So a token
// written against a word character keeps its span, and a character of the
// token's own alphabet written straight after a token is redacted with it.
//
// Its name is "pypi-api-token".
func PyPIAPIToken() Pattern { return pypiAPIToken }

// What PyPI states and what PyPI shows are worth separating here, as they are
// wherever a vendor names a prefix and leaves the rest of a format to be read
// off the values it issued — but here the separation barely matters, because
// the whole of it is readable from the code that writes a token rather than
// from what anybody publishes about the result.
//
// The help page states two of the three things this pattern reads. It gives the
// username a token is sent under, __token__; it says to set the password to the
// token value, including the pypi- prefix; and it tells an advanced reader to
// inspect a token by decoding it with base64 and checking the output against
// the identifier PyPI displays. So the prefix and a base64 body are PyPI's own
// statement, and what is left unstated is every count: no length, no alphabet
// and no checksum appears anywhere on the page.
//
// What warehouse itself does is write f"pypi-{m.serialize()}", and read a token
// back by partitioning on the first hyphen and requiring the part in front of
// it to be exactly pypi. So the prefix is not a convention that a later kind of
// token might spell differently — it is the whole of what tells warehouse a
// string is one of these at all, and both indexes and the OpenID Connect
// exchange write it.
//
// Behind the prefix is a macaroon. warehouse builds it with pymacaroons at
// version 2 and calls serialize with no argument, which is the binary
// serializer: the macaroon's bytes, base64url encoded, with the padding
// stripped. That is where the alphabet comes from — isBase64URLByte in
// builtin_scan.go, the letters of both cases, the digits, the hyphen and the
// underscore, and no equals sign, because the padding is stripped rather than
// merely absent from the examples.
//
// The first three bytes of those macaroon bytes are the same in every token,
// and they are what this pattern reads. The binary form opens with the version
// number, 2; then a packet, whose first byte names the field — 1, the location
// — and whose second is the length of that location as a variable length
// integer. Base64 reads three bytes as four characters, so those three bytes
// are the first four characters of the body, and the first three of the four
// are fixed: Ag spells the version and the top half of the field number, and
// the third character spells the bottom half of the field number together with
// the top two bits of the length, which are zero for any location shorter than
// sixty-four characters. The third character is therefore E, and the anchor is
// pypi-AgE.
//
// It is worth writing out what that leaves as the fourth character, because it
// is where the two published rulesets stop and this one does not. The fourth
// character spells the rest of the length, and the characters after it spell
// the location itself: pypi.org is eight characters, so a token from it opens
// pypi-AgEIcHlwaS5vcmc, and test.pypi.org is thirteen, so a token from it opens
// pypi-AgENdGVzdC5weXBpLm9yZw. gitleaks reads pypi-AgEIcHlwaS5vcmc and between
// fifty and a thousand more characters; trufflehog reads
// pypi-AgEIcHlwaS5vcmcCJ and between a hundred and fifty and a hundred and
// fifty-seven. Both name pypi.org, and so neither locates a TestPyPI token —
// which is issued by the same code, uploads to a real index and is a live
// credential in every sense. The location is the one part of the format an
// instance chooses rather than the format fixing it, and reading it is the same
// stale table the OpenAI and Anthropic scans beside this one weigh and decline:
// a name that moves costs a whole credential, and here it is not even a name
// that has to move for the reading to be wrong, only a second deployment.
//
// What the anchor does assume is the serialization it is read from: a macaroon
// at version 2, a location written as the first field, and a location shorter
// than sixty-four characters. The first two are the format warehouse pins by
// asking pymacaroons for MACAROON_V2, and by the deserializer beside it
// refusing anything whose first byte is not that version. The third is the
// assumption with a real edge to it — a location of sixty-four characters or
// more spells the third character F rather than E — and it is a long domain
// name, on a deployment of warehouse nobody has stood up.
// Test_pypiAPITokenHeader encodes the three bytes for every length the
// character stands for and for the first one it does not, so the edge is stated
// rather than assumed.
//
// The count of what follows is read as a floor and not as a count, which is
// where this scan stands with the Anthropic one rather than with the AWS,
// GitLab and Google ones. Those read an exact count because the count is most
// of what tells a value from the text around it; here the anchor has already
// done that work, and a count that is wrong is a token located nowhere. The
// count would be wrong easily: what a macaroon carries between its location and
// its signature is a caveat list, and what stands in it differs by how the
// token was issued — a token scoped to projects carries a name caveat and an id
// caveat, one scoped to a user carries a user caveat, and one minted for a
// Trusted Publisher carries a publisher caveat, an id caveat and an expiry.
// warehouse numbers five kinds of caveat and the numbers run from zero without
// a gap, which is a list that has been added to rather than one that was
// settled. trufflehog's window of eight characters is a reading of what one
// index writes today.
//
// What the floor is for is the rest of the run. Eight characters of anchor turn
// prose away by themselves — no word is spelled pypi-AgE — but they say nothing
// about what stands behind them, and a run of the alphabet can open that way
// and carry nothing else. Fifty characters is the shortest a macaroon can be
// written in: the three bytes the anchor is read from are followed, at the very
// least, by a signature — two bytes naming the field and its length, then the
// thirty-two bytes of an HMAC-SHA256 — and thirty-seven bytes is fifty
// base64url characters. Every token warehouse issues is more than three times
// that, since it carries a location, an identifier of thirty-six characters and
// at least one caveat as well, so the floor is a long way below anything that
// has to be located and a long way above anything anybody writes by hand.
//
// What the floor costs is the token shorter than it, which is a line cut to a
// column limit a few characters past the prefix. What is left there is a
// version byte, a field number and the opening of a domain name, and none of
// that is the signature a macaroon is a credential by. The cases in
// builtin_pypi_api_token_test.go pin both sides so that it stays a decision on
// the record.
//
// There is no boundary on either side of a match. A boundary in front would
// drop the whole match rather than trim it wherever a token is written against
// a word character, as PYPI_TOKEN_pypi-AgE... is. One behind would drop rather
// than trim as well, and where it were asked decides what it drops. Asked
// behind the count, it drops the token a letter, a digit or an underscore is
// written against wherever the count closes on one of those, and the token
// whose count closes on the hyphen wherever no word character is written
// against it. Asked behind that run, it drops the token whose body closes on a
// hyphen and nothing else, since every word character belongs to base64url —
// so the character standing behind a run is never one, and a boundary is left
// asking the token's own last character to be one.
//
// The scan resumes one byte past the start of a candidate whether it became a
// token or not. Every character of pypi-AgE belongs to the alphabet a body is
// written in, so the anchor can stand inside a body and a token can begin
// inside the span of the one before it. Consuming a match would step over such
// a token; the two spans then overlap, which a Masker resolves into one.
//
// Where the run ends is remembered, as it is in the OpenAI and Anthropic scans.
// A run can hold a candidate every eight characters — pypi-AgEpypi-AgE written
// over and over is one run, not two — and each of them reading that run to its
// end costs time quadratic in the length of such a line, so the end is worked
// out once and reused wherever a body begins inside the run already read. That
// is sound because a body stands a fixed five characters past the start of its
// candidate and candidates only move forward, so a body never begins in front
// of the body of the candidate before it. Nothing else about a candidate is a
// search over the rest of the input: one byte of the anchor is searched for and
// the rest of it compared where that byte is found, and the floor is read off
// the cursor.
// Test_PyPIAPIToken_scanIsLinear drives it.
//
// What this pattern over-matches on: a run of base64url characters carrying
// pypi-AgE and forty-seven more characters behind it — the floor is fifty and
// the header is three of them. Eight characters drawn from an
// alphabet of sixty-four stand where the anchor stands about once in three
// hundred million million characters, and one of the eight is a hyphen, which
// standard base64 never writes — so a certificate, a PEM body or an embedded
// image holds no anchor to be found at however long it runs, and only a
// base64url encoding can carry one. What is taken there is a stretch of a value
// that was already opaque to a reader, and the tightening on offer is the
// location, which the paragraphs above weigh and decline.
//
// What reaches a span is never prose, a git SHA or an MD5. A digest carries no
// hyphen, so it holds no pypi- to be found at, and neither g nor E is a
// hexadecimal digit. The strings that do carry the prefix are hyphenated names
// — gh-action-pypi-publish is one, and pypi-publish, pypi-server and
// pypi-timemachine are more — and what turns each of them away is the three
// characters behind the prefix, which no such name is spelled with.
//
// referencePyPIAPITokenFind in builtin_pypi_api_token_test.go states the same
// grammar with no cursor in it, spelling the prefix, the header, the floor and
// the alphabet again so that the two are changed together, and the fuzz target
// beside it holds this scan to that statement.
var pypiAPIToken = newBuiltin("pypi-api-token", &pypiAPITokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := pypiAPITokenTail.start(src)

	// The run a token is read as is worked out once and remembered, for the
	// reason the rationale above gives. The cursor holds the end of the run the
	// last body was read in, and -1 before there has been one, which every body
	// is past.
	runEnd := -1

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], pypiAPITokenAnchorByte)
		if i < 0 {
			break
		}
		at := offset + i

		// The scan resumes here whether this candidate became a token or not, for the
		// reason the rationale above gives: every character of the anchor belongs to
		// the alphabet a body is written in, so a token can begin inside the body of
		// the one before it.
		offset = at + 1

		if at < pypiAPITokenAnchorIndex {
			continue
		}
		start := at - pypiAPITokenAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != pypiAPITokenAnchor[0] || !strings.HasPrefix(src[start:], pypiAPITokenAnchor) {
			continue
		}

		// The body opens at the header, which the anchor has already read, so
		// the run it stands in is the run the header stands in. A body is a
		// fixed distance past the start of its candidate and candidates only
		// move forward, so the walk is repeated only where this body is past
		// what was already read.
		body := start + len(pypiAPITokenPrefix)
		if body >= runEnd {
			runEnd = base64URLRunEnd(src, body)
		}
		if runEnd == len(src) {
			// The run reaches the end of the input, so neither where the
			// macaroon ends nor whether enough of it is here is settled: what
			// comes next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if runEnd-body < pypiAPITokenBodyChars {
			continue
		}
		spans = append(spans, Span{Start: start, End: runEnd})
	}
	return spans, retain
})

const (
	// pypiAPITokenPrefix is what warehouse writes in front of every token it
	// serializes, and what it requires in front of every token it is handed
	// back. Every character of it belongs to the alphabet a body is written in,
	// which is what lets one token be written inside another and is why the
	// scan resumes a byte along; Test_pypiAPITokenAnchor holds it to that.
	pypiAPITokenPrefix = "pypi-"

	// pypiAPITokenHeader is the three characters every serialized macaroon
	// opens with: the version number 2, the field number of a location, and the
	// top two bits of that location's length. The rationale above sets out
	// which bits each character carries and what a location of sixty-four
	// characters or more would do to the third of them;
	// Test_pypiAPITokenHeader encodes the bytes and holds the claim to them.
	pypiAPITokenHeader = "AgE"

	// pypiAPITokenAnchor is what a candidate is read back as, the two above
	// together. Testing both at once rather than the prefix and then the header
	// is what keeps an ordinary line — which carries pypi- in every hyphenated
	// name that mentions the index — from reaching the body of the loop at all.
	pypiAPITokenAnchor = pypiAPITokenPrefix + pypiAPITokenHeader

	// pypiAPITokenAnchorByte is the byte the scan searches the input for and
	// pypiAPITokenAnchorIndex is where it stands in the anchor, so a candidate
	// begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of what it is
	// looking for rather than for the whole of it; what makes it this byte is
	// that pypi- is spelled in three ordinary letters and a hyphen — over the
	// log line these benchmarks are written on the p stands five times, the i
	// five and the hyphen twice — where neither capital of the header stands
	// once. Either capital would do on that line; the E is taken over the A
	// because base64url writes a zero byte as an A, so a run of them is what a
	// padded or sparse encoding is full of, and the header's own A stands
	// beside its E in every token either way.
	pypiAPITokenAnchorByte  = 'E'
	pypiAPITokenAnchorIndex = len(pypiAPITokenPrefix) + 2

	// pypiAPITokenBodyChars is the count a body is held to, read as a floor
	// rather than exactly and counted from the header rather than from behind
	// it. Fifty is the base64url length of the smallest macaroon that can be
	// written at all — the three bytes the header is read from, and a
	// thirty-four byte signature packet behind them — which is why it is not a
	// number that can be raised on its own. The rationale above weighs both
	// sides of it.
	pypiAPITokenBodyChars = 50
)

// pypiAPITokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var pypiAPITokenTail = newPrefixTail(pypiAPITokenAnchor)
