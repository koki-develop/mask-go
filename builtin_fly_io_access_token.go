package mask

import "strings"

// FlyIOAccessToken locates the access tokens Fly.io issues: one of the labels
// fm2_, fm1r_ and fm1a_, and behind it a body of sixty-four characters or more
// written in standard base64 and closing with the padding base64 calls for,
// redacted to the end of the run it stands in. The padding counts toward the
// sixty-four. Every token Fly.io mints today carries fm2_, whatever it was
// scoped to — a personal access token, a deploy token cut for one app, an org
// token, an SSH token or a machine-exec token — and a token authenticates the
// API within the scope it was created with.
//
// A token is located wherever it is written, with no word boundary either side,
// and with or without the FlyV1 scheme it is sent under. So text of that shape
// is redacted whether or not Fly.io issued it. A space, an underscore, a
// character outside the alphabet or a body of fewer than sixty-four characters
// ends the reading, so text as it is ordinarily written is not affected. Where
// the run carries on past the sixty-fourth character, it is redacted to its
// end.
//
// Its name is "fly-io-access-token".
func FlyIOAccessToken() Pattern { return flyIOAccessToken }

// Access token is Fly.io's own name for this string: the heading of the page it
// keeps on them, and the term that page collects every scope under — app, org,
// SSH and machine-exec are what a token reaches rather than what a token is
// called. The scopes are one pattern rather than five for the reason the
// vendor's own naming already gives: none of them is published by design, none
// is the identifier another is kept under, every one goes into the same
// Authorization header against the same API, and nothing a redactor could key
// on separates them. A caller with reason to redact one has the same reason for
// the rest.
//
// The format is stated in Fly.io's own token library, superfly/macaroon, which
// is where a reader is sent by fly tokens debug. Its format.go declares the
// labels a token may carry — permissionTokenLabel = "fm1r", dischargeTokenLabel
// = "fm1a", v2TokenLabel = "fm2" and oauthTokenLabel = "fo1" — and encodeTokens
// writes a token as a label, an underscore and
// base64.StdEncoding.EncodeToString of the encoded macaroon, joining several
// with commas. Parse reads the same string back: it cuts at the first
// underscore and admits the label. Fly.io's documentation states the current
// label again in prose, telling a reader to pass an "existing token starting
// with fm2_", and the header a token is sent in is FlyV1 followed by the token
// — which is why nothing here reads the scheme: it stands in front of the value
// and says nothing about whether a value stands there.
//
// Three of the four labels are read and the fourth is not, and it is Parse that
// divides them. fm1r, fm1a and fm2 share one arm of its switch: each is decoded
// with base64.StdEncoding.DecodeString and handed to macaroon.Decode, which
// unmarshals the same Macaroon — the same nonce, the same caveats, the same
// tail — whichever label stood in front of it. bundle/tokens.go reads the three
// the same way again. So the alphabet below and the count read off that struct
// are stated for all three by the same source. fo1 is the arm that skips: Parse
// reaches it and goes on to the next token without decoding anything, so no
// source of the vendor's states what alphabet or what length stands behind that
// label, and a prefix read without a body's grammar is a pattern firing on the
// prefix. Test_FlyIOAccessToken_theLabelThatIsNotRead pins it.
//
// The three read are one pattern under one name for the reason the scopes are.
// A v1 label is not minted today — encodeTokens emits fm2 and nothing else —
// but a token carrying one is a token the vendor's own parser still accepts, so
// a caller redacting Fly.io credentials has the same reason to redact it. What
// the vendor hands a user as an access token is the whole of the Authorization
// header's value, which carries a permission token and the discharges answering
// its third-party caveats together, comma-joined and each with a label of its
// own; the term covers the whole of that rather than the one part of it a user
// asked for.
//
// The alphabet is the standard base64 one of RFC 4648 and not the base64url
// alphabet isBase64URLByte in builtin_scan.go holds, because StdEncoding is
// what both ends of Fly.io's library name: the two characters that differ are +
// and / here where they are - and _ there. The underscore falling outside it is
// what the whole of the reading below rests on. Padding is admitted, and is
// read at the end of a body alone: StdEncoding writes it, and the DecodeString
// on the other side demands it, so a token Fly.io wrote carries whatever its
// length calls for and never more than the two characters base64 can ask for.
//
// The count is a floor, and it is read off what a macaroon cannot be smaller
// than rather than off the length of any token. Fly.io publishes no length: its
// documentation writes a token as fm2_ and an ellipsis, and the string is a
// MessagePack encoding whose size moves with the caveats attenuating it, so
// there is no length to publish. What every one of them carries is a
// sixteen-byte random nonce — nonceRndSize in the library's nonce.go — and the
// thirty-two-byte HMAC-SHA256 tail its sign function returns. Those forty-eight
// bytes are sixty-four base64 characters, and that is the floor. It cannot be
// too high: every token carries the MessagePack framing, the location and the
// key identifier besides, so a real one is half as long again at least. Reading
// the floor at what a token cannot undercut, rather than at the length of a
// token Fly.io or a ruleset writes, is what keeps a count from being wrong
// about the shortest token Fly.io ever writes — and a count that is wrong
// there costs the whole credential rather than the end of one.
//
// What the floor costs on the other side is the token cut short of it: a line
// cut to a column limit partway through one leaves a label and a body too short
// to be a body, and nothing is located.
// Test_FlyIOAccessToken_cutShortOfTheFloor pins that, so that it stays a
// decision on the record.
//
// The length is not read as a multiple of four, which base64 itself would allow
// and which the Sentry scan does read of the payload it walks. The two are not
// the same position. That payload closes against a separator the alphabet does
// not admit, so its length is whatever Sentry wrote and the group rules out
// only a payload Sentry could not have written. A body here closes wherever the
// run closes, so the group would be asked of the token together with whatever
// was written against it — and a base64 character standing directly behind a
// token would make its length no multiple of four and leave the whole
// credential in the output. A tightening that can lose a credential to what was
// written next to it is not one this pattern takes.
//
// There is no boundary on either side of a match. A word boundary in front
// would drop the whole match rather than trim it wherever a token is written
// against a word character, as FLY_API_TOKEN_fm2_… is. One behind would drop
// rather than trim as well, and where it were asked decides what it drops.
// Asked behind the count, it drops the token a letter, a digit or an
// underscore is written against wherever the count closes on a letter or a
// digit, and the token whose count closes on +, / or the padding wherever no
// word character is written against it. Asked behind that run, what it drops
// is decided by the characters either side of the end, since a boundary asks
// for exactly one of them to be a word character: the + and the / standard
// base64 holds are neither, nor is the padding, and the underscore is the one
// word character the alphabet leaves out. So it drops three: the token an
// underscore is written against wherever that token closes on a letter or a
// digit, the token closing on + or / wherever an underscore is not what stands
// behind it, and the padded token wherever no word character stands behind it
// at all.
//
// The byte the scan searches the input for is the underscore closing every
// prefix, and the label in front of it is read back from there.
// builtin_scan.go says why a scan searches for one byte of its prefix rather
// than for the prefix itself; what makes it this byte is the length of a body.
// No body carries an underscore, so a token however long stops the search
// exactly once, at its own prefix, where each character of a label would stop
// it about once in every sixty-four characters of every body on the line. On
// the log line these benchmarks are written on the underscore stands not at
// all, where the a stands six times, the m five times, the 1 and the 2 twice
// each and the f and the r once.
//
// Reading back from the separator rather than from a fixed index in one opening
// is what the labels being of two lengths asks for: fm2 is three characters and
// the two v1 labels are four. Each length is tried in turn, and a length that
// does not fit is almost always turned away by the one byte a label opens with,
// since the byte standing that far in front of a separator is seldom an f. At
// most one of them can fit: the three differ in the character standing directly
// in front of the separator, so the first that matches is the only one that
// could have, and Test_flyIOAccessTokenPrefixes holds them to that.
//
// The scan resumes one byte past the separator, which is the step
// builtin_scan.go argues: it reaches the next candidate at that candidate's own
// separator and steps over none. Consuming a match would step over a token
// written inside the one just found and leave it in the output whole. What is
// written inside one here is the label of the next: every character of every
// label belongs to the alphabet a body is written in, so a body may close with
// one and hand the underscore behind it to a token of its own. The two spans
// then overlap, which a Masker resolves into one, and
// Test_FlyIOAccessToken_aTokenAgainstAnother drives the shape.
//
// The scan keeps no cursor and needs none. The run behind a candidate is read
// to its end however long that run is, and what bounds the work is where a body
// opens rather than how far it reads: the underscore in front of one is written
// in neither the alphabet nor the padding, so every body begins where a run
// begins and no two candidates can read the same run. That is what rules out
// the quadratic input a line dense in prefixes would otherwise be, and
// Test_flyIOAccessTokenPrefixes_runsDoNotOverlap names the character the
// guarantee rests on while Test_FlyIOAccessToken_scanIsLinear drives the inputs
// that would find it wrong.
//
// What this pattern over-matches on is sixty-four characters of standard base64
// written behind one of the labels, and one shape is worth naming. A base64url
// payload is the one encoding in ordinary use carrying the underscore, so it
// can hold a whole prefix — and what it then has to carry for the run behind
// that prefix to be redacted is sixty-four characters drawn from the sixty-two
// its own alphabet shares with this one, which lands about one time in eight.
// Such a payload is a value already opaque to a reader, so being wrong about
// one costs the reader nothing, and declining it would mean declining every
// token written in the same characters.
// Test_FlyIOAccessToken_aBase64URLPayload pins it.
//
// What reaches a span is never prose, a git SHA or an MD5, and never a
// certificate or an embedded image. Every prefix closes on an underscore, which
// no word runs into and which neither standard base64 nor hexadecimal admits,
// so a digest and a base64 blob each carry nothing a prefix could be found in
// at however long they run.
//
// referenceFlyIOAccessTokenAt in builtin_fly_io_access_token_test.go states
// that grammar again, spelled out at one position, with the labels, the floor,
// the alphabet and the padding written afresh so that the two are changed
// together, and the fuzz target beside it holds this scan to it. It is written
// out rather than built on an expression because the floor and the padding are
// one arithmetic over the two of them together: an expression saying it needs
// three alternations differing only in where the floor falls, which is three
// counts to keep right where the walk has one.
var flyIOAccessToken = newBuiltin("fly-io-access-token", &flyIOAccessTokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := flyIOAccessTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], flyIOAccessTokenSeparator)
		if i < 0 {
			break
		}
		separator := offset + i

		// The scan resumes here whether this candidate became a token or not,
		// for the reason the rationale above gives: a body may close with a
		// label, so a token can begin a label's width before the end of the one
		// before it.
		offset = separator + 1

		start, ok := flyIOAccessTokenPrefixStart(src, separator)
		if !ok {
			continue
		}

		body := separator + 1
		end, open := flyIOAccessTokenBodyEnd(src, body)
		if open {
			// The input ends inside the body, so neither where it ends nor
			// whether it is long enough to be one is settled here: what comes
			// next either carries the run on, pads it, or closes it.
			retain = min(retain, start)
		}
		if end-body >= flyIOAccessTokenBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// flyIOAccessTokenLabels is what superfly/macaroon's format.go calls a token by,
// one entry for each label its Parse decodes: the v2 label every token minted
// today carries, and the two v1 labels its switch admits alongside it. The
// label its switch skips is not here, and the rationale above says why.
//
// The order is the order a candidate is read back in, so the label a scan meets
// oftenest stands first.
var flyIOAccessTokenLabels = [...]string{"fm2", "fm1r", "fm1a"}

// flyIOAccessTokenPrefixes is what a candidate opens with, one prefix a label,
// built from the labels above and the separator rather than written out again.
// A table of its own is one that can come to disagree with them about which
// labels there are, and what a stream would then do with the label it had not
// been told about is release the characters a token opens with and redact
// nothing. It is what the tail below is built from as well.
var flyIOAccessTokenPrefixes = func() []string {
	prefixes := make([]string, 0, len(flyIOAccessTokenLabels))
	for _, l := range flyIOAccessTokenLabels {
		prefixes = append(prefixes, l+string(flyIOAccessTokenSeparator))
	}
	return prefixes
}()

const (
	// flyIOAccessTokenSeparator is what encodeTokens writes between a label and
	// the base64 behind it, and it is the byte the scan searches the input for:
	// it closes every prefix, and it belongs to neither the alphabet a body is
	// written in nor the padding a body closes with. That is what ends a body
	// where it stands, what keeps two candidates from ever reading the same run,
	// and what makes the search cost nothing over a body however long.
	// Test_flyIOAccessTokenPrefixes_runsDoNotOverlap holds the second of those.
	flyIOAccessTokenSeparator = '_'

	// flyIOAccessTokenBodyChars is the count a body is held to, padding
	// included, read as a floor rather than exactly. It is the sixteen-byte
	// nonce and the thirty-two-byte tail every macaroon carries, written in
	// base64: forty-eight bytes is sixty-four characters. The rationale above
	// says why the floor is read off what a token cannot undercut.
	flyIOAccessTokenBodyChars = 64

	// flyIOAccessTokenPadding is what a body closes with where its bytes do not
	// fill the last group, and flyIOAccessTokenPaddingMax is the most of it
	// base64 can call for. StdEncoding writes it and the DecodeString reading a
	// token back demands it, so a body carries whatever its length calls for
	// and never more.
	flyIOAccessTokenPadding    = '='
	flyIOAccessTokenPaddingMax = 2
)

// flyIOAccessTokenPrefixStart returns where the prefix closing at the separator
// standing at i in src begins, and whether one closes there at all.
//
// Returning the first prefix that matches rests on no two of them being able to
// close at one separator, which Test_flyIOAccessTokenPrefixes holds them to; the
// rationale above says why the lengths are tried in turn at all.
//
// The byte a prefix opens with is compared before the prefix is. Every
// separator the search stops at reaches this line, and all but the few that
// open a candidate are turned away by one byte per length where a comparison
// of a whole prefix is a length and a read.
func flyIOAccessTokenPrefixStart(src string, i int) (int, bool) {
	for _, p := range flyIOAccessTokenPrefixes {
		if i+1 < len(p) {
			continue
		}
		start := i + 1 - len(p)
		if src[start] == p[0] && strings.HasPrefix(src[start:], p) {
			return start, true
		}
	}
	return 0, false
}

// flyIOAccessTokenBodyEnd returns where the body beginning at i in src ends: the
// run of the alphabet, and the padding that run closes with.
//
// It reports as well whether the end of the input was what ended the body
// rather than the text. A run reaching the end of the input is one more text
// may carry further, and a body closing on fewer padding characters than base64
// admits is one more text may pad — where a body already carrying the whole of
// the padding ends where it ends whatever follows, since nothing past it
// belongs to this body.
func flyIOAccessTokenBodyEnd(src string, i int) (int, bool) {
	for i < len(src) && isFlyIOAccessTokenBase64Byte(src[i]) {
		i++
	}
	pad := 0
	for pad < flyIOAccessTokenPaddingMax && i < len(src) && src[i] == flyIOAccessTokenPadding {
		i++
		pad++
	}
	return i, i == len(src) && pad < flyIOAccessTokenPaddingMax
}

// isFlyIOAccessTokenBase64Byte reports whether c belongs to the standard base64
// alphabet of RFC 4648, which is what superfly/macaroon writes a token's body
// with and reads it back with. It is not the base64url alphabet isBase64URLByte
// reads: the two characters that differ are + and / here where they are - and _
// there, and the underscore being outside this alphabet is what the scan's
// resumption and its want of a cursor both rest on. The padding character is
// not part of it and is counted separately, since it may stand only where a
// body ends.
func isFlyIOAccessTokenBase64Byte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z' ||
		c == '+' || c == '/'
}

// flyIOAccessTokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var flyIOAccessTokenTail = newPrefixTail(flyIOAccessTokenPrefixes...)
