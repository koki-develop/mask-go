package mask

import "strings"

// CratesIOToken locates the tokens crates.io issues: the API tokens a user
// creates on the settings page and cargo authenticates with, which are the
// prefix cio and thirty-two alphanumeric characters, and the short-lived access
// tokens Trusted Publishing mints in a CI job, which are the prefix cio_tp_ and
// thirty-two more. Thirty-five characters and thirty-nine.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly thirty-five characters of an API token or thirty-nine of a
// Trusted Publishing one are. So text of that shape is redacted whether or not
// crates.io issued it. A character that is neither a letter nor a digit ends the
// reading, so text as it is ordinarily written is not affected.
//
// Its name is "crates-io-token".
func CratesIOToken() Pattern { return cratesIOToken }

// What crates.io states about these formats it states in the code that writes
// them, as the Grafana, Vault and RubyGems formats are stated in theirs.
// crates.io is published under MIT and Apache-2.0, so the generators are
// readable rather than inferred.
//
// An API token is format!("{}{}", TOKEN_PREFIX,
// generate_secure_alphanumeric_string(TOKEN_LENGTH)) in the token utilities of
// crates_io_database, where TOKEN_PREFIX is cio and TOKEN_LENGTH is 32. The
// prefix carries a comment in capitals forbidding its change — changing it
// would revoke every token issued under it — which is a firmer statement that a
// prefix is stable than any vendor page gives. The alphabet is rand's rather
// than crates.io's, which is firmer still: generate_secure_alphanumeric_string
// is Alphanumeric.sample_string, and rand documents Alphanumeric as sampling
// uniformly from A-Z, a-z and 0-9. Sixty-two characters, and thirty-two of
// them. Neither the count nor the alphabet is read off a value somebody was
// shown.
//
// A Trusted Publishing access token is AccessToken in crates_io_trustpub: a
// prefix of cio_tp_, thirty-one characters of that same Alphanumeric, and one
// character of checksum behind them. Its parser demands exactly those
// thirty-two behind the prefix and that every one of them be ASCII
// alphanumeric, so what the writer writes and what the reader accepts agree
// character for character.
//
// The two are one pattern rather than two, which is a decision about the
// caller and not about the scanning. Neither of them is published by design and
// neither is the identifier the other is kept under: both authenticate the same
// endpoints, both are what cargo is handed to publish a crate with, and a caller
// with reason to redact one has the same reason for the other. Nothing a
// redactor could key on separates them either. What is left is the name, and
// crates.io draws a line there that this pattern does not: its settings page
// says API Tokens, its Trusted Publishing page says access token, and the
// action it publishes for CI says a temporary crates.io access token. So API
// token is a name for the durable half alone. The name below is the wider term
// crates.io uses for the pair — its own parser rejects a string that does not
// open with what it calls a known crates.io-specific prefix, and the trustpub
// file speaks of the cio prefix used for other tokens — and a wider term is
// what leaves credentials under one scan rather than splitting them.
//
// The prefixes cannot both stand at one candidate, which is what lets one walk
// read either. An API token's body is alphanumeric and holds no underscore, so
// cio followed by _tp_ is no API token at whatever length it runs. crates.io
// makes the same observation where it declares the longer prefix: it overlaps
// with the cio the other tokens carry, and the underscores are what tell the
// two apart. Test_CratesIOToken_theTwoFormsCannotBothStand pins it.
//
// The counts are read exactly rather than as floors, for the reason the AWS,
// GitLab and Google scans give: a run of the alphabet longer than the count is
// not one longer token but a token with something written after it, and only
// the token is redacted. cio and thirty-three alphanumeric characters is
// thirty-six, and the thirty-sixth stays in the text. A floor is what a scan
// reads where its vendor states no length; here the lengths are the arguments
// two generators are called with.
//
// They are two counts and not one, though both come to thirty-two. TOKEN_LENGTH
// is the whole of an API token's body; the other is thirty-one of random and one
// of checksum, declared apart and free to move apart. A single count written
// here would be a claim that they are one number, which nothing about the two
// generators makes true.
//
// The checksum is not verified. It is one character standing for the XOR of the
// thirty-one bytes in front of it, folded into the same sixty-two, so verifying
// it would turn away sixty-one of every sixty-two candidates that reached it.
// What that would buy is nothing a caller wants kept: cio_tp_ and thirty-two
// alphanumeric characters is out of reach of prose, and of every encoding a
// caller passes through — the over-match below counts them — so there is no
// text left for the checksum to tell from a token.
// What it would cost is real twice over. crates.io says of the checksum itself
// that it is not cryptographically secure and detects invalid tokens and
// nothing more, which is a thing free to change, and the day it changes a scan
// verifying it locates no Trusted Publishing token at all. And a token that
// reached a log with one character mangled is thirty-eight characters of a live
// credential which a scan doing the arithmetic would hand back whole.
// Test_CratesIOToken_aTrustedPublishingTokenWithAWrongChecksum pins the
// decision.
//
// There is no boundary on either side of a match. A word boundary in front
// would drop the whole match rather than trim it wherever a token is written
// against a word character, as CARGO_REGISTRY_TOKEN_cio... is, and one behind
// it would drop a token followed by a character of the token's own alphabet.
// What may stand either side is held back by the character class and the counts
// alone. All three published rules reading this prefix ask for both boundaries
// — noseyparker reads \b(cio[a-zA-Z0-9]{32})\b, kingfisher reads the same
// expression, and osv-scalibr's veles reads \bcio[a-zA-Z-0-9]{32}\b with
// thirty-five as the longest a match may be, its class carrying a stray hyphen
// no body is written with. Each of them reads the durable token alone.
//
// kingfisher asks for two more things this does not: at least two digits in the
// match, and a Shannon entropy of 3.3. Neither is part of the format, and the
// first is measurably wrong — a body of thirty-two characters drawn uniformly
// from sixty-two carries fewer than two digits about once in thirty-nine, so
// one issued token in thirty-nine is one kingfisher's rule declines. A demand
// on the content of a random body turns away real credentials at a rate the
// vendor's own generator sets, which is the trade this library does not make.
//
// The byte the scan searches the input for is the c of cio, and the opening is
// read back from it. builtin_scan.go says why a scan searches for one byte
// rather than for the opening itself, and it warns about this byte in
// particular: the letter a vendor's own name opens with is the letter its host
// name and its paths open with too, and crates.io, crate and cargo are each
// spelled with a c. That warning is why the three are counted here rather than
// reasoned about. The c is the rarest of them over the log lines this package's
// benchmarks are written on, over the text shapes its conformance corpus holds
// and over the output cargo writes while publishing a crate; the i, which is a
// vowel of prose as well as the first letter of io, is the commonest of the
// three on all of them. Those are counts of the corpora entire, and lines
// within them go the other way wherever a name carrying the c is written out:
// the line these benchmarks are written on repeats the vendor's own name and
// the path behind it, so the c stands three times there against the o's two,
// and the line cargo writes while publishing names a crate spelled with one.
// Neither a line of the vendor's own URLs nor one crate's name is what a
// caller's log is. Neither opening carries the c a second time, so a candidate
// stops the search once however it ends.
//
// The scan resumes one byte past the start of a candidate whether it became a
// token or not. The body is written in an alphabet holding every character of
// the shorter prefix, so an API token can begin inside another token's body:
// cio_tp_ and a body spelling cio partway along carries a candidate that reads
// on past the end of the token it stands in, and a scan stepping over what it
// found or declined would step over it. The spans then overlap, which
// Masker.locate resolves into one.
//
// The scan keeps no cursor and needs none: a candidate reads at most thirty-nine
// bytes and stops, which bounds what it reads with no state to be wrong about.
// That is the guarantee a scan reading a body to the end of its run has to buy
// with a run cursor instead, and it is bought here by the counts being counts.
//
// What this pattern over-matches on: thirty-five characters of the alphabet
// standing inside a longer run of it. cio is three lowercase letters, so how
// often a run carries them with thirty-two more characters of the alphabet
// behind is what the encoding that run is written in decides, and the encodings
// are taken here in order of how often. Lowercase base32 is the closest of
// them: every character it writes is a character a body may hold, so the
// opening stands about once in thirty-three thousand characters — a Tor v3
// onion address is fifty-six of
// them and leaves twenty-two positions the opening could stand at, so about one
// address in fifteen hundred carries thirty-five characters of itself redacted.
// A base62 identifier carries the opening about once in two hundred and
// thirty-eight thousand characters. A base64 payload — a certificate, an
// embedded image, a JWT signature — carries the opening and thirty-two
// characters of a body behind it about once in seven hundred thousand, two of
// its sixty-four characters being ones no body is written with. Hexadecimal and
// uppercase base32 carry it never: the first writes neither the i nor the o,
// and the second writes no lowercase letter at all.
//
// What is taken in any of them is thirty-five characters of a value that was
// already opaque, and it is a token's format exactly: nothing is left in the
// text to tell the two apart, so a pattern letting that run through would let a
// real token through with it.
//
// A boundary would turn every one of them away, on either side, since a run
// carrying the opening partway along carries a character of the alphabet on
// both sides of what a candidate covers. Both are declined above and it is
// worth saying what each costs, since the two costs are not the same. A match
// that fails a boundary is not trimmed by it but dropped whole: the demand in
// front costs the token written as CARGO_REGISTRY_TOKEN_cio..., and the demand
// behind costs the token a letter or a digit is written straight after — a
// column limit that cut a line and joined the next to it, a token concatenated
// into an identifier. Neither is a shape nobody writes, and what is on the
// other side of the trade is thirty-five characters of an onion address or of a
// certificate. A credential left in the output whole is the failure this
// library is for, and a redaction reaching into an opaque run is not.
// Test_CratesIOToken_aRunOfTheAlphabetAroundTheOpening pins the shapes.
//
// The longer form is reached by none of them, and not for the reason the
// shorter form's counts suggest. Base62, standard base64 and base32 write no
// underscore at all, so a run in any of them holds no cio_tp_ at whatever
// length it runs; base64url writes one, and there the seven characters the
// prefix comes to stand about once in four million million characters.
//
// What reaches a span is never a word either: thirty-two unbroken letters and
// digits written behind the three is longer than anything prose is written in.
//
// The value crates.io issued before the prefix existed is not read, and there is
// nothing left to read: HashedToken::parse rejects a string that does not open
// with the prefix, so a token carrying none authenticates nothing today. Were
// one read it would be thirty-two characters of the same Alphanumeric with
// nothing in front of them, which is the shape of every identifier, cache key
// and content hash a caller passes through — the loose grammar this package
// declines rather than the unlucky one.
// Test_CratesIOToken_aBodyWithNoPrefix pins the decision so that reading it is
// a change somebody argues for rather than one somebody notices afterwards.
//
// referenceCratesIOTokenAt in builtin_crates_io_token_test.go states the same
// grammar the plain way, spelling both prefixes, both counts and the character
// class again so that the two are changed together, and the fuzz target beside
// it holds this scan to that statement. It is written out rather than built on
// an expression, and it says there what settled that: the opening is written in
// the same alphabet as the body behind it, so every position of a run of that
// alphabet is a candidate an engine hands the rest of the input to.
var cratesIOToken = newBuiltin("crates-io-token", &cratesIOTokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := cratesIOTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], cratesIOTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not, for the
		// reason the rationale above gives: the body is written in an alphabet
		// holding every character of the opening, so a token can begin inside the
		// body of the one before it.
		offset = anchor + 1

		// The guard stands although the index below is zero, so that the byte
		// the search stops at and the place a candidate begins stay two
		// declarations rather than one: a scan reading the opening back from a
		// later byte would read behind the input without it.
		if anchor < cratesIOTokenAnchorIndex {
			continue
		}
		start := anchor - cratesIOTokenAnchorIndex
		if !strings.HasPrefix(src[start:], cratesIOTokenOpening) {
			continue
		}

		// The longer form first, and at most one of the two is read here. Its
		// infix is written in no body, so a candidate carrying it is no API
		// token at whatever length it runs and there is nothing to fall back
		// to.
		body := start + len(cratesIOTokenOpening)
		chars := cratesIOAPITokenChars
		if strings.HasPrefix(src[body:], cratesIOTrustedPublishingInfix) {
			body += len(cratesIOTrustedPublishingInfix)
			chars = cratesIOTrustedPublishingTokenChars
		}

		end := start + chars
		if end > len(src) {
			// The input ends inside this candidate, so the count that is the
			// whole of what tells it from anything else written behind the
			// prefix cannot be taken here. The infix is settled either way: a
			// candidate reaching its own count has the four characters of it
			// to read, and one that does not is held from here regardless of
			// which form it would have become.
			retain = min(retain, start)
			continue
		}
		if isCratesIOTokenBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// cratesIOTokenOpening is what every token of either form opens with, and
	// what the scan reads back from its anchor. It is TOKEN_PREFIX, the string
	// the API token generator writes in front of what it draws from
	// Alphanumeric, and the first three characters of the Trusted Publishing
	// prefix as well. Test_cratesIOTokenOpening holds it to both.
	cratesIOTokenOpening = "cio"

	// cratesIOTrustedPublishingInfix is what a Trusted Publishing token carries
	// between the opening and its body. Both of its underscores are characters
	// no body is written with, which is the whole of what tells the two forms
	// apart and is why the scan reads only one of them at a candidate.
	cratesIOTrustedPublishingInfix = "_tp_"

	// cratesIOTrustedPublishingPrefix is the prefix such a token opens with,
	// AccessToken::PREFIX. It is built from the two parts above rather than
	// written out again, so that the openings the scan reads and the tail below
	// cannot come to disagree about what a prefix is.
	cratesIOTrustedPublishingPrefix = cratesIOTokenOpening + cratesIOTrustedPublishingInfix

	// cratesIOTokenAnchor is the byte the scan searches the input for and
	// cratesIOTokenAnchorIndex is where it stands in either opening, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what made it
	// this byte and what the choice is close against.
	cratesIOTokenAnchor      = 'c'
	cratesIOTokenAnchorIndex = 0

	// cratesIOAPITokenBodyChars is TOKEN_LENGTH, the argument the API token
	// generator hands Alphanumeric.
	cratesIOAPITokenBodyChars = 32

	// cratesIOTrustedPublishingRawChars is AccessToken::RAW_LENGTH, the
	// characters such a token draws from Alphanumeric, and
	// cratesIOTrustedPublishingBodyChars is those and the one character of
	// checksum written behind them — what the parser demands and what the scan
	// reads. They are declared apart from the count above because crates.io
	// declares them apart: the two come to the same number today and neither
	// generator's argument moves the other's.
	cratesIOTrustedPublishingRawChars  = 31
	cratesIOTrustedPublishingBodyChars = cratesIOTrustedPublishingRawChars + 1

	// cratesIOAPITokenChars is the whole of an API token, thirty-five
	// characters, and cratesIOTrustedPublishingTokenChars the whole of a
	// Trusted Publishing one, thirty-nine.
	// Test_cratesIOTokenChars holds both to those numbers.
	cratesIOAPITokenChars               = len(cratesIOTokenOpening) + cratesIOAPITokenBodyChars
	cratesIOTrustedPublishingTokenChars = len(cratesIOTrustedPublishingPrefix) + cratesIOTrustedPublishingBodyChars
)

// isCratesIOTokenBody reports whether s is a token's body: the base62 alphabet
// throughout, which is what rand's Alphanumeric draws from.
//
// The count is the caller's here where the RubyGems scan beside it hands its
// helper one, and for a reason rather than by oversight: there are two counts,
// one per form, and which of them a body is held to is settled where the form
// is. A helper taking the count would be handed a number the caller had already
// cut the slice to.
func isCratesIOTokenBody(s string) bool {
	for i := range len(s) {
		if !isBase62Byte(s[i]) {
			return false
		}
	}
	return true
}

// cratesIOTokenPrefixes is what a candidate opens with, one entry a form. They
// are built from the parts above rather than written out again, for the reason
// builtin_scan.go gives: a table of prefixes kept beside the declarations a scan
// reads is one that can come to disagree with them, and what a stream does with
// the form it was not told about is release the characters a token opens with.
var cratesIOTokenPrefixes = []string{cratesIOTokenOpening, cratesIOTrustedPublishingPrefix}

// cratesIOTokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var cratesIOTokenTail = newPrefixTail(cratesIOTokenPrefixes...)
