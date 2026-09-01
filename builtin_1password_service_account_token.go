package mask

import "strings"

// OnePasswordServiceAccountToken locates 1Password service account tokens: the
// prefix ops_, and behind it the account's credentials serialized into a JSON
// object and written out in base64url. One string serves every service account,
// whichever vaults it was granted and whatever it may do with them, so nothing
// in a token says what it reaches.
//
// A token is located wherever it is written, with no word boundary either side,
// and is redacted from its ops_ to the end of the run it stands in. So a token
// written against a word character keeps its span, and a character of the
// token's own alphabet written straight after a token is redacted with it.
//
// Its name is "1password-service-account-token".
func OnePasswordServiceAccountToken() Pattern { return onePasswordServiceAccountToken }

// 1Password states the whole of this format on its own service account security
// page, which is the firmest footing a format can be read on short of the code
// that writes one. The prefix is stated as a prefix rather than shown: the page
// says 1Password uses a unique string format to help code analyzers find
// accidental credential exposure, and that the format uses ops_ as the token
// prefix. The body is stated as well — a token is an authentication string
// representing an object that is serialized and Base64 URL encoded — and the
// page prints a token encoded beside a token decoded, so the encoding can be
// read against what it encodes rather than guessed from a shape.
//
// What the decoded object holds is why a token is worth redacting: the master
// unlock key that decrypts the account's keyset, the Secret Key, the SRP
// verifier the account authenticates with, the address to send them to and the
// email the account is kept under. There is nothing to revoke inside a token
// and nothing that identifies it; the whole of it is the credential.
//
// The three characters behind the prefix are the part of this grammar that is
// derived rather than observed, and they are what tells a token from a name.
// The body encodes a JSON object, so its first two bytes are a brace and a
// quotation mark, and its third is the first character of the first key. Base64
// reads three bytes as four characters and the first three of those four are
// settled by the first two bytes and the top two bits of the third: a brace
// spells e, a brace and a quotation mark together spell y, and the third
// character is I, J, K or L as those two bits run 00 to 11. Every ASCII letter
// carries 01, so every object whose first key opens with a letter encodes to
// eyJ — which is why the anchor is ops_eyJ and does not depend on which key
// 1Password writes first. That matters: the page's own token opens on email and
// the tokens gitleaks carries as examples open on signInAddress, so a scan
// reading further than eyJ would read one account's key order and miss the
// other's. Test_onePasswordServiceAccountTokenHeader encodes the three bytes
// for every value the third can take and holds the claim to them.
//
// The alphabet is base64url, isBase64URLByte in builtin_scan.go: the letters of
// both cases, the digits, the hyphen and the underscore. That is 1Password's
// own word for the encoding, and the printed token agrees — it carries no plus
// and no slash, and it is six hundred and thirty characters, which is two past
// a multiple of four, so it is written without the padding a base64 encoder
// would otherwise close it with. A token that did carry padding would be
// located up to the equals signs and the equals signs left in the output, which
// is nothing: the padding is a function of the length and no part of the
// secret.
//
// The two published rulesets read the same prefix and the same three characters
// and differ from this scan on either side of them. gitleaks reads ops_eyJ and
// two hundred and fifty or more characters of the standard base64 alphabet with
// optional padding, which is the wrong alphabet for a base64url encoding — it
// stops a span at the first hyphen or underscore a token carries. It gets away
// with it because the encoded bytes are ASCII JSON: base64 spells its last two
// characters only where the third byte of a group is one of four values, and a
// JSON object of names, hexadecimal and base64url values holds almost none of
// them, which is why the vendor's own six hundred and thirty character body is
// alphanumeric from end to end — not one hyphen and not one underscore in it.
// Almost none is not none, and where one falls the rest of the token is left in
// the output. kingfisher reads
// the right alphabet but bounds the body at five hundred characters and puts a
// word boundary behind it, which is fewer characters than the vendor's own
// printed token has. This scan reads the run to its end and bounds it nowhere,
// so a token longer than the one 1Password prints is redacted whole.
//
// The count of what follows is read as a floor and not as a count, since no
// length is stated anywhere and none can be: the object carries an email
// address and a sign-in address, both of which are as long as the account made
// them. What the floor is derived from is the two secrets an object has to
// carry to be a credential at all — the master unlock key, a 256-bit key
// written into a JWK as forty-three base64url characters, and the SRP verifier,
// sixty-four hexadecimal characters. A hundred and seven characters of value,
// in an object that has to name and quote both of them, is a hundred and twenty
// bytes at the very least, and a hundred and twenty bytes encode to a hundred
// and sixty characters. The token 1Password prints is six hundred and thirty
// characters of body, which is that object with the email, the Secret Key, the
// sign-in address and the SRP parameters in it as well; the decoded form the
// page prints beside it names a throttle secret and a device identifier too, so
// a token carrying those is longer again.
//
// So the floor is about a quarter of the token 1Password prints, which is the
// room a floor wants — and the room is worth more here than the count would be.
// A token is long enough that the ordinary way to meet half of one is a log
// line or a diff cut to a column limit, and every character short of the floor
// is a token left in the output whole. Two hundred and fifty, the floor
// gitleaks reads, leaves a line cut at two hundred characters unredacted where
// this scan redacts it, and what is redacted there is a whole master unlock
// key. The cases in builtin_1password_service_account_token_test.go pin both
// sides so that it stays a decision on the record.
//
// There is no boundary on either side of a match. A boundary in front would
// drop the whole match rather than trim it wherever a token is written against
// a word character, as OP_SERVICE_ACCOUNT_TOKEN_ops_eyJ... is. One behind
// would drop rather than trim as well, and where it were asked decides what it
// drops. Asked behind the count, it drops the token a letter, a digit or an
// underscore is written against wherever the count closes on one of those, and
// the token whose count closes on the hyphen wherever no word character is
// written against it. Asked behind that run, it drops the token whose body
// closes on a hyphen and nothing else, since every word character belongs to
// base64url — so the character standing behind a run is never one, and a
// boundary is left asking the token's own last character to be one.
//
// The prefix is read in the case 1Password writes it and in no other. It is a
// literal the vendor declares rather than a word that might be capitalized, and
// the three characters behind it are an encoding rather than a spelling: EYJ
// encodes nothing, so a case-insensitive reading buys no token and admits
// OPS_EYJ, which is a shape a shouted identifier can reach.
//
// The scan resumes one byte past the start of a candidate whether it became a
// token or not. Every character of ops_eyJ belongs to the alphabet a body is
// written in — the underscore included, which base64url writes and standard
// base64 does not — so the anchor can stand inside a body and a token can begin
// inside the span of the one before it. Consuming a match would step over such
// a token; the two spans then overlap, which a Masker resolves into one.
//
// Where the run ends is remembered. A run can hold a candidate every seven
// characters — ops_eyJops_eyJ written over and over is one run, not two — and
// each of them reading that run to its end costs time quadratic in the length
// of such a line, so the end is worked out once and reused wherever a body
// begins inside the run already read. That is sound because a body stands a
// fixed four characters past the start of its candidate and candidates only
// move forward, so a body never begins in front of the body of the candidate
// before it. Nothing else about a candidate is a search over the rest of the
// input: one byte of the anchor is searched for and the rest of it compared
// where that byte is found, and the floor is read off the cursor.
// Test_OnePasswordServiceAccountToken_scanIsLinear drives it.
//
// What this pattern over-matches on: a run of base64url characters carrying
// ops_eyJ and a hundred and fifty-seven more characters behind it. Seven
// characters drawn from an alphabet of sixty-four stand where the anchor stands
// about once in four million million characters, and one of the seven is the
// underscore, which standard base64 never writes — so a certificate, a PEM body
// or an embedded image holds no anchor to be found at however long it runs, and
// only a base64url encoding can carry one. What is taken there is a stretch of
// a value that was already opaque to a reader.
//
// What reaches a span is never prose, never a git SHA and never an MD5. A
// digest carries no underscore, so it holds no ops_ to be found at, and neither
// y nor J is a hexadecimal digit. The strings that do carry the prefix are
// snake_case names whose first segment is ops — ops_team and ops_runbook are
// two — and what turns every one of them away is the three characters behind
// it, which no word is spelled with, before the floor is ever reached.
//
// The Secret Key 1Password issues an account is a credential of its own and is
// not read here. It is written A3- and a run of uppercase letters and digits
// divided into groups by hyphens, and it stands inside the object this token
// encodes — so wherever it is written in the clear it is a second value with a
// grammar of its own and a caller who could reasonably want one and not the
// other, which is a pattern to add rather than a name to widen.
//
// referenceOnePasswordServiceAccountTokenFind in
// builtin_1password_service_account_token_test.go states the same grammar with
// no cursor in it, spelling the prefix, the header, the floor and the alphabet
// again so that the two are changed together, and the fuzz target beside it
// holds this scan to that statement.
var onePasswordServiceAccountToken = newBuiltin("1password-service-account-token", &onePasswordServiceAccountTokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := onePasswordServiceAccountTokenTail.start(src)

	// The run a token is read as is worked out once and remembered, for the
	// reason the rationale above gives. The cursor holds the end of the run the
	// last body was read in, and -1 before there has been one, which every body
	// is past.
	runEnd := -1

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], onePasswordServiceAccountTokenAnchorByte)
		if i < 0 {
			break
		}
		at := offset + i

		// The scan resumes here whether this candidate became a token or not, for the
		// reason the rationale above gives: every character of the anchor belongs to
		// the alphabet a body is written in, so a token can begin inside the body of
		// the one before it.
		offset = at + 1

		if at < onePasswordServiceAccountTokenAnchorIndex {
			continue
		}
		start := at - onePasswordServiceAccountTokenAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != onePasswordServiceAccountTokenAnchor[0] ||
			!strings.HasPrefix(src[start:], onePasswordServiceAccountTokenAnchor) {
			continue
		}

		// The body opens at the header, which the anchor has already read, so
		// the run it stands in is the run the header stands in. A body is a
		// fixed distance past the start of its candidate and candidates only
		// move forward, so the walk is repeated only where this body is past
		// what was already read.
		body := start + len(onePasswordServiceAccountTokenPrefix)
		if body >= runEnd {
			runEnd = base64URLRunEnd(src, body)
		}
		if runEnd == len(src) {
			// The run reaches the end of the input, so neither where the object
			// ends nor whether enough of it is here is settled: what comes next
			// either carries the run on or closes it.
			retain = min(retain, start)
		}
		if runEnd-body < onePasswordServiceAccountTokenBodyChars {
			continue
		}
		spans = append(spans, Span{Start: start, End: runEnd})
	}
	return spans, retain
})

const (
	// onePasswordServiceAccountTokenPrefix is what 1Password states it writes in
	// front of every service account token, so that a code analyzer has
	// something to find one by. Every character of it belongs to the alphabet a
	// body is written in, which is what lets one token be written inside another
	// and is why the scan resumes a byte along;
	// Test_onePasswordServiceAccountTokenAnchor holds it to that.
	onePasswordServiceAccountTokenPrefix = "ops_"

	// onePasswordServiceAccountTokenHeader is the three characters the base64url
	// of a JSON object opens with. The rationale above sets out which bits each
	// of them carries and which first keys the third one stands for;
	// Test_onePasswordServiceAccountTokenHeader encodes the bytes and holds the
	// claim to them.
	onePasswordServiceAccountTokenHeader = "eyJ"

	// onePasswordServiceAccountTokenAnchor is what a candidate is read back as,
	// the two above together. Testing both at once rather than the prefix and
	// then the header is what keeps an ordinary line — which carries ops_ in
	// every snake_case name whose first segment is ops — from reaching the body
	// of the loop at all.
	onePasswordServiceAccountTokenAnchor = onePasswordServiceAccountTokenPrefix + onePasswordServiceAccountTokenHeader

	// onePasswordServiceAccountTokenAnchorByte is the byte the scan searches the
	// input for and onePasswordServiceAccountTokenAnchorIndex is where it stands
	// in the anchor, so a candidate begins that many bytes in front of what a
	// search reported. builtin_scan.go says why a scan searches for one byte of
	// what it is looking for rather than for the whole of it; what makes it this
	// byte is that the other six are ordinary lowercase letters and the
	// underscore, each of which stands several times in an environment
	// assignment and in the log line these benchmarks are written on, where a
	// capital J stands nowhere at all.
	onePasswordServiceAccountTokenAnchorByte  = 'J'
	onePasswordServiceAccountTokenAnchorIndex = len(onePasswordServiceAccountTokenPrefix) + 2

	// onePasswordServiceAccountTokenBodyChars is the count a body is held to,
	// read as a floor rather than exactly and counted from the header rather
	// than from behind it. A hundred and sixty is the base64url length of the
	// smallest object that can carry both of the secrets a token is a credential
	// by — the forty-three characters of the master unlock key and the
	// sixty-four of the SRP verifier, named and quoted — which is why it is not
	// a number that can be raised on its own. The rationale above weighs both
	// sides of it.
	onePasswordServiceAccountTokenBodyChars = 160
)

// onePasswordServiceAccountTokenTail is what the scan settles the tail of its
// input by. prefixTail (builtin_scan.go) says what that is and why it is built
// once.
var onePasswordServiceAccountTokenTail = newPrefixTail(onePasswordServiceAccountTokenAnchor)
