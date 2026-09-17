package mask

import "strings"

// AtlasServiceAccountSecret locates the secrets of the service accounts that
// authenticate to the MongoDB Atlas Administration API: the prefix mdb_sa_sk_
// and the forty base64url characters behind it, fifty characters altogether. A
// service account exchanges its client ID and one of its secrets for an access
// token carrying the roles that account holds, so a secret reaches whatever the
// account was granted across an organisation and the projects in it.
//
// A secret is located wherever it is written, with no word boundary either
// side, and exactly fifty characters of it are. So text of that shape is
// redacted whether or not Atlas issued it. A space, a dot, a character outside
// the alphabet or an uppercase prefix ends the reading, so text as it is
// ordinarily written is not affected. A longer run of the alphabet is a secret
// with something written after it, and the secret alone is redacted.
//
// Its name is "atlas-service-account-secret".
func AtlasServiceAccountSecret() Pattern { return atlasServiceAccountSecret }

// Service account secret is MongoDB's own term for the whole of what this
// locates. Its API schema names the object ServiceAccountSecret and the field
// carrying the value secret, the page on replacing one is titled Rotate Service
// Account Secrets, and the limits MongoDB publishes for these accounts are
// headed MongoDB Atlas Service Account Limits. One shape serves every secret:
// an account may hold more than one at a time so that a replacement can be
// brought in before the old one is dropped, and nothing in the string says
// which of them is which, nor how long it has left.
//
// The client ID standing beside a secret is not read here. Atlas writes it
// mdb_sa_id_ and twenty-four hexadecimal characters, so a scan could locate it
// as readily — but the two are the username and the password of one account,
// and a caller keeping a log keyed on which account acted needs the identifier
// left in the text while the secret goes. That is a decision only a boundary
// can hand them, so the identifier belongs to a pattern of its own or to none.
//
// What MongoDB states of the secret is the prefix and stops there. The
// Administration API specification it publishes gives the secret and the masked
// form of it an example apiece, both written mdb_sa_sk_ with the rest elided;
// none of its pages writes a whole secret, and the specification carries no
// length, alphabet or checksum for one today.
//
// So the count and the alphabet are read off the specification as it stood
// earlier, and what still carries them is MongoDB's own changelog rather than
// any version of the specification a reader can open today. Its entry of 19
// December 2024, recorded against API version 2024-11-13, says of every
// operation returning a secret that the property's pattern
// ^mdb_sa_sk_[0-9a-zA-Z_-]{40}$ was removed. That is the source to reopen: the
// published versions carry the example alone, each being kept as the API now
// stands rather than as it was released.
//
// The identifier's own pattern was kept where the secret's was dropped, so the
// removal was aimed at this field rather than at the specification's use of
// patterns, and what it withdrew is MongoDB's undertaking to keep issuing this
// width. It does not say the width changed: a secret is still shown as
// mdb_sa_sk_.
//
// Two other shapes have been declared for this property, and both are older
// than the count read here. MongoDB's own tooling is tested against snapshots
// of the specification taken from its production and its development
// environments, and the two disagree: the production snapshot, which runs to
// API version 2024-08-05, declares the secret mdb_sa_sk_ and a UUID,
// thirty-six characters; the development snapshot, which runs on to 2025-01-01,
// declares forty instead. Development is where the specification is ahead, so
// the forty supersedes the UUID rather than the other way about, and the order
// is the UUID, then the forty, then the declaration withdrawn. What that rules
// out is the reading on which the width became a UUID and the pattern was
// dropped for no longer fitting it.
//
// Reading them in that order rather than by the version they name is what one
// label reading three ways calls for. API version 2024-08-05 carries no pattern
// at all in the specification MongoDB publishes today, forty characters in the
// development snapshot and a UUID in the production one: the label names a
// version of the API, where each file is the whole specification as it stood
// when that file was taken. So a reader who finds the production snapshot first
// has found the oldest of the three rather than the truth about 2024-08-05, and
// the UUID it declares is set aside for its place in the order.
//
// The development snapshot writes its forty without the hyphen and the
// underscore where the changelog writes them with. The wider is read here: a
// body of the narrower alphabet is a body of this one, so base64url locates
// what either declares, where base62 would leave a secret carrying a hyphen in
// the text.
//
// So the UUID is left alone, and what that costs is pinned rather than argued.
// Test_AtlasServiceAccountSecret_aDigestBehindThePrefix writes out that
// mdb_sa_sk_ and a UUID come through whole, so a secret ever issued that way is
// one this scan misses and that case is where it would be noticed.
//
// What the count therefore rests on is the vendor's own former declaration,
// which is firmer than a reading somebody took off values they had seen and
// weaker than a rule the vendor still stands behind. A reader widening either
// should know that is the footing.
//
// The count is read exactly rather than as a floor, and a withdrawn count is
// the reading where that choice is worth arguing: what was withdrawn is the
// undertaking to keep the width, so a body wider than forty is the shape to
// weigh the two readings on. A floor takes such a body whole where an exact
// count redacts its first forty — and forty characters of a longer secret taken
// out of it leave a fragment rather than a credential, which is the same
// nothing an attacker is left with either way. The floor is declined because
// what it pays for that is the reading of every secret of the stated width: a
// body is written in base64url, which holds the hyphen and the underscore, so a
// run does not stop where a word written against a secret begins —
// mdb_sa_sk_<body>_backup is one run to the end — and a floor takes the word
// with the secret where an exact count leaves it, so a reader can still see
// what the field was called.
//
// What an exact count costs instead is the secret cut short of it. A line cut
// to a column limit partway through one leaves a prefix and a body too short to
// be a body, and nothing at all is located: the characters written before the
// cut stay in the output. Test_AtlasServiceAccountSecret_cutShortOfTheCount
// pins that, and a floor would cost it just the same, since a floor of forty is
// forty characters a body must reach.
//
// The alphabet is base64url, isBase64URLByte in builtin_scan.go: the letters of
// both cases, the digits, the hyphen and the underscore. It is the wider of the
// two the declarations above spell.
//
// The prefix is read in the one case MongoDB writes it. It is the whole of what
// tells this format from text, so reading it in either case buys nothing —
// MDB_SA_SK_ is no form a secret is issued in — and costs a candidate at every
// spelling of the environment variable a caller keeps one in.
//
// There is no boundary on either side of a match. One in front would drop the
// whole match rather than trim it wherever a secret is written against a word
// character, as MONGODB_ATLAS_CLIENT_SECRET_mdb_sa_sk_... is. One behind would
// drop rather than trim as well: under an exact count a secret written against
// a forty-first character of the alphabet is still a secret with something
// after it, and a boundary there would locate nothing at all where this scan
// redacts the fifty Atlas issued and leaves the character that belongs to no
// credential in the text. Test_AtlasServiceAccountSecret_nextToWordCharacters
// writes out what a boundary in front would cost and
// Test_AtlasServiceAccountSecret_leavesWhatFollowsAlone what one behind would.
//
// The byte the scan searches the input for is the k of the prefix.
// builtin_scan.go says why a scan searches for one byte of its prefix rather
// than for the prefix itself; here every character of the prefix stands in a
// base64url run one time in sixty-four, so a run opens the same number of
// candidates whichever byte is chosen and what is left to separate them is how
// often each is written in the text a caller is masking. That text is an Atlas
// record, and the vendor's own vocabulary is what settles it: time, msg and the
// host name mongodb.com spell the m four times over, the hexadecimal
// identifiers and the words around them spell the d eleven times and the b
// seven, and the underscore divides the field names five. The k stands twice,
// in disk and in backup, which is the fewest of them. The line those counts are
// read off is held by
// Test_atlasServiceAccountSecretFindBenchmarks_lineTheAnchorWasChosenAgainst.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a secret or not, which is the default and needs no argument.
// It is load-bearing here rather than merely correct: every character of the
// prefix belongs to the alphabet a body is written in, so a secret can begin
// inside the body of the one before it — a prefix written twice with a body
// behind the second is a secret from either of them — and a scan consuming its
// match would step over the second and leave it in the output whole. The two
// spans overlap where it happens, and Masker.locate resolves them.
// Test_AtlasServiceAccountSecret_aSecretBeginningInsideAnother drives that,
// where both candidates become secrets; the case named "a secret inside a
// candidate the body turned away" drives the other half, where the candidate
// stepped over is one the body test rejected, since a scan may consume a match
// it never made.
//
// The scan keeps no cursor and needs none: a candidate reads at most fifty
// bytes and stops, which bounds what it reads with no state to be wrong about.
// That is what rules out a quadratic input here, and it is what the exact count
// buys beyond the discrimination. A scan reading a body to the end of its run
// would have nothing to divide the runs between candidates by — the prefix
// closes with the underscore and the alphabet admits it — so it would need a
// cursor over the run, and a line dense in prefixes would otherwise be walked
// once per candidate in it.
//
// What this pattern over-matches on: forty characters of the alphabet written
// behind the prefix by something other than Atlas. Ten characters have to be
// written, three of them underscores, then forty more with nothing between any
// of them. Prose holds no such run — a body is longer than any word and carries
// no space or punctuation — and hexadecimal, base62, standard base64 and base32
// write no underscore at all, so an identifier, a certificate body or an
// embedded image carries no candidate at however long it runs. What is left is
// base64url, which writes every character of the prefix: there the ten have to
// fall exactly, which is about once in a million million million characters,
// and the forty behind them are in the alphabet by construction.
// Test_AtlasServiceAccountSecret_insideAnOpaqueRun pins it.
//
// The digest is the same over-match taking a value a reader had a use for. The
// hexadecimal digits are base64url and a digest carries nothing that ends a
// run, so a digest of at least forty characters written behind the prefix is a
// secret to this scan: a SHA-256 at sixty-four is redacted for its first forty
// characters and the remaining twenty-four stay in the text, and a SHA-1 at
// exactly forty is redacted whole. What holds the other side of it is the count
// and the prefix — an MD5 at thirty-two is short of a body, as is the
// thirty-six characters of a UUID, whose hyphens the alphabet reads straight
// through — and a digest with nothing in front of it opens no candidate at all.
// The tightening that would rule the long one out is the demand that the run
// stop at the count, and it is declined for what it costs: a secret written
// against a letter, a digit, a hyphen or an underscore answers the count and
// not the demand, so a scan asking for both would locate nothing there and
// leave every character of a secret in the output.
// Test_AtlasServiceAccountSecret_aDigestBehindThePrefix pins each of those.
//
// referenceAtlasServiceAccountSecret in
// builtin_atlas_service_account_secret_test.go keeps the grammar as a regular
// expression, spelling the prefix, the count and the alphabet again so that the
// two are changed together, and the fuzz target beside it holds this scan to
// that expression. An expression is affordable here: the repetition is exact,
// so the machine an engine builds is read once and stops, and the ten character
// literal in front of it is what an engine searches the text for.
var atlasServiceAccountSecret = newBuiltin("atlas-service-account-secret", &atlasServiceAccountSecretTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two, and this format adds nothing to them — a
	// secret whole is a secret finished, since nothing behind the count is
	// read.
	retain := atlasServiceAccountSecretTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], atlasServiceAccountSecretAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a secret or not,
		// for the reason the rationale above gives: the prefix is written in
		// the alphabet a body is, so a secret can begin inside the body of the
		// one before it.
		offset = anchor + 1

		if anchor < atlasServiceAccountSecretAnchorIndex {
			continue
		}
		start := anchor - atlasServiceAccountSecretAnchorIndex

		// The byte the prefix begins with is tested before the prefix is
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != atlasServiceAccountSecretPrefix[0] ||
			!strings.HasPrefix(src[start:], atlasServiceAccountSecretPrefix) {
			continue
		}

		body := start + atlasServiceAccountSecretPrefixChars
		end := start + atlasServiceAccountSecretChars
		if end > len(src) {
			// The input ends inside the body, and the count is the whole of
			// what tells a secret from any other run written behind the prefix.
			retain = min(retain, start)
			continue
		}
		if isAtlasServiceAccountSecretBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// atlasServiceAccountSecretPrefix is what every secret opens with, and what
	// the scan reads back from its anchor.
	atlasServiceAccountSecretPrefix = "mdb_sa_sk_"

	// atlasServiceAccountSecretAnchor is the byte the scan searches the input
	// for and atlasServiceAccountSecretAnchorIndex is where it stands in the
	// prefix, so a candidate begins that many bytes in front of what a search
	// reported. builtin_scan.go says why a scan searches for one byte of its
	// prefix rather than for the prefix itself; the rationale above says what
	// made it this byte. Test_atlasServiceAccountSecretAnchor holds it to
	// standing at this index.
	atlasServiceAccountSecretAnchor      = 'k'
	atlasServiceAccountSecretAnchorIndex = 8

	// The counts a secret is written to. Forty is the count MongoDB's own
	// specification declared for the secret property before the declaration was
	// withdrawn, which the rationale above reads off the changelog; ten is the
	// prefix the scan reads a body from, and fifty is the two together.
	// Test_atlasServiceAccountSecretChars holds the arithmetic to all three.
	atlasServiceAccountSecretBodyChars   = 40
	atlasServiceAccountSecretPrefixChars = len(atlasServiceAccountSecretPrefix)
	atlasServiceAccountSecretChars       = atlasServiceAccountSecretPrefixChars + atlasServiceAccountSecretBodyChars
)

// isAtlasServiceAccountSecretBody reports whether s is the body of a secret:
// exactly atlasServiceAccountSecretBodyChars characters, all of them in the
// alphabet a body is written in.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count being left to the caller to have cut
// correctly.
func isAtlasServiceAccountSecretBody(s string) bool {
	if len(s) != atlasServiceAccountSecretBodyChars {
		return false
	}
	for i := range len(s) {
		if !isBase64URLByte(s[i]) {
			return false
		}
	}
	return true
}

// atlasServiceAccountSecretTail is what the scan settles the tail of its input
// by. prefixTail (builtin_scan.go) says what that is and why it is built once.
var atlasServiceAccountSecretTail = newPrefixTail(atlasServiceAccountSecretPrefix)
