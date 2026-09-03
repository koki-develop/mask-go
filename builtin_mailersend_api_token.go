package mask

import "strings"

// MailerSendAPIToken locates MailerSend API tokens: the prefix mlsn. and the
// thirty or more letters and digits behind it, redacted to the end of the run
// they stand in. One token sends mail from the account's verified domains and
// reaches the account endpoints behind the same API, within the scopes it was
// created with.
//
// A token is located wherever it is written, with no word boundary either side.
// So text of that shape is redacted whether or not MailerSend issued it. A
// space, a dot, a hyphen, an underscore or a run of fewer than thirty letters
// and digits ends the reading, so text as it is ordinarily written is not
// affected. Where the run carries on past the thirtieth character, it is
// redacted to its end.
//
// Its name is "mailersend-api-token".
func MailerSendAPIToken() Pattern { return mailerSendAPIToken }

// MailerSend states the prefix and nothing else about the shape of a token. It
// states the prefix three times over, each of them its own: the CLI
// documentation writes MAILERSEND_API_TOKEN="mlsn.your_token_here", the Claude
// skill MailerSend publishes for that CLI writes the same placeholder at its
// auth and profile commands, and the Python SDK MailerSend publishes guards its
// own commits with git secrets --add 'mlsn\.[A-Za-z0-9._-]+', beside a second
// rule for the SMTP passwords the account issues under a prefix of its own.
//
// API token is MailerSend's own term for what is located here: the title of the
// help page kept on one, the section of the dashboard one is created in, the
// object its HTTP reference creates and deletes, and the variable
// MAILERSEND_API_TOKEN its CLI reads one out of. An account holds more than one
// — a token per set of scopes, and a token cut for a single verified domain —
// and each of them is the same string with no mark on it to tell one from
// another, so those put no boundary between patterns: a caller cannot act on a
// distinction the value does not carry.
//
// The alphabet and the count rest on betterleaks, which reads this format as
// the prefix and thirty to a hundred characters of letters and digits, marks
// the rule high confidence and carries a call to MailerSend's own api-quota
// endpoint to tell a live token from a dead one. It is the whole of what states
// a shape here: gitleaks, trufflehog, noseyparker, secretlint, leaktk and 2ms
// read this format not at all, and MailerSend's own documentation gives a
// placeholder where a length would be.
//
// One clause of that rule this scan does not read: betterleaks drops a match
// whose body falls below an entropy of three and a half. Entropy is no part of
// the format but what a scanner puts between its rule and the person who will
// go and look — a false positive costs that person a minute, where a redaction
// declined costs a credential in a log, so a clause written to keep a value out
// of a report is not one to keep it in the text. What it turns away is the body
// of few distinct characters, which thirty random base62 characters practically
// never are and a placeholder or a stand-in typed by hand often is — and where
// such a body stands behind this prefix there is no reading of it that is not a
// token. Declining it spares a second walk over every candidate besides.
// Test_MailerSendAPIToken_aBodyOfFewCharacters pins the divergence.
//
// The guard in the Python SDK is not a second statement of the alphabet, and
// reading one off it would be reading a net as a format. It admits the dot, so
// what it matches at mlsn. runs on through a host name and a sentence alike —
// which is what a pre-commit net is written to do, since catching too much
// costs its author a moment and catching too little costs a token. What it
// settles is the prefix, which it spells exactly; the class behind that prefix
// is an upper bound on a body and no reading of one. So the alphabet is base62,
// isBase62Byte in builtin_scan.go, the letters of both cases with the digits.
// What base62 leaves out against that bound is three characters: the dot, the
// hyphen and the underscore. A token carrying any of them is read only as far
// as the first — located short where thirty characters stand in front of it,
// and not located at all where fewer do — which is the cost of reading the one
// alphabet anybody states rather than a wider one nobody does, and where to
// look first if a token is ever seen coming through in pieces.
//
// The dot is the one of the three no evidence could widen a body to. It is what
// the prefix closes with, so a body admitting it would read on through the host
// name or the sentence a token is written in, and two candidates could then
// read the same run — which is what the scan below rests on being impossible.
//
// The count is read as a floor rather than exactly, and the hundred betterleaks
// closes its range at is not read at all. Neither end is MailerSend's: both are
// a scanner's reading of the tokens it was written against. A ceiling read
// exactly would locate the first hundred characters of a longer token and leave
// the rest of it in the output, which is the failure a floor cannot have: read
// as a floor, a token of any length at or above thirty is located to the end of
// its run, whatever MailerSend lengthens it to.
//
// What the floor costs is the token shorter than it. A line cut to a column
// limit partway through a token leaves a prefix and a body too short to be one,
// and the characters written before the cut stay in the output. Thirty is where
// the one source that states a length puts the shortest body, so lowering it
// would rest on nothing and raising it would turn away a token that source
// says is issued.
//
// The prefix is read in the one case MailerSend writes it. A prefix is the
// whole of what tells this format from text, so reading it in either case buys
// nothing — MLSN. is no form a token is issued in — and costs a candidate
// opened at every uppercase spelling.
//
// There is no boundary on either side of a match. A boundary in front drops
// rather than trims the match wherever a token is written against a word
// character, which is what MAILERSEND_API_TOKEN_mlsn... is and what a shell
// writes into a log line. One behind drops rather than trims as well: a run
// ends at the first character base62 turns away, and the underscore is one of
// those and a word character both, so the token an underscore is written
// against would go through whole. What may stand either side is held back by
// the character class and the floor alone.
//
// The byte the scan searches the input for is the dot the prefix closes with.
// Over the log line these benchmarks are written on it stands twice, against
// three n, four s and six each of m and l — the four letters of the opening are
// the letters the vendor's own name, its host name and the words of the message
// around them are spelled with, where the dot stands only inside the host name.
// What the dot costs is a line dense in host names, addresses or version
// numbers, which stops the search once a dot; each of those stops is turned
// away by the single byte four characters in front of it, which has to be an m
// and in such text is not.
//
// The scan resumes one byte past the start of a candidate whether that
// candidate became a token or not, which it reaches by stepping one byte past
// the anchor; builtin_scan.go sets out why those are the same step. The four
// letters of the prefix belong to the alphabet a body is written in, so a body
// may close with mlsn and the dot of the next token stand directly behind it: a
// token can begin four characters before the one in front of it ends, and
// consuming a match would step over it. The two spans overlap where it happens,
// and Masker.locate resolves them.
//
// The scan keeps no cursor over the run it reads and needs none. The prefix
// closes with the dot, which no body is written with, so every body begins
// where a run begins and no two candidates can read the same run — which is
// what rules out the quadratic input a line dense in prefixes would otherwise
// be, and Test_mailerSendAPITokenPrefix_runsDoNotOverlap names the character it
// rests on.
//
// What this pattern over-matches on is thirty letters and digits written behind
// the prefix, and the dot is what keeps the shapes that reach it few. Neither
// base64url nor standard base64 writes a dot, so no encoded payload can carry
// this prefix inside itself however long it runs, and neither can a digest, a
// git SHA or an MD5 standing on its own. What is left is the boundary between
// two dotted segments — a JOSE header or payload whose encoding happens to
// close on mlsn, with thirty base62 characters opening the segment behind it —
// and the host name whose label mlsn stands in front of a label of thirty
// unbroken letters and digits. Both are paid rather than avoided, because there
// is nothing left to tell either from a token: a scan declining thirty letters
// and digits behind this prefix declines every token MailerSend issues.
// Test_MailerSendAPIToken_theShapesWrittenByAccident pins them.
//
// A digest written behind the prefix is that same reading and is worth naming
// on its own, because the floor sits below the three digests a log is most
// often written with: an MD5 is thirty-two characters, a git SHA forty and a
// SHA-256 sixty-four, all of them base62 and none of them carrying anything
// that ends a run, so mlsn. and any of the three is a token's format exactly.
// Test_MailerSendAPIToken_aDigestBehindThePrefix pins that, and what holds the
// other side of it is the prefix: a digest reaches nothing without the five
// characters written in front of it.
//
// What reaches a span is never prose. Thirty unbroken letters and digits are
// what a digest or an encoded field is written as rather than what a word is,
// and mlsn is no word for the dot in front of them to stand behind.
//
// Two other MailerSend values are worth naming, since both are credentials and
// neither reaches this scan. The SMTP password an account issues is written
// with a prefix of its own, mssp., which carries no mlsn. to be found at, and
// no source states a shape for what stands behind it — a credential this
// pattern's name does not cover. The other is the API token MailerSend issued
// before it wrote a prefix on any of them, which was JOSE-shaped: its own
// Firebase extension still gives eyJ and a row of asterisks as the example of
// one. That one the name does cover and the grammar cannot, because the grammar
// is the prefix and such a token carries none — so what this pattern locates is
// the prefixed format and no more.
//
// referenceMailerSendAPITokenFind in builtin_mailersend_api_token_test.go keeps
// the grammar as a regular expression, spelling the prefix, the floor and the
// alphabet again so that the two are changed together, and the fuzz target
// beside it holds this scan to that expression.
var mailerSendAPIToken = newBuiltin("mailersend-api-token", &mailerSendAPITokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two.
	retain := mailerSendAPITokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], mailerSendAPITokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not,
		// for the reason the rationale above gives: a body may close with the
		// four letters the prefix opens with, so a token can begin four
		// characters before the end of the one before it.
		offset = anchor + 1

		if anchor < mailerSendAPITokenAnchorIndex {
			continue
		}
		start := anchor - mailerSendAPITokenAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != mailerSendAPITokenPrefix[0] || !strings.HasPrefix(src[start:], mailerSendAPITokenPrefix) {
			continue
		}

		body := start + len(mailerSendAPITokenPrefix)
		end := base62RunEnd(src, body)
		if end == len(src) {
			// The run reaches the end of the input, so neither where the body
			// ends nor whether it is long enough to be one is settled here:
			// what comes next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if end-body >= mailerSendAPITokenBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// mailerSendAPITokenPrefix is what every API token opens with, and what the
	// scan reads back from its anchor. Its four letters belong to the alphabet
	// a body is written in, which is what lets one token begin inside another
	// and is why the scan resumes a byte along; the dot it closes with does
	// not, which is what keeps two candidates from ever reading the same run.
	// Test_mailerSendAPITokenPrefix holds it to the first and
	// Test_mailerSendAPITokenPrefix_runsDoNotOverlap to the second.
	mailerSendAPITokenPrefix = "mlsn."

	// mailerSendAPITokenAnchor is the byte the scan searches the input for and
	// mailerSendAPITokenAnchorIndex is where it stands in the prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what makes it
	// this byte and what it costs.
	mailerSendAPITokenAnchor      = '.'
	mailerSendAPITokenAnchorIndex = 4

	// mailerSendAPITokenBodyChars is the count a body is held to, read as a
	// floor rather than exactly. MailerSend states no length at all, and the
	// rationale above says where this one comes from and why the upper end of
	// the range it was read out of is left off.
	mailerSendAPITokenBodyChars = 30
)

// mailerSendAPITokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var mailerSendAPITokenTail = newPrefixTail(mailerSendAPITokenPrefix)
