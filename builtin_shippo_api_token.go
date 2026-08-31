package mask

import (
	"slices"
	"strings"
)

// ShippoAPIToken locates the API tokens Shippo issues, in either of the two
// modes it issues them for: the prefix shippo_live_ or shippo_test_ and the
// forty or more hexadecimal characters behind it, redacted to the end of the
// run they stand in. A live token buys postage labels and reads the shipments,
// addresses and carrier accounts of the account it belongs to; a test token
// reaches the test data of that same account.
//
// A token is located wherever it is written, with no word boundary either side.
// So text of that shape is redacted whether or not Shippo issued it. A space, a
// letter past f, an underscore, or a run of fewer than forty hexadecimal
// characters ends the reading, so text as it is ordinarily written is not
// affected. Where the run carries on past the fortieth character, it is
// redacted to its end.
//
// Its name is "shippo-api-token".
func ShippoAPIToken() Pattern { return shippoAPIToken }

// Shippo states the prefixes and stops there. Its authentication guide says
// that live keys begin with shippo_live_ and that test keys begin with
// shippo_test_, and the release note that introduced the format says of the two
// together that all tokens will now begin with shippo_live_ or shippo_test_.
// Neither gives a length, an alphabet or a checksum, and the only whole token
// any Shippo page writes is the placeholder shippo_test_token, which the
// authentication example puts where a key goes. Its own client library asks
// nothing more of a token than that it opens with shippo_, which is where the
// library decides whether to send it as one.
//
// So everything behind the prefixes is read off the rulesets, and five of them
// carry this format at one shape: gitleaks reads shippo_live_ or shippo_test_
// and exactly forty hexadecimal characters of either case, betterleaks reads
// the same expression with an entropy floor beside it, and trufflehog, trivy
// and Vulnetix read the same forty in lowercase alone. GitHub's secret scanning
// lists the credential twice, as Shippo Live API Token and Shippo Test API
// Token, and GitLab lists both as well; each publishes what it detects rather than the expression it detects
// with, so they corroborate that live and test are the two kinds and add
// nothing to the count.
//
// Five counts the rulesets that state the format, not the rules they state it
// in: Vulnetix states it as two, one to a prefix, and kingfisher states it
// under betterleaks' own name rather than writing one of its own, which is why
// it is carried below rather than counted here.
//
// Nor is it a count of readings taken apart from one another, and that
// difference is worth naming, because a floor read off agreeing sources is only
// as strong as the number of sources that looked. Some of these plainly descend: betterleaks
// writes gitleaks' expression with a delimiter behind it and gitleaks'
// description word for word, trivy writes gitleaks' rule id, kingfisher ships
// betterleaks' rule, and Vulnetix generates its two out of a catalog it keeps
// rather than writing them against tokens. For trufflehog nothing here shows
// where the forty came from, and where the number was first read off a token is
// published by none of them.
//
// That count is read as a floor. A count is read exactly where the vendor wrote
// the length down, or where it is most of what tells a value from the text
// around it; here Shippo wrote no length at all, and the twelve characters of a
// prefix have already done the telling, so a count would buy no discrimination
// it does not have. Were Shippo to lengthen the random part, a scan asking for
// forty exactly would locate the first fifty-two characters of a token and
// leave the rest of it in the output. Read as a floor, a token of any length at
// or above it goes to the end of its run.
//
// The floor is forty, which is the count every rule that reads this format
// carries. It fails downward in
// silence: were a real token shorter, this pattern would locate none at all,
// every test here would pass, and the corpus could not report it either, since
// its tokens are built to the floor and move with it. What would move the floor
// down is a token shorter than forty, written somewhere it can be counted.
//
// What the floor costs when it is right is the token cut short of it. A line
// cut to a column limit partway through one leaves a prefix and a body too
// short to be a body, and nothing is located: the random characters written
// before the cut stay in the output. Test_ShippoAPIToken_cutShortOfTheFloor
// pins that.
//
// The body is read in hexadecimal of either case, which is the reading two of
// the five rulesets take and the one that fails safely. Reading lowercase alone
// would not trim a token carrying an uppercase letter but lose it: the body
// would end at that letter, fall short of forty, and the whole credential would
// stay in the output. The wider class costs the uppercase digest written behind
// a prefix, which is redacted, and Test_ShippoAPIToken_aDigestBehindThePrefix
// pins what that costs.
//
// Widening past hexadecimal is declined: no source reads anything but
// hexadecimal behind these prefixes, so a wider class would rest on nothing.
// What that wagers is a token whose body carried a letter past f — the body
// would end at that letter, fall short of the floor, and nothing at all would
// be located — and what bounds the wager is every rule that reads this format
// agreeing on the class and parting only over its case.
//
// The mode is what stands between the opening and the body, and this scan reads
// the two names Shippo writes rather than reading that there is a name at all.
// A scan reading shippo_ and any lowercase word would open a candidate on
// shippo_ups_account, which is the account id Shippo's own carrier-account
// response carries, and on anything else written the same way.
// What pinning the modes wagers is a mode Shippo has not written yet,
// which would then be left in the output whole; against that stands the release
// note naming these two as the whole of the division and no page since adding a
// third.
//
// The prefix is read in the one case Shippo writes it. It is the whole of what
// tells this format from text, so reading it in either case buys nothing —
// SHIPPO_LIVE_ is no form a token is issued in — and costs a candidate at every
// spelling of the environment variable a caller keeps one in.
//
// There is no boundary on either side of a match. One in front would drop the
// whole match rather than trim it wherever a token is written against a word
// character, as SHIPPO_API_TOKEN_shippo_live_... is. One behind would drop
// rather than trim as well, and where it were asked decides what it drops.
// Asked behind the count, it drops the token a letter, a digit or an
// underscore is written against. Asked behind that run, it drops the token a
// letter past f or an underscore is written against, those being the word
// characters no body admits.
// Test_ShippoAPIToken_reachesTheEndOfTheRun writes all three out.
//
// The tokens Shippo issued before this format are not read. The release note
// says existing implementations with old tokens go on working, and no Shippo
// page states what one looks like: a pattern reading them would have nothing to
// key on but a bare run, which is the loose grammar this package declines
// rather than the unlucky one. The no-match table's bare digests are what that
// decision looks like from the other side.
//
// The byte the scan searches for is the underscore closing shippo_, and the
// opening is read back from it. builtin_scan.go says why a scan searches for
// one byte rather than for the prefix itself; what makes it this byte is that
// everything else the opening is written with is a letter an ordinary line
// carries, and shipping vocabulary carries the p and the s in particular. Over
// the line these
// benchmarks are written on the s stands eight times, the i seven, the p and
// the o six each and the h three, where the underscore stands once. What it
// costs in return is the snake_case name and the environment block, which carry
// underscores a line of prose does not, and shippoAPITokenFindBenchmarks times
// a line of them for that reason.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a token or not, which is the default and needs no argument.
// What it finds there is nothing, and the reason is worth stating: no token of
// this format can begin inside another. Nothing the opening is written with is
// a hexadecimal digit, so no part of it can fall inside a body, and the
// opening stands nowhere in a prefix past its own first character, so no
// opening begins inside a prefix either.
// Test_ShippoAPIToken_noTokenBeginsInsideAnother drives the claim. It is stated
// rather than used: the scan still steps one byte along, because the default
// costs nothing worth an optimisation resting on a claim about the grammar.
//
// The scan keeps no cursor and needs none. The run behind a candidate is read
// to its end however long it is, and what bounds the work is where a body opens
// rather than how far it reads: the underscore a prefix closes with is written
// in no body, so every body begins where a run begins and no two candidates can
// read the same run. That rules out the quadratic input a line dense in
// prefixes would otherwise be, and
// Test_shippoAPITokenPrefixes_runsDoNotOverlap names the character it rests on.
//
// What this pattern over-matches on is forty hexadecimal characters written
// behind one of the two prefixes, and the twelve characters of a prefix are
// what keeps that rare. Base62, standard base64 and base32 write no underscore
// at all, so an identifier, a certificate or an embedded image carries no
// candidate at however long it runs; base64url writes every character of a
// prefix, and there the twelve have to fall exactly — sixty-four raised to the
// twelfth against it, halved by there being two prefixes — before forty of that
// alphabet's sixty-four characters must fall in the sixteen a body is written
// in. What is left outside an encoding is a snake_case name whose segments are
// shippo and one of the two modes, with a digest behind it.
//
// The digest is what makes that reachable, and this pattern pays for it rather
// than ruling it out. A SHA-1 is forty hexadecimal characters exactly, which is
// a body exactly, so a prefix and a SHA-1 is a token to this scan. There is
// nothing left in the text to tell the two apart — the format is that prefix
// and that many of those characters — so a scan declining this would decline
// every token Shippo issues. A longer digest goes with it: the count is a floor
// and the span reaches the end of the run, so a SHA-256 behind a prefix is
// redacted whole rather than cut at the fortieth character. An MD5 at
// thirty-two falls short of the floor and stays in the text, as does a bare
// digest of any length with no prefix in front of it, which is what keeps every
// hexadecimal identifier a caller passes through out of this.
// Test_ShippoAPIToken_aDigestBehindThePrefix pins each of those.
//
// What reaches a span is never prose. A token holds two underscores in its
// first twelve characters and none after, holds no space, and forty unbroken
// hexadecimal characters are longer than anything prose is written in.
//
// referenceShippoAPITokenFind in builtin_shippo_api_token_test.go states the
// grammar again as a walk over every position, spelling the prefixes, the floor
// and the character class out so that the two are changed together, and the
// fuzz target beside it holds this scan to that walk. Why it is a walk rather
// than the expression the grammar states compactly as is written there.
var shippoAPIToken = NewPattern("shippo-api-token", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := shippoAPITokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], shippoAPITokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not.
		offset = anchor + 1

		if anchor < shippoAPITokenAnchorIndex {
			continue
		}
		start := anchor - shippoAPITokenAnchorIndex

		// The byte the opening starts with is tested before the opening is
		// compared. Every anchor the search stops at reaches this line — the
		// underscore closing a mode reaches it as often as the one closing the
		// opening — and all but the few that open a candidate are turned away
		// by one byte where a comparison of the whole opening is a length and a
		// read.
		if src[start] != shippoAPITokenOpening[0] ||
			!strings.HasPrefix(src[start:], shippoAPITokenOpening) {
			continue
		}

		mode := start + len(shippoAPITokenOpening)
		if !opensShippoAPITokenMode(src[mode:]) {
			continue
		}

		body := mode + shippoAPITokenModeChars + 1
		end := shippoAPITokenBodyEnd(src, body)
		if end == len(src) {
			// The run reaches the end of the input, so neither where the body
			// ends nor whether it is long enough to be one is settled here:
			// what comes next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if end-body >= shippoAPITokenBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// shippoAPITokenOpening is what every prefix opens with, and what the scan
	// reads back from its anchor.
	//
	// What it is written with is load-bearing: not one of those characters is a
	// hexadecimal digit, so no part of the opening can fall inside a body and no
	// token can begin inside another.
	// Test_ShippoAPIToken_noTokenBeginsInsideAnother holds them there.
	shippoAPITokenOpening = "shippo_"

	// shippoAPITokenSeparator closes a prefix, behind the mode. It is written
	// in no body, which is what makes every body begin where a run begins and
	// what lets the scan walk one of any length without a cursor.
	shippoAPITokenSeparator = '_'

	// shippoAPITokenModeChars is how many characters name the mode in every
	// prefix, between the opening and the separator. Test_shippoAPITokenModes
	// holds every mode to it.
	shippoAPITokenModeChars = 4

	// shippoAPITokenAnchor is the byte the scan searches the input for and
	// shippoAPITokenAnchorIndex is where it stands in every prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what made it
	// this byte.
	shippoAPITokenAnchor      = '_'
	shippoAPITokenAnchorIndex = 6

	// shippoAPITokenBodyChars is the count a body is held to, read as a floor
	// rather than exactly. The rationale above weighs both the reading and the
	// number.
	shippoAPITokenBodyChars = 40
)

// shippoAPITokenModes is what stands between the opening and the separator in
// the prefix of every token this scan reads: live for the mode a label is
// bought in and test for the mode Shippo returns test data in.
//
// It is the one declaration saying which modes there are, and
// shippoAPITokenPrefixes below reads it rather than writing the prefixes out
// again. builtin_scan.go says why: a table kept beside this is one that can
// come to disagree with it, and what a stream would then do with the mode it
// had not been told about is release the characters a token opens with and
// redact nothing.
var shippoAPITokenModes = []string{"live", "test"}

// opensShippoAPITokenMode reports whether s, which is the text behind the
// opening of a candidate, begins with one of the modes above and the separator
// that closes a prefix.
//
// It is handed the separator to check as well as the mode so that the two are
// read in one place: a mode found with nothing behind it is no prefix, and a
// caller left to check the separator for itself is a caller that can forget to.
// The separator is compared first because it is one byte against a fixed index
// and turns away everything the modes would then be walked for.
func opensShippoAPITokenMode(s string) bool {
	if len(s) <= shippoAPITokenModeChars || s[shippoAPITokenModeChars] != shippoAPITokenSeparator {
		return false
	}
	return slices.Contains(shippoAPITokenModes, s[:shippoAPITokenModeChars])
}

// shippoAPITokenBodyEnd returns where the run of body characters beginning at i
// in src ends, which is len(src) where the run reaches the end of the input.
//
// The walk is this scan's own rather than one of the runs in builtin_scan.go,
// because the class under it is: a hexadecimal class is not one class across
// this package, since whether a body is read in either case or in lowercase
// alone is decided for each format by what its own sources say. A class shared
// under a name for the alphabet rather than for what reads it would silently be
// the wrong answer for one of them.
func shippoAPITokenBodyEnd(src string, i int) int {
	for i < len(src) && isShippoAPITokenBodyByte(src[i]) {
		i++
	}
	return i
}

// isShippoAPITokenBodyByte reports whether c is a hexadecimal digit of either
// case, which is what a token is written in behind its prefix. The rationale
// above says what the case rests on and what reading it narrowly would cost.
func isShippoAPITokenBodyByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// shippoAPITokenPrefixes is what a candidate opens with, one entry a mode.
//
// The modes are read out of shippoAPITokenModes rather than written out again,
// so that a mode admitted there is a mode this knows about.
var shippoAPITokenPrefixes = func() []string {
	prefixes := make([]string, 0, len(shippoAPITokenModes))
	for _, mode := range shippoAPITokenModes {
		prefixes = append(prefixes, shippoAPITokenOpening+mode+string(shippoAPITokenSeparator))
	}
	return prefixes
}()

// shippoAPITokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var shippoAPITokenTail = newPrefixTail(shippoAPITokenPrefixes...)
