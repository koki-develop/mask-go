package mask

import "strings"

// BuildkiteToken locates the tokens Buildkite issues with a prefix of its own:
// API access tokens (bkua_), agent session tokens (bkaa_), agent job tokens
// (bkaj_), unclustered agent tokens (bkar_), agent tokens (bkct_), registry and
// Package Registries temporary tokens (bkpt_), portal tokens (bkpat_), portal
// secrets (bkps_), job acquisition tokens (bkjat_) and the tokens an exchanged
// assertion is minted into (bktx_).
//
// Buildkite documents the prefixes and no length, so this pattern keys on the
// prefix: a token is redacted from it to the end of the run of base64url
// characters behind it, whatever that run comes to, once it is long enough to
// be a body at all.
//
// A token is located wherever it is written, with no word boundary either side.
// So a token written against a word character keeps its span, and a character
// of the token's own alphabet written straight after a token is redacted with
// it.
//
// Its name is "buildkite-token".
func BuildkiteToken() Pattern { return buildkiteToken }

// What Buildkite states of this format is the prefixes, and it states them
// carefully: the token security page carries a section per kind of token, each
// naming the prefix and the words the prefix is the acronym of — bkua_ for a
// Buildkite user access token, bkaa_ for an agent access token, bkar_ for an
// agent registration token, bkct_ for a cluster token, and so on through the
// registry, portal and job acquisition tokens. The tenth is stated elsewhere:
// the token exchange page says a signed assertion is exchanged at
// POST /oauth/token for a short-lived Buildkite API token prefixed bktx_.
//
// It states neither a length nor an alphabet. The prose gives none, and the
// code Buildkite publishes beside it — the agent, the CLI, the Terraform
// provider and the MCP server — carries a token from a flag to an Authorization
// header without ever parsing one, so there is no minting call and no parser to
// read a count off. What each section does draw is the body as a row of
// asterisks, and those rows turn out to be the lengths: fifty-three for bkua_,
// seventy-five for bkaa_, three hundred and thirty-three for bkaj_,
// seventy-three for bkar_ and for bkct_, a hundred and ninety-nine for bkpt_,
// fifty-four for bkpat_, sixty-four for bkps_ and fifty-three for bkjat_.
// bktx_ is drawn as an ellipsis.
//
// The rulesets are what says so, and are the whole of what states a shape here.
// betterleaks reads seven of the prefixes under one rule, each over
// [A-Za-z0-9_-] at a count exactly, and its seven counts are seven of the
// widths above. It reads bkua_ under a rule of its own, over [a-z0-9] at forty
// characters or at fifty-three — the second of which is that prefix's width.
// trufflehog reads bkua_ at forty and nothing else. Neither covers bkjat_ or
// bktx_.
//
// The alphabet is base64url, isBase64URLByte in builtin_scan.go: the letters of
// both cases, the digits, the hyphen and the underscore. That is what
// betterleaks admits behind seven of the ten prefixes, hyphen and underscore
// both. The one kind read narrower there — bkua_, over lowercase and digits
// alone, which is what trufflehog admits behind it too — is read at the wider
// alphabet here rather than at its own. An alphabet a kind is read at
// separately is a second grammar to keep in step with the first, and what it
// would buy is the few characters a match reaches past a bkua_ token written
// against a hyphen. What it would risk is the other side of the same
// arithmetic: a body of a kind nothing states an alphabet for, cut at the first
// character the narrower reading turns away, with the rest of the credential
// left in the output.
//
// The count is read as a floor and not as a count, and one floor serves every
// kind rather than the counts above being read one apiece. A count is read
// exactly where it is most of what tells a value from the text around it; here
// the prefix is doing that work, and none of the counts is Buildkite's — each
// is a scanner's reading of a row of asterisks. bkua_ is the worked case for
// what that is worth: betterleaks carries two lengths for that one prefix,
// forty and fifty-three, because the length changed. A scan holding it to the
// earlier count exactly would have located the first forty characters of every
// token issued after the change and left thirteen of it in the output. Read as
// a floor, a token of any length at or above it is located to the end of its
// run, whichever kind it is and whatever Buildkite lengthens it to.
//
// The floor is forty, the shortest body attested of any kind, so that no kind
// is turned away for being short. What that costs is the token shorter than it,
// in two ways worth keeping apart. A line cut to a column limit partway through
// a token leaves a prefix and a body too short to be one, and the characters
// written before the cut stay in the output; that is what a floor costs
// everywhere. The other is this pattern's own: a kind written shorter than
// forty would be located nowhere at all rather than located short, and two
// kinds have no length from any source — bkjat_, which Buildkite draws at
// fifty-three, and bktx_, which it draws not at all. The cases in
// builtin_buildkite_token_test.go pin both so that they stay decisions on the
// record.
//
// Ten prefixes make one pattern because a caller has one decision to make about
// all of them. Every one of them names a secret that authenticates — there is
// no counterpart here published by design, as a publishable key is — so no
// caller enables one of these and not another, and none of them is the
// identifier a log is kept for. Buildkite's own term for the whole is what this
// pattern is named after: the page enumerating them calls them Buildkite
// tokens, and a caller reaching for the vendor would otherwise have to know all
// ten to redact what it issues.
//
// The one bk value left out is bktr_, which stands in the URL of a pipeline
// trigger. Buildkite does not call it a token, does not enumerate it among
// them, and prints it in the middle of a webhook endpoint rather than as a
// credential of its own — so a pattern locating it would locate more than
// "buildkite-token" names, and the name is what the boundary is held to. It is
// written in the same alphabet as the rest, so a caller who wants it redacted
// has MustRegexp.
//
// There is no boundary on either side of a match. A boundary in front would
// drop the whole match rather than trim it wherever a token is written against
// a word character, as BUILDKITE_API_TOKEN_bkua_... is, and one behind it would
// drop a token followed by a character of the token's own alphabet — which,
// since the span already reaches to the end of the run, is every token with
// anything written against it.
//
// The scan searches for the k of the opening rather than for the underscore
// closing a prefix, and the reason is not rarity. A prefix here is bk, a kind
// of two or three characters, and the underscore, so the underscore stands at
// two different depths depending on the kind — and an anchor a scan reads a
// candidate back from has to stand at one index in every prefix it can match.
// Only the two characters of the opening do. Which of the two is searched for
// is then rarity, and it is the k: over the log line these benchmarks are
// written on the b stands six times against the k's one. One byte of the
// opening is compared at a candidate because the anchor is the other, which is
// what Test_buildkiteTokenAnchor holds the opening to two characters for.
//
// The scan resumes one byte past the start of a candidate whether it became a
// token or not, which it reaches by stepping one byte past the anchor;
// builtin_scan.go sets out why those are the same step. Every character of a
// prefix belongs to the alphabet a body is written in, the underscore closing
// it included, so a prefix can stand inside a body and a token can begin inside
// the span of the one before it. Consuming a match would step over such a
// token; the two spans then overlap, which a Masker resolves into one.
//
// Where the run ends is remembered. The prefix being written in the body's own
// alphabet is what makes that necessary: bkua_ written over and over is one run
// and not a run apiece, so a run can hold a candidate every five characters,
// and each of them reading that run to its end costs time quadratic in the
// length of such a line. The end is worked out once and reused wherever a body
// begins inside the run already read. That is sound while a body never begins
// in front of the body of the candidate before it, and none can: a candidate
// standing one byte further along carries a kind at most one character shorter,
// so its body stands where the last one did or past it.
// Test_buildkiteTokenKinds_bodyNeverMovesBack holds the kinds to the one thing
// that argument rests on, and Test_BuildkiteToken_scanIsLinear drives it.
//
// What this pattern over-matches on: a prefix written inside a longer run of
// base64url with forty characters behind it. The underscore is what makes that
// rare. Standard base64 writes none at all, so a certificate, a PEM body or an
// embedded image carries no prefix to be found at however long it runs, and
// only a base64url encoding can hold one. There the eight five-character
// prefixes stand about once in a hundred and thirty million characters and the
// two six-character ones far more rarely again, and the run from such a prefix
// to the end of the encoding is then redacted. What is taken is a stretch of a
// value that was already opaque to a reader.
//
// What reaches a span is never prose, a git SHA or an MD5. A digest carries no
// underscore, so it holds no prefix to be found at however long it runs, and no
// word is spelled bk with two or three letters and an underscore behind them. A
// space, a dot and a slash all end a run, so a sentence and a path are turned
// away by the floor long before forty characters of one have been read.
//
// What the floor leaves is the identifier long enough to reach it. The alphabet
// holds the underscore and the hyphen, so snake_case and kebab-case run through
// it unbroken, and a name opening with one of these prefixes and carrying forty
// more characters of letters, digits, underscores and hyphens is redacted —
// bkct_ and a forty-character description of a cluster is that shape. It is the
// residue the Anthropic scan is left with as well, and what has to be written to
// reach it is narrower here: two or three characters no word closes with,
// standing between bk and an underscore. Raising the floor is what would rule it
// out and is not available, since forty is the shortest body attested of any
// kind and a higher floor would turn a real API access token away.
// Test_BuildkiteToken_anIdentifierBehindThePrefix pins it.
//
// referenceBuildkiteTokenFind in builtin_buildkite_token_test.go states the same
// grammar with no cursor in it, spelling the opening, the kinds, the separator,
// the floor and the alphabet again so that the two are changed together, and the
// fuzz target beside it holds this scan to that statement.
var buildkiteToken = NewPattern("buildkite-token", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := buildkiteTokenTail.start(src)

	// The run a body is read as is worked out once and remembered, for the
	// reason the rationale above gives. The cursor holds the end of the run the
	// last body was read in, and -1 before there has been one, which every body
	// is past.
	runEnd := -1

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], buildkiteTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not, for
		// the reason the rationale above gives: a prefix is written in the alphabet
		// a body is, so a token can begin inside the body of the one before it.
		offset = anchor + 1

		if anchor < buildkiteTokenAnchorIndex {
			continue
		}
		start := anchor - buildkiteTokenAnchorIndex

		// One byte is the whole of the opening left to compare, since the anchor
		// is the other. Every anchor the search stops at reaches this line, and
		// all but the few that open a candidate are turned away here before any
		// kind is looked for.
		if src[start] != buildkiteTokenOpening[0] {
			continue
		}

		body := buildkiteTokenBodyAt(src, start+len(buildkiteTokenOpening))
		if body < 0 {
			continue
		}

		// A body never begins in front of the body of the candidate before it,
		// which the rationale above sets out, so the walk is repeated only
		// where this body is past what was already read.
		if body >= runEnd {
			runEnd = base64URLRunEnd(src, body)
		}
		if runEnd == len(src) {
			// The run reaches the end of the input, so neither where the body
			// ends nor whether it is long enough to be one is settled here:
			// what comes next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if runEnd-body >= buildkiteTokenBodyChars {
			spans = append(spans, Span{Start: start, End: runEnd})
		}
	}
	return spans, retain
})

// buildkiteTokenBodyAt returns where the body of the candidate whose kind
// begins at kind in src begins, and -1 where no prefix stands there.
//
// The kinds are of two lengths, so the separator can stand at either of two
// depths, and which one it stands at is what says how long the kind is. The
// separator is compared before the kind is: it is one byte where a kind is a
// length and a read, so a position opening no candidate is turned away by a
// byte at every entry of the table.
//
// The first entry that fits is the answer, and no second one can fit beside it.
// Two of the same length would have to be the same string, and where one stands
// at the front of a longer one the longer one carries a character of its own
// where the shorter one wants the separator. The second of those rests on no
// kind being written with the separator, which Test_buildkiteTokenKinds holds
// them to.
func buildkiteTokenBodyAt(src string, kind int) int {
	for _, k := range buildkiteTokenKinds {
		end := kind + len(k)
		if end < len(src) && src[end] == buildkiteTokenSeparator && src[kind:end] == k {
			return end + 1
		}
	}
	return -1
}

// buildkiteTokenKinds is what stands between the opening and the separator, one
// entry a kind of token, spelled as Buildkite spells the acronym: ua for a user
// access token, aa for an agent access token, aj for an agent job token, ar for
// an agent registration token, ct for a cluster token, pt for a package
// registries token, ps for a portal secret, pat for a portal access token and
// jat for a job acquisition token. tx is the exception: the token exchange page
// gives it as a prefix without saying what its letters stand for.
//
// It is the one place they are written. The prefixes below are built from it,
// so a kind added here is a kind the scan finds and a kind the tail of a stream
// is settled by; a table written out beside it is one that can come to disagree
// about which kinds there are, and what a stream would then do with the kind it
// had not been told about is release the characters a token opens with.
//
// Two tests hold what the scan reads out of it. Test_buildkiteTokenKinds asks
// that no kind be written twice, that none be written with the separator —
// which is what lets the walk above take the first entry that fits — and that
// every character of one belong to the alphabet a body is written in, which is
// what lets a token begin inside the one before it.
// Test_buildkiteTokenKinds_bodyNeverMovesBack asks that no two kinds differ in
// length by more than one character, which is what the run cursor rests on.
var buildkiteTokenKinds = []string{"ua", "aa", "aj", "ar", "ct", "pt", "ps", "tx", "pat", "jat"}

// buildkiteTokenPrefixes is what a candidate opens with, one entry a kind.
var buildkiteTokenPrefixes = func() []string {
	prefixes := make([]string, 0, len(buildkiteTokenKinds))
	for _, kind := range buildkiteTokenKinds {
		prefixes = append(prefixes, buildkiteTokenOpening+kind+string(buildkiteTokenSeparator))
	}
	return prefixes
}()

const (
	// buildkiteTokenOpening is what every prefix opens with, and what the scan
	// reads back from its anchor. The kind and the separator stand behind it,
	// so a prefix is two characters longer than its kind. Both of its
	// characters belong to the alphabet a body is written in, which is what
	// lets one token begin inside another and is why the scan resumes a byte
	// along.
	buildkiteTokenOpening = "bk"

	// buildkiteTokenAnchor is the byte the scan searches the input for and
	// buildkiteTokenAnchorIndex is where it stands in every prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says why the
	// separator cannot be that byte here and why, of the two characters that
	// can, it is this one. Test_buildkiteTokenAnchor holds it to standing at
	// this index in every prefix the scan can match, and holds the opening to
	// the two characters the scan compares it as one byte and an anchor.
	buildkiteTokenAnchor      = 'k'
	buildkiteTokenAnchorIndex = len(buildkiteTokenOpening) - 1

	// buildkiteTokenSeparator closes every prefix and opens the body behind it.
	// A body is written with it as well, which is what the run cursor above is
	// for: a prefix can stand inside a body, so a run can hold a candidate
	// every five characters.
	buildkiteTokenSeparator = '_'

	// buildkiteTokenBodyChars is the count a body is held to, read as a floor
	// rather than exactly and read for every kind rather than one apiece. Forty
	// is the shortest body attested of any of the ten. The rationale above
	// weighs reading it as a floor, and says what a kind written shorter than
	// it would cost.
	buildkiteTokenBodyChars = 40
)

// buildkiteTokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var buildkiteTokenTail = newPrefixTail(buildkiteTokenPrefixes...)
