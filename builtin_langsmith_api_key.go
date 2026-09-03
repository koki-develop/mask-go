package mask

import "strings"

// LangSmithAPIKey locates the API keys LangSmith issues: the letters lsv2, an
// underscore, one of the words naming the kind, another underscore, and the
// thirty-two or more letters and digits behind it, together with every further
// run an underscore joins to them. Two prefixes are written in that shape —
// lsv2_pt_, which a personal access token carries, and lsv2_sk_, which a
// service key carries — and a key of either kind authenticates requests to the
// LangSmith API, so whoever holds one reaches the traces, the datasets and the
// prompts of the workspaces it is scoped to.
//
// A key is located wherever it is written, with no word boundary either side.
// So text of that shape is redacted whether or not LangSmith issued it. A
// space, a hyphen or a first run of fewer than thirty-two letters and digits
// ends the reading, so text as it is ordinarily written is not affected. Where
// further runs are joined to the first by an underscore, the span reaches the
// end of the last of them.
//
// Its name is "langsmith-api-key".
func LangSmithAPIKey() Pattern { return langSmithAPIKey }

// LangSmith states the two prefixes in prose and the rest of the format in
// code. Its administration pages say that PATs are prefixed with lsv2_pt_ and
// that service keys are prefixed with lsv2_sk_, and stop there: no alphabet, no
// length and no checksum appears on any page LangSmith publishes, and the
// console that issues a key is behind a login.
//
// What states the rest is the SDK LangSmith publishes. langsmith/anonymizer.py
// carries the rules its own client redacts a trace with, and the rule for this
// format reads lsv2_, either of the two words, an underscore, thirty-two or
// more letters and digits, and then zero or more further runs of letters and
// digits each opened by an underscore. That is the vendor stating the alphabet,
// the count and the shape of the tail, in the code it ships to redact its own
// credentials with, rather than an observation of the values somebody was
// shown.
//
// The rulesets carry one rule between them and it is tighter rather than
// looser. trufflehog reads the two prefixes, exactly thirty-two lowercase
// hexadecimal digits, an underscore and exactly ten more, which is the shape of
// the keys it was written against; gitleaks and noseyparker have no LangSmith
// rule at all. GitHub's list of supported secret scanning patterns names the
// two kinds — LangSmith Personal Access Token and LangSmith Service Key — and
// publishes no expression for either.
//
// So the alphabet and the count are read as the SDK states them and not as
// trufflehog observed them, and the two places they differ are both places
// where the narrower reading is the one that loses a credential. The alphabet
// is base62, isBase62Byte in builtin_scan.go: the letters of both cases and the
// digits. Hexadecimal is what the keys in front of trufflehog happened to
// carry, and a scan asking for it would locate nothing at all of a key holding
// one letter past f, which is every character of a live key left in the output.
// The count is thirty-two and is read as a floor, which is the reading the SDK's
// own thirty-two-or-more asks for: a longer first run is still located whole,
// where an exact count would locate the first thirty-two characters of it and
// leave the rest behind.
//
// The floor fails downward in silence. Were a real key's first run shorter than
// thirty-two, this pattern would locate none of them, every case here would
// pass, and the corpus could not report it either — its keys are built to the
// floor, so they move with it. What would move the count down is a shorter key
// written into what LangSmith publishes, or a rule that reads one.
//
// What the floor costs when it is right is the key cut short of it. A line cut
// to a column limit partway through one leaves a prefix and a run too short to
// be a first run, and nothing is located: the characters in front of the cut
// stay in the output. Test_LangSmithAPIKey_cutShortOfTheFloor pins that.
//
// The tail is what this format has that a single opaque run does not, and
// reading it is the whole of why the scan is written the way it is below. A key
// is written in more than one run — the keys trufflehog was written against
// carry a second of ten characters — and the underscore joining them is a
// character no run is written with, so a scan stopping at the end of the first
// run would leave every character behind that underscore in the output. That is
// the tail of a live credential written into a log, and the SDK's own comment
// beside the rule says the tail is in the rule to keep it out of one.
//
// Reading to the end of the last run is what that costs, and it is paid
// knowingly. Where a key is written against a name in the same shape —
// underscores joining runs of letters and digits — the span reaches through
// that name as well, since there is nothing in the text saying where the key
// stopped and the name began. Test_LangSmithAPIKey_reachesTheEndOfTheRuns
// writes out what that takes and what ends it: a dot, a quotation mark and a
// hyphen all close a body, and so does a second underscore, that one because a
// run has to carry at least one character to be one.
//
// The two kinds are one pattern and not two. A caller has no reason to redact
// the key a script authenticates with and leave the one a service does, since
// neither is published where the other authenticates and both reach the same
// API; a redactor telling them apart in its output would be telling apart two
// spellings of one credential; and API keys is LangSmith's own term for the
// whole of what is here, under which its administration pages put both. Two
// switches would mean a caller reaching for LangSmith had to know both to
// redact what LangSmith issues.
//
// The other credentials LangSmith issues are not read. GitHub's list names a
// LangSmith license key and a LangSmith SCIM bearer token beside the two kinds
// above, and neither has a prefix, an alphabet or a length anywhere LangSmith
// publishes — the pages that hand out a license key show none, and the SDK
// carries no rule for either. What is left to read them by is a shape nobody
// has stated, which is the part of a grammar it is least safe to invent.
//
// The keys LangSmith issued before these are not read either. They open with
// ls__ and everything behind them is one run; LangSmith's administration pages say
// support for them ended on 22 October 2024, and the line under the rule this
// pattern is built on reads ls__ and sixteen or more letters and digits, so the
// vendor goes on keeping them out of the traces it collects.
//
// What decides it here is what the two openings are worth against what they
// locate. Behind lsv2_pt_ stand four characters no word is spelled with, a
// separator, a word naming a kind, a separator and a floor of thirty-two;
// behind ls__ stand two letters, a doubled underscore and a floor of sixteen in
// one class, which is a shape a name reaches by closing a segment on ls where
// no name closes one on lsv2. Paying that for a credential the vendor stopped
// honouring is the trade this declines. Test_LangSmithAPIKey_theLegacyPrefix
// pins the decision, so that reading the prefix is a change somebody argues for
// rather than one somebody notices afterwards.
//
// The byte the scan searches for is the underscore behind the opening, and the
// prefix is read back from it. builtin_scan.go says why a scan searches for one
// byte rather than for the prefix itself. Over the line these benchmarks are
// written on the underscore and the v stand twice apiece where the l, the s and
// the 2 stand four times each, so the choice is between those two, and what
// settles it is the text that holds a key: a body is thirty-two or more
// characters of an alphabet the v belongs to, so a search for the v stops
// inside every key already located, once for every v written in it, where the
// separator stands inside one at most once a run. What the underscore costs is
// a candidate opened at every underscore of a snake_case name, and that is paid
// here because the four characters read back spell no segment of any such name,
// so the candidate is turned away by the first byte tested.
//
// The separator stands at two depths in every prefix — behind the opening and
// behind the word naming the kind — and the scan reads its candidates back from
// the first. Both prefixes carry the byte at both depths, so a search anchored
// at either finds the same candidates; what the first buys is that the four
// characters read back are the opening both prefixes share, which is compared
// once, where reading back from the second would compare one whole prefix and
// then the other.
//
// The openings are declared, and that wants an argument because the scan reads
// a candidate back from an opening narrower than a whole prefix and reads the
// word naming the kind forward from there. What builtin_scan.go asks of a
// pattern declaring its openings is that the scan settle no less than the table
// of them does, and the narrower opening never pins the input: a candidate the
// end of the input cut short is reported at its start only once the whole
// prefix has matched, the opening and the separator and the word and the
// separator behind it, so every candidate this scan is held open by is one the
// table carries a prefix for. An opening with no word behind it, or with a word
// the separator does not close, is given up on without pinning anything, and
// what settles the tail there is the table's own reading of a piece of a
// prefix. Test_builtins_prefilterAgreesWithFind holds both halves of that.
//
// The scan advances one byte past the start of a candidate, which is the
// default, and here it is load-bearing: the four characters the opening is made
// of belong to the alphabet a run is written in, so a run may close with lsv2
// and the underscore of the next key stand directly behind it. A scan consuming
// its match would step over that key and leave it in the output whole. The two
// spans overlap where it happens, and Masker.locate resolves them.
//
// The scan keeps a cursor over the runs behind a body, and it is what rules out
// the quadratic input. Two things divide the work a candidate does. Its first
// run cannot be a run any other candidate reads: a body opens directly behind
// the underscore closing a prefix, no run is written with that character, so
// every first run begins where a run begins and two candidates asking for one
// are asking about two different runs.
// Test_langSmithAPIKeyPrefixes_bodyNeverMovesBack names the character that
// rests on. The runs behind the first are the opposite — a body carries the
// underscore that joins them, so a key written into another's tail reads the
// runs its host reads, and a line of keys joined by underscores would be walked
// once for every key in it. The cursor is what keeps that to one walk: runs
// reached from anywhere inside them end where they end, so a body opening in
// front of where the last walk stopped is answered from there rather than
// walked again, and the cursor never moves back.
// Test_LangSmithAPIKey_scanIsLinear drives the line that would find it wrong.
//
// What this pattern over-matches on is thirty-two letters and digits written
// behind one of the prefixes, in two shapes. One is base64url text: that alphabet
// holds the underscore where hexadecimal and standard base64 do not, so a
// payload written in it can carry a whole prefix inside itself. The other is
// the digest: an MD5 is thirty-two hexadecimal characters, which are base62 and
// carry nothing that ends a run, so an MD5 written behind a prefix is a key's
// first run exactly, as the longer digests are. Both are paid rather than
// avoided, because there is nothing left to tell them from a key: a scan
// declining thirty-two letters and digits behind these prefixes declines every
// key LangSmith issues. Test_LangSmithAPIKey_insideAnOpaqueRun and
// Test_LangSmithAPIKey_aDigestBehindThePrefix pin them. What stays out is
// prose, where no word runs into an underscore for thirty-two characters.
//
// referenceLangSmithAPIKey in builtin_langsmith_api_key_test.go keeps the
// grammar as a regular expression, spelling the opening, the kinds, the
// separator, the floor and the alphabet again so that the two are changed
// together, and the fuzz target beside it holds this scan to that expression.
var langSmithAPIKey = newBuiltin("langsmith-api-key", &langSmithAPIKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := langSmithAPIKeyTail.start(src)

	// The cursor the rationale above is about: where the runs behind the last
	// body read ended, and whether the end of the input is what ended them. A
	// body opening in front of that end reads those same runs and ends where
	// they end, so it is answered from here rather than walked again.
	runsEnd, runsEndAtInput := 0, false

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], langSmithAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for
		// the reason the rationale above gives: a run may close with the four
		// characters the opening is made of, so a key can begin four characters
		// before the end of the run in front of it.
		offset = anchor + 1

		if anchor < langSmithAPIKeyAnchorIndex {
			continue
		}
		start := anchor - langSmithAPIKeyAnchorIndex

		// The byte the opening begins with is tested before the opening is
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the whole opening is a length and a read.
		if src[start] != langSmithAPIKeyOpening[0] || !strings.HasPrefix(src[start:], langSmithAPIKeyOpening) {
			continue
		}

		// The word naming the kind, and the separator that has to close it. The
		// words open on different bytes and neither is written inside the other
		// from its start, so at most one of them can stand at this position —
		// which is why a word that matches and is not closed by the separator
		// ends the search rather than letting the other be tried.
		body := -1
		for _, kind := range langSmithAPIKeyKinds {
			if !strings.HasPrefix(src[anchor+1:], kind) {
				continue
			}
			at := anchor + 1 + len(kind)
			if at == len(src) || src[at] != langSmithAPIKeySeparator {
				break
			}
			body = at + 1
			break
		}
		if body < 0 {
			continue
		}

		first := base62RunEnd(src, body)
		if first-body < langSmithAPIKeyBodyChars {
			if first == len(src) {
				// The run reaches the end of the input, so whether it is long
				// enough to be a first run is not settled here: what comes next
				// either carries it on or closes it.
				retain = min(retain, start)
			}
			continue
		}

		if first >= runsEnd {
			runsEnd, runsEndAtInput = langSmithAPIKeyRunsEnd(src, first)
		}
		if runsEndAtInput {
			// The runs reach the end of the input, so where the last of them
			// ends is not settled here.
			retain = min(retain, start)
		}
		spans = append(spans, Span{Start: start, End: runsEnd})
	}
	return spans, retain
})

// langSmithAPIKeyRunsEnd returns where the runs of a body whose first run ends
// at i end, and whether the end of the input is what ended them.
//
// It answers the second because only the walk can. A body goes on for as long
// as a separator with a run behind it is written against it, so a walk stopping
// at a separator standing last in the input, or at the end of a run that
// reaches it, stopped because there was no more input rather than because the
// text said so — and a scan that could not tell those apart would either hold a
// stream open on every body or release the tail of a key arriving in two
// pieces.
//
// The separator written twice with nothing between the two is where a body ends
// for good: a run carries at least one character, so nothing arriving after
// that can join a run to what stands in front of it.
func langSmithAPIKeyRunsEnd(src string, i int) (int, bool) {
	for {
		if i == len(src) {
			return i, true
		}
		if src[i] != langSmithAPIKeySeparator {
			return i, false
		}
		if i+1 == len(src) {
			return i, true
		}
		if !isBase62Byte(src[i+1]) {
			return i, false
		}
		i = base62RunEnd(src, i+1)
	}
}

// langSmithAPIKeyPrefixes is what a candidate opens with, one entry to a word
// naming a kind.
//
// The words are read out of the declaration the scan reads them from rather
// than written out again, so that a word added there is a word this knows
// about: a table of its own is one that can come to disagree with it, and what
// a stream would then do with the prefix it had not been told about is release
// the characters a key opens with and redact nothing.
var langSmithAPIKeyPrefixes = func() []string {
	prefixes := make([]string, 0, len(langSmithAPIKeyKinds))
	for _, kind := range langSmithAPIKeyKinds {
		prefixes = append(prefixes, langSmithAPIKeyOpening+string(langSmithAPIKeySeparator)+kind+string(langSmithAPIKeySeparator))
	}
	return prefixes
}()

// langSmithAPIKeyKinds is the words a prefix carries between its two
// separators: pt, which a personal access token carries, and sk, which a
// service key carries. Both carry the same body, so the word is read to tell a
// prefix from text that merely opens like one and for nothing else.
//
// Test_langSmithAPIKeyKinds holds them to opening on different bytes, which is
// what rejects all but one of them on a byte, and to being words a prefix can
// be built from. What lets the scan stop at the first word it matches is the
// weaker half of that: no word is written inside another from its start.
var langSmithAPIKeyKinds = []string{"pt", "sk"}

const (
	// langSmithAPIKeyOpening is what every prefix opens with, and what the scan
	// reads back from its anchor. Its four characters belong to the alphabet a
	// run is written in, which is what lets one key begin inside another and is
	// why the scan resumes a byte along; Test_langSmithAPIKeyOpening holds them
	// there.
	langSmithAPIKeyOpening = "lsv2"

	// langSmithAPIKeySeparator stands twice in every prefix — behind the
	// opening and behind the word naming the kind — and again wherever a body
	// joins a run to the one in front of it. No run is written with it, which
	// is what ends a run where it stands and what makes every first run begin
	// where a run begins.
	langSmithAPIKeySeparator = '_'

	// langSmithAPIKeyAnchor is the byte the scan searches the input for and
	// langSmithAPIKeyAnchorIndex is where it stands in a prefix, so a candidate
	// begins that many bytes in front of what a search reported. It is the
	// separator at the first of the two depths a prefix writes it at.
	// builtin_scan.go says why a scan searches for one byte of what opens a
	// candidate rather than for the whole of it; the rationale above says what
	// makes it this byte and why the first depth rather than the second.
	langSmithAPIKeyAnchor      = langSmithAPIKeySeparator
	langSmithAPIKeyAnchorIndex = len(langSmithAPIKeyOpening)

	// langSmithAPIKeyBodyChars is the count a body's first run is held to, read
	// as a floor rather than exactly. Thirty-two is what the rule in
	// LangSmith's own SDK asks for. The rationale above weighs both the reading
	// and the number.
	langSmithAPIKeyBodyChars = 32
)

// langSmithAPIKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var langSmithAPIKeyTail = newPrefixTail(langSmithAPIKeyPrefixes...)
