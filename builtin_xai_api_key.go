package mask

import "strings"

// XAIAPIKey locates xAI API keys: the prefix xai- and the letters and digits
// behind it, of which there are at least eighty — eighty-four characters
// altogether where a key is the length xAI prints one at. The key an account
// manages its other keys with is written xai-token- and a body of the same
// shape, and is located too. One string authenticates every request a key of
// either kind is issued for, so nothing in one says what it may be spent on.
//
// A key is located wherever it is written, with no word boundary either side,
// and is redacted from its prefix to the end of the run it stands in. So a
// letter or a digit written straight after a key is redacted with it, and text
// of that shape is redacted whether or not xAI issued it. A space, a hyphen, an
// underscore or a run of fewer than eighty letters and digits ends the reading,
// so text as it is ordinarily written is not affected.
//
// Its name is "xai-api-key".
func XAIAPIKey() Pattern { return xaiAPIKey }

// API key is xAI's own name for this string. The console page one is created on
// is titled API Keys, the environment variable every client reads one from is
// XAI_API_KEY, the management API creates one at /auth/teams/{teamId}/api-keys
// and hands it back in a field named apiKey, and GitHub's partner pattern for
// the same value is filed under the token identifier xai_api_key. The key an
// account reaches the management API itself with is xAI's management API key,
// reported through a field named redactedApiKey like the other, so the term is
// the head of both names and covers the whole of what this scan locates. The
// two put no boundary between patterns besides: a caller redacting the key that
// spends an account's credit redacts the key that issues those keys, and there
// is no reading of one without the other.
//
// What xAI states about the format it states by printing a key rather than by
// describing one. The response that creates a key is the one place a key is
// ever shown whole — the reference says the field is set only when the key is
// created, and every other response carries the value redacted to xai- and its
// last four characters — and the key it prints there is xai- and eighty letters
// and digits, eighty-four characters altogether.
//
// The management key xAI prints redacted only, which says the two share the
// opening and stops there: a value cut to its first four characters and its
// last four would read the same whatever stands between. What states the rest
// is Google's osv-scalibr, which reads a management key as xai-token- and
// eighty letters and digits and validates what it finds against xAI's own
// management endpoint. That is a rule written against the live service rather
// than inferred from a key somebody published, which is the strongest thing
// there is for an opening no vendor page prints; no other ruleset reads the
// form at all.
//
// Reading it is a decision, and what it rests on is which way being wrong
// falls. An opening that turns out not to exist locates nothing and costs a
// comparison no candidate reaches; an opening left out leaves the credential
// that issues every other key of an account in the output whole, which is the
// failure this library is for.
// Test_XAIAPIKey_aManagementKey pins the form.
//
// The rulesets divide on the length, and that division is what the floor below
// answers. trufflehog reads xai- and exactly eighty characters, admitting the
// underscore besides the letters and digits; osv-scalibr reads the same count
// in the letters and digits alone, and publishes a whole key of each kind, each
// with a body of eighty. kingfisher reads xai- and a range of seventy to a
// hundred and twenty, admitting the hyphen as well, under an entropy floor of
// 3.8 and a demand for two digits; betterleaks reads the same range and the
// same class under an entropy filter of its own, and kingfisher cites
// betterleaks for the rule. gitleaks reads this format not at all. So two
// rulesets read a count and two read a range, the count is the length of every
// whole key those sources carry — xAI's own, osv-scalibr's two and
// kingfisher's three — and the range reaches ten characters below it and forty
// above, where none of those keys is written.
//
// The count is therefore read as a floor and not as a count. A count is read
// exactly where the vendor wrote the length down, and xAI wrote down a key
// rather than a length: nothing holds it to eighty the day it lengthens the
// random part, and a scan asking for eighty exactly would locate the first
// eighty-four characters of a longer key and leave the rest of it in the
// output. Read as a floor, a key of any length at or above it is located to the
// end of its run.
//
// The floor is eighty rather than the seventy two of the rulesets read, because
// eighty is the length every whole key those sources carry runs to and seventy
// is a number none of them is written at. What a body looks like is the one
// thing an opening of four characters does not give this scan, so a floor
// lowered towards prose is a guess at exactly the part of the grammar that is
// load bearing, and what it would buy is a key neither xAI nor a ruleset
// carries.
//
// What the floor costs is the key shorter than it. A line cut to a column limit
// partway through one leaves an opening and a body too short to be a body, and
// nothing is located: the random characters written before the cut stay in the
// output. It also costs the character written against the end of a key, which
// the span reaching to the end of the run takes with it. Both are the far side
// of this choice, and the cases in builtin_xai_api_key_test.go pin them so that
// they stay a decision on the record.
//
// The entropy floors two of the rulesets carry, and the two digits kingfisher
// asks for besides, are not read here. They are demands on how the bytes of a
// random body happened to fall rather than parts of the format, and a scan
// reading one would be deciding whether a value is a credential by how ordinary
// it looks. What declining them costs is the run of the right shape whose body
// is too regular for a generator to have drawn: xai- and eighty zeros is
// redacted here and turned away by both floors. What taking one would cost is a
// key whose body fell that way, which nothing but chance rules out and which a
// redaction library may not leave in the output.
// Test_XAIAPIKey_aBodyBelowTheEntropyFloors pins the decision.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the digits, and neither the hyphen nor the underscore base64url
// adds. Every whole key xAI, osv-scalibr and kingfisher carry is written in
// the letters and digits alone, and osv-scalibr is the ruleset reading that
// class exactly. The two characters the others admit besides are both
// declined, though for different reasons.
//
// The underscore is the one trufflehog admits, and what it would cast a net
// over is the snake_case name: eighty characters of letters, digits and
// underscores behind four characters is a width an identifier reaches where the
// same run written unbroken is not.
//
// The hyphen is the one this scan could least afford, because it is the
// character both openings close with. Admitting it would make xai- written in
// front of any kebab-cased run of eighty characters a key, and would leave the
// management opening unreadable besides, since token- would then be eighty
// characters of body rather than the thing that says which kind this is.
// Test_xaiAPIKeyOpenings holds both openings to closing on a character no body
// may carry, which is what the account of a candidate below rests on twice
// over.
//
// The opening is read in the one case xAI writes it. It is the whole of what
// tells this format from text, so reading it in either case buys nothing — XAI-
// is no form a key is issued in — and costs a candidate opened at every
// uppercase spelling. betterleaks is the one ruleset reading it without regard
// to case; the other three read it as xAI writes it.
//
// There is no boundary on either side of a match, and here that is a
// disagreement with three of the four, since trufflehog, kingfisher and
// betterleaks each write one at both ends where osv-scalibr writes neither. A
// boundary in front drops rather than trims the match wherever a key is
// written against a word character, which is what XAI_API_KEY_xai-... is and
// what a shell writes into a log line. One behind drops rather than trims as
// well, and where it were asked decides what it drops. Asked behind the count,
// it drops the key a letter, a digit or an underscore is written against.
// Asked behind that run, it drops the key an underscore is written against and
// nothing else, the underscore being the one word character no body admits.
// What may stand either side is held back by the character class and the floor
// alone.
//
// A key can be written inside another, which is what the scan resuming a byte
// past the start of a candidate is for. The three characters in front of the
// prefix's hyphen belong to the alphabet a body is written in, so a body may
// close with xai and the hyphen opening the next key stand directly behind it:
// two keys written with nothing between them are a span reaching through the
// second key's xai to the hyphen that ends the run, and a second span three
// characters before the first one ends. The spans overlap there, which
// Masker.locate resolves, and a scan consuming the first match would step over
// the second and leave it in the output whole.
// Test_XAIAPIKey_aKeyInsideAKey drives the shape.
//
// At most one of the two openings is read at a candidate, and which one is
// settled by the hyphen again rather than by trying both. Where token- stands
// behind the prefix, the body begins past it; where it does not, the body
// begins at the prefix. The two cannot both reach the floor, because a body
// beginning at the prefix of a key whose infix is there runs out at that
// infix's own hyphen five characters in — so there is nothing to fall back to
// and no candidate is read twice.
//
// The scan keeps no cursor and needs none, and what rules out a quadratic input
// is the hyphen an opening closes with. A body begins directly behind one, so
// every body begins where a run of the alphabet begins, and a run begun inside
// the run a candidate before it read would have to hold that hyphen — which
// ends a run rather than standing inside one. So no two candidates read the
// same run, and the bodies walked over an input come to its length however
// dense in openings it is. Test_xaiAPIKeyOpenings holds the character the
// guarantee rests on, and Test_XAIAPIKey_scanIsLinear drives the input that
// would find it wrong.
//
// The byte the scan searches the input for is the x the prefix opens with, and
// the prefix is read forward from it. builtin_scan.go says why a scan searches
// for one byte of its prefix rather than for the prefix itself; what makes it
// this byte is that the other three are each written far more often than it.
// The a and the i are two of the commonest letters English is spelled with,
// standing five and seven times on the line these benchmarks are written on
// where the x stands once. The hyphen the prefix closes with stands twice there
// and is the byte not to anchor on for the reason it is everywhere else: it is
// what every ISO timestamp, every UUID and every kebab-cased name is written
// with. The infix carries no x at all, so it adds no anchor and the search
// stops once at a key of either kind.
//
// What the x costs, and the hyphen would not, is that it is written in the
// alphabet a body is: a run of that alphabet stops the search about once every
// sixty-two characters however long it runs, where a hyphen stops it nowhere in
// one. That is the trade, and it is taken because a caller's text is mostly
// prose and log lines rather than base62 payloads, and because a stop that
// opens no candidate costs a comparison of four bytes.
//
// The prefix opens where the search stops, so a candidate begins at the anchor
// rather than behind it, and the byte test other scans make in front of
// comparing the whole prefix would be a byte compared with itself. It is not
// written. The index the candidate is read back from stays a declaration of its
// own all the same, so that a prefix and an index cannot come apart silently;
// Test_xaiAPIKeyAnchor holds the two together.
//
// What this pattern over-matches on is eighty letters and digits written behind
// an opening, and the shape worth stating is the digest: a SHA-256 is
// sixty-four hexadecimal characters, sixteen short of the floor, so one written
// behind the prefix is left alone and two written together are a key. Those
// characters are indistinguishable from a body — a scan declining eighty
// letters and digits behind this opening declines every key there is — and what
// has to be written to reach it is the opening with the digests against it and
// nothing between. Test_XAIAPIKey_aDigestBehindThePrefix pins the decision.
//
// What reaches a span is never prose: eighty unbroken letters and digits behind
// three letters and a hyphen is longer than anything prose is written in, and a
// word running into the prefix runs the body out at its first space or
// punctuation mark. The prefix is what xAI's own repositories are named with —
// xai-org, xai-sdk and xai-cookbook are each a prefix and a word — and what
// turns those away is the floor, which the word behind the hyphen falls short
// of by seventy or more.
//
// referenceXAIAPIKey in builtin_xai_api_key_test.go keeps the grammar as a
// regular expression, spelling the openings, the floor and the alphabet again
// so that the two are changed together, and the fuzz target beside it holds
// this scan to that expression.
var xaiAPIKey = newBuiltin("xai-api-key", &xaiAPIKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two. Every opening this scan reads begins with the
	// prefix, so the tail is built on that alone: a piece of the infix standing
	// at the end of the input stands behind a whole prefix, which is a
	// candidate the loop below reports for itself.
	retain := xaiAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], xaiAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for
		// the reason the rationale above gives: a body may close with the three
		// characters the prefix opens with, so a key can begin three characters
		// before the end of the one before it.
		offset = anchor + 1

		// The guard stands although the index below is zero, so that the byte
		// the search stops at and the place a candidate begins stay two
		// declarations rather than one: a scan reading the prefix back from a
		// later byte would read behind the input without it.
		if anchor < xaiAPIKeyAnchorIndex {
			continue
		}
		start := anchor - xaiAPIKeyAnchorIndex
		if !strings.HasPrefix(src[start:], xaiAPIKeyPrefix) {
			continue
		}

		// The management form, and at most one of the two is read here. The
		// infix closes on the character a body ends at, so a body beginning at
		// the prefix of a key carrying one runs out five characters in and
		// there is nothing to fall back to.
		body := start + len(xaiAPIKeyPrefix)
		if strings.HasPrefix(src[body:], xaiAPIKeyManagementInfix) {
			body += len(xaiAPIKeyManagementInfix)
		}

		end := base62RunEnd(src, body)
		if end == len(src) {
			// The run reaches the end of the input, so neither where the body
			// ends nor whether it is long enough to be one is settled here:
			// what comes next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if end-body >= xaiAPIKeyBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// xaiAPIKeyPrefix is what every API key opens with, and what the scan reads
	// forward from its anchor. Its first three characters belong to the
	// alphabet a body is written in, which is what lets a key begin inside
	// another and is why the scan resumes a byte along; the hyphen it closes
	// with does not, which is what keeps two candidates from ever reading the
	// same run. Test_xaiAPIKeyOpenings holds it to both.
	xaiAPIKeyPrefix = "xai-"

	// xaiAPIKeyManagementInfix stands between the prefix and the body of the
	// key an account manages its other keys with, and is the whole of what
	// tells one kind from the other. It closes on the same hyphen the prefix
	// does, so the two openings are one rule to everything below: a body begins
	// directly behind a character no body may carry.
	xaiAPIKeyManagementInfix = "token-"

	// xaiAPIKeyAnchor is the byte the scan searches the input for and
	// xaiAPIKeyAnchorIndex is where it stands in the prefix, so a candidate
	// begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what made it
	// this byte and what the choice costs.
	xaiAPIKeyAnchor      = 'x'
	xaiAPIKeyAnchorIndex = 0

	// xaiAPIKeyBodyChars is the count a body is held to, read as a floor
	// rather than exactly. Eighty is what the key xAI prints whole runs to and
	// what the keys osv-scalibr and kingfisher carry run to; the rationale
	// above weighs reading it as a floor and says why the floor is not the
	// lower one two rulesets read.
	xaiAPIKeyBodyChars = 80
)

// xaiAPIKeyTail is what the scan settles the tail of its input by. prefixTail
// (builtin_scan.go) says what that is and why it is built once.
var xaiAPIKeyTail = newPrefixTail(xaiAPIKeyPrefix)
