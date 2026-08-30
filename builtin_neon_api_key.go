package mask

import "strings"

// NeonAPIKey locates Neon API keys: the prefix napi_ and the sixty-four or more
// letters and digits behind it, redacted to the end of the run they stand in.
// One shape serves all three keys Neon issues — the personal key, the
// organization key and the project-scoped key — so nothing in the string says
// which of them it is or what it reaches.
//
// A key is located wherever it is written, with no word boundary either side.
// So text of that shape is redacted whether or not Neon issued it. A space, a
// hyphen, an underscore or a run of fewer than sixty-four letters and digits
// ends the reading, so text as it is ordinarily written is not affected. Where
// the run carries on past the sixty-fourth character, it is redacted to its
// end.
//
// Its name is "neon-api-key".
func NeonAPIKey() Pattern { return neonAPIKey }

// Neon states the prefix in a changelog entry of January 2025: newly created
// Neon API keys are prefixed with napi_, so that secret scanning relying on
// identifiable markers can be used on them. Of the rest it states a number with
// no unit a string can carry — the page that issues keys calls each one "a
// randomly-generated 64-bit token" and the API specification describes the key
// field of a create response the same way, giving it neither a pattern nor an
// example. Sixty-four bits is eleven characters of the alphabet below, and no
// key is eleven characters. The one whole key Neon writes down settles nothing
// either: the CLI transcript prints napi_examplekey, the ten digits and the
// lowercase alphabet, which is a word and two ordered runs rather than a shape.
//
// So everything behind the prefix is read off the rulesets, and of the ones a
// scanner ships only betterleaks carries this format: it reads napi_ and
// sixty-four letters and digits, exactly, with an entropy floor beside it.
// GitHub's secret scanning lists the credential under the token identifier
// neon_api_key and publishes what it detects rather than the expression, so it
// corroborates the prefix and adds nothing to the count.
//
// That count is read as a floor. A count is read exactly where it is most of
// what tells a value from the text around it, or where the vendor wrote the
// length down; here Neon wrote no length at all, and one ruleset read
// sixty-four off the keys it was shown. Were Neon to lengthen the random part,
// a scan asking for sixty-four exactly would locate the first sixty-nine
// characters of a key and leave the rest in the output. Read as a floor, a key
// of any length at or above it goes to the end of its run. That is the reading
// the Linear scan takes on a prefix its vendor states alone.
//
// The floor is sixty-four and not lower, which is the opposite of how one is
// usually chosen: where rules disagree, the shortest body any of them admits is
// the floor, so that a key of a length somebody allowed for is still redacted
// whole. Lower numbers exist — a static-analysis rule carried in an application
// repository reads forty to sixty-four, and two one-off scripts read floors of
// thirty and of twenty — and none of them moves this one. They are rules
// written for a repository rather than rulesets a scanner ships, none says
// where its number came from, and the only one naming an upper bound names
// sixty-four. Reaching down to forty would take in the SHA-1 written behind
// this prefix, a value a reader has a use for, when the tighter net is already
// here.
//
// The floor fails downward in silence. Were a real body shorter than
// sixty-four, this pattern would locate no key at all, every test here would
// pass, and the corpus could not report it either — its keys are built to the
// floor, so they move with it. What holds the count up is three sources
// carrying it and disagreeing about nothing else: betterleaks reads sixty-four
// exactly, the static-analysis rule stops there, and Neon's own pages write it
// without a unit. What would move it down is a key shorter than that, written
// somewhere it can be counted.
//
// What the floor costs when it is right is the key cut short of it. A line cut
// to a column limit partway through one leaves a prefix and a body too short to
// be a body, and nothing is located: the random characters in front of the cut
// stay in the output. Test_NeonAPIKey_cutShortOfTheFloor pins that.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the digits, and neither the hyphen nor the underscore base64url
// adds. Leaving the underscore out is doing more work here than an alphabet
// usually does — it is what ends a body at the next segment of a snake_case
// name, which is what turns the Node-API names below away, and it is what makes
// every body begin where a run begins, which the account of the scan's cost
// rests on.
//
// One prefix serves the three kinds of key Neon issues, and Neon's own
// documentation is what argues against reading more. The create responses there
// write the personal key as neon_api_key_ and a run of hexadecimal, the
// organization one as neon_org_key_ and the project-scoped one as
// neon_project_key_. The first is a prefix no key carries — the changelog says
// napi_ — so all three are the field's own name written where a value goes.
// Against them stand the CLI transcript on the same page, which prints napi_
// for each of the three kinds, and the specification, where the organization
// and project-scoped create responses are the personal one with a project_id
// added and inherit its key field verbatim.
//
// Being wrong about that costs the whole of a key rather than the end of one,
// and nothing reports it: a prefix no value carries opens no candidate, so a
// scan reading one locates nothing and every test of it passes.
// Test_NeonAPIKey_theResponseExamplePrefixes drives the three spellings so that
// the decision moves as a decision.
//
// The prefix is read in the one case Neon writes it. It is the whole of what
// tells this format from text, so reading it in either case buys nothing —
// NAPI_ is no form a key is issued in — and costs a candidate at every
// uppercase spelling.
//
// There is no boundary on either side of a match. One in front would drop the
// whole match rather than trim it wherever a key is written against a word
// character, as NEON_API_KEY_napi_... is, and one behind would drop a key
// followed by a character of the key's own alphabet — which, since the span
// already reaches the end of the run, is every key with a letter or a digit
// written against it.
//
// The tightening on offer in front is the demand that no letter and no digit
// stand before the prefix. It is declined because it would reject the key
// written inside another, whose prefix stands against the last letter of the
// body in front of it. What declining it admits is a snake_case name whose
// segment closes on napi, and that is no hypothetical: Node-API writes its
// names with this prefix — napi_value, napi_status, napi_create_string_utf8 —
// so a source file of a native addon carries napi_ on nearly every line. None
// of those names reaches a body, because the underscore after the next word
// ends the run long before the sixty-fourth character.
// Test_NeonAPIKey_theNodeAPINamesThatCarryThePrefix pins a handful of them.
//
// The byte the scan searches for is the underscore the prefix closes with, and
// the prefix is read back from it. builtin_scan.go says why a scan searches for
// one byte rather than for the prefix itself; what makes it this byte is that
// the other four are letters an English log line is written in — over the line
// these benchmarks are written on the n stands six times, the p five, the i
// five and the a three, where the underscore stands not at all.
//
// The scan advances one byte past the start of a candidate, which is the
// default, and here it is load-bearing: the four letters the prefix opens with
// belong to the alphabet a body is written in, so a body may close with napi
// and the underscore of the next key stand directly behind it. A scan consuming
// its match would step over that key and leave it in the output whole. The two
// spans overlap where it happens, and Masker.locate resolves them.
//
// The scan keeps no cursor and needs none. The run behind a candidate is read
// to its end however long it is, and what bounds the work is where a body opens
// rather than how far it reads: the underscore in front of one is written in
// neither the prefix's own alphabet nor the body's, so every body begins where
// a run begins and no two candidates can read the same run. That rules out the
// quadratic input a line dense in prefixes would otherwise be, and
// Test_neonAPIKeyPrefix_runsDoNotOverlap names the character it rests on.
//
// What this pattern over-matches on is sixty-four letters and digits written
// behind the prefix, in two shapes. One is base64url text: that alphabet holds
// the underscore where hexadecimal and standard base64 do not, so a payload
// written in it — a JWT signature, the routable body some other vendor encodes
// a credential as — can carry napi_ inside itself. The other is the digest: a
// SHA-256 is sixty-four hexadecimal characters, which are base62 and carry
// nothing that ends a run, so napi_ written in front of one is a key's format
// exactly. Both are paid rather than avoided, because there is nothing left to
// tell them from a key: a scan declining sixty-four letters and digits behind
// this prefix declines every key Neon issues. Test_NeonAPIKey_insideAnOpaqueRun
// and Test_NeonAPIKey_aDigestBehindThePrefix pin them. What stays out is prose
// and the shorter digests: no word runs into an underscore, and a SHA-1 at
// forty characters and an MD5 at thirty-two fall short of the floor.
//
// referenceNeonAPIKeyFind in builtin_neon_api_key_test.go states the grammar
// again as a walk over every position, spelling the prefix, the floor and the
// alphabet out so that the two are changed together, and the fuzz target beside
// it holds this scan to that walk. Why it is a walk rather than the expression
// the grammar states compactly as is written there.
var neonAPIKey = NewPattern("neon-api-key", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two.
	retain := neonAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], neonAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for
		// the reason the rationale above gives: a body may close with the four
		// letters the prefix opens with, so a key can begin four characters
		// before the end of the one before it.
		offset = anchor + 1

		if anchor < neonAPIKeyAnchorIndex {
			continue
		}
		start := anchor - neonAPIKeyAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != neonAPIKeyPrefix[0] || !strings.HasPrefix(src[start:], neonAPIKeyPrefix) {
			continue
		}

		body := start + len(neonAPIKeyPrefix)
		end := base62RunEnd(src, body)
		if end == len(src) {
			// The run reaches the end of the input, so neither where the body
			// ends nor whether it is long enough to be one is settled here:
			// what comes next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if end-body >= neonAPIKeyBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// neonAPIKeyPrefix is what every API key opens with, and what the scan
	// reads back from its anchor. Its first four characters belong to the
	// alphabet a body is written in and the underscore it closes with does not,
	// which is why the scan resumes a byte along and why it needs no cursor.
	// Test_neonAPIKeyPrefix holds it to the first and
	// Test_neonAPIKeyPrefix_runsDoNotOverlap to the second.
	neonAPIKeyPrefix = "napi_"

	// neonAPIKeyAnchor is the byte the scan searches the input for and
	// neonAPIKeyAnchorIndex is where it stands in the prefix, so a candidate
	// begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what makes it
	// this byte.
	neonAPIKeyAnchor      = '_'
	neonAPIKeyAnchorIndex = 4

	// neonAPIKeyBodyChars is the count a body is held to, read as a floor
	// rather than exactly. The rationale above weighs both the reading and the
	// number.
	neonAPIKeyBodyChars = 64
)

// neonAPIKeyTail is what the scan settles the tail of its input by. prefixTail
// (builtin_scan.go) says what that is and why it is built once.
var neonAPIKeyTail = newPrefixTail(neonAPIKeyPrefix)
