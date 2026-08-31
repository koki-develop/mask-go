package mask

import "strings"

// RenderAPIKey locates Render API keys: the prefix rnd_ and the twenty-eight or
// more letters and digits behind it, redacted to the end of the run they stand
// in. One key authenticates against the whole of the Render API, over every
// workspace the account it belongs to is a member of, so nothing in the string
// says what it reaches.
//
// A key is located wherever it is written, with no word boundary either side.
// So text of that shape is redacted whether or not Render issued it. A space, a
// hyphen, an underscore or a run of fewer than twenty-eight letters and digits
// ends the reading, so text as it is ordinarily written is not affected. Where
// the run carries on past the twenty-eighth character, it is redacted to its
// end.
//
// Its name is "render-api-key".
func RenderAPIKey() Pattern { return renderAPIKey }

// Render states the prefix and states it nowhere in prose. What writes it down
// is Render's own code and its own examples: the SDK README initialises a
// client with rnd_..., the skills Render publishes tell a reader to export
// RENDER_API_KEY=rnd_..., and the CLI and the MCP server carry rnd_ in the
// fixtures they test their authentication against. The documentation itself
// adds nothing to that — the authentication page writes Bearer
// API_KEY_GOES_HERE where a key goes, and the OpenAPI specification gives the
// credential neither a pattern nor an example.
//
// So everything behind the prefix is read off a ruleset rather than off
// Render: betterleaks reads rnd_ and twenty-eight letters and digits, exactly,
// with a delimiter behind them. The rulesets the other scanners ship carry no
// Render rule at all, so there is nothing to weigh it against and nothing that
// disagrees with it.
//
// That count is read as a floor. A count is read exactly where the vendor wrote
// the length down, or where it is most of what tells a value from the text
// around it; Render wrote no length anywhere, and the four characters of the
// prefix have already done the telling, so reading twenty-eight exactly would
// buy a discrimination the prefix does not need. What it would cost is the day
// Render lengthens the random part, and it would cost the whole key rather than
// the end of one: the rule reads its twenty-eight with a delimiter behind them,
// so a body of thirty answers neither the count nor the delimiter, and a scan
// asking exactly would locate nothing at all while every case here passed. Read
// as a floor, a key of any length at or above twenty-eight is redacted to the
// end of its run.
//
// Twenty-eight is neither raised nor lowered from what the one rule reads,
// which is the only length anything states. Lowering it would widen the net
// with nothing asking for the width.
//
// The floor fails downward in silence. Were a real body shorter than
// twenty-eight, nothing here would be located, every case would pass and the
// corpus could not report it either, since its keys are built to the floor and
// move with it. What would move the number down is a shorter key written into
// what Render publishes, or a rule that reads one.
//
// What the floor costs when it is right is the key cut short of it. A line cut
// to a column limit partway through one leaves a prefix and a body too short to
// be a body, and nothing is located: the random characters written in front of
// the cut stay in the output. Test_RenderAPIKey_cutShortOfTheFloor pins that.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the digits, and neither the hyphen nor the underscore base64url
// adds. Leaving the underscore out is what this scan leans on hardest. It is
// what ends a body at the next segment of a snake_case name, and rnd is how
// ordinary code abbreviates random — rnd_seed, rnd_state, rnd_next — so a
// source file of a simulation or a game carries this prefix as often as a
// native addon carries a Node-API name. It is also what makes every body begin
// where a run begins, which the account of the scan's cost below rests on.
//
// The prefix is read in the one case Render writes it. Reading RND_ as well
// would buy nothing — no key is issued in capitals — and would cost a candidate
// at RND_MAX and at every other shouted constant a random number generator is
// configured with.
//
// There is no boundary on either side of a match. One in front would drop the
// whole match rather than trim it wherever a key is written against a word
// character, as RENDER_API_KEY_rnd_... is. One behind would drop rather than
// trim as well, and where it were asked decides what it drops. Asked behind
// the count, it drops the key a letter, a digit or an underscore is written
// against. Asked behind that run, it drops the key an underscore is written
// against and nothing else, the underscore being the one word character no
// body admits.
// Test_RenderAPIKey_reachesTheEndOfTheRun writes both keys out.
//
// The tightening on offer in front is the demand that no letter and no digit
// stand before the prefix. It is declined because it would reject the key
// written inside another, whose prefix stands against the last letter of the
// body in front of it. What declining it admits is a name whose segment closes
// on rnd with a body behind it, and Test_RenderAPIKey_theRandomNamesThatCarryThePrefix
// pins both that and the ordinary names the floor turns away on its own.
//
// The byte the scan searches for is the underscore the prefix closes with, and
// the prefix is read back from it. builtin_scan.go says why a scan searches for
// one byte rather than for the prefix itself; what makes it this byte is that
// the other three are letters an English log line is written in — over the line
// these benchmarks are written on the r stands six times, the d three times and
// the n twice, where the underscore stands not at all.
//
// The scan advances one byte past the start of a candidate, which is the
// default, and here it is load-bearing: the three letters the prefix opens with
// belong to the alphabet a body is written in, so a body may close with rnd and
// the underscore of the next key stand directly behind it. A scan consuming its
// match would step over that key and leave it in the output whole. The two
// spans overlap where it happens, and Masker.locate resolves them.
//
// The scan keeps no cursor and needs none. The run behind a candidate is read
// to its end however long it is, and what bounds the work is where a body opens
// rather than how far it reads: the underscore in front of one is written in
// neither the prefix's own alphabet nor the body's, so every body begins where
// a run begins and no two candidates can read the same run. That rules out the
// quadratic input a line dense in prefixes would otherwise be, and
// Test_renderAPIKeyPrefix_runsDoNotOverlap names the character it rests on.
//
// What this pattern over-matches on is twenty-eight letters and digits written
// behind the prefix, and the floor being as low as it is, that takes in every
// digest a reader is likely to have written down: an MD5 is thirty-two
// hexadecimal characters, a SHA-1 forty and a SHA-256 sixty-four, all of them
// base62 and none of them carrying anything that ends a run. The other shape is
// base64url text — that alphabet holds the underscore where hexadecimal and
// standard base64 do not, so a payload written in it can carry rnd_ inside
// itself. Both are paid rather than avoided, because there is nothing left to
// tell them from a key: twenty-eight letters and digits behind rnd_ is a key's
// format exactly, and a scan declining them declines every key Render issues.
// Test_RenderAPIKey_aDigestBehindThePrefix and
// Test_RenderAPIKey_insideAnOpaqueRun pin them. What stays out is prose, since
// no word runs into an underscore with twenty-eight unbroken letters and digits
// behind it.
//
// One pattern, because Render issues one credential to authenticate its API
// with, and "API key" is Render's own word for it — the word its dashboard, its
// documentation and its RENDER_API_KEY environment variable use. The CLI writes
// the access token an interactive login returns into the same configuration
// field it writes a key into and sends both as the same bearer credential, so a
// caller who redacts one wants the other gone as well. Nothing of Render's
// states that token's shape; where it is a key's, this scan locates it, and
// nothing here is written to it.
//
// referenceRenderAPIKeyFind in builtin_render_api_key_test.go states the
// grammar again as a walk over every position, spelling the prefix, the floor
// and the alphabet out so that the two are changed together, and the fuzz
// target beside it holds this scan to that walk. Why it is a walk rather than
// the expression the grammar states compactly as is written there.
var renderAPIKey = NewPattern("render-api-key", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two.
	retain := renderAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], renderAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for
		// the reason the rationale above gives: a body may close with the three
		// letters the prefix opens with, so a key can begin three characters
		// before the end of the one before it.
		offset = anchor + 1

		if anchor < renderAPIKeyAnchorIndex {
			continue
		}
		start := anchor - renderAPIKeyAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != renderAPIKeyPrefix[0] || !strings.HasPrefix(src[start:], renderAPIKeyPrefix) {
			continue
		}

		body := start + len(renderAPIKeyPrefix)
		end := base62RunEnd(src, body)
		if end == len(src) {
			// The run reaches the end of the input, so neither where the body
			// ends nor whether it is long enough to be one is settled here:
			// what comes next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if end-body >= renderAPIKeyBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// renderAPIKeyPrefix is what every API key opens with, and what the scan
	// reads back from its anchor. Its first three characters belong to the
	// alphabet a body is written in and the underscore it closes with does not,
	// which is why the scan resumes a byte along and why it needs no cursor.
	// Test_renderAPIKeyPrefix holds it to the first and
	// Test_renderAPIKeyPrefix_runsDoNotOverlap to the second.
	renderAPIKeyPrefix = "rnd_"

	// renderAPIKeyAnchor is the byte the scan searches the input for and
	// renderAPIKeyAnchorIndex is where it stands in the prefix, so a candidate
	// begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what makes it
	// this byte.
	renderAPIKeyAnchor      = '_'
	renderAPIKeyAnchorIndex = 3

	// renderAPIKeyBodyChars is the count a body is held to, read as a floor
	// rather than exactly. The rationale above weighs both the reading and the
	// number.
	renderAPIKeyBodyChars = 28
)

// renderAPIKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var renderAPIKeyTail = newPrefixTail(renderAPIKeyPrefix)
