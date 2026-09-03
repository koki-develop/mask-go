package mask

import "strings"

// PerplexityAPIKey locates Perplexity API keys: the prefix pplx- and the
// forty-eight or more letters and digits behind it, redacted to the end of the
// run they stand in. One string authenticates every request an account makes,
// against one balance, so nothing in a key says what it may be spent on.
//
// A key is located wherever it is written, with no word boundary either side.
// So text of that shape is redacted whether or not Perplexity issued it. A
// space, a hyphen, an underscore or a run of fewer than forty-eight letters and
// digits ends the reading, so text as it is ordinarily written is not affected.
// Where the run carries on past the forty-eighth character, it is redacted to
// its end.
//
// Its name is "perplexity-api-key".
func PerplexityAPIKey() Pattern { return perplexityAPIKey }

// API key is Perplexity's own name for this string, and it covers the whole of
// what this scan locates. The console page one is created on is API Keys, the
// page describing how they are held is API key management, the environment
// variable its own clients read one from is PERPLEXITY_API_KEY, and GitHub's
// secret scanning files the value under the token identifier perplexity_api_key.
// The endpoint that issues one programmatically names its response field
// auth_token and its example token name Production API Key; the reference
// describes that endpoint as creating an API key and the page above it uses the
// two words for the one credential, so there is a single thing here under a
// single term rather than two credentials sharing an opening.
//
// What Perplexity states of the format is the prefix, and stops there. The
// reference for the endpoint above prints what it returns as
// pplx-1234567890abcdef; the CLI's README writes
// export PERPLEXITY_API_KEY=pplx-...; every other page and every SDK writes a
// placeholder of its own. Sixteen characters in a docs example are an
// elision rather than a key masked byte for byte, so it establishes no length,
// and no alphabet and no checksum appears anywhere Perplexity publishes. The
// console page that issues a key is the one place a whole one is ever shown,
// and it is behind a login.
//
// So everything behind the prefix is read off the rulesets, and what they carry
// is one shape from one lineage. gitleaks reads pplx- and forty-eight
// characters of the letters of both cases and the digits, inside a word
// boundary either side and under an entropy floor of four; betterleaks reads
// that same expression under that same floor; kingfisher reads the format
// through the betterleaks rule under an alias rather than through a rule of its
// own. trufflehog and noseyparker do not read it at all. GitHub does list the
// format, with push protection, and its entry is not a partner pattern — it is
// GitHub's own reading rather than a format Perplexity wrote down and handed
// over — and it publishes what it detects rather than the expression it detects
// with. Forty-eight is therefore one count with one origin, which is what the
// reading below answers.
//
// The count is read as a floor and not as a count. A count is read exactly
// where it is most of what tells a value from the text around it, or where the
// vendor wrote the length down; here Perplexity wrote the prefix down and
// stopped, and forty-eight is a number somebody read off the keys they were
// shown. Were Perplexity to lengthen the random part, a scan asking for
// forty-eight exactly would locate the first fifty-three characters of a key
// and leave the rest of it in the output. Read as a floor, a key of any length
// at or above it is located to the end of its run.
//
// What the floor costs is the key cut short of it. A line cut to a column limit
// partway through one leaves a prefix and a body too short to be a body, and
// nothing is located: the random characters written before the cut stay in the
// output. Test_PerplexityAPIKey_cutShortOfTheFloor pins that, so that it stays
// a decision on the record.
//
// The entropy floor both published rules carry is not read, and it is the one
// tightening here that would cost a key rather than buy one. This
// library has no entropy heuristic: it redacts rather than reports, so a value
// declined is a credential written out in full where a value taken wrongly is a
// stretch of opaque text lost to a reader. A floor of four bits a character
// declines the key an issuer happened to draw a repetitive string for, and
// nothing about the format says such a key cannot be issued. What reading no
// entropy admits is the run of repeated characters written behind the prefix,
// which is redacted here and which Test_PerplexityAPIKey_noEntropyFloor pins.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the digits, and neither the hyphen nor the underscore base64url
// adds. That is what both published rules admit behind the prefix. Leaving the
// hyphen out is doing more work here than an alphabet usually does — it is what
// ends a body at the next segment of a kebab-cased name, and it is what makes
// every body begin where a run begins, which the account of the scan's cost
// below rests on.
//
// The prefix is read in the one case Perplexity writes it. A prefix is the
// whole of what tells this format from text, so reading it in either case buys
// nothing — PPLX- is no form a key is issued in — and it costs a candidate at
// every other spelling, including one Perplexity writes itself: its MCP server
// sends a header named X-Pplx-Integration, which carries the four letters
// capitalised and is no credential. Both published rules read the prefix as
// Perplexity writes it.
//
// There is no boundary on either side of a match. A boundary in front would
// drop the whole match rather than trim it wherever a key is written against a
// word character, as PERPLEXITY_API_KEY_pplx-... is. One behind would drop
// rather than trim as well, and where it were asked decides what it drops.
// Asked behind the count, it drops the key a letter, a digit or an underscore
// is written against. Asked behind that run, it drops the key an underscore is
// written against and nothing else, the underscore being the one word character
// no body admits. Test_PerplexityAPIKey_reachesTheEndOfTheRun writes both keys
// out. Both published rules ask for a word boundary in front of the prefix and
// close on a word boundary or one of a handful of delimiters.
//
// The tightening on offer in front is the demand that no letter and no digit
// stand before the prefix. It is declined because it would reject the key
// written inside another, whose prefix stands against the last letter of the
// body in front of it — which is a shape this scan locates and the cases pin.
// What declining it admits is a word closing on the four letters of the prefix
// with a hyphen behind it; the floor is what turns such a word away, and the
// next hyphen of a kebab-cased name ends the run long before forty-eight
// characters.
//
// The byte the scan searches the input for is the x, and the prefix is read
// back from it. builtin_scan.go says why a scan searches for one byte of its
// prefix rather than for the prefix itself; what makes it this byte is that the
// three others are each written far more often. The p and the l stand six times
// each on the line these benchmarks are written on, where the x stands once,
// and the one place an x reliably falls in a line about this vendor is the
// vendor's own name. The hyphen the prefix closes with is the byte not to
// anchor on, and for a reason unrelated to the work it does as a last
// character: it is what an ISO timestamp, a UUID, a kebab-cased name and a long
// command-line flag are each written with, and it stands twice on that same
// line.
//
// What the x costs, and the hyphen would not, is that a body may be written
// with it: a run of the alphabet stops the search about once in sixty-two
// characters however long that run is, where a hyphen stops it nowhere inside
// one. That is the trade, and it is taken because a caller's text is prose and
// log lines far more often than it is base62 payloads, and because a stop that
// opens no candidate is three bytes read and gone.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a key or not, which is the default. It is what a key
// beginning inside another needs: the four letters the prefix opens with belong
// to the alphabet a body is written in, so a body may close with pplx and the
// hyphen of the next key stand directly behind it, and a scan consuming its
// match would step over that key and leave it in the output whole. The two
// spans overlap where it happens, and Masker.locate resolves them.
//
// The scan keeps no cursor and needs none. The run behind a candidate is read
// to its end however long that run is, and what bounds the work is where a body
// opens rather than how far it reads: the hyphen in front of one is written in
// neither the prefix's own alphabet nor the body's, so every body begins where
// a run begins and no two candidates can read the same run. That is what rules
// out the quadratic input a line dense in prefixes would otherwise be, and
// Test_perplexityAPIKeyPrefix_runsDoNotOverlap names the character it rests on.
//
// What this pattern over-matches on is forty-eight letters and digits written
// behind the prefix, and two shapes are worth naming. One is base64url text:
// that alphabet holds the hyphen where hexadecimal and standard base64 do not,
// so a payload written in it — a JWT signature, the routable body some other
// vendor encodes a credential as — can carry pplx- inside itself, and where
// forty-eight base62 characters follow, the run from the prefix to the end of
// that payload is redacted. The other is the digest: a SHA-256 is sixty-four
// hexadecimal characters, which are base62 and carry nothing that ends a run,
// so pplx- written in front of one is a key's format exactly and is redacted
// whole. Both are paid rather than avoided, because there is nothing left to
// tell them from a key: a scan declining forty-eight letters and digits behind
// this prefix declines every key Perplexity issues.
// Test_PerplexityAPIKey_insideAnOpaqueRun and
// Test_PerplexityAPIKey_aDigestBehindThePrefix pin them.
//
// What reaches a span is never prose, a git SHA or an MD5. The prefix closes on
// a hyphen, which no word runs into, and behind it must stand forty-eight
// unbroken letters and digits: a SHA-1 is forty characters and an MD5
// thirty-two, so neither reaches the floor even written straight behind the
// prefix, and a digest standing on its own carries no hyphen to hold a prefix
// at however long it runs.
//
// The names Perplexity gives its own products carry this prefix and are the
// text most likely to be written near a key, so what holds them away is worth
// stating. The API was announced as pplx-api; the embedding models are
// pplx-embed-v1-0 and pplx-embed-context-v1-0; the command line is pplx-cli and
// ships as pplx-aarch64-apple-darwin.bin; the MCP server names itself
// pplx-mcp-server in a header of its own, and the search SDK pplx-srch-sdk.
// Each of them carries a whole prefix and none is located, because the segment
// behind the prefix is broken by the next hyphen long before forty-eight
// characters — the same floor doing the same work it does for a word.
// Test_PerplexityAPIKey_theVendorsOwnNames holds every one of those names
// there, and holds beside them the name that is located: a segment that does
// run forty-eight unbroken characters is a key's format exactly, and this scan
// cannot tell it from one.
//
// referencePerplexityAPIKeyFind in builtin_perplexity_api_key_test.go keeps the
// grammar as a regular expression, spelling the prefix, the floor and the
// alphabet again so that the two are changed together, and the fuzz target
// beside it holds this scan to that expression.
var perplexityAPIKey = newBuiltin("perplexity-api-key", &perplexityAPIKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two.
	retain := perplexityAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], perplexityAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for
		// the reason the rationale above gives: a body may close with the four
		// letters the prefix opens with, so a key can begin four characters
		// before the end of the one before it.
		offset = anchor + 1

		if anchor < perplexityAPIKeyAnchorIndex {
			continue
		}
		start := anchor - perplexityAPIKeyAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != perplexityAPIKeyPrefix[0] || !strings.HasPrefix(src[start:], perplexityAPIKeyPrefix) {
			continue
		}

		body := start + len(perplexityAPIKeyPrefix)
		end := base62RunEnd(src, body)
		if end == len(src) {
			// The run reaches the end of the input, so neither where the body
			// ends nor whether it is long enough to be one is settled here:
			// what comes next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if end-body >= perplexityAPIKeyBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// perplexityAPIKeyPrefix is what every API key opens with, and what the
	// scan reads back from its anchor. Its first four characters belong to the
	// alphabet a body is written in, which is what lets one key begin inside
	// another and is why the scan resumes a byte along; the hyphen it closes
	// with does not, which is what keeps two candidates from ever reading the
	// same run. Test_perplexityAPIKeyPrefix holds it to the first and
	// Test_perplexityAPIKeyPrefix_runsDoNotOverlap to the second.
	perplexityAPIKeyPrefix = "pplx-"

	// perplexityAPIKeyAnchor is the byte the scan searches the input for and
	// perplexityAPIKeyAnchorIndex is where it stands in the prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what made it
	// this byte and what the choice costs.
	perplexityAPIKeyAnchor      = 'x'
	perplexityAPIKeyAnchorIndex = 3

	// perplexityAPIKeyBodyChars is the count a body is held to, read as a floor
	// rather than exactly. Forty-eight is what the one published expression
	// states, and Perplexity states no length of its own; the rationale above
	// weighs reading it as a floor.
	perplexityAPIKeyBodyChars = 48
)

// perplexityAPIKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var perplexityAPIKeyTail = newPrefixTail(perplexityAPIKeyPrefix)
