package mask

import "strings"

// GroqAPIKey locates Groq API keys: the prefix gsk_ and the fifty or more
// letters and digits behind it, redacted to the end of the run they stand in.
// Every key any published ruleset carries is fifty-two characters behind the
// prefix, fifty-six altogether. One string serves every model Groq serves and
// every endpoint it is served at, so nothing in a key says what it may be spent
// on.
//
// A key is located wherever it is written, with no word boundary either side.
// So text of that shape is redacted whether or not Groq issued it. A space, a
// hyphen, an underscore or a run of fewer than fifty letters and digits ends
// the reading, so text as it is ordinarily written is not affected. Where the
// run carries on past the fiftieth character, it is redacted to its end.
//
// Its name is "groq-api-key".
func GroqAPIKey() Pattern { return groqAPIKey }

// Groq states the prefix and stops there. Its cookbook writes a key as gsk_...
// in the environment assignment a tutorial opens with, as gsk_XXXXX in the
// .env.example beside another, and its security onboarding page writes
// gsk_your_secret_key_here; the console page that issues a key is the only
// place a whole one is ever shown, and it is behind a login. No length, no
// alphabet and no checksum appears anywhere Groq publishes.
//
// GitHub carries the format as a partner pattern under the token identifier
// groq_api_key, with push protection and a validity check, and publishes what
// it detects rather than the expression it detects with. A partner pattern is
// one the vendor wrote and gave to GitHub rather than one somebody inferred
// from published keys, so the format is written down — just not anywhere a
// scan can read it. What that entry does say out loud is that this token has
// versions: it carries GitHub's token-versions note, which states that a
// provider may support more than one version of a token and that push
// protection covers only the most recent ones.
//
// So everything behind the prefix is read off the rulesets, and they divide on
// exactly one thing. trufflehog reads gsk_ and fifty-two letters and digits;
// kingfisher reads the same and holds what that admits down with four digits at
// least and an entropy floor; betterleaks reads the same count without regard
// to case, which over the letters of one case and the digits is the same class
// read twice over. noseyparker reads fifty to fifty-four. Every key any of the
// four publishes is fifty-two.
//
// The count is therefore read as a floor and not as a count. A count is read
// exactly where it is most of what tells a value from the text around it, or
// where the vendor wrote the length down; here Groq wrote the prefix down and
// stopped. Were Groq to lengthen the random part, a scan asking for fifty-two
// exactly would locate the first fifty-six characters of a key and leave the
// rest of it in the output — and GitHub's entry says there is already more than
// one version of this token, which is the thing an exact count cannot survive.
// Read as a floor, a key of any length at or above it is located to the end of
// its run. That is the reading the Linear scan takes on a prefix its vendor
// states alone, and it is taken here for that reason.
//
// The floor is fifty rather than fifty-two, which is the one number here that
// is nobody's example. A floor fails in one direction only — a key shorter than
// it is located nowhere — and fifty is the shortest body any published rule
// admits, so a key of a length noseyparker allowed for is still redacted whole.
// The two characters that costs are two characters of an already unreachable
// grammar.
//
// What the floor costs on the other side is the key cut short of it. A line cut
// to a column limit partway through one leaves a prefix and a body too short to
// be a body, and nothing is located: the random characters written before the
// cut stay in the output. Test_GroqAPIKey_cutShortOfTheFloor pins that, so that
// it stays a decision on the record.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the digits, and neither the hyphen nor the underscore base64url
// adds. That is what all four rulesets admit behind the prefix. Leaving the
// underscore out is doing more work here than an alphabet usually does — it is
// what ends a body at the next segment of a snake_case name, and it is what
// makes every body begin where a run begins, which the account of the scan's
// cost below rests on.
//
// Every published key carries eight characters at the twenty-first character of
// its body, and this scan declines to read them. In the two keys published
// unaltered they are WGdyb3FY, the base64 encoding of the six bytes XgroqX,
// which is the vendor's own name standing inside the value the way the eight
// characters of the OpenAI marker do; the two noseyparker publishes carry
// WGdyb2FY and WGdyb4FY, the same eight with the q written over, which is what
// an example scrubbed by hand looks like. What separates this marker from the
// OpenAI one is who states it: that one is read by every ruleset that reads the
// format and rests on a partner pattern, where this one is stated by no vendor
// source and by no published rule, and appears here only in the keys somebody
// happened to publish. A marker read wrong locates nothing at all, which is the
// whole credential rather than the end of one, and what declining it admits is
// fifty letters and digits behind the prefix that carry no marker — text as
// opaque as a key and of a key's format exactly.
// Test_GroqAPIKey_theMarkerThePublishedKeysCarry drives both.
//
// The prefix is read in the one case Groq writes it. A prefix is the whole of
// what tells this format from text, so reading it in either case buys nothing —
// GSK_ is no form a key is issued in — and costs a candidate opened at every
// uppercase spelling. betterleaks is the one ruleset that reads it without
// regard to case; the other three read it as Groq writes it.
//
// There is no boundary on either side of a match. A boundary in front would
// drop the whole match rather than trim it wherever a key is written against a
// word character, as GROQ_API_KEY_gsk_... is. One behind would drop rather
// than trim as well, and where it were asked decides what it drops. Asked
// behind the count, it drops the key a letter, a digit or an underscore is
// written against. Asked behind that run, it drops the key an underscore is
// written against and nothing else, the underscore being the one word
// character no body admits.
// Test_GroqAPIKey_reachesTheEndOfTheRun writes both keys out. Every ruleset
// reading this format asks for \b on both sides.
//
// The tightening on offer in front is the demand that no letter and no digit
// stand before the prefix. It is declined because it would reject the key
// written inside another, whose prefix stands against the last letter of the
// body in front of it — which is a shape this scan locates and the cases pin.
// What declining it admits is a snake_case name whose segment closes on gsk,
// which carries a whole prefix; what turns such a name away instead is the
// floor, which the next underscore of the name ends long before.
//
// The byte the scan searches the input for is the underscore the prefix closes
// with, and the prefix is read back from it. builtin_scan.go says why a scan
// searches for one byte of its prefix rather than for the prefix itself; what
// makes it this byte is that the other three are letters an English log line is
// written in — over the line these benchmarks are written on the s stands five
// times, the g twice and the k once, where the underscore stands not at all.
// It is also the one character of the prefix no body is written with, so a run
// of a body opens no candidate however long it runs, which is what keeps a
// base64 payload or a digest from stopping the search at every letter it
// carries.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a key or not, which is the default. It is what a key
// beginning inside another needs: the three letters the prefix opens with
// belong to the alphabet a body is written in, so a body may close with gsk and
// the underscore of the next key stand directly behind it, and a scan consuming
// its match would step over that key and leave it in the output whole. The two
// spans overlap where it happens, and Masker.locate resolves them.
//
// The scan keeps no cursor and needs none. The run behind a candidate is read
// to its end however long that run is, and what bounds the work is where a body
// opens rather than how far it reads: the underscore in front of one is written
// in neither the prefix's own alphabet nor the body's, so every body begins
// where a run begins and no two candidates can read the same run. That is what
// rules out the quadratic input a line dense in prefixes would otherwise be,
// and Test_groqAPIKeyPrefix_runsDoNotOverlap names the character it rests on.
//
// What this pattern over-matches on is fifty letters and digits written behind
// the prefix, and two shapes are worth naming. One is base64url text: that
// alphabet holds the underscore where hexadecimal and standard base64 do not,
// so a payload written in it — a JWT signature, the routable body some other
// vendor encodes a credential as — can carry gsk_ inside itself, and where
// fifty base62 characters follow, the run from the prefix to the end of that
// payload is redacted. The other is the digest: a SHA-256 is sixty-four
// hexadecimal characters, which are base62 and carry nothing that ends a run,
// so gsk_ written in front of one is a key's format exactly and is redacted
// whole. Both are paid rather than avoided, because there is nothing left to
// tell them from a key: a scan declining fifty letters and digits behind this
// prefix declines every key Groq issues. Test_GroqAPIKey_insideAnOpaqueRun and
// Test_GroqAPIKey_aDigestBehindThePrefix pin them.
//
// What reaches a span is never prose, a git SHA or an MD5. The prefix closes on
// an underscore, which no word runs into, and behind it must stand fifty
// unbroken letters and digits: a SHA-1 is forty characters and an MD5
// thirty-two, so neither reaches the floor even written straight behind the
// prefix, and a digest standing on its own carries no underscore to hold a
// prefix at however long it runs.
//
// referenceGroqAPIKeyFind in builtin_groq_api_key_test.go keeps the grammar as
// a regular expression, spelling the prefix, the floor and the alphabet again
// so that the two are changed together, and the fuzz target beside it holds
// this scan to that expression.
var groqAPIKey = NewPattern("groq-api-key", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two.
	retain := groqAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], groqAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for
		// the reason the rationale above gives: a body may close with the three
		// letters the prefix opens with, so a key can begin three characters
		// before the end of the one before it.
		offset = anchor + 1

		if anchor < groqAPIKeyAnchorIndex {
			continue
		}
		start := anchor - groqAPIKeyAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != groqAPIKeyPrefix[0] || !strings.HasPrefix(src[start:], groqAPIKeyPrefix) {
			continue
		}

		body := start + len(groqAPIKeyPrefix)
		end := base62RunEnd(src, body)
		if end == len(src) {
			// The run reaches the end of the input, so neither where the body
			// ends nor whether it is long enough to be one is settled here:
			// what comes next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if end-body >= groqAPIKeyBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// groqAPIKeyPrefix is what every API key opens with, and what the scan
	// reads back from its anchor. Its first three characters belong to the
	// alphabet a body is written in, which is what lets one key begin inside
	// another and is why the scan resumes a byte along; the underscore it
	// closes with does not, which is what keeps two candidates from ever
	// reading the same run. Test_groqAPIKeyPrefix holds it to the first and
	// Test_groqAPIKeyPrefix_runsDoNotOverlap to the second.
	groqAPIKeyPrefix = "gsk_"

	// groqAPIKeyAnchor is the byte the scan searches the input for and
	// groqAPIKeyAnchorIndex is where it stands in the prefix, so a candidate
	// begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what makes it
	// this byte.
	groqAPIKeyAnchor      = '_'
	groqAPIKeyAnchorIndex = 3

	// groqAPIKeyBodyChars is the count a body is held to, read as a floor
	// rather than exactly. Groq states no length of its own, three rulesets
	// read fifty-two and the fourth reads fifty to fifty-four; the rationale
	// above weighs reading the shortest of those as a floor.
	groqAPIKeyBodyChars = 50
)

// groqAPIKeyTail is what the scan settles the tail of its input by. prefixTail
// (builtin_scan.go) says what that is and why it is built once.
var groqAPIKeyTail = newPrefixTail(groqAPIKeyPrefix)
