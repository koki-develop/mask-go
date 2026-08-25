package mask

import "strings"

// LinearAPIKey locates Linear personal API keys: the prefix lin_api_ and the
// characters behind it. One shape serves every key Linear issues — a key
// carries the permissions of whoever created it and may be narrowed to reading
// alone or to a single team, so nothing in the string says what it is allowed
// to do.
//
// A key is located wherever it is written, with no word boundary either side,
// and is redacted from its lin_api_ to the end of the run it stands in. So a
// key written against a word character keeps its span, and a character of the
// key's own alphabet written straight after a key is redacted with it.
//
// Its name is "linear-api-key".
func LinearAPIKey() Pattern { return linearAPIKey }

// What Linear states of this format it states in one place, a changelog entry
// from 2021, and what it states there is the prefix and nothing else. Linear
// joined GitHub's secret scanning program and changed the format of its API
// keys and OAuth access tokens to carry Linear specific prefixes, lin_api_ and
// lin_oauth_, so that GitHub could detect them; the entry names Slack and
// Stripe as having done the same for their own keys. No length, no alphabet and
// no checksum is given there. Nor is one given anywhere else: the developer
// documentation says where a personal API key is created and that a request
// carries it in the Authorization header with no Bearer in front of it, and
// writes the key itself as a placeholder rather than as a shape.
//
// Everything behind the prefix is therefore read off the rulesets, and the two
// that state a shape agree exactly, which is rarer here than it sounds:
// gitleaks reads lin_api_ and forty case-insensitive alphanumerics, trufflehog
// reads lin_api_ and forty characters of the letters of both cases and the
// digits, inside a word boundary of its own. Neither the count nor the alphabet
// differs between them. GitHub's secret scanning lists a Linear API key under
// the token identifier linear_api_key and GitGuardian ships a detector for the
// same credential; both publish what they detect rather than the expression
// they detect it with, so neither adds to or contradicts the forty.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the digits, and neither the hyphen nor the underscore base64url
// adds. That is what both rulesets admit behind the prefix, and leaving the
// underscore out is doing more work here than an alphabet usually does. It is
// what ends a body at the next segment of a snake_case name, and it is what
// makes every body begin where a run begins — which the account of the scan's
// cost below rests on.
//
// The count is read as a floor and not as a count. A count is read exactly
// where it is most of what tells a value from the text around it, or where the
// vendor wrote the length down. Here the vendor wrote the prefix down and
// stopped there: forty is a number two rulesets read off the keys they were
// shown, and there is no page to hold Linear to it. Were Linear to lengthen
// the random part, a scan asking for forty exactly would locate the first
// forty-eight characters of a key and leave the rest of it in the output. Read
// as a floor, a key of any length at or above it is located to the end of its
// run.
//
// What the floor costs is the key shorter than it. A line cut to a column limit
// partway through one leaves a prefix and a body too short to be a body, and
// nothing is located: the random characters written before the cut stay in the
// output. That is the far side of this choice, and the cases in
// builtin_linear_api_key_test.go pin it so that it stays a decision on the
// record.
//
// The floor is doing more here than a length, and more than the npm floor this
// scan is otherwise shaped like. Four characters ending in npm close no word
// anybody writes, so nothing but a snake_case name npm itself exports reaches
// that prefix at all. These three letters do close words: berlin, dublin,
// merlin, marlin, muslin, poplin, kaolin, insulin, gremlin, violin and javelin
// each end on them, so berlin_api_ is a whole prefix inside an ordinary
// snake_case name. What turns such a name away is the forty unbroken characters
// of the alphabet a body is held to, which the next underscore of the name ends
// long before.
//
// There is no boundary on either side of a match. A boundary in front would
// drop the whole match rather than trim it wherever a key is written against a
// word character, as LINEAR_API_KEY_lin_api_... is, and one behind it would
// drop a key followed by a character of the key's own alphabet — which, since
// the span already reaches to the end of the run, is every key with a letter
// or a digit written against it.
//
// The tightening on offer in front is the one the Slack and Stripe scans take:
// to ask that no letter and no digit stand before the prefix. That is exactly
// what would turn the berlin_api_ family away, and it is still declined,
// because of what else it would turn away. A key can be written inside the one
// before it here — the paragraph below is about how — and where it is, the
// character in front of the second key's prefix is the last letter of the first
// key's body. The demand would reject that second key and leave its whole body
// in the output, which is a live credential against a snake_case name that also
// carries forty unbroken characters of one run. Stripe can take the demand
// because no Stripe key can begin inside another; this format can, so the two
// are not the same trade. What is admitted instead is pinned by the cases in
// builtin_linear_api_key_test.go, so that it stays a decision on the record.
//
// The scan resumes one byte past the start of a candidate whether it became a
// key or not. The three letters in front of the prefix's first underscore
// belong to the alphabet a body is written in, so a body may close with lin and
// the underscore opening the next key stand directly behind it: lin_api_, a
// body whose last three characters are lin, then _api_ and a body of its own is
// two keys, the second beginning three characters before the first one ends.
// Consuming a match would step over such a key and leave it in the output
// whole. The two spans then overlap, which a Masker resolves into one.
//
// No cursor is kept over the run, and none is needed, which is the other thing
// the underscore buys. A candidate asks for an underscore at the character in
// front of its body and base62 holds none, so the underscore of the next
// candidate can be no earlier than the byte that ends this run, and the run
// that candidate reads therefore begins past this one. Successive candidates
// read runs that do not overlap, and reading all of them comes to the length
// of the input — the guarantee a scan whose prefix closes on a character its
// own body admits has to keep a run cursor for instead, bought here without
// state. Test_linearAPIKeyPrefix_runsDoNotOverlap holds the prefix to the one
// thing that argument rests on, and Test_LinearAPIKey_scanIsLinear drives it.
//
// What this pattern over-matches on: forty characters of base62 behind
// lin_api_ inside something nobody issued. The two underscores are what make
// that rare. Standard base64 writes none at all, so a certificate, a PEM body
// or an embedded image carries no prefix to be found at however long it runs,
// and only a base64url encoding can hold one — and there eight characters drawn
// from an alphabet of sixty-four stand where the prefix stands about once in
// two hundred and eighty million million characters. What is left is text
// somebody wrote: a snake_case name whose segment closes on lin, then api, then
// forty unbroken letters and digits. berlin_api_ and a digest behind it is
// redacted from its lin onward, and ber is what stays. That text is a key's
// format exactly, and the tightening that would have ruled it out is the one
// the paragraph above declines and says what it costs.
//
// The collision this format leaves is the same one npm's leaves, and it is
// reached at the same place: a digest written behind the prefix. The
// hexadecimal digits are base62 and nothing inside a digest ends a run, so
// lin_api_ and the forty characters of a SHA-1 is a key to this scan, as
// lin_api_ and the sixty-four of a SHA-256 is. Those are redacted, and nothing
// could be done about it that would not cost a credential: such a run is a
// key's format exactly, so a scan declining it would decline every key Linear
// happened to write in the digits alone. An MD5 is left alone, at thirty-two
// characters eight short of the floor, and so is any digest written behind a
// hyphen rather than an underscore. Test_LinearAPIKey_aDigestBehindThePrefix
// pins all four.
//
// What reaches a span is never prose, and never a digest standing on its own. A
// digest carries no underscore, so it holds no prefix to be found at however
// long it runs, and no word is spelled lin_api_. Ordinary snake_case text
// carries the prefix, as berlin_api_key does, and what turns it away is the
// forty unbroken characters of the alphabet the body is held to.
//
// The other credential that changelog names is not read, and what stops it is
// that the entry is the only thing naming it. lin_oauth_ is stated as a prefix
// and nothing states what stands behind one: neither ruleset above carries a
// rule for it, no example of such a token has been published, and Linear's own
// OAuth page still prints its example access token as sixty-four hexadecimal
// characters with no prefix at all — which is the format the changelog says was
// replaced. So the one thing a scan needs that an anchor does not give it, what
// a body looks like, has never been written down for this one. A floor invented
// for it would be a guess at exactly the part of the grammar that is load
// bearing here, and being wrong about it locates nothing at all. What declining
// it costs is an OAuth access token left in the output whole, which is stated
// rather than hidden: Test_LinearAPIKey_theOtherPrefix pins the decision, so
// that reading the second prefix is a change somebody argues for rather than
// one somebody notices afterwards. GitHub's secret
// scanning does list a Linear OAuth access token beside the API key, under the
// token identifier linear_oauth_access_token, and publishes an expression for
// neither.
//
// The client secret an OAuth app is configured with is not read either. The one
// ruleset reading it reads thirty-two hexadecimal characters where the word
// linear stands in front of them in the same assignment, which is a rule about
// the text around a value rather than about the value: thirty-two hexadecimal
// characters on their own are an MD5, and a grammar admitting one would redact
// every digest a log line carries.
//
// referenceLinearAPIKey in builtin_linear_api_key_test.go keeps the grammar as
// a regular expression, spelling the prefix, the floor and the alphabet again
// so that the two are changed together, and the fuzz target beside it holds
// this scan to that expression.
var linearAPIKey = NewPattern("linear-api-key", func(src string) []Span {
	var spans []Span

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], linearAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for the
		// reason the rationale above gives: a body may close with the three letters
		// the prefix opens with, so a key can begin three characters before the end
		// of the one before it. Stepping one byte past the anchor is what leaves the
		// next candidate one byte past this one, which builtin_scan.go sets out.
		offset = anchor + 1

		if anchor < linearAPIKeyAnchorIndex {
			continue
		}
		start := anchor - linearAPIKeyAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != linearAPIKeyPrefix[0] || !strings.HasPrefix(src[start:], linearAPIKeyPrefix) {
			continue
		}

		body := start + len(linearAPIKeyPrefix)

		// A candidate that carries the prefix resumes at the first position a
		// key could begin at instead, which is the body: the prefix carries the
		// l it opens with nowhere else, so no key begins inside one that has
		// matched. Without this the second underscore of every prefix is an
		// anchor of its own, and a line of prefixes is walked twice over.
		//
		// Test_linearAPIKeyAnchor holds the prefix to carrying that l once,
		// which is the whole of the claim.
		offset = body + linearAPIKeyAnchorIndex

		if end := base62RunEnd(src, body); end-body >= linearAPIKeyBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
})

const (
	// linearAPIKeyPrefix is what every personal API key opens with, and what the
	// scan reads back from its anchor. Its first three characters belong to the
	// alphabet a body is written in, which is what lets one key begin inside
	// another and is why the scan resumes a byte along; the underscore it closes
	// with does not, which is what keeps two candidates from ever reading the
	// same run. Test_linearAPIKeyPrefix holds it to the first and
	// Test_linearAPIKeyPrefix_runsDoNotOverlap to the second.
	linearAPIKeyPrefix = "lin_api_"

	// linearAPIKeyAnchor is the byte the scan searches the input for and
	// linearAPIKeyAnchorIndex is where it stands in the prefix, so a candidate
	// begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; what makes it this byte is that every
	// letter of lin_api_ is one an English log line is written in — over the
	// line these benchmarks are written on the l stands five times, the i and
	// the a six each — where neither underscore stands once. The first of the
	// two is taken rather than the second so that a candidate is turned away by
	// the l three characters in front of it, which is where the shorter walk
	// back ends.
	linearAPIKeyAnchor      = '_'
	linearAPIKeyAnchorIndex = 3

	// linearAPIKeyBodyChars is the count a body is held to, read as a floor
	// rather than exactly. Forty is what both rulesets stating a shape state,
	// and Linear states no length of its own; the rationale above weighs
	// reading it as a floor. It is also what holds a snake_case name closing on
	// lin away from the prefix, which the npm scan needs no count for.
	linearAPIKeyBodyChars = 40
)
