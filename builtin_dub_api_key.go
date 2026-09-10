package mask

import "strings"

// DubAPIKey locates Dub API keys: the prefix dub_ and twenty-four letters and
// digits behind it — twenty-eight characters altogether. One shape serves every
// key Dub issues: a key carries whatever scopes it was created with and may be
// tied to a machine user rather than to a person, so nothing in the string says
// what it reaches.
//
// A key is located wherever it is written, with no word boundary either side,
// and exactly twenty-eight characters of it are. So text of that shape is
// redacted whether or not Dub issued it. A space, a dot, a hyphen, an
// underscore or a character outside the alphabet ends the reading, so text as
// it is ordinarily written is not affected. A longer run of letters and digits
// is a key with something written after it, and the key alone is redacted.
//
// Its name is "dub-api-key".
func DubAPIKey() Pattern { return dubAPIKey }

// API key is Dub's own term for the whole of what this locates. The
// authentication page heads the section "API keys" and writes the format as
// DUB_API_KEY=dub_xxxxxxxx, the reference sends one as Authorization: Bearer
// dub_xxxx, and the dashboard that mints one titles the dialog "Create API key"
// and reports "API Key Created".
//
// What those pages state is the prefix and nothing else — every one of them
// writes the rest as placeholder characters. The alphabet and the length come
// from Dub's own implementation, which is public: the route behind that dialog
// mints a key as dub_ and a nanoid of twenty-four characters, and the nanoid it
// calls is built over a custom alphabet of the digits and the letters of both
// cases. So the prefix, the alphabet and the count are all read off what Dub
// issues a key with rather than off a value somebody was shown.
//
// No published ruleset reads this format. gitleaks, trufflehog, noseyparker and
// kingfisher carry no Dub rule at all, so there is nothing to weigh the
// vendor's own numbers against and nothing that disagrees with them.
//
// The count is read exactly rather than as a floor. A count is read exactly
// where the vendor wrote the length down, and here the length is the argument
// the generator is called with. What an exact count costs is what it costs
// everywhere: a run of the alphabet longer than twenty-four is not one longer
// key but a key with something written after it, and only the key is redacted.
// A floor would swallow what the run went on to hold, which is text belonging
// to no credential.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the digits, and neither the hyphen nor the underscore base64url
// adds. That is the alphabet Dub's generator is handed, and leaving the
// underscore out is doing more work here than an alphabet usually does. It ends
// a body at the next segment of a snake_case name, and it is what tells this
// format from everything else Dub writes with the same four characters in
// front. An API key is the one string where a body opens straight behind dub_;
// every other kind names itself first and closes that name with an underscore,
// so the twenty-four characters this scan reads run into a character no body
// admits and the value is turned away. That is a rule about the format rather
// than a list, and it holds of a kind Dub adds tomorrow as it holds of the ones
// Test_DubAPIKey_theOtherPrefixes writes out.
//
// The prefix is read in the one case Dub issues keys in. Reading DUB_ as well
// would buy nothing — no key is minted in capitals — and would cost a candidate
// at DUB_API_KEY, which is the name a caller keeps a log by and the name Dub's
// own documentation writes a key against.
//
// There is no boundary on either side of a match. One in front would drop the
// whole match rather than trim it wherever a key is written against a word
// character, as DUB_API_KEY_dub_... is. One behind would drop rather than trim
// as well: under an exact count a key written against a twenty-fifth character
// of the alphabet is still a key with something after it, and a boundary there
// would locate nothing at all where this scan redacts the twenty-eight Dub
// issued and leaves the character that belongs to no credential in the text.
// Test_DubAPIKey_nextToWordCharacters writes both out.
//
// The byte the scan searches the input for is the underscore the prefix closes
// with, and the prefix is read back from it. builtin_scan.go says why a scan
// searches for one byte rather than for the prefix itself; what makes it this
// byte is that the other three are letters an English log line is written in —
// over the line these benchmarks are written on the d stands four times, the u
// three and the b twice, where the underscore stands not at all. It is
// also the byte that costs the search least inside a body: no body is written
// with an underscore, so a search resuming into one runs to the end of it
// without stopping, where any of the three letters would stop about once in
// sixty-two characters and be turned away again.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a key or not, which is the default and needs no argument. It
// is load-bearing here rather than merely correct: the three letters the prefix
// opens with belong to the alphabet a body is written in, so a body may close
// with dub and the underscore of the next key stand directly behind it, which
// makes the second key begin three characters before the first one ends. A scan
// consuming its match would step over that key and leave it in the output
// whole. The two spans overlap where it happens, and Masker.locate resolves
// them. Test_DubAPIKey_aKeyBeginningInsideAnother drives that, where both
// candidates become keys; the case named "a key inside a candidate the body
// turned away" drives the other half, where the candidate stepped over is one
// the body test rejected, since a scan may consume a match it never made.
//
// The scan keeps no cursor and needs none: a candidate reads at most
// twenty-eight bytes and stops, which bounds what it reads with no state to be
// wrong about. That is what rules out a quadratic input here. A scan reading a
// body to the end of its run would need the underscore's absence from the
// alphabet to divide the runs between candidates; an exact count needs nothing
// of the sort, because no candidate reads past its own twenty-eighth character
// however long the run behind it goes on.
//
// What this pattern over-matches on: twenty-four letters and digits written
// behind the prefix by something other than Dub. The underscore is what makes
// that rare in text somebody wrote — no word is spelled dub_, and a snake_case
// name whose segment closes on dub runs its next segment out at the underscore
// long before the twenty-fourth character, which the case named "a snake_case
// name long enough to be rejected rather than cut short" states as the offset
// the scan settles at. What is left is a run written in an alphabet that spells
// the prefix, and only base64url does: hexadecimal and standard base64 write no
// underscore at all, so a digest, a certificate body or an embedded image
// carries no candidate at however long it runs — the cases named "a git sha"
// and "a certificate body in standard base64" write the two encodings out.
// Test_DubAPIKey_insideAnOpaqueRun pins what base64url costs instead.
//
// The digest is the same over-match taking a value a reader had a use for.
// Hexadecimal digits are base62 and a digest carries nothing that ends a run,
// so every digest written behind the prefix is at least twenty-four characters
// — an MD5 is thirty-two, a SHA-1 forty and a SHA-256 sixty-four — and the
// first twenty-four of one are redacted with the prefix while the rest stays in
// the text. The tightening that would rule it out is the demand that the run
// stop at the count, and it is declined for what it costs: a key written
// against a letter or a digit answers the count and not the demand, so a scan
// asking for both would locate nothing there and leave every character of a
// live key in the output. Nothing else in the text tells the two apart, since
// twenty-four letters and digits behind dub_ is a key's format exactly.
// Test_DubAPIKey_aDigestBehindThePrefix pins all three digests.
//
// The kinds turned away that way are left for a reason of their own rather than
// for want of a shape, and the reason differs between them. dub_app_secret_ and
// dub_access_token_ are what an OAuth app is configured
// with and what it is issued — hexadecimal bodies of sixty and eighty
// characters where a key's is twenty-four base62 — and neither is an API key in
// Dub's own words, which is the term this pattern's name is held to. dub_pk_
// and dub_embed_ are a publishable key and a short-lived embed token, both of
// which Dub hands to a browser on purpose: they are published by design where
// an API key authenticates, so a caller has reason to redact one and not the
// other, and each is a switch of its own rather than a widening of this one.
// dub_app_ is the client id standing beside that secret and travels in a
// redirect, so it is an identifier rather than a credential.
// Test_DubAPIKey_theOtherPrefixes writes each of them out, so that reading one
// is a change somebody argues for rather than one somebody notices afterwards.
//
// referenceDubAPIKey in builtin_dub_api_key_test.go keeps the grammar as a
// regular expression, spelling the prefix, the count and the alphabet again so
// that the two are changed together, and the fuzz target beside it holds this
// scan to that expression. An expression is affordable here: the repetition is
// exact, so the machine an engine builds is read once and stops, and the four
// character literal in front of it is what an engine searches the text for.
var dubAPIKey = newBuiltin("dub-api-key", &dubAPIKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two, and this format adds nothing to them — a key
	// whole is a key finished, since nothing behind the count is read.
	retain := dubAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], dubAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for
		// the reason the rationale above gives: a body may close with the three
		// letters the prefix opens with, so a key can begin three characters
		// before the end of the one before it.
		offset = anchor + 1

		if anchor < dubAPIKeyAnchorIndex {
			continue
		}
		start := anchor - dubAPIKeyAnchorIndex

		// The byte the prefix opens with is tested before the prefix is
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != dubAPIKeyPrefix[0] || !strings.HasPrefix(src[start:], dubAPIKeyPrefix) {
			continue
		}

		body := start + len(dubAPIKeyPrefix)
		end := start + dubAPIKeyChars
		if end > len(src) {
			// The input ends inside the body, and the count is the whole of
			// what tells a key from any other run written behind the prefix.
			retain = min(retain, start)
			continue
		}
		if isDubAPIKeyBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// dubAPIKeyPrefix is what every API key opens with, and what the scan reads
	// back from its anchor. Its first three characters belong to the alphabet a
	// body is written in, which is what lets one key begin inside another and is
	// why the scan resumes a byte along; the underscore it closes with does not,
	// which is what keeps a search from stopping inside a body and what turns
	// away the other kinds Dub writes behind the same four characters.
	// Test_dubAPIKeyPrefix holds it to both.
	dubAPIKeyPrefix = "dub_"

	// dubAPIKeyAnchor is the byte the scan searches the input for and
	// dubAPIKeyAnchorIndex is where it stands in the prefix, so a candidate
	// begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what made it
	// this byte. Test_dubAPIKeyAnchor holds it to standing at this index.
	dubAPIKeyAnchor      = '_'
	dubAPIKeyAnchorIndex = 3

	// The counts a key is written to. Twenty-four is the length Dub's own
	// generator is called with, and twenty-eight is that with the prefix in
	// front. Test_dubAPIKeyChars holds the arithmetic to both.
	dubAPIKeyBodyChars = 24
	dubAPIKeyChars     = len(dubAPIKeyPrefix) + dubAPIKeyBodyChars
)

// isDubAPIKeyBody reports whether s is the body of a key: exactly
// dubAPIKeyBodyChars characters, all of them in the alphabet a body is written
// in.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count being left to the caller to have cut
// correctly.
func isDubAPIKeyBody(s string) bool {
	if len(s) != dubAPIKeyBodyChars {
		return false
	}
	for i := range len(s) {
		if !isBase62Byte(s[i]) {
			return false
		}
	}
	return true
}

// dubAPIKeyTail is what the scan settles the tail of its input by. prefixTail
// (builtin_scan.go) says what that is and why it is built once.
var dubAPIKeyTail = newPrefixTail(dubAPIKeyPrefix)
