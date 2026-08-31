package mask

import "strings"

// OryAPIKey locates the API keys Ory Network issues: the letters ory, an
// underscore, one of the words naming the kind, another underscore, and the
// thirty-two or more letters and digits behind it, redacted to the end of the
// run they stand in. Three prefixes are written in that shape — ory_pat_ and
// ory_apikey_, which a project API key carries, and ory_wak_, which a workspace
// API key carries — and a key of either kind authorizes the privileged
// operations of an admin API, so whoever holds one can read and change the
// identities, sessions and configuration it reaches.
//
// A key is located wherever it is written, with no word boundary either side.
// So text of that shape is redacted whether or not Ory issued it. A space, a
// hyphen, an underscore or a run of fewer than thirty-two letters and digits
// ends the reading, so text as it is ordinarily written is not affected. Where
// the run carries on past the thirty-second character, it is redacted to its
// end.
//
// Its name is "ory-api-key".
func OryAPIKey() Pattern { return oryAPIKey }

// Ory states the three prefixes and stops there. Its page on identifiable token
// formats lists them under the heading Ory Network API keys — ory_pat_ or
// ory_apikey_ for the Admin API key a project is reached with, ory_wak_ for the
// Management API key a workspace is reached with — and the page that issues
// them says of a key only that Ory API Keys have a ory_apikey_ or ory_pat_
// prefix, which makes it easy to identify them when analyzing code. No
// alphabet, no length and no checksum appears anywhere Ory publishes, and the
// console that issues a key is behind a login.
//
// The rulesets add nothing, because none of them carries this format at all:
// gitleaks, trufflehog, kingfisher, noseyparker and betterleaks have no Ory
// rule between them, and GitHub's list of supported secret scanning patterns
// names no Ory credential. So everything behind the prefix is read off the one
// key Ory writes down whole: the bearer token its create-identity and
// import-identities calls are shown with. It carries ory_pat_ and thirty-two
// characters behind it, written in the letters of either case and the digits,
// with neither a hyphen nor an underscore among them.
//
// One key is what the count rests on, which is thinner than a ruleset and is
// why the count is read as a floor. A count is read exactly where the vendor
// wrote the length down or where its own generator does, and Ory does neither.
// Were Ory to lengthen the random part, a scan asking for thirty-two exactly
// would locate the first forty characters of a key and leave the rest in the
// output. Read as a floor, a key of any length at or above it goes to the end
// of its run.
//
// The floor fails downward in silence. Were a real body shorter than
// thirty-two, this pattern would locate no key at all, every case here would
// pass, and the corpus could not report it either — its keys are built to the
// floor, so they move with it. What would move the count down is a shorter key
// written into what Ory publishes, or a rule that reads one.
//
// What the floor costs when it is right is the key cut short of it. A line cut
// to a column limit partway through one leaves a prefix and a body too short to
// be a body, and nothing is located: the random characters in front of the cut
// stay in the output. Test_OryAPIKey_cutShortOfTheFloor pins that.
//
// Ory writes no whole key under the other two prefixes, so the body they are
// read with is a wager, and the two do not rest on the same thing. Ory
// writes a workspace key once, in its guide to the CLI, cut off after six
// characters: two digits, three lowercase letters and one uppercase. Six
// characters state no length, and they witness which characters a body may
// carry rather than which it may not — the exclusion this scan leans on is not
// among the things they can show. The apikey_ spelling has not even that much,
// and is read at the length and in the alphabet the pat_ key carries on Ory
// stating one shape for the API keys it issues and dividing them by prefix
// alone.
//
// The two halves of the wager fail differently, and only one of them fails
// safely. Read as a floor, the length is bounded in the direction that matters:
// a longer body is still located whole, and only a shorter one is missed, which
// is what leaving a prefix out would do to every key carrying it. The alphabet
// has no such bound. Were a real body to carry a hyphen or an underscore, the
// body would end there — a first segment short of thirty-two locates nothing
// and leaves the whole key in the output, and a longer one is located only as
// far as the break. Test_OryAPIKey_theThreePrefixes drives all three through
// the same body.
//
// The line under the one that writes a workspace key writes a project key as
// ory_pt_, and that spelling is not read. Ory names the project key's prefixes
// on the page that states the format and on the page that issues one, and both
// name ory_pat_ and ory_apikey_; no other page of Ory's carries the shorter
// spelling and none of the Go source Ory publishes does. So that block is read
// for what a body is written in and not for what a prefix is.
//
// Reading it would cost the invariant the kinds are held to as well as a
// fourth entry. Test_oryAPIKeyKinds asks that the three words open on three
// different bytes, which a fourth opening on p would not, and what that buys is
// a rejection on one byte: at any position at most one word is compared past
// its first character.
//
// Loosening the invariant rather than declining the word would leave the scan
// locating what it locates and cost it that. Two words can stand at one
// position only where one is written inside the other from its start, which pt
// and pat are not, so the loop would still be right to give up on a candidate
// whose word the separator does not close — it would only test two words at
// every p where it now tests one. Test_OryAPIKey_theCLIGuideSpelling pins the
// spelling as one this scan leaves alone.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the digits, and neither the hyphen nor the underscore base64url
// adds. That is what the key Ory writes down is written in. Leaving the
// underscore out is doing more work here than an alphabet usually does — it is
// what ends a body at the next segment of a snake_case name, and it is what
// makes every body begin where a run begins, which the account of the scan's
// cost rests on.
//
// The prefixes are read in the one case Ory writes them. A prefix is the whole
// of what tells this format from text, so reading it in either case buys
// nothing — ORY_PAT_ is no form a key is issued in — and costs a candidate
// opened at every uppercase spelling.
//
// The three are one pattern and not two or three. A caller has no reason to
// redact the key its deployment reaches a project with and leave the one its
// provisioning reaches the workspace with; neither is published where the other
// authenticates; and Ory Network API keys is Ory's own term for the whole of
// what is here. Two switches would mean a caller reaching for Ory had to know
// both to redact what Ory issues. The other prefixes that page carries —
// ory_at_, ory_rt_ and ory_ac_ for OAuth2, ory_session_ and ory_st_ for
// sessions, ory_lo_ for logout — stand under headings of their own and are
// written in a shape of their own: the access token Ory publishes is two runs
// of base64url divided by a dot, where an API key is one opaque run.
//
// There is no boundary on either side of a match. One in front would drop the
// whole match rather than trim it wherever a key is written against a word
// character, as ORY_API_KEY_ory_pat_... is. One behind would drop rather than
// trim as well, and where it were asked decides what it drops. Asked behind
// the count, it drops the key a letter, a digit or an underscore is written
// against. Asked behind that run, it drops the key an underscore is written
// against and nothing else, the underscore being the one word character no
// body admits.
// Test_OryAPIKey_reachesTheEndOfTheRun writes both keys out.
//
// The tightening on offer in front is the demand that no letter and no digit
// stand before the opening. It is declined because it would reject the key
// written inside another, whose opening stands against the last letter of the
// body in front of it. What declining it admits is a snake_case name whose
// segment closes on ory, and English has a shelf of words that do — directory,
// factory, memory, history, inventory, repository. Such a name carries the
// opening and the underscore behind it, and what turns it away is the word
// naming the kind and the floor together: repository_pattern and
// directory_path spell no kind, since the second underscore has to stand
// directly behind pat, apikey or wak, and a name that does spell one runs into
// the underscore of its next segment long before the thirty-second character.
// Test_OryAPIKey_theSnakeCaseNamesThatCarryTheOpening pins both.
//
// The byte the scan searches for is the underscore behind the opening, and the
// prefix is read back from it. builtin_scan.go says why a scan searches for one
// byte rather than for the prefix itself; what makes it this byte is that the
// other three are the letters of Ory's own name, which is what the host names,
// the paths and the words of a line about Ory are written with — over the line
// these benchmarks are written on the r stands eight times, the o six and the y
// twice, where the underscore stands not at all.
//
// The underscore each prefix closes with is the same character and is passed
// over, because it stands at a different depth in the three: it is the eighth
// character of ory_pat_ and of ory_wak_ and the eleventh of ory_apikey_, so a
// search for it would read two candidates back from every underscore of a
// snake_case name where this one reads one.
//
// The scan advances one byte past the start of a candidate, which is the
// default, and here it is load-bearing: the three letters the opening is made
// of belong to the alphabet a body is written in, so a body may close with ory
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
// Test_oryAPIKeyPrefixes_runsDoNotOverlap names the character it rests on.
//
// What this pattern over-matches on is thirty-two letters and digits written
// behind one of the prefixes, in two shapes. One is base64url text: that
// alphabet holds the underscore where hexadecimal and standard base64 do not,
// so a payload written in it — a JWT signature, the routable body some other
// vendor encodes a credential as — can carry a whole prefix inside itself. The
// other is the digest: an MD5 is thirty-two hexadecimal characters, which are
// base62 and carry nothing that ends a run, so an MD5 written behind a prefix
// is a key's format exactly, as the longer digests are. Both are paid rather
// than avoided, because there is nothing left to tell them from a key: a scan
// declining thirty-two letters and digits behind these prefixes declines every
// key Ory issues. Test_OryAPIKey_insideAnOpaqueRun and
// Test_OryAPIKey_aDigestBehindThePrefix pin them. What stays out is prose,
// where no word runs into an underscore for thirty-two characters.
//
// referenceOryAPIKey in builtin_ory_api_key_test.go keeps the grammar as a
// regular expression, spelling the opening, the kinds, the separator, the floor
// and the alphabet again so that the two are changed together, and the fuzz
// target beside it holds this scan to that expression.
var oryAPIKey = NewPattern("ory-api-key", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := oryAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], oryAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for
		// the reason the rationale above gives: a body may close with the three
		// letters the opening is made of, so a key can begin three characters
		// before the end of the one before it.
		offset = anchor + 1

		if anchor < oryAPIKeyAnchorIndex {
			continue
		}
		start := anchor - oryAPIKeyAnchorIndex

		// The byte the opening begins with is tested before the opening is
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the whole opening is a length and a read.
		if src[start] != oryAPIKeyOpening[0] || !strings.HasPrefix(src[start:], oryAPIKeyOpening) {
			continue
		}

		// The word naming the kind, and the separator that has to close it. The
		// three words open on three different bytes, so the comparison here
		// rejects all but one of them on its first character and at most one of
		// them can stand at this position — which is why a word that matches
		// and is not closed by the separator ends the search rather than
		// letting the next word be tried.
		body := -1
		for _, kind := range oryAPIKeyKinds {
			if !strings.HasPrefix(src[anchor+1:], kind) {
				continue
			}
			at := anchor + 1 + len(kind)
			if at == len(src) || src[at] != oryAPIKeySeparator {
				break
			}
			body = at + 1
			break
		}
		if body < 0 {
			continue
		}

		end := base62RunEnd(src, body)
		if end == len(src) {
			// The run reaches the end of the input, so neither where the body
			// ends nor whether it is long enough to be one is settled here:
			// what comes next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if end-body >= oryAPIKeyBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// oryAPIKeyPrefixes is what a candidate opens with, one entry to a word naming
// a kind.
//
// The words are read out of the declaration the scan reads them from rather
// than written out again, so that a word added there is a word this knows
// about: a table of its own is one that can come to disagree with it, and what
// a stream would then do with the prefix it had not been told about is release
// the characters a key opens with and redact nothing.
var oryAPIKeyPrefixes = func() []string {
	prefixes := make([]string, 0, len(oryAPIKeyKinds))
	for _, kind := range oryAPIKeyKinds {
		prefixes = append(prefixes, oryAPIKeyOpening+string(oryAPIKeySeparator)+kind+string(oryAPIKeySeparator))
	}
	return prefixes
}()

// oryAPIKeyKinds is the words a prefix carries between its two separators: pat
// and apikey, which Ory issues a project API key with, and wak, which it issues
// a workspace API key with. All three carry the same body, so the word is read
// to tell a prefix from text that merely opens like one and for nothing else.
//
// Test_oryAPIKeyKinds holds them to opening on three different bytes, which is
// what lets the scan stop at the first word it matches, and to being words a
// prefix can be built from.
var oryAPIKeyKinds = []string{"pat", "apikey", "wak"}

const (
	// oryAPIKeyOpening is what every prefix opens with, and what the scan reads
	// back from its anchor. Its three letters belong to the alphabet a body is
	// written in, which is what lets one key begin inside another and is why
	// the scan resumes a byte along; Test_oryAPIKeyOpening holds them there.
	oryAPIKeyOpening = "ory"

	// oryAPIKeySeparator stands twice in every prefix: behind the opening and
	// behind the word naming the kind. No body is written with it, which is
	// what keeps two candidates from ever reading the same run.
	oryAPIKeySeparator = '_'

	// oryAPIKeyAnchor is the byte the scan searches the input for and
	// oryAPIKeyAnchorIndex is where it stands in a prefix, so a candidate
	// begins that many bytes in front of what a search reported. It is the
	// separator at the first of the two places a prefix writes it, which is the
	// only depth all three prefixes carry the same byte at. builtin_scan.go
	// says why a scan searches for one byte of what opens a candidate rather
	// than for the whole of it; the rationale above says what makes it this
	// byte and why not the separator behind the word.
	oryAPIKeyAnchor      = oryAPIKeySeparator
	oryAPIKeyAnchorIndex = len(oryAPIKeyOpening)

	// oryAPIKeyBodyChars is the count a body is held to, read as a floor rather
	// than exactly. Thirty-two is what the key Ory writes down carries behind
	// its prefix. The rationale above weighs both the reading and the number.
	oryAPIKeyBodyChars = 32
)

// oryAPIKeyTail is what the scan settles the tail of its input by. prefixTail
// (builtin_scan.go) says what that is and why it is built once.
var oryAPIKeyTail = newPrefixTail(oryAPIKeyPrefixes...)
