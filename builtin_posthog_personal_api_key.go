package mask

import "strings"

// PostHogPersonalAPIKey locates PostHog personal API keys: the prefix phx_ and
// the forty-one or more letters and digits behind it, redacted to the end of
// the run they stand in. One key reads and writes the projects and
// organizations its owner can reach, within the scopes and the teams it was cut
// for, so it is worth as much as the access of the person who made it.
//
// A key is located wherever it is written, with no word boundary either side.
// So text of that shape is redacted whether or not PostHog issued it. A space,
// a hyphen, an underscore or a run of fewer than forty-one letters and digits
// ends the reading, so text as it is ordinarily written is not affected. Where
// the run carries on past the forty-first character, it is redacted to its end.
//
// Its name is "posthog-personal-api-key".
func PostHogPersonalAPIKey() Pattern { return postHogPersonalAPIKey }

// PostHog documents no format for this key and states the whole of one in the
// server that mints it, which PostHog publishes. The prefix is
// PERSONAL_API_KEY_PREFIX in posthog/models/utils.py, phx_ with the comment
// "x standing for nothing in particular" beside it, and what stands behind the
// prefix is generate_random_token_personal in the same file, three lines that
// say how many random bytes a body carries and what alphabet they are written
// in. The one shape PostHog does publish is the masked hint the settings page
// shows, phx_***1234, which is the prefix and four characters of a body with no
// length between them.
//
// Personal API key is PostHog's own term for the whole of what is located here:
// the title of the documentation page kept on one, the model PersonalAPIKey the
// server stores one in, and the variable POSTHOG_PERSONAL_API_KEY that PostHog's
// own scripts read one out of.
//
// PostHog writes four more prefixes with the same two letters — phc_ for the
// project API token, phs_ for the project secret API keys and team secret
// tokens, pha_ and phr_ for the OAuth access and refresh tokens — and each of
// them is a credential of its own rather than another spelling of this one. The
// project API token is the one worth naming, because it is published by design:
// it is written into the page source of every site PostHog is installed on and
// into the client configuration in a repository, so it is a value a caller has
// reason to leave in a log while redacting the key beside it. That is a decision
// a caller can only act on where the two are separate switches, and
// Test_PostHogPersonalAPIKey_theSiblingPrefixes holds all four away from this
// pattern.
//
// The body has been minted three ways, and a key of each still authenticates:
// the server hashes what it is handed and looks the hash up, with nothing along
// that path reading a length. So the count is read as a floor rather than
// exactly.
//
//   - Thirty-two random bytes written in base62, which is forty-three
//     characters and no more, since sixty-two raised to the forty-third power
//     is larger than two to the two hundred and fifty-sixth.
//   - Thirty-five random bytes written in base62, which is forty-eight at most
//     and forty-seven as one is ordinarily written. The three bytes were added
//     so that the last four characters could be kept in the clear for a reader
//     to recognise a key by.
//   - Thirty-five random bytes with the top bit forced on, written in base57,
//     which is forty-eight or forty-nine.
//
// A count read exactly is a count that cannot survive that, and there is
// nothing to say the fourth is not coming: each of the three lengthened the
// body, and a scan asking for forty-nine exactly would locate the first
// characters of a longer key and leave the rest of it in the output. Read as a
// floor, a key of any length at or above it is redacted whole.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the digits, and neither the hyphen nor the underscore base64url
// adds. Base57 is base62 with the five characters a reader confuses — 0, 1, O,
// I and l — taken out of it, so every key of the third kind is written in the
// wider alphabet as well, and reading the narrower one would turn away the
// keys of the first two: fewer than three in a hundred of those carry none of
// the five, since fifty-seven sixty-seconds raised to the forty-third power is
// under three in a hundred, and
// Test_PostHogPersonalAPIKey_theAlphabetIsWiderThanTodaysKeys pins it.
//
// The floor is forty-one, and two things put it there. A base62 numeral loses
// its leading digit whenever the value it encodes falls below the next power,
// so forty-three is what a key of the shortest kind is written at and not what
// it is guaranteed: about one key in sixty is forty-two characters, about one
// in three thousand eight hundred is forty-one, and fewer than one in two
// hundred thousand is shorter than that. A floor fails in one direction only —
// a key below it is located nowhere — so it is set where what falls below stops
// being something a caller would meet. And forty-one is one character past the forty
// of a git SHA, so a digest written straight behind the prefix falls short of a
// body where a floor of forty would have taken one; an MD5's thirty-two falls
// nine further short again.
//
// What the floor costs is the key cut short of it. A line cut to a column limit
// partway through one leaves a prefix and a body too short to be a body, and
// nothing is located: the random characters written before the cut stay in the
// output. Test_PostHogPersonalAPIKey_cutShortOfTheFloor pins that, so that it
// stays a decision on the record.
//
// The keys this pattern cannot locate are the ones PostHog issued before it
// wrote a prefix on them, and its authentication carries a note saying so — it
// declines to reject a token opening with anything else because "we need to
// support legacy personal api keys that may not have been prefixed with phx_".
// Such a key is a bare run of base62 with nothing in the text to tell it from
// an identifier, and a pattern reading it would read every word of the same
// shape.
//
// The prefix is read in the one case PostHog writes it. A prefix is the whole
// of what tells this format from text, so reading it in either case buys
// nothing — PHX_ is no form a key is issued in — and costs a candidate opened
// at every uppercase spelling.
//
// There is no boundary on either side of a match. A boundary in front would
// drop the whole match rather than trim it wherever a key is written against a
// word character, as POSTHOG_PERSONAL_API_KEY_phx_… is. One behind would drop
// rather than trim as well, and where it were asked decides what it drops.
// Asked behind the count, it drops the key a letter, a digit or an underscore
// is written against. Asked behind that run, it drops the key an underscore is
// written against and nothing else, the underscore being the one word
// character no body admits.
// Test_PostHogPersonalAPIKey_reachesTheEndOfTheRun writes both keys out.
//
// The byte the scan searches the input for is the underscore the prefix closes
// with, and the prefix is read back from it. builtin_scan.go says why a scan
// searches for one byte of its prefix rather than for the prefix itself. What
// makes it this byte is the other three: the p and the h are letters the
// vendor's own name, its host names and the words of a message around them are
// written with — over the line these benchmarks are written on the p stands
// six times and the h twice — and while the x stands on that line no more than
// the underscore does, it is a character base62 admits, so a digest, a payload
// or the body of a key would stop the search about once in every sixty-two
// characters it ran. The underscore is written in no body at all, so a run of
// any length opens no candidate at it.
//
// What that costs is the four sibling prefixes: each of them carries the
// underscore this scan searches for and the p it reads back to, so each is
// turned away by the comparison of the whole prefix rather than by the byte in
// front of it. A line of project API tokens pays that once a token, and a
// snake_case name pays it once a segment whose last four characters open with a
// p.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a key or not, which is the default. It is what a key
// beginning inside another needs: the three letters the prefix opens with
// belong to the alphabet a body is written in, so a body may close with phx and
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
// and Test_postHogPersonalAPIKeyPrefix_runsDoNotOverlap names the character it
// rests on.
//
// What this pattern over-matches on is forty-one letters and digits written
// behind the prefix, and two shapes reach it. One is base64url text: that
// alphabet holds the underscore where hexadecimal and standard base64 do not,
// so a payload written in it can carry phx_ inside itself, and where forty-one
// base62 characters follow, the run from the prefix to the end of that payload
// is redacted. The other is the digest: a SHA-256 is sixty-four hexadecimal
// characters, which are base62 and carry nothing that ends a run, so phx_
// written in front of one is a key's format exactly. Both are paid rather than
// avoided, because there is nothing left to tell them from a key: a scan
// declining forty-one letters and digits behind this prefix declines every key
// PostHog issues. Test_PostHogPersonalAPIKey_insideAnOpaqueRun and
// Test_PostHogPersonalAPIKey_aDigestBehindThePrefix pin them.
//
// What reaches a span is never prose, a git SHA or an MD5. The prefix closes on
// an underscore, which no word runs into, and behind it must stand forty-one
// unbroken letters and digits, which neither digest reaches even written
// straight behind the prefix; and a digest standing on its own carries no
// underscore to hold a prefix at however long it runs.
//
// referencePostHogPersonalAPIKeyFind in builtin_posthog_personal_api_key_test.go
// keeps the grammar as a regular expression, spelling the prefix, the floor and
// the alphabet again so that the two are changed together, and the fuzz target
// beside it holds this scan to that expression.
var postHogPersonalAPIKey = NewPattern("posthog-personal-api-key", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two.
	retain := postHogPersonalAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], postHogPersonalAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for
		// the reason the rationale above gives: a body may close with the three
		// letters the prefix opens with, so a key can begin three characters
		// before the end of the one before it.
		offset = anchor + 1

		if anchor < postHogPersonalAPIKeyAnchorIndex {
			continue
		}
		start := anchor - postHogPersonalAPIKeyAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != postHogPersonalAPIKeyPrefix[0] || !strings.HasPrefix(src[start:], postHogPersonalAPIKeyPrefix) {
			continue
		}

		body := start + len(postHogPersonalAPIKeyPrefix)
		end := base62RunEnd(src, body)
		if end == len(src) {
			// The run reaches the end of the input, so neither where the body
			// ends nor whether it is long enough to be one is settled here:
			// what comes next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if end-body >= postHogPersonalAPIKeyBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// postHogPersonalAPIKeyPrefix is what every personal API key opens with,
	// and what the scan reads back from its anchor. Its first three characters
	// belong to the alphabet a body is written in, which is what lets one key
	// begin inside another and is why the scan resumes a byte along; the
	// underscore it closes with does not, which is what keeps two candidates
	// from ever reading the same run. Test_postHogPersonalAPIKeyPrefix holds it
	// to the first and Test_postHogPersonalAPIKeyPrefix_runsDoNotOverlap to the
	// second.
	postHogPersonalAPIKeyPrefix = "phx_"

	// postHogPersonalAPIKeyAnchor is the byte the scan searches the input for
	// and postHogPersonalAPIKeyAnchorIndex is where it stands in the prefix, so
	// a candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what makes it
	// this byte and what it costs.
	postHogPersonalAPIKeyAnchor      = '_'
	postHogPersonalAPIKeyAnchorIndex = 3

	// postHogPersonalAPIKeyBodyChars is the count a body is held to, read as a
	// floor rather than exactly. PostHog has minted a body three ways and
	// lengthened it each time, and the rationale above weighs where the floor
	// goes: below the shortest of the three, and past the forty characters of a
	// git SHA.
	postHogPersonalAPIKeyBodyChars = 41
)

// postHogPersonalAPIKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var postHogPersonalAPIKeyTail = newPrefixTail(postHogPersonalAPIKeyPrefix)
