package mask

import "strings"

// PrefectAPIKey locates the API keys Prefect Cloud issues: the letters pn, one
// character naming the kind, an underscore, and thirty-six or more characters
// behind it. Two kinds are written in that shape — a user key and a service account
// key — and both go into the same Authorization header against the same API, so
// a key says which of the two it is and not what it may reach.
//
// A key is located wherever it is written, with no word boundary either side,
// and is redacted from its pn to the end of the run it stands in. So a key
// written against a word character keeps its span, and a character of the key's
// own alphabet written straight after a key is redacted with it.
//
// Its name is "prefect-api-key".
func PrefectAPIKey() Pattern { return prefectAPIKey }

// API key is Prefect's own term for both of the kinds this locates. The page
// that mints one is headed "How to manage API keys" and calls what it mints an
// API key whether the holder is a person or a service account, the environment
// variable a key is read from is PREFECT_API_KEY, and the CLI that turns away a
// string opening with neither prefix says so of the one name: "Your key is not
// in our expected format: 'pnu_' or 'pnb_'."
//
// The two kinds are one pattern and not two. A service account is what a worker
// and a CI job authenticate as, a user key is what a person's CLI holds, and
// neither is published where the other authenticates: both are secrets against
// the same API, so a caller with reason to redact either has the same reason for
// the other. Nothing a redactor could key on separates them, and two switches
// would mean a caller had to know both to redact what Prefect issues.
//
// The two prefixes are Prefect's own. Its CLI turns away a key that opens with
// neither, naming both in the message it turns it away with, and its
// troubleshooting page writes the same two — pnu_ for a user, pnb_ for a
// service account. That is the whole of what Prefect states. Neither the page
// nor the code says what may stand behind a prefix, how much of it there is, or
// whether the two kinds are written alike.
//
// The thirty-six and the alphabet are read off the rules, and off the rules for
// pnu_ alone. gitleaks and trufflehog each read pnu_ and thirty-six letters and
// digits; betterleaks reads gitleaks' expression with a closing boundary added,
// and kingfisher reads this format through it rather than through one of its
// own; noseyparker carries no Prefect rule at all. Prefect's own page
// corroborates the count from its side without stating it: the key masked there
// is written as pnu_ and thirty-six x's, which is a mask of that width rather
// than a length Prefect has written down.
//
// A fixture in Prefect's own prefect-cloud tests disagrees with that width and
// settles nothing. It is written pnu_ and thirty-two hexadecimal characters,
// which is neither the count nor the alphabet, and the code it is handed to
// makes a mocked request rather than reading a body — so it is a placeholder and
// not a key Prefect issued. It is named here because it is the nearest thing to
// a length in the vendor's own repositories, and so the first answer a reader
// looking for one will find.
//
// Nothing states a service account key's body at all. No rule reads pnb_ and no
// page of Prefect's masks one. So what is read behind pnb_ is what the user
// key's rules state, and the floor below is what makes reading it affordable: a
// body longer than thirty-six is redacted to the end of its run whatever its
// length, so a service account key written longer than a user key is still
// redacted whole.
//
// A lower floor behind pnb_ alone is the other way to read a kind nothing
// states, and it is declined. The number would rest on nothing whatever, where
// thirty-six rests on the sibling kind's rules and on one character of a prefix
// being the whole of the difference between the two. It would also be a second
// count where the format has one, which the reference would then have to branch
// on — two numbers to keep in step, and the invented one free to drift.
//
// The count is read as a floor and not as a count, and each kind gives its own
// reason for it. For pnu_ it is that thirty-six is a number the rules state
// rather than one Prefect has written down, so a scan asking for it exactly
// would locate the first forty characters of a key Prefect had lengthened and
// leave the rest of it in the output. For pnb_ it is the whole of what makes
// reading the kind defensible: with nothing stating that body's length, an exact
// count is a tightening with nothing under it, and a tightening with nothing
// under it cuts a credential short and leaves its tail in the log.
//
// What the floor costs is the key shorter than it, and it costs it for a service
// account key at any length under thirty-six. A line cut to a column limit
// partway through a key leaves a prefix and a body too short to be one, and
// nothing is located: the random characters written before the cut stay in the
// output. Test_PrefectAPIKey_cutShortOfTheFloor pins that.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the digits, and neither the hyphen nor the underscore base64url
// adds. Nothing of Prefect's says so, and what the rules reading pnu_ state is
// that same alphabet.
//
// A body admitting the underscore is the reading to rule out, and three things
// rule it out. It is no encoding: the alphabet that adds the underscore to
// base62 is base64url, and base64url adds the hyphen with it, so an alphabet
// holding the one and not the other is neither of the two a key is plausibly
// written in. It would put the separator inside the thing the separator
// divides, leaving a prefix that cannot be read off a key by the character that
// closes it. And it would make the grammar admit snake_case text: pn, a kind
// character and thirty-six word characters is the shape of an ordinary
// identifier, which is a value a reader reads rather than one already opaque,
// and this pattern reaches every caller of AllBuiltinPatterns.
//
// What the narrow alphabet costs is a key whose body carried an underscore
// after all. The run would end there, and unless thirty-six characters stood in
// front of it nothing would be located and the whole key would come through.
// That is the risk taken, and it is taken against a certainty on the other side:
// the wide alphabet redacts ordinary identifiers of the right length wherever
// they are written. Test_PrefectAPIKey_anUnderscoreInTheBody pins the risk.
//
// There is no boundary on either side of a match. A boundary in front would drop
// the whole match rather than trim it wherever a key is written against a word
// character, as PREFECT_API_KEY_pnu_... is. One behind would drop rather than
// trim as well, and where it were asked decides what it drops. Asked behind the
// floor, it drops the key a letter, a digit or an underscore is written against.
// Asked behind the run, it drops the key an underscore is written against and
// nothing else, the underscore being the one word character no body admits.
// Test_PrefectAPIKey_nextToWordCharacters and
// Test_PrefectAPIKey_reachesTheEndOfTheRun write those out.
//
// The byte the scan searches the input for is the underscore the prefix closes
// with, three characters in. builtin_scan.go says why a scan searches for one
// byte of what opens a candidate rather than for the whole of it; what makes it
// this byte is that the two letters in front of the kind are ordinary ones —
// over the log line these benchmarks are written on the p stands six times and
// the n four, where the underscore stands not at all. It is also the character
// the run guarantee below rests on, so a candidate found by it is a candidate
// whose body is the run beginning one byte along.
//
// The scan resumes one byte past the start of a candidate whether it became a
// key or not, which is the default and needs no argument. It is load-bearing
// here rather than merely correct: the three characters in front of the
// underscore belong to the alphabet a body is written in, so a body may close
// with pn and a kind character and the underscore of the next key stand directly
// behind it, which makes the second key begin three characters before the first
// one ends. A scan consuming its match would step over that key and leave it in
// the output whole. The two spans overlap where it happens, and Masker.locate
// resolves them. Test_PrefectAPIKey_aKeyBeginningInsideAnother drives it.
//
// No cursor is kept over the run, and none is needed, which is what the
// underscore buys. A candidate asks for an underscore four characters in and
// base62 holds none, so the underscore of the next candidate can be no earlier
// than the byte that ends this run, and the run that candidate reads therefore
// begins past this one. Successive candidates read runs that do not overlap, and
// reading all of them comes to the length of the input — the guarantee a scan
// whose prefix closes on a character its own body admits has to keep a run
// cursor for, bought here without state.
// Test_prefectAPIKeyPrefixes_runsDoNotOverlap holds the prefixes to the one
// thing that argument rests on, and Test_PrefectAPIKey_scanIsLinear drives it.
//
// What this pattern over-matches on: thirty-six characters of base62 behind a
// prefix inside a longer value. The underscore is what makes that rare. Standard
// base64 writes none at all, so a certificate, a PEM body or an embedded image
// carries no prefix to be found at however long it runs, and only a base64url
// encoding can hold one. There a prefix and a body together — three fixed
// characters and one of two out of an alphabet of sixty-four, then thirty-six
// carrying neither of the two characters base64url adds — stand about once in
// twenty-six million characters. The run from that prefix to the end of the
// encoding is then redacted, and what is taken is a stretch of a value that was
// already opaque to a reader. Test_PrefectAPIKey_insideAnOpaqueRun pins it.
//
// The collision this format leaves is a digest written behind a prefix. The
// hexadecimal digits are base62 and nothing inside a digest ends a run, so a
// prefix and the forty characters of a SHA-1 is a key to this scan, as a prefix
// and the sixty-four of a SHA-256 is. Those are redacted, and nothing could be
// done about it that would not cost a credential: such a run is a key's format
// exactly, so a scan declining it would decline every key Prefect happened to
// write in the digits alone. An MD5 is left alone, at thirty-two characters four
// short of the floor, and so is any digest written behind a hyphen rather than
// an underscore. Test_PrefectAPIKey_aDigestBehindThePrefix pins all four.
//
// The key Prefect Cloud 1 issued is not read here. Its CLI names that format
// only to tell a caller which service the key was minted against, and what it
// names is three letters with no separator behind them — pcu and nothing else.
// Three letters are what an ordinary word is written with, so a candidate read
// off them would open inside prose, and Prefect states no alphabet, no length
// and no separator to close one with.
// Test_PrefectAPIKey_theKeyCloudOneIssued writes it out.
//
// referencePrefectAPIKey in builtin_prefect_api_key_test.go keeps the grammar as
// a regular expression rather than writing the rules out again, spelling the
// opening, the kinds, the separator, the floor and the alphabet so that the two
// are changed together, and the fuzz target beside it holds this scan to that
// expression.
//
// An expression is affordable here even though the floor is written as a counted
// repetition, which costs an engine a machine as wide as the floor at every
// candidate. What makes that flat cost rather than a quadratic one is what makes
// the scan need no cursor: a candidate asks for the underscore and no body
// admits one, so candidates cannot crowd inside a single run and no input makes
// an engine walk the same run twice. What an engine skips on here is weaker
// than a whole prefix would be: the character naming the kind is written as a
// class, so the literal it can extract from the expression is the opening alone.
// Two ordinary letters turn away less text than four fixed characters would,
// which is the same thing that makes the underscore worth searching for and them
// not. Measured rather than supposed: the target turns over a million executions
// in its thirty seconds.
var prefectAPIKey = newBuiltin("prefect-api-key", &prefectAPIKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := prefectAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], prefectAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for
		// the reason the rationale above gives: a body may close with the three
		// characters in front of the underscore, so a key can begin three
		// characters before the end of the one before it.
		offset = anchor + 1

		if anchor < prefectAPIKeyAnchorIndex {
			continue
		}
		start := anchor - prefectAPIKeyAnchorIndex

		// The byte the opening begins with is tested before the opening is
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the whole opening is a length and a read.
		if src[start] != prefectAPIKeyOpening[0] || !strings.HasPrefix(src[start:], prefectAPIKeyOpening) {
			continue
		}
		if strings.IndexByte(prefectAPIKeyKinds, src[start+len(prefectAPIKeyOpening)]) < 0 {
			continue
		}

		body := start + prefectAPIKeyPrefixChars
		end := base62RunEnd(src, body)
		if end == len(src) {
			// The run reaches the end of the input, so neither where the body
			// ends nor whether it is long enough to be one is settled here:
			// what comes next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if end-body >= prefectAPIKeyBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// prefectAPIKeyPrefixes is what a candidate opens with, one entry to a kind.
//
// The kinds are read out of the declaration the scan reads them from rather than
// written out again, so that a kind added there is a kind this knows about: a
// table of its own is one that can come to disagree with it, and what a stream
// would then do with the kind it had not been told about is release the
// characters a key opens with and redact nothing.
var prefectAPIKeyPrefixes = func() []string {
	prefixes := make([]string, 0, len(prefectAPIKeyKinds))
	for _, kind := range prefectAPIKeyKinds {
		prefixes = append(prefixes, prefectAPIKeyOpening+string(kind)+string(prefectAPIKeyAnchor))
	}
	return prefixes
}()

const (
	// prefectAPIKeyOpening is what every prefix opens with, and what the scan
	// reads back from its anchor. The character naming the kind and the
	// underscore closing the prefix stand behind it, so a prefix is
	// prefectAPIKeyPrefixChars long whichever kind it names. Both its characters
	// belong to the alphabet a body is written in, which is part of what lets one
	// key begin inside another and is why the scan resumes a byte along;
	// Test_prefectAPIKeyOpening holds them there.
	prefectAPIKeyOpening = "pn"

	// prefectAPIKeyAnchor is the byte the scan searches the input for and
	// prefectAPIKeyAnchorIndex is where it stands in a prefix, so a candidate
	// begins that many bytes in front of what a search reported. The rationale
	// above says what made it this byte.
	prefectAPIKeyAnchor      = '_'
	prefectAPIKeyAnchorIndex = prefectAPIKeyPrefixChars - 1

	// prefectAPIKeyPrefixChars is the whole of a prefix: the opening, the one
	// character naming the kind and the underscore behind it.
	prefectAPIKeyPrefixChars = len(prefectAPIKeyOpening) + 2

	// prefectAPIKeyKinds is the characters naming a kind, which are what the two
	// prefixes Prefect issues differ in: u for a key issued to a user, b for one
	// issued to a service account. Both are read with the same body, which the
	// rationale above weighs against what states one. The character is read to
	// tell a prefix from text that merely opens like one and for nothing else.
	// Test_prefectAPIKeyKinds holds them to naming no character twice and to
	// being characters a prefix can be built from.
	prefectAPIKeyKinds = "ub"

	// prefectAPIKeyBodyChars is the count a body is held to, read as a floor
	// rather than exactly. Thirty-six is what the rules reading a user key state,
	// and Prefect's own masked example is that wide; nothing states a service
	// account key's body at all. The rationale above weighs reading a floor, and
	// weighs it separately for each of the two.
	prefectAPIKeyBodyChars = 36
)

// prefectAPIKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var prefectAPIKeyTail = newPrefixTail(prefectAPIKeyPrefixes...)
