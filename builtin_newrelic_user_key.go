package mask

import "strings"

// NewRelicUserKey locates New Relic user keys: the prefix NRAK- and the
// twenty-seven or more uppercase letters and digits behind it, or the prefix
// NRAA- and the twenty-seven or more hexadecimal characters behind it, redacted
// to the end of the run they stand in. Every key the rulesets carry is
// twenty-seven characters behind the prefix, thirty-two altogether. A key
// queries NerdGraph and the REST API as the user it was issued to, across every
// account that user can see, so what one reaches is whatever its user was
// granted rather than one account's data.
//
// A key is located wherever it is written, with no word boundary either side. So
// text of that shape is redacted whether or not New Relic issued it. A space, an
// underscore, a second hyphen or a run of fewer than twenty-seven characters of
// the kind's own alphabet ends the reading, so text as it is ordinarily written
// is not affected. Where the run carries on past the twenty-seventh character,
// it is redacted to its end.
//
// Its name is "newrelic-user-key".
func NewRelicUserKey() Pattern { return newRelicUserKey }

// User key is New Relic's own name for this string: the heading its API keys
// page keeps on it, the thing its NerdGraph reference creates and revokes, and
// what its documentation says is required for NerdGraph and for the REST API.
// The page also gives "personal API key" as another name for the same string,
// which is what the Terraform provider and the CLI call it.
//
// Two prefixes fall under that one name, and it is New Relic that puts them
// there. NRAK- is what a key issued today opens with: the REST API keys
// end-of-life notice tells a reader that a key starting with NRAK needs no
// action, the setup page for New Relic's MCP server writes one as
// NRAK-YOUR-KEY-HERE, and the Terraform provider's migration guide states the
// prefix outright. NRAA- opened an admin key, which New Relic deprecated and
// then migrated: as of 4 December 2020 every admin key became a user key,
// keeping the string it had, labelled a user key in the API keys UI and granted
// the same permissions. New Relic's own CLI reads the two together — its check
// on a user API key admits NRAK and NRAA, and the error it prints when neither
// stands there names both.
//
// So the boundary question is answered by the vendor rather than by the shapes:
// a caller redacting New Relic user keys has no reason to enable one and not
// the other, since either authenticates the same way, and no reason to tell
// them apart in the output, since neither says anything the other does not.
// One pattern reads both, and the name covers what it locates.
//
// What New Relic states of either is the prefix and nothing else. No length, no
// alphabet and no checksum appears anywhere it publishes: the placeholders it
// writes a key as are NRAK-xxxx, NRAK-YOUR-KEY-HERE and a row of capital X, and
// its diagnostics CLI writes one as NRAK-123 followed by a row of dots. The
// closest thing to a format the vendor has written down is the check in its own
// CLI, which asks for one of the two prefixes, a hyphen, and word characters —
// of any length, in either case, the underscore admitted. That is a filter on
// what a caller may hand the tool rather than a description of what New Relic
// issues, and reading it as the format would leave a scan firing on any name
// opening with those five characters.
//
// Everything behind the prefix is therefore read off the published rulesets and
// the keys they carry, and the two kinds are not equally well attested.
//
// Behind NRAK-, three rulesets agree on twenty-seven characters and none of
// them reads a range: trufflehog reads twenty-seven uppercase letters and
// digits, gitleaks and noseyparker read the same count without regard to case,
// which over the letters of one case and the digits is the same class read
// twice over. Every key any of them publishes is twenty-seven uppercase
// letters and digits.
//
// Behind NRAA-, one ruleset reads a format at all. noseyparker reads
// twenty-seven hexadecimal characters without regard to case, and the one key it
// publishes is twenty-seven lowercase hexadecimal characters. That is a thinner
// record than the other kind's, and where it is thinnest — the case those
// characters are written in — is what the alphabets below are decided against.
//
// The counts are read as floors and not as counts. A count is read exactly
// where it is most of what tells a value from the text around it, or where the
// vendor wrote the length down. Here the vendor wrote neither: the prefix is
// five characters closing on a hyphen and is the whole of what tells this
// format from text, so the count is carrying nothing the prefix is not already
// carrying. What a floor costs against an exact count is the run written behind
// a key with no separator between, which is redacted along with it; what an
// exact count costs against a floor is the tail of a key longer than the count,
// which is left in the output. The first costs a reader characters that are
// part of no credential, the second leaves part of a credential behind, and
// this is a library for not leaving credentials behind.
//
// What a floor costs on the other side is the key cut short of it. A line cut
// to a column limit partway through one leaves a prefix and a body too short to
// be a body, and nothing is located: the characters written before the cut stay
// in the output. Test_NewRelicUserKey_cutShortOfTheFloor pins that, so that it
// stays a decision on the record.
//
// The two kinds are read in two alphabets. The single published migrated key
// settles hexadecimal with room to spare: twenty-seven characters drawn from
// the letters and digits land inside hexadecimal about three times in ten
// thousand million, so a key that is twenty-seven hexadecimal characters is not
// one that happened to look like it. What it does not settle is the case, and
// there the two kinds part — an issued body is read in uppercase alone, a
// migrated body in hexadecimal of either case.
//
// That is one question weighed against two costs, and the cost is the base64url
// payload. base64url is the one alphabet in ordinary use carrying the hyphen,
// so text written in it can hold a whole prefix, and what a body's alphabet
// admits decides how often the twenty-seven characters behind that prefix are
// all admitted. Uppercase and the digits are thirty-six of the sixty-four,
// which lands about twice in ten million, where the letters of both cases and
// the digits are sixty-two of them and land two times in five: reading an
// issued body in both cases would turn a fair share of all base64url text into
// keys. Hexadecimal is sixteen of the sixty-four in one case and twenty-two in
// both, which land so seldom that the difference is no cost to weigh — so
// reading a migrated body in one case would buy nothing, and would risk a key
// New Relic wrote in the other, located nowhere.
//
// The prefixes are read in the one case New Relic writes them, and what decides
// that is where the cost falls rather than what the case is: nraa- and nrak- are
// no form a key is issued in, so reading them without regard to case buys no key
// that exists, and it would open a candidate at every lowercase spelling —
// which, the opening being three letters of the alphabet an issued body is
// written in, is a candidate inside every other word of prose.
//
// There is no boundary on either side of a match. A boundary in front would
// drop the whole match rather than trim it wherever a key is written against a
// word character, as NEW_RELIC_API_KEY_NRAK-... is. One behind would drop
// rather than trim as well, and where it were asked decides what it drops.
// Asked behind the count, it drops the key a letter, a digit or an underscore
// is written against. Asked behind that run, it drops the key a word character
// that alphabet leaves out is written against — a lowercase letter behind an
// issued key, a letter past f behind a migrated one, an underscore behind
// either. The rulesets reading this format ask for \b on both sides.
//
// The byte the scan searches the input for is the R of the opening, and the
// prefix is read back from it. builtin_scan.go says why a scan searches for one
// byte of its prefix rather than for the prefix itself; what makes it this byte
// is that the hyphen is the character a timestamp, a flag and a kebab-cased
// name are written with — it stands twice on the line these benchmarks are
// written on, in the date alone — where none of the three capitals stands on
// that line at all. What separates the three from one another is not that line
// but the language a log line is written in: A and N are among the six letters
// English spells most often and R is not, and the capitals a line carries are
// its words written in another case.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a key or not, which is the default. It is what a key
// beginning inside another needs: the three letters of the opening and the
// character naming a kind all belong to the alphabet an issued body is written
// in, so such a body may close with NRAK and the hyphen of the next key stand
// directly behind it, and a scan consuming its match would step over that key
// and leave it in the output whole. The two spans overlap where it happens, and
// Masker.locate resolves them. No key begins inside a migrated body: that
// alphabet carries the A of the opening but neither the N nor the R, so an
// opening cannot stand in one however long it runs. The shape is therefore the
// issued kind's alone, and Test_NewRelicUserKey_aKeyInsideAKey drives it.
//
// The scan keeps no cursor and needs none. The run behind a candidate is read to
// its end however long that run is, and what bounds the work is where a body
// opens rather than how far it reads: the hyphen in front of one is written in
// neither alphabet a body is read in, so every body begins where a run begins
// and no two candidates can read the same run. That is what rules out the
// quadratic input a line dense in prefixes would otherwise be, and
// Test_newRelicUserKeyPrefixes_runsDoNotOverlap names the character it rests on.
//
// What this pattern over-matches on is twenty-seven characters of one kind's
// alphabet written behind that kind's prefix, and two shapes are worth naming.
// One is the base64url payload above, which carries the hyphen a prefix closes
// with and can therefore hold a whole one; what such a payload has to carry for
// the run from the prefix to the end of it to be redacted is twenty-seven
// characters the kind's own alphabet admits, which for the issued kind means
// twenty-seven of a single case and for the migrated kind twenty-seven
// hexadecimal characters of either. The other is the digest: a SHA-1 is forty
// hexadecimal characters, so one written behind NRAA- is a migrated key's format
// exactly and is redacted whole, in whichever case it was written. Both are
// paid rather than avoided, because there is nothing left to tell them from a
// key: a scan declining twenty-seven characters of the alphabet behind the
// prefix declines every key of that kind.
// Test_NewRelicUserKey_theShapesWrittenByAccident pins them.
//
// What reaches a span is never prose, a git SHA or an MD5. Both prefixes close
// on a hyphen, which no word runs into, and behind one must stand twenty-seven
// unbroken characters the kind admits: a digest standing on its own carries no
// hyphen to hold a prefix at however long it runs, and a hyphenated word carries
// no run of capitals or of hexadecimal behind the hyphen.
//
// referenceNewRelicUserKey in builtin_newrelic_user_key_test.go keeps the
// grammar as a regular expression, spelling the prefixes, the floor and the two
// alphabets again so that the two are changed together, and the fuzz target
// beside it holds this scan to that expression.
var newRelicUserKey = newBuiltin("newrelic-user-key", &newRelicUserKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := newRelicUserKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], newRelicUserKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for
		// the reason the rationale above gives: an issued body may close with
		// the four characters a prefix opens with, so a key can begin four
		// characters before the end of the one before it.
		offset = anchor + 1

		if anchor < newRelicUserKeyAnchorIndex {
			continue
		}
		start := anchor - newRelicUserKeyAnchorIndex

		// The byte the opening begins with is tested before the opening is
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the opening is a length and a read.
		if src[start] != newRelicUserKeyOpening[0] || !strings.HasPrefix(src[start:], newRelicUserKeyOpening) {
			continue
		}

		// The character naming the kind and the hyphen closing the prefix.
		// Where the end of the input cut the prefix short rather than the text
		// spelling it otherwise, prefixTail has already reported it: what
		// stands at the end is then a piece of a prefix, and this walk has
		// nothing to add.
		kind := start + len(newRelicUserKeyOpening)
		if kind+1 >= len(src) || src[kind+1] != newRelicUserKeySeparator {
			continue
		}

		body := kind + 2
		end, ok := newRelicUserKeyBodyEnd(src[kind], src, body)
		if !ok {
			continue
		}
		if end == len(src) {
			// The run reaches the end of the input, so neither where the body
			// ends nor whether it is long enough to be one is settled here:
			// what comes next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if end-body >= newRelicUserKeyBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// newRelicUserKeyKinds is the two kinds of user key, one entry apiece: the
// character standing between the opening and the separator, and where a body
// written in that kind's alphabet ends.
//
// The two are in one table because everything else about a kind is derived from
// it — the prefixes below, and the walk the scan takes at a candidate. A kind
// listed in one place and walked in another is a pair that can come to disagree,
// and what a stream would then do with the kind it had not been told about is
// release the characters a key opens with and redact nothing.
//
// The walk is reached through the entry rather than written into the scan, which
// costs one indirect call at a candidate. It is not on the cost of a byte: the
// walk itself is a loop of its own, and what a line holding no key pays is the
// search for the anchor and the comparison above.
var newRelicUserKeyKinds = [...]struct {
	kind byte
	end  func(src string, i int) int
}{
	{newRelicUserKeyIssuedKind, newRelicUserKeyIssuedRunEnd},
	{newRelicUserKeyMigratedKind, newRelicUserKeyMigratedRunEnd},
}

// newRelicUserKeyPrefixes is what a candidate opens with, one prefix a kind,
// built from the opening, the kind and the separator rather than written out
// again. A table of its own is one that can come to disagree with the kinds
// above about which prefixes there are, and it is what the tail below is built
// from.
var newRelicUserKeyPrefixes = func() []string {
	prefixes := make([]string, 0, len(newRelicUserKeyKinds))
	for _, k := range newRelicUserKeyKinds {
		prefixes = append(prefixes, newRelicUserKeyOpening+string(k.kind)+string(newRelicUserKeySeparator))
	}
	return prefixes
}()

const (
	// newRelicUserKeyOpening is what both prefixes open with and
	// newRelicUserKeySeparator is what both close with. Every character of the
	// opening belongs to the alphabet an issued body is written in, which is
	// what lets one key begin inside another and is why the scan resumes a byte
	// along; the separator belongs to neither alphabet, which is what keeps two
	// candidates from ever reading the same run.
	// Test_newRelicUserKeyPrefixes holds the first and
	// Test_newRelicUserKeyPrefixes_runsDoNotOverlap the second.
	newRelicUserKeyOpening   = "NRA"
	newRelicUserKeySeparator = '-'

	// newRelicUserKeyIssuedKind names the key New Relic issues today and
	// newRelicUserKeyMigratedKind the admin key it migrated into a user key.
	// The rationale above says what each is and what its body is read from.
	newRelicUserKeyIssuedKind   = 'K'
	newRelicUserKeyMigratedKind = 'A'

	// newRelicUserKeyAnchor is the byte the scan searches the input for and
	// newRelicUserKeyAnchorIndex is where it stands in both prefixes, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what makes it
	// this byte.
	newRelicUserKeyAnchor      = 'R'
	newRelicUserKeyAnchorIndex = 1

	// newRelicUserKeyBodyChars is the count a body of either kind is held to,
	// read as a floor rather than exactly. New Relic states no length of its
	// own; every key any ruleset publishes is this many characters behind the
	// prefix, and the rationale above weighs reading that as a floor.
	newRelicUserKeyBodyChars = 27
)

// newRelicUserKeyBodyEnd returns where the body of the kind named by kind ends,
// beginning at i in src, and whether kind names a kind at all.
//
// A kind is looked for rather than switched on so that the table above stays the
// one statement of which kinds there are.
func newRelicUserKeyBodyEnd(kind byte, src string, i int) (int, bool) {
	for _, k := range newRelicUserKeyKinds {
		if k.kind == kind {
			return k.end(src, i), true
		}
	}
	return 0, false
}

// newRelicUserKeyIssuedRunEnd returns where the run of characters an issued
// key's body is written in beginning at i in src ends, which is len(src) where
// the run reaches the end of the input.
func newRelicUserKeyIssuedRunEnd(src string, i int) int {
	for i < len(src) && isNewRelicUserKeyIssuedByte(src[i]) {
		i++
	}
	return i
}

// newRelicUserKeyMigratedRunEnd returns where the run of characters a migrated
// key's body is written in beginning at i in src ends, which is len(src) where
// the run reaches the end of the input.
func newRelicUserKeyMigratedRunEnd(src string, i int) int {
	for i < len(src) && isNewRelicUserKeyMigratedByte(src[i]) {
		i++
	}
	return i
}

// isNewRelicUserKeyIssuedByte reports whether c belongs to the alphabet an
// issued key's body is written in: the uppercase letters and the digits, which
// is every character any published key of that kind carries.
func isNewRelicUserKeyIssuedByte(c byte) bool {
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z'
}

// isNewRelicUserKeyMigratedByte reports whether c belongs to the alphabet a
// migrated key's body is written in: hexadecimal, in either case. The rationale
// above says why this one is read in both cases where the issued body is read
// in one.
func isNewRelicUserKeyMigratedByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// newRelicUserKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var newRelicUserKeyTail = newPrefixTail(newRelicUserKeyPrefixes...)
