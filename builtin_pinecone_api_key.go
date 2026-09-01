package mask

import "strings"

// PineconeAPIKey locates Pinecone API keys: the prefix pcsk_ or pckey_, a
// public label of five or more letters and digits, an underscore, and the
// sixty-three or more letters and digits of the secret behind it, redacted to
// the end of the run they stand in. One key authenticates every request to the
// project it was created for, so whoever holds one can read and write the
// vector indexes in that project.
//
// A key is located wherever it is written, with no word boundary either side.
// So text of that shape is redacted whether or not Pinecone issued it. A space,
// a hyphen, anything but an underscore where the separator belongs, or a run
// too short to be a label or a secret ends the reading, so text as it is
// ordinarily written is not affected.
//
// Its name is "pinecone-api-key".
func PineconeAPIKey() Pattern { return pineconeAPIKey }

// Pinecone states the two prefixes and stops there. Its CLI reference writes a
// key as pcsk_abc123 in the line that configures one and as pcsk_... in the
// line that sets it, and its Admin API reference states of the value a created
// key comes back as that new keys will have the format
// pckey_<public-label>_<unique-key> and that the entire string is what
// authenticates. Everywhere else a key is written the documentation masks it as
// YOUR_API_KEY, and the console that issues one is behind a login. No length,
// no alphabet and no checksum appears anywhere Pinecone publishes.
//
// So the two prefixes are the vendor's and the division into a label and a
// secret is the vendor's, and everything else behind them is read off one
// published rule. trufflehog is the one ruleset carrying this format:
// pcsk_, five or six letters and digits, an underscore and exactly sixty-three
// more, with a word boundary either side. gitleaks, kingfisher and noseyparker
// carry no Pinecone rule at all. GitHub carries the format under the token
// identifier pinecone_api_key, with push protection and a validity check, and
// publishes what it detects rather than the expression it detects with — so the
// format is written down there too, just not anywhere a scan can read it.
//
// Both counts are therefore read as floors. A count is read exactly where the
// vendor wrote the length down or where its own generator does, and Pinecone
// does neither: sixty-three is the count trufflehog's rule reads, and being
// wrong about it upward costs the end of a key while being wrong about it
// downward costs the whole of one. Read as a floor, a key with a longer secret
// is still redacted whole, and the day Pinecone lengthens either part nothing
// here has to change. That is the reading the Groq scan takes on a prefix its
// vendor states alone, and it is taken here for that reason.
//
// The label's floor is five rather than six, which is the shorter of the two
// lengths trufflehog's rule admits, and no ceiling is read at all. Six is the
// longer of the two and is what a ceiling would be read off, over a part the
// vendor names and describes no further. A ceiling wrong by one character
// locates nothing at all, which is the whole credential rather than the end of
// one, and what dropping it admits is a longer run of letters and digits
// standing where a label stands, in front of a separator and sixty-three more.
// The secret behind it is what makes this format tell itself from text, and
// that count is untouched.
//
// What the floors cost on the other side is the key cut short of one. A line
// cut to a column limit partway through a key leaves a prefix, a label and a
// secret too short to be a secret, and nothing is located: the characters
// written before the cut stay in the output.
// Test_PineconeAPIKey_cutShortOfTheFloor pins that, so that it stays a decision
// on the record.
//
// The pckey_ prefix is read with the same body grammar as pcsk_, and that is a
// wager worth naming: no published rule reads pckey_, and Pinecone writes no
// whole key carrying it. Pinecone states one shape for both, so the parts are
// read at the lengths and in the alphabet the keys of the other prefix carry.
// A wager on a floor is bounded in the direction that matters: if a pckey_
// key's parts are longer, the floors still locate it whole, and only a shorter
// one is missed, which is what leaving the prefix out would do to every one of
// them. Against that stands the format Pinecone says new keys are issued in
// going unread. Test_PineconeAPIKey_theNewPrefix drives both prefixes through
// the same body.
//
// What the label is made of is the part of that wager the floors do not bound,
// since Pinecone states nothing about it at all: not a length, not an
// alphabet, and not where the characters come from. A label read too narrowly
// locates no key rather than part of one. The reading here is that a label is
// an identifier Pinecone generates rather than a name somebody typed, which is
// what the one rule that reads this format treats it as: it reads letters and
// digits there and surfaces the part as a key id. The alternative the vendor's
// own word leaves open is a label derived from the name a key was created
// under, and the names Pinecone's guides write are hyphenated: were that the
// derivation, every key whose name carried a hyphen or an underscore would be
// located nowhere, since the run in front of the separator would end at that
// character. Test_PineconeAPIKey_aLabelOutsideTheAlphabet pins what that would
// cost, so that widening the label is a change somebody argues for rather than
// one somebody notices afterwards.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the digits, and neither the hyphen nor the underscore base64url
// adds. That is what the one published rule admits in both parts. Leaving the
// underscore out is doing more work here than an alphabet usually does — it is
// what ends the label where the separator stands, so the count in front of that
// separator is readable at all, and it is what bounds how many candidates can
// read one run, which the account of the scan's cost below rests on.
//
// The prefixes are read in the one case Pinecone writes them. A prefix is the
// whole of what tells this format from text, so reading it in either case buys
// nothing — PCSK_ is no form a key is issued in — and costs a candidate opened
// at every uppercase spelling.
//
// There is no boundary on either side of a match, where the one published rule
// asks for \b on both. A boundary in front would drop the whole match rather
// than trim it wherever a key is written against a word character, as
// PINECONE_API_KEY_pcsk_... is. One behind would drop rather than trim as
// well, and where it were asked decides what it drops. Asked behind the count,
// it drops the key a letter, a digit or an underscore is written against.
// Asked behind that run, it drops the key an underscore is written against and
// nothing else, the underscore being the one word character no secret admits.
// Test_PineconeAPIKey_leavesWhatFollowsAlone writes the second of those out.
//
// The tightening on offer in front is the demand that no letter and no digit
// stand before a prefix. It is declined because it would reject the key written
// inside another, whose prefix stands against the last character of the secret
// in front of it — which is a shape this scan locates and the cases pin. What
// declining it admits is a snake_case name whose segment closes on pcsk or
// pckey; what turns such a name away instead is the secret's floor, which the
// next underscore of the name ends long before.
//
// The byte the scan searches the input for is the c both prefixes carry at
// their second character, and a candidate is read back one byte from it.
// builtin_scan.go says why a scan searches for one byte of its prefix rather
// than for the prefix itself. What makes it this byte is that it is the rarer
// of the two the prefixes share at a depth of their own: the p and the c are
// the whole of what pcsk_ and pckey_ have in common — behind them one spells an
// s where the other spells a k — and over the line these benchmarks are written
// on the p stands four times against the c's twice. The underscore each prefix
// closes with is rarer still on that line and is passed over, because it stands
// at a different depth in the two: a search for it would read two candidates
// back from every underscore of a snake_case name where the c reads one.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a key or not, which is the default. It is what a key
// beginning inside another needs: the characters in front of each prefix's
// underscore belong to the alphabet a label and a secret are written in, and
// the underscore itself is the separator a key already carries, so a secret may
// close with pcsk and the underscore dividing the next key's label from its
// secret stand where that key's prefix needs one. A scan consuming its match
// would step over that key and leave it in the output whole. The two spans
// overlap where it happens, and Masker.locate resolves them.
//
// The scan keeps no cursor and needs none. Each candidate walks two runs — the
// label's and the secret's — and it is the separator that bounds how many
// candidates can walk any one of them. A run is
// walked as a label only by a candidate whose prefix closes on the character in
// front of that run, and as a secret only by a candidate whose label is the run
// ending at that character; each of those is at most one candidate, since two
// prefixes of different lengths cannot both stand there and spell themselves.
// So no run is walked more than twice however dense in prefixes a line is,
// walking all of them comes to twice the length of the input, and that is what
// rules out the quadratic input a cursor would otherwise be needed for.
// Test_PineconeAPIKey_scanIsLinear drives the line that would find it wrong.
//
// What this pattern over-matches on is a label and sixty-three letters and
// digits written behind one of the prefixes. One shape that reaches it is
// base64url text: that alphabet holds the underscore where hexadecimal
// and standard base64 do not, so a payload written in it — a JWT signature, the
// routable body some other vendor encodes a credential as — can carry a whole
// prefix and both separators inside itself, and where the runs between them are
// long enough, the stretch from the prefix to the end of that payload is
// redacted. The other is the digest: a SHA-256 is sixty-four hexadecimal
// characters, which are base62 and carry nothing that ends a run, so a digest
// written where a secret belongs is a key's format exactly and is redacted
// whole. Both are paid rather than avoided, because there is nothing left to
// tell them from a key: a scan declining sixty-three letters and digits behind
// a label and a separator declines every key Pinecone issues.
// Test_PineconeAPIKey_insideAnOpaqueRun and
// Test_PineconeAPIKey_aDigestWhereTheSecretBelongs pin them.
//
// What reaches a span is never prose, a git SHA or an MD5. A prefix closes on
// an underscore, which no word runs into, and a digest standing on its own
// carries none to hold a prefix at however long it runs; written behind a label
// instead, a SHA-1 at forty characters and an MD5 at thirty-two are both short
// of the secret's floor.
//
// The other credential Pinecone issues is a service account's client secret,
// which the Admin API is authenticated with by exchanging it for an access
// token. It is not read: Pinecone writes it as YOUR_CLIENT_SECRET everywhere it
// appears and states no prefix, no length and no alphabet for it, so there is
// nothing to anchor on. Test_PineconeAPIKey_theClientSecret pins the decision,
// so that reading one is a change somebody argues for rather than one somebody
// notices afterwards.
//
// referencePineconeAPIKeyFind in builtin_pinecone_api_key_test.go states the
// grammar again as a plain walk, spelling the prefixes, both floors, the
// separator and the alphabet out so that the two are changed together, and the
// fuzz target beside it holds this scan to that walk. It is written out rather
// than built on an expression, and weighs the two where it stands.
var pineconeAPIKey = newBuiltin("pinecone-api-key", &pineconeAPIKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := pineconeAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], pineconeAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for
		// the reason the rationale above gives: a secret may close with the
		// characters a prefix opens with, so a key can begin inside the one
		// before it.
		offset = anchor + 1

		if anchor < pineconeAPIKeyAnchorIndex {
			continue
		}
		start := anchor - pineconeAPIKeyAnchorIndex

		// The byte every prefix opens with is tested before any of them is
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison against the prefixes is a length and a read apiece.
		if src[start] != pineconeAPIKeyOpening[0] {
			continue
		}
		prefix := pineconeAPIKeyPrefixLen(src[start:])
		if prefix == 0 {
			continue
		}

		label := start + prefix
		labelEnd := base62RunEnd(src, label)
		if labelEnd == len(src) {
			// The run reaches the end of the input, so neither how long the
			// label is nor whether the separator stands behind it is settled
			// here: what comes next either carries the run on or closes it.
			retain = min(retain, start)
			continue
		}
		if labelEnd-label < pineconeAPIKeyLabelChars || src[labelEnd] != pineconeAPIKeySeparator {
			continue
		}

		secret := labelEnd + 1
		end := base62RunEnd(src, secret)
		if end == len(src) {
			// The same again for the secret: where the run ends and whether it
			// is long enough to be one are both open.
			retain = min(retain, start)
		}
		if end-secret >= pineconeAPIKeySecretChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// pineconeAPIKeyPrefixes is what a candidate opens with, one entry per prefix
// Pinecone writes a key with: pcsk_, which its CLI reference writes a key with
// and which trufflehog's rule reads, and pckey_, which the Admin API reference
// states new keys are issued with. They agree on their first two characters
// and part at the third, so at most one of them stands at any position.
//
// It is one table, read by the scan and by the tail below, so there is nothing
// here for a second list to come to disagree with.
var pineconeAPIKeyPrefixes = []string{"pcsk_", "pckey_"}

const (
	// pineconeAPIKeyOpening is what every prefix opens with, and the whole of
	// what they have in common. The scan tests its first byte before comparing
	// a prefix, and the anchor stands inside it.
	// Test_pineconeAPIKeyPrefixes holds every prefix to opening with it.
	pineconeAPIKeyOpening = "pc"

	// pineconeAPIKeyAnchor is the byte the scan searches the input for and
	// pineconeAPIKeyAnchorIndex is where it stands in every prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what makes it
	// this byte and why not the underscore.
	pineconeAPIKeyAnchor      = 'c'
	pineconeAPIKeyAnchorIndex = 1

	// pineconeAPIKeySeparator divides the label from the secret. It belongs to
	// neither, which is what ends the label where it stands and what makes the
	// count in front of it readable at all; it is also the character every
	// prefix closes with, which is what lets one key be written inside another
	// and why the scan resumes a byte along.
	pineconeAPIKeySeparator = '_'

	// The counts each part of a key is held to, read as floors rather than
	// exactly. Pinecone states no length of its own and the one published rule
	// reads five or six for the label and exactly sixty-three for the secret;
	// the rationale above weighs reading the shorter of the label's two lengths
	// as a floor with no ceiling, and the secret's count as a floor.
	pineconeAPIKeyLabelChars  = 5
	pineconeAPIKeySecretChars = 63
)

// pineconeAPIKeyPrefixLen returns the length of the prefix standing at the
// start of s, and zero where none does.
//
// The prefixes part at their third character, so the loop reports the one
// prefix that can stand here rather than the first of several. It is a function
// of its own so that the scan reads a length and the table stays the one place
// the prefixes are written.
func pineconeAPIKeyPrefixLen(s string) int {
	for _, p := range pineconeAPIKeyPrefixes {
		if strings.HasPrefix(s, p) {
			return len(p)
		}
	}
	return 0
}

// pineconeAPIKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var pineconeAPIKeyTail = newPrefixTail(pineconeAPIKeyPrefixes...)
