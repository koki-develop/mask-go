package mask

import "strings"

// HoneycombAPIKey locates the Honeycomb API keys that carry a key ID: ingest
// keys, classic ingest keys and management keys. Each is a six character
// opening — hc, the character Honeycomb assigns at key creation, the two
// naming the kind and an underscore — then the twenty-six characters of the
// key ID and the thirty-two of the secret, sixty-four characters altogether,
// or sixty-five where a management key's colon divides the two.
//
// A key is located wherever it is written, with no word boundary either side,
// and exactly the characters of one are. So text of that shape is redacted
// whether or not Honeycomb issued it. A character outside the key's alphabet, a
// colon standing where the layout writes none or missing where it writes one, a
// run the input cuts short — any of those ends the reading, so text as it is
// ordinarily written is not affected. A longer run is a key with something
// written after it, and the key alone is redacted.
//
// Its name is "honeycomb-api-key".
func HoneycombAPIKey() Pattern { return honeycombAPIKey }

// API key is Honeycomb's own term for the whole of what this locates. Its
// authentication page heads the section API Key Format, states that Honeycomb
// has three types of API keys and lists the prefix of each; the page a caller
// mints one from is titled Manage Environment API Keys. Ingest key, management
// key and configuration key are the three terms under that one, and no term of
// Honeycomb's covers two of them and leaves the third out, so the vendor's
// wider word is the name and the kinds stay under one scan.
//
// They are one pattern rather than one apiece because the boundary is the
// caller's and none of the three things that puts one in is here. A caller
// redacting what Honeycomb issues has the same reason for each kind — each of
// them authenticates a caller to Honeycomb, differing in what it may then
// reach rather than in whether it is a secret — and nothing a redactor keying on
// Match.Pattern.Name could act on separates them. A switch per kind would be
// worse than one besides: a caller reaching for this vendor would have to know
// all three to redact what it issues.
//
// The opening is the vendor's, stated as a grammar rather than shown in an
// example. Honeycomb's authentication page writes the three prefixes as
// hc[x]ik_, hc[x]lk_ and hc[x]mk_ and says of the third character that it
// varies and is assigned at key creation. What that character may be is stated
// in Honeycomb's own code rather than on the page: libhoney-go reads a classic
// ingest key with ^hc[a-z]ic_[a-z0-9]*$, husky walks the same shape a byte at a
// time and rejects both an uppercase and a digit where the character stands,
// and the alternative Refinery's expression for an API key ends in is written
// hc[a-z][a-z]{2}_ and a body. Three implementations of the vendor's, agreeing
// on a lowercase letter.
//
// The kinds are read as a table of two characters rather than as Refinery's
// [a-z]{2}, and the reason is what Honeycomb writes with the openings that
// table leaves out. The resources it names carry one of the same shape — a
// team is hcxtm_, an environment hcxen_, a user hcxus_, a signal hcasp_ — and
// none of those is a credential. Refinery can read any two letters because it
// only ever asks the question of a value already handed to it as an API key;
// a scan reading a log cannot, and the kinds the vendor enumerates are what
// keeps a resource identifier from being redacted as a secret.
//
// Which kinds carry a secret is the other half of that. An ingest key is the
// key ID and the secret concatenated with no separator, which is the value
// Honeycomb's page writes into X-Honeycomb-Team; a management key joins the
// two with a colon, which is the value it writes into Authorization: Bearer. A
// configuration key has neither shape: the page gives it a Token rather than a
// secret, writes that token into X-Honeycomb-Team on its own, and leaves
// hc[x]lk_ naming the key ID, which the page on managing keys calls a label
// that identifies this key in the Honeycomb UI. So lk opens no candidate here
// — a key ID standing alone is not a credential, and redacting one would take
// away the label a caller keeps a log by.
// Test_HoneycombAPIKey_aKeyIDIsNoValue writes out what that leaves alone.
//
// The token itself is out of reach of any grammar. Honeycomb's authentication
// page writes it as twenty-two characters of letters and digits with no prefix
// and no separator, and Refinery's expression admits twenty to twenty-three of
// them; the older classic key is thirty-two hexadecimal characters, which that
// same expression states. Either is a word of an identifier, a git short SHA
// or an MD5, so a pattern reading them would redact text a reader reads rather
// than a value already opaque, which is the grammar AllBuiltinPatterns may not
// grow. Test_HoneycombAPIKey_theKeysThatCarryNoOpening pins the decision.
//
// The classic ingest key is a Classic team's, and it is read beside the other
// two because Honeycomb's own code still reads it: the ic_ libhoney-go and
// husky spell is a kind Refinery's release notes name as supported, so those
// are live credentials.
//
// The counts are Honeycomb's, and the sources that state them agree. Refinery
// reads a whole ingest key as fifty-eight characters behind the opening, and
// husky holds a classic one to sixty-four altogether, which is that number
// with the opening in front. The OpenAPI Honeycomb publishes states the key ID
// on its own, an anchored expression asking for twenty-six characters behind
// the opening, so the secret is the thirty-two the other two leave — the width
// the authentication page writes a management key's secret at, behind a key ID
// of twenty-six and the colon between them. Neither count is read off a value
// somebody was shown.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the digits, and neither the hyphen nor the underscore base64url
// adds. That is the wider of two readings Honeycomb's own sources offer, and
// the wider is taken deliberately. Its OpenAPI spells a key ID in the letters
// of both cases and the digits where Refinery, libhoney-go and husky each read
// a body in lowercase and digits alone. Reading the three would be a tightening
// that costs a credential when it is wrong: a key carrying one uppercase
// character fails a count read in the narrower class, and a candidate that
// fails is a key left in the output whole, where the wider class over-matches
// only on the sixty-four characters of the shape below that nobody issued. The
// same spec is already wrong about the opening it spells beside that class,
// writing hcxik_ literally where the vendor's own page says the third character
// varies, so it is the source to read widely rather than the one to narrow on.
//
// No ruleset states any of this, so there is nothing to weigh the grammar
// against and nothing that disagrees with it. gitleaks, noseyparker, secretlint
// and the secrets-patterns-db carry no Honeycomb rule at all. trufflehog and
// betterleaks each carry one, and both read the keys that carry no opening —
// thirty-two hexadecimal characters or twenty-two of letters and digits, behind
// the vendor's name written as a keyword — which is the pair this scan declines
// above and a shape no key located here has. kingfisher reads this format
// through betterleaks' rule rather than one of its own.
//
// The byte the scan searches the input for is the h an opening begins with, and
// it is chosen for where it stands rather than for how often. builtin_scan.go
// says why a scan searches for one byte of its opening rather than for the
// opening itself. Standing first means a search for it stops at every position
// a candidate could begin, the pieces of an opening the end of the input cut
// short among them, so one walk both reads an opening and says where the input
// stops being settled — which is what the scans opening on a literal reach for
// prefixTail (builtin_scan.go) to do, and there is no table of literals here
// to hand it.
//
// The two rarer bytes are passed over for that. Over the line these benchmarks
// are written on the underscore stands not at all and the c twice against the
// h's three, which
// Test_honeycombAPIKeyFindBenchmarks_lineTheAnchorWasChosenAgainst holds that
// line to. A search for either would reach no piece of an opening the end of
// the input cut short — a stream carrying hcx and then hcxik_ and a body would
// be released with the piece written out — so the rarer byte costs a second
// walk over the end of every input against a resumption or two on a line.
//
// So the scan declares the three characters an opening closes with to a Masker
// as literals and no tail, which grams (builtin_scan.go) says is the pattern
// that may be passed over but never answered for. Every key carries its kind's
// three, so a text carrying none of them carries no key; what a Masker may not
// do is report them as settling the tail, since the walk above settles further
// back than they stand. A stream runs this scan rather than answering for it,
// and Mask, which settles nothing, passes it over.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a key or not, which is the default. It is load-bearing here
// rather than merely correct: the last five characters of a body may spell hc,
// a letter and a kind, and the separator closing that opening is then the
// character written straight behind the key — so a key can begin five
// characters before the one in front of it ends. A scan consuming its match
// would step over that key and leave it in the output whole. The two spans
// overlap where it happens, and Masker.locate resolves them.
// Test_HoneycombAPIKey_aKeyBeginningInsideAnother writes the input out.
//
// The other place a candidate could open is inside an opening, and none does.
// The only character of one that may be an h besides the first is the one
// Honeycomb assigns, and the character behind that one names a kind — an i or
// an m, never the c an opening asks for.
// Test_honeycombAPIKeyOpening_holdsNoSecondOpening holds the three things that
// rests on, none of which an input reports.
//
// The scan keeps no cursor and needs none: a candidate reads at most sixty-five
// bytes and stops, which bounds what it reads with no state to be wrong about —
// the guarantee a scan reading a body to the end of its run has to buy with a
// run cursor instead.
//
// There is no boundary on either side of a match. One in front would drop the
// whole match rather than trim it wherever a key is written against a word
// character, as HONEYCOMB_API_KEY=hcxik_... is. One behind would drop rather
// than trim as well: under a fixed layout a key written against a
// fifty-ninth character of the body's alphabet is still a key with something
// after it, and a boundary there would locate nothing at all where this scan
// redacts the sixty-four Honeycomb issued and leaves the character that belongs
// to no credential in the text. Test_HoneycombAPIKey_nextToWordCharacters
// writes both out.
//
// What this pattern over-matches on: a body of the right counts written behind
// an opening by something other than Honeycomb. Nothing else in the text tells
// such a run from a key — they are the same sixty-four bytes — so a scan
// declining it would decline every real key of the same shape. What makes it
// rare is the opening rather than the body: hc, a letter, two more naming a
// kind and an underscore spell no word, and the underscore is most of what
// keeps an encoded run from holding one. Standard base64 and base32 write none
// at all, so a certificate, a PEM body or an embedded image carries no opening
// at however long it runs; only a base64url encoding can hold one, and only an
// ingest key, since base64url writes no colon and a management key's body
// carries one. There an opening and a body together — six characters out of an
// alphabet of sixty-four, three of them fixed, one a lowercase letter and two
// naming one of the two ingest kinds, then fifty-eight carrying neither of the
// characters base64url adds — stand about once in eight thousand million
// characters. Test_HoneycombAPIKey_insideAnOpaqueRun pins what is taken there.
//
// The collision an opening leaves where everything behind it is one class is a
// digest written there, and this format pays for one of the three. A SHA-256
// is sixty-four hexadecimal characters, six more than a body, so the first
// fifty-eight of one written behind an opening are a key to this scan and the
// six behind them stay in the text — and by the reasoning above nothing could
// be done about it that would not cost a key Honeycomb wrote in the
// hexadecimal digits alone. A SHA-1 at forty characters and an MD5 at
// thirty-two are short of the count, and no digest reaches the divided shape,
// carrying no colon. Test_HoneycombAPIKey_aDigestBehindAnOpening pins all four.
//
// referenceHoneycombAPIKeyAt in builtin_honeycomb_api_key_test.go states the
// grammar again by hand, spelling the opening, the character Honeycomb
// assigns, the kinds, the separator, the counts, the colon and the character
// class so that the two are changed together, and the fuzz target beside it
// holds this scan to those rules.
//
// It is written out rather than built on a regular expression, and the reason
// is the opening: hc is written in the alphabet a body is written in, which is
// one of the two things builtin-patterns.md names as having made an expression
// too slow to fuzz with. An engine's literal search cannot skip a run of that
// alphabet, so it walks a machine as wide as the counts at every byte of one.
// The file stating the reference measures what that came to here.
var honeycombAPIKey = newBuiltinFilteredOn("honeycomb-api-key", honeycombAPIKeyLiterals, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of an opening standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two, and the walk below answers both — the byte
	// the search stops at is the byte an opening begins with, so a piece of one
	// is reached exactly as a whole one is.
	retain := len(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], honeycombAPIKeyAnchor)
		if i < 0 {
			break
		}
		start := offset + i

		// The scan resumes one byte past the start of the candidate whether it
		// became a key or not, which is the default.
		offset = start + 1

		kind, opens, cut := opensHoneycombAPIKeyAt(src, start)
		if cut {
			// The end of the input stopped the walk part way through an
			// opening, so nothing here has opened a candidate yet and no text
			// carrying on from it could be decided.
			retain = min(retain, start)
			continue
		}
		if !opens {
			continue
		}

		body := start + honeycombAPIKeyOpeningChars
		end := body + kind.chars
		if end > len(src) {
			// The input ends inside this candidate, so the counts that are the
			// whole of what tells it from anything else written behind an
			// opening cannot be taken here.
			retain = min(retain, start)
			continue
		}
		if isHoneycombAPIKeyBody(src[body:end], kind.divided) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// honeycombAPIKeyKind is one kind of key this scan reads: what an opening
// closes with where a key of that kind is written, and the shape of the body
// behind it.
type honeycombAPIKeyKind struct {
	// close is the three characters an opening closes with: the two naming the
	// kind and the separator behind them. It is what a Masker passes the
	// pattern over on as well, honeycombAPIKeyLiterals being these and nothing
	// else.
	close string

	// chars is how many characters of body stand behind an opening of this
	// kind, the colon of a divided kind counted among them.
	chars int

	// divided is whether a colon stands between the key ID and the secret,
	// honeycombAPIKeyIDChars characters into the body. Where it does not, the
	// two are written concatenated with nothing between them.
	divided bool
}

// honeycombAPIKeyKinds is every kind of key that carries an opening and a
// secret behind it, one entry apiece. A kind Honeycomb writes an opening for
// and no secret behind is not here, and the rationale above says which and
// why.
var honeycombAPIKeyKinds = [...]honeycombAPIKeyKind{
	// The two ingest kinds write the key ID and the secret concatenated with
	// nothing between them, which is the value Honeycomb's page puts in the
	// X-Honeycomb-Team header.
	{close: "ic_", chars: honeycombAPIKeyBodyChars},
	{close: "ik_", chars: honeycombAPIKeyBodyChars},
	// A management key joins the two with a colon instead, which is the value
	// that page puts behind Authorization: Bearer.
	{close: "mk_", chars: honeycombAPIKeyBodyChars + 1, divided: true},
}

// honeycombAPIKeyLiterals is what a Masker may pass this pattern over on.
//
// They are read out of the kinds rather than written out again, so that a kind
// added there is a kind a Masker knows about. A table of its own is one that
// can come to disagree about which kinds there are, and what a Masker would
// then do with the kind it had not been told about is pass the scan over a text
// holding one of its keys.
var honeycombAPIKeyLiterals = func() []string {
	literals := make([]string, len(honeycombAPIKeyKinds))
	for i, k := range honeycombAPIKeyKinds {
		literals[i] = k.close
	}
	return literals
}()

const (
	// honeycombAPIKeyOpening is what every opening begins with, and the whole
	// of what an opening states before the character Honeycomb assigns at key
	// creation and the two naming the kind.
	honeycombAPIKeyOpening = "hc"

	// honeycombAPIKeyAnchor is the byte the scan searches the input for. It
	// stands at the first character of every opening, so a candidate begins
	// where a search reported rather than some way in front of it, and a piece
	// of an opening the end of the input cut short is reached the same way a
	// whole one is. builtin_scan.go says why a scan searches for one byte of
	// its opening rather than for the opening itself; the rationale above says
	// what made it this byte. Test_honeycombAPIKeyAnchor holds it to being the
	// one byte an opening may begin with.
	honeycombAPIKeyAnchor = 'h'

	// honeycombAPIKeySeparator closes every opening and opens the body behind
	// it. It belongs to no body, which is what bounds how far into a key
	// another can begin — an opening cannot stand wholly inside a body, so the
	// nearest one begins its own width short of the end — and what puts an
	// opening out of reach of an encoding that writes no underscore.
	// Test_honeycombAPIKeyKinds holds every kind's close to ending on it.
	honeycombAPIKeySeparator = '_'

	// honeycombAPIKeyCloseChars is how many characters an opening closes with:
	// the two naming the kind and the separator behind them.
	// Test_honeycombAPIKeyKinds holds every kind to that width.
	honeycombAPIKeyCloseChars = 3

	// honeycombAPIKeyOpeningChars is the whole of an opening: what every one of
	// them begins with, the one character Honeycomb assigns at key creation,
	// and what the kind closes it with.
	honeycombAPIKeyOpeningChars = len(honeycombAPIKeyOpening) + 1 + honeycombAPIKeyCloseChars

	// honeycombAPIKeyDivider is what a management key writes between its key ID
	// and its secret. It belongs to no body either, so a kind writing none can
	// never read one as part of a body.
	honeycombAPIKeyDivider = ':'

	// The counts either half of a body is written to: the key ID Honeycomb's
	// OpenAPI states the width of, and the secret its authentication page
	// writes behind one. Test_honeycombAPIKeyChars holds the two and what they
	// come to.
	honeycombAPIKeyIDChars     = 26
	honeycombAPIKeySecretChars = 32

	// honeycombAPIKeyBodyChars is the two written together, which is the count
	// Refinery reads a whole ingest key's body at and the count husky's length
	// of a classic ingest key leaves behind the opening.
	honeycombAPIKeyBodyChars = honeycombAPIKeyIDChars + honeycombAPIKeySecretChars
)

// opensHoneycombAPIKeyAt returns the kind of key an opening at i in src names,
// whether one opens there at all, and whether the end of the input was what
// stopped the walk.
//
// It is the one place an opening is stated, which is what lets the scan settle
// the tail of its input from the same grammar it locates values by rather than
// from a table of openings kept beside it and free to disagree.
func opensHoneycombAPIKeyAt(src string, i int) (kind honeycombAPIKeyKind, opens, cut bool) {
	if !strings.HasPrefix(src[i:], honeycombAPIKeyOpening) {
		// Either the text decided it, or the end of the input arrived inside
		// what every opening begins with.
		return kind, false, strings.HasPrefix(honeycombAPIKeyOpening, src[i:])
	}

	assigned := i + len(honeycombAPIKeyOpening)
	if assigned == len(src) {
		return kind, false, true
	}
	if !isHoneycombAPIKeyAssignedByte(src[assigned]) {
		return kind, false, false
	}

	// The two characters naming the kind and the separator behind them, which
	// are one comparison a kind rather than a walk: the kinds are the same
	// width, so an input too short for one is too short for all of them and
	// what is left to ask there is whether any of them begins with what is
	// written.
	at := assigned + 1
	for _, k := range honeycombAPIKeyKinds {
		if len(src)-at < len(k.close) {
			cut = cut || strings.HasPrefix(k.close, src[at:])
			continue
		}
		if src[at:at+len(k.close)] == k.close {
			return k, true, false
		}
	}
	return kind, false, cut
}

// isHoneycombAPIKeyAssignedByte reports whether c may stand where an opening
// writes the character Honeycomb assigns at key creation: a lowercase letter,
// which is the class each of the vendor's three implementations reads it in.
//
// What that character stands for is not read here and is stated nowhere the
// grammar rests on: the page says only that it varies and is assigned when the
// key is made.
func isHoneycombAPIKeyAssignedByte(c byte) bool { return 'a' <= c && c <= 'z' }

// isHoneycombAPIKeyBody reports whether s is the body of a key of a kind
// divided or not: the key ID and the secret, with the colon between them where
// the kind writes one.
func isHoneycombAPIKeyBody(s string, divided bool) bool {
	if divided {
		return s[honeycombAPIKeyIDChars] == honeycombAPIKeyDivider &&
			isHoneycombAPIKeyRun(s[:honeycombAPIKeyIDChars]) &&
			isHoneycombAPIKeyRun(s[honeycombAPIKeyIDChars+1:])
	}
	return isHoneycombAPIKeyRun(s)
}

// isHoneycombAPIKeyRun reports whether the whole of s is written in the
// alphabet a key ID and a secret are written in.
func isHoneycombAPIKeyRun(s string) bool { return base62RunEnd(s, 0) == len(s) }
