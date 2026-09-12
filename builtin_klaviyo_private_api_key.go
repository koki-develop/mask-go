package mask

import "strings"

// KlaviyoPrivateAPIKey locates the private API keys Klaviyo issues: the prefix
// pk_ and the body behind it, with or without the six characters and the second
// underscore a key may carry between the two. One shape serves every key — a
// key is minted with whatever scopes its creator chose and may be read-only,
// full-access or narrowed to a handful of them, so nothing in the string says
// what it is allowed to reach.
//
// A key is located wherever it is written, with no word boundary either side,
// and is redacted from its pk_ to the end of the run it stands in. So a key
// written against a word character keeps its span, and a character of the key's
// own alphabet written straight after a key is redacted with it.
//
// Its name is "klaviyo-private-api-key".
func KlaviyoPrivateAPIKey() Pattern { return klaviyoPrivateAPIKey }

// Private API key is Klaviyo's own term, and the word private is load-bearing
// rather than decoration. Klaviyo issues two things it calls API keys: this one,
// which reads and writes the profiles, lists, events and campaigns an account
// holds and goes into an Authorization header as Klaviyo-API-Key; and a public
// API key, which Klaviyo also calls a site ID, which identifies the account to a
// browser and is safe to publish. Only the first is located here, so the name
// has to carry the word that separates them — KlaviyoAPIKey would claim the
// other as well.
//
// The public key is not a pattern of its own either, and the reason is the gate
// every built-in is weighed at rather than any judgement about what it is worth.
// Klaviyo states it as six alphanumeric characters and nothing else: no prefix,
// no separator, no length that is unusual. Six such characters are an ordinary
// word, a git short SHA and half the identifiers in a configuration file, so a
// pattern reading them would redact text a reader reads rather than a value
// already opaque — and it would do so for every caller of AllBuiltinPatterns.
// Those same six characters are read here, but only where a whole key is
// written around them, which is a different claim entirely.
//
// What Klaviyo states of the private key it states in two places, its
// authentication guide and the page on obtaining credentials, and what it states
// in both is the prefix and the alphabet: private keys have the prefix pk_
// followed by a longer alphanumeric string. No length is given, and nothing
// about the second underscore. Klaviyo's own OpenAPI is the nearest thing to a
// shape in its repositories and settles no length either: the api-keys endpoints
// return a redacted_key documented as showing only the last four characters, and
// the example beside it is written pk_ then four asterisks then four characters.
// The asterisks are a placeholder for a body of any width rather than a mask of
// one, so the example corroborates no count.
//
// The length is therefore read off the rulesets, and the two that state a shape
// agree on it. trufflehog reads pk_ and thirty-four characters, or pk_, six
// characters, an underscore and the same thirty-four; betterleaks reads pk_ and
// thirty-four characters behind a keyword, and kingfisher reads this format
// through betterleaks' rule rather than one of its own. gitleaks, noseyparker
// and secretlint carry no Klaviyo rule at all. So the thirty-four is two rules
// agreeing and the second shape is one rule alone.
//
// The alphabet is base62, isBase62Byte in builtin_scan.go: the letters of both
// cases and the digits, and neither the hyphen nor the underscore base64url
// adds. That is Klaviyo's own word for it, and it is what the wider of the two
// rules admits — betterleaks writes its body class in lowercase but sets the
// case-insensitive flag over the whole expression, so the class it compiles to
// is the letters of both cases and the digits. trufflehog reads the narrower
// hexadecimal, and every key it would read is read here, the hexadecimal digits
// being letters and digits.
//
// Reading the narrower one is the tightening on offer and it is declined twice
// over. It would hold the format to one rule against both the other rule and the
// vendor's own word, and what that costs when it is wrong is not a key cut short
// but a key located nowhere at all: a body stopping early falls under the floor
// and nothing is reported, so a key carrying a g would come through whole. A
// middle reading — the lowercase letters and the digits, narrower than one rule
// and wider than the other — is worse again, because no source states it. That
// is a tightening with nothing under it, and a tightening with nothing under it
// cuts a credential short for a saving nobody can check.
//
// The six characters between a prefix and a body are read in the same alphabet,
// which is what lets the scan read them without a second walk: the run behind
// the prefix is the segment exactly where it is six long and an underscore ends
// it. The one rule stating that shape admits the letters of both cases there,
// and Klaviyo's public key — which is six alphanumeric characters, the width
// that segment has — is stated with no case either.
//
// The second shape is read at all because one rule states it and nothing
// contradicts it, and because of what leaving it out would cost. A key written
// pk_, six characters, an underscore and a body is not a key with an extra piece
// this scan could ignore: no body admits the underscore, so a scan reading the
// first shape alone finds a run of six where it wants thirty-four and reports
// nothing. The whole key would come through.
//
// The six is read exactly and not as a floor, which is the opposite of how the
// count is read below, and the two differ because what the number is doing
// differs. The body's count separates a key from ordinary text, and a floor
// there is what keeps a lengthened key from being cut short. The six is not a
// length anything could grow: it is the width the one rule stating this shape
// writes, and reading it as a floor would put a second grammar behind the
// prefix — pk_, any run at all, an underscore and a body — which no source
// states and which is a whole class of over-match bought for nothing. A run of
// some other width in front of the underscore is a candidate this scan declines,
// and it declines it to the plain shape's reading, which is already in hand.
//
// The count is read as a floor and not as a count. A count is read exactly where
// it is most of what tells a value from the text around it, or where the vendor
// wrote the length down. Here Klaviyo wrote the prefix and the alphabet down and
// stopped: thirty-four is a number two rules are written to, and there is no
// page to hold Klaviyo to it. Were Klaviyo to lengthen the random part, a scan
// asking for thirty-four exactly would locate the first thirty-seven characters
// of a key and leave the rest of it in the output. Read as a floor, a key of any
// length at or above it is located to the end of its run.
//
// What the floor costs is the key shorter than it. A line cut to a column limit
// partway through one leaves a prefix and a body too short to be a body, and
// nothing is located: the random characters written before the cut stay in the
// output. Test_KlaviyoPrivateAPIKey_cutShortOfTheFloor pins that.
//
// The prefix is read in the one case Klaviyo writes it in. betterleaks matches
// it without regard to case, and that is not a claim about the format: the flag
// is set once over a generated expression whose point is the vendor's name in
// front of the value, and it reaches the prefix because it reaches everything.
// Klaviyo writes pk_ and trufflehog reads pk_, so pk_ is what is read here.
//
// There is no boundary on either side of a match. One behind would drop a match
// rather than trim it, and where it were asked decides what it drops. Asked
// behind the floor, it drops the key a letter, a digit or an underscore is
// written against. Asked behind that run, it drops the key an underscore is
// written against and nothing else, the underscore being the one word character
// no body admits. Test_KlaviyoPrivateAPIKey_reachesTheEndOfTheRun writes both
// keys out.
//
// The tightening on offer in front is the one the Stripe scans take: to ask that
// no letter and no digit stand before the prefix. It would buy something real
// here, because three characters ending in pk do close an identifier — topk_ is
// how the top-k operation is spelled in a name, and topk_ with thirty-four
// characters behind it is this format exactly.
// Test_KlaviyoPrivateAPIKey_aWordEndingInThePrefix pins what is redacted for
// want of that demand.
//
// It is declined all the same, because of what else it would turn away. A key
// can be written inside the one before it here, and where it is, the character
// in front of the second key's prefix is a character of the first key's own run.
// The demand would reject that second key — and where the first candidate was
// not itself a key, nothing else reaches it, so a whole live body would be left
// in the output. Test_KlaviyoPrivateAPIKey_aKeyBeginningInsideAnother writes
// that input out: a run of six that is no segment, and inside it a key the
// demand would drop and this scan locates.
//
// builtin_stripe_publishable_key.go can take the demand because no Stripe key
// can begin inside another. That is the whole of the difference between the two
// scans, and it is why a caller running both sees topk_ redacted by this pattern
// and left alone by that one — two vendors who picked the same three characters,
// not two halves of one format that may not disagree.
//
// The byte the scan searches the input for is the underscore the prefix closes
// with, two characters in. builtin_scan.go says why a scan searches for one byte
// of what opens a candidate rather than for the whole of it; what makes it this
// byte is that the two letters in front of it are ordinary ones — over the log
// line these benchmarks are written on the p stands five times and the k once,
// that one being Klaviyo's own name in the host, where the underscore stands not
// at all. It is also the character the run guarantee below rests on, so a
// candidate found by it is a candidate whose body begins one byte along or
// eight.
//
// A key of the second shape carries a second underscore, which the search stops
// at as well; the two characters in front of that one are the last of the six,
// so all but a vanishing few are turned away by a single comparison. Where those
// two are pk the candidate is a real one and is read as any other —
// Test_KlaviyoPrivateAPIKey_aKeyBeginningInsideAnother drives it.
//
// The scan resumes one byte past the start of a candidate whether it became a
// key or not, which is the default and needs no argument. It is load-bearing
// here rather than merely correct: both characters of the prefix in front of the
// underscore belong to the alphabet a body is written in, so a body may close
// with pk and the underscore of the next key stand directly behind it, which
// makes the second key begin two characters before the first one ends. A scan
// consuming its match would step over that key and leave it in the output whole.
// The two spans overlap where it happens, and Masker.locate resolves them.
//
// No cursor is kept over the run, and none is needed, which is what the
// underscore buys. A body begins one byte past an underscore, no body is written
// with one, and so a run read here ends at or before the underscore of the next
// candidate. Two candidates can read one run and no more than two — the shapes
// put a body three characters past a prefix or ten, so the candidates whose body
// could begin at a given position are the one starting three bytes in front of
// it and the one starting ten — which makes reading all of them twice the length
// of the input at worst rather than a walk per candidate.
// Test_klaviyoPrivateAPIKeyPrefix_runsDoNotOverlap holds the prefix to the one
// character that argument rests on, and Test_KlaviyoPrivateAPIKey_scanIsLinear
// drives the inputs that would find it wrong.
//
// What this pattern over-matches on: thirty-four characters of base62 behind the
// prefix inside something nobody issued. The underscore is what makes that rare.
// Standard base64 writes none at all, so a certificate, a PEM body or an
// embedded image carries no prefix to be found at however long it runs, and only
// a base64url encoding can hold one. There a prefix and a body together — three
// fixed characters out of an alphabet of sixty-four, then thirty-four carrying
// neither of the two characters base64url adds — stand about once in seven
// hundred and seventy thousand characters. The run from the prefix to the end of
// the encoding is then redacted, and what is taken is a stretch of a value that
// was already opaque to a reader.
// Test_KlaviyoPrivateAPIKey_insideAnOpaqueRun pins it.
//
// The collision this format leaves is a digest written behind the prefix.
// Hexadecimal digits are base62 and nothing inside a digest ends a run, so the
// prefix and the forty characters of a SHA-1 is a key to this scan, as the
// prefix and the sixty-four of a SHA-256 is. Those are redacted, and nothing
// could be done about it that would not cost a credential: such a run is a key's
// format exactly — it is the format trufflehog reads, the narrower of the two
// rules — so a scan declining it would decline every key Klaviyo happened to
// write in the hexadecimal digits alone. An MD5 is left alone, at thirty-two
// characters two short of the floor.
// Test_KlaviyoPrivateAPIKey_aDigestBehindThePrefix pins all three.
//
// The Stripe publishable keys share this prefix and are located by a pattern of
// their own, builtin_stripe_publishable_key.go, with no case where the two
// disagree about a value: a Stripe key writes live or test and an underscore
// behind pk_, which is four characters where the second shape here reads six, so
// the segment is declined and the first shape finds a run of four against a
// floor of thirty-four. Nothing of Klaviyo's reaches a Stripe key either, since
// no body here may hold the underscore that key carries.
// Test_KlaviyoPrivateAPIKey_aStripePublishableKey writes it out from this side.
//
// referenceKlaviyoPrivateAPIKey in builtin_klaviyo_private_api_key_test.go keeps
// the grammar as a regular expression rather than writing the rules out again,
// spelling the prefix, the segment, the floor and the alphabet so that the two
// are changed together, and the fuzz target beside it holds this scan to that
// expression.
//
// An expression is affordable here even though the floor is written as a counted
// repetition, which costs an engine a machine as wide as the floor at every
// candidate. What makes that flat cost rather than a quadratic one is what makes
// the scan need no cursor: no body admits the underscore a candidate is found
// by, so candidates cannot crowd inside a single run and no input makes an
// engine walk the same run more than twice. The prefix is three fixed characters
// in front of the grammar besides, which is the literal an engine searches the
// text for. Measured rather than supposed: the target turns over hundreds of
// thousands of executions in its thirty seconds, where a reference whose
// candidates crowd inside one run reports next to none.
var klaviyoPrivateAPIKey = newBuiltin("klaviyo-private-api-key", &klaviyoPrivateAPIKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two.
	retain := klaviyoPrivateAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], klaviyoPrivateAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for
		// the reason the rationale above gives: a body may close with the two
		// characters in front of the underscore, so a key can begin two
		// characters before the end of the one before it.
		offset = anchor + 1

		if anchor < klaviyoPrivateAPIKeyAnchorIndex {
			continue
		}
		start := anchor - klaviyoPrivateAPIKeyAnchorIndex

		// The byte the prefix opens with is tested before the prefix is
		// compared. Every anchor the search stops at reaches this line — the
		// second underscore of a key of the scoped shape among them — and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != klaviyoPrivateAPIKeyPrefix[0] || !strings.HasPrefix(src[start:], klaviyoPrivateAPIKeyPrefix) {
			continue
		}

		body := start + len(klaviyoPrivateAPIKeyPrefix)
		end := base62RunEnd(src, body)
		if end == len(src) {
			// The run reaches the end of the input, so nothing behind the
			// prefix is settled here: what comes next either carries the run on
			// or closes it, and either could still make a key of this candidate
			// under whichever of the two shapes. Both shapes are read out of
			// this one run, so this is the whole of what the end of the input
			// leaves undecided at a candidate.
			retain = min(retain, start)
		}
		if end-body >= klaviyoPrivateAPIKeyBodyChars {
			// The two shapes cannot both stand at one candidate: a run reaching
			// the floor writes the alphabet where the scoped shape asks for the
			// underscore that closes its segment.
			spans = append(spans, Span{Start: start, End: end})
			continue
		}

		// The scoped shape reads no second walk, only what this run already
		// says: a segment is this run where it is the declared width and an
		// underscore is what ended it. Where either fails, the text decided the
		// candidate and there is nothing left to settle.
		if end-body != klaviyoPrivateAPIKeySegmentChars || end == len(src) || src[end] != klaviyoPrivateAPIKeyAnchor {
			continue
		}

		scoped := end + 1
		end = base62RunEnd(src, scoped)
		if end == len(src) {
			retain = min(retain, start)
		}
		if end-scoped >= klaviyoPrivateAPIKeyBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// klaviyoPrivateAPIKeyPrefixes is what a candidate opens with. Both shapes open
// with it — the six characters of the scoped shape stand behind the prefix
// rather than inside it — so one entry states what every key this scan locates
// carries, which is what a Masker passes the pattern over on and what the tail
// below is built from.
var klaviyoPrivateAPIKeyPrefixes = [...]string{klaviyoPrivateAPIKeyPrefix}

const (
	// klaviyoPrivateAPIKeyPrefix is what Klaviyo states of the format: the two
	// letters and the underscore behind them. Both letters belong to the
	// alphabet a body is written in, which is what lets one key begin inside
	// another and is why the scan resumes a byte along;
	// Test_klaviyoPrivateAPIKeyPrefix holds them there.
	klaviyoPrivateAPIKeyPrefix = "pk_"

	// klaviyoPrivateAPIKeyAnchor is the byte the scan searches the input for
	// and klaviyoPrivateAPIKeyAnchorIndex is where it stands in the prefix, so
	// a candidate begins that many bytes in front of what a search reported.
	// The rationale above says what made it this byte. It is also what closes
	// the segment of the scoped shape, which is what lets that shape be read
	// off the run the plain shape already walked.
	klaviyoPrivateAPIKeyAnchor      = '_'
	klaviyoPrivateAPIKeyAnchorIndex = len(klaviyoPrivateAPIKeyPrefix) - 1

	// klaviyoPrivateAPIKeySegmentChars is how many characters stand between the
	// prefix and the body of a key of the scoped shape, read exactly rather
	// than as a floor for the reason the rationale above gives. It is the width
	// the one rule stating that shape reads, and the width Klaviyo states its
	// public key in.
	klaviyoPrivateAPIKeySegmentChars = 6

	// klaviyoPrivateAPIKeyBodyChars is the count a body is held to, read as a
	// floor rather than exactly. Thirty-four is what both rules stating a shape
	// are written to, and no page of Klaviyo's states a length at all. The
	// rationale above weighs reading it as a floor.
	klaviyoPrivateAPIKeyBodyChars = 34
)

// klaviyoPrivateAPIKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var klaviyoPrivateAPIKeyTail = newPrefixTail(klaviyoPrivateAPIKeyPrefixes[:]...)
