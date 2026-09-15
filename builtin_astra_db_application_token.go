package mask

import "strings"

// AstraDBApplicationToken locates the application tokens DataStax issues for
// Astra DB: the prefix AstraCS:, the twenty-four characters of the client
// identifier, a colon, and the sixty-four of the secret — ninety-seven
// characters in all. The whole of it is redacted, identifier included, because
// the whole of it is what authenticates a request.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly the ninety-seven characters of one are. So text of that shape is
// redacted whether or not DataStax issued it, and a character written straight
// after a token is left in the text.
//
// Its name is "astra-db-application-token".
func AstraDBApplicationToken() Pattern { return astraDBApplicationToken }

// Application token is DataStax's own term for the whole of what this locates.
// Its documentation heads the page a caller mints one from Manage application
// tokens, and the name its CLI, its SDKs and its own examples read the value
// out of the environment under is ASTRA_DB_APPLICATION_TOKEN. One term covers
// the whole, so there is one name and one pattern.
//
// There is one shape rather than several beneath that name. A token
// authenticates with the role it was created for, so what one may reach differs
// between two of them while nothing in the string says which — no kind, no
// scope, no second prefix. A caller has no reason to enable one and not another
// and nothing a redactor keying on Match.Pattern.Name could act on, so no
// boundary falls inside this.
//
// The grammar is DataStax's own, and the source is the code that accepts a
// token rather than an example of one. The Astra CLI's AstraToken.parse refuses
// a token that does not begin with AstraCS:, refuses one that is not exactly
// ninety-seven characters, refuses one that does not divide into exactly three
// parts on the colon, and refuses one whose second part is not exactly
// twenty-four characters. The third part is what those leave: ninety-seven
// characters less the eight of the prefix, the twenty-four of the identifier
// and the colon between them is sixty-four. DataStax's documentation states the
// same structure from the other side, writing the prefix as AstraCS: and the
// token as the one value that carries everything the older clientId and secret
// pair carried separately.
//
// So the prefix, both counts and the colon between the halves are the vendor's.
// astraDBApplicationTokenChars holds them to the total the CLI states, which is
// what keeps a count edited here from quietly parting from the format.
//
// The alphabet is not the vendor's, and the reader widening it needs to know
// that. Nothing DataStax publishes states what characters either half is drawn
// from: what its CLI asks of them is that neither hold a colon, which is all
// that dividing into three parts amounts to, and it asks nothing else. The
// tokens written into its own sources are values rather than rules — a
// placeholder, an example beside a field, a string built to be the right shape
// for a test — and a value says only that it happened to fall that way.
//
// One ruleset carries a rule for this format and the rest carry none.
// betterleaks reads AstraCS: and then twenty or more characters of letters and
// digits, with no keyword in front of it and nothing of the structure behind
// it: no divider, no second half, no total. gitleaks, trufflehog, noseyparker,
// secretlint, kingfisher and the secrets-patterns-db carry no Astra rule at
// all.
//
// What that rule corroborates is the prefix and a floor the vendor's own count
// clears, twenty being short of the twenty-four DataStax holds the identifier
// to. What it does not settle is the alphabet, and the reason is the shape of
// the rule rather than the class written into it. A floor read against a
// character class stops at the first character outside that class and keeps
// whatever it has reached, so it fires on a token whose halves carry a hyphen
// exactly as it fires on one whose halves do not — reporting a shorter value
// and nothing else. A rule that cannot fail on the characters it leaves out
// says nothing about whether a value carries them, where a rule reading an
// exact count would have missed such a token and so would have said something.
//
// What the scan reads instead is the wider of the two run alphabets this
// package declares, isBase64URLByte in builtin_scan.go: the letters of both
// cases, the digits, the hyphen and the underscore. Two narrower readings were
// available and both are declined.
//
// The first is base62, isBase62Byte beside it, which is the class that ruleset
// writes and the reading a body of letters and digits alone would ask for. It
// is declined because the paragraph above leaves nothing under it: a tightening
// rests on the vendor or on nothing, and narrowing an alphabet on its absence
// is how a token carrying one hyphen comes to fail the count and be left in the
// log whole. The widening costs nothing against it — the counts are exact and
// the prefix is eight bytes of a vendor's name and a colon, so what the two
// extra characters admit is the same opaque run by another spelling.
//
// The second is the other direction, and it is where the widening stops.
// Standard base64 would add the plus, the solidus and the equals, and those are
// characters a path, a URL and an assignment are written with — a grammar
// admitting them behind a prefix would be admitting the text around a value
// rather than a value, which is the loose grammar AllBuiltinPatterns may not
// grow. The hyphen and the underscore do the opposite: wherever a token is
// written, in a log line, a URL or an environment assignment, they leave the
// body one opaque run.
//
// What this pattern over-matches on is twenty-four and sixty-four characters of
// that alphabet written behind the prefix by something other than DataStax, and
// the shape worth stating is the placeholder. A page of documentation writing
// AstraCS: and two runs of one repeated character is a token's format character
// for character, and nothing is left in the text to tell the two apart, so it is
// redacted. Test_AstraDBApplicationToken_aPlaceholderBody pins it. Declining it
// would mean declining every real token of the same shape, since a scan cannot
// read who minted a run.
//
// The credentials this pattern leaves in the output are the two halves standing
// on their own. DataStax issues a clientId and a secret as well as the token
// that bundles them, and its documentation names that pair the older way of
// authenticating; either half written without the prefix carries no opening at
// all. Twenty-four characters of this alphabet are a word of an identifier and
// sixty-four are any encoded blob, so a pattern reading one would redact text a
// reader has every reason to see rather than a value already opaque. Neither is
// located, and Test_AstraDBApplicationToken_theHalvesThatCarryNoPrefix pins
// what that leaves alone.
//
// The byte the scan searches the input for is the C the prefix carries five
// characters in. builtin_scan.go says why a scan searches for one byte of its
// prefix rather than for the prefix itself; what makes it this byte is that it
// is the one of the eight an ordinary line does not write. Over the line these
// benchmarks are written on the lowercase letters stand between three and ten
// times each, the colon twice, the capital A and the capital S once apiece, and
// the C not at all —
// Test_astraDBApplicationTokenFindBenchmarks_lineTheAnchorWasChosenAgainst
// holds that line to those counts, so the sentence is read as a measurement
// rather than as a recollection.
//
// The C belongs to the body's own alphabet, which is what this choice costs and
// there is no byte of the prefix that would avoid it: seven of the eight are
// characters a body may carry, and the eighth is the colon a log line writes in
// every timestamp, every port and every field written as a name against a
// value. So a run of this alphabet stops the search about once in sixty-four
// characters, and each of those stops is one comparison of the prefix read back
// from it.
//
// The scan resumes one byte past the start of a candidate whether that
// candidate became a token or not, which is the default and needs no argument.
//
// A candidate can open inside another here, and where it can follows from the
// divider: a half carries no colon, so the only colon a second candidate can
// open against inside the first is that divider, and what stands in front of it
// is then the prefix. So a scan consuming its match would step over such a
// token, which Test_AstraDBApplicationToken_aTokenBeginningInsideAnother writes
// out — and a token reported whole can leave the input unsettled from the
// candidate that opened inside it, which is the cut candidate of
// builtin_scan.go rather than a third shape and is what the last case of
// Test_AstraDBApplicationToken_holdsATokenTheInputCutShort states.
//
// What rules out a quadratic input is the count being a count: a candidate
// reads at most astraDBApplicationTokenChars bytes and stops, whatever the run
// it stands in runs to, so the scan keeps no cursor and needs none.
// Test_AstraDBApplicationToken_scanIsLinear drives the inputs that would find
// that wrong.
//
// There is no boundary on either side of a match. One in front would drop
// rather than trim the match wherever a token is written against a word
// character, which is what ASTRA_DB_APPLICATION_TOKEN_AstraCS:... is; one
// behind would drop rather than trim as well, since under exact counts a token
// written against a ninety-eighth character of the body's alphabet is still a
// token with something after it.
// Test_AstraDBApplicationToken_nextToWordCharacters writes both out.
//
// Nothing in front of a value is read. The prefix decides on its own whether a
// token stands somewhere, so every byte the scan reads is inside the value it
// reports and there is no count to state against LookBehind.
//
// The pattern is declared with newBuiltin, which grams (builtin_scan.go) says
// is the pattern a Masker may both pass over and answer for. Every token
// carries the prefix, so a text carrying no piece of it holds no token; and the
// scan opens its candidates on that same prefix and nowhere else, so what the
// prefix settles is what the scan settles and a Masker passing it over may
// report the one for the other.
//
// referenceAstraDBApplicationToken in
// builtin_astra_db_application_token_test.go keeps the grammar as a regular
// expression, spelling the prefix, the two counts, the colon between the halves
// and the character class again so that the two are changed together, and the
// fuzz target beside it holds this scan to that expression. An expression is
// affordable here for both of the reasons one usually is: every repetition is
// exact, so the machine an engine builds is read once and stops rather than
// being as wide as a floor at every candidate, and the prefix is an
// eight-character literal closing on a character no body carries, so an engine
// searches the text for it and finds it nowhere in a run of the body's
// alphabet.
var astraDBApplicationToken = newBuiltin("astra-db-application-token", &astraDBApplicationTokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two.
	retain := astraDBApplicationTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], astraDBApplicationTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not,
		// which is the default step and needs no argument.
		offset = anchor + 1

		if anchor < astraDBApplicationTokenAnchorIndex {
			continue
		}
		start := anchor - astraDBApplicationTokenAnchorIndex

		// The prefix is read back from the anchor. Almost every anchor the
		// search stops at reaches this line and is turned away here, so what
		// this comparison costs is most of what the scan pays for a line
		// carrying the letter but no token.
		if !strings.HasPrefix(src[start:], astraDBApplicationTokenPrefix) {
			continue
		}

		body := start + len(astraDBApplicationTokenPrefix)
		end := body + astraDBApplicationTokenBodyChars
		if end > len(src) {
			// The input ends inside this candidate, so the counts and the colon
			// between the halves — which are the whole of what tells a token
			// from anything else written behind the prefix — cannot be read
			// here. The text from the candidate's start is held back until the
			// rest of it arrives.
			retain = min(retain, start)
			continue
		}
		if isAstraDBApplicationTokenBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// astraDBApplicationTokenPrefix is what every token opens with, and what
	// the scan reads back from its anchor. It closes on the colon, which
	// belongs to no run of the body's alphabet, so no prefix can stand wholly
	// inside one.
	astraDBApplicationTokenPrefix = "AstraCS:"

	// astraDBApplicationTokenAnchor is the byte the scan searches the input for
	// and astraDBApplicationTokenAnchorIndex is where it stands in the prefix,
	// so a candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what made it
	// this byte, which is a count over the text around a token rather than
	// anything about the body. Test_astraDBApplicationTokenAnchor holds it to
	// standing at that index of the prefix.
	astraDBApplicationTokenAnchor      = 'C'
	astraDBApplicationTokenAnchorIndex = 5

	// astraDBApplicationTokenDivider is what stands between the client
	// identifier and the secret. It is the character the prefix closes with as
	// well, and the CLI dividing a token into exactly three parts on it is what
	// says neither half may carry one.
	astraDBApplicationTokenDivider = ':'

	// The counts either half is written to. The Astra CLI holds the client
	// identifier to the first exactly; the second is what its total leaves once
	// the prefix, the identifier and the divider are taken off.
	// Test_astraDBApplicationTokenChars holds the three to that total.
	astraDBApplicationTokenClientIDChars = 24
	astraDBApplicationTokenSecretChars   = 64

	// astraDBApplicationTokenBodyChars is everything behind the prefix: the two
	// halves and the divider between them, which is the count the scan cuts a
	// candidate by.
	astraDBApplicationTokenBodyChars = astraDBApplicationTokenClientIDChars + 1 + astraDBApplicationTokenSecretChars

	// astraDBApplicationTokenChars is the whole of a token, which is the length
	// the Astra CLI states and refuses a token for not having.
	astraDBApplicationTokenChars = len(astraDBApplicationTokenPrefix) + astraDBApplicationTokenBodyChars
)

// isAstraDBApplicationTokenBody reports whether s is everything behind the
// prefix of a token: the client identifier, the divider, and the secret.
//
// The divider is compared before either half is walked, since it is one test
// against as many as eighty-eight, and it is where a candidate that is no token
// most often parts from one — a run of the body's alphabet carries no colon at
// all.
func isAstraDBApplicationTokenBody(s string) bool {
	return s[astraDBApplicationTokenClientIDChars] == astraDBApplicationTokenDivider &&
		isAstraDBApplicationTokenRun(s[:astraDBApplicationTokenClientIDChars]) &&
		isAstraDBApplicationTokenRun(s[astraDBApplicationTokenClientIDChars+1:])
}

// isAstraDBApplicationTokenRun reports whether the whole of s is written in the
// alphabet the two halves are read in.
func isAstraDBApplicationTokenRun(s string) bool { return base64URLRunEnd(s, 0) == len(s) }

// astraDBApplicationTokenTail is what the scan settles the tail of its input
// by. prefixTail (builtin_scan.go) says what that is and why it is built once.
var astraDBApplicationTokenTail = newPrefixTail(astraDBApplicationTokenPrefix)
