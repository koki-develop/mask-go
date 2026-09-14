package mask

import "strings"

// LangfuseSecretKey locates the secret keys Langfuse mints: the prefix sk-lf-
// and the UUID behind it, forty-two characters in all. One shape serves every
// key Langfuse mints — a key is minted for a project or for an organization and
// reaches the API through the same header either way, so nothing in the string
// says what it is allowed to reach. A key a caller supplied rather than had
// minted is not located.
//
// A key is located wherever it is written, with no word boundary either side,
// and exactly forty-two characters of it are. So text of that shape is redacted
// whether or not Langfuse issued it, and a character written straight after a
// key is left in the text.
//
// Its name is "langfuse-secret-key".
func LangfuseSecretKey() Pattern { return langfuseSecretKey }

// Secret key is Langfuse's own term, and it is one half of a pair. Langfuse
// issues a public key and a secret key together and the two authenticate as
// one, base64 encoded into a Basic header; the SDKs take them as
// LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY, and the CLI and the docs write
// them the same way. Only the secret key is located here, so the name has to
// carry the word that separates them — LangfuseAPIKey would claim the other as
// well.
//
// The public key is not a pattern of its own either, and what settles that is
// the caller rather than the format: Langfuse publishes the public key by
// design. Its browser SDK takes the public key alone and its own docs write
// that key into NEXT_PUBLIC_LANGFUSE_PUBLIC_KEY, which is a Next.js name
// meaning the value is compiled into what the browser downloads. A caller
// redacting the value Langfuse asks them to ship to every visitor is redacting
// an identifier, and one that says which project a log line belongs to. The two
// halves are not worth the same to redact, so a caller who wanted both would
// need two switches and gets one.
//
// What Langfuse states of the secret key is the prefix, and it states it
// everywhere the pair is written: the environment assignments its SDK pages,
// its CLI page and its integration guides all print are sk-lf- and an ellipsis.
// Its admin API states the same prefix as a rule rather than as an example, by
// rejecting a caller-supplied secret key that does not begin with sk-lf-.
//
// The rest of the format comes from the vendor's own implementation, which
// Langfuse publishes: generateKeySet, in the shared package its server reads
// keys through, mints one as sk-lf- and randomUUID from Node's crypto module,
// which Node documents as generating an RFC 4122 version 4 UUID. So the length
// and the alphabet are not read off a value somebody was shown — they are what
// the code issuing the credential writes, which is the vendor stating them.
//
// What that code states is the key Langfuse mints, and there is a second way a
// key comes to exist that it does not reach. The same function takes a pair of
// keys from its caller instead of minting one, and the two doors to it ask for
// less than a format. The admin API asks that a caller-supplied secret key begin
// with sk-lf- and nothing else — no length, no alphabet — so sk-lf- and a
// handful of digits is a key it accepts. The self-hosting door asks for nothing
// at all: LANGFUSE_INIT_PROJECT_SECRET_KEY is an unconstrained string handed
// straight to that function, and the example Langfuse prints beside it writes
// sk-1234567890, which carries no lf- to be found.
//
// Neither is located here, because neither has a format to read. What is left
// once the UUID goes is a prefix and then whatever an operator typed, so a scan
// reaching the first would be reading sk-lf- and a run whose alphabet and length
// nothing states; the second carries no prefix at all, and no pattern anchored
// on one can reach it whatever its body were read as. What declining costs is a
// live credential left in the output whole — and on a self-hosted deployment
// that is the key most likely to be written down, since a provisioned one goes
// into a compose file and every log line that echoes the environment.
// Test_LangfuseSecretKey_aKeyNobodyMinted pins both shapes, so that this is a
// decision on the record rather than something the next reader discovers.
//
// Two rulesets corroborate it and agree with each other. trufflehog reads
// sk-lf- and the five groups of a UUID in lowercase hexadecimal, behind a
// keyword; betterleaks reads the same five groups with no keyword in front, and
// kingfisher reads this format through betterleaks' rule rather than one of its
// own. gitleaks, noseyparker and secretlint carry no Langfuse rule at all.
//
// The hexadecimal is read in either case where every source read reads it
// lowercase. RFC 4122 asks for lowercase output and Node writes lowercase, so
// what the wider reading admits is a shape nobody issues — while a key
// upper-cased on its way through a log is the same credential, and declining it
// would leave the whole of it in the output. A reading too narrow costs a
// credential where one too wide costs nothing.
//
// The tightening on offer is the rest of version 4: it fixes the first
// character of the third group to a 4 and the first of the fourth group to one
// of 8, 9, a and b, which between them turn away all but a sixty-fourth of the
// UUIDs this reads. It is declined, and what decides it is that the prefix is
// already doing the work those characters would do. Six characters spelling
// sk-lf- are what separates a key from the text around it; the two nibbles
// separate a version 4 UUID from a version 7 one, which is a distinction about
// how Langfuse generates keys today rather than about what a key is. Were
// Langfuse to change generators — a thing a caller of this library would never
// see — a scan reading those nibbles would locate no key at all, where this one
// carries on reading them. Test_LangfuseSecretKey_aBodyOutsideVersionFour pins
// the decision, so that taking the tightening is a change somebody argues for.
//
// The count is read exactly rather than as a floor, which is what the layout
// asks for: a UUID's four separators stand at fixed places, so the shape is a
// layout and not a length, and there is no floor to read. A run carrying on
// past the thirty-sixth character is a key with something written after it, and
// the key alone is redacted.
//
// There is no boundary on either side of a match. A boundary in front drops
// rather than trims the match wherever a key is written against a word
// character, which is what LANGFUSE_SECRET_KEY_sk-lf-... is; one behind it
// drops a key followed by a character of the body's own alphabet, which under
// an exact count is a key with a character written after it. Both rulesets ask
// for a word boundary in front and something behind — a word boundary for
// trufflehog, a quote, whitespace, a semicolon or an escaped newline for
// betterleaks — so a key written straight against a letter is one they leave in
// the text where this pattern trims it.
// Test_LangfuseSecretKey_nextToWordCharacters writes those out.
//
// The byte the scan searches the input for is the k the prefix carries one
// character in. builtin_scan.go says why a scan searches for one byte of its
// prefix rather than for the prefix itself; what makes it this byte is that it
// is the rarest of the five the prefix is written with. Over the log line these
// benchmarks are written on the l stands seven times, the s six, the f three
// and the hyphen twice, where the k stands not at all — the ordinary words of a
// log line carry the other four and spell no k.
// Test_langfuseSecretKeyFindBenchmarks_lineTheAnchorWasChosenAgainst holds that
// line to those counts, so the sentence is read as a measurement rather than as
// a recollection. The k belongs to no body besides, neither to a group nor to
// the separators between them, so the search can never stop inside one, which is
// what keeps a line dense in UUIDs off the cost of this scan altogether.
//
// The scan resumes one byte past the start of a candidate whether that
// candidate became a key or not, which is the default and needs no argument.
// What it finds there is bounded rather than open: a body is hexadecimal and
// the separators between its groups, and the s, the k and the l of the prefix
// are neither, so no prefix can stand inside a body and no key can begin inside
// another. Test_langfuseSecretKeyPrefix_holdsWhatNoBodyDoes holds the prefix to
// that, so that the sentence is read as a measurement rather than as an
// assumption.
//
// What rules out a quadratic input is the count being a count: a candidate
// reads at most thirty-six bytes and stops, whatever the run behind it runs to,
// so the scan keeps no cursor and needs none.
// Test_LangfuseSecretKey_scanIsLinear drives the inputs that would find that
// wrong.
//
// What this pattern over-matches on is a UUID written behind the prefix that
// Langfuse did not issue, and the shape worth stating is the placeholder. A
// page of documentation writing sk-lf- and a UUID of zeroes is this format
// character for character, and it is redacted. betterleaks declines such a value
// with a minimum-entropy filter, where trufflehog locates it and leaves the
// deciding to the call it makes against the API. The filter is what this library
// may not have: entropy is a property of the characters rather than of who
// issued them, so one declining a UUID of zeroes declines the key Langfuse
// happened to mint with a long run of one digit in it. Redacting a placeholder
// costs a reader a value that told them nothing; declining one costs a caller a
// live credential. Test_LangfuseSecretKey_aPlaceholderUUID pins it.
//
// Nothing else reaches a span. A UUID standing on its own is not read, and
// could not be — it is what a request id, a trace id and a correlation id are
// written as, and a grammar admitting one would redact those wherever a log
// line carries them. Prose does not spell sk-lf- either, and an opaque run that
// happens to is still not a key unless four separators stand at the four places
// a UUID puts them.
//
// referenceLangfuseSecretKeyFind in builtin_langfuse_secret_key_test.go keeps
// the grammar as a regular expression, spelling the prefix, the five groups and
// the character class again so that the two are changed together, and the fuzz
// target beside it holds this scan to that expression. An expression is
// affordable here for both of the reasons one usually is: every repetition is
// exact, so the machine an engine builds is read once and stops, and the prefix
// is a six-character literal no body can spell, so an engine searches the text
// for it and finds it nowhere in a run of hexadecimal.
var langfuseSecretKey = newBuiltin("langfuse-secret-key", &langfuseSecretKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two.
	retain := langfuseSecretKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], langfuseSecretKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not,
		// which is the default step and needs no argument.
		offset = anchor + 1

		if anchor < langfuseSecretKeyAnchorIndex {
			continue
		}
		start := anchor - langfuseSecretKeyAnchorIndex

		// The prefix is read back from the anchor. Almost every anchor the
		// search stops at reaches this line and is turned away here, so what
		// this comparison costs is most of what the scan pays for a line
		// carrying the letter but no key.
		if !strings.HasPrefix(src[start:], langfuseSecretKeyPrefix) {
			continue
		}

		body := start + len(langfuseSecretKeyPrefix)
		end := body + langfuseSecretKeyBodyChars
		if end > len(src) {
			// The input ends inside this candidate, so the layout that is the
			// whole of what tells it from anything else written behind the
			// prefix cannot be read here. The text from the candidate's start
			// is held back until the rest of it arrives.
			retain = min(retain, start)
			continue
		}
		if isLangfuseSecretKeyBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// langfuseSecretKeyPrefix is what every secret key opens with, and what the
	// scan reads back from its anchor. Its letters other than the f belong to no
	// body, neither to a group nor to the separators between them, which is what
	// keeps a key from ever beginning inside another;
	// Test_langfuseSecretKeyPrefix_holdsWhatNoBodyDoes holds it to that.
	langfuseSecretKeyPrefix = "sk-lf-"

	// langfuseSecretKeyAnchor is the byte the scan searches the input for and
	// langfuseSecretKeyAnchorIndex is where it stands in the prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what made it
	// this byte, which is a count over the text around a key rather than
	// anything about the body.
	langfuseSecretKeyAnchor      = 'k'
	langfuseSecretKeyAnchorIndex = 1

	// langfuseSecretKeyBodyChars is how many characters stand behind the
	// prefix: the thirty-six of a UUID, written out here as the groups and the
	// separators between them so that the count and the walk below cannot come
	// apart. Test_langfuseSecretKeyBodyChars holds the two together.
	langfuseSecretKeyBodyChars = 8 + 1 + 4 + 1 + 4 + 1 + 4 + 1 + 12

	// langfuseSecretKeySeparator is what divides the groups of a UUID. It is
	// the character the prefix closes with as well, which is why the layout
	// rather than any count is what tells a body from thirty-six other
	// characters written behind the prefix.
	langfuseSecretKeySeparator = '-'
)

// langfuseSecretKeyGroups are the five groups of hexadecimal a UUID is written
// in, eight characters then three of four then twelve, with a separator between
// each pair. Test_langfuseSecretKeyBodyChars holds them to coming to
// langfuseSecretKeyBodyChars, which is what keeps the walk below and the count
// the scan cuts by from disagreeing.
var langfuseSecretKeyGroups = [...]int{8, 4, 4, 4, 12}

// isLangfuseSecretKeyBody reports whether s is everything behind the prefix of
// a secret key: a UUID, which is langfuseSecretKeyGroups written in hexadecimal
// with a separator between each pair of groups.
//
// The groups are walked rather than the positions of the separators listed,
// because a list of positions is a second statement of the layout that can come
// to disagree with the count the scan cuts by.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count left to the caller to have cut correctly.
func isLangfuseSecretKeyBody(s string) bool {
	if len(s) != langfuseSecretKeyBodyChars {
		return false
	}
	i := 0
	for g, width := range langfuseSecretKeyGroups {
		if g > 0 {
			if s[i] != langfuseSecretKeySeparator {
				return false
			}
			i++
		}
		for range width {
			if !isLangfuseSecretKeyByte(s[i]) {
				return false
			}
			i++
		}
	}
	return true
}

// isLangfuseSecretKeyByte reports whether c is a hexadecimal digit, which is
// what the groups of a UUID are written in.
//
// Either case is admitted where Langfuse writes these lowercase, for the reason
// the rationale above gives: a key upper-cased on its way through a log is the
// same credential, and what the wider reading admits besides is a shape nobody
// issues.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go,
// which hold what more than one scan reads. A shared hexadecimal test named for
// the class rather than for what reads it would settle the case question for
// every scan reading it at once, and that question is answered here on what
// this vendor writes and what declining a case would cost this pattern.
func isLangfuseSecretKeyByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'F' ||
		'a' <= c && c <= 'f'
}

// langfuseSecretKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var langfuseSecretKeyTail = newPrefixTail(langfuseSecretKeyPrefix)
