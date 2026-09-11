package mask

import "strings"

// AxiomPersonalAccessToken locates Axiom personal access tokens: the prefix
// xapt- and a UUID behind it — forty-one characters altogether. One shape
// serves every token of the kind: a personal access token performs every action
// the person who created it can perform, so nothing in the string says what it
// reaches.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly forty-one characters of it are. So text of that shape is redacted
// whether or not Axiom issued it. Anything but a UUID behind the prefix ends the
// reading — a character outside hexadecimal, a separator standing where the
// layout writes none, a run the input cuts short — so text as it is ordinarily
// written is not affected. A longer run of hexadecimal is a token with something
// written after it, and the token alone is redacted.
//
// Its name is "axiom-personal-access-token".
func AxiomPersonalAccessToken() Pattern { return axiomPersonalAccessToken }

// Personal access token is Axiom's own term for the whole of what this locates.
// The page on authenticating API requests heads a section "Personal access
// tokens (PAT)" and says such a token provides full control over an Axiom
// account, the CLI reference says a personal access token starts with xapt- and
// lets you do everything you can do in the Axiom Console, and the Console mints
// one under Settings, Profile, Personal tokens.
//
// The API token Axiom writes xaat- is not read here, and where one is written it
// stays in the output whole. That is stated rather than hidden, and what puts the
// boundary there is the difference Axiom itself draws: a personal access token
// performs every action its holder can perform, across every organization they
// belong to, where an API token carries only the privileges it was created with
// and reaches only the datasets it was given. A caller has reason to redact one
// and not the other, and a redactor keying on Match.Pattern.Name can say which of
// the two a log carried — so the two belong under separate switches rather than
// under this one widened to cover both.
// Test_AxiomPersonalAccessToken_theAPIToken pins that this scan declines the
// other prefix, so that reading it is a change somebody argues for.
//
// The prefix is Axiom's own, stated as a rule rather than shown in an example.
// The CLI reference writes it twice in prose, and Axiom's own Go SDK is where it
// is executable: IsPersonalToken is a test for exactly this prefix, and the CLI
// refuses a token failing it with "token is not a personal access token (missing
// 'xapt-' prefix)". The Python and Rust SDKs carry the same five characters in
// the error they raise when a personal token is passed where an API token is
// required.
//
// What Axiom does not write down anywhere is the length. Two artifacts of its
// own state the layout instead, and they agree. The first is the Go SDK's own
// test fixtures, which write a personal token as the prefix followed by an X for
// each hexadecimal character of a UUID with the four separators standing where a
// UUID's stand — a mask byte for byte rather than an elision, since an elision
// would not reproduce the separators at all, and written that way in three files
// of that SDK. The second is Axiom's documentation, which prints one whole token
// of the other kind, the API token's prefix and a UUID in lowercase hexadecimal.
// So the layout is read off the vendor on both of the kinds it issues rather
// than off one masked example.
//
// No published ruleset reads this format. gitleaks, trufflehog, noseyparker and
// kingfisher carry no Axiom rule at all, so there is nothing to weigh the layout
// against and nothing that disagrees with it.
//
// The body is read as a UUID rather than as thirty-six more characters behind
// the prefix. A UUID's four separators stand at fixed places, and that is the
// whole of what tells the shape from any other run of that length: reading the
// thirty-six loosely would admit a great deal more for no token gained, since
// every token Axiom writes carries the separators where the layout puts them.
//
// The hexadecimal is read in either case. Axiom prints these lowercase and an
// encoder writing a UUID writes lowercase, but a UUID upper-cased on its way
// through a log is the same credential, and a reading too narrow costs the whole
// of it where one too wide costs nothing but a shape nobody issues.
//
// The version and the variant a UUID carries are not read. The one whole token
// Axiom prints — the API token above — is version 4, and the nibbles that say so
// stand at fixed places where they could be demanded, but nothing of Axiom's
// states a version, so demanding it would be a tightening read off a value
// somebody was shown rather than off the format. Being wrong about it locates
// nothing at all, where being wrong about the alphabet locates a token with a
// character too many.
// Test_AxiomPersonalAccessToken_anyVersionAndVariant pins the decision.
//
// The byte the scan searches the input for is the x the prefix opens with, and
// the prefix is read back from it. builtin_scan.go says why a scan searches for
// one byte rather than for the prefix itself; what makes it this byte is two
// things. The first is the text around a token: over the line these benchmarks
// are written on the x stands once, in the vendor's own name, where the t stands
// fourteen times, the a six, and the p and the hyphen four apiece, so the x is
// the byte the search stops at least often — which is what a scan pays for a
// line holding no token.
// Test_axiomPersonalAccessTokenFindBenchmarks_lineTheAnchorWasChosenAgainst
// holds that line to the counts the choice was read off.
//
// The second is what happens inside a body. The x is no hexadecimal digit, so a
// search resuming into a UUID runs to the end of it without stopping; so do the
// p and the t, where the hyphen the prefix closes with is a body character and
// would stop the search at every separator of every UUID and of every ISO
// timestamp a log line is written with, and the a would stop about once in
// sixteen characters of any body at all.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a token or not, which is the default and needs no argument.
// What it catches here is the candidate the body turned away with a token
// written inside it: the prefix written twice over runs its first candidate's
// body into the x of the second, which is no hexadecimal digit, so that
// candidate is rejected and the token stands five characters along inside the
// bytes it reached over.
// Test_AxiomPersonalAccessToken_aTokenInsideARejectedCandidate drives it. A
// token cannot open inside the body of another, since three characters of the
// prefix are written outside hexadecimal and the body admits nothing else, so
// the spans this pattern reports never overlap.
//
// The scan keeps no cursor and needs none: a candidate reads at most forty-one
// bytes — the prefix compared and the body walked — and stops, which bounds what
// it reads with no state to be wrong about. That is what rules out a quadratic
// input here, whatever the run behind a candidate goes on to.
//
// There is no boundary on either side of a match. One in front would drop the
// whole match rather than trim it wherever a token is written against a word
// character, as AXIOM_TOKEN_xapt-... is. One behind would drop rather than trim
// as well: under a fixed layout a token written against a thirty-seventh
// hexadecimal character is still a token with something after it, and a boundary
// there would locate nothing at all where this scan redacts the forty-one Axiom
// issued and leaves the character that belongs to no credential in the text.
// Test_AxiomPersonalAccessToken_nextToWordCharacters writes both out.
//
// What this pattern over-matches on: a UUID written behind the prefix by
// something other than Axiom. Nothing else in the text tells such a run from a
// token — they are the same forty-one bytes — so a scan declining it would
// decline every real token of the same shape. What makes it rare is the prefix
// rather than the body: xapt spells no word, and the hyphen it closes with means
// a kebab-case run could reach it only through a word ending in those four
// characters, which English has none of. A UUID is common in a log and the five
// characters in front of one are not.
//
// referenceAxiomPersonalAccessToken in
// builtin_axiom_personal_access_token_test.go keeps the grammar as a regular
// expression, spelling the prefix, the groups, the separators and the character
// class again so that the two are changed together, and the fuzz target beside
// it holds this scan to that expression. An expression is affordable here for
// both of the reasons it usually is: every repetition is exact, so the machine
// an engine builds is read once and stops, and the prefix is written outside the
// alphabet its own body is written in, so a run of that alphabet is no position
// an engine stops at. The five-character literal in front is what it searches
// the text for.
var axiomPersonalAccessToken = newBuiltin("axiom-personal-access-token", &axiomPersonalAccessTokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two, and this format adds nothing to them — a
	// token whole is a token finished, since nothing behind the layout is read.
	retain := axiomPersonalAccessTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], axiomPersonalAccessTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not,
		// for the reason the rationale above gives: a candidate the body turned
		// away can hold a whole token inside it, which a scan stepping over its
		// own reach would leave in the output.
		offset = anchor + 1

		if anchor < axiomPersonalAccessTokenAnchorIndex {
			continue
		}
		start := anchor - axiomPersonalAccessTokenAnchorIndex

		if !strings.HasPrefix(src[start:], axiomPersonalAccessTokenPrefix) {
			continue
		}

		body := start + len(axiomPersonalAccessTokenPrefix)
		end := start + axiomPersonalAccessTokenChars
		if end > len(src) {
			// The input ends inside the body, and the layout is the whole of
			// what tells a token from any other run written behind the prefix.
			retain = min(retain, start)
			continue
		}
		if isAxiomPersonalAccessTokenBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// axiomPersonalAccessTokenPrefix is what every personal access token opens
	// with, and what the scan reads back from its anchor. Three of its
	// characters are written outside the alphabet a body is written in, which is
	// what keeps a token from opening inside another and what keeps a search
	// from stopping inside a body; the hyphen it closes with is a body
	// character, which is why nothing here rests on the prefix closing outside
	// that alphabet. Test_axiomPersonalAccessTokenPrefix holds it to both.
	axiomPersonalAccessTokenPrefix = "xapt-"

	// axiomPersonalAccessTokenAnchor is the byte the scan searches the input for
	// and axiomPersonalAccessTokenAnchorIndex is where it stands in the prefix,
	// so a candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix rather
	// than for the prefix itself; the rationale above says what made it this
	// byte. Test_axiomPersonalAccessTokenAnchor holds it to standing at this
	// index.
	axiomPersonalAccessTokenAnchor      = 'x'
	axiomPersonalAccessTokenAnchorIndex = 0

	// axiomPersonalAccessTokenBodyChars is how many characters stand behind the
	// prefix: the thirty-six of a UUID, written out here as the groups and the
	// separators between them so that the count and the walk below cannot come
	// apart.
	axiomPersonalAccessTokenBodyChars = 8 + 1 + 4 + 1 + 4 + 1 + 4 + 1 + 12

	// axiomPersonalAccessTokenChars is the whole of a token.
	// Test_axiomPersonalAccessTokenChars holds it to the forty-one the prefix
	// and a UUID come to.
	axiomPersonalAccessTokenChars = len(axiomPersonalAccessTokenPrefix) + axiomPersonalAccessTokenBodyChars

	// axiomPersonalAccessTokenSeparator is what divides the groups of a UUID.
	// The separators standing at fixed places are the whole of what tells the
	// shape from thirty-six other characters written behind the prefix, which is
	// why the body is read as a layout rather than as a count.
	axiomPersonalAccessTokenSeparator = '-'
)

// axiomPersonalAccessTokenGroups are the five groups of hexadecimal a UUID is
// written in, eight characters then three of four then twelve, with a separator
// between each pair. Test_axiomPersonalAccessTokenChars holds them to coming to
// axiomPersonalAccessTokenBodyChars, which is what keeps the walk below and the
// count the scan cuts by from disagreeing.
var axiomPersonalAccessTokenGroups = [...]int{8, 4, 4, 4, 12}

// isAxiomPersonalAccessTokenBody reports whether s is everything behind the
// prefix of a token: a UUID, which is axiomPersonalAccessTokenGroups written in
// hexadecimal with a separator between each pair of groups.
//
// The groups are walked rather than the positions of the separators listed,
// because a list of positions is a second statement of the layout that can come
// to disagree with the count the scan cuts by.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count being left to the caller to have cut
// correctly.
func isAxiomPersonalAccessTokenBody(s string) bool {
	if len(s) != axiomPersonalAccessTokenBodyChars {
		return false
	}
	i := 0
	for g, width := range axiomPersonalAccessTokenGroups {
		if g > 0 {
			if s[i] != axiomPersonalAccessTokenSeparator {
				return false
			}
			i++
		}
		for range width {
			if !isAxiomPersonalAccessTokenHexByte(s[i]) {
				return false
			}
			i++
		}
	}
	return true
}

// isAxiomPersonalAccessTokenHexByte reports whether c is a hexadecimal digit,
// which is what the groups of a UUID are written in.
//
// Either case is admitted where Axiom prints these lowercase, for the reason the
// rationale above gives: a UUID upper-cased on its way through a log is the same
// credential, and what the wider reading admits besides is a shape nobody issues.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go,
// which hold what more than one scan reads. Every hexadecimal run this package
// reads keeps its own test for the reason its own file gives — one admits either
// case where another admits lowercase alone — and a shared test named for the
// class rather than for what reads it would silently be the wrong answer for one
// of them.
func isAxiomPersonalAccessTokenHexByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'F' ||
		'a' <= c && c <= 'f'
}

// axiomPersonalAccessTokenTail is what the scan settles the tail of its input
// by. prefixTail (builtin_scan.go) says what that is and why it is built once.
var axiomPersonalAccessTokenTail = newPrefixTail(axiomPersonalAccessTokenPrefix)
