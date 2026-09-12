package mask

import "strings"

// AxiomAPIToken locates Axiom API tokens: the prefix xaat- and a UUID behind it
// — forty-one characters altogether. One shape serves every token of the kind:
// an API token carries the privileges it was created with, and whether those
// reach one dataset or every monitor in an organization is not written into the
// string.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly forty-one characters of it are. So text of that shape is redacted
// whether or not Axiom issued it. Anything but a UUID behind the prefix ends the
// reading — a character outside hexadecimal, a separator standing where the
// layout writes none, a run the input cuts short — so text as it is ordinarily
// written is not affected. A longer run of hexadecimal is a token with something
// written after it, and the token alone is redacted.
//
// Its name is "axiom-api-token".
func AxiomAPIToken() Pattern { return axiomAPIToken }

// API token is Axiom's own term for the whole of what this locates. The page on
// authenticating API requests names two types of token and heads the first of
// them "API tokens", which let you control the actions that can be performed
// with the token, and the Console mints one under Settings, API tokens.
//
// That page divides API tokens again — a basic one ingests to the datasets it
// was given, an advanced one performs the actions it was created with, up to
// creating datasets and changing monitors — and the division puts no boundary
// here, because it reaches nothing a caller could act on: the two are minted
// from one page under one term, and nothing in the string says which was issued
// — Axiom's SDKs test an API token for the one prefix below and for no other,
// and neither its documentation nor its SDKs write a second one anywhere. A
// redactor keying on Match.Pattern.Name could not tell them apart if there were
// two patterns, so what two switches would offer a caller is a choice they have
// no way to make.
//
// AxiomPersonalAccessToken (builtin_axiom_personal_access_token.go) is the
// other half of this vendor's format, and there the boundary is one a caller
// can act on: a personal access token performs every action its holder can
// perform, across every organization they belong to, where this one carries
// only what it was created with. Axiom draws the line itself and tells callers
// to prefer an API token where they can, so a log kept under one is not a log
// kept under the other.
//
// The prefix is Axiom's own, stated as a rule rather than shown in an example,
// and Axiom's Go SDK is where it is executable: IsAPIToken is a test for exactly
// these five characters. The error that SDK raises when a personal token is
// passed to an edge operation names them in prose — use an API token (xaat-) —
// and the Rust SDK carries them in the error it raises for the same case. The
// JavaScript SDK carries them in the warning it prints when a caller passes a
// personal token, which tells them to use an API token instead. The
// documentation writes the same five characters wherever it says which kind an
// edge endpoint requires.
//
// What Axiom does not write down anywhere is the length. The layout is read off
// two artifacts of its own instead, and they agree. The first is the one whole
// token Axiom prints: the response that provisions an organization carries a
// token of this kind, the prefix and a UUID in lowercase hexadecimal. The second
// is the Go SDK's own test fixtures, which write an API token as the prefix
// followed by an X for each hexadecimal character of a UUID with the four
// separators standing where a UUID's stand — a mask byte for byte rather than an
// elision, since an elision would not reproduce the separators at all. The two
// halves of this format are declared together for that reason, and the file
// naming the other half says so where the declarations stand.
//
// No ruleset states a shape for this format, so there is nothing to weigh the
// layout against and nothing that disagrees with it. gitleaks, trufflehog,
// noseyparker and the secrets-patterns-db carry no Axiom rule at all. kingfisher
// announces one from v1.96.0 for a token of each kind, and it is a rule nobody
// can read: kingfisher generates its catalog at build time from upstream
// Betterleaks and Veles sources and checks none of it in, and neither the
// Betterleaks catalog it pins nor the Veles detectors it selects carries an
// Axiom rule. A provider named in a changelog is not an expression, and a
// tightening read off one would rest on nothing.
//
// How that body is read — as a UUID's layout rather than as thirty-six loose
// characters, in hexadecimal of either case, with the version and the variant
// left unread — is not this half's to decide. One layout is declared once and
// read by both scans, and builtin_axiom_personal_access_token.go argues all
// three where the declarations stand. Test_AxiomAPIToken_anyVersionAndVariant
// drives the last of them against this prefix, since a version demanded here
// would locate nothing at all and no case of the other half's would report it.
//
// The byte the scan searches the input for is the x the prefix opens with, and
// the prefix is read back from it. builtin_scan.go says why a scan searches for
// one byte rather than for the prefix itself; what makes it this byte is two
// things. The first is the text around a token: over the line these benchmarks
// are written on the x stands once, in the vendor's own name, where the t stands
// eleven times, the a nine and the hyphen three, so the x is the byte the search
// stops at least often — which is what a scan pays for a line holding no token.
// Test_axiomAPITokenFindBenchmarks_lineTheAnchorWasChosenAgainst holds that line
// to the counts the choice was read off.
//
// The second is what happens inside a body. The x is no hexadecimal digit, so a
// search resuming into a UUID runs to the end of it without stopping; so does
// the t, where the hyphen the prefix closes with is a body character and would
// stop the search at every separator of every UUID and of every ISO timestamp a
// log line is written with, and the a — which this prefix writes twice — would
// stop about once in sixteen characters of any body at all.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a token or not, which is the default and needs no argument.
// What it catches here is the candidate the body turned away with a token
// written inside it: the prefix written twice over runs its first candidate's
// body into the x of the second, which is no hexadecimal digit, so that
// candidate is rejected and the token stands five characters along inside the
// bytes it reached over.
// Test_AxiomAPIToken_aTokenInsideARejectedCandidate drives it. A token cannot
// open inside another at all, so the spans this pattern reports never overlap,
// and the two places it could open want separate reasons. Inside the body: a
// body is hexadecimal and the separator alone and two characters of the prefix
// are neither. Inside the prefix: the rest of that prefix would have to open a
// prefix of its own, and no proper suffix of this one does.
// Test_axiomAPITokenPrefix holds both.
//
// The scan keeps no cursor and needs none: a candidate reads at most forty-one
// bytes — the prefix compared and the body walked — and stops, which bounds what
// it reads with no state to be wrong about. That is what rules out a quadratic
// input here, whatever the run behind a candidate goes on to.
//
// There is no boundary on either side of a match. One in front would drop the
// whole match rather than trim it wherever a token is written against a word
// character, as AXIOM_TOKEN_xaat-... is. One behind would drop rather than trim
// as well: under a fixed layout a token written against a thirty-seventh
// hexadecimal character is still a token with something after it, and a boundary
// there would locate nothing at all where this scan redacts the forty-one Axiom
// issued and leaves the character that belongs to no credential in the text.
// Test_AxiomAPIToken_nextToWordCharacters writes both out.
//
// What this pattern over-matches on: a UUID written behind the prefix by
// something other than Axiom. Nothing else in the text tells such a run from a
// token — they are the same forty-one bytes — so a scan declining it would
// decline every real token of the same shape. What makes it rare is the prefix
// rather than the body: xaat spells no word, and the hyphen it closes with means
// a kebab-case run could reach it only through a word ending in those four
// characters, which English has none of. A UUID is common in a log and the five
// characters in front of one are not.
//
// referenceAxiomAPIToken in builtin_axiom_api_token_test.go keeps the grammar as
// a regular expression, spelling the prefix, the groups, the separators and the
// character class again so that the two are changed together, and the fuzz
// target beside it holds this scan to that expression. An expression is
// affordable here for both of the reasons it usually is: every repetition is
// exact, so the machine an engine builds is read once and stops, and the prefix
// opens on a character no body is written with, so a run of the body's alphabet
// is no position an engine stops at. The five-character literal in front is what
// it searches the text for.
var axiomAPIToken = newBuiltin("axiom-api-token", &axiomAPITokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two, and this format adds nothing to them — a
	// token whole is a token finished, since nothing behind the layout is read.
	retain := axiomAPITokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], axiomAPITokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not,
		// for the reason the rationale above gives: a candidate the body turned
		// away can hold a whole token inside it, which a scan stepping over its
		// own reach would leave in the output.
		offset = anchor + 1

		if anchor < axiomAPITokenAnchorIndex {
			continue
		}
		start := anchor - axiomAPITokenAnchorIndex

		if !strings.HasPrefix(src[start:], axiomAPITokenPrefix) {
			continue
		}

		body := start + len(axiomAPITokenPrefix)
		end := start + axiomAPITokenChars
		if end > len(src) {
			// The input ends inside the body, and the layout is the whole of
			// what tells a token from any other run written behind the prefix.
			retain = min(retain, start)
			continue
		}
		if isAxiomTokenBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// axiomAPITokenPrefix is what every API token opens with, and what the scan
	// reads back from its anchor. Two of its characters are written outside the
	// alphabet a body is written in, which is what keeps a token from opening
	// inside another and what keeps a search from stopping inside a body; the
	// hyphen it closes with is a body character, which is why nothing here rests
	// on the prefix closing outside that alphabet. Test_axiomAPITokenPrefix
	// holds it to both.
	axiomAPITokenPrefix = "xaat-"

	// axiomAPITokenAnchor is the byte the scan searches the input for and
	// axiomAPITokenAnchorIndex is where it stands in the prefix, so a candidate
	// begins that many bytes in front of what a search reported. builtin_scan.go
	// says why a scan searches for one byte of its prefix rather than for the
	// prefix itself; the rationale above says what made it this byte.
	// Test_axiomAPITokenAnchor holds it to standing at this index.
	//
	// The byte and the index are written out rather than read from the other
	// half, where the counts of the body are read from it. What a scan searches
	// for is not part of the format and neither half's choice binds the other: a
	// byte borrowed would carry an index that means nothing in this prefix the
	// moment the other scan moved its own, and nothing would report it.
	axiomAPITokenAnchor      = 'x'
	axiomAPITokenAnchorIndex = 0

	// axiomAPITokenChars is the whole of an API token: this half's prefix and
	// the body both halves share. Test_axiomAPITokenChars holds it to the
	// forty-one the prefix and a UUID come to.
	axiomAPITokenChars = len(axiomAPITokenPrefix) + axiomTokenBodyChars
)

// axiomAPITokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var axiomAPITokenTail = newPrefixTail(axiomAPITokenPrefix)
