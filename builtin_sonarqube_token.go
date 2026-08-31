package mask

import (
	"slices"
	"strings"
)

// SonarQubeToken locates SonarQube tokens: the prefix squ_ a user token is
// written with, the sqa_ of a global analysis token, the sqp_ of a project
// analysis token or the sqb_ of a project badge token, then forty hexadecimal
// characters — forty-four characters altogether.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly forty-four characters of it are. So text of that shape is
// redacted whether or not SonarQube issued it. A space, a dot, an uppercase
// prefix or a character outside lowercase hexadecimal ends the reading, so text
// as it is ordinarily written is not affected. A longer run of hexadecimal is a
// token with something written after it, and the token alone is redacted.
//
// Its name is "sonarqube-token".
func SonarQubeToken() Pattern { return sonarQubeToken }

// Token is SonarQube's own term for the whole of what this locates, and the
// generator it writes them with is the term's definition: one constant naming
// the SonarQube token prefix, sq, a one character identifier for the kind, an
// underscore, and twenty random bytes rendered in hexadecimal. The four kinds
// standing in the enumeration beside it — u for a user token, a for a global
// analysis token, p for a project analysis token, b for a project badge token —
// are four spellings of that one string, not four formats.
//
// They are one pattern because nothing divides them for a caller. All four
// authenticate: a user token carries the permissions of the user who issued it,
// the analysis tokens run analyses, and the badge token is what the endpoints
// serving a private project's badges are called with, which the endpoint
// renewing it says in as many words. A count of prefixes is not what puts a
// boundary in.
//
// The badge token is the one of the four written to be published — SonarQube's
// own README carries one, in the URL a badge is rendered from — which is the
// shape of a reason to hold two credentials apart. It is read here all the
// same: it still guards what a private project measures, SonarQube keeps an
// endpoint for renewing one that has leaked, and the forty-four characters say
// nothing about themselves beyond the kind, so a caller told which kind it was
// looking at would learn nothing a second switch could act on.
//
// What SonarQube states about the string it states twice. The generator above
// is the first: it is the vendor's own source, so the prefixes, the count and
// the alphabet are read off the code that mints a token rather than off any
// token SonarQube prints. Behind it stands prose — the release notes for
// the version that introduced the prefixes say that newly generated tokens
// carry a brief prefix distinguishing the project (sqp), global analysis (sqa)
// and legacy or user (squ) types, which names three of the four and no length
// at all.
//
// The count is forty because twenty bytes in hexadecimal are forty characters,
// which is what the vendor's own tests assert behind the prefix of every kind,
// and the whole is forty-four with a prefix in front.
// Test_sonarQubeTokenChars holds the arithmetic to both. It is read exactly
// rather than as a floor, because a run of hexadecimal longer than the count is
// not one longer token but a token with something written after it, and a floor
// would swallow what the run went on to hold.
//
// The alphabet is lowercase hexadecimal, which is what the generator's
// hexadecimal encoder writes. A wider class is available — gitleaks and
// kingfisher, which read these prefixes, both take it — and it is declined for
// the reason the RubyGems scan declines it, the worked case of the same choice:
// the class here is the whole of the body, so widening it draws in text a
// narrower reading would have turned away, and the case it would guard against
// does not exist. Were SonarQube to stop rendering those twenty bytes in
// hexadecimal, the count would move with the alphabet, and a scan reading forty
// characters of a wider class would locate nothing either.
//
// The prefixes are read in the one case SonarQube writes them. kingfisher reads
// this format without regard to case, which locates SQU_ with a lowercase body
// behind it; that is the shape an environment variable's name is written in
// rather than the shape a token is, and reading it would redact the name a
// caller keeps a log by.
//
// There is no boundary on either side of a match. What a boundary in front
// would buy is a candidate written straight against a word character, and prose
// carries no prefix with forty hexadecimal characters behind it to be written
// against anything. What it would cost is a token dropped whole rather than
// trimmed wherever it is written against one, and SONAR_TOKEN_squ_... is how a
// token reaches a log line from a shell.
// Test_SonarQubeToken_nextToWordCharacters pins the shape that pays for it.
// Behind the match the same demand costs a token written against a
// forty-first character of hexadecimal, which under an exact count is a token
// and one character belonging to no credential.
//
// The byte the scan searches the input for is the q, one character into every
// prefix. builtin_scan.go says why a scan searches for one byte of its prefix
// rather than for the prefix itself, and here three things settle which byte.
// The character naming the kind stands at a fixed index but is a different byte
// in each prefix, so it is no byte a single search can look for. The underscore
// is what an environment variable, a snake_case name and a log field are
// written with, so a scan anchored on one opens a candidate on a great deal of
// the text a caller is masking only to reject it again. And of the two left,
// the q is the rarer in prose by a wide margin — it stands in about a thousandth
// of the letters of English where the s stands in near a sixteenth. It is also
// no character a body is written with, which
// Test_sonarQubeTokenAnchor holds it to: a digest, an identifier or any other
// hexadecimal run stops this search nowhere, however long it runs.
//
// The scan resumes one byte past the anchor whether the candidate became a
// token or not, which is the default step reached from where the search stops:
// builtin_scan.go argues it once, and this scan needs no more than that it
// resumes there. Consuming the match would step over a token written inside the
// one just found.
//
// The scan keeps no cursor and needs none: a candidate reads at most forty-four
// bytes and stops, which bounds what it reads with no state to be wrong about,
// and is what rules out a quadratic input.
//
// What this pattern over-matches on is the vendor's format exactly: four
// characters written as a prefix is, then forty of hexadecimal with nothing
// between any of them. Prose holds no such run, and neither does any encoding
// that writes no underscore — standard base64, base32 and hexadecimal itself,
// so a certificate body or an embedded image carries no candidate at however
// long it runs. What is left is base64url, where all four characters of
// a prefix stand: there a prefix falls at a given position about once in four
// million, and the forty characters behind it are all hexadecimal about once in
// four to the fortieth, hexadecimal being a quarter of that alphabet. Where the
// two do coincide there is nothing left in the text to tell the run from a
// token, and redacting it is the same decision as redacting a real one.
// Test_SonarQubeToken_insideAnOpaqueRun pins it.
//
// SonarQube Cloud writes a fifth prefix that this scan does not read. Its
// scoped organization tokens are identified by sqco_, which the documentation
// states and which is the whole of what it states: no length, no alphabet, and
// no token printed in full. trufflehog reads fifty-nine letters and digits
// behind that prefix. A count resting on one ruleset is how a pattern comes to
// locate nothing at all, which is the failure nothing downstream reports — a
// pattern that fires on nothing looks exactly like a caller whose text held
// nothing. A width SonarQube states, or a token it prints, is a prefix and a
// number added here.
// Test_SonarQubeToken_theScopedOrganizationTokenPrefix pins the decision so that
// reading it is a change somebody argues for.
//
// The shape SonarQube issued before these prefixes is not read, and reading it
// is what this package exists not to do: forty hexadecimal characters with
// nothing in front of them, which is a git SHA exactly. noseyparker and
// kingfisher both read that shape and can only do it by the name beside it,
// asking for sonar.login within a few characters; gitleaks asks for the same
// keyword and makes the prefix optional. A pattern reading it here would redact
// every commit hash a caller passes through. It is the loose grammar this
// package declines rather than the unlucky one, and a token of that shape
// reaching a log stays in the output whole.
// Test_SonarQubeToken_theShapeItReplaced pins the decision.
//
// referenceSonarQubeToken in builtin_sonarqube_token_test.go keeps the grammar
// as a regular expression, spelling the prefixes, the count and the character
// class again so that the two are changed together, and the fuzz target beside
// it holds this scan to that expression. An expression is affordable here: the
// repetition is exact, so the machine an engine builds is read once and stops,
// and every prefix opens with the same two characters for an engine to search
// the text for.
var sonarQubeToken = NewPattern("sonarqube-token", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := sonarQubeTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], sonarQubeTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not,
		// which is the default step and needs no claim about the grammar to
		// rest on.
		offset = anchor + 1

		if anchor < sonarQubeTokenAnchorIndex {
			continue
		}
		start := anchor - sonarQubeTokenAnchorIndex

		// The byte every prefix opens with is tested before the prefixes are
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the prefixes is a length and a read apiece.
		if src[start] != sonarQubeTokenOpening[0] || !opensSonarQubeToken(src[start:]) {
			continue
		}

		body := start + sonarQubeTokenPrefixChars
		end := start + sonarQubeTokenChars
		if end > len(src) {
			// The input ends inside the body, and the count behind the prefix
			// is the whole of what tells a token from any other run written
			// there.
			retain = min(retain, start)
			continue
		}
		if isSonarQubeTokenBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// sonarQubeTokenPrefixes is what a candidate opens with: one entry per kind,
// each of them the opening, the kind and the separator.
//
// They are built from those parts rather than written out, so that the table
// below is the one place a kind is named. A second list is one that can come to
// disagree about which kinds there are, and what a stream would then do with the
// kind it had not been told about is release the characters a token opens with
// and redact nothing.
var sonarQubeTokenPrefixes = func() []string {
	prefixes := make([]string, 0, len(sonarQubeTokenKinds))
	for _, kind := range sonarQubeTokenKinds {
		prefixes = append(prefixes, sonarQubeTokenOpening+kind+string(sonarQubeTokenSeparator))
	}
	return prefixes
}()

// sonarQubeTokenKinds is the character each prefix names the kind with, in the
// order SonarQube's own enumeration writes them: u for the user token that
// carries its author's permissions, a for the global analysis token that
// analyses every project, b for the project badge token the badge endpoints of
// a private project are called with, p for the project analysis token that
// analyses one project. They are the same string behind the prefix, which is
// why they are kinds of one pattern rather than four patterns.
var sonarQubeTokenKinds = []string{"u", "a", "b", "p"}

const (
	// sonarQubeTokenOpening is what every prefix opens with, and is the byte
	// tested before the prefixes are compared. It is the constant SonarQube's
	// generator writes in front of the kind.
	sonarQubeTokenOpening = "sq"

	// sonarQubeTokenSeparator closes every prefix, dividing it from the body.
	// Test_sonarQubeTokenPrefixes holds it to standing once in every prefix.
	sonarQubeTokenSeparator = '_'

	// sonarQubeTokenKindChars is how many characters name the kind, and
	// sonarQubeTokenPrefixChars the whole of a prefix: the opening, the kind
	// and the separator.
	sonarQubeTokenKindChars   = 1
	sonarQubeTokenPrefixChars = len(sonarQubeTokenOpening) + sonarQubeTokenKindChars + 1

	// sonarQubeTokenAnchor is the byte the scan searches the input for and
	// sonarQubeTokenAnchorIndex is where it stands in every prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what made it
	// this byte, and Test_sonarQubeTokenAnchor holds it to both the index and
	// to being no character a body may carry.
	sonarQubeTokenAnchor      = 'q'
	sonarQubeTokenAnchorIndex = 1

	// sonarQubeTokenBodyChars is how many hexadecimal characters stand behind
	// the prefix — the width twenty bytes come to — and sonarQubeTokenChars the
	// whole of a token. Test_sonarQubeTokenChars holds the arithmetic to both.
	sonarQubeTokenBodyChars = 40
	sonarQubeTokenChars     = sonarQubeTokenPrefixChars + sonarQubeTokenBodyChars
)

// opensSonarQubeToken reports whether s opens with one of the prefixes a token
// is written with.
//
// It is handed the text from a candidate's start rather than a prefix cut to
// width, so that the width is checked in one place rather than left to the
// caller to have cut correctly. A prefix the end of the input cut short is
// answered false and is what sonarQubeTokenTail holds the input back for, so
// nothing is lost by saying no without saying why.
func opensSonarQubeToken(s string) bool {
	if len(s) < sonarQubeTokenPrefixChars {
		return false
	}
	return slices.Contains(sonarQubeTokenPrefixes, s[:sonarQubeTokenPrefixChars])
}

// isSonarQubeTokenBody reports whether s is the body of a token: exactly
// sonarQubeTokenBodyChars characters, all of them hexadecimal.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count being left to the caller to have cut
// correctly.
func isSonarQubeTokenBody(s string) bool {
	if len(s) != sonarQubeTokenBodyChars {
		return false
	}
	for i := range len(s) {
		if !isSonarQubeTokenBodyByte(s[i]) {
			return false
		}
	}
	return true
}

// isSonarQubeTokenBodyByte reports whether c is a lowercase hexadecimal digit,
// which is what a body is written in.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go,
// which hold what more than one scan reads. Every hexadecimal run this package
// reads keeps its own test for the reason its own file gives — one admits
// either case where another admits lowercase alone — and a shared test named
// for the class rather than for what reads it would silently be the wrong
// answer for one of them.
func isSonarQubeTokenBodyByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f'
}

// sonarQubeTokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var sonarQubeTokenTail = newPrefixTail(sonarQubeTokenPrefixes...)
