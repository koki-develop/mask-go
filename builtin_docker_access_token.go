package mask

import "strings"

// DockerAccessToken locates the access tokens Docker issues in place of a
// password: personal access tokens, which carry the prefix dckr_pat_, and
// organization access tokens, which carry dckr_oat_.
//
// A token is located wherever it is written, with no word boundary either side.
// A personal access token is thirty-six characters and exactly that many are
// redacted, so a longer run of the alphabet is a token with something written
// after it and the token alone is redacted. An organization access token is
// redacted from its prefix to the end of the run it stands in. A space, a dot, a
// character outside the alphabet or an uppercase prefix ends either reading, so
// text as it is ordinarily written is not affected.
//
// Its name is "docker-access-token".
func DockerAccessToken() Pattern { return dockerAccessToken }

// Access token is Docker's own term for the whole of what this locates, and the
// two kinds sit under it: the documentation keeps organization access tokens
// beneath the path personal access tokens are written at, and the announcement
// of the second kind introduces it as the first one at an organizational level.
// Neither is published by design and neither is the identifier standing beside a
// secret, so a caller reaching for Docker redacts both, and two switches would
// mean a caller who knew of one leaving the other in their logs.
//
// What one name costs is the third thing a boundary is put in for, and it is
// worth writing down rather than passing over: a Redactor keying on
// Match.Pattern.Name() cannot say which of the two it found, where a personal
// token leaked implicates one account and an organization token leaked implicates
// every repository the organization owns. That is a real distinction to route an
// alert by, and it is outweighed here rather than absent — the vendor has one
// term for both, a caller switching them on switches them on together, and a
// caller who had to know there were two kinds to redact what Docker issues is the
// failure the single switch rules out.
//
// Each kind's prefix is stated by Docker. For a personal access token three of
// its own pages state it: the credential table of the endpoint such a token is
// exchanged at writes the format as dckr_pat_*, the Hub API reference gives the
// secret field of that same endpoint an example opening with it, and the Scout
// metrics exporter page writes dckr_pat_... into the file Prometheus is pointed
// at for a bearer credential. For an organization access token the published Hub
// OpenAPI specification states it: the token field of the response an
// organization access token is created in, described there as the actual token
// value that can be used for authentication, carries an example opening with
// dckr_oat_.
//
// What no page of Docker's states for either is a length, an alphabet or a
// checksum, so both counts are read off the rules the published rulesets state,
// which is a weaker footing than a vendor's own validator. The two kinds are not
// on the same footing as each other either, and the counts are read differently
// because of it.
//
// For a personal access token the rulesets agree and the count is read exactly.
// Five of them read the format and none disputes either part: trufflehog,
// noseyparker, kingfisher, projectdiscovery's nuclei templates and Google's
// osv-scalibr each ask for the prefix and twenty-seven characters of the letters
// of both cases, the digits, the hyphen and the underscore. Twenty-seven is a
// width that says something about itself, which is what makes it readable as a
// count rather than as wherever a run happened to stop: a base64url encoding
// with no padding is one character to every six bits, so twenty bytes come to
// twenty-seven characters and no other whole number of bytes does — nineteen
// give twenty-six and twenty-one give twenty-eight. The body is the width of a
// fixed twenty byte value, which is a size a token is minted at rather than a
// length it grew to. A run of the alphabet longer than the count is therefore
// not one longer token but a token with something written after it, and a floor
// would swallow what the run went on to hold, which is text belonging to no
// credential.
//
// For an organization access token the footing is thinner, and that is why its
// body is read as a floor rather than as a count. Thirty-two is what trufflehog
// and betterleaks each read behind the prefix — two rules, one of them read by a
// third, since kingfisher reads betterleaks' rules — and no other ruleset carries
// a rule for this prefix at all: the five above read dckr_pat_ and stop there,
// and osv-scalibr reaches the second prefix only in a test of its validator. So
// where the personal count rests on five rules agreeing, this one rests on two.
//
// Docker's own specification prints a body of twenty-seven characters behind this
// prefix, and what that is worth has to be stated carefully, because it is not a
// length. A docs example may elide rather than mask byte for byte, and this
// specification is shown to elide by the line above: it writes a personal access
// token of fifteen characters where that body is twenty-seven. So the
// twenty-seven grounds no count of its own.
//
// What it does do is take the exact reading away. An example that may be elided
// cannot say a token is twenty-seven characters, but it does say this is the
// shape Docker prints where a token goes, and a scan asking for thirty-two
// exactly locates nothing whatever in a token of the shorter shape — no part of
// it, not a prefix, nothing. That is the failure nothing downstream reports: a
// pattern that fires on nothing looks exactly like a caller whose text held
// nothing. A floor cannot fail that way, and reading one costs the characters
// written behind a token rather than the token.
//
// Twenty-seven is where the floor goes because it is the lowest width any source
// attaches to this prefix, so no token either source describes is cut short by
// it. Lower would widen what the scan reaches over without reaching any token
// that thirty-two and twenty-seven do not already cover between them, and the
// exact reading is what to revisit if Docker ever writes a width down.
//
// What the floor costs is the run an organization access token is written
// against. Where one stands in front of more of the alphabet — another token
// with nothing between them, or a base64url value it was written into — the
// characters past the token are redacted with it, and nothing in the text
// distinguishes them: the body has no width of its own to end at.
// Test_DockerAccessToken_theOrganizationBodyReachesTheEndOfTheRun writes that
// out, so that it stays a decision on the record.
//
// It costs a stream more than it costs Mask, and that is the sharper end of it. A
// candidate whose run reaches the end of the input settles nothing from its
// prefix on, so a Writer handed a long unbroken base64url blob carrying a chance
// dckr_oat_ holds everything from that prefix until the run closes — and the
// alphabet admits the hyphen and the underscore, so what closes one is whitespace
// or punctuation rather than any separator a blob is likely to hold. Reaching
// WithMaxRetained there is giving up, and what a stream writes when it gives up is
// a redaction over everything it was holding. A count would bound the wait at
// thirty-six bytes; the floor is what trades that bound for locating a token of
// either width.
//
// The alphabet is base64url for both, isBase64URLByte in builtin_scan.go, and
// there is no tightening available to decline: the encoding is the whole of what
// a body is, and every one of its sixty-four characters stands in one.
//
// The prefixes are read in lowercase alone. kingfisher reads this format without
// regard to case, which locates DCKR_PAT_ with a lowercase body behind it; that
// is the shape an environment variable's name is written in rather than the
// shape a token is, and reading it would redact the name a caller keeps a log
// by.
//
// There is no boundary on either side of a match, and here that is a choice four
// of the five rulesets above make the other way — trufflehog, noseyparker,
// kingfisher and the nuclei templates open on \b and close on a character
// outside the alphabet or the end of the input, where osv-scalibr asks for
// neither. What a boundary in front would buy is a candidate written straight
// against a word character, and the words of prose do not end in dckr. What it
// would cost is a token dropped whole rather than trimmed wherever it is written
// against one, and DOCKER_TOKEN_dckr_pat_... is how a token reaches a log line
// from a shell. Test_DockerAccessToken_nextToWordCharacters pins the shape that
// pays for it. Behind a personal access token the same demand costs more again:
// those four locate nothing at all in a token written against a twenty-eighth
// character of the alphabet, where this scan redacts the thirty-six Docker
// issued and leaves the character that belongs to no credential in the text.
//
// The byte the scan searches the input for is the k, two characters into the
// opening both prefixes share. builtin_scan.go says why a scan searches for one
// byte of its prefix rather than for the prefix itself, and here the choice is
// settled by prose rather than by a body: every character of a prefix stands in
// a base64url run one time in sixty-four, so a run opens the same number of
// candidates whichever byte is chosen, and what is left to separate them is how
// often each is written in ordinary text. The k is the rarest of the opening's
// letters in English by a wide margin, standing in well under a hundredth of the
// letters where the a and the t of the kinds behind it stand in near a tenth
// apiece. The two underscores are rarer still in prose and are passed over all
// the same: an underscore is what an environment variable, a snake_case name and
// a log field are written with, so a scan anchored on one opens a candidate on a
// great deal of the text a caller is masking to reject it again. What the k
// costs is visible on the line these benchmarks are written on, where the
// vendor's own host name carries one.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a token or not, which is the default and needs no argument.
// It is load-bearing here rather than merely correct: every character of both
// prefixes belongs to the alphabet a body is written in, so a token can begin
// inside the body of the one before it — either prefix written twice with a body
// behind the second is a token from either of them — and a scan consuming its
// match would step over the second and leave it in the output whole. The two
// spans overlap and a Masker resolves them into one.
// Test_DockerAccessToken_aTokenBeginningInsideAnother drives it.
//
// What rules out a quadratic input is a count for one kind and a cursor for the
// other. A personal access token reads at most thirty-six bytes and stops, so its
// work is bounded with no state to be wrong about. An organization access token reads its body to the end of
// the run it stands in, and a prefix written in its own body's alphabet gives a
// run no character to be divided at, so a run can hold a candidate for every
// nine characters it has and each of them would read that run to its end. The
// run is therefore worked out once and remembered: every candidate crowded
// inside one reaches the same end.
//
// What makes reusing it sound is the alphabet rather than the lengths of the
// prefixes. A body is read from the end of its own prefix, so a body reached at a
// later candidate can fall behind one reached earlier wherever two prefixes
// overlap — and the bytes between them then lie inside the earlier prefix, which
// is written in that same alphabet. A run ends at the first character the alphabet
// does not hold, so it ends in one place whichever body it is read from.
// Test_dockerAccessTokenPrefixes holds that claim, the one the resumption a byte
// along rests on as well, and Test_dockerAccessTokenAnchor holds the other half:
// every prefix carries the anchor at one index, which is what makes a candidate's
// start a function of where the search stopped and so keeps the starts moving
// forward. Test_DockerAccessToken_scanIsLinear drives the input that would find
// the cursor wrong.
//
// What this pattern over-matches on: a run of the right shape that nobody
// issued. Nine characters have to be written, two of them underscores, then
// twenty-seven more of the alphabet with nothing between any of them. Prose
// holds no such run — a body is longer than any word and carries no space or
// punctuation — and standard base64, base32 and hexadecimal write no underscore
// at all, so an identifier, a certificate body or an embedded image carries no
// candidate at however long it runs. What is left is base64url, which writes
// every character of both prefixes: there the nine stand about once in eighteen
// thousand million million characters, and the twenty-seven behind them are in
// the alphabet by construction. That is the collision this pattern pays for, and
// there is nothing in the text to tell such a run from a token — the vendor's
// format is that prefix and that many of those characters, with no part of it
// left over to fail. Test_DockerAccessToken_insideAnOpaqueRun pins it.
//
// The shape Docker Hub's login endpoint took before a prefix was written in
// front of one is not read, and reading it is what this package exists not to
// do. trufflehog keeps two detectors for this vendor, and the older of them says
// what that shape is: a UUID with no prefix at all, found near the word docker
// and verified by logging in with it as a password. A pattern reading that would
// redact every request id, every trace id and every fixture a caller passes
// through, since a UUID carries nothing to be recognised by and the only net
// left is the word standing near it. It is the loose grammar this package
// declines rather than the unlucky one, and a token of that shape reaching a log
// stays in the output whole.
// Test_DockerAccessToken_theShapeItReplaced pins the decision so that reading it
// is a change somebody argues for.
//
// referenceDockerAccessTokenFind in builtin_docker_access_token_test.go states
// the same grammar the plain way, spelling the prefixes, the counts and the
// alphabet again so that the two are changed together, and the fuzz target
// beside it holds this scan to that statement.
//
// It is written out rather than built on an expression, and the floor is what
// decided that. A floor spelled as a counted repetition costs an engine a
// machine as wide as the floor at every candidate, and candidates crowd as close
// as nine characters here because a prefix is written in its own body's
// alphabet. Written as an expression the target managed a quarter of the
// executions it manages now over the same thirty seconds, and reported none at
// all for stretches of that run. That was measured rather than supposed.
var dockerAccessToken = newBuiltin("docker-access-token", &dockerAccessTokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := dockerAccessTokenTail.start(src)

	// The cursor over the run an organization access token's body is read
	// along, shared by every candidate standing in that run. The rationale
	// above says why reading the run again at each candidate would be
	// quadratic, and why a body never begins in front of the body of the
	// candidate before it.
	runEnd := -1

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], dockerAccessTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not,
		// for the reason the rationale above gives: a prefix is written in the
		// alphabet a body is, so a token can begin inside the body of the one
		// before it.
		offset = anchor + 1

		if anchor < dockerAccessTokenAnchorIndex {
			continue
		}
		start := anchor - dockerAccessTokenAnchorIndex

		// The byte the opening begins with is tested before either prefix is
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where
		// comparing a prefix is a length and a read. A prefix the end of the
		// input cut short matches neither case below and is left to the tail,
		// which is what settles a piece of one standing there.
		if src[start] != dockerAccessTokenOpening[0] {
			continue
		}

		switch {
		case strings.HasPrefix(src[start:], dockerAccessTokenPersonalPrefix):
			body := start + len(dockerAccessTokenPersonalPrefix)
			end := start + dockerAccessTokenPersonalChars
			if end > len(src) {
				// The input ends inside the body, and the count is the whole of
				// what tells a token from any other run written behind the
				// prefix.
				retain = min(retain, start)
				continue
			}
			if isDockerAccessTokenPersonalBody(src[body:end]) {
				spans = append(spans, Span{Start: start, End: end})
			}
		case strings.HasPrefix(src[start:], dockerAccessTokenOrganizationPrefix):
			body := start + len(dockerAccessTokenOrganizationPrefix)
			// The run is read from this body only where it reaches past what
			// the cursor already holds; a body standing inside that run ends
			// where it ends, since a run is read to the first character that is
			// not one of the alphabet's.
			if body >= runEnd {
				runEnd = base64URLRunEnd(src, body)
			}
			if runEnd == len(src) {
				// The run reaches the end of the input, so neither where the
				// token ends nor whether enough of it is here is settled.
				retain = min(retain, start)
			}
			if runEnd-body >= dockerAccessTokenOrganizationBodyChars {
				spans = append(spans, Span{Start: start, End: runEnd})
			}
		}
	}
	return spans, retain
})

const (
	// dockerAccessTokenOpening is what every prefix opens with, and the byte the
	// scan tests a candidate by is in it. The kind naming what a token
	// authenticates for and the separator closing it stand behind this.
	dockerAccessTokenOpening = "dckr_"

	// dockerAccessTokenSeparator closes a prefix, behind the kind.
	dockerAccessTokenSeparator = "_"

	// The kinds Docker writes between the opening and the separator, one per
	// kind of token it issues.
	dockerAccessTokenPersonalKind     = "pat"
	dockerAccessTokenOrganizationKind = "oat"

	// The prefixes themselves, each built from the opening, its own kind and the
	// separator rather than spelled out a second time, so that a kind renamed
	// above reaches the scan, the tail and a Masker's filter at once.
	// Test_dockerAccessTokenPrefixes_areAllRead holds each of them to being a
	// prefix the scan goes on to read a body behind.
	dockerAccessTokenPersonalPrefix     = dockerAccessTokenOpening + dockerAccessTokenPersonalKind + dockerAccessTokenSeparator
	dockerAccessTokenOrganizationPrefix = dockerAccessTokenOpening + dockerAccessTokenOrganizationKind + dockerAccessTokenSeparator

	// dockerAccessTokenAnchor is the byte the scan searches the input for and
	// dockerAccessTokenAnchorIndex is where it stands in the opening, so a
	// candidate begins that many bytes in front of what a search reported. The
	// rationale above says what made it this byte;
	// Test_dockerAccessTokenAnchor holds it to standing at this index in every
	// prefix.
	dockerAccessTokenAnchor      = 'k'
	dockerAccessTokenAnchorIndex = 2

	// dockerAccessTokenPersonalBodyChars is the count a personal access token's
	// body is written to, read exactly, and dockerAccessTokenPersonalChars is
	// that with the prefix in front. Docker states no length, so the count is
	// read off the rules the published rulesets state, which agree on it —
	// twenty-seven base64url characters, which is the width twenty bytes encode
	// to, and thirty-six with the prefix in front.
	// Test_dockerAccessTokenPersonalChars holds the arithmetic to both.
	dockerAccessTokenPersonalBodyChars = 27
	dockerAccessTokenPersonalChars     = len(dockerAccessTokenPersonalPrefix) + dockerAccessTokenPersonalBodyChars

	// dockerAccessTokenOrganizationBodyChars is the count an organization access
	// token's body is held to, read as a floor rather than exactly. The
	// rationale above weighs the two widths claimed for this kind and why the
	// lower of them is read as a bound.
	dockerAccessTokenOrganizationBodyChars = 27
)

// dockerAccessTokenPrefixes is what a candidate opens with: the prefix constants
// the scan itself compares against, named here so that the tail and a Masker's
// filter are built from the same two declarations the scan reads.
//
// Spelling a prefix out a second time here is what this avoids, since a spelling
// that came to disagree with the scan's would leave a stream releasing the
// characters a token opens with and redacting nothing.
var dockerAccessTokenPrefixes = []string{
	dockerAccessTokenPersonalPrefix,
	dockerAccessTokenOrganizationPrefix,
}

// isDockerAccessTokenPersonalBody reports whether s is the body of a personal
// access token: exactly dockerAccessTokenPersonalBodyChars characters, all of
// them in the alphabet a body is written in.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count being left to the caller to have cut
// correctly.
func isDockerAccessTokenPersonalBody(s string) bool {
	if len(s) != dockerAccessTokenPersonalBodyChars {
		return false
	}
	for i := range len(s) {
		if !isBase64URLByte(s[i]) {
			return false
		}
	}
	return true
}

// dockerAccessTokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var dockerAccessTokenTail = newPrefixTail(dockerAccessTokenPrefixes...)
