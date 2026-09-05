package mask

import "strings"

// DockerPersonalAccessToken locates Docker personal access tokens: the prefix
// dckr_pat_ and twenty-seven base64url characters behind it — thirty-six
// characters altogether.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly thirty-six characters of it are. So text of that shape is
// redacted whether or not Docker issued it. A space, a dot, a character outside
// the alphabet or an uppercase prefix ends the reading, so text as it is
// ordinarily written is not affected. A longer run of the alphabet is a token
// with something written after it, and the token alone is redacted.
//
// Its name is "docker-personal-access-token".
func DockerPersonalAccessToken() Pattern { return dockerPersonalAccessToken }

// Personal access token is Docker's own term for the whole of what this
// locates: the page a user creates one on is titled that, and the reference for
// the endpoint such a token is exchanged at names it that way in the table of
// credentials that endpoint accepts.
//
// What Docker states about the string is the prefix, and three of its own pages
// state it. The credential table above writes the format of a personal access
// token as dckr_pat_*, beside the organization access token's dckr_oat_ and the
// account password neither of them is; the Hub API reference gives the secret
// field of that same endpoint an example opening with dckr_pat_; and the Scout
// metrics exporter page writes dckr_pat_... into the file Prometheus is pointed
// at for a bearer credential. None of them states a length, an alphabet or a
// checksum, and none prints a personal access token in full — the example
// beside the secret field carries fifteen characters where a body is
// twenty-seven.
//
// So the count and the alphabet are read off the rules the published rulesets
// state, which is a weaker footing than a vendor's own validator. Five rulesets
// read this format and none of them disputes either part: trufflehog,
// noseyparker, kingfisher, projectdiscovery's nuclei templates and Google's
// osv-scalibr each ask for the prefix and twenty-seven characters of the
// letters of both cases, the digits, the hyphen and the underscore. Behind the
// organization prefix, the one Docker's API reference prints is twenty-seven
// characters as well.
//
// Twenty-seven is a width that says something about itself, which is what makes
// it readable as a count rather than as wherever a run happened to stop. A
// base64url encoding with no padding is one character to every six bits, so
// twenty bytes come to twenty-seven characters and no other whole number of
// bytes does: nineteen give twenty-six and twenty-one give twenty-eight. The
// body is the width of a fixed twenty byte value, which is a size a token is
// minted at rather than a length it grew to.
//
// The count is read exactly rather than as a floor. A run of the alphabet
// longer than the count is not one longer token but a token with something
// written after it, and a floor would swallow what the run went on to hold,
// which is text belonging to no credential.
//
// The alphabet is base64url, isBase64URLByte in builtin_scan.go, and there is
// no tightening available to decline: the encoding is the whole of what the
// body is, and every one of its sixty-four characters stands in one.
//
// The prefix is read in lowercase alone. kingfisher reads this format without
// regard to case, which locates DCKR_PAT_ with a lowercase body behind it; that
// is the shape an environment variable's name is written in rather than the
// shape a token is, and reading it would redact the name a caller keeps a log
// by.
//
// There is no boundary on either side of a match, and here that is a choice
// four of the five rulesets make the other way — trufflehog, noseyparker,
// kingfisher and the nuclei templates open on \b and close on a character
// outside the alphabet or the end of the input, where osv-scalibr asks for
// neither. What a boundary in front would buy is a candidate written straight
// against a word character, and the words of prose do not end in dckr. What it
// would cost is a token dropped whole rather than trimmed wherever it is
// written against one, and DOCKER_TOKEN_dckr_pat_... is how a token reaches a
// log line from a shell.
// Test_DockerPersonalAccessToken_nextToWordCharacters pins the shape that pays
// for it. Behind the match the same demand costs more again: those four locate
// nothing at all in a token written against a twenty-eighth character of the
// alphabet, where this scan redacts the thirty-six Docker issued and leaves the
// character that belongs to no credential in the text.
//
// The byte the scan searches the input for is the k, two characters into the
// prefix. builtin_scan.go says why a scan searches for one byte of its prefix
// rather than for the prefix itself, and here the choice is settled by prose
// rather than by a body: every character of the prefix stands in a base64url
// run one time in sixty-four, so a run opens the same number of candidates
// whichever byte is chosen, and what is left to separate them is how often each
// is written in ordinary text. The k is the rarest of the prefix's seven letters
// in English by a wide margin, standing in well under a hundredth of the
// letters where the a and the t stand in near a tenth apiece. The two
// underscores are rarer still in prose and are passed over all the same: an
// underscore is what an environment variable, a snake_case name and a log field
// are written with, so a scan anchored on one opens a candidate on a great deal
// of the text a caller is masking to reject it again. What the k costs is
// visible on the line these benchmarks are written on, where the vendor's own
// host name carries one.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a token or not, which is the default and needs no argument.
// It is load-bearing here rather than merely correct: every character of the
// prefix belongs to the alphabet a body is written in, so a token can begin
// inside the body of the one before it — the prefix written twice with
// twenty-seven characters behind the second is a token from either of them —
// and a scan consuming its match would step over the second and leave it in the
// output whole. The two spans overlap and a Masker resolves them into one.
// Test_DockerPersonalAccessToken_aTokenBeginningInsideAnother drives it.
//
// The scan keeps no cursor and needs none: a candidate reads at most thirty-six
// bytes and stops, which bounds what it reads with no state to be wrong about.
// That is what rules out a quadratic input here, and it is the only thing that
// could: a prefix written in its own body's alphabet gives a run no character
// to be divided at, so a scan reading a body to the end of its run would read
// the same run once for every candidate the run holds.
//
// What this pattern over-matches on: thirty-six characters of the right shape
// that nobody issued. Nine characters have to be written, two of them
// underscores, then exactly twenty-seven more of the alphabet with nothing
// between any of them. Prose holds no such run — a body is longer than any word
// and carries no space or punctuation — and standard base64, base32 and
// hexadecimal write no underscore at all, so an identifier, a certificate body
// or an embedded image carries no candidate at however long it runs. What is
// left is base64url, which writes every character of the prefix: there the nine
// stand about once in eighteen thousand million million characters, and the
// twenty-seven behind them are in the alphabet by construction. That is the
// collision this pattern pays for, and there is nothing in the text to tell
// such a run from a token — the vendor's format is that prefix and that many of
// those characters, with no part of it left over to fail.
// Test_DockerPersonalAccessToken_insideAnOpaqueRun pins it.
//
// Docker writes a second prefix that this scan does not read. The credential
// table names dckr_oat_ as the format of an organization access token, which
// authenticates the same registry for an organization rather than for a person,
// and what is missing is its width: the token Docker's API reference prints
// behind that prefix carries twenty-seven characters, where trufflehog and
// kingfisher, the two rulesets reading the format, both ask for thirty-two. A
// count taken from either side of that is a scan that locates no organization
// token at all, which is the failure nothing downstream reports — a pattern
// that fires on nothing looks exactly like a caller whose text held nothing. A
// width Docker states, or a token it prints in full, is a prefix and a number
// added here.
// Test_DockerPersonalAccessToken_theOrganizationTokenPrefix pins the decision so
// that reading it is a change somebody argues for.
//
// The shape Docker Hub's login endpoint took before a prefix was written in
// front of one is not read, and reading it is what this package exists not to
// do. trufflehog keeps two detectors for this vendor, and the older of them
// says what that shape is: a UUID with no prefix at all, found near the word
// docker and verified by logging in with it as a password. A pattern reading
// that would redact every request id, every trace id and every fixture a caller
// passes through, since a UUID carries nothing to be recognised by and the only
// net left is the word standing near it. It is the loose grammar this package
// declines rather than the unlucky one, and a token of that shape reaching a log
// stays in the output whole.
// Test_DockerPersonalAccessToken_theShapeItReplaced pins the decision so that
// reading it is a change somebody argues for.
//
// referenceDockerPersonalAccessToken in
// builtin_docker_personal_access_token_test.go keeps the grammar as a regular
// expression, spelling the prefix, the count and the character class again so
// that the two are changed together, and the fuzz target beside it holds this
// scan to that expression. An expression is affordable here: the repetition is
// exact, so the machine an engine builds is read once and stops, and the nine
// character literal in front of it is what an engine searches the text for.
var dockerPersonalAccessToken = newBuiltin("docker-personal-access-token", &dockerPersonalAccessTokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two.
	retain := dockerPersonalAccessTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], dockerPersonalAccessTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not, for the
		// reason the rationale above gives: the prefix is written in the alphabet a
		// body is, so a token can begin inside the body of the one before it.
		offset = anchor + 1

		if anchor < dockerPersonalAccessTokenAnchorIndex {
			continue
		}
		start := anchor - dockerPersonalAccessTokenAnchorIndex

		// The byte the prefix opens with is tested before the prefix is
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != dockerPersonalAccessTokenPrefix[0] ||
			!strings.HasPrefix(src[start:], dockerPersonalAccessTokenPrefix) {
			continue
		}

		body := start + len(dockerPersonalAccessTokenPrefix)
		end := start + dockerPersonalAccessTokenChars
		if end > len(src) {
			// The input ends inside the body, and the count is the whole of
			// what tells a token from any other run written behind the prefix.
			retain = min(retain, start)
			continue
		}
		if isDockerPersonalAccessTokenBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// dockerPersonalAccessTokenPrefix is what Docker writes a personal access
	// token with, and what the scan reads back from the anchor. Every character
	// of it belongs to the alphabet a body is written in, which is what lets one
	// token be written inside another and is why the scan resumes a byte along;
	// Test_dockerPersonalAccessTokenPrefix holds it to that.
	dockerPersonalAccessTokenPrefix = "dckr_pat_"

	// dockerPersonalAccessTokenAnchor is the byte the scan searches the input
	// for and dockerPersonalAccessTokenAnchorIndex is where it stands in the
	// prefix, so a candidate begins that many bytes in front of what a search
	// reported. The rationale above says what made it this byte;
	// Test_dockerPersonalAccessTokenAnchor holds it to standing at this index.
	dockerPersonalAccessTokenAnchor      = 'k'
	dockerPersonalAccessTokenAnchorIndex = 2

	// The counts a token is written to. Docker states no length of its own, so
	// these are read off the rules the published rulesets state, which agree on
	// them — twenty-seven base64url characters, which is the width twenty bytes
	// encode to, and thirty-six with the prefix in front.
	// Test_dockerPersonalAccessTokenChars holds the arithmetic to both.
	dockerPersonalAccessTokenBodyChars = 27
	dockerPersonalAccessTokenChars     = len(dockerPersonalAccessTokenPrefix) + dockerPersonalAccessTokenBodyChars
)

// isDockerPersonalAccessTokenBody reports whether s is the body of a token:
// exactly dockerPersonalAccessTokenBodyChars characters, all of them in the
// alphabet a body is written in.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count being left to the caller to have cut
// correctly.
func isDockerPersonalAccessTokenBody(s string) bool {
	if len(s) != dockerPersonalAccessTokenBodyChars {
		return false
	}
	for i := range len(s) {
		if !isBase64URLByte(s[i]) {
			return false
		}
	}
	return true
}

// dockerPersonalAccessTokenTail is what the scan settles the tail of its input
// by. prefixTail (builtin_scan.go) says what that is and why it is built once.
var dockerPersonalAccessTokenTail = newPrefixTail(dockerPersonalAccessTokenPrefix)
