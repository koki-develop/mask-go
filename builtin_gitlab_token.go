package mask

import "strings"

// GitLabToken locates GitLab credentials that carry a token prefix: personal,
// project, group and impersonation access tokens (glpat-), OAuth application
// secrets (gloas-), deploy tokens (gldt-), runner authentication tokens (glrt-
// and glrtr-), CI/CD job tokens (glcbt-), pipeline trigger tokens (glptt-),
// feed tokens (glft-), incoming mail tokens (glimt-), agent tokens for
// Kubernetes (glagent-), SCIM OAuth tokens (glsoat-) and feature flags client
// tokens (glffct-).
//
// Both shapes a body is written in are read. The classic one is the count of
// base64url characters that kind of token has carried since GitLab gave it a
// prefix, and the count differs by kind. The routable one is what GitLab.com is
// moving to for Cells: a longer payload carrying the routing information,
// closed by a dot, the length of that payload and a checksum.
//
// The workspace token (glwt-) is left alone, and so are the runner registration
// token GitLab removed in 18.0 and the session cookie, which is named by the
// text in front of it rather than by a prefix of its own.
//
// Its name is "gitlab-token".
func GitLabToken() Pattern { return gitLabToken }

// What GitLab states and what GitLab publishes are worth separating here, as
// they were for Slack, because the prose documentation gives only half of the
// grammar below.
//
// What the documentation states is the prefix, in one table of them: glpat- for
// a personal access token and for the project, group and impersonation tokens
// written the same way, gloas- for an OAuth application secret, gldt- for a
// deploy token, glrt- for a runner authentication token — "glrt- or glrtr- if
// created via registration token" — glcbt- for a CI/CD job token, glptt- for a
// pipeline trigger token, glft- for a feed token, glimt- for an incoming mail
// token, glagent- for an agent token, glsoat- for a SCIM OAuth token, glffct-
// for a feature flags client token, and glwt- for a workspace token. That page
// gives no length, no alphabet and no checksum for any of them.
//
// What GitLab publishes beyond the prose is a detection ruleset of its own:
// rules/mit/gitlab.toml in the secret-detection-rules project, which is what
// GitLab's own secret detection and secret push protection run. It gives a
// regular expression a kind, and that is where every count below comes from —
// twenty characters behind glpat-, gldt-, glrt-, glft-, glsoat-, glffct- and
// the underscore of a glcbt-, twenty-five behind glimt-, forty behind glptt-,
// fifty behind glagent- and sixty-four behind gloas-; glrtr- takes glrt-'s, for
// the reason given further down. It is GitLab's own statement of the shape
// rather than a third party's reading of issued tokens, which is what makes it
// something to key on; the counts are nonetheless a ruleset's and not a
// specification's, and what that wagers is set out below.
//
// The alphabet is the base64url one, isBase64URLByte in builtin_scan.go: the
// letters of both cases, the digits, the hyphen and the underscore. That is
// what every one of those expressions admits behind its prefix, and it is what
// Devise.friendly_token, which GitLab generates a classic body with, emits. The
// pipeline trigger token is narrower still — forty hexadecimal characters — and
// is read in the wider alphabet anyway: nothing a reader can read is admitted
// by the difference, and a scan keyed on the narrower one would lose the token
// the day GitLab widens it.
//
// The counts are exact rather than floors, for the reason the AWS scan beside
// this one gives: a run of the alphabet longer than the count is not one longer
// token but a token with something written after it, and only the token is
// redacted. glpat-0123456789abcdefghijklmn leaves klmn in the output, and those
// four characters are part of no credential if the twenty in front of them are
// a token. The alternative, running the alphabet out, would redact every
// character of the run — and the run alphabet holds the hyphen and the
// underscore, so it would swallow a hyphenated identifier written after a
// prefix whole.
//
// What the exactness wagers is a body longer than the ruleset says, which would
// then be left in the output in part. That is not a small thing where the
// remainder is itself secret, and it is why the routable shape below is read
// for every prefix rather than only where GitLab has already shipped it.
//
// The routable shape is the second body, and it is a format GitLab documents
// rather than a count anyone observed. Its design document writes it as
// <prefix><base64-payload>.<base64-payload-length><crc32>, and
// Authn::TokenField::Generator::RoutableToken, which emits it, has since put a
// version between the payload and the rest, so that the two forms in the wild
// are
//
//	glpat-<payload>.<length><crc>
//	glpat-<payload>.<version>.<length><crc>
//
// The payload is the base64url encoding, without padding, of sixteen random
// bytes, the routing payload naming the cell and organization, and the size of
// that routing payload. The length is the size of the payload in base36, held
// in two characters; the version is two more; the checksum is the CRC32 of what
// precedes it, in seven. So what closes a routable token is a dot and nine
// characters of lowercase base36, or a dot, two of them, a dot and nine.
//
// Neither the length nor the checksum is verified, and that is a decision
// rather than an omission. Both are readable — the length of the payload in
// GitLab's own published example is twenty-seven characters and the two behind
// its dot are 0r, which is twenty-seven in base36 — so a scan could check them
// and would then be as good as exact. What it would also be is keyed on
// arithmetic GitLab has already revised once: the version segment above was
// added to this format after it shipped, and a scan verifying the fields around
// it would have gone on finding nothing while GitLab issued tokens in the new
// shape. A wrong checksum costs a credential; a wrong shape costs the end of a
// hostname. The scan takes the second.
//
// The floor on the payload is gitLabTokenPayloadChars, which is what the
// shortest routable token can be: sixteen random bytes, the size byte and the
// shortest routing payload come to twenty bytes, and twenty bytes are
// twenty-seven base64url characters unpadded. It is also the floor GitLab's own
// routable expression states. There is no ceiling. GitLab's expression stops at
// three hundred characters and the generator caps the routing payload, but a
// ceiling here would buy nothing — what it would exclude is a longer opaque run
// closed by a checksum, which is no more readable than a shorter one — and it
// would cost the whole token the day the payload grows, which is the direction
// this format was built to grow in.
//
// The routable shape is read behind every prefix, and not only behind the three
// GitLab has converted. The Cells design document names the personal access
// token, the CI/CD job token and the runner authentication token as the ones
// made routable first, which says the rest are to follow; keying on today's
// three would mean that the day a routable deploy token is issued, the scan
// redacts the first twenty characters of a payload of hundreds and leaves the
// rest of a live credential in the output. Admitting the shape everywhere costs
// the opposite and much less: where a classic token is followed by a dot and
// nine or twelve characters of lowercase base36, the redaction reaches over
// them too. A hostname is the way that happens — glagent-<fifty
// characters>.production.example.com loses the first nine characters of
// production, because a label of nine lowercase characters is what a checksum
// looks like. The tables in builtin_gitlab_token_test.go pin it.
//
// The two shapes cannot be confused with one another. A classic body carries no
// dot, so the routable alternative never fires on one, and a payload short of
// the floor falls through to the classic reading rather than failing outright:
// glpat- followed by twenty characters, a dot and nine is a classic token, and
// the dot and what follows it stay in the text.
//
// The CI/CD job token is the one kind whose classic body is written with
// something in front of it. GitLab prefixed the token with glcbt- in front of a
// partition id it already carried, so the body is that id — up to
// gitLabTokenPartitionChars alphanumerics — an underscore, and then the twenty
// characters. It needs no separate treatment in the routable shape: the id and
// its underscore are base64url characters, so they are simply the opening of
// the payload, which is also what makes the t1_ of a routable runner token part
// of its payload rather than part of its prefix.
//
// There is no boundary on either side of a match, as there is none in the AWS
// scan and unlike the Slack one. A boundary in front would drop rather than
// trim a token written against a letter or a digit, and the reason Slack needs
// one does not arise here: that scan guards against xapp closing linuxapp, and
// no prefix here can close a word — each is gl, a few letters naming the kind
// and a hyphen, and none of the twelve is a word or the ending of one. A
// boundary behind the match would drop a token followed by a word character,
// which is what the counts already handle by leaving the tail in the text.
//
// What this pattern over-matches on, which the gate in CLAUDE.md asks to be
// weighed rather than assumed: the run behind a prefix admits the hyphen and
// the underscore, so a hyphenated identifier written straight after one of
// these prefixes reaches the count.
// glagent-config-map-0123456789abcdef-production-tokyo-01234 carries fifty
// characters behind glagent- and is redacted whole. What makes that admissible
// is that the grammar is already the ruleset GitLab publishes and there is no
// tightening on offer that does not cost real tokens: asking a body for a digit
// would tell most such text apart and would also drop the one real token in
// eighty thousand whose fifty characters happen to be all letters, and asking
// it to hold no hyphen would drop far more than that. What reaches a span is
// never prose as a reader writes it — a space, a dot or a comma ends the run,
// so the text has to be an unbroken identifier of the exact length before the
// question arises — and unlike the bare forty hex characters the gate names, it
// cannot be a git SHA or an MD5, because the prefix is not something either of
// those carries.
//
// Three kinds of credential are left out, and each for a reason of its own.
// glwt- names the workspace token, which GitLab introduced in 18.2 and whose
// shape it publishes nowhere: no length in the documentation and no rule in the
// ruleset, so a pattern for it would be keyed on a guess, which is where the
// AWS scan leaves ABIA and ACCA. The runner registration token is the GR1348941
// literal rather than a gl prefix, and GitLab removed registration tokens in
// 18.0; reading it would mean searching the input for a second opening byte for
// the sake of a credential GitLab no longer issues. The session cookie is a
// value named by the _gitlab_session= written in front of it rather than by any
// prefix of its own, and this library does not read the text beside a value. A
// caller who needs one of the three redacted has to say so with a pattern of
// their own.
//
// glrtr- is admitted where those three are not, and the difference is that it
// is not a fourth kind: GitLab's table gives glrt- and glrtr- in one row, as
// the two prefixes of the runner authentication token, so the body behind it is
// that token's body rather than a shape nobody has stated.
//
// referenceGitLabToken in builtin_gitlab_token_test.go keeps the grammar as a
// regular expression, spelling the prefixes, the counts, the alphabets and the
// two routable forms again so that the two are changed together, and the fuzz
// target beside it holds this scan to that expression.
var gitLabToken = NewPattern("gitlab-token", func(src string) []Span {
	var spans []Span

	// The run a body is read as is worked out once and remembered. The alphabet
	// holds every letter a prefix is written in, so a prefix can be written
	// inside a body and a run can hold a candidate for every five characters it
	// has — glrt-glrt-glrt- is one run, not three — and each of them would
	// otherwise read that same run to its end, which costs time quadratic in
	// the length of such a line.
	//
	// One cursor serves every candidate in the run because a candidate's body
	// never begins in front of the body of the one before it, which
	// Test_gitLabTokenKinds_bodyNeverMovesBack holds the table to.
	runEnd := -1

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], gitLabTokenFirstByte)
		if i < 0 {
			break
		}
		start := offset + i

		// The scan resumes here whether this candidate became a token or not.
		// The body alphabet holds the letters the prefixes are written in, so a
		// token can begin inside the span of the one before it, as the one
		// twenty-two characters into
		// glpat-0123456789abcdefglpat-0123456789abcdefghij does, and consuming
		// a match would step over that token and leave it in the output whole.
		// The two spans then overlap, which a Masker resolves into one.
		offset = start + 1

		// The byte test comes before the prefix table because it is one
		// comparison where that is up to twelve, and every g in a word reaches
		// this line. Searching for the two bytes together with strings.Index is
		// the shorter way to write the same thing and is slower by about a
		// fifteenth on a log line, measured: what the second byte rules out is
		// cheaper to rule out here than inside a search for a two byte needle.
		if start+1 >= len(src) || src[start+1] != gitLabTokenSecondByte {
			continue
		}
		kind := gitLabTokenKindAt(src, start)
		if kind == nil {
			continue
		}

		body := start + len(kind.prefix)
		if body >= runEnd {
			runEnd = base64URLRunEnd(src, body)
		}

		// The routable shape is tried first, and has to be: its payload is a
		// run of the same alphabet a classic body is written in, so a classic
		// reading would take the first characters of a payload for a whole
		// token and leave the rest of one in the output. A candidate that is
		// not routable falls through rather than failing here.
		if end, ok := gitLabTokenRoutableEnd(src, body, runEnd); ok {
			spans = append(spans, Span{Start: start, End: end})
			continue
		}
		if end, ok := gitLabTokenClassicEnd(kind, src, body, runEnd); ok {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
})

// gitLabTokenKind is one kind of token: the prefix GitLab writes it with, the
// count of characters its classic body is written to, and whether a partition
// id stands in front of that body.
type gitLabTokenKind struct {
	prefix    string
	bodyChars int
	partition bool
}

// gitLabTokenKinds are the kinds this pattern reads, in the order the scan
// tries them.
//
// The order is a courtesy rather than a rule: no two of these match at the same
// position, because each carries a character that tells its kind apart from
// every other at a position both of them have — glrt- and glrtr- differ at the
// fifth, glpat- and glptt- at the fourth, glft- and glffct- at the fourth.
// Test_gitLabTokenKinds holds them to that, and to opening with the two bytes a
// candidate is found by, closing with a hyphen, and naming a body long enough
// to be one.
//
// The rationale above says where each count comes from and which kinds are left
// out. A kind added here is a kind AllBuiltinPatterns redacts with, so it wants
// the same weighing as the ones already in the list.
var gitLabTokenKinds = [...]gitLabTokenKind{
	{prefix: "glpat-", bodyChars: 20},   // personal, project, group and impersonation access tokens
	{prefix: "gldt-", bodyChars: 20},    // deploy tokens
	{prefix: "glrt-", bodyChars: 20},    // runner authentication tokens
	{prefix: "glrtr-", bodyChars: 20},   // runner authentication tokens created through a registration token
	{prefix: "glft-", bodyChars: 20},    // feed tokens
	{prefix: "glsoat-", bodyChars: 20},  // SCIM OAuth tokens
	{prefix: "glffct-", bodyChars: 20},  // feature flags client tokens
	{prefix: "glimt-", bodyChars: 25},   // incoming mail tokens
	{prefix: "glptt-", bodyChars: 40},   // pipeline trigger tokens
	{prefix: "glagent-", bodyChars: 50}, // agent tokens for Kubernetes
	{prefix: "gloas-", bodyChars: 64},   // OAuth application secrets

	// The one kind whose classic body carries a partition id in front of it.
	{prefix: "glcbt-", bodyChars: 20, partition: true}, // CI/CD job tokens
}

const (
	// The two bytes every prefix opens with. The scan searches the input for
	// the first and tests the second before it reaches the table at all.
	gitLabTokenFirstByte  = 'g'
	gitLabTokenSecondByte = 'l'

	// gitLabTokenPartitionSeparator divides the partition id of a CI/CD job
	// token from the body behind it, and gitLabTokenPartitionChars is the most
	// characters that id is written in. The id is the partition the job belongs
	// to, rendered in hexadecimal, and GitLab's own expression admits one to
	// five characters of it.
	gitLabTokenPartitionSeparator = '_'
	gitLabTokenPartitionChars     = 5

	// gitLabTokenTailSeparator divides the payload of a routable token from
	// what closes it, and the version from the length where a token carries
	// one. It is the one character a body is written in that the base64url
	// alphabet does not hold, which is what lets a payload be read as far as
	// that alphabet runs and still end where the tail begins.
	gitLabTokenTailSeparator = '.'

	// gitLabTokenPayloadChars is the fewest characters a routable payload is
	// written in: sixteen random bytes, the byte holding the size of the
	// routing payload and the shortest routing payload come to twenty bytes,
	// which are twenty-seven base64url characters written without padding. It
	// is the floor GitLab's own routable expression states as well. There is no
	// ceiling, for the reason the rationale above gives.
	gitLabTokenPayloadChars = 27

	// The counts the fields closing a routable token are written to, all of
	// them in lowercase base36. The version is what GitLab added to the format
	// after it shipped and is absent from the tokens issued before that; the
	// length is the size of the payload; the checksum is a CRC32 of what stands
	// in front of it. Neither the length nor the checksum is read as a number,
	// which the rationale above weighs.
	gitLabTokenVersionChars  = 2
	gitLabTokenLengthChars   = 2
	gitLabTokenChecksumChars = 7
	gitLabTokenTailChars     = gitLabTokenLengthChars + gitLabTokenChecksumChars
)

// gitLabTokenKindAt returns the kind whose prefix begins at i in src, or nil
// where none does.
func gitLabTokenKindAt(src string, i int) *gitLabTokenKind {
	for k := range gitLabTokenKinds {
		if strings.HasPrefix(src[i:], gitLabTokenKinds[k].prefix) {
			return &gitLabTokenKinds[k]
		}
	}
	return nil
}

// gitLabTokenRoutableEnd returns where the routable token whose payload begins
// at body in src ends, and whether one is written there. runEnd is where the
// run of payload characters beginning at body ends, which the scan has already
// read.
//
// A routable token is the payload, a separator, the length and checksum closing
// it, and — in the form GitLab writes today — a version between the two, itself
// closed by a separator. The two forms are told apart by the separator standing
// three characters behind the payload, which is a position the version form has
// and the other cannot: the characters of a length are base36 and a separator
// is not, so neither form can be read as the other.
func gitLabTokenRoutableEnd(src string, body, runEnd int) (int, bool) {
	if runEnd-body < gitLabTokenPayloadChars ||
		runEnd == len(src) || src[runEnd] != gitLabTokenTailSeparator {
		return 0, false
	}

	tail := runEnd + 1
	if tail+gitLabTokenVersionChars < len(src) && src[tail+gitLabTokenVersionChars] == gitLabTokenTailSeparator {
		for i := tail; i < tail+gitLabTokenVersionChars; i++ {
			if !isGitLabTokenTailByte(src[i]) {
				return 0, false
			}
		}
		tail += gitLabTokenVersionChars + 1
	}

	end := tail + gitLabTokenTailChars
	if end > len(src) {
		return 0, false
	}
	for i := tail; i < end; i++ {
		if !isGitLabTokenTailByte(src[i]) {
			return 0, false
		}
	}
	return end, true
}

// gitLabTokenClassicEnd returns where the classic token of kind k whose body
// begins at body in src ends, and whether one is written there. runEnd is where
// the run of body characters ends, which the scan has already read.
//
// The count is exact, so a run longer than the body is a token and what is
// written after it. What the run has to be is long enough; where it ends says
// nothing about where the token does.
func gitLabTokenClassicEnd(k *gitLabTokenKind, src string, body, runEnd int) (int, bool) {
	if k.partition {
		i := body
		for i < runEnd && i-body < gitLabTokenPartitionChars && isGitLabTokenPartitionByte(src[i]) {
			i++
		}
		// The separator is a body character, so it stands inside the run
		// wherever it stands at all, and reaching the end of the run is
		// reaching text that holds no partition id.
		if i == body || i == runEnd || src[i] != gitLabTokenPartitionSeparator {
			return 0, false
		}
		body = i + 1
	}

	if runEnd-body < k.bodyChars {
		return 0, false
	}
	return body + k.bodyChars, true
}

// isGitLabTokenPartitionByte reports whether c may appear in the partition id
// of a CI/CD job token: a letter of either case or a digit. The id itself is
// written in hexadecimal, and the wider class is what GitLab's own expression
// admits — nothing a reader can read is drawn in by the difference, and a scan
// keyed on hexadecimal alone would lose the token the day an id is rendered any
// other way.
func isGitLabTokenPartitionByte(c byte) bool {
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
}

// isGitLabTokenTailByte reports whether c may appear in the version, the length
// or the checksum closing a routable token: lowercase base36, which is what
// Ruby's Integer#to_s(36) writes those three fields with. Uppercase is not
// admitted, and admitting it would mean a payload followed by a dot and nine
// capitals — the opening of a sentence in an ALL CAPS log line among them —
// being read as a token.
func isGitLabTokenTailByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'z'
}
