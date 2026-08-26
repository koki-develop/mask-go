package mask

import (
	"slices"
	"strings"
)

// GitLabToken locates GitLab credentials that carry a token prefix: personal,
// project, group and impersonation access tokens (glpat-), OAuth application
// secrets (gloas-), deploy tokens (gldt-), runner authentication tokens (glrt-
// and glrtr-), CI/CD job tokens (glcbt-), pipeline trigger tokens (glptt-),
// feed tokens (glft-), incoming mail tokens (glimt-), agent tokens for
// Kubernetes (glagent-), SCIM OAuth tokens (glsoat-) and feature flags client
// tokens (glffct-).
//
// Both shapes a body is written in are read. The classic one is a count of
// base64url characters that kind of token has carried since GitLab gave it a
// prefix; the count differs by kind, and a pipeline trigger token is written to
// either of two. The routable one is what GitLab.com is moving to for Cells: a
// longer payload carrying the routing information, closed by a dot, the length
// of that payload and a checksum.
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
// rules/mit/gitlab/gitlab.toml in the secret-detection-rules project, which is
// what GitLab's own secret detection and secret push protection run. It gives a
// regular expression a kind, and that is where the counts below come from —
// twenty characters behind glpat-, gldt-, glrt-, glft-, glsoat- and the
// underscore of a glcbt-, twenty-five behind glimt-, fifty behind glagent- and
// sixty-four behind gloas-; glrtr- takes glrt-'s, for the reason given further
// down. It is GitLab's own statement of the shape rather than a third party's
// reading of issued tokens, which is what makes it something to key on; the
// counts are nonetheless a ruleset's and not a specification's, and what that
// wagers is the exactness weighed below.
//
// A pipeline trigger token is the one kind that ruleset writes two counts for,
// twenty characters behind glptt- or forty, and both are read. Reading only the
// forty would leave a token written to the shorter of the two in the output
// whole, which is the direction that costs a reader something rather than the
// direction that costs them a tail.
//
// One kind is not in that ruleset at all. GitLab's prefix table names glffct-
// for a feature flags client token, and no rule of GitLab's own states what
// stands behind it, so the twenty characters read here are gitleaks' — a third
// party's reading of issued tokens, which is the source the paragraph above
// prefers not to key on. It is kept, because the prefix is GitLab's own and a
// body of twenty is what every other kind written to a single count is written
// to. It is named here rather than left to look like the rest: the one count
// nobody can check against GitLab should be the one a reader can find.
//
// The alphabet is the base64url one, isBase64URLByte in builtin_scan.go: the
// letters of both cases, the digits, the hyphen and the underscore. That is
// what every one of those expressions admits behind its prefix, and it is what
// Devise.friendly_token, which GitLab generates a classic body with, emits.
// gitleaks reads a pipeline trigger token more narrowly than GitLab's own rule
// does, as forty hexadecimal characters, and the wider alphabet is read here
// anyway: nothing a reader can read is admitted by the difference, and a scan
// keyed on the narrower one would lose the token the day GitLab widens it —
// which GitLab's own rule, admitting the whole alphabet behind glptt-, has
// already done.
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
// Neither the length nor the checksum is verified. Both are readable — the
// length of the payload in GitLab's own published example is twenty-seven
// characters and the two behind its dot are 0r, which is twenty-seven in
// base36 — so a scan could check them and would then be as good as exact. What
// it would also be is keyed on arithmetic GitLab has already revised once: the
// version segment above was added to this format after it shipped, and a scan
// verifying the fields around it would have gone on finding nothing while
// GitLab issued tokens in the new shape. A wrong checksum costs a credential;
// a wrong shape costs the end of a hostname. The scan takes the second.
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
// What this pattern over-matches on: the run behind a prefix admits the hyphen
// and the underscore, so a hyphenated identifier written straight after one of
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
// question arises — and it cannot be a git SHA or an MD5, because the prefix is
// not something either of those carries.
//
// glrtr- takes glrt-'s count because it is not a kind of its own: GitLab's
// table gives glrt- and glrtr- in one row, as the two prefixes of the runner
// authentication token, so the body behind it is that token's body.
//
// referenceGitLabToken in builtin_gitlab_token_test.go keeps the grammar as a
// regular expression, spelling the prefixes, the counts, the alphabets and the
// two routable forms again so that the two are changed together, and the fuzz
// target beside it holds this scan to that expression.
var gitLabToken = NewPattern("gitlab-token", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := gitLabTokenTail.start(src)

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
		i := strings.IndexByte(src[offset:], gitLabTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not.
		// The body alphabet holds the letters the prefixes are written in, so a
		// token can begin inside the span of the one before it, as the one
		// twenty-two characters into
		// glpat-0123456789abcdefglpat-0123456789abcdefghij does, and consuming
		// a match would step over that token and leave it in the output whole.
		// The two spans then overlap, which a Masker resolves into one. Stepping one
		// byte past the anchor is what leaves the next candidate of every
		// length one byte past this one, which builtin_scan.go sets out.
		offset = anchor + 1

		kind := gitLabTokenKindEndingAt(src, anchor)
		if kind == nil {
			continue
		}
		start := anchor + 1 - len(kind.prefix)

		body := start + len(kind.prefix)
		if body >= runEnd {
			runEnd = base64URLRunEnd(src, body)
		}

		// The routable shape is tried first, and has to be: its payload is a
		// run of the same alphabet a classic body is written in, so a classic
		// reading would take the first characters of a payload for a whole
		// token and leave the rest of one in the output. A candidate that is
		// not routable falls through rather than failing here.
		end, ok, open := gitLabTokenRoutableEnd(src, body, runEnd)
		if open || runEnd == len(src) {
			// Either the payload run reaches the end of the input, so where
			// the body ends is still open, or the tail behind it is cut short
			// and what the routable form needs of it has not arrived. Which
			// form this is decides the whole span, so neither is settled.
			retain = min(retain, start)
		}
		if ok {
			spans = append(spans, Span{Start: start, End: end})
			continue
		}
		if end, ok := gitLabTokenClassicEnd(kind, src, body, runEnd); ok {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// gitLabTokenKind is one kind of token: the prefix GitLab writes it with, the
// counts of characters its classic body is written to, and whether a partition
// id stands in front of that body.
//
// bodyChars holds more than one count where the ruleset the rationale above
// reads states more than one, and is ordered longest first: the scan takes the
// first count the run reaches, so a run long enough for two is the longer
// token and what is written after it, never the shorter token and a tail left
// in the output. Test_gitLabTokenKinds holds the order.
type gitLabTokenKind struct {
	prefix    string
	bodyChars []int
	partition bool
}

// gitLabTokenTail is what the scan settles the tail of its input by. The
// prefixes are read out of gitLabTokenKinds rather than gathered into a table
// of their own, so that a kind added there is a kind this knows about, and
// prefixTail (builtin_scan.go) says what a tail is and why it is built once.
var gitLabTokenTail = func() prefixTail {
	prefixes := make([]string, 0, len(gitLabTokenKinds))
	for i := range gitLabTokenKinds {
		prefixes = append(prefixes, gitLabTokenKinds[i].prefix)
	}
	return newPrefixTail(prefixes...)
}()

// gitLabTokenKinds are the kinds this pattern reads, in the order the scan
// tries them.
//
// The order is a courtesy rather than a rule: no two of these match at the same
// position, because each carries a character that tells its kind apart from
// every other at a position both of them have — glrt- and glrtr- differ at the
// fifth, glpat- and glptt- at the fourth, glft- and glffct- at the fourth.
// Test_gitLabTokenKinds holds them to that, and to opening with the two bytes a
// candidate is read back to, closing with the hyphen a candidate is found by,
// and naming a body long enough to be one.
//
// The rationale above says where each count comes from.
var gitLabTokenKinds = [...]gitLabTokenKind{
	{prefix: "glpat-", bodyChars: []int{20}},     // personal, project, group and impersonation access tokens
	{prefix: "gldt-", bodyChars: []int{20}},      // deploy tokens
	{prefix: "glrt-", bodyChars: []int{20}},      // runner authentication tokens
	{prefix: "glrtr-", bodyChars: []int{20}},     // runner authentication tokens created through a registration token
	{prefix: "glft-", bodyChars: []int{20}},      // feed tokens
	{prefix: "glsoat-", bodyChars: []int{20}},    // SCIM OAuth tokens
	{prefix: "glffct-", bodyChars: []int{20}},    // feature flags client tokens
	{prefix: "glimt-", bodyChars: []int{25}},     // incoming mail tokens
	{prefix: "glptt-", bodyChars: []int{40, 20}}, // pipeline trigger tokens, the one kind written to two counts
	{prefix: "glagent-", bodyChars: []int{50}},   // agent tokens for Kubernetes
	{prefix: "gloas-", bodyChars: []int{64}},     // OAuth application secrets

	// The one kind whose classic body carries a partition id in front of it.
	{prefix: "glcbt-", bodyChars: []int{20}, partition: true}, // CI/CD job tokens
}

const (
	// gitLabTokenOpening is what every prefix opens with, and what a candidate
	// is read back to from the hyphen the scan searches for.
	// gitLabTokenKindEndingAt tests the byte it opens with before it compares a
	// prefix at all and leaves the rest of it to that comparison, but the whole
	// of it is load-bearing: a suffix of one of these prefixes would have to
	// carry the opening somewhere past its own start, and that is the argument
	// no two entries close at the same position rests on.
	//
	// The hyphen is the anchor rather than this, for the reason builtin_scan.go
	// gives. A g opens log, message and every word a GitLab path is made of —
	// over the line these benchmarks are written on it stands four times
	// against the hyphen's two — and text carrying the opening without the
	// hyphen behind it, which prose does wherever it spells a word with gl in
	// the middle, reaches the table at every g under that anchor and at nothing
	// under this one.
	gitLabTokenOpening = "gl"

	// gitLabTokenAnchor is the hyphen every prefix closes with and the byte the
	// scan searches the input for. It is the one character every entry of the
	// table shares at a position of its own, which is what lets one search find
	// all twelve; Test_gitLabTokenKinds holds them to closing on it.
	gitLabTokenAnchor = '-'

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

// gitLabTokenKindEndingAt returns the kind whose prefix closes at the anchor
// standing at i in src, or nil where none does.
//
// It reads backwards, where a prefix lookup ordinarily reads forwards, because
// what the scan searches for is the hyphen a prefix ends on rather than the
// letter it begins with. At most one entry can close at any position, so which
// one is found does not depend on the order the table is walked in: two
// entries closing together would mean the shorter were a suffix of the longer,
// and a suffix of one of these carries the gl it opens with somewhere past its
// own start, which none of them does.
//
// That is the suffix relation, and it is not the relation
// Test_gitLabTokenKinds holds the table to — that one rules out a prefix
// opening another, which is what a forward lookup needs. A table breaking the
// suffix relation would have the winner decided by the order
// gitLabTokenPrefixChars happens to hold the lengths in, silently and only for
// that pair. Slack's table is the worked example of one that does break it, and
// the scan there reports both candidates rather than choosing between them.
//
// The byte the opening begins with is tested before the prefix is compared,
// which is what makes the walk over the table cheap enough to do at every
// hyphen: a hyphen with no g standing four to seven characters in front of it
// is turned away by one byte an entry, where comparing twelve prefixes against
// the text would be twelve lengths and twelve reads. The l behind the g is
// left to the comparison rather than tested here — it would be a second read
// at every entry to rule out what the first read has already ruled out almost
// everywhere.
func gitLabTokenKindEndingAt(src string, i int) *gitLabTokenKind {
	for _, n := range gitLabTokenPrefixChars {
		start := i + 1 - n
		if start < 0 || src[start] != gitLabTokenOpening[0] {
			continue
		}
		for k := range gitLabTokenKinds {
			kind := &gitLabTokenKinds[k]
			if len(kind.prefix) == n && src[start:i+1] == kind.prefix {
				return kind
			}
		}
	}
	return nil
}

// gitLabTokenPrefixChars are the lengths the table holds, each of them once.
// The walk above reads it rather than the table itself so that entries sharing
// a length cost one read of the text between them: prefixes of a length are
// read back to the same byte, and asking each of them the same question about
// that byte is asking it over again for nothing.
//
// It is worked out from the table rather than written beside it, so that it
// cannot come to disagree with what the table holds — a length written down
// here and left behind by an entry added would be a kind no candidate is ever
// found at, and nothing would say so.
var gitLabTokenPrefixChars = func() []int {
	var chars []int
	for _, kind := range gitLabTokenKinds {
		if !slices.Contains(chars, len(kind.prefix)) {
			chars = append(chars, len(kind.prefix))
		}
	}
	return chars
}()

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
//
// It reports whether saying no was the end of the input speaking rather than
// the text: a tail the input cut short is one more text may complete, where a
// tail carrying a character no tail is written with is no tail whatever
// follows. A tail that is both — cut short, and already carrying such a
// character — is read as cut short. The scan does not read what is written of
// a candidate the end of the input took the rest of, and builtin_scan.go
// argues that trade rather than each scan arguing it again.
func gitLabTokenRoutableEnd(src string, body, runEnd int) (int, bool, bool) {
	if runEnd-body < gitLabTokenPayloadChars ||
		runEnd == len(src) || src[runEnd] != gitLabTokenTailSeparator {
		return 0, false, false
	}

	tail := runEnd + 1
	if tail+gitLabTokenVersionChars < len(src) && src[tail+gitLabTokenVersionChars] == gitLabTokenTailSeparator {
		for i := tail; i < tail+gitLabTokenVersionChars; i++ {
			if !isGitLabTokenTailByte(src[i]) {
				return 0, false, false
			}
		}
		tail += gitLabTokenVersionChars + 1
	}

	end := tail + gitLabTokenTailChars
	if end > len(src) {
		return 0, false, true
	}
	for i := tail; i < end; i++ {
		if !isGitLabTokenTailByte(src[i]) {
			return 0, false, false
		}
	}
	return end, true, false
}

// gitLabTokenClassicEnd returns where the classic token of kind k whose body
// begins at body in src ends, and whether one is written there. runEnd is where
// the run of body characters ends, which the scan has already read.
//
// A count is exact, so a run longer than the body is a token and what is
// written after it. What the run has to be is long enough; where it ends says
// nothing about where the token does. Where the kind names more than one count
// the longest the run reaches is the one read, which is what the order of
// bodyChars gives: reading the shorter first would end a pipeline trigger token
// twenty characters in and leave the other twenty in the output.
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

	for _, n := range k.bodyChars {
		if runEnd-body >= n {
			return body + n, true
		}
	}
	return 0, false
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
