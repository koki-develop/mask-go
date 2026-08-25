package mask

import "strings"

// GitHubToken locates GitHub credentials that carry a token prefix: personal
// access tokens (ghp_, github_pat_), OAuth app access tokens (gho_), GitHub App
// user and installation access tokens (ghu_, ghs_) and GitHub App refresh
// tokens (ghr_).
//
// GitHub documents the prefixes but no token length, and changed installation
// tokens in 2026 from 40 characters to a longer format holding a JWT. This
// pattern therefore keys on the prefix rather than on an exact length. That
// longer format is read for installation tokens, which carry it, and for user
// access tokens, whose format GitHub has said is to change without saying what
// to; the kinds that announcement leaves out are read for the classic form
// alone.
//
// Its name is "github-token".
func GitHubToken() Pattern { return githubToken }

// The prefix is what anchors these: a word boundary either side would drop the
// whole match, not merely trim it, where a token abuts a word character, and a
// token written as TOKEN_ghp_... would go unredacted. What may follow a token
// is held back by the character classes instead.
//
// The scan reads the same grammar a regular expression would, written out by
// hand because regexp costs three times what the byte tests below do on a line
// holding no token, and six times on a line of them. referenceGitHubTokenAt in
// builtin_github_token_test.go states that grammar again, spelled out at one
// position with none of the state below, and the fuzz target beside it holds
// the two to the same answer.
//
// Only the grammar is stated twice; how often it is tried is not. A value this
// scan locates may hold the start of the next one, so the grammar is tried at
// every byte rather than resumed past a match, which would step over the token
// inside it.
var githubToken = NewPattern("github-token", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := githubTokenTail.start(src)

	// The JWT a token in the stateless form holds ends where its run of
	// base64url characters and the segments after it end. Every candidate
	// crowded inside one run reaches the same end, and the positions asked
	// about only ever move forward, so the run is worked out once and
	// remembered. Working it out again at each candidate would cost time
	// quadratic in the length of a line of ghs_a_ey written over and over,
	// which nothing else here rules out: no candidate consumes what it read,
	// and the underscores such a line is built from are base64url characters.
	// The cursor is shared by every kind isGitHubStatelessKind admits, so
	// ghu_a_ey written over and over is the same input under another name.
	runEnd := -1
	var jwt segments
	// Whether the JWT walk stopped because the input did. It belongs to the
	// run the cursor above remembers rather than to a candidate, as the walk
	// itself does.
	var jwtOpen bool

	// The body of a fine grained token is read the same way, and needs a
	// cursor of its own because its alphabet holds the underscore: the prefix
	// can be written inside a body, so a run can hold a candidate for every
	// eleven characters it has, and each of them reads the run to its end.
	// The bodies of the other kinds admit no underscore and so cannot hold a
	// whole prefix, which leaves at most one candidate to a run and nothing
	// for a cursor to save.
	patRunEnd := -1

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], githubTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate becomes a token or
		// not: only the starting point is settled by what follows, never the
		// stretch of text it reaches over, and a token can begin anywhere
		// inside that stretch. Consuming a match would step over such a token
		// and leave it in the output whole — GitHub documents no length, so
		// the body is read as far as its alphabet runs and swallows the
		// prefix of a token written straight after it, ghp_ and gho_ with
		// nothing between them among them. The two spans then overlap, which
		// a Masker resolves into one. Stepping one byte past the anchor is
		// what leaves the next candidate of either form one byte past this
		// one, which builtin_scan.go sets out.
		offset = anchor + 1

		// The fine grained form first, whose prefix carries the anchor at
		// githubPATAnchorIndex. It is tried at a start of its own rather than
		// at the one below, because the two prefixes carry the h at different
		// depths; neither can match where the other does, since this one
		// spells an i where that one spells the h.
		if pat := anchor - githubPATAnchorIndex; pat >= 0 && src[pat] == githubPATPrefix[0] &&
			strings.HasPrefix(src[pat:], githubPATPrefix) {
			body := pat + len(githubPATPrefix)
			if body >= patRunEnd {
				patRunEnd = body
				for patRunEnd < len(src) && isGitHubPATByte(src[patRunEnd]) {
					patRunEnd++
				}
			}
			if patRunEnd == len(src) {
				// The run reaches the end of the input, so neither where the
				// token ends nor whether enough of it is here is settled.
				retain = min(retain, pat)
			}
			if patRunEnd-body >= githubPATChars {
				spans = append(spans, Span{Start: pat, End: patRunEnd})
			}
		}

		start := anchor - githubTokenAnchorIndex
		if start < 0 {
			continue
		}

		// The bound comes next and on its own, so that the byte tests behind
		// it may be read and reordered as byte tests rather than as an
		// argument about which of them runs first.
		body := start + githubTokenPrefixChars
		if body > len(src) {
			continue
		}

		kind := start + len(githubTokenOpening)
		if src[start] != githubTokenOpening[0] ||
			!isGitHubTokenKind(src[kind]) ||
			src[kind+1] != githubTokenSeparator {
			continue
		}

		// Both of the alternatives left read the same run, so it is scanned
		// once. No cursor is kept over it, and none is needed: a candidate
		// asks for an underscore four characters in and base62 holds none, so
		// the underscore of the next candidate can be no earlier than the
		// byte that ends this run, and the run that candidate reads therefore
		// begins past this one. Successive candidates read runs that do not
		// overlap, and reading all of them comes to the length of the input.
		end := base62RunEnd(src, body)

		// The stateless form comes first, as it does in the reference: an
		// app id of thirty-six characters or more would otherwise be taken
		// for a whole classic token, leaving the rest of the token to the JWT
		// pattern and the underscore between them unredacted. Which kinds
		// reach this alternative at all is isGitHubStatelessKind's to say.
		// Its JWT is anchored on what opens a JOSE header, which
		// opensJOSEHeaderAt in builtin_jwt.go states, and without which an
		// underscore and two dots written after a classic token, as in a file
		// name, would be drawn in before the classic alternative is reached.
		//
		// That anchor is the whole of what is read of the JWT. It asks the
		// header for the brace a JSON object opens with and the byte behind
		// it, and decodes nothing past them: GitHub signs this JWT with an
		// issuer of its own and says a client neither can nor should validate
		// it, so a run that opens a header and carries the segments is
		// redacted whether or not it decodes to one. Reading it for alg would
		// cost the token itself the day GitHub writes a header this pattern
		// does not recognise.
		//
		// The shape the anchor asks for is not free. The whitespace JSON
		// allows behind the brace beside the space — a tab, a carriage return
		// and a newline — leaves a header that does not open with ey at all,
		// so a stateless token carrying one is not located: not shortened,
		// not partly redacted, left whole. It is the header the JWT pattern
		// declines as well, for the same reason. Asking for less is worse
		// rather than better: an anchor reading the ey alone draws a file
		// name written after an app id into a token wherever the name opens
		// with those letters.
		//
		// A token clipped before its second dot, as a log line cut to a column
		// limit leaves one, is not located either: what authenticates a
		// stateless token is its signature, and a token cut that early carries
		// none of it. One surviving signature character is already enough to
		// have the whole token located. Reaching that remnant would mean
		// keying on the prefix and a run of characters, as GitHub's own advice
		// does, and admitting the dot into that run draws in the file name
		// written after a classic token, which the anchor holds back.
		//
		// open, below, is whether the input stopped inside this candidate. The
		// body running to the end of it is one way; the JWT is the other, and
		// it has to be read before the question is settled, since a body
		// followed by an underscore and a header reaches further than the body
		// alone does.
		open := end == len(src)
		if isGitHubStatelessKind(src[kind]) && end > body && end < len(src) && src[end] == '_' {
			opens, headerOpen := opensJOSEHeaderAt(src, end+1)
			open = open || headerOpen
			if opens {
				header := end + 1 + len(jwtHeaderPrefix)
				if header >= runEnd {
					runEnd = base64URLRunEnd(src, header)
					jwt, jwtOpen = segments{}, runEnd == len(src)
					// The run holds at least the character the anchor read, so
					// where it ends is where the header ends; only a dot there
					// begins the segments.
					if runEnd < len(src) && src[runEnd] == '.' {
						jwt, jwtOpen = githubJWTEnd(src, runEnd)
					}
				}
				open = open || jwtOpen
				if jwt.ok {
					if open {
						retain = min(retain, start)
					}
					spans = append(spans, Span{Start: start, End: jwt.end})
					continue
				}
			}
		}
		if open {
			retain = min(retain, start)
		}

		// Classic tokens, forty characters in all. The last six characters of
		// the body are a CRC32 checksum of the thirty before them, which this
		// does not verify: the alphabet and the length are the whole of what
		// is asked for, so thirty-six characters written after a prefix are
		// located whether or not GitHub could have issued them. Checking the
		// digits would rule out none of the revoked, example and test tokens
		// a caller wants redacted, and would cost the scan the token itself
		// the day GitHub changes how the checksum is computed.
		if end-body >= githubClassicChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// githubTokenPrefixes is what a candidate opens with: the literal a fine
// grained token opens with, and one entry per kind of the two-character
// opening the rest are written from.
//
// The kinds are read out of isGitHubTokenKind rather than written out again, so
// that a kind admitted there is a kind this knows about. A table of its own is
// one that can come to disagree with the test about which kinds there are, and
// what a stream would then do with the kind it had not been told about is
// release the characters a token opens with and redact nothing.
var githubTokenPrefixes = func() []string {
	prefixes := []string{githubPATPrefix}
	for c := range 256 {
		if isGitHubTokenKind(byte(c)) {
			prefixes = append(prefixes, githubTokenOpening+string(rune(c))+string(githubTokenSeparator))
		}
	}
	return prefixes
}()

// The literal a fine grained personal access token opens with, and the counts
// the two token bodies must reach. GitHub documents no length, so these are
// the shortest bodies seen rather than exact sizes.
const (
	githubPATPrefix    = "github_pat_"
	githubPATChars     = 82
	githubClassicChars = 36
)

const (
	// githubTokenOpening is what every prefix but the fine grained one opens
	// with. The character naming the kind and the separator stand behind it, so
	// such a prefix is githubTokenPrefixChars long whichever kind it names, and
	// the scan reads it by arithmetic rather than by comparing a string.
	githubTokenOpening = "gh"

	// githubTokenSeparator closes those prefixes and opens the body behind
	// them. It belongs to no classic body, which is what keeps two candidates
	// from ever reading the same run, and it belongs to a fine grained one,
	// which is why that form keeps a cursor of its own.
	githubTokenSeparator = '_'

	// githubTokenPrefixChars is the whole of such a prefix: the opening, the
	// one character naming the kind and the separator.
	githubTokenPrefixChars = len(githubTokenOpening) + 2
)

// githubTokenAnchor is the byte the scan searches the input for.
// githubTokenAnchorIndex is where it stands in the prefix of the classic and
// stateless forms, gh, a kind and an underscore; githubPATAnchorIndex is where
// it stands in githubPATPrefix. One search serves both forms because the h is
// the one byte they share at a fixed depth apiece, and a candidate of either
// begins its own number of bytes in front of what the search reported.
//
// builtin_scan.go says why a scan searches for one byte of its prefix rather
// than for the prefix itself. What makes it this byte is that the g every
// GitHub prefix opens with is also the g of log, message and login: over the
// line these benchmarks are written on it stands six times against the h's
// three. Neither of the lines crowded with candidates carries a second h to
// either prefix, so the rarer byte costs nothing there.
//
// The underscore each prefix closes with is rarer still on an ordinary line
// and is passed over: githubPATPrefix carries two of them, so a line of fine
// grained prefixes would open two candidates where the h opens one.
const (
	githubTokenAnchor      = 'h'
	githubTokenAnchorIndex = 1
	githubPATAnchorIndex   = 3
)

// isGitHubTokenKind reports whether c, the character after gh, names one of the
// token kinds: personal access (p), OAuth app (o), GitHub App user (u),
// installation (s) and refresh (r).
func isGitHubTokenKind(c byte) bool {
	return c == 'p' || c == 'o' || c == 'u' || c == 's' || c == 'r'
}

// isGitHubStatelessKind reports whether c, the character after gh, names a kind
// of token read for the form GitHub writes as a prefix, an app id and a JWT:
// installation (s), which moved to that form in 2026, and user (u), which has
// not.
//
// The user kind is admitted on what GitHub has said and no more, which is less
// than the shape. The changelog announcing the installation format scopes the
// rollout to installation tokens alone and says of the rest only that format
// changes for user-to-server tokens are planned — it names no shape for them,
// so admitting the kind is a wager that the next shape is the one already
// shipped beside it.
//
// What the wager costs is bounded, which is why it is taken. A body followed
// by an underscore and a run opening like a JOSE header is drawn into one
// span, so the file name in
// ghu_0123456789abcdefghijklmnopqrstuvwxyz_eyJson.min.js goes with the token
// beside it: the redaction reaches past the value and takes text that was
// never one. Against that stands a whole user access token left in the output
// the day such a format lands. The kinds that announcement leaves out
// altogether are read for the classic form alone, where the same cost would
// buy nothing.
//
// referenceGitHubTokenAt in builtin_github_token_test.go spells these kinds
// again, so the two are changed together or the fuzz target beside it reports
// them apart.
func isGitHubStatelessKind(c byte) bool { return c == 's' || c == 'u' }

// isGitHubPATByte reports whether c may appear in the body of a fine grained
// personal access token: the base62 alphabet a classic body is read in,
// isBase62Byte in builtin_scan.go, and the underscore this body carries between
// its two parts.
//
// That one extra character is why this body needs a cursor of its own where a
// classic body needs none. The prefix closes with an underscore, so a prefix
// can be written inside a body of this kind and a run can hold a candidate for
// every eleven characters it has; a classic body admits none, which leaves at
// most one candidate to such a run and nothing for a cursor to save.
func isGitHubPATByte(c byte) bool { return isBase62Byte(c) || c == '_' }

// githubJWTEnd returns where the two segments a signed token carries after its
// header end, and whether both are there. Unlike segmentsEnd in builtin_jwt.go,
// which serves the JWT pattern, a segment here must hold at least one
// character, so that the two dots of a file name written after a token do not
// stand in for them. referenceGitHubStatelessAt asks the same of a segment,
// which is what the fuzz target holds the two to.
//
// This and the scan above read opensJOSEHeaderAt, jwtHeaderPrefix and
// signedSegments from that file rather than spelling them again. A stateless
// installation token carries a JWT, so what this scan knows of one is the JWT
// pattern's to define; only where the two read it differently is written out
// here.
// It reports whether the walk ran to the end of the input as well, for the
// reason segmentsEnd does: an empty segment is an empty segment where a byte
// stands behind the dot, and the input running out where that byte belongs.
func githubJWTEnd(src string, dot int) (segments, bool) {
	i := dot
	for range signedSegments {
		if i == len(src) {
			return segments{}, true
		}
		if src[i] != '.' {
			return segments{}, false
		}
		i++
		start := i
		i = base64URLRunEnd(src, i)
		if i == start {
			return segments{}, i == len(src)
		}
	}
	return segments{end: i, ok: true}, i == len(src)
}

// githubTokenTail is what the scan settles the tail of its input by. prefixTail
// (builtin_scan.go) says what that is and why it is built once.
var githubTokenTail = newPrefixTail(githubTokenPrefixes...)
