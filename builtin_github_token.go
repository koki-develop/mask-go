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
var githubToken = NewPattern("github-token", func(src string) []Span {
	var spans []Span

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

	// The body of a fine grained token is read the same way, and needs a
	// cursor of its own because its alphabet holds the underscore: the prefix
	// can be written inside a body, so a run can hold a candidate for every
	// eleven characters it has, and each of them reads the run to its end.
	// The bodies of the other kinds admit no underscore and so cannot hold a
	// whole prefix, which leaves at most one candidate to a run and nothing
	// for a cursor to save.
	patRunEnd := -1

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], 'g')
		if i < 0 {
			break
		}
		start := offset + i

		// The scan resumes here whether this candidate becomes a token or
		// not: only the starting point is settled by what follows, never the
		// stretch of text it reaches over, and a token can begin anywhere
		// inside that stretch. Consuming a match would step over such a token
		// and leave it in the output whole — GitHub documents no length, so
		// the body is read as far as its alphabet runs and swallows the
		// prefix of a token written straight after it, ghp_ and gho_ with
		// nothing between them among them. The two spans then overlap, which
		// a Masker resolves into one.
		offset = start + 1

		if strings.HasPrefix(src[start:], githubPATPrefix) {
			body := start + len(githubPATPrefix)
			if body >= patRunEnd {
				patRunEnd = body
				for patRunEnd < len(src) && isGitHubPATByte(src[patRunEnd]) {
					patRunEnd++
				}
			}
			if patRunEnd-body < githubPATChars {
				continue
			}
			spans = append(spans, Span{Start: start, End: patRunEnd})
			continue
		}

		if start+4 > len(src) || src[start+1] != 'h' || !isGitHubTokenKind(src[start+2]) || src[start+3] != '_' {
			continue
		}

		// Both of the alternatives left read the same run, so it is scanned
		// once. No cursor is kept over it, and none is needed: a candidate
		// asks for an underscore four characters in and base62 holds none, so
		// the underscore of the next candidate can be no earlier than the
		// byte that ends this run, and the run that candidate reads therefore
		// begins past this one. Successive candidates read runs that do not
		// overlap, and reading all of them comes to the length of the input.
		body := start + 4
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
		if isGitHubStatelessKind(src[start+2]) && end > body && end < len(src) &&
			src[end] == '_' && opensJOSEHeaderAt(src, end+1) {
			header := end + 1 + len(jwtHeaderPrefix)
			if header >= runEnd {
				runEnd = base64URLRunEnd(src, header)
				jwt = segments{}
				// The run holds at least the character the anchor read, so
				// where it ends is where the header ends; only a dot there
				// begins the segments.
				if runEnd < len(src) && src[runEnd] == '.' {
					jwt = githubJWTEnd(src, runEnd)
				}
			}
			if jwt.ok {
				spans = append(spans, Span{Start: start, End: jwt.end})
				continue
			}
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
	return spans
})

// The literal a fine grained personal access token opens with, and the counts
// the two token bodies must reach. GitHub documents no length, so these are
// the shortest bodies seen rather than exact sizes.
const (
	githubPATPrefix    = "github_pat_"
	githubPATChars     = 82
	githubClassicChars = 36
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
func githubJWTEnd(src string, dot int) segments {
	i := dot
	for range signedSegments {
		if i == len(src) || src[i] != '.' {
			return segments{}
		}
		i++
		start := i
		i = base64URLRunEnd(src, i)
		if i == start {
			return segments{}
		}
	}
	return segments{end: i, ok: true}
}
