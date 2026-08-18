package mask

import "strings"

// GitHubToken locates GitHub credentials that carry a token prefix: personal
// access tokens (ghp_, github_pat_), OAuth app access tokens (gho_), GitHub App
// user and installation access tokens (ghu_, ghs_) and GitHub App refresh
// tokens (ghr_).
//
// GitHub documents the prefixes but no token length, and changed installation
// tokens in 2026 from 40 characters to a longer format holding a JWT. This
// pattern therefore keys on the prefix rather than on an exact length.
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
// holding no token, and six times on a line of them. referenceGitHubToken in
// builtin_github_token_test.go keeps the expression as the statement of what is
// located, and the fuzz target beside it holds the two to the same answer.
//
// Only the grammar is the expression's; how often it is tried is not. A value
// this scan locates may hold the start of the next one, so the expression is
// tried at every byte rather than handed to FindAllStringIndex, which would
// resume past a match and step over the token inside it.
var githubToken = NewPattern("github-token", func(src string) []Span {
	var spans []Span

	// The JWT a stateless installation token holds ends where its run of
	// base64url characters and the segments after it end. Every candidate
	// crowded inside one run reaches the same end, and the positions asked
	// about only ever move forward, so the run is worked out once and
	// remembered. Working it out again at each candidate would cost time
	// quadratic in the length of a line of ghs_a_ey written over and over,
	// which nothing else here rules out: no candidate consumes what it read,
	// and the underscores such a line is built from are base64url characters.
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
		// asks for an underscore four characters in and this alphabet holds
		// none, so the underscore of the next candidate can be no earlier
		// than the byte that ends this run, and the run that candidate reads
		// therefore begins past this one. Successive candidates read runs
		// that do not overlap, and reading all of them comes to the length of
		// the input.
		body := start + 4
		end := body
		for end < len(src) && isGitHubTokenByte(src[end]) {
			end++
		}

		// The stateless installation token comes first, as it does in the
		// expression: an app id of thirty-six characters or more would
		// otherwise be taken for a whole classic token, leaving the rest of
		// the token to the JWT pattern and the underscore between them
		// unredacted. Its JWT is anchored on what opens a JOSE header, which
		// opensJOSEHeaderAt in builtin_jwt.go states, and without which an
		// underscore and two dots written after a classic token, as in a file
		// name, would be drawn in before the classic alternative is reached.
		//
		// That anchor is the whole of what is read of the JWT. It asks the
		// header for the bytes { and a quote and decodes nothing past them:
		// GitHub signs this JWT with an issuer of its own and says a client
		// neither can nor should validate it, so a run that opens a header
		// and carries the segments is redacted whether or not it decodes to
		// one. Reading it for alg would cost the token itself the day GitHub
		// writes a header this pattern does not recognise.
		//
		// The shape the anchor does ask for is not free, and what it costs is
		// stated rather than passed over: a header written with space after
		// the brace leaves a third character outside the four, so a stateless
		// token carrying one is not located at all. That is the header the
		// JWT pattern declines as well, for the same reason, and a signer
		// emitting compact JSON never writes it. The alternative costs more:
		// an anchor asking for the ey alone draws a file name written after
		// an app id into a token wherever the name opens with those letters.
		//
		// A token clipped before its second dot, as a log line cut to a column
		// limit leaves one, is deliberately not located: what authenticates a
		// stateless token is its signature, and a token cut that early carries
		// none of it. One surviving signature character is already enough to
		// have the whole token located. Reaching that remnant would mean
		// keying on the prefix and a run of characters, as GitHub's own advice
		// does, and admitting the dot into that run draws in the file name
		// written after a classic token, which the anchor holds back.
		if src[start+2] == 's' && end > body && end < len(src) &&
			src[end] == '_' && opensJOSEHeaderAt(src, end+1) {
			header := end + 1 + len(jwtHeaderPrefix)
			if header >= runEnd {
				runEnd = header
				for runEnd < len(src) && isBase64URLByte(src[runEnd]) {
					runEnd++
				}
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

		// Classic tokens, forty characters in all.
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

func isGitHubTokenByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z'
}

func isGitHubPATByte(c byte) bool { return isGitHubTokenByte(c) || c == '_' }

// githubJWTEnd returns where the two segments a signed token carries after its
// header end, and whether both are there. Unlike segmentsEnd in builtin_jwt.go,
// which serves the JWT pattern, a segment here must hold at least one
// character: the expression this scan reads spells them with a plus, so that
// the two dots of a file name written after a token do not stand in for them.
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
		for i < len(src) && isBase64URLByte(src[i]) {
			i++
		}
		if i == start {
			return segments{}
		}
	}
	return segments{end: i, ok: true}
}
