package mask

import (
	"slices"
	"strings"
	"testing"
)

// The GitHub token pattern: what it locates and what it leaves alone, written
// out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real.

func Test_GitHubToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "classic personal access token",
			src:  "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			name: "oauth app access token",
			src:  "gho_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			name: "app user access token",
			src:  "ghu_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			name: "app installation access token",
			src:  "ghs_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			name: "app refresh token",
			src:  "ghr_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			// The form GitHub issues: github_pat_, twenty-two characters, an
			// underscore, and fifty-nine more. The underscore inside the body
			// is a character base64 does not hold, picked so that a random
			// string could not be mistaken for a token, and the alphabet the
			// body is read in has to admit it.
			name: "fine grained personal access token",
			src:  "github_pat_0123456789abcdefABCDEF_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW",
			want: []Span{{0, 93}},
		},
		{
			// A header written with the space JSON allows between the brace
			// and the first member name, which decodes to
			// { "alg":"HS256"}. The anchor reads the byte behind the brace
			// and admits the space as well as the quote.
			name: "stateless installation token whose header opens with a space",
			src:  "ghs_123456_eyAiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: []Span{{0, 69}},
		},
		{
			// The ghs_APPID_JWT form GitHub moved installation tokens to in
			// 2026.
			name: "stateless installation token",
			src:  "ghs_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: []Span{{0, 83}},
		},
		{
			// An app id of thirty-six characters or more opens like a whole
			// classic token, and the alternation must still prefer the
			// stateless form: matched the other way round, the underscore
			// after the app id is left behind.
			name: "stateless installation token with a long app id",
			src:  "ghs_0123456789abcdefghijklmnopqrstuvwxyz0123_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: []Span{{0, 117}},
		},
		{
			// The same form under the other kind that reaches it. GitHub has
			// said the format of user access tokens is to change and has
			// named no shape for it, and isGitHubStatelessKind admits the
			// kind on that much.
			name: "stateless user access token",
			src:  "ghu_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: []Span{{0, 83}},
		},
		{
			// And a kind that does not reach it. The classic alternative is
			// all that is left, and an app id of six characters is far short
			// of what that asks for, so nothing is located at all.
			name: "a personal access token prefix in the stateless form",
			src:  "ghp_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: nil,
		},
		{
			// What admitting a kind costs. A file name written after a body
			// of thirty-six characters opens like a JOSE header and carries
			// the two dots the segments need, so it is drawn into the span
			// under a kind that reaches the stateless form and left where it
			// is under one that does not.
			name: "a file name after a user access token, which goes with it",
			src:  "ghu_0123456789abcdefghijklmnopqrstuvwxyz_eyJson.min.js",
			want: []Span{{0, 54}},
		},
		{
			name: "the same file name after a personal access token, which stays",
			src:  "ghp_0123456789abcdefghijklmnopqrstuvwxyz_eyJson.min.js",
			want: []Span{{0, 40}},
		},
		{
			// GitHub documents no length, so a body is read as far as its
			// alphabet runs: the first token here swallows the gho of the
			// second, whose start the first match therefore covers. A scan
			// resuming past a match would step over it and leave a whole
			// token in the output. The spans overlap, which a Masker resolves
			// into one.
			name: "two tokens with nothing between them",
			src:  "ghp_0123456789abcdefghijklmnopqrstuvwxyzgho_0123456789abcdefGHIJKLMNOPQRSTUVWXYZ",
			want: []Span{{0, 43}, {40, 80}},
		},
		{
			// Admitting the underscore into a fine grained body lets the
			// prefix be written inside one, so a run holds a candidate every
			// eleven characters and each of them reads that same run to its
			// end. Every candidate with eighty-two characters left in front
			// of it is a token; the run cursor is what keeps the reading from
			// being paid for again at each.
			name: "the fine grained prefix written inside a fine grained body",
			src:  strings.Repeat("github_pat_", 16),
			want: []Span{
				{0, 176}, {11, 176}, {22, 176}, {33, 176},
				{44, 176}, {55, 176}, {66, 176}, {77, 176},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := GitHubToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GitHubToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "ghp_",
		},
		{
			// Thirty-five characters where the pattern asks for thirty-six.
			name: "body one character too short",
			src:  "ghp_0123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			name: "unknown prefix letter",
			src:  "ghx_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "prefix without separator",
			src:  "ghp0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			// Eighty-one characters where the pattern asks for eighty-two.
			name: "fine grained body one character too short",
			src:  "github_pat_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012345678",
		},
		{
			// The whitespace JSON allows there beside the space is out of the
			// anchor's reach: {\t"alg":"HS256"} encodes to ew rather than ey,
			// so the header prefix is not in the text and the token is left
			// whole.
			name: "stateless installation token whose header opens with a tab",
			src:  "ghs_123456_ewkiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
		},
		{
			// {\r"alg":"HS256"}, and the newline beside it, which the
			// conformance corpus states.
			name: "stateless installation token whose header opens with a carriage return",
			src:  "ghs_123456_ew0iYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
		},
		{
			name: "an identifier that starts like the prefix",
			src:  "github_pattern_for_matching",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := GitHubToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_GitHubToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "GITHUB_TOKEN=****************************************",
		},
		{
			name: "quoted",
			src:  `"ghp_0123456789abcdefghijklmnopqrstuvwxyz"`,
			want: `"****************************************"`,
		},
		{
			name: "header",
			src:  "Authorization: token ghp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "Authorization: token ****************************************",
		},
		{
			name: "twice",
			src:  "ghp_0123456789abcdefghijklmnopqrstuvwxyz ghp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "**************************************** ****************************************",
		},
	}

	m := New(WithPatterns(GitHubToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GitHubToken_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the token through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "underscore after",
			src:  "ghp_0123456789abcdefghijklmnopqrstuvwxyz_x",
			want: "****************************************_x",
		},
		{
			name: "word character before",
			src:  "xghp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "x****************************************",
		},
		{
			name: "underscore before",
			src:  "TOKEN_ghp_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "TOKEN_****************************************",
		},
		{
			name: "underscore before a fine grained token",
			src:  "X_github_pat_0123456789abcdefABCDEF_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW",
			want: "X_*********************************************************************************************",
		},
	}

	m := New(WithPatterns(GitHubToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GitHubToken_leavesWhatFollowsAlone(t *testing.T) {
	// Only the stateless installation token carries dots and dashes, so a
	// classic one must not draw in the host or word written after it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "host",
			src:  "host=ghp_0123456789abcdefghijklmnopqrstuvwxyz.example.com",
			want: "host=****************************************.example.com",
		},
		{
			name: "dashed word",
			src:  "ghp_0123456789abcdefghijklmnopqrstuvwxyz-suffix",
			want: "****************************************-suffix",
		},
		{
			name: "sentence",
			src:  "the token is ghp_0123456789abcdefghijklmnopqrstuvwxyz.",
			want: "the token is ****************************************.",
		},
		{
			// An underscore and two dots after a classic ghs_ token are the
			// shape of the stateless form, which is tried first. Only a JWT
			// may follow the underscore, so this file name does not join the
			// token.
			name: "file name after a classic installation token",
			src:  "ghs_0123456789abcdefghijklmnopqrstuvwxyz_backup.tar.gz",
			want: "****************************************_backup.tar.gz",
		},
	}

	m := New(WithPatterns(GitHubToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GitHubToken_statelessTokenLeavesNothingBehind(t *testing.T) {
	// Both built-in patterns fire on a token written in the stateless form,
	// and the app id, the underscore after it and the JWT must all go,
	// however long the app id is and whichever kind reaches that form.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "short app id",
			src:  "ghs_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: "***********************************************************************************",
		},
		{
			name: "user access token",
			src:  "ghu_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: "***********************************************************************************",
		},
		{
			name: "app id as long as a classic token",
			src:  "ghs_0123456789abcdefghijklmnopqrstuvwxyz0123_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: "*********************************************************************************************************************",
		},
	}

	m := New(WithPatterns(AllBuiltinPatterns()...))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

// Test_githubTokenAnchor holds both prefixes to carrying the byte the scan
// searches the input for at the index each is read back from. One search finds
// candidates of both forms only while both spell that byte at their own depth,
// and a prefix that did not would be one no candidate is ever found at.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_githubTokenAnchor(t *testing.T) {
	if githubTokenAnchorIndex >= len(githubTokenOpening) {
		t.Fatalf("the anchor stands at %d, the opening is %d characters", githubTokenAnchorIndex, len(githubTokenOpening))
	}
	if c := githubTokenOpening[githubTokenAnchorIndex]; c != githubTokenAnchor {
		t.Errorf("the opening carries %q where the scan searches for %q, so no candidate is ever found at it",
			c, byte(githubTokenAnchor))
	}
	if githubPATAnchorIndex >= len(githubPATPrefix) {
		t.Fatalf("the anchor stands at %d, the fine grained prefix is %d characters", githubPATAnchorIndex, len(githubPATPrefix))
	}
	if c := githubPATPrefix[githubPATAnchorIndex]; c != githubTokenAnchor {
		t.Errorf("the fine grained prefix carries %q where the scan searches for %q, so no candidate is ever found at it",
			c, byte(githubTokenAnchor))
	}

	// And each carries the anchor at that depth and nowhere else, so an anchor
	// opens one candidate of a form rather than several. Without it the two
	// read-backs could land on the same prefix from different depths and the
	// scan would report the same token twice.
	for name, prefix := range map[string]string{"the opening": githubTokenOpening, "the fine grained prefix": githubPATPrefix} {
		for i := range len(prefix) {
			if i != githubTokenAnchorIndex && i != githubPATAnchorIndex && prefix[i] == githubTokenAnchor {
				t.Errorf("%s carries %q at %d as well as at the depth it is read back from, so an anchor opens a candidate at more than one position",
					name, byte(githubTokenAnchor), i)
			}
		}
	}

	// And the two are read back from different depths, which is what keeps one
	// anchor from opening the same candidate under both readings.
	if githubTokenAnchorIndex == githubPATAnchorIndex {
		t.Error("both prefixes are read back from the same depth, so an anchor opens the same candidate twice")
	}
}

// Test_githubTokenSeparator holds the character a classic prefix closes on to
// belonging to no classic body. That is what keeps a run from holding two
// candidates, and so what lets the scan read a body to the end of its run
// without a cursor over it.
func Test_githubTokenSeparator(t *testing.T) {
	if isBase62Byte(githubTokenSeparator) {
		t.Errorf("the separator %q belongs to the alphabet a classic body is written in, so two candidates could read the same run",
			byte(githubTokenSeparator))
	}

	// The other side of the same character, which is why one of these forms
	// keeps a cursor and the other needs none. A fine grained body admits the
	// separator, so a whole prefix can be written inside one and a run can hold
	// a candidate for every character of a prefix it has; were that to stop
	// being true, the cursor Test_GitHubToken_scanIsLinear drives would be
	// saving nothing and the input crafted against it would stop crowding.
	if !isGitHubPATByte(githubTokenSeparator) {
		t.Errorf("the separator %q is no longer read as a character of a fine grained body, so that form no longer needs the cursor it keeps",
			byte(githubTokenSeparator))
	}
}

func Test_GitHubToken_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a line dense in prefixes
	// holds a candidate for every character of a prefix it has. This scan keeps
	// two run cursors between candidates, and each of them is what stops a run
	// from being walked once per candidate sitting in it. Neither may ever
	// answer for a position in front of one it has already given, and neither
	// can be read from outside the scan: what would find either wrong is an
	// input that crowds candidates into one run, which is what is driven here.
	// The bound is far above a linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats each sample and its first
	// half, so the closest two candidates come to each other there is half a
	// token. The crowding a line can actually carry stays here.
	sources := map[string]string{
		// The header run of a stateless token. The J is what carries these past
		// the anchor and into the run: ey and it are the base64url of a brace
		// and the quote a member name opens with, which is the shape
		// opensJOSEHeaderAt asks for, and a unit written ey and anything at all
		// is turned away in front of the cursor and measures nothing. Every
		// character of the unit is one base64url admits, so the run behind the
		// first header reaches the end of the input and every candidate behind
		// it asks about that same run. Working it out again at each of them is
		// quadratic.
		"stateless candidates sharing one header run": strings.Repeat("ghs_a_eyJ", 150000),
		// The cursor is shared by every kind isGitHubStatelessKind admits, so
		// this is the input above under another name.
		"the same run under the other stateless kind": strings.Repeat("ghu_a_eyJ", 150000),
		// The body run of a fine grained token. The prefix is written in the
		// alphabet the body is, so every eleven characters open a candidate and
		// each of them reads the run to its end.
		"fine grained prefixes crowded in one body run": strings.Repeat(githubPATPrefix, 100000),
		// The form that keeps no cursor, driven for the same crowding: the
		// separator belongs to no classic body, so these runs cannot overlap
		// and reading all of them comes to the length of the input.
		"classic prefixes crowded": strings.Repeat("ghp_", 250000),
	}

	checkScanIsLinear(t, GitHubToken(), sources)
}

// referenceGitHubTokenAt reports where a GitHub token written at start ends,
// and whether one is written there at all. It is the statement of what the scan
// in builtin_github_token.go locates, kept here so that the scan can be held to
// it, and it reads one position and stops.
//
// The three alternatives are tried in the order an alternation would try them,
// leftmost-first rather than leftmost-longest: the stateless form comes before
// the classic one it opens like, so that an app id of thirty-six characters or
// more is not taken for a whole classic token.
//
// The kinds spelled into the first alternative are the ones the scan admits to
// the stateless form, and the two have to be changed together: a kind added to
// one and not the other is a kind the scan and this disagree about, which is
// what the fuzz target below is for.
//
// The class the header prefix is read with is the third character of a JOSE
// header: the four the quote of a member name leaves, and the four the space
// JSON allows before one leaves. A run written as ey and anything at all draws
// in a file name written after an app id, ghs_1_eyes.tar.gz among them.
//
// It is written out rather than built on a regular expression. Both bodies
// spell a floor, thirty-six characters and eighty-two, and a floor written as
// a counted repetition costs an engine a machine as wide as the floor at every
// candidate — over an input the mutator had grown, that leaves
// FuzzGitHubToken_matchesReference running for three seconds of its thirty and
// reporting no executions at all for the rest. The walks below read a byte at
// a time and pay nothing for the width of a count.
//
// The prefixes, the kinds, the counts and the alphabets are written out here
// rather than read from the scan. Reading them would move this with whatever
// the scan was changed to, and the fuzz target below would then hold a rule
// against itself; Test_references_shareNoDeclarationWithTheScans is what keeps
// the two apart.
func referenceGitHubTokenAt(src string, start int) (int, bool) {
	if end, ok := referenceGitHubStatelessAt(src, start); ok {
		return end, true
	}
	if end, ok := referenceGitHubClassicAt(src, start); ok {
		return end, true
	}
	return referenceGitHubFineGrainedAt(src, start)
}

// referenceGitHubStatelessAt reads gh, one of the two kinds written in the
// stateless form, an underscore, an app id of at least one character, an
// underscore, and the JWT behind it: a header opening on ey and the third
// character of a JOSE header, then two segments each holding at least one
// character, so that the two dots of a file name written after an app id do not
// stand in for them.
func referenceGitHubStatelessAt(src string, start int) (int, bool) {
	if start+4 > len(src) || src[start] != 'g' || src[start+1] != 'h' {
		return 0, false
	}
	if kind := src[start+2]; kind != 's' && kind != 'u' {
		return 0, false
	}
	if src[start+3] != '_' {
		return 0, false
	}

	app := referenceGitHubTokenRunEnd(src, start+4, referenceGitHubTokenBase62Byte)
	if app == start+4 || app == len(src) || src[app] != '_' {
		return 0, false
	}

	header := app + 1
	if header+3 > len(src) || src[header] != 'e' || src[header+1] != 'y' {
		return 0, false
	}
	if !referenceGitHubHeaderThirdByte(src[header+2]) {
		return 0, false
	}

	i := referenceGitHubTokenRunEnd(src, header+3, referenceGitHubTokenBase64URLByte)
	for range 2 {
		if i == len(src) || src[i] != '.' {
			return 0, false
		}
		segment := referenceGitHubTokenRunEnd(src, i+1, referenceGitHubTokenBase64URLByte)
		if segment == i+1 {
			return 0, false
		}
		i = segment
	}
	return i, true
}

// referenceGitHubClassicAt reads gh, any of the five token kinds, an underscore
// and a body of thirty-six characters or more. The count is a floor and the
// body is read to the end of its run, so a token is located to the end of what
// is written rather than to a length.
func referenceGitHubClassicAt(src string, start int) (int, bool) {
	if start+4 > len(src) || src[start] != 'g' || src[start+1] != 'h' {
		return 0, false
	}
	switch src[start+2] {
	case 'p', 'o', 'u', 's', 'r':
	default:
		return 0, false
	}
	if src[start+3] != '_' {
		return 0, false
	}

	body := start + 4
	end := referenceGitHubTokenRunEnd(src, body, referenceGitHubTokenBase62Byte)
	if end-body < 36 {
		return 0, false
	}
	return end, true
}

// referenceGitHubFineGrainedAt reads the literal a fine grained personal access
// token opens with and a body of eighty-two characters or more, written in the
// alphabet a classic body is and the underscore this body carries between its
// two parts.
func referenceGitHubFineGrainedAt(src string, start int) (int, bool) {
	if !strings.HasPrefix(src[start:], "github_pat_") {
		return 0, false
	}

	body := start + len("github_pat_")
	end := referenceGitHubTokenRunEnd(src, body, referenceGitHubTokenPATByte)
	if end-body < 82 {
		return 0, false
	}
	return end, true
}

// referenceGitHubHeaderThirdByte reports whether c is the third character of a
// JOSE header: the four the quote of a member name leaves behind the brace, and
// the four the space JSON allows before one leaves.
func referenceGitHubHeaderThirdByte(c byte) bool {
	return 'A' <= c && c <= 'D' || 'I' <= c && c <= 'L'
}

// referenceGitHubTokenBase62Byte reports whether c may appear in an app id or in
// a classic body.
func referenceGitHubTokenBase62Byte(c byte) bool {
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
}

// referenceGitHubTokenPATByte reports whether c may appear in the body of a fine
// grained personal access token.
func referenceGitHubTokenPATByte(c byte) bool {
	return referenceGitHubTokenBase62Byte(c) || c == '_'
}

// referenceGitHubTokenBase64URLByte reports whether c may appear in a segment of
// the JWT a stateless token carries.
func referenceGitHubTokenBase64URLByte(c byte) bool {
	return referenceGitHubTokenBase62Byte(c) || c == '-' || c == '_'
}

// referenceGitHubTokenRunEnd returns where the run beginning at i in src ends,
// reading the characters admits accepts.
func referenceGitHubTokenRunEnd(src string, i int, admits func(byte) bool) int {
	for i < len(src) && admits(src[i]) {
		i++
	}
	return i
}

// referenceGitHubTokenFind locates tokens the plain way: every position in turn,
// with no cursor and nothing remembered between them. It is the control flow of
// the scan with the grammar above in place of the byte tests the scan reads it
// with.
//
// Asking at every position is what a reference must do here, and the shorter
// way of resuming past a match is the wrong one. A token can begin inside
// another: a body is read as far as its alphabet runs, so it swallows the prefix
// of a token written straight after it and hides that token from every starting
// point a search resuming past the match would go on to try. The scan finds
// both, and reports the two spans overlapping for a Masker to resolve, so the
// reference must ask about both.
//
// Asking everywhere is also what makes this quadratic in the length of a run the
// fine grained prefix can be written inside: every candidate in such a run
// matches, so nothing about the bytes lets a position be skipped, and each of
// them reads the run to its end. It is the price of a reference with no cursor
// to be wrong about, and the reason the seeds below keep that shape to a hundred
// and thirty bytes rather than inviting the mutator to grow it.
// Test_builtins_scanIsLinear is where the cost the scan pays is held down.
func referenceGitHubTokenFind(src string) []Span {
	var spans []Span
	for start := range len(src) {
		if end, ok := referenceGitHubTokenAt(src, start); ok {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
}

// FuzzGitHubToken_matchesReference guards the hand-written scan: the two
// cursors it keeps, over the JWT of a token in the stateless form and over
// the body of a fine grained one, the order it tries the alternatives in, the
// run it shares between them and the byte it resumes at may none of them
// change which tokens are located.
//
// The seeds below spell the anchor of that JWT in full, ey and the character
// behind it. One written as ey and anything at all reaches no further than the
// anchor, so a seed aimed at the segments or at the run behind them would sit
// in the corpus testing nothing — and there is no checked-in corpus for this
// target, so what the seeds reach is all a cold run starts from.
func FuzzGitHubToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz")
	f.Add("TOKEN_ghp_0123456789abcdefghijklmnopqrstuvwxyz_suffix")
	f.Add("ghp_0123456789abcdefghijklmnopqrstuvwxy")  // one short of a classic token
	f.Add("ghq_0123456789abcdefghijklmnopqrstuvwxyz") // not a token kind
	f.Add("gh0123456789abcdefghijklmnopqrstuvwxyz")   // no kind and no underscore
	f.Add("github_pat_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789")
	f.Add("github_pat_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012345678") // one short
	f.Add("github_pat_github_pat_github_pat_github_pat_github_pat_github_pat_github_pat_github_pat_")     // the prefix inside the body
	f.Add("ghs_11223344_eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef")
	f.Add("ghs_0123456789abcdefghijklmnopqrstuvwxyz_eyJhbGciOiJIUzI1NiJ9.a.b")     // an app id long enough to look classic
	f.Add("ghs_0123456789abcdefghijklmnopqrstuvwxyz_config.json.bak")              // dots after a classic token
	f.Add("ghs__eyJ1.a.b")                                                         // no app id
	f.Add("ghs_a_eyJ.a.b")                                                         // a header of nothing but the anchor
	f.Add("ghs_a_eyes.tar.gz")                                                     // a file name opening with the two letters alone
	f.Add("ghs_a_eyA.a.b")                                                         // the third character a space leaves
	f.Add("ghs_a_eyE.a.b")                                                         // just above those four
	f.Add("ghs_a_eyH.a.b")                                                         // and just below the four a quote leaves
	f.Add("ghs_a_eyM.a.b")                                                         // and just above them
	f.Add("ghs_123456_ewkiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJhYmMifQ.0123456789abcdef") // a tab behind the brace, which is no ey at all
	f.Add("ghs_123456_ew0iYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJhYmMifQ.0123456789abcdef") // and a carriage return
	f.Add("ghu_123456_eyJhbGciOiJIUzI1NiJ9.a.b")                                   // the other kind that reaches the stateless form
	f.Add("ghp_123456_eyJhbGciOiJIUzI1NiJ9.a.b")                                   // a kind that does not
	f.Add("ghr_123456_eyJhbGciOiJIUzI1NiJ9.a.b")                                   // nor this one
	f.Add("ghu_0123456789abcdefghijklmnopqrstuvwxyz_eyJson.min.js")                // a file name drawn in under a stateless kind
	f.Add("ghp_0123456789abcdefghijklmnopqrstuvwxyz_eyJson.min.js")                // and left where it is under one that is not
	f.Add("ghs_a_eyJ1..b")                                                         // an empty segment
	f.Add("ghs_a_eyJ1.a")                                                          // one segment short
	f.Add("ghs_a_eyJghp_0123456789abcdefghijklmnopqrstuvwxyz")                     // a classic token inside the JWT run
	f.Add("gghs_a_eyJ1.a.b")
	f.Add(strings.Repeat("ghs_a_eyJ", 16)) // candidates crowded in one run
	f.Add(strings.Repeat("ghs_a_eyJ", 16) + ".a.b")
	f.Add(strings.Repeat("ghu_a_eyJ", 16)) // the same run under the other stateless kind
	f.Add(strings.Repeat("ghu_a_eyJ", 16) + ".a.b")
	// A token beginning inside the match before it, which a scan resuming
	// past a match steps over, and a run holding a candidate for every eleven
	// characters it has, which is what the fine grained cursor is for.
	f.Add("ghp_0123456789abcdefghijklmnopqrstuvwxyzgho_0123456789abcdefGHIJKLMNOPQRSTUVWXYZ")
	f.Add("ghs_1_eyJ1.a.bghs_2_eyJ2.c.d")
	f.Add(strings.Repeat("github_pat_", 12))
	f.Add(strings.Repeat("github_pat_", 12) + "!")

	fuzzAgainstReference(f, GitHubToken().Find, referenceGitHubTokenFind)
}

// githubTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under
// a plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func githubTokenFindBenchmarks() []benchmarkCase {
	// Every g in the line reaches the byte tests behind the search, so the line
	// carries the ones a log line has anyway rather than none.
	line := `time=2026-08-17T00:00:00Z level=info msg="getting the login" url=https://github.com/login `
	classic := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	stateless := "ghs_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every nine characters, each of them anchoring a JWT
			// in the same run of base64url characters, and no dot anywhere for
			// the segments to begin at. The underscores are base64url
			// characters themselves, so the whole line is that one run: this is
			// what the cursor over it is for.
			name:  "stateless candidates crowded in one run",
			src:   strings.Repeat("ghs_a_eyJ", 64),
			spans: 0,
		},
		{
			// The fine grained prefix written inside the body it opens, which
			// the underscore in that alphabet allows: a candidate every eleven
			// characters, every one of them asking for the same run, which
			// only the first of them reads. The run stays long enough to be a
			// body to most of them, so the crowding is carried through to the
			// spans rather than turned away at the count.
			name:  "fine grained prefixes crowded in one body",
			src:   strings.Repeat("github_pat_", 48),
			spans: 40,
		},
		{
			name:  "one value",
			src:   line + "token=" + classic,
			spans: 1,
		},
		{
			// The stateless form, where the body is followed by an underscore,
			// a header and the segments after it — the one alternative that
			// reads past the body it began with.
			name:  "one stateless value",
			src:   line + "token=" + stateless,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "token=" + classic,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"token="+classic+"\n", 32),
			spans: 32,
		},
	}
}
