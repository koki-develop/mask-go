package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The GitHub token pattern: what it locates and what it leaves alone, written
// out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, exhaustive and idempotent masking, concurrent use and a
// linear-time scan — is held to in builtins_test.go, which drives every
// built-in from one table rather than a set of tests apiece.
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
			if got := GitHubToken().Find(tt.src); !slices.Equal(got, tt.want) {
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
			if got := GitHubToken().Find(tt.src); len(got) != 0 {
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
	// Both built-in patterns fire on a stateless installation token, and the
	// app id, the underscore after it and the JWT must all go, however long
	// the app id is.
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
			name: "app id as long as a classic token",
			src:  "ghs_0123456789abcdefghijklmnopqrstuvwxyz0123_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			want: "*********************************************************************************************************************",
		},
	}

	m := New(WithPatterns(DefaultPatterns()...))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

// referenceGitHubToken is the expression the scan in builtin_github_token.go
// reads by hand: the statement of what a GitHub token is, kept here so that the
// scan can be held to it. Go matches an alternation leftmost-first rather than
// leftmost-longest, which is why the stateless installation token comes before
// the classic one it opens like.
//
// The class after the header prefix is the third character of a JOSE header,
// which opensJOSEHeader admits and this expression spells out: a run written
// as ey and anything at all draws in a file name written after an app id,
// ghs_1_eyes.tar.gz among them.
var referenceGitHubToken = regexp.MustCompile(
	`ghs_[0-9A-Za-z]+_` + jwtHeaderPrefix + `[I-L][0-9A-Za-z_-]*\.[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+` +
		`|gh[pousr]_[0-9A-Za-z]{36,}` +
		`|` + githubPATPrefix + `[0-9A-Za-z_]{82,}`,
)

// referenceGitHubTokenFind locates tokens the plain way: the leftmost match of
// the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with no cursor and nothing remembered between
// them. It is the control flow of the scan spelled with a regexp in place of
// the byte tests.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a token can begin inside one: a body is read as
// far as its alphabet runs, so it swallows the prefix of a token written
// straight after it and hides that token from every starting point the engine
// would go on to try. The scan finds both, and reports the two spans
// overlapping for a Masker to resolve, so the reference must ask about both.
//
// Resuming a byte along is what the run cursors save the scan from, so this
// costs time quadratic in the length of a run the fine grained prefix can be
// written inside: every candidate in such a run matches, so nothing about the
// bytes lets the engine skip one, and eighty kilobytes of github_pat_ written
// over and over take seconds here against half a millisecond in the scan. It
// is the price of a reference with no cursor to be wrong about, and the reason
// the seeds below keep that shape to a hundred and thirty bytes rather than
// inviting the mutator to grow it. Test_builtins_scanIsLinear is where the
// cost the scan pays is held down.
func referenceGitHubTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceGitHubToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzGitHubToken_matchesReference guards the hand-written scan: the two
// cursors it keeps, over the JWT of a stateless installation token and over
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
	f.Add("ghs_0123456789abcdefghijklmnopqrstuvwxyz_eyJhbGciOiJIUzI1NiJ9.a.b") // an app id long enough to look classic
	f.Add("ghs_0123456789abcdefghijklmnopqrstuvwxyz_config.json.bak")          // dots after a classic token
	f.Add("ghs__eyJ1.a.b")                                                     // no app id
	f.Add("ghs_a_eyJ.a.b")                                                     // a header of nothing but the anchor
	f.Add("ghs_a_eyes.tar.gz")                                                 // a file name opening with the two letters alone
	f.Add("ghs_a_eyA.a.b")                                                     // a third character just below the four
	f.Add("ghs_a_eyM.a.b")                                                     // and just above them
	f.Add("ghs_a_eyJ1..b")                                                     // an empty segment
	f.Add("ghs_a_eyJ1.a")                                                      // one segment short
	f.Add("ghs_a_eyJghp_0123456789abcdefghijklmnopqrstuvwxyz")                 // a classic token inside the JWT run
	f.Add("gghs_a_eyJ1.a.b")
	f.Add(strings.Repeat("ghs_a_eyJ", 16)) // candidates crowded in one run
	f.Add(strings.Repeat("ghs_a_eyJ", 16) + ".a.b")
	// A token beginning inside the match before it, which a scan resuming
	// past a match steps over, and a run holding a candidate for every eleven
	// characters it has, which is what the fine grained cursor is for.
	f.Add("ghp_0123456789abcdefghijklmnopqrstuvwxyzgho_0123456789abcdefGHIJKLMNOPQRSTUVWXYZ")
	f.Add("ghs_1_eyJ1.a.bghs_2_eyJ2.c.d")
	f.Add(strings.Repeat("github_pat_", 12))
	f.Add(strings.Repeat("github_pat_", 12) + "!")

	fuzzAgainstReference(f, GitHubToken().Find, referenceGitHubTokenFind)
}
