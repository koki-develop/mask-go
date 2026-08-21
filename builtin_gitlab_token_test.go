package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The GitLab token pattern: what it locates and what it leaves alone, written
// out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, exhaustive and idempotent masking, concurrent use and a
// linear-time scan — is held to in builtins_test.go, which drives every
// built-in from one table rather than a set of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. A body is the run 0123456789abcdef carried on
// through the alphabet to the count its kind is written to, and a routable
// token closes with a payload of twenty-seven of them, a separator and the nine
// characters standing for a length and a checksum — which are ordered too,
// because neither is read as a number.

func Test_GitLabToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a personal access token",
			src:  "glpat-0123456789abcdefghij",
			want: []Span{{0, 26}},
		},
		{
			name: "a deploy token",
			src:  "gldt-0123456789abcdefghij",
			want: []Span{{0, 25}},
		},
		{
			name: "a runner authentication token",
			src:  "glrt-0123456789abcdefghij",
			want: []Span{{0, 25}},
		},
		{
			// The same kind of token under the prefix GitLab gives it when it
			// was created through a registration token.
			name: "a runner authentication token created through a registration token",
			src:  "glrtr-0123456789abcdefghij",
			want: []Span{{0, 26}},
		},
		{
			name: "a feed token",
			src:  "glft-0123456789abcdefghij",
			want: []Span{{0, 25}},
		},
		{
			name: "a scim oauth token",
			src:  "glsoat-0123456789abcdefghij",
			want: []Span{{0, 27}},
		},
		{
			name: "a feature flags client token",
			src:  "glffct-0123456789abcdefghij",
			want: []Span{{0, 27}},
		},
		{
			name: "an incoming mail token",
			src:  "glimt-0123456789abcdefghijklmno",
			want: []Span{{0, 31}},
		},
		{
			name: "a pipeline trigger token",
			src:  "glptt-0123456789abcdefghijklmnopqrstuvwxyzABCD",
			want: []Span{{0, 46}},
		},
		{
			name: "an agent token",
			src:  "glagent-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN",
			want: []Span{{0, 58}},
		},
		{
			name: "an oauth application secret",
			src:  "gloas-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01",
			want: []Span{{0, 70}},
		},
		{
			// The one kind whose classic body carries a partition id and an
			// underscore in front of it.
			name: "a ci job token",
			src:  "glcbt-0f_0123456789abcdefghij",
			want: []Span{{0, 29}},
		},
		{
			name: "a ci job token with the longest partition id",
			src:  "glcbt-0123f_0123456789abcdefghij",
			want: []Span{{0, 32}},
		},
		{
			name: "a personal access token in an environment assignment",
			src:  "GITLAB_TOKEN=glpat-0123456789abcdefghij",
			want: []Span{{13, 39}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GitLabToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GitLabToken_routable(t *testing.T) {
	// The shape GitLab.com is moving to for Cells: a payload carrying the
	// routing information, a separator, and the length and checksum closing it
	// — with a version between the two in the form GitLab writes today. The
	// payload is read as far as its alphabet runs, so unlike a classic body it
	// has no count of its own.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a routable personal access token",
			src:  "glpat-0123456789abcdefghijklmnopq.012345678",
			want: []Span{{0, 43}},
		},
		{
			name: "a routable personal access token carrying a version",
			src:  "glpat-0123456789abcdefghijklmnopq.01.012345678",
			want: []Span{{0, 46}},
		},
		{
			// The payload has no ceiling: what GitLab writes into one has grown
			// once already, and a longer one is no more readable than a
			// shorter.
			name: "a payload longer than the shortest",
			src:  "glpat-0123456789abcdefghijklmnopqrstuvwxyzABCDEF.012345678",
			want: []Span{{0, 58}},
		},
		{
			// The t1_ naming the scope of a routable runner token is written in
			// the payload alphabet, so it is the opening of the payload rather
			// than part of the prefix and needs no rule of its own.
			name: "a routable runner authentication token",
			src:  "glrt-t1_0123456789abcdefghijklmnopq.012345678",
			want: []Span{{0, 45}},
		},
		{
			// And the same for the partition id of a CI job token.
			name: "a routable ci job token",
			src:  "glcbt-0f_0123456789abcdefghijklmnopq.012345678",
			want: []Span{{0, 46}},
		},
		{
			name: "a routable token in an environment assignment",
			src:  "GITLAB_TOKEN=glpat-0123456789abcdefghijklmnopq.012345678",
			want: []Span{{13, 56}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GitLabToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GitLabToken_routableFallsBackToClassic(t *testing.T) {
	// A candidate that is not routable is read as a classic token rather than
	// failing, which is what keeps a classic token followed by a dot from going
	// unredacted. The dot and what follows it are then text, and stay.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a checksum one character short",
			src:  "glpat-0123456789abcdefghijklmnopq.01234567",
			want: "**************************klmnopq.01234567",
		},
		{
			name: "a checksum written in capitals",
			src:  "glpat-0123456789abcdefghijklmnopq.01234567A",
			want: "**************************klmnopq.01234567A",
		},
		{
			// Two characters and a separator behind the payload are where a
			// version stands, so this is read as one — and then the nine
			// characters a length and a checksum need are not there.
			name: "a version with too little behind it",
			src:  "glpat-0123456789abcdefghijklmnopq.01.0123456",
			want: "**************************klmnopq.01.0123456",
		},
		{
			name: "a payload one character short of the floor",
			src:  "glpat-0123456789abcdefghijklmnop.012345678",
			want: "**************************klmnop.012345678",
		},
		{
			// A classic token is shorter than the floor a payload has, so a dot
			// written behind one never reaches the routable reading at all.
			name: "a classic token written in front of a dot",
			src:  "glpat-0123456789abcdefghij.012345678",
			want: "**************************.012345678",
		},
	}

	m := New(WithPatterns(GitLabToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GitLabToken_identifiersThatAreNotCredentials(t *testing.T) {
	// Text that is a token's format without being a token. The alphabet a body
	// is read in holds the hyphen and the underscore, so a hyphenated
	// identifier written straight after a prefix reaches the count, and a label
	// of nine lowercase characters written after a payload reads as a checksum.
	//
	// They are held to being redacted rather than to being spared. The grammar
	// is already the one GitLab publishes for these kinds, so nothing in the
	// text tells these from a token, which builtin_gitlab_token.go sets out.
	// What the table is for is that the cases move with the scan: one of them
	// ceasing to be located means the grammar changed, and that is a decision
	// to be taken rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a hyphenated identifier of exactly the count behind a prefix",
			src:  "glagent-config-map-0123456789abcdef-production-tokyo-01234",
			want: "**********************************************************",
		},
		{
			// Longer than the count, so the tail stays rather than the whole
			// identifier going.
			name: "a hyphenated identifier longer than the count",
			src:  "glagent-config-map-0123456789abcdef-production-tokyo-0123456",
			want: "**********************************************************56",
		},
		{
			// The routable reading, which has no count, takes the host label
			// behind the payload for a checksum. Nine characters of it go and
			// the rest of the name stays.
			name: "a host name written after a payload",
			src:  "glagent-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN.production.example.com",
			want: "********************************************************************n.example.com",
		},
		{
			// A label of eight is one short of a checksum, so the routable
			// reading fails and the classic one leaves the whole name.
			name: "a shorter host label, which is no checksum",
			src:  "glagent-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN.internal.example.com",
			want: "**********************************************************.internal.example.com",
		},
	}

	m := New(WithPatterns(GitLabToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GitLabToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "glpat-",
		},
		{
			name: "body one character too short",
			src:  "glpat-0123456789abcdefghi",
		},
		{
			name: "an incoming mail token at the count of the shorter kinds",
			src:  "glimt-0123456789abcdefghij",
		},
		{
			name: "an oauth application secret one character too short",
			src:  "gloas-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0",
		},
		{
			name: "uppercase prefix",
			src:  "GLPAT-0123456789abcdefghij",
		},
		{
			name: "the prefix without its hyphen",
			src:  "glpat0123456789abcdefghij",
		},
		{
			name: "a space inside the body",
			src:  "glpat-0123456789abcdef ghij",
		},
		{
			name: "a dot inside the body",
			src:  "glpat-0123456789abcdef.ghij",
		},
		{
			// GitLab names the workspace token's prefix and publishes no shape
			// for it, so this pattern reads none.
			name: "a workspace token, whose shape GitLab does not publish",
			src:  "glwt-0123456789abcdefghij",
		},
		{
			// Runner registration tokens were removed in GitLab 18.0, and the
			// literal in front of one is not a gl prefix.
			name: "a runner registration token",
			src:  "GR13489410123456789abcdefghij",
		},
		{
			// A session cookie is named by the text in front of it rather than
			// by a prefix of its own.
			name: "a session cookie",
			src:  "_gitlab_session=0123456789abcdef0123456789abcdef",
		},
		{
			name: "a ci job token with no partition id",
			src:  "glcbt-0123456789abcdefghij",
		},
		{
			name: "a ci job token with an empty partition id",
			src:  "glcbt-_0123456789abcdefghij",
		},
		{
			// Six characters where the partition id is written in at most five,
			// so the underscore does not stand where a body begins.
			name: "a ci job token with a partition id too long",
			src:  "glcbt-01234f_0123456789abcdefghij",
		},
		{
			name: "a prefix that is not one of the kinds",
			src:  "glzzz-0123456789abcdefghij",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "prose holding the two bytes a candidate opens with",
			src:  "the global glossary is a glimpse of a glacier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GitLabToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_GitLabToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "GITLAB_TOKEN=glpat-0123456789abcdefghij",
			want: "GITLAB_TOKEN=**************************",
		},
		{
			name: "quoted",
			src:  `"glpat-0123456789abcdefghij"`,
			want: `"**************************"`,
		},
		{
			name: "json",
			src:  `{"token":"glpat-0123456789abcdefghij"}`,
			want: `{"token":"**************************"}`,
		},
		{
			name: "a clone url carrying the token as a password",
			src:  "https://oauth2:glpat-0123456789abcdefghij@gitlab.com/group/project.git",
			want: "https://oauth2:**************************@gitlab.com/group/project.git",
		},
		{
			name: "a private token header",
			src:  "PRIVATE-TOKEN: glpat-0123456789abcdefghij",
			want: "PRIVATE-TOKEN: **************************",
		},
		{
			name: "a runner registration command",
			src:  "gitlab-runner register --token glrt-0123456789abcdefghij",
			want: "gitlab-runner register --token *************************",
		},
		{
			name: "two tokens of different kinds",
			src:  "glpat-0123456789abcdefghij gldt-0123456789abcdefghij",
			want: "************************** *************************",
		},
	}

	m := New(WithPatterns(GitLabToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GitLabToken_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the token through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xglpat-0123456789abcdefghij",
			want: "x**************************",
		},
		{
			name: "underscore before",
			src:  "GITLAB_TOKEN_glpat-0123456789abcdefghij",
			want: "GITLAB_TOKEN_**************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this token
			// rather than trim it; without one the twenty characters GitLab
			// issued are redacted and what was written after them stays.
			name: "an alphabet run longer than a body",
			src:  "glpat-0123456789abcdefghijklmn",
			want: "**************************klmn",
		},
		{
			name: "a hyphen after",
			src:  "glpat-0123456789abcdefghij-backup",
			want: "**************************-backup",
		},
	}

	m := New(WithPatterns(GitLabToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_GitLabToken_tokenBeginningInsideTheOneBeforeIt(t *testing.T) {
	// The body alphabet holds the letters a prefix is written in, so a token
	// can begin inside the span of the one before it and a scan resuming past a
	// match would leave that token in the output whole. The spans overlap,
	// which a Masker resolves into one.
	src := "glpat-0123456789abcdefglpat-0123456789abcdefghij"
	want := []Span{{0, 26}, {22, 48}}
	if got := GitLabToken().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}

	m := New(WithPatterns(GitLabToken()))
	if got, w := m.Mask(src), strings.Repeat("*", len(src)); got != w {
		t.Errorf("Mask(%q) = %q, want %q", src, got, w)
	}
}

func Test_gitLabTokenKinds(t *testing.T) {
	// The scan finds candidate positions with one IndexByte and one byte test,
	// and reads a body from the character behind the prefix, so a prefix not
	// opening with those two bytes is one the scan never reaches, and one not
	// closing with a hyphen would have its last characters read as the opening
	// of a body. Neither shows as a failing case: the pattern would quietly
	// stop locating that kind of token, or start locating it a few characters
	// short.
	if len(gitLabTokenKinds) == 0 {
		t.Fatal("no kind is documented, so the pattern locates nothing")
	}
	for _, k := range gitLabTokenKinds {
		t.Run(k.prefix, func(t *testing.T) {
			if len(k.prefix) < 3 {
				t.Fatalf("the prefix %q is too short to be one", k.prefix)
			}
			if k.prefix[0] != gitLabTokenFirstByte {
				t.Errorf("the prefix does not open with %q, which is what the scan searches for", gitLabTokenFirstByte)
			}
			if k.prefix[1] != gitLabTokenSecondByte {
				t.Errorf("the prefix does not carry %q second, which is what the scan tests before the table", gitLabTokenSecondByte)
			}
			if k.prefix[len(k.prefix)-1] != '-' {
				t.Error("the prefix does not close with a hyphen, so a body would begin inside it")
			}
			if k.bodyChars <= 0 {
				t.Errorf("the kind names a body of %d characters, so anything behind the prefix is one", k.bodyChars)
			}
		})
	}

	// And no two of them match at the same position. gitLabTokenKindAt takes
	// the first that does, so a table where one prefix opened another would
	// have its order decide which, silently and only for that pair.
	for i, k := range gitLabTokenKinds {
		for j, other := range gitLabTokenKinds {
			if i != j && strings.HasPrefix(other.prefix, k.prefix) {
				t.Errorf("the prefix %q opens %q, so which of them is read depends on the order of the table", k.prefix, other.prefix)
			}
		}
	}
}

func Test_gitLabTokenKinds_bodyNeverMovesBack(t *testing.T) {
	// The scan keeps one run cursor for every candidate, and reuses it wherever
	// a body begins inside the run already read. That is sound only while a
	// body never begins in front of the body of the candidate before it: were
	// one to, the cursor would answer for a stretch of run it had never looked
	// at, and a token there would be missed rather than mislocated.
	//
	// A candidate can begin d characters into a prefix only where the two agree
	// over what they share, and its body then begins d+len(other) characters
	// along. So the table is safe exactly while no prefix reaches past that,
	// which is checked here over every pair and every offset rather than argued
	// about for the pair that happens to exist today.
	for _, k := range gitLabTokenKinds {
		for d := 1; d < len(k.prefix); d++ {
			for _, other := range gitLabTokenKinds {
				rest := k.prefix[d:]
				if !strings.HasPrefix(rest, other.prefix) && !strings.HasPrefix(other.prefix, rest) {
					continue
				}
				if len(k.prefix) > d+len(other.prefix) {
					t.Errorf("a %q beginning %d characters into a %q starts a body %d characters in front of it",
						other.prefix, d, k.prefix, len(k.prefix)-d-len(other.prefix))
				}
			}
		}
	}
}

func Test_gitLabTokenByteClasses(t *testing.T) {
	// The two classes are what the pattern is widest on, so each is stated over
	// every byte rather than by example. A body is read in the base64url
	// alphabet, which builtin_scan.go states; these are the two the GitLab scan
	// adds.
	for c := range 256 {
		b := byte(c)
		partition := '0' <= b && b <= '9' || 'A' <= b && b <= 'Z' || 'a' <= b && b <= 'z'
		tail := '0' <= b && b <= '9' || 'a' <= b && b <= 'z'

		if got := isGitLabTokenPartitionByte(b); got != partition {
			t.Errorf("isGitLabTokenPartitionByte(%q) = %v, want %v", b, got, partition)
		}
		if got := isGitLabTokenTailByte(b); got != tail {
			t.Errorf("isGitLabTokenTailByte(%q) = %v, want %v", b, got, tail)
		}
	}

	// The separator between a partition id and the body behind it is not a
	// partition character, which is what ends the id; and it is a body
	// character, which is what puts it inside the run the scan has read.
	if isGitLabTokenPartitionByte(gitLabTokenPartitionSeparator) {
		t.Error("the partition separator is read as part of the id it closes")
	}
	if !isBase64URLByte(gitLabTokenPartitionSeparator) {
		t.Error("the partition separator is not a body character, so it stands outside the run")
	}

	// And the separator closing a routable payload is the other way round: it
	// is not a body character, which is what makes the payload end where the
	// tail begins, and it is not a tail character either, which is what tells
	// the two routable forms apart.
	if isBase64URLByte(gitLabTokenTailSeparator) {
		t.Error("the tail separator is read as part of a payload, which would never then end")
	}
	if isGitLabTokenTailByte(gitLabTokenTailSeparator) {
		t.Error("the tail separator is read as a tail character, so a version could not be told from a length")
	}
}

// referenceGitLabToken is the expression the scan in builtin_gitlab_token.go
// reads by hand: the statement of what a GitLab token is, kept here so that the
// scan can be held to it.
//
// The routable alternative comes first, as it does in the scan: its payload is
// written in the alphabet a classic body is, so a classic alternative reached
// first would take the opening of a payload for a whole token.
//
// The prefixes, the counts and the character classes are spelled again rather
// than built from gitLabTokenKinds and the constants beside it. A reference
// sharing those declarations could not disagree with the scan about them, and
// it is exactly that disagreement the fuzz target below is for: the two have to
// be changed together or reported apart.
var referenceGitLabToken = regexp.MustCompile(
	`(?:glpat-|gldt-|glrtr-|glrt-|glft-|glsoat-|glffct-|glimt-|glptt-|glagent-|gloas-|glcbt-)` +
		`[0-9A-Za-z_-]{27,}\.(?:[0-9a-z]{2}\.)?[0-9a-z]{2}[0-9a-z]{7}` +
		`|glpat-[0-9A-Za-z_-]{20}` +
		`|gldt-[0-9A-Za-z_-]{20}` +
		`|glrtr-[0-9A-Za-z_-]{20}` +
		`|glrt-[0-9A-Za-z_-]{20}` +
		`|glft-[0-9A-Za-z_-]{20}` +
		`|glsoat-[0-9A-Za-z_-]{20}` +
		`|glffct-[0-9A-Za-z_-]{20}` +
		`|glimt-[0-9A-Za-z_-]{25}` +
		`|glptt-[0-9A-Za-z_-]{40}` +
		`|glagent-[0-9A-Za-z_-]{50}` +
		`|gloas-[0-9A-Za-z_-]{64}` +
		`|glcbt-[0-9A-Za-z]{1,5}_[0-9A-Za-z_-]{20}`,
)

// referenceGitLabTokenFind locates tokens the plain way: the leftmost match of
// the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a token can begin inside one: a body is written
// in an alphabet that holds every letter a prefix is, so glpat-glpat-... holds
// a token the engine would never go on to try. The scan finds both and reports
// the two spans overlapping for a Masker to resolve, so the reference must ask
// about both.
func referenceGitLabTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceGitLabToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzGitLabToken_matchesReference guards the hand-written scan: the bytes it
// searches for, the prefixes it admits, the counts it reads behind them, the
// alphabets it reads them in, the two routable forms it tells apart and the
// byte it resumes at may none of them change which tokens are located.
func FuzzGitLabToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("GITLAB_TOKEN=glpat-0123456789abcdefghij")
	f.Add("glpat-0123456789abcdefghi")      // one short of a body
	f.Add("glpat-0123456789abcdefghijklmn") // and a run longer than one
	f.Add("gldt-0123456789abcdefghij")
	f.Add("glrt-0123456789abcdefghij")
	f.Add("glrtr-0123456789abcdefghij") // the prefix the shorter one opens
	f.Add("glimt-0123456789abcdefghijklmno")
	f.Add("glptt-0123456789abcdefghijklmnopqrstuvwxyzABCD")
	f.Add("glagent-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
	f.Add("gloas-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01")
	// The partition id of a CI job token: present, absent, empty and too long.
	f.Add("glcbt-0f_0123456789abcdefghij")
	f.Add("glcbt-0123f_0123456789abcdefghij")
	f.Add("glcbt-0123456789abcdefghij")
	f.Add("glcbt-_0123456789abcdefghij")
	f.Add("glcbt-01234f_0123456789abcdefghij")
	// The routable forms, and the ways one falls short of being routable.
	f.Add("glpat-0123456789abcdefghijklmnopq.012345678")
	f.Add("glpat-0123456789abcdefghijklmnopq.01.012345678")
	f.Add("glpat-0123456789abcdefghijklmnopq.01234567")
	f.Add("glpat-0123456789abcdefghijklmnopq.01234567A")
	f.Add("glpat-0123456789abcdefghijklmnopq.01.0123456")
	f.Add("glpat-0123456789abcdefghijklmnop.012345678")
	f.Add("glpat-0123456789abcdefghij.012345678")
	f.Add("glrt-t1_0123456789abcdefghijklmnopq.012345678")
	f.Add("glcbt-0f_0123456789abcdefghijklmnopq.012345678")
	f.Add("glagent-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN.production.example.com")
	// The prefixes this pattern leaves alone, and prose holding the two bytes a
	// candidate opens with.
	f.Add("glwt-0123456789abcdefghij")
	f.Add("GR13489410123456789abcdefghij")
	f.Add("_gitlab_session=0123456789abcdef0123456789abcdef")
	f.Add("the global glossary is a glimpse of a glacier")
	// A token beginning inside the one before it, which a scan resuming past a
	// match steps over, and candidate positions crowded as close as they can
	// be.
	f.Add("glpat-0123456789abcdefglpat-0123456789abcdefghij")
	f.Add(strings.Repeat("glrt-", 16))
	f.Add(strings.Repeat("glpat-", 8) + "0123456789abcdefghij")
	f.Add(strings.Repeat("gl", 32))
	f.Add(strings.Repeat("g", 64))
	f.Add(strings.Repeat("glpat-0123456789abcdefghijklmnopq.", 4) + "012345678")

	fuzzAgainstReference(f, GitLabToken().Find, referenceGitLabTokenFind)
}
