package mask

import (
	"slices"
	"strings"
	"testing"
)

// The Slack token pattern: what it locates and what it leaves alone, written
// out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in builtins_test.go, which drives every
// built-in from one table rather than a set of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. Their parts are that run cut to the lengths
// Slack's own examples are written in — identifiers of twelve and thirteen
// characters, and a secret of twenty-four, of thirty-two or of sixty-four.

func Test_SlackToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "bot token",
			src:  "xoxb-0123456789ab-0123456789abc-0123456789abcdefghijklmn",
			want: []Span{{0, 56}},
		},
		{
			name: "user token",
			src:  "xoxp-0123456789ab-0123456789abc-0123456789abcd-0123456789abcdef0123456789abcdef",
			want: []Span{{0, 79}},
		},
		{
			name: "app-level token",
			src:  "xapp-1-A0123456789-0123456789abc-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 97}},
		},
		{
			name: "workflow token",
			src:  "xwfp-0123456789ab-0123456789abcdefghijklmn",
			want: []Span{{0, 42}},
		},
		{
			name: "refresh token",
			src:  "xoxe-1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 71}},
		},
		{
			// A rotatable access token is a bot or user token written behind
			// xoxe., and both prefixes are matched: the whole of what Slack
			// writes, and the token inside it. The dot is neither a letter nor
			// a digit, so the inner prefix is reached. The two spans end
			// together and a Masker merges them.
			name: "rotatable access token",
			src:  "xoxe.xoxb-1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 76}, {5, 76}},
		},
		{
			name: "the user kind of the same",
			src:  "xoxe.xoxp-1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 76}, {5, 76}},
		},
		{
			// A body is read as far as its alphabet runs and that alphabet
			// holds the letters a prefix is written in, so a prefix can stand
			// inside a body. The separator in front of the second is neither a
			// letter nor a digit, so both candidates are reached, both read
			// the same run and both find a secret in it. A scan resuming past
			// a match would step over the second and leave it in the output
			// whole. The spans overlap, which a Masker resolves into one.
			name: "a prefix written inside a body",
			src:  "xoxb-xoxb-0123456789ab-0123456789abcdefghijklmn",
			want: []Span{{0, 47}, {5, 47}},
		},
		{
			// A part in front of the secret is all the pattern asks for, and
			// one character is a part: Slack writes the version number of a
			// refresh token that way.
			name: "a secret behind a part of one character",
			src:  "xwfp-1-0123456789abcdefghijklmn",
			want: []Span{{0, 31}},
		},
		{
			// The secret is asked for at eighteen characters, which is a
			// floor rather than a count: the segment here is exactly that.
			name: "a secret of eighteen characters",
			src:  "xoxb-0123456789ab-0123456789abcdefgh",
			want: []Span{{0, 36}},
		},
		{
			// A secret is asked for a letter, not for a particular alphabet,
			// so one digit among seventeen letters is a secret as readily as
			// one letter among seventeen digits.
			name: "a secret of one digit and seventeen letters",
			src:  "xoxb-0123456789ab-0abcdefghijklmnopq",
			want: []Span{{0, 36}},
		},
		{
			// What asking that of some segment rather than of the last one
			// costs. The run reaches past the token, so the word written
			// after it goes into the span; asked of the last segment, this
			// token would not be located at all.
			name: "a hyphenated word after a token, which goes with it",
			src:  "xoxb-0123456789ab-0123456789abcdefghijklmn-backup",
			want: []Span{{0, 49}},
		},
		{
			name: "a token in an environment assignment",
			src:  "SLACK_BOT_TOKEN=xoxb-0123456789ab-0123456789abc-0123456789abcdefghijklmn",
			want: []Span{{16, 72}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SlackToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SlackToken_identifiersThatAreNotTokens(t *testing.T) {
	// The text the two demands on a candidate are there for: names as build
	// output, log lines and branches carry them, each of which a prefix and a
	// run alone would have redacted. Every one of them is a value a reader
	// reads — a git SHA, an MD5, a nanosecond timestamp, a build number — and
	// none of them may be redacted.
	//
	// The first two are held out by the part a secret must stand behind. Their
	// prefix opens a word of its own — xApp is what an application on a radio
	// access network is called — so nothing in front of it holds them back,
	// and a digest is a run of alphanumerics with letters in it, so the length
	// and the letter do not either.
	//
	// The next three are held out by what stands in front of the prefix: xapp
	// closes linuxapp and nginxapp, and a letter there opens nothing. The
	// first two of those write their digest behind a part, so for them it is
	// the one demand left.
	//
	// The last two are held out by the letter a secret must carry: their long
	// parts are all digits, which is an id or a timestamp and not a secret.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "an md5 after a prefix that stands on its own",
			src:  "image: registry.example.com/xapp-8f14e45fceea167a5a36dedd4bea2543",
		},
		{
			name: "a git sha after a prefix that stands on its own",
			src:  "branch xapp-4f3d2c1b0a9e8d7c6b5a49382716f5e4c3b2a190",
		},
		{
			name: "an md5 after a name ending in a prefix",
			src:  "image: registry.example.com/linuxapp-build-8f14e45fceea167a5a36dedd4bea2543",
		},
		{
			name: "a git sha after a branch name ending in a prefix",
			src:  "branch nginxapp-fix-4f3d2c1b0a9e8d7c6b5a49382716f5e4c3b2a190",
		},
		{
			name: "a nanosecond timestamp after a name ending in a prefix",
			src:  "linuxapp-1705311000123456789.log",
		},
		{
			name: "a nanosecond timestamp after a prefix",
			src:  "span=xapp-trace-1705311000123456789 done",
		},
		{
			name: "a build number after a prefix",
			src:  "xapp-build-20240115093000123456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SlackToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_SlackToken_aDigestBehindAPart(t *testing.T) {
	// Where the demand for a part in front of the secret stops, stated here
	// rather than left for the next reader to discover. A prefix, a part and a
	// long alphanumeric run behind it is the shape of an app-level token, so
	// there is nothing in these lines left to tell them apart from one, and
	// declining them would mean declining every token written that way. What
	// the demand does reach — the same digests written straight after the
	// prefix — is in Test_SlackToken_identifiersThatAreNotTokens.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "an md5 behind a part",
			src:  "xapp-build-8f14e45fceea167a5a36dedd4bea2543",
			want: "*******************************************",
		},
		{
			name: "a git sha behind a part",
			src:  "xapp-main-4f3d2c1b0a9e8d7c6b5a49382716f5e4c3b2a190",
			want: "**************************************************",
		},
	}

	m := New(WithPatterns(SlackToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SlackToken_aWordBehindAPart(t *testing.T) {
	// The same stopping point as Test_SlackToken_aDigestBehindAPart, reached by
	// text a reader reads rather than by a digest. A word of eighteen letters
	// is a segment long enough to be a secret and carries the letter one is
	// asked for, so a name whose parts run that long is redacted. The rationale
	// in builtin_slack_token.go weighs the two tightenings that would reach
	// these and takes neither; what holds the shorter names back is the count
	// alone, which Test_SlackToken_identifiersThatAreNotTokens states.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "an english word behind a part",
			src:  "xapp-config-internationalization",
			want: "********************************",
		},
		{
			name: "a camel case identifier behind a part",
			src:  "xapp-svc-authenticationProvider",
			want: "*******************************",
		},
	}

	m := New(WithPatterns(SlackToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SlackToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "xoxb-",
		},
		{
			// Seventeen characters where the pattern asks for eighteen, and
			// no other segment reaches it either.
			name: "every segment one character too short",
			src:  "xoxb-0123456789ab-0123456789abcdefg",
		},
		{
			// Long enough, and all digits, so it is an identifier rather than
			// a secret.
			name: "a long segment with no letter in it",
			src:  "xoxb-0123456789ab-012345678901234567",
		},
		{
			// A secret standing against the prefix with no part in front of
			// it. Every Slack token whose shape is published carries one, and
			// without the demand a prefix and a single run would be a token.
			name: "a secret with no part in front of it",
			src:  "xoxb-0123456789abcdefghijklmn",
		},
		{
			// And the same where the run goes on: the parts behind the secret
			// are not what the demand asks for, which is one in front.
			name: "a secret with parts behind it but none in front",
			src:  "xoxb-0123456789abcdefghijklmn-backup-2",
		},
		{
			// The tightening that keeps this pattern off text a reader can
			// read. Every part here is shorter than a secret, so no segment is
			// one, and a grammar asking only for the prefix and the run would
			// have redacted the whole of it. It is the count doing that and
			// nothing else: an identifier with a part of eighteen letters is
			// redacted, which Test_SlackToken_aWordBehindAPart states.
			name: "an identifier whose every part is shorter than a secret",
			src:  "xapp-frontend-integration-tests",
		},
		{
			// The other side of the same tightening. A letter in front of the
			// prefix opens nothing, so a prefix that closes a word is not one.
			name: "a prefix that closes a word",
			src:  "xxoxb-0123456789ab-0123456789abcdefghijklmn",
		},
		{
			name: "a prefix after a digit",
			src:  "1xoxb-0123456789ab-0123456789abcdefghijklmn",
		},
		{
			name: "an unknown prefix letter",
			src:  "xoxz-0123456789ab-0123456789abcdefghijklmn",
		},
		{
			// The workspace app tokens. They are credentials and they are
			// left alone: Slack has withdrawn every description of them.
			name: "a legacy workspace access token",
			src:  "xoxa-2-0123456789abcdef-0123456789abcdefghijklmn",
		},
		{
			name: "a legacy workspace refresh token",
			src:  "xoxr-2-0123456789abcdef-0123456789abcdefghijklmn",
		},
		{
			// And the custom integration tokens, one of which is a word.
			name: "a legacy session token",
			src:  "xoxs-0123456789abcdef-0123456789abcdefghijklmn",
		},
		{
			name: "a legacy token whose prefix is a word",
			src:  "xoxo-0123456789abcdef-0123456789abcdefghijklmn",
		},
		{
			name: "a browser session token slack has never published",
			src:  "xoxc-0123456789abcdef-0123456789abcdefghijklmn",
		},
		{
			// Slack writes its prefixes in lowercase and the pattern reads
			// them that way, which is what keeps XOXO out of reach.
			name: "an uppercase prefix",
			src:  "XOXB-0123456789ab-0123456789abcdefghijklmn",
		},
		{
			name: "a prefix without its separator",
			src:  "xoxb0123456789ab0123456789abcdefghijklmn",
		},
		{
			// The dot of a rotatable access token stands in front of a
			// prefix, not in a body, so it is not the separator and xoxe. on
			// its own opens nothing.
			name: "the rotation prefix with no token behind it",
			src:  "xoxe.0123456789abcdefghijklmn",
		},
		{
			name: "an underscore where the separator would be",
			src:  "xoxb_0123456789ab_0123456789abcdefghijklmn",
		},
		{
			name: "a secret with no prefix in front of it",
			src:  "0123456789ab-0123456789abcdefghijklmn",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SlackToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_SlackToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "SLACK_BOT_TOKEN=xoxb-0123456789ab-0123456789abc-0123456789abcdefghijklmn",
			want: "SLACK_BOT_TOKEN=********************************************************",
		},
		{
			name: "quoted",
			src:  `"xoxb-0123456789ab-0123456789abc-0123456789abcdefghijklmn"`,
			want: `"********************************************************"`,
		},
		{
			name: "header",
			src:  "Authorization: Bearer xoxb-0123456789ab-0123456789abc-0123456789abcdefghijklmn",
			want: "Authorization: Bearer ********************************************************",
		},
		{
			name: "json",
			src:  `{"ok":true,"access_token":"xoxb-0123456789ab-0123456789abc-0123456789abcdefghijklmn"}`,
			want: `{"ok":true,"access_token":"********************************************************"}`,
		},
		{
			name: "twice",
			src:  "xwfp-0123456789ab-0123456789abcdefghijklmn xwfp-0123456789ab-0123456789abcdefghijklmn",
			want: "****************************************** ******************************************",
		},
		{
			// The two spans are merged, so the token that begins inside the
			// one before it leaves nothing of itself behind.
			name: "a prefix written inside a body",
			src:  "xoxb-xoxb-0123456789ab-0123456789abcdefghijklmn",
			want: "***********************************************",
		},
		{
			// And the same for a rotatable access token, which is located at
			// both of its prefixes.
			name: "rotatable access token",
			src:  "xoxe.xoxb-1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "****************************************************************************",
		},
	}

	m := New(WithPatterns(SlackToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SlackToken_whatMayStandInFront(t *testing.T) {
	// The byte in front of a prefix may be anything but a letter or a digit,
	// which is narrower than a word boundary in one direction and wider in the
	// other. The underscore is the case the width is for: a word boundary
	// there would drop the first token below rather than trim it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "underscore",
			src:  "SLACK_BOT_TOKEN_xoxb-0123456789ab-0123456789abcdefghijklmn",
			want: "SLACK_BOT_TOKEN_******************************************",
		},
		{
			name: "equals sign",
			src:  "token=xoxb-0123456789ab-0123456789abcdefghijklmn",
			want: "token=******************************************",
		},
		{
			name: "slash",
			src:  "https://example.com/xoxb-0123456789ab-0123456789abcdefghijklmn",
			want: "https://example.com/******************************************",
		},
		{
			name: "colon",
			src:  "authorization:xoxb-0123456789ab-0123456789abcdefghijklmn",
			want: "authorization:******************************************",
		},
		{
			name: "separator",
			src:  "xoxb-xoxb-0123456789ab-0123456789abcdefghijklmn",
			want: "***********************************************",
		},
		{
			// And the narrow direction, which is what the pattern is
			// tightened by: a letter in front and the prefix opens nothing,
			// so the name and the digest written after it stay.
			name: "letter",
			src:  "linuxapp-build-8f14e45fceea167a5a36dedd4bea2543",
			want: "linuxapp-build-8f14e45fceea167a5a36dedd4bea2543",
		},
		{
			name: "digit",
			src:  "1xoxb-0123456789ab-0123456789abcdefghijklmn",
			want: "1xoxb-0123456789ab-0123456789abcdefghijklmn",
		},
	}

	m := New(WithPatterns(SlackToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SlackToken_whatEndsABody(t *testing.T) {
	// There is no boundary behind the match, so what ends a token is the
	// alphabet alone: the separator is the one punctuation a body admits, and
	// everything else ends the run and stays in the text.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "host",
			src:  "host=xoxb-0123456789ab-0123456789abcdefghijklmn.example.com",
			want: "host=******************************************.example.com",
		},
		{
			name: "sentence",
			src:  "the token is xoxb-0123456789ab-0123456789abcdefghijklmn.",
			want: "the token is ******************************************.",
		},
		{
			name: "query parameter",
			src:  "?token=xoxb-0123456789ab-0123456789abcdefghijklmn&pretty=1",
			want: "?token=******************************************&pretty=1",
		},
		{
			name: "underscore",
			src:  "xoxb-0123456789ab-0123456789abcdefghijklmn_x",
			want: "******************************************_x",
		},
		{
			// A boundary behind the match would drop this token rather than
			// trim it, so the three letters written after it are redacted
			// with it: nothing in the run says where Slack stopped writing.
			name: "letters",
			src:  "xoxb-0123456789ab-0123456789abcdefghijklmnZZZ",
			want: "*********************************************",
		},
		{
			// The hyphen is not one of them, which is the cost stated in
			// builtin_slack_token.go: a run reaching past a token takes what
			// it reaches with it.
			name: "a hyphenated word",
			src:  "xoxb-0123456789ab-0123456789abcdefghijklmn-backup",
			want: "*************************************************",
		},
	}

	m := New(WithPatterns(SlackToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_slackTokenPrefixes(t *testing.T) {
	// The scan finds candidate positions with one IndexByte and divides a body
	// into segments at one separator, so a prefix not opening with that byte
	// is one the scan never reaches, and one not closing with the separator
	// would have its last characters read as the opening of a body. Neither
	// shows as a failing case: the pattern would quietly stop locating that
	// kind of token, or start locating it a few characters short.
	if len(slackTokenPrefixes) == 0 {
		t.Fatal("no prefix is documented, so the pattern locates nothing")
	}
	for _, prefix := range slackTokenPrefixes {
		t.Run(prefix, func(t *testing.T) {
			if prefix == "" || prefix[0] != slackTokenFirstByte {
				t.Errorf("the prefix does not open with %q, which is what the scan searches for", slackTokenFirstByte)
			}
			if prefix == "" || prefix[len(prefix)-1] != slackTokenSeparator {
				t.Errorf("the prefix does not close with %q, so a body would not begin at a segment", slackTokenSeparator)
			}
		})
	}

	// And no two of them match at the same position. slackTokenPrefixAt takes
	// the first that does, so a table where one prefix opened another would
	// have its order decide which, silently and only for that pair.
	for i, prefix := range slackTokenPrefixes {
		for j, other := range slackTokenPrefixes {
			if i != j && strings.HasPrefix(other, prefix) {
				t.Errorf("the prefix %q opens %q, so which of them is read depends on the order of the table", prefix, other)
			}
		}
	}
}

func Test_slackTokenPrefixes_bodyNeverMovesBack(t *testing.T) {
	// The scan keeps one run cursor for every candidate, and reuses it
	// wherever a body begins inside the run already read. That is sound only
	// while a body never begins in front of the body of the candidate before
	// it: were one to, the cursor would answer for a stretch of run it had
	// never looked at, and a token there would be missed rather than
	// mislocated.
	//
	// A candidate can begin d characters into a prefix only where the two
	// agree over what they share, and its body then begins d+len(other)
	// characters along. So the table is safe exactly while no prefix reaches
	// past that, which is checked here over every pair and every offset rather
	// than argued about for the pair that happens to exist today.
	for _, prefix := range slackTokenPrefixes {
		for d := 1; d < len(prefix); d++ {
			for _, other := range slackTokenPrefixes {
				rest := prefix[d:]
				if !strings.HasPrefix(rest, other) && !strings.HasPrefix(other, rest) {
					continue
				}
				if len(prefix) > d+len(other) {
					t.Errorf("a %q beginning %d characters into a %q starts a body %d characters in front of it",
						other, d, prefix, len(prefix)-d-len(other))
				}
			}
		}
	}
}

func Test_slackTokenByteClasses(t *testing.T) {
	// The three classes are what the pattern is widest on, so each is stated
	// over every byte rather than by example. They nest: a letter is a word
	// byte, a word byte is a body byte, and the separator is what the body
	// adds. What each of them turns away is in builtin_slack_token.go.
	for c := range 256 {
		b := byte(c)
		letter := 'A' <= b && b <= 'Z' || 'a' <= b && b <= 'z'
		word := letter || '0' <= b && b <= '9'
		body := word || b == '-'

		if got := isSlackTokenLetterByte(b); got != letter {
			t.Errorf("isSlackTokenLetterByte(%q) = %v, want %v", b, got, letter)
		}
		if got := isSlackTokenWordByte(b); got != word {
			t.Errorf("isSlackTokenWordByte(%q) = %v, want %v", b, got, word)
		}
		if got := isSlackTokenByte(b); got != body {
			t.Errorf("isSlackTokenByte(%q) = %v, want %v", b, got, body)
		}
	}

	// The underscore is the byte the three classes turn on. It is not a word
	// byte, so a token may be written against one; it is not a body byte, so
	// one behind a token ends it. A pattern reading a word boundary in front
	// would have it the other way round on both counts.
	if isSlackTokenWordByte('_') || isSlackTokenByte('_') {
		t.Error("the underscore is read as part of a token")
	}

	// And the dot, which stands in front of the prefix of a rotatable access
	// token rather than inside a body. Admitting it would draw a host name
	// written after a token into the span.
	if isSlackTokenWordByte('.') || isSlackTokenByte('.') {
		t.Error("the dot is read as part of a token")
	}
}

// referenceSlackTokenFind locates tokens the plain way: every position in turn,
// each prefix tried at it, and the run behind it walked segment by segment,
// with no cursor and nothing remembered between candidates. The first segment
// is skipped rather than measured, which is the demand for a part in front of
// the secret written the way a walk states it — the scan states the same thing
// as a comparison against a remembered offset. The prefixes, the count and the
// character classes are spelled again here rather than shared with the scan. A
// reference reading those declarations could not disagree with it about them,
// and it is exactly that disagreement the fuzz target below is for: the two
// have to be changed together or reported apart.
//
// Every position is a starting point in its own right, a match included,
// because a body is read as far as its alphabet runs and that alphabet holds
// the letters of a prefix: xoxb-xoxb-... holds a token beginning inside the
// match before it, and a rotatable access token holds the bot token it is
// written from. The scan finds both and reports the two spans overlapping for a
// Masker to resolve, so the reference must ask about both.
//
// Walking the run at every position is what the cursor saves the scan from, so
// this costs time quadratic in the length of a run a prefix can be written
// inside. That is the price of a reference with no cursor to be wrong about,
// and the reason the seeds below keep such a run to sixty bytes rather than
// inviting the mutator to grow it. Test_builtins_scanIsLinear is where the cost
// the scan pays is held down.
func referenceSlackTokenFind(src string) []Span {
	const secretChars = 18
	prefixes := []string{"xoxe.xoxb-", "xoxe.xoxp-", "xoxb-", "xoxp-", "xoxe-", "xapp-", "xwfp-"}

	letter := func(c byte) bool { return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' }
	word := func(c byte) bool { return letter(c) || '0' <= c && c <= '9' }
	body := func(c byte) bool { return word(c) || c == '-' }

	var spans []Span
	for start := range len(src) {
		if start > 0 && word(src[start-1]) {
			continue
		}
		from := -1
		for _, prefix := range prefixes {
			if strings.HasPrefix(src[start:], prefix) {
				from = start + len(prefix)
				break
			}
		}
		if from < 0 {
			continue
		}

		end := from
		for end < len(src) && body(src[end]) {
			end++
		}

		secret := false
		for i := from; i <= end; {
			j, holds := i, false
			for j < end && src[j] != '-' {
				if letter(src[j]) {
					holds = true
				}
				j++
			}
			if i > from && holds && j-i >= secretChars {
				secret = true
			}
			i = j + 1
		}
		if secret {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
}

// FuzzSlackToken_matchesReference guards the hand-written scan: the run cursor
// it keeps, the rightmost secret it remembers along with that run, the byte it
// reads in front of a prefix, the order it reads the prefixes in and the byte
// it resumes at may none of them change which tokens are located.
//
// The seeds spell each prefix once and then the edges the two demands and the
// cursor live on — a body opening straight onto a separator, a long part with
// no letter in it, a secret with a part in front of it and one without, a
// prefix closing a word, a prefix written inside a body, and a run of prefixes
// with a secret at the end of it and without one. There is no checked-in
// corpus for this target, so what the seeds reach is all a cold run starts
// from.
func FuzzSlackToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("SLACK_BOT_TOKEN=xoxb-0123456789ab-0123456789abc-0123456789abcdefghijklmn")
	f.Add("xoxb-0123456789ab-0123456789abcdefgh") // a secret of exactly eighteen
	f.Add("xoxb-0123456789ab-0123456789abcdefg")  // one character short of one
	f.Add("xoxb-0123456789abcdefgh")              // a secret with no part in front of it
	f.Add("xoxb-1-0123456789abcdefgh")            // and the shortest part there is
	f.Add("xoxb-0123456789abcdefgh-1")            // a part behind it rather than in front
	f.Add("xoxb-012345678901234567")              // eighteen with no letter in it
	f.Add("xoxb-01234567890123456a")              // and the same with one at the end
	f.Add("xoxb-a12345678901234567")              // and at the start
	f.Add("xoxb-")
	f.Add("xoxp-0123456789abcdefgh")
	f.Add("xoxe-1-0123456789abcdefgh")
	f.Add("xapp-1-A0-0123456789abcdefgh")
	f.Add("xwfp-0123456789abcdefgh")
	f.Add("xoxe.xoxb-1-0123456789abcdefgh") // located at both of its prefixes
	f.Add("xoxe.xoxp-1-0123456789abcdefgh") // and the user kind of the same
	f.Add("xoxe.xoxe.xoxb-1-0123456789abcdefgh")
	f.Add("xoxe.0123456789abcdefgh")                     // the rotation prefix opening nothing
	f.Add("xoxa-2-0123456789abcdefgh")                   // a prefix slack no longer documents
	f.Add("xoxo-0123456789abcdefgh")                     // and the one that is a word
	f.Add("XOXB-0123456789abcdefgh")                     // the prefixes are read in lowercase
	f.Add("xapp-frontend-integration-tests")             // hyphens with no secret between them
	f.Add("xapp-8f14e45fceea167a5a36dedd4bea2543")       // a digest against the prefix
	f.Add("xapp-build-8f14e45fceea167a5a36dedd4bea2543") // and the same behind a part
	f.Add("linuxapp-build-8f14e45fceea167a5a36dedd4bea2543")
	f.Add("xapp-trace-1705311000123456789")
	f.Add("xoxb--0123456789abcdefgh")       // an empty segment in front of the secret
	f.Add("xoxb-0123456789abcdefgh--")      // and two behind it
	f.Add("xoxb-0123456789abcdefgh-backup") // a word the run reaches over
	f.Add("xoxb-0123456789abcdefgh.example.com")
	f.Add("xoxb-0123456789abcdefgh_x")
	f.Add("xxoxb-0123456789abcdefgh")     // a prefix that closes a word
	f.Add("1xoxb-0123456789abcdefgh")     // and one against a digit
	f.Add("_xoxb-0123456789abcdefgh")     // where an underscore opens one
	f.Add("xoxbxoxb-0123456789abcdefgh")  // a prefix that is not one
	f.Add("xoxb-xoxb-0123456789abcdefgh") // a token beginning inside the one before it
	f.Add(strings.Repeat("xoxb-", 12))    // candidates crowded in one run, with no secret
	f.Add(strings.Repeat("xoxb-", 12) + "0123456789abcdefgh")

	fuzzAgainstReference(f, SlackToken().Find, referenceSlackTokenFind)
}
