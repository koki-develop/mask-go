package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The SendGrid API key pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The keys written out below are made only of ordered characters: valid in
// shape, obviously not real. The identifier is 0123456789abcdefghijkl, which is
// twenty-two characters and so is a whole one, and the secret is
// 0123456789abcdefghijklmnopqrstuvwxyzABCDEFG, which is forty-three and so is a
// whole one too. Written out with the prefix and the dot between them they come
// to the sixty-nine characters SendGrid states a key always is.

func Test_SendGridAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: []Span{{0, 69}},
		},
		{
			name: "a key in an environment assignment",
			src:  "SENDGRID_API_KEY=SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: []Span{{17, 86}},
		},
		{
			// The hyphen and the underscore are base64url characters, and
			// every rule here that spells a class admits both of them.
			name: "an identifier and a secret carrying a hyphen and an underscore",
			src:  "SG.0123456789abcdef-hij_l.0123456789abcdefghijklmnopqrstuvwxy-ABCDE_G",
			want: []Span{{0, 69}},
		},
		{
			// The counts are read exactly, so what follows the sixty-ninth
			// character is not part of the key and stays in the text.
			name: "an alphabet run longer than the secret is a key and what follows it",
			src:  "SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH",
			want: []Span{{0, 69}},
		},
		{
			// Neither key is inside the other, and nothing separates them.
			name: "two keys with nothing between them",
			src:  "SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGSG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: []Span{{0, 69}, {69, 138}},
		},
		{
			// A secret closing with SG opens a candidate two characters before
			// the key ends: the dot it wants is the one written after the key,
			// and a second key's identifier, dot and secret follow it. A scan
			// resuming past a match would step over that key and leave it in
			// the output whole. The spans overlap, which a Masker resolves into
			// one.
			name: "a key beginning inside the key before it",
			src:  "SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDESG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: []Span{{0, 69}, {67, 136}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SendGridAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SendGridAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "SG.",
		},
		{
			name: "an identifier with no secret behind it",
			src:  "SG.0123456789abcdefghijkl",
		},
		{
			name: "an identifier and a dot with no secret behind them",
			src:  "SG.0123456789abcdefghijkl.",
		},
		{
			// Twenty-one characters where the pattern asks for twenty-two, and
			// so a dot one character too early.
			name: "an identifier one character too short",
			src:  "SG.0123456789abcdefghijk.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			// Twenty-three, and so a dot one character too late.
			name: "an identifier one character too long",
			src:  "SG.0123456789abcdefghijklm.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			name: "a secret one character too short",
			src:  "SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEF",
		},
		{
			// The dot is the one character of the format that is not in the
			// alphabet, so nothing else divides the two segments.
			name: "a hyphen where the separator belongs",
			src:  "SG.0123456789abcdefghijkl-0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			name: "an underscore where the separator belongs",
			src:  "SG.0123456789abcdefghijkl_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			// A space is a non-alphabet, non-separator byte terminating the
			// identifier run at exactly twenty-two — the position the
			// separator itself stands at.
			name: "a space where the separator belongs",
			src:  "SG.0123456789abcdefghijkl 0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			// The excluded byte at the very first character of the
			// identifier, with the rest of the shape otherwise intact.
			name: "a plus at the first character of the identifier",
			src:  "SG.+123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			name: "a second dot at the first character of the identifier",
			src:  "SG..123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			name: "a hyphen where the prefix carries its dot",
			src:  "SG-0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			// A second dot inside the secret. The alphabet holds no dot, so the
			// run ends there and forty-three characters are not reached.
			name: "a dot inside the secret",
			src:  "SG.0123456789abcdefghijkl.0123456789abcdefghij.lmnopqrstuvwxyzABCDEFG",
		},
		{
			// Standard base64 rather than base64url: the two characters
			// base64url writes as - and _ are + and /, and neither belongs to
			// the alphabet a segment is read in.
			name: "a plus in the identifier",
			src:  "SG.0123456789abcdef+hijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			name: "a slash in the secret",
			src:  "SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyz/BCDEFG",
		},
		{
			// Padding does not arise: twenty-two and forty-three are the
			// unpadded lengths of sixteen bytes and of thirty-two. gitleaks
			// admits = behind the prefix all the same; this pattern does not.
			name: "an equals sign in the secret",
			src:  "SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEF=",
		},
		{
			name: "a secret broken by a space",
			src:  "SG.0123456789abcdefghijkl.0123456789abcdefghijkl nopqrstuvwxyzABCDEFG",
		},
		{
			name: "a key broken by a line break",
			src:  "SG.0123456789abcdefghijkl.\n123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			name: "a lowercase prefix",
			src:  "sg.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			// Sixty-nine characters of the right shape opening with something
			// else. The prefix is the whole of the anchor.
			name: "a value of the right shape opening with no prefix",
			src:  "XY.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// Forty hexadecimal characters. A digest carries no dot, so it
			// holds no prefix to be found at however long it runs.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
		{
			// Neither base64 alphabet writes the dot the prefix closes with,
			// so a payload carrying the two letters a prefix opens with hands
			// them nowhere to close, however long the payload runs.
			name: "a base64url payload carrying the letters a prefix opens with",
			src:  "SG0123456789abcdefghijklSG0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		{
			name: "a base64 payload carrying them",
			src:  "SG0123456789abcdef+hijklSG0123456789abcdefghijklmnopqrstuvwxyz/BCDEFG",
		},
		{
			// A signed JWT is three dot-separated base64url segments, which is
			// this format's shape, and it holds no candidate: the header and
			// the payload are JSON, so the bytes each encodes close with a
			// brace, and base64url turns a final brace into 9, into 0 or into
			// fQ. The character in front of a token's dots is never the G a
			// candidate needs.
			name: "a jwt",
			src:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SendGridAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_SendGridAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "SENDGRID_API_KEY=SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: "SENDGRID_API_KEY=*********************************************************************",
		},
		{
			// How a key reaches the API, and how it reaches a log line that
			// echoed the header.
			name: "a bearer token header",
			src:  "Authorization: Bearer SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: "Authorization: Bearer *********************************************************************",
		},
		{
			// The SMTP password a key is used as, which SendGrid documents
			// beside the username apikey.
			name: "an smtp password",
			src:  "smtp://apikey:SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG@smtp.sendgrid.net:587",
			want: "smtp://apikey:*********************************************************************@smtp.sendgrid.net:587",
		},
		{
			name: "json",
			src:  `{"api_key":"SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"}`,
			want: `{"api_key":"*********************************************************************"}`,
		},
		{
			name: "twice",
			src:  "SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG SG.0123456789abcdef-hij_l.0123456789abcdefghijklmnopqrstuvwxy-ABCDE_G",
			want: "********************************************************************* *********************************************************************",
		},
		{
			// The two spans are merged, so the key that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a key beginning inside the key before it",
			src:  "SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDESG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: "****************************************************************************************************************************************",
		},
		{
			// A key immediately against a multi-byte rune on both sides. The
			// pattern reads no word boundary either side of a match, so the
			// key keeps its span.
			name: "between japanese",
			src:  "キーはSG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGです",
			want: "キーは*********************************************************************です",
		},
		{
			name: "between bytes that are not utf-8",
			src:  "\xffSG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG\xff",
			want: "\xff*********************************************************************\xff",
		},
	}

	m := New(WithPatterns(SendGridAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SendGridAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the key through whole. The first of them is also
	// what the tightening the Slack and Stripe scans take would cost here,
	// which builtin_sendgrid_api_key.go weighs against what it would buy.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "xSG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: "x*********************************************************************",
		},
		{
			name: "underscore before",
			src:  "SENDGRID_API_KEY_SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: "SENDGRID_API_KEY_*********************************************************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this key rather
			// than trim it; without one the sixty-nine characters SendGrid
			// issued are redacted and the one written after them, which is part
			// of no credential, stays in the text.
			name: "a character of the alphabet after",
			src:  "SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH",
			want: "*********************************************************************H",
		},
	}

	m := New(WithPatterns(SendGridAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SendGridAPIKey_leavesWhatFollowsAlone(t *testing.T) {
	// A key is sixty-nine characters and no more, so what is written after one
	// stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the key is SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG.",
			want: "the key is *********************************************************************.",
		},
		{
			name: "quoted",
			src:  `"SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"`,
			want: `"*********************************************************************"`,
		},
		{
			// The hyphen is a secret character, so a hyphenated word written
			// against a key is read as more of the secret and the count is what
			// ends the key rather than the hyphen.
			name: "dashed word",
			src:  "SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG-suffix",
			want: "*********************************************************************-suffix",
		},
	}

	m := New(WithPatterns(SendGridAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SendGridAPIKey_wordClosingOnThePrefix(t *testing.T) {
	// What this pattern redacts that nobody issued. SG. can close an ordinary
	// identifier — MSG., NSG., ESG. and PSG. each carry the whole prefix — so a
	// property chain whose first component is one of them, whose second is
	// exactly twenty-two characters of the alphabet and whose third is at least
	// forty-three, is redacted from its SG onward.
	//
	// They are held to being redacted rather than to being spared. Asking that
	// no letter and no digit stand in front of the prefix would turn all of
	// these away, and would leave a key written against a letter in the output
	// whole; builtin_sendgrid_api_key.go weighs the two. What this table is for
	// is that the cases move with the scan: one of them ceasing to be located
	// means the grammar changed, and that is a decision to be taken rather than
	// noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a property chain whose first component closes on the prefix",
			src:  "MSG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: "M*********************************************************************",
		},
		{
			// The rationale names four identifiers closing on the prefix;
			// only MSG. is driven above. The other three are here so that
			// each is on the record rather than assumed to follow from it.
			name: "a chain whose first component is NSG",
			src:  "NSG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: "N*********************************************************************",
		},
		{
			name: "a chain whose first component is ESG",
			src:  "ESG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: "E*********************************************************************",
		},
		{
			name: "a chain whose first component is PSG",
			src:  "PSG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: "P*********************************************************************",
		},
		{
			// The counts are what most of such a chain fails: the middle
			// component has to be exactly twenty-two characters.
			name: "the same chain with a component of another length",
			src:  "MSG.0123456789abcdefghij.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			want: "MSG.0123456789abcdefghij.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
	}

	m := New(WithPatterns(SendGridAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

// Test_SendGridAPIKey_retain holds the second return of Find to a literal
// offset, on the two shapes builtin_scan.go names: a piece of the prefix
// standing at the end of the input, and a candidate the end of the input cut
// short of the count.
func Test_SendGridAPIKey_retain(t *testing.T) {
	tests := []struct {
		name       string
		src        string
		wantRetain int
	}{
		{
			// The last two characters are "SG", a piece of the three-character
			// prefix "SG." cut short by the end of the input.
			name:       "a piece of the prefix standing at the end of the input",
			src:        "key SG",
			wantRetain: 4,
		},
		{
			// A whole prefix and identifier with the separator and a partial
			// secret behind it, all standing at the end of the input. More
			// characters arriving could still complete the key, so the
			// candidate is unsettled from its own start.
			name:       "a candidate the end of the input cut short of the count",
			src:        "SG.0123456789abcdefghijkl.0123456789",
			wantRetain: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := SendGridAPIKey().Find(tt.src)
			if len(got) != 0 {
				t.Fatalf("Find(%q) located %v, want no span", tt.src, got)
			}
			if retain != tt.wantRetain {
				t.Errorf("Find(%q) retain = %d, want %d", tt.src, retain, tt.wantRetain)
			}
		})
	}
}

func Test_sendGridAPIKeyPrefix(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a key can
	// begin inside the one before it, and that holds on what the prefix is made
	// of: the characters in front of its last one are ones a segment is written
	// with, and its last one is the separator a key already carries. A prefix
	// built any other way would make the two impossible to nest, and the case
	// above pinning the nesting would stand for nothing — which is not a
	// failure anything else here reports.
	if sendGridAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	if c := sendGridAPIKeyPrefix[len(sendGridAPIKeyPrefix)-1]; c != sendGridAPIKeySeparator {
		t.Errorf("the prefix closes with %q, want the separator %q", c, sendGridAPIKeySeparator)
	}
	for i := range len(sendGridAPIKeyPrefix) - 1 {
		if c := sendGridAPIKeyPrefix[i]; !isBase64URLByte(c) {
			t.Errorf("the prefix holds %q, which no segment may be written with", c)
		}
	}

	// The separator ends a segment where it stands, which is what makes the
	// count on either side of it readable at all.
	if isBase64URLByte(sendGridAPIKeySeparator) {
		t.Errorf("the separator %q belongs to the alphabet a segment is written in", sendGridAPIKeySeparator)
	}
}

// Test_sendGridAPIKeyAnchor holds the prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_sendGridAPIKeyAnchor(t *testing.T) {
	if sendGridAPIKeyAnchorIndex >= len(sendGridAPIKeyPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", sendGridAPIKeyAnchorIndex, len(sendGridAPIKeyPrefix))
	}
	if c := sendGridAPIKeyPrefix[sendGridAPIKeyAnchorIndex]; c != sendGridAPIKeyAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(sendGridAPIKeyAnchor))
	}
}

func Test_sendGridAPIKeyChars(t *testing.T) {
	// Sixty-nine is the one part of this grammar SendGrid states outright: a
	// support article on whether a shorter key can be issued says a key is
	// always this many characters. The two counts either side of the separator
	// come from the rulesets instead, so they are only as good as their total
	// agreeing with the number the vendor wrote down.
	const documented = 69
	if sendGridAPIKeyChars != documented {
		t.Errorf("a key is read as %d characters, SendGrid states %d", sendGridAPIKeyChars, documented)
	}
}

func Test_isSendGridAPIKeyBody(t *testing.T) {
	// The counts, the separator and the alphabet together, stated over every
	// byte rather than by example.
	id := strings.Repeat("a", sendGridAPIKeyIDChars)
	secret := strings.Repeat("b", sendGridAPIKeySecretChars)
	body := id + string(sendGridAPIKeySeparator) + secret

	if !isSendGridAPIKeyBody(body) {
		t.Errorf("isSendGridAPIKeyBody(%q) = false, want a body of %d characters to be one", body, sendGridAPIKeyBodyChars)
	}
	for _, s := range []string{body[:len(body)-1], body + "b"} {
		if isSendGridAPIKeyBody(s) {
			t.Errorf("isSendGridAPIKeyBody(%q) = true, want only %d characters to be a body", s, sendGridAPIKeyBodyChars)
		}
	}

	// Every position of the body, byte by byte: the separator's position admits
	// the separator alone, and every other position the alphabet alone.
	for i := range sendGridAPIKeyBodyChars {
		for c := range 256 {
			b := byte(c)
			src := body[:i] + string([]byte{b}) + body[i+1:]

			want := isBase64URLByte(b)
			if i == sendGridAPIKeyIDChars {
				want = b == sendGridAPIKeySeparator
			}
			if got := isSendGridAPIKeyBody(src); got != want {
				t.Errorf("isSendGridAPIKeyBody(%q) = %v with %q at %d, want %v", src, got, b, i, want)
			}
		}
	}
}

// referenceSendGridAPIKey is the expression the scan in
// builtin_sendgrid_api_key.go reads by hand: the statement of what a SendGrid
// API key is, kept here so that the scan can be held to it.
//
// The prefix, the two counts, the separator and the alphabet are spelled again
// rather than built from sendGridAPIKeyPrefix, sendGridAPIKeyIDChars,
// sendGridAPIKeySecretChars, sendGridAPIKeySeparator and isBase64URLByte. A
// reference sharing those declarations could not disagree with the scan about
// them, and it is exactly that disagreement the fuzz target below is for: the
// two have to be changed together or reported apart.
//
// The counted repetitions here are twenty-two and forty-three, so the machine
// an engine builds for a candidate is sixty-five states wide and bounded. That
// is what lets this reference be an expression at all, where the Anthropic one
// beside it is written out: a floor spelled as a counted repetition leaves an
// engine building a machine of that width and then running it over a run of any
// length, which is what wedged that target.
var referenceSendGridAPIKey = regexp.MustCompile(`SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}`)

// referenceSendGridAPIKeyFind locates keys the plain way: the leftmost match of
// the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a key can begin inside one: the two letters of
// the prefix belong to the alphabet a segment is written in and the dot behind
// them is the separator a key already carries, so a secret closing with SG
// opens a candidate the engine would never go on to try. The scan finds both
// and reports the two spans overlapping for a Masker to resolve, so the
// reference must ask about both.
//
// As in the AWS and Google references, resuming a byte along costs this one
// nothing beyond a constant: every candidate reads at most sixty-nine
// characters, here as in the scan, so neither has a run to walk and there is no
// cursor for either to be wrong about.
func referenceSendGridAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceSendGridAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzSendGridAPIKey_matchesReference guards the hand-written scan: the prefix
// it searches for, the two counts it reads behind that prefix, the separator
// between them, the alphabet it reads them in and the byte it resumes at may
// none of them change which keys are located.
func FuzzSendGridAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("SENDGRID_API_KEY=SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
	f.Add("SG.0123456789abcdef-hij_l.0123456789abcdefghijklmnopqrstuvwxy-ABCDE_G")  // a hyphen and an underscore in each segment
	f.Add("SG.0123456789abcdefghijk.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")   // an identifier one short
	f.Add("SG.0123456789abcdefghijklm.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG") // and one long
	f.Add("SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEF")   // a secret one short
	f.Add("SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH") // and a run longer than one
	f.Add("SG.0123456789abcdefghijkl-0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")  // a hyphen where the separator belongs
	f.Add("SG-0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")  // a hyphen where the prefix carries its dot
	f.Add("SG.0123456789abcdefghij.l.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")  // a dot inside the identifier
	f.Add("SG.0123456789abcdefghijkl.0123456789abcdefghij.lmnopqrstuvwxyzABCDEFG")  // and one inside the secret
	f.Add("SG.0123456789abcdef+hijkl.0123456789abcdefghijklmnopqrstuvwxyz/BCDEFG")  // standard base64 rather than base64url
	f.Add("SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEF=")  // padding, which no key carries
	f.Add("sg.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")  // a lowercase prefix
	f.Add("SG.0123456789abcdefghijkl.\n123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
	f.Add("MSG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
	// A key beginning inside the match before it, which a scan resuming past a
	// match steps over, and two keys with nothing between them, which is the
	// same text without the overlap.
	f.Add("SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDESG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
	f.Add("SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGSG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
	// Candidate positions crowded as close as they can be, and a run of
	// separators, which is where the count on either side of one is decided.
	f.Add(strings.Repeat("SG.", 32))
	f.Add(strings.Repeat("SG.", 32) + "0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
	f.Add(strings.Repeat("SG.0123456789abcdefghijkl.", 8))
	f.Add(strings.Repeat(".", 128))
	// A JWT, which is three dot-separated base64url segments as a key is, and
	// which carries no candidate because the base64url of a JSON object never
	// closes with SG.
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef")

	fuzzAgainstReference(f, SendGridAPIKey().Find, referenceSendGridAPIKeyFind)
}

// sendGridAPIKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func sendGridAPIKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="sending mail" url=https://api.sendgrid.com/v3/mail/send `
	key := "SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is three characters, so a run of them holds a
			// candidate for every three it has. Each of these is turned away by
			// the one comparison the separator's position costs, which is the
			// cheapest this scan declines a candidate for.
			name:  "candidates that are not values",
			src:   strings.Repeat("SG.", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: an identifier of the right
			// length and a separator where one belongs, so the whole of the
			// secret is walked before the count turns the candidate away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEF ", 16),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "key=" + key,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "key=" + key,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"key="+key+"\n", 32),
			spans: 32,
		},
	}
}
