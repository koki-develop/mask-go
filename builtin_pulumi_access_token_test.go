package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Pulumi access token pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. A body is forty hexadecimal characters, which is
// 0123456789abcdef twice over and eight more, so with the prefix in front a
// token is forty-four. Where a case is about the alphabet a body is written in,
// it carries the same ordered characters spelled uppercase or spelled past f
// instead.

func Test_PulumiAccessToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "pul-0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}},
		},
		{
			name: "a token in an environment assignment",
			src:  "PULUMI_ACCESS_TOKEN=pul-0123456789abcdef0123456789abcdef01234567",
			want: []Span{{20, 64}},
		},
		{
			name: "a token in the header the api reads it from",
			src:  "Authorization: token pul-0123456789abcdef0123456789abcdef01234567",
			want: []Span{{21, 65}},
		},
		{
			// The count is read exactly, so what follows the forty-fourth
			// character is not part of the token and stays in the text.
			name: "a body run longer than the count is a token and what follows it",
			src:  "pul-0123456789abcdef0123456789abcdef012345670",
			want: []Span{{0, 44}},
		},
		{
			// Neither token is inside the other, and nothing separates them.
			name: "two tokens with nothing between them",
			src:  "pul-0123456789abcdef0123456789abcdef01234567pul-0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}, {44, 88}},
		},
		{
			// The candidate the scan resuming a byte along is for. The first
			// prefix opens a candidate whose body would begin with the p of the
			// second, which no body may hold; the whole token stands at the
			// second. A scan resuming past the length the first candidate hoped
			// for would step over it.
			name: "a prefix written in front of a token",
			src:  "pul-pul-0123456789abcdef0123456789abcdef01234567",
			want: []Span{{4, 48}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PulumiAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PulumiAccessToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "pul-",
		},
		{
			name: "a body one character short",
			src:  "pul-0123456789abcdef0123456789abcdef0123456",
		},
		{
			name: "a body carrying a space",
			src:  "pul-0123456789abcdef 123456789abcdef01234567",
		},
		{
			name: "a body carrying a hyphen",
			src:  "pul-0123456789abcdef-123456789abcdef01234567",
		},
		{
			name: "a body carrying an underscore",
			src:  "pul-0123456789abcdef_123456789abcdef01234567",
		},
		{
			name: "a body carrying a dot",
			src:  "pul-0123456789abcdef.123456789abcdef01234567",
		},
		{
			name: "an uppercase prefix",
			src:  "PUL-0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "the prefix without the hyphen closing it",
			src:  "pul0123456789abcdef0123456789abcdef012345678",
		},
		{
			name: "an underscore where the prefix closes",
			src:  "pul_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "the prefix without its middle letter",
			src:  "pl-0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a body of the right length opening with no prefix",
			src:  "xxxx0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a bare sha-1 with no prefix",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
		{
			// The word the vendor's own name is spelled with opens with the
			// three letters of the prefix, so it is what most often reaches the
			// byte the scan searches for; the hyphen closing the prefix is what
			// turns it away.
			name: "the command line a stack is updated from",
			src:  "pulumi up --yes --stack acme/website/prod",
		},
		{
			name: "the host a token authenticates against",
			src:  "PULUMI_BACKEND_URL=https://api.pulumi.com",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PulumiAccessToken().Find(tt.src); got != nil {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PulumiAccessToken_inContext(t *testing.T) {
	// The places a token is written: the environment every Pulumi tool reads
	// one from, the header the REST API takes it in, the credentials file the
	// CLI stores it in and the command lines that pass it along.
	const token = "pul-0123456789abcdef0123456789abcdef01234567"

	tests := []struct {
		name  string
		src   string
		start int
	}{
		{
			name:  "a token in a dotenv line",
			src:   "PULUMI_ACCESS_TOKEN=" + token,
			start: 20,
		},
		{
			name:  "a token in the authorization header",
			src:   "Authorization: token " + token,
			start: 21,
		},
		{
			name:  "a token on a curl command line",
			src:   `curl -H "Authorization: token ` + token + `" https://api.pulumi.com/api/user`,
			start: 30,
		},
		{
			name:  "a token in the credentials file the cli writes",
			src:   `{"current":"https://api.pulumi.com","accessTokens":{"https://api.pulumi.com":"` + token + `"}}`,
			start: 78,
		},
		{
			name:  "a token in the yaml a deployment runner is configured with",
			src:   "    token: " + token,
			start: 11,
		},
		{
			name:  "a token in the json a token exchange returns",
			src:   `{"accessToken":"` + token + `","tokenType":"Bearer"}`,
			start: 16,
		},
		{
			name:  "a token at the end of a sentence",
			src:   "the token is " + token + ".",
			start: 13,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := []Span{{tt.start, tt.start + len(token)}}
			if got, _ := PulumiAccessToken().Find(tt.src); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, want)
			}
		})
	}
}

func Test_PulumiAccessToken_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match. A word boundary in front
	// would drop the whole match rather than trim it wherever a token is
	// written against a word character, and one behind it would drop a token
	// followed by a character of the body's own alphabet.
	const token = "pul-0123456789abcdef0123456789abcdef01234567"

	tests := []struct {
		name  string
		src   string
		start int
	}{
		{
			name:  "a token after an underscore",
			src:   "PULUMI_ACCESS_TOKEN_" + token,
			start: 20,
		},
		{
			name:  "a token after a letter",
			src:   "x" + token,
			start: 1,
		},
		{
			name:  "a word written against a token",
			src:   token + "suffix",
			start: 0,
		},
		{
			name:  "a hyphenated word written against a token",
			src:   token + "-suffix",
			start: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := []Span{{tt.start, tt.start + len(token)}}
			if got, _ := PulumiAccessToken().Find(tt.src); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, want)
			}
		})
	}
}

func Test_PulumiAccessToken_leavesWhatFollowsAlone(t *testing.T) {
	// A token is forty-four characters and no more, so what is written after
	// one stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the token is pul-0123456789abcdef0123456789abcdef01234567.",
			want: "the token is ********************************************.",
		},
		{
			name: "quoted",
			src:  `"pul-0123456789abcdef0123456789abcdef01234567"`,
			want: `"********************************************"`,
		},
		{
			// The hyphen belongs to the body's alphabet no more than an
			// uppercase letter does, however much of the prefix is written with
			// one, so a hyphenated word against a token is left where it
			// stands.
			name: "dashed word",
			src:  "pul-0123456789abcdef0123456789abcdef01234567-suffix",
			want: "********************************************-suffix",
		},
		{
			// A letter past f is no body character either, so an ordinary word
			// written against a token survives it whole.
			name: "a word past f",
			src:  "pul-0123456789abcdef0123456789abcdef01234567suffix",
			want: "********************************************suffix",
		},
		{
			// And a character the alphabet does admit: the count is what ends a
			// token, so the digit stays in the text rather than joining it.
			name: "a digit written against a token",
			src:  "pul-0123456789abcdef0123456789abcdef012345678",
			want: "********************************************8",
		},
	}

	m := New(WithPatterns(PulumiAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PulumiAccessToken_anUppercaseBody(t *testing.T) {
	// Half of the alphabet decision builtin_pulumi_access_token.go argues: the
	// body is lowercase hexadecimal, which is what every published rule reading
	// this format asks for and what a hexadecimal encoder settles once for the
	// whole of its output. Admitting the other case is the widening declined,
	// and this is what pins it.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "an uppercase body",
			src:  "pul-0123456789ABCDEF0123456789ABCDEF01234567",
		},
		{
			name: "one uppercase character in a body",
			src:  "pul-0123456789abcdef0123456789abcdef0123456F",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PulumiAccessToken().Find(tt.src); got != nil {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PulumiAccessToken_aBodyPastHexadecimal(t *testing.T) {
	// The other half of it: trufflehog reads this count through a class holding
	// every lowercase letter, where the two rules beside it read hexadecimal.
	// The wider class is the widening declined, and these are the bodies it
	// would have admitted.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a body carrying letters past f",
			src:  "pul-0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "one letter past f in a body",
			src:  "pul-0123456789abcdef0123456789abcdef0123456g",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PulumiAccessToken().Find(tt.src); got != nil {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PulumiAccessToken_aBodyBelowTheEntropyFloors(t *testing.T) {
	// The third tightening on offer and the one builtin_pulumi_access_token.go
	// declines with the other two: two of the three rules reading this format
	// ask that a body be irregular enough to have been drawn at random, and a
	// body regular enough to fail that is located here all the same. These are
	// the bodies the floors would have turned away.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a body of one character repeated",
			src:  "pul-0000000000000000000000000000000000000000",
			want: []Span{{0, 44}},
		},
		{
			name: "a body carrying no digit at all",
			src:  "pul-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			want: []Span{{0, 44}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PulumiAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PulumiAccessToken_noTokenBeginsInsideAnother(t *testing.T) {
	// The claim builtin_pulumi_access_token.go makes: the spans of this pattern
	// never overlap one another. Everything a span covers past the prefix is a
	// hexadecimal digit, and the prefix opens with a p that neither of the two
	// letters behind it is, that the hyphen closing it is not and that no body
	// may hold, so no position inside a span opens a prefix.
	//
	// It is not a claim one input can state, so a whole token is written into
	// every position of another here — at each character of its prefix, at each
	// character of its body and against either end — with nothing, a body and a
	// second token behind it in turn. What is asserted is only that no two
	// spans overlap; where the tokens fall is what the table at the top of this
	// file is for.
	body := strings.Repeat("0123456789abcdef", 2) + "01234567"
	token := pulumiAccessTokenPrefix + body
	p := PulumiAccessToken()

	for i := range len(token) + 1 {
		for _, tail := range []string{"", body, token} {
			src := token[:i] + token + token[i:] + tail
			spans, _ := p.Find(src)
			for j, got := range spans {
				if j > 0 && got.Start < spans[j-1].End {
					t.Errorf("Find(%q) = %v, which holds two values overlapping", src, spans)
					break
				}
			}
		}
	}
}

func Test_PulumiAccessToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision this format pays for rather than ruling out. Everything
	// behind the prefix is one class and a lowercase digest is written in it,
	// so the count is the whole of what tells the two apart: an MD5 is
	// thirty-two characters and is turned away, a SHA-1 is forty and is a
	// token's format character for character, and a SHA-256 is sixty-four, of
	// which the first forty are a body.
	//
	// The last case is the one the demand in front of a match would have turned
	// away, and is the false positive gitleaks carries a case for: a
	// content-addressed asset written as a word, a hyphen and a digest, where
	// the word ends in the letters the prefix opens with.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an md5 behind the prefix",
			src:  "pul-0123456789abcdef0123456789abcdef",
			want: nil,
		},
		{
			name: "a uuid behind the prefix",
			src:  "pul-01234567-89ab-cdef-0123-456789abcdef",
			want: nil,
		},
		{
			name: "a sha-1 behind the prefix",
			src:  "pul-0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 44}},
		},
		{
			name: "a sha-256 behind the prefix",
			src:  "pul-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 44}},
		},
		{
			name: "a word ending in the letters of the prefix in front of a digest",
			src:  "vipul-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.png",
			want: []Span{{2, 46}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PulumiAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_pulumiAccessTokenPrefix(t *testing.T) {
	// Two things about the prefix are load-bearing, and neither shows anywhere
	// else.
	//
	// It opens with a character no body is written with, and one it carries
	// nowhere else. That is the whole of the claim that no token can begin
	// inside another, which Test_PulumiAccessToken_noTokenBeginsInsideAnother
	// drives and which a prefix built any other way would make false without
	// failing there — the drive would pass on a pattern whose spans do overlap
	// somewhere it does not reach.
	//
	// And it closes with a character no body is written with, so a run of body
	// characters can never hold the prefix and every body begins where such a
	// run begins. That is not what bounds the scan — the count is — but it is
	// what a count relaxed to a floor would have to fall back on, which is why
	// it is held to here rather than worked out then.
	if pulumiAccessTokenPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}

	opening := pulumiAccessTokenPrefix[0]
	if isPulumiAccessTokenBodyByte(opening) {
		t.Errorf("the prefix opens with %q, which a body may be written with", opening)
	}
	if i := strings.IndexByte(pulumiAccessTokenPrefix[1:], opening); i >= 0 {
		t.Errorf("the prefix carries %q again at %d, so a prefix can open inside one", opening, i+1)
	}
	if c := pulumiAccessTokenPrefix[len(pulumiAccessTokenPrefix)-1]; isPulumiAccessTokenBodyByte(c) {
		t.Errorf("the prefix closes with %q, which a body may be written with", c)
	}
}

// Test_pulumiAccessTokenAnchor holds the prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_pulumiAccessTokenAnchor(t *testing.T) {
	if pulumiAccessTokenAnchorIndex >= len(pulumiAccessTokenPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", pulumiAccessTokenAnchorIndex, len(pulumiAccessTokenPrefix))
	}
	if c := pulumiAccessTokenPrefix[pulumiAccessTokenAnchorIndex]; c != pulumiAccessTokenAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(pulumiAccessTokenAnchor))
	}

	// What the anchor costs, counted rather than claimed in prose. It stands
	// once in the prefix, so a run of prefixes stops the search once a prefix;
	// it is no character a body is written with, so a hexadecimal run stops it
	// not once however long it runs; and it is not the hyphen the prefix closes
	// with, which is the byte every ISO timestamp and every hyphenated word is
	// written with.
	if n := strings.Count(pulumiAccessTokenPrefix, string(pulumiAccessTokenAnchor)); n != 1 {
		t.Errorf("the anchor stands %d times in %q, want 1", n, pulumiAccessTokenPrefix)
	}
	if isPulumiAccessTokenBodyByte(pulumiAccessTokenAnchor) {
		t.Errorf("the anchor is %q, which a body may be written with", byte(pulumiAccessTokenAnchor))
	}
	if closing := pulumiAccessTokenPrefix[len(pulumiAccessTokenPrefix)-1]; pulumiAccessTokenAnchor == closing {
		t.Errorf("the anchor is the character the prefix closes with, %q, which ordinary text is written with", closing)
	}
}

func Test_pulumiAccessTokenChars(t *testing.T) {
	// The prefix Pulumi publishes and the count every rule reading this format
	// asks for. Four characters and forty make a token of forty-four.
	if got := len(pulumiAccessTokenPrefix); got != 4 {
		t.Errorf("len(pulumiAccessTokenPrefix) = %d, want 4", got)
	}
	if got := pulumiAccessTokenBodyChars; got != 40 {
		t.Errorf("pulumiAccessTokenBodyChars = %d, want 40", got)
	}
	if got := pulumiAccessTokenChars; got != 44 {
		t.Errorf("pulumiAccessTokenChars = %d, want 44", got)
	}
}

func Test_isPulumiAccessTokenBodyByte(t *testing.T) {
	// The lowercase hexadecimal digits and nothing else, stated over every byte
	// rather than by example. Neither the uppercase half nor the letters past f
	// is admitted, which builtin_pulumi_access_token.go weighs.
	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9' || 'a' <= b && b <= 'f'
		if got := isPulumiAccessTokenBodyByte(b); got != want {
			t.Errorf("isPulumiAccessTokenBodyByte(%q) = %v, want %v", b, got, want)
		}
	}
}

func Test_isPulumiAccessTokenBody(t *testing.T) {
	// The count and the character class together, stated over every byte rather
	// than by example.
	body := strings.Repeat("a", pulumiAccessTokenBodyChars)

	if !isPulumiAccessTokenBody(body) {
		t.Errorf("isPulumiAccessTokenBody(%q) = false, want a body of %d characters to be one", body, pulumiAccessTokenBodyChars)
	}
	for _, s := range []string{body[:len(body)-1], body + "a"} {
		if isPulumiAccessTokenBody(s) {
			t.Errorf("isPulumiAccessTokenBody(%q) = true, want only %d characters to be a body", s, pulumiAccessTokenBodyChars)
		}
	}

	for i := range pulumiAccessTokenBodyChars {
		for c := range 256 {
			b := byte(c)
			src := body[:i] + string([]byte{b}) + body[i+1:]
			if got, want := isPulumiAccessTokenBody(src), isPulumiAccessTokenBodyByte(b); got != want {
				t.Errorf("isPulumiAccessTokenBody(%q) = %v with %q at %d, want %v", src, got, b, i, want)
			}
		}
	}
}

// referencePulumiAccessToken is the expression the scan in
// builtin_pulumi_access_token.go reads by hand: the statement of what a Pulumi
// access token is, kept here so that the scan can be held to it.
//
// The prefix, the count and the character class are spelled again rather than
// built from pulumiAccessTokenPrefix, pulumiAccessTokenBodyChars and
// isPulumiAccessTokenBodyByte. A reference sharing those declarations could not
// disagree with the scan about them, and it is exactly that disagreement the
// fuzz target below is for: the two have to be changed together or reported
// apart.
//
// The counted repetition here is exact, so the machine an engine builds for a
// candidate is forty states wide and is read once and stops, and the prefix in
// front of it is one literal, which is what an engine searches the text for.
// That is what lets this reference be an expression at all, where the Anthropic
// one is written out for a floor spelled as a counted repetition and the Notion
// one for an alternation of two literals.
var referencePulumiAccessToken = regexp.MustCompile(`pul-[0-9a-f]{40}`)

// referencePulumiAccessTokenFind locates tokens the plain way: the leftmost
// match of the expression above, then the leftmost one beginning after that
// match's first byte, over and over, with nothing remembered between them.
//
// Asking at every byte rather than resuming past a match is what the scan does.
// No token can be written inside another here, which the scan claims and
// builtin_pulumi_access_token.go argues, and a reference is written to know
// nothing its scan claims — so the reference asks anyway, and the target below
// is what holds the claim to being true rather than assumed on both sides.
func referencePulumiAccessTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referencePulumiAccessToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzPulumiAccessToken_matchesReference guards the hand-written scan: the
// prefix it searches for, the case it reads that prefix in, the count it reads
// behind it, the alphabet it reads that count in and the byte it resumes at may
// none of them change which tokens are located.
func FuzzPulumiAccessToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("PULUMI_ACCESS_TOKEN=pul-0123456789abcdef0123456789abcdef01234567")
	f.Add("pul-0123456789abcdef0123456789abcdef012345")    // a body two short
	f.Add("pul-0123456789abcdef0123456789abcdef0123456")   // and one short
	f.Add("pul-0123456789abcdef0123456789abcdef012345678") // and one long
	f.Add("pul-0123456789abcdef 123456789abcdef01234567")
	f.Add("pul-0123456789abcdef-123456789abcdef01234567")
	f.Add("pul-0123456789abcdef_123456789abcdef01234567")
	f.Add("pul-0123456789abcdef\n123456789abcdef01234567")
	f.Add("pul-0123456789ABCDEF0123456789ABCDEF01234567") // an uppercase body
	f.Add("pul-0123456789abcdefghijklmnopqrstuvwxyz0123") // letters past f
	f.Add("PUL-0123456789abcdef0123456789abcdef01234567") // an uppercase prefix
	f.Add("pul0123456789abcdef0123456789abcdef012345678") // no hyphen closing it
	f.Add("pul_0123456789abcdef0123456789abcdef01234567") // an underscore closing it
	f.Add("xpul-0123456789abcdef0123456789abcdef01234567")
	// The digests and the UUID the count and the alphabet are read against,
	// and the word ending in the letters the prefix opens with.
	f.Add("pul-0123456789abcdef0123456789abcdef")
	f.Add("pul-01234567-89ab-cdef-0123-456789abcdef")
	f.Add("pul-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("vipul-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.png")
	f.Add("0123456789abcdef0123456789abcdef01234567")
	// The bodies the entropy floors two of those rules carry would have turned
	// away, and this scan reads.
	f.Add("pul-0000000000000000000000000000000000000000")
	f.Add("pul-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	// A prefix in front of a token, two tokens with nothing between them, and
	// candidate positions crowded as close as they can be.
	f.Add("pul-pul-0123456789abcdef0123456789abcdef01234567")
	f.Add("pul-0123456789abcdef0123456789abcdef01234567pul-0123456789abcdef0123456789abcdef01234567")
	f.Add(strings.Repeat("pul-", 64))
	f.Add(strings.Repeat("pul-", 64) + "0123456789abcdef0123456789abcdef01234567")
	f.Add(strings.Repeat("pul-0123456789abcdef0123456789abcdef01234567", 4))
	f.Add(strings.Repeat("-", 128))
	f.Add(strings.Repeat("u", 128))
	f.Add("pulumi login --cloud-url https://api.pulumi.com")

	fuzzAgainstReference(f, PulumiAccessToken().Find, referencePulumiAccessTokenFind)
}

// pulumiAccessTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func pulumiAccessTokenFindBenchmarks() []benchmarkCase {
	// The line the anchor is chosen against: the u stands five times on it, the
	// l four and the p six, and the word Pulumi's own host name is spelled with
	// carries two of the five. Nothing on it opens the prefix, so what the line
	// times is the search for the anchor, which is most of what this pattern
	// costs a caller whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="updating stack" org=acme stack=prod url=https://api.pulumi.com/api/user/stacks `
	token := "pul-0123456789abcdef0123456789abcdef01234567"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is four characters carrying the anchor once, so a run
			// of them holds a candidate for every four it has. Each is turned
			// away by the first byte of the body it never had, since the p
			// opening the next prefix is not one a body may hold — which is the
			// cheapest this scan declines a candidate for once the prefix has
			// been read.
			name:  "candidates that are not values",
			src:   strings.Repeat("pul-", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads a prefix, since the byte in front of each
			// is the anchor rather than the p. That is one comparison a stop,
			// and the cheapest a stop is answered for at all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("u", 4096),
			spans: 0,
		},
		{
			// The way a candidate is walked furthest: a body of the right
			// length whose last character is a letter past f, so the whole of
			// it is walked before the candidate is turned away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("pul-0123456789abcdef0123456789abcdef0123456g ", 16),
			spans: 0,
		},
		{
			// A hexadecimal run, which is what a digest and an identifier are
			// written in and carries no character of the prefix at all, so the
			// search walks the whole of it in one pass.
			name:  "a run of the body alphabet",
			src:   strings.Repeat("0123456789abcdef", 256),
			spans: 0,
		},
		{
			// The class the widening on offer would have read a body in, which
			// reaches the anchor where hexadecimal does not: a run of it stops
			// the search once every thirty-six characters, and each stop is
			// turned away by the one byte in front of it.
			name:  "a run of the wider alphabet the widening would admit",
			src:   strings.Repeat("0123456789abcdefghijklmnopqrstuvwxyz", 128),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "token=" + token,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "token=" + token,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"token="+token+"\n", 32),
			spans: 32,
		},
	}
}
