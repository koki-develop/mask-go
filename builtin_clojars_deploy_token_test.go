package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Clojars deploy token pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a set
// of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. A body is sixty hexadecimal characters, written
// here as 0123456789abcdef three times over and then twelve more of the same
// run, which with the prefix in front comes to sixty-eight characters. Where a
// case turns on what stands at the first character of a body, that character is
// written first and the run follows it — three times over and eleven more,
// which is sixty again — so that the run stands unbroken behind the character
// the case is about rather than being cut in half by it.

func Test_ClojarsDeployToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{0, 68}},
		},
		{
			// The assignment a token is most often written in, and the reason
			// there is no word boundary in front of a match: the prefix Clojars
			// names its deploy environment variables with is the prefix a token
			// opens with, so a boundary here would drop the match rather than
			// trim it.
			name: "a token in an environment assignment",
			src:  "CLOJARS_PASSWORD=CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{17, 85}},
		},
		{
			// The count is read exactly, so what follows the sixty-eighth
			// character is not part of the token and stays in the text.
			name: "a run longer than the count is a token and what follows it",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
			want: []Span{{0, 68}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abCLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{0, 68}, {68, 136}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ClojarsDeployToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ClojarsDeployToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "CLOJARS_",
		},
		{
			name: "a body broken by a space",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef 123456789ab",
		},
		{
			name: "a hyphen in the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef-123456789ab",
		},
		{
			name: "an underscore in the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef_123456789ab",
		},
		{
			name: "a newline in the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef\n123456789ab",
		},
		{
			// The third of the three places gitleaks' rule is wider than the
			// vendor, which builtin_clojars_deploy_token.go's rationale names:
			// its (?i) reaches the prefix as well as the body, where Clojars
			// writes CLOJARS_ as a literal and asks for it case-sensitively.
			name: "a lowercase prefix",
			src:  "clojars_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
		},
		{
			name: "the prefix without its underscore",
			src:  "CLOJARS0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
		},
		{
			name: "a hyphen where the prefix writes its underscore",
			src:  "CLOJARS-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
		},
		{
			// The other names Clojars writes with this prefix, which is why an
			// uppercase letter behind the underscore has to end the reading.
			name: "the environment variable names the prefix also opens",
			src:  "CLOJARS_USERNAME=example CLOJARS_ENVIRONMENT=production",
		},
		{
			// The anchor standing nearer the start of the input than its index
			// in the prefix, so the candidate it would be read back from begins
			// in front of the input. A whole body stands behind it, which is
			// what makes the position the only thing turning the candidate
			// away.
			name: "a body behind an anchor with no room for a prefix in front of it",
			src:  "JARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
		},
		{
			name: "the same with one more character in front of the anchor",
			src:  "OJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ClojarsDeployToken().Find(tt.src); got != nil {
				t.Errorf("Find(%q) = %v, want none", tt.src, got)
			}
		})
	}
}

// Test_ClojarsDeployToken_theAlphabetAtItsEnds drives the declared alphabet at
// both of its ends — the digits and the letters — at the first character of a
// body, in the middle of one and at the last character, which is where a walk
// that read its class off by one at either end would show itself.
func Test_ClojarsDeployToken_theAlphabetAtItsEnds(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the first digit at the first character of the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
		},
		{
			name: "the last digit at the first character of the body",
			src:  "CLOJARS_90123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "the first letter at the first character of the body",
			src:  "CLOJARS_a0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "the last letter at the first character of the body",
			src:  "CLOJARS_f0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "the first digit in the middle of the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcd0f0123456789abcdef0123456789ab",
		},
		{
			name: "the last digit in the middle of the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcd9f0123456789abcdef0123456789ab",
		},
		{
			name: "the first letter in the middle of the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdaf0123456789abcdef0123456789ab",
		},
		{
			name: "the last letter in the middle of the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdff0123456789abcdef0123456789ab",
		},
		{
			name: "the first digit at the last character of the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789a0",
		},
		{
			name: "the last digit at the last character of the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789a9",
		},
		{
			name: "the first letter at the last character of the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789aa",
		},
		{
			name: "the last letter at the last character of the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789af",
		},
	}

	want := []Span{{0, 68}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ClojarsDeployToken().Find(tt.src); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, want)
			}
		})
	}
}

// Test_ClojarsDeployToken_theCharactersJustOutsideTheAlphabet drives the four
// characters standing immediately outside the declared alphabet — the one below
// the digits, the one above them, the one below the letters and the one above
// them — at the same three places, which is where a class read one character
// wide at either end would let a body through.
func Test_ClojarsDeployToken_theCharactersJustOutsideTheAlphabet(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the character below the digits at the first character of the body",
			src:  "CLOJARS_/0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "the character above the digits at the first character of the body",
			src:  "CLOJARS_:0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "the character below the letters at the first character of the body",
			src:  "CLOJARS_`0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "the character above the letters at the first character of the body",
			src:  "CLOJARS_g0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "the character below the digits in the middle of the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcd/f0123456789abcdef0123456789ab",
		},
		{
			name: "the character above the digits in the middle of the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcd:f0123456789abcdef0123456789ab",
		},
		{
			name: "the character below the letters in the middle of the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcd`f0123456789abcdef0123456789ab",
		},
		{
			name: "the character above the letters in the middle of the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdgf0123456789abcdef0123456789ab",
		},
		{
			name: "the character below the digits at the last character of the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789a/",
		},
		{
			name: "the character above the digits at the last character of the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789a:",
		},
		{
			name: "the character below the letters at the last character of the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789a`",
		},
		{
			name: "the character above the letters at the last character of the body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ClojarsDeployToken().Find(tt.src); got != nil {
				t.Errorf("Find(%q) = %v, want none", tt.src, got)
			}
		})
	}
}

// Test_ClojarsDeployToken_theCount drives the count from either side: a body one
// character short of it, the count exactly, and a run one character longer.
func Test_ClojarsDeployToken_theCount(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a body one character short of the count",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a body of exactly the count",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{0, 68}},
		},
		{
			// A run one longer is a token with a character written after it,
			// and only the token is redacted.
			name: "a run one character longer than the count",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
			want: []Span{{0, 68}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ClojarsDeployToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ClojarsDeployToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token in a settings file",
			src:  `{"username": "example", "password": "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"}`,
			want: []Span{{37, 105}},
		},
		{
			name: "a token on a command line",
			src:  "lein deploy clojars --password CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{31, 99}},
		},
		{
			name: "a token in a log line",
			src:  `time=2026-08-17T00:00:00Z level=info msg="deploying" token=CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab`,
			want: []Span{{59, 127}},
		},
		{
			name: "prose with no token in it",
			src:  "the deploy token stands in for the password of the account that made it",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ClojarsDeployToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

// Test_ClojarsDeployToken_nextToWordCharacters writes out what a boundary on
// either side of a match would cost, which is why there is none:
// builtin_clojars_deploy_token.go's rationale says a boundary in front would
// drop rather than trim the match wherever a token is written against a word
// character, and one behind would drop a token with a character written after
// it.
func Test_ClojarsDeployToken_nextToWordCharacters(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token against a letter in front",
			src:  "xCLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{1, 69}},
		},
		{
			name: "a token against a digit in front",
			src:  "7CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{1, 69}},
		},
		{
			name: "a token against an underscore in front",
			src:  "_CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{1, 69}},
		},
		{
			name: "a token against a letter behind it",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abz",
			want: []Span{{0, 68}},
		},
		{
			name: "a token against a digit behind it",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab7",
			want: []Span{{0, 68}},
		},
		{
			name: "a token against an underscore behind it",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab_",
			want: []Span{{0, 68}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ClojarsDeployToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

// Test_ClojarsDeployToken_anUppercaseBody pins the case this pattern reads a
// body in. hexadecimalize lowercases every character it writes, so a body
// carrying an uppercase one is no token Clojars issued and is-deploy-token?
// would decline it as well. Reading either case instead is the widening on
// offer, and this is what would have to change for it.
func Test_ClojarsDeployToken_anUppercaseBody(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a wholly uppercase body",
			src:  "CLOJARS_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789AB",
		},
		{
			name: "one uppercase character at the first character of a body",
			src:  "CLOJARS_A0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "one uppercase character at the last character of a body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789aB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ClojarsDeployToken().Find(tt.src); got != nil {
				t.Errorf("Find(%q) = %v, want none", tt.src, got)
			}
		})
	}
}

// Test_ClojarsDeployToken_aWiderAlphabet pins the alphabet against the ruleset
// that reads this format. gitleaks reads sixty characters of letters and digits
// where Clojars writes hexadecimal, so a body carrying a letter past f is a
// value that rule admits and this pattern declines. What the decision rests on
// is the vendor rather than the rule's silence:
// builtin_clojars_deploy_token.go's rationale names the generator and the
// validator that state the narrower alphabet.
func Test_ClojarsDeployToken_aWiderAlphabet(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a letter past f at the first character of a body",
			src:  "CLOJARS_z0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a letter past f in the middle of a body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdzf0123456789abcdef0123456789ab",
		},
		{
			name: "a letter past f at the last character of a body",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789az",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ClojarsDeployToken().Find(tt.src); got != nil {
				t.Errorf("Find(%q) = %v, want none", tt.src, got)
			}
		})
	}
}

// Test_ClojarsDeployToken_aDigestBehindThePrefix pins what this pattern
// over-matches on and what it does not. A body is sixty hexadecimal characters
// and no digest in common use is that many, so three of the four fall short of
// the count and locate nothing, and the fourth is redacted for sixty with its
// last four characters left in the text.
func Test_ClojarsDeployToken_aDigestBehindThePrefix(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an MD5 behind the prefix, thirty-two characters",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a SHA-1 behind the prefix, forty characters",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a SHA-224 behind the prefix, fifty-six characters",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef01234567",
		},
		{
			// Sixty-four characters, four past the count, so a token's worth of
			// it is redacted and the rest stays in the text. There is nothing
			// left to tell the first sixty from a token — a scan declining them
			// would decline every real token of the same shape.
			name: "a SHA-256 behind the prefix, sixty-four characters",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 68}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ClojarsDeployToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

// Test_ClojarsDeployToken_theCredentialThatCarriesNoPrefix writes out the other
// secret Clojars keeps, which this pattern does not read: a password reset code
// is forty hexadecimal characters with nothing in front of them, which is a git
// SHA and an identifier as much as it is a code. A grammar admitting it is the
// grammar AllBuiltinPatterns may not grow, so it is a credential this pattern
// does not name rather than one the scan happens to miss.
func Test_ClojarsDeployToken_theCredentialThatCarriesNoPrefix(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a reset code on its own",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a reset code in an assignment",
			src:  "reset_code=0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ClojarsDeployToken().Find(tt.src); got != nil {
				t.Errorf("Find(%q) = %v, want none", tt.src, got)
			}
		})
	}
}

// Test_ClojarsDeployToken_noTokenBeginsInsideAnother drives what the scan does
// with the claim builtin_clojars_deploy_token.go argues about a crowded input,
// and which Test_clojarsDeployTokenAnchor and Test_clojarsDeployTokenPrefix
// hold the two halves of.
func Test_ClojarsDeployToken_noTokenBeginsInsideAnother(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own reports one span",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{0, 68}},
		},
		{
			name: "two tokens with nothing between them report two",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abCLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{0, 68}, {68, 136}},
		},
		{
			// A whole body written behind a token, which is where a second span
			// would stand if a candidate could open inside one.
			name: "a token with a whole body written behind it",
			src:  "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{0, 68}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ClojarsDeployToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

// Test_ClojarsDeployToken_aPrefixInFrontOfAToken is what the scan's one-byte
// step reaches, and so why it steps rather than consuming what it read. The
// candidate the first prefix opens is no token — its body would have to begin
// with the C of the second — and the token opens at the second prefix, which a
// scan resuming past the first candidate would have stepped over.
func Test_ClojarsDeployToken_aPrefixInFrontOfAToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "one prefix in front of a token",
			src:  "CLOJARS_CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{8, 76}},
		},
		{
			name: "two prefixes in front of a token",
			src:  "CLOJARS_CLOJARS_CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{16, 84}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ClojarsDeployToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

// Test_ClojarsDeployToken_holdsACandidateTheInputCutShort states, with a literal
// number, what the second return of Find settles on the three shapes
// builtin_clojars_deploy_token.go's rationale on settling names: a piece of the
// prefix standing at the end of the input, a candidate the end of the input cut
// short, and a whole match with nothing left unsettled behind it.
func Test_ClojarsDeployToken_holdsACandidateTheInputCutShort(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		want   []Span
		retain int
	}{
		{
			// A piece of the prefix stands at the very end of the input: three
			// more bytes could still make it whole, so nothing behind where it
			// opens is settled.
			name:   "a piece of the prefix at the end of the input",
			src:    "CLOJA",
			retain: 0,
		},
		{
			// The same piece with prose in front of it, so what is unsettled is
			// only the piece itself rather than the whole input.
			name:   "a piece of the prefix behind prose",
			src:    "the token starts with CLOJA",
			retain: len("the token starts with "),
		},
		{
			// A whole prefix and a body the input cuts short of the count. The
			// candidate could still become a token were the input longer, so
			// what is unsettled reaches back to where the candidate opened
			// rather than to the byte the input stopped at.
			name:   "a body the input cuts short of the count",
			src:    "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
			retain: 0,
		},
		{
			// The same, with a candidate that had already failed: its first
			// character is a letter past f, so no text carrying on from here
			// could have made it a token. The scan settles where the candidate
			// opened all the same, which is the decision builtin_scan.go argues
			// — reading what is written of a truncated candidate would cost a
			// second grammar, and a few bytes at the end of a write are not
			// worth one.
			name:   "a body the input cuts short, already carrying a character no body holds",
			src:    "CLOJARS_g123456789abcdef",
			retain: 0,
		},
		{
			// A whole token with more text after it, ending in a byte no piece
			// of the prefix opens, so nothing at the end of the input is left
			// unsettled — the token found is reported and the input is settled
			// to its end.
			name:   "a whole token followed by settled text",
			src:    "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab tail",
			want:   []Span{{0, 68}},
			retain: 73,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := ClojarsDeployToken().Find(tt.src)
			if retain != tt.retain {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, retain, tt.retain)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ClojarsDeployToken_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor, and what holds it linear is the count being a
	// count: a candidate reads at most sixty-eight bytes and stops. These are
	// the inputs that would find it wrong here — a line that is nothing but
	// prefixes, a line that is nothing but tokens, and a single hexadecimal run
	// as long as the line, which is where a scan reading a run instead of a
	// count would show itself.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// whole body apiece and so hold a candidate every sixty-eight bytes at
	// their densest. The crowding a line can actually carry, a candidate every
	// eight, stays here.
	sources := map[string]string{
		// A candidate every eight characters, each turned away at the first
		// character of its body, which is the C the next prefix opens with and
		// no character a body is written with.
		"a candidate every eight characters": strings.Repeat("CLOJARS_", 250000),
		// The same crowding with a whole token at each candidate, so every one
		// of them reads sixty characters of body and reports a span.
		"a token every sixty-eight characters": strings.Repeat("CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab", 30000),
		// A candidate walked to its last character before the body's class
		// turns it away, which is the most a rejected candidate can cost.
		"a candidate walked to its last character": strings.Repeat("CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ag ", 30000),
		// One candidate whose run is the whole line. The count is what stops
		// it, sixty bytes in, where a scan reading the run to its end would
		// read two mebibytes before deciding anything.
		"a hexadecimal run the length of the line": "CLOJARS_" + strings.Repeat("a", 2000000),
		// The same run with no prefix in front of it, so no candidate is found
		// in it at all.
		"a hexadecimal run with no prefix": strings.Repeat("a", 2000000),
	}

	checkScanIsLinear(t, ClojarsDeployToken(), sources)
}

// Test_clojarsDeployTokenPrefix holds the prefix to the property the scan's
// reading of a crowded input rests on: no character of it is written in the
// alphabet a body is written in.
//
// What that buys is two things at once: a run of the body alphabet stops the
// search not once however long it runs, which is what makes this scan cheap
// over a line of digests, and no candidate can open at a position inside a
// body, which is half of why no token begins inside another.
func Test_clojarsDeployTokenPrefix(t *testing.T) {
	for i := range len(clojarsDeployTokenPrefix) {
		if c := clojarsDeployTokenPrefix[i]; isClojarsDeployTokenBodyByte(c) {
			t.Errorf("the prefix %q carries %q at %d, which a body is written with, so a candidate can open inside a body", clojarsDeployTokenPrefix, c, i)
		}
	}
}

// Test_clojarsDeployTokenAnchor holds the byte the scan searches the input for
// to standing where the scan reads a candidate back from, and to standing
// nowhere else in the prefix.
//
// The first half is what builtin_scan.go asks of every anchor: a prefix carrying
// it somewhere else is a prefix no candidate is ever found at, and nothing that
// was passing would stop passing.
//
// The second half is one of the two things no token beginning inside another
// rests on, which builtin_clojars_deploy_token.go's rationale argues and
// Test_clojarsDeployTokenPrefix holds the other of.
func Test_clojarsDeployTokenAnchor(t *testing.T) {
	p := clojarsDeployTokenPrefix
	if clojarsDeployTokenAnchorIndex >= len(p) {
		t.Fatalf("the anchor stands at %d, the prefix %q is %d characters", clojarsDeployTokenAnchorIndex, p, len(p))
	}
	if c := p[clojarsDeployTokenAnchorIndex]; c != clojarsDeployTokenAnchor {
		t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", p, c, byte(clojarsDeployTokenAnchor))
	}
	if n := strings.Count(p, string(rune(clojarsDeployTokenAnchor))); n != 1 {
		t.Errorf("the prefix %q carries the anchor %q %d times, so a candidate can open inside one", p, byte(clojarsDeployTokenAnchor), n)
	}
}

// Test_clojarsDeployTokenChars holds the arithmetic to the numbers this
// pattern's documentation states: the eight characters of the prefix, the sixty
// of the body and the sixty-eight a token comes to.
//
// What it holds is the documentation rather than the scan. Every count the scan
// reads is written from the two above, so a prefix of another length would be
// located correctly and nothing would go wrong. What would go wrong is the
// sentence on ClojarsDeployToken promising sixty-eight characters, and the spans
// every case in this file is written with.
func Test_clojarsDeployTokenChars(t *testing.T) {
	const (
		documentedPrefixChars = 8
		documentedBodyChars   = 60
		documentedChars       = 68
	)

	if len(clojarsDeployTokenPrefix) != documentedPrefixChars {
		t.Errorf("the prefix %q is %d characters, the documentation promises %d", clojarsDeployTokenPrefix, len(clojarsDeployTokenPrefix), documentedPrefixChars)
	}
	if clojarsDeployTokenBodyChars != documentedBodyChars {
		t.Errorf("the body is read as %d characters, the documentation promises %d", clojarsDeployTokenBodyChars, documentedBodyChars)
	}
	if clojarsDeployTokenChars != documentedChars {
		t.Errorf("a token is read as %d characters, the documentation promises %d", clojarsDeployTokenChars, documentedChars)
	}
}

// referenceClojarsDeployToken is the grammar as a regular expression: the prefix
// Clojars writes a token with, the count of thirty bytes written two characters
// to a byte, and the lowercase alphabet hexadecimalize leaves them in. Every
// part of it is spelled again rather than read from the scan, so that the two
// can disagree and the target below report it.
//
// It is built on an expression rather than written out because the count is
// exact, so an engine reads its machine once and stops, and because the prefix
// is a literal an engine can search the text for — written, besides, in no
// character of the alphabet its own body is written in, which is the second of
// the two things builtin-patterns.md names as having made an expression too
// slow to fuzz with.
var referenceClojarsDeployToken = regexp.MustCompile(`CLOJARS_[0-9a-f]{60}`)

// referenceClojarsDeployTokenFind locates tokens the plain way: the leftmost
// match of the expression above, then the leftmost one beginning after that
// match's first byte, over and over, with nothing remembered between them.
//
// Asking at every byte rather than resuming past a match is what the scan does.
// No token can begin inside another here, but a reference is written to know
// nothing its scan claims, and that is one of the things the scan claims.
func referenceClojarsDeployTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceClojarsDeployToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzClojarsDeployToken_matchesReference guards the hand-written scan: the byte
// it searches for, the index it reads a candidate back from, the case it reads
// the prefix and the body in, the count it reads behind the prefix and the byte
// it resumes at may none of them change which tokens are located.
func FuzzClojarsDeployToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("CLOJARS_PASSWORD=CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab")
	f.Add("CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789a")   // a body one character short
	f.Add("CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc") // and a run one longer
	f.Add("CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef 123456789ab")  // a body broken by a space
	f.Add("CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef-123456789ab")  // a hyphen in the body
	f.Add("CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef_123456789ab")  // an underscore in the body
	f.Add("CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdefg123456789ab")  // a letter outside hexadecimal
	f.Add("CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef\n123456789ab")
	f.Add("CLOJARS_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789AB") // an uppercase body
	f.Add("CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789aB") // one uppercase character in one
	f.Add("clojars_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab") // a lowercase prefix
	f.Add("CLOJARS0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc") // the prefix without its underscore
	f.Add("CLOJARS-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab") // a hyphen where the underscore stands
	f.Add("xCLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab")
	// The other names Clojars writes with this prefix, and the credential it
	// keeps that carries no prefix at all.
	f.Add("CLOJARS_USERNAME=example CLOJARS_ENVIRONMENT=production")
	f.Add("0123456789abcdef0123456789abcdef01234567")
	// The digests, which the count admits one of and turns three away.
	f.Add("CLOJARS_0123456789abcdef0123456789abcdef")
	f.Add("CLOJARS_0123456789abcdef0123456789abcdef01234567")
	f.Add("CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef01234567")
	f.Add("CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// A prefix written in front of a token, two tokens with nothing between
	// them, and a whole body written behind a token.
	f.Add("CLOJARS_CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab")
	f.Add("CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abCLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab")
	f.Add("CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab")
	// Pieces of the prefix at the end of the input, which is what the tail the
	// scan settles by is read from.
	f.Add("CLOJA")
	f.Add("CLOJARS_")
	f.Add("J")

	fuzzAgainstReference(f, ClojarsDeployToken().Find, referenceClojarsDeployTokenFind)
}

// Test_clojarsDeployTokenFindBenchmarks_lineTheAnchorWasChosenAgainst holds the
// line the benchmarks below are written on to the counts the anchor was chosen
// against, which builtin_clojars_deploy_token.go names: the J stands on it not
// at all where every other character of the prefix stands at least once.
//
// Then it holds the anchor to being the character that count belongs to. That
// half is what makes this a test of the choice rather than of the line: every
// character of the prefix stands outside the alphabet a body is written in, so
// the scan locates the same tokens whichever of the eight it searches for, and
// nothing else here would fail if the anchor moved to the underscore — the one
// the rationale names as the most often written of the eight.
func Test_clojarsDeployTokenFindBenchmarks_lineTheAnchorWasChosenAgainst(t *testing.T) {
	line := clojarsDeployTokenFindBenchmarks()[0].src

	counts := map[byte]int{'C': 1, 'L': 2, 'O': 2, 'J': 0, 'A': 1, 'R': 2, 'S': 1, '_': 1}
	for c, want := range counts {
		if got := strings.Count(line, string(c)); got != want {
			t.Errorf("the line carries %q %d times, where the choice of anchor was read off %d", c, got, want)
		}
	}

	if n, ok := counts[clojarsDeployTokenAnchor]; !ok {
		t.Errorf("the scan searches for %q, which is no character of the prefix %q", byte(clojarsDeployTokenAnchor), clojarsDeployTokenPrefix)
	} else if n != 0 {
		t.Errorf("the scan searches for %q, which the line carries %d times, where the prefix has a character it carries not at all", byte(clojarsDeployTokenAnchor), n)
	}
}

// clojarsDeployTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func clojarsDeployTokenFindBenchmarks() []benchmarkCase {
	// A deploy line from the place a token is actually written, a CI job
	// publishing to Clojars. The byte the scan searches for stands on it not at
	// all, where every other character of the prefix stands once or twice —
	// Test_clojarsDeployTokenFindBenchmarks_lineTheAnchorWasChosenAgainst holds
	// it to those counts. What the line times is the search for the anchor,
	// which is most of what this pattern costs a caller whose text holds no
	// token.
	line := `time=2026-08-17T00:00:00Z level=INFO msg="PUT https://repo.clojars.org/org/clojars/example/example-lib/1.0.0/example-lib-1.0.0.jar" status=201 User-Agent=Leiningen/2.11.2 CI=true RUNNER_OS=Linux `
	token := "CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is eight characters carrying the anchor once, so a run
			// of them stops the search once every eight characters and each
			// stop reads a body that fails at its first character, which is the
			// C of the prefix beginning a byte later.
			name:  "candidates that are not values",
			src:   strings.Repeat("CLOJARS_", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads a prefix, which is the cheapest a candidate
			// is declined for at all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("J", 4096),
			spans: 0,
		},
		{
			// The other way a candidate fails: a body of the right alphabet up
			// to its last character, so the whole of it is walked before the
			// candidate is turned away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("CLOJARS_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ag ", 16),
			spans: 0,
		},
		{
			// A run of the alphabet a body is read in, carrying no anchor at
			// all, which is what the search walks a digest of.
			name:  "a run of the body alphabet",
			src:   strings.Repeat("0123456789abcdef", 256),
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
