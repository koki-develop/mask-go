package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The HashiCorp Vault token pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. The twenty-four characters
// 0123456789abcdef01234567 are a whole body at the floor, which is a recovery
// token and a root service token exactly; the ninety-one of
// 0123456789abcdef repeated and cut are the shape a server side consistent
// service token is written at. Neither body is an abbreviation.

func Test_HashiCorpVaultToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a service token on its own",
			src:  "hvs.0123456789abcdef01234567",
			want: []Span{{0, 28}},
		},
		{
			name: "a batch token on its own",
			src:  "hvb.0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 52}},
		},
		{
			name: "a recovery token on its own",
			src:  "hvr.0123456789abcdef01234567",
			want: []Span{{0, 28}},
		},
		{
			name: "a service token in an environment assignment",
			src:  "VAULT_TOKEN=hvs.0123456789abcdef01234567",
			want: []Span{{12, 40}},
		},
		{
			// The two long shapes are written with base64.RawURLEncoding, so
			// both characters base64url adds to base62 belong to a body.
			name: "a body carrying both characters base64url adds",
			src:  "hvs.0123456789abcdef-123456789_bcdef0123456789abcdef",
			want: []Span{{0, 52}},
		},
		{
			// base64url holds the letters of both cases, so a body is a body in
			// either. Only the prefix is fixed in case.
			name: "a body written in capitals",
			src:  "hvs.0123456789ABCDEF01234567",
			want: []Span{{0, 28}},
		},
		{
			// The shape Vault writes where server side consistent tokens are
			// on, which is everything but a root token by default: the random
			// part wrapped in a signed protobuf and encoded, ninety-one
			// characters here.
			name: "a server side consistent service token",
			src:  "hvs.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 95}},
		},
		{
			// The count is a floor, so a run longer than it is one token to the
			// end of the run rather than a token and a character left over.
			name: "a run longer than the floor is a token to the end of it",
			src:  "hvs.0123456789abcdef012345678",
			want: []Span{{0, 29}},
		},
		{
			// Neither token is inside the other, but the run of the first
			// reaches into the prefix of the second: the two characters of the
			// anchor and the letter naming a kind all belong to the alphabet a
			// body is written in, so the first span stops only at the second
			// token's separator.
			name: "two tokens with nothing between them",
			src:  "hvs.0123456789abcdef01234567hvs.0123456789abcdef01234567",
			want: []Span{{0, 31}, {28, 56}},
		},
		{
			name: "a token of each kind on one line",
			src:  "hvs.0123456789abcdef01234567 hvb.0123456789abcdef01234567 hvr.0123456789abcdef01234567",
			want: []Span{{0, 28}, {29, 57}, {58, 86}},
		},
		{
			// A body closing with hvs and the separator of the next token
			// standing directly behind it: the second token begins three
			// characters before the first one ends, and the scan resuming a
			// byte along is what finds it. The spans overlap, which a Masker
			// resolves into one.
			name: "a token beginning inside the token before it",
			src:  "hvs.0123456789abcdef01234hvs.0123456789abcdef01234567",
			want: []Span{{0, 28}, {25, 53}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HashiCorpVaultToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HashiCorpVaultToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a prefix alone",
			src:  "hvs.",
		},
		{
			name: "a body one character short of the floor",
			src:  "hvs.0123456789abcdef0123456",
		},
		{
			name: "a batch prefix with a body one character short of the floor",
			src:  "hvb.0123456789abcdef0123456",
		},
		{
			name: "a recovery prefix with a body one character short of the floor",
			src:  "hvr.0123456789abcdef0123456",
		},
		{
			// The separator ends nothing else: a body carries none, so a dot
			// inside one ends it where it stands and what follows is a body of
			// no candidate.
			name: "a separator inside the body",
			src:  "hvs.0123456789abcdef.01234567",
		},
		{
			name: "a body broken by a space",
			src:  "hvs.0123456789abcdef 01234567",
		},
		{
			name: "a body broken by a line break",
			src:  "hvs.0123456789abcdef\n01234567",
		},
		{
			// Standard base64 adds the plus and the slash where base64url adds
			// the hyphen and the underscore, and neither belongs to a body.
			name: "a body carrying the characters of standard base64",
			src:  "hvs.0123456789abcdef+1234567",
		},
		{
			name: "a letter naming no kind of token",
			src:  "hvx.0123456789abcdef01234567",
		},
		{
			name: "an uppercase prefix",
			src:  "HVS.0123456789abcdef01234567",
		},
		{
			name: "an underscore where the prefix carries its separator",
			src:  "hvs_0123456789abcdef01234567",
		},
		{
			name: "a hyphen where the prefix carries its separator",
			src:  "hvs-0123456789abcdef01234567",
		},
		{
			name: "the anchor alone in front of a run",
			src:  "hv.0123456789abcdef01234567",
		},
		{
			name: "a run of the right length with no prefix at all",
			src:  "0123456789abcdef01234567",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// Forty hexadecimal characters, and no separator standing behind a
			// prefix anywhere in them.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a jwt",
			src:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
		},
		{
			// The environment a Vault client is configured through, whose names
			// carry no separator at all.
			name: "the environment a vault client reads",
			src:  "VAULT_ADDR=https://vault.example.com:8200 VAULT_NAMESPACE=admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HashiCorpVaultToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_HashiCorpVaultToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "VAULT_TOKEN=hvs.0123456789abcdef01234567",
			want: "VAULT_TOKEN=****************************",
		},
		{
			name: "a batch token in an assignment",
			src:  "VAULT_TOKEN=hvb.0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "VAULT_TOKEN=****************************************************",
		},
		{
			name: "a recovery token as the unseal output prints it",
			src:  "Recovery Token: hvr.0123456789abcdef01234567",
			want: "Recovery Token: ****************************",
		},
		{
			// How a token reaches the API, and how it reaches a log line that
			// echoed the header.
			name: "the header a request to vault carries",
			src:  "X-Vault-Token: hvs.0123456789abcdef01234567",
			want: "X-Vault-Token: ****************************",
		},
		{
			name: "json",
			src:  `{"auth":{"client_token":"hvs.0123456789abcdef01234567"}}`,
			want: `{"auth":{"client_token":"****************************"}}`,
		},
		{
			name: "a server side consistent service token",
			src:  "VAULT_TOKEN=hvs.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
			want: "VAULT_TOKEN=***********************************************************************************************",
		},
		{
			name: "a command line",
			src:  "vault login hvs.0123456789abcdef01234567",
			want: "vault login ****************************",
		},
		{
			name: "a token of each kind on one line",
			src:  "hvs.0123456789abcdef01234567 hvb.0123456789abcdef01234567 hvr.0123456789abcdef01234567",
			want: "**************************** **************************** ****************************",
		},
		{
			// The two spans are merged, so the token that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a token beginning inside the token before it",
			src:  "hvs.0123456789abcdef01234hvs.0123456789abcdef01234567",
			want: "*****************************************************",
		},
	}

	m := New(WithPatterns(HashiCorpVaultToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HashiCorpVaultToken_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the token through whole. The first two are also
	// the first of the two costs builtin_hashicorp_vault_token.go weighs the
	// front tightening at — the demand that no character of base64url stand in
	// front of a prefix would reject both. The second cost is the nesting case
	// in Test_HashiCorpVaultToken, where what stands in front of a token's
	// prefix is the last character of the previous token's body.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "xhvs.0123456789abcdef01234567",
			want: "x****************************",
		},
		{
			name: "underscore before",
			src:  "VAULT_TOKEN_hvs.0123456789abcdef01234567",
			want: "VAULT_TOKEN_****************************",
		},
		{
			// The far side of the same choice. A boundary behind the match
			// would drop this token rather than trim it; without one the span
			// reaches to the end of the run, which is what the floor asks for.
			name: "a character of the alphabet after",
			src:  "hvs.0123456789abcdef012345678",
			want: "*****************************",
		},
	}

	m := New(WithPatterns(HashiCorpVaultToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HashiCorpVaultToken_readsToTheEndOfTheRun(t *testing.T) {
	// The count is a floor and the span reaches to the end of the run, which
	// is what a token longer than the floor needs and what a word written
	// against one pays. base64url holds the hyphen and the underscore, so a
	// hyphenated or underscored word written straight against a token is
	// redacted with it — which is what tells this pattern from one whose body
	// is base62 and stops at either character.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a word written against a token",
			src:  "hvs.0123456789abcdef01234567suffix",
			want: "**********************************",
		},
		{
			name: "a hyphenated word written against a token",
			src:  "hvs.0123456789abcdef01234567-suffix",
			want: "***********************************",
		},
		{
			name: "an underscored word written against a token",
			src:  "hvs.0123456789abcdef01234567_suffix",
			want: "***********************************",
		},
	}

	m := New(WithPatterns(HashiCorpVaultToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HashiCorpVaultToken_leavesWhatFollowsAlone(t *testing.T) {
	// The other side of reading to the end of the run: what belongs to no
	// base64url run ends the span where it stands, and everything written after
	// it stays.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a token at the end of a sentence",
			src:  "the token is hvs.0123456789abcdef01234567.",
			want: "the token is ****************************.",
		},
		{
			name: "quoted",
			src:  `"hvs.0123456789abcdef01234567"`,
			want: `"****************************"`,
		},
		{
			name: "a token in front of a path segment",
			src:  "/v1/auth/token/lookup hvs.0123456789abcdef01234567/renew",
			want: "/v1/auth/token/lookup ****************************/renew",
		},
		{
			// RawURLEncoding writes no padding, so the equals sign belongs to
			// no body and ends the run.
			name: "a token written against standard base64 padding",
			src:  "hvs.0123456789abcdef01234567==",
			want: "****************************==",
		},
	}

	m := New(WithPatterns(HashiCorpVaultToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HashiCorpVaultToken_theLegacyPrefixes(t *testing.T) {
	// The tokens Vault issued until 1.10 are not read, and the decision is
	// pinned here so that reading them is a change somebody argues for. They
	// still authenticate where they have not expired, so what these cases hold
	// is a credential left in the output whole.
	//
	// The last case is why. s. and twenty-four characters of base64url is a
	// field access, a method call and a qualified name, and this library
	// redacts rather than reports: there is no entropy floor and no window of
	// surrounding text here to tell the two apart, which is what both rulesets
	// reading the old prefix need.
	// builtin_hashicorp_vault_token.go weighs both sides.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a service token of the format issued before vault 1.10",
			src:  "VAULT_TOKEN=s.0123456789abcdef01234567",
			want: "VAULT_TOKEN=s.0123456789abcdef01234567",
		},
		{
			name: "a batch token of that format",
			src:  "VAULT_TOKEN=b.0123456789abcdef01234567",
			want: "VAULT_TOKEN=b.0123456789abcdef01234567",
		},
		{
			name: "a recovery token of that format",
			src:  "VAULT_TOKEN=r.0123456789abcdef01234567",
			want: "VAULT_TOKEN=r.0123456789abcdef01234567",
		},
		{
			name: "the field access that grammar could not be told from",
			src:  `logger.WithField("vault", s.0123456789abcdef01234567)`,
			want: `logger.WithField("vault", s.0123456789abcdef01234567)`,
		},
	}

	m := New(WithPatterns(HashiCorpVaultToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HashiCorpVaultToken_theClientSecret(t *testing.T) {
	// The other Vault credential carrying a prefix, held outside. An OIDC
	// provider's client secret is hvo_secret_ and sixty-four characters of
	// base62, and it opens with the two letters this scan searches for — what
	// turns it away is the character behind them, which names a kind of token,
	// and the underscore where a prefix carries its separator. It is a
	// credential this pattern is not for rather than one it fails on, and
	// reading it would be a pattern of its own.
	const src = "hvo_secret_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	m := New(WithPatterns(HashiCorpVaultToken()))
	if got := m.Mask(src); got != src {
		t.Errorf("Mask(%q) = %q, want the text unchanged", src, got)
	}
}

func Test_HashiCorpVaultToken_aNamespacedBatchToken(t *testing.T) {
	// A batch token minted in a namespace carries the namespace ID behind its
	// body, separated by the same dot the prefix closes with — as does a
	// service token whose external form is the unwrapped one. The separator
	// belongs to no body, so the span stops in front of it and the namespace ID
	// stays in the output — which is what admitting the separator into a body
	// would have to be traded for, and that grammar reaches into the sentence a
	// token was written in.
	const (
		src  = "hvb.0123456789abcdef0123456789abcdef0123456789abcdef.0abcd"
		want = "****************************************************.0abcd"
	)

	m := New(WithPatterns(HashiCorpVaultToken()))
	if got := m.Mask(src); got != want {
		t.Errorf("Mask(%q) = %q, want %q", src, got, want)
	}
}

func Test_HashiCorpVaultToken_insideAnEncoding(t *testing.T) {
	// What this pattern over-matches on, and the only place a prefix is
	// reachable inside an encoding: a value written as dot-separated segments
	// of base64url, where a segment closes on the three characters of a prefix
	// and the dot after it is the prefix's separator. A base64url run holds no
	// dot of its own, so no single blob can carry a prefix at however long it
	// runs.
	//
	// What is taken there is the tail of a value that was opaque to begin with
	// and is itself a credential — the JWT and SendGrid patterns beside this one
	// redact the whole of either input. The third case is the same shape with no
	// segment closing that way, which is every other JWT.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a jwt whose payload closes on a prefix",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQhvs.0123456789abcdef01234567",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ****************************",
		},
		{
			name: "a sendgrid key whose first segment closes on a prefix",
			src:  "SG.0123456789abcdef012hvb.0123456789abcdef0123456789abcdef0123456789a",
			want: "SG.0123456789abcdef012***********************************************",
		},
		{
			name: "a jwt no segment of which closes on a prefix",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef01234567",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef01234567",
		},
	}

	m := New(WithPatterns(HashiCorpVaultToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HashiCorpVaultToken_aBodyBetweenTheShapes(t *testing.T) {
	// The window builtin_hashicorp_vault_token.go sets out: Vault issues a body
	// of twenty-four characters or of ninety-one and up, and the floor admits
	// everything between. A grammar asking for twenty-four of base62 exactly or
	// for ninety-one of base64url would be tighter than this one against the
	// tokens Vault emits today.
	//
	// It is not taken, and the third case is why. A log line cut through the
	// middle of a service token is the case this library exists for, and what
	// it leaves is a body in exactly that window — live token material, which
	// the floor redacts and the tighter grammar would leave in the output
	// whole. The fourth case is the far side of the same floor: cut it below
	// twenty-four and nothing is located at all.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a body of thirty-five characters, which no shape Vault issues has",
			src:  "hvs.0123456789abcdef0123456789abcdef012",
			want: "***************************************",
		},
		{
			name: "a body at the length a consistent token is written to",
			src:  "hvs.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
			want: "***********************************************************************************************",
		},
		{
			name: "a consistent token a column limit cut inside its body",
			src:  "VAULT_TOKEN=hvs.0123456789abcdef0123456789abcdef01234567",
			want: "VAULT_TOKEN=********************************************",
		},
		{
			name: "the same token cut below the floor",
			src:  "VAULT_TOKEN=hvs.0123456789abcdef0123456",
			want: "VAULT_TOKEN=hvs.0123456789abcdef0123456",
		},
	}

	m := New(WithPatterns(HashiCorpVaultToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HashiCorpVaultToken_aDottedName(t *testing.T) {
	// The other thing this pattern over-matches on, and the one text somebody
	// wrote rather than a machine encoded. Anything written as dot-separated
	// names reaches a token's format where the name after the hvs, hvb or hvr
	// runs to the floor: the name is redacted from the h to the end of that
	// segment and the rest is left standing. A hostname is one shape of that; a
	// qualified name in source is the other, and it is the same shape that
	// makes the legacy s., b. and r. prefixes unreadable — the difference being
	// that hvs is a rare thing to call a receiver where s is not.
	//
	// The second and fourth cases are the same text with a segment short of the
	// floor, which is what turns an ordinary name away. Nothing in the grammar
	// could have turned the first and third away: twenty-four unbroken
	// characters behind one of the prefixes is a root service token exactly.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a hostname whose first label is a prefix",
			src:  "https://hvs.0123456789abcdef01234567.example.com/v1",
			want: "https://****************************.example.com/v1",
		},
		{
			name: "the same name with a label shorter than the floor",
			src:  "https://hvs.0123456789abcdef0123456.example.com/v1",
			want: "https://hvs.0123456789abcdef0123456.example.com/v1",
		},
		{
			name: "a call on a receiver named for a prefix",
			src:  "hvs.CreateOrUpdateSecretVersion(ctx)",
			want: "*******************************(ctx)",
		},
		{
			// The underscore belongs to base64url, so a member name written in
			// snake_case runs on rather than being broken by it — which makes
			// this the more reachable of the two spellings, not the less.
			name: "the same call with the name written in snake case",
			src:  "hvs.create_or_update_secret_version(ctx)",
			want: "***********************************(ctx)",
		},
		{
			name: "the same call with a name shorter than the floor",
			src:  "hvs.CreateOrUpdateSecret(ctx)",
			want: "hvs.CreateOrUpdateSecret(ctx)",
		},
	}

	m := New(WithPatterns(HashiCorpVaultToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_hashiCorpVaultTokenAnchor(t *testing.T) {
	// The scan searches for the anchor and reads the kind and the separator
	// behind it, so a prefix is the anchor and two bytes. What lets one token
	// be written inside another is that every character in front of the
	// separator belongs to the alphabet a body is written in: a body closing
	// with them hands the separator of the next token to a candidate beginning
	// inside this one. Nothing else here reports the loss of that — the nesting
	// cases above would simply stop nesting.
	if hashiCorpVaultTokenAnchor == "" {
		t.Fatal("the pattern carries no anchor, so there is no candidate to reason about")
	}
	for i := range len(hashiCorpVaultTokenAnchor) {
		if c := hashiCorpVaultTokenAnchor[i]; !isBase64URLByte(c) {
			t.Errorf("the anchor holds %q at %d, which no body may be written with", c, i)
		}
	}
	if hashiCorpVaultTokenKinds == "" {
		t.Fatal("the pattern names no kind of token, so it locates nothing")
	}
	for i := range len(hashiCorpVaultTokenKinds) {
		if c := hashiCorpVaultTokenKinds[i]; !isBase64URLByte(c) {
			t.Errorf("the kind %q is a character no body may be written with", c)
		}
	}

	// The prefix is what the scan reads by arithmetic rather than by comparing
	// a string, and the arithmetic is the anchor's length plus the kind and the
	// separator. So the total is held to the number Vault states rather than to
	// that sum, which it would agree with however long the anchor became.
	const documented = 4
	if hashiCorpVaultTokenPrefixChars != documented {
		t.Errorf("a prefix is read as %d characters, Vault's TokenPrefixLength states %d", hashiCorpVaultTokenPrefixChars, documented)
	}
}

func Test_hashiCorpVaultTokenSeparator_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over
	// it, where a scan whose prefix closes on a character its own body admits
	// has to keep one. What makes the cursor unnecessary is that two
	// candidates can never read the same run: a candidate asks for the
	// separator at the character in front of its body, no body may be written
	// with it, so the run of an earlier candidate has already ended there and
	// the later candidate's run begins past it. Were the separator a character
	// a body admits, a run dense in prefixes would be walked once for every
	// candidate in it and the scan would cost time quadratic in the length of
	// such a line.
	if isBase64URLByte(hashiCorpVaultTokenSeparator) {
		t.Errorf("the separator %q belongs to the alphabet a body is written in, so two candidates can read the same run", byte(hashiCorpVaultTokenSeparator))
	}

	// And no character naming a kind may be the separator, which is what keeps
	// a prefix from closing one byte early.
	if strings.IndexByte(hashiCorpVaultTokenKinds, hashiCorpVaultTokenSeparator) >= 0 {
		t.Errorf("the separator %q is also read as a kind of token", byte(hashiCorpVaultTokenSeparator))
	}
}

func Test_isHashiCorpVaultTokenKind(t *testing.T) {
	// The kinds, stated over every byte rather than by example. The three
	// characters are read from one string because that is the only place the
	// three prefixes differ, so what holds the test honest is that the byte
	// test and the string say the same thing in both directions.
	for c := range 256 {
		b := byte(c)
		want := strings.IndexByte(hashiCorpVaultTokenKinds, b) >= 0
		if got := isHashiCorpVaultTokenKind(b); got != want {
			t.Errorf("isHashiCorpVaultTokenKind(%q) = %v, want %v", b, got, want)
		}
	}

	// The three Vault issues, named so that dropping one is reported here
	// rather than in a case that quietly stops locating a kind of token.
	for _, kind := range []byte{'s', 'b', 'r'} {
		if !isHashiCorpVaultTokenKind(kind) {
			t.Errorf("isHashiCorpVaultTokenKind(%q) = false, want the prefix Vault issues that kind with to be read", kind)
		}
	}
	if got := len(hashiCorpVaultTokenKinds); got != 3 {
		t.Errorf("%d kind(s) of token are read, Vault issues 3", got)
	}
}

func Test_HashiCorpVaultToken_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a line dense in prefixes
	// holds a candidate for every four characters it has. The one thing a
	// candidate reads that is a walk over the rest of the input rather than a
	// bounded test is where its run ends, and repeating that walk at every
	// candidate would cost time quadratic in the length of the line. The bound
	// here is far above a linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// candidate every twenty-eight bytes where they are densest, because a
	// sample has to carry a whole body to be one. The crowding a line can
	// actually carry stays here.
	sources := map[string]string{
		// Candidates as close together as a prefix allows, none of them with a
		// run long enough to be a body: every one reaches the body of the loop
		// and every one is rejected.
		"a candidate every four characters": strings.Repeat("hvs.", 500000),
		// Tokens written into one another, each beginning three characters
		// before the one in front of it ends, so every candidate is a token and
		// every one of them walks a run.
		"a token beginning inside every token": strings.Repeat("hvs.0123456789abcdef01234", 50000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a token.
		"a body that runs the length of the line": "hvs." + strings.Repeat("a", 1800000),
		// The anchor at every other byte with nothing behind it that names a
		// kind, which is the cheapest way a candidate position is declined.
		"the anchor with no kind behind it": strings.Repeat("hv", 900000),
		// And a kind behind every anchor with no separator behind that, which
		// is the next cheapest.
		"a kind with no separator behind it": strings.Repeat("hvs", 600000),
	}

	m := New(WithPatterns(HashiCorpVaultToken()))
	for name, src := range sources {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_ = m.Mask(src)
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("Mask() of %d bytes took %v", len(src), d)
			}
		})
	}
}

// referenceHashiCorpVaultToken is the expression the scan in
// builtin_hashicorp_vault_token.go reads by hand: the statement of what a Vault
// token is, kept here so that the scan can be held to it.
//
// The anchor, the kinds, the separator, the floor and the alphabet are spelled
// again rather than built from hashiCorpVaultTokenAnchor,
// hashiCorpVaultTokenKinds, hashiCorpVaultTokenSeparator,
// hashiCorpVaultTokenBodyChars and isBase64URLByte. A reference sharing those
// declarations could not disagree with the scan about them, and it is exactly
// that disagreement the fuzz target below is for: the two have to be changed
// together or reported apart. The prefix is spelled as the three characters and
// the dot the scan reads one at a time, so that the arithmetic the scan does
// over them is something the two can disagree about too.
//
// The floor is written as a counted repetition, which is what the Anthropic
// and Notion references beside this one are written out by hand to avoid. It
// costs nothing here, and for the reason the scan needs no cursor: candidates
// cannot crowd inside one run, so no input makes an engine walk the same run
// more than once. Nor does the alternation of three prefixes cost what the
// alternation of two costs the Notion reference — all three agree on the two
// characters they open with, so an engine still has one literal to search the
// text for.
var referenceHashiCorpVaultToken = regexp.MustCompile(`hv[sbr]\.[0-9A-Za-z_-]{24,}`)

// referenceHashiCorpVaultTokenFind locates tokens the plain way: the leftmost
// match of the expression above, then the leftmost one beginning after that
// match's first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a token can begin inside one: the two characters
// of the anchor and the letter naming a kind are all written in the alphabet a
// body is, so a body closing with hvs holds the start of the token behind it.
// The scan finds both and reports the two spans overlapping for a Masker to
// resolve, so the reference must ask about both.
func referenceHashiCorpVaultTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceHashiCorpVaultToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzHashiCorpVaultToken_matchesReference guards the hand-written scan: the
// anchor it searches for, the characters it reads a kind by, the separator it
// asks for behind one, the floor it holds a body to, the alphabet it reads that
// body in and the byte it resumes at may none of them change which tokens are
// located.
func FuzzHashiCorpVaultToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("VAULT_TOKEN=hvs.0123456789abcdef01234567")
	f.Add("hvb.0123456789abcdef0123456789abcdef0123456789abcdef")                                            // a batch token
	f.Add("hvr.0123456789abcdef01234567")                                                                    // a recovery token
	f.Add("hvs.0123456789abcdef-123456789_bcdef0123456789abcdef")                                            // both characters base64url adds
	f.Add("hvs.0123456789ABCDEF01234567")                                                                    // a body written in capitals
	f.Add("hvs.0123456789abcdef0123456")                                                                     // a body one short of the floor
	f.Add("hvs.0123456789abcdef012345678")                                                                   // and a run longer than it
	f.Add("hvs.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789a") // the shape a consistent token is written at
	f.Add("hvs.0123456789abcdef+1234567")                                                                    // standard base64 rather than base64url
	f.Add("hvs.0123456789abcdef.01234567")                                                                   // the separator inside a body
	f.Add("hvx.0123456789abcdef01234567")                                                                    // a letter naming no kind
	f.Add("HVS.0123456789abcdef01234567")                                                                    // an uppercase prefix
	f.Add("hvs_0123456789abcdef01234567")                                                                    // an underscore where the separator stands
	f.Add("hv.0123456789abcdef01234567")                                                                     // the anchor with no kind behind it
	f.Add("s.0123456789abcdef01234567")                                                                      // the prefix Vault issued until 1.10
	f.Add("hvo_secret_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")                     // an OIDC provider client secret
	f.Add("hvb.0123456789abcdef0123456789abcdef0123456789abcdef.0abcd")                                      // a batch token minted in a namespace
	// A token beginning inside the match before it, which a scan resuming past
	// a match steps over, and two tokens with nothing between them, which is
	// the same text without the overlap.
	f.Add("hvs.0123456789abcdef01234hvs.0123456789abcdef01234567")
	f.Add("hvs.0123456789abcdef01234567hvs.0123456789abcdef01234567")
	f.Add("hvs.0123456789abcdef01234567 hvb.0123456789abcdef01234567 hvr.0123456789abcdef01234567")
	// Candidate positions crowded as close as they can be, and the two ways a
	// candidate is declined before it reads a run at all.
	f.Add(strings.Repeat("hvs.", 32))
	f.Add(strings.Repeat("hvs.", 32) + "0123456789abcdef01234567")
	f.Add(strings.Repeat("hv", 64))
	f.Add(strings.Repeat("hvs", 64))
	f.Add(strings.Repeat(".", 64))
	// The prefix inside an encoding, which is where the separator makes one
	// reachable at all, and a hostname, which is where writing does.
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQhvs.0123456789abcdef01234567")
	f.Add("SG.0123456789abcdef012hvb.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("https://hvs.0123456789abcdef01234567.example.com/v1")
	// A qualified name in source, which is the other half of that shape, and a
	// body inside the window between the two lengths Vault issues — the one a
	// truncated token leaves and the one such a name reaches.
	f.Add("token, err := hvs.CreateOrUpdateSecretVersion(ctx, req)")
	f.Add("token, err := hvs.create_or_update_secret_version(ctx, req)")
	f.Add("hvs.0123456789abcdef0123456789abcdef012")

	fuzzAgainstReference(f, HashiCorpVaultToken().Find, referenceHashiCorpVaultTokenFind)
}

// hashiCorpVaultTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func hashiCorpVaultTokenFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line carries the anchor, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://vault.example.com:8200/v1/sys/health `
	token := "hvs.0123456789abcdef01234567"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The anchor at every other byte with nothing behind it that names
			// a kind. This is the cheapest way a candidate position is
			// declined, and what a line of base64 reaches once in every four
			// thousand characters.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("hv", 1024),
			spans: 0,
		},
		{
			// A candidate at every anchor, each turned away three bytes into
			// its body by the separator of the next prefix.
			name:  "candidates that are not values",
			src:   strings.Repeat("hvs.", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: a body of the alphabet one
			// character short of the floor, so the whole of it is walked before
			// the character that ends it turns the candidate away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("hvs.0123456789abcdef0123456 ", 16),
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
