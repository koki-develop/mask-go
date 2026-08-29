package mask

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// The 1Password service account token pattern: what it locates and what it
// leaves alone, written out case by case, and the reference its scan is held
// to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The tokens written out below carry the three characters the base64url of a
// JSON object opens with and an ordered run behind them: valid in shape,
// obviously not real. What stands behind eyJ, 0123456789abcdef written over and
// over, stands in for the master unlock key, the Secret Key, the SRP verifier
// and the addresses a real token encodes there; the scan reads those as a run
// against a floor rather than to a count, so a hundred and sixty characters
// state the grammar as well as the six hundred and thirty the vendor's own
// printed token carries and leave a case that fits on a screen.

func Test_OnePasswordServiceAccountToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
			want: []Span{{0, 180}},
		},
		{
			// The variable 1Password's own CLI reads a token from.
			name: "a token in an environment assignment",
			src:  "OP_SERVICE_ACCOUNT_TOKEN=ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
			want: []Span{{25, 205}},
		},
		{
			name: "a token in a JSON field",
			src:  `{"token":"ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc"}`,
			want: []Span{{10, 190}},
		},
		{
			// Base64url writes the hyphen and the underscore where standard
			// base64 writes the plus and the slash, and a token carries both
			// wherever the bytes it encodes call for them.
			name: "a body carrying a hyphen and an underscore",
			src:  "ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab_0123456789abcdef0123456789abcdef012",
			want: []Span{{0, 164}},
		},
		{
			// A hundred and sixty characters behind the prefix, which is the
			// floor exactly: shorter than an object carrying both of the
			// secrets a token is a credential by, and a quarter of what the
			// vendor's own printed token carries.
			name: "a body exactly as long as the floor",
			src:  "ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
			want: []Span{{0, 164}},
		},
		{
			name: "two tokens separated by a space",
			src:  "ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab_0123456789abcdef0123456789abcdef012",
			want: []Span{{0, 164}, {165, 329}},
		},
		{
			// Every character of the anchor belongs to the alphabet a body is
			// written in, so a token can begin inside the span of the one
			// before it, and a scan resuming past a match would step over it.
			// The spans overlap, which a Masker resolves into one.
			name: "a token beginning inside the token before it",
			src:  "ops_eyJops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
			want: []Span{{0, 171}, {7, 171}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := OnePasswordServiceAccountToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OnePasswordServiceAccountToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "ops_",
		},
		{
			name: "the prefix and a long run carrying no header",
			src:  "ops_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "the header with no prefix in front of it",
			src:  "eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
		},
		{
			// Two of the header's three characters. The whole of it is read, so
			// a body carrying part of it carries none.
			name: "two characters of the header",
			src:  "ops_ey0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		},
		{
			// The header is an encoding rather than a spelling: EYJ encodes
			// nothing, so reading it would buy no token and admit a shouted
			// identifier.
			name: "a header in the wrong case",
			src:  "ops_EYJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
		},
		{
			name: "an uppercase prefix",
			src:  "OPS_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
		},
		{
			// The prefix is four characters and all four are read. A hyphen
			// where the underscore is is not one.
			name: "a hyphen where the prefix carries an underscore",
			src:  "ops-eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
		},
		{
			// The header stands against the prefix, so anything written between
			// the two leaves no anchor at all.
			name: "a space between the prefix and the header",
			src:  "ops_ eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
		},
		{
			// Standard base64 rather than base64url: the two characters
			// base64url writes as - and _ are + and /, and neither belongs to
			// the alphabet a body is read in, so the run ends there and what is
			// left of it is short of the floor.
			name: "a plus inside the body",
			src:  "ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef+0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a slash inside the body",
			src:  "ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a line break inside the body",
			src:  "ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// A JWT written behind the prefix. Its header segment closes on a
			// dot, which no body is written with, so the run ends twenty
			// characters in and nothing here reaches the floor.
			name: "a jwt behind the prefix",
			src:  "ops_eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// The names that carry the prefix. Each of them is a snake_case
			// word whose first segment is ops, and what turns them away is the
			// three characters behind the prefix rather than the floor.
			name: "a line of names carrying the prefix",
			src:  "the ops_team runbook lives beside ops_runbook and ops_oncall",
		},
		{
			// Forty hexadecimal characters. A digest carries no underscore, so
			// it holds no prefix to be found at, and neither y nor J is a
			// hexadecimal digit.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := OnePasswordServiceAccountToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_OnePasswordServiceAccountToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "OP_SERVICE_ACCOUNT_TOKEN=ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
			want: "OP_SERVICE_ACCOUNT_TOKEN=********************************************************************************************************************************************************************",
		},
		{
			name: "quoted",
			src:  `"ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc"`,
			want: `"********************************************************************************************************************************************************************"`,
		},
		{
			name: "json",
			src:  `{"token":"ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc"}`,
			want: `{"token":"********************************************************************************************************************************************************************"}`,
		},
		{
			// The way the CLI is handed a token in a pipeline, which is where
			// one is written by hand more often than anywhere else.
			name: "a command line",
			src:  "OP_SERVICE_ACCOUNT_TOKEN=ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc op item get login",
			want: "OP_SERVICE_ACCOUNT_TOKEN=******************************************************************************************************************************************************************** op item get login",
		},
		{
			name: "twice",
			src:  "ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab_0123456789abcdef0123456789abcdef012",
			want: "******************************************************************************************************************************************************************** ********************************************************************************************************************************************************************",
		},
		{
			// The two spans are merged, so the token that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a token beginning inside the token before it",
			src:  "ops_eyJops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
			want: "***************************************************************************************************************************************************************************",
		},
	}

	m := New(WithPatterns(OnePasswordServiceAccountToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OnePasswordServiceAccountToken_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the token through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
			want: "x********************************************************************************************************************************************************************",
		},
		{
			name: "underscore before",
			src:  "OP_SERVICE_ACCOUNT_TOKEN_ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
			want: "OP_SERVICE_ACCOUNT_TOKEN_********************************************************************************************************************************************************************",
		},
	}

	m := New(WithPatterns(OnePasswordServiceAccountToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OnePasswordServiceAccountToken_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a run rather than a count. Where a token ends is
	// where its alphabet stops, so ordinary punctuation ends one and nothing
	// written after it joins it — but a character of the token's own alphabet
	// written straight against a token is redacted with the token, which is
	// what buys a token whose object nobody has measured being located whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the token is ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc.",
			want: "the token is ********************************************************************************************************************************************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export OP_SERVICE_ACCOUNT_TOKEN="ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc"`,
			want: `export OP_SERVICE_ACCOUNT_TOKEN="********************************************************************************************************************************************************************"`,
		},
		{
			// The hyphen is a body character, so a hyphenated word written
			// against a token is read as more of the run and redacted with it.
			name: "a dashed word against the token",
			src:  "ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc-suffix",
			want: "***************************************************************************************************************************************************************************",
		},
		{
			name: "a word against the token",
			src:  "ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcsuffix",
			want: "**************************************************************************************************************************************************************************",
		},
	}

	m := New(WithPatterns(OnePasswordServiceAccountToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OnePasswordServiceAccountToken_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, which is the token a column limit cut short of it.
	// The two cases here are one character apart: the shorter is left in the
	// output whole. A token is long enough that a line cut this way is the
	// ordinary way to meet half of one, which is what a low floor is bought
	// for and what raising it would sell.
	//
	// Lowering it further would let a run of the alphabet that merely opens the
	// right way in, which builtin_1password_service_account_token.go weighs.
	// The pair is here so that a change to the number is a decision rather than
	// something noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a body one character short of the floor",
			src:  "ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
			want: "ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
		},
		{
			name: "a body exactly as long as the floor",
			src:  "ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
			want: "********************************************************************************************************************************************************************",
		},
	}

	m := New(WithPatterns(OnePasswordServiceAccountToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OnePasswordServiceAccountToken_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The anchor is seven
	// characters of the base64url alphabet, so a long enough encoding written
	// in that alphabet carries them somewhere, and the run from there to the
	// end of the encoding is redacted.
	//
	// The cases are held to being redacted rather than to being spared. What is
	// taken is a stretch of a value already opaque to a reader, and the
	// underscore the anchor carries keeps standard base64 — a certificate, a
	// PEM body, an embedded image — out of reach of it. What the table is for
	// is that the cases move with the scan: one of them ceasing to be located
	// means the grammar changed, and that is a decision to be taken rather than
	// noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "inside a base64url payload",
			src:  "payload=zzzzops_eyJzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			want: "payload=zzzz********************************************************************************************************************************************************************",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is this
			// pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzops_eyJzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz********************************************************************************************************************************************************************",
		},
	}

	m := New(WithPatterns(OnePasswordServiceAccountToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_onePasswordServiceAccountTokenAnchor(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a token
	// can begin inside the run of the one before it, and that holds only while
	// every character of the anchor is one a body may be written in. An anchor
	// carrying a character outside the alphabet would make the two impossible
	// to nest, and the case above pinning the nesting would stand for nothing —
	// which is not a failure anything else here reports.
	if onePasswordServiceAccountTokenPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	if onePasswordServiceAccountTokenHeader == "" {
		t.Fatal("the pattern carries no header, so its prefix alone would locate tokens")
	}
	if want := onePasswordServiceAccountTokenPrefix + onePasswordServiceAccountTokenHeader; onePasswordServiceAccountTokenAnchor != want {
		t.Errorf("the anchor is %q, the prefix and the header together are %q", onePasswordServiceAccountTokenAnchor, want)
	}
	for i := range len(onePasswordServiceAccountTokenAnchor) {
		if c := onePasswordServiceAccountTokenAnchor[i]; !isBase64URLByte(c) {
			t.Errorf("the anchor holds %q, which no body may be written with", c)
		}
	}

	// The body opens at the header, so the run a candidate is measured in is
	// the run the header stands in. The scan reaches that run by walking from
	// the character behind the prefix, which is sound only while the prefix is
	// what the anchor opens with.
	if !strings.HasPrefix(onePasswordServiceAccountTokenAnchor, onePasswordServiceAccountTokenPrefix) {
		t.Errorf("the anchor %q does not open with the prefix %q", onePasswordServiceAccountTokenAnchor, onePasswordServiceAccountTokenPrefix)
	}

	// And the byte the search stops at stands at the index a candidate is read
	// back from. builtin_scan.go says why that is held here rather than left to
	// the targets.
	if onePasswordServiceAccountTokenAnchorIndex >= len(onePasswordServiceAccountTokenAnchor) {
		t.Fatalf("the search stops at %d, the anchor is %d characters", onePasswordServiceAccountTokenAnchorIndex, len(onePasswordServiceAccountTokenAnchor))
	}
	if c := onePasswordServiceAccountTokenAnchor[onePasswordServiceAccountTokenAnchorIndex]; c != onePasswordServiceAccountTokenAnchorByte {
		t.Errorf("the anchor carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(onePasswordServiceAccountTokenAnchorByte))
	}
}

func Test_onePasswordServiceAccountTokenHeader(t *testing.T) {
	// What the three characters are: the opening of the base64url of a JSON
	// object, which is why they stand behind the prefix whichever key
	// 1Password writes first. The first two bytes of such an object are a brace
	// and a quotation mark and are fixed; the third is the first character of
	// that key, and only its top two bits reach the third character of the
	// encoding.
	//
	// The claim is checked by encoding the bytes for every value the third can
	// take rather than by naming the keys the vendor's own token and the
	// published examples happen to open on, so that the edge is stated as an
	// edge: the header stands for a key opening with any byte whose top two
	// bits are 01, which is every ASCII letter, and stands for no other.
	const (
		firstByteTheHeaderSpells = 0x40
		lastByteTheHeaderSpells  = 0x7f
	)

	for b := range 256 {
		got := serializedJSONObjectHeader(byte(b))
		spells := strings.HasPrefix(got, onePasswordServiceAccountTokenHeader)
		want := firstByteTheHeaderSpells <= b && b <= lastByteTheHeaderSpells
		if spells != want {
			t.Errorf("an object whose first key opens with byte %#02x encodes to %q; the header %q spells it %v, want %v", b, got, onePasswordServiceAccountTokenHeader, spells, want)
		}
	}

	// And the letters every key of the object the vendor prints opens with,
	// which is what the cases above rest on.
	for _, key := range []string{"email", "muk", "secretKey", "srpX", "signInAddress", "userAuth", "throttleSecret", "deviceUuid"} {
		if got := serializedJSONObjectHeader(key[0]); !strings.HasPrefix(got, onePasswordServiceAccountTokenHeader) {
			t.Errorf("an object opening on %q encodes to %q, which does not open with the header %q", key, got, onePasswordServiceAccountTokenHeader)
		}
	}
}

// serializedJSONObjectHeader returns the four characters the base64url of a
// JSON object opens with when the first character of its first key is
// firstKeyByte: the brace the object opens with, the quotation mark that opens
// the key, and that character, which are the first three bytes of the
// serialization and so the first base64 group of the encoding.
//
// It is written out here rather than taken from encoding/base64, and the two
// fixed bytes are named rather than read from the pattern, so that the claim
// onePasswordServiceAccountTokenHeader makes can be read from the test that
// makes it.
func serializedJSONObjectHeader(firstKeyByte byte) string {
	const (
		alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		brace    = '{' // what a JSON object opens with
		quote    = '"' // what the first key opens with
	)

	group := int(brace)<<16 | int(quote)<<8 | int(firstKeyByte)

	var b strings.Builder
	for shift := 18; shift >= 0; shift -= 6 {
		b.WriteByte(alphabet[group>>shift&0x3f])
	}
	return b.String()
}

func Test_OnePasswordServiceAccountToken_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a run dense in anchors
	// holds a candidate for every seven characters it has. One thing a
	// candidate reads is a walk over the rest of the input rather than a
	// bounded test — where its run ends — and repeating it at every candidate
	// costs time quadratic in the length of the line. The bound here is far
	// above a linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every hundred and sixty-four bytes where they are densest,
	// because a sample has to carry a whole body to be one. The crowding a run
	// can actually carry, a candidate every seven bytes, stays here.
	sources := map[string]string{
		// One run, a candidate every seven characters, and every one of them a
		// token reaching the end of it: the run cursor is walked once and read
		// two hundred thousand times.
		"a candidate every seven characters in one run": strings.Repeat("ops_eyJ", 200000),
		// A candidate every eight characters instead, with every run ended
		// before a body can reach the floor, so every candidate is rejected and
		// the cursor is moved at each of them.
		"a candidate every eight characters, none with a run": strings.Repeat("ops_eyJ.", 200000),
		// The byte the search stops at, as often as it can be written, with no
		// prefix behind any of them: the search reads the whole line and reaches
		// no candidate at all.
		"an anchor byte at every character and no candidate": strings.Repeat("J", 300000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the same and finding a token.
		"a body that runs the length of the line": "ops_eyJ" + strings.Repeat("a", 1800000),
	}

	m := New(WithPatterns(OnePasswordServiceAccountToken()))
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

// referenceOnePasswordServiceAccountTokenFind is the statement of what a
// 1Password service account token is, kept here so that the scan in
// builtin_1password_service_account_token.go can be held to it: the prefix, the
// three characters the base64url of a JSON object opens with, and a body of the
// base64url alphabet at least as long as the floor, found afresh at every
// position with nothing remembered between them.
//
// The prefix, the header, the floor and the alphabet are spelled again rather
// than built from onePasswordServiceAccountTokenPrefix,
// onePasswordServiceAccountTokenHeader,
// onePasswordServiceAccountTokenBodyChars and isBase64URLByte. A reference
// sharing those declarations could not disagree with the scan about them, and
// it is exactly that disagreement the fuzz target below is for: the two have to
// be changed together or reported apart.
//
// Every position is a starting point in its own right, a match included,
// because every character of the anchor belongs to the alphabet a body is
// written in: ops_eyJops_eyJ... holds a token beginning inside the match before
// it. The scan finds both and reports the two spans overlapping for a Masker to
// resolve, so the reference must ask about both.
//
// It is written out rather than built on a regular expression, for the reason
// the PyPI reference gives: the grammar states compactly as
// ops_eyJ[0-9A-Za-z_-]{157,}, and a counted repetition is what an engine has the
// least room to skip, so a run the anchor can be written inside is re-walked at
// every candidate through a machine a hundred and fifty-seven states wide —
// three times the width the PyPI floor asks for. The walk below re-walks the
// same run and nothing more, which still costs time quadratic in the length of
// such a run; that is the price of a reference with no cursor to be wrong
// about, and the reason the seeds below keep such a run short rather than
// inviting the mutator to grow it. Test_builtins_scanIsLinear and
// Test_OnePasswordServiceAccountToken_scanIsLinear are where the cost the scan
// pays is held down.
func referenceOnePasswordServiceAccountTokenFind(src string) []Span {
	const (
		prefix    = "ops_"
		header    = "eyJ"
		bodyChars = 160
	)

	body := func(c byte) bool {
		return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || c == '-' || c == '_'
	}

	var spans []Span
	for start := range len(src) {
		if !strings.HasPrefix(src[start:], prefix+header) {
			continue
		}

		at := start + len(prefix)
		end := at
		for end < len(src) && body(src[end]) {
			end++
		}
		if end-at < bodyChars {
			continue
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return spans
}

// FuzzOnePasswordServiceAccountToken_matchesReference guards the hand-written
// scan: the anchor it searches for, the floor it holds a body to, the alphabet
// it reads that body in, the run it remembers between candidates and the byte
// it resumes at may none of them change which tokens are located.
func FuzzOnePasswordServiceAccountToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("OP_SERVICE_ACCOUNT_TOKEN=ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc")
	f.Add("ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab_0123456789abcdef0123456789abcdef012")     // a hyphen and an underscore in the body
	f.Add("ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc")     // a body exactly as long as the floor
	f.Add("ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab")      // one short of one
	f.Add("ops_ey0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd")     // two characters of the header
	f.Add("ops_EYJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc")     // a header in the wrong case
	f.Add("OPS_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc")     // an uppercase prefix
	f.Add("ops-eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc")     // a hyphen where the prefix carries an underscore
	f.Add("ops_ eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc")    // a space between the prefix and the header
	f.Add("ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef+0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") // standard base64 rather than base64url
	f.Add("ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") // a dot ends the body
	f.Add("ops_eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef")                                                                                                             // a JWT behind the prefix
	f.Add("ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc-suffix")
	f.Add("ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc\nops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc")
	// A token beginning inside the match before it, which a scan resuming past
	// a match steps over, and two tokens with nothing between them.
	f.Add("ops_eyJops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc")
	f.Add("ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc")
	// Candidate positions crowded as close as they can be: a body long enough
	// for all of them, and a body long enough for none.
	f.Add(strings.Repeat("ops_eyJ", 12) + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc")
	f.Add(strings.Repeat("ops_eyJ.", 12))
	f.Add(strings.Repeat("ops_", 16))
	// The names that carry the prefix, which only the header turns away.
	f.Add("the ops_team runbook lives beside ops_runbook and ops_oncall")
	// The anchor written inside a run of the alphabet, which is the over-match
	// the pattern admits.
	f.Add("payload=zzzzops_eyJzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzops_eyJzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")

	fuzzAgainstReference(f, OnePasswordServiceAccountToken().Find, referenceOnePasswordServiceAccountTokenFind)
}

// onePasswordServiceAccountTokenFindBenchmarks is what this scan is timed on.
// The builtinPatterns entry for the pattern names it, and BenchmarkBuiltins
// times every case it holds under the pattern's own name, so that a built-in
// cannot arrive without a benchmark. Every case is held to the count it states
// under a plain go test as well, which is what a benchmark nobody has run yet
// cannot be.
func onePasswordServiceAccountTokenFindBenchmarks() []benchmarkCase {
	// An ordinary line carries no anchor and no capital J, so what it times is
	// the search for one and the return behind it — which is the whole of what
	// this pattern costs a caller whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="reading a secret from the vault" op=item-get account=my.1password.com `
	token := "ops_eyJ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every eight characters with every run ended short of
			// the floor: each of them reaches the body of the loop and none
			// becomes a token. What it times is the run cursor being moved,
			// once per candidate and no more.
			name:  "candidates that are not values",
			src:   strings.Repeat("ops_eyJ.", 128),
			spans: 0,
		},
		{
			// The same crowding inside one run long enough for every candidate,
			// so each locates a token and every span reaches the same place.
			// This is what the run cursor exists for: without it the run is
			// read once per candidate. The tail is what carries the last
			// candidate to the floor exactly.
			name:  "candidates crowded in one run",
			src:   strings.Repeat("ops_eyJ", 128) + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc",
			spans: 128,
		},
		{
			// The byte the search stops at, as often as a word of prose can
			// carry it and with no prefix behind any of them: the search stops
			// at every one and the index test turns it away.
			name:  "anchor bytes that open no candidate",
			src:   strings.Repeat("JSON ", 256),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "OP_SERVICE_ACCOUNT_TOKEN=" + token,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "OP_SERVICE_ACCOUNT_TOKEN=" + token,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"OP_SERVICE_ACCOUNT_TOKEN="+token+"\n", 32),
			spans: 32,
		},
	}
}
