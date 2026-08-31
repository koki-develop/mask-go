package mask

import (
	"slices"
	"strings"
	"testing"
)

// The Pinecone API key pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. The label is 012345, which is six characters and
// so is a whole one; the secret is 0123456789abcdef written three times and
// then as far as its e, which is sixty-three and so is a whole one too. Written
// out with a prefix and the separator between them they come to seventy-five
// characters under pcsk_ and seventy-six under pckey_.

func Test_PineconeAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{0, 75}},
		},
		{
			name: "a key in an environment assignment",
			src:  "PINECONE_API_KEY=pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{17, 92}},
		},
		{
			// The prefix the Admin API reference states new keys are issued
			// with, over the same body.
			name: "a key under the new prefix",
			src:  "pckey_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{0, 76}},
		},
		{
			// Both parts are base62, so an uppercase key is as ordinary as a
			// lowercase one.
			name: "an uppercase secret",
			src:  "pcsk_012345_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDE",
			want: []Span{{0, 75}},
		},
		{
			// The label's floor is five, which is the shorter of the two
			// lengths the one published rule admits.
			name: "a label of five characters",
			src:  "pcsk_01234_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{0, 74}},
		},
		{
			// No ceiling is read on the label, so a longer run in front of the
			// separator is a label as much as a six character one is.
			name: "a label longer than any published key carries",
			src:  "pcsk_0123456789abcdef_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{0, 85}},
		},
		{
			// The secret is read as a floor and the span reaches to the end of
			// its run, so a run longer than sixty-three characters is one key
			// and not a key with something written after it.
			name: "a secret run longer than the floor",
			src:  "pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 76}},
		},
		{
			// Written with nothing between them, the first key's secret run
			// carries on through the four letters the second key's prefix opens
			// with and ends at the underscore that prefix closes with. The two
			// spans overlap, which a Masker resolves into one.
			name: "two keys with nothing between them",
			src:  "pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdepcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{0, 79}, {75, 150}},
		},
		{
			name: "two keys with a space between them",
			src:  "pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde pckey_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{0, 75}, {76, 152}},
		},
		{
			// A secret closing with pcsk opens a candidate four characters
			// before that secret ends: the underscore it reads as the end of
			// its prefix is the one dividing the next label from its secret. A
			// scan resuming past a match would step over this key and leave it
			// in the output whole.
			name: "a key beginning inside the key before it",
			src:  "pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789apcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{0, 75}, {71, 146}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PineconeAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PineconeAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "pcsk_",
		},
		{
			name: "a label with no separator behind it",
			src:  "pcsk_012345",
		},
		{
			name: "a label and a separator with no secret behind them",
			src:  "pcsk_012345_",
		},
		{
			// Four characters where the pattern asks for five.
			name: "a label one character short of the floor",
			src:  "pcsk_0123_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// Sixty-two where the pattern asks for sixty-three.
			name: "a secret one character short of the floor",
			src:  "pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		},
		{
			// The underscore is the one character of the format that is in
			// neither part's alphabet, so nothing else divides the two.
			name: "a hyphen where the separator belongs",
			src:  "pcsk_012345-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "a dot where the separator belongs",
			src:  "pcsk_012345.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "a hyphen where the prefix carries its underscore",
			src:  "pcsk-012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// The label is base62, so the underscore that ends it cannot stand
			// inside it: the run ended at the first, and what follows is a
			// secret of four characters.
			name: "an underscore inside the label",
			src:  "pcsk_0123_45_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// Neither character base64url adds beyond base62 is admitted, so
			// the run is cut where the hyphen falls and the secret is short of
			// its floor.
			name: "a hyphen inside the secret",
			src:  "pcsk_012345_0123456789abcdef-123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "a secret broken by a space",
			src:  "pcsk_012345_0123456789abcdef 123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "a secret broken by a line break",
			src:  "pcsk_012345_0123456789abcdef\n123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "an uppercase prefix",
			src:  "PCSK_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// A run of the right shape opening with something else. The two
			// prefixes are the whole of the anchor.
			name: "a value of the right shape opening with no prefix",
			src:  "xxxx_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// The two prefixes agree on pc and part at the third character, so
			// an opening that carries neither of the two spellings behind it is
			// no prefix however much of one it holds.
			name: "the opening with neither spelling behind it",
			src:  "pcs_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "the shorter prefix with a letter where its underscore belongs",
			src:  "pcsky_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// No word is spelled pcsk or pckey, so no snake_case name reaches a
			// prefix however it is written.
			name: "a snake_case name whose segment is nearly a prefix",
			src:  "pck_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PineconeAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PineconeAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "PINECONE_API_KEY=pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: "PINECONE_API_KEY=***************************************************************************",
		},
		{
			// How a key reaches the API, and how it reaches a log line that
			// echoed the header.
			name: "the api-key header Pinecone's endpoints are called with",
			src:  "Api-Key: pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: "Api-Key: ***************************************************************************",
		},
		{
			// The response a key is first read out of, which is the only place
			// the Admin API ever returns one.
			name: "the response that first reports it",
			src:  `{"key":{"name":"example-api-key"},"value":"pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"}`,
			want: `{"key":{"name":"example-api-key"},"value":"***************************************************************************"}`,
		},
		{
			name: "the command line that configures the cli",
			src:  "pc auth configure --api-key pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: "pc auth configure --api-key ***************************************************************************",
		},
		{
			name: "twice",
			src:  "pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde pckey_012345_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDE",
			want: "*************************************************************************** ****************************************************************************",
		},
		{
			// The two spans are merged, so the key that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a key beginning inside the key before it",
			src:  "pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789apcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: "**************************************************************************************************************************************************",
		},
	}

	m := New(WithPatterns(PineconeAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PineconeAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern, which the one published rule
	// asks for, would not trim these matches but drop them, letting the key
	// through whole. The first of them is also what the tightening some scans
	// here take would cost — which, since no word closes on pcsk or pckey, buys
	// nothing.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "xpcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: "x***************************************************************************",
		},
		{
			name: "underscore before",
			src:  "PINECONE_API_KEY_pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: "PINECONE_API_KEY_***************************************************************************",
		},
		{
			// The far side of the same choice. The secret is read to the end of
			// its run, so a character of the key's own alphabet written after
			// one is redacted with it rather than left standing.
			name: "a character of the secret's class after",
			src:  "pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeX",
			want: "****************************************************************************",
		},
	}

	m := New(WithPatterns(PineconeAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PineconeAPIKey_leavesWhatFollowsAlone(t *testing.T) {
	// Neither the hyphen nor the underscore belongs to the alphabet either part
	// is written in, so a run ends where one falls and what is written after a
	// key stays where it stands.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the key is pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde.",
			want: "the key is ***************************************************************************.",
		},
		{
			name: "quoted",
			src:  `"pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"`,
			want: `"***************************************************************************"`,
		},
		{
			name: "dashed word",
			src:  "pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde-suffix",
			want: "***************************************************************************-suffix",
		},
		{
			name: "underscored word",
			src:  "pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde_tail",
			want: "***************************************************************************_tail",
		},
	}

	m := New(WithPatterns(PineconeAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PineconeAPIKey_cutShortOfTheFloor(t *testing.T) {
	// What reading the secret as a floor costs. A line cut to a column limit
	// partway through a key leaves a prefix, a label and a secret too short to
	// be one, and nothing is located: the characters written before the cut
	// stay in the output. builtin_pinecone_api_key.go weighs that against what
	// an exact count would cost the day Pinecone lengthens a secret, which is
	// every key issued from then on.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "cut inside the label",
			src:  "pcsk_0123",
		},
		{
			name: "cut at the separator",
			src:  "pcsk_012345_",
		},
		{
			name: "cut a third of the way through the secret",
			src:  "pcsk_012345_0123456789abcdef0123",
		},
		{
			name: "cut one character short of the floor",
			src:  "pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PineconeAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PineconeAPIKey_theNewPrefix(t *testing.T) {
	// The two prefixes read the same body. pcsk_ is what Pinecone's CLI reference
	// writes a key with and what the one published rule reads; pckey_ is what
	// Pinecone's Admin API reference states new keys are issued with, and
	// Pinecone writes no whole key carrying it. Reading it with the same floors
	// is the wager builtin_pinecone_api_key.go names, and this is what holds the
	// two prefixes to the same grammar rather than letting one drift.
	body := "012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"

	for _, prefix := range []string{"pcsk_", "pckey_"} {
		t.Run(prefix, func(t *testing.T) {
			src := prefix + body
			want := []Span{{0, len(src)}}
			if got, _ := PineconeAPIKey().Find(src); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", src, got, want)
			}
		})
	}
}

func Test_PineconeAPIKey_aLabelOutsideTheAlphabet(t *testing.T) {
	// The label is read as letters and digits, which is what the one rule that
	// reads this format admits there, surfacing the part as a key id. Pinecone
	// states nothing about the part at all, and the reading it leaves open is
	// a label derived from the name a key was created under — where names are
	// hyphenated in Pinecone's own guides. This is what that would cost: a key
	// whose label carried a hyphen or an underscore is located nowhere, whole
	// secret and all, because the run in front of the separator ends at that
	// character. builtin_pinecone_api_key.go weighs it, and the cases are here
	// so that the sentence is held to the scan rather than taken on trust.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a hyphenated label",
			src:  "pcsk_example-api-key_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "an underscored label",
			src:  "pckey_example_api_key_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PineconeAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PineconeAPIKey_insideAnOpaqueRun(t *testing.T) {
	// base64url holds the underscore where hexadecimal and standard base64 do
	// not, so a payload written in it can carry a whole prefix and both
	// separators inside itself. Where the runs between them are long enough,
	// the stretch from the prefix to the end of the payload is redacted. It is
	// paid rather than avoided: there is nothing left to tell such a stretch
	// from a key, and a scan declining it would decline every key Pinecone
	// issues.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// The shape the rationale names: a prefix and both separators
			// standing inside a payload, with the payload carrying on past the
			// characters that stand where a secret stands. What is redacted
			// reaches from the prefix to wherever the payload's own run ends,
			// which here is the underscore in front of its last segment — so
			// the redaction takes text that was never a credential, and the
			// text either side of it stays.
			name: "a prefix and both separators inside a base64url payload",
			src:  "eyJhbGciOiJIUzI1NiJ9_pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0123456789abcdef_signature",
			want: []Span{{21, 112}},
		},
		{
			// The prefix written straight behind base62 characters, which is
			// where the demand that no letter stand in front of a prefix would
			// have dropped the key.
			name: "a prefix behind an opaque run",
			src:  "0123456789abcdefpcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{16, 91}},
		},
		{
			// The characters that end a run are what a payload has to be free
			// of for the shape to be reached at all.
			name: "a prefix behind a run a hyphen ends",
			src:  "0123456789abcdef-pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{17, 92}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PineconeAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PineconeAPIKey_aDigestWhereTheSecretBelongs(t *testing.T) {
	// The collision a prefix leaves where everything behind it is one class is a
	// digest written there. Hexadecimal digits are base62 and a digest carries
	// nothing that ends a run, so a digest standing where a secret belongs is a key's
	// format exactly and is redacted whole — which is right for the reason the
	// floor is read at all: declining it would decline every key Pinecone
	// happened to write in the digits and the first six letters.
	//
	// What the floor turns away is the digest too short to be a secret, and
	// what the separator turns away is the digest with no label in front of it.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// Sixty-four hexadecimal characters, which is more than the floor
			// asks for, so nothing turns this away.
			name: "a sha-256 where the secret belongs",
			src:  "pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 76}},
		},
		{
			// Forty characters, which is short of the floor.
			name: "a sha-1 where the secret belongs",
			src:  "pcsk_012345_0123456789abcdef0123456789abcdef01234567",
		},
		{
			// Thirty-two, shorter again.
			name: "an md5 where the secret belongs",
			src:  "pcsk_012345_0123456789abcdef0123456789abcdef",
		},
		{
			// A digest carries no underscore, so a prefix written in front of
			// one has no separator behind it to divide a label from a secret.
			name: "a sha-256 straight behind the prefix",
			src:  "pcsk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// And a digest on its own holds no prefix to be found at however
			// long it runs.
			name: "a digest on its own",
			src:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PineconeAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PineconeAPIKey_theClientSecret(t *testing.T) {
	// The other credential Pinecone issues is a service account's client
	// secret, which the Admin API is authenticated with by exchanging it for an
	// access token. It is not read, and builtin_pinecone_api_key.go says why:
	// Pinecone writes it as YOUR_CLIENT_SECRET everywhere it appears and states
	// no prefix, no length and no alphabet for it, so there is nothing to
	// anchor on. The decision is pinned here so that reading one is a change
	// somebody argues for rather than one somebody notices afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a client secret in an environment assignment",
			src:  "PINECONE_CLIENT_SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "a client secret in the body of a token request",
			src:  `{"client_id":"0123456789abcdef","client_secret":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PineconeAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_pineconeAPIKeyPrefixes(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a key can
	// begin inside the one before it, and that holds on what a prefix is made
	// of: the characters in front of its last one are ones a label and a secret
	// are written with, and its last one is the separator a key already
	// carries. A prefix built any other way would make the two impossible to
	// nest, and the case above pinning the nesting would stand for nothing —
	// which is not a failure anything else here reports.
	if len(pineconeAPIKeyPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for _, p := range pineconeAPIKeyPrefixes {
		if !strings.HasPrefix(p, pineconeAPIKeyOpening) {
			t.Errorf("the prefix %q does not open with %q, which the scan tests before comparing it", p, pineconeAPIKeyOpening)
		}
		if c := p[len(p)-1]; c != pineconeAPIKeySeparator {
			t.Errorf("the prefix %q closes with %q, want the separator %q", p, c, pineconeAPIKeySeparator)
		}
		for i := range len(p) - 1 {
			if c := p[i]; !isBase62Byte(c) {
				t.Errorf("the prefix %q holds %q, which no label and no secret may be written with", p, c)
			}
		}
	}

	// The separator ends a label where it stands, which is what makes the count
	// in front of it readable at all and what bounds how many candidates can
	// walk one run.
	if isBase62Byte(pineconeAPIKeySeparator) {
		t.Errorf("the separator %q belongs to the alphabet a label and a secret are written in", pineconeAPIKeySeparator)
	}

	// No prefix stands inside another, which is what lets the scan report the
	// first that matches rather than the longest.
	for i, a := range pineconeAPIKeyPrefixes {
		for j, b := range pineconeAPIKeyPrefixes {
			if i != j && strings.HasPrefix(a, b) {
				t.Errorf("the prefix %q opens with %q, so which of them a candidate carries depends on the order they are tried in", a, b)
			}
		}
	}
}

// Test_pineconeAPIKeyAnchor holds every prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_pineconeAPIKeyAnchor(t *testing.T) {
	for _, p := range pineconeAPIKeyPrefixes {
		if pineconeAPIKeyAnchorIndex >= len(p) {
			t.Fatalf("the anchor stands at %d, the prefix %q is %d characters", pineconeAPIKeyAnchorIndex, p, len(p))
		}
		if c := p[pineconeAPIKeyAnchorIndex]; c != pineconeAPIKeyAnchor {
			t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", p, c, byte(pineconeAPIKeyAnchor))
		}
	}
}

func Test_pineconeAPIKeyPrefixLen(t *testing.T) {
	// What the scan reads a prefix by: the length of the one standing at the
	// start of what it is handed, and zero where none does.
	tests := []struct {
		name string
		src  string
		want int
	}{
		{name: "the shorter prefix", src: "pcsk_012345_", want: 5},
		{name: "the longer prefix", src: "pckey_012345_", want: 6},
		{name: "the opening alone", src: "pc", want: 0},
		{name: "the opening and neither spelling", src: "pcs_012345_", want: 0},
		{name: "an uppercase prefix", src: "PCSK_012345_", want: 0},
		{name: "a prefix one character in", src: "xpcsk_012345_", want: 0},
		{name: "nothing at all", src: "", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pineconeAPIKeyPrefixLen(tt.src); got != tt.want {
				t.Errorf("pineconeAPIKeyPrefixLen(%q) = %d, want %d", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PineconeAPIKey_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a line dense in prefixes
	// holds a candidate for every five characters it has, and each of them
	// walks two runs rather than one. What keeps that linear is the separator:
	// a run is walked as a label only by the candidate whose prefix closes on
	// the character in front of it, and as a secret only by the candidate whose
	// label is the run ending at that character, so no run is walked more than
	// twice. Repeating either walk at every candidate would cost time quadratic
	// in the length of the line. The bound here is far above a linear scan and
	// far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every seventy-one bytes where they are densest, because a sample
	// has to carry a whole key to be one. The crowding a line can actually carry
	// stays here.
	sources := map[string]string{
		// Candidates as close together as the shorter prefix allows, none of
		// them with a label long enough to be one: every one reaches the body
		// of the loop and every one is rejected at the label.
		"a candidate every five characters": strings.Repeat("pcsk_", 400000),
		// The same with a label that reaches its floor, so every candidate
		// walks a label run and a secret run before the floor turns it away.
		"a candidate whose label and secret are both walked": strings.Repeat("pcsk_012345_", 160000),
		// Keys written into one another, each beginning four characters before
		// the one in front of it ends, so every candidate is a key and every one
		// of them walks both runs.
		"a key beginning inside every key": strings.Repeat("pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789apcsk", 20000),
		// One candidate whose secret is the whole line, which is the walk over
		// a run reading the length of the input and finding a key.
		"a secret that runs the length of the line": "pcsk_012345_" + strings.Repeat("a", 1800000),
		// The same for the label, which is the run walked before any count is
		// read.
		"a label that runs the length of the line": "pcsk_" + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("ac", 900000),
		// And the opening's own first letter with no anchor among them, which
		// is the walk reading a whole line and stopping nowhere in it.
		"the letter a prefix opens with and no anchor": strings.Repeat("p", 1800000),
	}

	checkScanIsLinear(t, PineconeAPIKey(), sources)
}

// referencePineconeAPIKeyFind is what a Pinecone API key is, stated again as a
// plain implementation of the same rules and kept here so that the scan in
// builtin_pinecone_api_key.go can be held to it.
//
// The prefixes, the separator, the two floors and the character class are
// spelled again here rather than shared with the scan. A reference reading
// those declarations could not disagree with it about them, and it is exactly
// that disagreement the fuzz target below is for: the two have to be changed
// together or reported apart.
//
// Every position is a starting point in its own right, a match included,
// because the characters in front of each prefix's underscore are written in
// the alphabet a secret is: a secret closing with pcsk holds the start of the
// key behind it. The scan finds both and reports the two spans overlapping for
// a Masker to resolve, so the reference must ask about both.
//
// It is written out rather than built on a regular expression, for the reason
// the Anthropic reference is. The grammar states compactly as
// pc(?:sk|key)_[0-9A-Za-z]{5,}_[0-9A-Za-z]{63,}, and a counted repetition is
// what an engine has the least room to skip. Measured on this pattern's own
// seeds, that expression left the fuzz target at a hundred and sixty thousand
// executions in its first three seconds and none at all for the forty after
// them, where the walks below hold a hundred and eighty thousand a second for
// the whole of a run. The second floor is the difference: the Groq reference
// spells one as a repetition and costs nothing, and this grammar puts another
// behind it.
//
// Walking both runs at every position is what the scan's own arrangement saves
// it from, so this still costs time quadratic in the length of a run a prefix
// can be written inside. That is the price of a reference with nothing
// remembered between candidates to be wrong about, and the reason the seeds
// below keep such a run short rather than inviting the mutator to grow it.
func referencePineconeAPIKeyFind(src string) []Span {
	const (
		separator   = '_'
		labelChars  = 5
		secretChars = 63
	)

	part := func(c byte) bool {
		return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
	}

	var spans []Span
	for start := range len(src) {
		var from int
		switch {
		case strings.HasPrefix(src[start:], "pcsk_"):
			from = start + len("pcsk_")
		case strings.HasPrefix(src[start:], "pckey_"):
			from = start + len("pckey_")
		default:
			continue
		}

		i := from
		for i < len(src) && part(src[i]) {
			i++
		}
		if i-from < labelChars || i == len(src) || src[i] != separator {
			continue
		}

		at := i + 1
		end := at
		for end < len(src) && part(src[end]) {
			end++
		}
		if end-at < secretChars {
			continue
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return spans
}

// FuzzPineconeAPIKey_matchesReference guards the hand-written scan: the
// prefixes it searches for, the two floors it holds a label and a secret to,
// the separator between them, the alphabet it reads them in and the byte it
// resumes at may none of them change which keys are located.
func FuzzPineconeAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("PINECONE_API_KEY=pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	f.Add("pckey_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	f.Add("pcsk_01234_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")            // a label at its floor
	f.Add("pcsk_0123_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")             // and one short of it
	f.Add("pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd")            // a secret one short of its floor
	f.Add("pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")          // and a run longer than one
	f.Add("pcsk_012345-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")           // a hyphen where the separator belongs
	f.Add("pcsk-012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")           // a hyphen where the prefix carries its underscore
	f.Add("pcsk_0123_45_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")          // an underscore inside the label
	f.Add("pcsk_example-api-key_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")  // a hyphenated label
	f.Add("pckey_example_api_key_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde") // and an underscored one
	f.Add("pcsk_012345_0123456789abcdef-123456789abcdef0123456789abcdef0123456789abcde")           // and a hyphen inside the secret
	f.Add("PCSK_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")           // an uppercase prefix
	f.Add("pcs_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")            // the opening with neither spelling behind it
	f.Add("pcsky_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")          // the shorter prefix with a letter where its underscore belongs
	f.Add("pcsk_012345_0123456789abcdef\n123456789abcdef0123456789abcdef0123456789abcde")
	f.Add("xpcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	// A digest where the secret belongs, which the floor admits, and one
	// straight behind the prefix, which the separator turns away.
	f.Add("pcsk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// A key beginning inside the match before it, which a scan resuming past a
	// match steps over, and two keys with nothing between them, which is the
	// same text without the nesting.
	f.Add("pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789apcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	f.Add("pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdepcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	// Candidate positions crowded as close as they can be, under each prefix,
	// and a run of separators, which is where the count either side of one is
	// decided.
	f.Add(strings.Repeat("pcsk_", 32))
	f.Add(strings.Repeat("pckey_", 32))
	f.Add(strings.Repeat("pcsk_", 32) + "012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	f.Add(strings.Repeat("pcsk_012345_", 8))
	f.Add(strings.Repeat("_", 128))
	// The client secret this pattern declines to read.
	f.Add("PINECONE_CLIENT_SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	// A prefix and both separators standing inside a base64url payload, which
	// is the over-match this pattern pays for.
	f.Add("eyJhbGciOiJIUzI1NiJ9_pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0123456789abcdef_signature")

	fuzzAgainstReference(f, PineconeAPIKey().Find, referencePineconeAPIKeyFind)
}

// pineconeAPIKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func pineconeAPIKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens a prefix, so what the line times is the
	// search for one — which is most of what this pattern costs a caller whose
	// text holds no key. It carries the anchor twice, in svc and in the vendor's
	// own name, and neither has the p in front of it that a prefix opens with.
	line := `time=2026-08-17T00:00:00Z level=info msg="querying index" url=https://example-0123456789.svc.aped-0123-a56b.pinecone.io/query status=200 `
	key := "pcsk_012345_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The shorter prefix is five characters, so a run of them holds a
			// candidate for every five it has. Each is turned away at the
			// label, whose run is the four letters of the next prefix and so is
			// short of the floor.
			name:  "candidates that are not values",
			src:   strings.Repeat("pcsk_", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: a label that reaches its floor
			// and a separator behind it, so the secret's run is walked before
			// its length turns the candidate away.
			name:  "candidates walked past the separator",
			src:   strings.Repeat("pcsk_012345_0123456789abcdef ", 16),
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
