package mask

import (
	"slices"
	"strings"
	"testing"
)

// The Honeycomb API key pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a set
// of tests apiece.
//
// The keys written out below are made only of ordered characters: valid in
// shape, obviously not real. A body is written in letters and digits, so the run
// 0123456789abcdefghijklmnopqrstuvwxyz serves for it and carries on from 0 once
// it runs out — once and a half over for the fifty-eight characters an ingest
// key's body comes to, and restarted at each half of a management key's, whose
// twenty-six and thirty-two the colon divides. With the six characters of an
// opening in front, an ingest key comes to sixty-four and a management key to
// sixty-five.

func Test_HoneycombAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an ingest key",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			name: "an ingest key in an environment assignment",
			src:  "HONEYCOMB_API_KEY=hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: []Span{{18, 82}},
		},
		{
			// The shape a Classic team's ingest key takes, which Honeycomb's own
			// libhoney-go and husky still read.
			name: "a classic ingest key",
			src:  "hcaic_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			// The key ID and the secret joined by a colon, which is the value
			// Honeycomb's page writes behind Authorization: Bearer.
			name: "a management key",
			src:  "hcxmk_0123456789abcdefghijklmnop:0123456789abcdefghijklmnopqrstuv",
			want: []Span{{0, 65}},
		},
		{
			// The character Honeycomb assigns at key creation, at either end of
			// the class its own implementations read it in.
			name: "the assigned character at the bottom of its class",
			src:  "hcaik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			name: "the assigned character at the top of its class",
			src:  "hczik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			// The alphabet is read in both cases, so a body carrying no
			// lowercase letter at all is a key.
			name: "an uppercase body",
			src:  "hcxik_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKL",
			want: []Span{{0, 64}},
		},
		{
			// The one opening that carries the byte the scan searches for
			// twice, the character Honeycomb assigns being the anchor itself.
			// One span and not two: the character behind that second h names a
			// kind, where an opening asks for the c.
			name: "the assigned character is the byte the scan searches for",
			src:  "hchik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			name: "two keys with nothing between them",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklhcxmk_0123456789abcdefghijklmnop:0123456789abcdefghijklmnopqrstuv",
			want: []Span{{0, 64}, {64, 129}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HoneycombAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HoneycombAPIKey_theAlphabetAtItsEdges(t *testing.T) {
	// The alphabet a key ID and a secret are written in is the letters of both
	// cases and the digits, so it has six ends, and a value built from an
	// ordered run reaches none of them at a position that matters. Each of the
	// six is written here at the first character of a body, in the middle of
	// one and at the last character, since a scan reading its class at one
	// position and not at another is wrong in a way no ordered body reports.
	//
	// The characters just outside those six ends are in
	// Test_HoneycombAPIKey_noMatch, at the same three positions.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "the first digit opening a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			name: "the last digit opening a body",
			src:  "hcxik_9123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			name: "the first uppercase letter opening a body",
			src:  "hcxik_A123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			name: "the last uppercase letter opening a body",
			src:  "hcxik_Z123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			name: "the first lowercase letter opening a body",
			src:  "hcxik_a123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			name: "the last lowercase letter opening a body",
			src:  "hcxik_z123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			name: "the first digit in the middle of a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrs0uvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			name: "the last digit in the middle of a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrs9uvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			name: "the first uppercase letter in the middle of a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrsAuvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			name: "the last uppercase letter in the middle of a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrsZuvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			name: "the first lowercase letter in the middle of a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrsauvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			name: "the last lowercase letter in the middle of a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrszuvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			name: "the first digit closing a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk0",
			want: []Span{{0, 64}},
		},
		{
			name: "the last digit closing a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk9",
			want: []Span{{0, 64}},
		},
		{
			name: "the first uppercase letter closing a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkA",
			want: []Span{{0, 64}},
		},
		{
			name: "the last uppercase letter closing a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkZ",
			want: []Span{{0, 64}},
		},
		{
			name: "the first lowercase letter closing a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijka",
			want: []Span{{0, 64}},
		},
		{
			name: "the last lowercase letter closing a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkz",
			want: []Span{{0, 64}},
		},
		{
			// The two halves a colon divides are read in the same alphabet, and
			// each of them has its own two ends to reach.
			name: "a key id opening and closing on the ends of the alphabet",
			src:  "hcxmk_z123456789abcdefghijklmnoZ:0123456789abcdefghijklmnopqrstuv",
			want: []Span{{0, 65}},
		},
		{
			name: "a secret opening and closing on the ends of the alphabet",
			src:  "hcxmk_0123456789abcdefghijklmnop:Z123456789abcdefghijklmnopqrstua",
			want: []Span{{0, 65}},
		},
		{
			name: "a digit in the middle of each half",
			src:  "hcxmk_0123456789abc9efghijklmnop:0123456789abcdefgh0jklmnopqrstuv",
			want: []Span{{0, 65}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HoneycombAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HoneycombAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "an opening alone",
			src:  "hcxik_",
		},
		{
			name: "a body one character short",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk",
		},
		{
			name: "a key id one character short",
			src:  "hcxmk_0123456789abcdefghijklmno:0123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "a key id one character long",
			src:  "hcxmk_0123456789abcdefghijklmnopq:0123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "a secret one character short",
			src:  "hcxmk_0123456789abcdefghijklmnop:0123456789abcdefghijklmnopqrstu",
		},
		// The two halves a colon divides are read in the same alphabet as an
		// undivided body, and the characters that alphabet leaves out reach
		// each half at either end and in the middle.
		{
			name: "the separator opening a key id",
			src:  "hcxmk__123456789abcdefghijklmnop:0123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "a hyphen in the middle of a key id",
			src:  "hcxmk_0123456789abc-efghijklmnop:0123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "the separator closing a key id",
			src:  "hcxmk_0123456789abcdefghijklmno_:0123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "a hyphen opening a secret",
			src:  "hcxmk_0123456789abcdefghijklmnop:-123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "a hyphen in the middle of a secret",
			src:  "hcxmk_0123456789abcdefghijklmnop:0123456789abcdefgh-jklmnopqrstuv",
		},
		{
			name: "the separator closing a secret",
			src:  "hcxmk_0123456789abcdefghijklmnop:0123456789abcdefghijklmnopqrstu_",
		},
		// The characters just outside the six ends of the alphabet, at the
		// first character of a body, in the middle of one and at the last.
		{
			name: "the character below the digits opening a body",
			src:  "hcxik_/123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the character above the digits opening a body",
			src:  "hcxik_:123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the character below the uppercase letters opening a body",
			src:  "hcxik_@123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the character above the uppercase letters opening a body",
			src:  "hcxik_[123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the character below the lowercase letters opening a body",
			src:  "hcxik_`123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the character above the lowercase letters opening a body",
			src:  "hcxik_{123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the character below the digits in the middle of a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrs/uvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the character above the digits in the middle of a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrs:uvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the character below the uppercase letters in the middle of a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrs@uvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the character above the uppercase letters in the middle of a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrs[uvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the character below the lowercase letters in the middle of a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrs`uvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the character above the lowercase letters in the middle of a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrs{uvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the character below the digits closing a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk/",
		},
		{
			name: "the character above the digits closing a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk:",
		},
		{
			name: "the character below the uppercase letters closing a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk@",
		},
		{
			name: "the character above the uppercase letters closing a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk[",
		},
		{
			name: "the character below the lowercase letters closing a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk`",
		},
		{
			name: "the character above the lowercase letters closing a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk{",
		},
		// The two word characters the alphabet leaves out, which is what keeps
		// an opening from standing inside a body and what an encoded run would
		// otherwise carry.
		{
			name: "the separator opening a body",
			src:  "hcxik__123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the separator in the middle of a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrs_uvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the separator closing a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk_",
		},
		{
			name: "a hyphen opening a body",
			src:  "hcxik_-123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "a hyphen in the middle of a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrs-uvwxyz0123456789abcdefghijkl",
		},
		{
			name: "a hyphen closing a body",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk-",
		},
		{
			name: "a body broken by a space",
			src:  "hcxik_0123456789abcdefghijklmnopqrs uvwxyz0123456789abcdefghijkl",
		},
		{
			name: "a body broken by a line break",
			src:  "hcxik_0123456789abcdefghijklmnopqrs\nuvwxyz0123456789abcdefghijkl",
		},
		// The character Honeycomb assigns at key creation, read in the class its
		// own implementations read it in and in no other.
		{
			name: "an uppercase letter where the assigned character stands",
			src:  "hcXik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "a digit where the assigned character stands",
			src:  "hc1ik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "a hyphen where the assigned character stands",
			src:  "hc-ik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "no assigned character at all",
			src:  "hcik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		// The opening itself, which is what tells this vendor's keys from
		// anything else of the same width.
		{
			name: "an uppercase opening",
			src:  "HCXIK_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "a letter other than the one an opening begins with",
			src:  "xcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "a letter other than the one behind it",
			src:  "hxxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the separator missing from the opening",
			src:  "hcxik0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "a hyphen where the opening's separator stands",
			src:  "hcxik-0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// A line carrying the byte the scan searches for several times over,
			// none of them with an opening behind it.
			name: "the anchor as it is written in prose",
			src:  "the hive holds the honey that the hexagons hold",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HoneycombAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_HoneycombAPIKey_theKindsItReads(t *testing.T) {
	// The two characters naming the kind are read as a table rather than as any
	// two letters, which is what keeps the openings Honeycomb writes its
	// resource identifiers with from being redacted as secrets. Every kind this
	// scan reads is located, and the ones it does not are left alone however the
	// body behind them is written.
	//
	// mc is there because it is what a scan reading the two characters
	// separately would admit: the m of one kind and the c of another, naming
	// nothing Honeycomb issues.
	located := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an ingest key",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			name: "a classic ingest key",
			src:  "hcxic_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: []Span{{0, 64}},
		},
		{
			name: "a management key",
			src:  "hcxmk_0123456789abcdefghijklmnop:0123456789abcdefghijklmnopqrstuv",
			want: []Span{{0, 65}},
		},
	}

	// Counted rather than trusted, for the reason the corpus counts the case
	// naming every built-in: a kind added to honeycombAPIKeyKinds and to no
	// case here is a kind the scan locates keys of, written out nowhere and
	// absent from the corpus, and nothing that was passing would stop passing.
	if len(located) != len(honeycombAPIKeyKinds) {
		t.Errorf("%d kind(s) are written out here, where the scan reads %d", len(located), len(honeycombAPIKeyKinds))
	}

	for _, tt := range located {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HoneycombAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}

	left := []struct {
		name string
		src  string
	}{
		{
			name: "a configuration key id with a body behind it",
			src:  "hcxlk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the two characters of two different kinds",
			src:  "hcxmc_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the opening an environment identifier carries",
			src:  "hcxen_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the opening a team identifier carries",
			src:  "hcxtm_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "the opening a user identifier carries",
			src:  "hcxus_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
	}

	for _, tt := range left {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HoneycombAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_HoneycombAPIKey_theColonBelongsToOneKindAlone(t *testing.T) {
	// A management key joins its key ID and its secret with a colon where the
	// ingest kinds concatenate the two, and the kind decides which layout is
	// read. A colon written into an ingest key's body is a character the
	// alphabet leaves out, and a management key written without one is a body
	// whose colon is missing where the layout puts it: neither is located.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "an ingest key written with a colon",
			src:  "hcxik_0123456789abcdefghijklmnop:0123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "a classic ingest key written with a colon",
			src:  "hcaic_0123456789abcdefghijklmnop:0123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "a management key written without one",
			src:  "hcxmk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
		},
		{
			name: "a management key whose colon stands one character early",
			src:  "hcxmk_0123456789abcdefghijklmn:op0123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "a management key whose colon stands one character late",
			src:  "hcxmk_0123456789abcdefghijklmnopq:0123456789abcdefghijklmnopqrstu",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HoneycombAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_HoneycombAPIKey_aKeyIDIsNoValue(t *testing.T) {
	// Honeycomb's page on managing keys calls the key ID a label that
	// identifies this key in the Honeycomb UI, and it is the whole of what a
	// configuration key's opening ever stands in front of. So an opening and
	// twenty-six characters is not a value and nothing here redacts one —
	// redacting it would take away the label a caller keeps a log by.
	//
	// What the scan asks for past a key ID is the secret, which is
	// thirty-two characters more for an ingest kind and a colon and
	// thirty-two for a management key.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "an ingest key id on its own",
			src:  "hcxik_0123456789abcdefghijklmnop",
		},
		{
			name: "a configuration key id on its own",
			src:  "hcxlk_0123456789abcdefghijklmnop",
		},
		{
			name: "a management key id on its own",
			src:  "hcxmk_0123456789abcdefghijklmnop",
		},
		{
			name: "a management key id with the colon behind it and no secret",
			src:  "hcxmk_0123456789abcdefghijklmnop:",
		},
		{
			name: "a key id in a log line",
			src:  "time=2026-08-17T00:00:00Z level=info msg=\"key used\" key_id=hcxik_0123456789abcdefghijklmnop",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HoneycombAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_HoneycombAPIKey_theKeysThatCarryNoOpening(t *testing.T) {
	// The credentials of this vendor's that reading an opening leaves in the
	// output, which builtin_honeycomb_api_key.go weighs. A configuration key's
	// Token is the twenty-two characters of letters and digits its
	// authentication page writes, and a Classic team's API key is thirty-two
	// hexadecimal characters, both with no prefix and no separator — Refinery's
	// expression admits twenty to twenty-three of the first and states the
	// second exactly.
	//
	// Either is a word of an identifier, a git short SHA or an MD5, so a pattern
	// reading them would redact text a reader reads rather than a value already
	// opaque. The decision is written down here so that reading them is a change
	// somebody argues for rather than one somebody notices afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a configuration key token in the header it is sent in",
			src:  "X-Honeycomb-Team: 0123456789abcdefghijkl",
		},
		{
			name: "a configuration key token in an environment assignment",
			src:  "HONEYCOMB_API_KEY=0123456789abcdefghijkl",
		},
		{
			name: "a classic api key in the header it is sent in",
			src:  "X-Honeycomb-Team: 0123456789abcdef0123456789abcdef",
		},
		{
			name: "a classic api key in an environment assignment",
			src:  "HONEYCOMB_API_KEY=0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HoneycombAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_HoneycombAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "HONEYCOMB_API_KEY=hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: "HONEYCOMB_API_KEY=****************************************************************",
		},
		{
			// How an ingest key reaches the API, and how it reaches a log line
			// that echoed the header.
			name: "the header an ingest key is sent in",
			src:  "X-Honeycomb-Team: hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: "X-Honeycomb-Team: ****************************************************************",
		},
		{
			name: "the header a management key is sent in",
			src:  "Authorization: Bearer hcxmk_0123456789abcdefghijklmnop:0123456789abcdefghijklmnopqrstuv",
			want: "Authorization: Bearer *****************************************************************",
		},
		{
			name: "a command line",
			src:  "curl -H 'X-Honeycomb-Team: hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl' https://api.honeycomb.io/1/batch/my-dataset",
			want: "curl -H 'X-Honeycomb-Team: ****************************************************************' https://api.honeycomb.io/1/batch/my-dataset",
		},
		{
			name: "a json body",
			src:  `{"apiKey":"hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl"}`,
			want: `{"apiKey":"****************************************************************"}`,
		},
		{
			// The two keys a collector's configuration is written with, which is
			// where two of them arrive together.
			name: "the values a collector is configured with",
			src:  "  api_key: hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl\n  mgmt_key: hcxmk_0123456789abcdefghijklmnop:0123456789abcdefghijklmnopqrstuv",
			want: "  api_key: ****************************************************************\n  mgmt_key: *****************************************************************",
		},
	}

	m := New(WithPatterns(HoneycombAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HoneycombAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the key through whole. The first two are what a
	// boundary in front would cost.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "xhcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: "x****************************************************************",
		},
		{
			name: "underscore before",
			src:  "HONEYCOMB_API_KEY_hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
			want: "HONEYCOMB_API_KEY_****************************************************************",
		},
		{
			// The far side of the same choice, and the one that costs something.
			// A boundary behind the match would drop this key rather than trim
			// it; without one the sixty-four characters Honeycomb issued are
			// redacted and the one written after them, which is part of no
			// credential, stays in the text.
			name: "a character of the body's class after",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklm",
			want: "****************************************************************m",
		},
		{
			name: "a character of the body's class after a management key",
			src:  "hcxmk_0123456789abcdefghijklmnop:0123456789abcdefghijklmnopqrstuvw",
			want: "*****************************************************************w",
		},
	}

	m := New(WithPatterns(HoneycombAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HoneycombAPIKey_leavesWhatFollowsAlone(t *testing.T) {
	// A key is sixty-four characters and no more, or sixty-five where a colon
	// divides its halves, so what is written after one stays whatever it is
	// written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the key is hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl.",
			want: "the key is ****************************************************************.",
		},
		{
			name: "quoted",
			src:  `"hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl"`,
			want: `"****************************************************************"`,
		},
		{
			name: "dashed word",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl-suffix",
			want: "****************************************************************-suffix",
		},
		{
			// A multi-byte rune written immediately against the key. Neither its
			// UTF-8 encoding nor the byte in front of it belongs to the body's
			// alphabet, so the count alone ends the key exactly as it does
			// against a single-byte character.
			name: "a rune written against a key",
			src:  "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl日本語",
			want: "****************************************************************日本語",
		},
	}

	m := New(WithPatterns(HoneycombAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HoneycombAPIKey_aKeyBeginningInsideAnother(t *testing.T) {
	// What advancing rather than consuming the match is load-bearing for here.
	// The body below closes with hc, the character Honeycomb assigns and a
	// kind, and the separator of the next opening is the character written
	// straight behind the key — so the second key begins five characters before
	// the first one ends. A scan consuming its match would step over it and
	// leave a whole live key in the output.
	//
	// The two spans overlap, which Masker.locate resolves into one redaction.
	src := "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghcaik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl"
	want := []Span{{0, 64}, {59, 123}}

	if got, _ := HoneycombAPIKey().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}

	m := New(WithPatterns(HoneycombAPIKey()))
	masked := "***************************************************************************************************************************"
	if got := m.Mask(src); got != masked {
		t.Errorf("Mask(%q) = %q, want %q", src, got, masked)
	}
}

func Test_HoneycombAPIKey_aDigestBehindAnOpening(t *testing.T) {
	// The collision an opening invites is a digest written behind it, and this
	// format pays for one of these rather than ruling it out.
	//
	// A SHA-256 is sixty-four hexadecimal characters where a body is
	// fifty-eight, so the first fifty-eight of one are a key to this scan and
	// the six behind them stay: fifty-eight characters of the body's own
	// alphabet behind the vendor's own opening is a key's format exactly, and a
	// scan declining it would decline every key Honeycomb happened to write in
	// the hexadecimal digits alone. A SHA-1 at forty characters and an MD5 at
	// thirty-two are short of the count, and a digest reaches the divided shape
	// nowhere, carrying no colon.
	m := New(WithPatterns(HoneycombAPIKey()))

	redacted := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sha-256 behind an ingest opening",
			src:  "hcxik_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "****************************************************************abcdef",
		},
	}

	for _, tt := range redacted {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}

	left := []struct {
		name string
		src  string
	}{
		{
			name: "a sha-1 behind an ingest opening",
			src:  "hcxik_0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "an md5 behind an ingest opening",
			src:  "hcxik_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a sha-256 behind a management opening",
			src:  "hcxmk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range left {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HoneycombAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_HoneycombAPIKey_insideAnOpaqueRun(t *testing.T) {
	// What an encoded run can hold. Standard base64 and base32 write no
	// underscore, so a certificate, a PEM body or an embedded image carries no
	// opening at however long it runs; base64url writes one, so an opening and a
	// body can fall inside a base64url payload by chance.
	//
	// The run from the opening on is then redacted, and what is taken is a
	// stretch of a value that was already opaque to a reader.
	src := "0123456789abcdefghij-_hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl0123456789"
	want := []Span{{22, 86}}

	if got, _ := HoneycombAPIKey().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}
}

func Test_HoneycombAPIKey_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor, and what holds it linear is the counts being
	// counts: a candidate reads at most sixty-five bytes and stops. These are the
	// inputs that would find it wrong here — a line that is nothing but
	// openings, a line that is nothing but keys, and a single base62 run as long
	// as the line, which is where a scan reading a run instead of a count would
	// show itself.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// whole key apiece and so hold a candidate every sixty-four bytes at their
	// densest. The crowding a line can actually carry, a candidate every six,
	// stays here.
	sources := map[string]string{
		// A candidate every six characters, each turned away where the first
		// character of its body would stand, which is the cheapest this scan
		// declines a candidate whose opening is whole.
		"a candidate every six characters": strings.Repeat("hcxik_", 300000),
		// The same crowding with a whole key at each candidate, so every one of
		// them reads fifty-eight characters and reports a span.
		"a key every sixty-four characters": strings.Repeat("hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl", 20000),
		// A candidate walked to its last character before the body's alphabet
		// turns it away, which is the most a rejected candidate can cost.
		"a candidate walked to its last character": strings.Repeat("hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk! ", 20000),
		// One candidate whose body is the whole line. The count stops it at
		// fifty-eight characters; a scan reading the run would read two
		// mebibytes.
		"a base62 run the length of the line": "hcxik_" + strings.Repeat("a", 2000000),
		// The same run with no opening in front of it, so no candidate is found
		// in it at all.
		"a base62 run with no opening": strings.Repeat("a", 2000000),
	}

	checkScanIsLinear(t, HoneycombAPIKey(), sources)
}

// Test_HoneycombAPIKey_holdsAKeyTheInputCutShort states, with a literal number,
// what the second return of Find settles: a piece of an opening standing at the
// end of the input, a candidate the end of the input cut short, and a whole
// match with nothing left unsettled behind it.
func Test_HoneycombAPIKey_holdsAKeyTheInputCutShort(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		want   []Span
		retain int
	}{
		{
			// The byte an opening begins with, and nothing behind it yet.
			name:   "the first character of an opening at the end of the input",
			src:    "the key starts with h",
			retain: len("the key starts with "),
		},
		{
			// A piece reaching the character Honeycomb assigns, which is as far
			// as the input carries it.
			name:   "a piece of an opening at the end of the input",
			src:    "the key starts with hcx",
			retain: len("the key starts with "),
		},
		{
			// And a piece reaching into the two characters naming the kind,
			// where two of the kinds are still open.
			name:   "a piece of an opening inside the kind",
			src:    "the key starts with hcxi",
			retain: len("the key starts with "),
		},
		{
			// The text decided this one: no kind is named with a q, so nothing
			// carrying on from here could open a candidate and the input is
			// settled to its end.
			name:   "a piece the text turned away",
			src:    "the key starts with hcxq",
			retain: len("the key starts with hcxq"),
		},
		{
			// A whole opening and a body the input cuts short of the count. The
			// candidate could still become a key were the input longer, so what
			// is unsettled reaches back to where the candidate opened.
			name:   "a body the input cuts short of the count",
			src:    "hcxik_0123456789abcdefghijklmnop",
			retain: 0,
		},
		{
			// A whole key, and its last five characters an opening of their own.
			// The key is settled and the opening inside it is not: the separator
			// and a body behind it would make a second key that begins here.
			name:   "a key whose last characters open another",
			src:    "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghcaik",
			want:   []Span{{0, 64}},
			retain: 59,
		},
		{
			// A whole key with more text after it, ending in a byte that opens no
			// piece of any opening, so nothing at the end of the input is left
			// unsettled.
			name:   "a whole key followed by settled text",
			src:    "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl tail",
			want:   []Span{{0, 64}},
			retain: len("hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl tail"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := HoneycombAPIKey().Find(tt.src)
			if retain != tt.retain {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, retain, tt.retain)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

// Test_honeycombAPIKeyAnchor holds the byte the scan searches the input for to
// being the one byte an opening may begin with, so that stepping through the
// anchors reaches every candidate there is.
//
// builtin_scan.go says why that is held here rather than left to the targets: an
// opening widened at its first character — a second vendor prefix admitted, a
// case relaxed — would be located nowhere, and nothing that was passing would
// stop passing.
func Test_honeycombAPIKeyAnchor(t *testing.T) {
	if len(honeycombAPIKeyOpening) == 0 {
		t.Fatal("the opening is empty, so every byte of the input opens a candidate")
	}
	if c := honeycombAPIKeyOpening[0]; c != honeycombAPIKeyAnchor {
		t.Errorf("an opening begins with %q, where the scan searches for %q", c, byte(honeycombAPIKeyAnchor))
	}
}

// Test_honeycombAPIKeyKinds holds the kinds to what the scan takes for granted
// about them, none of which any case above reports: the kinds are one width, so
// an input too short for one is too short for all of them and the walk reading
// them may ask about the input's length once; each closes on the separator, so
// every candidate the walk accepts has one; and no two of them are the same
// string, since a kind written twice would report a key twice over.
func Test_honeycombAPIKeyKinds(t *testing.T) {
	for i, k := range honeycombAPIKeyKinds {
		if len(k.close) != honeycombAPIKeyCloseChars {
			t.Errorf("the kind %q closes an opening with %d characters, where an opening is read as %d", k.close, len(k.close), honeycombAPIKeyCloseChars)
		}
		if c := k.close[len(k.close)-1]; c != honeycombAPIKeySeparator {
			t.Errorf("the kind %q closes on %q rather than on the separator %q", k.close, c, byte(honeycombAPIKeySeparator))
		}
		for j, other := range honeycombAPIKeyKinds {
			if i != j && k.close == other.close {
				t.Errorf("the kind %q is written twice, where each kind is read once", k.close)
			}
		}
	}

	// And what the two characters the alphabet leaves out are for. The
	// separator is what keeps an opening from standing inside a body, and the
	// colon is what lets a divided body be read as two halves rather than as
	// one run.
	if isBase62Byte(honeycombAPIKeySeparator) {
		t.Errorf("the separator %q is a character a body is written with", byte(honeycombAPIKeySeparator))
	}
	if isBase62Byte(honeycombAPIKeyDivider) {
		t.Errorf("the divider %q is a character a body is written with", byte(honeycombAPIKeyDivider))
	}
}

// Test_honeycombAPIKeyOpening_holdsNoSecondOpening holds the claim
// builtin_honeycomb_api_key.go makes about where a candidate may open: inside
// an opening, none does. One case drives the input that would find it wrong —
// an opening whose assigned character is the anchor itself — and what is held
// here is the structure behind it, which no input reports.
//
// A second opening would need the anchor and the character behind it standing
// together somewhere past the first byte. Three positions could carry the
// anchor: the character behind the first, which is fixed; the one Honeycomb
// assigns, which is a letter and so may be it; and the three the kind closes
// with. So the character behind the first may not be the anchor, no kind may
// be written with one, and no kind may open on the character an opening asks
// for behind its anchor.
func Test_honeycombAPIKeyOpening_holdsNoSecondOpening(t *testing.T) {
	if len(honeycombAPIKeyOpening) < 2 {
		t.Fatal("an opening states fewer than two characters, so nothing here says where a second one could stand")
	}
	if honeycombAPIKeyOpening[1] == honeycombAPIKeyAnchor {
		t.Errorf("an opening writes %q behind its first character, which is the byte the scan searches for", byte(honeycombAPIKeyAnchor))
	}
	for _, k := range honeycombAPIKeyKinds {
		if i := strings.IndexByte(k.close, honeycombAPIKeyAnchor); i >= 0 {
			t.Errorf("the kind %q writes %q, which is the byte the scan searches for", k.close, byte(honeycombAPIKeyAnchor))
		}
		if k.close[0] == honeycombAPIKeyOpening[1] {
			t.Errorf("the kind %q opens on %q, so an opening whose assigned character is the anchor holds a second one", k.close, honeycombAPIKeyOpening[1])
		}
	}
}

// Test_honeycombAPIKeyChars holds the arithmetic to the numbers Honeycomb's own
// sources state: the twenty-six characters of a key ID its OpenAPI spells, the
// thirty-two of the secret its authentication page writes behind one, the
// fifty-eight Refinery reads a whole ingest key's body at, and the sixty-four a
// classic ingest key comes to in husky.
//
// What it holds is the documentation rather than the scan. The scan never states
// a whole key twice: it reads each half from where the one in front of it ended,
// so counts of other sizes would be located correctly and nothing would go
// wrong. What would go wrong is the sentence on HoneycombAPIKey promising
// sixty-four characters, and the spans every case in this file is written with.
func Test_honeycombAPIKeyChars(t *testing.T) {
	const (
		documentedOpeningChars = 6
		documentedIDChars      = 26
		documentedSecretChars  = 32
		documentedBodyChars    = 58
		documentedChars        = 64
	)

	if honeycombAPIKeyOpeningChars != documentedOpeningChars {
		t.Errorf("an opening is read as %d characters, the documentation prints %d", honeycombAPIKeyOpeningChars, documentedOpeningChars)
	}
	if honeycombAPIKeyIDChars != documentedIDChars {
		t.Errorf("a key id is read as %d characters, the OpenAPI states %d", honeycombAPIKeyIDChars, documentedIDChars)
	}
	if honeycombAPIKeySecretChars != documentedSecretChars {
		t.Errorf("a secret is read as %d characters, the authentication page writes %d", honeycombAPIKeySecretChars, documentedSecretChars)
	}
	if honeycombAPIKeyBodyChars != documentedBodyChars {
		t.Errorf("a body is read as %d characters, Refinery reads %d", honeycombAPIKeyBodyChars, documentedBodyChars)
	}
	if got := honeycombAPIKeyOpeningChars + honeycombAPIKeyBodyChars; got != documentedChars {
		t.Errorf("an ingest key is read as %d characters, husky reads %d", got, documentedChars)
	}
}

// referenceHoneycombAPIKeyAt reads a key at start: hc, a lowercase letter, one
// of the three kinds and an underscore, then a key ID of twenty-six characters
// and a secret of thirty-two, concatenated where the kind writes them so and
// divided by a colon where it writes that. It reports where the key ends.
//
// It is written out rather than built on a regular expression, and what
// decides that is what an expression costs this grammar. The two characters an
// opening begins with are written in the alphabet a body is written in, which
// builtin-patterns.md names as one of the two things that has made an
// expression too slow to fuzz with: an engine's literal search cannot skip a
// run of that alphabet, so it walks a machine as wide as the counts — a
// hundred and sixteen characters between the two halves — at every byte of
// one. Measured over sixteen kibibytes of the characters an opening begins
// with, an expression costs two milliseconds a call unanchored and five asked
// at every byte, against a hundred microseconds for the scan beside it, and
// leaves FuzzHoneycombAPIKey_matchesReference reporting no executions at all
// for a third of its thirty seconds. The walks below read a byte at a time and
// pay nothing for the width of a count.
//
// The opening, the kinds, the counts and the alphabet are written out here
// rather than read from the scan. Reading them would move this with whatever
// the scan was changed to, and the fuzz target below would then hold a rule
// against itself; Test_references_shareNoDeclarationWithTheScans is what keeps
// the two apart.
func referenceHoneycombAPIKeyAt(src string, start int) (int, bool) {
	if start+6 > len(src) || src[start] != 'h' || src[start+1] != 'c' {
		return 0, false
	}
	if c := src[start+2]; c < 'a' || c > 'z' {
		return 0, false
	}
	if src[start+5] != '_' {
		return 0, false
	}

	kind := src[start+3 : start+5]
	body := start + 6
	if kind == "ic" || kind == "ik" {
		end := body + 58
		if end > len(src) || !referenceHoneycombAPIKeyRun(src[body:end]) {
			return 0, false
		}
		return end, true
	}
	if kind != "mk" {
		return 0, false
	}

	id := body + 26
	end := id + 1 + 32
	if end > len(src) || src[id] != ':' {
		return 0, false
	}
	if !referenceHoneycombAPIKeyRun(src[body:id]) || !referenceHoneycombAPIKeyRun(src[id+1:end]) {
		return 0, false
	}
	return end, true
}

// referenceHoneycombAPIKeyRun reports whether every character of s is a letter
// of either case or a digit, which is the alphabet a key ID and a secret are
// written in.
func referenceHoneycombAPIKeyRun(s string) bool {
	for i := range len(s) {
		c := s[i]
		if '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' {
			continue
		}
		return false
	}
	return true
}

// referenceHoneycombAPIKeyFind locates keys the plain way: the rules above
// asked at every byte of the input, with nothing remembered between them.
//
// Asking at every byte is what the scan does too, and it is what a key
// beginning inside another needs: the last characters of a body can open one,
// so a reference resuming past a match would miss the key the scan reports.
func referenceHoneycombAPIKeyFind(src string) []Span {
	var spans []Span
	for start := range len(src) {
		if end, ok := referenceHoneycombAPIKeyAt(src, start); ok {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
}

// FuzzHoneycombAPIKey_matchesReference guards the hand-written scan: the byte it
// searches for, the opening it reads back from that byte, the character
// Honeycomb assigns, the two naming the kind, the separator, the colon of a
// divided body, the counts it reads and the character class it reads them in may
// none of them change which keys are located.
func FuzzHoneycombAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("HONEYCOMB_API_KEY=hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl")
	f.Add("hcaic_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl")                                 // a classic ingest key
	f.Add("hcxmk_0123456789abcdefghijklmnop:0123456789abcdefghijklmnopqrstuv")                                // a management key
	f.Add("hcaik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl")                                 // the assigned character at the bottom of its class
	f.Add("hczik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl")                                 // and at the top
	f.Add("hcXik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl")                                 // an uppercase one, which is none
	f.Add("hc1ik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl")                                 // a digit, which is none either
	f.Add("hcxlk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl")                                 // the configuration key id
	f.Add("hcxmc_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl")                                 // the two characters of two different kinds
	f.Add("hcxen_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl")                                 // the opening an environment identifier carries
	f.Add("hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk")                                  // a body one character short
	f.Add("hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklm")                                // and a run longer than one
	f.Add("hcxik_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKL")                                 // an uppercase body
	f.Add("hcxik_0123456789abcdefghijklmnopqrs_uvwxyz0123456789abcdefghijkl")                                 // the separator inside a body
	f.Add("hcxik_0123456789abcdefghijklmnop:0123456789abcdefghijklmnopqrstuv")                                // an ingest key written with a colon
	f.Add("hcxmk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl")                                 // and a management key written without one
	f.Add("hcxmk_0123456789abcdefghijklmno:0123456789abcdefghijklmnopqrstuv")                                 // a key id one character short
	f.Add("hcxmk_0123456789abcdefghijklmnop:0123456789abcdefghijklmnopqrstu")                                 // a secret one character short
	f.Add("hcxik_0123456789abcdefghijklmnop")                                                                 // a key id on its own
	f.Add("hcxik_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")                           // a sha-256 behind an opening
	f.Add("X-Honeycomb-Team: 0123456789abcdef0123456789abcdef")                                               // a key that carries no opening
	f.Add("xhcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl")                                // written against a letter
	f.Add("0123456789abcdefghij-_hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl0123456789") // an opening inside a base64url run
	// A key whose last characters open another, and two keys with nothing
	// between them, which is what advancing rather than consuming the match has
	// to find.
	f.Add("hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghcaik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl")
	f.Add("hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklhcxmk_0123456789abcdefghijklmnop:0123456789abcdefghijklmnopqrstuv")
	// Candidate positions crowded as close as they can be, and a base62 run
	// with no opening in front of it.
	f.Add(strings.Repeat("hcxik_", 32))
	f.Add(strings.Repeat("hcxik_", 32) + strings.Repeat("0123456789abcdef", 4))
	f.Add(strings.Repeat("0123456789abcdef", 16))

	fuzzAgainstReference(f, HoneycombAPIKey().Find, referenceHoneycombAPIKeyFind)
}

// Test_honeycombAPIKeyFindBenchmarks_lineTheAnchorWasChosenAgainst holds the
// line the benchmarks below are written on to the counts the anchor was chosen
// against, which builtin_honeycomb_api_key.go names: the three bytes standing at
// a fixed index of every opening are the h, the c and the separator, and this
// line carries three of the first, two of the second and none of the third.
//
// The h is searched for all the same, because it stands first and so reaches the
// pieces of an opening the end of the input cut short. The counts are held here
// so that the sentence weighing that choice is one a reader can check rather
// than take.
func Test_honeycombAPIKeyFindBenchmarks_lineTheAnchorWasChosenAgainst(t *testing.T) {
	line := honeycombAPIKeyFindBenchmarks()[0].src

	counts := map[byte]int{'h': 3, 'c': 2, '_': 0}
	for c, want := range counts {
		if got := strings.Count(line, string(c)); got != want {
			t.Errorf("the line carries %q %d times, where the choice of anchor was read off %d", c, got, want)
		}
	}
}

// honeycombAPIKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func honeycombAPIKeyFindBenchmarks() []benchmarkCase {
	// The line carries the byte the scan searches for three times — in the
	// scheme, in the vendor's own host name and in the path — and none of them
	// opens a candidate. It carries the c twice and the separator not at all,
	// which are the other two bytes standing at a fixed index of every opening.
	// Test_honeycombAPIKeyFindBenchmarks_lineTheAnchorWasChosenAgainst holds it
	// to those counts.
	line := `time=2026-08-17T00:00:00Z level=info msg="sending events" url=https://api.honeycomb.io/1/batch/my-dataset `
	key := "hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The opening written over and over, so a candidate stands at every
			// sixth byte and every one of them is turned away where the first
			// character of its body would stand. That is the cheapest this scan
			// declines a candidate whose opening is whole.
			name:  "candidates that are not values",
			src:   strings.Repeat("hcxik_", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: fifty-seven characters of the body
			// walked before the last one turns the candidate away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("hcxik_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijk! ", 16),
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
