package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Atlas service account secret pattern: what it locates and what it leaves
// alone, written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The secrets written out below are made only of ordered characters: valid in
// shape, obviously not real. The run they are built from opens on
// 0123456789abcdef and carries on through the alphabet to z, then back to 0,
// which comes to the forty characters a body is. Where a case is about one
// position of the body rather than about the count, that position is rewritten
// and the rest of the run is left standing, so the body is still forty
// characters.

func Test_AtlasServiceAccountSecret(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a secret on its own",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{0, 50}},
		},
		{
			name: "a secret in an environment assignment",
			src:  "MONGODB_ATLAS_CLIENT_SECRET=mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{28, 78}},
		},
		{
			// The alphabet holds the letters of both cases, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "mdb_sa_sk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
			want: []Span{{0, 50}},
		},
		{
			// The count is exact and the span ends at it, so a forty-first
			// character of the alphabet is a character written after the secret
			// rather than part of one.
			name: "a run longer than the count",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz01234",
			want: []Span{{0, 50}},
		},
		{
			name: "two secrets separated by a space",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123 mdb_sa_sk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
			want: []Span{{0, 50}, {51, 101}},
		},
		{
			// The count ends the first secret where the second opens, so the two
			// spans meet rather than overlapping.
			name: "two secrets with nothing between them",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{0, 50}, {50, 100}},
		},
		{
			// A secret immediately preceded by a digit, by a hyphen, and by a
			// multi-byte rune, and followed by one. The pattern reads no word
			// boundary either side of a match.
			name: "a digit before",
			src:  "9mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{1, 51}},
		},
		{
			name: "a hyphen before",
			src:  "atlas-mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{6, 56}},
		},
		{
			name: "between japanese",
			src:  "シークレットはmdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123です",
			want: []Span{{21, 71}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AtlasServiceAccountSecret().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AtlasServiceAccountSecret_theAlphabetAtItsEnds(t *testing.T) {
	// The base64url alphabet at each of its ends, written at the first character
	// of a body and at the last. A body built from the ordered run reaches none
	// of these by itself: the run opens on a digit and closes on one, so the
	// hyphen, the underscore, the last letter of either case and the last digit
	// are each written into a position of their own here.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a body opening on a hyphen",
			src:  "mdb_sa_sk_-123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{0, 50}},
		},
		{
			name: "a body closing on a hyphen",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz012-",
			want: []Span{{0, 50}},
		},
		{
			name: "a body opening on an underscore",
			src:  "mdb_sa_sk__123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{0, 50}},
		},
		{
			name: "a body closing on an underscore",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz012_",
			want: []Span{{0, 50}},
		},
		{
			name: "a body opening on the last letter of the alphabet",
			src:  "mdb_sa_sk_z123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{0, 50}},
		},
		{
			name: "a body closing on the last letter of the alphabet",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz012z",
			want: []Span{{0, 50}},
		},
		{
			name: "a body opening on the last capital of the alphabet",
			src:  "mdb_sa_sk_Z123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{0, 50}},
		},
		{
			name: "a body closing on the last capital of the alphabet",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz012Z",
			want: []Span{{0, 50}},
		},
		{
			name: "a body opening on the first capital of the alphabet",
			src:  "mdb_sa_sk_A123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{0, 50}},
		},
		{
			name: "a body closing on the last digit",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0129",
			want: []Span{{0, 50}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AtlasServiceAccountSecret().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AtlasServiceAccountSecret_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the prefix alone",
			src:  "mdb_sa_sk_",
		},
		{
			// Thirty-nine characters where the pattern asks for forty. This is
			// the shape a line cut to a column limit leaves.
			name: "a body one character too short",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz012",
		},
		{
			// The characters just outside each end of the alphabet, written at
			// the first position of a body, in the middle of one and at the last,
			// with the rest of the run standing so that only the one character
			// decides it. The colon follows the digits, the at sign comes before
			// the capitals, the bracket follows them, the backtick comes before
			// the lowercase letters, the brace follows them and the caret comes
			// before the underscore.
			name: "a colon at the first character of a body",
			src:  "mdb_sa_sk_:123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "a backtick at the first character of a body",
			src:  "mdb_sa_sk_`123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "an at sign at the last character of a body",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz012@",
		},
		{
			name: "a brace at the last character of a body",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz012{",
		},
		{
			name: "a bracket in the middle of a body",
			src:  "mdb_sa_sk_0123456789abcdefghijklmno[qrstuvwxyz0123",
		},
		{
			name: "a caret in the middle of a body",
			src:  "mdb_sa_sk_0123456789abcdefghijklmno^qrstuvwxyz0123",
		},
		{
			// The two characters standard base64 writes where base64url writes
			// the hyphen and the underscore. Neither is in the alphabet, so a
			// body carrying one is no body.
			name: "a plus sign in the middle of a body",
			src:  "mdb_sa_sk_0123456789abcdefghijklmno+qrstuvwxyz0123",
		},
		{
			name: "a slash in the middle of a body",
			src:  "mdb_sa_sk_0123456789abcdefghijklmno/qrstuvwxyz0123",
		},
		{
			name: "a dot at the first character of a body",
			src:  "mdb_sa_sk_.123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "a dot in the middle of a body",
			src:  "mdb_sa_sk_0123456789abcdefghijklmno.qrstuvwxyz0123",
		},
		{
			name: "a dot at the last character of a body",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz012.",
		},
		{
			name: "a space in the body",
			src:  "mdb_sa_sk_0123456789abcdefghijklmno qrstuvwxyz0123",
		},
		{
			name: "a body broken by a line break",
			src:  "mdb_sa_sk_0123456789abcdefghijklmno\nqrstuvwxyz0123",
		},
		{
			name: "an uppercase prefix",
			src:  "MDB_SA_SK_0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			// A prefix whose letters are neither all lowercase nor all uppercase,
			// which a scan comparing case-insensitively or lower-casing before
			// comparing would pass.
			name: "a prefix in mixed case",
			src:  "Mdb_Sa_Sk_0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			// The prefix is written with the underscores MongoDB divides it by,
			// not with the hyphens a delimiter is elsewhere.
			name: "hyphens where the prefix carries underscores",
			src:  "mdb-sa-sk-0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "the prefix without the underscore that closes it",
			src:  "mdb_sa_sk0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			// The prefix short of its first character, with a whole body behind
			// it. This is what the front of the input being cut leaves — a line
			// read from an offset, or one trimmed at its left edge — and the
			// anchor then stands nearer the start of the input than the prefix
			// is long, which is the one place the scan reads back from a byte
			// that is not there.
			name: "a prefix the front of the input cut short",
			src:  "db_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "a prefix cut back to the anchor itself",
			src:  "k_0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			// The identifier standing beside a secret, which this pattern does
			// not read: a different kind behind the same three opening letters.
			name: "a service account client id",
			src:  "mdb_sa_id_0123456789abcdef01234567",
		},
		{
			// And the identifier's opening with a body of this pattern's width
			// behind it, so that only the kind decides it.
			name: "the identifier opening with a body of this width behind it",
			src:  "mdb_sa_id_0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// the whole of what tells this format from any other run of the
			// alphabet.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AtlasServiceAccountSecret().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_AtlasServiceAccountSecret_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "MONGODB_ATLAS_CLIENT_SECRET=mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: "MONGODB_ATLAS_CLIENT_SECRET=**************************************************",
		},
		{
			// The basic authorization the Administration API exchanges a secret
			// for an access token with, where the secret stands as the password.
			name: "a client credentials request",
			src:  "client_id=mdb_sa_id_0123456789abcdef01234567&client_secret=mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: "client_id=mdb_sa_id_0123456789abcdef01234567&client_secret=**************************************************",
		},
		{
			name: "json",
			src:  `{"secret":"mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123"}`,
			want: `{"secret":"**************************************************"}`,
		},
		{
			name: "a command line",
			src:  `curl -u "mdb_sa_id_0123456789abcdef01234567:mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123" https://cloud.mongodb.com/api/atlas/v2/groups`,
			want: `curl -u "mdb_sa_id_0123456789abcdef01234567:**************************************************" https://cloud.mongodb.com/api/atlas/v2/groups`,
		},
		{
			name: "a configuration environment block",
			src:  `"env": {"MONGODB_ATLAS_CLIENT_SECRET": "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123"}`,
			want: `"env": {"MONGODB_ATLAS_CLIENT_SECRET": "**************************************************"}`,
		},
		{
			name: "two secrets on one line",
			src:  "current=mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123 next=mdb_sa_sk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
			want: "current=************************************************** next=**************************************************",
		},
	}

	m := New(WithPatterns(AtlasServiceAccountSecret()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AtlasServiceAccountSecret_leavesTheClientIDAlone(t *testing.T) {
	// The boundary builtin_atlas_service_account_secret.go argues for, held to
	// what it leaves in the text. The identifier is the username of the account
	// and the secret its password, and a caller keeping a log keyed on which
	// account acted needs the first left behind while the second goes. The
	// identifier is written with the kind this scan does not read, so nothing of
	// it is redacted however long a run stands behind it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "the pair as a log line carries them",
			src:  "client_id=mdb_sa_id_0123456789abcdef01234567 secret=mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: "client_id=mdb_sa_id_0123456789abcdef01234567 secret=**************************************************",
		},
		{
			name: "the identifier on its own",
			src:  "client_id=mdb_sa_id_0123456789abcdef01234567",
			want: "client_id=mdb_sa_id_0123456789abcdef01234567",
		},
	}

	m := New(WithPatterns(AtlasServiceAccountSecret()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AtlasServiceAccountSecret_aSecretBeginningInsideAnother(t *testing.T) {
	// Every character of the prefix belongs to the alphabet a body is written
	// in, so the prefix can stand inside the body of the secret before it. The
	// scan steps one byte past the start of a candidate rather than past its
	// end, so both are located; a scan consuming its match would step over the
	// second and leave it in the output whole.
	//
	// The second case is the other half: the candidate stepped over is one the
	// body test rejected, so a scan resuming past a match it never made would
	// lose the secret a character in as surely as one resuming past a match it
	// did.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a secret beginning inside the secret before it",
			src:  "mdb_sa_sk_mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{0, 50}, {10, 60}},
		},
		{
			name: "a secret inside a candidate the body turned away",
			src:  "mdb_sa_sk_.mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{11, 61}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AtlasServiceAccountSecret().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AtlasServiceAccountSecret_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the secret through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xmdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: "x**************************************************",
		},
		{
			name: "underscore before",
			src:  "MONGODB_ATLAS_CLIENT_SECRET_mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: "MONGODB_ATLAS_CLIENT_SECRET_**************************************************",
		},
	}

	m := New(WithPatterns(AtlasServiceAccountSecret()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AtlasServiceAccountSecret_leavesWhatFollowsAlone(t *testing.T) {
	// The near side of reading the count exactly rather than as a floor. A
	// secret ends at its fiftieth character whatever is written against it, so a
	// forty-first character of the alphabet stays in the text — which is what a
	// word boundary behind the match would drop the whole secret over, and what
	// a floor would take with it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the secret is mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123.",
			want: "the secret is **************************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export MONGODB_ATLAS_CLIENT_SECRET="mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123"`,
			want: `export MONGODB_ATLAS_CLIENT_SECRET="**************************************************"`,
		},
		{
			name: "a word written against the secret",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123suffix",
			want: "**************************************************suffix",
		},
		{
			name: "a hyphenated word written against the secret",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123-suffix",
			want: "**************************************************-suffix",
		},
		{
			name: "an underscored word written against the secret",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123_backup",
			want: "**************************************************_backup",
		},
	}

	m := New(WithPatterns(AtlasServiceAccountSecret()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AtlasServiceAccountSecret_aBodyWiderThanTheCount(t *testing.T) {
	// The shape the count was chosen on, held to what it leaves behind. MongoDB
	// withdrew the width it had declared, so a body wider than forty is the
	// input the exact count and a floor answer differently, and these are the
	// answers: the first fifty characters go and the rest of the run stays.
	//
	// What the rationale rests on is how much stays. A secret is what it is for
	// the whole of its length, so forty characters of a wider one taken out of
	// the middle of a log leave a fragment nothing can be authenticated with —
	// one character here, eight, and twenty-four.
	//
	// The cases move with the count: a wider body starting to be redacted whole
	// means the reading became a floor, which is the decision this test is here
	// to make visible.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a body one character wider than the count",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz01234",
			want: "**************************************************4",
		},
		{
			name: "a body eight characters wider",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
			want: "**************************************************456789ab",
		},
		{
			name: "a body twenty-four characters wider",
			src:  "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			want: "**************************************************456789abcdefghijklmnopqr",
		},
	}

	m := New(WithPatterns(AtlasServiceAccountSecret()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AtlasServiceAccountSecret_cutShortOfTheCount(t *testing.T) {
	// What the count costs, held to being left in the text rather than redacted.
	// A line cut to a column limit partway through a secret leaves a prefix and
	// a body short of the count, and the characters written before the cut come
	// through whole.
	//
	// The cases move with the scan: one of them starting to be located means the
	// count moved, and that is a decision to be taken rather than noticed
	// afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a secret one character short of the count",
			src:  "MONGODB_ATLAS_CLIENT_SECRET=mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz012",
		},
		{
			name: "a secret cut off at its prefix",
			src:  "MONGODB_ATLAS_CLIENT_SECRET=mdb_sa_sk_",
		},
	}

	m := New(WithPatterns(AtlasServiceAccountSecret()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_AtlasServiceAccountSecret_insideAnOpaqueRun(t *testing.T) {
	// What base64url costs. Hexadecimal, base62, standard base64 and base32
	// write no underscore, so an identifier, a certificate body or an embedded
	// image carries no candidate at however long it runs; base64url writes every
	// character of the prefix, and there a chance prefix with the count behind
	// it is redacted along with the ten characters in front of it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "the prefix inside a longer run of base64url",
			src:  "payload=zzzzmdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123zzzz",
			want: "payload=zzzz**************************************************zzzz",
		},
		{
			name: "the prefix where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzmdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123zzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz**************************************************zzzz",
		},
		{
			name: "a certificate body in standard base64",
			src:  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0123456789abcdef+/0123456789abcdef",
			want: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0123456789abcdef+/0123456789abcdef",
		},
	}

	m := New(WithPatterns(AtlasServiceAccountSecret()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AtlasServiceAccountSecret_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_atlas_service_account_secret.go names, held to the
	// answer it gives rather than to the one a reader might want. The
	// hexadecimal digits are base64url and a digest carries nothing that ends a
	// run, so a digest of at least forty characters written behind the prefix is
	// a secret to this scan. Declining it would mean declining every secret
	// Atlas issues, since the format is that prefix and that many of those
	// characters and nothing is left over for a digest to fail.
	//
	// The count is what holds either side of it. A SHA-1 is exactly a body and
	// goes with the prefix whole; a SHA-256 is longer and the first forty of it
	// go while the rest stays; an MD5 and a UUID are each short of one, and a
	// digest with nothing in front of it opens no candidate at all. The UUID is
	// here because its hyphens are in the alphabet, so nothing inside one ends
	// the body either — what turns it away is the thirty-six characters it comes
	// to.
	//
	// The UUID case carries a second weight the others do not. It is the shape
	// the older of the two snapshots named in
	// builtin_atlas_service_account_secret.go declares for this property, and so
	// the shape this scan decided against: were a secret ever issued that way,
	// this is the case that would have to change, and what it says today is that
	// such a value is left in the text.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sha1 behind the prefix, exactly a body",
			src:  "mdb_sa_sk_0123456789abcdef0123456789abcdef01234567",
			want: "**************************************************",
		},
		{
			name: "a sha256 behind the prefix",
			src:  "mdb_sa_sk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "**************************************************89abcdef0123456789abcdef",
		},
		{
			name: "an md5 behind the prefix",
			src:  "mdb_sa_sk_0123456789abcdef0123456789abcdef",
			want: "mdb_sa_sk_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a uuid behind the prefix",
			src:  "mdb_sa_sk_01234567-89ab-cdef-0123-456789abcdef",
			want: "mdb_sa_sk_01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "a sha1 with no prefix in front of it",
			src:  "0123456789abcdef0123456789abcdef01234567",
			want: "0123456789abcdef0123456789abcdef01234567",
		},
	}

	m := New(WithPatterns(AtlasServiceAccountSecret()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AtlasServiceAccountSecret_holdsASecretTheInputCutShort(t *testing.T) {
	// The second return of Find, held to a literal offset on the two shapes
	// builtin_scan.go names: a piece of the prefix standing at the end of the
	// input, and a candidate the end of the input cut short.
	tests := []struct {
		name   string
		src    string
		want   []Span
		retain int
	}{
		{
			// A piece of the prefix stands at the very end of the input, so
			// nothing behind where it opens is settled.
			name:   "a piece of the prefix at the end of the input",
			src:    "mdb_sa_s",
			retain: 0,
		},
		{
			name:   "a piece of the prefix behind prose",
			src:    "the secret starts with mdb_sa_s",
			retain: len("the secret starts with "),
		},
		{
			// A whole prefix and a body the input cuts short before the count is
			// met. The candidate could still become a secret were the input
			// longer, so what is unsettled reaches back to where it opened.
			name:   "a body the input cuts short of the count",
			src:    "mdb_sa_sk_0123456789abcdef",
			retain: 0,
		},
		{
			// A candidate the end of the input cut short whose body already
			// carries a character outside the alphabet, so no text carrying on
			// from here could make it a secret. It is settled back to the
			// candidate all the same: builtin_scan.go argues that a scan reports
			// such a candidate rather than reading what is written of it, since
			// telling the dead ones apart costs a second grammar kept beside the
			// first and free to disagree with it. Nothing else here would fail
			// if the scan started reading them.
			name:   "a body the input cuts short, with a character no body may carry in it",
			src:    "mdb_sa_sk_0123.56789",
			retain: 0,
		},
		{
			// The identifier's kind, long enough for the prefix to be read and
			// turned away. Settled to the end says the kind was read rather than
			// cut short.
			name:   "the identifier with a body of this width behind it",
			src:    "mdb_sa_id_0123456789abcdefghijklmnopqrstuvwxyz0123",
			retain: len("mdb_sa_id_0123456789abcdefghijklmnopqrstuvwxyz0123"),
		},
		{
			// The same kind cut short by the end of the input. The d it closes on
			// is a character the prefix is written with, so the byte test does
			// not turn the input away — but no piece of the prefix ends in a d
			// where this one stands, so nothing is held back.
			name:   "the identifier's kind, cut short at a byte the prefix is written with",
			src:    "mdb_sa_id",
			retain: len("mdb_sa_id"),
		},
		{
			// And the same text a character shorter, where the byte at the end is
			// one the prefix does not carry at all and the byte test answers on
			// its own.
			name:   "the identifier's kind, cut short at a byte the prefix does not carry",
			src:    "mdb_sa_i",
			retain: len("mdb_sa_i"),
		},
		{
			// A whole secret with more text after it, ending in a byte that opens
			// no piece of the prefix, so nothing at the end of the input is left
			// unsettled.
			name:   "a whole secret followed by settled text",
			src:    "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123 tail",
			want:   []Span{{0, 50}},
			retain: len("mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123 tail"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := AtlasServiceAccountSecret().Find(tt.src)
			if retain != tt.retain {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, retain, tt.retain)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

// Test_atlasServiceAccountSecretPrefix holds the claim the scan's resumption
// rests on: every character of the prefix is one a body may be written with, so
// the prefix can stand anywhere inside a body and a secret can begin inside the
// one before it. A scan consuming its match would step over such a secret; this
// scan steps one byte along instead, and
// Test_AtlasServiceAccountSecret_aSecretBeginningInsideAnother drives what that
// finds.
//
// It is stated over the declaration rather than by a case, because the case that
// would state it in full is a body made of nothing but prefixes — a value
// carrying none of the ordered characters a value written into this repository
// is built from.
func Test_atlasServiceAccountSecretPrefix(t *testing.T) {
	if atlasServiceAccountSecretPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for i := range len(atlasServiceAccountSecretPrefix) {
		if c := atlasServiceAccountSecretPrefix[i]; !isBase64URLByte(c) {
			t.Errorf("the prefix %q holds %q at %d, which a body may not be written with, so no secret can begin there", atlasServiceAccountSecretPrefix, c, i)
		}
	}
}

// Test_atlasServiceAccountSecretAnchor holds the prefix to carrying the byte the
// scan searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_atlasServiceAccountSecretAnchor(t *testing.T) {
	if atlasServiceAccountSecretAnchorIndex >= len(atlasServiceAccountSecretPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix %q is %d characters", atlasServiceAccountSecretAnchorIndex, atlasServiceAccountSecretPrefix, len(atlasServiceAccountSecretPrefix))
	}
	if c := atlasServiceAccountSecretPrefix[atlasServiceAccountSecretAnchorIndex]; c != atlasServiceAccountSecretAnchor {
		t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", atlasServiceAccountSecretPrefix, c, byte(atlasServiceAccountSecretAnchor))
	}
}

// Test_atlasServiceAccountSecretFindBenchmarks_lineTheAnchorWasChosenAgainst
// holds the line the benchmarks are written on to the counts the rationale reads
// the anchor choice off. The counts are the whole of the evidence for searching
// on the k rather than on any other byte of the prefix, and nothing else reports
// them: a word added to that line falsifies the sentence in silence, since every
// benchmark goes on timing whatever the line became.
func Test_atlasServiceAccountSecretFindBenchmarks_lineTheAnchorWasChosenAgainst(t *testing.T) {
	var line string
	for _, c := range atlasServiceAccountSecretFindBenchmarks() {
		if c.name == "no value" {
			line = c.src
		}
	}
	if line == "" {
		t.Fatal(`no benchmark case named "no value", so the line the anchor was chosen against is not here to count`)
	}

	for _, tt := range []struct {
		c    byte
		want int
	}{
		{'m', 4},
		{'d', 11},
		{'b', 7},
		{'s', 12},
		{'a', 11},
		{'_', 5},
		{atlasServiceAccountSecretAnchor, 2},
	} {
		if got := strings.Count(line, string([]byte{tt.c})); got != tt.want {
			t.Errorf("the line carries %q %d times, the rationale reads the anchor off %d", tt.c, got, tt.want)
		}
	}
}

// Test_atlasServiceAccountSecretChars holds the counts to the numbers the
// rationale reads them as: forty is the count MongoDB's own specification
// declared for the secret, ten is the prefix a body is read from, and fifty is
// the two together.
func Test_atlasServiceAccountSecretChars(t *testing.T) {
	if atlasServiceAccountSecretBodyChars != 40 {
		t.Errorf("a body is read as %d characters, the rationale says forty", atlasServiceAccountSecretBodyChars)
	}
	if len(atlasServiceAccountSecretPrefix) != atlasServiceAccountSecretPrefixChars {
		t.Errorf("the prefix %q is %d characters, the scan reads a body from %d", atlasServiceAccountSecretPrefix, len(atlasServiceAccountSecretPrefix), atlasServiceAccountSecretPrefixChars)
	}
	if atlasServiceAccountSecretPrefixChars != 10 {
		t.Errorf("the prefix is read as %d characters, the rationale says ten", atlasServiceAccountSecretPrefixChars)
	}
	if want := atlasServiceAccountSecretPrefixChars + atlasServiceAccountSecretBodyChars; atlasServiceAccountSecretChars != want {
		t.Errorf("a secret is read as %d characters, the prefix and the body come to %d", atlasServiceAccountSecretChars, want)
	}
	if atlasServiceAccountSecretChars != 50 {
		t.Errorf("a secret is read as %d characters, the rationale says fifty", atlasServiceAccountSecretChars)
	}
}

func Test_isAtlasServiceAccountSecretBody(t *testing.T) {
	// The count and the alphabet together, stated over every byte rather than by
	// example: a body is exactly atlasServiceAccountSecretBodyChars characters
	// and each of them base64url.
	body := strings.Repeat("a", atlasServiceAccountSecretBodyChars)

	if !isAtlasServiceAccountSecretBody(body) {
		t.Errorf("isAtlasServiceAccountSecretBody(%q) = false, want a body of %d characters to be one", body, atlasServiceAccountSecretBodyChars)
	}
	for _, s := range []string{body[:len(body)-1], body + "a"} {
		if isAtlasServiceAccountSecretBody(s) {
			t.Errorf("isAtlasServiceAccountSecretBody(%q) = true, want only %d characters to be a body", s, atlasServiceAccountSecretBodyChars)
		}
	}

	for c := range 256 {
		b := byte(c)
		src := body[:len(body)-1] + string([]byte{b})
		if got, want := isAtlasServiceAccountSecretBody(src), isBase64URLByte(b); got != want {
			t.Errorf("isAtlasServiceAccountSecretBody(%q) = %v with %q in it, want %v", src, got, b, want)
		}
	}
}

// referenceAtlasServiceAccountSecret is the expression the scan in
// builtin_atlas_service_account_secret.go reads by hand: the statement of what an
// Atlas service account secret is, kept here so that the scan can be held to it.
//
// The prefix, the count and the alphabet are spelled again rather than built
// from atlasServiceAccountSecretPrefix, atlasServiceAccountSecretBodyChars and
// isBase64URLByte. A reference sharing those declarations could not disagree
// with the scan about them, and it is exactly that disagreement the fuzz target
// below is for: the two have to be changed together or reported apart.
var referenceAtlasServiceAccountSecret = regexp.MustCompile(`mdb_sa_sk_[0-9A-Za-z_-]{40}`)

// referenceAtlasServiceAccountSecretFind locates secrets the plain way: the
// leftmost match of the expression above, then the leftmost one beginning after
// that match's first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a secret can begin inside one: every character of
// the prefix is written in the alphabet a body is, so a body holding the prefix
// holds a secret the engine would never go on to try. The scan finds both and
// reports the two spans overlapping for a Masker to resolve, so the reference
// must ask about both.
//
// Resuming a byte along costs this one nothing beyond a constant: every
// candidate reads at most fifty characters, here as in the scan, so neither has
// a run to walk and there is no cursor for either to be wrong about.
//
// It is built on an expression rather than written out, and the exact count is
// what allows that. A floor spelled as a counted repetition costs an engine a
// machine as wide as the floor at every candidate, which is what has starved
// targets of executions; an exact count is read once and stops. The ten
// character literal in front of the repetition is what the engine searches the
// text for, so a line holding no prefix is skipped rather than walked.
func referenceAtlasServiceAccountSecretFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceAtlasServiceAccountSecret.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzAtlasServiceAccountSecret_matchesReference guards the hand-written scan:
// the prefix it searches for, the count it holds a body to, the alphabet it
// reads that body in and the byte it resumes at may none of them change which
// secrets are located.
func FuzzAtlasServiceAccountSecret_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("MONGODB_ATLAS_CLIENT_SECRET=mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123")
	f.Add(`{"secret":"mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123"}`)
	f.Add("mdb_sa_sk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123")  // a body written in capitals
	f.Add("mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz012")   // one short of a body
	f.Add("mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz01234") // and a run longer than one
	f.Add("mdb_sa_sk_-123456789abcdefghijklmnopqrstuvwxyz0123")  // a body opening on a hyphen
	f.Add("mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz012_")  // and one closing on an underscore
	f.Add("mdb_sa_sk_0123456789abcdefghijklmno+qrstuvwxyz0123")  // a plus sign ends a body
	f.Add("mdb_sa_sk_0123456789abcdefghijklmno.qrstuvwxyz0123")  // a dot, likewise
	f.Add("MDB_SA_SK_0123456789abcdefghijklmnopqrstuvwxyz0123")  // an uppercase prefix
	f.Add("mdb-sa-sk-0123456789abcdefghijklmnopqrstuvwxyz0123")  // hyphens where the prefix carries underscores
	f.Add("mdb_sa_sk0123456789abcdefghijklmnopqrstuvwxyz0123")   // the prefix without its closing underscore
	f.Add("mdb_sa_id_0123456789abcdef01234567")                  // the identifier standing beside a secret
	f.Add("mdb_sa_id_0123456789abcdefghijklmnopqrstuvwxyz0123")  // and its kind with a body of this width behind it
	f.Add("client_id=mdb_sa_id_0123456789abcdef01234567&client_secret=mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123")
	f.Add("mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123 mdb_sa_sk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123")
	f.Add("mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123")
	// A secret beginning inside another, and one inside a candidate the body
	// turned away.
	f.Add("mdb_sa_sk_mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123")
	f.Add("mdb_sa_sk_.mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123")
	// Candidate positions crowded as close as they can be, with no body for any
	// of them, and secrets written one against the next so that every candidate
	// has one.
	f.Add(strings.Repeat("mdb_sa_sk_", 16))
	f.Add(strings.Repeat("mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123", 4))
	// The digests either side of the count, behind the prefix and bare.
	f.Add("mdb_sa_sk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("mdb_sa_sk_0123456789abcdef0123456789abcdef01234567")
	f.Add("mdb_sa_sk_01234567-89ab-cdef-0123-456789abcdef")
	f.Add("0123456789abcdefghijklmnopqrstuvwxyz0123")
	// The prefix written inside a run of base64url, which is the over-match the
	// pattern admits.
	f.Add("payload=zzzzmdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123zzzz")

	fuzzAgainstReference(f, AtlasServiceAccountSecret().Find, referenceAtlasServiceAccountSecretFind)
}

// atlasServiceAccountSecretFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func atlasServiceAccountSecretFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no secret. The vendor's own host name and the words its
	// records are written in are here because they are what a line about Atlas
	// carries, and they are what the anchor was chosen against: time, msg and
	// the host name mongodb.com spell the m, the hexadecimal identifiers and
	// the words around them spell the d and the b, and the underscore divides
	// the field names. The k stands in disk and in backup and nowhere else.
	line := `time=2026-08-17T00:00:00Z level=info msg="cluster updated" org_id=0123456789abcdef01234567 group_id=0123456789abcdef01234567 cluster=atlas-cluster-0 disk_size_gb=40 backup_enabled=true url=https://cloud.mongodb.com/api/atlas/v2/groups/0123456789abcdef01234567/clusters `
	secret := "mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz0123"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The other side of passing over the underscore: a body of JSON
			// written in snake_case stops a scan anchored there at every field
			// name, where this one walks past them.
			name:  "underscores that open no candidate",
			src:   strings.Repeat(`{"org_id":"0123456789abcdef01234567","group_id":"0123456789abcdef01234567","client_id":"mdb_sa_id_0123456789abcdef01234567"}`, 2),
			spans: 0,
		},
		{
			// A candidate every fifty characters, each of them rejected by the
			// last character of its body. This is the dearest a candidate can be
			// turned away: the whole count is read before the answer comes. The
			// prefix repeated on its own would not do, for the reason
			// Test_atlasServiceAccountSecretPrefix states — every character of
			// it is in the alphabet, so a line of them is a line of secrets
			// rather than of rejected candidates.
			name:  "candidates that are not values",
			src:   strings.Repeat("mdb_sa_sk_0123456789abcdefghijklmnopqrstuvwxyz012.", 32),
			spans: 0,
		},
		{
			// Secrets written one against the next, so that every candidate is a
			// secret and the count is read in full at each of them.
			name:  "secrets written one against the next",
			src:   strings.Repeat(secret, 128),
			spans: 128,
		},
		{
			name:  "one value",
			src:   line + "secret=" + secret,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "secret=" + secret,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"secret="+secret+"\n", 32),
			spans: 32,
		},
	}
}
