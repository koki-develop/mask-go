package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Supabase publishable key pattern: what it locates and what it leaves
// alone, written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a set
// of tests apiece.
//
// The keys written out below are made only of ordered characters: valid in
// shape, obviously not real. The body is the one both halves of this format
// share and is written here as it is in builtin_supabase_secret_key_test.go —
// 0123456789abcdef and then as far as 5, the separator, and the first eight of
// the same run. With this half's prefix in front a key comes to forty-six
// characters.
//
// What the body is and why it is read the way it is belongs to the other half
// and is stated there. What is written out here is what this half locates: its
// own prefix, its own count, and the keys of the other half it leaves alone.

func Test_SupabasePublishableKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "sb_publishable_0123456789abcdef012345_01234567",
			want: []Span{{0, 46}},
		},
		{
			name: "a key in an environment assignment",
			src:  "NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=sb_publishable_0123456789abcdef012345_01234567",
			want: []Span{{37, 83}},
		},
		{
			// The count is read exactly, so what follows the forty-sixth
			// character is not part of the key and stays in the text.
			name: "a run longer than the count is a key and what follows it",
			src:  "sb_publishable_0123456789abcdef012345_012345678",
			want: []Span{{0, 46}},
		},
		{
			name: "two keys with nothing between them",
			src:  "sb_publishable_0123456789abcdef012345_01234567sb_publishable_0123456789abcdef012345_01234567",
			want: []Span{{0, 46}, {46, 92}},
		},
		{
			// Three rather than two: the shape a run of keys takes when it is
			// longer than a pair, still with the anchor's one occurrence in
			// front of a key deciding where each span begins.
			name: "three keys with nothing between them",
			src:  "sb_publishable_0123456789abcdef012345_01234567sb_publishable_0123456789abcdef012345_01234567sb_publishable_0123456789abcdef012345_01234567",
			want: []Span{{0, 46}, {46, 92}, {92, 138}},
		},
		{
			// The candidate this scan resumes a byte along for. The prefix at
			// the front of the input opens a candidate whose body carries no
			// separator where one has to stand; the key is the one fifteen
			// characters in, and a scan stepping over what it declined would
			// never reach it.
			name: "a prefix in front of a key",
			src:  "sb_publishable_sb_publishable_0123456789abcdef012345_01234567",
			want: []Span{{15, 61}},
		},
		{
			name: "a hyphen in the body",
			src:  "sb_publishable_0123456789-bcdef012345_01234567",
			want: []Span{{0, 46}},
		},
		{
			name: "an uppercase body",
			src:  "sb_publishable_0123456789ABCDEF012345_01234567",
			want: []Span{{0, 46}},
		},
		{
			// base64url's own two characters standing in the checksum, which
			// is a narrower run than the random part gets exercised at.
			name: "a hyphen in the checksum",
			src:  "sb_publishable_0123456789abcdef012345_0123456-",
			want: []Span{{0, 46}},
		},
		{
			name: "an underscore in the checksum",
			src:  "sb_publishable_0123456789abcdef012345_0123456_",
			want: []Span{{0, 46}},
		},
		{
			// Every character the alphabet has, at once: uppercase past F,
			// lowercase past f, both digits' neighbours and both of the
			// characters standard base64 leaves out. The body is the one
			// Test_isSupabaseKeyBody already holds the helper to; here it
			// stands behind this half's own prefix and count.
			name: "a body spanning the alphabet",
			src:  "sb_publishable_ABCDEFGHIJKLMNOPQRSTUV_wxyz-_09",
			want: []Span{{0, 46}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SupabasePublishableKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SupabasePublishableKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "sb_publishable_",
		},
		{
			name: "a body one character short",
			src:  "sb_publishable_0123456789abcdef012345_0123456",
		},
		{
			name: "the separator one character early",
			src:  "sb_publishable_0123456789abcdef01234_501234567",
		},
		{
			// The other side of the same claim: the separator has to stand at
			// exactly the twenty-third character, and one character late is
			// as much no key as one character early.
			name: "the separator one character late",
			src:  "sb_publishable_0123456789abcdef0123450_1234567",
		},
		{
			name: "a body of the right length with no separator",
			src:  "sb_publishable_0123456789abcdef012345001234567",
		},
		{
			name: "a character outside the alphabet in the body",
			src:  "sb_publishable_0123456789.bcdef012345_01234567",
		},
		{
			// The same rejection at the first body character rather than in
			// the middle of the run, which is a position no case here reaches
			// otherwise.
			name: "a character outside the alphabet at the first body character",
			src:  "sb_publishable_.123456789abcdef012345_01234567",
		},
		{
			// A character outside base64url standing in the checksum rather
			// than in the random part.
			name: "a character outside the alphabet in the checksum",
			src:  "sb_publishable_0123456789abcdef012345_0123456.",
		},
		{
			name: "a body broken by a space",
			src:  "sb_publishable_0123456789 bcdef012345_01234567",
		},
		{
			name: "an uppercase prefix",
			src:  "SB_PUBLISHABLE_0123456789abcdef012345_01234567",
		},
		{
			name: "a hyphen where the prefix carries its closing underscore",
			src:  "sb_publishable-0123456789abcdef012345_01234567",
		},
		{
			name: "the prefix without its closing underscore",
			src:  "sb_publishable0123456789abcdef012345_01234567",
		},
		{
			// The other half of this format, which is the same body behind a
			// shorter prefix. Neither pattern reads the other's prefix, which
			// is the whole of the boundary between them.
			name: "a secret key",
			src:  "sb_secret_0123456789abcdef012345_01234567",
		},
		{
			name: "a body of the right shape opening with no prefix",
			src:  "xxxxxxxxxxxxxxx0123456789abcdef012345_01234567",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "a log line",
			src:  `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.supabase.co/rest/v1/todos`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SupabasePublishableKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_SupabasePublishableKey_inContext(t *testing.T) {
	// The places a publishable key is written, which are the places the vendor
	// puts one: browser code, the bundle that code is built into, and the
	// configuration either is read from.
	const key = "sb_publishable_0123456789abcdef012345_01234567"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key in a dotenv line",
			src:  "NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=" + key,
			want: []Span{{37, 37 + len(key)}},
		},
		{
			name: "a key in a client constructor",
			src:  `createClient(url, "` + key + `")`,
			want: []Span{{19, 19 + len(key)}},
		},
		{
			name: "a key in an apikey header",
			src:  "apikey: " + key,
			want: []Span{{8, 8 + len(key)}},
		},
		{
			name: "a key in a bearer token header",
			src:  "Authorization: Bearer " + key,
			want: []Span{{22, 22 + len(key)}},
		},
		{
			name: "a key in the response that lists it",
			src:  `{"api_key":"` + key + `","type":"publishable"}`,
			want: []Span{{12, 12 + len(key)}},
		},
		{
			name: "a key at the end of a sentence",
			src:  "the key is " + key + ".",
			want: []Span{{11, 11 + len(key)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SupabasePublishableKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SupabasePublishableKey_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match, which is the other half's
	// decision as much as this one's. A word boundary in front would drop the
	// whole match rather than trim it wherever a key is written against a word
	// character, and one behind it would drop a key followed by a base64url
	// character.
	const key = "sb_publishable_0123456789abcdef012345_01234567"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key after an underscore",
			src:  "SUPABASE_KEY_" + key,
			want: []Span{{13, 13 + len(key)}},
		},
		{
			name: "a key after a letter",
			src:  "x" + key,
			want: []Span{{1, 1 + len(key)}},
		},
		{
			name: "a word written against a key",
			src:  key + "suffix",
			want: []Span{{0, len(key)}},
		},
		{
			name: "a hyphenated word written against a key",
			src:  key + "-suffix",
			want: []Span{{0, len(key)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SupabasePublishableKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SupabasePublishableKey_aKeyInsideAKey(t *testing.T) {
	// A key can be written inside another, which is why the scan resumes a byte
	// past the start of a candidate rather than past the candidate. The
	// alphabet a body is drawn from holds every character the prefix is written
	// with, so a body may spell the prefix and open a candidate that reads on
	// past the end of the key it stands in. The spans overlap where it does,
	// which Masker.locate resolves.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key beginning inside another",
			src:  "sb_publishable_sb_publishable_0123456_01234567012345_01234567",
			want: []Span{{0, 46}, {15, 61}},
		},
		{
			name: "a prefix inside a body that opens no key",
			src:  "sb_publishable_sb_publishable_0123456_01234567",
			want: []Span{{0, 46}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SupabasePublishableKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SupabasePublishableKey_aBase64URLRunBehindThePrefix(t *testing.T) {
	// The collision this format leaves, which is the other half's collision
	// behind a longer prefix: thirty-one characters of base64url with an
	// underscore twenty-three characters in is the vendor's format exactly, so
	// nothing is left in the text to tell such a run from a key.
	//
	// What has to be written to reach it here is fifteen characters carrying
	// two underscores, which is five more than the other half asks for.
	// Standard base64 writes no underscore at all, so a certificate, a PEM body
	// or an embedded image holds no candidate at however long it runs.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a base64url run behind the prefix",
			src:  "sb_publishable_0123456789abcdef012345_01234567",
			want: []Span{{0, 46}},
		},
		{
			name: "a longer base64url run behind the prefix",
			src:  "sb_publishable_0123456789abcdef012345_012345670123456789abcdef",
			want: []Span{{0, 46}},
		},
		{
			name: "a base64url run on its own",
			src:  "0123456789abcdef012345_01234567",
		},
		{
			name: "a standard base64 payload, which carries no underscore",
			src:  "payload=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsbpublishable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SupabasePublishableKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SupabasePublishableKey_underscoresInTheRandomPart(t *testing.T) {
	// The body is sliced out of a base64url encoding, which carries
	// underscores of its own, so the separator settles nothing about where
	// the parts divide — only the count either side of it does. A body of
	// underscores throughout is a key all the same, and one carrying a
	// character other than an underscore where the separator belongs is not,
	// however many underscores stand around it. This is the other half's own
	// claim, stated here behind this half's prefix rather than assumed to
	// carry over untested.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a body of underscores alone",
			src:  "sb_publishable_" + strings.Repeat("_", 31),
			want: []Span{{0, 46}},
		},
		{
			// The one position that may not be an underscore: a hyphen
			// standing where the separator belongs, with underscores on
			// every other position of the body.
			name: "a hyphen where the separator stands and underscores around it",
			src:  "sb_publishable_" + strings.Repeat("_", 22) + "-" + strings.Repeat("_", 8),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SupabasePublishableKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SupabasePublishableKey_holdsAKeyTheInputCutShort(t *testing.T) {
	// What this scan settles where the input ends inside a candidate: the
	// candidate's own start, reported but not read, held there until what
	// comes next either carries the body on to a key or closes it.
	tests := []struct {
		name       string
		src        string
		wantSpans  []Span
		wantRetain int
	}{
		{
			name:       "a body the input cuts short",
			src:        "apikey: sb_publishable_0123456789abcdef",
			wantSpans:  nil,
			wantRetain: 8,
		},
		{
			name:       "the prefix the input cuts short",
			src:        "apikey: sb_pub",
			wantSpans:  nil,
			wantRetain: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSpans, gotRetain := SupabasePublishableKey().Find(tt.src)
			if !slices.Equal(gotSpans, tt.wantSpans) {
				t.Errorf("Find(%q) spans = %v, want %v", tt.src, gotSpans, tt.wantSpans)
			}
			if gotRetain != tt.wantRetain {
				t.Errorf("Find(%q) retain = %d, want %d", tt.src, gotRetain, tt.wantRetain)
			}
		})
	}
}

// Test_SupabasePublishableKey_adjacentToASecretKey drives the boundary
// between the two project keys with nothing standing between them rather than
// elsewhere in the text: neither prefix reads inside the other's, sb_secret_
// closing where sb_publishable_ would still need five more characters and a
// second underscore, so this pattern locates the publishable half alone,
// wherever in the pair it stands.
func Test_SupabasePublishableKey_adjacentToASecretKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a secret key immediately followed by a publishable key",
			src:  "sb_secret_0123456789abcdef012345_01234567sb_publishable_0123456789abcdef012345_01234567",
			want: []Span{{41, 87}},
		},
		{
			name: "a publishable key immediately followed by a secret key",
			src:  "sb_publishable_0123456789abcdef012345_01234567sb_secret_0123456789abcdef012345_01234567",
			want: []Span{{0, 46}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SupabasePublishableKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_supabasePublishableKeyPrefix(t *testing.T) {
	// The prefix is the argument the generator is called with for this kind of
	// key, and it is the whole of what tells one from a secret key.
	if got := supabasePublishableKeyPrefix; got != "sb_publishable_" {
		t.Errorf("supabasePublishableKeyPrefix = %q, want %q", got, "sb_publishable_")
	}
}

func Test_supabasePublishableKeyAnchor(t *testing.T) {
	// The byte the scan searches for stands at the index it reads a candidate
	// back from. A prefix or an index changed without the other leaves the scan
	// opening candidates nowhere near where a key begins, and what such a scan
	// finds is nothing at all rather than something wrong.
	if got := supabasePublishableKeyPrefix[supabasePublishableKeyAnchorIndex]; got != supabasePublishableKeyAnchor {
		t.Errorf("supabasePublishableKeyPrefix[%d] = %q, want the anchor %q",
			supabasePublishableKeyAnchorIndex, got, supabasePublishableKeyAnchor)
	}

	// What the anchor costs here, counted rather than claimed in prose: it
	// stands three times in this prefix, so a line of keys stops the search
	// three times a key rather than once. The rationale rests on the two extra
	// stops being turned away by the one comparison a candidate opens with,
	// which is what the loop below holds — a prefix rewritten so that the byte
	// one character in front of one of them became the s a prefix opens with
	// would turn a cheap rejection into a whole comparison, and nothing else
	// here would report it.
	if n := strings.Count(supabasePublishableKeyPrefix, string(supabasePublishableKeyAnchor)); n != 3 {
		t.Errorf("the anchor stands %d times in %q, want 3", n, supabasePublishableKeyPrefix)
	}
	for i := range len(supabasePublishableKeyPrefix) {
		if supabasePublishableKeyPrefix[i] != supabasePublishableKeyAnchor || i == supabasePublishableKeyAnchorIndex {
			continue
		}
		start := i - supabasePublishableKeyAnchorIndex
		if supabasePublishableKeyPrefix[start] == supabasePublishableKeyPrefix[0] {
			t.Errorf("the anchor at index %d reads back to %q, which is the byte a prefix opens with",
				i, supabasePublishableKeyPrefix[start])
		}
	}
}

func Test_supabasePublishableKeyChars(t *testing.T) {
	// This half's prefix and the body both halves share. Fifteen characters and
	// thirty-one make a key of forty-six, which is five more than the other
	// half comes to and is the only count of this grammar that is this half's
	// own.
	if got := len(supabasePublishableKeyPrefix); got != 15 {
		t.Errorf("len(supabasePublishableKeyPrefix) = %d, want 15", got)
	}
	if got := supabasePublishableKeyChars; got != 46 {
		t.Errorf("supabasePublishableKeyChars = %d, want 46", got)
	}
}

// referenceSupabasePublishableKey is the grammar as a regular expression: the
// prefix the generator is called with for this kind of key, the twenty-two
// characters it slices out of a base64url encoding, the separator it writes
// behind them and the eight characters of checksum. Every part of it is spelled
// again rather than read from the scan, so that the two can disagree and the
// target below report it — including the counts the scan reads from its other
// half, since a reference is written to know nothing either scan claims.
//
// It is built on an expression for the reason the other half's is: both counts
// are exact, so an engine reads the machine once and stops, and the opening is a
// literal an engine can search the text for rather than a class it would have to
// walk its machine at every byte for.
var referenceSupabasePublishableKey = regexp.MustCompile(`sb_publishable_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{8}`)

// referenceSupabasePublishableKeyFind locates keys the plain way: the leftmost
// match of the expression above, then the leftmost one beginning after that
// match's first byte, over and over, with nothing remembered between them.
//
// Asking at every byte rather than resuming past a match is what the scan does
// and is what a key written inside another needs: a body may spell the prefix,
// so a match can begin fifteen characters into the one before it and resuming
// past the first would lose it.
func referenceSupabasePublishableKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceSupabasePublishableKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzSupabasePublishableKey_matchesReference guards the hand-written scan: the
// prefix it searches for, the counts it reads behind that prefix, the character
// it demands between them, the alphabet it reads them in and the byte it resumes
// at may none of them change which keys are located.
func FuzzSupabasePublishableKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=sb_publishable_0123456789abcdef012345_01234567")
	f.Add("sb_publishable_0123456789abcdef012345_0123456")   // a body one character short
	f.Add("sb_publishable_0123456789abcdef012345_012345678") // and a run one longer
	f.Add("sb_publishable_0123456789abcdef01234_501234567")  // the separator a character early
	f.Add("sb_publishable_0123456789abcdef012345001234567")  // no separator at all
	f.Add("sb_publishable_0123456789abcdef012345-01234567")  // a hyphen where it stands
	f.Add("sb_publishable_0123456789_bcdef012345_01234567")  // an underscore elsewhere in the body
	f.Add("sb_publishable_0123456789-bcdef012345_01234567")  // and a hyphen
	f.Add("sb_publishable_0123456789ABCDEF012345_01234567")  // an uppercase body
	f.Add("sb_publishable_0123456789.bcdef012345_01234567")  // a character outside the alphabet
	f.Add("sb_publishable_.123456789abcdef012345_01234567")  // the same, at the first body character
	f.Add("sb_publishable_0123456789abcdef012345_0123456.")  // and in the checksum
	f.Add("sb_publishable_0123456789abcdef012345_0123456-")  // a hyphen in the checksum
	f.Add("sb_publishable_0123456789abcdef0123450_1234567")  // the separator a character late
	f.Add("sb_publishable_ABCDEFGHIJKLMNOPQRSTUV_wxyz-_09")  // every character of the alphabet at once
	f.Add("sb_publishable_" + strings.Repeat("_", 31))       // a body of underscores alone
	f.Add("sb_publishable_0123456789abcdef012345\n01234567")
	f.Add("sb_publishable-0123456789abcdef012345_01234567") // a hyphen where the prefix closes
	f.Add("SB_PUBLISHABLE_0123456789abcdef012345_01234567") // an uppercase prefix
	f.Add("xsb_publishable_0123456789abcdef012345_01234567")
	// The other half of this format, which this pattern locates nothing in.
	f.Add("sb_secret_0123456789abcdef012345_01234567")
	// A key written inside another, which a scan resuming past a match would
	// lose, and two keys with nothing between them.
	f.Add("sb_publishable_sb_publishable_0123456_01234567012345_01234567")
	f.Add("sb_publishable_sb_publishable_0123456789abcdef012345_01234567")
	f.Add("sb_publishable_0123456789abcdef012345_01234567sb_publishable_0123456789abcdef012345_01234567")
	// Candidate positions crowded as close as they can be, and runs of the
	// bytes the search stops at and the body is divided by.
	f.Add(strings.Repeat("sb_publishable_", 32))
	f.Add(strings.Repeat("sb_publishable_", 32) + "0123456789abcdef012345_01234567")
	f.Add(strings.Repeat("sb_publishable_0123456789abcdef012345_01234567", 8))
	f.Add(strings.Repeat("_", 128))
	f.Add(strings.Repeat("b", 128))
	// The other Supabase credentials, which this pattern locates nothing in.
	f.Add("sbp_0123456789abcdef0123456789abcdef01234567")
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.0123456789abcdef")

	fuzzAgainstReference(f, SupabasePublishableKey().Find, referenceSupabasePublishableKeyFind)
}

// supabasePublishableKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func supabasePublishableKeyFindBenchmarks() []benchmarkCase {
	// The line the anchor is chosen against: the b of the vendor's own name
	// stands once on it where the s stands six times, and the underscore the
	// prefix closes with stands not once. What the line times is the search for
	// the anchor, which is most of what this pattern costs a caller whose text
	// holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.supabase.co/rest/v1/todos `
	key := "sb_publishable_0123456789abcdef012345_01234567"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is fifteen characters carrying the anchor three times,
			// so a run of them stops the search three times for every fifteen
			// characters it has. Two of the three are turned away by the one
			// comparison a candidate opens with and the third by the character
			// the separator would have to stand at, which is what this case
			// times against the one below it.
			name:  "candidates that are not values",
			src:   strings.Repeat("sb_publishable_", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads a prefix, which is the cheapest a
			// candidate is declined for at all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("b", 4096),
			spans: 0,
		},
		{
			// The other way a candidate fails: a body of the right alphabet up
			// to its last character, so the whole of it is walked before the
			// candidate is turned away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("sb_publishable_0123456789abcdef012345_0123456. ", 16),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "apikey=" + key,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "apikey=" + key,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"apikey="+key+"\n", 32),
			spans: 32,
		},
	}
}
