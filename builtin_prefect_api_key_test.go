package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Prefect API key pattern: what it locates and what it leaves alone, written
// out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a set
// of tests apiece.
//
// The keys written out below are made only of ordered characters: valid in
// shape, obviously not real. The run they are built from,
// 0123456789abcdefghijklmnopqrstuvwxyz, is thirty-six characters and so is a
// whole body — the shortest the scan reads, since the count is a floor, so a
// body shortened for readability would leave a case holding no key at all. It is
// written in lowercase where the case does not matter and in uppercase where the
// case is what a case is about: base62 holds the letters of both, so either
// spelling is a body.

func Test_PrefectAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a user key on its own",
			src:  "pnu_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			name: "a service account key on its own",
			src:  "pnb_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 40}},
		},
		{
			name: "a key in an environment assignment",
			src:  "PREFECT_API_KEY=pnu_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{16, 56}},
		},
		{
			// base62 holds the letters of both cases, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "pnu_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			want: []Span{{0, 40}},
		},
		{
			// base62 has six ends — 0, 9, A, Z, a and z — and a range bound
			// written one too wide at any of them admits a character no key
			// carries. A body built from an ordered run stands on two of them
			// and no more, at its first character and at its last, so each of
			// the cases here opens a body on one end and closes it on another.
			name: "a body opening on the last lowercase letter and closing on the first digit",
			src:  "pnu_z0123456789abcdefghijklmnopqrstuvwx0",
			want: []Span{{0, 40}},
		},
		{
			name: "a body opening on the last uppercase letter and closing on the last digit",
			src:  "pnu_Z0123456789abcdefghijklmnopqrstuvwx9",
			want: []Span{{0, 40}},
		},
		{
			name: "a body opening on the first lowercase letter and closing on the first uppercase one",
			src:  "pnu_a0123456789abcdefghijklmnopqrstuvwxA",
			want: []Span{{0, 40}},
		},
		{
			name: "a body opening on the last digit and closing on the first lowercase letter",
			src:  "pnu_90123456789ABCDEFGHIJKLMNOPQRSTUVWXa",
			want: []Span{{0, 40}},
		},
		{
			name: "a body opening on the first uppercase letter and closing on the last lowercase one",
			src:  "pnu_A0123456789ABCDEFGHIJKLMNOPQRSTUVWXz",
			want: []Span{{0, 40}},
		},
		{
			// The count is a floor and the span reaches the end of the run, so
			// a run longer than the shortest body is a key to the end of it
			// rather than a key and a character left over.
			name: "a run longer than the shortest body",
			src:  "pnu_0123456789abcdefghijklmnopqrstuvwxyz0",
			want: []Span{{0, 41}},
		},
		{
			// The same for a service account key, which is what the floor is
			// carrying: nothing states that body's length, so a key written
			// longer than a user key has to be located to the end of its run
			// rather than cut at thirty-six.
			name: "a service account key longer than the shortest body",
			src:  "pnb_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{0, 44}},
		},
		{
			name: "two keys of different kinds separated by a space",
			src:  "pnu_0123456789abcdefghijklmnopqrstuvwxyz pnb_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			want: []Span{{0, 40}, {41, 81}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PrefectAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PrefectAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "pnu_",
		},
		{
			// Thirty-five characters where the pattern asks for thirty-six.
			// This is the shape a line cut to a column limit leaves, and the
			// characters in front of the cut stay in the text: the far side of
			// reading a floor, which builtin_prefect_api_key.go weighs.
			name: "a body one character too short",
			src:  "pnu_0123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			// The hyphen and the underscore are base64url characters and no
			// base62 ones, so either ends a body where the run behind it is too
			// short to be one. Both are written at the ends of a body as well as
			// inside one, since a run ends at the character wherever it stands.
			name: "a body carrying a hyphen",
			src:  "pnu_0123456789abcdef-ghijklmnopqrstuvwxyz",
		},
		{
			name: "a body carrying an underscore",
			src:  "pnu_0123456789abcdef_ghijklmnopqrstuvwxyz",
		},
		{
			name: "a hyphen at the first character of the body",
			src:  "pnu_-0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "an underscore at the first character of the body",
			src:  "pnu__0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			// A hyphen at the last character of a body, with thirty-five
			// characters in front of it: the run ends one short of the floor
			// however far the text carries on behind the hyphen.
			name: "a hyphen at the last character of the body",
			src:  "pnu_0123456789abcdefghijklmnopqrstuvwxy-z",
		},
		{
			name: "an underscore at the last character of the body",
			src:  "pnu_0123456789abcdefghijklmnopqrstuvwxy_z",
		},
		{
			// A plus and a slash are base64 characters and not base62 ones, so
			// either ends a body exactly as the hyphen and the underscore do.
			name: "a plus in the body",
			src:  "pnu_0123456789abcdef+ghijklmnopqrstuvwxyz",
		},
		{
			name: "a slash in the body",
			src:  "pnu_0123456789abcdef/ghijklmnopqrstuvwxyz",
		},
		{
			// The bytes just outside the alphabet's six ends, which is where a
			// range bound written one too wide would show. Each stands in a run
			// of thirty-seven characters, so a body admitting it would be
			// located and the case would fail rather than merely stop stating
			// anything.
			name: "the byte past the last digit in the body",
			src:  "pnu_0123456789abcdef:ghijklmnopqrstuvwxyz",
		},
		{
			name: "the byte before the first uppercase letter in the body",
			src:  "pnu_0123456789abcdef@ghijklmnopqrstuvwxyz",
		},
		{
			name: "the byte past the last uppercase letter in the body",
			src:  "pnu_0123456789abcdef[ghijklmnopqrstuvwxyz",
		},
		{
			name: "the byte before the first lowercase letter in the body",
			src:  "pnu_0123456789abcdef`ghijklmnopqrstuvwxyz",
		},
		{
			name: "the byte past the last lowercase letter in the body",
			src:  "pnu_0123456789abcdef{ghijklmnopqrstuvwxyz",
		},
		{
			// The character between the opening and the underscore names one of
			// the two kinds Prefect issues, and an a names neither.
			name: "a character naming no kind",
			src:  "pna_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			// The prefix is read in the one case Prefect writes it in, so an
			// uppercase kind character names no kind.
			name: "the kind letter uppercased",
			src:  "pnU_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "a digit naming no kind",
			src:  "pn1_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			// The kind character is the underscore itself, which names no kind
			// of Prefect's.
			name: "an underscore naming no kind",
			src:  "pn__0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "a hyphen naming no kind",
			src:  "pn-_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			// The opening with no kind character between it and the underscore
			// at all.
			name: "the opening and the underscore with no kind between them",
			src:  "pn_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "an uppercase prefix",
			src:  "PNU_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			// The prefix closes with an underscore, so a hyphen written in its
			// place opens no candidate at all.
			name: "a hyphen where the prefix carries an underscore",
			src:  "pnu-0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "one character of the opening",
			src:  "pxu_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "a space in the body",
			src:  "pnu_0123456789abcdef ghijklmnopqrstuvwxyz",
		},
		{
			name: "a dot in the body",
			src:  "pnu_0123456789abcdef.ghijklmnopqrstuvwxyz",
		},
		{
			name: "a body broken by a line break",
			src:  "pnu_0123456789abcdef\nghijklmnopqrstuvwxyz",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// the whole of the anchor, so a run long enough is not a key without
			// it.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// Forty hexadecimal characters. A digest carries no underscore, so
			// it holds no prefix to be found at however long it runs.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PrefectAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PrefectAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "PREFECT_API_KEY=pnu_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "PREFECT_API_KEY=****************************************",
		},
		{
			// The line prefect config view prints, which is where the
			// troubleshooting page shows a key masked.
			name: "a profile line",
			src:  "PREFECT_API_KEY='pnu_0123456789abcdefghijklmnopqrstuvwxyz' (from profile)",
			want: "PREFECT_API_KEY='****************************************' (from profile)",
		},
		{
			// The header a request to the Prefect Cloud API carries a key in.
			name: "an authorization header",
			src:  "Authorization: Bearer pnu_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "Authorization: Bearer ****************************************",
		},
		{
			name: "a command line",
			src:  "prefect cloud login --key pnu_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "prefect cloud login --key ****************************************",
		},
		{
			// The key a worker is given, which is the service account kind.
			name: "a service account key in a container environment",
			src:  "docker run -e PREFECT_API_KEY=pnb_0123456789abcdefghijklmnopqrstuvwxyz prefecthq/prefect",
			want: "docker run -e PREFECT_API_KEY=**************************************** prefecthq/prefect",
		},
		{
			name: "twice",
			src:  "pnu_0123456789abcdefghijklmnopqrstuvwxyz pnb_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			want: "**************************************** ****************************************",
		},
	}

	m := New(WithPatterns(PrefectAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PrefectAPIKey_aKeyBeginningInsideAnother(t *testing.T) {
	// The three characters in front of the underscore belong to the alphabet a
	// body is written in, so a body may close with the opening and a kind
	// character and the underscore of the next key stand directly behind it. The
	// second key begins three characters before the first one ends, and a scan
	// resuming past a match would step over it. The spans overlap, which a
	// Masker resolves into one.
	src := "pnu_0123456789abcdefghijklmnopqrstuvwpnu_0123456789abcdefghijklmnopqrstuvwxyz"
	want := []Span{{0, 40}, {37, 77}}
	if got, _ := PrefectAPIKey().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}

	masked := "*****************************************************************************"
	if got := New(WithPatterns(PrefectAPIKey())).Mask(src); got != masked {
		t.Errorf("Mask(%q) = %q, want %q", src, got, masked)
	}
}

func Test_PrefectAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xpnu_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "x****************************************",
		},
		{
			name: "underscore before",
			src:  "PREFECT_API_KEY_pnu_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "PREFECT_API_KEY_****************************************",
		},
		{
			// A multi-byte rune is no word character, but it is worth pinning
			// beside the two above: nothing about a boundary is asked of it
			// either, in front or behind.
			name: "a multi-byte rune before and after",
			src:  "日本語pnu_0123456789abcdefghijklmnopqrstuvwxyz日本語",
			want: "日本語****************************************日本語",
		},
		{
			name: "an invalid utf-8 byte before",
			src:  "\xffpnu_0123456789abcdefghijklmnopqrstuvwxyz",
			want: "\xff****************************************",
		},
	}

	m := New(WithPatterns(PrefectAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PrefectAPIKey_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a floor rather than a count. Where a key ends is
	// where its alphabet stops, so a letter or a digit written straight against
	// a key is redacted with it — which is what buys a key of a length Prefect
	// has not published being located whole. The alphabet is base62 and not
	// base64url, so the two characters that separate them, the hyphen and the
	// underscore, end a key here.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the key is pnu_0123456789abcdefghijklmnopqrstuvwxyz.",
			want: "the key is ****************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export PREFECT_API_KEY="pnu_0123456789abcdefghijklmnopqrstuvwxyz"`,
			want: `export PREFECT_API_KEY="****************************************"`,
		},
		{
			name: "a word against the key",
			src:  "pnu_0123456789abcdefghijklmnopqrstuvwxyzsuffix",
			want: "**********************************************",
		},
		{
			name: "a dashed word against the key",
			src:  "pnu_0123456789abcdefghijklmnopqrstuvwxyz-suffix",
			want: "****************************************-suffix",
		},
		{
			name: "an underscored word against the key",
			src:  "pnu_0123456789abcdefghijklmnopqrstuvwxyz_suffix",
			want: "****************************************_suffix",
		},
		{
			// Base64 padding is neither base62 nor a character that closes a
			// prefix, so it ends the run exactly as a hyphen or an underscore
			// would and is left in the text behind the key.
			name: "base64 padding against the key",
			src:  "pnu_0123456789abcdefghijklmnopqrstuvwxyz==",
			want: "****************************************==",
		},
		{
			// Two keys written straight against each other are one span, and
			// not because they nest: the first key's run carries on through the
			// opening and the kind character of the second prefix and stops at
			// that prefix's underscore, so the first span already covers where
			// the second one begins.
			name: "two keys with nothing between them",
			src:  "pnu_0123456789abcdefghijklmnopqrstuvwxyzpnb_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			want: "********************************************************************************",
		},
	}

	m := New(WithPatterns(PrefectAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PrefectAPIKey_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than redacted.
	// A line cut to a column limit partway through a key leaves a prefix and a
	// body too short to be one, and the random characters written before the cut
	// come through whole.
	//
	// It is the price of reading a count no page of Prefect's states, and it is
	// the price for a service account key at any length under thirty-six, which
	// nothing states at all.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a user key one character short of the floor",
			src:  "PREFECT_API_KEY=pnu_0123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			name: "a service account key one character short of the floor",
			src:  "PREFECT_API_KEY=pnb_0123456789abcdefghijklmnopqrstuvwxy",
		},
		{
			name: "a key cut off at its prefix",
			src:  "PREFECT_API_KEY=pnu_",
		},
	}

	m := New(WithPatterns(PrefectAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_PrefectAPIKey_holdsAKeyTheInputCutShort(t *testing.T) {
	// What Find's second return settles. builtin_scan.go and the rationale in
	// builtin_prefect_api_key.go give two shapes: a piece of a prefix standing
	// at the end of the input, and a candidate the end of the input cut short.
	// A candidate is cut short whether or not it has already reached the floor:
	// a run touching the end of the input can still be carried on, which would
	// widen the span, so a key is reported and the text from its start is held
	// back at the same time. Everything else is settled to the end of the input,
	// since nothing there could still become or widen a key.
	tests := []struct {
		name   string
		src    string
		retain int
	}{
		{
			// No prefix and no piece of one anywhere in the text, so the whole
			// of it is settled.
			name:   "no credential at all",
			src:    "there is no credential in this sentence",
			retain: len("there is no credential in this sentence"),
		},
		{
			// The last two characters of the input are a piece of both prefixes
			// at once, so what comes next could still complete one: the text
			// from there on is held.
			name:   "a piece of the opening at the end of the input",
			src:    "xxx pn",
			retain: 4,
		},
		{
			// A candidate whose body has not reached the floor, with the run
			// carrying on to the end of the input. What comes next either
			// carries the run on to a key or ends it, so this candidate's start
			// is held rather than settled.
			name:   "a candidate the input cut short of the floor",
			src:    "xxx pnb_0123456789abcdef",
			retain: 4,
		},
		{
			// A candidate past the floor whose run the end of the input cut
			// short. The key is reported, and its start is held back all the
			// same: what comes next may carry the run on, and the span would
			// then reach further than the one just reported.
			name:   "a key whose run the end of the input cut short",
			src:    "xxx pnu_0123456789abcdefghijklmnopqrstuvwxyz",
			retain: 4,
		},
		{
			// A candidate rejected by the text rather than by the end of it:
			// the character naming a kind names none, so nothing arriving
			// behind it could make a key of this, and the whole input is
			// settled.
			name:   "a candidate the text turned away",
			src:    "xxx pna_0123456789abcdef",
			retain: len("xxx pna_0123456789abcdef"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, retain := PrefectAPIKey().Find(tt.src); retain != tt.retain {
				t.Errorf("Find(%q) retain = %d, want %d", tt.src, retain, tt.retain)
			}
		})
	}
}

func Test_PrefectAPIKey_anUnderscoreInTheBody(t *testing.T) {
	// The other side of reading the body in base62 rather than in an alphabet
	// holding the underscore, held to being left in the text.
	// builtin_prefect_api_key.go argues why the narrow reading is the right one;
	// what it risks is here. Were Prefect writing bodies that carry an
	// underscore, the run would end at that character and a key whose first
	// thirty-six were not all base62 would come through whole.
	//
	// The cases move with the alphabet: one of them starting to be redacted
	// means the body was widened, and that is a decision to be taken rather than
	// noticed afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "an underscore early in the body",
			src:  "PREFECT_API_KEY=pnu_0123_56789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "an underscore one character short of the floor",
			src:  "PREFECT_API_KEY=pnb_0123456789abcdefghijklmnopqrstuvwxy_z",
		},
	}

	m := New(WithPatterns(PrefectAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_PrefectAPIKey_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix carries an
	// underscore, which standard base64 writes nowhere, so only a base64url
	// encoding can hold one; where thirty-six base62 characters follow,
	// everything from the prefix to the end of that run is redacted.
	//
	// The cases are held to being redacted rather than to being spared. What is
	// taken is a stretch of a value already opaque to a reader, and the run is a
	// key's format exactly: nothing is left in the text to tell the two apart, so
	// a pattern letting it through would let a real key through with it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "inside a base64url payload",
			src:  "payload=zzzzpnu_0123456789abcdefghijklmnopqrstuvwxyzzzzz",
			want: "payload=zzzz********************************************",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the
			// Prefect pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzpnu_0123456789abcdefghijklmnopqrstuvwxyzzzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz********************************************",
		},
	}

	m := New(WithPatterns(PrefectAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PrefectAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_prefect_api_key.go names, held to the answer it
	// gives rather than to the one a reader might want. Hexadecimal digits are
	// base62 and a digest carries nothing that ends a run, so a digest of
	// thirty-six characters or more written behind a prefix is a key's format
	// exactly and is redacted. Declining it would mean declining every key
	// Prefect wrote in the digits alone, which is the whole credential against a
	// cache key.
	//
	// The two below it are where the floor and the prefix each hold: an MD5 is
	// four characters short of a body, and a hyphen is no character a prefix
	// carries.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sha1 behind the prefix",
			src:  "pnu_0123456789abcdef0123456789abcdef01234567",
			want: "********************************************",
		},
		{
			name: "a sha256 in a cache key",
			src:  "key: pnu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "key: ********************************************************************",
		},
		{
			name: "an md5 behind the prefix, four characters short of a body",
			src:  "pnu_0123456789abcdef0123456789abcdef",
			want: "pnu_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a sha1 behind a hyphen rather than the prefix",
			src:  "pnu-0123456789abcdef0123456789abcdef01234567",
			want: "pnu-0123456789abcdef0123456789abcdef01234567",
		},
	}

	m := New(WithPatterns(PrefectAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PrefectAPIKey_theKeyCloudOneIssued(t *testing.T) {
	// The credential this pattern has nothing to say about, held to being left
	// in the text. Prefect's CLI names the format its first cloud issued only to
	// tell a caller which service a key was minted against, and what it names is
	// three letters with no separator behind them. Nothing of Prefect's states
	// an alphabet, a length or a character to close a prefix with, and three
	// letters on their own open a candidate inside prose.
	//
	// The case moves with that decision: were the format read here, this would
	// start being redacted, and that is a change to argue for rather than to
	// notice afterwards.
	src := "PREFECT__CLOUD__API_KEY=pcu0123456789abcdefghijklmnopqrstuvwxyz"
	if got := New(WithPatterns(PrefectAPIKey())).Mask(src); got != src {
		t.Errorf("Mask(%q) = %q, want the text unchanged", src, got)
	}
}

func Test_prefectAPIKeyOpening(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a key can
	// begin inside the one before it, and that holds only while the characters
	// in front of the underscore are ones a body may be written with. Here they
	// are the opening and the character naming the kind: a body closing with
	// those three leaves the underscore of the next key standing directly behind
	// it. An opening written outside the alphabet would make the two impossible
	// to nest, and the case above pinning the nesting would stand for nothing —
	// which is not a failure anything else here reports.
	if prefectAPIKeyOpening == "" {
		t.Fatal("the pattern carries no opening, so it locates nothing")
	}
	for i := range len(prefectAPIKeyOpening) {
		if c := prefectAPIKeyOpening[i]; !isBase62Byte(c) {
			t.Errorf("the opening holds %q, which no body may be written with", c)
		}
	}
}

func Test_prefectAPIKeyKinds(t *testing.T) {
	// The characters naming a kind, held to naming no character twice and to
	// being ones a body may be written with. A character repeated would build
	// two prefixes the same, which costs the tail of the input a comparison it
	// can never need; one outside the alphabet would part the nesting the scan
	// resumes a byte along for from the grammar that makes it possible.
	if prefectAPIKeyKinds == "" {
		t.Fatal("the pattern names no kind, so it locates nothing")
	}

	// The count builtin_prefect_api_key.go states in prose, held here so that a
	// kind added fails where the sentence naming the number can be found.
	if got, want := len(prefectAPIKeyKinds), 2; got != want {
		t.Errorf("the table names %d kind(s) and builtin_prefect_api_key.go says %d", got, want)
	}
	seen := map[byte]bool{}
	for i := range len(prefectAPIKeyKinds) {
		c := prefectAPIKeyKinds[i]
		if seen[c] {
			t.Errorf("the kinds name %q twice", c)
		}
		seen[c] = true
		if !isBase62Byte(c) {
			t.Errorf("the kinds name %q, which no body may be written with", c)
		}
	}
}

// Test_prefectAPIKeyAnchor holds every prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from, and to the
// width the scan reads a body from. builtin_scan.go says why that is held here
// rather than left to the targets.
func Test_prefectAPIKeyAnchor(t *testing.T) {
	if len(prefectAPIKeyPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for _, p := range prefectAPIKeyPrefixes {
		if len(p) != prefectAPIKeyPrefixChars {
			t.Errorf("the prefix %q is %d characters where the scan reads a body %d in", p, len(p), prefectAPIKeyPrefixChars)
			continue
		}
		if c := p[prefectAPIKeyAnchorIndex]; c != prefectAPIKeyAnchor {
			t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", p, c, byte(prefectAPIKeyAnchor))
		}
	}
}

func Test_prefectAPIKeyPrefixes_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over it,
	// where a scan whose prefix closes on a character its own body admits has to
	// keep one. What makes the cursor unnecessary is that two candidates can
	// never read the same run: a candidate asks for the last character of a
	// prefix four characters in, no body may be written with it, so the run of an
	// earlier candidate has already ended there and the later candidate's run
	// begins past it. Were that character one a body admits, a run dense in
	// prefixes would be walked once for every candidate in it and the scan would
	// cost time quadratic in the length of such a line.
	if len(prefectAPIKeyPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so there is no candidate to reason about")
	}
	for _, p := range prefectAPIKeyPrefixes {
		if c := p[len(p)-1]; isBase62Byte(c) {
			t.Errorf("the prefix %q closes with %q, which a body may be written with, so two candidates can read the same run", p, c)
		}
	}
}

func Test_PrefectAPIKey_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a line dense in prefixes
	// holds a candidate for every four characters it has. The one thing a
	// candidate reads that is a walk over the rest of the input rather than a
	// bounded test is where its run ends, and repeating that walk at every
	// candidate would cost time quadratic in the length of the line. The bound
	// here is far above a linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every thirty-seven bytes where they are densest, because a
	// sample has to carry a whole body to be one. The crowding a line can
	// actually carry, a candidate every four bytes, stays here.
	sources := map[string]string{
		// Candidates as close together as a prefix allows, none of them with a
		// run long enough to be a body: every one reaches the body of the loop
		// and every one is rejected.
		"a candidate every four characters": strings.Repeat("pnu_", 500000),
		// Keys written into one another, each beginning three characters before
		// the one in front of it ends, so every candidate is a key and every one
		// of them walks a run.
		"a key beginning inside every key": strings.Repeat("pnu_0123456789abcdefghijklmnopqrstuvw", 50000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a key.
		"a body that runs the length of the line": "pnu_" + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("a_", 900000),
		// An opening and an anchor with no character naming a kind between them,
		// which is the candidate that costs a whole opening to decline.
		"an opening that names no kind": strings.Repeat("pna_", 500000),
		// And the opening's own letters with no anchor among them, which is the
		// walk reading a whole line and stopping nowhere in it.
		"the letters of the opening with no anchor": strings.Repeat("pn", 900000),
	}

	checkScanIsLinear(t, PrefectAPIKey(), sources)
}

// referencePrefectAPIKey is the expression the scan in
// builtin_prefect_api_key.go reads by hand: the statement of what a Prefect API
// key is, kept here so that the scan can be held to it.
//
// The opening, the kinds, the separator, the floor and the alphabet are spelled
// again rather than built from prefectAPIKeyOpening, prefectAPIKeyKinds,
// prefectAPIKeyAnchor, prefectAPIKeyBodyChars and isBase62Byte. A reference
// sharing those declarations could not disagree with the scan about them, and it
// is exactly that disagreement the fuzz target below is for: the two have to be
// changed together or reported apart.
//
// The floor is written as a counted repetition, which costs an engine a machine
// as wide as the floor at every candidate. It costs nothing here, and for the
// reason the scan needs no cursor: candidates cannot crowd inside one run, so no
// input makes an engine walk the same run more than once. The opening is a
// literal in front of the grammar besides, which is what an engine searches the
// text for.
var referencePrefectAPIKey = regexp.MustCompile(`pn[ub]_[0-9A-Za-z]{36,}`)

// referencePrefectAPIKeyFind locates keys the plain way: the leftmost match of
// the expression above, then the leftmost one beginning after that match's first
// byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a key can begin inside one: the three characters
// in front of the underscore are written in the alphabet a body is, so a body
// closing with them holds the start of the key behind it. The scan finds both
// and reports the two spans overlapping for a Masker to resolve, so the
// reference must ask about both.
func referencePrefectAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referencePrefectAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzPrefectAPIKey_matchesReference guards the hand-written scan: the opening
// it searches back from, the kinds it admits between that opening and the
// underscore, the floor it holds a body to, the alphabet it reads that body in
// and the byte it resumes at may none of them change which keys are located.
func FuzzPrefectAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("PREFECT_API_KEY=pnu_0123456789abcdefghijklmnopqrstuvwxyz")
	f.Add("pnb_0123456789abcdefghijklmnopqrstuvwxyz")
	f.Add("pna_0123456789abcdefghijklmnopqrstuvwxyz") // a character naming no kind
	f.Add("pnu_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	f.Add("pnu_0123456789abcdefghijklmnopqrstuvwxy")   // one short of a body
	f.Add("pnu_0123456789abcdefghijklmnopqrstuvwxyz0") // and a run longer than one
	f.Add("pnu_0123456789abcdef-ghijklmnopqrstuvwxyz") // a hyphen, which base64url admits and base62 does not
	f.Add("pnu_0123456789abcdef_ghijklmnopqrstuvwxyz") // an underscore, likewise
	f.Add("pnu_0123456789abcdef.ghijklmnopqrstuvwxyz") // a dot ends the body
	f.Add("PNU_0123456789abcdefghijklmnopqrstuvwxyz")  // an uppercase prefix
	f.Add("pnu-0123456789abcdefghijklmnopqrstuvwxyz")  // a hyphen where the prefix carries an underscore
	f.Add("pn_0123456789abcdefghijklmnopqrstuvwxyz")   // no character naming a kind at all
	f.Add("pnu_0123456789abcdefghijklmnopqrstuvwxyz-suffix")
	f.Add("pnu_0123456789abcdefghijklmnopqrstuvwxyz_suffix")
	f.Add("pnu_0123456789abcdefghijklmnopqrstuvwxyz\npnb_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	// A key beginning inside the match before it, which a scan resuming past a
	// match steps over, and two keys with nothing between them.
	f.Add("pnu_0123456789abcdefghijklmnopqrstuvwpnu_0123456789abcdefghijklmnopqrstuvwxyz")
	f.Add("pnu_0123456789abcdefghijklmnopqrstuvwxyzpnb_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	// Candidate positions crowded as close as they can be, with no run long
	// enough for any of them, and keys written into one another so that every
	// candidate has one.
	f.Add(strings.Repeat("pnu_", 16))
	f.Add(strings.Repeat("pnu_0123456789abcdefghijklmnopqrstuvw", 4))
	// A digest written behind the prefix, which is a key's format exactly, and
	// one four characters short of a body.
	f.Add("pnu_0123456789abcdef0123456789abcdef01234567")
	f.Add("key: pnu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("pnu_0123456789abcdef0123456789abcdef")
	// The prefix written inside a run of base64url, which is the over-match the
	// pattern admits.
	f.Add("payload=zzzzpnu_0123456789abcdefghijklmnopqrstuvwxyzzzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzpnu_0123456789abcdefghijklmnopqrstuvwxyzzzzz")
	// The key Prefect Cloud 1 issued, which carries no separator to read a
	// candidate back from.
	f.Add("PREFECT__CLOUD__API_KEY=pcu0123456789abcdefghijklmnopqrstuvwxyz")

	fuzzAgainstReference(f, PrefectAPIKey().Find, referencePrefectAPIKeyFind)
}

// prefectAPIKeyFindBenchmarks is what this scan is timed on. The builtinPatterns
// entry for the pattern names it, and BenchmarkBuiltins times every case it
// holds under the pattern's own name, so that a built-in cannot arrive without a
// benchmark. Every case is held to the count it states under a plain go test as
// well, which is what a benchmark nobody has run yet cannot be.
func prefectAPIKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens a prefix, so what the line times is the
	// search for the underscore — which is most of what this pattern costs a
	// caller whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="polling for flow runs" url=https://api.prefect.cloud/api/accounts/0123/workspaces `
	key := "pnu_0123456789abcdefghijklmnopqrstuvwxyz"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every four characters with no run long enough behind
			// any of them: each reaches the body of the loop and none becomes a
			// key. What it times is the walk over a run being started and
			// stopped, once per candidate and no more.
			name:  "candidates that are not values",
			src:   strings.Repeat("pnu_", 128),
			spans: 0,
		},
		{
			// The same crowding with a character naming no kind, which is the
			// candidate declined by the one byte read after the opening.
			name:  "candidates naming no kind",
			src:   strings.Repeat("pna_", 128),
			spans: 0,
		},
		{
			// Keys written into one another, each beginning three characters
			// before the one in front of it ends. This is what the scan gets
			// away with keeping no cursor for: the runs the candidates read
			// follow one another rather than overlapping. The four characters at
			// the end are what closes the body of the last of them, which
			// otherwise has only the run it was written with.
			name:  "keys written into one another",
			src:   strings.Repeat("pnu_0123456789abcdefghijklmnopqrstuvw", 128) + "xyz",
			spans: 128,
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
