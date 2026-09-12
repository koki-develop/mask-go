package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Klaviyo private API key pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. A body is built from the run
// 0123456789abcdefghijklmnopqrstuvwx, thirty-four characters and so the shortest
// body the scan reads, since the count is a floor — a body shortened for
// readability would leave a case holding no key at all. It is written in
// lowercase where the case does not matter and in uppercase where the case is
// what a case is about: base62 holds the letters of both, so either spelling is
// a body.
//
// The six characters a key of the scoped shape carries between its prefix and
// its body are written 012345, and in other cases wherever the width or the
// character closing them is what the case is about.

func Test_KlaviyoPrivateAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "pk_0123456789abcdefghijklmnopqrstuvwx",
			want: []Span{{0, 37}},
		},
		{
			// The other shape: six characters and a second underscore between
			// the prefix and the body.
			name: "a key carrying the six characters between its prefix and its body",
			src:  "pk_012345_0123456789abcdefghijklmnopqrstuvwx",
			want: []Span{{0, 44}},
		},
		{
			name: "a key in an environment assignment",
			src:  "KLAVIYO_API_KEY=pk_0123456789abcdefghijklmnopqrstuvwx",
			want: []Span{{16, 53}},
		},
		{
			// base62 holds the letters of both cases, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "pk_0123456789ABCDEFGHIJKLMNOPQRSTUVWX",
			want: []Span{{0, 37}},
		},
		{
			// base62 has six ends — 0, 9, A, Z, a and z — and a range bound
			// written one too wide at any of them admits a character no key
			// carries. A body built from an ordered run stands on two of them
			// and no more, at its first character and at its last, so each of
			// the cases here opens a body on one end and closes it on another.
			name: "a body opening on the last lowercase letter and closing on the first digit",
			src:  "pk_z0123456789abcdefghijklmnopqrstuv0",
			want: []Span{{0, 37}},
		},
		{
			name: "a body opening on the last uppercase letter and closing on the last digit",
			src:  "pk_Z0123456789abcdefghijklmnopqrstuv9",
			want: []Span{{0, 37}},
		},
		{
			name: "a body opening on the first lowercase letter and closing on the first uppercase one",
			src:  "pk_a0123456789abcdefghijklmnopqrstuvA",
			want: []Span{{0, 37}},
		},
		{
			name: "a body opening on the last digit and closing on the first lowercase letter",
			src:  "pk_90123456789ABCDEFGHIJKLMNOPQRSTUVa",
			want: []Span{{0, 37}},
		},
		{
			name: "a body opening on the first uppercase letter and closing on the last lowercase one",
			src:  "pk_A0123456789ABCDEFGHIJKLMNOPQRSTUVz",
			want: []Span{{0, 37}},
		},
		{
			name: "a body opening on the first digit and closing on the last uppercase letter",
			src:  "pk_00123456789abcdefghijklmnopqrstuvZ",
			want: []Span{{0, 37}},
		},
		{
			// The segment is read in the alphabet a body is, so the same six
			// ends stand there. What is its own is the width and the underscore
			// behind it, which the cases below this one are about.
			name: "a segment written in capitals",
			src:  "pk_ABCDEF_0123456789abcdefghijklmnopqrstuvwx",
			want: []Span{{0, 44}},
		},
		{
			// The count is a floor and the span reaches the end of the run, so
			// a run longer than the shortest body is a key to the end of it
			// rather than a key and a character left over.
			name: "a run longer than the shortest body",
			src:  "pk_0123456789abcdefghijklmnopqrstuvwxy",
			want: []Span{{0, 38}},
		},
		{
			name: "a scoped key whose run is longer than the shortest body",
			src:  "pk_012345_0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 46}},
		},
		{
			name: "two keys separated by a space",
			src:  "pk_0123456789abcdefghijklmnopqrstuvwx pk_012345_0123456789abcdefghijklmnopqrstuvwx",
			want: []Span{{0, 37}, {38, 82}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := KlaviyoPrivateAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_KlaviyoPrivateAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "pk_",
		},
		{
			// Thirty-three characters where the pattern asks for thirty-four.
			// This is the shape a line cut to a column limit leaves, and the
			// characters in front of the cut stay in the text: the far side of
			// reading a floor, which builtin_klaviyo_private_api_key.go weighs.
			name: "a body one character too short",
			src:  "pk_0123456789abcdefghijklmnopqrstuvw",
		},
		{
			name: "a scoped key whose body is one character too short",
			src:  "pk_012345_0123456789abcdefghijklmnopqrstuvw",
		},
		{
			// The hyphen and the underscore are base64url characters and no
			// base62 ones, so either ends a body where the run behind it is too
			// short to be one. Both are written at the ends of a body as well
			// as inside one, since a run ends at the character wherever it
			// stands.
			name: "a body carrying a hyphen",
			src:  "pk_0123456789abcdef-ghijklmnopqrstuvwxyz",
		},
		{
			name: "a body carrying an underscore",
			src:  "pk_0123456789abcdef_ghijklmnopqrstuvwxyz",
		},
		{
			name: "a hyphen at the first character of the body",
			src:  "pk_-0123456789abcdefghijklmnopqrstuvwx",
		},
		{
			name: "an underscore at the first character of the body",
			src:  "pk__0123456789abcdefghijklmnopqrstuvwx",
		},
		{
			// A hyphen at the last character of a body, with thirty-three
			// characters in front of it: the run ends one short of the floor
			// however far the text carries on behind the hyphen.
			name: "a hyphen at the last character of the body",
			src:  "pk_0123456789abcdefghijklmnopqrstuvw-x",
		},
		{
			name: "an underscore at the last character of the body",
			src:  "pk_0123456789abcdefghijklmnopqrstuvw_x",
		},
		{
			// A plus is a base64 character and no base62 one, so it ends a body
			// exactly as the hyphen and the underscore do.
			name: "a plus in the body",
			src:  "pk_0123456789abcdef+ghijklmnopqrstuvwxyz",
		},
		{
			// The bytes just outside base62's six ends, which is where a range
			// bound written one too wide would show. Each stands in a run of
			// thirty-seven characters, so a body admitting it would be located
			// and the case would fail rather than merely stop stating anything.
			// The first of them is the slash base64 writes a body with.
			name: "the byte before the first digit in the body",
			src:  "pk_0123456789abcdef/ghijklmnopqrstuvwxyz0",
		},
		{
			name: "the byte past the last digit in the body",
			src:  "pk_0123456789abcdef:ghijklmnopqrstuvwxyz0",
		},
		{
			name: "the byte before the first uppercase letter in the body",
			src:  "pk_0123456789abcdef@ghijklmnopqrstuvwxyz0",
		},
		{
			name: "the byte past the last uppercase letter in the body",
			src:  "pk_0123456789abcdef[ghijklmnopqrstuvwxyz0",
		},
		{
			name: "the byte before the first lowercase letter in the body",
			src:  "pk_0123456789abcdef`ghijklmnopqrstuvwxyz0",
		},
		{
			name: "the byte past the last lowercase letter in the body",
			src:  "pk_0123456789abcdef{ghijklmnopqrstuvwxyz0",
		},
		{
			// A segment of some other width. Six is read exactly, and a
			// candidate whose segment is wider or narrower is read as the plain
			// shape instead, whose body then ends at the segment's own
			// underscore.
			name: "a segment one character too narrow",
			src:  "pk_01234_0123456789abcdefghijklmnopqrstuvwx",
		},
		{
			name: "a segment one character too wide",
			src:  "pk_0123456_0123456789abcdefghijklmnopqrstuvwx",
		},
		{
			name: "no segment at all, the two underscores written together",
			src:  "pk__0123456789abcdefghijklmnopqrstuvwx0",
		},
		{
			// A segment is the run behind the prefix, so a character that alphabet
			// leaves out ends it short of the width wherever it stands.
			name: "a segment carrying a hyphen",
			src:  "pk_012-45_0123456789abcdefghijklmnopqrstuvwx",
		},
		{
			name: "a hyphen at the last character of the segment",
			src:  "pk_01234-_0123456789abcdefghijklmnopqrstuvwx",
		},
		{
			// The segment is the right width and what ends it is no underscore,
			// which is the one comparison that tells the scoped shape from a
			// candidate the text turned away.
			name: "a segment the right width closed by a hyphen",
			src:  "pk_012345-0123456789abcdefghijklmnopqrstuvwx",
		},
		{
			name: "an uppercase prefix",
			src:  "PK_0123456789abcdefghijklmnopqrstuvwx",
		},
		{
			// The prefix closes with an underscore, so a hyphen written in its
			// place opens no candidate at all.
			name: "a hyphen where the prefix carries an underscore",
			src:  "pk-0123456789abcdefghijklmnopqrstuvwx",
		},
		{
			name: "one character of the prefix",
			src:  "px_0123456789abcdefghijklmnopqrstuvwx",
		},
		{
			name: "a space in the body",
			src:  "pk_0123456789abcdef ghijklmnopqrstuvwxyz",
		},
		{
			name: "a dot in the body",
			src:  "pk_0123456789abcdef.ghijklmnopqrstuvwxyz",
		},
		{
			name: "a body broken by a line break",
			src:  "pk_0123456789abcdef\nghijklmnopqrstuvwxyz",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// the whole of the anchor, so a run long enough is not a key
			// without it.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdefghijklmnopqrstuvwx",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := KlaviyoPrivateAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_KlaviyoPrivateAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "KLAVIYO_API_KEY=pk_0123456789abcdefghijklmnopqrstuvwx",
			want: "KLAVIYO_API_KEY=*************************************",
		},
		{
			// The header Klaviyo's API takes a private key in, which its
			// authentication guide writes as Klaviyo-API-Key and the key.
			name: "an authorization header",
			src:  "Authorization: Klaviyo-API-Key pk_0123456789abcdefghijklmnopqrstuvwx",
			want: "Authorization: Klaviyo-API-Key *************************************",
		},
		{
			name: "a command line",
			src:  `curl -H "Authorization: Klaviyo-API-Key pk_0123456789abcdefghijklmnopqrstuvwx" https://a.klaviyo.com/api/profiles`,
			want: `curl -H "Authorization: Klaviyo-API-Key *************************************" https://a.klaviyo.com/api/profiles`,
		},
		{
			name: "a scoped key in a container environment",
			src:  "docker run -e KLAVIYO_API_KEY=pk_012345_0123456789abcdefghijklmnopqrstuvwx app",
			want: "docker run -e KLAVIYO_API_KEY=******************************************** app",
		},
		{
			name: "a key in json",
			src:  `{"private_key":"pk_0123456789abcdefghijklmnopqrstuvwx"}`,
			want: `{"private_key":"*************************************"}`,
		},
		{
			name: "twice",
			src:  "pk_0123456789abcdefghijklmnopqrstuvwx pk_012345_0123456789abcdefghijklmnopqrstuvwx",
			want: "************************************* ********************************************",
		},
	}

	m := New(WithPatterns(KlaviyoPrivateAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_KlaviyoPrivateAPIKey_aKeyBeginningInsideAnother(t *testing.T) {
	// Both characters of the prefix in front of the underscore belong to the
	// alphabet a body is written in, so a body may close with them and the
	// underscore of the next key stand directly behind it. The second key begins
	// two characters before the first one ends, and a scan resuming past a match
	// would step over it. The spans overlap, which a Masker resolves into one.
	//
	// The segment does the same and reaches further: it is the run behind the
	// prefix, so a segment closing with those two characters makes the
	// underscore that separates a scoped key from its body the underscore of a
	// whole second key. That is the one input where the scan reads back from a
	// second underscore into a real prefix, and it is the worst case the account
	// of the scan's cost rests on — one run read by two candidates and by no
	// more than two.
	tests := []struct {
		name   string
		src    string
		want   []Span
		masked string
	}{
		{
			name:   "a key beginning inside a body",
			src:    "pk_0123456789abcdefghijklmnopqrstuvwxpk_0123456789abcdefghijklmnopqrstuvwx",
			want:   []Span{{0, 39}, {37, 74}},
			masked: "**************************************************************************",
		},
		{
			// The segment closes with the two characters a prefix opens with,
			// so both candidates are keys and both read the one body run: the
			// outer through its segment, the inner from its own prefix.
			name:   "a key beginning inside a segment",
			src:    "pk_0123pk_0123456789abcdefghijklmnopqrstuvwx",
			want:   []Span{{0, 44}, {7, 44}},
			masked: "********************************************",
		},
		{
			// The same shape with the run one character too narrow to be a
			// segment, which is what reading the width exactly is for: the
			// outer candidate is declined and the key written inside it stands
			// on its own. It is also what asking for no letter and no digit in
			// front of a prefix would cost — a digit stands in front of this
			// key's pk_, and nothing else here reaches its body, so the demand
			// would leave the whole of it in the output.
			name:   "a key inside a run too narrow to be a segment",
			src:    "pk_012pk_0123456789abcdefghijklmnopqrstuvwx",
			want:   []Span{{6, 43}},
			masked: "pk_012*************************************",
		},
	}

	m := New(WithPatterns(KlaviyoPrivateAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := KlaviyoPrivateAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
			if got := m.Mask(tt.src); got != tt.masked {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.masked)
			}
		})
	}
}

func Test_KlaviyoPrivateAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xpk_0123456789abcdefghijklmnopqrstuvwx",
			want: "x*************************************",
		},
		{
			name: "underscore before",
			src:  "KLAVIYO_API_KEY_pk_0123456789abcdefghijklmnopqrstuvwx",
			want: "KLAVIYO_API_KEY_*************************************",
		},
		{
			// A multi-byte rune is no word character, but it is worth pinning
			// beside the two above: nothing about a boundary is asked of it
			// either, in front or behind.
			name: "a multi-byte rune before and after",
			src:  "日本語pk_0123456789abcdefghijklmnopqrstuvwx日本語",
			want: "日本語*************************************日本語",
		},
		{
			name: "an invalid utf-8 byte before",
			src:  "\xffpk_0123456789abcdefghijklmnopqrstuvwx",
			want: "\xff*************************************",
		},
	}

	m := New(WithPatterns(KlaviyoPrivateAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_KlaviyoPrivateAPIKey_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a floor rather than a count. Where a key ends is
	// where its alphabet stops, so a letter of either case or a digit written
	// straight against a key is redacted with it — which is what buys a key of a
	// length Klaviyo has not published being located whole. The alphabet is
	// base62 and not base64url, so the two characters that separate them, the
	// hyphen and the underscore, end a key here.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the key is pk_0123456789abcdefghijklmnopqrstuvwx.",
			want: "the key is *************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export KLAVIYO_API_KEY="pk_0123456789abcdefghijklmnopqrstuvwx"`,
			want: `export KLAVIYO_API_KEY="*************************************"`,
		},
		{
			name: "a word against the key",
			src:  "pk_0123456789abcdefghijklmnopqrstuvwxsuffix",
			want: "*******************************************",
		},
		{
			// The alphabet holds the letters of both cases, so a capital
			// against a key is redacted with it exactly as a lowercase letter
			// is.
			name: "a capitalised word against the key",
			src:  "pk_0123456789abcdefghijklmnopqrstuvwxSuffix",
			want: "*******************************************",
		},
		{
			name: "a dashed word against the key",
			src:  "pk_0123456789abcdefghijklmnopqrstuvwx-suffix",
			want: "*************************************-suffix",
		},
		{
			name: "an underscored word against the key",
			src:  "pk_0123456789abcdefghijklmnopqrstuvwx_suffix",
			want: "*************************************_suffix",
		},
		{
			// Base64 padding is neither base62 nor a character that closes a
			// prefix, so it ends the run exactly as a hyphen or an underscore
			// would and is left in the text behind the key.
			name: "base64 padding against the key",
			src:  "pk_0123456789abcdefghijklmnopqrstuvwx==",
			want: "*************************************==",
		},
	}

	m := New(WithPatterns(KlaviyoPrivateAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_KlaviyoPrivateAPIKey_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than redacted.
	// A line cut to a column limit partway through a key leaves a prefix and a
	// body too short to be one, and the random characters written before the cut
	// come through whole. It is the price of reading a count no page of
	// Klaviyo's states.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a key one character short of the floor",
			src:  "KLAVIYO_API_KEY=pk_0123456789abcdefghijklmnopqrstuvw",
		},
		{
			name: "a scoped key one character short of the floor",
			src:  "KLAVIYO_API_KEY=pk_012345_0123456789abcdefghijklmnopqrstuvw",
		},
		{
			name: "a key cut off at its prefix",
			src:  "KLAVIYO_API_KEY=pk_",
		},
	}

	m := New(WithPatterns(KlaviyoPrivateAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_KlaviyoPrivateAPIKey_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued, and the price of reading the
	// body in the alphabet Klaviyo states rather than in the narrower one of the
	// two rules. The prefix carries an underscore, which standard base64 writes
	// nowhere, so only a base64url encoding can hold one; where thirty-four
	// base62 characters follow, everything from the prefix to the end of that
	// run is redacted.
	//
	// The cases are held to being redacted rather than to being spared. What is
	// taken is a stretch of a value already opaque to a reader, and the run is a
	// key's format exactly: nothing is left in the text to tell the two apart,
	// so a pattern letting it through would let a real key through with it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "inside a base64url payload",
			src:  "payload=zzzzpk_0123456789abcdefghijklmnopqrstuvwxzzzz",
			want: "payload=zzzz*****************************************",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the
			// Klaviyo pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzpk_0123456789abcdefghijklmnopqrstuvwxzzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz*****************************************",
		},
	}

	m := New(WithPatterns(KlaviyoPrivateAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_KlaviyoPrivateAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_klaviyo_private_api_key.go names, held to the answer
	// it gives rather than to the one a reader might want. Hexadecimal digits
	// are base62 and a digest carries nothing that ends a run, so a digest of
	// thirty-four characters or more written behind the prefix is a key's format
	// exactly and is redacted. Declining it would mean declining every key
	// Klaviyo wrote in the hexadecimal digits alone — which is the narrower of
	// the two rules read here, so it would be declining the format one of them
	// states.
	//
	// The two below them are where the floor and the prefix each hold: an MD5 is
	// two characters short of a body, and a hyphen is no character a prefix
	// carries.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sha1 behind the prefix",
			src:  "pk_0123456789abcdef0123456789abcdef01234567",
			want: "*******************************************",
		},
		{
			name: "a sha256 in a cache key",
			src:  "key: pk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "key: *******************************************************************",
		},
		{
			name: "an md5 behind the prefix, two characters short of a body",
			src:  "pk_0123456789abcdef0123456789abcdef",
			want: "pk_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a sha1 behind a hyphen rather than the prefix",
			src:  "pk-0123456789abcdef0123456789abcdef01234567",
			want: "pk-0123456789abcdef0123456789abcdef01234567",
		},
	}

	m := New(WithPatterns(KlaviyoPrivateAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_KlaviyoPrivateAPIKey_aWordEndingInThePrefix(t *testing.T) {
	// What asking for no letter and no digit in front of the prefix would have
	// bought, held to being redacted rather than spared.
	// builtin_klaviyo_private_api_key.go weighs the demand and declines it: a key
	// can be written inside the one before it, and the demand would drop that
	// second key. What it costs is here — three characters ending in pk close an
	// identifier, so a name ending in topk_ with a run of the right length behind
	// it is this format exactly and is redacted from its own pk_ onwards.
	//
	// The second case is the same name against the Stripe prefix, which
	// builtin_stripe_publishable_key.go does ask the demand of and so leaves
	// alone. The pair is the disagreement that file's rule and this one's produce
	// on one line, written down rather than left to be discovered.
	tests := []struct {
		name    string
		src     string
		want    string
		pattern Pattern
	}{
		{
			name:    "an identifier ending in the prefix, read here",
			src:     "topk_0123456789abcdefghijklmnopqrstuvwx",
			want:    "to*************************************",
			pattern: KlaviyoPrivateAPIKey(),
		},
		{
			name:    "the same identifier against the stripe prefix, left alone there",
			src:     "topk_live_0123456789abcdef01234567",
			want:    "topk_live_0123456789abcdef01234567",
			pattern: StripePublishableKey(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(WithPatterns(tt.pattern)).Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_KlaviyoPrivateAPIKey_aStripePublishableKey(t *testing.T) {
	// The value that shares this prefix, held to being left alone from this
	// side. A Stripe publishable key writes its mode and an underscore behind
	// pk_, which is four characters where the scoped shape here reads six, so
	// the segment is declined and the plain shape finds a run of four against a
	// floor of thirty-four. builtin_stripe_publishable_key.go is what locates
	// these; the case in conformance/testdata/builtins_together.txt is where the
	// two patterns are run over one line.
	//
	// The last of them is the one that would go wrong quietly: a Stripe key
	// whose own body is long enough to be a body here is still not one, because
	// the underscore in front of it is where a Klaviyo body may not begin.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a live publishable key",
			src:  "pk_live_0123456789abcdef01234567",
		},
		{
			name: "a test publishable key",
			src:  "pk_test_0123456789abcdef01234567",
		},
		{
			name: "a publishable key whose body is as long as a body here",
			src:  "pk_live_0123456789abcdefghijklmnopqrstuvwx",
		},
	}

	m := New(WithPatterns(KlaviyoPrivateAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_KlaviyoPrivateAPIKey_holdsAKeyTheInputCutShort(t *testing.T) {
	// What Find's second return settles. builtin_scan.go and the rationale in
	// builtin_klaviyo_private_api_key.go give two shapes: a piece of the prefix
	// standing at the end of the input, and a candidate the end of the input cut
	// short. A candidate is cut short whether or not it has already reached the
	// floor: a run touching the end of the input can still be carried on, which
	// would widen the span, so a key is reported and the text from its start is
	// held back at the same time. Everything else is settled to the end of the
	// input, since nothing there could still become or widen a key.
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
			// The last two characters of the input are a piece of the prefix,
			// so what comes next could still complete it: the text from there
			// on is held.
			name:   "a piece of the prefix at the end of the input",
			src:    "xxx pk",
			retain: 4,
		},
		{
			// A candidate whose body has not reached the floor, with the run
			// carrying on to the end of the input. What comes next either
			// carries the run on to a key or ends it, so this candidate's start
			// is held rather than settled.
			name:   "a candidate the input cut short of the floor",
			src:    "xxx pk_0123456789abcdef",
			retain: 4,
		},
		{
			// A candidate past the floor whose run the end of the input cut
			// short. The key is reported, and its start is held back all the
			// same: what comes next may carry the run on, and the span would
			// then reach further than the one just reported.
			name:   "a key whose run the end of the input cut short",
			src:    "xxx pk_0123456789abcdefghijklmnopqrstuvwx",
			retain: 4,
		},
		{
			// A run the end of the input left at the segment's width. What
			// comes next decides which shape this is — an underscore makes it a
			// segment and anything else of the alphabet carries the plain
			// body on — so neither is settled.
			name:   "a run the end of the input left at the width of a segment",
			src:    "xxx pk_012345",
			retain: 4,
		},
		{
			// The scoped shape's own body run, below the floor and carrying on
			// to the end of the input. The segment was decided by the text, so
			// what holds this candidate is the run behind it — the second place
			// this scan reports a candidate the end of the input cut short.
			name:   "a scoped candidate the input cut short of the floor",
			src:    "xxx pk_012345_0123456789abcdef",
			retain: 4,
		},
		{
			// A scoped key past the floor whose run the end of the input cut
			// short. The key is reported, and its start is held back all the
			// same.
			name:   "a scoped key whose run the end of the input cut short",
			src:    "xxx pk_012345_0123456789abcdefghijklmnopqrstuvwx",
			retain: 4,
		},
		{
			// A candidate rejected by the text rather than by the end of it:
			// the run is the segment's width and what closed it is no
			// underscore, so nothing arriving behind it could make a key of
			// this, and the whole input is settled.
			name:   "a candidate the text closed at the segment's width",
			src:    "xxx pk_012345.",
			retain: len("xxx pk_012345."),
		},
		{
			// A body the text ended one character short of the floor. The walk
			// over the run is what decided it rather than a bound on what is
			// left of the input, so the whole input is settled — which is the
			// answer a case ending inside the run cannot state.
			name:   "a body the text ended one character short of the floor",
			src:    "xxx pk_0123456789abcdefghijklmnopqrstuvw.",
			retain: len("xxx pk_0123456789abcdefghijklmnopqrstuvw."),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, retain := KlaviyoPrivateAPIKey().Find(tt.src); retain != tt.retain {
				t.Errorf("Find(%q) retain = %d, want %d", tt.src, retain, tt.retain)
			}
		})
	}
}

func Test_klaviyoPrivateAPIKeyPrefix(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a key can
	// begin inside the one before it, and that holds only while the characters
	// in front of the underscore are ones a body may be written with. A prefix
	// written outside the alphabet would make the two impossible to nest, and
	// the cases above pinning the nesting would stand for nothing — which is not
	// a failure anything else here reports.
	if klaviyoPrivateAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for i := range klaviyoPrivateAPIKeyAnchorIndex {
		if c := klaviyoPrivateAPIKeyPrefix[i]; !isBase62Byte(c) {
			t.Errorf("the prefix holds %q in front of its anchor, which no body may be written with", c)
		}
	}
}

// Test_klaviyoPrivateAPIKeyAnchor holds every prefix to carrying the byte the
// scan searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_klaviyoPrivateAPIKeyAnchor(t *testing.T) {
	if len(klaviyoPrivateAPIKeyPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for _, p := range klaviyoPrivateAPIKeyPrefixes {
		if len(p) <= klaviyoPrivateAPIKeyAnchorIndex {
			t.Errorf("the prefix %q is %d characters where the scan reads its anchor at %d", p, len(p), klaviyoPrivateAPIKeyAnchorIndex)
			continue
		}
		if c := p[klaviyoPrivateAPIKeyAnchorIndex]; c != klaviyoPrivateAPIKeyAnchor {
			t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", p, c, byte(klaviyoPrivateAPIKeyAnchor))
		}
	}
}

func Test_klaviyoPrivateAPIKeyPrefix_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over it,
	// where a scan whose prefix closes on a character its own body admits has to
	// keep one. What makes the cursor unnecessary is that a body begins one byte
	// past an underscore and no body is written with one, so a run read here
	// ends at or before the underscore the next candidate is found by. The two
	// shapes put a body three characters past a prefix or ten, so at most two
	// candidates can read one run — which is a constant and not a walk per
	// candidate. Were the character a body admitted, a run dense in prefixes
	// would be walked once for every candidate in it and the scan would cost
	// time quadratic in the length of such a line.
	if len(klaviyoPrivateAPIKeyPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so there is no candidate to reason about")
	}
	for _, p := range klaviyoPrivateAPIKeyPrefixes {
		if c := p[len(p)-1]; isBase62Byte(c) {
			t.Errorf("the prefix %q closes with %q, which a body may be written with, so a run has no bound on how many candidates read it", p, c)
		}
	}
	// The segment is the run behind the prefix, and the character closing it is
	// read off that run's end. A character the alphabet admitted could not close
	// a run, so the scoped shape would have nothing to be read by.
	if isBase62Byte(klaviyoPrivateAPIKeyAnchor) {
		t.Errorf("the anchor %q belongs to the alphabet a run is read in, so no run can end at one", byte(klaviyoPrivateAPIKeyAnchor))
	}
}

func Test_KlaviyoPrivateAPIKey_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a line dense in prefixes
	// holds a candidate for every three characters it has. The one thing a
	// candidate reads that is a walk over the rest of the input rather than a
	// bounded test is where its run ends, and repeating that walk at every
	// candidate would cost time quadratic in the length of the line. The bound
	// here is far above a linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every thirty-seven bytes where they are densest, because a
	// sample has to carry a whole body to be one. The crowding a line can
	// actually carry, a candidate every three bytes, stays here.
	sources := map[string]string{
		// Candidates as close together as a prefix allows, none of them with a
		// run long enough to be a body: every one reaches the body of the loop
		// and every one is rejected.
		"a candidate every three characters": strings.Repeat("pk_", 500000),
		// Keys written into one another, each beginning two characters before
		// the one in front of it ends, so every candidate is a key and every one
		// of them walks a run.
		"a key beginning inside every key": strings.Repeat("pk_0123456789abcdefghijklmnopqrstuvwx", 50000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a key.
		"a body that runs the length of the line": "pk_" + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("a_", 900000),
		// Candidates that reach the segment and are declined behind it, which
		// is the longest a rejected candidate can walk.
		"a scoped candidate every ten characters": strings.Repeat("pk_012345_", 180000),
		// The worst case the bound on how many candidates read one run states:
		// a segment closing with the two characters a prefix opens with, so
		// every run is read twice and by no more than twice.
		"a run read by two candidates": strings.Repeat("pk_0123pk_0123456789abcdefghijklmnopqrstuvwx", 40000),
		// The same pair of readers over one run of the length of the input,
		// which is where a third reader would show as time rather than as a
		// constant.
		"one run the length of the line read by two candidates": "pk_0123pk_" + strings.Repeat("a", 1800000),
		// A run of segments with no prefix in front of any of them, which is
		// the anchor found at every seventh byte and declined by one comparison.
		"a segment every seven characters": strings.Repeat("012345_", 250000),
		// And the prefix's own letters with no anchor among them, which is the
		// walk reading a whole line and stopping nowhere in it.
		"the letters of the prefix with no anchor": strings.Repeat("pk", 900000),
	}

	checkScanIsLinear(t, KlaviyoPrivateAPIKey(), sources)
}

// referenceKlaviyoPrivateAPIKey is the expression the scan in
// builtin_klaviyo_private_api_key.go reads by hand: the statement of what a
// Klaviyo private API key is, kept here so that the scan can be held to it.
//
// The prefix, the segment, the separator behind it, the floor and the alphabet
// are spelled again rather than built from klaviyoPrivateAPIKeyPrefix,
// klaviyoPrivateAPIKeySegmentChars, klaviyoPrivateAPIKeyAnchor,
// klaviyoPrivateAPIKeyBodyChars and isBase62Byte. A reference sharing those
// declarations could not disagree with the scan about them, and it is exactly
// that disagreement the fuzz target below is for: the two have to be changed
// together or reported apart.
//
// The segment is written as an optional group in front of the body, which is the
// scan's two shapes as one grammar. An engine tries the group before it tries
// skipping it, and the two cannot both hold at a candidate — a run reaching the
// floor writes the alphabet where the group asks for the underscore — so which
// one an engine reaches first cannot change what is located.
//
// The floor is written as a counted repetition, which costs an engine a machine
// as wide as the floor at every candidate. It costs nothing here, and for the
// reason the scan needs no cursor: no body admits the character a candidate is
// found by, so candidates cannot crowd inside one run. The prefix is a literal
// in front of the grammar besides, which is what an engine searches the text
// for.
var referenceKlaviyoPrivateAPIKey = regexp.MustCompile(`pk_(?:[0-9A-Za-z]{6}_)?[0-9A-Za-z]{34,}`)

// referenceKlaviyoPrivateAPIKeyFind locates keys the plain way: the leftmost
// match of the expression above, then the leftmost one beginning after that
// match's first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a key can begin inside one: both characters in
// front of the prefix's underscore are written in the alphabet a body is, so a
// body closing with them holds the start of the key behind it. The scan finds
// both and reports the two spans overlapping for a Masker to resolve, so the
// reference must ask about both.
func referenceKlaviyoPrivateAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceKlaviyoPrivateAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzKlaviyoPrivateAPIKey_matchesReference guards the hand-written scan: the
// prefix it searches back from, the segment it reads between that prefix and a
// body, the floor it holds a body to, the alphabet it reads both in and the byte
// it resumes at may none of them change which keys are located.
func FuzzKlaviyoPrivateAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("KLAVIYO_API_KEY=pk_0123456789abcdefghijklmnopqrstuvwx")
	f.Add("pk_012345_0123456789abcdefghijklmnopqrstuvwx")
	f.Add("pk_ABCDEF_0123456789abcdefghijklmnopqrstuvwx")
	f.Add("pk_0123456789ABCDEFGHIJKLMNOPQRSTUVWX")
	f.Add("pk_0123456789abcdefghijklmnopqrstuvw")     // one short of a body
	f.Add("pk_0123456789abcdefghijklmnopqrstuvwxy")   // and a run longer than one
	f.Add("pk_0123456789abcdef-ghijklmnopqrstuvwxyz") // a hyphen, which base64url admits and base62 does not
	f.Add("pk_0123456789abcdef_ghijklmnopqrstuvwxyz") // an underscore, likewise
	f.Add("pk_0123456789abcdef.ghijklmnopqrstuvwxyz") // a dot ends the body
	f.Add("PK_0123456789abcdefghijklmnopqrstuvwx")    // an uppercase prefix
	f.Add("pk-0123456789abcdefghijklmnopqrstuvwx")    // a hyphen where the prefix carries an underscore
	// Segments of every width around the one that is read, one closed by a
	// character that is no underscore, and one carrying a character the
	// alphabet leaves out.
	f.Add("pk_01234_0123456789abcdefghijklmnopqrstuvwx")
	f.Add("pk_0123456_0123456789abcdefghijklmnopqrstuvwx")
	f.Add("pk_012345-0123456789abcdefghijklmnopqrstuvwx")
	f.Add("pk__0123456789abcdefghijklmnopqrstuvwx0")
	f.Add("pk_012-45_0123456789abcdefghijklmnopqrstuvwx")
	f.Add("pk_0123456789abcdefghijklmnopqrstuvwx-suffix")
	f.Add("pk_0123456789abcdefghijklmnopqrstuvwx_suffix")
	f.Add("pk_0123456789abcdefghijklmnopqrstuvwx\npk_012345_0123456789abcdefghijklmnopqrstuvwx")
	// A key beginning inside the match before it, which a scan resuming past a
	// match steps over: inside a body, and inside a segment, where the
	// underscore that closes the segment is the next key's own.
	f.Add("pk_0123456789abcdefghijklmnopqrstuvwxpk_0123456789abcdefghijklmnopqrstuvwx")
	f.Add("pk_0123pk_0123456789abcdefghijklmnopqrstuvwx")
	f.Add("pk_012pk_0123456789abcdefghijklmnopqrstuvwx")
	f.Add("pk_0123456789abcdefghijklmnopqrstuvwxpk_012345_0123456789abcdefghijklmnopqrstuvwx")
	// Candidate positions crowded as close as they can be, with no run long
	// enough for any of them, and segments crowded the same way.
	f.Add(strings.Repeat("pk_", 16))
	f.Add(strings.Repeat("pk_012345_", 16))
	f.Add(strings.Repeat("pk_0123pk_0123456789abcdefghijklmnopqrstuvwx", 4))
	f.Add(strings.Repeat("pk_0123456789abcdefghijklmnopqrstuvwx", 4))
	// A digest written behind the prefix, which is a key's format exactly, and
	// one two characters short of a body.
	f.Add("pk_0123456789abcdef0123456789abcdef01234567")
	f.Add("key: pk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("pk_0123456789abcdef0123456789abcdef")
	// The prefix written inside a run of base64url, which is the over-match the
	// pattern admits.
	f.Add("payload=zzzzpk_0123456789abcdefghijklmnopqrstuvwxzzzz")
	// The Stripe publishable keys, which write the same prefix and are located
	// by a pattern of their own.
	f.Add("pk_live_0123456789abcdef01234567")
	f.Add("pk_test_0123456789abcdef01234567")
	f.Add("pk_live_0123456789abcdefghijklmnopqrstuvwx")
	// Candidates the end of the input cuts short in each of the places it can,
	// and one the text closed at the segment's width.
	f.Add("xxx pk")
	f.Add("xxx pk_012345")
	f.Add("xxx pk_012345_0123456789abcdef")
	f.Add("xxx pk_012345.")

	fuzzAgainstReference(f, KlaviyoPrivateAPIKey().Find, referenceKlaviyoPrivateAPIKeyFind)
}

// klaviyoPrivateAPIKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func klaviyoPrivateAPIKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens a prefix, so what the line times is the
	// search for the underscore — which is most of what this pattern costs a
	// caller whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="upserting profile" url=https://a.klaviyo.com/api/profiles revision=2026-04-15 `
	key := "pk_0123456789abcdefghijklmnopqrstuvwx"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every three characters with no run long enough behind
			// any of them: each reaches the body of the loop and none becomes a
			// key. What it times is the walk over a run being started and
			// stopped, once per candidate and no more.
			name:  "candidates that are not values",
			src:   strings.Repeat("pk_", 128),
			spans: 0,
		},
		{
			// Candidates that reach the segment and are declined behind it,
			// which is the longest a rejected candidate can walk.
			name:  "candidates declined behind their segment",
			src:   strings.Repeat("pk_012345_", 128),
			spans: 0,
		},
		{
			// Keys written into one another, each beginning two characters
			// before the one in front of it ends. This is what the scan gets
			// away with keeping no cursor for: the runs the candidates read
			// follow one another rather than overlapping. The two characters at
			// the end are what closes the body of the last of them, which
			// otherwise has only the run it was written with.
			name:  "keys written into one another",
			src:   strings.Repeat("pk_0123456789abcdefghijklmnopqrstuvwx", 128) + "yz",
			spans: 128,
		},
		{
			// The one shape where a run is read twice: the segment closes with
			// the characters a prefix opens with, so the outer candidate reads
			// the body through its segment and the inner one reads it again.
			name:  "a run read by two candidates",
			src:   strings.Repeat("pk_0123pk_0123456789abcdefghijklmnopqrstuvwx", 128),
			spans: 256,
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
