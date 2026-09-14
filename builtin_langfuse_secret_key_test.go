package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Langfuse secret key pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. A body is the run 0123456789abcdef written twice
// over with the separators a UUID puts through it,
// 01234567-89ab-cdef-0123-456789abcdef, which is the thirty-six characters the
// count asks for exactly. It is written in lowercase where the case does not
// matter and in uppercase where the case is what a case is about: the
// hexadecimal is read in either.
//
// Three groups of cases carry no run. The bodies that open or close on an end of
// the alphabet write that character in place of the one the run puts there, the
// bodies in Test_LangfuseSecretKey_aBodyOutsideVersionFour write the version and
// variant characters of the UUID they are about, and the bodies in
// Test_LangfuseSecretKey_aPlaceholderUUID are one repeated digit, which is what
// makes them placeholders.

func Test_LangfuseSecretKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "sk-lf-01234567-89ab-cdef-0123-456789abcdef",
			want: []Span{{0, 42}},
		},
		{
			name: "a key in an environment assignment",
			src:  "LANGFUSE_SECRET_KEY=sk-lf-01234567-89ab-cdef-0123-456789abcdef",
			want: []Span{{20, 62}},
		},
		{
			// The hexadecimal is read in either case, so a body written in
			// capitals is a body.
			name: "a body written in capitals",
			src:  "sk-lf-01234567-89AB-CDEF-0123-456789ABCDEF",
			want: []Span{{0, 42}},
		},
		{
			// The hexadecimal has six ends — 0, 9, A, F, a and f — and a range
			// bound written one too wide at any of them admits a character no
			// key carries. A body built from the run stands on two of them and
			// no more, at its first character and at its last, so each of the
			// cases here opens a body on one end and closes it on another.
			name: "a body opening on the last lowercase letter and closing on the first digit",
			src:  "sk-lf-f1234567-89ab-cdef-0123-456789abcde0",
			want: []Span{{0, 42}},
		},
		{
			name: "a body opening on the last uppercase letter and closing on the last digit",
			src:  "sk-lf-F1234567-89ab-cdef-0123-456789abcde9",
			want: []Span{{0, 42}},
		},
		{
			name: "a body opening on the first lowercase letter and closing on the first uppercase one",
			src:  "sk-lf-a1234567-89ab-cdef-0123-456789abcdeA",
			want: []Span{{0, 42}},
		},
		{
			name: "a body opening on the last digit and closing on the first lowercase letter",
			src:  "sk-lf-91234567-89ab-cdef-0123-456789abcdea",
			want: []Span{{0, 42}},
		},
		{
			name: "a body opening on the first uppercase letter and closing on the last lowercase one",
			src:  "sk-lf-A1234567-89ab-cdef-0123-456789abcdef",
			want: []Span{{0, 42}},
		},
		{
			name: "a body opening on the first digit and closing on the last uppercase letter",
			src:  "sk-lf-01234567-89ab-cdef-0123-456789abcdeF",
			want: []Span{{0, 42}},
		},
		{
			// The count is read exactly and the layout is what a body is held
			// to, so a hexadecimal character written against a key is a
			// character after the key rather than part of it.
			name: "a run longer than the count",
			src:  "sk-lf-01234567-89ab-cdef-0123-456789abcdef0",
			want: []Span{{0, 42}},
		},
		{
			name: "two keys separated by a space",
			src:  "sk-lf-01234567-89ab-cdef-0123-456789abcdef sk-lf-01234567-89ab-cdef-0123-456789abcdef",
			want: []Span{{0, 42}, {43, 85}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := LangfuseSecretKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LangfuseSecretKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "sk-lf-",
		},
		{
			// Thirty-five characters where the layout asks for thirty-six. This
			// is the shape a line cut to a column limit leaves, and the
			// characters in front of the cut stay in the text.
			name: "a body one character too short",
			src:  "sk-lf-01234567-89ab-cdef-0123-456789abcde",
		},
		{
			// The walk reads the groups from a table and the reference spells
			// each of them out again, so a group the tables never write a wrong
			// character into is one the two could come to disagree about with
			// nothing here reporting it. The cases below this pair reach the
			// first group, the third and the fifth; these are the other two.
			name: "a non-hexadecimal character in the second group",
			src:  "sk-lf-01234567-89gb-cdef-0123-456789abcdef",
		},
		{
			name: "a non-hexadecimal character in the fourth group",
			src:  "sk-lf-01234567-89ab-cdef-01g3-456789abcdef",
		},
		{
			// The bytes just outside the alphabet's six ends, which is where a
			// range bound written one too wide would show. Each stands in a body
			// of the right length and layout, so a body admitting it would be
			// located and the case would fail rather than merely stop stating
			// anything. They are written in the middle of a body here and at
			// either end of one below, since each group of the reference spells
			// the class again and a bound is free to be wrong in one of them
			// alone.
			name: "the byte before the first digit in the body",
			src:  "sk-lf-01234567-89ab-c/ef-0123-456789abcdef",
		},
		{
			name: "the byte past the last digit in the body",
			src:  "sk-lf-01234567-89ab-c:ef-0123-456789abcdef",
		},
		{
			name: "the byte before the first uppercase letter in the body",
			src:  "sk-lf-01234567-89ab-c@ef-0123-456789abcdef",
		},
		{
			name: "the byte past the last uppercase letter in the body",
			src:  "sk-lf-01234567-89ab-cGef-0123-456789abcdef",
		},
		{
			name: "the byte before the first lowercase letter in the body",
			src:  "sk-lf-01234567-89ab-c`ef-0123-456789abcdef",
		},
		{
			name: "the byte past the last lowercase letter in the body",
			src:  "sk-lf-01234567-89ab-cgef-0123-456789abcdef",
		},
		{
			// The same six at the first character of a body and at the last,
			// which is where a range bound written one too wide would show in
			// the first group and in the fifth. Each stands in a body of the
			// right length and layout, so a body admitting it would be located.
			name: "the byte before the first digit at the first character of the body",
			src:  "sk-lf-/1234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "the byte past the last digit at the first character of the body",
			src:  "sk-lf-:1234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "the byte before the first uppercase letter at the first character of the body",
			src:  "sk-lf-@1234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "the byte past the last uppercase letter at the first character of the body",
			src:  "sk-lf-G1234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "the byte before the first lowercase letter at the first character of the body",
			src:  "sk-lf-`1234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "the byte past the last lowercase letter at the first character of the body",
			src:  "sk-lf-g1234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "the byte before the first digit at the last character of the body",
			src:  "sk-lf-01234567-89ab-cdef-0123-456789abcde/",
		},
		{
			name: "the byte past the last digit at the last character of the body",
			src:  "sk-lf-01234567-89ab-cdef-0123-456789abcde:",
		},
		{
			name: "the byte before the first uppercase letter at the last character of the body",
			src:  "sk-lf-01234567-89ab-cdef-0123-456789abcde@",
		},
		{
			name: "the byte past the last uppercase letter at the last character of the body",
			src:  "sk-lf-01234567-89ab-cdef-0123-456789abcdeG",
		},
		{
			name: "the byte before the first lowercase letter at the last character of the body",
			src:  "sk-lf-01234567-89ab-cdef-0123-456789abcde`",
		},
		{
			name: "the byte past the last lowercase letter at the last character of the body",
			src:  "sk-lf-01234567-89ab-cdef-0123-456789abcdeg",
		},
		{
			// The separators are the whole of what tells a body from
			// thirty-six other characters written behind the prefix, so one
			// standing anywhere but where a UUID puts it ends the walk.
			name: "a separator one character in front of where a uuid puts it",
			src:  "sk-lf-0123456-789ab-cdef-0123-456789abcdef",
		},
		{
			name: "a separator one character past where a uuid puts it",
			src:  "sk-lf-012345678-9ab-cdef-0123-456789abcdef",
		},
		{
			name: "a hexadecimal digit where the first separator stands",
			src:  "sk-lf-01234567089ab-cdef-0123-456789abcdef",
		},
		{
			name: "a hexadecimal digit where the last separator stands",
			src:  "sk-lf-01234567-89ab-cdef-01230456789abcdef",
		},
		{
			// The two separators the cases above do not reach, for the reason
			// the groups above give: each of the four is spelled again in the
			// reference.
			name: "a hexadecimal digit where the second separator stands",
			src:  "sk-lf-01234567-89ab0cdef-0123-456789abcdef",
		},
		{
			name: "a hexadecimal digit where the third separator stands",
			src:  "sk-lf-01234567-89ab-cdef00123-456789abcdef",
		},
		{
			name: "an underscore where a separator stands",
			src:  "sk-lf-01234567_89ab-cdef-0123-456789abcdef",
		},
		{
			name: "an uppercase prefix",
			src:  "SK-LF-01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "underscores where the prefix carries hyphens",
			src:  "sk_lf_01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "one character of the prefix",
			src:  "sk-lg-01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			// The prefix is the whole of the anchor, so a UUID of the right
			// shape is not a key without it. It is also what a request id, a
			// trace id and a correlation id are written as, which is why a
			// pattern here may not be anchored on one.
			name: "a uuid with no prefix",
			src:  "01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "a space in the body",
			src:  "sk-lf-01234567-89ab cdef-0123-456789abcdef",
		},
		{
			name: "a body broken by a line break",
			src:  "sk-lf-01234567-89ab-cdef\n0123-456789abcdef",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := LangfuseSecretKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_LangfuseSecretKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "LANGFUSE_SECRET_KEY=sk-lf-01234567-89ab-cdef-0123-456789abcdef",
			want: "LANGFUSE_SECRET_KEY=******************************************",
		},
		{
			// The SDKs take the pair as constructor arguments, which is where a
			// secret key is written straight beside the public key Langfuse
			// publishes by design.
			name: "the pair in a constructor",
			src:  `Langfuse(public_key="pk-lf-01234567-89ab-cdef-0123-456789abcdef", secret_key="sk-lf-01234567-89ab-cdef-0123-456789abcdef")`,
			want: `Langfuse(public_key="pk-lf-01234567-89ab-cdef-0123-456789abcdef", secret_key="******************************************")`,
		},
		{
			name: "a command line",
			src:  `curl -u pk-lf-01234567-89ab-cdef-0123-456789abcdef:sk-lf-01234567-89ab-cdef-0123-456789abcdef https://cloud.langfuse.com/api/public/projects`,
			want: `curl -u pk-lf-01234567-89ab-cdef-0123-456789abcdef:****************************************** https://cloud.langfuse.com/api/public/projects`,
		},
		{
			name: "a key in json",
			src:  `{"secretKey":"sk-lf-01234567-89ab-cdef-0123-456789abcdef"}`,
			want: `{"secretKey":"******************************************"}`,
		},
		{
			name: "a key in a container environment",
			src:  "docker run -e LANGFUSE_SECRET_KEY=sk-lf-01234567-89ab-cdef-0123-456789abcdef app",
			want: "docker run -e LANGFUSE_SECRET_KEY=****************************************** app",
		},
		{
			name: "twice",
			src:  "sk-lf-01234567-89ab-cdef-0123-456789abcdef sk-lf-01234567-89ab-cdef-0123-456789abcdef",
			want: "****************************************** ******************************************",
		},
	}

	m := New(WithPatterns(LangfuseSecretKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LangfuseSecretKey_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the key through whole. Both rulesets reading this
	// format ask for one, so each of these is a key they leave in the text.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xsk-lf-01234567-89ab-cdef-0123-456789abcdef",
			want: "x******************************************",
		},
		{
			name: "underscore before",
			src:  "LANGFUSE_SECRET_KEY_sk-lf-01234567-89ab-cdef-0123-456789abcdef",
			want: "LANGFUSE_SECRET_KEY_******************************************",
		},
		{
			// The count is exact, so a hexadecimal character written straight
			// against a key is left in the text rather than redacted with it —
			// which is the other half of asking for no boundary behind a match.
			name: "a hexadecimal character after",
			src:  "sk-lf-01234567-89ab-cdef-0123-456789abcdefa",
			want: "******************************************a",
		},
		{
			// A multi-byte rune is no word character, but it is worth pinning
			// beside the two above: nothing about a boundary is asked of it
			// either, in front or behind.
			name: "a multi-byte rune before and after",
			src:  "日本語sk-lf-01234567-89ab-cdef-0123-456789abcdef日本語",
			want: "日本語******************************************日本語",
		},
		{
			name: "an invalid utf-8 byte before",
			src:  "\xffsk-lf-01234567-89ab-cdef-0123-456789abcdef",
			want: "\xff******************************************",
		},
	}

	m := New(WithPatterns(LangfuseSecretKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LangfuseSecretKey_aBodyOutsideVersionFour(t *testing.T) {
	// The tightening builtin_langfuse_secret_key.go declines, pinned so that
	// taking it is a change somebody argues for. Langfuse mints a key from a
	// version 4 UUID, which writes a 4 at the first character of the third group
	// and one of 8, 9, a and b at the first of the fourth; a scan reading those
	// two characters would locate the first of these keys and neither of the
	// others.
	//
	// The bodies here write the version and the variant they are about and carry
	// the run elsewhere.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a version 4 uuid, which is what langfuse mints today",
			src:  "sk-lf-01234567-89ab-4def-8123-456789abcdef",
		},
		{
			name: "a version 7 uuid",
			src:  "sk-lf-01234567-89ab-7def-9123-456789abcdef",
		},
		{
			// The version character version 4 asks for with a variant character
			// it does not, which is what separates the two halves of the
			// tightening: a scan reading the version alone would locate this and
			// a scan reading both would not.
			name: "a version 4 uuid whose variant is outside the four version 4 writes",
			src:  "sk-lf-01234567-89ab-4def-c123-456789abcdef",
		},
		{
			name: "a uuid of no version at all",
			src:  "sk-lf-01234567-89ab-cdef-0123-456789abcdef",
		},
	}

	m := New(WithPatterns(LangfuseSecretKey()))
	want := strings.Repeat("*", 42)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, want)
			}
		})
	}
}

func Test_LangfuseSecretKey_aPlaceholderUUID(t *testing.T) {
	// What this pattern over-matches on, held to being redacted rather than
	// spared. A page of documentation writing the prefix and a UUID of one
	// repeated digit is a key's format character for character, and nothing is
	// left in the text to tell the two apart.
	//
	// betterleaks declines such a value with a minimum-entropy filter, where
	// trufflehog locates it. That filter is what this library may not have:
	// entropy is a property of the characters rather than of who issued them, so
	// declining a UUID of zeroes declines the key Langfuse happened to mint with
	// a long run of one digit in it.
	//
	// These bodies are one repeated character, which no ordered run can state.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a uuid of zeroes",
			src:  "LANGFUSE_SECRET_KEY=sk-lf-00000000-0000-0000-0000-000000000000",
			want: "LANGFUSE_SECRET_KEY=******************************************",
		},
		{
			name: "a uuid of ones",
			src:  "LANGFUSE_SECRET_KEY=sk-lf-11111111-1111-1111-1111-111111111111",
			want: "LANGFUSE_SECRET_KEY=******************************************",
		},
	}

	m := New(WithPatterns(LangfuseSecretKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LangfuseSecretKey_thePublicKeyBesideIt(t *testing.T) {
	// The other half of the pair, held to being left alone. Langfuse publishes
	// the public key by design — its browser SDK takes that key and nothing
	// else, and its docs write it into a name Next.js compiles into what the
	// browser downloads — so redacting it would take an identifier out of a log
	// that says which project the line belongs to.
	//
	// Every one of these reaches the body of the scan's loop, because a public
	// key carries the k the scan searches for at the index it reads a candidate
	// back from. What turns them away is the single byte in front of that k, so
	// these cases are what holds the one comparison the pair is told apart by.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a public key on its own",
			src:  "pk-lf-01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "a public key in an environment assignment",
			src:  "LANGFUSE_PUBLIC_KEY=pk-lf-01234567-89ab-cdef-0123-456789abcdef",
		},
		{
			name: "a public key written against a word character",
			src:  "xpk-lf-01234567-89ab-cdef-0123-456789abcdef",
		},
	}

	m := New(WithPatterns(LangfuseSecretKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_LangfuseSecretKey_holdsAKeyTheInputCutShort(t *testing.T) {
	// What Find's second return settles. builtin_scan.go and the rationale in
	// builtin_langfuse_secret_key.go give two shapes: a piece of the prefix
	// standing at the end of the input, and a candidate the end of the input cut
	// short. Everything else is settled to the end of the input: the count is
	// exact and no boundary is asked behind a match, so a candidate that fits
	// inside the input is decided by the text and nothing arriving later can
	// change it.
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
			// The last three characters of the input are a piece of the prefix,
			// so what comes next could still complete it: the text from there
			// on is held.
			name:   "a piece of the prefix at the end of the input",
			src:    "xxx sk-",
			retain: 4,
		},
		{
			// A candidate whose body the end of the input cut short. What comes
			// next may carry it to thirty-six characters of the right layout,
			// so the candidate's start is held rather than settled.
			name:   "a candidate the input cut short",
			src:    "xxx sk-lf-01234567-89ab",
			retain: 4,
		},
		{
			// The same candidate one character short of the count, which is the
			// last offset the end of the input can still decide.
			name:   "a candidate one character short of the count",
			src:    "xxx sk-lf-01234567-89ab-cdef-0123-456789abcde",
			retain: 4,
		},
		{
			// A whole key, with nothing behind it that could widen the span.
			// The count is exact, so the key is reported and the input is
			// settled to the end.
			name:   "a whole key at the end of the input",
			src:    "xxx sk-lf-01234567-89ab-cdef-0123-456789abcdef",
			retain: len("xxx sk-lf-01234567-89ab-cdef-0123-456789abcdef"),
		},
		{
			// A candidate rejected by the text rather than by the end of it: a
			// separator stands where the layout asks for hexadecimal, so
			// nothing arriving behind it could make a key of this and the whole
			// input is settled.
			name:   "a candidate the text turned away",
			src:    "xxx sk-lf-0123456-789ab-cdef-0123-456789abcdef",
			retain: len("xxx sk-lf-0123456-789ab-cdef-0123-456789abcdef"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, retain := LangfuseSecretKey().Find(tt.src); retain != tt.retain {
				t.Errorf("Find(%q) retain = %d, want %d", tt.src, retain, tt.retain)
			}
		})
	}
}

func Test_langfuseSecretKeyPrefix_holdsWhatNoBodyDoes(t *testing.T) {
	// The scan resumes one byte past the start of a candidate, and what it can
	// find there is bounded by the prefix carrying a character no body does.
	// Were every character of the prefix one a body carries, a whole prefix
	// could stand inside a body and a key could begin inside another, which the
	// rationale says cannot happen. Nothing else here reports that sentence
	// going wrong.
	//
	// What a body carries is both things: the hexadecimal of its groups and the
	// separator between each pair of them. Asking about the hexadecimal alone
	// would let the separator answer this, and the separator is the one
	// character the prefix has that a body writes four of.
	//
	// The characters are counted rather than merely looked for, because the
	// rationale names them — the s, the k and the l — and a sentence naming
	// three is one an existence check lets drift to one.
	if langfuseSecretKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	outside := 0
	for i := range len(langfuseSecretKeyPrefix) {
		c := langfuseSecretKeyPrefix[i]
		if !isLangfuseSecretKeyByte(c) && c != langfuseSecretKeySeparator {
			outside++
		}
	}
	if outside != 3 {
		t.Errorf("%d characters of the prefix %q are ones no body carries, where the rationale names three of them", outside, langfuseSecretKeyPrefix)
	}
}

// Test_langfuseSecretKeyAnchor holds the prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_langfuseSecretKeyAnchor(t *testing.T) {
	if len(langfuseSecretKeyPrefix) <= langfuseSecretKeyAnchorIndex {
		t.Fatalf("the prefix %q is %d characters where the scan reads its anchor at %d", langfuseSecretKeyPrefix, len(langfuseSecretKeyPrefix), langfuseSecretKeyAnchorIndex)
	}
	if c := langfuseSecretKeyPrefix[langfuseSecretKeyAnchorIndex]; c != langfuseSecretKeyAnchor {
		t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", langfuseSecretKeyPrefix, c, byte(langfuseSecretKeyAnchor))
	}
	// The search never stopping inside a body is what the rationale rests the
	// cost of a line dense in UUIDs on, and a body is the hexadecimal of its
	// groups and the separator between each pair of them alike.
	if isLangfuseSecretKeyByte(langfuseSecretKeyAnchor) || langfuseSecretKeyAnchor == langfuseSecretKeySeparator {
		t.Errorf("the anchor %q is a character a body carries, so the search stops inside every body it walks past", byte(langfuseSecretKeyAnchor))
	}
}

// Test_langfuseSecretKeyBodyChars holds the groups the walk reads to the count
// the scan cuts a candidate by. The two are written apart, so a group widened
// without the count moving would leave the walk reading past what it was handed
// or stopping short of it.
func Test_langfuseSecretKeyBodyChars(t *testing.T) {
	chars := len(langfuseSecretKeyGroups) - 1
	for _, width := range langfuseSecretKeyGroups {
		chars += width
	}
	if chars != langfuseSecretKeyBodyChars {
		t.Errorf("the groups and their separators come to %d characters where the scan cuts a candidate at %d", chars, langfuseSecretKeyBodyChars)
	}
}

func Test_isLangfuseSecretKeyBody(t *testing.T) {
	// The count the helper is handed the characters with. The scan cuts a
	// candidate at that count and so can never hand it anything else, which
	// leaves the guard unreachable through Find and its reason unread: the
	// length and the layout are checked in one place rather than the length
	// left to a caller to have cut correctly. This is where that is driven.
	tests := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "the count exactly",
			src:  "01234567-89ab-cdef-0123-456789abcdef",
			want: true,
		},
		{
			name: "one character short of the count",
			src:  "01234567-89ab-cdef-0123-456789abcde",
			want: false,
		},
		{
			name: "one character past the count",
			src:  "01234567-89ab-cdef-0123-456789abcdef0",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLangfuseSecretKeyBody(tt.src); got != tt.want {
				t.Errorf("isLangfuseSecretKeyBody(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_LangfuseSecretKey_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a line dense in prefixes
	// holds a candidate for every character it has. What keeps that linear is
	// the count being a count: a candidate reads at most thirty-six bytes and
	// stops, whatever stands behind it. The bound here is far above a linear
	// scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every forty-two bytes where they are densest, because a sample
	// has to carry a whole key to be one. The crowding a line can actually
	// carry stays here.
	sources := map[string]string{
		// Candidates as close together as a whole prefix allows, none of them
		// with a body behind it: every one reaches the walk over the layout and
		// every one is rejected at its first character.
		"a candidate every six characters": strings.Repeat("sk-lf-", 300000),
		// Keys written one against the next, so every candidate is a key and
		// every one of them walks a whole body.
		"a key against every key": strings.Repeat("sk-lf-01234567-89ab-cdef-0123-456789abcdef", 40000),
		// An anchor at every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("ak", 900000),
		// The same crowding with the byte a prefix opens with in front of every
		// anchor, so each of them is declined by the comparison of the prefix
		// rather than by the byte before it.
		"an anchor behind the byte a prefix opens with": strings.Repeat("sk", 900000),
		// One key and then a run of hexadecimal the length of the line, which is
		// the search reading the whole input and stopping nowhere in it — the
		// shape the anchor being no hexadecimal digit is chosen for.
		"a hexadecimal run the length of the line": "sk-lf-01234567-89ab-cdef-0123-456789abcdef" + strings.Repeat("0123456789abcdef", 110000),
		// UUIDs written one after another with no prefix among them, which is a
		// line dense in the layout this scan reads and holding no anchor at all.
		"a uuid every thirty-seven characters": strings.Repeat("01234567-89ab-cdef-0123-456789abcdef ", 48000),
		// And the prefix's own characters with the anchor taken out, which is the
		// walk reading a whole line and stopping nowhere in it.
		"the prefix with its anchor taken out": strings.Repeat("s-lf-", 360000),
	}

	checkScanIsLinear(t, LangfuseSecretKey(), sources)
}

// referenceLangfuseSecretKey is the expression the scan in
// builtin_langfuse_secret_key.go reads by hand: the statement of what a Langfuse
// secret key is, kept here so that the scan can be held to it.
//
// The prefix, the five groups, the separators between them and the character
// class are spelled again rather than built from langfuseSecretKeyPrefix,
// langfuseSecretKeyGroups, langfuseSecretKeySeparator and
// isLangfuseSecretKeyByte. A reference sharing those declarations could not
// disagree with the scan about them, and it is exactly that disagreement the
// fuzz target below is for: the two have to be changed together or reported
// apart.
//
// Every repetition is exact, so the machine an engine builds is read once and
// stops rather than being as wide as a floor at every candidate. The prefix is a
// six-character literal in front of the grammar besides, and no body can spell
// it, so an engine searching the text for that literal finds it nowhere in a run
// of hexadecimal.
var referenceLangfuseSecretKey = regexp.MustCompile(`sk-lf-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}`)

// referenceLangfuseSecretKeyFind locates keys the plain way: the leftmost match
// of the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this. It resumes past a
// match, and the scan it checks resumes one byte along — so a reference written
// that way would agree with the scan only while no key can begin inside
// another, which is a thing the scan claims and a reference may take nothing
// on trust.
func referenceLangfuseSecretKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceLangfuseSecretKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzLangfuseSecretKey_matchesReference guards the hand-written scan: the
// prefix it searches back from, the groups and separators it walks a body by,
// the count it cuts a candidate at, the alphabet it reads the groups in and the
// byte it resumes at may none of them change which keys are located.
func FuzzLangfuseSecretKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("LANGFUSE_SECRET_KEY=sk-lf-01234567-89ab-cdef-0123-456789abcdef")
	f.Add("sk-lf-01234567-89AB-CDEF-0123-456789ABCDEF")
	f.Add("sk-lf-01234567-89ab-cdef-0123-456789abcde")   // one character short of the count
	f.Add("sk-lf-01234567-89ab-cdef-0123-456789abcdef0") // and a run longer than it
	f.Add("sk-lf-g1234567-89ab-cdef-0123-456789abcdef")  // a character the alphabet leaves out, at each end of a body and inside one
	f.Add("sk-lf-01234567-89ab-cdef-0123-456789abcdeg")
	f.Add("sk-lf-01234567-89ab-cgef-0123-456789abcdef")
	f.Add("sk-lf-01234567_89ab-cdef-0123-456789abcdef") // an underscore where a separator stands
	f.Add("SK-LF-01234567-89ab-cdef-0123-456789abcdef") // an uppercase prefix
	f.Add("sk_lf_01234567-89ab-cdef-0123-456789abcdef") // underscores where the prefix carries hyphens
	// Separators standing anywhere but where a UUID puts them, and hexadecimal
	// standing where one belongs.
	f.Add("sk-lf-0123456-789ab-cdef-0123-456789abcdef")
	f.Add("sk-lf-012345678-9ab-cdef-0123-456789abcdef")
	f.Add("sk-lf-01234567089ab-cdef-0123-456789abcdef")
	f.Add("sk-lf-01234567-89ab-cdef-01230456789abcdef")
	f.Add("sk-lf-01234567-89ab0cdef-0123-456789abcdef")
	f.Add("sk-lf-01234567-89ab-cdef00123-456789abcdef")
	// The groups the tables reach at no other character, which the reference
	// spells out one by one.
	f.Add("sk-lf-01234567-89gb-cdef-0123-456789abcdef")
	f.Add("sk-lf-01234567-89ab-cdef-01g3-456789abcdef")
	// A body outside version 4, which this pattern reads and a scan tightened on
	// the version and variant characters would not, each half of that
	// tightening failing on its own.
	f.Add("sk-lf-01234567-89ab-4def-8123-456789abcdef")
	f.Add("sk-lf-01234567-89ab-7def-9123-456789abcdef")
	f.Add("sk-lf-01234567-89ab-4def-c123-456789abcdef")
	// The placeholder a page of documentation writes, which both rulesets
	// reading this format decline and this pattern redacts.
	f.Add("LANGFUSE_SECRET_KEY=sk-lf-00000000-0000-0000-0000-000000000000")
	// The public key, which shares everything but the first character.
	f.Add("pk-lf-01234567-89ab-cdef-0123-456789abcdef")
	f.Add(`Langfuse(public_key="pk-lf-01234567-89ab-cdef-0123-456789abcdef", secret_key="sk-lf-01234567-89ab-cdef-0123-456789abcdef")`)
	// Keys written against word characters at either end, which no boundary is
	// asked of.
	f.Add("xsk-lf-01234567-89ab-cdef-0123-456789abcdef")
	f.Add("sk-lf-01234567-89ab-cdef-0123-456789abcdefa")
	// A UUID with no prefix, and a prefix written inside a run of hexadecimal
	// where none can stand.
	f.Add("01234567-89ab-cdef-0123-456789abcdef")
	f.Add("0123456789abcdefsk-lf-01234567-89ab-cdef-0123-456789abcdef")
	// Candidate positions crowded as close as they can be, with no body behind
	// any of them, and keys written one against the next.
	f.Add(strings.Repeat("sk-lf-", 16))
	f.Add(strings.Repeat("sk", 16))
	f.Add(strings.Repeat("sk-lf-01234567-89ab-cdef-0123-456789abcdef", 4))
	f.Add("sk-lf-01234567-89ab-cdef-0123-456789abcdef\nsk-lf-01234567-89ab-cdef-0123-456789abcdef")
	// Candidates the end of the input cuts short in each of the places it can,
	// and one the text turned away.
	f.Add("xxx sk-")
	f.Add("xxx sk-lf-01234567-89ab")
	f.Add("xxx sk-lf-01234567-89ab-cdef-0123-456789abcde")
	f.Add("xxx sk-lf-0123456-789ab-cdef-0123-456789abcdef")

	fuzzAgainstReference(f, LangfuseSecretKey().Find, referenceLangfuseSecretKeyFind)
}

// langfuseSecretKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func langfuseSecretKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens a prefix, so what the line times is the
	// search for the anchor — which is most of what this pattern costs a caller
	// whose text holds no key. It is the line the rationale's count of the five
	// characters a prefix is written with is taken over.
	line := `time=2026-09-14T00:00:00Z level=info msg="flushing trace batch" url=https://cloud.langfuse.com/api/public/ingestion events=12 `
	key := "sk-lf-01234567-89ab-cdef-0123-456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A whole prefix every six characters with no body behind any of
			// them: each reaches the walk over the layout and each is rejected
			// at its first character.
			name:  "candidates that are not values",
			src:   strings.Repeat("sk-lf-", 128),
			spans: 0,
		},
		{
			// The same crowding one step earlier: an anchor at every other byte
			// behind the byte a prefix opens with, so each candidate is declined
			// by the comparison of the prefix.
			name:  "candidates declined at their prefix",
			src:   strings.Repeat("sk", 128),
			spans: 0,
		},
		{
			// A run of hexadecimal the length of the line, which is the search
			// reading the whole of it and stopping nowhere — what the anchor
			// being no hexadecimal digit buys.
			name:  "a hexadecimal run holding no anchor",
			src:   strings.Repeat("0123456789abcdef", 8),
			spans: 0,
		},
		{
			name:  "keys written one against the next",
			src:   strings.Repeat(key, 128),
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
