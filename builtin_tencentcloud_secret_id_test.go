package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Tencent Cloud SecretId pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The SecretIds written out below are built from ordered characters: valid in
// shape, obviously not real. The run opens on 0123456789abcdef and carries on
// through the alphabet, so a body of thirty-two characters runs to v and one of
// sixty-four runs the alphabet out and begins it again. Where a case turns on
// the hyphen or the underscore, the run carries one at the position the case is
// about and nowhere else.
//
// The exception is the two cases about an encoded blob — the one pinning what a
// base64url run behind the prefix reaches, and the one pinning what such a run
// written against a value costs. Those carry a JOSE header and a payload rather
// than the run, because a blob a reader would recognise is the whole of what
// they are for.

func Test_TencentCloudSecretID(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a secret id naming an account",
			src:  "AKID0123456789abcdefghijklmnopqrstuv",
			want: []Span{{0, 36}},
		},
		{
			name: "a secret id in an environment assignment",
			src:  "TENCENTCLOUD_SECRET_ID=AKID0123456789abcdefghijklmnopqrstuv",
			want: []Span{{23, 59}},
		},
		{
			name: "a temporary secret id",
			src:  "AKID0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			want: []Span{{0, 68}},
		},
		{
			// The hyphen and the underscore are what the longer body carries
			// and the shorter one does not, so a body with either in its first
			// thirty-two characters is the longer shape or nothing.
			name: "a temporary secret id with a hyphen and an underscore in its body",
			src:  "AKID0123456789abcdef-123456789abcdef_123456789abcdefghijklmnopqrstuv",
			want: []Span{{0, 68}},
		},
		{
			// The count is a count and not a floor, so what follows the
			// thirty-second character of the body is not part of the SecretId
			// and stays in the text.
			name: "an alphabet run longer than the shorter shape is a secret id and what follows it",
			src:  "AKID0123456789abcdefghijklmnopqrstuvwxyz ",
			want: []Span{{0, 36}},
		},
		{
			// The same on the longer shape: sixty-four characters of body and
			// six written after them.
			name: "an alphabet run longer than the longer shape is a secret id and what follows it",
			src:  "AKID0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwx ",
			want: []Span{{0, 68}},
		},
		{
			// Sixty-three characters of base64url behind the prefix: too few
			// for the longer shape, and the first thirty-two of them are the
			// shorter shape exactly, so that is what is located and the
			// thirty-one characters behind it stay.
			name: "a body one character short of the longer shape is the shorter shape",
			src:  "AKID0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq ",
			want: []Span{{0, 36}},
		},
		{
			// A character outside base64url at the last position of the longer
			// body, which is the position furthest from the prefix. The longer
			// reading is declined there and the shorter one, which that
			// character stands well behind, is not.
			name: "a character outside the longer alphabet at its last position leaves the shorter shape",
			src:  "AKID0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq/",
			want: []Span{{0, 36}},
		},
		{
			// Two of the shorter shape with nothing between them are the
			// longer shape at the first of them: the prefix of the second is
			// written in the first's body alphabet, so sixty-four characters
			// of that alphabet stand behind the first prefix. The two spans
			// overlap and leave nothing of either behind.
			name: "two secret ids with nothing between them",
			src:  "AKID0123456789abcdefghijklmnopqrstuvAKID0123456789abcdefghijklmnopqrstuv",
			want: []Span{{0, 68}, {36, 72}},
		},
		{
			// The same two with a character neither alphabet carries between
			// them, which is what leaves each of them its own span.
			name: "two secret ids with a character outside both alphabets between them",
			src:  "AKID0123456789abcdefghijklmnopqrstuv AKID0123456789abcdefghijklmnopqrstuv",
			want: []Span{{0, 36}, {37, 73}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := TencentCloudSecretID().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

// Test_TencentCloudSecretID_theTemporaryShapeOpensWithTheShorterOne holds the
// order the two shapes are read in, which builtin_tencentcloud_secret_id.go
// argues is load-bearing: the shorter body's alphabet is inside the longer
// one's, so a temporary SecretId carries the shorter shape at its own first
// thirty-six characters whenever neither the hyphen nor the underscore stands
// among them. A scan taking the shorter reading first would report the
// span inside the value and leave the rest of it in the text, and would settle
// the text behind such a value the end of the input cut short.
func Test_TencentCloudSecretID_theTemporaryShapeOpensWithTheShorterOne(t *testing.T) {
	// The body carries neither the hyphen nor the underscore, so its first
	// thirty-two characters are the shorter shape as well as the opening of
	// the longer one.
	const temporary = "AKID0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr"

	t.Run("the whole of it is one span", func(t *testing.T) {
		want := []Span{{0, 68}}
		if got, _ := TencentCloudSecretID().Find(temporary); !slices.Equal(got, want) {
			t.Errorf("Find(%q) = %v, want %v", temporary, got, want)
		}
	})

	t.Run("what reading the longer shape first costs", func(t *testing.T) {
		// The other side of the same decision, and the one the order is paid
		// for with. A SecretId of the shorter shape with a run of base64url
		// written straight against it is sixty-four characters of that
		// alphabet behind the prefix, so the longer reading takes the value
		// and thirty-two characters of whatever was written after it. The case
		// is here so that anyone reversing the order sees both halves of the
		// trade.
		const src = "AKID0123456789abcdefghijklmnopqrstuveyJzdWIiOiIwMTIzNDU2Nzg5YWJjZGVmIn0"

		want := []Span{{0, 68}}
		if got, _ := TencentCloudSecretID().Find(src); !slices.Equal(got, want) {
			t.Errorf("Find(%q) = %v, want %v", src, got, want)
		}
	})

	t.Run("the end of the input cutting it short holds the text from its start", func(t *testing.T) {
		// Forty characters of it: the longer shape is cut short and the
		// shorter one is whole. The span the shorter reading reports is one
		// the rest of the value would widen, so the text is held from the
		// start of the candidate rather than settled behind that span.
		cut := temporary[:40]
		want := []Span{{0, 36}}
		got, retain := TencentCloudSecretID().Find(cut)
		if !slices.Equal(got, want) {
			t.Errorf("Find(%q) = %v, want %v", cut, got, want)
		}
		if retain != 0 {
			t.Errorf("Find(%q) settled %d, want 0", cut, retain)
		}
	})
}

// Test_TencentCloudSecretID_theAlphabetsAtTheEndsOfABody drives each alphabet
// at the first and the last character of a body rather than only in the middle,
// through Find and not through the byte tests alone.
//
// What that reaches and the byte tests cannot is the cut: a scan reading a body
// from one character in, or holding the character furthest from the prefix to
// some other class, answers every case built from an ordered run that opens on
// 0 and closes on a lowercase letter. So the ends of each range stand at both
// ends of a body here, and the bytes just outside them do too.
func Test_TencentCloudSecretID_theAlphabetsAtTheEndsOfABody(t *testing.T) {
	located := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "the top of the digits at the first character of a shorter body",
			src:  "AKID9123456789abcdefghijklmnopqrstuv",
			want: []Span{{0, 36}},
		},
		{
			name: "the bottom of the uppercase letters at the first character of a shorter body",
			src:  "AKIDA123456789abcdefghijklmnopqrstuv",
			want: []Span{{0, 36}},
		},
		{
			name: "the top of the uppercase letters at the first character of a shorter body",
			src:  "AKIDZ123456789abcdefghijklmnopqrstuv",
			want: []Span{{0, 36}},
		},
		{
			name: "the bottom of the lowercase letters at the first character of a shorter body",
			src:  "AKIDa123456789abcdefghijklmnopqrstuv",
			want: []Span{{0, 36}},
		},
		{
			name: "the top of the lowercase letters at the first character of a shorter body",
			src:  "AKIDz123456789abcdefghijklmnopqrstuv",
			want: []Span{{0, 36}},
		},
		{
			name: "the bottom of the digits at the last character of a shorter body",
			src:  "AKID0123456789abcdefghijklmnopqrstu0",
			want: []Span{{0, 36}},
		},
		{
			name: "the top of the digits at the last character of a shorter body",
			src:  "AKID0123456789abcdefghijklmnopqrstu9",
			want: []Span{{0, 36}},
		},
		{
			name: "the bottom of the uppercase letters at the last character of a shorter body",
			src:  "AKID0123456789abcdefghijklmnopqrstuA",
			want: []Span{{0, 36}},
		},
		{
			name: "the top of the uppercase letters at the last character of a shorter body",
			src:  "AKID0123456789abcdefghijklmnopqrstuZ",
			want: []Span{{0, 36}},
		},
		{
			name: "the top of the lowercase letters at the last character of a shorter body",
			src:  "AKID0123456789abcdefghijklmnopqrstuz",
			want: []Span{{0, 36}},
		},
		{
			// The hyphen and the underscore are what the longer body holds
			// over the shorter one, so the ends of a longer body are where
			// they say most: a scan reading the longer body from an offset
			// answers every case that keeps them in the middle.
			name: "a hyphen at the first character of a longer body and an underscore at its last",
			src:  "AKID-123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq_",
			want: []Span{{0, 68}},
		},
		{
			name: "an underscore at the first character of a longer body and a hyphen at its last",
			src:  "AKID_123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq-",
			want: []Span{{0, 68}},
		},
	}

	for _, tt := range located {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := TencentCloudSecretID().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}

	// And the bytes just outside each range, at both ends of a body. The
	// longer body is ruled out in each of these by the count or by the same
	// byte, so what is left to decline is the shorter reading.
	declined := []struct {
		name string
		src  string
	}{
		{
			name: "a character just under the digits at the last character of a shorter body",
			src:  "AKID0123456789abcdefghijklmnopqrstu/",
		},
		{
			name: "a character just over the digits at the first character of a shorter body",
			src:  "AKID:123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "a character just under the uppercase letters at the first character of a shorter body",
			src:  "AKID@123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "a character just over the uppercase letters at the first character of a shorter body",
			src:  "AKID[123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "a character just under the lowercase letters at the first character of a shorter body",
			src:  "AKID`123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "a character just over the lowercase letters at the first character of a shorter body",
			src:  "AKID{123456789abcdefghijklmnopqrstuv",
		},
		{
			// A longer body whose first character is outside base64url, with
			// the same character ruling the shorter reading out as well.
			name: "a character outside the longer alphabet at the first character of a longer body",
			src:  "AKID/123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq_",
		},
	}

	for _, tt := range declined {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := TencentCloudSecretID().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

// Test_TencentCloudSecretID_aSecretIDBeginningInsideAnother drives what the
// scan advancing a byte past the start of a candidate is for: every character
// of the prefix is written in both body alphabets, so a whole prefix can stand
// anywhere inside a body and a SecretId written inside another is located as
// well as the one around it.
func Test_TencentCloudSecretID_aSecretIDBeginningInsideAnother(t *testing.T) {
	// The prefix written out and a whole SecretId behind it: the outer
	// candidate reads the inner prefix as the first four characters of its own
	// body, and the inner one begins four characters into that span.
	const src = "AKIDAKID0123456789abcdefghijklmnopqrstuv"

	want := []Span{{0, 36}, {4, 40}}
	if got, _ := TencentCloudSecretID().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}

	// The two spans overlap, so what a Masker makes of them is one redaction
	// leaving nothing of either behind.
	m := New(WithPatterns(TencentCloudSecretID()))
	const masked = "****************************************"
	if got := m.Mask(src); got != masked {
		t.Errorf("Mask(%q) = %q, want %q", src, got, masked)
	}
}

// Test_TencentCloudSecretID_aBase64URLRunBehindThePrefix pins what the pattern
// is widest on, so that narrowing it is a change somebody argues for. Sixty-four
// characters of base64url behind the prefix are what Tencent Cloud's own
// examples show a temporary SecretId to be, so an encoded blob written
// straight behind that prefix is one character for character: there is nothing
// left in the text to read the two apart, and a scan declining it would decline
// every such SecretId issued.
func Test_TencentCloudSecretID_aBase64URLRunBehindThePrefix(t *testing.T) {
	// A JOSE header and a payload, which is base64url as a reader meets it,
	// cut to the count and written against the prefix with nothing between.
	const src = "AKIDeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9eyJzdWIiOiIwMTIzNDU2Nzg5YWJjZGVmIn0"

	want := []Span{{0, 68}}
	if got, _ := TencentCloudSecretID().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}
}

func Test_TencentCloudSecretID_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "AKID",
		},
		{
			// Thirty-one characters where the shorter shape asks for
			// thirty-two, closed by a character neither alphabet carries so
			// that nothing is left open.
			name: "a body one character too short",
			src:  "AKID0123456789abcdefghijklmnopqrstu ",
		},
		{
			// A body of twenty-eight characters, which is the length the
			// vendor prints as the example for the SecretId field of its own
			// API reference. builtin_tencentcloud_secret_id.go reads the
			// lengths off the two peaks of what the vendor publishes and the
			// spread around them as examples written short, so a body of this
			// length is left alone — and this is that decision on the record.
			name: "a body of the length the vendor prints as its own field example",
			src:  "AKID0123456789abcdefghijklmnopqr.",
		},
		{
			// Sixty-three characters where the longer shape asks for
			// sixty-four, with a hyphen among the first thirty-two so that the
			// shorter shape is no reading of them either.
			name: "a longer body one character too short, with no shorter shape inside it",
			src:  "AKID-123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq ",
		},
		{
			name: "lowercase prefix",
			src:  "akid0123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "a prefix with the second letter lowercase",
			src:  "AkID0123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "a prefix with the last letter lowercase",
			src:  "AKId0123456789abcdefghijklmnopqrstuv",
		},
		{
			// The access key ID prefix of another vendor, which this pattern
			// admits nowhere: it differs from this one at its last character
			// alone.
			name: "a prefix differing at its last character",
			src:  "AKIA0123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "a hyphen at the first position of the shorter body",
			src:  "AKID-123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "an underscore at the first position of the shorter body",
			src:  "AKID_123456789abcdefghijklmnopqrstuv",
		},
		{
			// The last position of the body is the one furthest from the
			// prefix, and so the one a scan reading only the characters
			// closest to it would miss.
			name: "a hyphen at the last position of the shorter body",
			src:  "AKID0123456789abcdefghijklmnopqrstu-",
		},
		{
			name: "an underscore at the last position of the shorter body",
			src:  "AKID0123456789abcdefghijklmnopqrstu_",
		},
		{
			name: "a character just under the digits at the first position of the shorter body",
			src:  "AKID/123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "a character just over the digits at the last position of the shorter body",
			src:  "AKID0123456789abcdefghijklmnopqrstu:",
		},
		{
			name: "a character just under the uppercase letters at the last position of the shorter body",
			src:  "AKID0123456789abcdefghijklmnopqrstu@",
		},
		{
			name: "a character just over the uppercase letters at the last position of the shorter body",
			src:  "AKID0123456789abcdefghijklmnopqrstu[",
		},
		{
			name: "a character just under the lowercase letters at the last position of the shorter body",
			src:  "AKID0123456789abcdefghijklmnopqrstu`",
		},
		{
			name: "a character just over the lowercase letters at the last position of the shorter body",
			src:  "AKID0123456789abcdefghijklmnopqrstu{",
		},
		{
			name: "a space in the middle of the shorter body",
			src:  "AKID0123456789abcdef hijklmnopqrstuv ",
		},
		{
			// A character outside base64url at the last position of the longer
			// body, with a hyphen among the first thirty-two so that the
			// shorter shape is no reading of them.
			name: "a character outside the longer alphabet with no shorter shape inside it",
			src:  "AKID0123456789abcdef-123456789abcdef_123456789abcdefghijklmnopqrstu/",
		},
		{
			name: "thirty-two characters of the alphabet that open with no prefix",
			src:  "0123456789abcdefghijklmnopqrstuv",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "prose in capitals",
			src:  "THERE IS NO CREDENTIAL IN THIS SENTENCE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := TencentCloudSecretID().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_TencentCloudSecretID_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "TENCENTCLOUD_SECRET_ID=AKID0123456789abcdefghijklmnopqrstuv",
			want: "TENCENTCLOUD_SECRET_ID=************************************",
		},
		{
			name: "quoted",
			src:  `"AKID0123456789abcdefghijklmnopqrstuv"`,
			want: `"************************************"`,
		},
		{
			name: "json",
			src:  `{"SecretId":"AKID0123456789abcdefghijklmnopqrstuv"}`,
			want: `{"SecretId":"************************************"}`,
		},
		{
			name: "a query parameter of a signed url",
			src:  "?q-ak=AKID0123456789abcdefghijklmnopqrstuv&q-sign-time=0",
			want: "?q-ak=************************************&q-sign-time=0",
		},
		{
			name: "a temporary secret id in json",
			src:  `{"TmpSecretId":"AKID0123456789abcdef-123456789abcdef_123456789abcdefghijklmnopqrstuv"}`,
			want: `{"TmpSecretId":"********************************************************************"}`,
		},
		{
			name: "twice",
			src:  "AKID0123456789abcdefghijklmnopqrstuv AKID0123456789abcdefghijklmnopqrstuv",
			want: "************************************ ************************************",
		},
	}

	m := New(WithPatterns(TencentCloudSecretID()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TencentCloudSecretID_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the SecretId through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xAKID0123456789abcdefghijklmnopqrstuv",
			want: "x************************************",
		},
		{
			name: "underscore before",
			src:  "TENCENTCLOUD_SECRET_ID_AKID0123456789abcdefghijklmnopqrstuv",
			want: "TENCENTCLOUD_SECRET_ID_************************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this SecretId
			// rather than trim it; without one the thirty-six characters
			// Tencent Cloud issued are redacted and the four written after
			// them stay in the text.
			name: "alphabet characters after",
			src:  "AKID0123456789abcdefghijklmnopqrstuvwxyz ",
			want: "************************************wxyz ",
		},
		{
			// A multi-byte rune flush against the SecretId on both sides, with
			// no space between them.
			name: "a multi-byte rune flush against the secret id on both sides",
			src:  "日本語AKID0123456789abcdefghijklmnopqrstuv日本語",
			want: "日本語************************************日本語",
		},
	}

	m := New(WithPatterns(TencentCloudSecretID()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

// Test_TencentCloudSecretID_settlesWhatTheInputCutShort holds Find's second
// return to the offset in front of which nothing further back can still become
// a SecretId, which is either a piece of the prefix standing at the end of the
// input or a candidate the end of the input cut short. What every built-in owes
// about that offset over generated text and over the samples is driven in
// builtins_test.go and fuzz_test.go; what is written out here is which inputs of
// this pattern's own shape hold anything back, since nothing else names them.
func Test_TencentCloudSecretID_settlesWhatTheInputCutShort(t *testing.T) {
	const id = "AKID0123456789abcdefghijklmnopqrstuv"

	tests := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "a piece of the prefix",
			src:  "AKI",
			want: 0,
		},
		{
			name: "a prefix alone",
			src:  "AKID",
			want: 0,
		},
		{
			name: "a body the end of the input cut short",
			src:  "AKID0123456789abcdefghijklmnopqrstu",
			want: 0,
		},
		{
			// A whole SecretId of the shorter shape reaching the end of the
			// input is the opening of one of the longer shape, so the text is
			// held from where the candidate opened rather than settled behind
			// the span.
			name: "a whole secret id of the shorter shape reaching the end of the input",
			src:  id,
			want: 0,
		},
		{
			// The same SecretId with a character behind it that neither body
			// alphabet carries: the longer reading is closed by the text
			// rather than by the end of the input, and nothing is held back.
			name: "a whole secret id of the shorter shape closed by a character outside both alphabets",
			src:  id + strings.Repeat(" ", 32),
			want: 68,
		},
		{
			// A whole SecretId of the longer shape reaching the end of the
			// input. Nothing is read behind the count, and no character of the
			// prefix stands at the end of it, so nothing is held back.
			name: "a whole secret id of the longer shape reaching the end of the input",
			src:  "AKID0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
			want: 68,
		},
		{
			// A whole prefix at the end of the input with no body behind it:
			// the candidate it opens is cut short by the end of the input, and
			// what is held back is the whole of it rather than the prose in
			// front.
			name: "a whole prefix at the end of the input",
			src:  "nothing here yet AKID",
			want: 17,
		},
		{
			name: "prose closing on a character no prefix is written with",
			src:  "a line of prose, and nothing else at all",
			want: 40,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, got := TencentCloudSecretID().Find(tt.src); got != tt.want {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TencentCloudSecretID_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor and can keep none: every character of the
	// prefix is written in both body alphabets, so a run of either may hold a
	// prefix at any of its characters and no two candidates can be told apart
	// by where the run before them ended. What holds it linear is the counts
	// being counts — a candidate reads at most sixty-four bytes and stops —
	// and these are the inputs that would find that wrong.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// whole body apiece and so hold a candidate every thirty-six bytes at their
	// densest. The crowding a line can actually carry stays here.
	sources := map[string]string{
		// The byte the scan searches for at every position, each turned away
		// because the character in front of it opens no prefix, which is the
		// cheapest this scan declines anything.
		"the anchor at every byte": strings.Repeat("K", 2000000),
		// The anchor and the byte in front of it, so the prefix is read and
		// turned away at its third character.
		"a piece of the prefix every two characters": strings.Repeat("AK", 1000000),
		// A whole prefix every four characters, each of which reads
		// sixty-four characters of body and reports a span, since the prefix
		// is written in the body's own alphabet.
		"a prefix every four characters": strings.Repeat("AKID", 250000),
		// One candidate whose body is the whole line. The longer count stops
		// it at sixty-four characters; a scan reading the run would read two
		// mebibytes.
		"an alphabet run the length of the line": "AKID" + strings.Repeat("a", 2000000),
		// The same run with no prefix in front of it, so no candidate is found
		// in it at all.
		"an alphabet run with no prefix": strings.Repeat("a", 2000000),
	}

	checkScanIsLinear(t, TencentCloudSecretID(), sources)
}

// Test_tencentCloudSecretIDPrefix holds the prefix to being written in both
// body alphabets, which is what several sentences in
// builtin_tencentcloud_secret_id.go rest on: that a SecretId can begin anywhere
// inside another, that the scan can keep no cursor, and that the byte it
// searches for had to be chosen on the text around a SecretId rather than on
// the body.
//
// It is held rather than assumed so that those sentences are a measurement. A
// prefix carrying one character outside base62 would make all three of them
// wrong at once, and nothing else here would report it: the cases above would
// go on passing, since what they drive is a prefix that still stands where it
// is written.
func Test_tencentCloudSecretIDPrefix(t *testing.T) {
	if len(tencentCloudSecretIDPrefix) == 0 {
		t.Fatal("the prefix is empty, so every position in the input is a candidate")
	}
	for i := range len(tencentCloudSecretIDPrefix) {
		c := tencentCloudSecretIDPrefix[i]
		if !isBase62Byte(c) {
			t.Errorf("the prefix carries %q, which the shorter body is not written with", c)
		}
		if !isBase64URLByte(c) {
			t.Errorf("the prefix carries %q, which the longer body is not written with", c)
		}
	}
}

// Test_tencentCloudSecretIDAnchor holds the prefix to carrying the byte the
// scan searches the input for at the index it reads a candidate back from. A
// prefix that did not would be one no candidate is ever found at, and no case
// above would report it: the scan would simply stop locating anything.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_tencentCloudSecretIDAnchor(t *testing.T) {
	if tencentCloudSecretIDAnchorIndex >= len(tencentCloudSecretIDPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters",
			tencentCloudSecretIDAnchorIndex, len(tencentCloudSecretIDPrefix))
	}
	if c := tencentCloudSecretIDPrefix[tencentCloudSecretIDAnchorIndex]; c != tencentCloudSecretIDAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it",
			c, byte(tencentCloudSecretIDAnchor))
	}
}

func Test_isTencentCloudSecretIDBody(t *testing.T) {
	// The alphabet is stated over every byte rather than by example, and the
	// count with it: a body is the letters of both cases and the digits, and
	// exactly thirty-two of them.
	const body = "0123456789abcdefghijklmnopqrstuv"

	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9' || 'A' <= b && b <= 'Z' || 'a' <= b && b <= 'z'
		if got := isTencentCloudSecretIDBody(string(b) + body[1:]); got != want {
			t.Errorf("isTencentCloudSecretIDBody with %q at the first position = %v, want %v", b, got, want)
		}
		if got := isTencentCloudSecretIDBody(body[:len(body)-1] + string(b)); got != want {
			t.Errorf("isTencentCloudSecretIDBody with %q at the last position = %v, want %v", b, got, want)
		}
	}

	// The hyphen and the underscore are what the longer body carries and this
	// one does not, which is the whole of what separates the two alphabets.
	for _, c := range []byte{'-', '_'} {
		if isTencentCloudSecretIDBody(string(c) + body[1:]) {
			t.Errorf("isTencentCloudSecretIDBody admitted %q, which only the longer body carries", c)
		}
	}

	if !isTencentCloudSecretIDBody(body) {
		t.Errorf("isTencentCloudSecretIDBody(%q) = false, want the count exactly", body)
	}
	if isTencentCloudSecretIDBody(body[:len(body)-1]) {
		t.Error("isTencentCloudSecretIDBody admitted a body one character short of the count")
	}
	if isTencentCloudSecretIDBody(body + "w") {
		t.Error("isTencentCloudSecretIDBody admitted a body one character over the count")
	}
}

func Test_isTencentCloudSecretIDTemporaryBody(t *testing.T) {
	// The same over the longer body, whose alphabet is the whole of base64url:
	// the letters of both cases, the digits, the hyphen and the underscore.
	const body = "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr"

	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9' || 'A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' || b == '-' || b == '_'
		if got := isTencentCloudSecretIDTemporaryBody(string(b) + body[1:]); got != want {
			t.Errorf("isTencentCloudSecretIDTemporaryBody with %q at the first position = %v, want %v", b, got, want)
		}
		if got := isTencentCloudSecretIDTemporaryBody(body[:len(body)-1] + string(b)); got != want {
			t.Errorf("isTencentCloudSecretIDTemporaryBody with %q at the last position = %v, want %v", b, got, want)
		}
	}

	if !isTencentCloudSecretIDTemporaryBody(body) {
		t.Errorf("isTencentCloudSecretIDTemporaryBody(%q) = false, want the count exactly", body)
	}
	if isTencentCloudSecretIDTemporaryBody(body[:len(body)-1]) {
		t.Error("isTencentCloudSecretIDTemporaryBody admitted a body one character short of the count")
	}
	if isTencentCloudSecretIDTemporaryBody(body + "s") {
		t.Error("isTencentCloudSecretIDTemporaryBody admitted a body one character over the count")
	}
}

// referenceTencentCloudSecretID is the expression the scan in
// builtin_tencentcloud_secret_id.go reads by hand: the statement of what a
// Tencent Cloud SecretId is, kept here so that the scan can be held to it.
//
// The prefix, the counts and the character classes are spelled again rather
// than built from tencentCloudSecretIDPrefix, the two counts and the shared
// alphabet tests. A reference sharing those declarations could not disagree
// with the scan about them, and it is exactly that disagreement the fuzz target
// below is for: the two have to be changed together or reported apart.
//
// The longer shape is written first, which is what makes the alternation prefer
// it: Go's engine takes the alternative a backtracking search would have
// reached first, so the order here states the same rule the scan states by
// reading the longer body before the shorter one.
var referenceTencentCloudSecretID = regexp.MustCompile(`AKID(?:[0-9A-Za-z_-]{64}|[0-9A-Za-z]{32})`)

// referenceTencentCloudSecretIDFind locates SecretIds the plain way: the
// leftmost match of the expression above, then the leftmost one beginning after
// that match's first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a SecretId can begin inside one: every character
// of the prefix is written in both body alphabets, so a whole prefix stands
// inside a body wherever the body spells one. The scan finds both and reports
// the two spans overlapping for a Masker to resolve, so the reference must ask
// about both.
//
// Resuming a byte along costs this one nothing beyond a constant: every
// candidate reads at most sixty-four characters, here as in the scan, so
// neither has a run to walk and there is no cursor for either to be wrong
// about.
func referenceTencentCloudSecretIDFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceTencentCloudSecretID.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzTencentCloudSecretID_matchesReference guards the hand-written scan: the
// byte it searches for, the prefix it admits, the two counts it reads behind
// that prefix, the order it reads them in, the alphabets it reads them in and
// the byte it resumes at may none of them change which SecretIds are located.
func FuzzTencentCloudSecretID_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("TENCENTCLOUD_SECRET_ID=AKID0123456789abcdefghijklmnopqrstuv")
	f.Add("AKID0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
	f.Add("AKID0123456789abcdef-123456789abcdef_123456789abcdefghijklmnopqrstuv")
	f.Add("AKID0123456789abcdefghijklmnopqrstu")                                   // one short of the shorter shape
	f.Add("AKID0123456789abcdefghijklmnopqrstuvw")                                 // and a run longer than it
	f.Add("AKID0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq")   // one short of the longer shape
	f.Add("AKID0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrs") // and a run longer than it
	f.Add("AKID-123456789abcdefghijklmnopqrstuv")                                  // a character only the longer body carries
	f.Add("AKID0123456789abcdefghijklmnopqrstu-")                                  // and the same at the last position of the body
	f.Add("akid0123456789abcdefghijklmnopqrstuv")                                  // a lowercase prefix
	f.Add("AKIA0123456789abcdefghijklmnopqrstuv")                                  // a prefix differing at its last character
	f.Add("AKID0123456789abcdefghijklmnopqrstuv.")                                 // punctuation ends a SecretId
	f.Add("AKID0123456789abcdefghijklmnopqrstuv\nAKID0123456789abcdefghijklmnopqrstuv")
	// A SecretId beginning inside the match before it, which a scan resuming
	// past a match steps over, and two with nothing between them, which is the
	// same text without the overlap.
	f.Add("AKIDAKID0123456789abcdefghijklmnopqrstuv")
	f.Add("AKID0123456789abcdefghijklmnopqrstuvAKID0123456789abcdefghijklmnopqrstuv")
	// Candidate positions crowded as close as they can be: every byte in the
	// first, every fourth in the second, and a run that is a body to every
	// candidate in it.
	f.Add(strings.Repeat("K", 64))
	f.Add(strings.Repeat("AKID", 32))
	f.Add(strings.Repeat("AKID", 32) + "!")

	fuzzAgainstReference(f, TencentCloudSecretID().Find, referenceTencentCloudSecretIDFind)
}

// tencentCloudSecretIDFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func tencentCloudSecretIDFindBenchmarks() []benchmarkCase {
	// The line carries the capitals a log line has anyway — the name of the
	// call and the region — because they are what a scan searching for the
	// letter the prefix opens with would have stopped at. The K the scan does
	// search for stands in none of them, so what the line times is the walk
	// alone, and the difference between the two is what the anchor bought.
	line := `time=2026-08-17T00:00:00Z level=info msg="DescribeInstances" region=AP-NORTHEAST-1 `
	id := "AKID0123456789abcdefghijklmnopqrstuv"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The most a candidate can cost without becoming a value: the
			// longer body is read to its sixty-fourth character and turned
			// away by the dot standing there, and the shorter one is turned
			// away at its first character by the hyphen only the longer body
			// carries. This scan keeps no cursor and needs none — the counts
			// bound what a candidate reads — and this is the input that would
			// show the bound gone.
			name:  "candidates that are not values",
			src:   strings.Repeat("AKID-123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq.", 32),
			spans: 0,
		},
		{
			// The prefix written in the body's own alphabet, so a candidate
			// opens every four characters and every one of them that the end
			// of the line leaves room for becomes a value. The spans overlap
			// and a Masker resolves them into one redaction.
			name:  "values crowded in one run",
			src:   strings.Repeat("AKID", 32),
			spans: 24,
		},
		{
			name:  "one value",
			src:   line + "SecretId=" + id,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "SecretId=" + id,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"SecretId="+id+"\n", 32),
			spans: 32,
		},
	}
}
