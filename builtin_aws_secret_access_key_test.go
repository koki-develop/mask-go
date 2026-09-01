package mask

import (
	"slices"
	"strings"
	"testing"
)

// The AWS secret access key pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The values written out below are made of ordered characters: valid in shape,
// obviously not real. Where a case is about the alphabet rather than the count,
// the + and the / are written into that ordered run, since they are what
// separates this alphabet from the hexadecimal the run is otherwise read as.

// awsSecretAccessKeyTestValue is forty characters of the ordered run, which is
// a value in shape and no key anyone issued. It is written out here rather than
// repeated into every case because the cases below are about what stands in
// front of a value, and a value spelled forty times is forty chances to spell
// it wrong.
const (
	awsSecretAccessKeyTestValue      = "0123456789abcdef0123456789abcdef01234567"
	awsSecretAccessKeyTestValuePlus  = "0123456789abcdef0123456789ab+/ef01234567"
	awsSecretAccessKeyTestValueMixed = "0123456789abcdefABCDEF0123456789abcdef01"

	// The far ends of the alphabet. A value built from the ordered run alone
	// carries ten digits and six letters, so most of the alphabet stands in no
	// case at all — and a scan or a reference that stopped admitting the rest
	// would go on passing everything else written here. These two carry the
	// lowercase letters to z and the uppercase to Z between them.
	awsSecretAccessKeyTestValueLower = "0123456789abcdefghijklmnopqrstuvwxyzABCD"
	awsSecretAccessKeyTestValueUpper = "0123456789abcdefGHIJKLMNOPQRSTUVWXYZ+/01"
)

func Test_AWSSecretAccessKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an environment assignment",
			src:  "AWS_SECRET_ACCESS_KEY=" + awsSecretAccessKeyTestValue,
			want: []Span{{22, 62}},
		},
		{
			name: "a shared credentials file line",
			src:  "aws_secret_access_key = " + awsSecretAccessKeyTestValue,
			want: []Span{{24, 64}},
		},
		{
			// What an assume-role call prints, which is where a key reaches a
			// CI log without anyone writing it anywhere.
			name: "json",
			src:  `{"SecretAccessKey": "` + awsSecretAccessKeyTestValuePlus + `"}`,
			want: []Span{{21, 61}},
		},
		{
			name: "camel case with no separator between the words",
			src:  "secretAccessKey=" + awsSecretAccessKeyTestValueMixed,
			want: []Span{{16, 56}},
		},
		{
			name: "hyphens between the words, as a workflow input is written",
			src:  "aws-secret-access-key: " + awsSecretAccessKeyTestValue,
			want: []Span{{23, 63}},
		},
		{
			name: "the words written out, with a space assigning",
			src:  "Secret Access Key " + awsSecretAccessKeyTestValue,
			want: []Span{{18, 58}},
		},
		{
			// A shell line, where nothing but a space stands between the name
			// and the value.
			name: "a command line",
			src:  "aws configure set aws_secret_access_key " + awsSecretAccessKeyTestValue,
			want: []Span{{40, 80}},
		},
		{
			// A quote on the far side of the space, with no assignment
			// character anywhere.
			name: "a quoted value with nothing but a space in front of the quote",
			src:  `aws_secret_access_key "` + awsSecretAccessKeyTestValue + `"`,
			want: []Span{{23, 63}},
		},
		{
			name: "spaces on both sides of the assignment",
			src:  "aws_secret_access_key   =   " + awsSecretAccessKeyTestValue,
			want: []Span{{28, 68}},
		},
		{
			name: "tabs on both sides of the assignment",
			src:  "aws_secret_access_key\t=\t" + awsSecretAccessKeyTestValue,
			want: []Span{{24, 64}},
		},
		{
			name: "a value in single quotes",
			src:  "aws_secret_access_key='" + awsSecretAccessKeyTestValue + "'",
			want: []Span{{23, 63}},
		},
		{
			name: "a value carrying the lowercase alphabet to its end",
			src:  "aws_secret_access_key=" + awsSecretAccessKeyTestValueLower,
			want: []Span{{22, 62}},
		},
		{
			name: "a value carrying the uppercase alphabet to its end",
			src:  "aws_secret_access_key=" + awsSecretAccessKeyTestValueUpper,
			want: []Span{{22, 62}},
		},
		{
			// The count itself, from the side that is located. The case one
			// space further along is in Test_AWSSecretAccessKey_noMatch, and
			// the two are what hold the count to being the count.
			//
			// Sixteen is spelled here rather than read from
			// awsSecretAccessKeySpaceMax, and the span is written out rather
			// than worked out from it: a case built from the number it is about
			// moves with that number and reports nothing when it changes, which
			// is the one thing this case exists to catch.
			name: "as many spaces either side of the assignment as are read",
			src: "aws_secret_access_key" +
				strings.Repeat(" ", 16) + "=" +
				strings.Repeat(" ", 16) + awsSecretAccessKeyTestValue,
			want: []Span{{54, 94}},
		},
		{
			// The other side of leaving padding out of the alphabet. It ends a
			// run, so a run closed by it measures what stands in front of the
			// padding — forty here, which is a value, and the == is part of
			// none and stays in the text.
			name: "padding written behind a whole run",
			src:  "AWS_SECRET_ACCESS_KEY=" + awsSecretAccessKeyTestValue + "==",
			want: []Span{{22, 62}},
		},
		{
			// The name says where the value is, so nothing in front of the
			// name matters and there is no boundary either side of it.
			name: "a name written against a word",
			src:  "xxsecret_access_key=" + awsSecretAccessKeyTestValue,
			want: []Span{{20, 60}},
		},
		{
			name: "two values on one line",
			src:  "a=" + awsSecretAccessKeyTestValue + " SECRET_ACCESS_KEY=" + awsSecretAccessKeyTestValue + " secret_access_key=" + awsSecretAccessKeyTestValue,
			want: []Span{{61, 101}, {120, 160}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AWSSecretAccessKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AWSSecretAccessKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			// The whole of what keeps this pattern off a git SHA, an MD5 and
			// any forty characters cut out of a base64 blob: the value says
			// nothing on its own.
			name: "forty characters of the alphabet with no name in front of them",
			src:  awsSecretAccessKeyTestValue,
		},
		{
			name: "a git object written out in full",
			src:  "commit " + awsSecretAccessKeyTestValue,
		},
		{
			name: "the name with nothing behind it",
			src:  "AWS_SECRET_ACCESS_KEY=",
		},
		{
			name: "one character short of the count",
			src:  "AWS_SECRET_ACCESS_KEY=" + awsSecretAccessKeyTestValue[:39] + " ",
		},
		{
			// The run is read one character past the count, so a run longer
			// than a value is text that is no value rather than a value with
			// something written after it.
			name: "one character more than the count",
			src:  "AWS_SECRET_ACCESS_KEY=" + awsSecretAccessKeyTestValue + "0 ",
		},
		{
			name: "a run longer than a value by a whole value",
			src:  "AWS_SECRET_ACCESS_KEY=" + awsSecretAccessKeyTestValue + awsSecretAccessKeyTestValue + " ",
		},
		{
			// Padding ends a run, so thirty-eight characters closed by it
			// measure thirty-eight. Admitting the padding would measure them
			// forty and make them a value.
			name: "padding closing a run short of the count",
			src:  "AWS_SECRET_ACCESS_KEY=" + awsSecretAccessKeyTestValue[:38] + "== ",
		},
		{
			name: "a hyphen inside the count",
			src:  "AWS_SECRET_ACCESS_KEY=" + awsSecretAccessKeyTestValue[:20] + "-" + awsSecretAccessKeyTestValue[21:] + " ",
		},
		{
			// secret key is a name a dozen unrelated things carry, so the
			// middle word is asked for.
			name: "a name with the middle word left out",
			src:  "AWS_SECRET_KEY=" + awsSecretAccessKeyTestValue,
		},
		{
			name: "the words in the wrong order",
			src:  "ACCESS_SECRET_KEY=" + awsSecretAccessKeyTestValue,
		},
		{
			name: "two separators between two words",
			src:  "secret__access_key=" + awsSecretAccessKeyTestValue,
		},
		{
			name: "a separator no name is written with",
			src:  "secret.access.key=" + awsSecretAccessKeyTestValue,
		},
		{
			name: "the name written straight against the value",
			src:  "secret_access_key" + awsSecretAccessKeyTestValue,
		},
		{
			name: "a line break between the name and the value",
			src:  "AWS_SECRET_ACCESS_KEY=\n" + awsSecretAccessKeyTestValue,
		},
		{
			name: "a name on one line and a value on the next",
			src:  "AWS_SECRET_ACCESS_KEY\n" + awsSecretAccessKeyTestValue,
		},
		{
			// The run of spaces is counted, so a name further in front of a
			// value than the count reaches says nothing about it. Seventeen is
			// spelled here for the reason sixteen is spelled in the case this
			// one is paired with, in Test_AWSSecretAccessKey.
			name: "more spaces than the assignment reads",
			src:  "aws_secret_access_key=" + strings.Repeat(" ", 17) + awsSecretAccessKeyTestValue,
		},
		{
			name: "a word ending in the last word of a name",
			src:  "monkey=" + awsSecretAccessKeyTestValue,
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "prose naming the credential and holding none",
			src:  "the secret access key is issued once and shown once",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := AWSSecretAccessKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_AWSSecretAccessKey_inContext(t *testing.T) {
	// Forty is spelled here rather than read from awsSecretAccessKeyChars. What
	// these cases state is how much of a line comes back redacted, and an
	// expectation worked out from the count the scan reads comes back agreeing
	// with that count whatever it is changed to.
	stars := strings.Repeat("*", 40)

	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "AWS_SECRET_ACCESS_KEY=" + awsSecretAccessKeyTestValue,
			want: "AWS_SECRET_ACCESS_KEY=" + stars,
		},
		{
			// Only the value is redacted, so the name a reader needs to know
			// which credential leaked stays in the text.
			name: "json",
			src:  `{"SecretAccessKey": "` + awsSecretAccessKeyTestValue + `"}`,
			want: `{"SecretAccessKey": "` + stars + `"}`,
		},
		{
			name: "an ini section",
			src:  "[default]\naws_access_key_id = AKIA0123456789ABCDEF\naws_secret_access_key = " + awsSecretAccessKeyTestValue,
			want: "[default]\naws_access_key_id = AKIA0123456789ABCDEF\naws_secret_access_key = " + stars,
		},
		{
			name: "twice",
			src:  "a=" + awsSecretAccessKeyTestValue + " secret_access_key=" + awsSecretAccessKeyTestValue,
			want: "a=" + awsSecretAccessKeyTestValue + " secret_access_key=" + stars,
		},
	}

	m := New(WithPatterns(AWSSecretAccessKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_AWSSecretAccessKey_readsNoFurtherBackThanLookBehind(t *testing.T) {
	// This is the pattern that reads what stands in front of a value rather
	// than only the value, so LookBehind is what makes it a pattern a stream
	// may open a window on at all. The widest name and the widest assignment
	// are built from the declarations the scan reads them with, so that
	// widening either — a fourth word, a longer run of spaces — fails here
	// rather than leaving a stream to report a value it should have found.
	//
	// It is driven as well as measured. A limit the text fits under says
	// nothing if the scan stopped locating that text, and Find is what says
	// the widest shape is one the scan still reads.
	lead := strings.Join(awsSecretAccessKeyWords[:], "_") +
		`"` + strings.Repeat(" ", awsSecretAccessKeySpaceMax) +
		"=" + strings.Repeat(" ", awsSecretAccessKeySpaceMax) + `"`

	if len(lead) != awsSecretAccessKeyNameChars+awsSecretAccessKeySeparatorChars {
		t.Fatalf("the widest name and assignment are %d bytes, the counts beside the scan say %d",
			len(lead), awsSecretAccessKeyNameChars+awsSecretAccessKeySeparatorChars)
	}
	if len(lead) > LookBehind {
		t.Errorf("the scan reads %d bytes in front of a value, LookBehind is %d", len(lead), LookBehind)
	}

	src := lead + awsSecretAccessKeyTestValue + `"`
	want := []Span{{len(lead), len(lead) + awsSecretAccessKeyChars}}
	if got, _ := AWSSecretAccessKey().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}
}

func Test_awsSecretAccessKeyWords(t *testing.T) {
	// The scan folds every candidate into lowercase and compares it against
	// these, so a word spelled with anything else is a word no candidate ever
	// equals — and nothing else reports that: the pattern would quietly stop
	// locating keys, with every case here failing at once and none of them
	// saying why.
	if len(awsSecretAccessKeyWords) == 0 {
		t.Fatal("the name is made of no words, so the pattern locates nothing")
	}
	for _, word := range awsSecretAccessKeyWords {
		t.Run(word, func(t *testing.T) {
			if word == "" {
				t.Fatal("the word is empty")
			}
			for i := 0; i < len(word); i++ {
				if c := word[i]; c < 'a' || c > 'z' {
					t.Errorf("the word holds %q, which folding a candidate cannot produce", c)
				}
			}
			if isAWSSecretAccessKeyWordSeparator(word[0]) {
				t.Errorf("the word opens with %q, which is a separator; the scan takes a separator wherever one stands and never gives it back",
					word[0])
			}
		})
	}
}

// Test_awsSecretAccessKeyAnchor holds the first word to carrying the byte the
// scan searches the input for at the index it reads a candidate back from. A
// first word respelled there would be a word no candidate is ever found at, and
// builtin_scan.go says why that is held here rather than left to the target
// below.
func Test_awsSecretAccessKeyAnchor(t *testing.T) {
	word := awsSecretAccessKeyWords[0]
	if awsSecretAccessKeyAnchorIndex >= len(word) {
		t.Fatalf("the anchor stands at %d, the word is %d characters", awsSecretAccessKeyAnchorIndex, len(word))
	}
	if c := word[awsSecretAccessKeyAnchorIndex]; c != awsSecretAccessKeyAnchor {
		t.Errorf("the word carries %q where the scan searches for %q, so no candidate is ever found at it",
			c, byte(awsSecretAccessKeyAnchor))
	}
	if awsSecretAccessKeyAnchorUpper != awsSecretAccessKeyAnchor&^awsSecretAccessKeyFold {
		t.Error("the two cases the scan searches for are not the two cases of one letter")
	}

	// The scan searches for both cases and reads the name folded, so a name
	// written in either is found. A case written in one and not the other is
	// how the two cursors come apart.
	for _, name := range []string{"secret_access_key", "SECRET_ACCESS_KEY", "SecretAccessKey"} {
		t.Run(name, func(t *testing.T) {
			src := name + "=" + awsSecretAccessKeyTestValue + " "
			if got, _ := AWSSecretAccessKey().Find(src); len(got) != 1 {
				t.Errorf("Find(%q) = %v, want one span", src, got)
			}
		})
	}
}

func Test_isAWSSecretAccessKeyByte(t *testing.T) {
	// The alphabet is what a value is read by and the pattern is widest on, so
	// it is stated over every byte rather than by example.
	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9' || 'A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' || b == '+' || b == '/'
		if got := isAWSSecretAccessKeyByte(b); got != want {
			t.Errorf("isAWSSecretAccessKeyByte(%q) = %v, want %v", b, got, want)
		}
	}

	// Padding is what base64 would close on and forty characters never do.
	// Leaving it out is what ends a run at the padding, and the cases in
	// Test_AWSSecretAccessKey_noMatch are where that is driven either way.
	if isAWSSecretAccessKeyByte('=') {
		t.Error("isAWSSecretAccessKeyByte('=') = true, want padding left out of the alphabet")
	}

	// None of what stands between a name and a value is in the alphabet, which
	// is what gives a value its left edge without any test on the byte in
	// front of it.
	for _, b := range []byte{'"', '\'', ' ', '\t', '=', ':', '_', '-'} {
		if isAWSSecretAccessKeyByte(b) {
			t.Errorf("isAWSSecretAccessKeyByte(%q) = true, want what assigns a value kept out of it", b)
		}
	}
}

func Test_awsSecretAccessKeyValueEnd(t *testing.T) {
	// A value reaching the end of the input is reported and not settled: it is
	// the value in the text as handed over, and text arriving carries the run
	// past the count and takes it away again. The two answers are separate
	// results of the walk, so they are asked for separately here.
	value := awsSecretAccessKeyTestValue

	tests := []struct {
		name string
		src  string
		end  int
		ok   bool
		cut  bool
	}{
		{
			name: "the count, closed by a byte outside the alphabet",
			src:  value + " ",
			end:  40,
			ok:   true,
		},
		{
			name: "the count, closed by the end of the input",
			src:  value,
			end:  40,
			ok:   true,
			cut:  true,
		},
		{
			name: "one character more than the count",
			src:  value + "0 ",
			ok:   false,
		},
		{
			name: "one character more than the count, closed by the end of the input",
			src:  value + "0",
			ok:   false,
		},
		{
			name: "short of the count, closed by a byte outside the alphabet",
			src:  value[:20] + " ",
			ok:   false,
		},
		{
			name: "short of the count, closed by the end of the input",
			src:  value[:20],
			ok:   false,
			cut:  true,
		},
		{
			name: "no input at all",
			src:  "",
			ok:   false,
			cut:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			end, ok, cut := awsSecretAccessKeyValueEnd(tt.src, 0)
			if ok != tt.ok || cut != tt.cut || (ok && end != tt.end) {
				t.Errorf("awsSecretAccessKeyValueEnd(%q, 0) = %d, %v, %v; want %d, %v, %v",
					tt.src, end, ok, cut, tt.end, tt.ok, tt.cut)
			}
		})
	}
}

func Test_awsSecretAccessKeyNameTail(t *testing.T) {
	// What a stream holds on to when a name arrives in pieces. A name cut in
	// half opens no candidate at all, so the scan walks past it having found
	// nothing and this is the only thing that reports it.
	tests := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "a name cut before the anchor is reached",
			src:  "AWS_SE",
			want: 4,
		},
		{
			name: "a name cut in the middle",
			src:  "prose AWS_SECRET_ACC",
			want: 10,
		},
		{
			// A whole name is no piece of one. The scan reaches it through its
			// own anchor and settles by the candidate it opens, which is the
			// same offset arrived at the other way.
			name: "a whole name, which the scan reports for itself",
			src:  "AWS_SECRET_ACCESS_KEY",
			want: len("AWS_SECRET_ACCESS_KEY"),
		},
		{
			name: "one byte of a name",
			src:  "aws_s",
			want: 4,
		},
		{
			name: "prose closing on a word that is no name",
			src:  "there is no credential in this sentence",
			want: len("there is no credential in this sentence"),
		},
		{
			// A word closing on the letter a name opens with is held by that
			// letter, because the text carrying on from it can spell the rest
			// of the word into a name: ours followed by ecret_access_key= is
			// one.
			name: "prose closing on the letter a name opens with",
			src:  "the keys are ours",
			want: len("the keys are our"),
		},
		{
			name: "no input at all",
			src:  "",
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := awsSecretAccessKeyNameTail(tt.src); got != tt.want {
				t.Errorf("awsSecretAccessKeyNameTail(%q) = %d, want %d", tt.src, got, tt.want)
			}
		})
	}
}

func Test_awsSecretAccessKeyNameTail_holdsEveryPieceOfEveryName(t *testing.T) {
	// The cases above are the shapes; this is the count. A piece of a name is
	// turned away by the byte it closes on before anything is walked, so a byte
	// missing from that set is a piece of a name a stream lets go of — and no
	// case above would fail for it, since the pieces it happens to spell would
	// go on being held.
	//
	// The names are spelled here rather than read from the scan: every
	// separator a name may carry, in every case a word may be written in, which
	// is what the byte the piece closes on has to cover between them.
	const prose = "a line of prose, and nothing else at all "
	for _, sep := range []string{"", "_", "-", " "} {
		for _, name := range []string{
			"secret" + sep + "access" + sep + "key",
			"SECRET" + sep + "ACCESS" + sep + "KEY",
			"Secret" + sep + "Access" + sep + "Key",
		} {
			t.Run(name, func(t *testing.T) {
				for i := 1; i < len(name); i++ {
					src := prose + name[:i]
					if got := awsSecretAccessKeyNameTail(src); got != len(prose) {
						t.Errorf("awsSecretAccessKeyNameTail(prose + %q) = %d, want %d",
							name[:i], got, len(prose))
					}
				}
			})
		}
	}
}

// referenceAWSSecretAccessKeyFind is the statement of what a secret access key
// and the name in front of it are, written out plainly and kept here so that
// the scan in builtin_aws_secret_access_key.go can be held to it.
//
// The words, the separators, the counts and the alphabet are spelled again
// rather than built from awsSecretAccessKeyWords and the constants beside them.
// A reference sharing those declarations could not disagree with the scan about
// them, and it is exactly that disagreement the fuzz target below is for.
//
// It is written out rather than built on an expression, and what decided that
// is what an expression costs the target. An expression is the shorter
// statement of this grammar: a literal, two bounded runs of spaces and a
// counted class, none of which is the floor a counted repetition would make
// expensive. It costs the target its throughput all the same, and not through
// either half being slow — a scan alone and a reference alone each run hundreds
// of thousands of inputs where the two together run twenty thousand. What
// collapses is the coverage the two report between them: Go's engine carries
// branches of its own for every position of every counted repetition, and an
// input reaching a new combination of those is an input the fuzzer stops to
// minimize. Twenty seconds of a fresh corpus ran thirty-six thousand inputs
// with the expression and six hundred and eighty thousand without it, and the
// counter stopped freezing at nought a second.
//
// The walk asks at every byte and remembers nothing between positions, which is
// the plain reading of the grammar and is what the scan's anchor, its two
// cursors and its byte test are an optimisation of. Nothing here is written to
// know that a name opens with a particular letter or that a candidate can be
// found by searching for one.
func referenceAWSSecretAccessKeyFind(src string) []Span {
	const (
		valueChars = 40
		spaceMax   = 16
	)
	words := []string{"secret", "access", "key"}

	fold := func(c byte) byte {
		if 'A' <= c && c <= 'Z' {
			return c - 'A' + 'a'
		}
		return c
	}
	wordSeparator := func(c byte) bool { return c == '_' || c == '-' || c == ' ' }
	quote := func(c byte) bool { return c == '"' || c == '\'' }
	assignment := func(c byte) bool { return c == '=' || c == ':' }
	space := func(c byte) bool { return c == ' ' || c == '\t' }
	value := func(c byte) bool {
		return '0' <= c && c <= '9' ||
			'A' <= c && c <= 'Z' ||
			'a' <= c && c <= 'z' ||
			c == '+' || c == '/'
	}
	spaces := func(i int) int {
		for n := 0; n < spaceMax && i < len(src) && space(src[i]); n++ {
			i++
		}
		return i
	}

	var spans []Span
	for start := range len(src) {
		// The name: the three words in order, with one separator or nothing at
		// all between each pair, and the case of a letter set aside.
		i, ok := start, true
		for w, word := range words {
			if w > 0 && i < len(src) && wordSeparator(src[i]) {
				i++
			}
			if i+len(word) > len(src) {
				ok = false
				break
			}
			for j := range len(word) {
				if fold(src[i+j]) != word[j] {
					ok = false
					break
				}
			}
			if !ok {
				break
			}
			i += len(word)
		}
		if !ok {
			continue
		}

		// The assignment: a quote, a run of spaces, an assignment character,
		// another run of spaces and another quote, each of them optional and at
		// least one of them written.
		name := i
		if i < len(src) && quote(src[i]) {
			i++
		}
		i = spaces(i)
		if i < len(src) && assignment(src[i]) {
			i++
			i = spaces(i)
		}
		if i < len(src) && quote(src[i]) {
			i++
		}
		if i == name {
			continue
		}

		// The value: the count exactly, and the whole of the run it stands in.
		end := i + valueChars
		if end > len(src) || (end < len(src) && value(src[end])) {
			continue
		}
		whole := true
		for j := i; j < end; j++ {
			if !value(src[j]) {
				whole = false
				break
			}
		}
		if whole {
			spans = append(spans, Span{Start: i, End: end})
		}
	}
	return spans
}

// Test_AWSSecretAccessKey_matchesTheReferenceAcrossTheSpaceCount holds the scan
// and the reference to the same count of spaces, on either side of the
// assignment and on both sides of the count.
//
// The reference spells that count again rather than reading
// awsSecretAccessKeySpaceMax, which is what every rule about a reference asks
// for and is also the one number here that can drift without anything failing.
// Nothing else compares the two across it: builtinPatterns drives its samples,
// and no sample is written with a run of spaces this long; the tables above
// hold the scan to expectations written out by hand rather than to the
// reference; and the corpus states what Mask returns rather than what the two
// implementations agree on. That leaves the fuzz target below, which finds this
// only if it writes the run by chance. So the count is driven here, where
// raising it in one place and not the other fails under a plain go test.
func Test_AWSSecretAccessKey_matchesTheReferenceAcrossTheSpaceCount(t *testing.T) {
	value := awsSecretAccessKeyTestValue
	for n := range awsSecretAccessKeySpaceMax + 3 {
		spaces := strings.Repeat(" ", n)
		for _, src := range []string{
			"aws_secret_access_key=" + spaces + value,
			"aws_secret_access_key" + spaces + "=" + value,
			"aws_secret_access_key" + spaces + "=" + spaces + value,
			`aws_secret_access_key"` + spaces + "=" + spaces + `"` + value,
		} {
			got, _ := AWSSecretAccessKey().Find(src)
			want := referenceAWSSecretAccessKeyFind(src)
			if !slices.Equal(got, want) {
				t.Errorf("with %d space(s): Find(%q) = %v, reference gives %v", n, src, got, want)
			}
		}
	}
}

// FuzzAWSSecretAccessKey_matchesReference guards the hand-written scan: the
// byte it searches for in both of its cases, the words it folds a candidate
// into, the separators it admits between them, what it reads as an assignment,
// the count it reads behind that and the alphabet it reads it in may none of
// them change which keys are located.
func FuzzAWSSecretAccessKey_matchesReference(f *testing.F) {
	value := awsSecretAccessKeyTestValue

	f.Add("nothing to see here")
	f.Add("AWS_SECRET_ACCESS_KEY=" + value)
	f.Add("aws_secret_access_key = " + value)
	f.Add(`{"SecretAccessKey": "` + value + `"}`)
	f.Add("secretAccessKey=" + value)
	f.Add("aws-secret-access-key: " + value)
	f.Add("Secret Access Key " + value)
	f.Add("secretaccesskey=" + value)
	f.Add(value)                                 // the value with no name in front of it
	f.Add("commit " + value)                     // a git object of the same width
	f.Add("AWS_SECRET_ACCESS_KEY=" + value[:39]) // one short of the count
	f.Add("AWS_SECRET_ACCESS_KEY=" + value + "0")
	f.Add("AWS_SECRET_ACCESS_KEY=" + value + value)
	f.Add("AWS_SECRET_KEY=" + value)          // the middle word left out
	f.Add("secret__access_key=" + value)      // two separators where one may stand
	f.Add("secret.access.key=" + value)       // a separator no name is written with
	f.Add("secret_access_key" + value)        // nothing written between the two
	f.Add("AWS_SECRET_ACCESS_KEY=\n" + value) // a line break where a space may stand
	f.Add("aws_secret_access_key=" + strings.Repeat(" ", awsSecretAccessKeySpaceMax+1) + value)
	f.Add(`aws_secret_access_key "` + value + `"`)
	f.Add("aws_secret_access_key   =   " + value)
	f.Add("SeCrEt_AcCeSs_KeY=" + value) // the case alternating byte by byte
	f.Add("secret_access_key=" + value + " secret_access_key=" + value)
	// A name written inside the value of the one in front of it, and a name
	// written inside another name: both are places a scan resuming past a
	// match would step over a key.
	f.Add("secret_access_key=0123456789abcdefsecretaccesskey=" + value)
	f.Add("secretsecret_access_key=" + value)
	f.Add("secretaccesskeysecretaccesskey=" + value)
	// Candidate positions crowded as close as they can be: the anchor at every
	// byte, the first word repeated, and a run longer than any value behind a
	// name. Each is written just long enough to crowd what it is about — a
	// seed is what every input the fuzzer builds is mutated from, and Go
	// shrinks a new one by trying every subset of its bytes, so a seed written
	// longer than it needs to be is paid for in every minimization of
	// everything descended from it.
	f.Add(strings.Repeat("c", 16))
	f.Add(strings.Repeat("secret", 4))
	f.Add(strings.Repeat("secret_access_key=", 3))
	f.Add("secret_access_key=" + strings.Repeat("a", 48))

	fuzzAgainstReference(f, AWSSecretAccessKey().Find, referenceAWSSecretAccessKeyFind)
}

// awsSecretAccessKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func awsSecretAccessKeyFindBenchmarks() []benchmarkCase {
	// The line carries the c a log line has anyway — the word the scan
	// searches for its letter, the host name, the path — because those are the
	// positions the search stops at and reads a candidate back from. None of
	// them is a name, so what the line times is the walk and the comparison
	// that turns each of them away.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.example.com/config `
	value := awsSecretAccessKeyTestValue

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The name written out and a run one character short of the count:
			// the candidate at each name reads the whole name, the assignment
			// and all forty of the positions behind it, which is the most a
			// candidate can cost here. This scan keeps no cursor and needs
			// none — a count bounds every part of what a candidate reads — and
			// this is the input that would show the bound gone.
			name:  "candidates that are not values",
			src:   strings.Repeat("secret_access_key="+value[:39]+" ", 32),
			spans: 0,
		},
		{
			// A run of the alphabet longer than any value, behind a name: the
			// walk gives up one character past the count however far the run
			// goes on.
			name:  "a name in front of a run no value can be",
			src:   "secret_access_key=" + strings.Repeat(value, 32),
			spans: 0,
		},
		{
			// The first word repeated, which puts a candidate at every sixth
			// byte and the anchor's letter with it. Each is turned away inside
			// the second word.
			name:  "candidates crowded in one run",
			src:   strings.Repeat("secret", 128),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "AWS_SECRET_ACCESS_KEY=" + value,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "AWS_SECRET_ACCESS_KEY=" + value,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"AWS_SECRET_ACCESS_KEY="+value+"\n", 32),
			spans: 32,
		},
	}
}
