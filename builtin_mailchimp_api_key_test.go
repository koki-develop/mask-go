package mask

import (
	"slices"
	"strings"
	"testing"
)

// The Mailchimp API key pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. The body is 0123456789abcdef written twice, which
// is the thirty-two characters the pattern reads, and the number behind the
// separator is 19 wherever the number is not what a case is about.
//
// That body reaches two of the four ends of its alphabet at its own ends — it
// opens on 0 and closes on f — and the other two, the 9 and the a the two
// ranges meet at, fall in the middle of it wherever it is written. So the cases
// about the alphabet break the run: one writes a body opening on a and closing
// on 9, and the ones about a character the body excludes write that character
// at the first position and at the last rather than only inside.

func Test_MailchimpAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key",
			src:  "0123456789abcdef0123456789abcdef-us19",
			want: []Span{{0, 37}},
		},
		{
			name: "a key in an environment assignment",
			src:  "MAILCHIMP_API_KEY=0123456789abcdef0123456789abcdef-us19",
			want: []Span{{18, 55}},
		},
		{
			// The number is read to the end of its digits with a floor of one,
			// so the data center Mailchimp's own documentation names is located
			// as readily as a two-digit one.
			name: "a data center number of one digit",
			src:  "0123456789abcdef0123456789abcdef-us6",
			want: []Span{{0, 36}},
		},
		{
			// The far side of the floor: a number longer than any data center
			// Mailchimp has numbered is redacted whole rather than to the two
			// digits the rulesets read.
			name: "a data center number longer than any issued",
			src:  "0123456789abcdef0123456789abcdef-us123",
			want: []Span{{0, 38}},
		},
		{
			// The two ends of the alphabet an ordered body leaves in its
			// middle, written at its ends instead: the a the letters open on
			// first, the 9 the digits close on last.
			name: "a body opening and closing on the ends its ordered run leaves inside",
			src:  "a123456789abcdef0123456789abcde9-us19",
			want: []Span{{0, 37}},
		},
		{
			// The other two ends where the ordered body already has them, kept
			// as a case of its own so that all four are written down together.
			name: "a body opening and closing on the other two ends of its alphabet",
			src:  "0f9a0123456789abcdef0123456789f0-us19",
			want: []Span{{0, 37}},
		},
		{
			// The floor on the number met by its lowest digit, which no other
			// case writes as a whole number.
			name: "a data center number of a single zero",
			src:  "0123456789abcdef0123456789abcdef-us0",
			want: []Span{{0, 36}},
		},
		{
			// The character just above the number's alphabet, closing the run
			// rather than breaking the key: the number ends at it and what
			// follows stays in the text.
			name: "the character above nine behind the number",
			src:  "0123456789abcdef0123456789abcdef-us19:",
			want: []Span{{0, 37}},
		},
		{
			// The character in front of the body is the whole of what this scan
			// reads in front of a value, and a letter past f is one that ends a
			// run of the body's own alphabet.
			name: "a key written against a character that ends a body run",
			src:  "g0123456789abcdef0123456789abcdef-us19",
			want: []Span{{1, 38}},
		},
		{
			name: "a key written against an uppercase hexadecimal character",
			src:  "F0123456789abcdef0123456789abcdef-us19",
			want: []Span{{1, 38}},
		},
		{
			name: "two keys with a space between them",
			src:  "0123456789abcdef0123456789abcdef-us19 0123456789abcdef0123456789abcdef-us6",
			want: []Span{{0, 37}, {38, 74}},
		},
		{
			// What the number being a run costs where a body opens on digits.
			// The first key's number runs on through the ten digits the second
			// body opens with and stops at the first letter, and the second key
			// is not located at all: its body is written straight against a
			// digit, which is a character of a body's own alphabet. Two keys
			// written with nothing between them is not text anybody writes, and
			// what it shows is the two rules working rather than a shape to
			// support.
			name: "two keys with nothing between them",
			src:  "0123456789abcdef0123456789abcdef-us190123456789abcdef0123456789abcdef-us19",
			want: []Span{{0, 47}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := MailchimpAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_MailchimpAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a body one character short",
			src:  "0123456789abcdef0123456789abcde-us19",
		},
		{
			// The count from the other side. A body is the whole of the run it
			// stands in, so a run one character longer is not a key with a
			// character written in front of it but text that is no key.
			name: "a run one character longer than a body",
			src:  "00123456789abcdef0123456789abcdef-us19",
		},
		{
			name: "a run one character longer than a body, the character a letter",
			src:  "f0123456789abcdef0123456789abcdef-us19",
		},
		{
			// A digest with a region written behind it, which is what holding
			// the run to the count is for: a SHA-1 is forty hexadecimal
			// characters, so the thirty-two in front of the separator are the
			// tail of a run rather than a body.
			name: "a sha-1 in front of the separator",
			src:  "0123456789abcdef0123456789abcdef01234567-us19",
		},
		{
			name: "a letter past f at the first character of the body",
			src:  "g123456789abcdef0123456789abcdef-us19",
		},
		{
			name: "a letter past f in the middle of the body",
			src:  "0123456789abcdefg123456789abcdef-us19",
		},
		{
			name: "a letter past f at the last character of the body",
			src:  "0123456789abcdef0123456789abcdeg-us19",
		},
		{
			// The uppercase spelling of the body's own letters, which this
			// pattern reads nowhere.
			name: "an uppercase letter at the first character of the body",
			src:  "A123456789abcdef0123456789abcdef-us19",
		},
		{
			name: "an uppercase letter in the middle of the body",
			src:  "0123456789abcdefA123456789abcdef-us19",
		},
		{
			name: "an uppercase letter at the last character of the body",
			src:  "0123456789abcdef0123456789abcdeF-us19",
		},
		{
			// The characters standing either side of the two ranges the body's
			// alphabet is written in, each of them at the first character of a
			// body and at the last.
			name: "the character below zero at the first character of the body",
			src:  "/123456789abcdef0123456789abcdef-us19",
		},
		{
			name: "the character below zero at the last character of the body",
			src:  "0123456789abcdef0123456789abcde/-us19",
		},
		{
			name: "the character above nine at the first character of the body",
			src:  ":123456789abcdef0123456789abcdef-us19",
		},
		{
			name: "the character above nine at the last character of the body",
			src:  "0123456789abcdef0123456789abcde:-us19",
		},
		{
			name: "the character below a at the first character of the body",
			src:  "`123456789abcdef0123456789abcdef-us19",
		},
		{
			name: "the character below a at the last character of the body",
			src:  "0123456789abcdef0123456789abcde`-us19",
		},
		{
			name: "a hyphen inside the body",
			src:  "0123456789abcdef-123456789abcdef-us19",
		},
		{
			name: "a body broken by a space",
			src:  "0123456789abcdef 123456789abcdef-us19",
		},
		{
			name: "a body broken by a line break",
			src:  "0123456789abcdef\n123456789abcdef-us19",
		},
		{
			name: "a body broken by an invalid byte",
			src:  "0123456789abcdef\xff123456789abcdef-us19",
		},
		{
			// The floor on the number: the separator is whole and nothing is
			// written behind it.
			name: "no digits behind the separator",
			src:  "0123456789abcdef0123456789abcdef-us",
		},
		{
			name: "a letter where the number is written",
			src:  "0123456789abcdef0123456789abcdef-usa",
		},
		{
			// The characters standing either side of the number's alphabet,
			// written where the number's first digit would be, which is where
			// the floor of one is decided.
			name: "the character below zero where the number is written",
			src:  "0123456789abcdef0123456789abcdef-us/",
		},
		{
			name: "the character above nine where the number is written",
			src:  "0123456789abcdef0123456789abcdef-us:",
		},
		{
			name: "a space between the separator and the number",
			src:  "0123456789abcdef0123456789abcdef-us 19",
		},
		{
			name: "an uppercase separator",
			src:  "0123456789abcdef0123456789abcdef-US19",
		},
		{
			// The two letters of the separator are read as they are written and
			// nothing stands in for either of them.
			name: "a region the separator does not carry",
			src:  "0123456789abcdef0123456789abcdef-eu19",
		},
		{
			name: "a letter of the separator mistyped",
			src:  "0123456789abcdef0123456789abcdef-ux19",
		},
		{
			name: "an underscore where the separator carries its hyphen",
			src:  "0123456789abcdef0123456789abcdef_us19",
		},
		{
			name: "a space where the separator carries its hyphen",
			src:  "0123456789abcdef0123456789abcdef us19",
		},
		{
			// Thirty-two hexadecimal characters standing on their own, which is
			// an MD5 exactly and is the shape this pattern may not be anchored
			// on.
			name: "an md5 on its own",
			src:  "MAILCHIMP_API_KEY=0123456789abcdef0123456789abcdef",
		},
		{
			// The separator and a number with no body in front of them, which
			// is how a region is ordinarily written.
			name: "a region written after a word",
			src:  "bucket-us19",
		},
		{
			// The Transactional API key, which is twenty-two characters with
			// nothing in them to be recognised by: a credential this pattern's
			// name covers and its grammar reaches nowhere.
			name: "a transactional api key",
			src:  "MANDRILL_API_KEY=0123456789abcdefghijkl",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := MailchimpAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_MailchimpAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "MAILCHIMP_API_KEY=0123456789abcdef0123456789abcdef-us19",
			want: "MAILCHIMP_API_KEY=*************************************",
		},
		{
			// How a key reaches the API: it is the password of a basic
			// authorization header, with any string at all for the user.
			name: "a command line",
			src:  `curl --user "anystring:0123456789abcdef0123456789abcdef-us19" https://us19.api.mailchimp.com/3.0/ping`,
			want: `curl --user "anystring:*************************************" https://us19.api.mailchimp.com/3.0/ping`,
		},
		{
			name: "json",
			src:  `{"apiKey":"0123456789abcdef0123456789abcdef-us19","server":"us19"}`,
			want: `{"apiKey":"*************************************","server":"us19"}`,
		},
		{
			name: "a log line",
			src:  `time=2026-08-17T00:00:00Z level=info key=0123456789abcdef0123456789abcdef-us19`,
			want: `time=2026-08-17T00:00:00Z level=info key=*************************************`,
		},
	}

	m := New(WithPatterns(MailchimpAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_MailchimpAPIKey_nextToWordCharacters(t *testing.T) {
	// What holding the body to the whole of its run costs and what it leaves
	// alone. A key written against a character of the body's own alphabet is
	// not trimmed but dropped, which is the price of not reading the tail of a
	// digest as a body; a key written against anything else is located where it
	// stands.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a letter past f before",
			src:  "g0123456789abcdef0123456789abcdef-us19",
			want: "g*************************************",
		},
		{
			name: "an underscore before",
			src:  "MAILCHIMP_API_KEY_0123456789abcdef0123456789abcdef-us19",
			want: "MAILCHIMP_API_KEY_*************************************",
		},
		{
			// The one that costs something. A hexadecimal character written
			// against the body carries the run past the count, and none of the
			// key is redacted.
			name: "a hexadecimal character before",
			src:  "a0123456789abcdef0123456789abcdef-us19",
			want: "a0123456789abcdef0123456789abcdef-us19",
		},
		{
			// Behind a key there is no such cost: the number ends at the first
			// character that is no digit, and what is written after it stays in
			// the text.
			name: "a letter after",
			src:  "0123456789abcdef0123456789abcdef-us19x",
			want: "*************************************x",
		},
		{
			// A multi-byte rune flush against the key on both sides, with no
			// space between them.
			name: "a multi-byte rune flush against the key on both sides",
			src:  "日本語0123456789abcdef0123456789abcdef-us19日本語",
			want: "日本語*************************************日本語",
		},
	}

	m := New(WithPatterns(MailchimpAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_MailchimpAPIKey_aDigestInFrontOfTheSeparator(t *testing.T) {
	// The collision this format has no way out of, and the one it does. An MD5
	// is thirty-two hexadecimal characters, so an MD5 standing on its own in
	// front of the separator and a number is a key character for character:
	// there is nothing left to tell the two apart, and a scan declining it
	// would decline every key Mailchimp issues. A longer digest is a different
	// matter — the run says it is one — and holding the body to the whole of
	// its run is what leaves it in the text.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an md5 in front of the separator",
			src:  "0123456789abcdef0123456789abcdef-us19",
			want: []Span{{0, 37}},
		},
		{
			name: "a sha-1 in front of the separator",
			src:  "0123456789abcdef0123456789abcdef01234567-us19",
		},
		{
			name: "a sha-256 in front of the separator",
			src:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef-us19",
		},
		{
			// A digest with no separator behind it, which is every digest a log
			// ordinarily carries.
			name: "an md5 on its own",
			src:  "0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := MailchimpAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_MailchimpAPIKey_aKeyBeginningInsideAnother(t *testing.T) {
	// The claim builtin_mailchimp_api_key.go makes about advancing rather than
	// consuming the match, and the one position inside a key that carries it. A
	// body opens only where the character in front of it is not hexadecimal,
	// and everywhere inside a key that character is one — the body's own
	// characters and the digits of the number — except behind the s the
	// separator closes with. So a key beginning inside another begins at the
	// first character of its number and nowhere else, and it needs a number
	// long enough to be a body.
	//
	// A scan consuming its match would resume past the first key and leave the
	// second in the output whole. The two spans overlap, which a Masker
	// resolves into one, so the redaction reaches from the first character to
	// the last.
	//
	// The first key runs to the end of its own number, and that number carries
	// on through the second key's body and stops at the hyphen the second
	// separator opens with — so the two spans are the same length and are
	// staggered by the thirty-five characters in front of the second body.
	const src = "0123456789abcdef0123456789abcdef-us01234567890123456789012345678901-us19"

	want := []Span{{0, 67}, {35, 72}}
	if got, _ := MailchimpAPIKey().Find(src); !slices.Equal(got, want) {
		t.Fatalf("Find(%q) = %v, want %v", src, got, want)
	}

	m := New(WithPatterns(MailchimpAPIKey()))
	if got, want := m.Mask(src), strings.Repeat("*", len(src)); got != want {
		t.Errorf("Mask(%q) = %q, want %q", src, got, want)
	}
}

func Test_MailchimpAPIKey_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor. What holds it linear is a count for the body —
	// a candidate reads at most thirty-six bytes before it is given up on — and
	// the separator for the number: a candidate opens at a hyphen and a hyphen
	// is no digit, so the run one candidate reads ends where the next
	// candidate's separator begins. These are the inputs that would find either
	// wrong.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// whole key apiece and so hold a candidate every thirty-seven bytes at
	// their densest. The crowding a line can actually carry, a candidate every
	// three, stays here.
	sources := map[string]string{
		// A candidate every three characters, each turned away at the first
		// character of its body. The count and the separator are three and two
		// apart, so every candidate in this input opens on the u of the
		// separator in front of it, which no body is written with.
		"a candidate every three characters": strings.Repeat("-us", 500000),
		// The same crowding with a whole key at each candidate, so every one of
		// them reads a whole body and reports a span.
		"a key every thirty-eight characters": strings.Repeat("0123456789abcdef0123456789abcdef-us19 ", 40000),
		// A candidate walked to its last body character before the empty number
		// behind it turns the candidate away, which is the most a rejected
		// candidate can cost.
		"a candidate walked to its last body character": strings.Repeat("0123456789abcdef0123456789abcdef-us ", 40000),
		// Bodies written in digits alone, which is where two candidates come
		// closest to reading the same number: each one's run carries on through
		// the next body and stops at the hyphen the next separator opens with.
		"bodies a number can run into": strings.Repeat("01234567890123456789012345678901-us", 60000),
		// One candidate whose number is the whole line. The run is read once,
		// and no second candidate stands in it to read it again.
		"a number the length of the line": "0123456789abcdef0123456789abcdef-us" + strings.Repeat("1", 2000000),
		// A run of the body's alphabet with no separator anywhere in it, so no
		// candidate is found and the walk over the end of the input gives up
		// after thirty-three characters.
		"a body run the length of the line": strings.Repeat("a", 2000000),
	}

	checkScanIsLinear(t, MailchimpAPIKey(), sources)
}

// Test_MailchimpAPIKey_settlesWhatTheInputCutShort holds Find's second return
// to the offset in front of which nothing further back can still become a key,
// which is either a body run standing at the end of the input or a candidate
// the end of the input cut short. What every built-in owes about this offset
// over generated text and over the samples is driven in builtins_test.go and
// fuzz_test.go; what is written out here is which inputs of this pattern's own
// shape hold anything back, since nothing else names them.
func Test_MailchimpAPIKey_settlesWhatTheInputCutShort(t *testing.T) {
	const body = "0123456789abcdef0123456789abcdef"

	tests := []struct {
		name string
		src  string
		want int
	}{
		{
			// A body run the end of the input reaches into carries no separator
			// yet, so nothing of it has been found and the whole run is held.
			name: "a body the end of the input cut short",
			src:  "key=0123456789abcdef",
			want: 4,
		},
		{
			name: "a body reaching the end of the input at the count",
			src:  "key=" + body,
			want: 4,
		},
		{
			// A run already longer than a body can never become one, whatever
			// is written next, so it is settled rather than held. That reading
			// is what keeps a line of hexadecimal from holding a stream open
			// from its first character.
			name: "a run longer than a body",
			src:  "key=" + body + "0",
			want: 37,
		},
		{
			// The input the anchor's own argument turns on. The hyphen is the
			// first character of the separator, so a candidate opens here and
			// the body in front of it is read; anchored at the u instead, no
			// candidate would be found and this text would be settled with a
			// key half written in it.
			name: "the separator cut to its first character",
			src:  "key=" + body + "-",
			want: 4,
		},
		{
			name: "the separator cut in half",
			src:  "key=" + body + "-u",
			want: 4,
		},
		{
			// The separator whole with nothing behind it. A digit written next
			// gives this candidate a number and makes it a key.
			name: "the separator with no number behind it",
			src:  "key=" + body + "-us",
			want: 4,
		},
		{
			// A whole key reaching the end of the input, which is held back
			// from its own start: a digit written next carries the number
			// further and widens the key.
			name: "a whole key reaching the end of the input",
			src:  "key=" + body + "-us19",
			want: 4,
		},
		{
			name: "a whole key followed by a character that is no digit",
			src:  "key=" + body + "-us19 ",
			want: 42,
		},
		{
			// A hyphen at the end of the input with nothing in front of it that
			// could be a body. Nothing is held back: no candidate opens there,
			// and the hyphen is no character a body is written with.
			name: "a hyphen with no body in front of it",
			src:  "nothing here yet -",
			want: 18,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, got := MailchimpAPIKey().Find(tt.src); got != tt.want {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, got, tt.want)
			}
		})
	}
}

func Test_mailchimpAPIKeySeparator(t *testing.T) {
	// The two things the scan needs of the separator, neither of which anything
	// else here reports: a separator nothing locates simply locates nothing,
	// and the cases above would go on passing for the one that still works.
	//
	// The first is that it opens with a character no body is written with. That
	// is what bounds a body on its right without a second rule saying so, and
	// it is what keeps a body from running on through the key in front of it.
	//
	// The second is that the same character is no digit, which is what the
	// number being a run rather than a count rests on: the run one candidate
	// reads ends where the next candidate's separator begins, so two candidates
	// never read the same one and the scan stays linear.
	// Test_MailchimpAPIKey_scanIsLinear drives the input that would find it
	// wrong.
	if mailchimpAPIKeySeparator == "" {
		t.Fatal("the pattern carries no separator, so it locates nothing")
	}
	if c := mailchimpAPIKeySeparator[0]; isMailchimpAPIKeyBodyByte(c) {
		t.Errorf("the separator %q opens with %q, which a body is written with", mailchimpAPIKeySeparator, c)
	}
	if c := mailchimpAPIKeySeparator[0]; isMailchimpAPIKeyNumberByte(c) {
		t.Errorf("the separator %q opens with %q, which a number is written with", mailchimpAPIKeySeparator, c)
	}
}

// Test_mailchimpAPIKeyAnchor holds the separator to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_mailchimpAPIKeyAnchor(t *testing.T) {
	if mailchimpAPIKeySeparatorAnchorIndex >= len(mailchimpAPIKeySeparator) {
		t.Fatalf("the anchor stands at %d of the separator, which is %d characters",
			mailchimpAPIKeySeparatorAnchorIndex, len(mailchimpAPIKeySeparator))
	}
	if c := mailchimpAPIKeySeparator[mailchimpAPIKeySeparatorAnchorIndex]; c != mailchimpAPIKeyAnchor {
		t.Errorf("the separator carries %q where the scan searches for %q, so no candidate is ever found at it",
			c, byte(mailchimpAPIKeyAnchor))
	}
	if got := mailchimpAPIKeyBodyChars + mailchimpAPIKeySeparatorAnchorIndex; got != mailchimpAPIKeyAnchorIndex {
		t.Errorf("the anchor stands %d bytes into a key and the scan reads a candidate back from %d",
			got, mailchimpAPIKeyAnchorIndex)
	}
}

// referenceMailchimpAPIKeyFind locates keys the plain way: at every byte of the
// input, thirty-two lowercase hexadecimal characters held to being the whole of
// the run they stand in, the separator -us, and one or more decimal digits read
// to the end of theirs.
//
// The count, the separator and both character classes are spelled again here
// rather than built from the declarations in builtin_mailchimp_api_key.go. A
// reference sharing those could not disagree with the scan about them, and it
// is exactly that disagreement the fuzz target below is for: the two have to be
// changed together or reported apart.
//
// It is written out rather than built on an expression because neither boundary
// can be spelled in RE2, which has no lookaround: the character in front of a
// body and the one behind a number are both asked about outside the match. An
// expression would cost the other way besides — a key opens in the alphabet its
// body is written in, so a run of hexadecimal is a position an engine stops at,
// and there is no literal in front of the grammar for it to search the text for.
//
// Asking at every byte is what the scan does too, and it is not written here to
// restate that. A reference is written to know nothing its scan claims, and
// where a key may begin is one of the things the scan claims — so this one asks
// afresh at every byte whether or not a key can be written inside another, and
// the fuzz target below is what holds the two to the same answer.
func referenceMailchimpAPIKeyFind(src string) []Span {
	const body = 32
	const separator = "-us"

	hex := func(c byte) bool { return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' }
	digit := func(c byte) bool { return '0' <= c && c <= '9' }

	var spans []Span
	for i := range len(src) {
		if i+body+len(separator) > len(src) {
			break
		}
		if i > 0 && hex(src[i-1]) {
			continue
		}
		whole := true
		for j := i; j < i+body; j++ {
			if !hex(src[j]) {
				whole = false
				break
			}
		}
		if !whole {
			continue
		}
		if src[i+body:i+body+len(separator)] != separator {
			continue
		}
		end := i + body + len(separator)
		for end < len(src) && digit(src[end]) {
			end++
		}
		if end == i+body+len(separator) {
			continue
		}
		spans = append(spans, Span{Start: i, End: end})
	}
	return spans
}

// FuzzMailchimpAPIKey_matchesReference guards the hand-written scan: the byte
// it searches for, the count it reads in front of that byte, the character it
// reads in front of the count, the separator it compares and the digits it
// reads behind it may none of them change which keys are located.
func FuzzMailchimpAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("MAILCHIMP_API_KEY=0123456789abcdef0123456789abcdef-us19")
	f.Add("0123456789abcdef0123456789abcdef-us6")                  // a number of one digit
	f.Add("0123456789abcdef0123456789abcdef-us123")                // and one longer than any issued
	f.Add("0123456789abcdef0123456789abcde-us19")                  // a body one character short
	f.Add("00123456789abcdef0123456789abcdef-us19")                // and a run one longer
	f.Add("0123456789abcdef0123456789abcdef01234567-us19")         // a sha-1 in front of the separator
	f.Add("0123456789abcdef0123456789abcdef0123456789abcdef-us19") // and more of one
	f.Add("g0123456789abcdef0123456789abcdef-us19")                // written against a character that ends a run
	f.Add("0f9a0123456789abcdef0123456789f0-us19")                 // the ends of the body's alphabet
	f.Add("0123456789abcdefg123456789abcdef-us19")                 // a letter past f in the body
	f.Add("0123456789abcdefA123456789abcdef-us19")                 // and an uppercase one
	f.Add("0123456789abcdef-123456789abcdef-us19")                 // a hyphen inside the body
	f.Add("0123456789abcdef0123456789abcdef-us")                   // no digits behind the separator
	f.Add("0123456789abcdef0123456789abcdef-usa")                  // a letter where the number is written
	f.Add("0123456789abcdef0123456789abcdef-US19")                 // an uppercase separator
	f.Add("0123456789abcdef0123456789abcdef-eu19")                 // a region the separator does not carry
	f.Add("0123456789abcdef0123456789abcdef_us19")                 // an underscore where the hyphen stands
	f.Add("0123456789abcdef0123456789abcdef")                      // an md5 on its own
	f.Add("bucket-us19")                                           // a region written after a word
	f.Add("a123456789abcdef0123456789abcde9-us19")                 // the ends its ordered run leaves inside
	f.Add("0123456789abcdef0123456789abcdef-us0")                  // the number's lowest digit alone
	f.Add("0123456789abcdef0123456789abcdef-us:")                  // and the characters either side of its alphabet
	f.Add("0123456789abcdef0123456789abcdef-us/")                  //
	f.Add("0123456789abcdef0123456789abcdef-us19:")                // one of them closing a number
	f.Add("0123456789abcdef0123456789abcdef-us19 0123456789abcdef0123456789abcdef-us6")
	f.Add("0123456789abcdef0123456789abcdef-us190123456789abcdef0123456789abcdef-us19")
	// A key beginning inside another, which is what advancing rather than
	// consuming the match has to find: a body opening at the first character of
	// the number of the key in front of it.
	f.Add("0123456789abcdef0123456789abcdef-us01234567890123456789012345678901-us19")
	// Candidate positions crowded as close as they can be, a body of digits
	// alone, and a run of the body's alphabet with no separator in it.
	f.Add(strings.Repeat("-us", 32))
	f.Add(strings.Repeat("01234567890123456789012345678901-us", 4))
	f.Add(strings.Repeat("0123456789abcdef", 8))

	fuzzAgainstReference(f, MailchimpAPIKey().Find, referenceMailchimpAPIKeyFind)
}

// mailchimpAPIKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func mailchimpAPIKeyFindBenchmarks() []benchmarkCase {
	// An ordinary line carries the byte the scan searches for twice, both of
	// them in the timestamp, and neither has thirty-two characters of a body in
	// front of it. What the line times is that search and the two stops it
	// makes, which is what this pattern costs a caller whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://us19.api.mailchimp.com/3.0/lists `
	key := "0123456789abcdef0123456789abcdef-us19"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The separator written over and over, so a candidate stands at
			// every third byte and every one of them is turned away at the
			// first character of its body, which in this input is the u of the
			// separator in front of it. That is the cheapest this scan declines
			// a candidate for.
			name:  "candidates that are not values",
			src:   strings.Repeat("-us", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails, and the most expensive: a whole
			// body walked before the empty number behind it turns the candidate
			// away.
			name:  "candidates walked to their last body character",
			src:   strings.Repeat("0123456789abcdef0123456789abcdef-us ", 16),
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
