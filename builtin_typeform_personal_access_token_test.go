package mask

import (
	"slices"
	"strings"
	"testing"
)

// The Typeform personal access token pattern: what it locates and what it
// leaves alone, written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a set
// of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. The run they are built from is
// 0123456789abcdefghijklmnopqrstuvwxyz, carried back to 0 where a body is longer
// than thirty-six, so a body of forty is that run and then 0123. Cases turning
// on a particular character standing at a particular place say so and carry the
// run with that character put into it.

func Test_TypeformPersonalAccessToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{0, 44}},
		},
		{
			name: "a token in an environment assignment",
			src:  "TYPEFORM_TOKEN=tfp_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{15, 59}},
		},
		{
			// The width betterleaks reads for this format, which the floor
			// reaches as readily as it reaches the shortest one.
			name: "a body of the width betterleaks reads",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklm",
			want: []Span{{0, 63}},
		},
		{
			// The shape Typeform's own detection rule reads: a run, an
			// underscore, and a shorter run behind it. The underscore is a body
			// character, so the whole of it is one run and one token.
			name: "a body of the shape Typeform's own rule reads",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz0123_456789ab",
			want: []Span{{0, 53}},
		},
		{
			// The floor exactly, one character past it, and the first width at
			// which a body becomes one, stated from both sides.
			name: "a run one character longer than the floor",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz01234",
			want: []Span{{0, 45}},
		},
		{
			// The underscore doubles the one the prefix closes with. A scan
			// reading a prefix by that character rather than by the whole
			// literal would part from the reference here, and the run opens
			// behind the prefix rather than being cut short by it.
			name: "a body opening on an underscore",
			src:  "tfp__0123456789abcdefghijklmnopqrstuvwxyz012",
			want: []Span{{0, 44}},
		},
		{
			name: "a body closing on an underscore",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz012_",
			want: []Span{{0, 44}},
		},
		{
			// The ends of each range the alphabet is written in, standing where
			// a body opens.
			name: "a body opening on the last digit",
			src:  "tfp_90123456789abcdefghijklmnopqrstuvwxyz012",
			want: []Span{{0, 44}},
		},
		{
			name: "a body opening on the first uppercase letter",
			src:  "tfp_A0123456789abcdefghijklmnopqrstuvwxyz012",
			want: []Span{{0, 44}},
		},
		{
			name: "a body opening on the last uppercase letter",
			src:  "tfp_Z0123456789abcdefghijklmnopqrstuvwxyz012",
			want: []Span{{0, 44}},
		},
		{
			name: "a body opening on the last lowercase letter",
			src:  "tfp_z0123456789abcdefghijklmnopqrstuvwxyz012",
			want: []Span{{0, 44}},
		},
		{
			// The same ends at the last character the floor asks for, which is
			// where a walk stopping one byte early or late would show itself.
			name: "a body closing on the last digit",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz0129",
			want: []Span{{0, 44}},
		},
		{
			name: "a body closing on the first uppercase letter",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz012A",
			want: []Span{{0, 44}},
		},
		{
			name: "a body closing on the last uppercase letter",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz012Z",
			want: []Span{{0, 44}},
		},
		{
			name: "a body closing on the last lowercase letter",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz012z",
			want: []Span{{0, 44}},
		},
		{
			// Every end of every range at once, standing in the middle of a
			// body rather than at either of its edges.
			name: "a body carrying every end of the alphabet in the middle",
			src:  "tfp_0123456789abcd09AZaz_efghijklmnopqrstuvw",
			want: []Span{{0, 44}},
		},
		{
			// The upper half of the alphabet, which the run leaves untouched.
			name: "a body of uppercase letters",
			src:  "tfp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
			want: []Span{{0, 44}},
		},
		{
			// A character outside the alphabet standing where the floor is met
			// ends the run there, and forty characters are in front of it.
			name: "a hyphen behind a whole body",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz0123-suffix",
			want: []Span{{0, 44}},
		},
		{
			name: "a dot behind a whole body",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz0123.suffix",
			want: []Span{{0, 44}},
		},
		{
			// Two tokens with something between them, so neither run reaches
			// the other.
			name: "two tokens on one line",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz0123 tfp_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{0, 44}, {45, 89}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := TypeformPersonalAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TypeformPersonalAccessToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the prefix alone",
			src:  "tfp_",
		},
		{
			// Thirty-nine characters where the floor asks for forty.
			name: "a body one character short of the floor",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz012",
		},
		{
			// A character outside the alphabet at the last character the floor
			// asks for, with thirty-nine of the alphabet in front of it and more
			// behind: the run ends one short, and what stands past the character
			// cannot be reached to make up the difference.
			name: "a hyphen at the last character the floor asks for",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz012-456789ab",
		},
		{
			name: "a dot at the last character the floor asks for",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz012.456789ab",
		},
		{
			name: "an equals sign at the last character the floor asks for",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz012=456789ab",
		},
		{
			// The same three at the first character of a body, where the run is
			// ended before it begins.
			name: "a hyphen at the first character of the body",
			src:  "tfp_-123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "a dot at the first character of the body",
			src:  "tfp_.123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "an equals sign at the first character of the body",
			src:  "tfp_=123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "a body broken by a space",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxy 0123",
		},
		{
			name: "a body broken by a line break",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxy\n0123",
		},
		{
			name: "an uppercase prefix",
			src:  "TFP_0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "the prefix with one letter capitalized",
			src:  "Tfp_0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "a hyphen where the prefix carries its underscore",
			src:  "tfp-0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "the prefix without the underscore that closes it",
			src:  "tfp0123456789abcdefghijklmnopqrstuvwxyz01234",
		},
		{
			// A run long enough for a body opening with something else. The
			// prefix is the whole of the anchor, so a run of the right length is
			// no token without it.
			name: "a run of the right length opening with no prefix",
			src:  "xxx_0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// Forty hexadecimal characters. A digest carries no prefix, so it
			// holds no candidate to be found at.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
		{
			// The vendor's own name, which carries the byte the scan searches
			// for at the index it reads a candidate back from.
			name: "the vendor's name in a url",
			src:  "https://api.typeform.com/forms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := TypeformPersonalAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_TypeformPersonalAccessToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "TYPEFORM_TOKEN=tfp_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: "TYPEFORM_TOKEN=********************************************",
		},
		{
			name: "quoted",
			src:  `"tfp_0123456789abcdefghijklmnopqrstuvwxyz0123"`,
			want: `"********************************************"`,
		},
		{
			name: "json",
			src:  `{"token":"tfp_0123456789abcdefghijklmnopqrstuvwxyz0123"}`,
			want: `{"token":"********************************************"}`,
		},
		{
			// The header Typeform's documentation passes a token in.
			name: "a bearer header",
			src:  "Authorization: Bearer tfp_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: "Authorization: Bearer ********************************************",
		},
		{
			// The command line that documentation makes its first request with.
			name: "a curl command",
			src:  "curl -H 'Authorization: Bearer tfp_0123456789abcdefghijklmnopqrstuvwxyz0123' https://api.typeform.com/me",
			want: "curl -H 'Authorization: Bearer ********************************************' https://api.typeform.com/me",
		},
		{
			name: "twice",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz0123 tfp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
			want: "******************************************** ********************************************",
		},
	}

	m := New(WithPatterns(TypeformPersonalAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TypeformPersonalAccessToken_theBodyReachesTheEndOfTheRun(t *testing.T) {
	// What reading the body as a floor costs, held to being paid rather than
	// argued about. The four sources this format rests on disagree on its width,
	// so a body has no width of its own to end at and is read to the end of the
	// run it stands in. Where a token is written against more of the alphabet,
	// those characters are redacted with it.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a character of the alphabet behind a token",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz01234",
			want: "*********************************************",
		},
		{
			// A word joined to the token by an underscore, which is a body
			// character: what follows is read as body and goes with it.
			name: "a word joined to a token by an underscore",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz0123_suffix",
			want: "***************************************************",
		},
		{
			// Two tokens written against one another are one run, so the first
			// candidate reaches the end of the second token and the spans merge
			// into one redaction.
			name: "two tokens with nothing between them",
			src:  "tfp_0123456789abcdefghijklmnopqrstuvwxyz0123tfp_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: strings.Repeat("*", 88),
		},
	}

	m := New(WithPatterns(TypeformPersonalAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TypeformPersonalAccessToken_runEndsOutsideTheAlphabet(t *testing.T) {
	// Where a token ends, stated over every byte rather than by example. A body
	// has no count to stop at, so the character that is not one of the
	// alphabet's is the whole of what ends it — and a walk written as one
	// comparison rather than as the ranges it means would end a run at the wrong
	// byte and carry a span past or short of where it stops. The bytes that
	// catch such a walk are the ones just above and just below each range, which
	// no case written by hand reaches.
	//
	// The byte is driven at three places, because the floor makes them three
	// different questions: at the first character of a body, where a byte
	// outside the alphabet leaves no body at all; at the last character the
	// floor asks for, where it leaves one short; and one character past that,
	// where the floor is already met and the byte decides only where the span
	// closes.
	const head = "tfp_"
	const short = "0123456789abcdefghijklmnopqrstuvwxyz012"  // thirty-nine
	const whole = "0123456789abcdefghijklmnopqrstuvwxyz0123" // forty
	const tail = "456789ab"

	p := TypeformPersonalAccessToken()
	for c := range 256 {
		b := byte(c)
		body := isTypeformPersonalAccessTokenByte(b)

		opening := head + string([]byte{b}) + short + tail
		var want []Span
		if body {
			want = []Span{{0, len(opening)}}
		}
		if got, _ := p.Find(opening); !slices.Equal(got, want) {
			t.Errorf("Find(%q) = %v with %q opening the body, want %v", opening, got, b, want)
		}

		fortieth := head + short + string([]byte{b}) + tail
		want = nil
		if body {
			want = []Span{{0, len(fortieth)}}
		}
		if got, _ := p.Find(fortieth); !slices.Equal(got, want) {
			t.Errorf("Find(%q) = %v with %q at the fortieth character, want %v", fortieth, got, b, want)
		}

		past := head + whole + string([]byte{b}) + tail
		want = []Span{{0, len(head) + len(whole)}}
		if body {
			want = []Span{{0, len(past)}}
		}
		if got, _ := p.Find(past); !slices.Equal(got, want) {
			t.Errorf("Find(%q) = %v with %q behind the fortieth character, want %v", past, got, b, want)
		}
	}
}

func Test_TypeformPersonalAccessToken_aTokenBeginningInsideAnother(t *testing.T) {
	// Every character of the prefix belongs to the alphabet a body is written
	// in, so the prefix written twice with a body behind the second is a token
	// from either position. A scan resuming past its match would step over the
	// second and leave it in the output whole; the two spans overlap and a
	// Masker resolves them into one.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token inside a token",
			src:  "tfp_tfp_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{0, 48}, {4, 48}},
		},
		{
			// The prefix three times over, which is three candidates in one run
			// and three spans closing at the same place.
			name: "the prefix three times over",
			src:  "tfp_tfp_tfp_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: []Span{{0, 52}, {4, 52}, {8, 52}},
		},
	}

	m := New(WithPatterns(TypeformPersonalAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := TypeformPersonalAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
			if got, want := m.Mask(tt.src), strings.Repeat("*", len(tt.src)); got != want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, want)
			}
		})
	}
}

func Test_TypeformPersonalAccessToken_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the token through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xtfp_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: "x********************************************",
		},
		{
			name: "underscore before",
			src:  "TYPEFORM_TOKEN_tfp_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want: "TYPEFORM_TOKEN_********************************************",
		},
		{
			// A multi-byte rune written against the token on both sides. Neither
			// UTF-8 encoding shares a byte with the prefix or the body's
			// alphabet, so the token keeps its span exactly as it does against a
			// single-byte character.
			name: "a multi-byte rune before and after",
			src:  "日本語tfp_0123456789abcdefghijklmnopqrstuvwxyz0123日本語",
			want: "日本語********************************************日本語",
		},
	}

	m := New(WithPatterns(TypeformPersonalAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TypeformPersonalAccessToken_leavesWhatFollowsAlone(t *testing.T) {
	// A token carries no character outside the letters, the digits and the
	// underscore, so ordinary punctuation ends one and nothing written after it
	// joins it. That is what keeps the floor from reaching across a log line.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "host",
			src:  "host=tfp_0123456789abcdefghijklmnopqrstuvwxyz0123.example.com",
			want: "host=********************************************.example.com",
		},
		{
			name: "sentence",
			src:  "the token is tfp_0123456789abcdefghijklmnopqrstuvwxyz0123.",
			want: "the token is ********************************************.",
		},
		{
			name: "a query string",
			src:  "?token=tfp_0123456789abcdefghijklmnopqrstuvwxyz0123&page=2",
			want: "?token=********************************************&page=2",
		},
	}

	m := New(WithPatterns(TypeformPersonalAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TypeformPersonalAccessToken_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The prefix is four
	// characters a body is written with, so a run of letters, digits and
	// underscores long enough to spell one carries a candidate, and where forty
	// more of the alphabet stand behind it the run is redacted.
	//
	// They are held to being redacted rather than to being spared. Nothing in
	// the text tells such a run from a token — they are the same bytes — so a
	// scan that let these through would let a real token through with them,
	// which builtin_typeform_personal_access_token.go sets out. What the table
	// is for is that the cases move with the scan: one of them ceasing to be
	// located means the grammar changed, and that is a decision to be taken
	// rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "the prefix inside a snake_case identifier",
			src:  "name=prefix_tfp_0123456789abcdefghijklmnopqrstuvwxyz0123_suffix",
			want: "name=prefix_***************************************************",
		},
		{
			// The whole of an opaque run redacted from the prefix on, where the
			// characters either side of the token belong to no credential.
			name: "the prefix inside a longer run",
			src:  "payload=zzzztfp_0123456789abcdefghijklmnopqrstuvwxyz0123zzzz",
			want: "payload=zzzz************************************************",
		},
		{
			// The shape the rationale names, because base64url is the encoding
			// that writes the underscore and a JWT is three segments of it. The
			// prefix stands inside the payload by chance; the body runs to the
			// dot, which is no character of this alphabet, so the rest of that
			// segment goes and the segment behind it stays. The JWT pattern is
			// not enabled here, so what the case states is this pattern's own
			// reading of the text.
			name: "the prefix inside a jwt payload",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQtfp_0123456789abcdefghijklmnopqrstuvwxyz0123.0123456789abcdef",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ********************************************.0123456789abcdef",
		},
	}

	m := New(WithPatterns(TypeformPersonalAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

// Test_TypeformPersonalAccessToken_holdsATokenTheInputCutShort states, with a
// literal number, what the second return of Find settles: a piece of the prefix
// standing at the end of the input, a candidate the end of the input cut short,
// and a whole match with nothing left unsettled behind it.
func Test_TypeformPersonalAccessToken_holdsATokenTheInputCutShort(t *testing.T) {
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
			src:    "tfp",
			retain: 0,
		},
		{
			name:   "one character of the prefix at the end of the input",
			src:    "t",
			retain: 0,
		},
		{
			name:   "a piece of the prefix behind prose",
			src:    "the token starts with tfp",
			retain: len("the token starts with "),
		},
		{
			// The whole prefix with no body behind it yet. A body arriving would
			// make this a token, so what is unsettled reaches back to where the
			// candidate opened.
			name:   "the whole prefix at the end of the input",
			src:    "tfp_",
			retain: 0,
		},
		{
			name:   "a body the input cuts short of the floor",
			src:    "tfp_0123456789abcdefghijklmnopqrstuvwxyz012",
			retain: 0,
		},
		{
			// A body already past the floor and still running at the end of the
			// input. The span reported here is the text as handed over, and more
			// of the alphabet would carry it further, so the candidate is
			// unsettled even though it is a token.
			name:   "a body past the floor and still running",
			src:    "tfp_0123456789abcdefghijklmnopqrstuvwxyz0123",
			want:   []Span{{0, 44}},
			retain: 0,
		},
		{
			// The run closed by a character outside the alphabet, which is what
			// settles a token: no text appended can lengthen a run that has
			// already ended.
			name:   "a whole token followed by settled text",
			src:    "tfp_0123456789abcdefghijklmnopqrstuvwxyz0123 tail",
			want:   []Span{{0, 44}},
			retain: len("tfp_0123456789abcdefghijklmnopqrstuvwxyz0123 tail"),
		},
		{
			// The same, where the text behind the token ends on a byte the
			// prefix is written with: a piece of a prefix may stand there, so
			// the tail holds from it.
			name:   "a whole token followed by a byte the prefix carries",
			src:    "tfp_0123456789abcdefghijklmnopqrstuvwxyz0123 t",
			want:   []Span{{0, 44}},
			retain: len("tfp_0123456789abcdefghijklmnopqrstuvwxyz0123 "),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := TypeformPersonalAccessToken().Find(tt.src)
			if retain != tt.retain {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, retain, tt.retain)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TypeformPersonalAccessToken_scanIsLinear(t *testing.T) {
	// The prefix is written in the alphabet its own body is read in, so a line of
	// prefixes is one unbroken run that holds a candidate for every four
	// characters it has. A body is read to the end of the run it stands in, and
	// reading that run again at every candidate would cost time quadratic in the
	// length of the line — which is what the cursor over the run is for. The
	// bound here is far above a linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every forty-four bytes where they are densest, because a sample
	// has to carry a whole token to be one. The crowding a line can actually
	// carry stays here.
	sources := map[string]string{
		// An anchor at every byte, none of them opening a candidate at all,
		// which is the cheapest way a position is declined.
		"an anchor every byte": strings.Repeat("p", 2000000),
		// Whole prefixes as close together as they go, inside one run that every
		// candidate in it would otherwise read to the end of. This is the input
		// the cursor is for.
		//
		// It is shorter than the inputs either side of it, and deliberately: a
		// candidate every four bytes is a span every four bytes, so the spans
		// this one reports outweigh the text it is built from, and the memory
		// that costs is paid under the race detector as well. Two hundred
		// thousand candidates over eight hundred thousand bytes is still an
		// input no quadratic scan finishes.
		"a prefix every four characters": strings.Repeat("tfp_", 200000),
		// One candidate whose body is the whole line, which is the walk that
		// reads a run to its end and finds a token at the far side of it.
		"a body that runs the length of the line": "tfp_" + strings.Repeat("a", 2000000),
		// A token beginning inside every token before it, so every candidate the
		// scan opens is a token and none of the walks is wasted.
		"a token beginning inside every token": strings.Repeat("tfp_0123456789abcdefghijklmnopqrstuvwxyz0123", 45000),
		// The same crowding with the run closed every so often, so the cursor is
		// rebuilt rather than answered from once.
		"crowded prefixes in runs that keep ending": strings.Repeat(strings.Repeat("tfp_", 16)+".", 20000),
	}

	checkScanIsLinear(t, TypeformPersonalAccessToken(), sources)
}

// Test_typeformPersonalAccessTokenPrefix holds every character of the prefix to
// being one a body may be written in, which two things rest on.
//
// The scan resumes one byte past the start of a candidate because a token can
// begin inside the body of the one before it, and that holds only while the
// prefix is written in a body's own alphabet. A prefix carrying a character
// outside it would make the two impossible to nest, and the cases above pinning
// the nesting would stand for nothing — which is not a failure anything else
// here reports.
//
// The run cursor rests on the same claim from the other side: what makes a
// remembered run end the right answer for a later candidate is that the later
// body falls inside the run already walked, and a prefix carrying a character
// outside the alphabet would end that run between the two.
func Test_typeformPersonalAccessTokenPrefix(t *testing.T) {
	if typeformPersonalAccessTokenPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for i := range len(typeformPersonalAccessTokenPrefix) {
		if c := typeformPersonalAccessTokenPrefix[i]; !isTypeformPersonalAccessTokenByte(c) {
			t.Errorf("the prefix holds %q, which no body may be written with", c)
		}
	}
}

// Test_typeformPersonalAccessTokenFindBenchmarks_lineTheAnchorWasChosenAgainst
// holds the line the benchmarks are written on to carrying what the choice of
// anchor was counted over, and to opening candidates the scan then turns away.
//
// Both halves are needed and neither reports the other. A line that came to
// carry the anchor nowhere would time a search that stops nowhere, which is a
// benchmark getting faster while the scan stands still; a line that came to hold
// a whole prefix would time a body being read where the case says none is. The
// span count in the case holds neither: a value is what it rules out, and a
// candidate is not a value.
//
// The counts are the two characters apart rather than the anchor alone, because
// what the rationale weighs is the anchor against the alternative. A line
// rewritten until the underscore outnumbered the p would leave that comparison
// resting on text that no longer shows it.
func Test_typeformPersonalAccessTokenFindBenchmarks_lineTheAnchorWasChosenAgainst(t *testing.T) {
	line := typeformPersonalAccessTokenFindBenchmarks()[0].src

	counts := map[byte]int{'t': 6, 'f': 6, 'p': 5, '_': 2}
	for c, want := range counts {
		if got := strings.Count(line, string(c)); got != want {
			t.Errorf("the line carries %q %d times, where the choice of anchor was measured over %d", c, got, want)
		}
	}

	want, ok := counts[typeformPersonalAccessTokenAnchor]
	if !ok {
		t.Fatalf("the scan searches for %q, which is no character of the prefix %q", byte(typeformPersonalAccessTokenAnchor), typeformPersonalAccessTokenPrefix)
	}

	candidates := 0
	for i := typeformPersonalAccessTokenAnchorIndex; i < len(line); i++ {
		if line[i] != typeformPersonalAccessTokenAnchor {
			continue
		}
		candidates++
		if start := i - typeformPersonalAccessTokenAnchorIndex; strings.HasPrefix(line[start:], typeformPersonalAccessTokenPrefix) {
			t.Errorf("the line holds a whole prefix at %d, so the case times a body being read where it says no token stands", start)
		}
	}
	if candidates != want {
		t.Errorf("the line opens %d candidates where the anchor stands on it %d times, so the search is not stopping where the count says", candidates, want)
	}
}

// Test_typeformPersonalAccessTokenAnchor holds the prefix to carrying the byte
// the scan searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_typeformPersonalAccessTokenAnchor(t *testing.T) {
	if typeformPersonalAccessTokenAnchorIndex >= len(typeformPersonalAccessTokenPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", typeformPersonalAccessTokenAnchorIndex, len(typeformPersonalAccessTokenPrefix))
	}
	if c := typeformPersonalAccessTokenPrefix[typeformPersonalAccessTokenAnchorIndex]; c != typeformPersonalAccessTokenAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(typeformPersonalAccessTokenAnchor))
	}
}

func Test_isTypeformPersonalAccessTokenByte(t *testing.T) {
	// The alphabet stated over every byte rather than by example: the letters of
	// both cases, the digits and the underscore, and nothing else. The hyphen is
	// the byte this says most about, since it is what separates this alphabet
	// from base64url and what the rationale declines on the evidence it weighs.
	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9' ||
			'A' <= b && b <= 'Z' ||
			'a' <= b && b <= 'z' ||
			b == '_'
		if got := isTypeformPersonalAccessTokenByte(b); got != want {
			t.Errorf("isTypeformPersonalAccessTokenByte(%q) = %v, want %v", b, got, want)
		}
	}
}

// referenceTypeformPersonalAccessTokenFind is the statement of what a Typeform
// personal access token is, written out the plain way and kept here so that the
// scan in builtin_typeform_personal_access_token.go can be held to it: every
// position is asked about in turn, with nothing remembered between them.
//
// The prefix, the floor and the alphabet are spelled again rather than built
// from typeformPersonalAccessTokenPrefix, the count beside it and the scan's own
// byte test. A reference sharing those declarations could not disagree with the
// scan about them, and it is exactly that disagreement the fuzz target below is
// for: the two have to be changed together or reported apart.
//
// It is written out rather than built on an expression, and
// builtin_typeform_personal_access_token.go carries the timings that decided
// it, together with why thirty seconds of this target is not where the
// difference shows.
//
// Every position is asked about rather than resumed past, because a token can
// begin inside one: every character of the prefix is written in the alphabet a
// body is, so the prefix twice over with a body behind it holds a token that
// resuming would step over. The scan finds both and reports the two spans
// overlapping for a Masker to resolve, so the reference must ask about both.
func referenceTypeformPersonalAccessTokenFind(src string) []Span {
	var spans []Span
	for i := range len(src) {
		if !strings.HasPrefix(src[i:], "tfp_") {
			continue
		}
		body := i + len("tfp_")
		end := body
		for end < len(src) && isReferenceTypeformPersonalAccessTokenByte(src[end]) {
			end++
		}
		if end-body >= 40 {
			spans = append(spans, Span{Start: i, End: end})
		}
	}
	return spans
}

// isReferenceTypeformPersonalAccessTokenByte reports whether c is a character a
// body may be written with: the letters of both cases, the digits and the
// underscore, spelled out here rather than read from the scan's own alphabet.
func isReferenceTypeformPersonalAccessTokenByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z' ||
		c == '_'
}

// FuzzTypeformPersonalAccessToken_matchesReference guards the hand-written scan:
// the prefix it searches for, the floor it holds a body to, the alphabet it
// reads one in, the cursor it remembers a run by and the byte it resumes at may
// none of them change which tokens are located.
func FuzzTypeformPersonalAccessToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("TYPEFORM_TOKEN=tfp_0123456789abcdefghijklmnopqrstuvwxyz0123")
	f.Add("Authorization: Bearer tfp_0123456789abcdefghijklmnopqrstuvwxyz0123")
	f.Add(`{"token":"tfp_0123456789abcdefghijklmnopqrstuvwxyz0123"}`)
	f.Add("tfp_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklm") // the width betterleaks reads
	f.Add("tfp_0123456789abcdefghijklmnopqrstuvwxyz0123_456789ab")           // the shape Typeform's own rule reads
	f.Add("tfp_0123456789abcdefghijklmnopqrstuvwxyz012")                     // one short of the floor
	f.Add("tfp_0123456789abcdefghijklmnopqrstuvwxyz01234")                   // one longer than it
	f.Add("tfp__0123456789abcdefghijklmnopqrstuvwxyz012")                    // a body opening on an underscore
	f.Add("tfp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123")                    // a body of uppercase letters
	f.Add("TFP_0123456789abcdefghijklmnopqrstuvwxyz0123")                    // an uppercase prefix
	f.Add("tfp-0123456789abcdefghijklmnopqrstuvwxyz0123")                    // a hyphen where it carries an underscore
	f.Add("tfp0123456789abcdefghijklmnopqrstuvwxyz01234")                    // the underscore left out
	f.Add("tfp_-123456789abcdefghijklmnopqrstuvwxyz0123")                    // a hyphen where the body opens
	f.Add("tfp_0123456789abcdefghijklmnopqrstuvwxyz01.3")                    // a dot short of the floor
	f.Add("tfp_0123456789abcdefghijklmnopqrstuvwxy 0123")                    // and a space
	f.Add("tfp_0123456789abcdefghijklmnopqrstuvwxyz0123_suffix")             // a body character joins what follows
	f.Add("tfp_0123456789abcdefghijklmnopqrstuvwxyz0123.next")
	f.Add("tfp_0123456789abcdefghijklmnopqrstuvwxyz0123\ntfp_0123456789abcdefghijklmnopqrstuvwxyz0123")
	// A token beginning inside the match before it, which a scan resuming past a
	// match steps over, and two tokens with nothing between them, which is the
	// same text without the overlap.
	f.Add("tfp_tfp_0123456789abcdefghijklmnopqrstuvwxyz0123")
	f.Add("tfp_tfp_tfp_0123456789abcdefghijklmnopqrstuvwxyz0123")
	f.Add("tfp_0123456789abcdefghijklmnopqrstuvwxyz0123tfp_0123456789abcdefghijklmnopqrstuvwxyz0123")
	// Candidate positions crowded as close as they can be: every fourth byte,
	// and a run that is a body to every candidate in it. The run is left open at
	// the end of one and closed at the end of the other, which is where the
	// cursor answers differently.
	f.Add(strings.Repeat("tfp_", 8))
	f.Add(strings.Repeat("tfp_", 32))
	f.Add(strings.Repeat("tfp_", 32) + "!")
	f.Add(strings.Repeat("tfp_", 16) + "." + strings.Repeat("tfp_", 16))
	f.Add("tfp_" + strings.Repeat("a", 200))
	// The prefix written inside a run of the alphabet, which is the over-match
	// the pattern admits.
	f.Add("payload=zzzztfp_0123456789abcdefghijklmnopqrstuvwxyz0123zzzz")
	f.Add("name=prefix_tfp_0123456789abcdefghijklmnopqrstuvwxyz0123_suffix")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQtfp_0123456789abcdefghijklmnopqrstuvwxyz0123.0123456789abcdef")
	// The vendor's own name, which carries the byte the scan searches for at the
	// index it reads a candidate back from.
	f.Add("https://api.typeform.com/forms/abc123/responses")

	fuzzAgainstReference(f, TypeformPersonalAccessToken().Find, referenceTypeformPersonalAccessTokenFind)
}

// typeformPersonalAccessTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func typeformPersonalAccessTokenFindBenchmarks() []benchmarkCase {
	// A line from the place a token is actually written, a job reading
	// responses out of the API. It carries both of the shapes the choice of
	// anchor was measured over — snake_case field names, which an underscore
	// stops the search at, and the vendor's own host name, which carries the
	// byte the scan searches for — so what it times is a search stopping where
	// a caller's text really makes it stop, with every stop turned away on the
	// comparison of the prefix.
	// Test_typeformPersonalAccessTokenFindBenchmarks_lineTheAnchorWasChosenAgainst
	// holds it to carrying what was counted.
	line := `time=2026-09-17T00:00:00Z level=info msg="fetching responses" form_id=abc123 request_id=0123456789abcdef url=https://api.typeform.com/forms/abc123/responses `
	token := "tfp_0123456789abcdefghijklmnopqrstuvwxyz0123"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is four characters a body is written with, so a run can
			// hold a candidate for every four it has. Here each of them reads as
			// far as the character that is not one, which stands where the run
			// ends: the crowding this pattern admits, with no value at the end of
			// any of it.
			name:  "candidates that are not values",
			src:   strings.Repeat("tfp_tfp_tfp_.", 16),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "token=" + token,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "token=" + token,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"token="+token+"\n", 32),
			spans: 32,
		},
	}
}
