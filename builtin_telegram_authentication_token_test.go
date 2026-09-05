package mask

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The Telegram authentication token pattern: what it locates and what it leaves
// alone, written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The values written out below are made of ordered characters: valid in shape,
// obviously not real. The identifier is the ordered run of digits with the zero
// taken away, since a token opens on no zero. A secret is the head, then the
// run carried on through the alphabet as far as the width allows, then a last
// character written for the padding — the run reaches a character neither width
// may close on, so no secret here is the run alone.

const (
	// telegramAuthenticationTokenTestID is nine digits, which is what the
	// identifier on Telegram's own BotFather page is, and
	// telegramAuthenticationTokenTestIDWide is the widest an identifier may be.
	telegramAuthenticationTokenTestID     = "123456789"
	telegramAuthenticationTokenTestIDWide = "1234567890123456"

	// The two widths a secret is written to, thirty-four and thirty-five.
	telegramAuthenticationTokenTestBody     = "A0123456789abcdefghijklmnopqrstuvw"
	telegramAuthenticationTokenTestBodyWide = "A0123456789abcdefghijklmnopqrstuvwA"

	// The far ends of the alphabet, at the ends of a body and not only inside
	// it. The two above carry the digits and the lowercase letters and nothing
	// else, so the hyphen, the underscore and both ends of both letter ranges
	// stand in no case at all — and a scan or a reference that stopped
	// admitting them would go on passing everything else written here.
	// The second opens on two of the A the head asks for rather than one, which
	// is the wider of the two readings the public rules are written to.
	telegramAuthenticationTokenTestBodyEdges   = "A_0123456789abcdefghijklmnopqrst-w"
	telegramAuthenticationTokenTestBodyLetters = "AA0123456789abcdefghijklmnopqrZzgw"
)

// Test_telegramAuthenticationTokenTestValues holds the values above to the
// widths they are named for. Every case below is written against one of them,
// so a value miscounted here is a table that agrees with the scan about a width
// neither of them is reading.
func Test_telegramAuthenticationTokenTestValues(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want int
	}{
		{name: "the identifier", src: telegramAuthenticationTokenTestID, want: 9},
		{name: "the widest identifier", src: telegramAuthenticationTokenTestIDWide, want: 16},
		{name: "the narrower secret", src: telegramAuthenticationTokenTestBody, want: 34},
		{name: "the wider secret", src: telegramAuthenticationTokenTestBodyWide, want: 35},
		{name: "a secret ending on the alphabet", src: telegramAuthenticationTokenTestBodyEdges, want: 34},
		{name: "a secret reaching both ends of both letter ranges", src: telegramAuthenticationTokenTestBodyLetters, want: 34},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(tt.src); got != tt.want {
				t.Errorf("%q is %d characters, want %d", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TelegramAuthenticationToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "123456789:A0123456789abcdefghijklmnopqrstuvw",
			want: []Span{{0, 44}},
		},
		{
			name: "a token written to the wider of the two widths",
			src:  "123456789:A0123456789abcdefghijklmnopqrstuvwA",
			want: []Span{{0, 45}},
		},
		{
			// The Bot API is called with the token written into the path,
			// behind the word bot and with no separator between the two, so a
			// letter in front of an identifier may not turn a candidate away.
			name: "a token in a Bot API request path",
			src:  "https://api.telegram.org/bot123456789:A0123456789abcdefghijklmnopqrstuvw/sendMessage",
			want: []Span{{28, 72}},
		},
		{
			name: "an environment assignment",
			src:  "TELEGRAM_TOKEN=123456789:A0123456789abcdefghijklmnopqrstuvw",
			want: []Span{{15, 59}},
		},
		{
			name: "a quoted value in JSON",
			src:  `{"token": "123456789:A0123456789abcdefghijklmnopqrstuvw"}`,
			want: []Span{{11, 55}},
		},
		{
			name: "an identifier of one digit",
			src:  "1:A0123456789abcdefghijklmnopqrstuvw",
			want: []Span{{0, 36}},
		},
		{
			name: "an identifier of the widest count",
			src:  "1234567890123456:A0123456789abcdefghijklmnopqrstuvw",
			want: []Span{{0, 51}},
		},
		{
			name: "a secret opening and closing on the ends of its alphabet",
			src:  "123456789:A_0123456789abcdefghijklmnopqrst-w",
			want: []Span{{0, 44}},
		},
		{
			// The first character of a secret is a letter here, and the last
			// two are the ends of the two letter ranges. The A the rulesets
			// ask for at the head is written as well, and located rather than
			// asked for.
			name: "a secret reaching both ends of both letter ranges",
			src:  "123456789:AA0123456789abcdefghijklmnopqrZzgw",
			want: []Span{{0, 44}},
		},
		{
			// A token whose secret closes on digits, with the next token
			// opening at those digits: the colon that opens the second is the
			// character that closes the first secret's run, so both are values
			// and their spans overlap. A scan resuming past a match rather
			// than a byte along would report the first alone and leave the
			// whole of the second secret in the text.
			name: "a token opening inside the secret of the one in front of it",
			src:  "123456789:A0123456789abcdefghijklmnopqrstuv40:A0123456789abcdefghijklmnopqrstuvw",
			want: []Span{{0, 45}, {43, 80}},
		},
		{
			name: "two tokens on one line",
			src:  "123456789:A0123456789abcdefghijklmnopqrstuvw 987654321:A0123456789abcdefghijklmnopqrstuvwA",
			want: []Span{{0, 44}, {45, 90}},
		},
		{
			// A colon behind a number is what a log line writes anyway, and the
			// scan reads every one of them. What it takes is the one with a
			// secret behind it.
			name: "a token on a line that writes other colons",
			src:  "12:00:01 sending as 123456789:A0123456789abcdefghijklmnopqrstuvw",
			want: []Span{{20, 64}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := TelegramAuthenticationToken().Find(tt.src)
			if !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TelegramAuthenticationToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a secret one character short of the narrower width",
			src:  "123456789:0123456789abcdefghijklmnopqrstuvw",
		},
		{
			name: "a secret one character past the wider width",
			src:  "123456789:A0123456789abcdefghijklmnopqrstuvwAz",
		},
		{
			name: "a run of the alphabet far longer than any secret",
			src:  "123456789:A0123456789abcdefghijklmnopqrstuvwA0123456789abcdefghijklmnopqrstuvw",
		},
		{
			// The whole of the run is what a secret has to be, so a character
			// of the alphabet written against the end of one takes it away.
			name: "a character of the alphabet written behind a secret",
			src:  "123456789:A0123456789abcdefghijklmnopqrstuvwA0",
		},
		{
			name: "a hyphen written behind a secret",
			src:  "123456789:A0123456789abcdefghijklmnopqrstuvwA-",
		},
		{
			name: "an underscore written behind a secret",
			src:  "123456789:A0123456789abcdefghijklmnopqrstuvwA_",
		},
		{
			// A character the body excludes, at the front of one: the run
			// begins behind it and is a character short.
			name: "a full stop written at the front of a secret",
			src:  "123456789:.123456789abcdefghijklmnopqrstuvwx",
		},
		{
			name: "a full stop written inside a secret",
			src:  "123456789:0123456789abcdefg.ijklmnopqrstuvwxy",
		},
		{
			name: "a plus sign written at the end of a secret",
			src:  "123456789:0123456789abcdefghijklmnopqrstuv+",
		},
		{
			name: "a secret opening on a character that is not the head",
			src:  "123456789:B0123456789abcdefghijklmnopqrstuvw",
		},
		{
			// The padding: thirty-four characters leave four bits over, so a
			// secret of that width closes on one of four characters and x is
			// none of them.
			name: "a secret of the narrower width closing on a character the padding excludes",
			src:  "123456789:A0123456789abcdefghijklmnopqrstuvx",
		},
		{
			// Thirty-five leave two bits over, so a secret of that width
			// closes on one of sixteen. The character here is admitted at
			// neither width.
			name: "a secret of the wider width closing on a character the padding excludes",
			src:  "123456789:A0123456789abcdefghijklmnopqrstuvwx",
		},
		{
			// Neither width may close on a hyphen or an underscore: the
			// padding admits neither, at either width.
			name: "a secret closing on an underscore",
			src:  "123456789:A_0123456789abcdefghijklmnopqrst-_",
		},
		{
			// The text this pattern would redact out of a log if it read the
			// widths alone. An AWS service prefix ends in a digit and an IAM
			// action is written straight behind the colon, at exactly these
			// widths, in exactly this alphabet.
			name: "an iam action behind a service prefix ending in a digit",
			src:  "denied: user is not authorized to perform ec2:DescribeNetworkInterfacePermissions",
		},
		{
			name: "an iam condition key behind a service prefix ending in a digit",
			src:  `{"ForAllValues:StringEquals":{"route53:ChangeResourceRecordSetsRecordTypes":["NS"]}}`,
		},
		{
			// A Go module checksum, whose h1: is a digit and a colon and whose
			// body is base64 — which the run reads until it reaches a + or a /.
			name: "a go module checksum",
			src:  "github.com/foo/bar v1.2.3 h1:iEmbIRk4brAP3wevhCr5MGAqxHUbbIDHvE+9YrsZAlU=",
		},
		{
			name: "an algorithm name behind its object identifier",
			src:  "224:id-rsassa-pkcs1-v1_5-with-sha3-224",
		},
		{
			name: "a feature flag behind its version",
			src:  `"@aws-cdk/aws-elbv2:albListnerRuleDefaultActionReplaced": true`,
		},
		{
			name: "an identifier opening on a zero",
			src:  "023456789:A0123456789abcdefghijklmnopqrstuvw",
		},
		{
			name: "an identifier one digit past the widest count",
			src:  "12345678901234567:A0123456789abcdefghijklmnopqrstuvw",
		},
		{
			name: "no identifier at all",
			src:  ":A0123456789abcdefghijklmnopqrstuvw",
		},
		{
			name: "a letter where the identifier goes",
			src:  "abcdefghi:A0123456789abcdefghijklmnopqrstuvw",
		},
		{
			name: "no separator between the identifier and the secret",
			src:  "123456789 A0123456789abcdefghijklmnopqrstuvw",
		},
		{
			name: "a full stop where the separator goes",
			src:  "123456789.A0123456789abcdefghijklmnopqrstuvw",
		},
		{
			name: "a space between the separator and the secret",
			src:  "123456789: A0123456789abcdefghijklmnopqrstuvw",
		},
		{
			name: "a secret with no separator or identifier in front of it",
			src:  "A0123456789abcdefghijklmnopqrstuvw",
		},
		{
			name: "a log line that writes a number, a colon and a message",
			src:  "line 42: the request was refused by the upstream service",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := TelegramAuthenticationToken().Find(tt.src); got != nil {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_TelegramAuthenticationToken_inContext(t *testing.T) {
	// Forty-four and forty-five are spelled here rather than worked out from
	// the counts the scan reads. What these cases state is how much of a line
	// comes back redacted, and an expectation built from those counts comes
	// back agreeing with them whatever they are changed to.
	stars := strings.Repeat("*", 44)
	starsWide := strings.Repeat("*", 45)

	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			// The identifier is redacted with the secret. A caller wanting the
			// bot named in the log is naming it themselves; what the token
			// authorizes is the whole of it.
			name: "a log line",
			src:  `level=error msg="getMe failed" token=123456789:A0123456789abcdefghijklmnopqrstuvw`,
			want: `level=error msg="getMe failed" token=` + stars,
		},
		{
			name: "a request path",
			src:  "GET https://api.telegram.org/bot123456789:A0123456789abcdefghijklmnopqrstuvwA/getUpdates 200",
			want: "GET https://api.telegram.org/bot" + starsWide + "/getUpdates 200",
		},
		{
			name: "text that carries no token",
			src:  "the bot answered in 42:00 minutes, which is 2520 seconds",
			want: "the bot answered in 42:00 minutes, which is 2520 seconds",
		},
	}

	m := New(WithPatterns(TelegramAuthenticationToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

// Test_TelegramAuthenticationToken_readsNoFurtherBackThanLookBehind holds the
// scan to the one byte it reads in front of a value.
//
// That byte is the one in front of the identifier, and it is what says the
// digits are the whole of their run. Everything else the scan reads is inside
// the value it reports, identifier included, so there is no count to build a
// widest reading out of — what this drives instead is that the byte is read at
// all, from a window opening exactly on the value, which is the narrowest text
// a stream can hand a Find.
func Test_TelegramAuthenticationToken_readsNoFurtherBackThanLookBehind(t *testing.T) {
	value := telegramAuthenticationTokenTestID + ":" + telegramAuthenticationTokenTestBody

	widest := telegramAuthenticationTokenTestIDWide + ":" + telegramAuthenticationTokenTestBody
	src := "9" + widest
	if got, _ := TelegramAuthenticationToken().Find(src); got != nil {
		t.Errorf("Find(%q) = %v, want no span: the digit in front carries the run past the count", src, got)
	}

	want := []Span{{0, len(value)}}
	if got, _ := TelegramAuthenticationToken().Find(value); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", value, got, want)
	}
	if 1 > LookBehind {
		t.Errorf("the scan reads 1 byte in front of a value, LookBehind is %d", LookBehind)
	}
}

// Test_TelegramAuthenticationToken_settles holds the scan to the offset it
// reports alongside its spans, which the tables above leave to the shared
// properties and which those cannot state for a candidate of this shape.
func Test_TelegramAuthenticationToken_settles(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "a line holding nothing",
			src:  "a line of prose, and nothing else at all\n",
			want: 41,
		},
		{
			// A number at the end of the input may be the front of an
			// identifier, so nothing from where it begins is settled.
			name: "a number at the end of the input",
			src:  "the count is 123456789",
			want: 13,
		},
		{
			name: "a number one digit past the widest identifier",
			src:  "the count is 12345678901234567",
			want: 30,
		},
		{
			name: "a number opening on a zero",
			src:  "the count is 0123456789",
			want: 23,
		},
		{
			name: "a separator at the end of the input",
			src:  "123456789:",
			want: 0,
		},
		{
			// The character a secret opens with is written and is not the
			// head, so no text arriving makes a secret of what stands here and
			// there is nothing to hold on to.
			name: "a candidate whose secret opens on the wrong character",
			src:  "123456789:B0123456789abcdefghij",
			want: 31,
		},
		{
			name: "a secret the end of the input cut short",
			src:  "123456789:A0123456789abcdefghij",
			want: 0,
		},
		{
			// The span is reported and the text is not settled: another
			// character of the alphabet carries the run to the wider width, and
			// one more takes it past both.
			name: "a whole token at the end of the input",
			src:  "123456789:A0123456789abcdefghijklmnopqrstuvw",
			want: 0,
		},
		{
			name: "a run already past every width a secret is written to",
			src:  "123456789:A0123456789abcdefghijklmnopqrstuvwAz",
			want: 46,
		},
		{
			// The text in front of a candidate the end cut short was settled
			// before that candidate opened.
			name: "a candidate behind a line of prose",
			src:  "a line of prose, and nothing else at all\n123456789:A012",
			want: 41,
		},
		{
			name: "a token followed by a line break",
			src:  "123456789:A0123456789abcdefghijklmnopqrstuvw\n",
			want: 45,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, got := TelegramAuthenticationToken().Find(tt.src); got != tt.want {
				t.Errorf("Find(%q) settled %d, want %d", tt.src, got, tt.want)
			}
		})
	}
}

func Test_telegramAuthenticationTokenIDStart(t *testing.T) {
	tests := []struct {
		name  string
		src   string
		sep   int
		want  int
		wanOK bool
	}{
		{name: "digits with nothing in front of them", src: "123456789:", sep: 9, want: 0, wanOK: true},
		{name: "digits behind a letter", src: "bot123456789:", sep: 12, want: 3, wanOK: true},
		{name: "one digit", src: "x1:", sep: 2, want: 1, wanOK: true},
		{name: "the widest count", src: "x1234567890123456:", sep: 17, want: 1, wanOK: true},
		{name: "one digit past the widest count", src: "x12345678901234567:", sep: 18, wanOK: false},
		{name: "no digits at all", src: "x:", sep: 1, wanOK: false},
		{name: "a leading zero", src: "0123456789:", sep: 10, wanOK: false},
		{name: "a leading zero behind a letter", src: "x0123456789:", sep: 11, want: 0, wanOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := telegramAuthenticationTokenIDStart(tt.src, tt.sep)
			if ok != tt.wanOK {
				t.Fatalf("telegramAuthenticationTokenIDStart(%q, %d) reported %v, want %v", tt.src, tt.sep, ok, tt.wanOK)
			}
			if ok && got != tt.want {
				t.Errorf("telegramAuthenticationTokenIDStart(%q, %d) = %d, want %d", tt.src, tt.sep, got, tt.want)
			}
		})
	}
}

func Test_telegramAuthenticationTokenBodyEnd(t *testing.T) {
	// A run reaching the end of the input is unsettled wherever it is short of
	// the widest width, whether or not it is already wide enough to be a
	// secret: text arriving carries it on either way. The two answers are
	// separate results and are asked for separately here.
	tests := []struct {
		name    string
		src     string
		want    int
		wantOK  bool
		wantCut bool
	}{
		{
			name:   "one short of the narrower width",
			src:    "A0123456789abcdefghijklmnopqrstuv ",
			wantOK: false,
		},
		{
			name:   "the narrower width exactly",
			src:    "A0123456789abcdefghijklmnopqrstuvw ",
			want:   34,
			wantOK: true,
		},
		{
			name:   "the wider width exactly",
			src:    "A0123456789abcdefghijklmnopqrstuvwA ",
			want:   35,
			wantOK: true,
		},
		{
			name:   "one past the wider width",
			src:    "A0123456789abcdefghijklmnopqrstuvwAz ",
			wantOK: false,
		},
		{
			name:    "a run the end of the input cut short",
			src:     "A0123456789abcdefghij",
			wantOK:  false,
			wantCut: true,
		},
		{
			name:    "the narrower width at the end of the input",
			src:     "A0123456789abcdefghijklmnopqrstuvw",
			want:    34,
			wantOK:  true,
			wantCut: true,
		},
		{
			name:    "the wider width at the end of the input",
			src:     "A0123456789abcdefghijklmnopqrstuvwA",
			want:    35,
			wantOK:  true,
			wantCut: true,
		},
		{
			// Already past every width a secret is written to, so no text
			// appended to it makes one and the answer is settled.
			name:   "a run past the wider width at the end of the input",
			src:    "A0123456789abcdefghijklmnopqrstuvwAz",
			wantOK: false,
		},
		{
			name:    "nothing at all",
			src:     "",
			wantOK:  false,
			wantCut: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			end, ok, cut := telegramAuthenticationTokenBodyEnd(tt.src, 0)
			if ok != tt.wantOK || cut != tt.wantCut {
				t.Fatalf("telegramAuthenticationTokenBodyEnd(%q, 0) reported ok=%v cut=%v, want ok=%v cut=%v",
					tt.src, ok, cut, tt.wantOK, tt.wantCut)
			}
			if ok && end != tt.want {
				t.Errorf("telegramAuthenticationTokenBodyEnd(%q, 0) = %d, want %d", tt.src, end, tt.want)
			}
		})
	}
}

func Test_telegramAuthenticationTokenIDTail(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want int
	}{
		{name: "nothing at all", src: "", want: 0},
		{name: "text closing on no digit", src: "a line of prose", want: 15},
		{name: "digits at the end", src: "sent 123456789", want: 5},
		{name: "digits at the front of the input", src: "123456789", want: 0},
		{name: "digits one past the widest count", src: "x12345678901234567", want: 18},
		{name: "digits at the widest count", src: "x1234567890123456", want: 1},
		{name: "digits opening on a zero", src: "x0123456789", want: 11},
		{name: "a separator at the end", src: "123456789:", want: 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := telegramAuthenticationTokenIDTail(tt.src); got != tt.want {
				t.Errorf("telegramAuthenticationTokenIDTail(%q) = %d, want %d", tt.src, got, tt.want)
			}
		})
	}
}

func Test_isTelegramAuthenticationTokenDigit(t *testing.T) {
	// The identifier's alphabet is what a candidate is read back from, so it is
	// stated over every byte rather than by example.
	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9'
		if got := isTelegramAuthenticationTokenDigit(b); got != want {
			t.Errorf("isTelegramAuthenticationTokenDigit(%q) = %v, want %v", b, got, want)
		}
	}

	// The separator is not a digit, which is what stops the walk back from
	// reading over the colon of the token in front of this one.
	if isTelegramAuthenticationTokenDigit(telegramAuthenticationTokenSeparator) {
		t.Error("the separator reads as a digit, so the walk back over an identifier does not stop at one")
	}
}

// Test_telegramAuthenticationTokenSeparator holds the byte the scan searches
// the input for to being the one the grammar puts between an identifier and a
// secret, and to standing outside both of their alphabets.
//
// A separator respelled would be a separator no candidate is ever found at, and
// builtin_scan.go says why that is held here rather than left to the target
// below. A separator drawn from either alphabet would be worse than that: the
// walk back over the identifier or the walk forward over the secret would read
// straight through it.
func Test_telegramAuthenticationTokenSeparator(t *testing.T) {
	if telegramAuthenticationTokenSeparator != ':' {
		t.Errorf("the scan searches for %q, the grammar writes a colon", byte(telegramAuthenticationTokenSeparator))
	}
	if isTelegramAuthenticationTokenDigit(telegramAuthenticationTokenSeparator) {
		t.Error("the separator is a digit, so an identifier reads through it")
	}
	if isBase64URLByte(telegramAuthenticationTokenSeparator) {
		t.Error("the separator is in the secret's alphabet, so a secret reads through it")
	}
}

// Test_telegramAuthenticationTokenBodyValue holds the six bits a character
// stands for to the alphabet the run is read by.
//
// The two are separate declarations — isBase64URLByte (builtin_scan.go) says
// which characters a run may hold, this says what each of them weighs — and a
// character one admits and the other cannot weigh is two grammars for one
// alphabet: the walk would carry a run to a width and the padding would then be
// asked about a character it reads as nothing. So the two are held to admitting
// exactly the same bytes, and the weights to being each of the sixty-four once.
func Test_telegramAuthenticationTokenBodyValue(t *testing.T) {
	seen := map[int]byte{}
	for c := range 256 {
		b := byte(c)
		v := telegramAuthenticationTokenBodyValue(b)
		if got, want := v >= 0, isBase64URLByte(b); got != want {
			t.Errorf("telegramAuthenticationTokenBodyValue(%q) = %d, the alphabet says %v", b, v, want)
			continue
		}
		if v < 0 {
			continue
		}
		if v >= 64 {
			t.Errorf("telegramAuthenticationTokenBodyValue(%q) = %d, which is no six-bit value", b, v)
			continue
		}
		if other, ok := seen[v]; ok {
			t.Errorf("telegramAuthenticationTokenBodyValue reads %q and %q as %d", other, b, v)
			continue
		}
		seen[v] = b
	}
	if len(seen) != 64 {
		t.Errorf("the alphabet weighs %d characters, base64url has 64", len(seen))
	}

	// The character a secret opens with is base64url's zero, which is what the
	// rationale reads as the secret's first byte being zero.
	if v := telegramAuthenticationTokenBodyValue(telegramAuthenticationTokenBodyHead); v != 0 {
		t.Errorf("the head %q weighs %d, want 0", byte(telegramAuthenticationTokenBodyHead), v)
	}
}

// Test_telegramAuthenticationTokenBodyDecodes holds the padding rule to the
// characters each width may close on.
//
// The set is worked out here from the width rather than read off the scan's
// masks: bits over is what a width leaves, and a character may close a body
// only where the bits it writes into them are zero. A mask written the wrong
// way round would admit four times too many characters at one width and a
// quarter as many at the other, which no case elsewhere would report — the
// tables above drive one character at each end, and the fuzz target would have
// to write thirty-four of the alphabet against a digit run by chance.
func Test_telegramAuthenticationTokenBodyDecodes(t *testing.T) {
	// A remainder of one is no base64url at any content: one character carries
	// six bits and a byte needs eight.
	for _, c := range []byte{'A', 'Q', 'g', 'w', 'x', '-', '_'} {
		if telegramAuthenticationTokenBodyDecodes(c, 33) {
			t.Errorf("a body of 33 characters closing on %q decodes, and no body of that width does", c)
		}
	}

	tests := []struct {
		name  string
		n     int
		over  int
		count int
	}{
		{name: "the narrower width leaves four bits", n: telegramAuthenticationTokenBodyMin, over: 4, count: 4},
		{name: "the wider width leaves two bits", n: telegramAuthenticationTokenBodyMax, over: 2, count: 16},
		{name: "a multiple of four leaves none", n: 36, over: 0, count: 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := 0
			for c := range 256 {
				b := byte(c)
				if !isBase64URLByte(b) {
					continue
				}
				want := telegramAuthenticationTokenBodyValue(b)%(1<<tt.over) == 0
				if got := telegramAuthenticationTokenBodyDecodes(b, tt.n); got != want {
					t.Errorf("telegramAuthenticationTokenBodyDecodes(%q, %d) = %v, want %v", b, tt.n, got, want)
				}
				if want {
					n++
				}
			}
			if n != tt.count {
				t.Errorf("%d character(s) may close a body of %d, want %d", n, tt.n, tt.count)
			}
		})
	}
}

// referenceTelegramAuthenticationTokenFind is the plain implementation the scan
// is held to. It spells the counts and both alphabets out again rather than
// reading the declarations beside the scan, which is what lets the two disagree
// and the target below report it.
//
// It asks at every byte rather than resuming past a match. A secret is written
// in an alphabet that carries the digits, so a run of them inside one is a
// position an identifier could open at, and only the separator behind such a
// run — which the alphabet does not admit, so it closes the secret it would
// stand in — rules the position out. Asking at every byte is what keeps the
// reference from having to know that.
func referenceTelegramAuthenticationTokenFind(src string) []Span {
	const (
		idMax   = 16
		bodyMin = 34
		bodyMax = 35
	)
	digit := func(c byte) bool { return '0' <= c && c <= '9' }
	body := func(c byte) bool {
		return '0' <= c && c <= '9' ||
			'A' <= c && c <= 'Z' ||
			'a' <= c && c <= 'z' ||
			c == '-' || c == '_'
	}
	// The padding, spelled the long way round: the alphabet written out in
	// order, the leftover bits found by index, and the count of them taken
	// from the width. The scan reads the same rule off a switch on the
	// remainder and a mask.
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	head := func(b string) bool { return len(b) > 0 && b[0] == 'A' }
	decodes := func(b string) bool {
		over := map[int]int{0: 0, 1: -1, 2: 4, 3: 2}[len(b)%4]
		if over < 0 {
			return false
		}
		return strings.IndexByte(alphabet, b[len(b)-1])%(1<<over) == 0
	}

	var spans []Span
	for start := range len(src) {
		// The identifier: the whole of a run of digits, no wider than the
		// count and opening on no zero.
		if start > 0 && digit(src[start-1]) {
			continue
		}
		if !digit(src[start]) || src[start] == '0' {
			continue
		}
		i := start
		for i < len(src) && digit(src[i]) {
			i++
		}
		if i-start > idMax {
			continue
		}

		// The separator.
		if i == len(src) || src[i] != ':' {
			continue
		}
		i++

		// The secret: one of the two widths, and the whole of the run it
		// stands in.
		end := i
		for end < len(src) && body(src[end]) {
			end++
		}
		if n := end - i; bodyMin <= n && n <= bodyMax && head(src[i:end]) && decodes(src[i:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
}

// Test_TelegramAuthenticationToken_matchesTheReferenceAcrossTheIDCount holds
// the scan and the reference to the same count of digits, on both sides of the
// widest identifier.
//
// The reference spells that count again rather than reading
// telegramAuthenticationTokenIDMax, which is what every rule about a reference
// asks for and is also the one number here that can drift without anything
// failing. Nothing else compares the two across it: builtinPatterns drives its
// samples, and no sample is written with an identifier wider than the count;
// the tables above hold the scan to expectations written out by hand rather
// than to the reference; and the corpus states what Mask returns rather than
// what the two implementations agree on. That leaves the fuzz target below,
// which would have to write sixteen digits, a colon and thirty-four characters
// of the alphabet by chance. So the count is driven here, where raising it in
// one place and not the other fails under a plain go test.
func Test_TelegramAuthenticationToken_matchesTheReferenceAcrossTheIDCount(t *testing.T) {
	body := telegramAuthenticationTokenTestBody
	for n := 1; n <= telegramAuthenticationTokenIDMax+3; n++ {
		id := strings.Repeat("1234567890", n/10+1)[:n]
		for _, src := range []string{
			id + ":" + body,
			"bot" + id + ":" + body,
			id + ":" + body + " ",
		} {
			got, _ := TelegramAuthenticationToken().Find(src)
			want := referenceTelegramAuthenticationTokenFind(src)
			if !slices.Equal(got, want) {
				t.Errorf("with %d digit(s): Find(%q) = %v, reference gives %v", n, src, got, want)
			}
		}
	}
}

// FuzzTelegramAuthenticationToken_matchesReference guards the hand-written
// scan: the byte it searches for, the digits it walks back over, the count it
// holds them to, the alphabet it reads a secret in and the two widths it holds
// that secret to may none of them change which tokens are located.
func FuzzTelegramAuthenticationToken_matchesReference(f *testing.F) {
	id := telegramAuthenticationTokenTestID
	body := telegramAuthenticationTokenTestBody
	wide := telegramAuthenticationTokenTestBodyWide

	f.Add("nothing to see here")
	f.Add(id + ":" + body)
	f.Add(id + ":" + wide)
	f.Add("https://api.telegram.org/bot" + id + ":" + body + "/sendMessage")
	f.Add("TELEGRAM_TOKEN=" + id + ":" + body)
	f.Add(id + ":" + telegramAuthenticationTokenTestBodyEdges)
	f.Add(id + ":" + telegramAuthenticationTokenTestBodyLetters)
	f.Add(telegramAuthenticationTokenTestIDWide + ":" + body)
	f.Add(id + ":" + body[:33])  // one short of the narrower width
	f.Add(id + ":" + wide + "z") // one past the wider width
	f.Add("0" + id + ":" + body) // an identifier opening on a zero
	f.Add("9" + id + ":" + body) // a digit that carries the run further
	f.Add(id + " " + body)       // the separator left out
	f.Add(id + ": " + body)      // a space where the secret begins
	f.Add(body)                  // the secret with nothing in front of it
	f.Add("12:00:01 " + id + ":" + body)
	f.Add(id + ":" + body + id + ":" + body)
	// A token written inside the secret of the one in front of it, and a
	// separator written inside an identifier: both are places a scan resuming
	// past a match would step over a token.
	f.Add(id + ":" + body[:10] + id + ":" + body)
	f.Add(id + ":" + id + ":" + body)
	f.Add("123456789:0123456789abcdefghijklmnopqrstuv12:" + body)
	// Candidate positions crowded as close as they can be: a separator at
	// every other byte, a run of digits longer than any identifier, and a run
	// of the alphabet longer than any secret behind a separator. Each is
	// written just long enough to crowd what it is about — a seed is what every
	// input the fuzzer builds is mutated from, and Go shrinks a new one by
	// trying every subset of its bytes, so a seed written longer than it needs
	// to be is paid for in every minimization of everything descended from it.
	f.Add(strings.Repeat("1:", 24))
	f.Add(strings.Repeat("1", 24))
	f.Add("1:" + strings.Repeat("a", 48))

	fuzzAgainstReference(f, TelegramAuthenticationToken().Find, referenceTelegramAuthenticationTokenFind)
}

// telegramAuthenticationTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func telegramAuthenticationTokenFindBenchmarks() []benchmarkCase {
	// The line carries the colons a log line has anyway — the timestamp, the
	// scheme, the port — because those are the positions the search stops at
	// and reads a candidate back from. Some have a digit in front and so reach
	// the walk back over an identifier; the rest are turned away by that one
	// byte.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.example.com:8443/config `
	id := telegramAuthenticationTokenTestID
	body := telegramAuthenticationTokenTestBody

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// An identifier and a separator written out with a run one
			// character short of the narrower width behind them: the candidate
			// at each separator reads the whole identifier and all
			// thirty-four of the positions behind it, which is the most a
			// candidate can cost here. This scan keeps no cursor and needs
			// none — a count bounds both halves of what a candidate reads —
			// and this is the input that would show the bound gone.
			name:  "candidates that are not values",
			src:   strings.Repeat(id+":"+body[:33]+" ", 32),
			spans: 0,
		},
		{
			// A run of the alphabet longer than any secret, behind a
			// separator: the walk gives up one character past the wider width
			// however far the run goes on.
			name:  "a separator in front of a run no secret can be",
			src:   id + ":" + strings.Repeat(body, 32),
			spans: 0,
		},
		{
			// A separator at every other byte, each with a digit in front of
			// it, which is a candidate at every one of them. Each is turned
			// away inside the run behind it.
			name:  "candidates crowded in one run",
			src:   strings.Repeat("1:", 128),
			spans: 0,
		},
		{
			// A run of digits far longer than any identifier, which the walk
			// back gives up on one digit past the count.
			name:  "a run of digits no identifier can be",
			src:   strings.Repeat("1", 256) + ":" + body,
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + id + ":" + body,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + id + ":" + body,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+id+":"+body+"\n", 32),
			spans: 32,
		},
	}
}

// telegramAuthenticationTokenIDMaxDigits is what the widest identifier this
// scan reads comes to written out, and Test_telegramAuthenticationTokenIDMax
// holds the count beside the scan to it.
const telegramAuthenticationTokenIDMaxDigits = "4503599627370495"

// Test_telegramAuthenticationTokenIDMax holds the count of digits an identifier
// is read to against the bound it is derived from: the Bot API documentation
// states that a user identifier has at most fifty-two significant bits, and a
// bot's identifier is a user identifier.
//
// Nothing else reports a count set from the wrong bound. A narrower one is
// tokens of the widest identifiers left in the log whole, which no case here
// would fail unless it happened to be written that wide, and a wider one is a
// run of digits no identifier can be read as one.
func Test_telegramAuthenticationTokenIDMax(t *testing.T) {
	const bits = 52
	widest := strconv.FormatUint(1<<bits-1, 10)
	if widest != telegramAuthenticationTokenIDMaxDigits {
		t.Fatalf("%d significant bits reach %s, written out here as %s",
			bits, widest, telegramAuthenticationTokenIDMaxDigits)
	}
	if len(widest) != telegramAuthenticationTokenIDMax {
		t.Errorf("the widest identifier is %d digits, the scan reads %d",
			len(widest), telegramAuthenticationTokenIDMax)
	}
}
