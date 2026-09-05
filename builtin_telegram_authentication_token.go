package mask

import "strings"

// TelegramAuthenticationToken locates the authentication tokens Telegram issues
// to bots: the bot's numeric identifier, a colon, and the thirty-four or
// thirty-five characters of the secret written behind it. The whole of it is
// redacted, identifier included, because the whole of it is what authorizes a
// request to the Bot API.
//
// Its name is "telegram-authentication-token".
func TelegramAuthenticationToken() Pattern { return telegramAuthenticationToken }

// The token carries no opening of its own — no vendor marker, no word — and
// what stands in its place is its own shape: a run of digits, a colon, and a
// run of base64url characters held to a width, to the character it opens with
// and to the character it closes on. No part of that carries the pattern alone.
// A run of digits is written on every line of a log; thirty-four base64url
// characters are a blob somebody encoded; and the two of them written together
// at one of those widths is a shape ordinary text writes often enough to
// matter, which is what the head and the close are read for.
//
// Both runs are held to being whole, which is the part of the shape that needs
// no source: the digits are the whole of their run and the secret is the whole
// of its own, so a value cut out of a longer run of either is no value.
//
// The rules below do not rest on the same kind of source, and a reader widening
// one needs to know which they are holding.
//
// The structure is the vendor's own, twice over. The Bot API documentation
// writes the token as an identifier, a colon and a secret, and Telegram's Bot
// API server — the implementation it publishes for anyone to run — reads it
// that way: it splits on the first colon, reads the front as the bot's user
// identifier and refuses a token whose first character is a zero, and it
// base64url-decodes what stands behind the colon and refuses a token where that
// fails. So the separator, the digits in front of it, the leading digit that
// may not be a zero and the alphabet behind it are all things Telegram itself
// undertakes.
//
// The count is not. Telegram's own server asks only that the secret be at least
// twenty-four characters, which is a floor far too low to read as a format: a
// git SHA, an MD5 and any run cut out of a base64 blob all clear it, and a
// pattern admitting those would redact values a reader has every reason to see.
// What the count rests on instead is the rules the public secret-scanning
// rulesets state, which say what someone else read of the format rather than
// what Telegram undertakes to keep issuing. Those rules reach two
// widths and no others: four of them are written to thirty-five characters, and
// one admits thirty-four beside it — which is also the width of the secret
// Telegram writes on its own BotFather page. Both are read here, because a
// count narrowed to one of them is a token of the other width left in the log
// whole.
//
// The widths alone do not carry the pattern, and the two rules that make them
// carry it are the character a secret opens with and the one it closes on. A
// run of digits, a colon and thirty-four characters of this alphabet is a shape
// ordinary text writes, and writes often: an IAM action behind the service
// prefix that ends in a digit — ec2:, s3:, route53: — a Go module checksum
// behind its h1:, an OID table's algorithm name behind its number, a feature
// flag behind its version. Each of those is text a reader has every reason to
// see, so a grammar admitting them is the loose one the rules here rule out
// rather than the unlucky one, however rarely it would fire.
//
// The character it closes on is the vendor's, and it is free. Neither width is
// a multiple of four, so each leaves bits over that base64url demands be zero,
// and Telegram's own server refuses to serve a token whose secret does not
// decode — so conditioned on a width, telegramAuthenticationTokenBodyDecodes
// costs no token Telegram issues. What it rules out is the checksum and the
// algorithm name above.
//
// The character it opens with is not the vendor's, and it is what the rest of
// the false positives turn on: an English identifier of thirty-five characters
// ends in an s as often as not, and s is one of the sixteen the padding leaves,
// so the IAM actions clear the paragraph above untouched. What tells them from
// a secret is the head, and what the head rests on is two of the rulesets
// asking for it in the rule itself. One spells a literal A in front of the
// thirty-four characters it then reads; the other, the one written with no
// keyword in front of it, spells AA. Telegram's own example writes a secret
// opening that way as well. Read back through base64url an A is a zero, so what
// the two rules say between them is that a secret's first byte is zero.
//
// That is a ruleset's reading of the format rather than anything Telegram
// undertakes, which is the weaker of the two kinds of source this package
// admits and is why it is named as such here: a token whose first byte stopped
// being zero is one this scan would walk past. It is taken all the same,
// because the alternative is not a looser pattern but no pattern — a built-in
// that redacts ec2:DescribeNetworkInterfacePermissions out of a log is one no
// caller of AllBuiltinPatterns can be given.
//
// One A and not two, where the tighter of the two rules spells AA. The second A
// says the secret's second byte is below sixteen, which is a narrower claim
// about a byte with no stated meaning, and the rule asking for it is one rule
// rather than the two that agree on the first. One character is also enough:
// every shape named above is turned away by it.
//
// The identifier is one to telegramAuthenticationTokenIDMax digits, not opening
// with a zero. Both ends are the vendor's: the server refuses a leading zero,
// and the Bot API documentation states of every user identifier that it has at
// most fifty-two significant bits, which is sixteen digits written out. No
// floor above one digit is taken: Telegram undertakes no minimum, and the body
// behind the colon is what carries the pattern in any case.
//
// The pattern is declared with NewPattern rather than newBuiltin or
// newBuiltinFilteredOn because it has no literal either could be built from: a
// candidate opens on a run of digits, and the one literal a token carries is
// the colon, which is a single byte where a grams filter reads three. It is
// therefore run over every text a Masker is handed, where a pattern the filter
// can read is turned away on a line holding nothing before its scan is entered
// at all.
//
// The scan being cheap does not make that free. On its own it is in line with
// the others, but the others are mostly not run, so what this one adds lands on
// every call and grows with the text rather than with what is found in it: over
// a line of a few thousand bytes it is about a fifth of what Mask costs, and
// the share falls as the text shortens and the fixed work of a call takes over.
// BenchmarkMasker_Mask either side of the entry in builtins is what reports it.
// No arrangement of this grammar avoids it — what the filter reads is literals,
// and a value opening on a run of digits has none to give it.
//
// The byte the scan searches for is the character a secret opens with, which
// builtin_scan.go says why a scan searches for one byte rather than for the
// whole of what it opens with. An opening offers three: a digit, the colon and
// that character. The first two are what a log line is made of — a digit in
// every timestamp and every status code, and the colon written by the format
// rather than by the message, in every timestamp, every port and every field
// written as a name against a value. The character behind the colon is the
// message's, and an ordinary line of a log writes no capital at all.
//
// So the search stops where a secret could open and nowhere else, and one
// comparison against the colon that must stand in front of it turns away each
// of the ones a word wrote. Over the line the benchmarks below are written on
// the colon stands three times a record and the capital not at all, and the
// scan comes to a thirteenth of what searching for the colon leaves it costing.
//
// One shape of input is dearer for that choice, and it is the shape two
// searches cost most in: almost no colon, and a long run of the secret's
// alphabet spelling the capital every few dozen bytes and answering for none of
// them. The colon alone reads such a text in one pass where this reads it in one
// pass of each — the same bytes, one more call to make them in.
// a_separator_in_front_of_a_run_no_secret_can_be below is written on that shape
// and is the one case the colon would leave cheaper, by about a fifth; every
// other case there, and every case BenchmarkMasker_Mask drives, costs more under
// it, the ones a log line is made of by between a quarter and a third. The case
// is kept as the one that says what the choice costs.
//
// The end of the input is the one place the character cannot answer for the
// colon: a text ending on an identifier and its colon opens a candidate whose
// head has not arrived. telegramAuthenticationTokenIDTail is what reads it.
//
// What bounds a candidate is a count and not a cursor. The walk back over the
// identifier reads at most telegramAuthenticationTokenIDMax digits and one byte
// more, and the walk forward over the body reads at most
// telegramAuthenticationTokenBodyMax characters and one more, so the work at a
// candidate is bounded whatever runs it stands between and no candidate can
// read what another already read.
//
// LookBehind is one byte, and it is the byte in front of the identifier: the
// scan reads it to learn whether the digits it walked back over are the whole of
// their run. Everything else the scan reads is inside the value it reports.
//
// referenceTelegramAuthenticationTokenFind in
// builtin_telegram_authentication_token_test.go states the same grammar the
// plain way, spelling the counts and the alphabet again so that the two are
// changed together, and the fuzz target beside it holds this scan to that
// statement.
var telegramAuthenticationToken = NewPattern("telegram-authentication-token", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops settling: a piece of an identifier standing at the
	// end of it, or a candidate the end of it cut short, whichever comes first.
	retain := telegramAuthenticationTokenIDTail(src)

	// One cursor over the heads, only ever searching the text past its own last
	// hit, so the whole loop is one pass over the input rather than one per
	// candidate.
	for at := 0; at < len(src); {
		j := strings.IndexByte(src[at:], telegramAuthenticationTokenBodyHead)
		if j < 0 {
			break
		}
		head := at + j

		// The next candidate begins one byte past this one, and the search
		// resumes one byte past the head to reach it: a candidate opening inside
		// this one carries its own head further along again, so it is found at
		// that head and not stepped over. builtin_scan.go sets out why that is
		// the step a scan takes at a candidate.
		at = head + 1

		// The separator is tested before the identifier is walked back over:
		// one comparison against a loop over as many as seventeen bytes.
		//
		// What the search resumes at when one is turned away is not the next
		// byte but the byte behind the next separator. A head with no separator
		// against it says where the next one can stand — the earliest is the
		// byte behind the first separator at or past it, since every capital in
		// between carries something else in front of it — and that is what keeps
		// a run of the secret's alphabet, which spells this character every few
		// dozen bytes and holds no separator at all, from being read a candidate
		// at a time. The two searches are still one pass over the input apiece,
		// since each only ever looks past its own last hit.
		if head == 0 || src[head-1] != telegramAuthenticationTokenSeparator {
			j := strings.IndexByte(src[head:], telegramAuthenticationTokenSeparator)
			if j < 0 {
				break
			}
			at = max(at, head+j+1)
			continue
		}
		sep := head - 1

		start, ok := telegramAuthenticationTokenIDStart(src, sep)
		if !ok {
			continue
		}

		end, ok, cut := telegramAuthenticationTokenBodyEnd(src, sep+1)
		if ok {
			spans = append(spans, Span{Start: start, End: end})
		}
		if cut {
			// The run reaches the end of the input, so more text can carry it
			// to a width that is a value, or past every width that is one.
			// Whether a span was reported here or not, nothing from the
			// identifier on is settled.
			retain = min(retain, start)
		}
	}
	return spans, retain
})

const (
	// telegramAuthenticationTokenSeparator is what divides a bot's identifier
	// from its secret, and the byte the scan searches the input for.
	telegramAuthenticationTokenSeparator = ':'

	// telegramAuthenticationTokenIDMax is the most digits an identifier is
	// written in. A bot's identifier is a Telegram user identifier, of which
	// the Bot API documentation states that it has at most fifty-two
	// significant bits; the largest such value is 4503599627370495, which is
	// this many digits.
	telegramAuthenticationTokenIDMax = 16

	// telegramAuthenticationTokenBodyMin and telegramAuthenticationTokenBodyMax
	// are the widths a secret is written to, and a run of anything between them
	// is read as one. What the two rest on is the rationale above: the rules
	// the public rulesets state, rather than anything Telegram undertakes.
	telegramAuthenticationTokenBodyMin = 34
	telegramAuthenticationTokenBodyMax = 35

	// telegramAuthenticationTokenBodyHead is the character a secret opens
	// with, which two of the rulesets spell into the rule itself. It is
	// base64url's zero, so what it says about the secret behind it is that the
	// first six bits of one are zero.
	telegramAuthenticationTokenBodyHead = 'A'
)

// telegramAuthenticationTokenIDStart returns where the identifier standing in
// front of sep in src begins, and whether one stands there at all.
//
// The walk back stops at telegramAuthenticationTokenIDMax digits and then reads
// one byte more, which is what holds an identifier to being the whole of its
// run: a longer run of digits is not an identifier with something written in
// front of it but text that is no token, and that byte is the whole of what
// this scan reads in front of a value.
//
// A leading zero is turned away here rather than folded into the walk, because
// it is a rule about the identifier and not about where the run begins:
// Telegram's own server refuses such a token outright, so the digits behind the
// zero are not an identifier either.
func telegramAuthenticationTokenIDStart(src string, sep int) (int, bool) {
	i := sep
	for i > 0 && sep-i < telegramAuthenticationTokenIDMax && isTelegramAuthenticationTokenDigit(src[i-1]) {
		i--
	}
	if i == sep {
		return 0, false
	}
	if i > 0 && isTelegramAuthenticationTokenDigit(src[i-1]) {
		return 0, false
	}
	if src[i] == '0' {
		return 0, false
	}
	return i, true
}

// telegramAuthenticationTokenBodyEnd returns where the secret standing at i in
// src ends, whether the run there is a secret, and whether the end of the input
// can still change that answer.
//
// The run is read one character past the widest width before it is given up on,
// which is what holds a secret to being the whole of its run: thirty-six
// characters of the alphabet are no secret, and no text appended to them makes
// one. That is also what bounds this walk — it reads at most
// telegramAuthenticationTokenBodyMax+1 characters however long the run it
// stands in is.
//
// A run short of the narrower width and reaching the end of the input is
// unsettled, and so is one already wide enough: text arriving carries the first
// towards a secret and the second past every width that is one. Where a span is
// reported for the second it is reported all the same, because it is the value
// in the text as handed over, and the offset is what says a stream may not
// write it out yet.
//
// A run already past the widest width is settled wherever it ends, the end of
// the input included, and that is the one place this walk reads a candidate the
// end cut short rather than giving up on it. What it reads there is the walk
// above and nothing else — the same alphabet against the same count — so it is
// the grammar this file already states rather than a second one kept beside it.
//
// What that buys is the whole of a run rather than a few bytes. A colon behind
// a number is what a log line writes in front of a message, a duration or a
// path, so a scan pinned at every one of them for the length of a base64 blob
// would hold a stream from that colon onwards until WithMaxRetained gave up —
// which is a mebibyte by default, and what a stream does at its limit is redact
// everything it is holding.
func telegramAuthenticationTokenBodyEnd(src string, i int) (int, bool, bool) {
	if i == len(src) {
		// The input ends at the separator, so what a secret opens with is not
		// here to be read yet.
		return 0, false, true
	}
	if src[i] != telegramAuthenticationTokenBodyHead {
		// The character a secret opens with is written and is not it, which no
		// text arriving can change.
		return 0, false, false
	}

	end := i
	for end < len(src) && end-i <= telegramAuthenticationTokenBodyMax && isBase64URLByte(src[end]) {
		end++
	}
	switch n := end - i; {
	case n > telegramAuthenticationTokenBodyMax:
		return 0, false, false
	case n < telegramAuthenticationTokenBodyMin:
		return 0, false, end == len(src)
	case !telegramAuthenticationTokenBodyDecodes(src[end-1], n):
		// The run is one of the widths and still no secret, so it is no value
		// — but the end of the input can carry it to the other width, where
		// the character it closes on is a different one and answers again.
		return 0, false, end == len(src)
	default:
		return end, true, end == len(src)
	}
}

// telegramAuthenticationTokenBodyDecodes reports whether a body of n characters
// closing on c is one base64url can decode, which is what Telegram's own Bot
// API server demands of a secret before it will serve the token at all.
//
// Neither width this scan reads is a multiple of four, so each leaves a group
// short at the end: thirty-four leaves two characters, which carry twelve bits
// of which only eight are a byte, and thirty-five leaves three, which carry
// eighteen bits of which sixteen are two bytes. The bits over are padding, the
// decoder refuses a body that writes anything but zero into them, and they are
// the low bits of the character the body closes on — four of them at the first
// width and two at the second. So the whole of the constraint is a mask on that
// one character, and which mask it is follows from the width.
//
// A remainder of one is no base64url at all: one character carries six bits and
// a byte needs eight, so no such body decodes at any content. Nothing reaches
// that here, since the two widths leave two and three, and it is written out
// rather than left to the default so that a width added above cannot quietly
// take the answer yes.
//
// This is the tightening that makes the pattern's shape carry it. A run of
// digits, a colon and thirty-four characters is a shape ordinary text writes —
// an IAM action behind its service prefix, a module checksum behind its h1 —
// and holding the last character to a sixteenth or a quarter of the alphabet is
// what tells those from a secret. It costs no token Telegram issues: the widths
// are already fixed above, and conditioned on a width the constraint is the
// vendor's own decoder rather than anything observed of the values.
func telegramAuthenticationTokenBodyDecodes(c byte, n int) bool {
	switch n % 4 {
	case 1:
		return false
	case 2:
		return telegramAuthenticationTokenBodyValue(c)&0xf == 0
	case 3:
		return telegramAuthenticationTokenBodyValue(c)&0x3 == 0
	}
	return true
}

// telegramAuthenticationTokenBodyValue returns what base64url reads c as, and
// -1 where c is no character of that alphabet.
//
// It is the alphabet isBase64URLByte (builtin_scan.go) admits, read as the six
// bits each character stands for rather than as a yes or a no, which is what
// the padding above is a test on. The two are held to admitting the same bytes
// by Test_telegramAuthenticationTokenBodyValue: a walk that ended a run on a
// character this could not weigh would be two grammars for one alphabet.
func telegramAuthenticationTokenBodyValue(c byte) int {
	switch {
	case 'A' <= c && c <= 'Z':
		return int(c - 'A')
	case 'a' <= c && c <= 'z':
		return int(c-'a') + 26
	case '0' <= c && c <= '9':
		return int(c-'0') + 52
	case c == '-':
		return 62
	case c == '_':
		return 63
	}
	return -1
}

// telegramAuthenticationTokenIDTail returns where the piece of an opening
// standing at the end of src begins, and len(src) where none stands there.
//
// It is what prefixTail (builtin_scan.go) is for the scans whose openings are
// literals: an opening the end of the input cut in half opens no candidate
// at all and the scan walks past it having found nothing, so a stream carrying
// 123456789 in one write and the colon and the secret in the next would release
// the first with the token behind it redacted nowhere. prefixTail cannot serve here — it
// compares bytes, and an identifier is a run rather than a string — so the walk
// that already reads one is asked instead, at the end of the input, which is
// what keeps this from becoming a second grammar free to disagree with the
// first.
//
// Two pieces and not one: an input ending on an identifier and its colon is one
// the search finds no head in, so this is the only place that candidate is read
// at all. The colon is stepped over and the digits in front of it are the piece,
// which is the walk either way.
//
// What turns an input away before any of that is the byte it closes on. A piece
// of an opening closes on a digit or on the colon, so an input closing on
// anything else is answered by two tests — which is what keeps this off the cost
// of a line holding nothing, since every input a Masker is handed pays for it
// and a line of prose closes on a full stop, a quote or a line break.
func telegramAuthenticationTokenIDTail(src string) int {
	end := len(src)
	if end > 0 && src[end-1] == telegramAuthenticationTokenSeparator {
		end--
	}
	if end == 0 || !isTelegramAuthenticationTokenDigit(src[end-1]) {
		return len(src)
	}
	if start, ok := telegramAuthenticationTokenIDStart(src, end); ok {
		return start
	}
	return len(src)
}

// isTelegramAuthenticationTokenDigit reports whether c is a decimal digit,
// which is what an identifier is written in.
func isTelegramAuthenticationTokenDigit(c byte) bool {
	return '0' <= c && c <= '9'
}
