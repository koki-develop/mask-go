package mask

import "strings"

// TailscaleKey locates the keys Tailscale writes with a key prefix: API access
// tokens (tskey-api-), auth keys (tskey-auth-), OAuth client keys
// (tskey-client-), SCIM keys (tskey-scim-) and webhook keys (tskey-webhook-).
//
// A key is a prefix, the identifier the key is listed under, a hyphen and the
// secret behind it. Both of those are read as runs of letters and digits, to
// whatever length they run: Tailscale states no length for either, so a key is
// located from its prefix to the end of the run its secret stands in.
//
// An auth key wrapped for a tailnet under tailnet lock is located whole,
// including the signature and the wrapping private key written after it. The
// wrapping is read behind a key of any kind, though Tailscale writes one only
// onto an auth key.
//
// A key is located wherever it is written, with no word boundary either side.
// So a key written against a word character keeps its span, and a letter or a
// digit written straight after one is redacted with it.
//
// Its name is "tailscale-key".
func TailscaleKey() Pattern { return tailscaleKey }

// Tailscale states the prefixes and the shape and states no count for either
// half of a key, so the prefixes are the whole of what this scan keys on.
//
// The prefixes are an enumeration Tailscale publishes as one, the Key prefixes
// page of its documentation, which writes tskey-api for an API access token,
// tskey-auth for a pre-authentication key, tskey-client for an OAuth client
// key, tskey-scim for a SCIM key and tskey-webhook for a webhook key, and calls
// each of the five "the key". That is why one pattern reads all five: the
// caller enabling any of them wants the others, a redactor telling them apart
// would be telling apart five things Tailscale names alike, and the value
// itself is spelled tskey.
//
// The shape behind a prefix is stated three times over. The same page writes an
// example as tskey-api-abcDEF1CNTRL-091234567890ABCDEF, a prefix and two parts
// with a hyphen between them. Tailscale's own client reads that shape from
// either end: wrapAuthKey in cmd/tailscale/cli/tailnet-lock.go takes the text
// up to the first hyphen behind tskey-auth- and calls it the key's stable
// identifier, and clientIDFromSecret in cmd/k8s-operator/e2e/setup.go splits an
// OAuth secret on the hyphen, demands exactly four parts and calls the third
// the client id. Neither half may hold a hyphen, then, since either reading
// would find the wrong boundary if it did.
//
// The alphabet is letters and digits, and it is Tailscale's own redaction code
// that says so. sanitizeWriter in cmd/tailscale/cli/cli.go overwrites what
// stands behind tskey- in the client's output for exactly as long as the bytes
// are letters, digits or hyphens, and stops at the first byte that is not.
// Tailscale wrote that to keep a key out of its own output, so a key holding a
// character it stops at would be a key that routine leaks the tail of. The
// hyphen it admits is the separator this grammar already reads; what is left is
// base62, which isBase62Byte in builtin_scan.go holds.
//
// trufflehog reads an underscore in both halves besides. It is not admitted
// here, on the strength of the paragraph above and against the cost either way:
// admitting a character no key carries widens a span past the key and into
// whatever was written behind it, where declining a character a key does carry
// would leave the tail of one in the log. The vendor's own anti-leak code is
// the better evidence of the two, and it is what is followed.
//
// Neither half is held to a length. Tailscale publishes none, and neither does
// the one ruleset that reads this format: trufflehog asks for one character or
// more in each half and stops there. A count assembled from what an example or
// an issue report happens to carry is a count that costs the whole credential
// the day it is wrong, and there is nothing here for a floor to protect
// against — the prefixes are ten characters and more of text no word is
// spelled with, so they are the whole net and it is already a tight one. What
// reading no count costs is the far side of it: a key is redacted to the end of
// the run its secret stands in, so a letter or a digit written straight against
// a key goes with it.
//
// An auth key carries one more shape, and both ends of it are Tailscale's own.
// TailnetLockWrapPreauthKey in ipn/ipnlocal/tailnet-lock.go wraps a pre-auth key
// for unattended bringup in a locked tailnet, writing
// fmt.Sprintf("%s--TL%s-%s", preauthKey, enc(sig.Serialize()), enc(priv)) — the
// key, the literal --TL, a credential signature and the ed25519 private key that
// signature delegates to. DecodeWrappedAuthkey in tka/sig.go reads it back the
// same way, cutting at --TL, cutting again at the first hyphen and decoding both
// halves with base64.RawStdEncoding.
//
// The whole of that goes into one span. Reading the key alone would leave a
// signing private key and the signature authorizing it standing in the text,
// behind a redaction that reads as though the credential had been dealt with.
// It is one string the vendor writes in one call and parses in one call, and a
// caller passes the whole of it to tailscale up --authkey, so it reaches a log
// exactly where a plain auth key does.
//
// It is read behind a key of any kind, which is wider than what Tailscale
// writes: only TailnetLockWrapPreauthKey writes a suffix, it is handed a
// pre-auth key, and the command reaching it takes tskey-auth- and nothing else.
// So tskey-webhook-a-b--TLxy-z is redacted whole, and no such string is one
// Tailscale ever produced. The widening is taken rather than gated on the kind
// because a scan reading the suffix wherever it stands can only redact too
// much — four characters of literal and two runs of base64 behind a key is not
// prose — where one reading it behind a single kind would leave an ed25519
// private key in the log the day Tailscale wraps anything else it issues.
// Test_TailscaleKey_wrappingBehindEveryKind pins it.
//
// The two halves of the suffix are the standard base64 alphabet of RFC 4648,
// which isTailscaleKeyWrapByte holds, and not the base64url one isBase64URLByte
// reads: RawStdEncoding writes + and / where base64url writes - and _. The
// hyphen being outside it is what lets the vendor's own parser cut at the first
// hyphen, and it is what this scan rests on twice over — to find the end of the
// signature, and for the linearity argument below. RawStdEncoding writes no
// padding, so the padding character is outside the alphabet as well.
//
// Neither half of the suffix is held to a length either, and here that costs
// something the key's halves do not. The private key is an ed25519 one, so it
// is always eighty-six characters encoded — a count that could be read — and
// standard base64 admits the solidus, so without it the private key's run walks
// through one and a wrapped key written into a path is redacted along with the
// segments behind it. Test_TailscaleKey_wrappedSuffixReachesTheEndOfItsRun pins
// that. The count is declined anyway: this half is the last field of the format
// and the vendor's own parser bounds it by the end of the string rather than by
// any count, so an exact count here is read off the key type rather than off
// the format, and the day Tailscale wraps with another kind of key it would cut
// the suffix short and leave the tail of a private key in the log. What it
// would buy back is over-redaction of text standing against a credential, which
// is what every run this scan reads to its end already takes.
//
// What this pattern over-matches on: a prefix and two runs of letters and
// digits with a hyphen between them, written by somebody rather than issued by
// Tailscale. tskey-auth-x-y is redacted. Nothing is left in such a string to
// read it apart from a key by, since a key of the shortest shape Tailscale
// could issue is written exactly that way, and what is taken is opaque to a
// reader either way. Test_TailscaleKey_shortestShape pins it.
//
// The two key shapes Tailscale's documentation has left behind are not read.
// The auth keys page writes an old example as tskey- and sixteen characters,
// and the OAuth page writes an access token as tskey- and thirty-six, both
// without a kind and without the second half; the Key prefixes page is the
// current statement and gives every key a kind. Reading a bare tskey- and a run
// would admit the two, and would admit far more: six characters and a run of
// letters and digits is a shape a hostname, a branch name and a cache key are
// written in, so the kind and the second hyphen are what keep this pattern off
// text a reader reads.
//
// The scan resumes one byte past the start of a candidate whether it became a
// key or not. A key can begin inside the one before it: the letters and the
// hyphens a prefix is written with are the letters and the separators of the
// two halves, so tskey-api-tskey-auth-0-1 is a key whose identifier is tskey
// and whose secret is auth, with a second key beginning ten characters into it.
// Consuming a match would step over that one and leave it in the output whole.
// The two spans then overlap, which a Masker resolves into one.
//
// No cursor is kept over any of the runs, and none is needed. Every run a
// candidate reads begins directly behind a hyphen, and the hyphen belongs to
// none of the four alphabets, so a run is the maximal one at the byte it begins
// and is fixed by where it begins. One candidate at most reads a given run as
// its identifier — the one whose prefix closes at the hyphen in front of it —
// and one at most reads it as its secret, the one whose identifier is the run
// in front of that hyphen. The two runs of a wrapping suffix follow from the
// secret: a candidate looks for one only behind a whole key, and only one
// candidate's secret can end at a given byte, so only one candidate ever reads
// a given suffix. Its own two runs begin behind --TL and behind the hyphen
// dividing them, neither of which any base64 run can hold. So every run of the
// input is walked a bounded number of times however densely the candidates are
// crowded, and reading all of them comes to a constant times the length of the
// input. Test_tailscaleKeySeparator_runsDoNotOverlap holds the separator to the
// one thing that argument rests on, and Test_TailscaleKey_scanIsLinear drives
// the inputs that would find it wrong.
//
// What reaches a span is never prose, a git SHA or an MD5. None of those holds
// tskey- at all, and a run of hexadecimal holds neither the hyphen a key is
// divided by nor the letters its prefix is spelled with.
//
// referenceTailscaleKey in builtin_tailscale_key_test.go keeps the grammar as a
// regular expression, spelling the opening, the kinds, the separators, the two
// alphabets and the wrapping literal again so that the two are changed
// together, and the fuzz target beside it holds this scan to that expression.
var tailscaleKey = newBuiltin("tailscale-key", &tailscaleKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := tailscaleKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], tailscaleKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for the
		// reason the rationale above gives: the opening is written in the letters and
		// the separator the two halves are, so a key can begin inside the one before
		// it.
		offset = anchor + 1

		if anchor < tailscaleKeyAnchorIndex {
			continue
		}
		start := anchor - tailscaleKeyAnchorIndex

		// The byte the opening begins with is tested before the opening is
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the whole opening is a length and a read.
		if src[start] != tailscaleKeyOpening[0] || !strings.HasPrefix(src[start:], tailscaleKeyOpening) {
			continue
		}

		// Which kind is written behind the opening, and so where the identifier
		// begins. A kind is asked for with the separator behind it, so a kind
		// the end of the input cut short opens no candidate here — it is a piece
		// of a whole prefix, which the tail above already answers for.
		kind := start + len(tailscaleKeyOpening)
		body := -1
		for _, k := range tailscaleKeyKinds {
			if len(src)-kind > len(k) && src[kind:kind+len(k)] == k &&
				src[kind+len(k)] == tailscaleKeySeparator {
				body = kind + len(k) + 1
				break
			}
		}
		if body < 0 {
			continue
		}

		id := base62RunEnd(src, body)
		if id == len(src) {
			// The run reaches the end of the input, so the separator that would
			// divide an identifier from a secret has not arrived and neither
			// has the secret.
			retain = min(retain, start)
			continue
		}
		// An identifier of no characters at all, or one the text closed with
		// something that is no separator: either is settled, whatever follows.
		if id == body || src[id] != tailscaleKeySeparator {
			continue
		}

		secret := id + 1
		end := base62RunEnd(src, secret)
		// Whether the input stopped inside this candidate. The secret running
		// to the end of it is one way; the wrapping suffix is the other, and it
		// has to be read before the question is settled, since a key carrying
		// one reaches further than the secret alone does.
		open := end == len(src)
		if end > secret {
			// A wrapping suffix is looked for behind a whole key of any kind,
			// which is wider than the one kind Tailscale wraps. The rationale
			// above says why the widening is taken rather than gated on the
			// kind.
			wrap, ok, wrapOpen := tailscaleKeyWrapEnd(src, end)
			open = open || wrapOpen
			if ok {
				end = wrap
			}
		}
		if open {
			// The input ends inside the candidate, so where the key ends is not
			// settled: what comes next either carries a run on, or opens the
			// wrapping suffix, or closes the key. That holds whether or not a
			// character of the secret has arrived already.
			retain = min(retain, start)
		}
		if end > secret {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// tailscaleKeyKinds is what Tailscale writes between the opening and the
// identifier, one entry a kind of key its Key prefixes page names: an API
// access token, an auth key, an OAuth client key, a SCIM key and a webhook key.
//
// The scan reads these and the prefixes below are built from them, so a kind
// added here is a kind the scan finds and a kind a stream holds its opening
// for. A table of whole prefixes written out beside this one could come to
// disagree with it, and what a stream would then do with the kind it had not
// been told about is release the characters a key opens with and redact
// nothing.
var tailscaleKeyKinds = []string{"api", "auth", "client", "scim", "webhook"}

// tailscaleKeyPrefixes is what a candidate opens with, one entry a kind: the
// opening, the kind and the separator that closes it.
var tailscaleKeyPrefixes = func() []string {
	prefixes := make([]string, 0, len(tailscaleKeyKinds))
	for _, kind := range tailscaleKeyKinds {
		prefixes = append(prefixes, tailscaleKeyOpening+kind+string(tailscaleKeySeparator))
	}
	return prefixes
}()

const (
	// tailscaleKeyOpening is what every prefix opens with, and what the scan
	// reads back from its anchor. It is the word Tailscale spells a key with
	// and the separator behind it, so every prefix carries the anchor at one
	// index whichever kind it names.
	tailscaleKeyOpening = "tskey-"

	// tailscaleKeyAnchor is the byte the scan searches the input for and
	// tailscaleKeyAnchorIndex is where it stands in the opening, so a candidate
	// begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of what a candidate
	// opens with rather than for the whole of it.
	//
	// What makes it this byte is that the opening is a word with its vowels
	// taken out and a hyphen behind it, and four of those six bytes are among
	// the commonest a log line is written with: over the line these benchmarks
	// are written on the e stands ten times, the t seven, the s four and the
	// hyphen twice in the timestamp alone. The k and the y stand once each,
	// both of them in the same word, and what settles it between those two is
	// prose at large, where the k is the rarer by about half.
	tailscaleKeyAnchor      = 'k'
	tailscaleKeyAnchorIndex = 2

	// tailscaleKeySeparator closes the opening, closes every prefix, divides an
	// identifier from the secret behind it and divides the two halves of a
	// wrapping suffix. It belongs to none of those four runs' alphabets, which
	// is what ends an identifier where it stands, what makes the halves behind
	// it readable at all, and what bounds how often a run can be read.
	// Test_tailscaleKeySeparator_runsDoNotOverlap holds it to the last.
	tailscaleKeySeparator = '-'

	// tailscaleKeyWrapOpening is what stands between an auth key and the
	// tailnet-lock wrapping written after it, the literal
	// TailnetLockWrapPreauthKey writes and DecodeWrappedAuthkey cuts at. It
	// opens with the separator, so it can stand nowhere but where a key has
	// already ended: no run either side of it is written with one.
	tailscaleKeyWrapOpening = "--TL"
)

// tailscaleKeyWrapEnd returns where the tailnet-lock wrapping written at i in
// src ends and whether one is written there, together with whether the end of
// the input is what decided the answer.
//
// The third result is reported on both answers, and both are load-bearing.
// Saying no because the input ran out is the distinction builtin_scan.go asks
// of every such helper: a suffix the input cut short is one more text may
// complete, so the candidate in front of it is not settled, where a suffix
// carrying a character no half is written with is no suffix whatever follows
// and the key in front of it is a key. Saying yes matters for the same reason
// one step further on: a private key running to the end of the input is a
// suffix that may still grow, and the caller's own answer is already no by
// then — its secret ended where the wrapping opened, far short of the end — so
// this is the only thing that holds such a key back. Drop it as dead weight on
// the success path and a stream releases a wrapped key whose private key is
// still arriving.
//
// A piece of the opening standing at the end of the input is the same question
// one step earlier, and is answered here rather than by the tail: the tail
// settles what opens a candidate, and this opens nothing — it extends one.
func tailscaleKeyWrapEnd(src string, i int) (int, bool, bool) {
	if !strings.HasPrefix(src[i:], tailscaleKeyWrapOpening) {
		rest := len(src) - i
		return 0, false, rest < len(tailscaleKeyWrapOpening) &&
			src[i:] == tailscaleKeyWrapOpening[:rest]
	}

	signature := i + len(tailscaleKeyWrapOpening)
	end := tailscaleKeyWrapRunEnd(src, signature)
	if end == len(src) {
		return 0, false, true
	}
	if end == signature || src[end] != tailscaleKeySeparator {
		return 0, false, false
	}

	private := end + 1
	end = tailscaleKeyWrapRunEnd(src, private)
	if end == private {
		return 0, false, end == len(src)
	}
	return end, true, end == len(src)
}

// isTailscaleKeyWrapByte reports whether c belongs to the standard base64
// alphabet of RFC 4648, which both halves of a wrapping suffix are written in.
// It is not the base64url alphabet isBase64URLByte reads: the two characters
// that differ are + and / here where they are - and _ there, and the hyphen
// being outside this alphabet is what the vendor's own parser cuts on and what
// this scan reads the signature's end by. The padding character is outside it
// as well, since Tailscale encodes both halves with RawStdEncoding.
func isTailscaleKeyWrapByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z' ||
		c == '+' || c == '/'
}

// tailscaleKeyWrapRunEnd returns where the run of standard base64 characters
// beginning at i in src ends, which is len(src) where the run reaches the end
// of the input.
func tailscaleKeyWrapRunEnd(src string, i int) int {
	for i < len(src) && isTailscaleKeyWrapByte(src[i]) {
		i++
	}
	return i
}

// tailscaleKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var tailscaleKeyTail = newPrefixTail(tailscaleKeyPrefixes...)
