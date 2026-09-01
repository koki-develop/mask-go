package mask

import "strings"

// PrivateKey locates private keys written in the armor RFC 7468 lays out: a
// line opening with five dashes, BEGIN and a label, the base64 of the key
// behind it, and a closing line naming the same label. Every label whose last
// words are PRIVATE KEY is read, so the PKCS#8 key of RFC 7468, the encrypted
// PKCS#8 key beside it, the PKCS#1 and EC and DSA keys OpenSSL writes, the
// OPENSSH key ssh-keygen writes and the PGP PRIVATE KEY BLOCK of RFC 9580 are
// all located, as is a label no such document has been written for yet.
//
// The whole block is redacted, the two boundary lines included, not the base64
// alone. A block cut short — a key a log truncated before its closing line —
// is located as far as its last whole line of base64, so a truncation landing
// inside a line leaves that line, and one landing inside the first leaves the
// key.
//
// A block written into JSON or into an environment assignment, where the line
// breaks stand as the two characters \ and n rather than as line breaks, is
// located as one written across lines is, and so is one indented under a name
// in YAML. Text escaped twice over is not: a block whose line breaks are
// written \\n is located nowhere.
//
// Its name is "private-key".
func PrivateKey() Pattern { return privateKey }

// What a private key looks like is not one vendor's format but four documents'
// agreement on an envelope, and the envelope is the whole of what this pattern
// reads. RFC 7468 gives it exactly:
//
//	preeb     = "-----BEGIN " label "-----"
//	posteb    = "-----END " label "-----"
//	label     = [ labelchar *( ["-" / SP] labelchar ) ]
//	labelchar = %x21-2C / %x2E-7E
//
// and defines PRIVATE KEY for the PKCS#8 key of its section 10 and ENCRYPTED
// PRIVATE KEY for the section 11 one. RFC 5915 writes EC PRIVATE KEY in the
// same envelope, OpenSSL writes RSA PRIVATE KEY and DSA PRIVATE KEY in it,
// OpenSSH writes OPENSSH PRIVATE KEY — its sshkey.c spells the boundary out as
// MARK_BEGIN — and RFC 9580 writes PGP PRIVATE KEY BLOCK, five dashes and all.
//
// So the reading is not a roster of labels but the words they end on. A label
// closing with PRIVATE KEY, or with PRIVATE KEY BLOCK, opens a block this
// pattern locates whatever stands in front of those words. A roster would be
// the loose thing here rather than the tight one: it would have to be corrected
// by every format a vendor writes next, it goes stale without failing anything,
// and what being wrong costs is a whole key left in the output. The words
// themselves cost nothing to widen to, because nothing that is not a private
// key writes them inside a BEGIN boundary — a certificate, a public key and a
// certificate request each name themselves in that place and none of them names
// a private key.
//
// The label is read more narrowly than labelchar allows: uppercase letters and
// digits, separated by single spaces. Two things ask for that. Every label any
// of the documents above defines is written that way, and the hyphen labelchar
// admits inside a label is what makes the closing dashes ambiguous — a label
// free to hold hyphens leaves -----BEGIN A----------- with no reading, since
// the dashes could be four of the label and a boundary or a boundary and
// nothing. Test_privateKeyLabelSuffixes holds the words this narrowing has to
// keep reachable.
//
// What the scan searches the input for is the G of BEGIN, seven bytes into the
// prefix, and builtin_scan.go says why a scan searches for one byte of its
// prefix rather than for the prefix itself. What makes it the G is a choice
// among five, since the dash and the space the prefix is otherwise built from
// are two of the commonest bytes there are. Over the log line these benchmarks
// are written on none of B, E, G, I and N stands at all, which is the ordinary
// case and settles nothing; what settles it is the text a key is written
// beside. E closes KEY and stands in SECRET, TOKEN and ACCESS; I opens API and
// ID and stands twice in PRIVATE itself; N closes TOKEN and stands in
// CONNECTION; and B opens Bearer, which is written in front of a credential
// more often than any other word in the text this library is pointed at. G is
// what is left.
//
// A candidate reads forward from there and never back, and what it reads is a
// walk over lines:
//
//   - the boundary line itself, which must be closed by a line break with
//     nothing but spaces and tabs in front of it. A break and not a space: a
//     body a space could open would make -----BEGIN RSA PRIVATE KEY-----
//     followed by a sentence into a block reaching over that sentence, and a
//     sentence is exactly what this may not redact. Reading the spaces and then
//     still asking for the break gives up none of that — what stands behind
//     them in the sentence is a word — and it reaches the boundary line that
//     picked up a trailing space, which would otherwise lose the whole key.
//
//   - armor header lines, and at most one blank line closing them. RFC 1421
//     puts Proc-Type and DEK-Info there in the key OpenSSL encrypts, and RFC
//     9580 section 6.2.2 defines Version, Comment, Hash and Charset. Those six
//     names and no others, which privateKeyHeaderNames holds. At most one blank
//     line, because that is what both documents write and because any number of
//     them would let a block reach over a run of empty lines to whatever word
//     came next.
//
//     A roster is the wrong shape for the label, where a vendor writes a format
//     nobody has been told about and being wrong costs a whole key; it is the
//     right shape here, and what separates the two is what a name is worth as
//     evidence. Any name at all would mean any line of the form word, colon,
//     text — which is a log record, a YAML mapping and half the structured text
//     there is. A block would then reach from a boundary written into such a
//     line over every line behind it, redacting error: failed to load and
//     path: /etc/ssl/private/server.pem along with whatever base64 came next,
//     and that is prose written over, which no built-in of this package may do.
//     What the roster costs is a private key armored under a seventh name,
//     which nothing writes and neither document defines.
//
//     A header value carries anything but the dashes a boundary opens with, and
//     that exception is load-bearing rather than tidy: see the linearity below.
//
//   - base64 lines, at least one, each of them base64 to the end of its line
//     but for the spaces and tabs that may close it. This is what bounds the
//     block, and it is what keeps prose out of the body as the roster keeps it
//     out of the headers: a line of prose carries a space with a word behind
//     it, and a word is not the end of a line, so the sentence a boundary is
//     mentioned in ends the reading before anything is located.
//
//   - the CRC24 line RFC 9580 writes behind an armored block, an = and four
//     characters.
//
//   - the closing boundary, naming the same label. Where it names a different
//     label it closes nothing — a boundary naming a label of its own is text
//     this pattern has no reason to write over.
//
// Where nothing closes the block it ends at its last whole base64 line, which
// is what locates a key a log cut short. What that leaves behind is the line
// the cut landed inside: a key truncated as msg="-----BEGIN PRIVATE
// KEY-----\nAAAA\nBBBB" level=info is redacted as far as AAAA, and the BBBB the
// quote follows stays in the output.
//
// Reading that fragment as well was weighed and declined, and the reason is
// that the two readings cannot be told apart. A block ending inside the line
// that ended its body would take the run of base64 opening that line — but a
// line of prose written after a key opens with such a run as often as not, so
// the same rule that reaches BBBB reaches the first word of an ordinary line
// written under the key and writes over it. That is over-matching on a word
// somebody wrote, which is
// what a built-in of this package may not do, and no character tells the two
// apart: the run is stopped by a space in the one case and by a quote in the
// other, and each stands in both.
//
// What it costs is that the end of an unclosed block moves when text is written
// after it: a body reaching the end of the input ends there, and a byte
// appended to that line takes the block back to the line before. A block a
// closing boundary closes does not move, which is every block written whole.
//
// A blank line ends the body, and a block whose base64 is broken by one is
// located only as far as that line. A key a blank line was pasted into the
// middle of is therefore redacted in part, and the part left over reads as
// though the redaction had worked, which is the failure reading the spaces at
// the end of a line was for.
//
// It is given up because the alternative reaches further than the value. A
// block that read across a blank line would take whatever base64 stood behind
// the gap, and a word of prose is base64 as often as not, so the gap would be
// something to reach over rather than a bound — the same reason at most one
// blank line closes the headers. A blank line inside the base64 is written by
// no document here and arrives only where the text was edited or spliced,
// where the line above it is the last thing the block can be sure of.
//
// A body of one base64 character is a body. There is no floor under it, and
// declining to put one there is a decision rather than an omission. What a
// floor would buy back is the placeholder somebody wrote where a key stands
// — a word under a BEGIN line, in a template — and what it would cost is the
// key a column limit cut to fewer characters than the floor, which is the
// value this pattern most needs to reach and which carries nothing of its
// own to be found by: what is left of such a key is base64 and no more. The
// boundary line is the whole of the evidence and it is decisive on its own,
// so what stands in the key's place is redacted whatever it turns out to be.
//
// Line breaks are read in four spellings: a line feed, a carriage return and a
// line feed, and each of those written as the two characters \ and n rather
// than as itself. The escaped spelling is not a courtesy. A service account key
// reaches a program as one JSON string with its line breaks escaped, and an
// environment assignment carries one the same way, so a scan reading only real
// line breaks would leave the commonest written form of a private key whole.
// Admitting the escape costs nothing, because a backslash belongs to no part of
// this grammar otherwise: it is not base64, not a label character and not a
// boundary, so the two characters can mean a line break and nothing else.
//
// The line break is not the only character an encoder escapes, and reading it
// alone would leave most of what it was read for out of reach. The solidus is a
// character of the base64 alphabet and JSON may escape it — PHP's json_encode
// does by default — so a body line carrying one unread is a line that is not
// base64 to its end, and what is lost there is not the character but the whole
// key. privateKeyEscapedSolidus is that reading, and it says why the two
// together are the whole of what can arrive escaped.
//
// What is read is one level of escaping. A text escaped twice over — a JSON
// string encoded into another, as a log line quoting a document does — writes
// its line breaks \\n and its solidus \\/, and none of that is read: a block
// written that way is located nowhere. The level is where it is because the
// spellings have to be written down, and writing the second would raise the
// same question of the third with no answer that is not arbitrary. The
// conformance corpus states it.
//
// What holds the scan linear is that no candidate can read a run another
// candidate already read, and what gives it that is one rule kept everywhere:
// nothing a candidate walks may carry the run of dashes a boundary opens with.
// A label run stops at a dash because no label character is one; a base64 line
// and an indent stop at a dash for the same reason; and a header value stops at
// one because privateKeyHeaderLineEnd is written to. So everything a candidate
// reads lies in front of the next boundary in the input, which is where the
// next candidate begins reading — the regions are disjoint, and the walk over
// the whole input is one pass however many candidates it holds.
//
// The header value is the one of the three that had to be made so rather than
// found so, and the input that shows why is a line of the form Comment: and a
// boundary written after it, repeated. Every such line is a header to the
// candidate in the line above it, so without the rule each candidate reads to
// the end of the input and the scan is quadratic — measured at six seconds for
// a quarter of a mebibyte and fourfold again for every doubling after it, on
// text no more contrived than a log that quoted a key.
// Test_privateKey_scanIsLinear drives that input and the others: boundaries
// crowded against one another, boundaries sharing one long uppercase run, a
// boundary written inside a header value and inside a line that is no header at
// all, and a long body with no closing boundary behind it.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a block or not, which is the default builtin_scan.go sets
// out and which needs no argument. It happens to be true that no block can
// begin inside another — a body holds no dash — but the scan does not rest on
// it and neither does the reference.
//
// What this pattern over-matches on: base64 written under a boundary line by
// somebody who was not writing a key. That is over-matching on text already
// opaque to a reader, which is the standard the rules hold a built-in to,
// and the boundary line in front of it is a stronger statement of intent
// than a prefix: a prefix is a handful of characters a random string can
// open with by accident, where a boundary line spells out what the block
// beneath it is. What it does not reach is prose, a git SHA or an MD5, none
// of which carries a boundary line at all.
//
// The private key formats this pattern does not read are the ones written in
// no armor: PuTTY's .ppk, which opens PuTTY-User-Key-File-3 and counts its
// lines in a header rather than closing them with a boundary, and the ssh.com
// format, whose boundary is four dashes with spaces inside them rather than
// five without. Each is a grammar of its own rather than a label this one has
// not been told about, so neither is reachable by widening the words above.
//
// referencePrivateKeyFind in builtin_private_key_test.go states the same
// grammar the plain way, spelling the boundaries, the words, the alphabets and
// the line breaks again so that the two are changed together. It is written out
// rather than built on a regular expression, and not by preference: the closing
// boundary has to name the label the opening one named, which is a back
// reference, and RE2 has none. Its own comment says so.
var privateKey = newBuiltin("private-key", &privateKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the opening boundary
	// standing at the end of it, or a block the end of it cut short.
	// builtin_scan.go says why those are the two.
	retain := privateKeyTail.start(src)

	// Where the last line of src ends, which is what tells a walk that stopped
	// on a line the input holds whole from one that stopped because the input
	// ran out. It is worked out once and only where a candidate asks for it: a
	// line carrying no boundary never reaches a walk at all, and two searches
	// over the input would otherwise be paid by every line that holds nothing.
	lastBreak := noLineBreakWorkedOut

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], privateKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a block or not, which
		// builtin_scan.go sets out.
		offset = anchor + 1

		if anchor < privateKeyAnchorIndex {
			continue
		}
		start := anchor - privateKeyAnchorIndex

		label, body, open := privateKeyLabelAt(src, start)
		if body == 0 {
			if open {
				// The boundary line runs to the end of the input, so the label
				// naming what this block holds is not all here.
				retain = min(retain, start)
			}
			continue
		}

		if lastBreak == noLineBreakWorkedOut {
			lastBreak = privateKeyLastLineBreak(src)
		}
		end, open := privateKeyBlockEnd(src, body, label, lastBreak)
		if open {
			// The walk over the lines ran to the end of the input, so the
			// block reaches at least this far and may reach further. A block
			// is settled where its walk stopped on a line the input holds
			// whole — its closing boundary, or anything that is no line of a
			// block at all.
			retain = min(retain, start)
		}
		if end == 0 {
			continue
		}

		spans = append(spans, Span{Start: start, End: end})
	}
	return spans, retain
})

const (
	// privateKeyPrefix opens a block, and privateKeyEndPrefix closes one. The
	// space is part of each: RFC 7468 writes exactly one between the word and
	// the label, so a boundary carrying none is not one.
	privateKeyPrefix    = "-----BEGIN "
	privateKeyEndPrefix = "-----END "

	// privateKeyBoundary is the run of dashes each boundary closes with, and
	// the one every boundary opens with. Five, which is what RFC 7468 writes
	// and what OpenSSH and RFC 9580 write beside it.
	privateKeyBoundary = "-----"
)

const (
	// privateKeyAnchor is the byte the scan searches the input for and
	// privateKeyAnchorIndex is where it stands in privateKeyPrefix, so a
	// candidate begins that many bytes in front of what a search reported. The
	// rationale above says what made it this byte, and Test_privateKeyAnchor
	// holds the two to each other.
	privateKeyAnchor      = 'G'
	privateKeyAnchorIndex = 7
)

// privateKeyLabelSuffixes are the words a label must end on for the block it
// opens to be a private key. Both of them, because a label ending on the second
// does not end on the first: PGP PRIVATE KEY BLOCK is what RFC 9580 writes, and
// reading PRIVATE KEY alone would leave every OpenPGP secret key whole.
//
// They are the whole of what separates a private key from the certificate, the
// public key and the certificate request written in the same envelope. What
// stands in front of them is not read at all, which is what lets a label no
// document has been written for yet be located.
var privateKeyLabelSuffixes = [...]string{"PRIVATE KEY", "PRIVATE KEY BLOCK"}

// privateKeyLabelAt returns the label of the boundary standing at i in src and
// the offset just past that boundary, or the zero offset where no boundary
// naming a private key stands there.
//
// The label is a slice of src rather than a copy, because it is compared
// against the closing boundary and nothing more: a candidate that is not a
// block may not allocate, which TestMasker_Mask_withoutMatchDoesNotAllocate
// measures.
// It reports whether saying no was the end of the input speaking rather than
// the text. Everything the boundary line is read for can be cut in half by it:
// the words in front of the label, the label itself, and the dashes that close
// the line. PRIVATE reads as no key and PRIVATE KEY reads as one, so a scan
// settling a label the input cut short would release the opening of a block
// whose next word was the one that named it.
func privateKeyLabelAt(src string, i int) (label string, body int, open bool) {
	if !strings.HasPrefix(src[i:], privateKeyPrefix) {
		return "", 0, strings.HasPrefix(privateKeyPrefix, src[i:])
	}

	at := i + len(privateKeyPrefix)
	end, open := privateKeyLabelEnd(src, at)
	if end == at {
		return "", 0, open
	}
	label = src[at:end]
	if !privateKeyLabelNamesAKey(label) {
		return "", 0, open
	}
	if !strings.HasPrefix(src[end:], privateKeyBoundary) {
		// The dashes may be cut in half, and so may the label in front of
		// them: PGP PRIVATE KEY followed by a space is a label a stream may
		// yet be handed the word BLOCK for, and what stands where the dashes
		// belong is that space rather than a piece of them.
		return "", 0, open || strings.HasPrefix(privateKeyBoundary, src[end:])
	}
	return label, end + len(privateKeyBoundary), false
}

// privateKeyLabelEnd returns where the label beginning at i in src ends, which
// is i itself where no label begins there.
//
// A label is uppercase letters and digits with single spaces between them,
// which the rationale above says is narrower than RFC 7468's labelchar and why.
// The space is admitted only between two label characters, so a label neither
// opens nor closes with one and no two stand together — which is what RFC 7468
// asks for as well, since its own ABNF puts a separator only between two
// labelchars.
// It reports whether the walk stopped because the input did, which is two
// places rather than one: the label running to the end of the input, and a
// space standing at the end of it, where the word this label may still grow by
// has not arrived.
func privateKeyLabelEnd(src string, i int) (int, bool) {
	end := i
	for end < len(src) {
		if isPrivateKeyLabelByte(src[end]) {
			end++
			continue
		}
		if src[end] == ' ' && end > i && end+1 < len(src) && isPrivateKeyLabelByte(src[end+1]) {
			end += 2
			continue
		}
		return end, src[end] == ' ' && end > i && end+1 == len(src)
	}
	return end, true
}

// isPrivateKeyLabelByte reports whether c may stand in a label: an uppercase
// letter or a digit. The digit is what SSH2 and X509 are written with, and
// costs nothing to admit since the words a label is held to end on carry none.
func isPrivateKeyLabelByte(c byte) bool {
	return 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

// privateKeyLabelNamesAKey reports whether label ends on the words a private
// key's does.
//
// The words must stand as words: either the label is nothing else, or a space
// divides them from what comes in front. Without that a label ending
// NOTAPRIVATE KEY would name a key, and a label is read from a boundary rather
// than from anything that vouches for it.
func privateKeyLabelNamesAKey(label string) bool {
	for _, suffix := range privateKeyLabelSuffixes {
		if label == suffix {
			return true
		}
		if len(label) > len(suffix) && strings.HasSuffix(label, suffix) && label[len(label)-len(suffix)-1] == ' ' {
			return true
		}
	}
	return false
}

// privateKeyBlockEnd returns where the block ends whose opening boundary named
// label and left off at body in src, or zero where what follows is not a body.
//
// The walk is the one the rationale above lays out, and the order of its parts
// is the order both RFC 1421 and RFC 9580 write them in: headers, at most one
// blank line, base64, the checksum, the closing boundary. Every one of those
// lines may be indented, which privateKeyIndentEnd is for. Everything past the
// base64 is optional, which is what locates a block a log cut short, and the
// base64 itself is not: a boundary with nothing behind it is a boundary
// somebody wrote about rather than a key.
// It reports whether the walk ran to the end of the input as well, which is
// what says the block may reach further than what is written here. Every place
// the walk stops is one of two things: a line the input holds whole, which
// closes the question whatever follows it, or the input running out, which
// leaves it open — the closing boundary is a line like any other, so a line cut
// short is a line that may yet turn out to be one.
func privateKeyBlockEnd(src string, body int, label string, lastBreak int) (int, bool) {
	i, ok := privateKeyNextLine(src, body)
	if !ok {
		// The boundary line is not closed, so nothing stands under it. What
		// stands behind the dashes says whether that is the end of the input
		// speaking: a line closing on anything but spaces, or on a piece of the
		// break that would have closed it, is no boundary line whatever
		// follows. A piece is what a break of two characters leaves — the
		// carriage return of a CRLF, or the backslash of an escaped one.
		at := privateKeySpaceEnd(src, body)
		return 0, at == len(src) || privateKeyBreakTail.start(src) == at
	}

	for {
		n := privateKeyHeaderLineEnd(src, privateKeySpaceEnd(src, i))
		if n == 0 {
			break
		}
		next, ok := privateKeyNextLine(src, n)
		if !ok {
			// A header is the last line, so there is no base64 at all. A header
			// line ends at a break or at the end of the input, and a break here
			// would have closed it, so this is the input running out.
			return 0, true
		}
		i = next
	}
	if next, ok := privateKeyNextLine(src, i); ok {
		i = next // the blank line closing the headers
	}

	end := 0
	for {
		n := privateKeyBase64LineEnd(src, privateKeySpaceEnd(src, i))
		if n == 0 {
			break
		}
		end = n
		next, ok := privateKeyNextLine(src, n)
		if !ok {
			return end, true // the base64 reaches the end of the input
		}
		i = next
	}
	if end == 0 {
		return 0, i > lastBreak
	}

	if n := privateKeyCRCLineEnd(src, privateKeySpaceEnd(src, i)); n > 0 {
		end = n
		next, ok := privateKeyNextLine(src, n)
		if !ok {
			return end, true
		}
		i = next
	}
	if n := privateKeyEndBoundaryEnd(src, privateKeySpaceEnd(src, i), label); n > 0 {
		return n, false
	}
	// The line the walk stopped on is no line of a block. A line the input
	// holds whole says so for good; a line the input cut short says only that
	// the rest of it has not arrived, and the closing boundary is written on
	// such a line. What tells the two apart is whether a break stands anywhere
	// behind this line's beginning, not whether one stands at it — the line the
	// walk stopped on is a line, and it is closed by the break that ends it
	// rather than by one where it starts.
	return end, i > lastBreak
}

// privateKeyBreakTail is how a line the input cut short is told from a line
// that closes on something no break of this pattern's is written with: a break
// standing at the end of the input in pieces is a break the rest of which has
// not arrived. prefixTail (builtin_scan.go) says what a tail is.
var privateKeyBreakTail = newPrefixTail(privateKeyLineBreaks[:]...)

// noLineBreakWorkedOut stands for a last line break the scan has not looked for
// yet, apart from the -1 that says it looked and found none.
const noLineBreakWorkedOut = -2

// privateKeyLastLineBreak returns where the last line break in src begins, and
// -1 where src carries none.
//
// Every break this pattern reads carries a newline, or the two characters
// standing for one where the breaks are escaped, at its own offset or behind
// it: \r\n carries the newline one along, and the escaped \r\n carries the
// escaped newline two along. So the later of the two searches is at or past
// every break there is, and is itself the beginning of one — which makes "a
// break stands at or after i" exactly "i is at or before this".
func privateKeyLastLineBreak(src string) int {
	return max(strings.LastIndexByte(src, '\n'), strings.LastIndex(src, `\n`))
}

// privateKeyHeaderNames are the armor headers a block may carry: the two RFC
// 1421 puts in front of the data of an encrypted key, and the four RFC 9580
// section 6.2.2 defines. Nothing else, and the rationale above says what that
// buys and what it costs.
//
// Sorted, which decides nothing: no name is a prefix of another, and the colon
// behind a name has to be there either way, so at most one of them stands at
// any position whichever order they are tried in.
var privateKeyHeaderNames = [...]string{
	"Charset",   // RFC 9580 section 6.2.2.4
	"Comment",   // RFC 9580 section 6.2.2.2
	"DEK-Info",  // RFC 1421 section 4.6.1.3, as OpenSSL writes it
	"Hash",      // RFC 9580 section 6.2.2.3
	"Proc-Type", // RFC 1421 section 4.6.1.1, as OpenSSL writes it
	"Version",   // RFC 9580 section 6.2.2.1
}

// privateKeyHeaderLineEnd returns where the armor header line beginning at i in
// src ends, which is zero where no header line begins there.
//
// A header is one of the names above, a colon, and whatever follows to the end
// of the line — except the dashes a boundary opens with, which end the reading
// with nothing. That exception is what the linearity of this scan rests on and
// the rationale above sets out: a header value free to carry a boundary would
// let one candidate read over every candidate behind it.
func privateKeyHeaderLineEnd(src string, i int) int {
	name := privateKeyHeaderNameAt(src, i)
	if name == 0 {
		return 0
	}
	end := i + name + len(":")

	dashes := 0
	for end < len(src) && privateKeyLineBreak(src, end) == 0 {
		if src[end] != '-' {
			dashes = 0
		} else if dashes++; dashes == len(privateKeyBoundary) {
			return 0
		}
		end++
	}
	return end
}

// privateKeyHeaderNameAt returns the length of the armor header name standing
// at i in src with a colon behind it, or zero where none does.
func privateKeyHeaderNameAt(src string, i int) int {
	for _, name := range privateKeyHeaderNames {
		if strings.HasPrefix(src[i:], name) && strings.HasPrefix(src[i+len(name):], ":") {
			return len(name)
		}
	}
	return 0
}

// privateKeySpaceEnd returns where the run of spaces and tabs at i in src ends,
// which is i itself where none stands there.
//
// It is read at both ends of every line of a block. In front, because a key
// written into YAML is indented under the name it is bound to — a Kubernetes
// secret, a Helm value and a docker-compose file each carry one as a block
// scalar, and so does a fenced block in a document. Behind, because a line that
// picked up a trailing space is a line a hand-edited file and a log are both
// full of, and a scan that would not read past one loses the rest of the key:
// the block ends at the line above, which redacts most of a key and leaves the
// rest in the output reading as though the redaction had worked.
//
// Neither character is base64, a label character or a dash, so admitting them
// widens nothing else and takes nothing from the linearity above. A line of
// prose behind an indent is still a line of prose: what turns it away is the
// base64 reading, which asks that nothing but these stand between the run and
// the end of the line.
func privateKeySpaceEnd(src string, i int) int {
	for i < len(src) && (src[i] == ' ' || src[i] == '\t') {
		i++
	}
	return i
}

// privateKeyClosesLine reports whether nothing but spaces and tabs stands
// between i in src and the end of the line i is in, the end of the input
// counting as the end of a line.
func privateKeyClosesLine(src string, i int) bool {
	at := privateKeySpaceEnd(src, i)
	return at == len(src) || privateKeyLineBreak(src, at) > 0
}

// privateKeyNextLine returns where the line whose content ended at i in src
// gives way to the next, and whether a line break closed it at all. Spaces and
// tabs may stand between the two.
func privateKeyNextLine(src string, i int) (int, bool) {
	at := privateKeySpaceEnd(src, i)
	if w := privateKeyLineBreak(src, at); w > 0 {
		return at + w, true
	}
	return 0, false
}

// privateKeyBase64RunEnd returns where the run of base64 beginning at i in src
// ends, which is i itself where none begins there.
//
// The alphabet is the standard one of RFC 4648 rather than the base64url
// isBase64URLByte reads, since that is what every document writing this
// envelope encodes with, and the padding a key's last line carries is read as
// part of the run: at most two characters, and only behind the alphabet, which
// is where base64 puts them.
func privateKeyBase64RunEnd(src string, i int) int {
	end := i
	for end < len(src) {
		if isPrivateKeyBase64Byte(src[end]) {
			end++
			continue
		}
		w := privateKeyEscapedSolidus(src, end)
		if w == 0 {
			break
		}
		end += w
	}
	if end == i {
		return i
	}
	for pad := 0; pad < 2 && end < len(src) && src[end] == '='; pad++ {
		end++
	}
	return end
}

// privateKeyBase64LineEnd returns where the base64 line beginning at i in src
// ends, which is zero where the line is not base64 to its very end.
//
// The whole line, not the run inside it. A line ending in anything else is what
// bounds the block, and reading a run and ignoring the rest of the line would
// take that bound away: the sentence a boundary is mentioned in opens with a
// word that is base64 as often as not. What the run alone is good for is the
// one line privateKeyBlockEnd reads it on.
func privateKeyBase64LineEnd(src string, i int) int {
	end := privateKeyBase64RunEnd(src, i)
	if end == i || !privateKeyClosesLine(src, end) {
		return 0
	}
	return end
}

// isPrivateKeyBase64Byte reports whether c belongs to the base64 alphabet of
// RFC 4648: the letters of both cases, the digits, the plus and the slash.
//
// It is declared here rather than in builtin_scan.go because this is the one
// scan that reads it. What is shared there is what a second pattern came to
// need. The two characters this admits that base64url does not are exactly the
// two base64url exists to keep out of a URL, and a credential written into one
// carries neither.
func isPrivateKeyBase64Byte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z' ||
		c == '+' || c == '/'
}

// privateKeyCRCLineEnd returns where the checksum line beginning at i in src
// ends, which is zero where no checksum line begins there.
//
// RFC 9580 writes the CRC24 of an armored block as an = and the four characters
// three bytes of base64 come to, on a line of its own behind the data. It
// cannot be read as a base64 line, since a base64 line opens with a character
// of the alphabet and the = is not one, so the two readings cannot disagree.
//
// The four are counted in characters and not in bytes, because one of them can
// be the solidus and a solidus can be written escaped, as it can anywhere else
// a character of the alphabet stands.
func privateKeyCRCLineEnd(src string, i int) int {
	if i >= len(src) || src[i] != '=' {
		return 0
	}
	end := i + len("=")
	for range privateKeyCRCChars {
		switch {
		case end < len(src) && isPrivateKeyBase64Byte(src[end]):
			end++
		case privateKeyEscapedSolidus(src, end) > 0:
			end += len(`\/`)
		default:
			return 0
		}
	}
	if !privateKeyClosesLine(src, end) {
		return 0
	}
	return end
}

// privateKeyEscapedSolidus returns the width of a solidus written as the two
// characters \ and / at i in src, and zero where none stands there.
//
// The solidus is the one character of the base64 alphabet a JSON encoder
// escapes — PHP's json_encode does so by default — and a body line carrying one
// unread is a line that is not base64 to its end, which loses not that
// character but the whole key. Nothing else of this grammar can arrive
// escaped: of the alphabet only the solidus may be, the padding and the plus
// never are, and the dashes, the letters, the digits and the spaces a boundary
// and a label are written with are escaped by no encoder at all.
//
// It is admitted whether or not the text around it is escaped, and that costs
// nothing, because a backslash is not base64: the two characters can stand
// inside a run only where something escaped them.
func privateKeyEscapedSolidus(src string, i int) int {
	if strings.HasPrefix(src[i:], `\/`) {
		return len(`\/`)
	}
	return 0
}

// privateKeyCRCChars is what the CRC24 of RFC 9580 comes to in base64: three
// bytes, four characters, no padding.
const privateKeyCRCChars = 4

// privateKeyEndBoundaryEnd returns where the closing boundary naming label ends
// at i in src, which is zero where no such boundary stands there.
//
// The label must be the one the opening boundary named. A boundary naming
// another label closes another block, and this one then ends where its base64
// did — which leaves that boundary in the text, where it belongs.
func privateKeyEndBoundaryEnd(src string, i int, label string) int {
	if !strings.HasPrefix(src[i:], privateKeyEndPrefix) {
		return 0
	}
	end := i + len(privateKeyEndPrefix)
	if !strings.HasPrefix(src[end:], label) {
		return 0
	}
	end += len(label)
	if !strings.HasPrefix(src[end:], privateKeyBoundary) {
		return 0
	}
	return end + len(privateKeyBoundary)
}

// privateKeyLineBreaks are the spellings a line break is read in, longest of
// each pair first so that a carriage return is not left behind by the line feed
// standing after it.
//
// Four, and they are written out rather than composed of a carriage return and
// a line feed read apart. Composing them would admit two more — a real carriage
// return in front of an escaped line feed, and the other way about — which
// nothing writes and no case here could state: a text is escaped or it is not,
// and a line break inside one is escaped throughout or not at all.
var privateKeyLineBreaks = [...]string{"\r\n", `\r\n`, "\n", `\n`}

// privateKeyLineBreak returns the width of the line break at i in src, which is
// zero where none stands there.
func privateKeyLineBreak(src string, i int) int {
	for _, br := range privateKeyLineBreaks {
		if strings.HasPrefix(src[i:], br) {
			return len(br)
		}
	}
	return 0
}

// privateKeyTail is what the scan settles the tail of its input by. prefixTail
// (builtin_scan.go) says what that is and why it is built once.
var privateKeyTail = newPrefixTail(privateKeyPrefix)
