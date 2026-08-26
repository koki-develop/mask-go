package mask

import "strings"

// AWSSecretAccessKey locates AWS secret access keys: the forty characters the
// secret half of an access key is written in, standing behind the name it is
// assigned to. The name is what says a key is there — SECRET_ACCESS_KEY, the
// aws_secret_access_key of a shared credentials file, the SecretAccessKey of
// the JSON an assume-role call prints, and the rest of the ways those three
// words are written — and only the forty characters are redacted, so the name
// and the assignment stay in the text to be read.
//
// A key is located wherever those three words stand in front of one: the aws
// in front of them is not read, so a name is enough on its own, and a service
// naming its own credential the same way has that credential located too.
//
// Its name is "aws-secret-access-key".
func AWSSecretAccessKey() Pattern { return awsSecretAccessKey }

// The value carries no opening of its own, and that is the whole of what makes
// this pattern different from the one beside it. Forty characters of
// [A-Za-z0-9+/] is a grammar a git SHA satisfies, an MD5 written against eight
// more characters satisfies, and any forty characters cut out of a base64 blob
// satisfy. A built-in may over-match on values a reader cannot read, and none
// of those is one — so a grammar reading the value alone is not on offer here
// at any tightness, and what stands in front of the value is part of the
// grammar instead.
//
// LookBehind is what makes that a pattern this package can carry rather than
// one a stream would have to be denied: a name and an assignment fit inside it
// with room over. Test_AWSSecretAccessKey_readsNoFurtherBackThanLookBehind
// builds the widest of each out of the declarations the scan reads them with
// and holds the two together to the limit, so widening either fails there
// rather than in a stream.
//
// What AWS states about the value is nothing at all, and it is worth being
// exact about how little. The AccessKeyId beside it carries a documented
// length and a documented pattern in both the IAM AccessKey type and the STS
// Credentials type — sixteen to a hundred and twenty-eight characters matching
// [\w]+ — where SecretAccessKey in the same two types carries Type: String and
// no more. There is no filter to read as a format and no format to read
// instead.
//
// What AWS shows is forty characters, and it shows two of them:
// wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY, which the access keys page of the
// IAM user guide writes beside AKIAIOSFODNN7EXAMPLE, and
// je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY, which the CLI's configuration and
// credential file reference writes under a second profile. Two examples
// agreeing on a count is more than one example does, and both carry the / that
// puts this alphabet outside hexadecimal.
//
// It is a weaker observation than the twenty an access key ID is read as, all
// the same. The sample response on the CreateAccessKey page writes the first of
// those two with one character more — the same example value with a z inserted,
// which reads as a typo rather than as a second shape — so the count rests on
// the documentation agreeing with itself everywhere but one place.
//
// The count is therefore exact and the run is held to being the whole of it: a
// run of forty-one is not a key with something written after it but text that
// is no key. That tightening is available here and was not available to the
// access key ID, which has no assignment in front of it to say where the value
// begins and so cannot tell a longer run from a key written against a capital.
// Here the name and the assignment say where the value starts, and the byte
// after the fortieth says whether it stopped there. What it costs is a key AWS
// issued longer than forty: nothing of it would be redacted, where reading the
// first forty of a longer run would redact most of one. Against that stands
// what taking the first forty of every longer run costs on text that is no key
// at all — a name assigned a base64 blob, a token of some other shape — which
// is text that exists today. If a key is ever seen coming through whole, the
// count is what to revisit and not the alphabet.
//
// The alphabet is base64's own, the letters of both cases with the digits and
// + and /, and no padding: forty characters carry thirty bytes exactly, so a
// secret written in base64 closes on no =. What leaving = out buys is what a
// run measures. Padding ends one, so thirty-eight characters of somebody else's
// base64 closed by == measure thirty-eight and are no value, where admitting
// the padding would measure them forty and make them one. It says nothing about
// padding written behind a whole run: the forty in front of it are a value and
// are redacted, and the == stays in the text beside the redaction.
//
// The name is three words — secret, access, key — in that order, with one
// separator or nothing between each pair, read without regard to case. That is
// one rule for every way a name is written: SECRET_ACCESS_KEY and
// aws_secret_access_key, the SecretAccessKey and secretAccessKey of an API
// response and an SDK's configuration, the aws-secret-access-key of a workflow
// input, and Secret Access Key written out in words. A vendor's own term is
// what the words are: AWS calls this credential a secret access key, and a
// pattern keyed on that term rather than on a table of spellings does not have
// the table corrected every time somebody writes the name a new way.
//
// What the rule asks for is all three words. AWS_SECRET_KEY, which some SDKs
// read as well, is not located: secret key is a name a dozen unrelated things
// carry — a framework's signing key, a session key, a webhook secret — and the
// forty characters behind it are the only thing that would be left holding the
// pattern up. Asking for access is what keeps the name load-bearing.
//
// Between the name and the value stands a quote, a run of spaces, an
// assignment, another run of spaces and another quote, each of them optional
// and at least one of them written. That covers KEY=v and KEY = v, the
// "SecretAccessKey": "v" of JSON and the key: v of YAML, and the
// aws configure set aws_secret_access_key v of a shell line. Requiring one
// character of it is what gives the value its left edge: none of those
// characters is in the value's alphabet, so a value that starts behind one
// starts where a run starts, and a name written straight against forty
// characters is not a key. The runs of spaces are counted rather than run out,
// which is what keeps the whole of this inside LookBehind.
//
// Each of those is consumed as far as it goes and never given back. That is
// safe rather than lucky: no word of the name opens with a separator, and no
// character between the name and the value is one the value is written with,
// so a shorter reading of either would only put the next thing where it cannot
// stand.
//
// The byte the scan searches for is the c of secret, in both of its cases,
// which builtin_scan.go says why a scan searches for one byte rather than for
// the whole of what it opens with. The letter is the rarest of the six the
// first word is written in — k in the last word is rarer still, but it stands
// at the end of the name and a scan anchored there would read the name
// backwards to find where it began, where this one reads every candidate
// forward from its first character as the scans beside it do.
//
// What bounds a candidate is a count and not a cursor. A name is at most
// awsSecretAccessKeyNameChars characters, an assignment at most
// awsSecretAccessKeySeparatorChars, and a value is read one character past the
// count before it is given up on, so the work at a candidate is bounded
// whatever run it stands in and no candidate can read what another already
// read.
//
// referenceAWSSecretAccessKeyFind in builtin_aws_secret_access_key_test.go
// states the same grammar the plain way, spelling the words, the counts and the
// alphabet again so that the two are changed together, and the fuzz target
// beside it holds this scan to that statement.
var awsSecretAccessKey = NewPattern("aws-secret-access-key", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops settling: a piece of a name standing at the end of
	// it, or a candidate the end of it cut short, whichever comes first.
	retain := awsSecretAccessKeyNameTail(src)

	// Two cursors over the two cases of the anchor, merged. strings.IndexByte
	// is what a scan searches with here and is worth keeping — a walk testing
	// every byte for either case costs three times as much over a line holding
	// no value — and each cursor only ever searches the text past its own last
	// hit, so the two together are one pass over the input rather than one per
	// candidate.
	lower := awsSecretAccessKeyAnchorAt(src, 0, awsSecretAccessKeyAnchor)
	upper := awsSecretAccessKeyAnchorAt(src, 0, awsSecretAccessKeyAnchorUpper)
	for lower >= 0 || upper >= 0 {
		anchor := lower
		if anchor < 0 || (upper >= 0 && upper < anchor) {
			anchor = upper
		}

		// Both cursors are moved off the byte just taken before anything is
		// read, so that every path out of the loop body has already advanced
		// them and a candidate given up on leaves nothing to remember.
		if lower == anchor {
			lower = awsSecretAccessKeyAnchorAt(src, anchor+1, awsSecretAccessKeyAnchor)
		}
		if upper == anchor {
			upper = awsSecretAccessKeyAnchorAt(src, anchor+1, awsSecretAccessKeyAnchorUpper)
		}

		if anchor < awsSecretAccessKeyAnchorIndex {
			continue
		}
		// The next candidate begins one byte past this one: the anchors are
		// visited in order and a name opening one byte along carries its own
		// anchor one byte along, so it is reached at that anchor rather than
		// stepped over. builtin_scan.go sets out why that is the step a scan
		// takes at a candidate.
		start := anchor - awsSecretAccessKeyAnchorIndex

		// The byte a name opens with is tested before the name is read. Every
		// anchor the search stops at reaches this line, and all but the few
		// that open a candidate are turned away by one byte where reading the
		// name is a slice, a length and a walk over three words.
		if src[start]|awsSecretAccessKeyFold != awsSecretAccessKeyWords[0][0] {
			continue
		}

		name, ok, cut := awsSecretAccessKeyNameEnd(src, start)
		if cut {
			// The input ends inside the name, so what stands behind it is not
			// here to be read yet.
			retain = min(retain, start)
			continue
		}
		if !ok {
			continue
		}

		value, ok, cut := awsSecretAccessKeySeparatorEnd(src, name)
		if cut {
			retain = min(retain, start)
			continue
		}
		if !ok {
			continue
		}

		end, ok, cut := awsSecretAccessKeyValueEnd(src, value)
		if ok {
			spans = append(spans, Span{Start: value, End: end})
		}
		if cut {
			// The run reaches the end of the input, so more text can carry it
			// past the count and take the value away again. Whether a span was
			// reported here or not, nothing from the name on is settled.
			retain = min(retain, start)
		}
	}
	return spans, retain
})

// awsSecretAccessKeyWords are the three words a name is made of, in the order
// they are written, spelled in the case the scan folds every candidate into.
//
// The name is derived from these everywhere it is needed — the count below, the
// piece of one standing at the end of the input, the byte the scan searches for
// — so that a name widened here is widened in all of them at once rather than
// in whichever of them somebody remembered.
var awsSecretAccessKeyWords = [...]string{"secret", "access", "key"}

// awsSecretAccessKeyNameChars is the most bytes a name is written in: the words
// themselves and one separator between each pair of them. Nothing lists it,
// because a word added or renamed above would leave a listed count behind and
// the piece of a name this scan settles is measured with it.
var awsSecretAccessKeyNameChars = func() int {
	n := len(awsSecretAccessKeyWords) - 1
	for _, word := range awsSecretAccessKeyWords {
		n += len(word)
	}
	return n
}()

const (
	// awsSecretAccessKeyFold is the bit that separates the two cases of an
	// ASCII letter. A byte or-ed with it equals a lowercase letter only where
	// that byte is one of that letter's two cases, so folding a candidate into
	// lowercase admits the cases of a letter and nothing else.
	awsSecretAccessKeyFold = 0x20

	// awsSecretAccessKeyAnchor is the byte the scan searches the input for and
	// awsSecretAccessKeyAnchorIndex is where it stands in the first of the
	// words above — so a candidate begins that many bytes in front of what a
	// search reported. Test_awsSecretAccessKeyAnchor holds the byte to that
	// index: a first word respelled there would be a word no candidate is ever
	// found at.
	awsSecretAccessKeyAnchor      = 'c'
	awsSecretAccessKeyAnchorUpper = awsSecretAccessKeyAnchor &^ awsSecretAccessKeyFold
	awsSecretAccessKeyAnchorIndex = 2

	// awsSecretAccessKeyChars is the count a value is written to, and
	// awsSecretAccessKeySpaceMax is how far a run of spaces on either side of
	// an assignment is read. The second is a count rather than a run for the
	// reason the rationale gives: what stands between a name and a value is
	// read in front of the value, and LookBehind is what a stream can hand
	// back.
	//
	// What sets the count is that limit and the shape it has to reach. A name
	// and the characters that are not spaces come to
	// awsSecretAccessKeyNameChars and three, so the two runs have twenty-two
	// each to divide between them; sixteen takes most of that and leaves the
	// name room to grow by a word before the two constraints meet. Sixteen is
	// also past any column a name of this length is aligned to, which is the
	// shape a smaller count would miss — a value set out in a table, or a
	// credentials file padded to line its values up, is a value written behind
	// more spaces than one.
	awsSecretAccessKeyChars    = 40
	awsSecretAccessKeySpaceMax = 16

	// awsSecretAccessKeySeparatorChars is the most bytes an assignment is
	// written in: a quote either side of it, the assignment itself, and a run
	// of spaces on each side.
	awsSecretAccessKeySeparatorChars = 2 + 1 + 2*awsSecretAccessKeySpaceMax
)

// awsSecretAccessKeyAnchorAt returns where c stands next in src at or after i,
// and -1 where it stands nowhere from there on.
//
// Both cursors are opened and moved along with it, so that a cursor is only
// ever pointed at text it has not searched: opening one at the front of the
// input and moving one past the byte it just gave up are the same call, and
// neither can be written to search from anywhere else by accident.
func awsSecretAccessKeyAnchorAt(src string, i int, c byte) int {
	if j := strings.IndexByte(src[i:], c); j >= 0 {
		return i + j
	}
	return -1
}

// awsSecretAccessKeyNameEnd returns where the name standing at i in src ends,
// whether one stands there at all, and whether the end of the input is what
// answered.
//
// The third result is what the scan settles by. A name the text turned away is
// settled and a name the end of the input cut short is not, and only this walk
// can tell the two apart: what it compares is what is written of the word
// against that much of the word, so a candidate that has agreed as far as it
// goes and run out is reported as cut rather than as absent.
//
// A separator is taken wherever one stands and never given back. No word opens
// with a separator, so a reading that left one for the word behind it would
// only put that word where it cannot begin.
func awsSecretAccessKeyNameEnd(src string, i int) (int, bool, bool) {
	for w, word := range awsSecretAccessKeyWords {
		if w > 0 && i < len(src) && isAWSSecretAccessKeyWordSeparator(src[i]) {
			i++
		}
		end := min(i+len(word), len(src))
		if !awsSecretAccessKeyEqualFolded(src[i:end], word[:end-i]) {
			return 0, false, false
		}
		if end < i+len(word) {
			return 0, false, true
		}
		i = end
	}
	return i, true, false
}

// awsSecretAccessKeySeparatorEnd returns where the assignment standing at i in
// src ends, whether one stands there at all, and whether the end of the input
// is what answered.
//
// A quote, a run of spaces, an assignment character, another run of spaces and
// another quote, each of them optional and at least one of them written. The
// trailing quote is read whether or not an assignment character stood in front
// of it, which is what carries a name written against a quoted value with
// nothing but a space between them.
//
// One character of it has to be written, and that is what gives a value its
// left edge rather than any test on the byte in front: none of the characters
// read here is one a value is written with, so a value read behind one begins
// where a run of the alphabet begins.
func awsSecretAccessKeySeparatorEnd(src string, i int) (int, bool, bool) {
	start := i
	if i < len(src) && isAWSSecretAccessKeyQuote(src[i]) {
		i++
	}
	i = awsSecretAccessKeySpaceEnd(src, i)
	if i < len(src) && isAWSSecretAccessKeyAssignment(src[i]) {
		i++
		i = awsSecretAccessKeySpaceEnd(src, i)
	}
	if i < len(src) && isAWSSecretAccessKeyQuote(src[i]) {
		i++
	}

	// The end of the input is asked about before the walk's own answer,
	// because a walk that stopped there stopped for want of text: another
	// space, an assignment or a quote arriving carries it further, and a value
	// arriving is what it was reaching for.
	if i == len(src) {
		return 0, false, true
	}
	if i == start {
		return 0, false, false
	}
	return i, true, false
}

// awsSecretAccessKeySpaceEnd returns where the run of spaces beginning at i in
// src ends, reading no more than awsSecretAccessKeySpaceMax of them.
func awsSecretAccessKeySpaceEnd(src string, i int) int {
	for n := 0; n < awsSecretAccessKeySpaceMax && i < len(src) && isAWSSecretAccessKeySpace(src[i]); n++ {
		i++
	}
	return i
}

// awsSecretAccessKeyValueEnd returns where the value standing at i in src ends,
// whether the run there is a value, and whether the end of the input can still
// change that answer.
//
// The run is read one character past the count before it is given up on, which
// is what holds a value to being the whole of its run: forty-one characters of
// the alphabet are no value, and no text appended to them makes one. That is
// also what bounds this walk — it reads at most awsSecretAccessKeyChars+1
// characters however long the run it stands in is.
//
// A run short of the count and reaching the end of the input is unsettled, and
// so is one that is the count exactly: text arriving carries either of them
// further, the first towards a value and the second past one. Where a span is
// reported for the second it is reported all the same, because it is the value
// in the text as handed over, and the offset is what says a stream may not
// write it out yet.
//
// A run already past the count is settled wherever it ends, the end of the
// input included, and that is the one place this walk reads a candidate the end
// cut short rather than giving up on it. What it reads there is the walk above
// and nothing else — the same alphabet against the same count — so it is the
// grammar this file already states rather than a second one kept beside it.
//
// What that buys is the whole of a run rather than a few bytes. Text written
// behind one of these names is as often a base64 blob or a token of some other
// shape as it is a key, and a scan pinned at the name for the length of one
// would hold a stream from the name onwards until WithMaxRetained gave up —
// which is a mebibyte by default, and what a stream does at its limit is redact
// everything it is holding.
func awsSecretAccessKeyValueEnd(src string, i int) (int, bool, bool) {
	end := i
	for end < len(src) && end-i <= awsSecretAccessKeyChars && isAWSSecretAccessKeyByte(src[end]) {
		end++
	}
	switch n := end - i; {
	case n > awsSecretAccessKeyChars:
		return 0, false, false
	case n < awsSecretAccessKeyChars:
		return 0, false, end == len(src)
	default:
		return end, true, end == len(src)
	}
}

// awsSecretAccessKeyNameTail returns where the piece of a name standing at the
// end of src begins, and len(src) where none stands there.
//
// It is what prefixTail (builtin_scan.go) is for the scans whose openings are
// literals: a name the end of the input cut in half opens no candidate at all
// and the scan walks past it having found nothing, so a stream carrying
// SECRET_ACCESS in one write and _KEY=... in the next would release the first
// with the key behind it redacted nowhere. prefixTail cannot serve here — it
// compares bytes, and a name is read without regard to case — so the walk above
// is asked instead, which is what keeps this from becoming a second grammar
// free to disagree with the first.
//
// Only a position carrying the first byte of the first word is asked, in either
// case: every name opens with that word, so a piece of one does too, and the
// bytes in between are turned away by a comparison apiece. The comparison is
// walked here rather than searched for: this reads the last few bytes of the
// input and no more, and over that many bytes a search costs more in the call
// than it saves in the walk.
//
// What turns an input away before any of that is the byte it closes on. A piece
// of a name closes on a byte a name is written with, so an input closing on
// anything else is answered by a single lookup — which is what keeps this off
// the cost of a line holding nothing, since every input a Masker is handed pays
// for it and a line of prose closes on a full stop, a quote or a line break.
func awsSecretAccessKeyNameTail(src string) int {
	if len(src) == 0 {
		return 0
	}
	if last := src[len(src)-1]; awsSecretAccessKeyNameBytes[last>>6]&(1<<(last&63)) == 0 {
		return len(src)
	}
	for i := max(0, len(src)-awsSecretAccessKeyNameChars+1); i < len(src); i++ {
		if src[i]|awsSecretAccessKeyFold != awsSecretAccessKeyWords[0][0] {
			continue
		}
		if _, _, cut := awsSecretAccessKeyNameEnd(src, i); cut {
			return i
		}
	}
	return len(src)
}

// awsSecretAccessKeyNameBytes is every byte a name is written with, in either
// case, as four words of one bit to a byte. awsSecretAccessKeyNameTail reads it
// to answer an input that closes on none of them without walking anything.
//
// It is built from the words and the separator test rather than written out, so
// that a word respelled or a separator admitted reaches it without anyone
// remembering to come here — a byte missing from this set is a piece of a name
// a stream releases, and nothing else would report it.
var awsSecretAccessKeyNameBytes = func() [4]uint64 {
	var set [4]uint64
	add := func(c byte) { set[c>>6] |= 1 << (c & 63) }
	for _, word := range awsSecretAccessKeyWords {
		for i := 0; i < len(word); i++ {
			add(word[i])
			add(word[i] &^ awsSecretAccessKeyFold)
		}
	}
	for c := range 256 {
		if isAWSSecretAccessKeyWordSeparator(byte(c)) {
			add(byte(c))
		}
	}
	return set
}()

// awsSecretAccessKeyEqualFolded reports whether s is word once the case of its
// letters is set aside. word is written in lowercase, and a byte or-ed with
// awsSecretAccessKeyFold equals a lowercase letter only where it is one of that
// letter's two cases, so nothing outside the alphabet the words are written in
// can be folded into one of them.
func awsSecretAccessKeyEqualFolded(s, word string) bool {
	if len(s) != len(word) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i]|awsSecretAccessKeyFold != word[i] {
			return false
		}
	}
	return true
}

// isAWSSecretAccessKeyWordSeparator reports whether c is what may stand between
// two words of a name: the underscore of an environment variable, the hyphen of
// a workflow input, the space of a name written out in words. Nothing at all
// may stand there as well, which is what carries SecretAccessKey, so this is
// what a name may hold rather than what it must.
func isAWSSecretAccessKeyWordSeparator(c byte) bool {
	return c == '_' || c == '-' || c == ' '
}

// isAWSSecretAccessKeyQuote reports whether c is a quote a value may be written
// inside.
func isAWSSecretAccessKeyQuote(c byte) bool {
	return c == '"' || c == '\''
}

// isAWSSecretAccessKeyAssignment reports whether c assigns: the = of an
// environment variable or a credentials file, the : of JSON and YAML.
func isAWSSecretAccessKeyAssignment(c byte) bool {
	return c == '=' || c == ':'
}

// isAWSSecretAccessKeySpace reports whether c is whitespace that may stand
// inside an assignment. A line break may not: a name and the value assigned to
// it are written on one line, and admitting the break would let a name reach
// over the line behind it.
func isAWSSecretAccessKeySpace(c byte) bool {
	return c == ' ' || c == '\t'
}

// isAWSSecretAccessKeyByte reports whether c belongs to the alphabet a value is
// written in: base64's own, the letters of both cases with the digits and + and
// /. Padding is not admitted — forty characters carry thirty bytes exactly, so
// a secret written in base64 closes on no = — and what that decides is where a
// run ends, which the rationale above weighs.
func isAWSSecretAccessKeyByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z' ||
		c == '+' || c == '/'
}
