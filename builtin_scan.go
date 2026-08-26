package mask

// What more than one built-in scan reads. A pattern keeps its own grammar in
// its own file; only what a second pattern has come to need is moved here, so
// that a scan borrowing from another is borrowing something named as shared
// rather than reaching into the pattern it happens to sit beside.
//
// How a scan looks for its candidates is stated here as well, because every
// one of them does it and the reason is the same each time. A scan searches
// the input for one byte of what a candidate opens with and reads that opening
// back from where the byte was found, rather than searching for the opening
// itself. Usually the opening is the prefix a vendor writes a value with, and
// the words below say prefix for that reason; where a value carries no prefix
// of its own it is the name the value is assigned to, and every sentence here
// holds of that just the same.
//
// The two are the same search. strings.Index over a needle short enough to
// matter here searches the text for the needle's first byte and tests what
// stands behind each one it finds, so what a scan pays over a line holding no
// value is settled by how often that first byte is written — and a prefix is
// named by a vendor for what it reads as, not for what is rare in a log. The
// letter a vendor's own name opens with is the letter its host name, its paths
// and the words of the message around them open with too, and an s or a g
// stands in half the words of prose besides. Each of those is a position the
// search stops at, tests and resumes from, and resuming is what costs: the
// walk itself is one pass over the input either way.
//
// So the byte a scan searches for is the rarest one its prefix has, and where
// that byte stands in the prefix is a count the scan keeps beside it. Every
// occurrence of the prefix carries the anchor at that one index, so stepping
// through the anchors and reading the prefix back from each finds exactly the
// candidates a search for the prefix finds, in the same order and no others:
// what changes is which byte the walk stops at, never which text is a value.
// Each pattern's own file names the byte it chose and says what made that one
// the rarest — a count over the input its benchmarks are written on, or a
// character no body of that scan is written with.
//
// The step a scan takes at a candidate and the step its search takes are two
// distances, and it is the first that "What a scan does at a candidate" is
// written in. A scan resuming one byte past the anchor moves its search on by
// one byte and its candidate on by one byte as well, but not to the same
// place: the search resumes at the anchor's own index past the start of the
// candidate, and what that leaves is a next candidate beginning one byte past
// this one. The anchors are visited in order and a candidate opening one byte
// into this one carries its own anchor that far along again, so it is reached
// at that anchor and not stepped over. The step is therefore the default one —
// a byte past the start of the candidate — and a scan wanting a longer one
// still owes the argument for it.
//
// What a scan settles is stated here as well, and for the same reason: every
// scan answers it, and the answer has the same two parts each time.
//
// Pattern.Find asks a scan how far along its input the values it reported can
// no longer change, which is what lets a stream release text rather than keep
// the whole of it. A scan reads a candidate forward from its opening and
// decides it on what stands behind, so there are exactly two places the end of
// the input can leave a scan without an answer. An opening the end cut in half
// opens no candidate at all and the scan walks past it having found nothing:
// that is prefixTail.start below, which a scan whose openings are literals
// calls with its own. A scan opening on something else — a name read without
// regard to case, say — owes the same answer and asks the walk that already
// reads that opening for it, rather than a second grammar free to disagree
// about what an opening is. A candidate whose body the end cut short is the
// scan's own to report, at the candidate, and what it reports there is the
// candidate's start.
//
// A scan gives up on such a candidate rather than reading what is written of
// it. Working out that a truncated candidate could never have become a value
// releases a few more bytes at the end of a write, and it costs a second
// grammar — the grammar of the halves — kept beside the first and free to
// disagree with it. The bytes are not worth that.
//
// What it gives up on there is the candidate and no more, which
// Test_builtins_holdNoFurtherBackThanTheCutCandidate holds it to: the text in
// front of a candidate the end cut short was settled before that candidate
// opened, and a scan pinned in front of it holds a stream open on text that
// was never part of any candidate. Test_builtins_settleWhatIsNoValue asks the
// same of an input that goes on past the candidate and cannot ask it here,
// since every input it builds is followed by prose and so ends inside no
// candidate at all.
//
// Every pattern holds its own anchor to standing at its own index in every
// opening that pattern can match, in a test of its own beside the scan. What
// that test is for is the prefix added later, not the index moved: a pattern
// whose one prefix and index have come apart locates none of the values its
// own cases spell out, and those cases fail by the dozen without any help
// here. An entry added to a table is the silent one. Nothing locates it, so
// nothing that was passing stops passing, the fuzz target beside the reference
// would have to write the new prefix and a body behind it by chance to see the
// difference, and the corpus holds cases for the values a pattern locates
// rather than for the ones it never began to. The test is what turns that into
// a failure, and it names which of the two declarations is wrong.

// segments is where a run of dot separated segments ends, and whether the
// segments a scan asked for are all there. The zero value stands for absent,
// which is what a scan reads before it reaches a dot.
type segments struct {
	end int
	ok  bool
}

// isBase64URLByte reports whether c belongs to the base64url alphabet of RFC
// 4648. It is here rather than in the file of the first scan that needed it so
// that what the alphabet admits is one declaration: a scan spelling the
// alphabet again is one that can come to disagree about what a body may hold,
// and widening it here is a change every scan reading it is measured against
// at once. Which scans those are is what the callers say. A scan reading some
// other alphabet says so in its own file, as the Sentry scan does.
//
// Padding is not admitted: the compact serialization is defined without it, and
// neither the routable payload GitLab encodes nor the key Google shows carries
// any.
func isBase64URLByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z' ||
		c == '-' || c == '_'
}

// base64URLRunEnd returns where the run of base64url characters beginning at i
// in src ends, which is len(src) where the run reaches the end of the input.
//
// Every scan reading a base64url value reads it this way. What is shared is the
// walk alone: which run a scan reads, what it remembers about where that run
// ended and when it may reuse what it remembered are the scan's own, and differ
// between them. A helper taking the byte test as an argument would share more
// and cost an indirect call for every byte of every run, in the loops this
// package is most careful about.
func base64URLRunEnd(src string, i int) int {
	for i < len(src) && isBase64URLByte(src[i]) {
		i++
	}
	return i
}

// isBase62Byte reports whether c belongs to the base62 alphabet: the letters
// of both cases and the digits. Why a scan reading it reads it — a vendor's
// own announcement of the format, the one thing every ruleset behind a prefix
// agrees on, the alphabet a generator draws from — is that scan's to state,
// and it says so in its own file. What is shared is the alphabet, and it is
// one declaration for the reason isBase64URLByte gives.
//
// What it leaves out is what separates it from base64url above: neither the
// hyphen nor the underscore is admitted. Leaving the underscore out is
// load-bearing rather than incidental, and every scan reading this alphabet
// rests on it. A prefix of each of them closes with an underscore, so a run
// read here stops where the next prefix begins: a scan reading a body to the
// end of its run cannot read a run a candidate before it already read, which
// is what rules out the quadratic input a run dense in prefixes would
// otherwise be, and the Notion scan finds a candidate by that character at
// all. Admitting it here would cost every one of those at once, and would let
// a Grafana secret carry the character such a token is divided from its
// checksum by.
func isBase62Byte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z'
}

// base62RunEnd returns where the run of base62 characters beginning at i in src
// ends, which is len(src) where the run reaches the end of the input.
//
// What is shared is the walk alone, for the reason base64URLRunEnd gives: which
// run a scan reads, and what it may take for granted about where the run of the
// candidate before it ended, stay with the scan.
func base62RunEnd(src string, i int) int {
	for i < len(src) && isBase62Byte(src[i]) {
		i++
	}
	return i
}

// prefixTail is how a scan whose openings are literals settles the tail of its
// input, and such a scan reports what it says alongside the candidates it left
// open. A candidate is read forward from a prefix, so a prefix the end of the
// input cuts in half opens no candidate at all and the scan walks past it
// having found nothing: a stream carrying ghp_ in two pieces would be released
// with the first piece written out and the token behind it redacted nowhere.
// What this returns is where such a piece begins, so that the text from there
// on is held back until the rest of the prefix arrives, or until something that
// is no prefix does.
//
// A whole prefix is looked for as well as a piece of one, though a whole prefix
// opens a candidate the scan reports for itself. It costs a comparison and it
// puts the tail of the input in one place rather than in the hands of whichever
// scan is being changed, which is worth the byte it may hold back twice.
//
// The byte a piece would close on is compared before the piece is: two pieces
// of one prefix cannot close on the same byte unless the prefix repeats it, so
// all but one of the lengths tried are turned away by a single comparison, and
// a prefix that stands nowhere near the end of src costs one comparison per
// length rather than one per byte of it. What turns an input away before any of
// that is the set of bytes below.
type prefixTail struct {
	prefixes []string
	// bytes is every byte the prefixes are written with, four words of one bit
	// to a byte. A piece of a prefix standing at the end of the input closes on
	// one of them, so an input closing on anything else is answered by a single
	// lookup rather than by a walk over every prefix.
	//
	// It is what keeps this off the cost of a line holding nothing. Every scan
	// asks this of every input, and a table of a few prefixes is a few dozen
	// comparisons — more than the whole of what some scans pay to walk a log
	// line and find nothing in it. The bytes a prefix is written with are a
	// handful out of two hundred and fifty-six, and the last byte of a line of
	// prose is almost never one of them.
	bytes [4]uint64
}

// newPrefixTail returns a prefixTail over prefixes. A scan builds one once,
// beside its prefixes, rather than at every call.
func newPrefixTail(prefixes ...string) prefixTail {
	t := prefixTail{prefixes: prefixes}
	for _, p := range prefixes {
		for i := 0; i < len(p); i++ {
			t.bytes[p[i]>>6] |= 1 << (p[i] & 63)
		}
	}
	return t
}

// start returns where the longest of the prefixes standing at the end of src
// begins, whole or cut short by the end of the input, and len(src) where none
// of them stands there.
func (t *prefixTail) start(src string) int {
	if len(src) == 0 {
		return 0
	}
	last := src[len(src)-1]
	if t.bytes[last>>6]&(1<<(last&63)) == 0 {
		return len(src)
	}
	return t.walk(src, last)
}

// walk returns what start returns for a src closing on a byte the prefixes are
// written with.
//
// It is a function of its own so that start is small enough to be inlined:
// every scan calls start on every input, almost always to be told by the one
// lookup above that there is nothing here, and a call frame for that answer is
// most of what the answer costs.
func (t *prefixTail) walk(src string, last byte) int {
	start := len(src)
	for _, p := range t.prefixes {
		for k := min(len(p), len(src)); k > 0; k-- {
			if p[k-1] != last || src[len(src)-k:] != p[:k] {
				continue
			}
			start = min(start, len(src)-k)
			break
		}
	}
	return start
}
