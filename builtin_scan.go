package mask

// What more than one built-in scan reads. A pattern keeps its own grammar in
// its own file; only what a second pattern has come to need is moved here, so
// that a scan borrowing from another is borrowing something named as shared
// rather than reaching into the pattern it happens to sit beside.

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
// and widening it here is a change every scan reading it is measured against at
// once. Which scans those are is what the callers say, and they are not listed
// here — a list would have to be corrected by every pattern added, and the one
// it left out would be the scan a widening was never weighed against. A scan
// reading some other alphabet says so in its own file, as the Sentry scan does.
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

// isBase62Byte reports whether c belongs to the base62 alphabet: the letters of
// both cases and the digits. Why each scan reading it reads it is that scan's
// to state — that npm's own announcement of its format says it matched
// GitHub's, that the alphabet is all Notion's rulesets agree on behind either
// prefix it has issued, that it is what Grafana's generator draws a secret
// from — and each says so in its own file. What is shared is the alphabet, and
// it is one declaration for the reason isBase64URLByte gives.
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
