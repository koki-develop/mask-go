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
// 4648, which encodes the parts of a JWT, the JWT a stateless GitHub
// installation token carries, and the body of a GitLab token. Padding is not
// admitted: the compact serialization is defined without it, and neither is
// the routable payload GitLab encodes.
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
