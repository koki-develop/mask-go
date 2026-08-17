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
// 4648, which encodes the parts of a JWT and the JWT a stateless GitHub
// installation token carries. Padding is not admitted: the compact
// serialization is defined without it.
func isBase64URLByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z' ||
		c == '-' || c == '_'
}
