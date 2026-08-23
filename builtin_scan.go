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
// installation token carries, the body of a GitLab token, the body of a Google
// API key, the run an OpenAI key is read as, the body of an Anthropic key, the
// body of a PyPI token, both segments of a SendGrid key and the body of a
// HashiCorp Vault token. All nine are here so that changing what the alphabet
// admits is changed against every scan that reads it rather than the first
// few; the Sentry scan says in its own file that the alphabet it reads is not
// this one. Padding is not admitted: the compact serialization is defined
// without it, and neither the routable payload GitLab encodes nor the key
// Google shows carries any.
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
// both cases and the digits. It is what the body of a classic GitHub token is
// written in, what the body of an npm token is written in, what the body of a
// Linear API key is written in, what the body of a Notion API token is written
// in and what the secret of a Grafana service account token is written in —
// npm's own announcement of its format says it matched GitHub's, and the GitHub
// and npm bodies close with six characters of a checksum encoded in this
// alphabet, while the alphabet is all Notion's own rulesets agree on behind
// either of the prefixes it has issued and is the one Grafana's own generator
// draws a secret from.
//
// What it leaves out is what separates it from base64url above: neither the
// hyphen nor the underscore is admitted. The underscore is the character all
// five of those prefixes close with, so a run read in this alphabet stops
// where the next prefix begins, and that is what keeps the first four scans
// from reading one run twice. Admitting it here would cost the first three
// that guarantee at once and make every one of them quadratic on a run dense
// in prefixes, would cost the Notion scan the character it finds a candidate
// by at all, and would let a Grafana secret carry the character its own token
// is divided from its checksum by.
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
