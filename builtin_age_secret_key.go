package mask

import "strings"

// AgeSecretKey locates age secret keys: the identities age-keygen writes, each
// of which decrypts every file encrypted to the recipient beside it. Two kinds
// carry the name and both are located — the X25519 identity, written
// AGE-SECRET-KEY-1..., and the MLKEM768-X25519 hybrid one age-keygen -pq
// writes, AGE-SECRET-KEY-PQ-1....
//
// Either kind is one of those prefixes and exactly fifty-eight characters of
// the Bech32 alphabet behind it, in the uppercase age writes and reads them in.
// A key is located wherever it stands, with no word boundary either side.
//
// The recipient age prints above a key in an identity file, age1..., is the
// public half of the same key pair and is left in the text.
//
// Its name is "age-secret-key".
func AgeSecretKey() Pattern { return ageSecretKey }

// The prefix is what anchors these, with no boundary on either side of the
// match. A word boundary in front would drop the whole match rather than trim
// it wherever a key is written against a word character, as
// AGE_SECRET_KEY=AGE-SECRET-KEY-1... is, and one behind it would drop a key
// followed by a character of the alphabet. What may stand either side is held
// back by the character classes alone.
//
// The count behind the prefix is exact and comes from the format rather than
// from what has been seen written. An identity of either kind is thirty-two
// bytes; Bech32 writes five bits to a character, which is fifty-two of them,
// and closes with six characters of checksum. So both kinds are fifty-eight
// characters behind their prefix, and one count serves them both.
//
// Being a count and not a floor, a longer run of the alphabet is not one longer
// key but a key with something written after it, and only the key is redacted.
// That costs the tail: a key written against a fifty-ninth character of the
// alphabet leaves that character in the output. Asking for a boundary there
// would leave the key in the output whole instead, which is the worse of the
// two wherever two keys are written with nothing between them.
//
// The six characters a key closes with are a Bech32 checksum over everything in
// front of them, and this does not verify it. What verifying would buy is
// turning away fifty-eight characters of the alphabet that age could not have
// written — text a reader makes nothing of either way, and text a caller with a
// key mistyped into a log still wants redacted. What it would cost is the
// polymod of BIP173 written out twice, once here and once in the reference
// beside it, where the fuzz target holding the two together would have to
// arrive at a valid checksum by chance to report them apart.
//
// The alphabet and the case are both age's. Bech32 admits an all-lowercase
// spelling of any string, but age dispatches on the uppercase prefix before it
// decodes anything, so a lowercase identity is one nothing of age's writes and
// nothing of age's reads.
//
// What this pattern over-matches on is fifty-eight characters of that alphabet
// standing behind one of those prefixes. That is a key's format exactly, so
// there is nothing left in the text to tell such a run from a key age issued,
// and the prefix in front of it — fifteen characters of capitals and hyphens —
// is not something prose arrives at.
//
// The scan keeps no cursor and needs none: a candidate reads at most
// seventy-seven bytes and stops — nineteen of prefix at the wider kind and
// fifty-eight of body — which bounds what it reads with no state to be wrong
// about.
//
// referenceAgeSecretKey in builtin_age_secret_key_test.go keeps the grammar as
// a regular expression, spelling the prefixes, the count and the alphabet again
// so that the two are changed together, and the fuzz target beside it holds
// this scan to that expression.
var ageSecretKey = NewPattern("age-secret-key", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops settling: a piece of a prefix standing at the end
	// of it, or a candidate the end of it cut short, whichever comes first.
	retain := ageSecretKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], ageSecretKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, which is
		// the default step builtin_scan.go sets out.
		offset = anchor + 1

		if anchor < ageSecretKeyAnchorIndex {
			continue
		}
		start := anchor - ageSecretKeyAnchorIndex

		prefix := ageSecretKeyPrefixLen(src[start:])
		if prefix == 0 {
			continue
		}

		body := start + prefix
		end := body + ageSecretKeyBodyChars
		if end > len(src) {
			// The input ends inside this candidate, so what it is cannot be
			// decided here: a key is fifty-eight characters of the alphabet,
			// and the ones still to come are what say whether these are they.
			// What is written of the body is not read before giving up on it,
			// for the reason builtin_scan.go gives.
			retain = min(retain, start)
			continue
		}
		if isAgeSecretKeyBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// ageSecretKeyPrefixes is what a candidate opens with, one entry a kind: the
// human-readable part every secret key carries, what that kind writes behind
// it, and the separator Bech32 divides the two parts of a string by.
//
// They are built from those parts rather than written out, so that a kind added
// to ageSecretKeyKinds is a kind the tail below knows about as well. A table
// written out beside them is one that can come to disagree about which kinds
// there are, and what a stream does with the kind it was not told about is
// release the characters a key opens with.
var ageSecretKeyPrefixes = func() []string {
	prefixes := make([]string, 0, len(ageSecretKeyKinds))
	for _, kind := range ageSecretKeyKinds {
		prefixes = append(prefixes, ageSecretKeyHRP+kind+ageSecretKeySeparator)
	}
	return prefixes
}()

// ageSecretKeyKinds is what each kind of secret key writes between the
// human-readable part and the separator: nothing for the X25519 identity, and
// PQ- for the MLKEM768-X25519 hybrid one.
var ageSecretKeyKinds = [...]string{"", "PQ-"}

const (
	// ageSecretKeyHRP is the human-readable part every secret key opens with,
	// and ageSecretKeySeparator is what Bech32 closes that part with.
	ageSecretKeyHRP       = "AGE-SECRET-KEY-"
	ageSecretKeySeparator = "1"

	// ageSecretKeyBodyChars is what stands behind a prefix: a thirty-two byte
	// identity at five bits to a character, and the six characters of checksum
	// Bech32 closes on.
	ageSecretKeyBodyChars = 58
)

const (
	// ageSecretKeyAnchor is the byte the scan searches the input for and
	// ageSecretKeyAnchorIndex is where it stands in every prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself.
	//
	// What makes it this byte is that the human-readable part is written out
	// of the letters an uppercase name for a credential is written out of.
	// Over the line these benchmarks are written on, the E of the prefix
	// stands eight times, the T four, the A, the R and the S three each, and
	// the C, the G and the hyphen twice apiece, against one K and one Y.
	// Between those last two, a K stands in TOKEN as well as in KEY where a Y
	// stands in KEY alone, so the Y is the one that keeps costing nothing as
	// the text around a key changes.
	//
	// Every prefix carries it at this index, which is what lets one search
	// serve them all: a kind that spelled it elsewhere would be a kind no
	// candidate is ever found at, and Test_ageSecretKeyAnchor reports that.
	ageSecretKeyAnchor      = 'Y'
	ageSecretKeyAnchorIndex = 13
)

// ageSecretKeyPrefixLen returns how many bytes of s the prefix standing at its
// start is, and zero where none of them does.
//
// No two prefixes stand at one position: they agree on the human-readable part
// and then one writes the separator where the other writes the first character
// of its kind, so the first that matches is the only one that can.
func ageSecretKeyPrefixLen(s string) int {
	for _, prefix := range ageSecretKeyPrefixes {
		if strings.HasPrefix(s, prefix) {
			return len(prefix)
		}
	}
	return 0
}

// isAgeSecretKeyBody reports whether s is the body of a secret key: exactly
// ageSecretKeyBodyChars characters, all of them in the Bech32 alphabet.
//
// It is handed the body cut to the count rather than the rest of the input so
// that the count is checked here and not left to the caller to have cut
// correctly.
func isAgeSecretKeyBody(s string) bool {
	if len(s) != ageSecretKeyBodyChars {
		return false
	}
	for i := range len(s) {
		if !isAgeSecretKeyByte(s[i]) {
			return false
		}
	}
	return true
}

// isAgeSecretKeyByte reports whether c belongs to the Bech32 alphabet of
// BIP173, in the uppercase age writes a secret key in: the digits and the
// uppercase letters, less the four characters BIP173 leaves out. Three of them
// — B, I and O — are out because the set is chosen to hold as few characters as
// possible that a reader takes for one another, and the fourth is 1, which is
// the separator: it is chosen from outside the set so that the last one in a
// string is the character closing the human-readable part.
func isAgeSecretKeyByte(c byte) bool {
	return '0' <= c && c <= '9' && c != '1' ||
		'A' <= c && c <= 'Z' && c != 'B' && c != 'I' && c != 'O'
}

// ageSecretKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var ageSecretKeyTail = newPrefixTail(ageSecretKeyPrefixes...)
