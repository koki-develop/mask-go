package mask

import (
	"slices"
	"strings"
)

// DopplerAuthToken locates the auth tokens Doppler issues: the CLI token, the
// personal token, the service token, the service account token, the service
// account identity token, the SCIM token and the audit token, each written as
// dp, the two to five characters naming its kind and forty to forty-four
// letters and digits, with a full stop between each part. A service token may
// carry the name of the environment it was cut for between its prefix and its
// body, which no other kind does.
//
// A token is located wherever it is written, with no word boundary either side,
// and no more than forty-four characters of a body are. So text of that shape
// is redacted whether or not Doppler issued it. A space, a full stop, a hyphen
// or a body shorter than forty characters ends the reading, so text as it is
// ordinarily written is not affected.
//
// Its name is "doppler-auth-token".
func DopplerAuthToken() Pattern { return dopplerAuthToken }

// Doppler states the whole of this grammar itself. Its Auth Token Formats page
// is written for scanners — "Each token uses a unique format to assist with
// secret scanning/identification" — and prints a regular expression and an
// example for each kind it issues. Every
// part of what is read below is off that page: the seven kinds and the words
// Doppler names them by, the prefix each is written with, the alphabet of a
// body, the forty to forty-four characters a body runs to, and the optional
// segment a service token carries. Nothing here is read off a value or
// inferred from a ruleset.
//
// The counts are the vendor's own and are read as the range it wrote rather
// than as the length of what it printed. The example beside each kind is
// forty-three characters, and gitleaks reads exactly that many — its rule is
// dp\.pt\. and forty-three, with a TODO in the same file pointing at this page
// for the other kinds — so a body Doppler admits at forty or at forty-four is
// one that rule locates nowhere. Reading the range is what makes the difference
// a token rather than a near miss.
//
// The seven are one pattern rather than seven, which is a decision about the
// caller and not about the scanning. Not one of them is published by design and
// not one is the identifier another is kept under: every one of them goes into
// the same Authorization header against the same API, and a caller with reason
// to redact any has the same reason for the rest. Nothing a redactor could key
// on separates them either. What is left is the name, and auth token is the
// term Doppler uses for the whole of them — the page collects all seven under
// it, and the API route that tells a caller what it is holding is auth/me.
// Service token names one of the seven, and a name covering less than a pattern
// locates is a name to change rather than a pattern to split.
//
// The service account identity token is the kind no published ruleset reads.
// trufflehog, noseyparker and kingfisher each read six of the seven — ct, pt,
// st, sa, scim and audit — and each leaves dp.said. out; gitleaks reads pt
// alone. The kind is on the vendor's page with the other six and is short lived
// rather than absent, and a scan reading six of seven leaves the seventh in the
// output whole. Test_DopplerAuthToken_theKindNoRulesetReads pins it.
//
// The environment segment is read for the service token alone, which is where
// Doppler writes one. Its page gives the optional group to dp.st. and to no
// other kind, and the example it prints is dp.st.dev. with the body behind it.
// The segment cannot be confused with a body: it runs two to thirty-five
// characters and a body runs forty to forty-four, so at most one of the two
// readings can stand at a given position, and the scan tries the body first for
// no reason but that it is the shorter walk.
// Test_DopplerAuthToken_theSegmentOnlyAServiceTokenCarries drives both sides.
//
// The alphabets are the vendor's two and they differ. A body is letters of
// either case and digits; a segment is lowercase letters, digits, the hyphen
// and the underscore, which is the shape of a Doppler config name. So a segment
// carrying an uppercase letter is no segment, and a body carrying a hyphen is
// no body.
//
// There is no boundary on either side of a match. A word boundary in front
// would drop the whole match rather than trim it wherever a token is written
// against a word character, as DOPPLER_TOKEN_dp.pt.… is, and one behind it
// would drop a token followed by a character of the body's own alphabet. What
// may stand either side is held back by the character classes and the counts
// alone. Every ruleset reading this format asks for \b on both sides, and
// gitleaks' rule additionally reads a body without regard to case, which is the
// same class read twice over rather than a wider one.
//
// The byte the scan searches the input for is the full stop, two characters
// into every prefix. builtin_scan.go says why a scan searches for one byte of
// its opening rather than for the opening itself. Here the choice is settled by
// what a token is made of: neither alphabet admits a full stop, so a body and a
// segment carry none and a run of either alphabet holds no candidate at all.
// Every other byte at a fixed index is a letter both alphabets admit. On
// the line these benchmarks are written on the full stop stands twice against
// the d's four and the p's seven, and that line is the vendor's own host name
// and API path, which is where the two letters are commonest.
//
// What it costs is that a full stop stands twice in every prefix rather than
// once, so a token stops the search a second time under the full stop closing
// its kind. That stop is answered by the two characters read back from it — the
// last two of dp and a kind spell no dp — which is the cheapest this scan
// declines anything.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a token or not, which is the default and needs no argument.
// What it finds there is nothing: a token can hold dp. only where a segment
// closes with dp, and the kind such a candidate would read is the body behind
// it, which is forty characters at least where a kind is five at most.
// Test_DopplerAuthToken_aSegmentClosingWithTheOpening drives that shape.
//
// The scan keeps no cursor and needs none. The kind and the segment are read
// under counts — six bytes and thirty-six — so neither is ever walked twice.
// The body is not: the run it is cut from is read to its end however long that
// run is. What bounds it is where a body opens rather than how far it reads.
// The full stop in front of one is written in neither alphabet, so every body
// begins where a run begins and no two candidates can read the same run, which
// is what rules out the input a run dense in prefixes would otherwise be.
//
// What this pattern over-matches on: a body of the right shape that nobody
// issued. Nine characters at most have to be written, three of them full stops,
// and then forty letters and digits with nothing between any of them. The full
// stops are what make that narrow: base62, base64url and base32 write none at
// all, so a digest, an identifier, a certificate or an embedded image carries no
// candidate at however long it runs, and what is left is a dotted name whose
// segments are spelled dp, a kind Doppler names, and then forty unbroken
// letters and digits.
//
// The collision that is reachable is a digest written behind a prefix, and this
// pattern pays for it rather than ruling it out. Forty hexadecimal characters
// are a SHA-1 and sixty-four are a SHA-256; the first is a body exactly and the
// second is a run the scan cuts a body from, so dp.pt. and either of them is a
// token to this scan. There is nothing left in the text to tell the two apart —
// the vendor's format is that prefix and that many of those characters, and no
// part of it is left over for a digest to fail — so a scan declining this would
// decline every token Doppler issues. A digest with no prefix in front of it is
// turned away, which is what the prefix is for.
// Test_DopplerAuthToken_aDigestBehindThePrefix pins both.
//
// What reaches a span is never prose. Forty unbroken letters and digits are
// longer than any word, and the three full stops in front of them stand two
// characters apart at most.
//
// referenceDopplerAuthToken in builtin_doppler_auth_token_test.go keeps the
// grammar as a regular expression, one branch a kind, spelling the openings,
// the kinds, the counts and both character classes again so that the two are
// changed together. An expression is affordable here: both repetitions are
// bounded, so the machine an engine builds is read once and stops, and every
// branch opens on the same three character literal of which the last is written
// in neither alphabet — so a run of either is a place no search stops, and an
// engine skips the runs this library is handed most of.
var dopplerAuthToken = NewPattern("doppler-auth-token", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := dopplerAuthTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], dopplerAuthTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not.
		// Stepping one byte past the anchor is what leaves the next candidate
		// one byte past this one, which builtin_scan.go sets out.
		offset = anchor + 1

		if anchor < dopplerAuthTokenAnchorIndex {
			continue
		}
		start := anchor - dopplerAuthTokenAnchorIndex
		if !strings.HasPrefix(src[start:], dopplerAuthTokenOpening) {
			continue
		}

		kindEnd, ok, cut := dopplerAuthTokenKindEnd(src, start+len(dopplerAuthTokenOpening))
		if cut {
			retain = min(retain, start)
			continue
		}
		if !ok {
			continue
		}
		kind := src[start+len(dopplerAuthTokenOpening) : kindEnd]
		if !isDopplerAuthTokenKind(kind) {
			continue
		}

		// The body reading first, and the segment only where that fails: a
		// segment closes within thirty-five characters and a body opens on
		// forty, so no position admits both and the order decides nothing but
		// how far the scan walks before it knows.
		body := kindEnd + 1
		end, ok, cut := dopplerAuthTokenBodyEnd(src, body)
		if cut {
			retain = min(retain, start)
		}
		if ok {
			spans = append(spans, Span{Start: start, End: end})
			continue
		}
		if cut || kind != dopplerAuthTokenSegmentedKind {
			continue
		}

		body, ok, cut = dopplerAuthTokenSegmentEnd(src, body)
		if cut {
			retain = min(retain, start)
			continue
		}
		if !ok {
			continue
		}
		end, ok, cut = dopplerAuthTokenBodyEnd(src, body)
		if cut {
			retain = min(retain, start)
		}
		if ok {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// dopplerAuthTokenOpening is what every prefix opens with, the two letters
	// Doppler writes a token with and the separator behind them, and what the
	// scan reads back from its anchor.
	dopplerAuthTokenOpening = "dp."

	// dopplerAuthTokenSeparator divides the parts of a token: the opening from
	// the kind, the kind from what stands behind it, and a service token's
	// environment segment from its body. It is written in neither of the two
	// alphabets below, which is what lets the scan cut a token into its parts
	// by looking for it, and what makes it the byte worth searching for.
	dopplerAuthTokenSeparator = '.'

	// dopplerAuthTokenAnchor is the byte the scan searches the input for and
	// dopplerAuthTokenAnchorIndex is where it stands in every prefix, so a
	// candidate begins that many bytes in front of what a search reported. The
	// rationale above says what made it this byte.
	// Test_dopplerAuthTokenAnchor holds it to standing at this index in every
	// prefix the scan can match, and to being written in neither alphabet.
	dopplerAuthTokenAnchor      = dopplerAuthTokenSeparator
	dopplerAuthTokenAnchorIndex = len(dopplerAuthTokenOpening) - 1

	// dopplerAuthTokenSegmentedKind is the one kind Doppler writes an optional
	// environment segment into, which is the service token. Its page gives that
	// group to this kind and to no other.
	dopplerAuthTokenSegmentedKind = "st"

	// dopplerAuthTokenBodyMinChars and dopplerAuthTokenBodyMaxChars are what
	// stands behind a prefix: the forty to forty-four characters every one of
	// the vendor's seven expressions asks for.
	//
	// The maximum is a cut rather than a demand, which is what reading a range
	// means. A run longer than it is not one longer token but a token with
	// something written after it, and only the token is redacted.
	dopplerAuthTokenBodyMinChars = 40
	dopplerAuthTokenBodyMaxChars = 44

	// dopplerAuthTokenSegmentMinChars and dopplerAuthTokenSegmentMaxChars are
	// the environment segment a service token may carry, two to thirty-five
	// characters closed by a separator. The maximum is a demand rather than a
	// cut: a run longer than it is no segment, since the separator that would
	// have closed one does not stand where a segment ends.
	dopplerAuthTokenSegmentMinChars = 2
	dopplerAuthTokenSegmentMaxChars = 35
)

// dopplerAuthTokenKinds is what stands between the two separators of a prefix,
// one entry a kind, in the order Doppler's own page lists them: the CLI token,
// the personal token, the service token, the service account token, the service
// account identity token, the SCIM token and the audit token.
//
// It is the one declaration saying which kinds there are.
// dopplerAuthTokenPrefixes below reads it rather than writing the prefixes out
// again, and dopplerAuthTokenKindChars is the longest of them rather than a
// number beside them. builtin_scan.go says why: a table kept beside this is one
// that can come to disagree with it, and what a stream would then do with the
// kind it had not been told about is release the characters a token opens with
// and redact nothing.
var dopplerAuthTokenKinds = []string{"ct", "pt", "st", "sa", "said", "scim", "audit"}

// isDopplerAuthTokenKind reports whether s is one of the kinds Doppler names a
// token format for.
func isDopplerAuthTokenKind(s string) bool { return slices.Contains(dopplerAuthTokenKinds, s) }

// dopplerAuthTokenKindChars is the longest kind there is, which is what bounds
// the walk looking for the separator that closes one. It is read out of the
// kinds rather than written beside them, so that a longer kind added is a kind
// the walk still reaches.
var dopplerAuthTokenKindChars = func() int {
	chars := 0
	for _, kind := range dopplerAuthTokenKinds {
		chars = max(chars, len(kind))
	}
	return chars
}()

// dopplerAuthTokenPrefixes is what a candidate opens with, one entry a kind:
// the opening, the kind and the separator closing it.
//
// The kinds are read out of dopplerAuthTokenKinds rather than written out
// again, so that a kind added there is a kind this knows about.
var dopplerAuthTokenPrefixes = func() []string {
	prefixes := make([]string, 0, len(dopplerAuthTokenKinds))
	for _, kind := range dopplerAuthTokenKinds {
		prefixes = append(prefixes, dopplerAuthTokenOpening+kind+string(dopplerAuthTokenSeparator))
	}
	return prefixes
}()

// dopplerAuthTokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var dopplerAuthTokenTail = newPrefixTail(dopplerAuthTokenPrefixes...)

// dopplerAuthTokenKindEnd returns where the kind standing at i in src ends,
// which is the index of the separator closing it, whether a separator closed it
// within the width of the longest kind, and whether the end of the input is what
// stopped the walk.
//
// It reads to the separator rather than trying each prefix in turn, so that the
// kind is read once however many kinds there are. What is behind the separator
// is no business of this walk: it hands back the text between the two and the
// caller asks whether that is a kind.
func dopplerAuthTokenKindEnd(src string, i int) (int, bool, bool) {
	for j := i; j-i <= dopplerAuthTokenKindChars; j++ {
		if j == len(src) {
			// The kind is not closed, and what would close it may yet arrive.
			return 0, false, true
		}
		if src[j] == dopplerAuthTokenSeparator {
			return j, true, false
		}
	}
	// A run wider than the longest kind, which no text carrying on from here
	// can narrow.
	return 0, false, false
}

// dopplerAuthTokenBodyEnd returns where the body standing at i in src ends,
// whether one stands there at all, and whether a character arriving behind the
// end of the input could still change either answer.
//
// The count is a range, which is what makes the third answer worth having on
// its own. A run reaching the maximum is cut there and nothing further can move
// the cut, so such a body is settled although the run reaches the very end of
// the input — the same walk over the same alphabet against the same count rules
// out every text carrying on from it, so no second grammar is kept. That is
// what saves a stream a long run: a base64url payload written behind a prefix
// would otherwise be held to the limit and redacted there.
//
// A shorter run is settled only where the text itself ended it. A run the end
// of the input stopped is a body already where it has reached the minimum, and
// this reports it as one — Mask is handed the whole text and would leave a
// token of forty-three characters in the output otherwise — but a character
// arriving would lengthen the very span it reported, so the answer is a span
// and a candidate the scan is still holding.
func dopplerAuthTokenBodyEnd(src string, i int) (int, bool, bool) {
	end := base62RunEnd(src, i)
	if end-i >= dopplerAuthTokenBodyMaxChars {
		return i + dopplerAuthTokenBodyMaxChars, true, false
	}
	if end-i >= dopplerAuthTokenBodyMinChars {
		return end, true, end == len(src)
	}
	return 0, false, end == len(src)
}

// dopplerAuthTokenSegmentEnd returns where the environment segment standing at
// i in src ends — the index behind the separator closing it, which is where the
// body then opens — whether one stands there at all, and whether the end of the
// input is what stopped the walk.
//
// The walk stops at the widest segment there can be and then looks at the
// character standing behind it, so a run longer than a segment is turned away
// without being read to its end. That is what keeps a prefix written in front
// of a long run of lowercase from walking that run a second time.
func dopplerAuthTokenSegmentEnd(src string, i int) (int, bool, bool) {
	j := i
	for j < len(src) && j-i < dopplerAuthTokenSegmentMaxChars && isDopplerAuthTokenSegmentByte(src[j]) {
		j++
	}
	if j == len(src) {
		// Either the separator that would close a segment or the character
		// that would make the run too wide for one may yet arrive.
		return 0, false, true
	}
	if src[j] != dopplerAuthTokenSeparator || j-i < dopplerAuthTokenSegmentMinChars {
		return 0, false, false
	}
	return j + 1, true, false
}

// isDopplerAuthTokenSegmentByte reports whether c belongs to the alphabet a
// service token's environment segment is written in: lowercase letters, digits,
// the hyphen and the underscore, which is the shape of a Doppler config name.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go,
// which hold what more than one scan reads. What separates it from the base62
// alphabet a body is read in is the case and the two punctuation characters,
// and it is the difference between the two that lets a segment and a body be
// told apart at all.
func isDopplerAuthTokenSegmentByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'a' <= c && c <= 'z' ||
		c == '-' || c == '_'
}
