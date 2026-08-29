package mask

import "strings"

// SourcegraphAccessToken locates the access tokens the Sourcegraph GraphQL API
// takes: the prefix sgp_, an instance identifier and the separator behind it
// where one is written, and the forty hexadecimal characters that are the token
// value. A token carrying no identifier is forty-four characters, one carrying
// the identifier a licensed instance writes is sixty-one, and one carrying the
// identifier a development instance writes is fifty.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly forty-four, fifty or sixty-one characters of it are. So text of
// that shape is redacted whether or not Sourcegraph issued it. A letter past f,
// a body of the wrong length or an identifier of neither shape ends the
// reading, so text as it is ordinarily written is not affected.
//
// Its name is "sourcegraph-access-token".
func SourcegraphAccessToken() Pattern { return sourcegraphAccessToken }

// Sourcegraph publishes the grammar of this format itself, on a page written
// for the scanners that read it: doc/dev/security/secret_formats.md names each
// secret it issues and gives the expression matching it. Access token is the
// name it puts on this one, and the page divides the format into three versions
// under that one name — sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}, which it
// calls v3, sgp_[a-fA-F0-9]{40}, which it calls v2 and marks deprecated, and
// forty hexadecimal characters with nothing in front of them, which it calls v1
// and marks deprecated as well. Which version an instance issues depends on its
// own version, and it says so: newer instances stay backwards-compatible with
// every older form, so all three authenticate today.
//
// The generator behind the page agrees with it and says more. Sourcegraph's own
// internal/accesstoken/personal_access_token.go writes twenty random bytes as
// hexadecimal, which is the forty characters, and puts an identifier in front
// of them: the first sixteen characters of an HMAC-SHA-256 of the instance's
// license key, written as hexadecimal, or the word local where the instance is
// a development one or holds no license key. So the prefix, the two identifiers,
// the alphabet and both counts are read off the vendor's own statement of what
// a token is rather than off a ruleset — though gitleaks and trufflehog both
// read the page's expression back character for character.
//
// What the identifier is for is attribution rather than authentication.
// Sourcegraph states that it is deliberately not verified, so a token whose
// identifier was edited still authenticates. What is read here is the
// identifier as an instance
// writes it, which is what the vendor's own expression asks a scanner for. The
// cost is the token somebody edited by hand: sgp_ and a word that is neither
// sixteen hexadecimal characters nor local is no candidate here, however well
// the value behind it still works.
//
// The version with no prefix at all is declined, and it is the one decision
// here that is not the vendor's. Forty hexadecimal characters with nothing in
// front of them are a git commit name, a SHA-1 of anything, and the digest half
// of a lock file line — values a reader is meant to read — so a pattern
// admitting them would take meaning out of text rather than a secret, which is
// what the gate in .claude/rules/builtin-patterns.md rules out. The prefix is
// the whole of the anchor and there is no other net to cast: a bare body
// carries nothing that says it is a credential. What declining costs is a token
// issued before the prefix existed and never rotated since, left in the output
// whole. Test_SourcegraphAccessToken_aBareBody pins the decision.
//
// The alphabet is hexadecimal in either case, where the Pulumi and Supabase
// bodies beside it are read lowercase alone, and the difference is the vendor's
// rather than a taste. Sourcegraph says so twice: the expression on the secret
// formats page is written [a-fA-F0-9] at every one of its three positions, and the
// parser the API authenticates with, lib/accesstoken/personal_access_token.go,
// is written the same way, so an uppercased token is a token the vendor accepts
// and this library may not leave in the output. The generator writes lowercase,
// which makes the uppercase half a case nothing mints and everything accepts —
// and a credential the vendor authenticates is a credential to redact.
// Test_SourcegraphAccessToken_anUppercaseBody pins the half of the class the
// generator never writes.
//
// The counts are read exactly rather than as floors, the vendor having stated
// both of them twice over. A run longer than forty is not one longer token but a token with something
// written after it, and only the token is redacted; a run of seventeen
// hexadecimal characters where an identifier stands is no identifier, and the
// candidate is then read as the form carrying none.
//
// The three forms are read together because they are one credential to a
// caller. They are one string to Sourcegraph as well: its parser strips
// whichever prefix and identifier it is handed and looks the same forty
// characters up, so the three are one token written three ways rather than
// three kinds of token. Nothing about any of them asks to be switched on
// without the others or labelled apart from them, and declining the two the
// vendor calls deprecated would leave a live GraphQL credential in the output.
//
// Which of the readings applies is settled by the character behind the prefix,
// and they cannot both apply. The word local opens with a letter no
// hexadecimal identifier and no value is written with, so a candidate carrying
// it has a letter where either other reading needs a digit. And the two
// hexadecimal readings are told apart by the character sixteen along: the
// separator dividing an identifier from a value where a token carries one, and
// a seventeenth character of the value where it does not, which no run can be
// at once. So the scan reads the candidate once and takes the reading it lands
// in, rather than trying the shorter one after the longer one failed.
// Test_SourcegraphAccessToken_theReadingsAreExclusive holds it.
//
// There is no boundary on either side of a match, and the tightening on offer
// in front is the one the Slack and Stripe scans take: to ask that no letter
// and no digit stand before the prefix. It is declined. No word is spelled with
// sgp at the end of it, so the shape the demand would turn away is one neither
// published rule reading this format has shipped a false positive of, and what
// it would cost is a token written straight against a word character —
// SRC_ACCESS_TOKEN_sgp_... is how one reaches a log line from a shell — dropped
// whole rather than trimmed. A boundary behind a match would drop a token
// followed by a hexadecimal digit.
//
// No token can be written inside another, and what the scan rests that on is
// the letter its prefix opens with. Everything a span covers is the prefix, an
// identifier, a separator and hexadecimal characters, and the s the prefix
// opens with is neither of the two letters behind it in the prefix, is not the
// separator, is no letter of the word local and is no character a value may
// hold. So no position inside a span opens a prefix, and the spans this scan
// reports never overlap one another.
// Test_SourcegraphAccessToken_noTokenBeginsInsideAnother holds the claim.
//
// The scan resumes one byte past the start of a candidate all the same, which
// is the default, and what it is for is the candidate that failed rather than
// the one that became a token. sgp_sgp_ and a body is a candidate at the first
// prefix whose identifier would open with an s no identifier may hold, and a
// whole token at the second; a scan resuming past the length the first
// candidate hoped for would step over it.
//
// The scan keeps no cursor and needs none: a candidate reads at most sixty-one
// bytes and stops, which bounds what it reads with no state to be wrong about,
// and is what rules out a quadratic input.
//
// The byte the scan searches the input for is the underscore the prefix closes
// with, and the prefix is read back from it. builtin_scan.go says why a scan
// searches for one byte of its prefix rather than for the prefix itself; what
// makes it this byte is that the three letters in front of it are ordinary
// ones, and that the word Sourcegraph's own name, host names and paths are
// spelled with carries every one of them. Over the log line these benchmarks
// are written on the s stands five times, the g four and the p four, where the
// underscore stands once. None of the four is a hexadecimal character, so a
// digest stops the search not once whichever is chosen, and what separates them
// is prose alone. The underscore's own cost is that a token carrying an
// identifier carries a second one, so a line of such tokens stops the search
// twice a token; what stands three characters in front of that second
// underscore is a character of an identifier rather than the s the prefix opens
// with, so each of those stops is answered by one comparison.
//
// What this pattern over-matches on is a digest written behind the prefix, and
// that collision is the price of the format being what it is. Forty hexadecimal
// characters are a SHA-1, so the prefix written straight in front of one is a
// token character for character and the whole of it is redacted; an MD5 is
// thirty-two and is turned away by the count; a SHA-256 is sixty-four, of which
// the first forty are a value, so the prefix and forty of its characters go and
// twenty-four stay. Redacting the first of those is right for the reason
// the count is read at all: the prefix and forty hexadecimal characters are the
// vendor's format exactly, there is nothing left in the text to tell the two
// apart, and declining the run would decline every token Sourcegraph ever
// issued. Test_SourcegraphAccessToken_aDigestBehindThePrefix pins all of it.
//
// The prefix sgph_ is not read. Sourcegraph's parser accepts it in place of
// sgp_, but it appears in no format the secret formats page documents and
// nothing in the repository mints one: it is a prefix the vendor will strip
// rather than one the vendor writes, and reading it would widen the net over
// text no instance has ever produced.
//
// referenceSourcegraphAccessToken in builtin_sourcegraph_access_token_test.go
// keeps the grammar as a regular expression, spelling the prefix, the
// identifiers, the counts and the character class again so that the two are
// changed together, and the fuzz target beside it holds this scan to that
// expression.
var sourcegraphAccessToken = NewPattern("sourcegraph-access-token", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two.
	retain := sourcegraphAccessTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], sourcegraphAccessTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not.
		// No token can be written inside another, which the rationale above
		// argues, so what this is for is the candidate that failed: sgp_sgp_
		// and a body carries a whole token at its second prefix, and resuming
		// past the length this candidate hoped for would step over it.
		// Stepping one byte past the anchor is what leaves the next candidate
		// one byte past this one, which builtin_scan.go sets out.
		offset = anchor + 1

		if anchor < sourcegraphAccessTokenAnchorIndex {
			continue
		}
		start := anchor - sourcegraphAccessTokenAnchorIndex

		// The byte the prefix opens with is tested before the prefix is
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != sourcegraphAccessTokenPrefix[0] || !strings.HasPrefix(src[start:], sourcegraphAccessTokenPrefix) {
			continue
		}

		end, ok, cut := sourcegraphAccessTokenEnd(src, start+len(sourcegraphAccessTokenPrefix))
		if cut {
			// The input ends inside this candidate, so neither which of the
			// three forms it is nor the count that tells it from anything else
			// written behind the prefix can be taken here.
			retain = min(retain, start)
			continue
		}
		if ok {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// sourcegraphAccessTokenPrefix is what every token the vendor's secret
	// formats page still documents opens with, and what the scan reads back
	// from its anchor. Two of its characters are load-bearing.
	//
	// The s it opens with it carries nowhere else, no value may hold and the
	// word local does not, which is the whole of the claim that no token can
	// begin inside another. The underscore it closes with belongs to no value
	// either, so a run of value characters can never hold the prefix and every
	// body begins where such a run begins — which is not what bounds this scan,
	// since the counts are, but is what a count relaxed to a floor would have
	// to fall back on. Test_sourcegraphAccessTokenPrefix holds the prefix to
	// both.
	sourcegraphAccessTokenPrefix = "sgp_"

	// sourcegraphAccessTokenAnchor is the byte the scan searches the input for
	// and sourcegraphAccessTokenAnchorIndex is where it stands in the prefix,
	// so a candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what made it
	// this byte and what it costs.
	sourcegraphAccessTokenAnchor      = '_'
	sourcegraphAccessTokenAnchorIndex = 3

	// sourcegraphAccessTokenLocalIdentifier is the instance identifier written
	// in place of a hexadecimal one where an instance is a development one or
	// holds no license key. It opens with a letter no identifier and no value
	// is written with, which is what settles the reading of a candidate in one
	// byte. Test_sourcegraphAccessTokenLocalIdentifier holds it there.
	sourcegraphAccessTokenLocalIdentifier = "local"

	// sourcegraphAccessTokenIdentifierChars is how many hexadecimal characters
	// a licensed instance writes as its identifier: the first sixteen of an
	// HMAC-SHA-256 of its license key.
	sourcegraphAccessTokenIdentifierChars = 16

	// sourcegraphAccessTokenSeparator divides an identifier from the value
	// behind it. It is the character the prefix closes with as well, which is
	// what makes a token carrying an identifier carry two of them.
	sourcegraphAccessTokenSeparator = '_'

	// sourcegraphAccessTokenValueChars is how many hexadecimal characters the
	// value is: twenty random bytes as the generator writes them.
	sourcegraphAccessTokenValueChars = 40
)

// sourcegraphAccessTokenEnd returns where the token whose body begins at body
// ends, whether a token stands there at all, and whether the end of the input
// is what answered that.
//
// The three forms are decided here and nowhere else, which is what keeps the
// scan above from trying one reading after another: the identifier is read
// first, and where none stands the value is read from the body itself.
//
// Both halves are walked rather than measured against what is left of the
// input, and that is what lets a candidate the end of the input cut short be
// told from one the text ruled out. A candidate could be any of three lengths,
// so there is no one count to measure against before the body has been read —
// and measuring against the longest would hold back a token of the shortest
// form standing at the end of a write. The walk is the grammar and nothing
// else, the same alphabet against the same counts, so a candidate it turns away
// is turned away for every text carrying on from it rather than for the one in
// hand. What measuring would cost besides is the sixty-one bytes a stream would
// hold back at every sgp_ written in front of a word.
func sourcegraphAccessTokenEnd(src string, body int) (int, bool, bool) {
	value := body
	v, ok, cut := sourcegraphAccessTokenValueStart(src, body)
	if cut {
		return 0, false, true
	}
	if ok {
		value = v
	}
	return sourcegraphAccessTokenHexEnd(src, value, sourcegraphAccessTokenValueChars)
}

// sourcegraphAccessTokenValueStart returns where the value behind an instance
// identifier standing at body begins, whether an identifier stands there at
// all, and whether the end of the input is what answered that.
//
// An identifier is optional, so a body with none is no failure: what it reports
// then is that the value begins at the body itself, and the caller reads it
// from there.
func sourcegraphAccessTokenValueStart(src string, body int) (int, bool, bool) {
	if body == len(src) {
		// The prefix stands at the end of the input, so which of the three
		// forms this candidate is has nothing at all to be read from.
		return 0, false, true
	}

	// One byte settles which of the two identifiers could stand here: the word
	// opens with a letter no hexadecimal identifier is written with.
	if src[body] == sourcegraphAccessTokenLocalIdentifier[0] {
		end := body + len(sourcegraphAccessTokenLocalIdentifier)
		if end > len(src) {
			if strings.HasPrefix(sourcegraphAccessTokenLocalIdentifier, src[body:]) {
				return 0, false, true
			}
			return 0, false, false
		}
		if src[body:end] != sourcegraphAccessTokenLocalIdentifier {
			return 0, false, false
		}
		return sourcegraphAccessTokenSeparated(src, end)
	}

	end, ok, cut := sourcegraphAccessTokenHexEnd(src, body, sourcegraphAccessTokenIdentifierChars)
	if !ok {
		return 0, false, cut
	}
	return sourcegraphAccessTokenSeparated(src, end)
}

// sourcegraphAccessTokenHexEnd returns where the n hexadecimal characters
// standing at i in src end, whether n of them stand there at all, and whether
// the end of the input is what answered that.
//
// The identifier and the value are read by the same walk against different
// counts, which is what keeps the alphabet one declaration between them rather
// than two free to come apart.
func sourcegraphAccessTokenHexEnd(src string, i, n int) (int, bool, bool) {
	end := i + n
	for ; i < end; i++ {
		if i == len(src) {
			return 0, false, true
		}
		if !isSourcegraphAccessTokenHexByte(src[i]) {
			return 0, false, false
		}
	}
	return end, true, false
}

// sourcegraphAccessTokenSeparated returns where the value behind the separator
// standing at i begins, whether the separator stands there at all, and whether
// the end of the input is what answered that.
//
// An identifier of the right shape with no separator behind it is no
// identifier, and the candidate is then read as the form carrying none: a
// seventeenth hexadecimal character is a character of the value rather than a
// seventeenth of an identifier.
func sourcegraphAccessTokenSeparated(src string, i int) (int, bool, bool) {
	if i == len(src) {
		return 0, false, true
	}
	if src[i] != sourcegraphAccessTokenSeparator {
		return 0, false, false
	}
	return i + 1, true, false
}

// isSourcegraphAccessTokenHexByte reports whether c is a hexadecimal digit of
// either case, which is what an identifier and a value are written in.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go,
// which hold what more than one scan reads. Every hexadecimal run this package
// reads keeps its own test for the reason its own file gives — one admits
// either case where another admits lowercase alone — and a shared test named
// for the class rather than for what reads it would silently be the wrong
// answer for one of them.
func isSourcegraphAccessTokenHexByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// sourcegraphAccessTokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var sourcegraphAccessTokenTail = newPrefixTail(sourcegraphAccessTokenPrefix)
