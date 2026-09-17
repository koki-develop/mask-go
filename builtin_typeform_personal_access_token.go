package mask

import "strings"

// TypeformPersonalAccessToken locates the personal access tokens Typeform
// issues for its APIs: the prefix tfp_ and at least forty letters, digits and
// underscores behind it, read on to wherever the run of them ends.
//
// A token is located wherever it is written, with no word boundary either side,
// and is redacted from its prefix to the end of the run it stands in. A space, a
// hyphen, a dot, any other character outside the alphabet, or an uppercase
// prefix ends the reading, so text as it is ordinarily written is not affected.
//
// Its name is "typeform-personal-access-token".
func TypeformPersonalAccessToken() Pattern { return typeformPersonalAccessToken }

// Personal access token is Typeform's own term for the whole of what this
// locates: the page its documentation keeps for the credential is titled for
// that term and uses no other. The term covers the whole rather than part of it
// because the prefix belongs to this credential alone — the OAuth access token
// Typeform's applications page shows carries no prefix at all — so there is no
// second kind of credential under this grammar for the name to fall short of.
//
// The three parts of the grammar rest on different kinds of source, and the
// difference is what the next person widening one of them needs, so each is
// named. A vendor's own format is what the vendor undertakes to keep issuing; a
// detection rule says only that whoever wrote it read some values. Typeform
// publishes one of each, and its detection rule is sorted here with the vendor
// rather than with the third-party rulesets it shares a file format with.
//
// The prefix rests on the vendor's own format. Typeform's documentation states
// tfp_ and writes a token out behind it, and the detection rule Typeform
// publishes for scanning its own repositories reads the same four characters.
// Nothing weaker is involved, which is what a prefix most needs: being wrong
// about one is a pattern that never fires, and nothing downstream reports that.
//
// The alphabet is the letters of both cases, the digits and the underscore, and
// it rests on the vendor's two statements with one third-party rule agreeing.
// Typeform's own detection rule reads letters and digits either side of an
// underscore, and the body its documentation writes out is lowercase
// hexadecimal, which that class already holds. trufflehog reads exactly this
// class and nothing more.
//
// Three characters are declined that one third-party rule admits — the hyphen,
// the dot and the equals sign — and the declining rests on evidence about that
// rule rather than on the silence around them. The class the rule reads them in
// is a shared helper of its own generator, spelled once and used by many of its
// rules, so it states nothing about this format in particular; and a body read
// to the end of its run is where those three characters cost most, since a dot
// or a hyphen written against a token would be redacted with it.
//
// The length rests on four sources that disagree, and the disagreement is the
// reason the count is read as a floor. Typeform's documentation prints a body
// of forty characters. Typeform's own detection rule reads forty to fifty
// characters, an underscore, then eight to sixteen more, which is a body of
// forty-nine to sixty-seven. betterleaks reads a body of exactly fifty-nine.
// trufflehog reads forty to fifty-nine. No two of them describe the same widths,
// and a scan asking for any one of them exactly locates nothing whatever in a
// token of another width — which, like a prefix read wrong, is a pattern firing
// on no text, indistinguishable from a caller whose text held no credential. A
// floor cannot fail that way.
//
// Forty is where the floor goes because it is the lowest width any of the four
// attaches to this prefix, so no token any of them describes is cut short by it.
// Lower would widen what the scan reaches over without reaching a token none of
// them covers, and the exact reading is what to revisit if Typeform ever writes
// a width down.
//
// What the floor costs is the run a token is written against. Where one stands
// in front of more of the alphabet — another token with nothing between them, or
// an opaque value it was written into — the characters past the token are
// redacted with it, and nothing in the text distinguishes them: the body has no
// width of its own to end at.
// Test_TypeformPersonalAccessToken_theBodyReachesTheEndOfTheRun writes that out,
// so that it stays a decision on the record.
//
// It costs a stream more than it costs Mask. A candidate whose run reaches the
// end of the input settles nothing from its prefix on, so a Writer handed a long
// unbroken run carrying a chance tfp_ holds everything from that prefix until
// the run closes — and the alphabet admits the underscore, so what closes one is
// whitespace or punctuation rather than any separator such a run is likely to
// hold. Reaching WithMaxRetained there is giving up, and what a stream writes
// when it gives up is a redaction over everything it was holding. A count would
// bound the wait; the floor is what trades that bound for locating a token of
// any of the four widths.
//
// The prefix is read in lowercase alone. Typeform writes it in no other case,
// and reading either case would locate TFP_ with a body behind it, which is the
// shape an environment variable's name is written in rather than the shape a
// token is.
//
// There is no boundary on either side of a match. A boundary in front would drop
// rather than trim a token written against a word character, and
// TYPEFORM_TOKEN_tfp_... is how one reaches a log line from a shell; a boundary
// behind it would drop a token whose run carries on, which under a floor is
// every token written against more of the alphabet.
// Test_TypeformPersonalAccessToken_nextToWordCharacters pins the shape that pays
// for the first.
//
// The byte the scan searches the input for is the p, two characters into the
// prefix. builtin_scan.go says why a scan searches for one byte of its prefix
// rather than for the prefix itself. Every character of the prefix stands in the
// alphabet a body is written in, so each opens the same number of candidates
// inside a run, and a stop costs one four-byte comparison whichever is chosen —
// which leaves how often each is written in ordinary text as the whole of the
// choice.
//
// The p and the underscore were timed against each other over five shapes of
// text holding no token, and neither wins outright: the underscore is cheaper on
// English prose by about thirty times and on a logfmt line by about three, the p
// on the shapes an underscore is written into — about three times on a line of
// snake_case fields, two and a half on JSON keyed the same way, twenty on a
// listing of environment variables.
//
// The p is taken on the worst of those rather than the best: its dearest shape,
// prose, runs at about 1780 MB/s where the underscore's dearest, the snake_case
// fields, runs at about 870, and a caller masking logs writes all five. So the
// intuition that would settle this without measuring — that an underscore is
// what an environment variable and a log field are written with — is only half
// of it: it holds for three of the shapes and is the wrong way round for two.
// Test_typeformPersonalAccessTokenFindBenchmarks_lineTheAnchorWasChosenAgainst
// holds the line the benchmarks are written on to carrying what was counted.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a token or not, which is the default builtin_scan.go sets
// out. It is load-bearing here rather than merely correct: every character of
// the prefix belongs to the alphabet a body is written in, so the prefix written
// twice with a body behind the second is a token from either position, and a
// scan consuming its match would step over the second and leave it in the output
// whole. The two spans overlap and Masker.locate resolves them.
// Test_TypeformPersonalAccessToken_aTokenBeginningInsideAnother drives it.
//
// What rules out a quadratic input is a cursor over the run. A body is read to
// the end of the run it stands in, and a prefix written in its own body's
// alphabet gives a run no character to be divided at, so a run can hold a
// candidate for every four characters it has and each of them would read that
// run to its end. The run is therefore worked out once and remembered.
//
// What makes reusing it sound is that a body is only ever reached further along:
// candidates open at strictly increasing positions, and a body stands a fixed
// four characters past the start of its own candidate, so a body reached later
// falls at or beyond the one before it, and therefore inside the run already
// walked wherever the cursor is reused at all. A run ends at the first character
// the alphabet does not hold, so it ends in the same place read from anywhere
// inside it.
// Test_TypeformPersonalAccessToken_scanIsLinear drives the input that would find
// the cursor wrong.
//
// What this pattern over-matches on is a run of the right shape that nobody
// issued: four characters written, then forty more of the alphabet with nothing
// between any of them. Prose holds no such run — a body is longer than any word
// and carries no space or punctuation — and standard base64, base32 and
// hexadecimal write no underscore, so an identifier, a certificate body or an
// embedded image carries no candidate at however long it runs.
//
// base64url is the encoding that does write one, and it is worth naming rather
// than leaving to the sentence below, because it is the shape a caller of this
// package is likeliest to be masking a great deal of: a JWT is three base64url
// segments and this package locates those too. A segment carrying tfp_ by
// chance — about one position in sixty-four to the fourth — opens a candidate,
// and the body then runs to the end of that segment, since the dot dividing one
// segment from the next is no character of this alphabet. What that costs is the
// rest of one segment redacted, and, in a stream, held from the prefix until the
// dot arrives.
//
// What is left, base64url included, is a run of letters, digits and underscores
// long enough to spell the prefix inside it, and there the grammar is already as
// tight as the vendor's own: such a run is the same bytes as a token and carries
// nothing to be read it by, so declining it would mean declining every token
// Typeform issues.
// Test_TypeformPersonalAccessToken_insideAnOpaqueRun pins both, the segment
// among them.
//
// referenceTypeformPersonalAccessTokenFind in
// builtin_typeform_personal_access_token_test.go states the same grammar the
// plain way, spelling the prefix, the floor and the alphabet again so that the
// two are changed together, and the fuzz target beside it holds this scan to
// that statement.
//
// It is written out rather than built on an expression, and that was measured
// rather than supposed. Over sixteen thousand bytes of prefixes written one
// against the next — where candidates crowd every four characters, because the
// prefix is written in its own body's alphabet — the walk beside the reference
// takes about fifty milliseconds where ^tfp_[0-9A-Za-z_]{40,} asked at every
// position takes about one and four tenths of a second, which is the machine as
// wide as the floor being run again at every candidate. Over the same length of
// prose, holding no value at all, the walk takes about seventeen microseconds
// and the expression about two milliseconds, because an expression asked at
// every position leaves an engine no literal to skip on.
//
// The fuzz target is not where that difference shows, and it is worth saying so
// where the timings are, since the target is the cheaper thing to reach for.
// Driven for thirty seconds each way it reports more executions for the
// expression than for the walk, not fewer: the inputs a fuzzer generates are far
// too short to crowd candidates the way the two above do. The target alone
// argues the other way, and the timings are what the choice rests on.
var typeformPersonalAccessToken = newBuiltin("typeform-personal-access-token", &typeformPersonalAccessTokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two.
	retain := typeformPersonalAccessTokenTail.start(src)

	// The cursor over the run a body is read along, shared by every candidate
	// standing in that run. The rationale above says why reading the run again
	// at each candidate would be quadratic, and why a body reached later never
	// falls in front of one reached earlier.
	runEnd := -1

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], typeformPersonalAccessTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not,
		// for the reason the rationale above gives: the prefix is written in
		// the alphabet a body is, so a token can begin inside the body of the
		// one before it.
		offset = anchor + 1

		if anchor < typeformPersonalAccessTokenAnchorIndex {
			continue
		}
		start := anchor - typeformPersonalAccessTokenAnchorIndex

		// The whole prefix is in hand at this line: the anchor stands at a
		// fixed index in it, so a search that stopped that many bytes or more
		// into the input has every byte of the prefix behind it. A prefix the
		// end of the input cut short matches nothing here and is left to the
		// tail, which is what settles a piece of one standing there.
		if !strings.HasPrefix(src[start:], typeformPersonalAccessTokenPrefix) {
			continue
		}

		body := start + len(typeformPersonalAccessTokenPrefix)
		// The run is read from this body only where it reaches past what the
		// cursor already holds; a body standing inside that run ends where it
		// ends, since a run is read to the first character that is not one of
		// the alphabet's.
		if body >= runEnd {
			runEnd = typeformPersonalAccessTokenRunEnd(src, body)
		}
		if runEnd == len(src) {
			// The run reaches the end of the input, so neither where the token
			// ends nor whether enough of it is here is settled.
			retain = min(retain, start)
		}
		if runEnd-body >= typeformPersonalAccessTokenBodyChars {
			spans = append(spans, Span{Start: start, End: runEnd})
		}
	}
	return spans, retain
})

const (
	// typeformPersonalAccessTokenPrefix is what every token opens with, stated
	// by Typeform's documentation and read by the detection rule Typeform
	// publishes for its own repositories.
	typeformPersonalAccessTokenPrefix = "tfp_"

	// typeformPersonalAccessTokenAnchor is the byte the scan searches the input
	// for and typeformPersonalAccessTokenAnchorIndex is where it stands in the
	// prefix, so a candidate begins that many bytes in front of what a search
	// reported. builtin_scan.go says why a scan searches for one byte of its
	// prefix rather than for the prefix itself; the rationale above says what
	// made it this byte. Test_typeformPersonalAccessTokenAnchor holds it to
	// standing at this index.
	typeformPersonalAccessTokenAnchor      = 'p'
	typeformPersonalAccessTokenAnchorIndex = 2

	// typeformPersonalAccessTokenBodyChars is how many characters a body is
	// held to, read as a floor rather than exactly. The rationale above weighs
	// the four widths claimed for this format and why the lowest of them is
	// read as a bound.
	typeformPersonalAccessTokenBodyChars = 40
)

// isTypeformPersonalAccessTokenByte reports whether c is a character a body may
// be written with: the letters of both cases, the digits and the underscore.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go,
// which hold what more than one scan reads. What the class is here is the base62
// alphabet with the underscore admitted, and admitting it is this format's own
// decision resting on this format's own sources, so a test shared under a name
// for the class would silently answer for a scan that never weighed it.
func isTypeformPersonalAccessTokenByte(c byte) bool {
	return '0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z' ||
		c == '_'
}

// typeformPersonalAccessTokenRunEnd returns where the run of body characters
// beginning at i in src ends, which is len(src) where the run reaches the end of
// the input.
func typeformPersonalAccessTokenRunEnd(src string, i int) int {
	for i < len(src) && isTypeformPersonalAccessTokenByte(src[i]) {
		i++
	}
	return i
}

// typeformPersonalAccessTokenTail is what the scan settles the tail of its input
// by. prefixTail (builtin_scan.go) says what that is and why it is built once.
var typeformPersonalAccessTokenTail = newPrefixTail(typeformPersonalAccessTokenPrefix)
