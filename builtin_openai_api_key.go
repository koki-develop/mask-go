package mask

import "strings"

// OpenAIAPIKey locates OpenAI API keys: the project keys the platform issues
// today (sk-proj-), the keys of a service account (sk-svcacct-), the keys of
// the Admin API (sk-admin-) and the user keys issued before projects existed
// (sk-, and the sk-None- written beside them). Every one of them is written the
// same way — the prefix sk-, a run of random characters, the marker T3BlbkFJ,
// and more random characters — and it is that marker, rather than the prefix a
// kind is named for, that this pattern is anchored on.
//
// A key is located wherever it is written, with no word boundary either side,
// and is redacted from its sk- to the end of the run it stands in. So a key
// written against a word character keeps its span, and a character of the key's
// own alphabet written straight after a key is redacted with it.
//
// Its name is "openai-api-key".
func OpenAIAPIKey() Pattern { return openAIAPIKey }

// What OpenAI states and what OpenAI shows are worth separating here, as they
// are wherever a vendor names a prefix and leaves the rest of a format to be
// read off the values it issued, because on this format OpenAI states nothing.
//
// The API reference names the kinds of key — a project key, a service account
// key, an Admin API key — and gives each of them an endpoint that reports a
// redacted_value rather than the key, written sk-abc...def. No length, no
// alphabet and no checksum for any kind appears in OpenAI's documentation, and
// the OpenAPI description OpenAI publishes carries no example key at all.
//
// What is written down elsewhere is the shape of the keys issued, and every
// statement of it agrees on one thing: a key carries the eight characters
// T3BlbkFJ with random characters on either side. Those eight are the base64
// encoding of OpenAI, and they stand inside the key rather than in front of it.
// GitHub lists OpenAI among the partners its secret scanning carries a pattern
// for, under the token identifier openai_api_key, and a marker a scanner can
// search for is what such a partnership is built on — which is why the eight
// characters are read here as part of the format rather than as a regularity of
// the examples.
//
// The two rulesets that state a whole shape state that one. gitleaks reads a
// key as sk-proj-, sk-svcacct- or sk-admin- and seventy-four or fifty-eight
// characters, then T3BlbkFJ, then seventy-four or fifty-eight more — or, for
// the older kind, as sk-, twenty alphanumerics, T3BlbkFJ and twenty more.
// trufflehog reads the same marker with the runs either side left unbounded,
// names sk-service- where gitleaks does not, and declines sk-admin- where
// gitleaks reads it — so the two rulesets do not even agree on the set of
// names.
//
// The marker is the whole of the wager, and it is a good one. Eight characters
// drawn from an alphabet of sixty-four stand in a run of random ones about once
// in three hundred million million characters, so a run carrying them where a
// key carries them is a key. It is also the one part of the format nobody has
// to guess: the rules reading this format state more than one count, reading
// seventy-four or fifty-eight either side for the newer kinds and twenty either
// side for the older, while the marker is the
// same eight characters in every rule that reads one, for the older names and
// the newer alike.
//
// So the runs either side of the marker are read as runs and not as counts. A
// count is read exactly where it is most of what tells a value from the text
// around it, since a run longer than it is then a value with something written
// after it. Here the count tells nothing apart — the marker has already done
// that — and a count that is wrong is a key located nowhere: were OpenAI to
// issue a key with sixty-six characters in front of the marker, a scan asking
// for fifty-eight or seventy-four would find nothing at all and leave a live
// credential in the output whole. Reading to the end of the run is the far
// side of that choice and costs the smaller thing: where a key is written with
// no space in front of a character of its own alphabet, that character is
// redacted with the key. It is the same trade the GitLab scan takes on a
// routable payload, and for the same reason — a wrong shape costs the end of
// an identifier, a wrong count costs the credential.
//
// The alphabet is the base64url one, isBase64URLByte in builtin_scan.go, which
// is the class the rules reading the newer names are written to: a project,
// service account or admin key holds hyphens and underscores between the
// letters and digits of its runs. It is wider than the alphanumerics an older
// key is written in, and that width is admitted rather than told apart — a
// narrower reading of the older kind would buy a boundary nobody needs, since
// the marker inside the run has already said what the run is, and it would end
// a key at the first hyphen the day OpenAI widens the older format as it
// widened the newer one.
//
// Nothing is asked of how many characters stand either side of the marker. A
// floor would be a count again, which is the thing this scan is written not to
// depend on, and what a floor would exclude is no more readable than a key.
// Leaving the far side open matters more than it looks: a line cut at a column
// limit just after the marker still carries every random character in front of
// it, and those are as much of a live credential as the ones that were cut. A
// scan asking for something behind the marker would leave them in the output.
//
// There is no boundary on either side of a match, as there is none in the AWS,
// GitLab and Google scans. A boundary in front would drop the whole match
// rather than trim it wherever a key is written against a word character, as
// OPENAI_API_KEY_sk-proj-... is. One behind would drop rather than trim as
// well, and there is only one place it could be asked here, since this scan
// reads no count to ask it behind: at the end of the run. There it drops the
// key whose run closes on a hyphen and nothing else, since every word character
// belongs to base64url — so the character standing behind a run is never one,
// and a boundary is left asking the key's own last character to be one.
//
// The scan resumes one byte past the start of a candidate whether it became a
// key or not. Every character of sk- belongs to the alphabet a run is written
// in, so the prefix can stand inside a run and a key can begin inside the span
// of the one before it. Consuming a match would step over such a key; the two
// spans then overlap, which a Masker resolves into one.
//
// What this pattern over-matches on: a run of base64url characters carrying sk-
// and then T3BlbkFJ. The eight characters of the marker are rare in random
// text, but they are exactly what base64 writes when the bytes it encodes hold
// the word OpenAI at a position divisible by three — so a base64url encoding of
// a document naming OpenAI carries them about a third of the time, and where
// such an encoding also happens to carry sk- in front of them, the run from
// that sk- to the end of the encoding is redacted. What is taken there is a
// stretch of a value that was already opaque to a reader, and the two
// tightenings on offer are both lists that go stale. One is the count either
// side, which the paragraphs above weigh. The other is a table of the names a
// kind writes between the prefix and its run: asking for proj, svcacct or
// admin would tell such an encoding apart, and it would also have located
// nothing on the day svcacct and admin were added beside proj, and locates
// nothing on the sk-service- key trufflehog reads today. A stale list costs the
// whole credential and the blob costs a reader nothing, which is why neither
// list is kept. The cases in builtin_openai_api_key_test.go pin the over-match
// so that it stays a decision on the record.
//
// What reaches a span is never prose, a git SHA or an MD5. A digest carries no
// hyphen, so it holds no sk- to be found at and no marker either — T and J are
// no hexadecimal digit — and no word is spelled with T3BlbkFJ in it. The text
// has to be an unbroken run of the alphabet carrying both the prefix and the
// eight characters of the marker before the question arises at all.
//
// referenceOpenAIAPIKey in builtin_openai_api_key_test.go keeps the grammar as
// a regular expression, spelling the prefix, the marker and the alphabet again
// so that the two are changed together, and the fuzz target beside it holds
// this scan to that expression.
var openAIAPIKey = newBuiltin("openai-api-key", &openAIAPIKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at
	// the end of it, or a candidate the end of it cut short. builtin_scan.go
	// says why those are the two.
	retain := openAIAPIKeyTail.start(src)

	// The run a key is read as is worked out once and remembered, as the GitLab
	// scan does: every character of the prefix belongs to the run alphabet, so
	// a run can hold a candidate for every three characters it has —
	// sk-sk-sk-sk- is one run, not four — and each of them reading that run to
	// its end costs time quadratic in the length of such a line. A body here is
	// always three characters past the start of its candidate, so it never
	// begins in front of the body of the candidate before it and one cursor
	// serves them all.
	runEnd := -1

	// Where the marker stands is remembered the same way and for the same
	// reason, since finding it is a search over the rest of the input rather
	// than a bounded test. The cursor holds the first marker at or after the
	// body it was last searched from, and len(src) where there is none — which
	// no later body can be past, so a search that found nothing is never
	// repeated. Bodies only ever move forward, so a search that is repeated
	// starts past where the last one stopped.
	//
	// It is filled in before the loop rather than at the first candidate, which
	// is what lets a line holding no key cost one search instead of a walk over
	// every sk- in it. The first marker in the whole input is the first at or
	// after any body in front of it, so seeding it says nothing the loop would
	// not have worked out; where there is none, no candidate can become a key
	// and the scan is over before it starts. That is the ordinary case for text
	// a caller masks, and eight rare characters are cheaper to search for than
	// three common ones are to walk: a hyphenated word carries sk- in the
	// middle of it wherever it is written risk-register or task-list, and every
	// one of those reaches the body of the loop.
	marker := strings.Index(src, openAIAPIKeyMarker)
	if marker < 0 {
		// No marker in the input is no key in it, and what is left to answer
		// is where the input stops being settled. With no marker anywhere,
		// the tail alone decides that: a key is one run carrying the prefix
		// and the marker both, so a run the input has closed can gain
		// neither, and only a run still open at the end of it can become one.
		return nil, min(retain, openAIAPIKeyOpenStart(src))
	}

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], openAIAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not, for the
		// reason the rationale above gives: the prefix is written in the alphabet a
		// run is, so a key can begin inside the span of the one before it.
		offset = anchor + 1

		if anchor < openAIAPIKeyAnchorIndex {
			continue
		}
		start := anchor - openAIAPIKeyAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != openAIAPIKeyPrefix[0] || !strings.HasPrefix(src[start:], openAIAPIKeyPrefix) {
			continue
		}

		body := start + len(openAIAPIKeyPrefix)
		if body >= runEnd {
			runEnd = base64URLRunEnd(src, body)
		}
		if marker < body {
			if j := strings.Index(src[body:], openAIAPIKeyMarker); j < 0 {
				marker = len(src)
			} else {
				marker = body + j
			}
		}

		// One test settles the whole grammar. The marker was searched for from
		// the body, so it stands at or after it; every character of it belongs
		// to the run alphabet, so a marker beginning inside the run ends inside
		// it too. Ending inside the run is therefore the same thing as standing
		// in this candidate's run at all, and a marker past the run is past the
		// run for every candidate behind this one as well.
		if runEnd == len(src) {
			// The run reaches the end of the input, so neither where the key
			// ends nor whether the marker stands in it is settled here: what
			// comes next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if marker+len(openAIAPIKeyMarker) > runEnd {
			continue
		}
		spans = append(spans, Span{Start: start, End: runEnd})
	}
	return spans, retain
})

// openAIAPIKeyOpenStart returns where the earliest candidate standing in the
// run that reaches the end of src begins, and len(src) where no run reaches the
// end of src or the one that does opens no candidate.
//
// It is what the scan answers with when one search has already told it there is
// no key here at all. The walk above is the one that finds candidates and this
// is not a second one: it reads the same prefix, over the one run a key could
// still be written into, and it reads it whole rather than by the anchor
// because there is no line of candidates to step along — there is one run, and
// what is wanted of it is the first prefix in it and nothing else.
func openAIAPIKeyOpenStart(src string) int {
	i := len(src)
	for i > 0 && isBase64URLByte(src[i-1]) {
		i--
	}
	if i == len(src) {
		return len(src)
	}
	if j := strings.Index(src[i:], openAIAPIKeyPrefix); j >= 0 {
		return i + j
	}
	return len(src)
}

const (
	// openAIAPIKeyPrefix is what every kind of key opens with, whichever kind
	// names itself behind it. Every character of it belongs to the alphabet a
	// run is written in, which is what lets one key be written inside another
	// and is why the scan resumes a byte along; Test_openAIAPIKeyPrefix holds
	// it to that.
	openAIAPIKeyPrefix = "sk-"

	// openAIAPIKeyAnchor is the byte the scan searches the input for and
	// openAIAPIKeyAnchorIndex is where it stands in the prefix, so a candidate
	// begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself, and this is the prefix that argument
	// is worst for: sk- is three characters and only two of them are candidates
	// to be the rare one. Over the log line these benchmarks are written on the
	// s stands eight times and the hyphen twice.
	//
	// The k is rarer still on that line — it stands not once — and is passed
	// over all the same, because it is the one character of the three the
	// marker also carries. A run of keys or of markers would then be walked
	// twice over, once at each k, where the hyphen opens one candidate per
	// prefix and no more. What the hyphen gives up is the hyphenated word the
	// rationale above names: risk-register and task-list carry the whole
	// prefix, hyphen included, so they reach the body of the loop, and it is
	// the marker seeded before the loop that keeps a line of them cheap.
	openAIAPIKeyAnchor      = '-'
	openAIAPIKeyAnchorIndex = 2

	// openAIAPIKeyMarker is the base64 encoding of OpenAI, which every rule
	// reading this format asks for between its two runs of random ones. It is
	// what tells a key from the text around it, in place of a count, for the
	// reasons the rationale above gives. Its characters belong to the run
	// alphabet as well, which is what lets it stand inside a run rather than
	// divide one.
	openAIAPIKeyMarker = "T3BlbkFJ"
)

// openAIAPIKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var openAIAPIKeyTail = newPrefixTail(openAIAPIKeyPrefix)
