package mask

import "strings"

// HuggingFaceUserAccessToken locates Hugging Face user access tokens: the
// prefix hf_ and the thirty-four letters and digits behind it — thirty-seven
// characters altogether. One string serves every role a token is issued under,
// so nothing in a token says whether it may read a private repository, write to
// one, or reach only the resources a fine-grained token was scoped to.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly thirty-seven characters of it are. So text of that shape is
// redacted whether or not Hugging Face issued it. A space, a hyphen, an
// underscore or a run of fewer than thirty-four letters and digits ends the
// reading, so text as it is ordinarily written is not affected. A longer run is
// a token with something written after it, and the token alone is redacted.
//
// Its name is "huggingface-user-access-token".
func HuggingFaceUserAccessToken() Pattern { return huggingFaceUserAccessToken }

// User access token is Hugging Face's own name for this string, the title of
// the page its documentation keeps on it and the term GitHub's partner pattern
// for the same value is filed under. The page names the three roles a token is
// issued under — fine-grained, read and write — and gives each of them the same
// string with no mark on it to tell one from another, which is why the roles
// put no boundary between patterns: a caller cannot act on a distinction the
// value does not carry.
//
// What Hugging Face states in prose and what Hugging Face states in code are
// worth separating, because on this format the prose stops at the prefix. The
// documentation writes a token as hf_... wherever it shows one, and the client
// libraries ask no more than that: huggingface_hub and @huggingface/hub each
// test a credential with a prefix comparison alone, which is how they tell a
// token of Hugging Face's own from the third-party provider keys sent through
// the same argument. Neither a length nor an alphabet appears in any of that.
//
// What states both is Hugging Face's own inference playground, which validated
// a token pasted into it against \bhf_[a-zA-Z0-9]{34}\b — the prefix, a count
// of thirty-four, and the letters of both cases with the digits. That is the
// vendor writing down its own format rather than a reader inferring one from
// the tokens it has seen, and the count and the alphabet below are read off it.
//
// The rulesets agree on the prefix and on the count, and divide on the
// alphabet. trufflehog reads hf_ and thirty-four letters and digits; kingfisher
// reads the same alphabet with the prefix matched in either case and drops what
// falls below an entropy floor. gitleaks and Google's osv-scalibr read
// thirty-four letters with no digit admitted, which rests on the tokens that
// have been published being spelled that way. GitHub carries the format as a
// partner pattern with push protection, under the token identifier
// hf_user_access_token, and publishes what it detects rather than the
// expression it detects with.
//
// So the alphabet is the wider of the two, isBase62Byte in builtin_scan.go. The
// narrower one is available and is declined: what it would cost the first time
// a token carries a digit is not the end of a credential but the whole of it,
// left in the output with nothing found.
//
// The count is read exactly rather than as a floor. A run longer than
// thirty-four is not one longer token but a token with something written after
// it, and only the token is redacted; running the alphabet out instead would
// swallow whatever word was written against the end of one. Hugging Face states
// no second shape behind this prefix, so reading it exactly turns away nothing
// a range would have caught.
//
// The prefix is read in the one case Hugging Face writes it, which is a
// decision this format makes it worth stating plainly: HF_ in uppercase is how
// the environment variable holding a token is spelled, and HF_HOME and
// HF_HUB_CACHE are spelled that way beside it. A scan reading the prefix in
// either case would open a candidate at each of those, and the thirty-four
// characters it would then ask for are all that would stand between an
// environment dump and a redaction over a path.
//
// There is no boundary on either side of a match. A boundary in front drops
// rather than trims the match wherever a token is written against a word
// character, which is what HUGGINGFACE_TOKEN_hf_... is; one behind it drops a
// token followed by a letter or a digit, which under an exact count is a token
// with a character written after it. What may stand either side is held back by
// the character class and the count alone.
//
// The tightening on offer in front is to ask that no letter and no digit stand
// before the prefix. It is declined for the reason the paragraph above gives,
// and what it would turn away is narrow enough to name: a word closing on hf
// with a token written straight against it. Against that stands the assignment
// above, which is text people write.
//
// The byte the scan searches the input for is the underscore the prefix closes
// with, and the prefix is read back from it. builtin_scan.go says why a scan
// searches for one byte of its prefix rather than for the prefix itself; what
// makes it this byte is that the other two are letters of ordinary text. Over
// the log line these benchmarks are written on the h stands three times and the
// f twice, where the underscore stands not once — and over a token the
// underscore stands once, since the alphabet a body is read in leaves it out,
// so a run of a body opens no candidate however long it runs.
//
// That same character bounds where a token may be written inside another,
// without ruling it out. A candidate begins two characters in front of the
// underscore its prefix closes with, and the one underscore a span holds is
// that of its own prefix, so the positions inside a span that open a candidate
// are the last two characters of the body and no others: from either of those
// the underscore reading them back stands past the end of the span, where
// anywhere earlier it would have to stand inside the body and a body has none.
// A body closing on hf with an underscore written after it is such a token,
// thirty-five characters into the one it stands in.
// Test_HuggingFaceUserAccessToken_aTokenInsideAToken drives that shape, and
// Test_huggingFaceUserAccessTokenPrefix counts the positions.
//
// So the scan steps one byte past the start of a candidate, whether that
// candidate became a token or not, which is the default: consuming a match
// would step over a token beginning at the end of it and leave that one in the
// output whole. The two spans overlap where it happens, and Masker.locate
// resolves them.
//
// The scan keeps no cursor and needs none: a candidate reads at most
// thirty-four bytes and stops, which bounds what it reads with no state to be
// wrong about, and is what rules out a quadratic input.
//
// What this pattern over-matches on is thirty-four letters and digits written
// behind the prefix, which is the vendor's format exactly, and the shape worth
// stating is the digest: a SHA-1 is forty hexadecimal characters and a SHA-256
// sixty-four, so hf_ written in front of either is redacted for thirty-four of
// them with the rest left in the text. There is nothing left to tell the two
// apart — a scan declining thirty-four letters and digits behind this prefix
// declines every token there is — and what has to be written to reach it is the
// prefix with a digest against it and nothing between.
// Test_HuggingFaceUserAccessToken_aDigestBehindThePrefix pins the decision. An
// MD5 is thirty-two characters and reaches nothing at all, being two short.
//
// The other shape is base64url text, and it is the one the prefix is written by
// accident in. That alphabet holds the underscore where hexadecimal and
// standard base64 do not, so a payload written in it — a JWT signature, the
// routable body some other vendor encodes a credential as — carries hf_ about
// once in two hundred and sixty thousand characters, and where the thirty-four
// behind it are letters and digits alone those thirty-seven are redacted. What
// is taken there is a stretch of a value that was already opaque, and it is a
// token's format exactly, so a pattern letting it through would let a real
// token through with it.
// Test_HuggingFaceUserAccessToken_thePrefixInsideBase64URL pins it.
//
// What reaches a span is never prose: the prefix closes on an underscore, which
// no word runs into, and behind it must stand thirty-four unbroken letters and
// digits.
//
// Two Hugging Face credentials are left alone, and the alphabet is what leaves
// them. The OAuth access token an application receives is written hf_oauth_ and
// then a body Hugging Face publishes nothing of, and the underscore closing
// oauth is no character a body may hold, so a candidate opened at the prefix is
// turned away five characters in. The organization API token is written
// api_org_ and carries no hf_ to be found at; Hugging Face deprecated it and
// its documentation no longer names it, and it is a credential this pattern's
// name does not cover rather than one the scan happens to miss.
//
// referenceHuggingFaceUserAccessTokenFind in
// builtin_huggingface_user_access_token_test.go keeps the grammar as a regular
// expression, spelling the prefix, the count and the alphabet again so that the
// two are changed together, and the fuzz target beside it holds this scan to
// that expression.
var huggingFaceUserAccessToken = NewPattern("huggingface-user-access-token", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := huggingFaceUserAccessTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], huggingFaceUserAccessTokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not, for the
		// reason the rationale above gives: a body closing on hf can open a token
		// thirty-five characters into the one it stands in, and a scan stepping over
		// what it took would leave that one whole.
		offset = anchor + 1

		if anchor < huggingFaceUserAccessTokenAnchorIndex {
			continue
		}
		start := anchor - huggingFaceUserAccessTokenAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != huggingFaceUserAccessTokenPrefix[0] || !strings.HasPrefix(src[start:], huggingFaceUserAccessTokenPrefix) {
			continue
		}

		body := start + len(huggingFaceUserAccessTokenPrefix)
		end := start + huggingFaceUserAccessTokenChars
		if end > len(src) {
			// The input ends inside the body, and the count is the whole of
			// what tells a token from any other run written behind the prefix.
			retain = min(retain, start)
			continue
		}
		if isHuggingFaceUserAccessTokenBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// huggingFaceUserAccessTokenPrefix is what every user access token opens
	// with, and what the scan reads back from its anchor. It closes on a
	// character no body is written with, which is what makes the search cheap on
	// a line holding no token and what bounds where a token may begin inside
	// another; Test_huggingFaceUserAccessTokenPrefix holds it to both.
	huggingFaceUserAccessTokenPrefix = "hf_"

	// huggingFaceUserAccessTokenAnchor is the byte the scan searches the input
	// for and huggingFaceUserAccessTokenAnchorIndex is where it stands in the
	// prefix, so a candidate begins that many bytes in front of what a search
	// reported. builtin_scan.go says why a scan searches for one byte of its
	// prefix rather than for the prefix itself; the rationale above says what
	// makes it this byte.
	huggingFaceUserAccessTokenAnchor      = '_'
	huggingFaceUserAccessTokenAnchorIndex = 2

	// huggingFaceUserAccessTokenBodyChars is how many letters and digits stand
	// behind the prefix. It is the count Hugging Face's own expression asks
	// for, read exactly rather than as a floor for the reason the rationale
	// above gives.
	huggingFaceUserAccessTokenBodyChars = 34

	// huggingFaceUserAccessTokenChars is the whole of a token: the prefix and
	// the body. Test_huggingFaceUserAccessTokenChars holds it to thirty-seven.
	huggingFaceUserAccessTokenChars = len(huggingFaceUserAccessTokenPrefix) + huggingFaceUserAccessTokenBodyChars
)

// isHuggingFaceUserAccessTokenBody reports whether s is everything behind the
// prefix of a token: exactly huggingFaceUserAccessTokenBodyChars letters and
// digits.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count being left to the caller to have cut
// correctly.
func isHuggingFaceUserAccessTokenBody(s string) bool {
	if len(s) != huggingFaceUserAccessTokenBodyChars {
		return false
	}
	for i := range len(s) {
		if !isBase62Byte(s[i]) {
			return false
		}
	}
	return true
}

// huggingFaceUserAccessTokenTail is what the scan settles the tail of its input
// by. prefixTail (builtin_scan.go) says what that is and why it is built once.
var huggingFaceUserAccessTokenTail = newPrefixTail(huggingFaceUserAccessTokenPrefix)
