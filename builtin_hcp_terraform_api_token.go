package mask

import "strings"

// HCPTerraformAPIToken locates the API tokens HCP Terraform issues: fourteen
// letters and digits, the nine characters .atlasv1. and sixty-seven letters and
// digits behind them — ninety characters altogether. One format carries every
// kind of token the service hands out — the user token a person authenticates
// with, the team token a pipeline runs plans and applies under, the
// organization token that manages teams and workspaces, and the token an agent
// pool authenticates with — so nothing in a token says which of those it is.
//
// A token is located wherever it is written, with no word boundary either side,
// and exactly ninety characters of it are. So text of that shape is redacted
// whether or not HashiCorp issued it. A space, a hyphen, an underscore, a full
// stop out of place or a portion of the wrong length ends the reading, so text
// as it is ordinarily written is not affected.
//
// Its name is "hcp-terraform-api-token".
func HCPTerraformAPIToken() Pattern { return hcpTerraformAPIToken }

// API token is HashiCorp's own name for this string: the page it keeps on
// managing them is titled for them, and it is that page which names the four
// kinds under the one term. The kinds are what a caller might have wanted a
// boundary between, and the format is why there is none — the four are the same
// ninety characters with nothing written in them to say which was issued, so a
// caller can neither switch one on and the other off nor label them apart in
// the output. Terraform Enterprise is the same application again: HashiCorp
// calls it the self-hosted distribution of HCP Terraform, and its API reference
// publishes the same token in the same shape, so a self-hosted token is one of
// these rather than a second format.
//
// What HashiCorp states about the format is examples rather than a grammar. The
// four endpoints that return a token — user, team, organization and agent pool
// — each print one in their sample response, and all four are fourteen letters
// and digits, the separator, and sixty-seven letters and digits. The CLI
// configuration page writes the shape a third way, as placeholders either side
// of .atlasv1., which pins the separator and neither count. The separator is
// where the format's age shows: Atlas is what the platform was called before it
// was Terraform Cloud, which is what it was called before it was HCP Terraform.
// The v1 behind that name is not the API's, which is v2 in every path a token
// is spent on.
//
// So the separator is the vendor's and the counts are the vendor's examples,
// and the rulesets are what says whether anybody reads them otherwise. gitleaks
// and betterleaks read fourteen characters of letters and digits without regard
// to case, .atlasv1. in the one case it is written in, and sixty to seventy
// characters of letters, digits, hyphens, underscores and equals signs, dropping
// what falls at or below an entropy floor; the one whole token each of them
// publishes is fourteen and sixty-seven, in the middle of that range and in
// letters and digits alone. kingfisher reads this format through betterleaks'
// rule rather than one of its own. trufflehog reads exactly what the scan below
// reads — fourteen and sixty-seven of the letters of both cases and the digits —
// with a word boundary asked for either side. Google's osv-scalibr reads it not
// at all.
//
// The alphabet is therefore the letters of both cases with the digits,
// isBase62Byte in builtin_scan.go, and the reading that is wider is the one to
// argue against, and it is a reading two of the rules above take: gitleaks and
// betterleaks admit the hyphen, the underscore and the equals sign where
// trufflehog reads the letters and digits alone. What the wider class would buy
// is a token carrying one of those three. What it would take is the hyphenated
// slug and the snake-cased identifier a log line is full of, wherever one of
// those runs into a separator — which is why the narrower reading is the one
// taken here.
//
// The counts are read exactly rather than as floors, and what makes that safe
// here is that there is no boundary either side. A token whose portions
// HashiCorp lengthened is still located: the scan reads the fourteen letters
// and digits standing in front of the separator and the sixty-seven standing
// behind it, so what a longer token would keep in the output is the characters
// its ends reach past those counts and nothing more. A floor would take those
// too, and would take with them whatever word was written against the end of a
// token.
//
// The byte the scan searches the input for is the v of the separator, and the
// separator is read back from it. builtin_scan.go says why a scan searches for
// one byte of what a candidate opens with rather than for the whole of it; what
// makes it this byte is the rest of the separator. On the line these benchmarks
// are written on the v stands twice, where the a stands seven times, the s six,
// the l five, the t four and the 1 four. The full stop stands twice there as
// well and is the worse of the two either way: it stands twice in the separator
// too, so a line of tokens would stop the search twice a token where the v stops
// it once, and it is the character every host name, every version and every
// sentence is written with, so a line carrying more URLs than this one moves it
// further the wrong way. What the v costs instead is a run of the alphabet a
// portion is written in, which stops the search about once every sixty-two
// characters — and each of those stops is turned away by the one comparison
// that asks for the full stop the separator opens with.
//
// So the scan steps one byte past the anchor, whether the candidate became a
// token or not, which is the default step builtin_scan.go argues: the search
// resumes at the anchor of the next candidate, and what that leaves is a
// candidate beginning one byte past this one. A longer step would be an
// optimisation resting on a claim about the grammar, and this scan makes none.
//
// The scan keeps no cursor and needs none: a candidate reads fourteen bytes in
// front of the separator and sixty-seven behind it and stops, which bounds what
// it reads with no state to be wrong about, and is what rules out a quadratic
// input.
//
// What this pattern over-matches on is the format of another HashiCorp
// credential, and it is one that cannot be told apart. Vagrant Cloud issues its
// personal tokens in this same format — the same separator, the same two counts,
// the same alphabet — which is what trufflehog carrying a second detector on
// one expression records. There is nothing in either string to read the two
// apart, so a scan declining one declines every HCP Terraform token there is,
// and the decision is to redact it under this name.
// Test_HCPTerraformAPIToken_aVagrantCloudToken pins it.
//
// What reaches a span is never prose: a token carries the nine characters
// .atlasv1. with fourteen unbroken letters and digits in front of them and
// sixty-seven behind, and a full stop is what ends a word rather than what
// stands in the middle of one.
//
// referenceHCPTerraformAPITokenFind in builtin_hcp_terraform_api_token_test.go
// states that grammar again, read left to right at every position, with the
// separator, both counts and the alphabet written afresh so that the two are
// changed together, and the fuzz target beside it holds this scan to it. It is
// written out rather than built on an expression because a token opens on the
// alphabet its own portions are written in: an expression has no literal to
// search the text for there, and the one measured beside the reference collapsed
// on the inputs the mutator reaches.
//
// The scan declares the separator to a Masker as a literal and no tail, which
// grams (builtin_scan.go) says is the pattern that may be passed over but never
// answered for. Every token carries the separator — the scan asks for it before
// it reports anything — so a text carrying it nowhere carries no token.
//
// A tail it cannot declare, for the reason hcpTerraformAPITokenTailStart is
// written at all: what a candidate opens with is fourteen letters and digits and
// the separator behind them, which is no literal, so what the input settles is a
// walk rather than a table and it settles further back than the separator alone
// would. A stream runs this scan rather than answering for it, and Mask, which
// settles nothing, passes it over.
var hcpTerraformAPIToken = newBuiltinFilteredOn("hcp-terraform-api-token", []string{hcpTerraformAPITokenSeparator}, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of what a candidate opens
	// with standing at the end of it, or a candidate the end of it cut short.
	// builtin_scan.go says why those are the two.
	retain := hcpTerraformAPITokenTailStart(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], hcpTerraformAPITokenAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a token or not,
		// which is the default step: consuming a match would step over a token
		// beginning inside it.
		offset = anchor + 1

		if anchor < hcpTerraformAPITokenAnchorIndex {
			continue
		}
		separator := anchor - hcpTerraformAPITokenAnchorIndex

		// The byte a separator opens with is tested before the separator is
		// compared. Every anchor the search stops at reaches this line, and all
		// but the few that open a candidate are turned away by one byte where a
		// comparison of the whole separator is a length and a read.
		if src[separator] != hcpTerraformAPITokenSeparator[0] ||
			!strings.HasPrefix(src[separator:], hcpTerraformAPITokenSeparator) {
			continue
		}

		start := separator - hcpTerraformAPITokenIDChars
		if start < 0 {
			// The input begins inside what an identifier would have to be. A
			// stream has written out what stood in front of this window
			// already, so there is nothing here to hold back and nothing to
			// find.
			continue
		}
		if !isHCPTerraformAPITokenRun(src[start:separator], hcpTerraformAPITokenIDChars) {
			continue
		}

		secret := separator + len(hcpTerraformAPITokenSeparator)
		end := start + hcpTerraformAPITokenChars
		if end > len(src) {
			// The input ends inside the secret, and the count is the whole of
			// what tells a token from any other run written behind a separator.
			retain = min(retain, start)
			continue
		}
		if isHCPTerraformAPITokenRun(src[secret:end], hcpTerraformAPITokenSecretChars) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// hcpTerraformAPITokenSeparator is what stands between the two portions of
	// every token, and what the scan reads back from its anchor. It is the
	// whole of what tells this format from text: the portions either side carry
	// no mark of their own.
	hcpTerraformAPITokenSeparator = ".atlasv1."

	// hcpTerraformAPITokenAnchor is the byte the scan searches the input for
	// and hcpTerraformAPITokenAnchorIndex is where it stands in the separator,
	// so a separator begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of what a candidate
	// opens with rather than for the whole of it; the rationale above says what
	// made it this byte.
	hcpTerraformAPITokenAnchor      = 'v'
	hcpTerraformAPITokenAnchorIndex = 6

	// hcpTerraformAPITokenIDChars is how many letters and digits stand in front
	// of the separator and hcpTerraformAPITokenSecretChars how many stand
	// behind it. Both are the count every token HashiCorp publishes carries,
	// read exactly rather than as a floor for the reason the rationale above
	// gives.
	hcpTerraformAPITokenIDChars     = 14
	hcpTerraformAPITokenSecretChars = 67

	// hcpTerraformAPITokenChars is the whole of a token: both portions and the
	// separator between them. Test_hcpTerraformAPITokenChars holds it to the
	// ninety characters every published token is.
	hcpTerraformAPITokenChars = hcpTerraformAPITokenIDChars +
		len(hcpTerraformAPITokenSeparator) + hcpTerraformAPITokenSecretChars
)

// isHCPTerraformAPITokenRun reports whether s is a portion of a token: exactly
// chars letters and digits.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count being left to the caller to have cut
// correctly, and it is one function for both portions because they differ in
// nothing but the count.
func isHCPTerraformAPITokenRun(s string, chars int) bool {
	if len(s) != chars {
		return false
	}
	for i := range len(s) {
		if !isBase62Byte(s[i]) {
			return false
		}
	}
	return true
}

// hcpTerraformAPITokenTailStart returns where the input stops being settled on
// account of an opening the end of it cut short, and len(src) where no piece of
// one stands there.
//
// What a candidate opens with here is fourteen letters and digits and the
// separator behind them, which is no literal, so prefixTail alone cannot answer
// this and builtin_scan.go says to ask the walk that reads the opening instead.
// The two halves of the opening are cut in two different ways. A run of the
// alphabet an identifier is written in, standing at the end of the input, is an
// identifier as soon as a separator arrives behind it, so the last fourteen
// characters of such a run are held back — beyond fourteen no separator could
// reach them, which is what bounds the walk. A piece of the separator standing
// there instead belongs to a candidate that began an identifier's width
// earlier, and it is that offset the input is held to: released from the
// separator, the identifier in front of it would go out ahead of the token and
// the token behind it would be redacted nowhere.
//
// What stands in front of a separator piece is not read. A scan working out
// that the fourteen bytes there could never have been an identifier would
// release them at the end of a write and would cost the second grammar
// builtin_scan.go declines, and what it would win back is fourteen bytes.
//
// What this costs a stream is those fourteen bytes at the end of every write
// whose text closes on a letter or a digit, which is most of them.
func hcpTerraformAPITokenTailStart(src string) int {
	start := len(src)
	for start > 0 &&
		len(src)-start < hcpTerraformAPITokenIDChars &&
		isBase62Byte(src[start-1]) {
		start--
	}
	if separator := hcpTerraformAPITokenTail.start(src); separator < len(src) {
		start = min(start, max(0, separator-hcpTerraformAPITokenIDChars))
	}
	return start
}

// hcpTerraformAPITokenTail is what the scan finds a cut separator with.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var hcpTerraformAPITokenTail = newPrefixTail(hcpTerraformAPITokenSeparator)
