package mask

import "strings"

// CloudflareOriginCAKey locates Cloudflare Origin CA keys: the prefix v1.0-,
// twenty-four lowercase hexadecimal characters, a hyphen and a hundred and
// forty-six more — a hundred and seventy-six characters. One key issues and
// revokes origin certificates for every account the user holding it can reach,
// and the Keyless SSL key server is given one as well.
//
// A key is located wherever it is written, with no word boundary either side,
// and exactly a hundred and seventy-six characters of it are. So text of that
// shape is redacted whether or not Cloudflare issued it. A space, an uppercase
// letter, a letter past f, a separator standing anywhere but the twenty-fifth
// character behind the prefix or a run of the wrong length ends the reading, so
// text as it is ordinarily written is not affected.
//
// Its name is "cloudflare-origin-ca-key".
func CloudflareOriginCAKey() Pattern { return cloudflareOriginCAKey }

// What Cloudflare states about this credential it states on the page that hands
// one out. Origin CA keys are sent as the X-Auth-User-Service-Key header of the
// Origin CA certificates API and used by the Keyless SSL key server; one of them
// reaches every account its holder can reach; a user may hold several at once,
// since the page presents a different value each time it is viewed and says all
// of them are valid together; and the key value always starts with v1.0-. That
// last sentence is the whole of what the vendor writes about the format. There
// is no length, no alphabet and no division on that page or on any other, and
// Cloudflare has dated the credential's removal rather than described it: the
// deprecation notice above the same sentence gives 30 September 2026 as the day
// service key authentication stops working.
//
// Two things state the counts, and they do not carry the same weight.
//
// The first is Cloudflare's own API reference, which writes the header out with
// a whole value behind it rather than a masked one: the prefix, twenty-four
// lowercase hexadecimal characters, a hyphen and a hundred and forty-six more.
// That is the vendor writing its own format the only way it writes it, and it is
// one value — what it settles is a shape, not that the shape is the only one.
//
// The second is the published rulesets, which carry more weight here than they
// usually do because there is so little above them, and which agree. gitleaks
// and betterleaks each read v1\.0- and the same two counts of the same lowercase
// class. trufflehog reads v1\.0- and a hundred and seventy-one characters of the
// letters, the digits and the hyphen, which is those two counts and the
// separator between them exactly. So the split is read off one rule and
// corroborated by a second, and the width of the whole is read off a third that
// spells no split at all. None of the three is read for the values beside it.
//
// What states nothing is the page the two Cloudflare patterns beside this one
// are built on. The Credentials and Secrets table of the predefined DLP profiles
// carries a row apiece for cfk_, cfut_ and cfat_, each with its counts and its
// character classes written out, and no row for this credential at all. It is
// named here so that a reader auditing this rationale against it does not read
// the silence as the counts having been invented.
//
// The counts are read exactly rather than as floors. A floor is what a scan
// reads where its vendor states no length, and this vendor states none — but
// what stands in place of a stated length is the vendor writing a whole value
// and two rules spelling both counts to the character, which is firmer than the
// values somebody happened to be shown. A floor would also have to be read off
// those same sources, and it would cost more than it bought: a floor under the
// second count admits a digest written where the second run stands, where the
// count as it is admits none — an MD5 is thirty-two characters, a SHA-1 forty, a
// SHA-256 sixty-four and a SHA-512 a hundred and twenty-eight, and a hundred and
// forty-six is not one of them. What an exact count costs is what it costs
// everywhere: a run longer than the count is not one longer key but a key with
// something written after it, and only the key is redacted.
//
// The alphabet is read as lowercase alone. The whole of the body is one class,
// so widening it to either case would draw in every uppercase hexadecimal run
// written behind the prefix and buy no key a narrower reading loses: the value
// the vendor writes is lowercase and the two rules spelling the split ask for
// lowercase. trufflehog's is the wider reading on offer — every letter of either
// case, and the hyphen wherever it falls — and what it would admit behind a
// version string is a hundred and seventy-one characters of ordinary base62
// text, which is a net cast over identifiers rather than over keys.
// Test_CloudflareOriginCAKey_aWiderAlphabet pins the decision.
//
// The name is the term Cloudflare writes for the credential itself. The page
// documenting it is titled for Origin CA keys, the dashboard names the item
// Origin CA Key, and the changelog retiring it writes Service Key for the
// authentication scheme rather than for the value. Origin CA key is the term
// that names what this scan locates.
//
// It is a pattern of its own rather than something the Cloudflare key or token
// scan grows into, and the caller is what decides that. No term of Cloudflare's
// covers this credential and those: it is named for the one API it was issued
// to call, where an API key and an API token authenticate the whole of
// Cloudflare's, and the notice retiring it names it and neither of them. A
// caller who wants the one redacted and not the others needs a switch to say
// so, and a redactor keying on Match.Pattern.Name has nothing else to read them
// apart by.
//
// That prefix is ordinary text besides: v1.0- is how a pre-release version is
// written. What turns those away is the body. On a line of their own they carry
// nowhere near the hundred and seventy-one characters a key has behind its
// prefix, so the count gives up on them before a body is read; written into a
// longer line, each stops at its first character no run holds — v1.0-beta at the
// t, v1.0-rc1 at the r, and the output of git describe at the hyphen dividing
// its fields, which stands where the first run still wants twenty-two
// hexadecimal characters more. Test_CloudflareOriginCAKey_aVersionString drives
// the three as they are written, and
// Test_CloudflareOriginCAKey_rejectedByTheBodyRatherThanByTheEndOfTheInput one
// of them in a line the walk runs over.
//
// There is no boundary on either side of a match. A word boundary in front would
// drop the whole match rather than trim it wherever a key is written against a
// word character, as CLOUDFLARE_ORIGIN_CA_KEY_v1.0-... is, and one behind it
// would drop a key followed by a character of the body's own alphabet. What may
// stand either side is held back by the character class and the counts alone.
// Both rulesets spelling the split ask for something in front: gitleaks and
// betterleaks each open on \b, so a key written straight against a letter or an
// underscore is one they leave in the text where this pattern redacts it. What
// declining costs is a word closing on a v with a whole key written behind it,
// which is redacted from that v with the letters in front of it left where they
// were. Test_CloudflareOriginCAKey_aWordEndingInTheAnchor pins the shape that
// pays for it.
//
// The byte the scan searches the input for is the v the prefix opens with.
// builtin_scan.go says why a scan searches for one byte of its prefix rather
// than for the prefix itself, and here the body settles the choice. The 1 and
// the 0 are hexadecimal, so a search for either stops roughly ten times in the
// hundred and seventy hexadecimal characters of a key, and once in sixteen bytes
// of every digest, every identifier and every hash a log line carries. The
// hyphen is no hexadecimal character, but a key carries one of its own between
// the two runs, so a line of keys opens two candidates a key under it against
// the v's one — and it is what an ISO timestamp, a UUID and a kebab-case name
// are written with besides. That leaves the v and the full stop, neither of
// which any key carries past its prefix, and the v is the rarer of the two over
// the text this library is pointed at: over the log lines, JSON and command
// lines of conformance/testdata/text_shapes.txt the v stands 42 times against
// the full stop's 46. On the log line these benchmarks are written on the two
// stand twice apiece.
//
// The prefix opens where the search stops, so a candidate begins at the anchor
// rather than behind it, and the byte test other scans make in front of
// comparing the whole prefix would be a byte compared with itself. It is not
// written. The index stays a declaration of its own all the same, so that the
// byte and the place a candidate begins cannot come apart silently;
// Test_cloudflareOriginCAKeyAnchor holds the two together.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a key or not, which is the default and needs no argument.
// What it finds is nothing: the v is written nowhere in a key but at its first
// character — no body carries one and the rest of the prefix does not — so the
// search stops nowhere inside a key it has located and no key can begin inside
// another.
// Test_CloudflareOriginCAKey_noKeyBeginsInsideAnother drives it and
// Test_cloudflareOriginCAKeyAnchor holds the character it rests on.
//
// The scan keeps no cursor and needs none: a candidate reads at most a hundred
// and seventy-six bytes and stops, which bounds what it reads with no state to
// be wrong about — the guarantee a scan reading a run to its end has to buy with
// a run cursor instead, bought here by the counts being counts.
//
// What this pattern over-matches on: a hundred and seventy-six characters of the
// right shape that nobody issued. A version string has to be written, then
// exactly twenty-four lowercase hexadecimal characters, then a hyphen, then
// exactly a hundred and forty-six more, with nothing between any of them. The
// full stop is what keeps that out of an encoding altogether: base62, standard
// base64 and base64url are each written without one, so an identifier, a
// certificate, a PEM body or an embedded image carries no candidate at however
// long it runs. What is left is a version number with a hundred and seventy
// unbroken hexadecimal characters written behind it in two runs of the stated
// widths.
//
// What reaches a span is never prose, never a git SHA and never an MD5. A key
// holds a full stop at its third character and nowhere else, a hyphen at its
// fifth and its thirtieth and nowhere else, and no space; and a hundred and
// forty-six unbroken hexadecimal characters are longer than anything prose is
// written in.
//
// referenceCloudflareOriginCAKeyAt in builtin_cloudflare_origin_ca_key_test.go
// keeps the grammar, spelling the prefix, both counts, the separator and the
// character class again so that the two are changed together, and the fuzz
// target beside it holds this scan to that reference. It is written out by hand
// rather than built on an expression, and what settles that is the width of the
// second count rather than anything about the counts being exact: a hundred and
// forty-six unrolls into a program long enough to starve the target, which the
// reference's own comment measures.
var cloudflareOriginCAKey = newBuiltin("cloudflare-origin-ca-key", &cloudflareOriginCAKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of the prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := cloudflareOriginCAKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], cloudflareOriginCAKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not,
		// which is the default step. The rationale above says what it finds:
		// nothing, since the anchor stands nowhere in a key but at its first
		// character.
		offset = anchor + 1

		// The guard stands although the index below is zero, so that the byte
		// the search stops at and the place a candidate begins stay two
		// declarations rather than one: a scan reading the prefix back from a
		// later byte would read behind the input without it.
		if anchor < cloudflareOriginCAKeyAnchorIndex {
			continue
		}
		start := anchor - cloudflareOriginCAKeyAnchorIndex
		if !strings.HasPrefix(src[start:], cloudflareOriginCAKeyPrefix) {
			continue
		}

		body := start + len(cloudflareOriginCAKeyPrefix)
		end := body + cloudflareOriginCAKeyBodyChars
		if end > len(src) {
			// The input ends inside the body, so the counts that are the whole
			// of what tells this candidate from a version string cannot be
			// taken here.
			retain = min(retain, start)
			continue
		}
		if isCloudflareOriginCAKeyBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// cloudflareOriginCAKeyPrefix is what every key opens with and what the scan
	// reads forward from its anchor. It is the whole of what Cloudflare states
	// about this format, and the whole of what a candidate is opened on.
	//
	// Two tests hold it to what the scan needs of it.
	// Test_cloudflareOriginCAKeyAnchor asks that it carry the byte the search
	// stops at once and at the index a candidate is read back from, and that
	// the byte be written in no run and be no separator, which together are
	// what keeps a key from beginning inside another.
	// Test_cloudflareOriginCAKeyChars asks that it leave a hundred and
	// seventy-six character key with the body behind it, which is the count the
	// sentence on CloudflareOriginCAKey promises a caller.
	cloudflareOriginCAKeyPrefix = "v1.0-"

	// cloudflareOriginCAKeyAnchor is the byte the scan searches the input for
	// and cloudflareOriginCAKeyAnchorIndex is where it stands in the prefix, so
	// a candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix rather
	// than for the prefix itself; the rationale above says what made it this
	// byte, which is that no body carries one and no key carries a second.
	cloudflareOriginCAKeyAnchor      = 'v'
	cloudflareOriginCAKeyAnchorIndex = 0

	// cloudflareOriginCAKeySeparator is what divides the two runs behind the
	// prefix. It is the one character of a body that is no hexadecimal digit,
	// and it stands at one place and no other.
	cloudflareOriginCAKeySeparator = '-'

	// The two counts behind the prefix, named for where the runs stand rather
	// than for what they carry: Cloudflare divides the value nowhere and says
	// what neither run is for, so a name saying otherwise would be one this
	// package invented. What states them is the whole value the vendor's API
	// reference writes and the two rulesets spelling the same split, as the
	// rationale above sets out.
	cloudflareOriginCAKeyFirstRunChars  = 24
	cloudflareOriginCAKeySecondRunChars = 146

	// cloudflareOriginCAKeyBodyChars is everything behind the prefix: the two
	// runs and the separator between them.
	cloudflareOriginCAKeyBodyChars = cloudflareOriginCAKeyFirstRunChars + 1 + cloudflareOriginCAKeySecondRunChars

	// cloudflareOriginCAKeyChars is the whole of a key, which is what the
	// sentence on CloudflareOriginCAKey promises and what every span written in
	// the tests beside this file is wide.
	cloudflareOriginCAKeyChars = len(cloudflareOriginCAKeyPrefix) + cloudflareOriginCAKeyBodyChars
)

// isCloudflareOriginCAKeyBody reports whether s is everything behind the prefix
// of a key: exactly cloudflareOriginCAKeyFirstRunChars characters of the body's
// alphabet, the separator, and exactly cloudflareOriginCAKeySecondRunChars more.
//
// It is handed the counts as well as the characters so that they are checked in
// one place rather than left to the caller to have cut correctly. The first run
// is walked before the separator because that is where a candidate that is no
// key usually stops: the character straight behind the prefix is the one most
// text written this way fails on, and a version string reaches the separator
// only by carrying twenty-four hexadecimal characters first.
func isCloudflareOriginCAKeyBody(s string) bool {
	if len(s) != cloudflareOriginCAKeyBodyChars {
		return false
	}
	for i := range cloudflareOriginCAKeyFirstRunChars {
		if !isCloudflareOriginCAKeyByte(s[i]) {
			return false
		}
	}
	if s[cloudflareOriginCAKeyFirstRunChars] != cloudflareOriginCAKeySeparator {
		return false
	}
	for i := cloudflareOriginCAKeyFirstRunChars + 1; i < len(s); i++ {
		if !isCloudflareOriginCAKeyByte(s[i]) {
			return false
		}
	}
	return true
}

// isCloudflareOriginCAKeyByte reports whether c is a lowercase hexadecimal
// digit, which is what both runs of a key are written in.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go,
// and rather than reading the one the Cloudflare key and token scans share. A
// hexadecimal class is not one class between formats: a checksum standing behind
// a body that has already decided a match is read there in either case, and a
// whole body is read here in lowercase alone, each for the reason its own file
// gives. One declaration read by both would make widening either a change to the
// other, which is a change nothing would report.
func isCloudflareOriginCAKeyByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f'
}

// cloudflareOriginCAKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var cloudflareOriginCAKeyTail = newPrefixTail(cloudflareOriginCAKeyPrefix)
