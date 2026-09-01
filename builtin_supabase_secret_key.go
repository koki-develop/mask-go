package mask

import "strings"

// SupabaseSecretKey locates the secret API keys a Supabase project is reached
// with from a server: the prefix sb_secret_ and the thirty-one characters
// behind it, forty-one characters altogether. A key bypasses row level security
// and stands for the whole of the project's data, which is why Supabase refuses
// one sent from a browser.
//
// A key is located wherever it is written, with no word boundary either side,
// and exactly forty-one characters of it are. So text of that shape is redacted
// whether or not Supabase issued it. A character outside the base64url alphabet,
// or anything but an underscore twenty-three characters behind the prefix, ends
// the reading, so text as it is ordinarily written is not affected.
//
// Its name is "supabase-secret-key".
func SupabaseSecretKey() Pattern { return supabaseSecretKey }

// What Supabase states about this format it states in the code that mints a
// key. A self-hosted installation generates its own, and the repository the
// installation is published from carries the generator twice — in the script
// that writes the keys an installation starts with and in the one that rotates
// them — character for character the same in both:
//
//	function generateOpaqueKey(prefix) {
//	    const random = crypto.randomBytes(17).toString("base64url").slice(0, 22);
//	    const intermediate = prefix + random;
//	    const checksum = crypto.createHash("sha256")
//	        .update(PROJECT_REF + "|" + intermediate)
//	        .digest("base64url")
//	        .slice(0, 8);
//	    return intermediate + "_" + checksum;
//	}
//
// Every part of the grammar read here is a line of that function. base64url is
// what either slice is taken in, twenty-two and eight are the counts sliced,
// and the underscore between them is written by the generator rather than drawn
// from an alphabet. The prefix is the argument, and it is the whole of what
// tells one kind of key from the other: everything behind it is drawn the same
// way whichever prefix was passed in.
//
// The generator states a self-hosted installation rather than the platform, so
// it is worth being exact about what carries across. The documentation says it
// does: the self-hosting page prints
// sb_secret_<22-char-random>_<8-char-checksum> in prose, and says of the pair
// that the opaque keys use the same format as the platform, differing in that a
// self-hosted gateway does not validate the checksum. The keys the
// vendor's own tooling ships are the format again — the CLI writes
// sb_secret_N7UND0UgjKTVK-Uodkm0Hg_xSvEMPvz into a local stack by default, which
// is twenty-two characters, an underscore and eight, and carries a hyphen in the
// random part where the announcement's platform example carries none.
//
// The rulesets read the prefix and none of them reads the separator. betterleaks
// asks for thirty-one characters of exactly this alphabet, which is the count
// this grammar comes to, and holds what the alphabet lets in back with an
// entropy floor: the false positive it ships is the prefix and thirty-one a's,
// which its expression matches and the floor removes. osv-scalibr reads
// thirty-one to thirty-six of the same alphabet, and kingfisher the same range
// read without regard to case, held back by an entropy floor and a demand for
// three uppercase and three lowercase characters. So where they differ from each
// other they differ in the count, and where they all differ from this scan is
// the underscore: none of them asks that the twenty-third character behind the
// prefix be the one the generator writes there, and each buys with a floor what
// that character rules out by the grammar. trufflehog and gitleaks read nothing
// in one at all.
//
// Both counts are read exactly, which the three sources above agree on and the
// range the two rulesets read is the guess an exact count declines. So a run of
// thirty-two characters behind the prefix is not a longer key but a key with
// something written after it, and only the key is redacted; were the platform
// ever to mint a longer key, this scan would locate the first forty-one
// characters and leave the rest.
//
// Reading the separator pins the twenty-third character of a body to one value,
// so a run drawn from anything but the generator has about one chance in
// sixty-four of reaching the end of the scan at all. It costs nothing a key has,
// because the generator writes that character unconditionally.
//
// It is not what the Grafana separator is, and the difference is the alphabet
// either side. There the secret is base62 and carries no underscore, so the
// separator ends the secret where it stands. Here the random part may carry
// underscores of its own, so the separator settles nothing about where the parts
// divide — the counts do that — and pins one position and no more.
// Test_SupabaseSecretKey_underscoresInTheRandomPart drives a key holding one.
//
// The alphabet is base64url, which isBase64URLByte (builtin_scan.go) states, and
// it is read as the generator writes it: both cases, the digits, the hyphen and
// the underscore, and no padding, since Node's base64url encoding writes none
// and neither slice would reach it. The hyphen is what a narrower class would
// cost: the CLI's own key carries one.
//
// There is no boundary on either side of a match. A word boundary in front would
// drop the whole match rather than trim it wherever a key is written against a
// word character, as SUPABASE_SECRET_KEY_sb_secret_... is, and one behind it
// would drop a key followed by a base64url character.
//
// The tightening on offer in front is the one the Slack and Stripe scans take:
// to ask that no letter and no digit stand before the prefix. It is declined
// because there is nothing here for it to turn away. The prefix is ten
// characters carrying two underscores, of which the second closes it, so a
// prefix standing inside a word would need that word to be spelled with
// sb_secret_ at the end of it. What the demand would cost is a key written
// straight against a letter, which would then be left in the output whole
// rather than trimmed.
//
// The scan resumes one byte past the start of a candidate whether it became a
// key or not, which is the default and is what a key written inside another
// needs. One can be: the alphabet a body is drawn from holds every character the
// prefix is written with, so a body may spell sb_secret_ and open a candidate
// that reads on past the end of the key it stands in.
// Test_SupabaseSecretKey_aKeyInsideAKey drives the shape, and the spans overlap
// there, which Masker.locate resolves.
//
// The scan keeps no cursor and needs none: a candidate reads at most forty-one
// bytes and stops, which bounds what it reads with no state to be wrong about.
// The exact count is what buys that, and it has to, because the usual guarantee
// is not available here: the underscore this prefix closes with is in the
// alphabet the body is drawn from, so a run of body characters holds a candidate
// for every character it has rather than one.
//
// What this pattern over-matches on is thirty-one characters of base64url
// written behind the prefix with an underscore twenty-three characters in. That
// is the vendor's format exactly, so there is nothing left in the text to tell
// the two apart, and declining it would decline every key Supabase issues. What
// has to be written to reach it is the literal sb_secret_, which is ten
// characters carrying two underscores: standard base64 writes no underscore at
// all, so a certificate, a PEM body or an embedded image carries no candidate at
// however long it runs, and a base64url encoding puts those ten characters at a
// position about once in every sixty-four to the tenth.
// Test_SupabaseSecretKey_aBase64URLRunBehindThePrefix pins it.
//
// SupabasePublishableKey (builtin_supabase_publishable_key.go) is the other half
// of this format and reads the declarations below rather than a second copy of
// them, since neither half can move a count the one generator writes for both.
// What each half decides on its own is its prefix, the byte it searches for, and
// whether a caller wants it — a publishable key is published by design where
// this one authenticates.
//
// referenceSupabaseSecretKeyFind in builtin_supabase_secret_key_test.go keeps
// the grammar as a regular expression, spelling the prefix, the two counts, the
// separator and the character class again so that the two are changed together,
// and the fuzz target beside it holds this scan to that expression.
var supabaseSecretKey = newBuiltin("supabase-secret-key", &supabaseSecretKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := supabaseSecretKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], supabaseSecretKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not. A body
		// may spell the prefix, so a key can begin inside another and a scan stepping
		// over what it declined would step over the one behind it.
		offset = anchor + 1

		if anchor < supabaseSecretKeyAnchorIndex {
			continue
		}
		start := anchor - supabaseSecretKeyAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != supabaseSecretKeyPrefix[0] || !strings.HasPrefix(src[start:], supabaseSecretKeyPrefix) {
			continue
		}

		body := start + len(supabaseSecretKeyPrefix)
		end := start + supabaseSecretKeyChars
		if end > len(src) {
			// The input ends inside this candidate, so neither the count nor
			// the character dividing the two parts of the body can be taken
			// here.
			retain = min(retain, start)
			continue
		}
		if isSupabaseKeyBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// supabaseSecretKeyPrefix is what every secret key opens with, and what the
	// scan reads back from its anchor. It is the argument the generator is
	// called with for this kind of key, and the whole of what tells one from a
	// publishable key. Test_supabaseSecretKeyAnchor holds it to carrying the
	// anchor at the index below.
	supabaseSecretKeyPrefix = "sb_secret_"

	// supabaseSecretKeyAnchor is the byte the scan searches the input for and
	// supabaseSecretKeyAnchorIndex is where it stands in the prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; what makes it this byte is that it is
	// the rarest character the prefix has in ordinary text. Over the line these
	// benchmarks are written on the b stands once and every other character of
	// the prefix but the underscore stands at least twice: the s opens the
	// vendor's name, its host name and the paths beneath it and stands six
	// times, and the e and the t five apiece.
	//
	// The underscore stands not once on that line and is passed over all the
	// same, for a reason the alphabet gives: a body is drawn from base64url and
	// so carries underscores of its own, and the prefix carries two, so a line
	// of keys opens more candidates by the underscore than by the b. What each
	// of those costs is the single comparison below.
	supabaseSecretKeyAnchor      = 'b'
	supabaseSecretKeyAnchorIndex = 1

	// supabaseSecretKeySeparator divides the random part of a body from the
	// checksum behind it, and is written there by the generator rather than
	// drawn from an alphabet. Unlike a separator standing between two parts
	// written in an alphabet it is not in, it settles nothing about where the
	// parts divide — base64url holds it, so the counts are what divide them —
	// and what it is worth is the one character of the body it pins.
	supabaseSecretKeySeparator = '_'

	// The counts a body is written to: the two slices of the generator, twenty
	// two characters of randomness and the first eight of a SHA-256 written in
	// base64url.
	supabaseSecretKeyRandomChars   = 22
	supabaseSecretKeyChecksumChars = 8

	// supabaseSecretKeyBodyChars is everything behind a prefix: the random
	// part, the separator and the checksum. Both halves of this format read it,
	// because one generator writes the body for both and neither half can move
	// a count of it alone.
	supabaseSecretKeyBodyChars = supabaseSecretKeyRandomChars + 1 + supabaseSecretKeyChecksumChars

	// supabaseSecretKeyChars is the whole of a secret key.
	// Test_supabaseSecretKeyChars holds it to forty-one.
	supabaseSecretKeyChars = len(supabaseSecretKeyPrefix) + supabaseSecretKeyBodyChars
)

// isSupabaseKeyBody reports whether s is everything behind the prefix of a key
// of either kind: supabaseSecretKeyRandomChars characters of base64url, the
// separator, and supabaseSecretKeyChecksumChars characters of base64url.
//
// It is named for the vendor rather than for either kind because the generator
// writes one body and is told only which prefix to put in front of it. Both
// scans call it, and it is here rather than in builtin_scan.go because what it
// states is one vendor's format rather than something a third pattern could
// come to need.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than left to the caller to have cut correctly.
//
// The separator is tested for where it stands and then walked over with the
// rest, rather than the two parts being walked either side of it. base64url
// holds the underscore, so the second reading of that one character can only
// agree with the first, and one loop is the smaller thing to be right about.
func isSupabaseKeyBody(s string) bool {
	if len(s) != supabaseSecretKeyBodyChars || s[supabaseSecretKeyRandomChars] != supabaseSecretKeySeparator {
		return false
	}
	for i := range len(s) {
		if !isBase64URLByte(s[i]) {
			return false
		}
	}
	return true
}

// supabaseSecretKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var supabaseSecretKeyTail = newPrefixTail(supabaseSecretKeyPrefix)
