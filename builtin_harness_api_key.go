package mask

import "strings"

// HarnessAPIKey locates the Harness API keys that authenticate a caller to the
// Harness API: personal access tokens, which open on pat, and service account
// tokens, which open on sat. Either is those three letters, a full stop, the
// twenty-two characters of the account identifier, another full stop, the
// twenty-four of the token identifier, a third full stop and the secret behind
// it. One of them reaches the pipelines, connectors, secrets and environments
// its principal can reach.
//
// A key is located wherever it is written, with no word boundary either side,
// and is redacted from its prefix to the end of the run its secret stands in.
// So a key written against a word character keeps its span, and a character of
// the secret's own alphabet written straight after a key is redacted with it.
//
// Its name is "harness-api-key".
func HarnessAPIKey() Pattern { return harnessAPIKey }

// API key is Harness's own term for the whole of what this locates. The page a
// caller mints one from is titled Manage API keys and heads the two kinds
// separately — a personal access token for a user, a service account token for
// a service account — and the term above both of them is the one Harness writes
// wherever it says what a value is: the environment variable its MCP server
// reads is HARNESS_API_KEY, documented as taking a Harness personal access token
// or service account token, and the page listing that variable writes "Harness
// API key: A PAT in the format pat.<accountId>.<tokenId>.<secret>".
//
// The two kinds are one pattern rather than one apiece, and the boundary is the
// caller's. None of the three things that puts one in is here: both are secrets
// authenticating a caller to the same API, differing in whose permissions they
// carry rather than in whether they are worth redacting, so a caller has no
// reason to enable one and not the other; a redactor keying on
// Match.Pattern.Name has no decision the principal would answer; and the term
// above covers both. What a switch apiece would cost is a caller reaching for
// this vendor having to know both to redact what it issues.
//
// The prefixes and the layout are Harness's own, stated in its own code rather
// than only in prose. The MCP server it publishes extracts the account
// identifier from a key, names pat and sat as the prefixes it will do that for,
// and writes both layouts out —
// pat.<accountId>.<tokenId>.<secret> and sat.<accountId>.<tokenId>.<secret>.
// Its CLI reads the same value as pat.AccountID.Random.Random. So the vendor
// states the prefixes, the count of parts and what each part is.
//
// What the vendor states nowhere is a length or an alphabet for any of the three
// parts. Its documentation writes the layout with the parts named and nothing
// else; the CLI and the MCP server each read a key only as far as the account
// identifier, taking the prefix and then whatever stands between the first two
// stops; and the code that issues a key is not among what Harness publishes. So
// every count and every class below rests on the published rulesets rather than
// on Harness, which is a weaker thing to rest on — a rule states what its author
// observed of the values, not what the vendor undertakes to keep issuing.
//
// Three rules state this format and they agree on the three counts. gitleaks and
// betterleaks each read both prefixes and twenty-two, twenty-four and twenty;
// trufflehog reads pat alone, behind a demand for the word harness in the text
// in front, at the same three counts. So the counts of a personal access token
// are read off three rules and those of a service account token off the two that
// spell its prefix. kingfisher carries no rule of its own here and reads this
// format through betterleaks'; noseyparker, secretlint and the secrets-patterns-db
// carry none at all. None of the three is read for the values beside it.
//
// Where the three disagree is on the classes, and the widest reading is taken at
// each part. The account identifier is base64url, isBase64URLByte in
// builtin_scan.go: gitleaks and betterleaks read the letters of both cases, the
// digits, the underscore and the hyphen, where trufflehog leaves the hyphen out.
// The token identifier is base62, isBase62Byte: gitleaks reads the letters of
// both cases and the digits where betterleaks and trufflehog read lowercase
// hexadecimal, which is a subset of it. The secret is base62 as well, which all
// three read it in. Narrowing to a subset is what costs a key when it is wrong —
// a candidate carrying one character outside the narrower class fails and the
// whole key stays in the output — where the wider class costs only the shapes
// the gate below weighs, and there is nothing of Harness's saying which reading
// is right.
//
// The two identifiers are read at exactly their counts and the secret as a
// floor, and the asymmetry is about what each count is doing rather than about
// the evidence, which is one set of rules for all three. A count in the middle
// states a width and keeps the grammar off ordinary dotted text besides: compat
// closes on the three letters a key opens with, and a package path written
// through that word carries a full stop straight behind them, so a reading that
// took any run up to a full stop would make a candidate of
// org.example.compat.<anything>.<anything>. It is the two exact counts that
// leave nothing of that shape. The last count does only the first job, nothing
// standing behind it to be told apart from anything. Reading it exactly would
// cap a key at twenty characters of secret on the word of rules that state what
// was observed, and a key whose secret is wider than what was observed is then
// redacted to the cap with its tail left in the log. Read as a floor, a secret
// of any width at or above twenty is redacted to the end of its run, and what
// that costs is the character of the secret's own alphabet written straight
// behind a key, which belongs to no credential and is redacted with it.
// Test_HarnessAPIKey_aSecretLongerThanTheFloor and
// Test_HarnessAPIKey_cutShortOfTheFloor pin the two directions.
//
// There is no boundary on either side of a match, because either would drop a
// match rather than trim it: in front, wherever a key is written against a word
// character, as HARNESS_API_KEY=pat.… is, and behind, wherever a character of
// the secret's alphabet is written against one. gitleaks and betterleaks ask for
// nothing either side, and trufflehog asks for a word boundary at both ends and
// for the vendor's name in the text in front, which is a demand on the text
// around a value rather than a part of the format.
//
// The byte the scan searches the input for is the full stop every prefix closes
// with, three characters in. builtin_scan.go says why a scan searches for one
// byte of what a candidate opens with rather than for the whole of it; what
// makes it this byte is that the prefixes share only their last three characters
// — at. — so the choice is between the a, the t and the full stop, and the
// letters are two of the commonest in prose. Over the log lines, JSON and
// command lines of conformance/testdata/text_shapes.txt the full stop stands 46
// times against the a's 175 and the t's 140. On the log line these benchmarks
// are written on it stands twice, both times in the vendor's own host name,
// against the a's four and the t's three, which
// Test_harnessAPIKeyFindBenchmarks_lineTheAnchorWasChosenAgainst counts.
//
// The scan resumes one byte past the anchor whether the candidate became a key
// or not, which is the step builtin_scan.go argues. A key can begin inside
// another here, which is what consuming the match would step over: a key carries
// a full stop at three places, so a candidate can open twenty-three and
// forty-eight characters into one, wherever the three characters in front of the
// second stop or the third spell a prefix. Only the second of the two can go on
// to be a key — a candidate opening twenty-three characters in wants a full stop
// where the token identifier is still being written — and
// Test_HarnessAPIKey_aKeyBeginningInsideAnother writes out the text where it
// does. The spans overlap there and Masker.locate resolves them.
//
// No cursor is kept over the secret's run, and none is needed, which is what the
// separator buys. A secret begins one byte past a full stop and no part of a key
// is written with one, so a run a candidate reads ends at the next full stop
// whatever else stands there. Every candidate further along the input writes such
// a stop one byte in front of its own secret, and that stop stands past where
// this candidate's secret began — so this run ends before the next candidate's
// secret does. One run is therefore read by one candidate, which is what rules
// out the quadratic input a run dense in prefixes would otherwise be.
// Test_harnessAPIKeySeparator_runsDoNotOverlap holds the parts of a key to the
// one character that argument rests on, and Test_HarnessAPIKey_scanIsLinear
// drives the inputs that would find it wrong.
//
// What this pattern over-matches on is a run of exactly the stated shape that
// Harness did not issue: a prefix, twenty-two base64url characters, a full stop,
// twenty-four base62 characters, a full stop and twenty more. There is nothing
// left in such a run to tell it from a key — a scan declining it would decline
// every key Harness issues — and what makes it rare is the layout rather than
// any one part. Three full stops at fixed distances put it out of reach of every
// encoding: base62, standard base64 and base64url are each written without one,
// so an identifier, a certificate, a PEM body or an embedded image carries no
// candidate at however long it runs. A dotted name does reach the prefix —
// compat. is one, character for character — and then has to carry exactly
// twenty-two characters, a stop, exactly twenty-four, a stop and twenty more,
// which is no shape a package path, a host name or a version is written in.
// Test_HarnessAPIKey_aDottedName pins the shapes that reach the prefix.
//
// A digest written behind the prefix is no collision, and the identifiers are
// what turn one away rather than the floor: an MD5 is thirty-two characters, a
// SHA-1 forty and a SHA-256 sixty-four, none of them twenty-two or twenty-four,
// and a digest carries no full stop to be divided at either of those widths.
// Test_HarnessAPIKey_aDigestBehindThePrefix writes them out.
//
// The Airtable personal access token beside this one opens on the same three
// letters, and no value of either is a value of the other: that format writes
// fourteen characters of an identifier where this one writes its first full
// stop, and its secret is sixty-four hexadecimal characters with no stop at all,
// where this grammar wants a second one twenty-two characters past the first.
//
// What the shared letters do reach is candidates and spans, in both directions,
// and neither costs a redaction.
//
//   - A candidate of this scan opens inside an Airtable token wherever that
//     token's identifier closes on the three letters, its own first stop landing
//     on the stop Airtable writes at the eighteenth character. The secret behind
//     that stop is what turns the candidate away.
//   - A span of this scan reaches over an Airtable token written straight behind
//     a key, the secret's run reading on through the Airtable identifier and
//     stopping at that token's own separator. The two spans overlap and
//     Masker.locate makes them one redaction, so nothing of either credential
//     survives; what a reader loses is which of the two the redaction is
//     attributed to.
//
// Test_HarnessAPIKey_anAirtableToken drives both, and the cases named for the
// pair in conformance/testdata/builtins_together.txt state the second end to
// end.
//
// referenceHarnessAPIKeyAt in builtin_harness_api_key_test.go states the grammar
// again, spelling the prefixes, the three counts, the separator and the two
// classes so that the two are changed together, and the fuzz target beside it
// holds this scan to that statement. It is written out rather than built on an
// expression, and the floor is what settles that: the reference says why, and
// what it measured.
var harnessAPIKey = newBuiltin("harness-api-key", &harnessAPIKeyTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := harnessAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], harnessAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not,
		// which is the step builtin_scan.go argues. The rationale above says
		// what it finds: a key can begin inside another, and consuming the match
		// would step over one.
		offset = anchor + 1

		if anchor < harnessAPIKeyAnchorIndex {
			continue
		}
		start := anchor - harnessAPIKeyAnchorIndex

		if !harnessAPIKeyOpens(src[start:]) {
			continue
		}

		secret := start + harnessAPIKeySecretAt
		if secret > len(src) {
			// The input ends inside the identifiers, so the counts and the stops
			// between them — the whole of what tells this candidate from a
			// dotted name — cannot be taken here. What is written of the
			// candidate is not read before giving up on it, for the reason
			// builtin_scan.go gives.
			retain = min(retain, start)
			continue
		}
		if !isHarnessAPIKeyIdentifiers(src[start+harnessAPIKeyPrefixChars : secret]) {
			continue
		}

		end := base62RunEnd(src, secret)
		if end == len(src) {
			// The run reaches the end of the input, so nothing behind the
			// identifiers is settled here: what comes next either carries the
			// run on and lengthens the span, or closes it. That holds whether or
			// not the floor has already been met.
			retain = min(retain, start)
		}
		if end-secret >= harnessAPIKeySecretChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// harnessAPIKeyPrefixes is what a candidate opens with, one entry a kind: the
// three letters naming the kind and the separator behind them.
//
// They are built from those parts rather than written out, so that a kind added
// to harnessAPIKeyKinds is a kind the tail below knows about as well. A table
// written out beside them is one that can come to disagree about which kinds
// there are, and what a stream does with the kind it was not told about is
// release the characters a key opens with.
var harnessAPIKeyPrefixes = func() []string {
	prefixes := make([]string, 0, len(harnessAPIKeyKinds))
	for _, kind := range harnessAPIKeyKinds {
		prefixes = append(prefixes, kind+string(harnessAPIKeySeparator))
	}
	return prefixes
}()

// harnessAPIKeyKinds is what each key opens with, in the letters Harness's own
// code names them by: pat for a personal access token, which carries the
// permissions of the user who made it, and sat for a service account token,
// which carries a service account's.
var harnessAPIKeyKinds = [...]string{"pat", "sat"}

const (
	// harnessAPIKeySeparator divides a key into its parts: it closes every
	// prefix, and it stands again behind each of the two identifiers. It belongs
	// to neither class a part is written in, which is what makes the counts
	// readable, what puts a key out of reach of any encoding, and what the
	// argument that no two candidates read one run rests on.
	// Test_harnessAPIKeySeparator_runsDoNotOverlap holds it there.
	harnessAPIKeySeparator = '.'

	// harnessAPIKeyKindChars is how many letters name a kind, and
	// harnessAPIKeyPrefixChars is the whole of a prefix: those letters and the
	// separator behind them. Test_harnessAPIKeyKinds holds every kind to that
	// width.
	harnessAPIKeyKindChars   = 3
	harnessAPIKeyPrefixChars = harnessAPIKeyKindChars + 1

	// harnessAPIKeyAnchor is the byte the scan searches the input for and
	// harnessAPIKeyAnchorIndex is where it stands in every prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix rather
	// than for the prefix itself; the rationale above says what made it this
	// byte.
	//
	// Every prefix carries it at this index, which is what lets one search serve
	// them all: a kind that spelled it elsewhere would be a kind no candidate is
	// ever found at, and Test_harnessAPIKeyAnchor reports that.
	harnessAPIKeyAnchor      = harnessAPIKeySeparator
	harnessAPIKeyAnchorIndex = harnessAPIKeyKindChars

	// harnessAPIKeyAccountChars is the account identifier behind the prefix and
	// harnessAPIKeyTokenChars the token identifier behind that, each read at
	// exactly the count the three rules stating this format agree on.
	harnessAPIKeyAccountChars = 22
	harnessAPIKeyTokenChars   = 24

	// harnessAPIKeySecretChars is the count the secret is held to, read as a
	// floor rather than exactly. The rationale above weighs that against the
	// exact counts in front of it.
	harnessAPIKeySecretChars = 20

	// harnessAPIKeyIdentifiersChars is everything between the prefix and the
	// secret: the two identifiers and the separator behind each of them.
	harnessAPIKeyIdentifiersChars = harnessAPIKeyAccountChars + 1 + harnessAPIKeyTokenChars + 1

	// harnessAPIKeySecretAt is how far into a key its secret begins, and so how
	// much of one a candidate reads before the floor is asked about.
	harnessAPIKeySecretAt = harnessAPIKeyPrefixChars + harnessAPIKeyIdentifiersChars

	// harnessAPIKeyChars is the shortest key: everything in front of the secret
	// and the floor the secret is held to. Test_harnessAPIKeyChars holds it to
	// the seventy-two characters the tests beside this file are written with.
	harnessAPIKeyChars = harnessAPIKeySecretAt + harnessAPIKeySecretChars
)

// harnessAPIKeyOpens reports whether one of the prefixes stands at the start
// of s.
//
// No two prefixes stand at one position, so the first that matches is the only
// one that can. Test_harnessAPIKeyKinds holds that, and says what a kind added
// later would otherwise cost.
func harnessAPIKeyOpens(s string) bool {
	for _, prefix := range harnessAPIKeyPrefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// isHarnessAPIKeyIdentifiers reports whether s is everything a key writes
// between its prefix and its secret: exactly harnessAPIKeyAccountChars
// characters of the account identifier, the separator, exactly
// harnessAPIKeyTokenChars of the token identifier, and the separator again.
//
// The width is checked here rather than left to the caller to have cut
// correctly: the two indexed reads below would otherwise answer for a slice of
// some other length, or panic on one too short for them. Both separators are
// then compared before either identifier is walked, because a candidate that is
// no key is usually not one at a separator — a dotted name reaching the prefix
// writes its next stop wherever the name happens to end — and two comparisons
// turn it away where up to forty-six byte tests would.
func isHarnessAPIKeyIdentifiers(s string) bool {
	if len(s) != harnessAPIKeyIdentifiersChars {
		return false
	}
	if s[harnessAPIKeyAccountChars] != harnessAPIKeySeparator || s[len(s)-1] != harnessAPIKeySeparator {
		return false
	}
	for i := range harnessAPIKeyAccountChars {
		if !isBase64URLByte(s[i]) {
			return false
		}
	}
	for i := harnessAPIKeyAccountChars + 1; i < len(s)-1; i++ {
		if !isBase62Byte(s[i]) {
			return false
		}
	}
	return true
}

// harnessAPIKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var harnessAPIKeyTail = newPrefixTail(harnessAPIKeyPrefixes...)
