package mask

import "strings"

// RubyGemsAPIKey locates RubyGems.org API keys: the prefix rubygems_ and the
// forty-eight lowercase hexadecimal characters behind it — fifty-seven
// characters altogether. One string serves every key RubyGems.org issues,
// whatever scopes it carries and whichever gem it is scoped to, so nothing in a
// key says what it is allowed to do.
//
// A key is located wherever it is written, with no word boundary either side,
// and exactly fifty-seven characters of it are. So text of that shape is
// redacted whether or not RubyGems.org issued it. A space, an uppercase letter,
// a letter past f or a body of the wrong length ends the reading, so text as it
// is ordinarily written is not affected.
//
// Its name is "rubygems-api-key".
func RubyGemsAPIKey() Pattern { return rubyGemsAPIKey }

// What RubyGems.org states about this format it states in the code that writes
// it, as the Grafana and Vault formats are stated in theirs. RubyGems.org is
// published under MIT and the generator is the ApiKeyable concern:
// generate_rubygems_key is "rubygems_#{SecureRandom.hex(24)}", and
// generate_unique_rubygems_key is that method in a loop until the digest of
// what it returns is one no row holds. Every key the site hands out comes
// through the second — the settings page, the api_key endpoint gem signin
// posts to, the OIDC api key role exchange and the trusted publisher exchange
// each call it and nothing else builds a key. So the prefix and everything
// behind it are read off the thing that produces them rather than off the
// values it produced, which is the firmest footing a format here can be read
// on and firmer than a vendor page that prints an example and states no shape.
//
// The count and the alphabet are Ruby's rather than RubyGems.org's, which is
// firmer still. SecureRandom.hex(n) is random_bytes(n).unpack1("H*"), and
// Random::Formatter documents it in two sentences: the length of the resulting
// string is twice n, and the result may contain 0-9 and a-f. Twenty-four bytes
// are therefore forty-eight characters, and they are lowercase. Neither number
// here is an observation and neither is a wager on a vendor's habit.
//
// The documentation is the second source rather than the first, and reading it
// in that order matters, because it does not agree with itself. Two of the keys
// the RubyGems.org guides print are fifty-seven characters apiece — the one
// written into every Authorization header of the API guide, and the one the API
// key scopes page writes into a credentials file — each the prefix and
// forty-eight lowercase hexadecimal digits, divided the way the generator
// divides them. A third is forty-one, and the paragraph below is about it.
//
// That third example is the prefix and thirty-two hexadecimal digits, and this
// scan does not locate it. The API guide prints it three times: as the
// response of POST /api/v1/api_key, as the api_key parameter of the PATCH
// beside it, and as the response of the trusted publisher token exchange — all
// three of them endpoints whose keys come from generate_unique_rubygems_key,
// which is where the forty-eight comes from. So the guide contradicts the code
// it documents, and the code is what is read. Thirty-two is the length of what
// SecureRandom.hex(16) returns, which is what User#generate_api_key wrote
// before this prefix existed; no published ruleset reads forty-one either, all
// four asking for forty-eight exactly. What the decision costs is a reader
// auditing this pattern against the guide and finding a documented value it
// declines, so the value is written down here and pinned by
// Test_RubyGemsAPIKey_theShortExampleTheGuidePrints rather than left for them
// to come across.
//
// The rulesets agree too, and where they differ they are looser rather than
// tighter. gitleaks reads rubygems_ and forty-eight of [a-f0-9]; kingfisher
// reads the same, spelled with a POSIX class; osv-scalibr's veles reads
// rubygems_ and forty-eight of [0-9a-f] with fifty-seven as the longest a match
// may be. trufflehog reads rubygems_ and forty-eight of [a-zA0-9], a class
// carrying every lowercase letter and the single capital A, which is the same
// count read through an alphabet nothing writes. No published rule asks for
// more than the generator writes.
//
// The alphabet is read as lowercase alone, which is where this scan parts
// company with the Grafana one beside it — a hexadecimal run read in either
// case. The two decisions are not in tension, because what they are decisions
// about is not the same. There the eight characters are a checksum standing
// behind a prefix and a thirty-two character secret that have already decided
// the match, so widening the class draws in nothing further and guards against
// one call to encoding/hex having changed. Here the class is the whole of the
// body, and the guard it would be bought against does not exist: were
// RubyGems.org to stop calling SecureRandom.hex, the count would move with the
// alphabet and a scan reading forty-eight of a wider class would locate nothing
// either. So the wider class costs over-matching and buys no case that a
// narrower one loses, and every published rule reads the narrower one.
//
// The count is therefore read exactly rather than as a floor. A scan reads a
// floor instead for one reason: its vendor states no length, so a count would
// be read off the keys somebody was shown, and a count that is wrong there
// costs the whole credential rather than the end of one. Here the length is
// not an observation at all — twenty-four is the argument the generator passes
// and Ruby documents what doubles it — so there is nothing for a floor to
// protect against. What an exact count costs is what it costs everywhere: a
// run longer than the count is not one longer key but a key with something
// written after it, and only the key is redacted.
//
// There is no boundary on either side of a match. A word boundary in front
// would drop the whole match rather than trim it wherever a key is written
// against a word character, as RUBYGEMS_API_KEY_rubygems_... is, and one
// behind it would drop a key followed by a character of the key's own
// alphabet. What may stand either side is held back by the character class and
// the count alone.
//
// The tightening on offer in front is the one the Slack and Stripe scans take:
// to ask that no letter and no digit stand before the prefix. Three of the four
// rulesets above do ask for it, as the \b they open with; it is declined here
// for the AWS scan's reason and with less to weigh than any of them, since
// there is nothing here for it to buy. Unlike SG., which closes MSG. and ESG.,
// and unlike lin_api_, which closes berlin_api_, no word ends in the letters
// rubygems for a prefix to be spelled by the close of one, so there is no
// snake_case name for the demand to turn away. What it would cost is a key
// written straight against a letter or an underscore, which would then be left
// in the output whole rather than trimmed — RUBYGEMS_API_KEY_rubygems_... is
// how a key reaches a log line from a shell, and \b counts the underscore as a
// word character.
//
// The same three ask for something behind the match as well, and one of them
// asks for more than a boundary: kingfisher and trufflehog close on \b, where
// gitleaks demands a backtick, a quote, whitespace, a semicolon, an escaped
// newline or the end of the input — so a key written against a hyphen or a full
// stop is one gitleaks leaves in the text where this pattern redacts it.
// Declining the demand behind is what the digest below turns on, so it is
// weighed there rather than here.
//
// No key can be written inside another, and what this scan rests that on is the
// letter its prefix opens with. Everything a span covers past the prefix is a
// hexadecimal digit, and the prefix itself opens with r — a letter no body is
// written with and one none of the eight characters behind it is either. So no
// position inside a span opens a prefix, and the spans of this pattern never
// overlap one another.
// Test_RubyGemsAPIKey_noKeyBeginsInsideAnother is what holds the claim.
//
// The scan resumes one byte past the start of a candidate all the same, and
// what that is for is the candidate that did not become a key rather than the
// one that did. rubygems_rubygems_ and forty-eight digits is a candidate at the
// first prefix whose body opens with a letter no body may hold, and a whole key
// at the second; a scan resuming past the length it hoped for would step over
// it. Resuming past a match instead, where a match is what was found, would buy
// nothing measurable and cost a branch: the prefix has no proper border — it
// opens with r and closes with an underscore — so two occurrences of it cannot
// overlap, and the search below skips from one byte past the candidate to the
// next occurrence whichever of the two it was told to start from.
//
// The scan keeps no cursor and needs none: a candidate reads at most
// fifty-seven bytes and stops, which bounds what it reads with no state to be
// wrong about — the guarantee a scan reading a body to the end of its run has
// to buy with a run cursor instead, bought here by the count being a count.
//
// What this pattern over-matches on: fifty-seven characters of the right shape
// that nobody issued. Eight characters spelling a word and an underscore have
// to be written, then forty-eight unbroken characters of the sixteen a
// lowercase digest is written with. Outside an encoding that is a snake_case
// name whose first segment is rubygems and whose second is forty-eight
// hexadecimal characters, and the one such name anybody writes is the key of
// the credentials file gem signin stores a key in — :rubygems_api_key:, whose
// second character p no body may hold, so the line holding it is turned away
// one byte into the body it never had. Inside an encoding there is
// nothing to reach it by. Standard base64 writes no underscore at all, so a
// certificate, a PEM body or an embedded image carries no candidate at however
// long it runs; base64url writes every character of the prefix, and behind one
// the run would have to hold no uppercase letter and no letter past f for
// forty-eight characters, which in an alphabet of sixty-four stands about once
// in a hundred thousand million million million million characters.
//
// The collision that is reachable is a digest written behind the prefix, and
// this pattern pays for it rather than ruling it out. The Grafana format rules
// its own out with the underscore dividing a secret from a checksum, which a
// digest holds none of; here everything behind the prefix is one class and a
// digest is written in it. An MD5 at thirty-two and a SHA-1 at forty are both
// shorter than the count and are turned away by it, and so is a bare digest of
// any length with no prefix in front of it. A SHA-256 is sixty-four, which is
// longer, and since there is no boundary behind a match its first forty-eight
// characters are a body: rubygems_ and a SHA-256 is redacted for fifty-seven of
// its seventy-three characters, and the sixteen left over stay in the text.
//
// The demand behind a match that would turn that away is available and is
// declined, which is the second of the two places this pattern is looser than
// the three rulesets writing both. What it would cost is what such a demand
// costs everywhere in this package: a key with a hexadecimal character written
// straight after it would be dropped rather than trimmed, and a key left in
// the output whole is the failure this library is for. What it would buy is a
// name someone would have to have written as rubygems_ and a digest — where
// every character of that name is a character a key is written with, so
// nothing distinguishes the two but the sixteen characters standing past the
// count, and a scan that read those would be reading what is written after a
// credential to decide whether it is one.
// Test_RubyGemsAPIKey_aDigestBehindThePrefix pins both halves.
//
// What reaches a span is never prose and never a bare git SHA or MD5. A key
// holds an underscore at its ninth character and nowhere else, holds no space,
// and is longer than either digest.
//
// The key format RubyGems.org issued before this one is not read. It is
// User#generate_api_key, SecureRandom.hex(16), and so thirty-two lowercase
// hexadecimal characters with no prefix at all: the migration moving those keys
// into the ApiKey table hashes the value itself, so a legacy key never carried
// one. Nothing tells such a value from an MD5,
// because there is nothing to tell it by: it is an MD5's format exactly, and a
// pattern reading it would redact every digest in every
// lock file, cache key and manifest a caller passes through. That is the loose
// grammar this package declines rather than the unlucky one, and
// Test_RubyGemsAPIKey_theKeyFormatItReplaced pins the decision so that reading
// it is a change somebody argues for rather than one somebody notices
// afterwards.
//
// referenceRubyGemsAPIKey in builtin_rubygems_api_key_test.go keeps the grammar
// as a regular expression, spelling the prefix, the count and the character
// class again so that the two are changed together, and the fuzz target beside
// it holds this scan to that expression.
var rubyGemsAPIKey = NewPattern("rubygems-api-key", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := rubyGemsAPIKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], rubyGemsAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not. No key
		// can be written inside another, which the rationale above argues, so what
		// this is for is the candidate that failed: rubygems_rubygems_ and a body
		// carries a whole key at its second prefix, and resuming past the length this
		// candidate hoped for would step over it.
		offset = anchor + 1

		if anchor < rubyGemsAPIKeyAnchorIndex {
			continue
		}
		start := anchor - rubyGemsAPIKeyAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read.
		if src[start] != rubyGemsAPIKeyPrefix[0] || !strings.HasPrefix(src[start:], rubyGemsAPIKeyPrefix) {
			continue
		}

		body := start + len(rubyGemsAPIKeyPrefix)
		end := start + rubyGemsAPIKeyChars
		if end > len(src) {
			// The input ends inside this candidate, so the count that is the
			// whole of what tells it from anything else written behind the
			// prefix cannot be taken here.
			retain = min(retain, start)
			continue
		}
		if isRubyGemsAPIKeyBody(src[body:end]) {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

const (
	// rubyGemsAPIKeyPrefix is what every key opens with, and what the scan reads
	// back from its anchor. It is the string the generator writes in front of
	// what SecureRandom.hex returns, the underscore included.
	//
	// Two characters of it are load-bearing, and both are ones no body is
	// written with. The r it opens with it carries nowhere else, which is the
	// whole of the claim that no key begins inside another. The underscore it
	// closes with belongs to no body either, so a run of body characters can
	// never hold the prefix and every body begins where such a run begins.
	//
	// That second fact is not what bounds this scan — the count is, as the
	// rationale above says, and the scan would keep no cursor whatever the
	// prefix closed with. It is what a count relaxed to a floor would have to
	// fall back on, which is why it is stated and held to rather than left to
	// be worked out then. Test_rubyGemsAPIKeyPrefix holds the prefix to both.
	rubyGemsAPIKeyPrefix = "rubygems_"

	// rubyGemsAPIKeyAnchor is the byte the scan searches the input for and
	// rubyGemsAPIKeyAnchorIndex is where it stands in the prefix, so a
	// candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; what makes it this byte is that
	// rubygems is spelled in eight of the commonest letters there are — over
	// the log line these benchmarks are written on the r stands three times and
	// the e, the g and the s five each — where the underscore closing the
	// prefix stands not once. What that costs is a candidate opened at every
	// underscore of a snake_case name, and eight characters of a word no name
	// is spelled with turn each of them away.
	rubyGemsAPIKeyAnchor      = '_'
	rubyGemsAPIKeyAnchorIndex = 8

	// rubyGemsAPIKeyBodyChars is what SecureRandom.hex(24) comes to: Ruby
	// documents the result as twice the byte count, so twenty-four bytes are
	// forty-eight characters. Neither number is read off an example.
	rubyGemsAPIKeyBodyChars = 48

	// rubyGemsAPIKeyChars is the whole of a key, and the fifty-seven characters
	// both of the long examples in the RubyGems.org guides are.
	// Test_rubyGemsAPIKeyChars holds it to that number.
	rubyGemsAPIKeyChars = len(rubyGemsAPIKeyPrefix) + rubyGemsAPIKeyBodyChars
)

// isRubyGemsAPIKeyBody reports whether s is everything behind the prefix of a
// key: exactly rubyGemsAPIKeyBodyChars characters of the body's alphabet.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count left to the caller to have cut correctly.
func isRubyGemsAPIKeyBody(s string) bool {
	if len(s) != rubyGemsAPIKeyBodyChars {
		return false
	}
	for i := range len(s) {
		if !isRubyGemsAPIKeyBodyByte(s[i]) {
			return false
		}
	}
	return true
}

// isRubyGemsAPIKeyBodyByte reports whether c is a lowercase hexadecimal digit,
// which is what the body is written in.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go,
// which hold what more than one scan reads. The Grafana scan reads a
// hexadecimal run too and keeps its own test for it, and the two classes are
// not the same one: that one is a checksum and admits either case, this one is
// a whole body and admits lowercase alone, each for the reason its own file
// gives. A shared test named for the class rather than for what reads it would
// have to be one of them, would silently be the wrong answer for the other, and
// would invite the next pattern to read a digest with it.
func isRubyGemsAPIKeyBodyByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f'
}

// rubyGemsAPIKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var rubyGemsAPIKeyTail = newPrefixTail(rubyGemsAPIKeyPrefix)
