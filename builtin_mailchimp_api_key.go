package mask

import "strings"

// MailchimpAPIKey locates Mailchimp API keys: thirty-two hexadecimal
// characters, the separator -us, and the number of the data center the account
// is held in. One key reaches the whole of the Marketing API for that account —
// its audiences, the subscriber data behind them and the campaigns sent to
// them — with no scope on it to narrow what it can do.
//
// A key is located wherever it is written, with no word boundary either side,
// and the thirty-two characters are held to being the whole of the run they
// stand in: a hexadecimal character written against either end of them is text
// that is no key. The number is read to the end of its digits, so a key is
// redacted whole however far the data centers are numbered.
//
// Its name is "mailchimp-api-key".
func MailchimpAPIKey() Pattern { return mailchimpAPIKey }

// Mailchimp states the shape and not the count. The fundamentals page of the
// Marketing API documentation says the data center subdomain is appended to
// your API key in the form key-dc, and gives us6 as one. So the vendor's own
// statement is the separator, the letters us, and a number behind them — and
// that is what carries this pattern, since none of it is written in the body's
// alphabet.
//
// What the vendor does not state is the body. The example printed beside that
// sentence is thirty-one hexadecimal characters, which is a docs example
// eliding rather than masking byte for byte and establishes no length; the
// client library Mailchimp publishes never reads the key at all, taking the
// server prefix as a second argument, so it states nothing either.
//
// The count rests on the public rulesets, and the two that read this format do
// not read it the same way. trufflehog reads [0-9a-f]{32}-us[0-9]{1,2} standing
// on its own, which is the whole of the grammar below in one expression.
// gitleaks reads a body of thirty-two and a number of exactly two digits, but
// only where the word mailchimp is written in front of the value with an
// assignment between them — a rule that fires on a key in a configuration line
// and on the same key written anywhere else not at all. So the thirty-two is
// what both of them write down and the only count either states, while what
// reads a key with nothing beside it is trufflehog alone. It is a count to
// revisit if a key is ever seen coming through in pieces.
//
// The alphabet is lowercase hexadecimal alone, isMailchimpAPIKeyBodyByte below.
// Both rules spell that class lowercase, and gitleaks then folds it: its
// generator writes one (?i) across the whole expression for the sake of the
// identifier in front, so the case its body admits is a consequence of how the
// rule is built rather than anything said about a key. What states a lowercase
// body is therefore trufflehog's expression, with the other's spelling agreeing
// and its flag not. Admitting the uppercase spelling would buy no key: a key is
// copied out of a dashboard and pasted, where a UUID is a canonical identifier
// a tool may re-case on its way through a log, and nothing here is one. What
// the narrow reading costs is a key somebody upper-cased by hand, which no
// source shows.
//
// The body count is read exactly and the run is held to being the whole of it.
// Thirty-two hexadecimal characters are an MD5, and a pattern here may not be
// anchored on a digest; what makes a key locatable at all is the separator and
// the number behind it. Reading the last thirty-two characters of a longer run
// would widen that net over every digest a -us and a number happen to be
// written behind — a SHA-1 or a SHA-256 in a file name, an identifier with a
// region written after it — where holding the run to thirty-two leaves the
// grammar the vendor's format exactly.
//
// What the run boundary costs is the key written straight against a
// hexadecimal character: none of it is located, where a looser reading would
// have redacted most of one. That is a text nobody writes on purpose — a key
// stands behind an assignment, a quote, a space or a colon, and none of those
// is hexadecimal — and it is the price of not reading a digest as a key.
// Test_MailchimpAPIKey_nextToWordCharacters writes it out.
//
// The number is read as a floor of one digit to the end of its run, where both
// rulesets read a ceiling: trufflehog one or two digits, gitleaks exactly two.
// Mailchimp states no bound on it, and the two numbers it writes down are not
// the same width — us6 on the fundamentals page, us19 in the README of the
// client library it publishes — so a ceiling is a count that goes stale by the
// vendor adding a machine, and gitleaks' two is already a count that reads none
// of the keys held in the data centers numbered below ten. Read as a floor, a
// key is redacted whole whatever the number runs to; read at two, the third
// digit of a key would stay in the output beside its redaction. What the floor
// admits besides is a number longer than any Mailchimp issues, which is text
// nothing can be read out of.
//
// API key is Mailchimp's own term for what is located here: the name of the
// account section a key is created in, the title of the help page kept on one,
// and what the Marketing API documentation calls the value it authenticates
// with. The other credential the name covers and this grammar reaches nowhere
// is the Transactional API key, which is a different value of a different
// shape: twenty-two characters with nothing in them to be recognised by, which
// trufflehog reads only where the word mandrill stands beside it. A key of that
// kind is left in the output whole, which is stated rather than hidden.
//
// This pattern is declared with NewPattern and not with its openings, so a
// Masker runs it over every text rather than passing over the texts a filter
// turns away. What a candidate is read back from is the separator, and the
// separator stands behind the body rather than in front of it: a key opens on a
// run of hexadecimal, which is no literal a filter can be built from. Declaring
// the separator as an opening would settle the tail of every input by it, and a
// text ending inside a body carries no piece of the separator at all — so a
// stream would release thirty-two characters of a key and redact the -us19 that
// arrived after them. builtin_scan.go states the rule this is the far side of.
//
// What that costs is a scan of every text a caller masks, where a pattern the
// filter can read is passed over on almost all of them. It is the price of a
// format whose value carries no opening of its own, and it is not this
// pattern's to weigh alone: AWSSecretAccessKey pays the same for the same
// reason, and its file argues why a value with nothing in front of it can be
// carried here at all.
//
// The byte the scan searches the input for is the hyphen the separator opens
// with, and it is chosen for what it leaves the tail rather than for being
// rare. It is the first character of the separator, so every candidate whose
// separator has begun is reached at its own anchor and read there, and what is
// left for the walk over the end of the input is the body run alone. Anchored a
// byte later, at the u, a text ending in a body and a bare hyphen would reach no
// candidate at all, and settling it would take a second reading of the separator
// kept beside the first and free to disagree with it.
// Test_MailchimpAPIKey_settlesWhatTheInputCutShort drives the inputs the
// distinction is about.
//
// Rarity costs that nothing. Over the line these benchmarks are written on the
// hyphen and the u each stand twice — the first in the timestamp, the second in
// the words around it — and the s five times, so the search stops as often at
// either of the first two.
// Measured either way over this pattern's own benchmark cases, the hyphen is
// ahead on the ordinary line and further ahead on the lines that crowd values
// together, and behind only on a line that is nothing but separators, which is
// text no log carries.
//
// The scan advances one byte past the start of a candidate whether that
// candidate became a key or not, which is the default and needs no argument.
// What it finds there is a key written inside another, and there is exactly one
// place inside a key one can begin: the first character of the number. A body
// opens only where the character in front of it is not hexadecimal, and
// everywhere else inside a key that character is — the body's own characters,
// and the digits of the number — so the s the separator closes with is the one
// position that admits a body, and the digits behind it are a body where enough
// of them are written. A scan consuming its match would step over such a key and
// leave it in the output whole. The spans overlap and Masker.locate resolves
// them; Test_MailchimpAPIKey_aKeyBeginningInsideAnother drives the position.
//
// What rules out a quadratic input is a count for the body and the separator
// for the number. A candidate reads at most one character in front of the body,
// thirty-two of the body itself and three of the separator before it is given
// up on, whatever run it stands in. The number behind it is a run rather than a
// count, and two candidates cannot read the same one: a candidate opens at the
// hyphen the separator is written with, and a hyphen is no digit, so the run one
// candidate reads ends where the next candidate's separator begins.
// Test_MailchimpAPIKey_scanIsLinear drives the inputs that would find that
// wrong, a body of digits among them, which is where two candidates come
// closest to reading the same run.
//
// What this pattern over-matches on is the vendor's format exactly, and the one
// shape worth naming is the digest with a region written behind it. An MD5 is
// thirty-two hexadecimal characters, so an MD5 standing on its own in front of
// -us and a number is a key character for character and is redacted. There is
// nothing left to tell the two apart, and a scan declining it would decline
// every key Mailchimp issues, whose bodies are written in the same sixteen
// characters. What holds that back to the shape it is, rather than to every
// digest, is the run boundary above: a SHA-1 or a SHA-256 written there is a run
// too long to be a body and is left alone.
// Test_MailchimpAPIKey_aDigestInFrontOfTheSeparator pins both sides.
//
// What reaches a span is never prose. A word of thirty-two unbroken letters
// drawn from the first six of the alphabet is not one, and the separator and
// the digits have to be written straight against it.
//
// referenceMailchimpAPIKeyFind in builtin_mailchimp_api_key_test.go states the
// same grammar the plain way, spelling the count, the separator and both
// character classes again so that the two are changed together, and the fuzz
// target beside it holds this scan to that statement. It is written out rather
// than built on an expression because neither boundary can be spelled in RE2,
// which has no lookaround: a body held to being the whole of its run and a
// number read to the end of its own are both a character asked about outside
// the match. An expression would cost the other way besides — a key opens in
// the alphabet its body is written in, so a run of hexadecimal is a position an
// engine stops at, and there is no literal in front of the grammar for it to
// search the text for.
var mailchimpAPIKey = NewPattern("mailchimp-api-key", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a body run standing at the end of
	// it, or a candidate the end of it cut short. builtin_scan.go says why
	// those are the two, and mailchimpAPIKeyBodyTail is the first of them —
	// this scan opens its candidates on a run rather than on a literal, so it
	// walks that run itself rather than asking a table of prefixes about it.
	retain := mailchimpAPIKeyBodyTail(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], mailchimpAPIKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not,
		// which is the default step and the one builtin_scan.go argues for.
		offset = anchor + 1

		if anchor < mailchimpAPIKeyAnchorIndex {
			continue
		}
		start := anchor - mailchimpAPIKeyAnchorIndex
		sep := start + mailchimpAPIKeyBodyChars

		// The separator is compared before anything is walked. Every hyphen the
		// search stops at reaches this line, and all but the few that open a
		// candidate are turned away by the two bytes behind the one already
		// known.
		cut := false
		if !strings.HasPrefix(src[sep:], mailchimpAPIKeySeparator) {
			if !strings.HasPrefix(mailchimpAPIKeySeparator, src[sep:]) {
				continue
			}
			// The end of the input cut the separator in half, so what would
			// have decided this candidate is not here to be read. Whether the
			// body in front of it is one is still this scan's own question, and
			// it is asked below before anything is held back.
			cut = true
		}

		// The character in front of the body, which is the whole of what this
		// scan reads in front of a value: a body is the whole of the run it
		// stands in, and one hexadecimal character is what says it is not.
		if start > 0 && isMailchimpAPIKeyBodyByte(src[start-1]) {
			continue
		}
		if !isMailchimpAPIKeyBody(src[start:sep]) {
			continue
		}
		if cut {
			retain = min(retain, start)
			continue
		}

		number := sep + len(mailchimpAPIKeySeparator)
		end := mailchimpAPIKeyNumberEnd(src, number)
		if end > number {
			spans = append(spans, Span{Start: start, End: end})
		}
		if end == len(src) {
			// The number reaches the end of the input, so a digit written next
			// carries it further and widens this key — or gives one to a
			// candidate that has none yet. Whether a span was reported here or
			// not, nothing from the body on is settled.
			retain = min(retain, start)
		}
	}
	return spans, retain
})

const (
	// mailchimpAPIKeySeparator is what divides the body of a key from the
	// number of the data center it belongs to. It is the whole of what tells
	// this format from a digest, since every other character of a key is
	// written in a body's own alphabet or is a digit;
	// Test_mailchimpAPIKeySeparator holds it to being written in neither.
	mailchimpAPIKeySeparator = "-us"

	// mailchimpAPIKeyAnchor is the byte the scan searches the input for and
	// mailchimpAPIKeySeparatorAnchorIndex is where it stands in the separator,
	// so a candidate begins mailchimpAPIKeyAnchorIndex bytes in front of what a
	// search reported. builtin_scan.go says why a scan searches for one byte rather
	// than for the whole of what it reads a candidate back from; the rationale
	// above says what made it this byte, which is what anchoring on the first
	// character of the separator leaves the tail of the input.
	mailchimpAPIKeyAnchor               = '-'
	mailchimpAPIKeySeparatorAnchorIndex = 0
	mailchimpAPIKeyAnchorIndex          = mailchimpAPIKeyBodyChars + mailchimpAPIKeySeparatorAnchorIndex

	// mailchimpAPIKeyBodyChars is how many characters stand in front of the
	// separator, read exactly and held to being the whole of the run. The
	// rationale above says where the count comes from and what holding the run
	// to it buys and costs.
	mailchimpAPIKeyBodyChars = 32
)

// mailchimpAPIKeyBodyTail returns where the run of body characters standing at
// the end of src begins, and len(src) where no body can begin in it.
//
// A key opens on a body, so a body run the end of the input reaches into is a
// key that has not shown what it is yet: nothing of the separator has arrived
// to be found at, and the scan above walks past the run having reported
// nothing. What this returns is where such a run begins, so that the text from
// there on is held back until a separator arrives, or until something that is
// no separator does.
//
// A run already longer than a body is settled rather than held, and it is the
// one thing here read out of a candidate the end of the input cut short.
// builtin_scan.go allows that where the reading is the scan's own grammar and
// nothing else — the same alphabet against the same count, ruling the candidate
// out for every text carrying on from it rather than for the one in hand — and
// a run of thirty-three is that: a body is the whole of its run, the run can
// only grow from here, and no body can begin inside it since every character in
// front of one is a body character. What declining to read it would cost is
// unbounded, which is why it is read: a line of hexadecimal at the end of a
// write is held from its first character to its last, and a hex dump, a digest
// table or an encoded blob runs as long as the line does.
func mailchimpAPIKeyBodyTail(src string) int {
	i := len(src)
	for i > 0 && isMailchimpAPIKeyBodyByte(src[i-1]) {
		i--
		if len(src)-i > mailchimpAPIKeyBodyChars {
			return len(src)
		}
	}
	return i
}

// mailchimpAPIKeyNumberEnd returns where the run of digits beginning at i in
// src ends, which is len(src) where the run reaches the end of the input.
//
// The caller reads the run being empty as the candidate failing and the run
// reaching the end of the input as the candidate being unsettled, so both
// answers are the offset alone.
func mailchimpAPIKeyNumberEnd(src string, i int) int {
	for i < len(src) && isMailchimpAPIKeyNumberByte(src[i]) {
		i++
	}
	return i
}

// isMailchimpAPIKeyBody reports whether s is the body of a key: exactly
// mailchimpAPIKeyBodyChars characters of lowercase hexadecimal.
//
// It is handed the count as well as the characters so that the two are checked
// in one place rather than the count left to the caller to have cut correctly.
func isMailchimpAPIKeyBody(s string) bool {
	if len(s) != mailchimpAPIKeyBodyChars {
		return false
	}
	for i := range len(s) {
		if !isMailchimpAPIKeyBodyByte(s[i]) {
			return false
		}
	}
	return true
}

// isMailchimpAPIKeyBodyByte reports whether c is a lowercase hexadecimal digit,
// which is what a body is written in.
//
// The uppercase spelling is left out for the reason the rationale above gives:
// the one rule that reads a key standing on its own reads the body lowercase,
// and a key is copied rather than re-cased on its way through a log.
//
// It stays in this file rather than joining the byte tests in builtin_scan.go.
// Every hexadecimal run this package reads keeps its own test, because the two
// are not the same class — one admits either case where this admits one — and a
// shared test named for the class rather than for what reads it would silently
// be the wrong answer for one of them.
func isMailchimpAPIKeyBodyByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f'
}

// isMailchimpAPIKeyNumberByte reports whether c is a decimal digit, which is
// what the number of a data center is written in.
func isMailchimpAPIKeyNumberByte(c byte) bool {
	return '0' <= c && c <= '9'
}
