package mask

import "strings"

// HashiCorpVaultToken locates HashiCorp Vault tokens: the prefix hvs., hvb. or
// hvr. and the characters behind it. The three name the three kinds of token
// Vault issues — a service token, a batch token and a recovery token — and
// nothing else in the string says them apart, nor what any of them is allowed
// to do, which is carried by the policies attached to the token inside Vault.
//
// A token is located wherever it is written, with no word boundary either side,
// and is redacted from its prefix to the end of the run it stands in. So a
// token written against a word character keeps its span, and a character of the
// token's own alphabet written straight after a token is redacted with it.
//
// What Vault states of the format is a prefix and "24 or more" characters
// behind it, and this pattern reads exactly that, so text of that shape is
// redacted whether or not Vault issued it. The shape is reachable by writing as
// well as by encoding, which is worth knowing before this pattern is switched
// on over source code: a name written in dot-separated segments is located
// wherever the segment behind an hvs, hvb or hvr runs to twenty-four
// characters, so both hvs.example-host-name-of-that-length and a method call on
// a receiver named hvs are redacted from the h to the end of that segment. What
// holds ordinary text back is the twenty-four unbroken characters and nothing
// else.
//
// Its name is "hashicorp-vault-token".
func HashiCorpVaultToken() Pattern { return hashiCorpVaultToken }

// What the vendor states here it states twice over, in prose and in the
// source, and it is worth saying which part comes from where. The page on
// token concepts carries a table of the three prefixes against the three kinds
// of token, says that "after the prefix, a string of 24 or more
// randomly-generated characters is appended", and prints a service token as an
// example; Vault's own source states the same three prefixes as
// ServiceTokenPrefix, BatchTokenPrefix and RecoveryTokenPrefix, and the same
// twenty-four as TokenLength. So the prefixes, the count and the fact that the
// count is a floor are the vendor's rather than read off the keys a ruleset
// was shown, which is the firmer of the two footings a count here is read on.
//
// The alphabet is the one thing the prose does not state, and the source does.
// One grammar serves all three prefixes because what it leaves is one alphabet
// read to one floor, and because the three prefixes differ in a single
// character. A recovery token is that character and twenty-four of base62:
// Vault generates it as base62.Random(TokenLength) and prepends hvr., and
// nothing lengthens it afterwards. A service token is one of two shapes. Where
// server side consistent tokens are off, and for a root token whatever they are
// set to, it is base62.Random(TokenLength) behind hvs. — twenty-four
// characters, which is the shape the vendor's own example is written in.
// Otherwise Vault wraps that random string in a protobuf carrying the storage
// index it needs, signs it with an HMAC, marshals the two together and writes
// the result with base64.RawURLEncoding, which comes to between ninety-one and
// a hundred and twenty-two characters behind the prefix — the "95+ characters"
// the consistency FAQ states, prefix included, against the "27+" of the format
// before it. A batch token is the token's own entry encrypted and written with
// base64.RawURLEncoding as well, and is longer again.
//
// The alphabet is base64url, isBase64URLByte in builtin_scan.go. That is what
// RawURLEncoding writes, so it is what the two long shapes are written in, and
// base62 is inside it, so it is what the two short ones are written in too.
// Neither character of standard base64 is admitted and no padding is, which
// RawURLEncoding does not write. Of the rulesets, gitleaks and trufflehog read
// the same alphabet; kingfisher reads base62 behind hvs. and hvr. and
// base64url behind hvb. alone, which is wrong about the first of those and can
// be shown wrong from the sample gitleaks itself carries, a service token with
// both a hyphen and an underscore in its body.
//
// The count is a floor rather than a count, and it is one because the vendor
// wrote "or more". What that buys is the whole of why the three prefixes can
// share a grammar: twenty-four characters is a recovery token and a root
// service token exactly, and every longer shape is located to the end of its
// run rather than to a count that would leave the rest of it in the output. A
// scan reading the ninety the two rulesets that state a length state would
// locate neither of the short shapes at all — and one of the two is what
// GitHub's secret scanning lists separately as
// hashicorp_vault_root_service_token, beside hashicorp_vault_service_token and
// hashicorp_vault_batch_token.
//
// What the floor costs is the token shorter than it. A line cut to a column
// limit partway through one leaves a prefix and a body too short to be a body,
// and nothing is located: the random characters written before the cut stay in
// the output. That is the far side of this choice, and the cases in
// builtin_hashicorp_vault_token_test.go pin it so that it stays a decision on
// the record.
//
// The floor also admits a length Vault does not issue, and that is worth
// setting out rather than leaving to be found. Put the shapes above together
// and a body is twenty-four characters, or it is ninety-one and up for the one
// shape whose length can be computed: the two short shapes are
// base62.Random(TokenLength) by construction, and a server side consistent
// service token comes to ninety-one at its shortest, for the fields Vault
// marshals into one today. Nothing known lands between. So a tighter grammar
// was available — twenty-four of base62 exactly, or a much higher floor of
// base64url — and the window from twenty-five to ninety is where this scan is
// looser than the tokens Vault emits. It is where the dot-separated name below
// is reached: the thirty-one characters of create_or_update_secret_version are
// no token of any of the three shapes.
//
// The window is admitted all the same, for three reasons worth having on the
// record. The first is what the tighter grammar would do to a truncated token,
// which is the case this library exists for: a log line cut through the middle
// of a service token leaves forty or sixty characters of live token material,
// this floor redacts them, and a grammar asking for exactly twenty-four or at
// least ninety-one would leave every one of them in the output. The second is
// that ninety-one is arithmetic over Vault's current protobuf — the field
// numbers, an inner token that itself carries the hvs. prefix, a SHA-256 HMAC
// — and every one of those may move without the documented format moving,
// where what the vendor actually promises is "24 or more". A floor read from
// the implementation breaks silently on a release that stays inside the
// documentation, and it breaks by locating nothing. Raising the floor short of
// ninety-one rather than to it only trades the same coin at a worse rate: a
// cut falling uniformly inside a ninety-one character body leaves something
// this floor redacts three times in four, where a floor of forty redacts it a
// little over half the time and one of fifty fewer than half. The third is
// that no minimum is established for a batch token at all: its length is
// whatever the encrypted entry comes to, the rulesets disagree about it, and
// the source states none. So the count is read from what Vault documents in
// preference to the shapes it currently emits, and being wrong that way
// over-matches where being wrong the other way would miss a credential. That
// is the trade a scan makes wherever it reads a floor rather than a count;
// what is unusual here is only which side of it the vendor underwrites, since
// Vault wrote the floor down where a floor is usually read off a ruleset
// instead. Test_HashiCorpVaultToken_aBodyBetweenTheShapes pins the window and
// the truncated token that is the reason for it.
//
// The floor is also the whole of what turns text away, since three characters
// and a dot are little to find a candidate by. Twenty-four unbroken characters
// of base64url is what an ordinary hv-something has to carry to be read as a
// token, and the over-matching below is where that is paid for.
//
// The legacy prefixes are not read, and declining them is the largest decision
// in this file. Vault issued s., b. and r. until 1.10, has not revoked what it
// issued, and the tokens carrying them still authenticate. But s. and
// twenty-four characters of base64url is not a grammar this library can have:
// it is the shape of a field access, a method call and a qualified name, and
// gitleaks carries one as a false positive of its own — the
// s.DefaultListableBeanFactory inside a Spring log line, twenty-six characters
// behind the dot. Both rulesets reading the old prefix reach for something
// beyond the grammar to hold it back: gitleaks an entropy floor of three and a
// half and an allowlist for the all-letter case on top of that, trufflehog a
// refusal to look at the prefix at all unless the word vault stands somewhere
// in the same text. Neither device is available here. This library has no
// entropy heuristic, no window of surrounding text, and redacts rather than
// reports, so being wrong writes over what a reader wanted to keep instead of
// costing them a moment. b. and r. are the same shape with the same problem,
// and each is as ordinary an identifier. What declining
// them costs is a token of the old format left in the output whole, which is
// stated rather than hidden: Test_HashiCorpVaultToken_theLegacyPrefixes pins
// the decision, so that reading them is a change somebody argues for rather
// than one somebody notices afterwards.
//
// The other Vault credential carrying a prefix is not read either, and for a
// plainer reason: it is not a token. An OIDC provider's client secret is
// hvo_secret_ and sixty-four characters of base62, exactly as Vault's source
// generates it, and it would be a pattern rather than a prefix of this one —
// what it opens with is not a prefix this grammar can reach, since the
// character behind hv names a kind of token and the one behind that is the
// separator rather than an underscore. Test_HashiCorpVaultToken_theClientSecret
// holds it outside.
//
// The namespace of a token is the one thing a span can be left short of. Vault
// appends the namespace ID behind the body, separated by a dot, once the prefix
// is on, and the encoding a server side consistent service token is wrapped in
// then hides it again — so what carries a visible one is a batch token, and a
// service token whose external form is the unwrapped one. The dot ends the run,
// so the span stops in front of it and the few characters of namespace ID stay
// in the output. They are an identifier of a namespace and not of the token,
// and what they are written beside is already redacted; going on past the dot
// would mean admitting the separator into the body, and a grammar admitting it
// reaches into the sentence a token was written in.
// Test_HashiCorpVaultToken_aNamespacedBatchToken pins what is left.
//
// There is no boundary on either side of a match. A boundary in front would
// drop the whole match rather than trim it wherever a token is written against
// a word character. One behind would drop rather than trim as well, and where
// it were asked decides what it drops. Asked behind the count, it drops the
// token a letter, a digit or an underscore is written against wherever the
// count closes on one of those, and the token whose count closes on the hyphen
// wherever no word character is written against it. Asked behind that run, it
// drops the token whose body closes on a hyphen and nothing else, since every
// word character belongs to base64url — so the character standing behind a run
// is never one, and a boundary is left asking the token's own last character
// to be one.
//
// The tightening on offer in front is to ask that no character of base64url
// stand before the prefix, and it is declined. What it would buy is the first
// of the two kinds of over-match set out below and not the second: every
// over-match inside an encoding is the prefix found at the boundary between two
// base64url segments, and there the character in front of the h is a character
// of the segment, so the demand turns all of those away. It does nothing about
// the other kind, the dot-separated name, where what stands in front of the h
// is ordinarily a space, an equals sign, a slash or the start of the line. A
// word closing on hvs would be turned away by it, since the letter before the h
// is then one of the alphabet — but that is the same word the demand spares
// nothing else about, and it is not what makes the collision reachable.
//
// What it would cost is two things rather than one. The first is a token
// written straight against a letter, a digit, a hyphen or an underscore, which
// is a live credential left in the output whole. The second is the nesting the
// paragraph below is about: a token can be written inside the one before it,
// and where it is, the character in front of the second token's prefix is the
// last character of the first token's body — a character of base64url. The
// demand would reject that second token and leave its body in the output. This
// is where the Stripe scan and this one part company, and it is the trade the
// Linear scan declines for its own format in the same words: Stripe can ask
// that no letter and no digit stand in front of a prefix because no Stripe key
// can begin inside another, and a Vault token can.
//
// So the demand is a remedy for one of the two collisions, none at all for the
// other, and paid for in credentials that go unredacted — and the balance there
// is the asymmetry this library is built on: over-matching on a value already
// opaque costs a reader nothing, and declining a credential costs them the
// credential. Test_HashiCorpVaultToken_nextToWordCharacters pins the first of
// the two costs and the nesting case in Test_HashiCorpVaultToken the second.
//
// The scan resumes one byte past the start of a candidate whether it became a
// token or not. A token can be written inside the one before it, because h and
// v and the letter naming a kind all belong to the alphabet a body is written
// in: a body closing with hvs and the dot of the next token standing directly
// behind it is two tokens, the second beginning three characters before the
// first one ends. Consuming a match would step over such a token and leave it
// in the output whole. The two spans then overlap, which a Masker resolves into
// one.
//
// No cursor is kept over the run, and none is needed, which is what the
// separator buys. A candidate asks for a dot at the character in front of its
// body and base64url holds none, so the dot of the next candidate can be no
// earlier than the byte that ends this run, and the run that candidate reads
// therefore begins past this one. Successive candidates read runs that do not
// overlap, and reading all of them comes to the length of the input — the
// guarantee a scan whose prefix closes on a character its own body admits has
// to keep a run cursor for instead, bought here without state.
// Test_hashiCorpVaultTokenSeparator_runsDoNotOverlap holds the separator to
// the one thing that argument rests on, and
// Test_HashiCorpVaultToken_scanIsLinear drives it.
//
// What the scan searches the input for is the separator every prefix closes
// with, rather than any one prefix. The three prefixes agree on the two letters
// in front of the kind and on that separator and differ in one character, so
// one search over the text finds candidates of all three kinds where three
// searches would read the text three times. Which of the shared characters
// carries the search is settled where the separator is declared, and it is the
// separator by a narrow margin on an ordinary line and by a wide one on a line
// of hv with no kind behind it.
//
// What this pattern over-matches on: twenty-four characters of base64url
// behind hv, a letter and a dot inside something nobody issued. The dot is
// what makes that rare and what decides where it is reachable at all. Standard
// base64 writes none, a base64url encoding writes none, and neither does a run
// of hexadecimal, so a certificate, a PEM body, an embedded image or a digest
// carries no prefix to be found at however long it runs — which is the
// collision a pattern whose prefix closes on a character a body is written
// with has to state, and this one does not have.
//
// Where it is reachable is a value written as dot-separated segments of
// base64url, and a JWT is the one everybody has. Three characters of a segment
// are hvs, hvb or hvr about once in eighty-seven thousand, so about one JWT in
// forty thousand closes a segment that way and has the dot and twenty-four
// characters of the next segment behind it; the same holds of the segments of a
// SendGrid key and of a signed session cookie. What is redacted there is the
// tail of the value from the dot onward, and it costs a reader nothing: the
// value was opaque to begin with and is itself a credential, so the JWT and
// SendGrid patterns beside this one redact the whole of it anyway.
// Test_HashiCorpVaultToken_insideAnEncoding pins it.
//
// The other side is text somebody wrote, and it needs the dot as well: hv, a
// letter, a dot and twenty-four unbroken characters of base64url. What reaches
// that is a dot-separated name whose segment after the hvs, hvb or hvr runs to
// twenty-four characters, and it is redacted from the h to the end of that
// segment with the rest of the name left standing. A hostname is one shape of
// it. A qualified name in source is the other, and it is worth naming because
// it is the shape that makes the legacy prefixes unreadable, three paragraphs
// up: hvs.CreateOrUpdateSecretVersion is s.DefaultListableBeanFactory again,
// and the underscore being a character of the alphabet means a member name in
// snake_case runs on rather than being broken into segments short of the
// floor.
// What separates the two is not the grammar but how much text has to line up
// behind it. s. and a long member name is most of a Java or Go file; hvs. and
// one is not, and it is worth being exact about why, because the obvious reason
// is wrong. hvs is not a rare thing to call an identifier: HashiCorp itself
// abbreviates HCP Vault Secrets to HVS, spells it that way in the URLs of its
// own documentation, and names things for it in its own code — the Vault
// Secrets Operator carries vso-hvs, hvs-dynamic-secret-cache and an
// hvsaLabelPrefix. So the codebases likeliest to adopt this pattern are the
// ones likeliest to have the name in them.
//
// What is rare is the whole shape, and it has to be counted as the scan reads
// it rather than as one pictures it. There is no boundary in front, so what
// matches is hvs, hvb or hvr wherever they stand — a word closing on them as
// much as an identifier that is only them — with a dot straight after and
// twenty-four unbroken characters of base64url after that. Searched for exactly
// that way, the shape occurs nowhere in the Go standard library, nowhere in the
// Vault Secrets Operator — the codebase that uses the name most — and nowhere
// in Vault's own source but its token fixtures, which are tokens and are meant
// to match. The name being common and the shape being absent are both true, and
// it is the second that this pattern rests on.
//
// What admits such a name is worth separating from what admits a hostname of
// twenty-four characters. A segment of exactly twenty-four is a root service
// token's shape exactly, and declining it would mean declining every token
// Vault happened to write in the letters alone: nothing is left to read it by.
// A longer segment is reached instead by the window the paragraphs on the floor
// set out, and is admitted for the reasons given there — the truncated token
// most of all — rather than because nothing could have told it from a token.
// Test_HashiCorpVaultToken_aDottedName pins both shapes and the length either
// side of the floor.
//
// What reaches a span is never prose, never a git SHA and never an MD5. No word
// is spelled hvs, hvb or hvr, and neither digest holds the separator a
// candidate needs.
//
// referenceHashiCorpVaultToken in builtin_hashicorp_vault_token_test.go keeps
// the grammar as a regular expression, spelling the prefixes, the floor and the
// alphabet again so that the two are changed together, and the fuzz target
// beside it holds this scan to that expression.
var hashiCorpVaultToken = newBuiltin("hashicorp-vault-token", &hashiCorpVaultTokenTail, func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := hashiCorpVaultTokenTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], hashiCorpVaultTokenSeparator)
		if i < 0 {
			break
		}
		at := offset + i

		// The scan resumes here whether this candidate became a token or not, for the
		// reason the rationale above gives: a body may close with the three
		// characters a prefix opens with, so a token can begin three characters
		// before the end of the one before it.
		offset = at + 1

		body := at + 1
		start := body - hashiCorpVaultTokenPrefixChars

		// The byte a prefix opens with is tested before the rest of it is
		// compared and before the kind is looked up. Every separator the search
		// stops at reaches this line, and all but the few that open a candidate
		// are turned away by one byte.
		if start < 0 || src[start] != hashiCorpVaultTokenAnchor[0] ||
			src[start:start+len(hashiCorpVaultTokenAnchor)] != hashiCorpVaultTokenAnchor ||
			!isHashiCorpVaultTokenKind(src[start+len(hashiCorpVaultTokenAnchor)]) {
			continue
		}

		end := base64URLRunEnd(src, body)
		if end == len(src) {
			// The run reaches the end of the input, so neither where the body
			// ends nor whether it is long enough to be one is settled here:
			// what comes next either carries the run on or closes it.
			retain = min(retain, start)
		}
		if end-body >= hashiCorpVaultTokenBodyChars {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans, retain
})

// hashiCorpVaultTokenPrefixes is what a candidate opens with, one entry to a
// kind. It is built from the parts the scan reads rather than written out
// again, so that a kind added to hashiCorpVaultTokenKinds is a kind this knows
// about: a table spelling the prefixes out is one that can come to disagree
// with the scan about which kinds there are, and what a stream would then do
// with the kind it had not been told about is release the front of it and
// redact nothing.
var hashiCorpVaultTokenPrefixes = func() []string {
	prefixes := make([]string, 0, len(hashiCorpVaultTokenKinds))
	for _, kind := range hashiCorpVaultTokenKinds {
		prefixes = append(prefixes, hashiCorpVaultTokenAnchor+string(kind)+string(hashiCorpVaultTokenSeparator))
	}
	return prefixes
}()

const (
	// hashiCorpVaultTokenAnchor is what every prefix opens with and what a
	// candidate is read back to. Both its characters belong to the alphabet a
	// body is written in, which is what lets one token begin inside another and
	// is why the scan resumes a byte along.
	// Test_hashiCorpVaultTokenAnchor holds it to that.
	hashiCorpVaultTokenAnchor = "hv"

	// hashiCorpVaultTokenKinds are the characters that may stand between the
	// anchor and the separator, one per kind of token Vault issues: s for a
	// service token, b for a batch token, r for a recovery token. Vault's own
	// source names the three prefixes they complete ServiceTokenPrefix,
	// BatchTokenPrefix and RecoveryTokenPrefix.
	hashiCorpVaultTokenKinds = "sbr"

	// hashiCorpVaultTokenSeparator is what every prefix closes with, and the
	// byte the scan searches the input for. It belongs to no body, which is
	// what keeps two candidates from ever reading the same run — the argument
	// the scan's linearity rests on, held by
	// Test_hashiCorpVaultTokenSeparator_runsDoNotOverlap.
	//
	// It is searched for rather than the two characters a prefix opens with,
	// for the reason builtin_scan.go gives. The margin on an ordinary line is
	// narrow — over the one these benchmarks are written on the h stands three
	// times and the separator twice — and what makes the choice is the line
	// this pattern's own worst case is written from: hv with nothing behind it,
	// repeated, is an h every other byte and not one separator, so a search
	// that stops at the separator never reaches the loop at all.
	hashiCorpVaultTokenSeparator = '.'

	// hashiCorpVaultTokenPrefixChars is the whole of a prefix: the anchor, plus
	// the one character naming the kind and the one the prefix closes with. It
	// comes to four, which is what Vault's own TokenPrefixLength states, and
	// Test_hashiCorpVaultTokenAnchor holds it to that number rather than to
	// this arithmetic — an anchor of another length would be a different
	// format.
	hashiCorpVaultTokenPrefixChars = len(hashiCorpVaultTokenAnchor) + 2

	// hashiCorpVaultTokenBodyChars is the count a body is held to, read as a
	// floor rather than exactly. Twenty-four is Vault's own TokenLength and
	// what its documentation states as "24 or more"; the rationale above weighs
	// what reading it as a floor buys and what it costs.
	hashiCorpVaultTokenBodyChars = 24
)

// isHashiCorpVaultTokenKind reports whether c is a character naming a kind of
// token, which is what stands between the anchor and the separator.
//
// The kinds are read from one string rather than the three prefixes being
// tried in turn, because that is the only character the three differ in: a
// prefix table here would be three strings agreeing on three of their four
// bytes, and the scan would compare the anchor it has already found again at
// every candidate. Test_isHashiCorpVaultTokenKind holds this to admitting
// exactly what hashiCorpVaultTokenKinds names.
func isHashiCorpVaultTokenKind(c byte) bool {
	return strings.IndexByte(hashiCorpVaultTokenKinds, c) >= 0
}

// hashiCorpVaultTokenTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var hashiCorpVaultTokenTail = newPrefixTail(hashiCorpVaultTokenPrefixes...)
