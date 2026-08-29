package mask

import "strings"

// SupabasePublishableKey locates the publishable API keys a Supabase client is
// initialized with: the prefix sb_publishable_ and the thirty-one characters
// behind it, forty-six characters altogether.
//
// A key is located wherever it is written, with no word boundary either side,
// and exactly forty-six characters of it are. So text of that shape is redacted
// whether or not Supabase issued it. A character outside the base64url alphabet,
// or anything but an underscore twenty-three characters behind the prefix, ends
// the reading, so text as it is ordinarily written is not affected.
//
// Supabase says a publishable key is safe to expose: it is embedded in the
// client it initializes, it carries no privilege row level security has not
// already granted, and the documentation prints it into browser code. It is a
// pattern of its own for that reason rather than in spite of it — a caller
// masking a frontend bundle, a browser console log or a bug report has no reason
// to redact a value that belongs there and every reason to keep it, since it
// says which project the report came from, while a caller masking a
// configuration dump they are about to share may want it gone. Reaching for
// SupabaseSecretKey (builtin_supabase_secret_key.go) alone is how the first
// caller says so, and reaching for both, or for SupabasePatterns, is how the
// second does.
//
// Its name is "supabase-publishable-key".
func SupabasePublishableKey() Pattern { return supabasePublishableKey }

// Publishable key is Supabase's own name for this key, one row of the table of
// key types the documentation opens with, where it is the row a client-side
// application is told to use and the secret key the row that must stay in a
// backend. The boundary between the two patterns is drawn on that distinction,
// so a caller deciding between them is deciding what Supabase already decided
// for them.
//
// The grammar is the secret keys' grammar exactly, and
// builtin_supabase_secret_key.go carries the account of it. None of that is
// repeated here, because none of it is this pattern's to decide: one generator
// writes the body of both kinds and is told only which prefix to put in front of
// it, so the two halves cannot disagree about what stands behind a prefix. What
// is written here is what this half decides on its own.
//
// The prefix is the argument that generator is called with for this kind of key,
// and it is the whole of what tells one from a secret key. It is five characters
// longer, which is the only thing about this half's grammar that is not the
// other half's.
//
// The anchor is the b one character into the prefix, which the other half is
// found by as well because the two prefixes open alike. It stands three times
// here where it stands once there, and that is what the choice costs: a line of
// publishable keys stops the search three times a key rather than once. The two
// extra stops are turned away by the one comparison a candidate opens with,
// since neither the u nor the a standing a byte in front of them is the s a
// prefix opens with.
//
// The h nine characters in is the only other character of this prefix that could
// be argued for, and the argument is the crowded line: it stands once here where
// the b stands three times. It is declined because the line holding no key at
// all is what a scan walks most of, and the b is the rarer of the two there —
// over the prose these tests are written with the b stands not once and the h
// twice, and over the log line these benchmarks are written on they stand once
// each. Of the characters left, the u stands twice on that line and the rest
// four times or more. The underscore stands not once on it and is passed over
// for the reason the other half gives: it is written twice in each of the two
// prefixes, and a body drawn from base64url carries more of them.
//
// There is no boundary on either side of a match, no reading in front of one,
// and no cursor kept between candidates. Each of those is the other half's
// decision as much as this one's and is argued there, and none of them can be
// taken differently here without the two halves of one format disagreeing about
// where a key may be written.
//
// What this pattern over-matches on is thirty-one characters of base64url
// written behind the prefix with an underscore twenty-three characters in, which
// is the vendor's format exactly. The prefix is fifteen characters carrying two
// underscores, so what has to be written to reach it is longer and rarer than
// what reaches the other half.
// Test_SupabasePublishableKey_aBase64URLRunBehindThePrefix pins it.
//
// referenceSupabasePublishableKeyFind in
// builtin_supabase_publishable_key_test.go states the same grammar the plain
// way, spelling the prefix, the two counts, the separator and the character
// class again so that the two are changed together, and the fuzz target beside
// it holds this scan to that statement.
var supabasePublishableKey = NewPattern("supabase-publishable-key", func(src string) ([]Span, int) {
	var spans []Span

	// Where the input stops being settled: a piece of a prefix standing at the
	// end of it, or a candidate the end of it cut short. builtin_scan.go says
	// why those are the two.
	retain := supabasePublishableKeyTail.start(src)

	for offset := 0; offset < len(src); {
		i := strings.IndexByte(src[offset:], supabasePublishableKeyAnchor)
		if i < 0 {
			break
		}
		anchor := offset + i

		// The scan resumes here whether this candidate became a key or not. A body
		// may spell the prefix, so a key can begin inside another and a scan stepping
		// over what it declined would step over the one behind it.
		offset = anchor + 1

		if anchor < supabasePublishableKeyAnchorIndex {
			continue
		}
		start := anchor - supabasePublishableKeyAnchorIndex

		// The byte a prefix opens with is tested before the prefix is compared.
		// Every anchor the search stops at reaches this line, and all but the
		// few that open a candidate are turned away by one byte where a
		// comparison of the whole prefix is a length and a read. The two
		// anchors this prefix carries beyond the one that opens it are turned
		// away here.
		if src[start] != supabasePublishableKeyPrefix[0] || !strings.HasPrefix(src[start:], supabasePublishableKeyPrefix) {
			continue
		}

		body := start + len(supabasePublishableKeyPrefix)
		end := start + supabasePublishableKeyChars
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
	// supabasePublishableKeyPrefix is what every publishable key opens with,
	// and what the scan reads back from its anchor.
	// Test_supabasePublishableKeyAnchor holds it to carrying the anchor at the
	// index below, and counts the two further times it stands here.
	supabasePublishableKeyPrefix = "sb_publishable_"

	// supabasePublishableKeyAnchor is the byte the scan searches the input for
	// and supabasePublishableKeyAnchorIndex is where it stands in the prefix,
	// so a candidate begins that many bytes in front of what a search reported.
	// builtin_scan.go says why a scan searches for one byte of its prefix
	// rather than for the prefix itself; the rationale above says what makes it
	// this byte and what the two further occurrences of it in this prefix cost.
	//
	// The byte and the index are written out rather than read from the other
	// half, where the counts of the body are read from it. What a scan searches
	// for is not part of the format and neither half's choice binds the other:
	// a byte borrowed would carry an index that means nothing in this prefix
	// the moment the other scan moved its own, and nothing would report it.
	supabasePublishableKeyAnchor      = 'b'
	supabasePublishableKeyAnchorIndex = 1

	// supabasePublishableKeyChars is the whole of a publishable key: this
	// half's prefix and the body both halves share.
	// Test_supabasePublishableKeyChars holds it to forty-six.
	supabasePublishableKeyChars = len(supabasePublishableKeyPrefix) + supabaseSecretKeyBodyChars
)

// supabasePublishableKeyTail is what the scan settles the tail of its input by.
// prefixTail (builtin_scan.go) says what that is and why it is built once.
var supabasePublishableKeyTail = newPrefixTail(supabasePublishableKeyPrefix)
