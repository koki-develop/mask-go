package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Shopify access token pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a set
// of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. A body is thirty-two hexadecimal characters,
// written here as 0123456789abcdef twice over, and with a six character prefix
// in front of it that comes to thirty-eight. Where a case turns on the case a
// body is written in, the same run is written as 0123456789ABCDEF instead.

func Test_ShopifyAccessToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a public app access token",
			src:  "shpat_0123456789abcdef0123456789abcdef",
			want: []Span{{0, 38}},
		},
		{
			name: "a public app access token in an environment assignment",
			src:  "SHOPIFY_ACCESS_TOKEN=shpat_0123456789abcdef0123456789abcdef",
			want: []Span{{21, 59}},
		},
		{
			name: "a custom app access token",
			src:  "shpca_0123456789abcdef0123456789abcdef",
			want: []Span{{0, 38}},
		},
		{
			name: "a private app and delegate access token",
			src:  "shppa_0123456789abcdef0123456789abcdef",
			want: []Span{{0, 38}},
		},
		{
			// The rules read this class without regard to case, which is what
			// builtin_shopify_access_token.go reads either case on.
			name: "a body written in uppercase",
			src:  "shpat_0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 38}},
		},
		{
			name: "a body written in both cases at once",
			src:  "shpat_0123456789abcdef0123456789ABCDEF",
			want: []Span{{0, 38}},
		},
		{
			name: "a digit before",
			src:  "7shpat_0123456789abcdef0123456789abcdef",
			want: []Span{{1, 39}},
		},
		{
			name: "a hyphenated word before",
			src:  "store-shpat_0123456789abcdef0123456789abcdef",
			want: []Span{{6, 44}},
		},
		{
			name: "between japanese",
			src:  "トークンはshpat_0123456789abcdef0123456789abcdefです",
			want: []Span{{15, 53}},
		},
		{
			// The kind a legacy private app and a delegate token share,
			// written straight against a name — the shape a word boundary in
			// front would drop rather than trim, driven for shppa_ rather
			// than only for shpat_.
			name: "a private app token written straight against a name",
			src:  "TOKEN_shppa_0123456789abcdef0123456789abcdef",
			want: []Span{{6, 44}},
		},
		{
			// The count is read exactly, so what follows the thirty-eighth
			// character is not part of the token and stays in the text.
			name: "a run longer than the count is a token and what follows it",
			src:  "shpat_0123456789abcdef0123456789abcdef0",
			want: []Span{{0, 38}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "shpat_0123456789abcdef0123456789abcdefshpca_0123456789abcdef0123456789abcdef",
			want: []Span{{0, 38}, {38, 76}},
		},
		{
			// A candidate whose body would open with a prefix of its own. The
			// outer one is turned away at the first character of its body,
			// which is the s of the inner opening and no character a body is
			// written with; the inner token is found where it stands.
			name: "a candidate whose body opens with a prefix",
			src:  "shpat_shpat_0123456789abcdef0123456789abcdef",
			want: []Span{{6, 44}},
		},
		{
			// The one shape a word boundary in front would turn away. No word
			// is spelled shpat, shpca or shppa, so what can reach a prefix is a
			// snake_case name whose last segment is those five characters —
			// which the tightening on offer admits anyway, since it admits the
			// underscore.
			name: "a snake_case name closing on a prefix",
			src:  "store_shpat_0123456789abcdef0123456789abcdef",
			want: []Span{{6, 44}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ShopifyAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ShopifyAccessToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prose",
			src:  "the shop app posted an update to the storefront this morning",
		},
		{
			name: "a body one character short",
			src:  "shpat_0123456789abcdef0123456789abcde",
		},
		{
			name: "a letter past f in the body",
			src:  "shpat_0123456789abcdefg123456789abcdef",
		},
		{
			// A space is one of the characters the doc comment names as
			// ending the reading.
			name: "a space inside the body",
			src:  "shpat_0123456789abcdef 123456789abcdef",
		},
		{
			// The uppercase half of "a letter past f": the alphabet reads
			// case-insensitively, so G ends the run exactly as g does above.
			name: "an uppercase letter past f inside the body",
			src:  "shpat_0123456789ABCDEFG123456789ABCDEF",
		},
		{
			// A full thirty-two character hexadecimal run standing directly
			// behind a non-hex first body character, so nothing here
			// distinguishes "the count is measured from the prefix" from
			// "the count resumes past the offending byte".
			name: "a forbidden character at the first body position with a full run behind it",
			src:  "shpat_g0123456789abcdef0123456789abcdef",
		},
		{
			name: "a custom app token with a body one character short",
			src:  "shpca_0123456789abcdef0123456789abcde",
		},
		{
			name: "a private app token in a case an environment variable's name is written in",
			src:  "SHPPA_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a hyphen inside the body",
			src:  "shpat_0123456789abcdef-123456789abcdef",
		},
		{
			name: "an underscore inside the body",
			src:  "shpat_0123456789abcdef_123456789abcdef",
		},
		{
			name: "a line break inside the body",
			src:  "shpat_0123456789abcdef\n123456789abcdef",
		},
		{
			// The prefix is read in lowercase alone: this is the shape an
			// environment variable's name is written in, not the shape a token
			// is.
			name: "an uppercase prefix",
			src:  "SHPAT_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a hyphen where the separator stands",
			src:  "shpat-0123456789abcdef0123456789abcdef",
		},
		{
			name: "the separator missing altogether",
			src:  "shpat0123456789abcdef0123456789abcdef0",
		},
		{
			name: "the opening missing its first character",
			src:  "hpat_0123456789abcdef0123456789abcdef0",
		},
		{
			name: "the right shape with no prefix in front of it",
			src:  "xxxxx_0123456789abcdef0123456789abcdef",
		},
		{
			// The app secret key's kind is read by the pattern beside this one,
			// which is the boundary between them seen from this side.
			name: "an app secret key",
			src:  "shpss_0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ShopifyAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_ShopifyAccessToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "an environment assignment",
			src:  "SHOPIFY_ACCESS_TOKEN=shpat_0123456789abcdef0123456789abcdef",
			want: "SHOPIFY_ACCESS_TOKEN=**************************************",
		},
		{
			name: "the header the admin api reads",
			src:  "X-Shopify-Access-Token: shpat_0123456789abcdef0123456789abcdef",
			want: "X-Shopify-Access-Token: **************************************",
		},
		{
			name: "a json body",
			src:  `{"access_token":"shpat_0123456789abcdef0123456789abcdef","scope":"read_products"}`,
			want: `{"access_token":"**************************************","scope":"read_products"}`,
		},
		{
			name: "a command line",
			src:  "curl -H 'X-Shopify-Access-Token: shpat_0123456789abcdef0123456789abcdef' https://example.myshopify.com/admin/api/2026-07/shop.json",
			want: "curl -H 'X-Shopify-Access-Token: **************************************' https://example.myshopify.com/admin/api/2026-07/shop.json",
		},
	}

	m := New(WithPatterns(ShopifyAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ShopifyAccessToken_nextToWordCharacters(t *testing.T) {
	// What declining a word boundary in front of a value buys, which is the
	// shape a token reaches a log line in from a shell. A boundary would drop
	// the whole match rather than trim it here, leaving the token in the output
	// whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a token written straight against a name",
			src:  "TOKEN_shpat_0123456789abcdef0123456789abcdef",
			want: "TOKEN_**************************************",
		},
		{
			name: "a token written straight against a letter",
			src:  "xshpat_0123456789abcdef0123456789abcdef",
			want: "x**************************************",
		},
		{
			// A custom app token written straight against a name, driven the
			// same way the public app kind is above.
			name: "a custom app token written straight against a name",
			src:  "TOKEN_shpca_0123456789abcdef0123456789abcdef",
			want: "TOKEN_**************************************",
		},
		{
			// A body may close on a character of its own alphabet, so a
			// boundary behind the match would drop this one as well.
			name: "a token written straight in front of a letter of its own class",
			src:  "shpat_0123456789abcdef0123456789abcdef0",
			want: "**************************************0",
		},
	}

	m := New(WithPatterns(ShopifyAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ShopifyAccessToken_leavesWhatFollowsAlone(t *testing.T) {
	// The count is exact, so a token is redacted and the text behind it is not,
	// whatever that text is.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a full stop closing a sentence",
			src:  "the token is shpat_0123456789abcdef0123456789abcdef.",
			want: "the token is **************************************.",
		},
		{
			name: "a hyphen and a word",
			src:  "shpat_0123456789abcdef0123456789abcdef-suffix",
			want: "**************************************-suffix",
		},
		{
			name: "a quote and a comma",
			src:  `"shpat_0123456789abcdef0123456789abcdef",`,
			want: `"**************************************",`,
		},
		{
			// The uppercase half of "a letter past f", written straight
			// behind a complete body rather than inside one.
			name: "an uppercase letter past f written straight after a token",
			src:  "shpat_0123456789abcdef0123456789abcdefG",
			want: "**************************************G",
		},
		{
			// The header the admin API reads a private or delegate token
			// from, ending in a full stop — driven for shppa_ rather than
			// only for shpat_.
			name: "a private app token in the header, ended by a full stop",
			src:  "X-Shopify-Access-Token: shppa_0123456789abcdef0123456789abcdef.",
			want: "X-Shopify-Access-Token: **************************************.",
		},
	}

	m := New(WithPatterns(ShopifyAccessToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

// Test_ShopifyAccessToken_retain holds the second return of Find to a literal
// offset, on the two shapes builtin_scan.go names: a piece of a prefix
// standing at the end of the input, and a candidate the end of the input cut
// short of the count.
func Test_ShopifyAccessToken_retain(t *testing.T) {
	tests := []struct {
		name       string
		src        string
		wantRetain int
	}{
		{
			// The last five characters are "shpat", a piece of the
			// six-character prefix "shpat_" cut short by the end of the
			// input.
			name:       "a piece of a prefix standing at the end of the input",
			src:        "key shpat",
			wantRetain: 4,
		},
		{
			// A whole prefix with a body behind it too short to reach the
			// count, standing at the end of the input. More characters
			// arriving could still complete the token, so the candidate is
			// unsettled from its own start.
			name:       "a candidate the end of the input cut short of the count",
			src:        "shpat_0123456789abcdef01234",
			wantRetain: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retain := ShopifyAccessToken().Find(tt.src)
			if len(got) != 0 {
				t.Fatalf("Find(%q) located %v, want no span", tt.src, got)
			}
			if retain != tt.wantRetain {
				t.Errorf("Find(%q) retain = %d, want %d", tt.src, retain, tt.wantRetain)
			}
		})
	}
}

// Test_ShopifyAccessToken_noTokenBeginsInsideAnother drives the claim
// builtin_shopify_access_token.go makes about what advancing rather than
// consuming the match finds here, which is nothing: the opening is three
// letters and none of them is a hexadecimal digit, so no part of it can fall
// inside a body, and no prefix carries the opening again past its first
// character, so no opening begins inside a prefix either.
//
// The claim is about every credential this package reads for Shopify rather
// than about this pattern's three, so the app secret key's prefix is walked
// here too. It has to be: shpss_ is the one prefix carrying a letter of the
// opening again, and a guard reading this pattern's table alone would leave the
// sentence resting on the prefix it never looked at.
//
// The claim is stated rather than used — the scan takes the default step of one
// byte whatever the answer — so what this test guards is the sentence, which
// would otherwise go stale the day a kind is added whose prefix breaks it.
func Test_ShopifyAccessToken_noTokenBeginsInsideAnother(t *testing.T) {
	for _, prefix := range append(slices.Clone(shopifyAccessTokenPrefixes), shopifyAppSecretKeyPrefix) {
		for i := 1; i < len(prefix); i++ {
			if strings.HasPrefix(prefix[i:], shopifyCredentialOpening) {
				t.Errorf("the prefix %q carries the opening again at %d, so a token can begin inside another prefix", prefix, i)
			}
		}
	}
	for i := range len(shopifyCredentialOpening) {
		if c := shopifyCredentialOpening[i]; isShopifyCredentialBodyByte(c) {
			t.Errorf("the opening %q carries %q at %d, which a body is written with", shopifyCredentialOpening, c, i)
		}
	}

	// And the shape that would carry it if any of the above were false: two
	// whole tokens with nothing between them are two spans that do not overlap.
	src := "shpat_0123456789abcdef0123456789abcdefshppa_0123456789abcdef0123456789abcdef"
	want := []Span{{0, 38}, {38, 76}}
	if got, _ := ShopifyAccessToken().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}
}

func Test_ShopifyAccessToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_shopify_access_token.go weighs and pays for: an MD5
	// is thirty-two hexadecimal characters exactly, which is a body exactly, so
	// a prefix and an MD5 is a token to this scan. A scan declining it would
	// decline every token Shopify issues. A longer digest behind the prefix is
	// not turned away by the count either — the count decides where the span
	// ends, so the first thirty-two characters of it go and the rest stays. It
	// is the prefix that turns away a bare digest, and the last two cases are
	// what that leaves.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an md5 behind the prefix is redacted",
			src:  "shpat_0123456789abcdef0123456789abcdef",
			want: []Span{{0, 38}},
		},
		{
			name: "a sha-1 behind the prefix is read to the count and no further",
			src:  "shpat_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 38}},
		},
		{
			name: "a sha-256 behind the prefix is read to the count as well",
			src:  "shpat_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 38}},
		},
		{
			name: "a bare md5 with no prefix in front of it",
			src:  "0123456789abcdef0123456789abcdef",
			want: nil,
		},
		{
			name: "a bare md5 in an assignment",
			src:  "ETAG=0123456789abcdef0123456789abcdef",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ShopifyAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ShopifyAccessToken_theTokenFormatItReplaced(t *testing.T) {
	// The token Shopify issued before the prefixes arrived, which its changelog
	// describes as the thirty-two character form existing tokens go on working
	// in. That is a bare digest's shape, and reading it would redact every MD5
	// and every short hexadecimal identifier a caller passes through, so it is
	// left in the output whole. builtin_shopify_access_token.go argues the
	// decision; these are the shapes it gives up.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the token that came before, on its own",
			src:  "0123456789abcdef0123456789abcdef",
		},
		{
			name: "the token that came before, in an environment assignment",
			src:  "SHOPIFY_ACCESS_TOKEN=0123456789abcdef0123456789abcdef",
		},
		{
			name: "the token that came before, in the header the admin api reads",
			src:  "X-Shopify-Access-Token: 0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ShopifyAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_ShopifyAccessToken_aKindShopifyNamesNoPrefixFor(t *testing.T) {
	// Shopify's community forums name shpua_ as a prefix belonging to apps of
	// some other description, and Shopify itself documents no such credential:
	// neither changelog names it and no published ruleset reads one. So it is
	// not read, and reading it would be one entry added to
	// shopifyAccessTokenKinds. These are the shapes that stays a decision
	// rather than an oversight.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the kind the forums name",
			src:  "shpua_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a kind written in the body's own class",
			src:  "shpab_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a kind nothing suggests",
			src:  "shpxy_0123456789abcdef0123456789abcdef",
		},
		{
			name: "one character where two name the kind",
			src:  "shpa_0123456789abcdef0123456789abcdef0",
		},
		{
			name: "three characters where two name the kind",
			src:  "shpatx_0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ShopifyAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_ShopifyAccessToken_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor, and what holds it linear is the count being a
	// count: a candidate reads at most thirty-eight bytes and stops. These are
	// the inputs that would find it wrong here — a line that is nothing but
	// prefixes, a line that is nothing but tokens, and a single hexadecimal run
	// as long as the line, which is where a scan reading a run instead of a
	// count would show itself.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// whole body apiece and so hold a candidate every thirty-eight bytes at
	// their densest. The crowding a line can actually carry, a candidate every
	// six, stays here.
	sources := map[string]string{
		// A candidate every six characters, each turned away at the first
		// character of its body, which is the s the next opening carries and no
		// character a body is written with.
		"a candidate every six characters": strings.Repeat("shpat_", 300000),
		// The kind whose prefix carries the anchor twice, so the search stops
		// at twice as many positions as the line above opens candidates.
		"the kind carrying the anchor twice": strings.Repeat("shppa_", 300000),
		// The same crowding with a whole token at each candidate, so every one
		// of them reads thirty-two characters and reports a span.
		"a token every thirty-eight characters": strings.Repeat("shpat_0123456789abcdef0123456789abcdef", 30000),
		// A candidate walked to its last character before the body's class
		// turns it away, which is the most a rejected candidate can cost.
		"a candidate walked to its last character": strings.Repeat("shpat_0123456789abcdef0123456789abcdeg ", 30000),
		// One candidate whose body is the whole line. The count stops it at
		// thirty-two characters; a scan reading the run would read two
		// mebibytes.
		"a hexadecimal run the length of the line": "shpat_" + strings.Repeat("a", 2000000),
		// The same run with no prefix in front of it, so no candidate is found
		// in it at all.
		"a hexadecimal run with no prefix": strings.Repeat("a", 2000000),
	}

	checkScanIsLinear(t, ShopifyAccessToken(), sources)
}

// Test_shopifyCredentialOpening holds what both Shopify scans need of the
// opening and the separator they share, which nothing else here reports: an
// opening nothing locates simply locates nothing, and the cases above would go
// on passing for the opening that still works.
//
// Every character of the opening is asked the same question, because it is the
// whole opening rather than one character of it that caps how far a credential
// reaches into another: none of them may be written in a body, which is what
// leaves no position at all for a second credential to begin at.
// Test_ShopifyAccessToken_noTokenBeginsInsideAnother drives the consequence.
func Test_shopifyCredentialOpening(t *testing.T) {
	if len(shopifyCredentialOpening) == 0 {
		t.Fatal("the opening is empty, so it bounds nothing")
	}
	for i := range len(shopifyCredentialOpening) {
		if c := shopifyCredentialOpening[i]; isShopifyCredentialBodyByte(c) {
			t.Errorf("the opening %q carries %q at %d, which a body is written with", shopifyCredentialOpening, c, i)
		}
	}

	// And what the separator needs to be: a character no body holds, so that a
	// run of the body's alphabet can never hold a prefix. That is not what
	// bounds either scan, but it is what a count relaxed to a floor would fall
	// back on.
	if isShopifyCredentialBodyByte(shopifyCredentialSeparator) {
		t.Errorf("the separator %q is a character a body is written with", byte(shopifyCredentialSeparator))
	}
}

// Test_shopifyAccessTokenAnchor holds every prefix the scan can match to
// carrying the byte the scan searches the input for at the index it reads a
// candidate back from. builtin_scan.go says why that is held here rather than
// left to the targets: a kind added to shopifyAccessTokenKinds whose prefix
// carried the anchor somewhere else would be located nowhere, and nothing that
// was passing would stop passing.
func Test_shopifyAccessTokenAnchor(t *testing.T) {
	if len(shopifyAccessTokenPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for _, p := range shopifyAccessTokenPrefixes {
		if shopifyCredentialAnchorIndex >= len(p) {
			t.Errorf("the anchor stands at %d, the prefix %q is %d characters", shopifyCredentialAnchorIndex, p, len(p))
			continue
		}
		if c := p[shopifyCredentialAnchorIndex]; c != shopifyCredentialAnchor {
			t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", p, c, byte(shopifyCredentialAnchor))
		}
	}
}

// Test_shopifyCredentialChars holds the arithmetic to the two numbers Shopify's
// changelogs state: the thirty-eight characters a credential grew to, and the
// six a prefix comes to, whose difference is the body.
//
// What it holds is the documentation rather than the scans. Neither scan ever
// states a whole credential: each reads the body from where its prefix ends, so
// a prefix of another length would be located correctly and nothing would go
// wrong. What would go wrong is the sentence on ShopifyAccessToken and
// ShopifyAppSecretKey promising thirty-eight characters, and the spans every
// case in this file and the one beside it is written with.
func Test_shopifyCredentialChars(t *testing.T) {
	const (
		documentedPrefixChars = 6
		documentedChars       = 38
	)

	if shopifyCredentialPrefixChars != documentedPrefixChars {
		t.Errorf("a prefix is read as %d characters, the documentation promises %d", shopifyCredentialPrefixChars, documentedPrefixChars)
	}
	if shopifyCredentialChars != documentedChars {
		t.Errorf("a credential is read as %d characters, the documentation promises %d", shopifyCredentialChars, documentedChars)
	}
	for _, p := range append(slices.Clone(shopifyAccessTokenPrefixes), shopifyAppSecretKeyPrefix) {
		if len(p) != documentedPrefixChars {
			t.Errorf("the prefix %q is %d characters, the documentation promises %d", p, len(p), documentedPrefixChars)
		}
	}
}

// referenceShopifyAccessToken is the expression the scan in
// builtin_shopify_access_token.go reads by hand: the statement of what a
// Shopify access token is, kept here so that the scan can be held to it.
//
// The opening, the three kinds, the separator, the count and the character
// class are spelled again rather than built from the declarations beside the
// scan. A reference sharing those could not disagree with the scan about them,
// and it is exactly that disagreement the fuzz target below is for: the two
// have to be changed together or reported apart.
//
// The repetition is exact, so the machine an engine builds for a candidate is
// thirty-two states wide and is read once, where a floor spelled as a counted
// repetition would cost a machine as wide as the floor at every candidate. What
// an engine searches the text for is the three character literal the expression
// opens with, and none of those characters is written in a body — so a run of
// the body's alphabet, which is where candidates would otherwise crowd, holds no
// position for the engine to walk its machine at.
var referenceShopifyAccessToken = regexp.MustCompile(`shp(?:at|ca|pa)_[0-9a-fA-F]{32}`)

// referenceShopifyAccessTokenFind locates tokens the plain way: the leftmost
// match of the expression above, then the leftmost one beginning after that
// match's first byte, over and over, with nothing remembered between them.
//
// Asking at every byte is what the scan does too, and it is not written here to
// restate that. A reference is written to know nothing its scan claims, and
// where a token may begin is one of the things the scan claims — so this one
// starts afresh a byte along whether or not a token can be written inside
// another, and the fuzz target below is what holds the two to the same answer.
func referenceShopifyAccessTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceShopifyAccessToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzShopifyAccessToken_matchesReference guards the hand-written scan: the byte
// it searches for, the opening and the kinds it reads back from that byte, the
// separator behind them, the count it reads and the character class it reads it
// in may none of them change which tokens are located.
func FuzzShopifyAccessToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("SHOPIFY_ACCESS_TOKEN=shpat_0123456789abcdef0123456789abcdef")
	f.Add("shpca_0123456789abcdef0123456789abcdef")       // the custom app kind
	f.Add("shppa_0123456789abcdef0123456789abcdef")       // and the one carrying the anchor twice
	f.Add("shpua_0123456789abcdef0123456789abcdef")       // a kind with no prefix published
	f.Add("shpss_0123456789abcdef0123456789abcdef")       // the app secret key, which this pattern does not read
	f.Add("shpat_0123456789abcdef0123456789abcde")        // a body one short
	f.Add("shpat_0123456789abcdef0123456789abcdef0")      // and a run longer than one
	f.Add("shpat_0123456789ABCDEF0123456789ABCDEF")       // an uppercase body
	f.Add("shpat_0123456789abcdef0123456789ABCDEF")       // and one written in both cases
	f.Add("SHPAT_0123456789abcdef0123456789abcdef")       // an uppercase prefix
	f.Add("shpat_0123456789abcdefg123456789abcdef")       // a letter past f
	f.Add("shpat_0123456789abcdef-123456789abcdef")       // a hyphen inside the body
	f.Add("shpat_0123456789abcdef_123456789abcdef")       // and an underscore
	f.Add("shpat_0123456789abcdef\n123456789abcdef")      // a token a line break breaks
	f.Add("shpat-0123456789abcdef0123456789abcdef")       // a hyphen where the separator stands
	f.Add("shpat0123456789abcdef0123456789abcdef0")       // the separator missing
	f.Add("shpa_0123456789abcdef0123456789abcdef0")       // one character naming the kind
	f.Add("shpatx_0123456789abcdef0123456789abcdef")      // three of them
	f.Add("xxxxx_0123456789abcdef0123456789abcdef")       // the right shape with no prefix
	f.Add("xshpat_0123456789abcdef0123456789abcdef")      // written against a letter
	f.Add("store_shpat_0123456789abcdef0123456789abcdef") // and against a name
	f.Add("0123456789abcdef0123456789abcdef")             // the format this one replaced
	f.Add("shpat_shpat_0123456789abcdef0123456789abcdef") // a prefix where a body could hold one
	f.Add("shp_shpat_0123456789abcdef0123456789abcdef")   // the opening with no kind behind it
	// Two tokens with nothing between them, which is what advancing rather than
	// consuming the match has to keep apart.
	f.Add("shpat_0123456789abcdef0123456789abcdefshppa_0123456789abcdef0123456789abcdef")

	fuzzAgainstReference(f, ShopifyAccessToken().Find, referenceShopifyAccessTokenFind)
}

// shopifyAccessTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func shopifyAccessTokenFindBenchmarks() []benchmarkCase {
	// The line carries the byte the scan searches for six times — in the word
	// api of the message, in the scheme, twice in the shop's own host name, in
	// the api segment of the path and in the file it ends on — and none of them
	// opens a candidate. What it times is that search and the reads that turn
	// those positions away, which is what this pattern costs a caller whose text
	// holds no token. A Shopify caller's log is where this byte is at its
	// densest, so the line is written as one of those rather than as prose:
	// shop, shopify and http each carry one, where prose carries a p in about
	// two characters in a hundred.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling admin api" url=https://example.myshopify.com/admin/api/2026-07/shop.json `
	token := "shpat_0123456789abcdef0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix written over and over, so a candidate stands at every
			// sixth byte and every one of them is turned away at the first
			// character of its body, which is the s of the next opening. That
			// is the cheapest this scan declines a candidate whose prefix is
			// whole.
			name:  "candidates that are not values",
			src:   strings.Repeat("shpat_", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: thirty-one characters of the
			// body walked before its last one turns the candidate away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("shpat_0123456789abcdef0123456789abcdeg ", 16),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + token,
			spans: 1,
		},
		{
			// Every kind at once, so the walk that reads the kinds is driven
			// over all of them rather than over the first it compares.
			name:  "many values",
			src:   strings.Repeat(token+" shpca_0123456789abcdef0123456789abcdef shppa_0123456789abcdef0123456789abcdef ", 16),
			spans: 48,
		},
	}
}
