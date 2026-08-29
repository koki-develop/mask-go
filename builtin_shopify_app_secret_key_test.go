package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The Shopify app secret key pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares is held to in builtins_test.go, and what this
// credential shares with the access token beside it — the opening, the
// separator, the counts and the alphabet — is held to in
// builtin_shopify_access_token_test.go, where those declarations live.
//
// The keys written out below are made only of ordered characters: valid in
// shape, obviously not real. A body is thirty-two hexadecimal characters,
// written here as 0123456789abcdef twice over, and with a six character prefix
// in front of it that comes to thirty-eight.

func Test_ShopifyAppSecretKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an app secret key",
			src:  "shpss_0123456789abcdef0123456789abcdef",
			want: []Span{{0, 38}},
		},
		{
			name: "an app secret key in an environment assignment",
			src:  "SHOPIFY_API_SECRET=shpss_0123456789abcdef0123456789abcdef",
			want: []Span{{19, 57}},
		},
		{
			// The rulesets read this class without regard to case, and
			// trufflehog's own cases carry a body written wholly in uppercase
			// beside one written wholly in lowercase.
			name: "a body written in uppercase",
			src:  "shpss_0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 38}},
		},
		{
			name: "a body written in both cases at once",
			src:  "shpss_0123456789abcdef0123456789ABCDEF",
			want: []Span{{0, 38}},
		},
		{
			// The count is read exactly, so what follows the thirty-eighth
			// character is not part of the key and stays in the text.
			name: "a run longer than the count is a key and what follows it",
			src:  "shpss_0123456789abcdef0123456789abcdef0",
			want: []Span{{0, 38}},
		},
		{
			name: "two keys with nothing between them",
			src:  "shpss_0123456789abcdef0123456789abcdefshpss_0123456789abcdef0123456789abcdef",
			want: []Span{{0, 38}, {38, 76}},
		},
		{
			// A candidate whose body would open with the prefix again. The
			// outer one is turned away at the first character of its body,
			// which is the s of the inner opening and no character a body is
			// written with; the inner key is found where it stands.
			name: "a candidate whose body opens with the prefix",
			src:  "shpss_shpss_0123456789abcdef0123456789abcdef",
			want: []Span{{6, 44}},
		},
		{
			name: "a snake_case name closing on the prefix",
			src:  "app_shpss_0123456789abcdef0123456789abcdef",
			want: []Span{{4, 42}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ShopifyAppSecretKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ShopifyAppSecretKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prose",
			src:  "the app secret should be stored outside the repository",
		},
		{
			name: "a body one character short",
			src:  "shpss_0123456789abcdef0123456789abcde",
		},
		{
			name: "a letter past f in the body",
			src:  "shpss_0123456789abcdefg123456789abcdef",
		},
		{
			name: "a hyphen inside the body",
			src:  "shpss_0123456789abcdef-123456789abcdef",
		},
		{
			name: "an underscore inside the body",
			src:  "shpss_0123456789abcdef_123456789abcdef",
		},
		{
			name: "a line break inside the body",
			src:  "shpss_0123456789abcdef\n123456789abcdef",
		},
		{
			name: "an uppercase prefix",
			src:  "SHPSS_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a hyphen where the separator stands",
			src:  "shpss-0123456789abcdef0123456789abcdef",
		},
		{
			name: "the separator missing altogether",
			src:  "shpss0123456789abcdef0123456789abcdef0",
		},
		{
			// The access token's kinds are read by the pattern beside this one,
			// so this scan reports nothing for any of them.
			name: "a public app access token",
			src:  "shpat_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a custom app access token",
			src:  "shpca_0123456789abcdef0123456789abcdef",
		},
		{
			name: "a private app and delegate access token",
			src:  "shppa_0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ShopifyAppSecretKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_ShopifyAppSecretKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "the environment variable shopify's own libraries read",
			src:  "SHOPIFY_API_SECRET=shpss_0123456789abcdef0123456789abcdef",
			want: "SHOPIFY_API_SECRET=**************************************",
		},
		{
			name: "a yaml assignment",
			src:  "client_secret: shpss_0123456789abcdef0123456789abcdef",
			want: "client_secret: **************************************",
		},
		{
			name: "a json body",
			src:  `{"client_id":"0123456789abcdef","client_secret":"shpss_0123456789abcdef0123456789abcdef"}`,
			want: `{"client_id":"0123456789abcdef","client_secret":"**************************************"}`,
		},
		{
			name: "a command line",
			src:  "shopify app env show --client-secret shpss_0123456789abcdef0123456789abcdef",
			want: "shopify app env show --client-secret **************************************",
		},
	}

	m := New(WithPatterns(ShopifyAppSecretKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ShopifyAppSecretKey_nextToWordCharacters(t *testing.T) {
	// What declining a word boundary in front of a value buys, which is the
	// shape a key reaches a log line in from a shell. A boundary would drop the
	// whole match rather than trim it here, leaving the key in the output whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a key written straight against a name",
			src:  "SECRET_shpss_0123456789abcdef0123456789abcdef",
			want: "SECRET_**************************************",
		},
		{
			name: "a key written straight against a letter",
			src:  "xshpss_0123456789abcdef0123456789abcdef",
			want: "x**************************************",
		},
		{
			name: "a key written straight in front of a letter of its own class",
			src:  "shpss_0123456789abcdef0123456789abcdef0",
			want: "**************************************0",
		},
	}

	m := New(WithPatterns(ShopifyAppSecretKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ShopifyAppSecretKey_leavesWhatFollowsAlone(t *testing.T) {
	// The count is exact, so a key is redacted and the text behind it is not,
	// whatever that text is.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a full stop closing a sentence",
			src:  "the secret is shpss_0123456789abcdef0123456789abcdef.",
			want: "the secret is **************************************.",
		},
		{
			name: "a hyphen and a word",
			src:  "shpss_0123456789abcdef0123456789abcdef-suffix",
			want: "**************************************-suffix",
		},
		{
			name: "a quote and a comma",
			src:  `"shpss_0123456789abcdef0123456789abcdef",`,
			want: `"**************************************",`,
		},
	}

	m := New(WithPatterns(ShopifyAppSecretKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ShopifyAppSecretKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_shopify_access_token.go weighs for both Shopify
	// credentials and this one pays for on the same terms: an MD5 is thirty-two
	// hexadecimal characters exactly, which is a body exactly. A longer digest
	// behind the prefix is not turned away by the count either — the count
	// decides where the span ends, so the first thirty-two characters of it go
	// and the rest stays. It is the prefix that turns away a bare digest.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an md5 behind the prefix is redacted",
			src:  "shpss_0123456789abcdef0123456789abcdef",
			want: []Span{{0, 38}},
		},
		{
			name: "a sha-256 behind the prefix is read to the count and no further",
			src:  "shpss_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 38}},
		},
		{
			name: "a bare md5 with no prefix in front of it",
			src:  "0123456789abcdef0123456789abcdef",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ShopifyAppSecretKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_ShopifyAppSecretKey_theKeyFormatItReplaced(t *testing.T) {
	// The secret Shopify issued before the prefix arrived, which its changelog
	// describes as the thirty-two character form existing secrets go on working
	// in until a partner regenerates them. That is a bare digest's shape, and
	// reading it would redact every MD5 and every short hexadecimal identifier
	// a caller passes through, so it is left in the output whole.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the secret that came before, on its own",
			src:  "0123456789abcdef0123456789abcdef",
		},
		{
			name: "the secret that came before, in an environment assignment",
			src:  "SHOPIFY_API_SECRET=0123456789abcdef0123456789abcdef",
		},
		{
			// The client id standing beside it is the same shape and is no
			// secret at all, which is the other half of why this is declined.
			name: "the client id written beside it",
			src:  "SHOPIFY_API_KEY=0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ShopifyAppSecretKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_ShopifyAppSecretKey_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor, and what holds it linear is the count being a
	// count: a candidate reads at most thirty-eight bytes and stops. These are
	// the inputs that would find it wrong here.
	sources := map[string]string{
		// A candidate every six characters, each turned away at the first
		// character of its body, which is the s the next opening carries and no
		// character a body is written with.
		"a candidate every six characters": strings.Repeat("shpss_", 300000),
		// The same crowding with a whole key at each candidate, so every one of
		// them reads thirty-two characters and reports a span.
		"a key every thirty-eight characters": strings.Repeat("shpss_0123456789abcdef0123456789abcdef", 30000),
		// A candidate walked to its last character before the body's class
		// turns it away, which is the most a rejected candidate can cost.
		"a candidate walked to its last character": strings.Repeat("shpss_0123456789abcdef0123456789abcdeg ", 30000),
		// One candidate whose body is the whole line. The count stops it at
		// thirty-two characters; a scan reading the run would read two
		// mebibytes.
		"a hexadecimal run the length of the line": "shpss_" + strings.Repeat("a", 2000000),
		// The same run with no prefix in front of it, so no candidate is found
		// in it at all.
		"a hexadecimal run with no prefix": strings.Repeat("a", 2000000),
	}

	m := New(WithPatterns(ShopifyAppSecretKey()))
	for name, src := range sources {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_ = m.Mask(src)
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("Mask() of %d bytes took %v", len(src), d)
			}
		})
	}
}

// Test_shopifyAppSecretKeyAnchor holds the prefix the scan can match to carrying
// the byte the scan searches the input for at the index it reads a candidate
// back from, for the reason Test_shopifyAccessTokenAnchor gives: a prefix and an
// index that have come apart locate nothing, and nothing that was passing would
// stop passing.
func Test_shopifyAppSecretKeyAnchor(t *testing.T) {
	if shopifyCredentialAnchorIndex >= len(shopifyAppSecretKeyPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix %q is %d characters", shopifyCredentialAnchorIndex, shopifyAppSecretKeyPrefix, len(shopifyAppSecretKeyPrefix))
	}
	if c := shopifyAppSecretKeyPrefix[shopifyCredentialAnchorIndex]; c != shopifyCredentialAnchor {
		t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", shopifyAppSecretKeyPrefix, c, byte(shopifyCredentialAnchor))
	}
}

// Test_shopifyAppSecretKeyKind holds this credential's kind apart from every
// kind the access token beside it reads. The two patterns share an opening, a
// separator, a count and an alphabet, so the kind is the whole of what tells a
// key from a token — and a kind that drifted into the other table would leave
// one value located by two patterns and the boundary between them saying
// nothing.
func Test_shopifyAppSecretKeyKind(t *testing.T) {
	if len(shopifyAppSecretKeyKind) != shopifyCredentialKindChars {
		t.Errorf("the kind %q is %d characters, a prefix names the kind in %d", shopifyAppSecretKeyKind, len(shopifyAppSecretKeyKind), shopifyCredentialKindChars)
	}
	if slices.Contains(shopifyAccessTokenKinds, shopifyAppSecretKeyKind) {
		t.Errorf("the kind %q is read by the access token as well, so one value is located by both patterns", shopifyAppSecretKeyKind)
	}
}

// referenceShopifyAppSecretKey is the expression the scan in
// builtin_shopify_app_secret_key.go reads by hand: the statement of what a
// Shopify app secret key is, kept here so that the scan can be held to it.
//
// The whole prefix, the count and the character class are spelled again rather
// than built from the declarations beside the scan — including the opening and
// the separator that scan borrows from the access token's file, since a
// reference sharing a declaration with the scan it checks could not disagree
// with it and the target below would compare a rule with itself.
var referenceShopifyAppSecretKey = regexp.MustCompile(`shpss_[0-9a-fA-F]{32}`)

// referenceShopifyAppSecretKeyFind locates keys the plain way: the leftmost
// match of the expression above, then the leftmost one beginning after that
// match's first byte, over and over, with nothing remembered between them.
//
// Asking at every byte is what the scan does too, and it is not written here to
// restate that: a reference is written to know nothing its scan claims, and
// where a key may begin is one of the things the scan claims.
func referenceShopifyAppSecretKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceShopifyAppSecretKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzShopifyAppSecretKey_matchesReference guards the hand-written scan: the
// byte it searches for, the prefix it reads back from that byte, the count it
// reads and the character class it reads it in may none of them change which
// keys are located.
func FuzzShopifyAppSecretKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("SHOPIFY_API_SECRET=shpss_0123456789abcdef0123456789abcdef")
	f.Add("shpss_0123456789abcdef0123456789abcde")        // a body one short
	f.Add("shpss_0123456789abcdef0123456789abcdef0")      // and a run longer than one
	f.Add("shpss_0123456789ABCDEF0123456789ABCDEF")       // an uppercase body
	f.Add("shpss_0123456789abcdef0123456789ABCDEF")       // and one written in both cases
	f.Add("SHPSS_0123456789abcdef0123456789abcdef")       // an uppercase prefix
	f.Add("shpss_0123456789abcdefg123456789abcdef")       // a letter past f
	f.Add("shpss_0123456789abcdef-123456789abcdef")       // a hyphen inside the body
	f.Add("shpss_0123456789abcdef_123456789abcdef")       // and an underscore
	f.Add("shpss_0123456789abcdef\n123456789abcdef")      // a key a line break breaks
	f.Add("shpss-0123456789abcdef0123456789abcdef")       // a hyphen where the separator stands
	f.Add("shpss0123456789abcdef0123456789abcdef0")       // the separator missing
	f.Add("shpat_0123456789abcdef0123456789abcdef")       // the access token, which this pattern does not read
	f.Add("shpsa_0123456789abcdef0123456789abcdef")       // a kind one character away from this one
	f.Add("xxxxx_0123456789abcdef0123456789abcdef")       // the right shape with no prefix
	f.Add("xshpss_0123456789abcdef0123456789abcdef")      // written against a letter
	f.Add("app_shpss_0123456789abcdef0123456789abcdef")   // and against a name
	f.Add("0123456789abcdef0123456789abcdef")             // the format this one replaced
	f.Add("shpss_shpss_0123456789abcdef0123456789abcdef") // a prefix where a body could hold one
	// Two keys with nothing between them, which is what advancing rather than
	// consuming the match has to keep apart.
	f.Add("shpss_0123456789abcdef0123456789abcdefshpss_0123456789abcdef0123456789abcdef")

	fuzzAgainstReference(f, ShopifyAppSecretKey().Find, referenceShopifyAppSecretKeyFind)
}

// shopifyAppSecretKeyFindBenchmarks is what this scan is timed on, read by
// BenchmarkBuiltins through the pattern's builtinPatterns entry.
func shopifyAppSecretKeyFindBenchmarks() []benchmarkCase {
	// The same line the access token is timed on, which is where the byte both
	// scans search for is at its densest in a caller's text.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling admin api" url=https://example.myshopify.com/admin/api/2026-07/shop.json `
	key := "shpss_0123456789abcdef0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix written over and over, so a candidate stands at every
			// sixth byte and every one of them is turned away at the first
			// character of its body, which is the s of the next opening.
			name:  "candidates that are not values",
			src:   strings.Repeat("shpss_", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: thirty-one characters of the
			// body walked before its last one turns the candidate away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("shpss_0123456789abcdef0123456789abcdeg ", 16),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + key,
			spans: 1,
		},
		{
			// The access token's prefixes stand between the keys, so the walk
			// is driven over the candidates this scan rejects on the kind
			// rather than on the body.
			name:  "many values",
			src:   strings.Repeat(key+" shpat_0123456789abcdef0123456789abcdef ", 16),
			spans: 16,
		},
	}
}
