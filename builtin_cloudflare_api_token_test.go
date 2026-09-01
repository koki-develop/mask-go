package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Cloudflare API token pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. The body is 0123456789abcdef written three times,
// which is the forty characters of the secret and the eight of the checksum the
// pattern reads them at, and with a prefix in front of it that is fifty-three
// characters. Where the case is what a case is about the same run is written in
// uppercase, since the secret is base62 and the checksum hexadecimal and both
// hold the letters of either case.

func Test_CloudflareAPIToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token a user owns",
			src:  "cfut_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 53}},
		},
		{
			name: "a token an account owns",
			src:  "cfat_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 53}},
		},
		{
			name: "a token in an environment assignment",
			src:  "CLOUDFLARE_API_TOKEN=cfut_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{21, 74}},
		},
		{
			// The secret is base62 and the checksum hexadecimal, and both are
			// read in either case for the reason
			// builtin_cloudflare_api_token.go gives.
			name: "an uppercase body",
			src:  "cfut_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 53}},
		},
		{
			// The secret's alphabet is the letters and digits, so it runs past
			// f where the eight characters behind it may not.
			name: "a secret carrying letters past f",
			src:  "cfut_0123456789abcdefghijklmnopqrstuvwxyzABCD0123abcd",
			want: []Span{{0, 53}},
		},
		{
			// The counts are read exactly, so what follows the fifty-third
			// character is not part of the token and stays in the text.
			name: "a body run longer than the counts is a token and what follows it",
			src:  "cfut_0123456789abcdef0123456789abcdef0123456789abcdef0",
			want: []Span{{0, 53}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "cfut_0123456789abcdef0123456789abcdef0123456789abcdefcfat_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 53}, {53, 106}},
		},
		{
			// A candidate whose body opens with a prefix of its own. The outer
			// one is turned away at the fifth character of its body, which is
			// the underscore the inner prefix closes with and no character a
			// secret is written with; the inner token is found where it stands.
			name: "a candidate whose body opens with a prefix",
			src:  "cfut_cfut_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{5, 58}},
		},
		{
			// The one shape a word boundary in front would turn away. No word
			// is spelled cfut, so what can reach a prefix is a snake_case name
			// whose last segment is one — which the tightening on offer admits
			// anyway, since it admits the underscore.
			name: "a snake_case name closing on the prefix",
			src:  "zone_cfut_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{5, 58}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CloudflareAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CloudflareAPIToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "cfut_",
		},
		{
			name: "a body one character short",
			src:  "cfut_0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// Forty-seven characters of the body reached and the last one a
			// letter past f, which is the count met with the checksum's class
			// failing at its final character.
			name: "a letter past f at the end of the checksum",
			src:  "cfut_0123456789abcdef0123456789abcdef0123456789abcdeg",
		},
		{
			name: "an uppercase letter past F at the end of the checksum",
			src:  "cfut_0123456789abcdef0123456789abcdef0123456789abcdeG",
		},
		{
			// The eight characters behind the secret are hexadecimal, so a
			// letter past f may stand in the first forty and nowhere later.
			name: "a letter past f at the start of the checksum",
			src:  "cfut_0123456789abcdef0123456789abcdef01234567gabcdef0",
		},
		{
			// Neither character base64url adds beyond the letters and digits
			// may stand in a body, however the older format was written.
			name: "a hyphen inside the secret",
			src:  "cfut_0123456789abcdef-123456789abcdef0123456789abcdef",
		},
		{
			name: "an underscore inside the secret",
			src:  "cfut_0123456789abcdef_123456789abcdef0123456789abcdef",
		},
		{
			name: "a token broken by a space",
			src:  "cfut_0123456789abcdef0123456789 abcdef0123456789abcdef",
		},
		{
			name: "a token broken by a line break",
			src:  "cfut_0123456789abcdef0123456789\nabcdef0123456789abcdef",
		},
		{
			name: "an uppercase prefix",
			src:  "CFUT_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The credential Cloudflare names a key rather than a token, which
			// this pattern is named for not locating and CloudflareAPIKey
			// locates instead.
			name: "the api key prefix",
			src:  "cfk_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The two letters a candidate is read back to with neither kind
			// behind them.
			name: "the opening with no kind behind it",
			src:  "cfxt_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "the kind with no t behind it",
			src:  "cfu_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a hyphen where the prefix carries its underscore",
			src:  "cfut-0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// A body of the right counts and the right classes behind
			// something else. The prefix is the whole of the anchor.
			name: "a value of the right shape opening with no prefix",
			src:  "xxxx_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The unprefixed format Cloudflare issued until the tokens grew
			// one: forty characters with nothing in front of them, which is a
			// grammar this pattern reads nowhere whatever alphabet it is
			// written in.
			name: "a token of the format issued before the prefixes",
			src:  "CLOUDFLARE_API_TOKEN=0123456789abcdef0123456789abcdef0123-_ab",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// A prefix has to be written whole, and cf on its own is written
			// in prose as an abbreviation.
			name: "the opening as it is written in prose",
			src:  "cf. the token format page for what a token is",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CloudflareAPIToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_CloudflareAPIToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "CLOUDFLARE_API_TOKEN=cfut_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "CLOUDFLARE_API_TOKEN=*****************************************************",
		},
		{
			// How a token reaches the API, and how it reaches a log line that
			// echoed the header.
			name: "a bearer token header",
			src:  "Authorization: Bearer cfut_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "Authorization: Bearer *****************************************************",
		},
		{
			// The response a token is first read out of, which is the one
			// place its value is ever shown.
			name: "the response that first reports it",
			src:  `{"result":{"id":"0123456789abcdef0123456789abcdef","value":"cfat_0123456789abcdef0123456789abcdef0123456789abcdef"}}`,
			want: `{"result":{"id":"0123456789abcdef0123456789abcdef","value":"*****************************************************"}}`,
		},
		{
			name: "a command line",
			src:  "curl -H 'Authorization: Bearer cfut_0123456789abcdef0123456789abcdef0123456789abcdef' https://api.cloudflare.com/client/v4/user/tokens/verify",
			want: "curl -H 'Authorization: Bearer *****************************************************' https://api.cloudflare.com/client/v4/user/tokens/verify",
		},
		{
			name: "both kinds at once",
			src:  "cfut_0123456789abcdef0123456789abcdef0123456789abcdef cfat_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: "***************************************************** *****************************************************",
		},
	}

	m := New(WithPatterns(CloudflareAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CloudflareAPIToken_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the token through whole. The first two are what
	// the demand would cost.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "xcfut_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "x*****************************************************",
		},
		{
			name: "underscore before",
			src:  "CLOUDFLARE_API_TOKEN_cfut_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "CLOUDFLARE_API_TOKEN_*****************************************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this token
			// rather than trim it; without one the fifty-three characters
			// Cloudflare issued are redacted and the one written after them,
			// which is part of no credential, stays in the text.
			name: "a character of the checksum's class after",
			src:  "cfut_0123456789abcdef0123456789abcdef0123456789abcdef0",
			want: "*****************************************************0",
		},
	}

	m := New(WithPatterns(CloudflareAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CloudflareAPIToken_leavesWhatFollowsAlone(t *testing.T) {
	// A token is fifty-three characters and no more, so what is written after
	// one stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the token is cfut_0123456789abcdef0123456789abcdef0123456789abcdef.",
			want: "the token is *****************************************************.",
		},
		{
			name: "quoted",
			src:  `"cfut_0123456789abcdef0123456789abcdef0123456789abcdef"`,
			want: `"*****************************************************"`,
		},
		{
			name: "dashed word",
			src:  "cfut_0123456789abcdef0123456789abcdef0123456789abcdef-suffix",
			want: "*****************************************************-suffix",
		},
		{
			name: "underscored word",
			src:  "cfut_0123456789abcdef0123456789abcdef0123456789abcdef_tail",
			want: "*****************************************************_tail",
		},
		{
			// A letter past f ends nothing here — the counts have already
			// ended the token — so a word written straight against one comes
			// through.
			name: "a word written against a token",
			src:  "cfut_0123456789abcdef0123456789abcdef0123456789abcdefsuffix",
			want: "*****************************************************suffix",
		},
	}

	m := New(WithPatterns(CloudflareAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CloudflareAPIToken_checksumIsNotVerified(t *testing.T) {
	// The eight characters behind the secret are a CRC32 of what stands in
	// front of them, and Cloudflare's own detection entries recompute it before
	// reporting a token. This scan reads them as a shape and stops there, which
	// builtin_cloudflare_api_token.go weighs: a token whose secret is intact and
	// whose checksum was mistyped or truncated is still a secret somebody can
	// read, and a scan verifying the checksum would leave every one of them in
	// the output.
	//
	// The two inputs below carry the same secret and different checksums. At
	// most one of them can be the CRC32 of that secret, so a scan locating both
	// is one that did not compute it — which is what the decision here means,
	// stated without this file having to hold a checksum it computed.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "one checksum",
			src:  "cfut_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "another over the same secret",
			src:  "cfut_0123456789abcdef0123456789abcdef01234567abcdef01",
		},
	}

	want := []Span{{0, 53}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CloudflareAPIToken().Find(tt.src); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, want)
			}
		})
	}
}

func Test_CloudflareAPIToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision a prefix invites is a digest written behind it, and this
	// format pays it rather than ruling it out. The hexadecimal digits are
	// letters and digits, and every character of a digest is hexadecimal, so a
	// digest satisfies the secret's alphabet and the checksum's class alike.
	// builtin_cloudflare_api_token.go weighs it: the vendor's format is a prefix
	// and forty-eight characters whose last eight are hexadecimal, so a scan
	// declining a digest behind this prefix declines the tokens whose secret is
	// written in the same sixteen characters — which the tokens the rest of this
	// file is built from are.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// Sixty-four hexadecimal characters, of which the first forty-eight
			// are a body and the sixteen left over stay in the text.
			name: "a sha-256 behind the prefix",
			src:  "cfut_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 53}},
		},
		{
			// Forty characters, which is eight short of a body.
			name: "a sha-1 behind the prefix",
			src:  "cfut_0123456789abcdef0123456789abcdef01234567",
		},
		{
			// Thirty-two, which is sixteen short.
			name: "an md5 behind the prefix",
			src:  "cfut_0123456789abcdef0123456789abcdef",
		},
		{
			// A digest carries no underscore, so it holds no prefix to be found
			// in at however long it runs.
			name: "a digest on its own",
			src:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CloudflareAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CloudflareAPIToken_aTokenBeginningInsideAnother(t *testing.T) {
	// The claim builtin_cloudflare_api_token.go makes about advancing rather
	// than consuming the match, and the reason it is load-bearing here. The
	// underscore every prefix closes with has to fall past the first token's
	// last character, which caps the overlap at the four characters in front of
	// it and puts all four in the checksum; standing there they have to be
	// hexadecimal, which stops cfut_ at cf and cfat_ at cfa. Each is below at
	// its deepest, which is where a scan resuming too far along would drop the
	// second token first.
	//
	// A scan consuming its match would resume past the first token and leave
	// the second in the output whole. The two spans overlap, which a Masker
	// resolves into one, so the redaction reaches from the first character to
	// the last.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// cf as the last two characters of the first token's checksum,
			// with ut_ written after it.
			name: "a token a user owns, two characters inside",
			src:  "cfut_0123456789abcdef0123456789abcdef012345670123abcfut_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 53}, {51, 104}},
		},
		{
			// cfa as the last three, which only the account owned prefix can
			// reach, with t_ written after it.
			name: "a token an account owns, three characters inside",
			src:  "cfut_0123456789abcdef0123456789abcdef0123456701234cfat_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 53}, {50, 103}},
		},
	}

	m := New(WithPatterns(CloudflareAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := CloudflareAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Fatalf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
			if got, want := m.Mask(tt.src), strings.Repeat("*", len(tt.src)); got != want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, want)
			}
		})
	}
}

func Test_CloudflareAPIToken_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor, and what holds it linear is the counts being
	// counts: a candidate reads at most fifty-three bytes and stops. These are
	// the inputs that would find it wrong here — a line that is nothing but
	// prefixes, a line that is nothing but tokens, and a single base62 run as
	// long as the line, which is where a scan reading a run instead of a count
	// would show itself.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// whole body apiece and so hold a candidate every fifty-three bytes at their
	// densest. The crowding a line can actually carry, a candidate every five,
	// stays here.
	sources := map[string]string{
		// A candidate every five characters, each read back whole and turned
		// away by the table before a body is looked at because no prefix
		// stands there.
		"a candidate the table turns away": strings.Repeat("cfxt_", 400000),
		// A candidate every five, each turned away at the fifth character of
		// its body, which is the underscore the next prefix closes with.
		"a candidate every five characters": strings.Repeat("cfut_", 400000),
		// The same crowding with a whole token at each candidate, so every one
		// of them reads forty-eight characters and reports a span.
		"a token every fifty-three characters": strings.Repeat("cfut_0123456789abcdef0123456789abcdef0123456789abcdef", 40000),
		// A candidate walked to its last character before the checksum's class
		// turns it away, which is the most a rejected candidate can cost.
		"a candidate walked to its last character": strings.Repeat("cfut_0123456789abcdef0123456789abcdef0123456789abcdeg ", 40000),
		// One candidate whose body is the whole line. The counts stop it at
		// forty-eight characters; a scan reading the run would read two
		// mebibytes.
		"a base62 run the length of the line": "cfut_" + strings.Repeat("a", 2000000),
		// The same run with no prefix in front of it, so no candidate is found
		// in it at all.
		"a base62 run with no prefix": strings.Repeat("a", 2000000),
	}

	checkScanIsLinear(t, CloudflareAPIToken(), sources)
}

func Test_cloudflareAPITokenPrefixes(t *testing.T) {
	// The two things the scan needs of the table, neither of which anything
	// else here reports: a prefix nothing locates simply locates nothing, and
	// the cases above would go on passing for the prefix that still works.
	//
	// The first is that every prefix opens with the characters a candidate is
	// read back to, since one that does not is a prefix the scan turns away
	// unread. Where the search stops, and what that asks of the table, is
	// Test_cloudflareAPITokenAnchor's to hold.
	//
	// The second is that no prefix is written inside another at its first
	// character, which is what lets cloudflareAPITokenPrefixAt return the first
	// entry that matches and the table be written in any order. Where one
	// prefix opened another, the shorter would be taken at a position the
	// longer belongs at and the body read from the wrong character — cfa_ above
	// cfat_ would leave the scan reading t_ where a secret should stand and
	// locating no account owned token at all.
	//
	// The total is held here as well, and what it holds is the documentation
	// rather than the scan. The scan never states a whole token: it reads the
	// body from wherever the prefix it matched ends, so a prefix of another
	// length would be located correctly and nothing would go wrong. What would
	// go wrong is the sentence on CloudflareAPIToken promising fifty-three
	// characters either way, and the spans every case in this file is written
	// with. So a prefix of another length joining the table is meant to fail
	// here — not because the scan cannot read it, but because the exported
	// documentation says a length that a caller reads and would no longer be
	// true of every token located.
	const documentedChars = 53

	if len(cloudflareAPITokenPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for i, prefix := range cloudflareAPITokenPrefixes {
		if !strings.HasPrefix(prefix, cloudflareAPITokenOpening) {
			t.Errorf("the prefix %q does not open with %q, which a candidate is read back to", prefix, cloudflareAPITokenOpening)
		}
		if got := len(prefix) + cloudflareCredentialBodyChars; got != documentedChars {
			t.Errorf("a token opening %q is read as %d characters, the documentation promises %d", prefix, got, documentedChars)
		}
		for j, other := range cloudflareAPITokenPrefixes {
			if i != j && strings.HasPrefix(other, prefix) {
				t.Errorf("the prefix %q opens %q, so the two match at one position and the order of the table decides which", prefix, other)
			}
		}
	}
}

// Test_cloudflareAPITokenAnchor holds the table to what reading a candidate
// backwards asks of it, which is more than reading one forwards asked and is
// what Test_cloudflareAPITokenPrefixes above does not reach.
//
// Every prefix must carry the anchor at the index the scan reads back from and
// carry it nowhere else, or the position a search reports is not the position a
// prefix ends at. And every prefix must be the same length, since one index
// serves the whole table. builtin_scan.go says why both are held here rather
// than left to the targets.
func Test_cloudflareAPITokenAnchor(t *testing.T) {
	if len(cloudflareAPITokenPrefixes) == 0 {
		t.Fatal("no prefix is documented, so the pattern locates nothing")
	}
	width := len(cloudflareAPITokenPrefixes[0])
	for _, prefix := range cloudflareAPITokenPrefixes {
		t.Run(prefix, func(t *testing.T) {
			if len(prefix) != width {
				t.Errorf("the prefix is %d characters where the first is %d, so one anchor index cannot serve both", len(prefix), width)
			}
			if cloudflareAPITokenAnchorIndex >= len(prefix) {
				t.Fatalf("the anchor stands at %d, the prefix is %d characters", cloudflareAPITokenAnchorIndex, len(prefix))
			}
			if c := prefix[cloudflareAPITokenAnchorIndex]; c != cloudflareAPITokenAnchor {
				t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it",
					c, byte(cloudflareAPITokenAnchor))
			}
			for i := range len(prefix) {
				if i != cloudflareAPITokenAnchorIndex && prefix[i] == cloudflareAPITokenAnchor {
					t.Errorf("the prefix carries %q again at %d, so a token opens a candidate at more than one position",
						byte(cloudflareAPITokenAnchor), i)
				}
			}
		})
	}
}

func Test_isCloudflareCredentialChecksumByte(t *testing.T) {
	// The hexadecimal digits and nothing else, stated over every byte rather
	// than by example. Either case is admitted where an encoder writes lowercase
	// alone, which builtin_cloudflare_api_token.go weighs.
	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9' || 'a' <= b && b <= 'f' || 'A' <= b && b <= 'F'
		if got := isCloudflareCredentialChecksumByte(b); got != want {
			t.Errorf("isCloudflareCredentialChecksumByte(%q) = %v, want %v", b, got, want)
		}
	}
}

func Test_isCloudflareCredentialBody(t *testing.T) {
	// The two counts and the two character classes together, stated over every
	// byte rather than by example. Where the boundary between them falls is
	// what the substitution finds: the same byte is a body character at one
	// position and not at the next.
	body := strings.Repeat("a", cloudflareCredentialBodyChars)

	if !isCloudflareCredentialBody(body) {
		t.Errorf("isCloudflareCredentialBody(%q) = false, want a body of %d characters to be one", body, cloudflareCredentialBodyChars)
	}
	for _, s := range []string{body[:len(body)-1], body + "b"} {
		if isCloudflareCredentialBody(s) {
			t.Errorf("isCloudflareCredentialBody(%q) = true, want only %d characters to be a body", s, cloudflareCredentialBodyChars)
		}
	}

	for i := range cloudflareCredentialBodyChars {
		for c := range 256 {
			b := byte(c)
			src := body[:i] + string([]byte{b}) + body[i+1:]

			want := isBase62Byte(b)
			if i >= cloudflareCredentialSecretChars {
				want = isCloudflareCredentialChecksumByte(b)
			}
			if got := isCloudflareCredentialBody(src); got != want {
				t.Errorf("isCloudflareCredentialBody(%q) = %v with %q at %d, want %v", src, got, b, i, want)
			}
		}
	}
}

// referenceCloudflareAPIToken is the expression the scan in
// builtin_cloudflare_api_token.go reads by hand: the statement of what a
// Cloudflare API token is, kept here so that the scan can be held to it.
//
// Both prefixes, both counts and both character classes are spelled again
// rather than built from cloudflareAPITokenPrefixes, the counts beside them and
// the byte tests below the scan. A reference sharing those declarations could
// not disagree with the scan about them, and it is exactly that disagreement the
// fuzz target below is for: the two have to be changed together or reported
// apart.
//
// Both counted repetitions here are exact, so the machine an engine builds for
// a candidate is forty-eight states wide and is read once, and the two
// characters in front of the alternation are one literal, which is what an
// engine searches the text for. That is what lets this reference be an
// expression at all, where an alternation of literals sharing no first
// character leaves an engine walking its machine at every byte.
var referenceCloudflareAPIToken = regexp.MustCompile(`cf(?:ut|at)_[0-9A-Za-z]{40}[0-9A-Fa-f]{8}`)

// referenceCloudflareAPITokenFind locates tokens the plain way: the leftmost
// match of the expression above, then the leftmost one beginning after that
// match's first byte, over and over, with nothing remembered between them.
//
// Asking at every byte is what the scan does too, and it is not written here to
// restate that. A reference is written to know nothing its scan claims, and
// where a token may begin is one of the things the scan claims — so this one
// starts afresh a byte along whether or not a token can be written inside
// another, and the fuzz target below is what holds the two to the same answer.
func referenceCloudflareAPITokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceCloudflareAPIToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzCloudflareAPIToken_matchesReference guards the hand-written scan: the
// characters it searches for, the prefixes it reads at them, the counts it
// reads behind those prefixes, the two character classes it reads them in and
// the byte it resumes at may none of them change which tokens are located.
func FuzzCloudflareAPIToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("CLOUDFLARE_API_TOKEN=cfut_0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("cfat_0123456789abcdef0123456789abcdef0123456789abcdef")                 // the other kind
	f.Add("cfut_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")                 // an uppercase body
	f.Add("cfut_0123456789abcdefghijklmnopqrstuvwxyzABCD0123abcd")                 // a secret past f
	f.Add("cfut_0123456789abcdef0123456789abcdef0123456789abcde")                  // a body one short
	f.Add("cfut_0123456789abcdef0123456789abcdef0123456789abcdef0")                // and a run longer than one
	f.Add("cfut_0123456789abcdef0123456789abcdef0123456789abcdeg")                 // a letter past f at the end
	f.Add("cfut_0123456789abcdef0123456789abcdef01234567gabcdef0")                 // and at the start of the checksum
	f.Add("cfut_0123456789abcdef-123456789abcdef0123456789abcdef")                 // a hyphen inside the secret
	f.Add("cfut_0123456789abcdef_123456789abcdef0123456789abcdef")                 // and an underscore
	f.Add("CFUT_0123456789abcdef0123456789abcdef0123456789abcdef")                 // an uppercase prefix
	f.Add("cfk_0123456789abcdef0123456789abcdef0123456789abcdef")                  // the api key prefix
	f.Add("cfxt_0123456789abcdef0123456789abcdef0123456789abcdef")                 // neither kind
	f.Add("cfut-0123456789abcdef0123456789abcdef0123456789abcdef")                 // a hyphen where the underscore stands
	f.Add("cfut_0123456789abcdef0123456789\nabcdef0123456789abcdef")               // a token a line break breaks
	f.Add("xcfut_0123456789abcdef0123456789abcdef0123456789abcdef")                // written against a letter
	f.Add("zone_cfut_0123456789abcdef0123456789abcdef0123456789abcdef")            // and against a name
	f.Add("cfut_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") // a sha-256 behind the prefix
	f.Add("cfut_0123456789abcdef0123456789abcdef01234567")                         // a sha-1
	f.Add("cfut_0123456789abcdef0123456789abcdef")                                 // an md5
	f.Add("cfut_cfut_0123456789abcdef0123456789abcdef0123456789abcdef")            // a prefix where a body could hold one
	// A token beginning inside another, which is what advancing rather than
	// consuming the match has to find, and two written with nothing between
	// them.
	f.Add("cfut_0123456789abcdef0123456789abcdef012345670123abcfut_0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("cfut_0123456789abcdef0123456789abcdef0123456701234cfat_0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("cfut_0123456789abcdef0123456789abcdef0123456789abcdefcfat_0123456789abcdef0123456789abcdef0123456789abcdef")
	// Candidate positions crowded as close as they can be, a run of the
	// characters a candidate is read back to, and a base62 run with no prefix
	// in front of it.
	f.Add(strings.Repeat("cfut_", 32))
	f.Add(strings.Repeat("cfut_", 32) + "0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add(strings.Repeat("cf", 128))
	f.Add(strings.Repeat("0123456789abcdef", 16))

	fuzzAgainstReference(f, CloudflareAPIToken().Find, referenceCloudflareAPITokenFind)
}

// cloudflareAPITokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func cloudflareAPITokenFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line carries the underscore the scan searches for,
	// so what the line times is the search for it — which is most of what this
	// pattern costs a caller whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.cloudflare.com/client/v4/zones `
	token := "cfut_0123456789abcdef0123456789abcdef0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The underscore every fifth byte with the two characters a prefix
			// opens with in front of it and a middle that names no prefix, so
			// every candidate is read back whole and turned away by the table
			// before a body is looked at. That is the cheapest this scan
			// declines a candidate for.
			name:  "candidates that are not values",
			src:   strings.Repeat("cfxt_", 512),
			spans: 0,
		},
		{
			// The same crowding with a prefix at each candidate, so the body
			// is reached and turned away at its fifth character, which is the
			// underscore the next prefix closes with.
			name:  "candidates whose bodies are prefixes",
			src:   strings.Repeat("cfut_", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: forty-seven characters of the
			// body walked before its last one turns the candidate away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("cfut_0123456789abcdef0123456789abcdef0123456789abcdeg ", 16),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "token=" + token,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "token=" + token,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"token="+token+"\n", 32),
			spans: 32,
		},
	}
}
