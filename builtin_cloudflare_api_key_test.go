package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The Cloudflare API key pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The keys written out below are made only of ordered characters: valid in
// shape, obviously not real. The body is 0123456789abcdef written three times,
// which is the forty characters of the secret and the eight of the checksum the
// pattern reads them at, and with the prefix in front of it that is fifty-two
// characters. Where the case is what a case is about the same run is written in
// uppercase, since the secret is base62 and the checksum hexadecimal and both
// hold the letters of either case.

func Test_CloudflareAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key",
			src:  "cfk_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 52}},
		},
		{
			name: "a key in an environment assignment",
			src:  "CLOUDFLARE_API_KEY=cfk_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{19, 71}},
		},
		{
			// The secret is base62 and the checksum hexadecimal, and both are
			// read in either case for the reason builtin_cloudflare_api_key.go
			// gives.
			name: "an uppercase body",
			src:  "cfk_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 52}},
		},
		{
			// The secret's alphabet is the letters and digits, so it runs past
			// f where the eight characters behind it may not.
			name: "a secret carrying letters past f",
			src:  "cfk_0123456789abcdefghijklmnopqrstuvwxyzABCD0123abcd",
			want: []Span{{0, 52}},
		},
		{
			// The counts are read exactly, so what follows the fifty-second
			// character is not part of the key and stays in the text.
			name: "a body run longer than the counts is a key and what follows it",
			src:  "cfk_0123456789abcdef0123456789abcdef0123456789abcdef0",
			want: []Span{{0, 52}},
		},
		{
			name: "two keys with nothing between them",
			src:  "cfk_0123456789abcdef0123456789abcdef0123456789abcdefcfk_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 52}, {52, 104}},
		},
		{
			// A candidate whose body opens with a prefix of its own. The outer
			// one is turned away at the fourth character of its body, which is
			// the underscore the inner prefix closes with and no character a
			// secret is written with; the inner key is found where it stands.
			name: "a candidate whose body opens with a prefix",
			src:  "cfk_cfk_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{4, 56}},
		},
		{
			// The one shape a word boundary in front would turn away. No word
			// is spelled cfk, so what can reach the prefix is a snake_case name
			// whose last segment is those three characters — which the
			// tightening on offer admits anyway, since it admits the
			// underscore.
			name: "a snake_case name closing on the prefix",
			src:  "zone_cfk_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{5, 57}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CloudflareAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CloudflareAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "cfk_",
		},
		{
			name: "a body one character short",
			src:  "cfk_0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// Forty-seven characters of the body reached and the last one a
			// letter past f, which is the count met with the checksum's class
			// failing at its final character.
			name: "a letter past f at the end of the checksum",
			src:  "cfk_0123456789abcdef0123456789abcdef0123456789abcdeg",
		},
		{
			name: "an uppercase letter past F at the end of the checksum",
			src:  "cfk_0123456789abcdef0123456789abcdef0123456789abcdeG",
		},
		{
			// The eight characters behind the secret are hexadecimal, so a
			// letter past f may stand in the first forty and nowhere later.
			name: "a letter past f at the start of the checksum",
			src:  "cfk_0123456789abcdef0123456789abcdef01234567gabcdef0",
		},
		{
			// Neither character base64url adds beyond the letters and digits
			// may stand in a body, however the older format was written.
			name: "a hyphen inside the secret",
			src:  "cfk_0123456789abcdef-123456789abcdef0123456789abcdef",
		},
		{
			name: "an underscore inside the secret",
			src:  "cfk_0123456789abcdef_123456789abcdef0123456789abcdef",
		},
		{
			name: "a key broken by a space",
			src:  "cfk_0123456789abcdef0123456789 abcdef0123456789abcdef",
		},
		{
			name: "a key broken by a line break",
			src:  "cfk_0123456789abcdef0123456789\nabcdef0123456789abcdef",
		},
		{
			name: "an uppercase prefix",
			src:  "CFK_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The two credentials Cloudflare names tokens rather than keys,
			// which this pattern is named for not locating and
			// CloudflareAPIToken locates instead.
			name: "the api token prefix a user owns",
			src:  "cfut_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "the api token prefix an account owns",
			src:  "cfat_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The two letters both formats open with, with a kind behind them
			// that Cloudflare issues none of.
			name: "a kind cloudflare issues none of",
			src:  "cfx_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a hyphen where the prefix carries its underscore",
			src:  "cfk-0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// A body of the right counts and the right classes behind
			// something else. The prefix is the whole of the anchor.
			name: "a value of the right shape opening with no prefix",
			src:  "xxx_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The unprefixed format Cloudflare issued until the keys grew one:
			// thirty-seven to forty-five lowercase hexadecimal characters with
			// nothing in front of them, which is a grammar this pattern reads
			// nowhere. Forty of those characters is a SHA-1 exactly.
			name: "a key of the format issued before the prefix",
			src:  "CLOUDFLARE_API_KEY=0123456789abcdef0123456789abcdef01234",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// The prefix has to be written whole, and cf on its own is written
			// in prose as an abbreviation.
			name: "the opening as it is written in prose",
			src:  "cf. the token formats page for what a key is",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CloudflareAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_CloudflareAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "CLOUDFLARE_API_KEY=cfk_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "CLOUDFLARE_API_KEY=****************************************************",
		},
		{
			// How a key reaches the API, and how it reaches a log line that
			// echoed the header. A key is sent in a header of its own rather
			// than in the bearer header a token is sent in, and beside the
			// email address of the user holding it.
			name: "the auth key header",
			src:  "X-Auth-Email: user@example.com\nX-Auth-Key: cfk_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "X-Auth-Email: user@example.com\nX-Auth-Key: ****************************************************",
		},
		{
			// The response a key is read out of on the dashboard's own API.
			name: "the response that reports it",
			src:  `{"result":{"id":"0123456789abcdef0123456789abcdef","value":"cfk_0123456789abcdef0123456789abcdef0123456789abcdef"}}`,
			want: `{"result":{"id":"0123456789abcdef0123456789abcdef","value":"****************************************************"}}`,
		},
		{
			name: "a command line",
			src:  "curl -H 'X-Auth-Key: cfk_0123456789abcdef0123456789abcdef0123456789abcdef' https://api.cloudflare.com/client/v4/user",
			want: "curl -H 'X-Auth-Key: ****************************************************' https://api.cloudflare.com/client/v4/user",
		},
	}

	m := New(WithPatterns(CloudflareAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CloudflareAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the key through whole. The first two are what the
	// demand would cost.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "xcfk_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "x****************************************************",
		},
		{
			name: "underscore before",
			src:  "CLOUDFLARE_API_KEY_cfk_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "CLOUDFLARE_API_KEY_****************************************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this key rather
			// than trim it; without one the fifty-two characters Cloudflare
			// issued are redacted and the one written after them, which is part
			// of no credential, stays in the text.
			name: "a character of the checksum's class after",
			src:  "cfk_0123456789abcdef0123456789abcdef0123456789abcdef0",
			want: "****************************************************0",
		},
	}

	m := New(WithPatterns(CloudflareAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CloudflareAPIKey_leavesWhatFollowsAlone(t *testing.T) {
	// A key is fifty-two characters and no more, so what is written after one
	// stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the key is cfk_0123456789abcdef0123456789abcdef0123456789abcdef.",
			want: "the key is ****************************************************.",
		},
		{
			name: "quoted",
			src:  `"cfk_0123456789abcdef0123456789abcdef0123456789abcdef"`,
			want: `"****************************************************"`,
		},
		{
			name: "dashed word",
			src:  "cfk_0123456789abcdef0123456789abcdef0123456789abcdef-suffix",
			want: "****************************************************-suffix",
		},
		{
			name: "underscored word",
			src:  "cfk_0123456789abcdef0123456789abcdef0123456789abcdef_tail",
			want: "****************************************************_tail",
		},
		{
			// A letter past f ends nothing here — the counts have already ended
			// the key — so a word written straight against one comes through.
			name: "a word written against a key",
			src:  "cfk_0123456789abcdef0123456789abcdef0123456789abcdefsuffix",
			want: "****************************************************suffix",
		},
	}

	m := New(WithPatterns(CloudflareAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CloudflareAPIKey_checksumIsNotVerified(t *testing.T) {
	// The eight characters behind the secret are a CRC32 of what stands in
	// front of them, and Cloudflare's own detection entries recompute it before
	// reporting a key. This scan reads them as a shape and stops there, which
	// builtin_cloudflare_api_key.go weighs: a key whose secret is intact and
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
			src:  "cfk_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "another over the same secret",
			src:  "cfk_0123456789abcdef0123456789abcdef01234567abcdef01",
		},
	}

	want := []Span{{0, 52}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CloudflareAPIKey().Find(tt.src); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, want)
			}
		})
	}
}

func Test_CloudflareAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision every prefix in this package leaves is a digest written
	// behind it, and this format pays it rather than ruling it out. The
	// hexadecimal digits are letters and digits, and every character of a digest
	// is hexadecimal, so a digest satisfies the secret's alphabet and the
	// checksum's class alike. builtin_cloudflare_api_key.go weighs it: the
	// vendor's format is a prefix and forty-eight characters whose last eight
	// are hexadecimal, so a scan declining a digest behind this prefix declines
	// the keys whose secret is written in the same sixteen characters — which
	// the keys the rest of this file is built from are.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// Sixty-four hexadecimal characters, of which the first forty-eight
			// are a body and the sixteen left over stay in the text.
			name: "a sha-256 behind the prefix",
			src:  "cfk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 52}},
		},
		{
			// Forty characters, which is eight short of a body.
			name: "a sha-1 behind the prefix",
			src:  "cfk_0123456789abcdef0123456789abcdef01234567",
		},
		{
			// Thirty-two, which is sixteen short.
			name: "an md5 behind the prefix",
			src:  "cfk_0123456789abcdef0123456789abcdef",
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
			if got := CloudflareAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_CloudflareAPIKey_aKeyBeginningInsideAnother(t *testing.T) {
	// The claim builtin_cloudflare_api_key.go makes about advancing rather than
	// consuming the match, and the reason it is load-bearing here. The
	// underscore the prefix closes with has to fall past the first key's last
	// character, which caps the overlap at the three characters in front of it
	// and puts all three in the checksum; standing there they have to be
	// hexadecimal, and cfk is not while cf is. Both positions that leaves are
	// below.
	//
	// A scan consuming its match would resume past the first key and leave the
	// second in the output whole. The two spans overlap in either case, which a
	// Masker resolves into one, so the redaction reaches from the first
	// character to the last.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// cf as the last two characters of the first key's checksum, with
			// k_ written after it.
			name: "two characters inside",
			src:  "cfk_0123456789abcdef0123456789abcdef01234567012345cfk_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 52}, {50, 102}},
		},
		{
			// c as the last character alone, with fk_ written after it. The
			// deepest a prefix reaches is a ceiling rather than a requirement.
			name: "one character inside",
			src:  "cfk_0123456789abcdef0123456789abcdef012345670123456cfk_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 52}, {51, 103}},
		},
	}

	m := New(WithPatterns(CloudflareAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CloudflareAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Fatalf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
			if got, want := m.Mask(tt.src), strings.Repeat("*", len(tt.src)); got != want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, want)
			}
		})
	}
}

func Test_CloudflareAPIKey_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor, and what holds it linear is the counts being
	// counts: a candidate reads at most fifty-two bytes and stops. These are
	// the inputs that would find it wrong here — a line that is nothing but
	// prefixes, a line that is nothing but keys, and a single base62 run as long
	// as the line, which is where a scan reading a run instead of a count would
	// show itself.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// whole body apiece and so hold a candidate every fifty-two bytes at their
	// densest. The crowding a line can actually carry, a candidate every four,
	// stays here.
	sources := map[string]string{
		// A candidate every four characters, each turned away at the fourth
		// character of its body, which is the underscore the next prefix closes
		// with.
		"a candidate every four characters": strings.Repeat("cfk_", 500000),
		// The same crowding with a whole key at each candidate, so every one of
		// them reads forty-eight characters and reports a span.
		"a key every fifty-two characters": strings.Repeat("cfk_0123456789abcdef0123456789abcdef0123456789abcdef", 40000),
		// A candidate walked to its last character before the checksum's class
		// turns it away, which is the most a rejected candidate can cost.
		"a candidate walked to its last character": strings.Repeat("cfk_0123456789abcdef0123456789abcdef0123456789abcdeg ", 40000),
		// One candidate whose body is the whole line. The counts stop it at
		// forty-eight characters; a scan reading the run would read two
		// mebibytes.
		"a base62 run the length of the line": "cfk_" + strings.Repeat("a", 2000000),
		// The same run with no prefix in front of it, so no candidate is found
		// in it at all.
		"a base62 run with no prefix": strings.Repeat("a", 2000000),
	}

	m := New(WithPatterns(CloudflareAPIKey()))
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

func Test_cloudflareAPIKeyPrefix(t *testing.T) {
	// The two things the scan needs of the prefix, neither of which anything
	// else here reports: a prefix nothing locates simply locates nothing, and
	// the cases above would go on passing for the prefix that still works.
	//
	// The first is that it closes with a character no body is written with.
	// That is what turns away a candidate whose body opens with a prefix of its
	// own, and it is what caps how far a key reaches into another: the
	// underscore has to fall past the first key's last character, so the
	// overlap is at most the three characters in front of it and lands in the
	// checksum, where being hexadecimal narrows it to two.
	// Test_CloudflareAPIKey_aKeyBeginningInsideAnother drives both positions
	// that leaves. Only the secret's alphabet is asked about here, since the
	// checksum is read in sixteen characters that alphabet already holds — and
	// asking it of the underscore is the whole of what this cap rests on, since
	// c, f and k are all base62 and none of them would bound anything.
	//
	// The second is the total, and what it holds is the documentation rather
	// than the scan. The scan never states a whole key: it reads the body from
	// where the prefix ends, so a prefix of another length would be located
	// correctly and nothing would go wrong. What would go wrong is the sentence
	// on CloudflareAPIKey promising fifty-two characters, and the spans every
	// case in this file is written with. So a prefix of another length is meant
	// to fail here — not because the scan cannot read it, but because the
	// exported documentation says a length that a caller reads and would no
	// longer be true.
	const documentedChars = 52

	if cloudflareAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	if c := cloudflareAPIKeyPrefix[len(cloudflareAPIKeyPrefix)-1]; isBase62Byte(c) {
		t.Errorf("the prefix %q closes with %q, which a secret is written with", cloudflareAPIKeyPrefix, c)
	}
	if got := len(cloudflareAPIKeyPrefix) + cloudflareCredentialBodyChars; got != documentedChars {
		t.Errorf("a key opening %q is read as %d characters, the documentation promises %d", cloudflareAPIKeyPrefix, got, documentedChars)
	}
}

// Test_cloudflareAPIKeyAnchor holds the prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_cloudflareAPIKeyAnchor(t *testing.T) {
	if cloudflareAPIKeyAnchorIndex >= len(cloudflareAPIKeyPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", cloudflareAPIKeyAnchorIndex, len(cloudflareAPIKeyPrefix))
	}
	if c := cloudflareAPIKeyPrefix[cloudflareAPIKeyAnchorIndex]; c != cloudflareAPIKeyAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(cloudflareAPIKeyAnchor))
	}
}

// referenceCloudflareAPIKey is the expression the scan in
// builtin_cloudflare_api_key.go reads by hand: the statement of what a
// Cloudflare API key is, kept here so that the scan can be held to it.
//
// The prefix, both counts and both character classes are spelled again rather
// than built from cloudflareAPIKeyPrefix and the body declarations the token
// file holds. A reference sharing those declarations could not disagree with
// the scan about them, and it is exactly that disagreement the fuzz target
// below is for: the two have to be changed together or reported apart. The half
// borrowed from the token file is spelled out here for the same reason: a body
// two patterns share is a body one reference has to be able to contradict.
//
// Both counted repetitions here are exact, so the machine an engine builds for
// a candidate is forty-eight states wide and is read once, and the prefix in
// front of them is one four character literal, which is what an engine searches
// the text for. That is what lets this reference be an expression at all, where
// a floor spelled as a counted repetition would cost a machine as wide as the
// floor at every candidate.
var referenceCloudflareAPIKey = regexp.MustCompile(`cfk_[0-9A-Za-z]{40}[0-9A-Fa-f]{8}`)

// referenceCloudflareAPIKeyFind locates keys the plain way: the leftmost match
// of the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// Asking at every byte is what the scan does too, and it is not written here to
// restate that. A reference is written to know nothing its scan claims, and
// where a key may begin is one of the things the scan claims — so this one
// starts afresh a byte along whether or not a key can be written inside
// another, and the fuzz target below is what holds the two to the same answer.
func referenceCloudflareAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceCloudflareAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzCloudflareAPIKey_matchesReference guards the hand-written scan: the
// prefix it searches for, the counts it reads behind that prefix, the two
// character classes it reads them in and the byte it resumes at may none of
// them change which keys are located.
func FuzzCloudflareAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("CLOUDFLARE_API_KEY=cfk_0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("cfk_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")                 // an uppercase body
	f.Add("cfk_0123456789abcdefghijklmnopqrstuvwxyzABCD0123abcd")                 // a secret past f
	f.Add("cfk_0123456789abcdef0123456789abcdef0123456789abcde")                  // a body one short
	f.Add("cfk_0123456789abcdef0123456789abcdef0123456789abcdef0")                // and a run longer than one
	f.Add("cfk_0123456789abcdef0123456789abcdef0123456789abcdeg")                 // a letter past f at the end
	f.Add("cfk_0123456789abcdef0123456789abcdef01234567gabcdef0")                 // and at the start of the checksum
	f.Add("cfk_0123456789abcdef-123456789abcdef0123456789abcdef")                 // a hyphen inside the secret
	f.Add("cfk_0123456789abcdef_123456789abcdef0123456789abcdef")                 // and an underscore
	f.Add("CFK_0123456789abcdef0123456789abcdef0123456789abcdef")                 // an uppercase prefix
	f.Add("cfut_0123456789abcdef0123456789abcdef0123456789abcdef")                // the api token prefixes
	f.Add("cfat_0123456789abcdef0123456789abcdef0123456789abcdef")                //
	f.Add("cfx_0123456789abcdef0123456789abcdef0123456789abcdef")                 // a kind cloudflare issues none of
	f.Add("cfk-0123456789abcdef0123456789abcdef0123456789abcdef")                 // a hyphen where the underscore stands
	f.Add("cfk_0123456789abcdef0123456789\nabcdef0123456789abcdef")               // a key a line break breaks
	f.Add("xcfk_0123456789abcdef0123456789abcdef0123456789abcdef")                // written against a letter
	f.Add("zone_cfk_0123456789abcdef0123456789abcdef0123456789abcdef")            // and against a name
	f.Add("cfk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") // a sha-256 behind the prefix
	f.Add("cfk_0123456789abcdef0123456789abcdef01234567")                         // a sha-1
	f.Add("cfk_0123456789abcdef0123456789abcdef")                                 // an md5
	f.Add("CLOUDFLARE_API_KEY=0123456789abcdef0123456789abcdef01234")             // the format issued before the prefix
	f.Add("cfk_cfk_0123456789abcdef0123456789abcdef0123456789abcdef")             // a prefix where a body could hold one
	// A key beginning inside another, which is what advancing rather than
	// consuming the match has to find, and two written with nothing between
	// them.
	f.Add("cfk_0123456789abcdef0123456789abcdef01234567012345cfk_0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("cfk_0123456789abcdef0123456789abcdef012345670123456cfk_0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("cfk_0123456789abcdef0123456789abcdef0123456789abcdefcfk_0123456789abcdef0123456789abcdef0123456789abcdef")
	// Candidate positions crowded as close as they can be, and a base62 run
	// with no prefix in front of it.
	f.Add(strings.Repeat("cfk_", 32))
	f.Add(strings.Repeat("cfk_", 32) + "0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add(strings.Repeat("0123456789abcdef", 16))

	fuzzAgainstReference(f, CloudflareAPIKey().Find, referenceCloudflareAPIKeyFind)
}

// cloudflareAPIKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func cloudflareAPIKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line carries the byte the scan searches for, so
	// what the line times is that search — which is most of what this pattern
	// costs a caller whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.cloudflare.com/client/v4/user `
	key := "cfk_0123456789abcdef0123456789abcdef0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix written over and over, so a candidate stands at every
			// fourth byte and every one of them is turned away at the fourth
			// character of its body, which is the underscore the next prefix
			// closes with. That is the cheapest this scan declines a candidate
			// for, since the prefix it searches for is the whole of the anchor.
			name:  "candidates that are not values",
			src:   strings.Repeat("cfk_", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: forty-seven characters of the
			// body walked before its last one turns the candidate away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("cfk_0123456789abcdef0123456789abcdef0123456789abcdeg ", 16),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "key=" + key,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "key=" + key,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"key="+key+"\n", 32),
			spans: 32,
		},
	}
}
