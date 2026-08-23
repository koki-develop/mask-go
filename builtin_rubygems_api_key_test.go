package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The RubyGems API key pattern: what it locates and what it leaves alone,
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
// which is the forty-eight characters SecureRandom.hex(24) comes to, so with
// the prefix in front it is the fifty-seven characters both of the long
// examples in the RubyGems.org guides are.

func Test_RubyGemsAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "rubygems_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 57}},
		},
		{
			name: "a key in an environment assignment",
			src:  "RUBYGEMS_API_KEY=rubygems_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{17, 74}},
		},
		{
			// The count is read exactly, so what follows the fifty-seventh
			// character is not part of the key and stays in the text.
			name: "a body run longer than the count is a key and what follows it",
			src:  "rubygems_0123456789abcdef0123456789abcdef0123456789abcdef0",
			want: []Span{{0, 57}},
		},
		{
			// Neither key is inside the other, and nothing separates them.
			name: "two keys with nothing between them",
			src:  "rubygems_0123456789abcdef0123456789abcdef0123456789abcdefrubygems_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 57}, {57, 114}},
		},
		{
			// The candidate the scan resuming a byte along is for. The first
			// prefix opens a candidate whose body would begin with the r of the
			// second, which no body may hold; the whole key stands at the
			// second. A scan resuming past the length the first candidate hoped
			// for would step over it.
			name: "a prefix written in front of a key",
			src:  "rubygems_rubygems_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{9, 66}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RubyGemsAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_RubyGemsAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "rubygems_",
		},
		{
			// Forty-seven characters where the pattern asks for forty-eight.
			name: "a body one character too short",
			src:  "rubygems_0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			name: "a body of half the count",
			src:  "rubygems_0123456789abcdef01234567",
		},
		{
			// SecureRandom.hex writes lowercase, which Ruby documents as the
			// whole of what the result may contain, and the alphabet is read as
			// written for the reason builtin_rubygems_api_key.go gives.
			name: "an uppercase body",
			src:  "rubygems_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		{
			name: "one uppercase character in the body",
			src:  "rubygems_0123456789abcdef0123456789abcdef0123456789abcdeF",
		},
		{
			// The body is hexadecimal, so the letters it may carry stop at f.
			name: "a letter past f in the body",
			src:  "rubygems_0123456789abcdef0123456789abcdef0123456789abcdeg",
		},
		{
			// The alphabet holds neither the hyphen nor the underscore, so the
			// prefix's own underscore cannot stand inside a body either.
			name: "an underscore inside the body",
			src:  "rubygems_0123456789abcdef_123456789abcdef0123456789abcdef0",
		},
		{
			name: "a hyphen inside the body",
			src:  "rubygems_0123456789abcdef-123456789abcdef0123456789abcdef0",
		},
		{
			name: "a key broken by a space",
			src:  "rubygems_0123456789abcdef 123456789abcdef0123456789abcdef0",
		},
		{
			name: "a key broken by a line break",
			src:  "rubygems_0123456789abcdef\n123456789abcdef0123456789abcdef0",
		},
		{
			name: "a hyphen where the prefix carries its underscore",
			src:  "rubygems-0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "the prefix without its closing underscore",
			src:  "rubygems0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "an uppercase prefix",
			src:  "RUBYGEMS_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// Fifty-seven characters of the right shape opening with something
			// else. The prefix is the whole of the anchor.
			name: "a value of the right shape opening with no prefix",
			src:  "xxxxxxxx_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The key of the credentials file a key is stored in, which is the
			// one snake_case name anybody writes with this prefix. Its second
			// character is a p, which no body may hold.
			name: "the credentials file key that names one",
			src:  ":rubygems_api_key: something",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "a log line",
			src:  `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://rubygems.org/api/v1/gems.json`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RubyGemsAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_RubyGemsAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "RUBYGEMS_API_KEY=rubygems_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "RUBYGEMS_API_KEY=*********************************************************",
		},
		{
			// How a key reaches the API, and how it reaches a log line that
			// echoed the header. RubyGems.org reads the key from Authorization
			// with no scheme in front of it.
			name: "an authorization header",
			src:  "Authorization: rubygems_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "Authorization: *********************************************************",
		},
		{
			// The credentials file gem signin writes, where the key stands
			// behind the one name this pattern has to read past.
			name: "the credentials file",
			src:  "---\n:rubygems_api_key: rubygems_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "---\n:rubygems_api_key: *********************************************************",
		},
		{
			// The response the API signing a user in returns, which is the only
			// place a key created that way is ever shown.
			name: "the response that first reports it",
			src:  `{"rubygems_api_key":"rubygems_0123456789abcdef0123456789abcdef0123456789abcdef","name":"ci"}`,
			want: `{"rubygems_api_key":"*********************************************************","name":"ci"}`,
		},
		{
			name: "a command line",
			src:  "curl -H 'Authorization: rubygems_0123456789abcdef0123456789abcdef0123456789abcdef' https://rubygems.org/api/v1/gems.json",
			want: "curl -H 'Authorization: *********************************************************' https://rubygems.org/api/v1/gems.json",
		},
		{
			name: "twice",
			src:  "rubygems_0123456789abcdef0123456789abcdef0123456789abcdef rubygems_abcdef0123456789abcdef0123456789abcdef0123456789",
			want: "********************************************************* *********************************************************",
		},
	}

	m := New(WithPatterns(RubyGemsAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_RubyGemsAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the key through whole. The first of them is also
	// what the tightening the Slack and Stripe scans take would cost here,
	// which builtin_rubygems_api_key.go weighs against what it would buy —
	// which, since no word ends in the letters rubygems, is nothing.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "xrubygems_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "x*********************************************************",
		},
		{
			name: "underscore before",
			src:  "RUBYGEMS_API_KEY_rubygems_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "RUBYGEMS_API_KEY_*********************************************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this key rather
			// than trim it; without one the fifty-seven characters RubyGems.org
			// issued are redacted and the one written after them, which is part
			// of no credential, stays in the text.
			name: "a character of the body's class after",
			src:  "rubygems_0123456789abcdef0123456789abcdef0123456789abcdef0",
			want: "*********************************************************0",
		},
	}

	m := New(WithPatterns(RubyGemsAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_RubyGemsAPIKey_leavesWhatFollowsAlone(t *testing.T) {
	// A key is fifty-seven characters and no more, so what is written after one
	// stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the key is rubygems_0123456789abcdef0123456789abcdef0123456789abcdef.",
			want: "the key is *********************************************************.",
		},
		{
			name: "quoted",
			src:  `"rubygems_0123456789abcdef0123456789abcdef0123456789abcdef"`,
			want: `"*********************************************************"`,
		},
		{
			// The hyphen belongs to the body's alphabet no more than an
			// uppercase letter does, so a hyphenated word written against a key
			// is left where it stands.
			name: "dashed word",
			src:  "rubygems_0123456789abcdef0123456789abcdef0123456789abcdef-suffix",
			want: "*********************************************************-suffix",
		},
		{
			// The underscore belongs to it either, however much of the format
			// is written with one: the count is what ends a key, so an
			// underscored word against one is left where it stands as a
			// hyphenated one is.
			name: "underscored word",
			src:  "rubygems_0123456789abcdef0123456789abcdef0123456789abcdef_tail",
			want: "*********************************************************_tail",
		},
		{
			// A letter past f is not a body character either, so an ordinary
			// word written against a key survives it whole.
			name: "a word past f",
			src:  "rubygems_0123456789abcdef0123456789abcdef0123456789abcdefsuffix",
			want: "*********************************************************suffix",
		},
	}

	m := New(WithPatterns(RubyGemsAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_RubyGemsAPIKey_noKeyBeginsInsideAnother(t *testing.T) {
	// The claim builtin_rubygems_api_key.go makes, which of the built-ins here
	// only the Stripe pattern can make as well: the spans of this pattern never
	// overlap one another. Everything a span covers past the prefix is a
	// hexadecimal digit, and the prefix opens with an r that none of the eight
	// characters behind it is and no body may hold, so no position inside a
	// span opens a prefix.
	//
	// It is not a claim one input can state, so a whole key is written into
	// every position of another here — at each character of its prefix, at each
	// character of its body and against either end — with nothing, a body and a
	// second key behind it in turn. What is asserted is only that no two spans
	// overlap; where the keys fall is what the table at the top of this file is
	// for.
	body := strings.Repeat("0123456789abcdef", 3)
	key := rubyGemsAPIKeyPrefix + body
	p := RubyGemsAPIKey()

	for i := range len(key) + 1 {
		for _, tail := range []string{"", body, key} {
			src := key[:i] + key + key[i:] + tail
			spans := p.Find(src)
			for j, got := range spans {
				if j > 0 && got.Start < spans[j-1].End {
					t.Errorf("Find(%q) = %v, which holds two values overlapping", src, spans)
					break
				}
			}
		}
	}
}

func Test_RubyGemsAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision every prefix in this package leaves, and the one this
	// format pays for rather than ruling out. The Grafana format turns a digest
	// away with the underscore dividing its secret from its checksum; here
	// everything behind the prefix is one class, and a lowercase digest is
	// written in it.
	//
	// What the count turns away is the two digests shorter than it. What it does
	// not turn away is the SHA-256, which is longer: with no boundary behind a
	// match its first forty-eight characters are a body, so the prefix and a
	// SHA-256 are redacted for fifty-seven of their seventy-three characters.
	// builtin_rubygems_api_key.go weighs the boundary that would decline it —
	// what it would cost is a key with a hexadecimal character written straight
	// after it, dropped rather than trimmed.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// Thirty-two characters, which is sixteen short of a body.
			name: "an md5 behind the prefix",
			src:  "rubygems_0123456789abcdef0123456789abcdef",
		},
		{
			// Forty, which is eight short.
			name: "a sha-1 behind the prefix",
			src:  "rubygems_0123456789abcdef0123456789abcdef01234567",
		},
		{
			// A digest carries no underscore, so it holds no prefix to be found
			// at however long it runs.
			name: "a digest on its own",
			src:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// Sixty-four, which is sixteen more than a body: the first
			// forty-eight are one, and the sixteen past the count stay in the
			// text.
			name: "a sha-256 behind the prefix",
			src:  "rubygems_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 57}},
		},
		{
			// Which is the same span the key this file is written with reports,
			// because the two are the same text as far as the count reaches.
			name: "a key of forty-eight hexadecimal characters",
			src:  "rubygems_0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 57}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RubyGemsAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_RubyGemsAPIKey_theKeyFormatItReplaced(t *testing.T) {
	// The key format RubyGems.org issued before this one is
	// User#generate_api_key, SecureRandom.hex(16): thirty-two lowercase
	// hexadecimal characters with no prefix at all, the migration into the
	// ApiKey table having hashed the value itself. It is not read, and
	// builtin_rubygems_api_key.go says why — it is an MD5's format exactly, so
	// a pattern reading it would redact every digest in every lock file, cache
	// key and manifest a caller passes through. The decision is pinned here so
	// that reading it is a change somebody argues for rather than one somebody
	// notices afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a key of the format this one replaced",
			src:  "0123456789abcdef0123456789abcdef",
		},
		{
			name: "one in an environment assignment",
			src:  "RUBYGEMS_API_KEY=0123456789abcdef0123456789abcdef",
		},
		{
			name: "one in the credentials file",
			src:  ":rubygems_api_key: 0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RubyGemsAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_RubyGemsAPIKey_theShortExampleTheGuidePrints(t *testing.T) {
	// The one place the RubyGems.org API guide and the code it documents
	// disagree, and the one documented value this pattern declines. The guide
	// writes the prefix with thirty-two hexadecimal digits behind it — forty-one
	// characters — as the response of POST /api/v1/api_key, as the api_key
	// parameter of the PATCH beside it and as the response of the trusted
	// publisher token exchange, and all three of those endpoints build a key
	// with generate_unique_rubygems_key, which is SecureRandom.hex(24) and so
	// forty-eight. builtin_rubygems_api_key.go weighs the two and reads the
	// code.
	//
	// The cases are here so that a reader auditing this pattern against the
	// guide finds the answer rather than the contradiction, and so that the
	// decision moves with the scan: a count read as a floor, or read at
	// thirty-two, would start locating them.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the shortened example",
			src:  "rubygems_0123456789abcdef0123456789abcdef",
		},
		{
			name: "one in the response that prints it",
			src:  `{"rubygems_api_key":"rubygems_0123456789abcdef0123456789abcdef","status":"ok"}`,
		},
		{
			name: "one as the parameter of the patch that updates its scopes",
			src:  "api_key=rubygems_0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RubyGemsAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_rubyGemsAPIKeyPrefix(t *testing.T) {
	// Two things about the prefix are load-bearing, and neither shows anywhere
	// else.
	//
	// It opens with a character no body is written with, and one it carries
	// nowhere else. That is the whole of the claim that no key can begin inside
	// another, which Test_RubyGemsAPIKey_noKeyBeginsInsideAnother drives and
	// which a prefix built any other way would make false without failing
	// there — the drive would pass on a pattern whose spans do overlap
	// somewhere it does not reach.
	//
	// And it closes with a character no body is written with, so a run of body
	// characters can never hold the prefix and every body begins where such a
	// run begins. That is not what bounds the scan — the count is — but it is
	// what a count relaxed to a floor would have to fall back on, which is why
	// it is held to here rather than worked out then.
	if rubyGemsAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}

	opening := rubyGemsAPIKeyPrefix[0]
	if isRubyGemsAPIKeyBodyByte(opening) {
		t.Errorf("the prefix opens with %q, which a body may be written with", opening)
	}
	if i := strings.IndexByte(rubyGemsAPIKeyPrefix[1:], opening); i >= 0 {
		t.Errorf("the prefix carries %q again at %d, so a prefix can open inside one", opening, i+1)
	}
	if c := rubyGemsAPIKeyPrefix[len(rubyGemsAPIKeyPrefix)-1]; isRubyGemsAPIKeyBodyByte(c) {
		t.Errorf("the prefix closes with %q, which a body may be written with", c)
	}
}

func Test_rubyGemsAPIKeyChars(t *testing.T) {
	// Fifty-seven is what the count comes to with the prefix in front of it,
	// and what both of the long examples in the RubyGems.org guides are. The
	// count itself is Ruby's — SecureRandom.hex(24) is documented as twice its
	// argument — so this is what holds the two to still totalling the length a
	// published key has.
	const documented = 57
	if rubyGemsAPIKeyChars != documented {
		t.Errorf("a key is read as %d characters, the documented example is %d", rubyGemsAPIKeyChars, documented)
	}
}

func Test_isRubyGemsAPIKeyBodyByte(t *testing.T) {
	// The lowercase hexadecimal digits and nothing else, stated over every byte
	// rather than by example. The uppercase half is not admitted where the
	// Grafana checksum's class admits it, which builtin_rubygems_api_key.go
	// weighs.
	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9' || 'a' <= b && b <= 'f'
		if got := isRubyGemsAPIKeyBodyByte(b); got != want {
			t.Errorf("isRubyGemsAPIKeyBodyByte(%q) = %v, want %v", b, got, want)
		}
	}
}

func Test_isRubyGemsAPIKeyBody(t *testing.T) {
	// The count and the character class together, stated over every byte rather
	// than by example.
	body := strings.Repeat("a", rubyGemsAPIKeyBodyChars)

	if !isRubyGemsAPIKeyBody(body) {
		t.Errorf("isRubyGemsAPIKeyBody(%q) = false, want a body of %d characters to be one", body, rubyGemsAPIKeyBodyChars)
	}
	for _, s := range []string{body[:len(body)-1], body + "a"} {
		if isRubyGemsAPIKeyBody(s) {
			t.Errorf("isRubyGemsAPIKeyBody(%q) = true, want only %d characters to be a body", s, rubyGemsAPIKeyBodyChars)
		}
	}

	for i := range rubyGemsAPIKeyBodyChars {
		for c := range 256 {
			b := byte(c)
			src := body[:i] + string([]byte{b}) + body[i+1:]
			if got, want := isRubyGemsAPIKeyBody(src), isRubyGemsAPIKeyBodyByte(b); got != want {
				t.Errorf("isRubyGemsAPIKeyBody(%q) = %v with %q at %d, want %v", src, got, b, i, want)
			}
		}
	}
}

// referenceRubyGemsAPIKey is the expression the scan in
// builtin_rubygems_api_key.go reads by hand: the statement of what a RubyGems
// API key is, kept here so that the scan can be held to it.
//
// The prefix, the count and the character class are spelled again rather than
// built from rubyGemsAPIKeyPrefix, rubyGemsAPIKeyBodyChars and
// isRubyGemsAPIKeyBodyByte. A reference sharing those declarations could not
// disagree with the scan about them, and it is exactly that disagreement the
// fuzz target below is for: the two have to be changed together or reported
// apart.
//
// The counted repetition here is exact, so the machine an engine builds for a
// candidate is forty-eight states wide and is read once and stops, and the
// prefix in front of it is one literal, which is what an engine searches the
// text for. That is what lets this reference be an expression at all, where the
// Anthropic one is written out for a floor spelled as a counted repetition and
// the Notion one for an alternation of two literals.
var referenceRubyGemsAPIKey = regexp.MustCompile(`rubygems_[0-9a-f]{48}`)

// referenceRubyGemsAPIKeyFind locates keys the plain way: the leftmost match of
// the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// Every position is a starting point in its own right, a match included. No key
// can begin inside the span of another here, which builtin_rubygems_api_key.go
// sets out and Test_RubyGemsAPIKey_noKeyBeginsInsideAnother drives, so nothing
// turns on asking at a position a match already covers — but the reference is
// written to know nothing the scan claims, and where the scan resumes is one of
// the things the target below is for. FindAllStringIndex would be the shorter
// way to write this and would be that claim written into the reference.
//
// As in the AWS, Google, SendGrid, Notion and Grafana references, resuming a
// byte along costs this one nothing beyond a constant: every candidate reads at
// most fifty-seven characters, here as in the scan, so neither has a run to
// walk and there is no cursor for either to be wrong about.
func referenceRubyGemsAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceRubyGemsAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzRubyGemsAPIKey_matchesReference guards the hand-written scan: the prefix
// it searches for, the count it reads behind that prefix, the character class
// it reads it in and the byte it resumes at may none of them change which keys
// are located.
func FuzzRubyGemsAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("RUBYGEMS_API_KEY=rubygems_0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("rubygems_0123456789abcdef0123456789abcdef0123456789abcde")    // a body one short
	f.Add("rubygems_0123456789abcdef0123456789abcdef0123456789abcdef0")  // and a run one long
	f.Add("rubygems_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")   // an uppercase body
	f.Add("rubygems_0123456789abcdef0123456789abcdef0123456789abcdeg")   // a letter past f
	f.Add("rubygems_0123456789abcdef_123456789abcdef0123456789abcdef0")  // an underscore inside the body
	f.Add("rubygems_0123456789abcdef-123456789abcdef0123456789abcdef0")  // and a hyphen
	f.Add("rubygems-0123456789abcdef0123456789abcdef0123456789abcdef")   // a hyphen where the prefix carries its underscore
	f.Add("RUBYGEMS_0123456789abcdef0123456789abcdef0123456789abcdef")   // an uppercase prefix
	f.Add("rubygems_0123456789abcdef\n123456789abcdef0123456789abcdef0") // a key broken by a line break
	f.Add("xrubygems_0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add(":rubygems_api_key: rubygems_0123456789abcdef0123456789abcdef0123456789abcdef")
	// A digest behind the prefix at each of the three lengths one is written
	// at: two the count turns away, and the one it reads the front of.
	f.Add("rubygems_0123456789abcdef0123456789abcdef")
	f.Add("rubygems_0123456789abcdef0123456789abcdef01234567")
	f.Add("rubygems_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// A prefix in front of a key, which a scan resuming past the length a
	// candidate hoped for steps over, and two keys with nothing between them.
	f.Add("rubygems_rubygems_0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("rubygems_0123456789abcdef0123456789abcdef0123456789abcdefrubygems_0123456789abcdef0123456789abcdef0123456789abcdef")
	// Candidate positions crowded as close as they can be, and a run of body
	// characters long enough to hold one, which is where the count is decided.
	f.Add(strings.Repeat("rubygems_", 32))
	f.Add(strings.Repeat("rubygems_", 32) + strings.Repeat("0123456789abcdef", 3))
	f.Add(strings.Repeat("rubygems_0123456789abcdef0123456789abcdef0123456789abcdef", 8))
	f.Add(strings.Repeat("0123456789abcdef", 16))
	f.Add(strings.Repeat("_", 128))
	// The key format this one replaced, which is thirty-two hexadecimal
	// characters and no prefix.
	f.Add("RUBYGEMS_API_KEY=0123456789abcdef0123456789abcdef")
	// The forty-one character example the RubyGems.org API guide prints, which
	// is the prefix with a body of the length the format it replaced had.
	f.Add("rubygems_0123456789abcdef0123456789abcdef")

	fuzzAgainstReference(f, RubyGemsAPIKey().Find, referenceRubyGemsAPIKeyFind)
}

// rubyGemsAPIKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func rubyGemsAPIKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://rubygems.org/api/v1/gems.json `
	key := "rubygems_" + strings.Repeat("0123456789abcdef", 3)

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is nine characters, so a run of them holds a candidate
			// for every nine it has. Each is turned away by the first byte of
			// the body it never had, since the r opening the next prefix is not
			// one a body may hold — which is the cheapest this scan declines a
			// candidate for.
			name:  "candidates that are not values",
			src:   strings.Repeat("rubygems_", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: a body of the right length whose
			// last character is a letter past f, so the whole of it is walked
			// before the candidate is turned away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("rubygems_0123456789abcdef0123456789abcdef0123456789abcdeg ", 16),
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
