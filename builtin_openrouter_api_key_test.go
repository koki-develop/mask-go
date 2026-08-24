package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The OpenRouter API key pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. The body is 0123456789abcdef written four times,
// which is the sixty-four hexadecimal digits the pattern reads it at, and with
// the prefix in front of it that is the seventy-three characters the example in
// OpenRouter's own documentation is.

func Test_OpenRouterAPIKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 73}},
		},
		{
			name: "a key in an environment assignment",
			src:  "OPENROUTER_API_KEY=sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{19, 92}},
		},
		{
			// The body is hexadecimal, read in either case for the reason
			// builtin_openrouter_api_key.go gives, where every key OpenRouter
			// has printed is lowercase.
			name: "an uppercase body",
			src:  "sk-or-v1-0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: []Span{{0, 73}},
		},
		{
			// The count is read exactly, so what follows the seventy-third
			// character is not part of the key and stays in the text.
			name: "a body run longer than the count is a key and what follows it",
			src:  "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
			want: []Span{{0, 73}},
		},
		{
			// Neither key is inside the other, and nothing separates them.
			name: "two keys with nothing between them",
			src:  "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefsk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 73}, {73, 146}},
		},
		{
			// A candidate whose body opens with a prefix of its own. The outer
			// one is turned away at its first character, which is an s and so
			// no hexadecimal digit, and the scan resuming at the body finds the
			// inner one where it stands.
			name: "a candidate whose body opens with a prefix",
			src:  "sk-or-v1-sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{9, 82}},
		},
		{
			// The one shape a word boundary in front would turn away, and what
			// it would cost is the environment assignment above. The prefix
			// closes with a hyphen rather than with a letter, so no snake_case
			// name reaches it; a hyphenated word whose segments are risk, or
			// and v1 does, and then sixty-four hexadecimal digits have to
			// follow.
			name: "a hyphenated word closing on the prefix",
			src:  "risk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{2, 75}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OpenRouterAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OpenRouterAPIKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "sk-or-v1-",
		},
		{
			name: "a body one character short",
			src:  "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// Sixty-three hexadecimal digits and then a letter past f, which is
			// the count reached with the class failing at its last character.
			name: "a letter past f at the end of the body",
			src:  "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
		},
		{
			name: "an uppercase letter past F at the end of the body",
			src:  "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeG",
		},
		{
			// Neither character base64url adds beyond the digits and letters is
			// hexadecimal, so neither may stand in a body however much of the
			// prefix is written with one.
			name: "a hyphen inside the body",
			src:  "sk-or-v1-0123456789abcdef-123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "an underscore inside the body",
			src:  "sk-or-v1-0123456789abcdef_123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a key broken by a space",
			src:  "sk-or-v1-0123456789abcdef0123456789 abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a key broken by a line break",
			src:  "sk-or-v1-0123456789abcdef0123456789\nabcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "an uppercase prefix",
			src:  "SK-OR-V1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The version segment is what the count is read exactly on the
			// strength of: a shape that is not this one is written behind a
			// prefix that is not this one, and this pattern locates it nowhere.
			name: "a later version of the prefix",
			src:  "sk-or-v2-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "the version left out of the prefix",
			src:  "sk-or-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "underscores where the prefix carries its hyphens",
			src:  "sk_or_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// Sixty-four hexadecimal digits of the right count behind something
			// else. The prefix is the whole of the anchor.
			name: "a value of the right shape opening with no prefix",
			src:  "xx-xx-xx-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The prefix an OpenAI project key opens with, which shares sk-
			// with this one and nothing else. What follows it here is a body of
			// this pattern's count, and it is still located nowhere.
			name: "an openai prefix in front of a body of the right count",
			src:  "sk-proj-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// The prefix closes with a hyphen and holds two more, so what could
			// reach it is a hyphenated word rather than a snake_case name — and
			// only one spelled with these segments in this order.
			name: "a hyphenated word whose segments are nearly the prefix",
			src:  "sk-or-v-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OpenRouterAPIKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_OpenRouterAPIKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "OPENROUTER_API_KEY=sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "OPENROUTER_API_KEY=*************************************************************************",
		},
		{
			// How a key reaches the API, and how it reaches a log line that
			// echoed the header.
			name: "a bearer token header",
			src:  "Authorization: Bearer sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "Authorization: Bearer *************************************************************************",
		},
		{
			// The response a key is first read out of, which OpenRouter's own
			// documentation says is the only place it is ever shown whole.
			name: "the response that first reports it",
			src:  `{"key":"sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","data":{"label":"sk-or-v1-abc...123"}}`,
			want: `{"key":"*************************************************************************","data":{"label":"sk-or-v1-abc...123"}}`,
		},
		{
			name: "a command line",
			src:  "curl -H 'Authorization: Bearer sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' https://openrouter.ai/api/v1/key",
			want: "curl -H 'Authorization: Bearer *************************************************************************' https://openrouter.ai/api/v1/key",
		},
		{
			name: "twice",
			src:  "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef sk-or-v1-0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want: "************************************************************************* *************************************************************************",
		},
	}

	m := New(WithPatterns(OpenRouterAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OpenRouterAPIKey_nextToWordCharacters(t *testing.T) {
	// A word boundary either side of the pattern would not trim these matches
	// but drop them, letting the key through whole — and here that is a
	// disagreement with every ruleset reading this format, since all three
	// write one at both ends. The first two are what the demand would cost.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "letter before",
			src:  "xsk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "x*************************************************************************",
		},
		{
			name: "underscore before",
			src:  "OPENROUTER_API_KEY_sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "OPENROUTER_API_KEY_*************************************************************************",
		},
		{
			// The far side of the same choice, and the one that costs
			// something. A boundary behind the match would drop this key rather
			// than trim it; without one the seventy-three characters OpenRouter
			// issued are redacted and the one written after them, which is part
			// of no credential, stays in the text.
			name: "a character of the body's class after",
			src:  "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
			want: "*************************************************************************0",
		},
	}

	m := New(WithPatterns(OpenRouterAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OpenRouterAPIKey_leavesWhatFollowsAlone(t *testing.T) {
	// A key is seventy-three characters and no more, so what is written after
	// one stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the key is sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.",
			want: "the key is *************************************************************************.",
		},
		{
			name: "quoted",
			src:  `"sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`,
			want: `"*************************************************************************"`,
		},
		{
			name: "dashed word",
			src:  "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef-suffix",
			want: "*************************************************************************-suffix",
		},
		{
			name: "underscored word",
			src:  "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef_tail",
			want: "*************************************************************************_tail",
		},
		{
			// A letter past f ends nothing here — the count has already ended
			// the key — so a word written straight against one comes through.
			name: "a word written against a key",
			src:  "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefsuffix",
			want: "*************************************************************************suffix",
		},
	}

	m := New(WithPatterns(OpenRouterAPIKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OpenRouterAPIKey_aDigestBehindThePrefix(t *testing.T) {
	// The collision every prefix in this package leaves is a digest written
	// behind it, and here the count is a SHA-256's count exactly, so the shape
	// this pattern reads and the shape a digest is are the same shape.
	// builtin_openrouter_api_key.go pays it rather than avoiding it: a key
	// OpenRouter issued is sixty-four hexadecimal digits behind this prefix, so
	// a scan declining a digest behind this prefix declines every key there is.
	// Where the Grafana format has an underscore dividing its secret from its
	// checksum to turn a digest away with, this one has nothing.
	//
	// The keys the rest of this file is written with are exactly that shape,
	// which is why the decision is pinned here rather than left to be read off
	// them.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// Sixty-four hexadecimal characters, which is a body exactly.
			name: "a sha-256 behind the prefix",
			src:  "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 73}},
		},
		{
			// Forty characters, which is twenty-four short of a body.
			name: "a sha-1 behind the prefix",
			src:  "sk-or-v1-0123456789abcdef0123456789abcdef01234567",
		},
		{
			// Thirty-two, which is thirty-two short.
			name: "an md5 behind the prefix",
			src:  "sk-or-v1-0123456789abcdef0123456789abcdef",
		},
		{
			// A digest carries no hyphen, so it holds no prefix to be found at
			// however long it runs.
			name: "a digest on its own",
			src:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OpenRouterAPIKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_OpenRouterAPIKey_noKeyBeginsInsideAnother(t *testing.T) {
	// The claim builtin_openrouter_api_key.go makes: the spans of this pattern
	// never overlap one another. A candidate begins where an s begins, and the
	// only s a span covers is the one its prefix opens with — the rest of the
	// prefix is k, o, r, v, a digit and three hyphens, and a body is hexadecimal.
	//
	// It is what lets the scan resume at the body of a candidate rather than a
	// byte past its start, and it is not a claim one input can state, so the
	// prefix is written into a key at every place it could reach: against the
	// end of a body, where a body begins, inside a body, and against a body one
	// character short so that the outer candidate is rejected and the inner is
	// all there is.
	const (
		prefix = "sk-or-v1-"
		body   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)
	p := OpenRouterAPIKey()

	for _, src := range []string{
		prefix + body + prefix + body,
		prefix + prefix + body,
		prefix + body[:len(body)-1] + prefix + body,
		prefix + body[:32] + prefix + body,
		prefix + body + "-" + prefix + body,
		strings.Repeat(prefix, 8) + body,
	} {
		spans := p.Find(src)
		for i, got := range spans {
			if i > 0 && got.Start < spans[i-1].End {
				t.Errorf("Find(%q) = %v, which holds two values overlapping", src, spans)
				break
			}
		}
	}
}

func Test_OpenRouterAPIKey_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor, and what holds it linear is the count being a
	// count: a candidate reads at most seventy-three bytes and stops. The AWS,
	// Google, SendGrid, Notion and Grafana scans reach it the same way. These
	// are the inputs that would find it wrong here — a line that is nothing but
	// prefixes, a line that is nothing but keys, and a single hexadecimal run
	// as long as the line, which is where a scan reading a run instead of a
	// count would show itself.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// whole body apiece and so hold a candidate every seventy-three bytes at
	// their densest. The crowding a line can actually carry, a candidate every
	// nine, stays here.
	sources := map[string]string{
		// A candidate every nine characters, each rejected at the first
		// character of its body, which is the s the next prefix opens with.
		"a candidate every nine characters": strings.Repeat("sk-or-v1-", 250000),
		// The same crowding with a whole key at each candidate, so every one of
		// them reads sixty-four characters and reports a span.
		"a key every seventy-three characters": strings.Repeat("sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 30000),
		// A candidate walked to its last character before the class turns it
		// away, which is the most a rejected candidate can cost.
		"a candidate walked to its last character": strings.Repeat("sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg ", 30000),
		// One candidate whose body is the whole line. The count stops it at
		// sixty-four characters; a scan reading the run would read two mebibytes.
		"a hexadecimal run the length of the line": "sk-or-v1-" + strings.Repeat("a", 2000000),
		// The same run with no prefix in front of it, so no candidate is found
		// in it at all.
		"a hexadecimal run with no prefix": strings.Repeat("a", 2000000),
	}

	m := New(WithPatterns(OpenRouterAPIKey()))
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

func Test_openRouterAPIKeyPrefix(t *testing.T) {
	// The scan resumes at the body of a candidate rather than a byte past its
	// start, and the claim that this steps over nothing rests on two properties
	// of the prefix: it opens with a character no body is written with, so a
	// body cannot open a candidate, and that character stands nowhere else in
	// it, so a prefix cannot open inside a prefix. A prefix built any other way
	// would make the two able to nest, the resumption would step over a key,
	// and Test_OpenRouterAPIKey_noKeyBeginsInsideAnother would be pinning
	// something that is no longer true — which is not a failure anything else
	// here reports.
	if openRouterAPIKeyPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	if isOpenRouterAPIKeyBodyByte(openRouterAPIKeyPrefix[0]) {
		t.Errorf("the prefix opens with %q, which a body may be written with", openRouterAPIKeyPrefix[0])
	}
	if i := strings.IndexByte(openRouterAPIKeyPrefix[1:], openRouterAPIKeyPrefix[0]); i >= 0 {
		t.Errorf("the prefix carries %q again at %d, so a candidate can begin inside one", openRouterAPIKeyPrefix[0], i+1)
	}
}

func Test_openRouterAPIKeyChars(t *testing.T) {
	// Seventy-three is what the count comes to with the prefix in front of it,
	// and what the example in OpenRouter's own documentation is. The count
	// itself is read behind the prefix, so this is what holds the two together
	// to still totalling the length of a printed key.
	const documented = 73
	if openRouterAPIKeyChars != documented {
		t.Errorf("a key is read as %d characters, the documented example is %d", openRouterAPIKeyChars, documented)
	}
}

func Test_isOpenRouterAPIKeyBodyByte(t *testing.T) {
	// The hexadecimal digits and nothing else, stated over every byte rather
	// than by example. Either case is admitted where every published key is
	// lowercase alone, which builtin_openrouter_api_key.go weighs.
	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9' || 'a' <= b && b <= 'f' || 'A' <= b && b <= 'F'
		if got := isOpenRouterAPIKeyBodyByte(b); got != want {
			t.Errorf("isOpenRouterAPIKeyBodyByte(%q) = %v, want %v", b, got, want)
		}
	}
}

func Test_isOpenRouterAPIKeyBody(t *testing.T) {
	// The count and the character class together, stated over every byte rather
	// than by example.
	body := strings.Repeat("a", openRouterAPIKeyBodyChars)

	if !isOpenRouterAPIKeyBody(body) {
		t.Errorf("isOpenRouterAPIKeyBody(%q) = false, want a body of %d characters to be one", body, openRouterAPIKeyBodyChars)
	}
	for _, s := range []string{body[:len(body)-1], body + "b"} {
		if isOpenRouterAPIKeyBody(s) {
			t.Errorf("isOpenRouterAPIKeyBody(%q) = true, want only %d characters to be a body", s, openRouterAPIKeyBodyChars)
		}
	}

	for i := range openRouterAPIKeyBodyChars {
		for c := range 256 {
			b := byte(c)
			src := body[:i] + string([]byte{b}) + body[i+1:]

			want := isOpenRouterAPIKeyBodyByte(b)
			if got := isOpenRouterAPIKeyBody(src); got != want {
				t.Errorf("isOpenRouterAPIKeyBody(%q) = %v with %q at %d, want %v", src, got, b, i, want)
			}
		}
	}
}

// referenceOpenRouterAPIKey is the expression the scan in
// builtin_openrouter_api_key.go reads by hand: the statement of what an
// OpenRouter API key is, kept here so that the scan can be held to it.
//
// The prefix, the count and the character class are spelled again rather than
// built from openRouterAPIKeyPrefix, openRouterAPIKeyBodyChars and
// isOpenRouterAPIKeyBodyByte. A reference sharing those declarations could not
// disagree with the scan about them, and it is exactly that disagreement the
// fuzz target below is for: the two have to be changed together or reported
// apart.
//
// The counted repetition here is exact, so the machine an engine builds for a
// candidate is sixty-four states wide and is read once, and the prefix in front
// of it is one literal, which is what an engine searches the text for. That is
// what lets this reference be an expression at all, where the Anthropic one is
// written out for a floor spelled as a counted repetition and the Notion one
// for an alternation of two literals.
var referenceOpenRouterAPIKey = regexp.MustCompile(`sk-or-v1-[0-9A-Fa-f]{64}`)

// referenceOpenRouterAPIKeyFind locates keys the plain way: the leftmost match
// of the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// It starts afresh at every byte, which is more than the scan does — the scan
// resumes at the body of a candidate, nine characters along, on the strength of
// no key being writable inside another. That claim is the scan's and this
// reference is written to know nothing of it, so a key nested inside another is
// one this would report and the scan would not, and the fuzz target below is
// what holds the two together. It is the Stripe reference's arrangement, and it
// is here for the Stripe reference's reason.
//
// Resuming a byte along costs this one nothing beyond a constant, as it costs
// the AWS, Google, SendGrid, Notion and Grafana references nothing: every
// candidate reads at most seventy-three characters, here as in the scan, so
// neither has a run to walk and there is no cursor for either to be wrong
// about.
func referenceOpenRouterAPIKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceOpenRouterAPIKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzOpenRouterAPIKey_matchesReference guards the hand-written scan: the
// prefix it searches for, the count it reads behind that prefix, the character
// class it reads it in and the byte it resumes at may none of them change which
// keys are located.
func FuzzOpenRouterAPIKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("OPENROUTER_API_KEY=sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("sk-or-v1-0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")  // an uppercase body
	f.Add("sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")   // a body one short
	f.Add("sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0") // and a run longer than one
	f.Add("sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg")  // a letter past f at the end
	f.Add("sk-or-v1-0123456789abcdef-123456789abcdef0123456789abcdef0123456789abcdef")  // a hyphen inside the body
	f.Add("sk-or-v1-0123456789abcdef_123456789abcdef0123456789abcdef0123456789abcdef")  // and an underscore
	f.Add("SK-OR-V1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")  // an uppercase prefix
	f.Add("sk-or-v2-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")  // a later version
	f.Add("sk-or-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")     // the version left out
	f.Add("sk-or-v1-0123456789abcdef0123456789\nabcdef0123456789abcdef0123456789abcdef")
	f.Add("xsk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("risk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// A digest behind the prefix, which is a body exactly, and the two shorter
	// digests that are not.
	f.Add("sk-or-v1-0123456789abcdef0123456789abcdef01234567")
	f.Add("sk-or-v1-0123456789abcdef0123456789abcdef")
	// The prefix written where a key could hold one, which is what the scan
	// resuming at the body rather than a byte along has to step over nothing
	// of, and two keys with nothing between them.
	f.Add("sk-or-v1-sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("sk-or-v1-0123456789abcdef0123456789abcdefsk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefsk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	// Candidate positions crowded as close as they can be, a run of hyphens,
	// and a hexadecimal run with no prefix in front of it.
	f.Add(strings.Repeat("sk-or-v1-", 32))
	f.Add(strings.Repeat("sk-or-v1-", 32) + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add(strings.Repeat("-", 128))
	f.Add(strings.Repeat("0123456789abcdef", 16))
	// The two keys beside this one that also open sk-, neither of which this
	// pattern reads.
	f.Add("sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef")
	f.Add("sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")

	fuzzAgainstReference(f, OpenRouterAPIKey().Find, referenceOpenRouterAPIKeyFind)
}

// openRouterAPIKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func openRouterAPIKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://openrouter.ai/api/v1/chat/completions `
	key := "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is nine characters, so a run of them holds a candidate
			// for every nine it has. Each is turned away at the first character
			// of its body, which is the s the next prefix opens with, and that
			// is the cheapest this scan declines a candidate for.
			name:  "candidates that are not values",
			src:   strings.Repeat("sk-or-v1-", 512),
			spans: 0,
		},
		{
			// The other way a candidate fails: sixty-three hexadecimal digits
			// and then a letter past f, so the whole of the body is walked
			// before its last character turns the candidate away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg ", 16),
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
