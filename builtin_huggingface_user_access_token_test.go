package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Hugging Face user access token pattern: what it locates and what it
// leaves alone, written out case by case, and the reference its scan is held
// to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a set
// of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. A body is thirty-four letters and digits, written
// here as 0123456789abcdef twice and then 01, which with the prefix in front
// comes to thirty-seven characters.

func Test_HuggingFaceUserAccessToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  "hf_0123456789abcdef0123456789abcdef01",
			want: []Span{{0, 37}},
		},
		{
			name: "a token in an environment assignment",
			src:  "HF_TOKEN=hf_0123456789abcdef0123456789abcdef01",
			want: []Span{{9, 46}},
		},
		{
			// The count is read exactly, so what follows the thirty-seventh
			// character is not part of the token and stays in the text.
			name: "a run longer than the count is a token and what follows it",
			src:  "hf_0123456789abcdef0123456789abcdef012",
			want: []Span{{0, 37}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "hf_0123456789abcdef0123456789abcdef01hf_0123456789abcdef0123456789abcdef01",
			want: []Span{{0, 37}, {37, 74}},
		},
		{
			// The alphabet is the letters of both cases with the digits, so the
			// bodies written out here carry both. The narrower class the
			// rationale declines would leave every one of them in the output
			// whole.
			name: "an uppercase body",
			src:  "hf_0123456789ABCDEF0123456789ABCDEF01",
			want: []Span{{0, 37}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HuggingFaceUserAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HuggingFaceUserAccessToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "hf_",
		},
		{
			name: "a body one character short",
			src:  "hf_0123456789abcdef0123456789abcdef0",
		},
		{
			name: "a body broken by a space",
			src:  "hf_0123456789abcdef 123456789abcdef01",
		},
		{
			name: "a hyphen in the body",
			src:  "hf_0123456789abcdef-123456789abcdef01",
		},
		{
			name: "an underscore in the body",
			src:  "hf_0123456789abcdef_123456789abcdef01",
		},
		{
			name: "a character outside the alphabet in the body",
			src:  "hf_0123456789abcdef.123456789abcdef01",
		},
		{
			// The case the environment variable holding a token is spelled in,
			// which is the reason the prefix is read in one case.
			name: "an uppercase prefix",
			src:  "HF_0123456789abcdef0123456789abcdef01",
		},
		{
			name: "the prefix with its first letter capitalised",
			src:  "Hf_0123456789abcdef0123456789abcdef01",
		},
		{
			name: "the prefix with its second letter capitalised",
			src:  "hF_0123456789abcdef0123456789abcdef01",
		},
		{
			name: "the prefix without its closing underscore",
			src:  "hf0123456789abcdef0123456789abcdef012",
		},
		{
			name: "a hyphen where the prefix closes",
			src:  "hf-0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a hyphen at the first character of the body",
			src:  "hf_-123456789abcdef0123456789abcdef01",
		},
		{
			name: "an underscore at the first character of the body",
			src:  "hf__123456789abcdef0123456789abcdef01",
		},
		{
			name: "a hyphen at the last character of the body",
			src:  "hf_0123456789abcdef0123456789abcdef0-",
		},
		{
			name: "a space at the last character of the body",
			src:  "hf_0123456789abcdef0123456789abcdef0 ",
		},
		{
			// The OAuth access token an application receives, whose body opens
			// on a word the underscore behind it ends.
			name: "an oauth access token",
			src:  "hf_oauth_0123456789abcdef0123456789abcdef01",
		},
		{
			// The organization API token Hugging Face deprecated, which carries
			// a prefix of its own and no hf_ to be found at.
			name: "an organization api token",
			src:  "api_org_0123456789abcdef0123456789abcdef01",
		},
		{
			name: "a body of the right shape opening with no prefix",
			src:  "xxx0123456789abcdef0123456789abcdef01",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "a log line",
			src:  `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://huggingface.co/api/whoami-v2`,
		},
		{
			name: "a hugging face environment variable holding a path",
			src:  "HF_HUB_CACHE=/var/cache/huggingface/hub",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HuggingFaceUserAccessToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_HuggingFaceUserAccessToken_inContext(t *testing.T) {
	// The places a token is written, which are the places Hugging Face's own
	// documentation puts one: the environment the libraries read it from, the
	// argument they take it as, the bearer header a request carries it in and
	// the credential a git remote is cloned with.
	const token = "hf_0123456789abcdef0123456789abcdef01"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token in a dotenv line",
			src:  "HF_TOKEN=" + token,
			want: []Span{{9, 9 + len(token)}},
		},
		{
			name: "a token in a python argument",
			src:  `AutoModel.from_pretrained("private/model", token="` + token + `")`,
			want: []Span{{50, 50 + len(token)}},
		},
		{
			name: "a token in a bearer token header",
			src:  "Authorization: Bearer " + token,
			want: []Span{{22, 22 + len(token)}},
		},
		{
			name: "a token on a command line",
			src:  "hf auth login --token " + token,
			want: []Span{{22, 22 + len(token)}},
		},
		{
			name: "a token in a git remote",
			src:  "https://user:" + token + "@huggingface.co/org/model",
			want: []Span{{13, 13 + len(token)}},
		},
		{
			name: "a token in the body a revocation call posts",
			src:  `{"credentials":["` + token + `"]}`,
			want: []Span{{17, 17 + len(token)}},
		},
		{
			name: "a token at the end of a sentence",
			src:  "the token is " + token + ".",
			want: []Span{{13, 13 + len(token)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HuggingFaceUserAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HuggingFaceUserAccessToken_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match. A word boundary in front
	// would drop the whole match rather than trim it wherever a token is
	// written against a word character, and one behind it would drop a token
	// followed by a letter or a digit.
	const token = "hf_0123456789abcdef0123456789abcdef01"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token after an underscore",
			src:  "HUGGINGFACE_TOKEN_" + token,
			want: []Span{{18, 18 + len(token)}},
		},
		{
			name: "a token after a letter",
			src:  "x" + token,
			want: []Span{{1, 1 + len(token)}},
		},
		{
			name: "a word written against a token",
			src:  token + "suffix",
			want: []Span{{0, len(token)}},
		},
		{
			name: "a hyphenated word written against a token",
			src:  token + "-suffix",
			want: []Span{{0, len(token)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HuggingFaceUserAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HuggingFaceUserAccessToken_nextToNonASCIIAndInvalidBytes(t *testing.T) {
	// A token is located wherever it is written, with no word boundary either
	// side, and neither a multi-byte rune nor an invalid UTF-8 byte belongs to
	// the alphabet a prefix or a body is read in — so both leave a token's
	// span exactly where it would otherwise be.
	const token = "hf_0123456789abcdef0123456789abcdef01"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token between japanese",
			src:  "日本語" + token + "日本語",
			want: []Span{{9, 9 + len(token)}},
		},
		{
			name: "a token after an invalid byte",
			src:  "\xff" + token,
			want: []Span{{1, 1 + len(token)}},
		},
		{
			name: "a token before an invalid byte",
			src:  token + "\xff",
			want: []Span{{0, len(token)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HuggingFaceUserAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

// Test_HuggingFaceUserAccessToken_theBytesJustOutsideTheAlphabet drives a byte
// the alphabet forbids at the front of a body and at its last character, with
// a run of the alphabet otherwise long enough to be one either side of it.
// builtins_test.go's generic properties never place such a byte there: every
// input they build from a sample is a whole sample or a prefix of one, so a
// candidate's body is either entirely valid or cut off, and never wrong at one
// specific character away from the ones already written out above.
func Test_HuggingFaceUserAccessToken_theBytesJustOutsideTheAlphabet(t *testing.T) {
	// A body of thirty-four valid characters, the same run every other case in
	// this file is built from.
	const validBody = "0123456789abcdef0123456789abcdef01"

	forbidden := []byte{'/', ':', '@', '[', '`', '{'}

	for _, c := range forbidden {
		front := "hf_" + string(c) + validBody[1:]
		t.Run("at the front of the body: "+string(c), func(t *testing.T) {
			if got, _ := HuggingFaceUserAccessToken().Find(front); got != nil {
				t.Errorf("Find(%q) = %v, want no span", front, got)
			}
		})

		back := "hf_" + validBody[:len(validBody)-1] + string(c)
		t.Run("at the last character of the body: "+string(c), func(t *testing.T) {
			if got, _ := HuggingFaceUserAccessToken().Find(back); got != nil {
				t.Errorf("Find(%q) = %v, want no span", back, got)
			}
		})
	}
}

// Test_HuggingFaceUserAccessToken_holdsATokenTheInputCutShort holds what
// builtin_huggingface_user_access_token.go settles for a candidate the end of
// the input cut short: its own start, since the count is exact and is the
// whole of what tells a token from any other run behind the prefix. A piece
// of the prefix with nothing else behind it settles at its own start as well,
// which is prefixTail's to report. Where no candidate stands open at all, the
// whole of the input is settled.
func Test_HuggingFaceUserAccessToken_holdsATokenTheInputCutShort(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a body one character short of the count",
			src:  "hf_0123456789abcdef0123456789abcdef0",
		},
		{
			name: "a piece of the prefix",
			src:  "hf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spans, retain := HuggingFaceUserAccessToken().Find(tt.src)
			if spans != nil {
				t.Fatalf("Find(%q) = %v, want no span", tt.src, spans)
			}
			if retain != 0 {
				t.Errorf("Find(%q) settled from %d, want 0", tt.src, retain)
			}
		})
	}

	t.Run("no candidate at all", func(t *testing.T) {
		src := "there is no credential in this sentence"
		spans, retain := HuggingFaceUserAccessToken().Find(src)
		if spans != nil {
			t.Fatalf("Find(%q) = %v, want no span", src, spans)
		}
		if retain != len(src) {
			t.Errorf("Find(%q) settled from %d, want %d", src, retain, len(src))
		}
	})
}

func Test_HuggingFaceUserAccessToken_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor and needs none: a candidate reads at most
	// thirty-four bytes and stops, which bounds what it reads with no state to
	// be wrong about. The generic guard in builtins_test.go repeats the
	// samples, and the crowding a whole line of anchors or prefixes can carry
	// stays here.
	sources := map[string]string{
		// The anchor at every byte, each turned away by the two characters in
		// front of it not spelling the rest of the prefix.
		"the anchor at every byte": strings.Repeat("_", 2000000),
		// A whole prefix every three characters, with nothing between them, so
		// every candidate reads thirty-four characters of body and most
		// report nothing.
		"a prefix every three characters": strings.Repeat("hf_", 660000),
		// A prefix every four characters, each followed by a run that fails at
		// its last character before the count is reached.
		"a prefix every four characters with a body that fails last": strings.Repeat("hf_0123456789abcdef0123456789abcdef0.", 54000),
		// A run of the body alphabet carrying no prefix at all.
		"a base62 run with no prefix": strings.Repeat("0123456789abcdef", 125000),
	}

	checkScanIsLinear(t, HuggingFaceUserAccessToken(), sources)
}

func Test_HuggingFaceUserAccessToken_aTokenInsideAToken(t *testing.T) {
	// A token can be written inside another, which is why the scan resumes a
	// byte past the start of a candidate rather than past the candidate: the
	// underscore a candidate is read back from stands past the end of the token
	// it begins inside, so a body closing on hf opens one thirty-five characters
	// in. The spans overlap there, which Masker.locate resolves.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// A body closing on hf, with the underscore that reads it back
			// written after the token that body closes.
			name: "a token beginning at the end of another",
			src:  "hf_0123456789abcdef0123456789abcdefhf_0123456789abcdef0123456789abcdef01",
			want: []Span{{0, 37}, {35, 72}},
		},
		{
			// The same opening with nothing behind it long enough to be a body,
			// so the token in front of it is the one there is.
			name: "a body closing on hf that opens no token",
			src:  "hf_0123456789abcdef0123456789abcdefhf_0123456789",
			want: []Span{{0, 37}},
		},
		{
			// The other of the two positions: a body closing on h, with the f
			// and the underscore written after the token.
			name: "a token beginning at the last character of another",
			src:  "hf_0123456789abcdef0123456789abcdef0hf_0123456789abcdef0123456789abcdef01",
			want: []Span{{0, 37}, {36, 73}},
		},
		{
			// The prefix written where a body would have to hold it. The
			// underscore it closes with is no character a body may carry, so
			// the candidate in front of it ends there and the token is the one
			// that prefix opens.
			name: "a prefix written where a body would stand",
			src:  "hf_0123456789abchf_0123456789abcdef0123456789abcdef01",
			want: []Span{{16, 53}},
		},
		{
			name: "a prefix in front of a token",
			src:  "hf_hf_0123456789abcdef0123456789abcdef01",
			want: []Span{{3, 40}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "hf_0123456789abcdef0123456789abcdef01hf_0123456789abcdef0123456789abcdef01",
			want: []Span{{0, 37}, {37, 74}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HuggingFaceUserAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HuggingFaceUserAccessToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision this format leaves. Thirty-four letters and digits behind
	// the prefix is the vendor's format exactly, so a digest written there is
	// indistinguishable from a token and is redacted for thirty-four of its
	// characters. A digest on its own carries no prefix and reaches nothing.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a sha-1 behind the prefix",
			src:  "hf_0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 37}},
		},
		{
			name: "a sha-256 behind the prefix",
			src:  "hf_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 37}},
		},
		{
			// An MD5 is thirty-two characters, which is two short of a body.
			name: "an md5 behind the prefix",
			src:  "hf_0123456789abcdef0123456789abcdef",
			want: nil,
		},
		{
			name: "a sha-1 on its own",
			src:  "sha1=0123456789abcdef0123456789abcdef01234567",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HuggingFaceUserAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HuggingFaceUserAccessToken_thePrefixInsideBase64URL(t *testing.T) {
	// The other text this format is written by accident. base64url holds the
	// underscore where hexadecimal and standard base64 do not, so a payload
	// written in it carries the prefix where those cannot, and where the
	// thirty-four behind it are letters and digits alone those thirty-seven are
	// a token's format exactly.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "the prefix inside a longer base64url run",
			src:  "payload=zzzzhf_0123456789abcdef0123456789abcdef01zzzz",
			want: []Span{{12, 49}},
		},
		{
			name: "the prefix where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.hf_0123456789abcdef0123456789abcdef01",
			want: []Span{{40, 77}},
		},
		{
			// Standard base64 writes the plus and the slash where base64url
			// writes the hyphen and the underscore, so a payload written in it
			// holds no prefix to be found at however long it runs.
			name: "a standard base64 payload, which carries no underscore",
			src:  "payload=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhf0123456789abcdef",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HuggingFaceUserAccessToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_huggingFaceUserAccessTokenPrefix(t *testing.T) {
	// The prefix is the whole of what tells this format from text, and it
	// closes on a character no body is written with. That is what makes the
	// search cheap on a line holding no token — a run of a body opens no
	// candidate however long it runs — and it is what bounds where a token may
	// begin inside another, which the count below is of.
	if got := huggingFaceUserAccessTokenPrefix; got != "hf_" {
		t.Errorf("huggingFaceUserAccessTokenPrefix = %q, want %q", got, "hf_")
	}
	for i := range len(huggingFaceUserAccessTokenPrefix) {
		c := huggingFaceUserAccessTokenPrefix[i]
		if i == len(huggingFaceUserAccessTokenPrefix)-1 {
			if isBase62Byte(c) {
				t.Errorf("the prefix closes on %q, which a body may be written with", c)
			}
			continue
		}
		if !isBase62Byte(c) {
			t.Errorf("the prefix carries %q at index %d, which a body may not be written with", c, i)
		}
	}

	// Where a token may begin inside another, counted out of the declarations
	// that decide it rather than claimed in prose. A candidate opens where the
	// whole prefix stands, and the underscore that prefix closes with is no
	// character a body carries, so a position inside a span opens one only
	// where that underscore falls past the end of the span. What that leaves is
	// the last two characters of a body, which is what the scan resuming a byte
	// along exists to reach. A prefix lengthened or a count changed moves the
	// number, and nothing else here would report it; a body admitting the
	// underscore would move it as well, and that is what the walk above turns
	// away.
	inside := 0
	for p := 1; p < huggingFaceUserAccessTokenChars; p++ {
		if p+len(huggingFaceUserAccessTokenPrefix)-1 >= huggingFaceUserAccessTokenChars {
			inside++
		}
	}
	if want := 2; inside != want {
		t.Errorf("%d position(s) inside a token can open a candidate, want %d", inside, want)
	}
}

func Test_huggingFaceUserAccessTokenAnchor(t *testing.T) {
	// The byte the scan searches for stands at the index it reads a candidate
	// back from. A prefix or an index changed without the other leaves the scan
	// opening candidates nowhere near where a token begins, and what such a
	// scan finds is nothing at all rather than something wrong.
	if got := huggingFaceUserAccessTokenPrefix[huggingFaceUserAccessTokenAnchorIndex]; got != huggingFaceUserAccessTokenAnchor {
		t.Errorf("huggingFaceUserAccessTokenPrefix[%d] = %q, want the anchor %q",
			huggingFaceUserAccessTokenAnchorIndex, got, huggingFaceUserAccessTokenAnchor)
	}

	// What the anchor costs, counted rather than claimed in prose: it stands
	// once in the prefix, so a line of tokens stops the search once a token,
	// and nowhere in a body, so a run of one stops it not at all.
	if n := strings.Count(huggingFaceUserAccessTokenPrefix, string(huggingFaceUserAccessTokenAnchor)); n != 1 {
		t.Errorf("the anchor stands %d times in %q, want 1", n, huggingFaceUserAccessTokenPrefix)
	}
	if isBase62Byte(huggingFaceUserAccessTokenAnchor) {
		t.Errorf("the anchor %q is a character a body may be written with", huggingFaceUserAccessTokenAnchor)
	}
}

func Test_huggingFaceUserAccessTokenChars(t *testing.T) {
	// The prefix and the body Hugging Face's own expression asks for. Three
	// characters and thirty-four make a token of thirty-seven.
	if got := len(huggingFaceUserAccessTokenPrefix); got != 3 {
		t.Errorf("len(huggingFaceUserAccessTokenPrefix) = %d, want 3", got)
	}
	if got := huggingFaceUserAccessTokenBodyChars; got != 34 {
		t.Errorf("huggingFaceUserAccessTokenBodyChars = %d, want 34", got)
	}
	if got := huggingFaceUserAccessTokenChars; got != 37 {
		t.Errorf("huggingFaceUserAccessTokenChars = %d, want 37", got)
	}
}

// referenceHuggingFaceUserAccessToken is the grammar as a regular expression:
// the prefix Hugging Face writes a token with, the count its own expression
// asks for and the letters and digits that count is read in. Every part of it
// is spelled again rather than read from the scan, so that the two can disagree
// and the target below report it.
//
// It is built on an expression rather than written out because the count is
// exact, so an engine reads its machine once and stops, and because the opening
// is a literal an engine can search the text for rather than a class it would
// have to walk its machine at every byte for.
var referenceHuggingFaceUserAccessToken = regexp.MustCompile(`hf_[0-9A-Za-z]{34}`)

// referenceHuggingFaceUserAccessTokenFind locates tokens the plain way: the
// leftmost match of the expression above, then the leftmost one beginning after
// that match's first byte, over and over, with nothing remembered between them.
//
// Asking at every byte rather than resuming past a match is what the scan does
// and is what a token written inside another needs: a body may close on the
// characters a prefix opens with, so a match can begin thirty-five characters
// into the one before it, and resuming past the first would lose it.
func referenceHuggingFaceUserAccessTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceHuggingFaceUserAccessToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzHuggingFaceUserAccessToken_matchesReference guards the hand-written scan:
// the prefix it searches for, the case it reads that prefix in, the count it
// reads behind it, the alphabet it reads that count in and the byte it resumes
// at may none of them change which tokens are located.
func FuzzHuggingFaceUserAccessToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("HF_TOKEN=hf_0123456789abcdef0123456789abcdef01")
	f.Add("hf_0123456789abcdef0123456789abcdef0")   // a body one character short
	f.Add("hf_0123456789abcdef0123456789abcdef012") // and a run one longer
	f.Add("hf_0123456789abcdef 123456789abcdef01")  // a body broken by a space
	f.Add("hf_0123456789abcdef-123456789abcdef01")  // a hyphen in the body
	f.Add("hf_0123456789abcdef_123456789abcdef01")  // an underscore in the body
	f.Add("hf_0123456789abcdef.123456789abcdef01")  // a character outside the alphabet
	f.Add("hf_0123456789abcdef\n123456789abcdef01")
	f.Add("hf_0123456789ABCDEF0123456789ABCDEF01") // an uppercase body
	f.Add("HF_0123456789abcdef0123456789abcdef01") // an uppercase prefix
	f.Add("hf-0123456789abcdef0123456789abcdef01") // a hyphen where the prefix closes
	f.Add("hf0123456789abcdef0123456789abcdef012") // the prefix without its underscore
	f.Add("xhf_0123456789abcdef0123456789abcdef01")
	// The other Hugging Face credentials, which this pattern locates nothing
	// in, and a digest behind the prefix, which it locates a token in.
	f.Add("hf_oauth_0123456789abcdef0123456789abcdef01")
	f.Add("api_org_0123456789abcdef0123456789abcdef01")
	f.Add("hf_0123456789abcdef0123456789abcdef01234567")
	// The prefix inside base64url text, which is the alphabet that can hold it.
	f.Add("payload=zzzzhf_0123456789abcdef0123456789abcdef01zzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.hf_0123456789abcdef0123456789abcdef01")
	// A prefix written where a body would have to hold it, two tokens with
	// nothing between them, and candidate positions crowded as close as they
	// can be.
	f.Add("hf_hf_0123456789abcdef0123456789abcdef01")
	f.Add("hf_0123456789abchf_0123456789abcdef0123456789abcdef01")
	// A token beginning at each of the last two characters of another's body,
	// which a scan resuming past a match would lose, and the same characters a
	// byte further in, where the underscore falls inside the body and neither
	// token stands.
	f.Add("hf_0123456789abcdef0123456789abcdefhf_0123456789abcdef0123456789abcdef01")
	f.Add("hf_0123456789abcdef0123456789abcdef0hf_0123456789abcdef0123456789abcdef01")
	f.Add("hf_0123456789abcdef0123456789abchf_f0123456789abcdef0123456789abcdef01")
	f.Add("hf_0123456789abcdef0123456789abcdef01hf_0123456789abcdef0123456789abcdef01")
	f.Add(strings.Repeat("hf_", 64))
	f.Add(strings.Repeat("hf_", 64) + "0123456789abcdef0123456789abcdef01")
	f.Add(strings.Repeat("hf_0123456789abcdef0123456789abcdef01", 8))
	f.Add(strings.Repeat("_", 128))
	f.Add(strings.Repeat("f", 128))

	fuzzAgainstReference(f, HuggingFaceUserAccessToken().Find, referenceHuggingFaceUserAccessTokenFind)
}

// huggingFaceUserAccessTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func huggingFaceUserAccessTokenFindBenchmarks() []benchmarkCase {
	// The line the anchor is chosen against: the underscore the prefix closes
	// with stands not once on it, where the h stands three times and the f
	// twice. What the line times is the search for the anchor, which is most of
	// what this pattern costs a caller whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://huggingface.co/api/whoami-v2 `
	token := "hf_0123456789abcdef0123456789abcdef01"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// The prefix is three characters carrying the anchor once, so a run
			// of them stops the search once every three characters and each
			// stop reads a body that fails on its third character, which is the
			// underscore the prefix beginning a byte later closes with.
			name:  "candidates that are not values",
			src:   strings.Repeat("hf_", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads a prefix, which is the cheapest a
			// candidate is declined for at all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("_", 4096),
			spans: 0,
		},
		{
			// The other way a candidate fails: a body of the right alphabet up
			// to its last character, so the whole of it is walked before the
			// candidate is turned away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("hf_0123456789abcdef0123456789abcdef0. ", 16),
			spans: 0,
		},
		{
			// A run of the alphabet a body is read in, carrying no anchor at
			// all, which is what the search walks a payload of.
			name:  "a run of the body alphabet",
			src:   strings.Repeat("0123456789abcdef", 256),
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
