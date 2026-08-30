package mask

import (
	"slices"
	"strings"
	"testing"
)

// The HCP Terraform API token pattern: what it locates and what it leaves
// alone, written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a set
// of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. An identifier is fourteen letters and digits,
// written here as 0123456789abcd, and a secret is sixty-seven, written as
// 0123456789abcdef four times and then 012.

const hcpTerraformAPITokenTestToken = "0123456789abcd.atlasv1." +
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012"

func Test_HCPTerraformAPIToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token on its own",
			src:  hcpTerraformAPITokenTestToken,
			want: []Span{{0, 90}},
		},
		{
			name: "a token in an environment assignment",
			src:  "TF_TOKEN_app_terraform_io=" + hcpTerraformAPITokenTestToken,
			want: []Span{{26, 116}},
		},
		{
			// The alphabet is the letters of both cases with the digits, which
			// is what the tokens HashiCorp publishes are spelled in.
			name: "portions written in uppercase",
			src: "0123456789ABCD.atlasv1." +
				"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012",
			want: []Span{{0, 90}},
		},
		{
			// Both counts are read exactly, and there is no boundary either
			// side, so a longer run is a token with characters written against
			// its ends: the two written in front of the identifier and the one
			// written behind the secret stay in the text.
			name: "runs longer than the counts either side",
			src: "xy0123456789abcd.atlasv1." +
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123",
			want: []Span{{2, 92}},
		},
		{
			name: "two tokens with nothing between them",
			src:  hcpTerraformAPITokenTestToken + hcpTerraformAPITokenTestToken,
			want: []Span{{0, 90}, {90, 180}},
		},
		{
			name: "two tokens separated by a space",
			src:  hcpTerraformAPITokenTestToken + " " + hcpTerraformAPITokenTestToken,
			want: []Span{{0, 90}, {91, 181}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HCPTerraformAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HCPTerraformAPIToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the separator alone",
			src:  ".atlasv1.",
		},
		{
			name: "an identifier one character short",
			src: "0123456789abc.atlasv1." +
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012",
		},
		{
			name: "a secret one character short",
			src: "0123456789abcd.atlasv1." +
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
		},
		{
			// The three characters gitleaks and betterleaks admit and this scan
			// does not, one case apiece.
			name: "a hyphen in the secret",
			src: "0123456789abcd.atlasv1." +
				"0123456789abcdef-123456789abcdef0123456789abcdef0123456789abcdef012",
		},
		{
			name: "an underscore in the identifier",
			src: "0123456789abc_.atlasv1." +
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012",
		},
		{
			name: "an equals sign in the secret",
			src: "0123456789abcd.atlasv1." +
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01=",
		},
		{
			name: "a full stop in the secret",
			src: "0123456789abcd.atlasv1." +
				"0123456789abcdef.123456789abcdef0123456789abcdef0123456789abcdef012",
		},
		{
			// The separator is read in the one case HashiCorp writes it, which
			// is what gitleaks holds its own rule to as well.
			name: "an uppercase separator",
			src: "0123456789abcd.ATLASV1." +
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012",
		},
		{
			name: "the separator without the full stop it opens with",
			src: "0123456789abcdatlasv1." +
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012",
		},
		{
			name: "the separator without the full stop it closes with",
			src: "0123456789abcd.atlasv1" +
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012",
		},
		{
			name: "a hyphen where the separator opens",
			src: "0123456789abcd-atlasv1." +
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012",
		},
		{
			name: "the version the token format does not carry",
			src: "0123456789abcd.atlasv2." +
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012",
		},
		{
			// The other HashiCorp credential this package reads, which carries
			// a prefix of its own and no separator to be found at.
			name: "a vault token",
			src:  "hvs.0123456789abcdef01234567",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "a log line",
			src:  `time=2026-08-17T00:00:00Z level=info msg="applied run" url=https://app.terraform.io/api/v2/runs`,
		},
		{
			name: "an environment variable holding a host name",
			src:  "TF_CLOUD_HOSTNAME=app.terraform.io",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HCPTerraformAPIToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_HCPTerraformAPIToken_inContext(t *testing.T) {
	// The places a token is written, which are the places HashiCorp's own
	// documentation puts one: the environment variable the CLI reads it from,
	// the credentials block and the credentials file terraform login writes,
	// the bearer header an API request carries it in and the command line a
	// curl example writes that header on.
	const token = hcpTerraformAPITokenTestToken

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token in an environment assignment",
			src:  "TF_TOKEN_app_terraform_io=" + token,
			want: []Span{{26, 26 + len(token)}},
		},
		{
			name: "a token in a cli credentials block",
			src:  `credentials "app.terraform.io" {` + "\n" + `  token = "` + token + `"` + "\n}",
			want: []Span{{44, 44 + len(token)}},
		},
		{
			name: "a token in the credentials file terraform login writes",
			src:  `{"credentials":{"app.terraform.io":{"token":"` + token + `"}}}`,
			want: []Span{{45, 45 + len(token)}},
		},
		{
			name: "a token in a bearer token header",
			src:  "Authorization: Bearer " + token,
			want: []Span{{22, 22 + len(token)}},
		},
		{
			name: "a token on a command line",
			src:  `curl -H "Authorization: Bearer ` + token + `" https://app.terraform.io/api/v2/account/details`,
			want: []Span{{31, 31 + len(token)}},
		},
		{
			name: "a token at the end of a sentence",
			src:  "the token is " + token + ".",
			want: []Span{{13, 13 + len(token)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := HCPTerraformAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HCPTerraformAPIToken_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match. A word boundary in front
	// would drop the whole match rather than trim it wherever a token is
	// written against a word character, and one behind it would drop a token
	// followed by a letter or a digit. trufflehog asks for both; what stands
	// either side is held back here by the alphabet and the counts alone.
	const token = hcpTerraformAPITokenTestToken

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token after an underscore",
			src:  "TF_TOKEN_" + token,
			want: []Span{{9, 9 + len(token)}},
		},
		{
			// A letter written against the identifier is a fifteenth character
			// in front of the separator, and the fourteen the scan reads are
			// the ones behind it.
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
			if got, _ := HCPTerraformAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_HCPTerraformAPIToken_aVagrantCloudToken(t *testing.T) {
	// The collision this format leaves, and the decision taken on it. Vagrant
	// Cloud issues its personal tokens in the same separator, the same two
	// counts and the same alphabet, so its tokens are located under this
	// pattern's name. Nothing in either string reads the two apart, and a scan
	// declining one would decline every HCP Terraform token there is.
	src := "VAGRANT_CLOUD_TOKEN=" + hcpTerraformAPITokenTestToken
	want := []Span{{20, 20 + len(hcpTerraformAPITokenTestToken)}}

	if got, _ := HCPTerraformAPIToken().Find(src); !slices.Equal(got, want) {
		t.Errorf("Find(%q) = %v, want %v", src, got, want)
	}
}

func Test_hcpTerraformAPITokenSeparator(t *testing.T) {
	// The separator is the whole of what tells this format from text, and it
	// opens and closes on a character no portion is written with. That is what
	// keeps a run of the alphabet either portion is written in from ever
	// holding one, however long the run.
	if got := hcpTerraformAPITokenSeparator; got != ".atlasv1." {
		t.Errorf("hcpTerraformAPITokenSeparator = %q, want %q", got, ".atlasv1.")
	}
	for i := range len(hcpTerraformAPITokenSeparator) {
		c := hcpTerraformAPITokenSeparator[i]
		if i == 0 || i == len(hcpTerraformAPITokenSeparator)-1 {
			if isBase62Byte(c) {
				t.Errorf("the separator ends on %q at index %d, which a portion may be written with", c, i)
			}
			continue
		}
		if !isBase62Byte(c) {
			t.Errorf("the separator carries %q at index %d, which a portion may not be written with", c, i)
		}
	}
}

func Test_hcpTerraformAPITokenAnchor(t *testing.T) {
	// The byte the scan searches for stands at the index it reads a separator
	// back from. A separator or an index changed without the other leaves the
	// scan opening candidates nowhere near where a token begins, and what such
	// a scan finds is nothing at all rather than something wrong.
	if got := hcpTerraformAPITokenSeparator[hcpTerraformAPITokenAnchorIndex]; got != hcpTerraformAPITokenAnchor {
		t.Errorf("hcpTerraformAPITokenSeparator[%d] = %q, want the anchor %q",
			hcpTerraformAPITokenAnchorIndex, got, hcpTerraformAPITokenAnchor)
	}

	// What the anchor costs, counted rather than claimed in prose: it stands
	// once in the separator, so a line of tokens stops the search once a token.
	// The full stop stands twice there, which is half of why it was not chosen.
	if n := strings.Count(hcpTerraformAPITokenSeparator, string(hcpTerraformAPITokenAnchor)); n != 1 {
		t.Errorf("the anchor stands %d times in %q, want 1", n, hcpTerraformAPITokenSeparator)
	}
}

func Test_hcpTerraformAPITokenChars(t *testing.T) {
	// The two counts every token HashiCorp publishes carries, and the ninety
	// characters they come to with the separator between them.
	if got := hcpTerraformAPITokenIDChars; got != 14 {
		t.Errorf("hcpTerraformAPITokenIDChars = %d, want 14", got)
	}
	if got := hcpTerraformAPITokenSecretChars; got != 67 {
		t.Errorf("hcpTerraformAPITokenSecretChars = %d, want 67", got)
	}
	if got := len(hcpTerraformAPITokenSeparator); got != 9 {
		t.Errorf("len(hcpTerraformAPITokenSeparator) = %d, want 9", got)
	}
	if got := hcpTerraformAPITokenChars; got != 90 {
		t.Errorf("hcpTerraformAPITokenChars = %d, want 90", got)
	}
	if got := len(hcpTerraformAPITokenTestToken); got != hcpTerraformAPITokenChars {
		t.Errorf("the token these cases are written with is %d characters, want %d",
			got, hcpTerraformAPITokenChars)
	}
}

func Test_hcpTerraformAPITokenTailStart(t *testing.T) {
	// What a piece of an opening standing at the end of the input holds back.
	// The two halves of the opening are cut in two different ways — a run that
	// a separator has not arrived behind yet, and a separator the end came in
	// the middle of — and what each of them holds back is where the token it
	// would belong to began. Test_builtins_retainSettles drives the whole
	// answer over cut samples; what is written out here is the width the scan
	// steps back, which is the thing that could be wrong.
	tests := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "nothing standing at the end",
			src:  "a line of prose, and nothing else at all\n",
			want: 41,
		},
		{
			name: "the empty input",
			src:  "",
			want: 0,
		},
		{
			name: "a run shorter than an identifier",
			src:  "token=0123",
			want: 6,
		},
		{
			// Fourteen characters is all a separator arriving could reach, so
			// what stands further back than that is settled.
			name: "a run longer than an identifier",
			src:  "token=0123456789abcdef0123",
			want: 12,
		},
		{
			name: "the first character of the separator",
			src:  "token=0123456789abcd.",
			want: 6,
		},
		{
			name: "the separator cut in half",
			src:  "token=0123456789abcd.atl",
			want: 6,
		},
		{
			name: "the whole separator",
			src:  "token=0123456789abcd.atlasv1.",
			want: 6,
		},
		{
			// An identifier's width is all the scan steps back from a piece of
			// the separator, so text further in front of it is settled.
			name: "a piece of the separator behind a longer line",
			src:  "a line of prose, and nothing else at all.atlasv1",
			want: 26,
		},
		{
			// The window begins inside what an identifier would have to be, so
			// there is nothing in front of the piece to give back.
			name: "a piece of the separator with no room for an identifier",
			src:  "0123.atl",
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hcpTerraformAPITokenTailStart(tt.src); got != tt.want {
				t.Errorf("hcpTerraformAPITokenTailStart(%q) = %d, want %d", tt.src, got, tt.want)
			}
		})
	}
}

// referenceHCPTerraformAPITokenFind locates tokens the plain way: every
// position in turn, the ninety characters standing there read left to right —
// fourteen of the alphabet, the separator, sixty-seven of the alphabet — with
// nothing remembered between candidates.
//
// The separator, both counts and the alphabet are spelled again here rather
// than shared with the scan. A reference reading hcpTerraformAPITokenSeparator,
// the counts beside it and isBase62Byte could not disagree with it about them,
// and it is exactly that disagreement the fuzz target below is for: the two
// have to be changed together or reported apart.
//
// Every position is a starting point in its own right, a match included.
// Nothing here rests on where a token may begin relative to another: a
// reference is written to know nothing its scan claims, and non-nesting is one
// of the things a scan claims.
//
// It is written out rather than built on a regular expression, and the grammar
// states compactly enough as [0-9A-Za-z]{14}\.atlasv1\.[0-9A-Za-z]{67} that the
// reason has to be measured rather than assumed. What costs is the opening: a
// token opens on fourteen characters of the alphabet its own portions are
// written in rather than on a literal, so there is nothing for an engine to
// search the text for and it walks its machine at every byte, and a loop asking
// again a byte past each match hands it the rest of the input every time.
// Measured on ninety kibibytes of tokens written end to end, the expression
// costs thirty-five milliseconds where the walk below costs one and a half; on
// a mebibyte of alphanumerics holding no token at all, a quarter of a second
// against twelve milliseconds. The mutator reaches inputs of that size, and
// this target ran at speed for one thirty second run and then, with those
// inputs in its corpus, at nothing at all for the next.
//
// What is below has neither problem. Both counts are counts, so a position
// reads at most ninety bytes and stops: there is no run to walk again at the
// next position, nothing quadratic to keep the seeds small around, and the walk
// is linear in the length of the input as the scan is.
func referenceHCPTerraformAPITokenFind(src string) []Span {
	const (
		separator   = ".atlasv1."
		idChars     = 14
		secretChars = 67
	)
	portion := func(c byte) bool {
		return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
	}

	var spans []Span
	for start := range len(src) {
		end := start + idChars + len(separator) + secretChars
		if end > len(src) {
			break
		}

		ok := true
		for i := start; i < start+idChars; i++ {
			if !portion(src[i]) {
				ok = false
				break
			}
		}
		if !ok || src[start+idChars:start+idChars+len(separator)] != separator {
			continue
		}
		for i := start + idChars + len(separator); i < end; i++ {
			if !portion(src[i]) {
				ok = false
				break
			}
		}
		if ok {
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
}

// FuzzHCPTerraformAPIToken_matchesReference guards the hand-written scan: the
// separator it searches for, the case it reads that separator in, the counts it
// reads either side of it, the alphabet it reads those counts in and the byte
// it resumes at may none of them change which tokens are located.
func FuzzHCPTerraformAPIToken_matchesReference(f *testing.F) {
	const token = hcpTerraformAPITokenTestToken

	f.Add("nothing to see here")
	f.Add("TF_TOKEN_app_terraform_io=" + token)
	f.Add(token)
	// A portion one character short either side, and one character longer.
	f.Add("0123456789abc.atlasv1.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012")
	f.Add("0123456789abcd.atlasv1.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")
	f.Add("x" + token)
	f.Add(token + "x")
	// The characters the alphabet leaves out, in each portion.
	f.Add("0123456789abc_.atlasv1.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012")
	f.Add("0123456789abcd.atlasv1.0123456789abcdef-123456789abcdef0123456789abcdef0123456789abcdef012")
	f.Add("0123456789abcd.atlasv1.0123456789abcdef.123456789abcdef0123456789abcdef0123456789abcdef012")
	f.Add("0123456789abcd.atlasv1.0123456789abcdef\n123456789abcdef0123456789abcdef0123456789abcdef012")
	// The separator misspelled: the wrong case, the wrong version, and each of
	// its two full stops taken away.
	f.Add("0123456789abcd.ATLASV1.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012")
	f.Add("0123456789abcd.atlasv2.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012")
	f.Add("0123456789abcdatlasv1.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012")
	f.Add("0123456789abcd.atlasv10123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012")
	// Uppercase portions, and the other HashiCorp credential this package
	// reads, which carries no separator to be found at.
	f.Add("0123456789ABCD.atlasv1.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012")
	f.Add("hvs.0123456789abcdef01234567")
	// Two tokens written together, and separators crowded as close as they can
	// be, which is where a candidate read back from the wrong full stop would
	// show itself.
	f.Add(token + token)
	f.Add(token + " " + token)
	f.Add(".atlasv1..atlasv1.")
	f.Add(strings.Repeat(".atlasv1.", 64))
	f.Add(strings.Repeat(".atlasv1.", 64) + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012")
	f.Add(strings.Repeat("v", 128))
	f.Add(strings.Repeat(".", 128))
	f.Add(strings.Repeat("0123456789abcdefghijklmnopqrstuvwxyz", 8))
	f.Add(strings.Repeat(token, 8))

	fuzzAgainstReference(f, HCPTerraformAPIToken().Find, referenceHCPTerraformAPITokenFind)
}

// hcpTerraformAPITokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func hcpTerraformAPITokenFindBenchmarks() []benchmarkCase {
	// The line the anchor is chosen against: the v stands twice on it, where
	// the a stands seven times, the s six, the l five, and the t and the 1 four
	// apiece. The full stop stands twice as well and is the worse of the two,
	// for the reason the rationale beside the scan gives. What the line times is
	// the search for the anchor, which is most of what this pattern costs a
	// caller whose text holds no token.
	line := `time=2026-08-17T00:00:00Z level=info msg="applied run" run=run-0123456789abcdef ` +
		`changes=12 elapsed=41s url=https://app.terraform.io/api/v2/runs `
	token := hcpTerraformAPITokenTestToken

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A run of separators: the search stops once every nine characters
			// and each stop reads a whole separator and then the fourteen
			// characters in front of it, which are a stretch of the separators
			// before. The walk over those stops at the first full stop it
			// reaches, five characters in.
			name:  "candidates that are not values",
			src:   strings.Repeat(".atlasv1.", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads a separator, which is the cheapest a
			// candidate is declined for at all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("v", 4096),
			spans: 0,
		},
		{
			// The other way a candidate fails: an identifier and a secret of
			// the right alphabet up to the secret's last character, so the
			// whole of both is walked before the candidate is turned away.
			name: "candidates walked to their last character",
			src: strings.Repeat("0123456789abcd.atlasv1."+
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01 ", 16),
			spans: 0,
		},
		{
			// A run of the alphabet a portion is read in, which is what the
			// search walks a payload of. It carries the anchor once every
			// thirty-six characters, and each of those stops is turned away by
			// the one comparison that asks for a full stop.
			name:  "a run of the portion alphabet",
			src:   strings.Repeat("0123456789abcdefghijklmnopqrstuvwxyz", 128),
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
