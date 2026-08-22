package mask

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// The PyPI API token pattern: what it locates and what it leaves alone, written
// out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The tokens written out below carry a real serialization header and an ordered
// run behind it: valid in shape, obviously not real. AgEIcHlwaS5vcmc is what
// the opening of a macaroon issued by pypi.org encodes to, and
// AgENdGVzdC5weXBpLm9yZw what test.pypi.org's does — a version number, a field
// number, a length and a domain name, none of it secret. What stands behind
// them, 0123456789abcdef written over and over, stands in for the identifier,
// the caveats and the signature a real token carries there; the scan reads
// those as a run rather than to a count, so forty-eight characters state the
// grammar as well as the hundred and fifty a real token has and leave a case
// short enough to read.

func Test_PyPIAPIToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a token from pypi.org on its own",
			src:  "pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 68}},
		},
		{
			name: "a token in an environment assignment",
			src:  "PYPI_API_TOKEN=pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{15, 83}},
		},
		{
			// The password field of a .pypirc, which is where a token is
			// written by hand more often than anywhere else.
			name: "a token in the password field of a pypirc",
			src:  "password = pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{11, 79}},
		},
		{
			// The same code issues these, and they upload to a real index. The
			// two published rulesets read pypi.org into their expressions and
			// locate nothing here.
			name: "a token from test.pypi.org",
			src:  "pypi-AgENdGVzdC5weXBpLm9yZw0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 75}},
		},
		{
			// The location is read as part of the run rather than from a table
			// of domains, so an index nobody has named is located like any
			// other. The header here is what a location of x.io encodes to.
			name: "a token from an index the scan carries no name for",
			src:  "pypi-AgEEeC5pbw0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 63}},
		},
		{
			// The hyphen and the underscore are base64url characters, and the
			// serialization writes both wherever the bytes it encodes call for
			// them.
			name: "a body carrying a hyphen and an underscore",
			src:  "pypi-AgEIcHlwaS5vcmc0123456789abcdef-0123456789abcdef_0123456789abcdef",
			want: []Span{{0, 70}},
		},
		{
			// Fifty characters behind the prefix, which is the floor exactly:
			// shorter than any macaroon can be serialized to, and a third of
			// what a real token carries.
			name: "a body exactly as long as the floor",
			src:  "pypi-AgE0123456789abcdef0123456789abcdef0123456789abcde",
			want: []Span{{0, 55}},
		},
		{
			name: "two tokens separated by a space",
			src:  "pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef pypi-AgENdGVzdC5weXBpLm9yZw0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 68}, {69, 144}},
		},
		{
			// Every character of the anchor belongs to the alphabet a body is
			// written in, so a token can begin inside the span of the one
			// before it, and a scan resuming past a match would step over it.
			// The spans overlap, which a Masker resolves into one.
			name: "a token beginning inside the token before it",
			src:  "pypi-AgEpypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 76}, {8, 76}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PyPIAPIToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PyPIAPIToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "pypi-",
		},
		{
			name: "the prefix and a long run carrying no header",
			src:  "pypi-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "the header with no prefix in front of it",
			src:  "AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// Two of the header's three characters. The whole of it is read, so
			// a body carrying part of it carries none.
			name: "two characters of the header",
			src:  "pypi-Ag0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a header in the wrong case",
			src:  "pypi-age0123456789abcdef0123456789abcdef0123456789abcde",
		},
		{
			// The third character of the header spells the top two bits of the
			// location's length, so a location of sixty-four characters or more
			// spells it F rather than E and nothing here is located. That is
			// the one assumption the anchor makes about the serialization, and
			// it is a domain name longer than any index has: the case is here
			// so that the assumption is on the record rather than discovered.
			name: "a header spelling a location of sixty-four characters or more",
			src:  "pypi-AgFA0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "an uppercase prefix",
			src:  "PyPI-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The prefix is five characters and all five are read. An
			// underscore where the hyphen is is not one.
			name: "an underscore where the prefix carries a hyphen",
			src:  "pypi_AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// The header stands against the prefix, so anything written between
			// the two leaves no anchor at all.
			name: "a space between the prefix and the header",
			src:  "pypi- AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "a dot between the prefix and the header",
			src:  "pypi-.AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			// Standard base64 rather than base64url: the two characters
			// base64url writes as - and _ are + and /, and neither belongs to
			// the alphabet a body is read in, so the run ends there and what is
			// left of it is short of the floor.
			name: "a plus inside the body",
			src:  "pypi-AgEIcHlwaS5vcmc0123456789abcdef+0123456789abcdef0123456789abcdef",
		},
		{
			name: "a slash inside the body",
			src:  "pypi-AgEIcHlwaS5vcmc0123456789abcdef/0123456789abcdef0123456789abcdef",
		},
		{
			name: "a line break inside the body",
			src:  "pypi-AgEIcHlwaS5vcmc0123456789abcdef\n0123456789abcdef0123456789abcdef",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// The names that carry the prefix. Each of them is a hyphenated
			// word and the hyphen is a body character, so the run runs on
			// through it; what turns them away is the three characters behind
			// the prefix.
			name: "a line of names carrying the prefix",
			src:  "the gh-action-pypi-publish workflow replaced pypi-timemachine and pypi-server",
		},
		{
			// Forty hexadecimal characters. A digest carries no hyphen, so it
			// holds no prefix to be found at, and neither g nor E is a
			// hexadecimal digit.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PyPIAPIToken().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PyPIAPIToken_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "PYPI_API_TOKEN=pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "PYPI_API_TOKEN=********************************************************************",
		},
		{
			name: "quoted",
			src:  `"pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef"`,
			want: `"********************************************************************"`,
		},
		{
			name: "json",
			src:  `{"password":"pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef"}`,
			want: `{"password":"********************************************************************"}`,
		},
		{
			// The file twine reads a token from, with the username PyPI asks
			// for beside it.
			name: "a pypirc",
			src:  "[pypi]\n  username = __token__\n  password = pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "[pypi]\n  username = __token__\n  password = ********************************************************************",
		},
		{
			name: "a command line",
			src:  "twine upload -u __token__ -p pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef dist/*",
			want: "twine upload -u __token__ -p ******************************************************************** dist/*",
		},
		{
			name: "twice",
			src:  "pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef pypi-AgENdGVzdC5weXBpLm9yZw0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "******************************************************************** ***************************************************************************",
		},
		{
			// The two spans are merged, so the token that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a token beginning inside the token before it",
			src:  "pypi-AgEpypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "****************************************************************************",
		},
	}

	m := New(WithPatterns(PyPIAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PyPIAPIToken_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the token through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xpypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "x********************************************************************",
		},
		{
			name: "underscore before",
			src:  "PYPI_API_TOKEN_pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef",
			want: "PYPI_API_TOKEN_********************************************************************",
		},
	}

	m := New(WithPatterns(PyPIAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PyPIAPIToken_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a run rather than a count. Where a token ends is
	// where its alphabet stops, so ordinary punctuation ends one and nothing
	// written after it joins it — but a character of the token's own alphabet
	// written straight against a token is redacted with the token, which is
	// what buys a token whose caveats nobody has counted being located whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the token is pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef.",
			want: "the token is ********************************************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export PYPI_API_TOKEN="pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef"`,
			want: `export PYPI_API_TOKEN="********************************************************************"`,
		},
		{
			// The hyphen is a body character, so a hyphenated word written
			// against a token is read as more of the run and redacted with it.
			name: "a dashed word against the token",
			src:  "pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef-suffix",
			want: "***************************************************************************",
		},
		{
			name: "a word against the token",
			src:  "pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdefsuffix",
			want: "**************************************************************************",
		},
	}

	m := New(WithPatterns(PyPIAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PyPIAPIToken_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, which is the token a column limit cut short of it.
	// The two cases here are one character apart: the shorter is left in the
	// output whole, and what stays there is a version byte, a field number and
	// the opening of a domain name rather than the signature a macaroon is a
	// credential by.
	//
	// Lowering the floor would buy the shorter one back and let a run of the
	// alphabet that merely opens the right way in with it, which
	// builtin_pypi_api_token.go weighs. The pair is here so that a change to
	// the number is a decision rather than something noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a body one character short of the floor",
			src:  "pypi-AgE0123456789abcdef0123456789abcdef0123456789abcd",
			want: "pypi-AgE0123456789abcdef0123456789abcdef0123456789abcd",
		},
		{
			name: "a body exactly as long as the floor",
			src:  "pypi-AgE0123456789abcdef0123456789abcdef0123456789abcde",
			want: "*******************************************************",
		},
	}

	m := New(WithPatterns(PyPIAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PyPIAPIToken_insideAnOpaqueRun(t *testing.T) {
	// What this pattern redacts that nobody issued. The anchor is eight
	// characters of the base64url alphabet, so a long enough encoding written
	// in that alphabet carries them somewhere, and the run from there to the
	// end of the encoding is redacted.
	//
	// The cases are held to being redacted rather than to being spared. What is
	// taken is a stretch of a value already opaque to a reader, and the
	// tightening on offer is the location — the thing
	// builtin_pypi_api_token.go sets out why this scan does not read. What the
	// table is for is that the cases move with the scan: one of them ceasing to
	// be located means the grammar changed, and that is a decision to be taken
	// rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "inside a base64url payload",
			src:  "payload=zzzzpypi-AgEzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			want: "payload=zzzz*******************************************************",
		},
		{
			// The same run written where a JWT signature stands. The JWT
			// pattern is not enabled here, so what the case states is the PyPI
			// pattern's own reading of it.
			name: "where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzpypi-AgEzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			want: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzz*******************************************************",
		},
	}

	m := New(WithPatterns(PyPIAPIToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_pypiAPITokenAnchor(t *testing.T) {
	// The scan resumes one byte past the start of a candidate because a token
	// can begin inside the run of the one before it, and that holds only while
	// every character of the anchor is one a body may be written in. An anchor
	// carrying a character outside the alphabet would make the two impossible
	// to nest, and the case above pinning the nesting would stand for nothing —
	// which is not a failure anything else here reports.
	if pypiAPITokenPrefix == "" {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	if pypiAPITokenHeader == "" {
		t.Fatal("the pattern carries no header, so its prefix alone would locate tokens")
	}
	if want := pypiAPITokenPrefix + pypiAPITokenHeader; pypiAPITokenAnchor != want {
		t.Errorf("the anchor is %q, the prefix and the header together are %q", pypiAPITokenAnchor, want)
	}
	for i := range len(pypiAPITokenAnchor) {
		if c := pypiAPITokenAnchor[i]; !isBase64URLByte(c) {
			t.Errorf("the anchor holds %q, which no body may be written with", c)
		}
	}

	// The body opens at the header, so the run a candidate is measured in is
	// the run the header stands in. The scan reaches that run by walking from
	// the character behind the prefix, which is sound only while the prefix is
	// what the anchor opens with.
	if !strings.HasPrefix(pypiAPITokenAnchor, pypiAPITokenPrefix) {
		t.Errorf("the anchor %q does not open with the prefix %q", pypiAPITokenAnchor, pypiAPITokenPrefix)
	}
}

func Test_pypiAPITokenHeader(t *testing.T) {
	// What the three characters are: the opening of the macaroon binary format,
	// which is why they stand behind the prefix in every token whichever index
	// issued it. The version number and the field number of a location are
	// fixed; the length of that location is not, and the third character
	// carries its top two bits, so the header holds for a location shorter than
	// sixty-four characters and no further.
	//
	// The claim is checked by encoding the bytes rather than by naming the
	// tokens two indexes happen to issue, so that the edge is stated as an edge
	// — the first length the header does not stand for is held to not standing
	// for it, which is the case a reader would otherwise have to take on trust.
	const firstLengthTheHeaderDoesNotSpell = 64

	for locationChars := range firstLengthTheHeaderDoesNotSpell {
		got := serializedMacaroonHeader(locationChars)
		if !strings.HasPrefix(got, pypiAPITokenHeader) {
			t.Errorf("a location of %d character(s) serializes to %q, which does not open with the header %q", locationChars, got, pypiAPITokenHeader)
		}
	}
	if got := serializedMacaroonHeader(firstLengthTheHeaderDoesNotSpell); strings.HasPrefix(got, pypiAPITokenHeader) {
		t.Errorf("a location of %d characters serializes to %q, which the header %q was not meant to reach", firstLengthTheHeaderDoesNotSpell, got, pypiAPITokenHeader)
	}

	// And the two headers the indexes anybody uses do write, which is what the
	// cases above are built from.
	for _, tt := range []struct {
		location string
		want     string
	}{
		{location: "pypi.org", want: "AgEIcHlwaS5vcmc"},
		{location: "test.pypi.org", want: "AgENdGVzdC5weXBpLm9yZw"},
	} {
		if !strings.HasPrefix(tt.want, serializedMacaroonHeader(len(tt.location))) {
			t.Errorf("a token from %s opens %q, which is not what a location of %d characters serializes to", tt.location, tt.want, len(tt.location))
		}
	}
}

// serializedMacaroonHeader returns the four characters the base64url
// serialization of a macaroon opens with when its location is locationChars
// characters long: the version number, the field number a location is written
// under, and that length, which are the first three bytes of the binary form
// and so the first base64 group of the encoding.
//
// It is written out here rather than taken from encoding/base64, and the three
// bytes are named rather than read from the pattern, so that the claim
// pypiAPITokenHeader makes can be read from the test that makes it. It holds
// for a length a variable length integer writes in one byte, which is what the
// caller above stays within.
func serializedMacaroonHeader(locationChars int) string {
	const (
		alphabet      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		version       = 2 // the macaroon binary format warehouse asks pymacaroons for
		locationField = 1 // the field a location is written under
	)

	group := version<<16 | locationField<<8 | locationChars

	var b strings.Builder
	for shift := 18; shift >= 0; shift -= 6 {
		b.WriteByte(alphabet[group>>shift&0x3f])
	}
	return b.String()
}

func Test_PyPIAPIToken_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a run dense in anchors
	// holds a candidate for every eight characters it has. One thing a
	// candidate reads is a walk over the rest of the input rather than a
	// bounded test — where its run ends — and repeating it at every candidate
	// costs time quadratic in the length of the line. The bound here is far
	// above a linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every fifty-five bytes where they are densest, because a sample
	// has to carry a whole body to be one. The crowding a run can actually
	// carry, a candidate every eight bytes, stays here.
	sources := map[string]string{
		// One run, a candidate every eight characters, and every one of them a
		// token reaching the end of it: the run cursor is walked once and read
		// two hundred thousand times.
		"a candidate every eight characters in one run": strings.Repeat("pypi-AgE", 200000),
		// A candidate every nine characters instead, with every run ended
		// before a body can reach the floor, so every candidate is rejected and
		// the cursor is moved at each of them.
		"a candidate every nine characters, none with a run": strings.Repeat("pypi-AgE.", 200000),
		// The prefix as often as it can be written with no header behind it,
		// which is the search for the anchor reading the whole line and
		// reaching no candidate at all.
		"a prefix every five characters and no anchor": strings.Repeat("pypi-", 300000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the same and finding a token.
		"a body that runs the length of the line": "pypi-AgE" + strings.Repeat("a", 1800000),
	}

	m := New(WithPatterns(PyPIAPIToken()))
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

// referencePyPIAPITokenFind is the statement of what a PyPI API token is, kept
// here so that the scan in builtin_pypi_api_token.go can be held to it: the
// prefix, the three characters the serialization opens with, and a body of the
// base64url alphabet at least as long as the floor, found afresh at every
// position with nothing remembered between them.
//
// The prefix, the header, the floor and the alphabet are spelled again rather
// than built from pypiAPITokenPrefix, pypiAPITokenHeader, pypiAPITokenBodyChars
// and isBase64URLByte. A reference sharing those declarations could not
// disagree with the scan about them, and it is exactly that disagreement the
// fuzz target below is for: the two have to be changed together or reported
// apart.
//
// Every position is a starting point in its own right, a match included,
// because every character of the anchor belongs to the alphabet a body is
// written in: pypi-AgEpypi-AgE... holds a token beginning inside the match
// before it. The scan finds both and reports the two spans overlapping for a
// Masker to resolve, so the reference must ask about both.
//
// It is written out rather than built on a regular expression, as the JWT,
// Slack and Anthropic references are, and for the reason the Anthropic one
// gives: the grammar states compactly as pypi-AgE[0-9A-Za-z_-]{47,}, and a
// counted repetition is what an engine has the least room to skip, so a run the
// anchor can be written inside is re-walked at every candidate through a
// machine forty-seven states wide. The walk below re-walks the same run and
// nothing more, which still costs time quadratic in the length of such a run —
// that is the price of a reference with no cursor to be wrong about, and the
// reason the seeds below keep such a run short rather than inviting the mutator
// to grow it. Test_builtins_scanIsLinear and Test_PyPIAPIToken_scanIsLinear are
// where the cost the scan pays is held down.
func referencePyPIAPITokenFind(src string) []Span {
	const (
		prefix    = "pypi-"
		header    = "AgE"
		bodyChars = 50
	)

	body := func(c byte) bool {
		return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || c == '-' || c == '_'
	}

	var spans []Span
	for start := range len(src) {
		if !strings.HasPrefix(src[start:], prefix+header) {
			continue
		}

		at := start + len(prefix)
		end := at
		for end < len(src) && body(src[end]) {
			end++
		}
		if end-at < bodyChars {
			continue
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return spans
}

// FuzzPyPIAPIToken_matchesReference guards the hand-written scan: the anchor it
// searches for, the floor it holds a body to, the alphabet it reads that body
// in, the run it remembers between candidates and the byte it resumes at may
// none of them change which tokens are located.
func FuzzPyPIAPIToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("PYPI_API_TOKEN=pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("pypi-AgENdGVzdC5weXBpLm9yZw0123456789abcdef0123456789abcdef0123456789abcdef")     // test.pypi.org
	f.Add("pypi-AgEEeC5pbw0123456789abcdef0123456789abcdef0123456789abcdef")                 // an index the scan carries no name for
	f.Add("pypi-AgEIcHlwaS5vcmc0123456789abcdef-0123456789abcdef_0123456789abcdef")          // a hyphen and an underscore in the body
	f.Add("pypi-AgE0123456789abcdef0123456789abcdef0123456789abcde")                         // a body exactly as long as the floor
	f.Add("pypi-AgE0123456789abcdef0123456789abcdef0123456789abcd")                          // one short of one
	f.Add("pypi-Ag0123456789abcdef0123456789abcdef0123456789abcdef")                         // two characters of the header
	f.Add("pypi-age0123456789abcdef0123456789abcdef0123456789abcde")                         // a header in the wrong case
	f.Add("pypi-AgFA0123456789abcdef0123456789abcdef0123456789abcdef")                       // a location of sixty-four characters or more
	f.Add("PyPI-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef")            // an uppercase prefix
	f.Add("pypi_AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef")            // an underscore where the prefix carries a hyphen
	f.Add("pypi-.AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef")           // a dot between the prefix and the header
	f.Add("pypi-AgEIcHlwaS5vcmc0123456789abcdef+0123456789abcdef0123456789abcdef")           // standard base64 rather than base64url
	f.Add("pypi-AgEIcHlwaS5vcmc0123456789abcdef.0123456789abcdef0123456789abcdef")           // a dot ends the body
	f.Add("pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef-suffix")     // the run reaches over what is written against it
	f.Add("password = pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef") // a pypirc
	f.Add("pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef\npypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef")
	// A token beginning inside the match before it, which a scan resuming past
	// a match steps over, and two tokens with nothing between them.
	f.Add("pypi-AgEpypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdefpypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef")
	// Candidate positions crowded as close as they can be: a body long enough
	// for all of them, and a body long enough for none.
	f.Add(strings.Repeat("pypi-AgE", 12) + "0123456789abcdef0123456789abcdef0123456789abcde")
	f.Add(strings.Repeat("pypi-AgE.", 12))
	f.Add(strings.Repeat("pypi-", 16))
	// The names that carry the prefix, which only the header turns away.
	f.Add("the gh-action-pypi-publish workflow replaced pypi-timemachine and pypi-server")
	// The anchor written inside a run of the alphabet, which is the over-match
	// the pattern admits.
	f.Add("payload=zzzzpypi-AgEzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.zzzzpypi-AgEzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")

	fuzzAgainstReference(f, PyPIAPIToken().Find, referencePyPIAPITokenFind)
}

// pypiAPITokenFindBenchmarks is what this scan is timed on. The builtinPatterns
// entry for the pattern names it, and BenchmarkBuiltins times every case it
// holds under the pattern's own name, so that a built-in cannot arrive without
// a benchmark. Every case is held to the count it states under a plain go test
// as well, which is what a benchmark nobody has run yet cannot be.
func pypiAPITokenFindBenchmarks() []benchmarkCase {
	// An ordinary line carries no anchor, so what it times is the search for
	// one and the return behind it — which is the whole of what this pattern
	// costs a caller whose text holds no token, however many hyphenated names
	// on the line carry pypi-.
	line := `time=2026-08-17T00:00:00Z level=info msg="uploading to the index" url=https://upload.pypi.org/legacy/ `
	token := "pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every nine characters with every run ended short of
			// the floor: each of them reaches the body of the loop and none
			// becomes a token. What it times is the run cursor being moved,
			// once per candidate and no more.
			name:  "candidates that are not values",
			src:   strings.Repeat("pypi-AgE.", 128),
			spans: 0,
		},
		{
			// The same crowding inside one run long enough for every candidate,
			// so each locates a token and every span reaches the same place.
			// This is what the run cursor exists for: without it the run is
			// read once per candidate. The tail is what carries the last
			// candidate to the floor exactly.
			name:  "candidates crowded in one run",
			src:   strings.Repeat("pypi-AgE", 128) + "0123456789abcdef0123456789abcdef0123456789abcde",
			spans: 128,
		},
		{
			// The prefix as often as it can be written with no header behind
			// it, which is what a line dense in names mentioning the index
			// costs: the search for the anchor and nothing else.
			name:  "prefixes that are not candidates",
			src:   strings.Repeat("pypi-", 256),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "password=" + token,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "password=" + token,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"password="+token+"\n", 32),
			spans: 32,
		},
	}
}
