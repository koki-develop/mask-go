package mask

import (
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// streamInputs is the text a stream is driven over: every sample the registry
// names, the text no built-in finds anything in, and a few pieces of writing
// that carry a value into the middle of a line.
//
// The samples are read out of builtinPatterns rather than written out here so
// that a pattern added to the registry is driven through a stream without
// anybody adding it twice. What is written out beside them is the shape a
// sample does not have: a value with text either side of it, two values in one
// line, and a value cut short by the end of the text.
func streamInputs() []string {
	inputs := []string{
		"",
		"nothing to see here",
		"time=2026-08-17T00:00:00Z level=info msg=\"calling api\"\n",
		"日本語のログ行\n",
		"\xff\xfe\x00",
		// Longer than LookBehind, which is where a stream begins letting go of
		// what it has written out. Everything shorter is masked with the whole
		// of the text still in hand, so nothing shorter asks whether letting go
		// is safe.
		strings.Repeat("line of ordinary text with nothing in it\n", 8),
		strings.Repeat("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n", 4),
	}
	for _, b := range builtinPatterns {
		for _, s := range b.samples {
			inputs = append(inputs,
				s,
				"before "+s+" after\n",
				s+"\n"+s+"\n",
				s[:len(s)/2],
				"line one\n"+s,
			)
		}
	}
	return inputs
}

// streamRedactors is what a stream is driven with, one entry per way a
// redaction can differ in length from what it replaced.
//
// Fill is what a stream gets right by accident: two redactions written where
// one belongs still count the same number of runes, so a stream splitting a
// merged value in half reads the same as one that did not. Fixed is what
// catches that, and the empty one catches it again where the redaction is
// shorter than anything. Value is a different accident: Fill and Fixed never
// read Match.Value at all, so either would still agree with Mask if a stream
// handed the redactor text pulled in from the wrong side of a piece boundary,
// or a candidate repadded to the length it once had. Echoing Value back
// verbatim turns such a byte mismatch into a mismatch against Mask, which is
// what the other three cannot do.
//
// wide-fill is Fill accidentally getting the rune-count property right for the
// wrong reason a second time: a fill rune of more than one byte still has to
// come out once per rune of the original, not once per redaction, wherever a
// give-up splits a run of them across writes. credential-shaped is a redactor
// whose output is itself a value one of the patterns in the set would locate —
// a naming redactor that happens to emit a token-shaped label, or a Fixed
// copied from a template — which is what would show a stream rescanning its
// own redactions against Mask, which never does.
func streamRedactors() map[string]Redactor {
	return map[string]Redactor{
		"fill":              Fill('*'),
		"fixed":             Fixed("[REDACTED]"),
		"empty":             Fixed(""),
		"named":             NewRedactor(func(m Match) string { return "<" + m.Pattern.Name() + ">" }),
		"value":             NewRedactor(func(m Match) string { return "<" + m.Value + ">" }),
		"wide-fill":         Fill('█'),
		"credential-shaped": Fixed("sk_live_0123456789abcdef0123456789abcdef"),
	}
}

// throughWriter masks pieces through a Writer and returns what reached the
// writer underneath.
func throughWriter(t testing.TB, m *Masker, pieces []string, opts ...StreamOption) string {
	t.Helper()

	var got strings.Builder
	w := NewWriter(&got, m, opts...)
	for _, p := range pieces {
		n, err := w.Write([]byte(p))
		if err != nil {
			t.Fatalf("Write(%q) = %d, %v", p, n, err)
		}
		if n != len(p) {
			t.Fatalf("Write(%q) wrote %d of %d bytes", p, n, len(p))
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	return got.String()
}

// throughReader masks pieces through a Reader and returns what came out of it.
// The reader underneath hands over one piece per read, so the pieces are where
// the stream is cut whatever size the caller reads in.
func throughReader(t testing.TB, m *Masker, pieces []string, into int, opts ...StreamOption) string {
	t.Helper()
	return throughReaderSrc(t, m, newPieceReader(pieces, nil), into, opts...)
}

// throughReaderSrc masks what a Reader reads from src and returns what came
// out of it, which is throughReader's loop factored out so a stub reading
// differently from pieceReader — pieceReaderEOFWithData, below — is driven
// through the same one.
func throughReaderSrc(t testing.TB, m *Masker, src io.Reader, into int, opts ...StreamOption) string {
	t.Helper()

	r := NewReader(src, m, opts...)
	var got strings.Builder
	buf := make([]byte, into)
	for {
		n, err := r.Read(buf)
		got.Write(buf[:n])
		if err == io.EOF {
			return got.String()
		}
		if err != nil {
			t.Fatalf("Read() = %d, %v", n, err)
		}
	}
}

// pieceReader hands over one piece per read, so that a test says where the
// stream is cut rather than leaving it to a buffer size.
//
// Reading eats the pieces, so the list is cloned rather than kept: the same
// cut is driven at several read sizes, and a reader eating the caller's slice
// would leave every run after the first with nothing to read.
//
// An empty piece is a read that hands nothing over and reports no error, which
// io.Reader permits and nothing useful does.
// TestReader_readerMakingNoProgress is what drives them.
type pieceReader struct {
	pieces []string
	err    error
}

// newPieceReader returns a pieceReader over a list of its own.
func newPieceReader(pieces []string, err error) *pieceReader {
	return &pieceReader{pieces: slices.Clone(pieces), err: err}
}

func (r *pieceReader) Read(p []byte) (int, error) {
	if len(r.pieces) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		return 0, io.EOF
	}
	n := copy(p, r.pieces[0])
	if r.pieces[0] = r.pieces[0][n:]; r.pieces[0] == "" {
		r.pieces = r.pieces[1:]
	}
	return n, nil
}

// pieceReaderEOFWithData hands its last piece back together with the error
// that ends the stream, in the one call to Read that empties it, rather than
// reporting that piece and the error in two separate calls the way pieceReader
// always does. io.Reader documents (n > 0, err != nil) as a valid return — a
// Read may fill p and say why it will not be asked again in the same call —
// and both an http.Response.Body and a compress/flate reader do this in
// practice; pieceReader and strings.NewReader cannot drive it, so nothing built
// on either exercises a Reader against this shape.
type pieceReaderEOFWithData struct {
	pieces []string
	err    error
}

// newPieceReaderEOFWithData returns a pieceReaderEOFWithData over a list of its
// own, cloned for the reason newPieceReader clones: the same pieces are driven
// through more than one stub.
func newPieceReaderEOFWithData(pieces []string, err error) *pieceReaderEOFWithData {
	return &pieceReaderEOFWithData{pieces: slices.Clone(pieces), err: err}
}

func (r *pieceReaderEOFWithData) Read(p []byte) (int, error) {
	if len(r.pieces) == 0 {
		return 0, r.finalErr()
	}
	n := copy(p, r.pieces[0])
	if r.pieces[0] = r.pieces[0][n:]; r.pieces[0] != "" {
		return n, nil
	}
	if r.pieces = r.pieces[1:]; len(r.pieces) == 0 {
		// The last piece is fully copied out: what ends the stream travels
		// with it, rather than waiting for a call that finds nothing left.
		return n, r.finalErr()
	}
	return n, nil
}

// finalErr returns what pieceReaderEOFWithData ends the stream with: err where
// one was given, and io.EOF where none was.
func (r *pieceReaderEOFWithData) finalErr() error {
	if r.err != nil {
		return r.err
	}
	return io.EOF
}

// oneReadThenFailingReader hands src back on its first Read and fails the test
// if it is ever read again, in place of the block a live source with nothing
// more ready yet would put a caller through.
// TestReader_releasesTextBeforeItsSourceIsReadAgain is what drives it: every
// other Reader test here reads through to an EOF the source under it reports
// itself, which a Reader that buffered the whole stream before releasing
// anything would still pass — it would just hold everything until that EOF
// came. This stub never reports one, so asking it for more is what such a
// Reader would do instead, and is what fails the test in its place rather than
// hanging it.
type oneReadThenFailingReader struct {
	t    testing.TB
	src  string
	read bool
}

func (r *oneReadThenFailingReader) Read(p []byte) (int, error) {
	if r.read {
		r.t.Errorf("the source was read again before the text from its first read had come back")
		return 0, io.EOF
	}
	r.read = true
	return copy(p, r.src), nil
}

// splits returns the ways src is cut into pieces: at every single offset, at
// every pair of offsets for text short enough to try them all, and one byte at
// a time.
//
// The pairs are quadratic in the length of src, and under the race detector
// every one of them costs several times what it costs without. What a pair
// states is not a property the other cuts leave unstated — a stream agrees
// with Mask however it is cut — but a density: a piece bounded on both sides
// rather than on one. Every boundary a pair puts in the text, the byte-at-a-
// time cut puts there too, so what the detector loses here is the pairing of
// two boundaries with a whole piece between them, and it is the run without
// -race that holds that. The size moves rather than the test being skipped,
// which is what the race detector is branched on everywhere else here.
func splits(src string) [][]string {
	all := [][]string{{src}}
	for i := range len(src) + 1 {
		all = append(all, []string{src[:i], src[i:]})
	}
	if !raceEnabled && len(src) <= 48 {
		for i := range len(src) + 1 {
			for j := i; j < len(src)+1; j++ {
				all = append(all, []string{src[:i], src[i:j], src[j:]})
			}
		}
	}
	// A byte at a time and not a rune at a time: ranging over a string walks
	// runes, and a stream cut inside one is exactly what a cut anywhere has to
	// survive.
	byteAtATime := make([]string, 0, len(src))
	for i := 0; i < len(src); i++ {
		byteAtATime = append(byteAtATime, src[i:i+1])
	}
	return append(all, byteAtATime)
}

func TestWriter_matchesMask(t *testing.T) {
	// The whole of what a stream owes: cut the text anywhere at all and what
	// comes out is what Mask returns for the text uncut. Everything else about
	// a stream — how much it holds, when it rescans, where it discards — is
	// only ever a way of getting this right.
	// A subtest a redactor, run in parallel with the rest. Each builds a Masker
	// of its own and shares nothing with the others but the inputs, which
	// nothing here writes to.
	for name, r := range streamRedactors() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m := New(WithPatterns(AllBuiltinPatterns()...), WithRedactor(r))
			for _, src := range streamInputs() {
				want := m.Mask(src)
				for _, pieces := range splits(src) {
					if got := throughWriter(t, m, pieces); got != want {
						t.Errorf("writing %q in %d piece(s) gave %q, Mask gives %q", src, len(pieces), got, want)
					}
				}
			}
		})
	}
}

func TestReader_matchesMask(t *testing.T) {
	// The same for a Reader, driven at three sizes: one byte at a time, a size
	// no value fits in, and one that swallows whatever the stream releases.
	// What a caller reads in is not where the stream is cut — the pieces are —
	// but it is what says a partial read leaves the rest where the next one
	// finds it.
	//
	// The cut sweep runs in full for every redactor, whatever its read size:
	// the cuts are what finds a bug here, and that dimension does not depend
	// on the redactor at all. What is sampled instead is the pairing of a
	// redactor with a read size. fixed alone drives every size, since that is
	// what tells the three apart from one another; each of the rest drives one
	// size of its own, sizes assigned round-robin over others in the order
	// they are listed below, so every size is still driven by more than one
	// redactor and every redactor still drives the full cut sweep at least
	// once. Driving every redactor at every size would cost three times what
	// this does and check the same thing three times over past the first.
	all := streamRedactors()

	// others is every redactor besides fixed, checked against streamRedactors()
	// so that one added there without being added here is never silently left
	// out of this test rather than merely sampled less.
	others := []string{"fill", "empty", "named", "value", "wide-fill", "credential-shaped"}
	if got, want := len(all), len(others)+1; got != want {
		t.Fatalf("streamRedactors() has %d entries, this test accounts for %d", got, want)
	}
	sizes := []int{1, 7, 4096}

	// A subtest a redactor and, under it, a subtest an input, both run in
	// parallel with the rest. A Masker is safe for concurrent use and the one
	// here is shared as a caller shares it.
	run := func(name string, r Redactor, into []int) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m := New(WithPatterns(AllBuiltinPatterns()...), WithRedactor(r))
			for _, src := range streamInputs() {
				t.Run(fmt.Sprintf("%q", src), func(t *testing.T) {
					t.Parallel()

					want := m.Mask(src)
					for _, pieces := range splits(src) {
						for _, n := range into {
							if got := throughReader(t, m, pieces, n); got != want {
								t.Errorf("reading %q in %d piece(s) into %d bytes gave %q, Mask gives %q",
									src, len(pieces), n, got, want)
							}
						}
					}
				})
			}
		})
	}

	fixedRedactor, ok := all["fixed"]
	if !ok {
		t.Fatalf("streamRedactors() has no %q entry", "fixed")
	}
	run("fixed", fixedRedactor, sizes)
	for i, name := range others {
		r, ok := all[name]
		if !ok {
			t.Fatalf("streamRedactors() has no %q entry; others is stale against streamRedactors()", name)
		}
		run(name, r, []int{sizes[i%len(sizes)]})
	}
}

// regexpStreamPatterns is the expressions TestWriter_matchesMaskForRegexpPatterns
// and TestReader_matchesMaskForRegexpPatterns are both driven with: patterns
// built by MustRegexp, whose matches stand against one another in ways a
// window over a stream has to get right.
//
// A group standing further into a match than a window is deep, and a match
// anchored at the beginning of the text, are both cases where what a window
// would make of the match is not what the whole text makes of it — so neither
// settles anything and neither is ever handed one. `\Atoken=[0-9a-f]{6}` adds a
// second anchored expression with no group of its own, so what redacts is the
// whole match rather than a name inside it, and with a decoy repeating the same
// text past the anchor's reach so a stream matching it anywhere but the start
// would be caught.
//
// Either side of the boundary a window may still settle across, where a group
// stands as far into a match as one may and still be streamed and then a byte
// further, are two expressions more.
func regexpStreamPatterns() []string {
	return []string{
		`[0-9a-f]{40}`,
		`[0-9]{3}`,
		`\bkey-[0-9]{3}\b`,
		`(?m)^token=[0-9a-f]{6}`,
		`INT-(?P<mask>[0-9a-f]{8})`,
		`(?s)\A.{80}(?P<mask>SECRET)`,
		`(?s)x{2}.{200}(?P<mask>SECRET)`,
		`\Atoken=[0-9a-f]{6}`,
		`\bx` + strings.Repeat("A", LookBehind-utf8.UTFMax-1) + `(?P<mask>[0-9]{3})`,
		`\bx` + strings.Repeat("A", LookBehind-utf8.UTFMax) + `(?P<mask>[0-9]{3})`,
		`\b-x` + strings.Repeat("A", LookBehind-2) + `(?P<mask>[0-9]{3})`,
	}
}

// regexpStreamInputs is what every expression regexpStreamPatterns returns is
// driven over: text long enough that a stream lets go of some of what it has
// written before a match is found in it.
//
// The sixth entry opens on exactly eighty bytes and then "SECRET", which is
// what `(?s)\A.{80}(?P<mask>SECRET)` needs at the very start of the text to
// match anything at all. The eighth opens directly on "token=0123ab" instead,
// which is what `\Atoken=[0-9a-f]{6}` needs at the very start, and repeats that
// same opening a second time past sixty repeats of the word "filler" — text
// the anchor must not match a second time.
func regexpStreamInputs() []string {
	return []string{
		"sha=" + strings.Repeat("abcdef0123", 30),
		strings.Repeat("0123456789", 24),
		strings.Repeat("key-123 and INT-0123456789abcdef ", 8),
		strings.Repeat("token=0123ab\n", 20),
		strings.Repeat("x", 341) + "SECRET" + strings.Repeat("y", 300),
		strings.Repeat("x", 80) + "SECRET" + strings.Repeat("y", 300),
		strings.Repeat("z", 300) + "Qx" + strings.Repeat("A", LookBehind) + "123" + strings.Repeat("w", 100),
		"token=0123ab" + strings.Repeat(" filler", 60) + "token=0123ab",
		strings.Repeat("z", 300) + "Q-x" + strings.Repeat("A", LookBehind) + "123" + strings.Repeat("w", 100),
	}
}

func TestWriter_matchesMaskForRegexpPatterns(t *testing.T) {
	for _, expr := range regexpStreamPatterns() {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()

			m := New(WithPatterns(MustRegexp("p", expr)), WithRedactor(Fixed("[REDACTED]")))
			for _, src := range regexpStreamInputs() {
				want := m.Mask(src)
				for _, pieces := range splits(src) {
					if got := throughWriter(t, m, pieces); got != want {
						t.Errorf("writing %q in %d piece(s) gave %q, Mask gives %q", src, len(pieces), got, want)
					}
				}
			}
		})
	}
}

func TestReader_matchesMaskForRegexpPatterns(t *testing.T) {
	// The Reader side of TestWriter_matchesMaskForRegexpPatterns, driven at the
	// three read sizes TestReader_matchesMask drives.
	for _, expr := range regexpStreamPatterns() {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()

			m := New(WithPatterns(MustRegexp("p", expr)), WithRedactor(Fixed("[REDACTED]")))
			for _, src := range regexpStreamInputs() {
				want := m.Mask(src)
				for _, pieces := range splits(src) {
					for _, into := range []int{1, 7, 4096} {
						if got := throughReader(t, m, pieces, into); got != want {
							t.Errorf("reading %q in %d piece(s) into %d bytes gave %q, Mask gives %q",
								src, len(pieces), into, got, want)
						}
					}
				}
			}
		})
	}
}

// mixedRetainSrc is what TestWriter_combinesRetainFromMultiplePatterns and
// TestReader_combinesRetainFromMultiplePatterns are both driven over: a match
// for a MustRegexp expression with no opening literal, which settles nothing
// at all, followed by a GitHubToken value, which settles once its grammar
// closes.
//
// The pattern that settles nothing opens the text and the one that does
// settle follows it, so that a combiner reading anything but the least of the
// two retains would already have released text past the first match's start
// by the time a scan reports it — dropping that match outright rather than
// merely redacting it late. Masker.locate's doc comment on "from" is why:
// what starts in front of a released point is not redacted, it is dropped.
func mixedRetainSrc() string {
	return strings.Repeat("x", 80) + "SECRET\n" +
		"GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n"
}

func TestWriter_combinesRetainFromMultiplePatterns(t *testing.T) {
	// Every stream test above drives either a set of patterns that all settle
	// something, or one MustRegexp pattern that settles nothing, never both in
	// one Masker. How retain from several patterns combines — the least of
	// them, the last of them, the greatest — is what decides whether a stream
	// holding one pattern's open value releases it because another pattern
	// closed.
	m := New(WithPatterns(GitHubToken(), MustRegexp("nolit", `(?s).{80}SECRET`)), WithRedactor(Fixed("[REDACTED]")))
	src := mixedRetainSrc()
	want := m.Mask(src)

	for _, pieces := range splits(src) {
		if got := throughWriter(t, m, pieces, WithMaxRetained(0)); got != want {
			t.Errorf("writing %q in %d piece(s) gave %q, Mask gives %q", src, len(pieces), got, want)
		}
	}
}

func TestReader_combinesRetainFromMultiplePatterns(t *testing.T) {
	// The Reader side of TestWriter_combinesRetainFromMultiplePatterns, at the
	// three read sizes TestReader_matchesMask drives.
	m := New(WithPatterns(GitHubToken(), MustRegexp("nolit", `(?s).{80}SECRET`)), WithRedactor(Fixed("[REDACTED]")))
	src := mixedRetainSrc()
	want := m.Mask(src)

	for _, pieces := range splits(src) {
		for _, into := range []int{1, 7, 4096} {
			if got := throughReader(t, m, pieces, into, WithMaxRetained(0)); got != want {
				t.Errorf("reading %q in %d piece(s) into %d bytes gave %q, Mask gives %q",
					src, len(pieces), into, got, want)
			}
		}
	}
}

// naiveSecretPattern is a Pattern written the way NewPattern's own doc comment
// shows one: a Find that walks src for a literal with strings.Index and
// reports zero, the answer Pattern.Find's doc comment calls "what a Find
// written without a stream in mind returns." Every other NewPattern
// implementation in this package settles something instead: fixed
// (mask_test.go) and Test_NewPattern's inline pattern both report len(src),
// and TestMasker_Mask_concurrentUse's shared-secret pattern reports
// max(0, len(src)-len(secret)+1) the same way conformance's substringPattern
// does for that package. This one settles nothing at all, so a stream holding
// it never releases anything on its own — only a give-up or Close can.
func naiveSecretPattern() Pattern {
	return NewPattern("naive", func(src string) ([]Span, int) {
		var spans []Span
		for at := 0; ; {
			i := strings.Index(src[at:], "SECRET")
			if i < 0 {
				break
			}
			spans = append(spans, Span{Start: at + i, End: at + i + len("SECRET")})
			at += i + len("SECRET")
		}
		return spans, 0
	})
}

// naiveSecretSrc is what TestWriter_matchesMaskForANaivePatternThatSettlesNothing
// and TestReader_matchesMaskForANaivePatternThatSettlesNothing are both driven
// over: two occurrences of naiveSecretPattern's literal, far enough apart that
// a stream lets go of some of what it has written between them — if anything
// here ever lets go at all, which is what the test is asking.
func naiveSecretSrc() string {
	return "before SECRET middle\n" + strings.Repeat("filler line\n", 20) + "SECRET at the end\n"
}

func TestWriter_matchesMaskForANaivePatternThatSettlesNothing(t *testing.T) {
	m := New(WithPatterns(naiveSecretPattern()), WithRedactor(Fixed("[REDACTED]")))
	src := naiveSecretSrc()
	want := m.Mask(src)

	for _, pieces := range splits(src) {
		if got := throughWriter(t, m, pieces, WithMaxRetained(0)); got != want {
			t.Errorf("writing %q in %d piece(s) gave %q, Mask gives %q", src, len(pieces), got, want)
		}
	}
}

func TestReader_matchesMaskForANaivePatternThatSettlesNothing(t *testing.T) {
	// The Reader side of TestWriter_matchesMaskForANaivePatternThatSettlesNothing,
	// at the three read sizes TestReader_matchesMask drives.
	m := New(WithPatterns(naiveSecretPattern()), WithRedactor(Fixed("[REDACTED]")))
	src := naiveSecretSrc()
	want := m.Mask(src)

	for _, pieces := range splits(src) {
		for _, into := range []int{1, 7, 4096} {
			if got := throughReader(t, m, pieces, into, WithMaxRetained(0)); got != want {
				t.Errorf("reading %q in %d piece(s) into %d bytes gave %q, Mask gives %q",
					src, len(pieces), into, got, want)
			}
		}
	}
}

func TestWriter_holdsBackUntilAValueSettles(t *testing.T) {
	// What the property above cannot show, because it only ever looks at the
	// end: a value split across two writes reaches the writer underneath
	// redacted, and the half of it written first does not reach it at all in
	// the meantime.
	const token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"

	var got strings.Builder
	m := New(WithPatterns(GitHubToken()))
	w := NewWriter(&got, m)

	if _, err := w.Write([]byte("token=" + token[:12])); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if strings.Contains(got.String(), "ghp_") {
		t.Errorf("the first half of a token reached the writer underneath: %q", got.String())
	}
	if _, err := w.Write([]byte(token[12:] + "\n")); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if want := m.Mask("token=" + token + "\n"); got.String() != want {
		t.Errorf("the stream gave %q, Mask gives %q", got.String(), want)
	}
}

func TestWriter_releasesTextHoldingNoPrefix(t *testing.T) {
	// A stream that held a line back until the next one arrived would be no
	// use behind a log: nothing would appear until something else was logged.
	// Text ending in nothing any pattern opens with is settled where it
	// stands, so a line reaches the writer underneath as it is written.
	var got strings.Builder
	m := New(WithPatterns(AllBuiltinPatterns()...))
	w := NewWriter(&got, m)
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() = %v", err)
		}
	}()

	const line = "time=2026-08-17T00:00:00Z level=info msg=\"connection refused\"\n"
	if _, err := w.Write([]byte(line)); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if got.String() != line {
		t.Errorf("after one line the writer underneath has %q, want %q", got.String(), line)
	}
}

func TestWriter_releasesTextAnExpressionOpensOnNowhere(t *testing.T) {
	// A pattern built from an expression with no ceiling on its width holds a
	// stream from wherever a match could begin, and where the literal it opens
	// with stands nowhere, no match can begin anywhere. Without that, a pattern
	// finding nothing at all in a log would hold the log until the limit and
	// then redact the whole of it.
	m := New(WithPatterns(MustRegexp("key", `sk-[A-Za-z0-9]+`)))
	src := strings.Repeat("a line of prose, and nothing else at all\n", 40)

	var got strings.Builder
	w := NewWriter(&got, m, WithMaxRetained(128))
	if _, err := w.Write([]byte(src)); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if got.String() != src {
		t.Errorf("a pattern matching nothing changed the text: %q", got.String())
	}
}

func TestWriter_withoutPatternsReleasesEverything(t *testing.T) {
	var got strings.Builder
	w := NewWriter(&got, New())
	defer func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close() = %v", err)
		}
	}()

	if _, err := w.Write([]byte("ghp_0123456789abcdefghijklmnopqrstuvwxyz")); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if want := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"; got.String() != want {
		t.Errorf("the writer underneath has %q, want %q", got.String(), want)
	}
}

func TestWriter_closeWritesWhatIsHeld(t *testing.T) {
	// A value cut short by the end of the stream is settled by the end of the
	// stream, which is what Close says. Half a token is no token, so what
	// Close writes here is the text as it stands.
	var got strings.Builder
	m := New(WithPatterns(GitHubToken()))
	w := NewWriter(&got, m)

	const half = "ghp_012345"
	if _, err := w.Write([]byte(half)); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if got.String() != "" {
		t.Errorf("before Close the writer underneath has %q, want nothing", got.String())
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if got.String() != half {
		t.Errorf("after Close the writer underneath has %q, want %q", got.String(), half)
	}
}

func TestWriter_writeAfterClose(t *testing.T) {
	w := NewWriter(&strings.Builder{}, New())
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if _, err := w.Write([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Errorf("Write() after Close = %v, want %v", err, ErrClosed)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close() twice = %v, want nil", err)
	}
}

func TestWriter_closeTwiceDoesNotFlushHeldTextAgain(t *testing.T) {
	// TestWriter_writeAfterClose closes a Writer that never held anything, so
	// a second Close flushing the same text a second time would leave nothing
	// behind to notice it by. This drives a Writer that has real held-back
	// text instead — TestWriter_closeWritesWhatIsHeld's half token, which the
	// first Close settles and writes out — through a second Close, and checks
	// what the writer underneath holds rather than only what Close returns.
	var got strings.Builder
	m := New(WithPatterns(GitHubToken()))
	w := NewWriter(&got, m)

	const half = "ghp_012345"
	if _, err := w.Write([]byte(half)); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close() twice = %v, want nil", err)
	}
	if got.String() != half {
		t.Errorf("closing twice left %q in the writer underneath, want %q written once", got.String(), half)
	}
}

// closeCountingWriter is an io.Writer that is also an io.Closer, counting how
// many times it is closed. NewWriter's and Close's doc comments both say a
// Writer leaves dst open, and nothing here drove a dst capable of reporting
// otherwise: strings.Builder, io.Discard and errWriter (below) implement no
// Close at all, so a Writer that closed dst regardless would go unnoticed.
type closeCountingWriter struct {
	strings.Builder
	closes int
}

func (w *closeCountingWriter) Close() error {
	w.closes++
	return nil
}

func TestWriter_closeDoesNotCloseDst(t *testing.T) {
	dst := &closeCountingWriter{}
	m := New(WithPatterns(GitHubToken()))
	w := NewWriter(dst, m)

	if _, err := w.Write([]byte("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n")); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if dst.closes != 0 {
		t.Errorf("Writer.Close() closed dst %d time(s), want 0", dst.closes)
	}

	// dst is left open rather than merely uncounted: writing to it directly
	// after Writer.Close() has to still succeed and still land.
	if _, err := dst.Write([]byte("still open\n")); err != nil {
		t.Errorf("writing to dst after Writer.Close() = %v, want nil", err)
	}
	if want := "GITHUB_TOKEN=" + strings.Repeat("*", 40) + "\nstill open\n"; dst.String() != want {
		t.Errorf("dst has %q, want %q", dst.String(), want)
	}
}

// errWriter fails every write, so that a Writer is driven over a writer
// underneath that will not take what it is given.
type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWriter_errorIsSticky(t *testing.T) {
	// The text a failed write was carrying is gone with it. Writing on would
	// splice what comes next onto a stream missing its middle, so the failure
	// stands and every write after it reports the same thing.
	want := errors.New("no")
	w := NewWriter(errWriter{err: want}, New())

	if _, err := w.Write([]byte("something")); !errors.Is(err, want) {
		t.Fatalf("Write() = %v, want %v", err, want)
	}
	if _, err := w.Write([]byte("more")); !errors.Is(err, want) {
		t.Errorf("Write() after a failure = %v, want %v", err, want)
	}
	if err := w.Close(); !errors.Is(err, want) {
		t.Errorf("Close() after a failure = %v, want %v", err, want)
	}
}

// failAfter is an io.Writer that succeeds its first ok writes and fails every
// one after that with err. errWriter fails from the very first write, which is
// not the only way a real dst fails: a socket dropped mid-stream, a disk that
// fills up, or a pipe whose reader has gone all take some writes first.
type failAfter struct {
	ok  int
	err error
}

func (w *failAfter) Write(p []byte) (int, error) {
	if w.ok <= 0 {
		return 0, w.err
	}
	w.ok--
	return len(p), nil
}

func TestWriter_errorIsStickyAfterSeveralSuccessfulWrites(t *testing.T) {
	// TestWriter_errorIsSticky drives a dst that fails from its very first
	// write. This drives failAfter instead: the third write is what fails,
	// and everything after it — a fourth write and Close — has to report the
	// same error, the same way TestWriter_errorIsSticky holds a dst that fails
	// immediately to it.
	want := errors.New("no")
	w := NewWriter(&failAfter{ok: 2, err: want}, New())

	for i := range 2 {
		if _, err := w.Write([]byte("ok\n")); err != nil {
			t.Fatalf("Write() #%d = %v, want nil", i+1, err)
		}
	}
	if _, err := w.Write([]byte("third\n")); !errors.Is(err, want) {
		t.Fatalf("Write() #3 = %v, want %v", err, want)
	}
	if _, err := w.Write([]byte("fourth\n")); !errors.Is(err, want) {
		t.Errorf("Write() after a failure = %v, want %v", err, want)
	}
	if err := w.Close(); !errors.Is(err, want) {
		t.Errorf("Close() after a failure = %v, want %v", err, want)
	}
}

func TestWriter_closeReportsAFailureInItsOwnFlush(t *testing.T) {
	// TestWriter_errorIsSticky and TestWriter_errorIsStickyAfterSeveralSuccessfulWrites
	// both fail a write the caller made directly. This fails Close's own write
	// instead — the flush that lets go of whatever the stream is still
	// holding once the stream ends.
	//
	// TestWriter_closeWritesWhatIsHeld establishes that this half token
	// reaches the writer underneath only at Close, so the dst.Write inside
	// Close is the first one issued in this test at all, which makes it the
	// only place errWriter's failure can be reported from: every Write call
	// before Close has to succeed even though dst never accepts anything.
	want := errors.New("no")
	m := New(WithPatterns(GitHubToken()))
	w := NewWriter(errWriter{err: want}, m)

	if _, err := w.Write([]byte("ghp_012345")); err != nil {
		t.Fatalf("Write() = %v, want nil", err)
	}
	if err := w.Close(); !errors.Is(err, want) {
		t.Errorf("Close() = %v, want %v", err, want)
	}
}

func TestWriter_doesNotRetainTheSliceItIsGivenToWrite(t *testing.T) {
	// io.Writer's contract is explicit that "implementations must not retain
	// p." A Writer built to hold text back has a reason to break it that an
	// ordinary io.Writer does not, and nothing here drove a caller that reuses
	// its buffer the way io.Copy and a bufio-style loop both do: every write
	// above hands over a freshly allocated []byte(string) that nothing else
	// holds a reference to, so a Writer keeping the slice instead of copying
	// out of it would still pass.
	//
	// This buffer is reused and overwritten between writes instead: 'Z' fills
	// it right after each Write call returns, before the next one is filled
	// and handed over.
	m := New(WithPatterns(GitHubToken()))
	src := "prefix GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz suffix\n"

	var got strings.Builder
	w := NewWriter(&got, m)
	buf := make([]byte, 8)
	for i := 0; i < len(src); i += len(buf) {
		n := copy(buf, src[i:min(i+len(buf), len(src))])
		if _, err := w.Write(buf[:n]); err != nil {
			t.Fatalf("Write() = %v", err)
		}
		for j := range buf {
			buf[j] = 'Z'
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	if want := m.Mask(src); got.String() != want {
		t.Errorf("the writer underneath has %q, Mask gives %q", got.String(), want)
	}
	if strings.Contains(got.String(), "Z") {
		t.Errorf("the writer underneath holds a 'Z' the caller's buffer was overwritten with: %q", got.String())
	}
}

func TestWriter_maxRetained(t *testing.T) {
	// A run of the characters a value is written in, arriving without end, is
	// a value without end to the pattern reading it. The limit is where the
	// holding stops, and it stops with a redaction: the text goes out under
	// the name of the pattern that was holding it, not as it came in.
	const held = 512
	var got strings.Builder
	m := New(
		WithPatterns(StripeSecretKey()),
		WithRedactor(NewRedactor(func(m Match) string { return "<" + m.Pattern.Name() + ">" })),
	)
	w := NewWriter(&got, m, WithMaxRetained(held))

	src := "sk_live_" + strings.Repeat("0123456789abcdef", 4*held/16)
	if _, err := w.Write([]byte(src)); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if strings.Contains(got.String(), "0123456789abcdef") {
		t.Errorf("the run reached the writer underneath as it came in: %q", got.String())
	}
	if !strings.Contains(got.String(), "<stripe-secret-key>") {
		t.Errorf("the held text was not redacted under the pattern holding it: %q", got.String())
	}
}

func TestWriter_givesBackWhatItHeld(t *testing.T) {
	// A stream that once held a great deal must not go on holding it. Behind a
	// log a Writer is open for the life of the program, and a run that reached
	// the limit once would otherwise keep what it reached for.
	const held = 4 << 10

	m := New(WithPatterns(StripeSecretKey()))
	w := NewWriter(io.Discard, m, WithMaxRetained(held))

	big := "sk_live_" + strings.Repeat("0123456789abcdef", 64*held/16)
	for _, piece := range []string{big, " and then an ordinary line\n"} {
		if _, err := w.Write([]byte(piece)); err != nil {
			t.Fatalf("Write() = %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	if got := cap(w.s.buf); got > held {
		t.Errorf("after holding %d bytes and letting them go, the buffer keeps %d", len(big), got)
	}
	if got := cap(w.s.ready); got > held {
		t.Errorf("after writing out %d bytes, the masked text keeps %d", len(big), got)
	}
}

func TestWriter_maxRetainedGivesUpOnAnUnboundedLiteralLessExpressionEvenWithoutAMatch(t *testing.T) {
	// README advises writing counted repetition rather than an open "+" or
	// "*" for exactly this: an expression with no opening literal and no
	// ceiling on its width settles nothing at all, wherever it stands in the
	// text and whatever the text holds — Test_MustRegexp_settlesNothingWithoutABoundOrALiteral
	// is what holds MustRegexp to that. So nothing here ever leaves the
	// stream except by way of WithMaxRetained, and it reaches that limit on
	// prose the expression does not match even once.
	//
	// Once the limit is first exceeded, giving up takes the pattern's own scan
	// out of the window for the rest of the stream — WithMaxRetained's doc
	// comment says why — so no later write is ever checked against [0-9]+
	// again; it is simply swept into the next redaction.
	//
	// The count below is worked out from that rather than measured: 660 bytes
	// arrive in 42 writes of sixteen bytes each (the last one only four,
	// ceil(660/16) = 42) under a sixteen-byte limit. Nothing settles before
	// the limit is first exceeded, which the first two writes do together at
	// 32 held bytes, so those two land in one redaction; every write after
	// that starts from nothing held and ends past the limit on its own
	// sixteen bytes, so each lands in a redaction of its own. That is one
	// redaction for the first two writes and one for each of the forty writes
	// after them: 1 + (42 - 2) = 41, and no byte of the prose ever reaches
	// the writer underneath unredacted.
	const prose = "prose " // 6 bytes, holds no digit.
	src := strings.Repeat(prose, 110)
	if len(src) != 660 {
		t.Fatalf("test bug: len(src) = %d, want 660", len(src))
	}

	var got strings.Builder
	m := New(WithPatterns(MustRegexp("digits", "[0-9]+")), WithRedactor(Fixed("X")))
	w := NewWriter(&got, m, WithMaxRetained(16))
	for i := 0; i < len(src); i += 16 {
		if _, err := w.Write([]byte(src[i:min(i+16, len(src))])); err != nil {
			t.Fatalf("Write() = %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	if want := strings.Repeat("X", 41); got.String() != want {
		t.Errorf("got %q (%d bytes), want %q (%d bytes)", got.String(), len(got.String()), want, len(want))
	}
}

func TestReader_maxRetainedGivesUpOnAnUnboundedLiteralLessExpressionEvenWithoutAMatch(t *testing.T) {
	// The Reader side of TestWriter_maxRetainedGivesUpOnAnUnboundedLiteralLessExpressionEvenWithoutAMatch:
	// the same prose, arriving from its source in the same sixteen-byte
	// pieces, under the same limit. The source is what decides how much
	// arrives at once — Reader.Read pulls from it in one gulp per call to the
	// reader underneath — so pieces sixteen bytes wide reproduce the same
	// sequence of advances as sixteen-byte writes do, whatever size the
	// caller here reads into.
	const prose = "prose "
	src := strings.Repeat(prose, 110)
	if len(src) != 660 {
		t.Fatalf("test bug: len(src) = %d, want 660", len(src))
	}
	var pieces []string
	for i := 0; i < len(src); i += 16 {
		pieces = append(pieces, src[i:min(i+16, len(src))])
	}

	m := New(WithPatterns(MustRegexp("digits", "[0-9]+")), WithRedactor(Fixed("X")))
	got := throughReader(t, m, pieces, 4096, WithMaxRetained(16))

	if want := strings.Repeat("X", 41); got != want {
		t.Errorf("got %q (%d bytes), want %q (%d bytes)", got, len(got), want, len(want))
	}
}

func TestWriter_maxRetainedRedactsEveryByteOfAnUnboundedLiteralLessExpression(t *testing.T) {
	// TestWriter_maxRetainedGivesUpOnAnUnboundedLiteralLessExpressionEvenWithoutAMatch
	// derives an exact count from one specific way of cutting 660 bytes into
	// sixteen-byte writes. The property behind that count — no byte of prose
	// ever reaches the writer underneath, whatever the cut — does not depend
	// on that one way of cutting, so this drives it over every cut splits()
	// makes instead, at a size small enough that the full sweep costs little:
	// the count itself is not asserted here, only that everything the writer
	// underneath holds is the redaction.
	prose := strings.Repeat("word ", 8) // 40 bytes, holds no digit.
	m := New(WithPatterns(MustRegexp("digits", "[0-9]+")), WithRedactor(Fixed("X")))

	for _, pieces := range splits(prose) {
		got := throughWriter(t, m, pieces, WithMaxRetained(8))
		if trimmed := strings.ReplaceAll(got, "X", ""); trimmed != "" {
			t.Errorf("cutting into %d piece(s) left %q besides the redaction", len(pieces), trimmed)
		}
	}
}

func TestReader_maxRetainedRedactsEveryByteOfAnUnboundedLiteralLessExpression(t *testing.T) {
	// The Reader side of TestWriter_maxRetainedRedactsEveryByteOfAnUnboundedLiteralLessExpression.
	prose := strings.Repeat("word ", 8)
	m := New(WithPatterns(MustRegexp("digits", "[0-9]+")), WithRedactor(Fixed("X")))

	for _, pieces := range splits(prose) {
		for _, into := range []int{1, 7, 4096} {
			got := throughReader(t, m, pieces, into, WithMaxRetained(8))
			if trimmed := strings.ReplaceAll(got, "X", ""); trimmed != "" {
				t.Errorf("reading %d piece(s) into %d bytes left %q besides the redaction", len(pieces), into, trimmed)
			}
		}
	}
}

func TestWriter_maxRetainedRedactsWhatFollowsToo(t *testing.T) {
	// Giving up on a value takes the opening of that value out of the window
	// with it, and a pattern shown the middle of a value without its opening
	// reports nothing. A stream going back to passing text through would write
	// out the rest of the very value it gave up holding, so it does not go
	// back — and no part of the key here reaches the writer underneath.
	body := strings.Repeat("MIIBOgIBAAJBAK0123456789abcdefghijklmnopqrstuvwxyz0123456789ab\n", 60)
	src := "-----BEGIN RSA PRIVATE KEY-----\n" + body + "-----END RSA PRIVATE KEY-----\n"

	var got strings.Builder
	m := New(WithPatterns(PrivateKey()), WithRedactor(Fixed("<KEY>")))
	w := NewWriter(&got, m, WithMaxRetained(1<<10))
	for i := 0; i < len(src); i += 100 {
		if _, err := w.Write([]byte(src[i:min(i+100, len(src))])); err != nil {
			t.Fatalf("Write() = %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	for _, held := range []string{"MIIBOgIBAAJBAK", "-----BEGIN", "-----END"} {
		if strings.Contains(got.String(), held) {
			t.Errorf("%q reached the writer underneath: %q", held, got.String())
		}
	}

	// What is left is the redaction and nothing else, written once a write
	// because a stream cannot hold the rest of itself back to write it as one.
	if trimmed := strings.ReplaceAll(got.String(), "<KEY>", ""); trimmed != "" {
		t.Errorf("the writer underneath holds %q besides the redaction", trimmed)
	}
}

func TestWriter_maxRetainedCountsARuneOnce(t *testing.T) {
	// A redactor is handed the text it replaces, and Fill counts the runes of
	// it. A rune the writes are split inside must reach the redactor whole, or
	// the pieces are counted a rune apiece — which is a redaction longer than
	// the text it stands for, after a limit that is already redacting more than
	// it must.
	src := "sk_live_" + strings.Repeat("0123456789abcdef", 8) + "日本語のログ行"

	var got strings.Builder
	m := New(WithPatterns(StripeSecretKey()))
	w := NewWriter(&got, m, WithMaxRetained(8))
	for i := 0; i < len(src); i++ {
		if _, err := w.Write([]byte(src[i : i+1])); err != nil {
			t.Fatalf("Write() = %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	if want := utf8.RuneCountInString(src); utf8.RuneCountInString(got.String()) != want {
		t.Errorf("the writer underneath has %d runes, the text has %d",
			utf8.RuneCountInString(got.String()), want)
	}
}

func TestWriter_releasesAWholeRuneOrNoneOfIt(t *testing.T) {
	// What a scan settles is a place in the text rather than a place between
	// runes, so a settle point falls inside a rune wherever the text carries
	// one: the HashiCorp scan settles this text one byte in, which is inside
	// the two-byte rune it opens with.
	//
	// A stream releasing the first byte of that rune leaves the second behind
	// to go out on its own once the stream gives up holding — a redaction
	// opening in the middle of a rune, text that went in as valid UTF-8 coming
	// out as something that is not, and a rune counted twice by a redactor
	// counting what it is handed. So the byte is held with the rest of the rune
	// rather than released ahead of it.
	src := "ϻ0000000000000.000000000000000000000000000000"

	var got strings.Builder
	m := New(WithPatterns(HCPTerraformAPIToken()), WithRedactor(Fill('*')))
	w := NewWriter(&got, m, WithMaxRetained(9))
	for _, piece := range []string{src[:16], src[16:]} {
		if _, err := w.Write([]byte(piece)); err != nil {
			t.Fatalf("Write(%q) = %v", piece, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	if !utf8.ValidString(got.String()) {
		t.Errorf("the writer underneath holds %q, which the text is not", got.String())
	}
	if want := utf8.RuneCountInString(src); utf8.RuneCountInString(got.String()) != want {
		t.Errorf("the writer underneath has %d rune(s), the text has %d",
			utf8.RuneCountInString(got.String()), want)
	}
}

func TestWriter_maxRetainedZeroHoldsWithoutLimit(t *testing.T) {
	var got strings.Builder
	m := New(WithPatterns(StripeSecretKey()))
	w := NewWriter(&got, m, WithMaxRetained(0))

	src := "sk_live_" + strings.Repeat("0123456789abcdef", 1<<12)
	if _, err := w.Write([]byte(src)); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if want := m.Mask(src); got.String() != want {
		t.Errorf("holding without limit gave %d bytes, Mask gives %d", len(got.String()), len(want))
	}
}

func TestWriter_maxRetainedNegativeHoldsWithoutLimit(t *testing.T) {
	// WithMaxRetained's doc comment reads any n below zero as that same zero
	// rather than as a limit no text can come under. A limit read the other
	// way — as a bound nothing can meet — would give up on a stream as soon
	// as anything was written to it.
	src := "sk_live_" + strings.Repeat("0123456789abcdef", 1<<12)
	want := New(WithPatterns(StripeSecretKey())).Mask(src)

	for _, n := range []int{-1, -64, math.MinInt} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			t.Parallel()

			var got strings.Builder
			m := New(WithPatterns(StripeSecretKey()))
			w := NewWriter(&got, m, WithMaxRetained(n))
			if _, err := w.Write([]byte(src)); err != nil {
				t.Fatalf("Write() = %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close() = %v", err)
			}
			if got.String() != want {
				t.Errorf("WithMaxRetained(%d) gave %d bytes, Mask gives %d", n, len(got.String()), len(want))
			}
		})
	}
}

func TestReader_maxRetainedNegativeHoldsWithoutLimit(t *testing.T) {
	// The Reader side of TestWriter_maxRetainedNegativeHoldsWithoutLimit.
	src := "sk_live_" + strings.Repeat("0123456789abcdef", 1<<12)
	want := New(WithPatterns(StripeSecretKey())).Mask(src)

	for _, n := range []int{-1, -64, math.MinInt} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			t.Parallel()

			m := New(WithPatterns(StripeSecretKey()))
			r := NewReader(strings.NewReader(src), m, WithMaxRetained(n))
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("ReadAll() = %v", err)
			}
			if string(got) != want {
				t.Errorf("WithMaxRetained(%d) gave %d bytes, Mask gives %d", n, len(got), len(want))
			}
		})
	}
}

func TestWriter_maxRetainedDefaultGivesUp(t *testing.T) {
	// TestWriter_maxRetained holds an explicit, small WithMaxRetained to giving
	// up once a run of the value's characters crosses it. This asks the same
	// of the limit nobody sets: every other case here either gives
	// WithMaxRetained a small number or gives it zero, and FuzzStreamGivesUp
	// folds its limit into 1..256, so the default a Writer opened without an
	// option ever reaches is otherwise never exercised.
	//
	// WithMaxRetained's doc comment reads defaultMaxRetained as generous enough
	// that no credential written in one piece comes near it — a mebibyte — so
	// the body here is built past that mark by hand rather than read out of the
	// constant: a body sized from the constant would grow with it and never
	// find whatever the default drifted to.
	body := strings.Repeat("0123456789abcdef", 1<<16+1<<10) // > 1 MiB of hex.
	src := "sk_live_" + body

	var got strings.Builder
	m := New(WithPatterns(StripeSecretKey()), WithRedactor(Fixed("<gave up>")))
	w := NewWriter(&got, m)
	if _, err := w.Write([]byte(src)); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	if strings.Contains(got.String(), "0123456789abcdef") {
		t.Errorf("the run reached the writer underneath as it came in: %d byte(s) held it", len(got.String()))
	}
	if !strings.Contains(got.String(), "<gave up>") {
		t.Errorf("the default limit never gave up on %d bytes: %q", len(src), got.String())
	}
}

func TestWriter_maxRetainedDefaultCountsRunesEvenAfterGivingUp(t *testing.T) {
	// TestWriter_maxRetainedCountsARuneOnce holds Fill to counting a rune once
	// under an explicit limit. This holds the same thing under the default
	// one, built the same way TestWriter_maxRetainedDefaultGivesUp is, so that
	// a default read as unlimited fails this on rune count rather than only on
	// TestWriter_maxRetainedDefaultGivesUp's redaction.
	body := strings.Repeat("0123456789abcdef", 1<<16+1<<10)
	src := "sk_live_" + body

	var got strings.Builder
	m := New(WithPatterns(StripeSecretKey())) // Fill('*') by default.
	w := NewWriter(&got, m)
	if _, err := w.Write([]byte(src)); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	if want := utf8.RuneCountInString(src); utf8.RuneCountInString(got.String()) != want {
		t.Errorf("the writer underneath has %d rune(s), the text has %d",
			utf8.RuneCountInString(got.String()), want)
	}
}

func TestReader_maxRetainedDefaultGivesUp(t *testing.T) {
	// The Reader side of TestWriter_maxRetainedDefaultGivesUp.
	body := strings.Repeat("0123456789abcdef", 1<<16+1<<10)
	src := "sk_live_" + body

	m := New(WithPatterns(StripeSecretKey()), WithRedactor(Fixed("<gave up>")))
	got, err := io.ReadAll(NewReader(strings.NewReader(src), m))
	if err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}

	if strings.Contains(string(got), "0123456789abcdef") {
		t.Errorf("the run reached the reader's caller as it came in: %d byte(s) held it", len(got))
	}
	if !strings.Contains(string(got), "<gave up>") {
		t.Errorf("the default limit never gave up on %d bytes: %q", len(src), got)
	}
}

func TestReader_maxRetainedDefaultCountsRunesEvenAfterGivingUp(t *testing.T) {
	// The Reader side of TestWriter_maxRetainedDefaultCountsRunesEvenAfterGivingUp.
	body := strings.Repeat("0123456789abcdef", 1<<16+1<<10)
	src := "sk_live_" + body

	m := New(WithPatterns(StripeSecretKey())) // Fill('*') by default.
	got, err := io.ReadAll(NewReader(strings.NewReader(src), m))
	if err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}

	if want := utf8.RuneCountInString(src); utf8.RuneCountInString(string(got)) != want {
		t.Errorf("the reader's caller has %d rune(s), the text has %d", utf8.RuneCountInString(string(got)), want)
	}
}

func TestReader_errorIsHeldUntilTheTextIs(t *testing.T) {
	// The text held when the stream ended has to come out before the error
	// that ended it, or a caller reading to the error loses the tail.
	want := errors.New("no")
	m := New(WithPatterns(GitHubToken()))
	r := NewReader(newPieceReader([]string{"ghp_012345"}, want), m, WithMaxRetained(0))

	got, err := io.ReadAll(r)
	if !errors.Is(err, want) {
		t.Fatalf("ReadAll() = %v, want %v", err, want)
	}
	if string(got) != "ghp_012345" {
		t.Errorf("ReadAll() gave %q, want %q", got, "ghp_012345")
	}
}

func TestReader_holdsACompleteValueThroughANonEOFError(t *testing.T) {
	// TestReader_errorIsHeldUntilTheTextIs holds back "ghp_012345", a fragment
	// too short to be a value at all, so it reaches the caller unredacted
	// either way — an implementation redacting held text on error and one
	// writing it out raw would both pass that test. This drives the same
	// shape with a complete value instead: a full GitHub token, still held
	// because nothing yet says the stream has ended, meeting a non-EOF error.
	// What comes back has to be the redaction, not the token itself, and it
	// still has to come out before the error that ended the stream.
	want := errors.New("no")
	const token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	m := New(WithPatterns(GitHubToken()), WithRedactor(Fixed("[REDACTED]")))
	r := NewReader(newPieceReader([]string{token}, want), m, WithMaxRetained(0))

	got, err := io.ReadAll(r)
	if !errors.Is(err, want) {
		t.Fatalf("ReadAll() = %v, want %v", err, want)
	}
	if string(got) != "[REDACTED]" {
		t.Errorf("ReadAll() gave %q, want %q", got, "[REDACTED]")
	}
}

func TestReader_errorIsHeldUntilTheTextIsWhenItArrivesWithTheText(t *testing.T) {
	// TestReader_errorIsHeldUntilTheTextIs drives a source that reports its
	// last piece and the error that ends the stream in two separate reads, the
	// way pieceReader always does. Here they arrive together in one, which
	// io.Reader permits and pieceReader cannot drive: the text a Reader was
	// still holding has to come out before the error either way.
	want := errors.New("no")
	m := New(WithPatterns(GitHubToken()))
	r := NewReader(newPieceReaderEOFWithData([]string{"ghp_012345"}, want), m, WithMaxRetained(0))

	got, err := io.ReadAll(r)
	if !errors.Is(err, want) {
		t.Fatalf("ReadAll() = %v, want %v", err, want)
	}
	if string(got) != "ghp_012345" {
		t.Errorf("ReadAll() gave %q, want %q", got, "ghp_012345")
	}
}

func TestReader_matchesMaskWhenTheFinalReadCarriesEOFWithIt(t *testing.T) {
	// TestReader_matchesMask is driven over pieceReader, which always reports
	// its last piece and then a separate, empty read carrying io.EOF.
	// strings.NewReader does the same. Neither drives the shape io.Reader
	// documents as valid — (n > 0, err != nil) in the one call — and both an
	// http.Response.Body and a compress/flate reader return exactly that at
	// the end of a stream, so this holds a Reader to the same property over
	// pieceReaderEOFWithData instead.
	m := New(WithPatterns(AllBuiltinPatterns()...), WithRedactor(Fixed("[REDACTED]")))

	for _, src := range streamInputs() {
		t.Run(fmt.Sprintf("%q", src), func(t *testing.T) {
			t.Parallel()

			want := m.Mask(src)
			for _, pieces := range splits(src) {
				for _, into := range []int{1, 7, 4096} {
					got := throughReaderSrc(t, m, newPieceReaderEOFWithData(pieces, nil), into)
					if got != want {
						t.Errorf("reading %q in %d piece(s) into %d bytes gave %q, Mask gives %q",
							src, len(pieces), into, got, want)
					}
				}
			}
		})
	}
}

func TestReader_releasesTextBeforeItsSourceIsReadAgain(t *testing.T) {
	// TestWriter_releasesTextHoldingNoPrefix holds a Writer to giving back text
	// ending in nothing any pattern opens with as soon as it is written, rather
	// than waiting for something else to arrive first. The same property
	// matters for a Reader; oneReadThenFailingReader below is what lets this
	// catch a Reader that instead buffered the whole stream before releasing
	// anything.
	//
	// Behind a live source, arriving is what an EOF does not do on its own
	// schedule. A source that answers one Read and would otherwise block for
	// more has to have that answer handed back on the Reader's first Read,
	// without the Reader asking the source for a second one — which
	// oneReadThenFailingReader fails the test for instead of blocking it.
	const line = "time=2026-08-17T00:00:00Z level=info msg=\"connection refused\"\n"

	tests := []struct {
		name string
		m    *Masker
	}{
		{name: "no patterns at all", m: New()},
		{name: "patterns that settle the line without holding any of it", m: New(WithPatterns(AllBuiltinPatterns()...))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReader(&oneReadThenFailingReader{t: t, src: line}, tt.m)
			buf := make([]byte, len(line))
			n, err := r.Read(buf)
			if err != nil {
				t.Fatalf("Read() = %d, %v, want %d, nil", n, err, len(line))
			}
			if got := string(buf[:n]); got != line {
				t.Errorf("Read() gave %q, want %q", got, line)
			}
		})
	}
}

func TestReader_readerMakingNoProgress(t *testing.T) {
	// A reader handing nothing over and reporting no error is one a Reader
	// would otherwise turn on forever. maxEmptyReads is where the turning
	// stops and io.ErrNoProgress is what it stops with, which is where bufio
	// draws the line too.
	//
	// A read that hands something over starts the count again, and that is
	// driven here too: the count is how long a reader may pause for and not how
	// many times it may pause, so a Reader behind a slow source would otherwise
	// end on a wait it had already been through.
	tests := []struct {
		name   string
		pieces []string
		want   string
		err    error
	}{
		{
			name:   "a reader that hands nothing over at all",
			pieces: slices.Repeat([]string{""}, maxEmptyReads),
			err:    io.ErrNoProgress,
		},
		{
			name:   "a reader that waits one read short of the count and ends",
			pieces: slices.Repeat([]string{""}, maxEmptyReads-1),
		},
		{
			name: "a reader that waits one read short of the count either side of a value",
			pieces: slices.Concat(
				slices.Repeat([]string{""}, maxEmptyReads-1),
				[]string{"ghp_0123456789abcdefghijklmnopqrstuvwxyz"},
				slices.Repeat([]string{""}, maxEmptyReads-1),
			),
			want: "[REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(WithPatterns(GitHubToken()), WithRedactor(Fixed("[REDACTED]")))
			got, err := io.ReadAll(NewReader(newPieceReader(tt.pieces, nil), m))
			if !errors.Is(err, tt.err) {
				t.Fatalf("ReadAll() = %v, want %v", err, tt.err)
			}
			if string(got) != tt.want {
				t.Errorf("ReadAll() gave %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReader_emptyBuffer(t *testing.T) {
	r := NewReader(strings.NewReader("x"), New())
	if n, err := r.Read(nil); n != 0 || err != nil {
		t.Errorf("Read(nil) = %d, %v, want 0, nil", n, err)
	}
}

func TestStream_isLinear(t *testing.T) {
	// A stream rescanning everything it holds on every write costs time
	// quadratic in the length of a stretch that stays held, which is what
	// scanGrowth is weighed against. Two mebibytes of a run no pattern ever
	// closes is that stretch, written one byte at a time so that the number of
	// rescans is the number of bytes if nothing bounds it.
	//
	// Two seconds is a bound of use rather than one that merely passes: a
	// linear stream writes this in about thirty milliseconds, and a stream
	// scanning on every write would be walking two mebibytes two million
	// times.
	// The race detector puts a cost on every write that has nothing to do with
	// what is being measured, so what is driven under it is smaller. Smaller
	// and not skipped: a quadratic stream is quadratic at either size, and the
	// bound below is a hundredfold above what a linear one takes.
	size := 2 << 20
	if raceEnabled {
		size = 1 << 18
	}
	const limit = 2 * time.Second
	src := "sk_live_" + strings.Repeat("0123456789abcdef", size/16)

	// maxRetained is driven at two values: zero, where the stream never gives
	// up and every byte adds to what stays held, and one small enough that it
	// gives up early and spends the rest of the run redacting a write at a
	// time — the clock for that path, distinct from the memory
	// TestWriter_givesBackWhatItHeld already bounds.
	for _, maxRetained := range []int{0, 1024} {
		t.Run(fmt.Sprintf("WithMaxRetained(%d)", maxRetained), func(t *testing.T) {
			m := New(WithPatterns(AllBuiltinPatterns()...))
			w := NewWriter(io.Discard, m, WithMaxRetained(maxRetained))

			start := time.Now()
			for i := range len(src) {
				if _, err := w.Write([]byte(src[i : i+1])); err != nil {
					t.Fatalf("Write() = %v", err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close() = %v", err)
			}
			if d := time.Since(start); d > limit {
				t.Errorf("writing %d bytes one at a time took %v", len(src), d)
			}
			if maxRetained > 0 {
				if got := cap(w.s.buf); got > maxRetained*4 {
					t.Errorf("after giving up, the buffer keeps %d bytes under a %d-byte limit", got, maxRetained)
				}
			}
		})
	}
}

func FuzzWriter_matchesMask(f *testing.F) {
	f.Add("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz", 20)
	f.Add("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef", 40)
	f.Add("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----\n", 31)
	f.Add("xoxe.xoxb-0123456789-0123456789012-0123456789abcdefghijklmn", 10)
	f.Add("ghs_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef", 8)
	f.Add("there is no credential in this sentence", 7)
	f.Add("", 0)

	m := New(WithPatterns(AllBuiltinPatterns()...), WithRedactor(Fixed("[REDACTED]")))
	f.Fuzz(func(t *testing.T, src string, cut int) {
		cut = normalizeCut(src, cut)
		want := m.Mask(src)
		if got := throughWriter(t, m, []string{src[:cut], src[cut:]}); got != want {
			t.Fatalf("writing %q cut at %d gave %q, Mask gives %q", src, cut, got, want)
		}
	})
}

func TestWriter_writeAfterCloseTouchesNothing(t *testing.T) {
	// ErrClosed says a Writer written to after Close is finished. Finished
	// means dst hears nothing more from it, whether the bytes would have been
	// released at once or held back a while first, and whether p carries
	// anything at all.
	tests := []struct {
		name string
		m    *Masker
		p    []byte
	}{
		{name: "released text", m: New(), p: []byte("plain text that would pass straight through")},
		{name: "held text", m: New(WithPatterns(GitHubToken())), p: []byte("ghp_012345")},
		{name: "nil write", m: New(), p: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dst strings.Builder
			w := NewWriter(&dst, tt.m)
			if err := w.Close(); err != nil {
				t.Fatalf("Close() = %v", err)
			}
			n, err := w.Write(tt.p)
			if n != 0 || !errors.Is(err, ErrClosed) {
				t.Errorf("Write() after Close = %d, %v, want 0, %v", n, err, ErrClosed)
			}
			if dst.String() != "" {
				t.Errorf("a write after Close reached dst: %q", dst.String())
			}
		})
	}
}

func TestWriter_closeTwiceAfterAFailedFlush(t *testing.T) {
	// TestWriter_closeTwiceDoesNotFlushHeldTextAgain closes twice where the
	// first Close actually flushed held text and succeeded. This closes twice
	// where the first Close's own flush is what fails: "Closing twice reports
	// what the first close did rather than doing it again" said of a Close
	// that failed, not only one that didn't.
	want := errors.New("no")
	m := New(WithPatterns(GitHubToken()))
	w := NewWriter(errWriter{err: want}, m)

	// A half token is held rather than released, so Close's own flush — not
	// the Write above it — is the first write reaching dst at all, the same
	// way TestWriter_closeReportsAFailureInItsOwnFlush sets it up.
	if _, err := w.Write([]byte("ghp_012345")); err != nil {
		t.Fatalf("Write() = %v, want nil", err)
	}
	if err := w.Close(); !errors.Is(err, want) {
		t.Fatalf("first Close() = %v, want %v", err, want)
	}
	if err := w.Close(); !errors.Is(err, want) {
		t.Errorf("second Close() = %v, want %v", err, want)
	}
}

func TestWriter_writeAfterCloseWhenAlsoFailed(t *testing.T) {
	// Write checks a stored failure before it checks closed, so a Writer that
	// failed and was then closed goes on reporting the failure: the text a
	// failed write was carrying is gone with it, and closing afterwards does
	// not change what going on would splice together.
	want := errors.New("no")
	w := NewWriter(errWriter{err: want}, New())

	if n, err := w.Write([]byte("x")); n != 0 || !errors.Is(err, want) {
		t.Fatalf("Write() = %d, %v, want 0, %v", n, err, want)
	}
	if err := w.Close(); !errors.Is(err, want) {
		t.Fatalf("Close() = %v, want %v", err, want)
	}
	if n, err := w.Write([]byte("y")); n != 0 || !errors.Is(err, want) {
		t.Errorf("Write() after Close = %d, %v, want 0, %v", n, err, want)
	}
}

// recordingWriter is an io.Writer that keeps everything it is handed and fails
// from its (ok+1)th call on, so a dst that takes some writes before it fails —
// a socket dropped mid-stream rather than one dead from the start — can be
// told apart from errWriter, which never takes any.
type recordingWriter struct {
	ok  int
	err error

	buf   strings.Builder
	calls int
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.ok <= 0 {
		return 0, w.err
	}
	w.ok--
	w.buf.Write(p)
	return len(p), nil
}

func TestWriter_dstReceivesNothingAfterAFailedWrite(t *testing.T) {
	// TestWriter_errorIsSticky and TestWriter_errorIsStickyAfterSeveralSuccessfulWrites
	// hold the returned error to being sticky. Neither looks at dst: a Writer
	// that went on handing dst every write after the failure — splicing a
	// stream missing its middle back together — would pass both of them, since
	// what dst does with what it is given is not what either asserts.
	want := errors.New("no")
	dst := &recordingWriter{ok: 1, err: want}
	m := New()
	w := NewWriter(dst, m)

	if _, err := w.Write([]byte("aaaa\n")); err != nil {
		t.Fatalf("Write() #1 = %v, want nil", err)
	}
	if _, err := w.Write([]byte("bbbb\n")); !errors.Is(err, want) {
		t.Fatalf("Write() #2 = %v, want %v", err, want)
	}
	if _, err := w.Write([]byte("cccc\n")); !errors.Is(err, want) {
		t.Errorf("Write() #3 = %v, want %v", err, want)
	}
	if err := w.Close(); !errors.Is(err, want) {
		t.Errorf("Close() = %v, want %v", err, want)
	}

	if got := dst.buf.String(); got != "aaaa\n" {
		t.Errorf("dst holds %q, want only the write before the failure", got)
	}
	// One call for the write that succeeded, one for the write that failed,
	// and none after: a Writer that has failed stops calling dst at all.
	if dst.calls != 2 {
		t.Errorf("dst.Write was called %d time(s), want 2", dst.calls)
	}
}

// partialThenErrWriter returns n bytes together with err on its (ok+1)th call,
// which is the (n > 0, err != nil) shape io.Writer's contract permits and
// errWriter and recordingWriter cannot drive: a pipe or a socket can report
// that it took some of what it was given and will take no more in the same
// call.
type partialThenErrWriter struct {
	ok  int
	n   int
	err error

	buf   strings.Builder
	calls int
}

func (w *partialThenErrWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.ok <= 0 {
		n := min(w.n, len(p))
		w.buf.Write(p[:n])
		return n, w.err
	}
	w.ok--
	w.buf.Write(p)
	return len(p), nil
}

func TestWriter_dstPartialWriteWithAnError(t *testing.T) {
	want := errors.New("no")
	dst := &partialThenErrWriter{ok: 0, n: 3, err: want}
	w := NewWriter(dst, New())

	if _, err := w.Write([]byte("abcdef")); !errors.Is(err, want) {
		t.Fatalf("Write() = %v, want %v", err, want)
	}
	if _, err := w.Write([]byte("ghi")); !errors.Is(err, want) {
		t.Errorf("Write() after a partial failure = %v, want %v", err, want)
	}
	// A write reporting (n > 0, err) is a failure the same as one reporting
	// (0, err): the stream stands where the failed write left it, so nothing
	// after the partial bytes it did take reaches dst.
	if dst.calls != 1 {
		t.Errorf("dst.Write was called %d time(s) after a partial failure, want 1", dst.calls)
	}
}

// shortWriter consumes all but the last byte it is given and reports no
// error, which io.Writer's own contract calls out as ill-behaved ("Write must
// return a non-nil error if it returns n < len(p)") and which io.ErrShortWrite
// exists to name.
type shortWriter struct{ strings.Builder }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return w.Builder.Write(p[:len(p)-1])
}

func TestWriter_dstShortWriteWithNilError(t *testing.T) {
	dst := &shortWriter{}
	w := NewWriter(dst, New())

	if _, err := w.Write([]byte("a long line of ordinary text\n")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Write() = %v, want %v", err, io.ErrShortWrite)
	}
	// A short write with no error of its own is still a failure the stream
	// does not write past: it is sticky exactly as a dst that returned an
	// error outright would be.
	if _, err := w.Write([]byte("more\n")); !errors.Is(err, io.ErrShortWrite) {
		t.Errorf("Write() after a short write = %v, want %v", err, io.ErrShortWrite)
	}
	if err := w.Close(); !errors.Is(err, io.ErrShortWrite) {
		t.Errorf("Close() after a short write = %v, want %v", err, io.ErrShortWrite)
	}
}

func TestWriter_defaultLimitDoesNotGiveUpOnARealisticPrivateKey(t *testing.T) {
	// TestWriter_maxRetainedDefaultGivesUp holds the default to eventually
	// giving up on a run with no end. This holds the other side of the same
	// doc sentence: "The default is generous enough that no credential written
	// in one piece comes near it." A private key is the largest credential the
	// registry locates in one piece, and this one is sized to a real armored
	// key rather than to the constant the default is read out of, so a default
	// that shrank would fail this before it failed anything reading the
	// constant back.
	body := strings.Repeat("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0\n", 60)
	src := "-----BEGIN PRIVATE KEY-----\n" + body + "-----END PRIVATE KEY-----\n"

	m := New(WithPatterns(PrivateKey()), WithRedactor(Fill('*')))
	want := m.Mask(src)

	for _, pieces := range [][]string{{src}, splitEvery(src, 100)} {
		if got := throughWriter(t, m, pieces); got != want {
			t.Errorf("writing in %d piece(s) gave %d byte(s), Mask gives %d", len(pieces), len(got), len(want))
		}
		if got := throughReader(t, m, pieces, 4096); got != want {
			t.Errorf("reading in %d piece(s) gave %d byte(s), Mask gives %d", len(pieces), len(got), len(want))
		}
	}
}

// splitEvery cuts src into pieces of n bytes, the last one short where len(src)
// is not a multiple of n.
func splitEvery(src string, n int) []string {
	var pieces []string
	for i := 0; i < len(src); i += n {
		pieces = append(pieces, src[i:min(i+n, len(src))])
	}
	return pieces
}

func TestWriter_writeDoesNotModifyPDuringTheCall(t *testing.T) {
	// io.Writer's contract: "Write must not modify the slice data, even
	// temporarily." TestWriter_doesNotRetainTheSliceItIsGivenToWrite holds a
	// Writer to not keeping a reference to p once Write has returned; this
	// holds it to not changing what p holds while Write is running, which that
	// test's after-the-call overwrite cannot show.
	const src = "prefix GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz suffix\n"
	p := []byte(src)

	w := NewWriter(io.Discard, New(WithPatterns(GitHubToken())))
	if _, err := w.Write(p); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if string(p) != src {
		t.Errorf("the caller's slice reads %q after Write, want %q unchanged", p, src)
	}
}

func TestWriter_ordinaryTextAfterGiveUpIsFullyRedacted(t *testing.T) {
	// TestWriter_maxRetainedRedactsWhatFollowsToo drives one credential and
	// nothing else, so the only text after the give-up point is more of the
	// very value that triggered it. This drives ordinary lines holding no
	// credential at all in separate Write calls after the give-up, which is
	// what a long-lived log Writer spends the rest of its life doing: giving
	// up takes the pattern's scan out of the window, so nothing written after
	// that point is ever checked against it again.
	var got strings.Builder
	m := New(WithPatterns(StripeSecretKey()), WithRedactor(Fixed("X")))
	w := NewWriter(&got, m, WithMaxRetained(64))

	if _, err := w.Write([]byte("sk_live_" + strings.Repeat("0123456789abcdef", 32))); err != nil {
		t.Fatalf("Write() #1 = %v", err)
	}
	if _, err := w.Write([]byte("\nan entirely ordinary line\n")); err != nil {
		t.Fatalf("Write() #2 = %v", err)
	}
	if _, err := w.Write([]byte("and another\n")); err != nil {
		t.Fatalf("Write() #3 = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	for _, held := range []string{"ordinary", "another", "0123456789abcdef"} {
		if strings.Contains(got.String(), held) {
			t.Errorf("%q reached the writer underneath: %q", held, got.String())
		}
	}
	if trimmed := strings.ReplaceAll(got.String(), "X", ""); trimmed != "" {
		t.Errorf("the writer underneath holds %q besides the redaction", trimmed)
	}
}

func TestWriter_nEqualsLenPOnGiveUpAndAfter(t *testing.T) {
	// Write's doc comment pins n to len(p) "whenever there is no error". No
	// test checked that on the write that trips WithMaxRetained or on any
	// write after it, where what reaches dst is shorter or longer than p
	// itself once a redactor changes the length of what it replaces.
	tests := []struct {
		name     string
		redactor Redactor
	}{
		{name: "shorter redaction", redactor: Fixed("<KEY>")},
		{name: "empty redaction", redactor: Fixed("")},
	}
	body := strings.Repeat("MIIBOgIBAAJBAK0123456789abcdefghijklmnopqrstuvwxyz0123456789ab\n", 60)
	src := "-----BEGIN RSA PRIVATE KEY-----\n" + body + "-----END RSA PRIVATE KEY-----\n"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got strings.Builder
			m := New(WithPatterns(PrivateKey()), WithRedactor(tt.redactor))
			w := NewWriter(&got, m, WithMaxRetained(1<<10))
			for i := 0; i < len(src); i += 100 {
				piece := src[i:min(i+100, len(src))]
				n, err := w.Write([]byte(piece))
				if err != nil {
					t.Fatalf("Write(%d bytes) = %v", len(piece), err)
				}
				if n != len(piece) {
					t.Errorf("Write(%d bytes) = %d, want %d", len(piece), n, len(piece))
				}
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close() = %v", err)
			}
		})
	}
}

func TestWriter_settleNothingPatternMixedWithBuiltinsHoldsUntilClose(t *testing.T) {
	// "A Reader or a Writer holds what no pattern has settled." No test mixed
	// a settle-nothing pattern into a set that also holds every builtin, which
	// is the shape a caller actually reaches for — AllBuiltinPatterns plus one
	// pattern of their own. Mixing one such pattern in stops the whole stream
	// releasing anything before Close, however plainly the rest of the text
	// reads.
	m := New(WithPatterns(AllBuiltinPatterns()...), WithPatterns(naiveSecretPattern()))
	src := strings.Repeat("an entirely ordinary line of log output\n", 40)
	want := m.Mask(src)

	var got strings.Builder
	w := NewWriter(&got, m, WithMaxRetained(0))
	if _, err := w.Write([]byte(src)); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if got.Len() != 0 {
		t.Errorf("before Close the writer underneath has %d byte(s), want 0", got.Len())
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if got.String() != want {
		t.Errorf("the writer underneath has %q, Mask gives %q", got.String(), want)
	}
}

// degenerateSpanPattern reports the same four spans over any src: one with a
// negative Start, one whose Start is not less than its End the ordinary way
// (reversed), one whose Start equals its End (empty), and one reaching past
// the end of a 6-byte src. Pattern.Find's doc comment calls all four ignored.
// It settles nothing, so a Reader or a Writer holding one has to be driven
// with WithMaxRetained(0) or it would give up before the text it is fed ever
// ends.
func degenerateSpanPattern() Pattern {
	return NewPattern("degenerate", func(src string) ([]Span, int) {
		return []Span{
			{Start: -1, End: 2},
			{Start: 4, End: 2},
			{Start: 3, End: 3},
			{Start: 4, End: 7},
		}, 0
	})
}

func TestWriter_degenerateSpansAreIgnored(t *testing.T) {
	// unusable_spans.txt in conformance states this for Mask. This holds a
	// Writer and a Reader to it too: windowing makes "past the end" a
	// different offset in every window a stream opens, which the whole-text
	// corpus case says nothing about.
	m := New(WithPatterns(degenerateSpanPattern()))
	const src = "abcdef"
	want := m.Mask(src)
	if want != src {
		t.Fatalf("test bug: Mask(%q) = %q, want it unchanged", src, want)
	}

	for _, pieces := range splits(src) {
		if got := throughWriter(t, m, pieces, WithMaxRetained(0)); got != want {
			t.Errorf("writing %q in %d piece(s) gave %q, want %q", src, len(pieces), got, want)
		}
	}
}

func TestReader_degenerateSpansAreIgnored(t *testing.T) {
	// The Reader side of TestWriter_degenerateSpansAreIgnored, at the three
	// read sizes TestReader_matchesMask drives.
	m := New(WithPatterns(degenerateSpanPattern()))
	const src = "abcdef"
	want := m.Mask(src)

	for _, pieces := range splits(src) {
		for _, into := range []int{1, 7, 4096} {
			if got := throughReader(t, m, pieces, into, WithMaxRetained(0)); got != want {
				t.Errorf("reading %q in %d piece(s) into %d bytes gave %q, want %q",
					src, len(pieces), into, got, want)
			}
		}
	}
}

func TestWriter_redactorOutputIsNotRescanned(t *testing.T) {
	// Mask is a single pass and its output is never handed back through the
	// patterns, so a redactor whose own output one of the patterns in the set
	// would locate has to reach the writer underneath as it stands rather than
	// redacted a second time. A stream owes the same output as Mask, and a
	// stream whose window happened to catch its own redaction in a later scan
	// would diverge from it here.
	m := New(
		WithPatterns(StripeSecretKey(), GitHubToken()),
		WithRedactor(NewRedactor(func(mm Match) string {
			if mm.Pattern.Name() == StripeSecretKey().Name() {
				return "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
			}
			return "[GH]"
		})),
	)
	src := "a sk_live_" + strings.Repeat("0123456789abcdef", 2) + " b"
	want := m.Mask(src)
	if !strings.Contains(want, "ghp_0123456789abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("test bug: Mask(%q) = %q, want the substituted token literal in it", src, want)
	}

	for _, pieces := range splits(src) {
		if got := throughWriter(t, m, pieces); got != want {
			t.Errorf("writing %q in %d piece(s) gave %q, Mask gives %q", src, len(pieces), got, want)
		}
	}
}

func TestReader_redactorOutputIsNotRescanned(t *testing.T) {
	// The Reader side of TestWriter_redactorOutputIsNotRescanned.
	m := New(
		WithPatterns(StripeSecretKey(), GitHubToken()),
		WithRedactor(NewRedactor(func(mm Match) string {
			if mm.Pattern.Name() == StripeSecretKey().Name() {
				return "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
			}
			return "[GH]"
		})),
	)
	src := "a sk_live_" + strings.Repeat("0123456789abcdef", 2) + " b"
	want := m.Mask(src)

	for _, pieces := range splits(src) {
		for _, into := range []int{1, 7, 4096} {
			if got := throughReader(t, m, pieces, into); got != want {
				t.Errorf("reading %q in %d piece(s) into %d bytes gave %q, Mask gives %q",
					src, len(pieces), into, got, want)
			}
		}
	}
}

func TestWriter_redactionInvalidUTF8PassesThroughByteForByte(t *testing.T) {
	// Redactor.Redact: "It is written out as it is returned." A redaction that
	// is not itself valid UTF-8 has to reach the writer underneath exactly as
	// the redactor wrote it, whatever the stream's own rune-boundary handling
	// does with the text it replaced.
	m := New(WithPatterns(GitHubToken()), WithRedactor(Fixed("\xff\xfe")))
	src := "a ghp_0123456789abcdefghijklmnopqrstuvwxyz b"
	want := m.Mask(src)

	for _, pieces := range splits(src) {
		if got := throughWriter(t, m, pieces); got != want {
			t.Errorf("writing %q in %d piece(s) gave %q, Mask gives %q", src, len(pieces), got, want)
		}
	}
}

func TestWriter_noPatternsWithATinyMaxRetained(t *testing.T) {
	// "A Masker with no patterns redacts nothing" and WithMaxRetained "sets
	// how much text a Reader or a Writer holds back before it gives up" — with
	// nothing ever held, the limit is never reached, however small it is.
	src := strings.Repeat("an entirely ordinary line of log output\n", 256)

	for _, limit := range []int{1, 2, 8} {
		t.Run(fmt.Sprintf("limit=%d", limit), func(t *testing.T) {
			var got strings.Builder
			w := NewWriter(&got, New(), WithMaxRetained(limit))
			for _, piece := range splitEvery(src, 3) {
				if _, err := w.Write([]byte(piece)); err != nil {
					t.Fatalf("Write() = %v", err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close() = %v", err)
			}
			if got.String() != src {
				t.Errorf("a pattern-free Writer under WithMaxRetained(%d) changed the text", limit)
			}
		})
	}
}

// callRecordingWriter keeps a copy of every slice it is handed, so a test can
// ask how many times dst.Write was called and how long each call was, not only
// what the concatenation of them holds.
type callRecordingWriter struct{ calls [][]byte }

func (w *callRecordingWriter) Write(p []byte) (int, error) {
	w.calls = append(w.calls, append([]byte(nil), p...))
	return len(p), nil
}

func TestWriter_closeWithNothingHeldCallsDstZeroTimes(t *testing.T) {
	dst := &callRecordingWriter{}
	w := NewWriter(dst, New())
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if len(dst.calls) != 0 {
		t.Errorf("Close() on a Writer that was never written to called dst.Write %d time(s), want 0", len(dst.calls))
	}
}

func TestWriter_neverWritesAnEmptySliceToDst(t *testing.T) {
	// A Writer holding text back writes nothing to dst while it holds it,
	// rather than a zero-length slice standing in for nothing to say.
	const token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"

	dst := &callRecordingWriter{}
	m := New(WithPatterns(GitHubToken()))
	w := NewWriter(dst, m)

	for _, piece := range []string{"token=" + token[:12], token[12:] + "\n"} {
		if _, err := w.Write([]byte(piece)); err != nil {
			t.Fatalf("Write(%q) = %v", piece, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	for i, call := range dst.calls {
		if len(call) == 0 {
			t.Errorf("dst.Write call #%d was empty", i)
		}
	}
}

func TestWriter_ioCopyIntoAWriter(t *testing.T) {
	// NewWriter's own doc comment reaches for log.SetOutput(w), and io.Copy is
	// how text is fed to an ordinary io.Writer sink — through whatever
	// ReadFrom/WriteTo fast path io.Copy picks, which would bypass masking if
	// a Writer ever exposed one.
	src := strings.Repeat("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n", 200)
	m := New(WithPatterns(GitHubToken()))
	want := m.Mask(src)

	t.Run("Copy", func(t *testing.T) {
		var got strings.Builder
		w := NewWriter(&got, m)
		n, err := io.Copy(w, strings.NewReader(src))
		if err != nil {
			t.Fatalf("io.Copy() = %v", err)
		}
		if n != int64(len(src)) {
			t.Errorf("io.Copy() copied %d byte(s), want %d", n, len(src))
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close() = %v", err)
		}
		if got.String() != want {
			t.Errorf("the writer underneath has %d byte(s), Mask gives %d", got.Len(), len(want))
		}
	})

	t.Run("CopyBuffer with a 3-byte buffer", func(t *testing.T) {
		// strings.Reader implements io.WriterTo, and io.CopyBuffer prefers
		// that over the buffer it was handed — so a bare strings.NewReader
		// here would take the same fast path as the Copy subtest above and
		// never drive the buffer at all. Wrapping it in a bare io.Reader
		// hides WriteTo and forces io.CopyBuffer to read through the 3-byte
		// buffer a chunk at a time, which is the path this subtest exists to
		// drive.
		var got strings.Builder
		w := NewWriter(&got, m)
		n, err := io.CopyBuffer(w, struct{ io.Reader }{strings.NewReader(src)}, make([]byte, 3))
		if err != nil {
			t.Fatalf("io.CopyBuffer() = %v", err)
		}
		if n != int64(len(src)) {
			t.Errorf("io.CopyBuffer() copied %d byte(s), want %d", n, len(src))
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close() = %v", err)
		}
		if got.String() != want {
			t.Errorf("the writer underneath has %d byte(s), Mask gives %d", got.Len(), len(want))
		}
	})
}

// unevenCuts returns src cut into k pieces at a coarse, uneven stride, for
// values long enough that splits' own 3-piece sweep leaves alone: splits only
// tries every pair of offsets for src of 48 bytes or less, so a longer value
// arriving in three to six pieces the way a bufio.Writer or a network read
// loop actually produces it is driven nowhere else.
func unevenCuts(src string, ks []int) [][]string {
	var all [][]string
	for _, k := range ks {
		stride := max(1, len(src)/(k*3))
		var pieces []string
		at := 0
		for i := 0; i < k-1; i++ {
			n := min(stride*(i+1), len(src)-at)
			pieces = append(pieces, src[at:at+n])
			at += n
		}
		pieces = append(pieces, src[at:])
		all = append(all, pieces)
	}
	return all
}

func TestWriter_longValueUnevenMultiWayCuts(t *testing.T) {
	m := New(WithPatterns(AllBuiltinPatterns()...))
	srcs := []string{
		"GITHUB_TOKEN=" + "ghp_0123456789abcdefghijklmnopqrstuvwxyz" + " and more text after it\n",
		"sk_live_" + strings.Repeat("0123456789abcdef", 8),
	}
	for _, src := range srcs {
		want := m.Mask(src)
		for _, pieces := range unevenCuts(src, []int{3, 4, 5, 6}) {
			if got := throughWriter(t, m, pieces); got != want {
				t.Errorf("writing %q in %d uneven piece(s) gave %q, Mask gives %q", src, len(pieces), got, want)
			}
		}
	}
}

func TestWriter_closeWritesATruncatedRuneAtTheEnd(t *testing.T) {
	// "Close writes out the text the Writer is holding back": nothing may be
	// dropped at Close, including the fragment of a rune the input itself
	// stops inside — a log truncated at a byte limit, or a partial read.
	// incompleteRune's doc comment is what makes such a fragment held back at
	// all rather than released as it stands; this holds Close to writing it
	// out rather than discarding it once nothing more of the stream is
	// coming.
	src := "sk_live_" + strings.Repeat("0123456789abcdef", 4) + "\xe6\x97" // first two bytes of a three-byte rune

	var got strings.Builder
	m := New(WithPatterns(StripeSecretKey()), WithRedactor(Fill('*')))
	w := NewWriter(&got, m, WithMaxRetained(8))
	for i := 0; i < len(src); i++ {
		if _, err := w.Write([]byte(src[i : i+1])); err != nil {
			t.Fatalf("Write() = %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	if got.Len() == 0 {
		t.Fatal("Close() wrote nothing")
	}
	if want := utf8.RuneCountInString(src); utf8.RuneCountInString(got.String()) != want {
		t.Errorf("the writer underneath has %d rune(s), the text has %d", utf8.RuneCountInString(got.String()), want)
	}
}

func TestStream_concurrentWritersAndReadersOverASharedMasker(t *testing.T) {
	// "A Masker is fixed once created and is safe for concurrent use by
	// multiple goroutines," and neither a Writer nor a Reader is safe for
	// concurrent use itself — the supported shape is one Writer or Reader per
	// goroutine, all over one shared Masker. TestReader_matchesMask already
	// drives concurrent Readers over a shared Masker through its parallel
	// subtests; nothing drove concurrent Writers over one, or a mix of both.
	//
	// Each worker runs as a subtest with t.Parallel() rather than as a bare
	// spawned goroutine sharing the outer *testing.T: throughWriter and
	// throughReader call t.Fatalf on a Write/Read/Close error, and testing's
	// contract is that FailNow may only be called from the goroutine running
	// the test — a bare goroutine calling it would Goexit that one worker
	// without stopping or being accounted for by the rest, leaving the run's
	// report incomplete. A subtest's function runs on a goroutine the testing
	// package itself manages, so a failure there is attributed to that worker
	// alone and every other worker still runs to completion.
	m := New(WithPatterns(AllBuiltinPatterns()...))
	srcs := []string{
		"GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n",
		"sk_live_" + strings.Repeat("0123456789abcdef", 8),
		"nothing to see here\n",
		"日本語のログ行\n",
	}

	for g := range 8 {
		t.Run(fmt.Sprintf("goroutine %d", g), func(t *testing.T) {
			t.Parallel()

			for _, src := range srcs {
				want := m.Mask(src)
				if g%2 == 0 {
					if got := throughWriter(t, m, []string{src}); got != want {
						t.Errorf("writing %q gave %q, Mask gives %q", src, got, want)
					}
				} else {
					if got := throughReader(t, m, []string{src}, 7); got != want {
						t.Errorf("reading %q gave %q, Mask gives %q", src, got, want)
					}
				}
			}
		})
	}
}

func TestWriter_maxRetainedAttributionOnATie(t *testing.T) {
	// WithMaxRetained's doc comment: "attributed to the pattern that was
	// holding it" — singular. locations.holder (mask.go) is the pattern
	// reporting the least retain, kept on a strict less-than comparison as the
	// patterns are walked in the order a Masker was given them, so two
	// patterns reporting the same retain leave the earlier-registered one
	// holding it. Two expressions built identically but for their names give
	// that tie deterministically; running them in both orders is what shows
	// the answer follows registration order rather than something else the
	// two happen to share.
	src := "sk_live_" + strings.Repeat("0123456789abcdef", 8)

	for _, names := range [][2]string{{"a", "b"}, {"b", "a"}} {
		t.Run(strings.Join(names[:], ","), func(t *testing.T) {
			m := New(
				WithPatterns(MustRegexp(names[0], `sk_live_[0-9a-f]+`), MustRegexp(names[1], `sk_live_[0-9a-f]+`)),
				WithRedactor(NewRedactor(func(mm Match) string { return "<" + mm.Pattern.Name() + ">" })),
			)
			got := throughWriter(t, m, []string{src}, WithMaxRetained(8))

			if want := "<" + names[0] + ">"; !strings.Contains(got, want) {
				t.Errorf("got %q, want it to contain %q", got, want)
			}
			if other := "<" + names[1] + ">"; strings.Contains(got, other) {
				t.Errorf("got %q, the later-registered pattern %q was attributed instead", got, other)
			}
		})
	}
}

func TestWriter_streamOptionsLastWins(t *testing.T) {
	// WithRedactor's last-wins behaviour is pinned by Test_WithRedactor_lastWins
	// (option_test.go) for the Option family; StreamOption is built the same
	// way — a func applied to a struct in the order given, each one free to
	// overwrite what an earlier one set — so a later WithMaxRetained overwrites
	// an earlier one the same way.
	src := "sk_live_" + strings.Repeat("0123456789abcdef", 64)

	tests := []struct {
		name string
		opts []StreamOption
		want int
	}{
		{name: "generous then small", opts: []StreamOption{WithMaxRetained(4096), WithMaxRetained(16)}, want: 16},
		{name: "small then generous", opts: []StreamOption{WithMaxRetained(16), WithMaxRetained(4096)}, want: 4096},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(WithPatterns(StripeSecretKey()))
			got := throughWriter(t, m, []string{src}, tt.opts...)
			want := throughWriter(t, m, []string{src}, WithMaxRetained(tt.want))
			if got != want {
				t.Errorf("got %q, want the same as WithMaxRetained(%d) alone: %q", got, tt.want, want)
			}
		})
	}
}

func TestReader_streamOptionsLastWins(t *testing.T) {
	// The Reader side of TestWriter_streamOptionsLastWins.
	src := "sk_live_" + strings.Repeat("0123456789abcdef", 64)

	tests := []struct {
		name string
		opts []StreamOption
		want int
	}{
		{name: "generous then small", opts: []StreamOption{WithMaxRetained(4096), WithMaxRetained(16)}, want: 16},
		{name: "small then generous", opts: []StreamOption{WithMaxRetained(16), WithMaxRetained(4096)}, want: 4096},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(WithPatterns(StripeSecretKey()))
			got := throughReader(t, m, []string{src}, 4096, tt.opts...)
			want := throughReader(t, m, []string{src}, 4096, WithMaxRetained(tt.want))
			if got != want {
				t.Errorf("got %q, want the same as WithMaxRetained(%d) alone: %q", got, tt.want, want)
			}
		})
	}
}

func TestWriter_oneHugeWriteWithValuesAtBothEnds(t *testing.T) {
	// A single Write compared against Mask exists at 64KiB of one repeated
	// value (TestWriter_maxRetainedZeroHoldsWithoutLimit) and at ~3.9KiB of
	// many values (TestWriter_maxRetainedRedactsWhatFollowsToo). Neither is a
	// multi-megabyte single Write carrying distinct values at its very first
	// and very last bytes, which is what a whole file read with os.ReadFile
	// and written in one call looks like.
	size := 2 << 20
	if raceEnabled {
		size = 1 << 18
	}
	src := "ghp_0123456789abcdefghijklmnopqrstuvwxyz " +
		strings.Repeat("a line of ordinary log output\n", size/30) +
		" sk_live_0123456789abcdefghijklmnopqrstuvwx"

	m := New(WithPatterns(AllBuiltinPatterns()...))
	want := m.Mask(src)

	var got strings.Builder
	w := NewWriter(&got, m)
	n, err := w.Write([]byte(src))
	if err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if n != len(src) {
		t.Fatalf("Write() = %d, want %d", n, len(src))
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if got.String() != want {
		t.Errorf("the writer underneath has %d byte(s), Mask gives %d", got.Len(), len(want))
	}
}

func TestReader_oneHugeReadWithValuesAtBothEnds(t *testing.T) {
	// The Reader side of TestWriter_oneHugeWriteWithValuesAtBothEnds: the
	// whole of src comes from one io.Reader, rather than from pieces a test
	// chose the boundaries of.
	size := 2 << 20
	if raceEnabled {
		size = 1 << 18
	}
	src := "ghp_0123456789abcdefghijklmnopqrstuvwxyz " +
		strings.Repeat("a line of ordinary log output\n", size/30) +
		" sk_live_0123456789abcdefghijklmnopqrstuvwx"

	m := New(WithPatterns(AllBuiltinPatterns()...))
	want := m.Mask(src)

	got, err := io.ReadAll(NewReader(strings.NewReader(src), m))
	if err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}
	if string(got) != want {
		t.Errorf("the reader gave %d byte(s), Mask gives %d", len(got), len(want))
	}
}

// countingReader wraps an io.Reader and counts how many times Read was called
// on it, so a test can assert the reader underneath is not read again once a
// Reader has stopped asking it for more — after an error, or after io.EOF.
type countingReader struct {
	r     io.Reader
	calls int
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.calls++
	return r.r.Read(p)
}

func TestReader_emptyBufferLeavesTheStreamIntact(t *testing.T) {
	// TestReader_emptyBuffer pins the single return value of Read(nil). It
	// does not ask whether the pending text survives a zero-length read
	// untouched, whether the source is left alone by one, or whether
	// make([]byte, 0) is read the same way a literal nil is.
	const src = "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	m := New(WithPatterns(GitHubToken()), WithRedactor(Fixed("[REDACTED]")))
	src2 := &countingReader{r: strings.NewReader(src)}
	r := NewReader(src2, m)

	for _, p := range [][]byte{nil, make([]byte, 0)} {
		if n, err := r.Read(p); n != 0 || err != nil {
			t.Fatalf("Read(%#v) = %d, %v, want 0, nil", p, n, err)
		}
	}
	if src2.calls != 0 {
		t.Errorf("a zero-length Read touched the reader underneath %d time(s)", src2.calls)
	}

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}
	if want := "GITHUB_TOKEN=[REDACTED]"; string(got) != want {
		t.Errorf("ReadAll() after the zero-length reads gave %q, want %q", got, want)
	}
}

func TestReader_readAfterEOF(t *testing.T) {
	// io.Reader's convention: a Reader that has already reported io.EOF goes
	// on reporting it, rather than (0, nil) — which nothing here checked — or
	// re-reading a source that has nothing left, which io.Copy, a bufio.Reader
	// wrapper and a hand-written drain loop all do without asking first.
	src := &countingReader{r: strings.NewReader("ghp_0123456789abcdefghijklmnopqrstuvwxyz")}
	m := New(WithPatterns(GitHubToken()), WithRedactor(Fixed("[REDACTED]")))
	r := NewReader(src, m)

	if _, err := io.ReadAll(r); err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}
	callsAtEOF := src.calls

	buf := make([]byte, 16)
	for i := range 5 {
		n, err := r.Read(buf)
		if n != 0 || !errors.Is(err, io.EOF) {
			t.Errorf("Read() #%d after EOF = %d, %v, want 0, %v", i, n, err, io.EOF)
		}
	}
	if src.calls != callsAtEOF {
		t.Errorf("the reader underneath was read %d more time(s) after EOF", src.calls-callsAtEOF)
	}
}

func TestReader_errorIsStickyAfterANonEOFFailure(t *testing.T) {
	// TestReader_errorIsHeldUntilTheTextIs holds the error to being reported
	// once, after the text held with it. This calls Read again afterward,
	// and holds the reader underneath to not being read again either.
	want := errors.New("no")
	src := &countingReader{r: newPieceReader([]string{"ghp_012345"}, want)}
	m := New(WithPatterns(GitHubToken()))
	r := NewReader(src, m, WithMaxRetained(0))

	if _, err := io.ReadAll(r); !errors.Is(err, want) {
		t.Fatalf("ReadAll() = %v, want %v", err, want)
	}
	callsAtFailure := src.calls

	buf := make([]byte, 16)
	for i := range 3 {
		n, err := r.Read(buf)
		if n != 0 || !errors.Is(err, want) {
			t.Errorf("Read() #%d after the failure = %d, %v, want 0, %v", i, n, err, want)
		}
	}
	if src.calls != callsAtFailure {
		t.Errorf("the reader underneath was read %d more time(s) after it had already failed", src.calls-callsAtFailure)
	}
}

func TestReader_makesProgressForANonEmptyBuffer(t *testing.T) {
	// "Reading returns nothing until the stream settles enough text to fill
	// something, so a read here can take several reads of the reader
	// underneath." io.Reader's convention discourages (0, nil) for a
	// non-empty p, which is the risk while the source is still handing over
	// the opening of a value the stream has to hold rather than release.
	m := New(WithPatterns(GitHubToken()))

	for _, size := range []int{1, 7, 64} {
		t.Run(fmt.Sprintf("into=%d", size), func(t *testing.T) {
			src := newPieceReader([]string{"ghp_", "0123456789abcdefghijklmnopqrstuvwxyz", " done\n"}, nil)
			r := NewReader(src, m)
			buf := make([]byte, size)
			for {
				n, err := r.Read(buf)
				if n == 0 && err == nil {
					t.Fatal("Read() = 0, nil for a non-empty buffer")
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("Read() = %d, %v", n, err)
				}
			}
		})
	}
}

func TestReader_pendingNonEOFErrorDrainedAcrossSeveralSmallReads(t *testing.T) {
	// TestReader_errorIsHeldUntilTheTextIs drains through io.ReadAll, whose
	// buffer is large enough to take the held text in one call. This drains
	// one byte at a time instead, so the error can only surface once every
	// byte of the held text has already been handed back.
	want := errors.New("no")
	const src = "a line of ordinary text with nothing in it, held to the end\n"
	m := New(WithPatterns(GitHubToken()))
	r := NewReader(newPieceReader([]string{src}, want), m)

	var got strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			got.Write(buf[:n])
		}
		if err != nil {
			if !errors.Is(err, want) {
				t.Fatalf("Read() ended with %v, want %v", err, want)
			}
			break
		}
		if n != 1 {
			t.Fatalf("Read() = %d, nil, want 1, nil", n)
		}
	}
	if got.String() != src {
		t.Errorf("got %q, want %q", got.String(), src)
	}
}

// netishError is an error type of its own, distinct from errors.New's, so a
// test can type-assert the concrete type back out rather than only comparing
// with errors.Is.
type netishError struct{ msg string }

func (e *netishError) Error() string { return e.msg }

func TestReader_terminalErrorIdentityAndConcreteTypePreserved(t *testing.T) {
	// Read's doc comment: the error "is then reported as it was." errors.Is
	// does not tell an error handed back unchanged from one that merely
	// wraps or replaces it; this compares by == for a sentinel and by a type
	// assertion for a concrete type.
	t.Run("sentinel", func(t *testing.T) {
		want := errors.New("no")
		r := NewReader(newPieceReader(nil, want), New())
		_, err := io.ReadAll(r)
		if err != want {
			t.Errorf("ReadAll() = %v, want == %v", err, want)
		}
	})

	t.Run("concrete type", func(t *testing.T) {
		want := &netishError{msg: "no"}
		r := NewReader(newPieceReader(nil, want), New())
		_, err := io.ReadAll(r)
		var got *netishError
		if !errors.As(err, &got) || got != want {
			t.Errorf("ReadAll() = %v, want the same *netishError back", err)
		}
	})
}

func TestReader_maxRetained(t *testing.T) {
	// The Reader side of TestWriter_maxRetained: a run of a value's characters
	// with no end, driven at the three read sizes TestReader_matchesMask
	// drives.
	const held = 512
	m := New(
		WithPatterns(StripeSecretKey()),
		WithRedactor(NewRedactor(func(m Match) string { return "<" + m.Pattern.Name() + ">" })),
	)
	src := "sk_live_" + strings.Repeat("0123456789abcdef", 4*held/16)

	for _, into := range []int{1, 7, 4096} {
		got := throughReader(t, m, []string{src}, into, WithMaxRetained(held))
		if strings.Contains(got, "0123456789abcdef") {
			t.Errorf("into=%d: the run reached the caller as it came in: %q", into, got)
		}
		if !strings.Contains(got, "<stripe-secret-key>") {
			t.Errorf("into=%d: the held text was not redacted under the pattern holding it: %q", into, got)
		}
	}
}

func TestReader_maxRetainedRedactsWhatFollowsToo(t *testing.T) {
	// The Reader side of TestWriter_maxRetainedRedactsWhatFollowsToo.
	body := strings.Repeat("MIIBOgIBAAJBAK0123456789abcdefghijklmnopqrstuvwxyz0123456789ab\n", 60)
	src := "-----BEGIN RSA PRIVATE KEY-----\n" + body + "-----END RSA PRIVATE KEY-----\n"

	m := New(WithPatterns(PrivateKey()), WithRedactor(Fixed("<KEY>")))
	got := throughReader(t, m, splitEvery(src, 100), 4096, WithMaxRetained(1<<10))

	for _, held := range []string{"MIIBOgIBAAJBAK", "-----BEGIN", "-----END"} {
		if strings.Contains(got, held) {
			t.Errorf("%q reached the reader's caller: %q", held, got)
		}
	}
	if trimmed := strings.ReplaceAll(got, "<KEY>", ""); trimmed != "" {
		t.Errorf("the reader's caller holds %q besides the redaction", trimmed)
	}
}

func TestReader_giveUpRedactionAcrossSmallReads(t *testing.T) {
	// "a redactor writing a fixed string writes it once a write rather than
	// once" is stated for a Writer; a Reader's redaction is written the same
	// way, into whatever buffer the caller reads with — which may be smaller
	// than the redaction itself, so one give-up redaction has to be carried
	// across several small Read calls the way TestReader_matchesMask already
	// does for an ordinary match.
	src := "sk_live_" + strings.Repeat("0123456789abcdef", 32)
	m := New(WithPatterns(StripeSecretKey()), WithRedactor(Fixed("[REDACTED]")))

	writerGot := throughWriter(t, m, []string{src}, WithMaxRetained(8))
	if !strings.Contains(writerGot, "[REDACTED]") {
		t.Fatalf("test bug: %q never gave up", writerGot)
	}
	if len(writerGot) <= 3 {
		t.Fatalf("test bug: the redaction is too short to be carried across the small read sizes this drives")
	}
	for _, into := range []int{1, 3} {
		if got := throughReader(t, m, []string{src}, into, WithMaxRetained(8)); got != writerGot {
			t.Errorf("into=%d: reading gave %q, a Writer under the same limit gives %q", into, got, writerGot)
		}
	}
}

func TestReader_maxRetainedCountsARuneOnce(t *testing.T) {
	// The Reader side of TestWriter_maxRetainedCountsARuneOnce.
	src := "sk_live_" + strings.Repeat("0123456789abcdef", 8) + "日本語のログ行"
	m := New(WithPatterns(StripeSecretKey()))

	for _, into := range []int{1, 4096} {
		got := throughReader(t, m, splitEvery(src, 1), into, WithMaxRetained(8))
		if want := utf8.RuneCountInString(src); utf8.RuneCountInString(got) != want {
			t.Errorf("into=%d: the reader gave %d rune(s), the text has %d", into, utf8.RuneCountInString(got), want)
		}
	}
}

func TestReader_releasesAWholeRuneOrNoneOfIt(t *testing.T) {
	// The Reader side of TestWriter_releasesAWholeRuneOrNoneOfIt.
	src := "ϻ0000000000000.000000000000000000000000000000"
	m := New(WithPatterns(HCPTerraformAPIToken()), WithRedactor(Fill('*')))

	got := throughReader(t, m, []string{src[:16], src[16:]}, 4096, WithMaxRetained(9))
	if !utf8.ValidString(got) {
		t.Errorf("the reader gave %q, which the text is not", got)
	}
	if want := utf8.RuneCountInString(src); utf8.RuneCountInString(got) != want {
		t.Errorf("the reader gave %d rune(s), the text has %d", utf8.RuneCountInString(got), want)
	}
}

func TestReader_maxRetainedZeroHoldsPastTheDefaultLimit(t *testing.T) {
	// TestReader_maxRetainedNegativeHoldsWithoutLimit drives a run under the
	// default limit's own size. This drives one built the same way
	// TestReader_maxRetainedDefaultGivesUp is — past the default — under an
	// explicit zero instead, so a zero read as "small" rather than "without
	// limit" fails here rather than only on the negative-n cases.
	body := strings.Repeat("0123456789abcdef", 1<<16+1<<10)
	src := "sk_live_" + body
	m := New(WithPatterns(StripeSecretKey()))
	want := m.Mask(src)

	got, err := io.ReadAll(NewReader(strings.NewReader(src), m, WithMaxRetained(0)))
	if err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}
	if string(got) != want {
		t.Errorf("WithMaxRetained(0) gave %d byte(s), Mask gives %d", len(got), len(want))
	}
	if strings.Contains(string(got), "0123456789abcdef") {
		t.Errorf("the run reached the caller as it came in despite WithMaxRetained(0)")
	}
}

func TestReader_isLinear(t *testing.T) {
	// TestStream_isLinear bounds a Writer's cost over a run that stays held.
	// No Reader test bounds anything: every Reader assertion elsewhere in this
	// file is on kilobyte-scale input, so a Reader rescanning everything it
	// holds on every read from its source would pass all of them.
	size := 2 << 20
	if raceEnabled {
		size = 1 << 18
	}
	const limit = 2 * time.Second

	src := "sk_live_" + strings.Repeat("0123456789abcdef", size/16)
	m := New(WithPatterns(AllBuiltinPatterns()...))
	r := NewReader(oneByteReader{strings.NewReader(src)}, m, WithMaxRetained(0))

	start := time.Now()
	buf := make([]byte, 4096)
	for {
		_, err := r.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read() = %v", err)
		}
	}
	if d := time.Since(start); d > limit {
		t.Errorf("reading %d bytes one at a time from the source took %v", len(src), d)
	}
}

// oneByteReader wraps an io.Reader and hands over at most one byte per call,
// forcing the reader underneath a Reader to be read a byte at a time
// regardless of how large a buffer is offered — which building a []string of
// one-byte pieces the way pieceReader does would cost a slice entry per byte
// of a multi-megabyte run to drive the same way.
type oneByteReader struct{ r io.Reader }

func (o oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return o.r.Read(p)
}

func TestReader_givesBackWhatItHeld(t *testing.T) {
	// The Reader side of TestWriter_givesBackWhatItHeld: a Reader that once
	// held megabytes — an http body, a log tail — must not go on holding them
	// once it has gone back to ordinary text.
	const held = 4 << 10

	m := New(WithPatterns(StripeSecretKey()))
	big := "sk_live_" + strings.Repeat("0123456789abcdef", 64*held/16)
	r := NewReader(strings.NewReader(big+" and then an ordinary line\n"), m, WithMaxRetained(held))

	if _, err := io.Copy(io.Discard, r); err != nil {
		t.Fatalf("Copy() = %v", err)
	}
	if got := cap(r.s.buf); got > held {
		t.Errorf("after holding %d bytes and letting them go, the buffer keeps %d", len(big), got)
	}
	if got := cap(r.s.ready); got > held {
		t.Errorf("after handing out %d bytes, the masked text keeps %d", len(big), got)
	}
}

func TestReader_doesNotWritePastN(t *testing.T) {
	// Read's doc comment: "Read fills p with masked text." io.Reader allows
	// an implementation to use all of p as scratch, so a caller reusing a
	// slice of a larger frame buffer could otherwise find masked,
	// credential-adjacent bytes written past p[:n], into a region it never
	// asked to be filled.
	src := strings.Repeat("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n", 4)
	m := New(WithPatterns(GitHubToken()))
	r := NewReader(strings.NewReader(src), m)

	const bufSize = 4096
	buf := make([]byte, bufSize)
	for {
		for i := range buf {
			buf[i] = 0xAA
		}
		n, err := r.Read(buf)
		for i := n; i < bufSize; i++ {
			if buf[i] != 0xAA {
				t.Fatalf("Read() wrote past n=%d: buf[%d] = %#x, want 0xAA untouched", n, i, buf[i])
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read() = %v", err)
		}
	}
}

func TestReader_emptyBufferAtEveryStage(t *testing.T) {
	// TestReader_emptyBuffer and TestReader_emptyBufferLeavesTheStreamIntact
	// both drive Read(nil) on a fresh Reader. Neither drives it while the
	// Reader is holding text it cannot yet release, or after the stream has
	// already ended — both of which io.Reader's own doc leaves unstated too
	// ("may return 0, nil").
	//
	// A single Read call loops over the reader underneath until it either has
	// something to return or the stream has ended, so the only way to observe
	// a "held, nothing more asked for yet" state between two separate Read
	// calls is for the first of them to already have something releasable to
	// hand back: the plain text in front of the token here settles and
	// releases in the same call that opens the token, which is what lets that
	// call return before the source is ever asked for the token's rest.
	const prefix = "plain\n"
	const half = "ghp_012345"
	const rest = "6789abcdefghijklmnopqrstuvwxyz\n"
	m := New(WithPatterns(GitHubToken()), WithRedactor(Fixed("[REDACTED]")))
	r := NewReader(newPieceReader([]string{prefix + half, rest}, nil), m)

	if n, err := r.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) on a fresh Reader = %d, %v, want 0, nil", n, err)
	}

	buf := make([]byte, len(prefix))
	n, err := r.Read(buf)
	if err != nil || n != len(prefix) || string(buf[:n]) != prefix {
		t.Fatalf("Read() = %d, %v, %q, want %d, nil, %q", n, err, buf[:n], len(prefix), prefix)
	}

	if n, err := r.Read(nil); n != 0 || err != nil {
		t.Errorf("Read(nil) while the token is held = %d, %v, want 0, nil", n, err)
	}

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}
	if want := "[REDACTED]\n"; string(got) != want {
		t.Errorf("draining after the mid-hold Read(nil) gave %q, want %q", got, want)
	}

	// len(p) == 0 is handled before anything else Read does, io.EOF already
	// reported by the drain above included: io.Reader's own doc discourages
	// (0, nil) from a non-empty p but carves this case out by name ("except
	// when len(p) == 0"), so a zero-length Read reporting nothing is the
	// documented shape rather than a hole in this Reader's own EOF handling.
	if n, err := r.Read(nil); n != 0 || err != nil {
		t.Errorf("Read(nil) after EOF = %d, %v, want 0, nil", n, err)
	}
}

func TestReader_maxRetainedAcrossManyLimitsAndCuts(t *testing.T) {
	// TestReader_maxRetained and TestReader_maxRetainedRedactsWhatFollowsToo
	// drive the limits {512, 1024} deterministically; the fuzzer covers the
	// space between and above them, and a 30-second fuzz job is not a
	// deterministic regression test. This drives a handful of corpus-shaped
	// values through a Reader alone at every limit from 1 to 32, checking the
	// same properties on the Reader's own output rather than through a
	// Writer.
	srcs := []string{
		"sk_live_" + strings.Repeat("0123456789abcdef", 8),
		"GITHUB_TOKEN=" + strings.Repeat("ghp_0123456789abcdefghijklmnopqrstuvwxyz\n", 3),
	}
	for _, src := range srcs {
		m := New(WithPatterns(AllBuiltinPatterns()...), WithRedactor(Fixed("")))
		want := m.Mask(src)
		for limit := 1; limit <= 32; limit++ {
			for _, into := range []int{1, 4096} {
				got := throughReader(t, m, []string{src}, into, WithMaxRetained(limit))
				if !strings.HasPrefix(want, got) {
					t.Errorf("limit=%d into=%d: %q is not a prefix of Mask's %q", limit, into, got, want)
				}
			}
		}
	}
}

// endlessReader hands out prefix first and then fillByte forever, so a Reader
// can be driven against a source that never ends and never settles a value —
// the shape WithMaxRetained exists for, which every other Reader test reaches
// an io.EOF from its source instead.
//
// stop, once closed, turns the "forever" into an io.EOF on the next call
// instead: TestReader_givesUpOnAnEndlessSource drives r.Read from a goroutine
// of its own and gives up waiting on it after a timeout, and closing stop on
// that path is what lets the goroutine's own call into a Read that never
// blocks (each call returns immediately) notice and return rather than
// spinning against a source with nothing left to wait for the rest of the
// test binary's run.
type endlessReader struct {
	prefix   string
	fillByte byte
	stop     <-chan struct{}
}

func (r *endlessReader) Read(p []byte) (int, error) {
	if r.prefix != "" {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		return n, nil
	}
	select {
	case <-r.stop:
		return 0, io.EOF
	default:
	}
	for i := range p {
		p[i] = r.fillByte
	}
	return len(p), nil
}

func TestReader_givesUpOnAnEndlessSource(t *testing.T) {
	// "A run of the characters a value is written in, arriving without end,
	// is a value without end to every pattern that reads one, so somewhere
	// the holding has to stop." This drives a Reader against a source that
	// truly never ends: a Reader that waited for its own source to settle a
	// value before giving up would hang on one, rather than giving up at
	// WithMaxRetained the way it does on a finite run.
	stop := make(chan struct{})
	defer close(stop) // let the Read goroutine below return if it is still running once this test is done.

	m := New(WithPatterns(StripeSecretKey()), WithRedactor(Fixed("[REDACTED]")))
	r := NewReader(&endlessReader{prefix: "sk_live_", fillByte: '0', stop: stop}, m, WithMaxRetained(64))

	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	buf := make([]byte, 32)
	go func() {
		n, err := r.Read(buf)
		done <- result{n, err}
	}()

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("Read() = %d, %v, want a redaction and no error", res.n, res.err)
		}
		if res.n == 0 {
			t.Fatal("Read() = 0, nil against an endless source that has already exceeded the limit")
		}
		if strings.ContainsRune(string(buf[:res.n]), '0') {
			t.Errorf("Read() gave %q, which still holds the run rather than a redaction", buf[:res.n])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read() did not return: a Reader over an endless source has to give up rather than wait for it to settle")
	}
}

func TestWriter_unboundedExpressionRedactsFromItsOpening(t *testing.T) {
	// README advises counted repetition over an open "+" or "*" for exactly
	// this: an expression with no ceiling on its width holds a stream from
	// wherever a match could begin, whether or not a match is ever completed
	// there. TestWriter_maxRetainedRedactsWhatFollowsToo pins the same shape
	// for PrivateKey, whose grammar always closes; this pins it for an
	// expression that never does, over text that never completes a match at
	// all.
	m := New(WithPatterns(MustRegexp("internal", `INT-[0-9a-f]+`)), WithRedactor(Fixed("<X>")))

	var got strings.Builder
	w := NewWriter(&got, m, WithMaxRetained(32))
	for _, piece := range []string{"a line\nINT-", strings.Repeat(" ordinary words here", 20)} {
		if _, err := w.Write([]byte(piece)); err != nil {
			t.Fatalf("Write(%q) = %v", piece, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	if !strings.HasPrefix(got.String(), "a line\n") {
		t.Errorf("got %q, want it to open on the settled prefix %q", got.String(), "a line\n")
	}
	for _, held := range []string{"INT-", "ordinary"} {
		if strings.Contains(got.String(), held) {
			t.Errorf("%q reached the writer underneath: %q", held, got.String())
		}
	}
	trimmed := strings.TrimPrefix(got.String(), "a line\n")
	if remainder := strings.ReplaceAll(trimmed, "<X>", ""); remainder != "" {
		t.Errorf("the writer underneath holds %q besides the prefix and the redaction", remainder)
	}
}

func TestReader_unboundedExpressionRedactsFromItsOpening(t *testing.T) {
	// The Reader side of TestWriter_unboundedExpressionRedactsFromItsOpening.
	m := New(WithPatterns(MustRegexp("internal", `INT-[0-9a-f]+`)), WithRedactor(Fixed("<X>")))
	pieces := []string{"a line\nINT-", strings.Repeat(" ordinary words here", 20)}
	got := throughReader(t, m, pieces, 4096, WithMaxRetained(32))

	if !strings.HasPrefix(got, "a line\n") {
		t.Errorf("got %q, want it to open on the settled prefix %q", got, "a line\n")
	}
	for _, held := range []string{"INT-", "ordinary"} {
		if strings.Contains(got, held) {
			t.Errorf("%q reached the reader's caller: %q", held, got)
		}
	}
}

func TestStream_aGenerousLimitMatchesMask(t *testing.T) {
	// WithMaxRetained's doc comment: "The default is generous enough that no
	// credential written in one piece comes near it" — implying an explicit
	// limit at or above a value's own length behaves the same way. Nothing
	// pinned that an explicit, finite limit sized to the value it is meant to
	// allow gives exactly what Mask gives, rather than giving up early or late
	// by one byte at the boundary.
	value := "sk_live_" + strings.Repeat("0123456789abcdef", 4)
	src := "prefix line\n" + value + "\nsuffix line\n"
	m := New(WithPatterns(StripeSecretKey()))
	want := m.Mask(src)

	for _, limit := range []int{len(value), len(value) + 1, 4 * len(value)} {
		t.Run(fmt.Sprintf("limit=%d", limit), func(t *testing.T) {
			for _, pieces := range splits(src) {
				if got := throughWriter(t, m, pieces, WithMaxRetained(limit)); got != want {
					t.Errorf("writing in %d piece(s) gave %q, Mask gives %q", len(pieces), got, want)
				}
				for _, into := range []int{1, 4096} {
					if got := throughReader(t, m, pieces, into, WithMaxRetained(limit)); got != want {
						t.Errorf("reading in %d piece(s) into %d bytes gave %q, Mask gives %q", len(pieces), into, got, want)
					}
				}
			}
		})
	}
}

func TestStream_giveUpExactOutput(t *testing.T) {
	// Every give-up property elsewhere here bounds the output (no more than
	// the limit held) or relates it to something else (a prefix of Mask, the
	// same rune count as the input). Nothing states, as a literal a reviewer
	// can read, exactly how much of the text in front of a value a give-up
	// releases before it stops — which is what would fail if that boundary
	// moved by one byte.
	//
	// The whole of src arrives in a single Write, so the entirety of the
	// unclosable run past "sk_live_" is swept into one redaction the moment
	// the limit is first exceeded (giveUp redacts everything it is holding in
	// one call), and Close's own flush then finds nothing left to add.
	src := "prefix line\nsk_live_" + strings.Repeat("0123456789abcdef", 4)
	const limit = 32
	want := "prefix line\n<X>"

	m := New(WithPatterns(StripeSecretKey()), WithRedactor(Fixed("<X>")))
	if got := throughWriter(t, m, []string{src}, WithMaxRetained(limit)); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := throughReader(t, m, []string{src}, 4096, WithMaxRetained(limit)); got != want {
		t.Errorf("reading gave %q, want %q", got, want)
	}
}

func TestWriter_wideFillRuneAcrossAGiveUp(t *testing.T) {
	// streamRedactors' wide-fill entry drives Fill('█') through the ordinary
	// equivalence properties for free. What it does not reach there is the
	// give-up path specifically, where the redaction is produced write at a
	// time from held text rather than from one settled span — the rune-count
	// assertions elsewhere in this file would still pass a stream that counted
	// redaction bytes as redaction runes, since none of them use a fill rune
	// wider than one byte under a limit.
	src := "sk_live_" + strings.Repeat("0123456789abcdef", 8) + "日本語"
	m := New(WithPatterns(StripeSecretKey()), WithRedactor(Fill('█')))

	var got strings.Builder
	w := NewWriter(&got, m, WithMaxRetained(8))
	for i := 0; i < len(src); i++ {
		if _, err := w.Write([]byte(src[i : i+1])); err != nil {
			t.Fatalf("Write() = %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	if !utf8.ValidString(got.String()) {
		t.Errorf("the writer underneath holds %q, which is not valid UTF-8", got.String())
	}
	if want := utf8.RuneCountInString(src); utf8.RuneCountInString(got.String()) != want {
		t.Errorf("the writer underneath has %d rune(s), the text has %d", utf8.RuneCountInString(got.String()), want)
	}
}

func TestStream_writerReaderParityUnderALimitWithALengthChangingRedactor(t *testing.T) {
	// givingUp-style parity elsewhere is only ever driven with a
	// length-preserving redactor (Fill) or one collapsing to nothing (empty
	// Fixed), neither of which could show a Writer and a Reader disagreeing
	// about how many redactions a give-up produces. Fixed("[REDACTED]") can:
	// a Writer and a Reader driven over the same pieces under the same limit
	// have to agree byte for byte.
	src := "sk_live_" + strings.Repeat("0123456789abcdef", 40)
	m := New(WithPatterns(StripeSecretKey()), WithRedactor(Fixed("[REDACTED]")))

	for _, limit := range []int{1, 8, 64} {
		for _, pieces := range [][]string{{src}, splitEvery(src, 7), splitEvery(src, 1)} {
			t.Run(fmt.Sprintf("limit=%d/pieces=%d", limit, len(pieces)), func(t *testing.T) {
				w := throughWriter(t, m, pieces, WithMaxRetained(limit))
				for _, into := range []int{1, 7, 4096} {
					if r := throughReader(t, m, pieces, into, WithMaxRetained(limit)); r != w {
						t.Errorf("reading into %d bytes gave %q, a Writer over the same pieces gives %q", into, r, w)
					}
				}
			})
		}
	}
}

func TestWriter_patternSettlingNothingGivesUpAtALimit(t *testing.T) {
	// TestWriter_matchesMaskForANaivePatternThatSettlesNothing drives
	// naiveSecretPattern with WithMaxRetained(0), so it is never asked to give
	// up. This drives it against an explicit, reachable limit instead, to
	// check the claim "A Reader or a Writer holds what no pattern has
	// settled, and gives up holding at WithMaxRetained by redacting what it
	// holds — whether or not a match was ever written there."
	src := strings.Repeat("an entirely ordinary line of prose\n", 20)
	m := New(WithPatterns(naiveSecretPattern()), WithRedactor(Fixed("<X>")))

	got := throughWriter(t, m, []string{src}, WithMaxRetained(64))
	if trimmed := strings.ReplaceAll(got, "<X>", ""); !strings.HasPrefix(src, trimmed) {
		t.Errorf("got %q, want what is left after removing the redaction to be a prefix of the input", got)
	}
	if !strings.Contains(got, "<X>") {
		t.Errorf("got %q, want the settle-nothing pattern to have given up at the limit", got)
	}
}

func TestReader_patternSettlingNothingGivesUpAtALimit(t *testing.T) {
	// The Reader side of TestWriter_patternSettlingNothingGivesUpAtALimit,
	// held to agreeing with a Writer over the same limit byte for byte.
	src := strings.Repeat("an entirely ordinary line of prose\n", 20)
	m := New(WithPatterns(naiveSecretPattern()), WithRedactor(Fixed("<X>")))

	want := throughWriter(t, m, []string{src}, WithMaxRetained(64))
	if got := throughReader(t, m, []string{src}, 4096, WithMaxRetained(64)); got != want {
		t.Errorf("reading gave %q, a Writer under the same limit gives %q", got, want)
	}
}
