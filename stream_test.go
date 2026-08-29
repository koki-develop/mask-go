package mask

import (
	"errors"
	"fmt"
	"io"
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
// shorter than anything.
func streamRedactors() map[string]Redactor {
	return map[string]Redactor{
		"fill":  Fill('*'),
		"fixed": Fixed("[REDACTED]"),
		"empty": Fixed(""),
		"named": NewRedactor(func(m Match) string { return "<" + m.Pattern.Name() + ">" }),
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

	r := NewReader(newPieceReader(pieces, nil), m, opts...)
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

// splits returns the ways src is cut into pieces: at every single offset, at
// every pair of offsets for text short enough to try them all, and one byte at
// a time.
func splits(src string) [][]string {
	all := [][]string{{src}}
	for i := range len(src) + 1 {
		all = append(all, []string{src[:i], src[i:]})
	}
	if len(src) <= 48 {
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
	m := New(WithPatterns(AllBuiltinPatterns()...), WithRedactor(Fixed("[REDACTED]")))

	// A subtest an input, run in parallel with the rest: the cuts of one input
	// are as many as it has bytes, and the three read sizes are not the same
	// work as one another — a byte at a time is where most of this is spent, so
	// dividing by read size would leave one subtest carrying the test. A Masker
	// is safe for concurrent use and the one here is shared as a caller shares
	// it.
	for _, src := range streamInputs() {
		t.Run(fmt.Sprintf("%q", src), func(t *testing.T) {
			t.Parallel()

			want := m.Mask(src)
			for _, pieces := range splits(src) {
				for _, into := range []int{1, 7, 4096} {
					if got := throughReader(t, m, pieces, into); got != want {
						t.Errorf("reading %q in %d piece(s) into %d bytes gave %q, Mask gives %q",
							src, len(pieces), into, got, want)
					}
				}
			}
		})
	}
}

func TestWriter_matchesMaskForRegexpPatterns(t *testing.T) {
	// A pattern built by MustRegexp reaches the same stream, and what it
	// locates has to stand where it stands however much of the text in front
	// of it the stream still holds. The expressions here are the ones whose
	// matches stand against one another, so that letting go of the text
	// written out would move every match behind the point let go of, and the
	// inputs are long enough that a stream lets go at all.
	for _, expr := range []string{
		`[0-9a-f]{40}`,
		`[0-9]{3}`,
		`\bkey-[0-9]{3}\b`,
		`(?m)^token=[0-9a-f]{6}`,
		`INT-(?P<mask>[0-9a-f]{8})`,
		// A group standing further into a match than a window is deep, and a
		// match anchored at the beginning of the text: what a window would make
		// of either is not what the whole text makes of it, so neither settles
		// anything and neither is ever handed one.
		`(?s)\A.{80}(?P<mask>SECRET)`,
		`(?s)x{2}.{200}(?P<mask>SECRET)`,
		// Either side of that boundary, where a group stands as far into a
		// match as one may and still be streamed and then a byte further.
		`\bx` + strings.Repeat("A", LookBehind-utf8.UTFMax-1) + `(?P<mask>[0-9]{3})`,
		`\bx` + strings.Repeat("A", LookBehind-utf8.UTFMax) + `(?P<mask>[0-9]{3})`,
		`\b-x` + strings.Repeat("A", LookBehind-2) + `(?P<mask>[0-9]{3})`,
	} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()

			m := New(WithPatterns(MustRegexp("p", expr)), WithRedactor(Fixed("[REDACTED]")))
			for _, src := range []string{
				"sha=" + strings.Repeat("abcdef0123", 30),
				strings.Repeat("0123456789", 24),
				strings.Repeat("key-123 and INT-0123456789abcdef ", 8),
				strings.Repeat("token=0123ab\n", 20),
				strings.Repeat("x", 341) + "SECRET" + strings.Repeat("y", 300),
				strings.Repeat("z", 300) + "Qx" + strings.Repeat("A", LookBehind) + "123" + strings.Repeat("w", 100),
				strings.Repeat("z", 300) + "Q-x" + strings.Repeat("A", LookBehind) + "123" + strings.Repeat("w", 100),
			} {
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

	m := New(WithPatterns(AllBuiltinPatterns()...))
	w := NewWriter(io.Discard, m, WithMaxRetained(0))
	src := "sk_live_" + strings.Repeat("0123456789abcdef", size/16)

	start := time.Now()
	for i := range src {
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
		if len(src) == 0 {
			cut = 0
		} else {
			cut = ((cut % (len(src) + 1)) + len(src) + 1) % (len(src) + 1)
		}
		want := m.Mask(src)
		if got := throughWriter(t, m, []string{src[:cut], src[cut:]}); got != want {
			t.Fatalf("writing %q cut at %d gave %q, Mask gives %q", src, cut, got, want)
		}
	})
}
