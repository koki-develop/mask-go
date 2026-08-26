package mask

import (
	"errors"
	"io"
	"unicode/utf8"
)

// Streaming is masking text that arrives a piece at a time, which Mask cannot
// do: a value written across two pieces is in neither of them, so masking each
// piece as it comes releases both halves of a credential and redacts nothing.
//
// A Reader and a Writer hold text back instead, and let it go once the patterns
// agree nothing more of the stream can change what they found there. What each
// pattern reports about that is Pattern.Find's retain, and how far back a
// pattern may read is LookBehind.

// defaultMaxRetained is how much text a stream holds back before it gives up
// holding and redacts what it has.
//
// A mebibyte is far above every credential written in one piece — the largest
// is an armored private key, a few kibibytes of base64 — and it is not the
// length of a value that decides this. Several built-in patterns read a value
// to the end of the run of characters it is written in, so a run of any length
// is a value of any length: a megabyte of base64 carrying sk- and the marker
// behind it is a megabyte of OpenAI API key, and a stream matching Mask has to
// hold the whole of it.
const defaultMaxRetained = 1 << 20

// scanGrowth is the fraction of what a stream holds that has to arrive before
// the patterns are run over it again.
//
// A scan is a pass over everything held back, so a stream scanning on every
// write costs time quadratic in the length of a stretch that stays held: a
// megabyte arriving a byte at a time would be walked a million times. Waiting
// for a fixed fraction of it makes the total linear — a few passes over every
// byte, whatever the writes are sized — and it costs a fraction of the held
// text in latency, no more.
//
// Latency is what the fraction is chosen for rather than the work. Text stays
// held because some pattern has an open value in it, so what waiting delays is
// noticing that the value closed — an eighth of what is already being held, and
// nothing at all for ordinary text, which holds nothing and is scanned on every
// write.
const scanGrowth = 8

// readSize is how much a Reader asks of the reader underneath it at a time, and
// the size under which a buffer is never worth giving back.
const readSize = 4 << 10

// maxEmptyReads is how many times running a Reader tolerates the reader
// underneath it returning nothing and no error, which io.Reader permits and
// nothing useful does. bufio draws the line in the same place.
const maxEmptyReads = 100

// ErrClosed is returned by a Writer written to after it has been closed.
var ErrClosed = errors.New("mask: writer is closed")

// StreamOption configures a Reader or a Writer.
type StreamOption func(*streamOptions)

type streamOptions struct {
	maxRetained int
}

// WithMaxRetained sets how much text a Reader or a Writer holds back before it
// gives up and redacts what it is holding, in bytes. Zero holds without limit.
//
// A run of the characters a value is written in, arriving without end, is a
// value without end to every pattern that reads one, so somewhere the holding
// has to stop. It stops with a redaction rather than a release, because
// releasing held text is releasing the credential the pattern was still
// reading.
//
// The redaction covers everything held at that moment and is attributed to the
// pattern that was holding it, so a redactor reading Match.Pattern sees which
// grammar ran long — and so does everything written after it, to the end of the
// stream. Giving up takes the opening of the value out of the window along with
// the rest, and a pattern shown the middle of a value without its opening
// reports nothing and settles everything; a stream going back to passing text
// through would write out the rest of the very value it gave up holding, and
// nothing but the pattern could have said the value had ended.
//
// So the limit is a last resort rather than a knob to tune down. The default is
// generous enough that no credential written in one piece comes near it, and
// zero holds without limit for a caller who would rather spend the memory. Any
// n below zero is read as that same zero rather than as a limit no text can
// come under, which is what strings.SplitN reads a negative count as and what a
// caller computing the limit from a budget gets when the budget runs out.
//
// What is redacted after that is redacted a write at a time, since a stream
// cannot hold the rest of itself back to redact it as one. Fill writes a rune
// for a rune either way — a rune the writes are split inside is held until the
// rest of it arrives — and a redactor writing a fixed string writes it once a
// write rather than once.
func WithMaxRetained(n int) StreamOption {
	return func(o *streamOptions) { o.maxRetained = max(n, 0) }
}

// newStreamOptions reads the options a Reader or a Writer was given over the
// defaults they start from.
func newStreamOptions(opts []StreamOption) streamOptions {
	o := streamOptions{maxRetained: defaultMaxRetained}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// stream is the masking a Reader and a Writer share: text goes in a piece at a
// time, masked text comes out, and what neither has settled stays in between.
type stream struct {
	m           *Masker
	maxRetained int

	// buf is the text the stream is still working on. It opens with the text
	// already written out that a pattern may read back over — LookBehind
	// bytes of it, no more — and carries on with the text held back.
	buf []byte
	// out is where buf begins to be text nobody has seen, and everything in
	// front of it has been written out already.
	out int
	// held is how much was held back when the patterns last ran, which is
	// what scanGrowth is weighed against. Discarding takes the same amount off
	// buf and off out, so it leaves this standing.
	held int

	// ready is masked text waiting to leave, and taken is how much of it has
	// already left.
	ready []byte
	taken int

	// gave is the pattern the stream gave up holding text for, and nil while
	// it is still holding what it is asked to. Once it has given up, every byte
	// from there to the end of the stream is redacted under that pattern.
	gave Pattern
}

// write adds p to what the stream is working on.
func (s *stream) write(p []byte) { s.buf = append(s.buf, p...) }

// pending reports how much masked text is waiting to leave.
func (s *stream) pending() int { return len(s.ready) - s.taken }

// take copies what is waiting to leave into p and reports how much it moved.
func (s *stream) take(p []byte) int {
	n := copy(p, s.ready[s.taken:])
	s.consumed(n)
	return n
}

// consumed records that n bytes of the masked text have left, and starts that
// text again once all of it has. A Reader copies them out and a Writer writes
// them on, and the cursor either moves is the same one, so both end here.
func (s *stream) consumed(n int) {
	if s.taken += n; s.taken == len(s.ready) {
		s.empty()
	}
}

// empty starts the masked text again once all of it has left, rather than
// letting it grow forever behind a cursor that only moves forward.
func (s *stream) empty() {
	s.ready, s.taken = shrink(s.ready[:0]), 0
}

// shrink returns b with its capacity given back where it has grown far past
// what it holds.
//
// A stream that once held a megabyte — a run of the characters a value is
// written in, arriving without end until the limit stopped it — would otherwise
// hold the megabyte for as long as the stream is open, which behind a log is
// the life of the program. Giving it back costs a copy of what is left, and it
// is asked for only where what is left is a small part of what is held, so a
// buffer that grows and shrinks with every write is not copied at every one.
func shrink(b []byte) []byte {
	if cap(b) <= readSize || cap(b) < 4*len(b) {
		return b
	}
	return append(make([]byte, 0, max(len(b), readSize)), b...)
}

// advance runs the patterns over what is held and masks whatever they have
// settled. Where final is set the stream is over, so everything held is settled
// by the end of the text itself.
func (s *stream) advance(final bool) {
	if !s.due(final) {
		return
	}

	// The bytes are made into a string once, for every pattern and for the
	// values handed to the redactor. It is a copy, which is a pass over text
	// the scan is about to make a pass over anyway; what it buys is that a
	// Match.Value the redactor keeps is a string of its own rather than a
	// window on a buffer this stream goes on writing into.
	src := string(s.buf)

	if s.gave != nil {
		// The stream gave up holding, and what it gave up on was a value it
		// could not see the end of. Everything from there on goes out redacted.
		s.giveUp(src, final)
		s.scanned()
		return
	}

	found := s.m.locate(src, s.out)
	retain := found.retain
	if final {
		retain = len(src)
	}

	// Text is settled as far as retain, less any value that begins in front
	// of retain and reaches past it. Such a value is settled where it stands,
	// but a value still growing can begin inside it, and the two would then be
	// merged into one redaction that this one has already written half of.
	// Values do not overlap once merged, so at most one reaches past retain.
	end := retain
	for _, f := range found.found {
		if f.Start >= retain {
			break
		}
		if f.End > retain {
			end = f.Start
			break
		}
	}

	// What a scan settles moves backwards as often as forwards, so the point
	// this stream has written up to is held where it is rather than followed.
	// A scan reads a candidate back from an anchor, and an anchor arriving
	// puts a candidate in text the scan had already walked past and called
	// settled: ANTHROPIC_AP holds no candidate for an AWS access key ID and
	// ANTHROPIC_API holds one two characters in front of its end.
	//
	// Taking the later answer would be taking back text already written out.
	// The earlier one is not wrong for being narrower — what a scan settles it
	// settles for every text carrying on from there, this one included — so
	// both are true and the further of the two is the one to keep.
	end = max(end, s.out)

	// Nothing begins in front of s.out, which is what locate was given it for,
	// so every value here is one this pass is the first to see.
	at := s.out
	for _, f := range found.found {
		if f.Start >= end {
			break
		}
		s.ready = append(s.ready, src[at:f.Start]...)
		s.ready = append(s.ready, s.m.redactor.Redact(Match{Pattern: f.pattern, Value: src[f.Start:f.End]})...)
		at = f.End
	}
	s.ready = append(s.ready, src[at:end]...)
	s.out = end

	if s.maxRetained > 0 && len(src)-s.out > s.maxRetained && found.holder != nil {
		// Held longer than a caller is willing to hold.
		s.gave = found.holder
		s.giveUp(src, final)
	}

	s.scanned()
}

// scanned closes a pass of the patterns: it drops the text they can no longer
// reach and records what they were left holding, which is what the next pass is
// weighed against. Both ways out of advance end here, so that a change to what
// closes a pass cannot be made to one of them and missed on the other.
func (s *stream) scanned() {
	s.discard()
	s.held = len(s.buf) - s.out
}

// giveUp redacts everything from the point the stream has written up to.
//
// What is held when a stream gives up is text a pattern was still reading a
// value out of, so it goes out redacted rather than as it came in. What follows
// goes out redacted too, and that is not a second helping of caution: letting
// go of the text takes the opening of the value with it, and a pattern shown
// the middle of a value without its opening reports nothing and settles
// everything — so a stream that went back to passing text through would write
// out the rest of the very value it gave up holding.
//
// There is no reading of the text that says the value has ended, because the
// only thing that could say so is the pattern, and the pattern can no longer
// see what it was reading. So the stream does not go back. What that costs is
// the rest of a stream that reached the limit; what it buys is that no part of
// the value the limit was reached on is ever written out.
// The rune the input stops inside is held back rather than redacted, until the
// end of the stream says there is no more of it. A redactor is handed the text
// it is replacing, and one counting what it was given — Fill writes a rune for
// a rune — would count the pieces of a rune written across two writes as a rune
// apiece.
func (s *stream) giveUp(src string, final bool) {
	end := len(src)
	if !final {
		end -= incompleteRune(src)
	}
	if s.out >= end {
		return
	}
	s.ready = append(s.ready, s.m.redactor.Redact(Match{Pattern: s.gave, Value: src[s.out:end]})...)
	s.out = end
}

// incompleteRune returns how many bytes at the end of src are the beginning of
// a rune src stops inside, and zero where src ends on a whole one.
func incompleteRune(src string) int {
	for back := 1; back < utf8.UTFMax && back <= len(src); back++ {
		at := len(src) - back
		if !utf8.RuneStart(src[at]) {
			continue // a byte in the middle of a rune says nothing by itself
		}
		if !utf8.FullRuneInString(src[at:]) {
			return back
		}
		return 0
	}
	return 0
}

// due reports whether the patterns should run over what the stream is holding.
func (s *stream) due(final bool) bool {
	held := len(s.buf) - s.out
	if final || (s.maxRetained > 0 && held > s.maxRetained) {
		// Waiting for a fraction of what is held to arrive would let the
		// holding pass what a caller allows by that fraction before the stream
		// noticed. The limit is what a caller asked for, not a bound to be
		// approached.
		return true
	}
	return held-s.held >= s.held/scanGrowth
}

// discard drops the text no pattern can reach any more: everything more than
// LookBehind in front of the text still to be written out.
func (s *stream) discard() {
	keep := s.out - LookBehind
	if keep <= 0 {
		return
	}
	s.buf = shrink(append(s.buf[:0], s.buf[keep:]...))
	s.out -= keep
}

// Writer masks the text written to it and writes the result on to another
// writer.
//
// A Writer holds text back — a value split across two writes is in neither of
// them — so what reaches the writer underneath lags what was written here, and
// Close is what settles the end of the stream and lets the last of it go. A
// Writer that is never closed leaves whatever it was holding unwritten.
//
// A Writer is not safe for concurrent use.
type Writer struct {
	dst io.Writer
	s   stream

	closed bool
	err    error
}

// NewWriter returns a Writer that masks what is written to it with m and writes
// the result to dst:
//
//	w := mask.NewWriter(os.Stderr, m)
//	defer w.Close()
//	log.SetOutput(w)
//
// Close writes out what the Writer is still holding. It does not close dst.
func NewWriter(dst io.Writer, m *Masker, opts ...StreamOption) *Writer {
	o := newStreamOptions(opts)
	return &Writer{dst: dst, s: stream{m: m, maxRetained: o.maxRetained}}
}

// Write masks p and writes on whatever that settles.
//
// The count returned is len(p) whenever there is no error: p is taken in whole,
// and how much of it reaches dst is a question about the stream rather than
// about this write.
func (w *Writer) Write(p []byte) (int, error) {
	switch {
	case w.err != nil:
		return 0, w.err
	case w.closed:
		return 0, ErrClosed
	}
	w.s.write(p)
	w.s.advance(false)
	if err := w.drain(); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close writes out the text the Writer is holding back and reports what writing
// it cost. The writer underneath is left open, as a wrapper leaves what it
// wraps.
//
// Closing twice reports what the first close did rather than doing it again.
func (w *Writer) Close() error {
	if w.closed {
		return w.err
	}
	w.closed = true
	if w.err != nil {
		return w.err
	}
	w.s.advance(true)
	return w.drain()
}

// drain writes what the stream has masked on to dst.
func (w *Writer) drain() error {
	want := w.s.pending()
	if want == 0 {
		return nil
	}
	n, err := w.dst.Write(w.s.ready[w.s.taken:])
	w.s.consumed(n)
	if err == nil && n < want {
		err = io.ErrShortWrite
	}
	if err != nil {
		// A Writer that has failed once stays failed: the text it was holding
		// is gone with the write that did not land, and going on would splice
		// what comes next onto a stream missing its middle.
		w.err = err
	}
	return err
}

// Reader masks the text read from another reader.
//
// A Reader holds text back — a value split across two reads is in neither of
// them — so what it returns lags what it has read. The end of the stream
// settles the last of it, and the text held back is returned before the error
// that ended the stream is.
//
// A Reader is not safe for concurrent use.
type Reader struct {
	src io.Reader
	s   stream

	in   []byte
	err  error
	done bool
}

// NewReader returns a Reader that reads from src and masks what it reads with
// m:
//
//	body, err := io.ReadAll(mask.NewReader(resp.Body, m))
func NewReader(src io.Reader, m *Masker, opts ...StreamOption) *Reader {
	o := newStreamOptions(opts)
	return &Reader{src: src, s: stream{m: m, maxRetained: o.maxRetained}, in: make([]byte, readSize)}
}

// Read fills p with masked text.
//
// Reading returns nothing until the stream settles enough text to fill
// something, so a read here can take several reads of the reader underneath.
// The error that ended that reader is held back until the text held with it has
// been returned, and is then reported as it was.
func (r *Reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for empty := 0; ; {
		if n := r.s.take(p); n > 0 {
			return n, nil
		}
		if r.done {
			return 0, r.err
		}

		n, err := r.src.Read(r.in)
		if n > 0 {
			empty = 0
			r.s.write(r.in[:n])
			r.s.advance(false)
		}
		if err != nil {
			r.done, r.err = true, err
			r.s.advance(true)
			continue
		}
		if n == 0 {
			if empty++; empty >= maxEmptyReads {
				r.done, r.err = true, io.ErrNoProgress
				r.s.advance(true)
			}
		}
	}
}
