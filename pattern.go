package mask

// Span is a half-open byte range [Start, End) within the scanned text. Offsets
// are zero-based, and Start must be less than End.
type Span struct {
	Start int
	End   int
}

// LookBehind is how far in front of a value a Pattern may read: the bytes from
// LookBehind before the start of a span it reports up to that start, and no
// further back.
//
// A Masker scanning a whole string hands every pattern the whole of it and the
// limit costs nothing. It is what NewReader and NewWriter rest on: a stream is
// masked by scanning a window that moves along it, and text the window has
// already carried past is what those readers keep rather than release. The
// limit is what tells them how much to keep.
//
// Stated as a demand on a Find: hand it the text from an offset k on rather
// than the whole, where Find has settled at least k + LookBehind of the whole,
// and from k + LookBehind on it must report what it reports when handed
// everything. What that rules out is a Find whose answer at one place depends
// on the whole of the text in front of it. A scan walking the text from the
// start and stepping over each value it found would be such a Find: where the
// window begins would decide where the values fall, and a value would move
// under the window as the window moved.
//
// A built-in pattern reads no further in front of a value than what decides
// whether a value stands there at all. Where that is the one character a prefix
// may not stand behind there is no count to state; a scan reading further than
// that character states in its own file how far, and holds it to this limit. A
// pattern built by Regexp reads one rune, which is what \b, \B and ^ are
// decided by. The limit is far above either so that a Pattern written by hand
// has room to read a keyword or an assignment in front of what it locates. A
// Find that cannot be held to it, where a value is decided by more text in
// front of it than this, must settle nothing: what settles nothing is never
// handed a window.
const LookBehind = 64

// Pattern locates sensitive values in text.
//
// Implementations must be safe for concurrent use by multiple goroutines.
type Pattern interface {
	// Name identifies the pattern. It should be stable, lowercase and
	// hyphenated, such as "github-token".
	Name() string

	// Find returns the byte ranges to redact in src, and the offset from
	// which src is not yet settled.
	//
	// The spans may be unordered and may overlap; a Masker sorts them and
	// resolves the overlaps. Spans reaching outside src, and spans whose
	// Start is not less than their End, are ignored.
	//
	// Both ends must fall on a rune boundary. A span cutting a multi-byte
	// rune in half is neither ignored nor repaired: the bytes either side of
	// it are written back as they were found, so what is left of that rune
	// stands beside the redaction and the output is not valid UTF-8. The
	// built-in patterns and Regexp cannot report such a span — every
	// built-in decides its ends on an ASCII alphabet, and Go's regexp
	// matches runes — so this is a demand on a Find written by hand.
	//
	// retain answers what src alone cannot: whether src is all there is. For
	// every text beginning with src, the values in it that begin before
	// retain are exactly the spans reported here that begin before retain,
	// with the same Start and the same End. Nothing is promised about what
	// begins at retain or after it: a value there may grow, may appear where
	// nothing was reported, and may turn out to be no value at all.
	//
	// Both directions of that are load-bearing. A value the shorter text
	// misses is one a stream writes out before it is found; one it reports
	// that the longer text does not is a redaction a stream cannot take
	// back.
	//
	// Zero promises nothing and is always true. It is what a Find written
	// without a stream in mind returns, and what a Find returns when the
	// whole of src is still open — a value running to the end of it that
	// more text would carry further. Reporting len(src) says the opposite:
	// src stands complete, and nothing appended to it changes any of this.
	//
	// Mask reads the whole of its input at once and ignores retain. NewReader
	// and NewWriter are what it is for: they hold back the text from retain
	// on until more of the stream settles it.
	Find(src string) (spans []Span, retain int)
}

// NewPattern returns a Pattern that reports name as its name and locates
// values with find:
//
//	mask.NewPattern("high-entropy", func(src string) ([]mask.Span, int) {
//		// ...
//		return spans, len(src)
//	})
//
// find must be safe for concurrent use by multiple goroutines, and owes what
// Pattern.Find says about both of its results.
func NewPattern(name string, find func(src string) (spans []Span, retain int)) Pattern {
	return &funcPattern{name: name, find: find}
}

type funcPattern struct {
	name string
	find func(src string) (spans []Span, retain int)
}

func (p *funcPattern) Name() string { return p.name }

func (p *funcPattern) Find(src string) ([]Span, int) { return p.find(src) }
