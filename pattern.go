package mask

// Span is a half-open byte range [Start, End) within the scanned text. Offsets
// are zero-based, and Start must be less than End.
type Span struct {
	Start int
	End   int
}

// Pattern locates sensitive values in text.
//
// Implementations must be safe for concurrent use by multiple goroutines.
type Pattern interface {
	// Name identifies the pattern. It should be stable, lowercase and
	// hyphenated, such as "github-token".
	Name() string

	// Find returns the byte ranges to redact in src. The returned spans may
	// be unordered and may overlap; a Masker sorts them and resolves the
	// overlaps.
	Find(src string) []Span
}

// NewPattern returns a Pattern that reports name as its name and locates
// values with find:
//
//	mask.NewPattern("high-entropy", func(src string) []mask.Span {
//		// ...
//	})
//
// find must be safe for concurrent use by multiple goroutines.
func NewPattern(name string, find func(src string) []Span) Pattern {
	panic("not implemented")
}

// MustRegexp returns a Pattern backed by expr, and panics if expr is invalid.
//
// The whole match is redacted, unless expr contains a capture group named
// "mask", in which case only that group is:
//
//	// "Authorization: Bearer abc123" -> "Authorization: Bearer ******"
//	mask.MustRegexp("bearer-token", `Bearer (?P<mask>[\w.~+/-]+=*)`)
func MustRegexp(name, expr string) Pattern {
	panic("not implemented")
}
