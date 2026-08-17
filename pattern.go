package mask

import "regexp"

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
	// overlaps. Spans reaching outside src, and spans whose Start is not
	// less than their End, are ignored.
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
	return &funcPattern{name: name, find: find}
}

type funcPattern struct {
	name string
	find func(src string) []Span
}

func (p *funcPattern) Name() string { return p.name }

func (p *funcPattern) Find(src string) []Span { return p.find(src) }

// MustRegexp returns a Pattern backed by expr, and panics if expr is invalid.
//
// The whole match is redacted, unless expr contains a capture group named
// "mask", in which case only that group is:
//
//	// "Authorization: Bearer abc123" -> "Authorization: Bearer ******"
//	mask.MustRegexp("bearer-token", `Bearer (?P<mask>[\w.~+/-]+=*)`)
func MustRegexp(name, expr string) Pattern {
	re := regexp.MustCompile(expr)
	return &regexpPattern{name: name, re: re, mask: re.SubexpIndex("mask")}
}

type regexpPattern struct {
	name string
	re   *regexp.Regexp
	mask int // submatch index of the "mask" group, or -1 when expr has none
}

func (p *regexpPattern) Name() string { return p.name }

func (p *regexpPattern) Find(src string) []Span {
	if p.mask < 0 {
		locs := p.re.FindAllStringIndex(src, -1)
		spans := make([]Span, 0, len(locs))
		for _, loc := range locs {
			spans = append(spans, Span{Start: loc[0], End: loc[1]})
		}
		return spans
	}

	locs := p.re.FindAllStringSubmatchIndex(src, -1)
	spans := make([]Span, 0, len(locs))
	for _, loc := range locs {
		start, end := loc[2*p.mask], loc[2*p.mask+1]
		if start < 0 { // the group took part in no match
			continue
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return spans
}
