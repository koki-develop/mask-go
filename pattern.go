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
	//
	// Both ends must fall on a rune boundary. A span cutting a multi-byte
	// rune in half is neither ignored nor repaired: the bytes either side of
	// it are written back as they were found, so what is left of that rune
	// stands beside the redaction and the output is not valid UTF-8. The
	// built-in patterns and MustRegexp cannot report such a span — every
	// built-in decides its ends on an ASCII alphabet, and Go's regexp
	// matches runes — so this is a demand on a Find written by hand.
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
//
// Go admits the name more than once, which is what a marker written in
// variants asks for — one branch of an alternation apiece — and every group
// named "mask" that took part in the match is redacted. A match where none of
// them did is redacted nowhere.
func MustRegexp(name, expr string) Pattern {
	re := regexp.MustCompile(expr)
	var mask []int
	for i, sub := range re.SubexpNames() {
		if sub == "mask" {
			mask = append(mask, i)
		}
	}
	return &regexpPattern{name: name, re: re, mask: mask}
}

type regexpPattern struct {
	name string
	re   *regexp.Regexp
	// mask holds the submatch index of every group named "mask", and is
	// empty when expr names none. All of them rather than one, because
	// SubexpIndex reports the leftmost of the groups sharing a name: taking
	// that one alone would read the group of a branch that did not match, see
	// it take part in nothing and drop the whole match — an alternation
	// naming the group in each of its branches would then redact the first
	// branch and pass the rest through untouched.
	mask []int
}

func (p *regexpPattern) Name() string { return p.name }

func (p *regexpPattern) Find(src string) []Span {
	if len(p.mask) == 0 {
		locs := p.re.FindAllStringIndex(src, -1)
		spans := make([]Span, 0, len(locs))
		for _, loc := range locs {
			spans = append(spans, Span{Start: loc[0], End: loc[1]})
		}
		return spans
	}

	locs := p.re.FindAllStringSubmatchIndex(src, -1)
	// A match yields one span per group named "mask" that took part in it,
	// which is every one of them at most.
	spans := make([]Span, 0, len(locs)*len(p.mask))
	for _, loc := range locs {
		for _, i := range p.mask {
			start, end := loc[2*i], loc[2*i+1]
			if start < 0 { // the group took part in no match
				continue
			}
			spans = append(spans, Span{Start: start, End: end})
		}
	}
	return spans
}
