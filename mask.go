// Package mask redacts sensitive values such as API keys and access tokens
// from text.
//
// A Masker scans its input with the patterns it was given and redacts every
// value it locates:
//
//	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...))
//	fmt.Println(m.Mask("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
//
// Output:
//
//	GITHUB_TOKEN=****************************************
//
// A Masker scans only with the patterns given to it; nothing is enabled
// implicitly. AllBuiltinPatterns returns the built-in ones, and a custom
// pattern comes from NewPattern, MustRegexp or any implementation of the
// Pattern interface.
package mask

import (
	"cmp"
	"slices"
	"strings"
)

// Masker redacts sensitive values in text.
//
// A Masker is fixed once created and is safe for concurrent use by multiple
// goroutines.
type Masker struct {
	patterns []Pattern
	redactor Redactor
}

// New returns a Masker that scans with the patterns given to WithPatterns and
// redacts what it locates with the redactor given to WithRedactor, which
// defaults to Fill('*').
//
// A Masker with no patterns redacts nothing.
func New(opts ...Option) *Masker {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if o.redactor == nil {
		o.redactor = Fill('*')
	}
	return &Masker{patterns: o.patterns, redactor: o.redactor}
}

// Mask returns src with every located value redacted.
//
// Values that overlap are redacted together as one, so that no part of a
// located value survives. The combined text is attributed to the pattern that
// located the value starting earliest; among those, the longest; among those,
// the one added first by WithPatterns.
func (m *Masker) Mask(src string) string {
	found := m.locate(src)
	if len(found) == 0 {
		return src
	}

	var b strings.Builder
	b.Grow(len(src))
	end := 0
	for _, f := range found {
		b.WriteString(src[end:f.Start])
		b.WriteString(m.redactor.Redact(Match{Pattern: f.pattern, Value: src[f.Start:f.End]}))
		end = f.End
	}
	b.WriteString(src[end:])
	return b.String()
}

// located is a span of src together with the pattern it came from.
type located struct {
	Span
	pattern Pattern
	order   int // index of pattern in Masker.patterns
}

// locate returns the values every pattern finds in src, ordered by position
// and merged so that no two overlap.
func (m *Masker) locate(src string) []located {
	var all []located
	for i, p := range m.patterns {
		for _, s := range p.Find(src) {
			if s.Start < 0 || s.End > len(src) || s.Start >= s.End {
				continue
			}
			all = append(all, located{Span: s, pattern: p, order: i})
		}
	}
	if len(all) < 2 {
		return all
	}

	slices.SortFunc(all, func(a, b located) int {
		if d := cmp.Compare(a.Start, b.Start); d != 0 {
			return d
		}
		if d := cmp.Compare(b.End, a.End); d != 0 { // the longer one first
			return d
		}
		return cmp.Compare(a.order, b.order)
	})

	// merged shares the array of all. append never reaches past the element
	// being read, which range has already copied out, so writing through
	// merged cannot disturb the rest of the walk.
	merged := all[:1]
	for _, next := range all[1:] {
		last := &merged[len(merged)-1]
		if next.Start < last.End {
			last.End = max(last.End, next.End)
			continue
		}
		merged = append(merged, next)
	}
	return merged
}
