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
// pattern comes from NewPattern, Regexp, MustRegexp or any implementation of
// the Pattern interface.
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
//
// Masking is not idempotent, and what Mask is for is the text a program is
// about to write rather than text it has already masked. A redaction is itself
// text, and it does not read as the value it replaced: Fill('*') leaves an
// asterisk where a letter stood, and a prefix that letter closed is then open,
// so an AWS access key ID written against a Slack prefix is redacted on the
// first pass and takes a Slack token with it on the second. Fixed("") takes
// the value out altogether, splicing the text either side of it into text that
// was never written. Either way masking again may redact more than masking
// once did, and neither is a defect in a scan.
func (m *Masker) Mask(src string) string {
	found := m.locate(src, 0).found
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

// locations is what one pass of a Masker's patterns over a text found.
type locations struct {
	// found are the values, ordered by position and merged so that no two
	// overlap.
	found []located
	// retain is the offset from which the text is not settled: the least any
	// pattern reported, since the text is settled only as far as every
	// pattern scanning it agrees that it is, and len(src) where there are no
	// patterns at all.
	retain int
	// holder is the pattern that settled least, and nil where retain is the
	// whole of the text. It is what a stream names when it gives up holding
	// text back, so that the redaction says which grammar was still open.
	holder Pattern
}

// locate returns what every pattern finds in src beginning at or after from,
// and how far along src they leave settled.
//
// What a pattern reports is clamped into src rather than trusted: a Pattern is
// written by a caller, and one answering past either end would otherwise
// release text no pattern has read, or hold a stream that nothing will ever
// settle.
//
// from is zero for a whole text and is what a stream masking a window of one
// passes: the window opens LookBehind bytes in front of the text still to be
// written out, so that a pattern reading back over a value has the text to
// read, and a value beginning in that opening is one the window has already
// carried past. What stands in front of such a value is outside the window, so
// it is the one place a pattern cannot be right about.
//
// Such a value is dropped. Cutting it back to where the opening ends would
// redact text the whole input leaves alone — a candidate turned away by the
// character in front of it is turned away nowhere else, and the window is the
// one place that character is missing.
//
// Dropping is safe only because a value is dropped alone. A pattern reporting
// one span where two values overlap would have the second dropped with the
// first and written out as it stands, so a pattern that joins what it reports
// leaves out of the joining anything the text in front of it decides. That is
// what LookBehind asks of a Find, and what Regexp does with an expression
// carrying \b or an anchor.
func (m *Masker) locate(src string, from int) locations {
	var all []located
	found := locations{retain: len(src)}
	for i, p := range m.patterns {
		spans, r := p.Find(src)
		if r = min(max(r, 0), len(src)); r < found.retain {
			found.retain, found.holder = r, p
		}
		for _, s := range spans {
			if s.Start < from || s.End > len(src) || s.Start >= s.End {
				continue
			}
			all = append(all, located{Span: s, pattern: p, order: i})
		}
	}
	if len(all) < 2 {
		found.found = all
		return found
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
	found.found = merged
	return found
}
