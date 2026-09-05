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

	// tails are what a pattern's openings settle, one entry apiece and nil
	// where a pattern declares none this may answer with — a pattern with no
	// literals at all, and a pattern whose scan settles further back than its
	// literals do. What locate asks them is where a pattern it has already
	// passed over leaves the text settled.
	//
	// This is a shorter list than opens below, and the difference is the whole
	// of what the two fields are for. A pattern with literals and no tail is
	// passed over where nothing has to be settled and run where something
	// does, so locate reads opens to decide whether it may skip the scan and
	// tails to decide whether it may answer for it.
	//
	// They are gathered here rather than asked of each pattern in the loop
	// because asking is a type assertion, and a Masker holding the whole
	// registry would pay one per pattern per call to answer a question that
	// was settled when it was made.
	//
	// It is empty where the Masker holds too few patterns declaring literals
	// for a filter to be worth building for either side of the walk, and that
	// emptiness is one of the two things gather reads to build none —
	// settlingWorthIt below is the other. A tail must never be read without the
	// filter that answers it, since an empty filter turns every literal away
	// and would have the pattern passed over on text it locates values in.
	tails []*prefixTail

	// opens are where a pattern's literals stand in a filter, one entry apiece
	// and empty where a pattern declares none this can read. It is asked far
	// more often than tails — once a pattern a call, where a tail is walked
	// only for the ones turned away — so it is gathered here rather than
	// reached through the patterns.
	//
	// Every entry points into one array, so the walk over the registry reads
	// the openings of the patterns in the order it asks about them. Reached
	// through the tails they are a slice header in whichever global that
	// pattern was declared in, which is one miss a pattern on a line the whole
	// registry is turned away from.
	//
	// filterOn fills this and tails together, which is what lets locate read
	// this at the index of the pattern it is asking about without a bound of
	// its own.
	opens [][]gramPair

	// settlingWorthIt is whether the filter earns itself back when settling as
	// well as when masking, which is not the same question asked twice. Mask
	// may pass over every pattern declaring literals; a stream may pass over
	// only those with a tail to answer for them, and that is the shorter list.
	// A Masker whose count reaches gramsWorthIt on the first and not on the
	// second is one the filter pays for as a Masker and not as a stream, so it
	// builds the tables, reads them for Mask, and hands every pattern the text
	// when a stream asks.
	//
	// It is settled here rather than counted in gather because the counting is
	// a walk of the registry and the question is asked once a call.
	settlingWorthIt bool
}

// gramsWorthIt is the least number of patterns a Masker must be able to turn
// away for it to build a grams filter at all.
//
// The filter is one walk of the input, and what it saves is the walks of the
// patterns it turns away. Those are not the same walk: a scan looks for one
// byte with strings.Index, which reads a word of the input at a time, where the
// filter reads a word and takes six pieces out of it. So a Masker holding few
// patterns pays more for the filter than the scans it saves, however many of
// them it turns away, and one holding the registry saves many times it.
//
// Where the two cross is not one number. The filter is emptied once a call
// whatever the text is, where the scans it stands in for cost in proportion to
// the text, so the crossing climbs as the text shrinks:
// BenchmarkPrefilter_Patterns (benchmark_test.go) reads it off at several
// lengths, and it stands at eight over a record of eighty-seven bytes and over
// logs of several records, at twelve over a fragment of fifty, at sixteen over
// one of a couple of dozen, and at twenty-four over one of a few bytes.
//
// The first is the one to take, because it is where the difference is worth
// anything. A Masker of eight to sixteen patterns handed a fragment pays the
// emptying of a filter that did not earn itself back, which is a few tens of
// nanoseconds and no more; the same Masker handed a log of seven hundred bytes
// is faster for having built one, by an eighth of the work at the bottom of
// that range and by two thirds of it at the top. A caller reaching for one
// vendor's accessor is on the near side of the number and pays nothing either
// way.
//
// The number is asked of each side of the walk separately, because the two do
// not turn away the same patterns: a pattern with literals and no tail is one
// Mask passes over and a stream runs, so it pays for the filter when masking
// and not when settling. New counts both and gather reads the count of the side
// asking.
//
// One number serves both because settling is the side the filter is worth least
// in: its crossing stands at or above the masking side's at every length
// measured. That is so twice over: a pattern the filter turns away still owes a
// stream where its openings leave the text settled, and that walk is the
// filter's to pay, while a pattern declaring literals and no tail is not turned
// away when settling at all. So a number read off settling is one the masking
// side has already earned, and all a Masker gives up for holding one number
// rather than two is a seventh pattern over a record of eighty-seven bytes,
// which is the only reading either side puts below this number.
//
// Which side is the lesser is measured rather than assumed, and the benchmark
// times both for that reason: the two turn away different patterns, so the gap
// between them moves whenever a pattern declaring literals and no tail is
// added.
//
// It moves whenever the walk that fills the filter does, which is what the
// benchmark is for: a filter made cheaper and a number left where it was is a
// Masker paying for scans it need not run.
const gramsWorthIt = 8

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
	m := &Masker{patterns: o.patterns, redactor: o.redactor}
	// filterOpens (builtin_scan.go) is what leaves a pattern out of both the
	// count and the table: literals a filter cannot read are literals it says
	// yes to whatever the text is, and asking about those is a lookup at every
	// call for an answer settled here.
	//
	// Counted twice, because the two sides of the walk do not turn away the
	// same patterns and gramsWorthIt is the number each has to reach on its
	// own. Counted once, a Masker of patterns Mask alone can pass over would
	// build a filter a stream pays for and saves nothing by.
	masking, settling := 0, 0
	for _, p := range o.patterns {
		if len(filterOpens(p)) > 0 {
			masking++
			if settlingTail(p) != nil {
				settling++
			}
		}
	}
	if masking >= gramsWorthIt {
		m.filterOn(o.patterns)
		m.settlingWorthIt = settling >= gramsWorthIt
	}
	return m
}

// filterOn fills the tables a Masker turns patterns away by, from patterns.
//
// Both of them together, and nowhere else: locate reads one at the index of the
// other, so a Masker holding one without the other reaches past the end of it on
// the first text it is handed, and two statements are two a caller can write
// half of.
func (m *Masker) filterOn(patterns []Pattern) {
	m.tails = make([]*prefixTail, len(patterns))
	for i, p := range patterns {
		m.tails[i] = settlingTail(p)
	}
	m.opens = gatherOpens(patterns)
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
	found := m.gather(src, 0, false).found
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
	// patterns at all. It is zero, which promises nothing, where the walk that
	// filled this was not asked to settle the text — gather says why.
	retain int
	// holder is the pattern that settled least, and nil where no pattern is
	// holding the text back. It is what a stream names when it gives up
	// holding text back, so that the redaction says which grammar was still
	// open.
	holder Pattern
}

// locate returns what every pattern finds in src beginning at or after from,
// and how far along src they leave settled.
//
// Not every pattern is run. A built-in declares the openings its candidates are
// read back from, and grams (builtin_scan.go) says how one walk of src answers
// for the whole registry which of those openings src cannot hold. A pattern
// turned away there locates nothing in src, so what stands in for its answer is
// where its openings alone leave src settled — which is what its scan would
// have reported having found nothing, and what
// Test_builtins_prefilterAgreesWithFind holds every one of them to.
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
	return m.gather(src, from, true)
}

// gather is locate, and settles src as well where settle asks it to.
//
// Mask reads the whole of its input at once and ignores what the patterns leave
// settled, so answering for the ones turned away is a walk of their openings
// over the tail of the text for a number nothing reads — one walk per pattern
// turned away, which over a line holding no value is nearly the whole registry.
// What a stream asks is the same question with the number kept.
//
// Where settle is false it reports nothing settled, which Pattern.Find calls the
// answer that promises nothing. Skipping that walk can only leave the offset
// further along than the patterns agree it is, and an offset too far along is
// text released before a pattern has read it.
func (m *Masker) gather(src string, from int, settle bool) locations {
	var all []located
	found := locations{retain: len(src)}

	// What the patterns share about src, worked out once: a pattern whose
	// literals this turns away locates nothing in src and need not be run.
	//
	// It is built for the side asking, and only where that side has patterns
	// enough to pay for it — settlingWorthIt is where that stands.
	//
	// The filter stands here rather than in the Masker because a Masker is
	// shared between goroutines and a filter is one text's. It is nil where
	// none is to be built, which is what the walk below reads to hand every
	// pattern the text: an empty filter would turn every opening away.
	var g *grams
	if len(m.tails) > 0 && (!settle || m.settlingWorthIt) {
		var f grams
		f.fill(src)
		g = &f
	}

	for i, p := range m.patterns {
		// Two questions, and the second is asked only where the first says
		// yes. Do this pattern's literals stand in the text — which is the
		// whole of it where nothing has to be settled? And where something
		// does, is there a tail that settles no further than the scan would
		// have? builtin (builtin_scan.go) is what keeps the two apart.
		//
		// Asked in that order, and measured rather than reasoned about: the
		// tail is a nil test where the literals are a lookup, but asking the
		// cheaper one first costs Mask something over a twentieth of a short
		// text and saves a stream nothing, since the lookup it skips is one of
		// the few patterns declaring literals and no tail.
		if g != nil && gramsTurnAway(g, m.opens[i]) && (!settle || m.tails[i] != nil) {
			if settle {
				if r := m.tails[i].start(src); r < found.retain {
					found.retain, found.holder = r, p
				}
			}
			continue
		}
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
	if !settle {
		found.retain, found.holder = 0, nil
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
