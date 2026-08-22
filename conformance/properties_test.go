// What must hold of masking any text at all.
//
// The corpus states exactly what each of its cases masks to. That is what makes
// it reviewable, and it is also its limit: it says nothing about the text nobody
// wrote down. The properties here take the corpus as a starting point and drive
// the library through text derived from it — every prefix of every case, a byte
// pushed into every interesting position, cases run together — holding each
// result not to an expectation written by hand but to what must be true of any
// masking whatsoever.

package conformance

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/koki-develop/mask-go"
)

// separatorFor returns a byte that does not occur in src, which lets what was
// redacted be told from what was not without a notation the text could hold
// itself.
//
// It is one byte or nothing. A separator of two bytes would seem to extend the
// reach to text holding all 256 of them, but it does not: two bytes absent as a
// pair can still be made by the byte before the separator and the first byte of
// it, so splitting on it would find a separator that was never written. Text
// holding every byte there is has nothing to mark it with, and the caller has
// nothing to check.
func separatorFor(src string) (string, bool) {
	var held [256]bool
	for i := range len(src) {
		held[src[i]] = true
	}
	for b := range 256 {
		if !held[b] {
			return string([]byte{byte(b)}), true
		}
	}
	return "", false
}

// checkMasking holds masking src to what must hold of masking anything.
//
// Nothing here compares against a second implementation of the library. What is
// compared against is src itself: a redactor that writes a separator the text
// does not hold marks where each redaction went, and the values it was handed
// put back into those places must give src again. A redaction that ate a byte
// of the text around it, that was reported over text that was never there, or
// that left part of a value behind then has nowhere to hide.
func checkMasking(t testing.TB, patterns []mask.Pattern, src string) {
	t.Helper()

	sep, ok := separatorFor(src)
	if !ok {
		return // text holding every byte there is; nothing can mark it
	}

	known := make(map[mask.Pattern]bool, len(patterns))
	for _, p := range patterns {
		known[p] = true
	}

	var values []string
	marked := mask.New(
		mask.WithPatterns(patterns...),
		mask.WithRedactor(mask.NewRedactor(func(m mask.Match) string {
			values = append(values, m.Value)
			if m.Value == "" {
				t.Fatalf("masking %q redacted nothing at all in one region", src)
			}
			if !known[m.Pattern] {
				t.Fatalf("masking %q attributed a value to a pattern the masker was not given", src)
			}
			return sep
		})),
	).Mask(src)

	kept := strings.Split(marked, sep)
	if len(kept) != len(values)+1 {
		t.Fatalf("masking %q redacted %d value(s) but marked %d place(s)", src, len(values), len(kept)-1)
	}
	var b strings.Builder
	for i, value := range values {
		b.WriteString(kept[i])
		b.WriteString(value)
	}
	b.WriteString(kept[len(kept)-1])
	if b.String() != src {
		t.Fatalf("masking %q gave redactions and text that put back together are %q", src, b.String())
	}

	// What every other redactor writes goes in the same places. Fill is the one
	// that says how much was redacted, so it is the one held to the values.
	var want strings.Builder
	for i, value := range values {
		want.WriteString(kept[i])
		want.WriteString(strings.Repeat("*", utf8.RuneCountInString(value)))
	}
	want.WriteString(kept[len(kept)-1])

	m := maskerWith(patterns, mask.Fill('*'))
	masked := m.Mask(src)
	if masked != want.String() {
		t.Fatalf("masking %q gave %q, want %q", src, masked, want.String())
	}
	checkSecondPass(t, patterns, src, masked, kept, values)
	// A value that was in the text once and has been redacted is not in the
	// output at all. Where it was there more than once, some of them may have
	// been left on purpose — a pattern locating a single letter says nothing
	// about the other letters like it — so only the values that were there once
	// say anything here.
	//
	// What this catches on its own is little, and the guard is why it is worth
	// saying so: masked has just been held to kept and the values, and kept is
	// src with the redactions taken out of it, so a value standing in the
	// output is a value standing in a stretch the first pass left alone. On a
	// repeated input the guard is false throughout and this runs on nothing at
	// all. The property that reaches a scan which located one of two identical
	// values is checkSecondPass, run just above, which reads where the second
	// pass redacts rather than what the first pass left.
	for _, value := range values {
		if strings.Count(src, value) == 1 && strings.Contains(masked, value) {
			t.Fatalf("masking %q gave %q, which still holds the redacted %q", src, masked, value)
		}
	}
}

// checkSecondPass holds masking masked, which is what masking src gave, to
// redacting only where the first pass reached.
//
// Masking is not idempotent and the root package says so: a redaction reads
// differently from the value it replaced, so it can open a prefix that value
// closed, and an AWS access key ID written against a Slack prefix takes a Slack
// token with it on the second pass. What survives that is not whether the
// second pass redacts but where it may. masked is src with each of values
// replaced by a run of asterisks and kept are the stretches of src between
// them, so where the first pass wrote is known exactly, and a value the second
// pass locates must either overlap one of those runs or stand against one — a
// redaction beside it is what changed how it reads.
//
// A value that does neither is the defect this is here for. It sits in text the
// first pass left as it found it, with the bytes either side of it the ones it
// was written with, so nothing about it had changed when the first pass read
// over it and declined to locate it: a scan whose cursor carried past a value,
// or one that stopped at the first of two.
func checkSecondPass(t testing.TB, patterns []mask.Pattern, src, masked string, kept, values []string) {
	t.Helper()

	// Where the first pass wrote, in the offsets of masked. Fill writes one
	// asterisk per rune, which is what the run lengths come from.
	type run struct{ start, end int }
	runs := make([]run, 0, len(values))
	at := 0
	for i, value := range values {
		at += len(kept[i])
		end := at + utf8.RuneCountInString(value)
		runs = append(runs, run{start: at, end: end})
		at = end
	}

	sep, ok := separatorFor(masked)
	if !ok {
		return // text holding every byte there is; nothing can mark it
	}
	var found []string
	remarked := mask.New(
		mask.WithPatterns(patterns...),
		mask.WithRedactor(mask.NewRedactor(func(match mask.Match) string {
			found = append(found, match.Value)
			return sep
		})),
	).Mask(masked)
	if len(found) == 0 {
		return
	}

	between := strings.Split(remarked, sep)
	if len(between) != len(found)+1 {
		t.Fatalf("masking %q redacted %d value(s) but marked %d place(s)", masked, len(found), len(between)-1)
	}
	at = 0
	for i, value := range found {
		at += len(between[i])
		start, end := at, at+len(value)
		at = end

		// start <= r.end and r.start <= end is overlapping or touching: a
		// value ending where a run begins, or beginning where one ends, has a
		// redaction for a neighbour.
		if slices.ContainsFunc(runs, func(r run) bool { return start <= r.end && r.start <= end }) {
			continue
		}
		t.Fatalf("masking %q gave %q, in which %q is located again at %d, with no redaction of the first pass beside it", src, masked, value, start)
	}
}

// namedSet is a pattern set under the name a failure reports it by.
type namedSet struct {
	name     string
	patterns []mask.Pattern
}

// builtinSets is what the properties are driven with: the built-in patterns
// together, and each of them on its own.
//
// It is derived from AllBuiltinPatterns rather than written out, so that a pattern
// added to the library is driven through every property below without anyone
// remembering to add it here. A set of one is what says a pattern locates a
// value on its own; inside the whole set another pattern's match can cover for
// a defect.
//
// The sets a case builds out of substrings and reported spans are not here:
// they say what they say about the cases they were written for and nothing
// about text derived from them.
var builtinSets = func() []namedSet {
	sets := []namedSet{{name: "default", patterns: mask.AllBuiltinPatterns()}}
	for _, p := range mask.AllBuiltinPatterns() {
		sets = append(sets, namedSet{name: p.Name(), patterns: []mask.Pattern{p}})
	}
	return sets
}()

// readableCases returns the cases whose patterns look at the text they are
// handed, which are the ones text derived from them says anything about.
func readableCases(t testing.TB) []*corpusCase {
	t.Helper()

	var cases []*corpusCase
	for _, c := range corpusCases(t) {
		if c.reads {
			cases = append(cases, c)
		}
	}
	return cases
}

func TestProperties_everyPrefix(t *testing.T) {
	// A log line cut to a column limit, a read that stopped early, a value
	// still being written: text arrives cut short, and every prefix of every
	// case is masked here. A scan reading past the end of its input, or
	// resuming past what it has not consumed, shows up as a redaction that no
	// longer restores to the text it came from.
	cases := readableCases(t)
	for _, set := range builtinSets {
		t.Run(set.name, func(t *testing.T) {
			for _, c := range cases {
				for i := range len(c.in) + 1 {
					checkMasking(t, set.patterns, c.in[:i])
				}
			}
		})
	}
}

func TestProperties_everySuffix(t *testing.T) {
	// The other end: text that begins in the middle of a value, as a reader
	// resuming from an offset leaves it.
	cases := readableCases(t)
	for _, set := range builtinSets {
		t.Run(set.name, func(t *testing.T) {
			for _, c := range cases {
				for i := range len(c.in) + 1 {
					checkMasking(t, set.patterns, c.in[i:])
				}
			}
		})
	}
}

// injected is the bytes pushed into a case: the ones the built-in scans key on,
// the ones that end a run, and bytes text cannot hold.
var injected = []byte{'.', '_', '-', 'g', 'e', 'y', '0', ' ', '\n', 0x00, 0xff}

// injectionPoints returns where a byte is pushed into src. Every position of a
// short text, and of a longer one the edges of every redaction it holds, where a
// scan that has just decided something is about to be caught deciding it
// differently.
func injectionPoints(src string, bounds [][2]int) []int {
	if len(src) <= 48 {
		points := make([]int, 0, len(src)+1)
		for i := range len(src) + 1 {
			points = append(points, i)
		}
		return points
	}

	seen := map[int]bool{}
	var points []int
	add := func(i int) {
		if i < 0 || i > len(src) || seen[i] {
			return
		}
		seen[i] = true
		points = append(points, i)
	}
	for _, b := range bounds {
		start, end := b[0], b[1]
		add(start - 1)
		add(start)
		add(start + 1)
		add(end - 1)
		add(end)
		add(end + 1)
	}
	for i := 0; i <= len(src); i += 8 {
		add(i)
	}
	add(len(src))
	return points
}

func TestProperties_aByteInTheMiddle(t *testing.T) {
	// A byte pushed into a value breaks it, and a byte pushed beside one must
	// not. Either way what comes out has to put back together into what went
	// in, which is what a scan whose cursor runs past a byte it did not consume
	// stops doing.
	for _, c := range readableCases(t) {
		c.requireOut(t)
		m, err := parseMarked(c.out)
		if err != nil {
			t.Fatalf("%s: %v", c.id(), err)
		}
		_, values := maskMarked(c.patterns(), c.in)
		bounds, err := m.bounds(values)
		if err != nil {
			t.Fatalf("%s: %v; run go test ./conformance -update", c.id(), err)
		}
		points := injectionPoints(c.in, bounds)
		for _, set := range builtinSets {
			t.Run(set.name+"/"+c.subtest(), func(t *testing.T) {
				for _, b := range injected {
					for _, i := range points {
						checkMasking(t, set.patterns, c.in[:i]+string(b)+c.in[i:])
					}
				}
			})
		}
	}
}

func TestProperties_casesRunTogether(t *testing.T) {
	// Text does not arrive one case at a time. Cases are run together, with and
	// without a newline between them, so that a value ending where another
	// begins is masked as what it is rather than as what the pair looks like.
	cases := readableCases(t)
	for _, set := range builtinSets {
		t.Run(set.name, func(t *testing.T) {
			for i, c := range cases {
				for k := 1; k <= 6; k++ {
					other := cases[(i+k)%len(cases)]
					for _, sep := range []string{"", "\n", " ", "."} {
						checkMasking(t, set.patterns, c.in+sep+other.in)
					}
				}
			}
		})
	}
}

func TestProperties_repeatedCases(t *testing.T) {
	// A value repeated is a value every time. A scan that carries a cursor
	// forward through a run, as several of the built-in scans do, is what this
	// is aimed at: the second value must not be lost to what the first left
	// behind.
	for _, c := range readableCases(t) {
		for _, set := range builtinSets {
			t.Run(set.name+"/"+c.subtest(), func(t *testing.T) {
				for _, sep := range []string{"", "\n", " "} {
					checkMasking(t, set.patterns, strings.Repeat(c.in+sep, 8))
				}
			})
		}
	}
}

func TestProperties_maskerIsReusable(t *testing.T) {
	// A Masker is built once and handed everything a program logs. Driving
	// every readable case through a single Masker holds what a built-in scan
	// keeps between calls — a cursor, a decoder — to keeping nothing that
	// outlives the call it belongs to.
	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...))
	cases := readableCases(t)

	want := make([]string, len(cases))
	for i, c := range cases {
		want[i] = mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...)).Mask(c.in)
	}
	for round := range 3 {
		for i, c := range cases {
			if got := m.Mask(c.in); got != want[i] {
				t.Fatalf("round %d: %s: Mask(%q) = %q, want %q", round, c.id(), c.in, got, want[i])
			}
		}
	}
}

func TestProperties_redactorSeesTheValue(t *testing.T) {
	// What a redactor is handed is the text about to be redacted, and the
	// pattern that located it. A redactor writing the value straight back must
	// therefore leave the text untouched, whatever was located in it.
	identity := mask.NewRedactor(func(m mask.Match) string { return m.Value })

	for _, c := range corpusCases(t) {
		m := maskerWith(c.patterns(), identity)
		if got := m.Mask(c.in); got != c.in {
			t.Errorf("%s: a redactor writing the value back changed %q into %q", c.id(), c.in, got)
		}
	}
}

func TestProperties_redactorSeesThePattern(t *testing.T) {
	// The pattern a Match carries is the one the caller gave, the same value
	// every time, so that a redactor can key on it by identity rather than by
	// name.
	for _, c := range corpusCases(t) {
		patterns := c.patterns()
		known := make(map[mask.Pattern]bool, len(patterns))
		for _, p := range patterns {
			known[p] = true
		}

		var seen int
		m := maskerWith(patterns, mask.NewRedactor(func(match mask.Match) string {
			seen++
			if !known[match.Pattern] {
				t.Errorf("%s: a value was attributed to a pattern the masker was not given", c.id())
			}
			return ""
		}))
		m.Mask(c.in)
		if want := len(c.names(t)); seen != want {
			t.Errorf("%s: the redactor was called %d time(s), the case holds %d value(s)", c.id(), seen, want)
		}
	}
}

func TestProperties_noValueLeaksThroughAnyRedactor(t *testing.T) {
	// Whatever a redactor writes, what it was given must not be in the output
	// unless the redactor itself put it there. The redactors below are the ones
	// a caller reaches for.
	redactors := []struct {
		name     string
		redactor mask.Redactor
	}{
		{name: "Fill('*')", redactor: mask.Fill('*')},
		{name: `Fixed("[REDACTED]")`, redactor: mask.Fixed("[REDACTED]")},
		{name: `Fixed("")`, redactor: mask.Fixed("")},
		{name: "marking", redactor: markRedactor},
	}

	for _, c := range readableCases(t) {
		_, values := maskMarked(c.patterns(), c.in)
		for _, r := range redactors {
			got := maskerWith(c.patterns(), r.redactor).Mask(c.in)
			for _, value := range values {
				if strings.Count(c.in, value) == 1 && strings.Contains(got, value) {
					t.Errorf("%s: with %s, %q still holds %q", c.id(), r.name, got, value)
				}
			}
		}
	}
}

func TestProperties_everyCaseThroughEveryBuiltinSet(t *testing.T) {
	// Every case, whatever it was written for, through every built-in set. A
	// case written for one pattern says nothing about another, but nothing may
	// go wrong when it reaches one.
	for _, c := range corpusCases(t) {
		for _, set := range builtinSets {
			t.Run(fmt.Sprintf("%s/%s", set.name, c.subtest()), func(t *testing.T) {
				checkMasking(t, set.patterns, c.in)
			})
		}
	}
}
