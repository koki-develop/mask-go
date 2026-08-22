// What every corpus case is held to.
//
// A case states one thing — the text it masks to, with every redaction marked
// and named — and everything below is derived from that one statement. Nothing
// here is written per case, so a case cannot arrive with some of the properties
// and not others, and adding a case is adding a line rather than a test.

package conformance

import (
	"cmp"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/koki-develop/mask-go"
)

func TestConformance(t *testing.T) {
	files := loadCorpus(t)
	if *update {
		regenerate(t, files)
		files = loadCorpus(t) // hold what was written, not what was in hand
	}

	for _, f := range files {
		t.Run(f.name, func(t *testing.T) {
			for _, c := range f.cases {
				t.Run(c.name, func(t *testing.T) { checkCase(t, c) })
			}
		})
	}
}

// regenerate writes the out field of every case from what the library does now.
// It is what -update runs, and it runs before the checks rather than instead of
// them: a regenerated corpus is held to everything below in the same command
// that wrote it.
func regenerate(t *testing.T, files []*corpusFile) {
	t.Helper()

	for _, f := range files {
		for _, c := range f.cases {
			out, _ := maskMarked(c.patterns(), c.in)
			c.out, c.hasOut = out, true
		}
		data := f.render()
		old, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatalf("reading %s: %v", f.path, err)
		}
		if string(old) == string(data) {
			continue
		}
		if err := os.WriteFile(f.path, data, 0o644); err != nil {
			t.Fatalf("writing %s: %v", f.path, err)
		}
		t.Logf("%s rewritten", f.path)
	}
}

// checkCase holds one case to everything masking must be.
func checkCase(t *testing.T, c *corpusCase) {
	t.Helper()

	c.requireOut(t)
	patterns := c.patterns()

	// The statement itself. One comparison carries all of it: which text was
	// redacted, what each redaction is attributed to, how many there are, in
	// what order, and that the text around them is the text that went in.
	out, values := maskMarked(patterns, c.in)
	if out != c.out {
		t.Fatalf("%s: masking %q gives\n\t%s\nthe out field says\n\t%s", c.id(), c.in, out, c.out)
	}

	m, err := parseMarked(c.out)
	if err != nil {
		t.Fatalf("%s: the out field is not marked text: %v", c.id(), err)
	}
	restored, err := m.restore(values)
	if err != nil {
		t.Fatalf("%s: %v", c.id(), err)
	}
	if restored != c.in {
		t.Fatalf("%s: the marked text with the values back in it is %q, the in field is %q", c.id(), restored, c.in)
	}

	t.Run("redactors", func(t *testing.T) {
		// One marked text says what every redactor must give, so each is held
		// to it rather than to a line of asterisks written by hand.
		redactors := []struct {
			name     string
			redactor mask.Redactor
			want     string
		}{
			{name: "default", redactor: nil, want: m.fill(values, '*')},
			{name: "Fill('*')", redactor: mask.Fill('*'), want: m.fill(values, '*')},
			{name: "Fill('#')", redactor: mask.Fill('#'), want: m.fill(values, '#')},
			{name: "Fill('●')", redactor: mask.Fill('●'), want: m.fill(values, '●')},
			{name: "Fixed(\"[REDACTED]\")", redactor: mask.Fixed("[REDACTED]"), want: m.fixed("[REDACTED]")},
			{name: "Fixed(\"\")", redactor: mask.Fixed(""), want: m.fixed("")},
			{name: "marking", redactor: markRedactor, want: c.out},
		}

		for _, r := range redactors {
			t.Run(r.name, func(t *testing.T) {
				masker := maskerWith(patterns, r.redactor)
				if got := masker.Mask(c.in); got != r.want {
					t.Fatalf("Mask(%q) = %q, want %q", c.in, got, r.want)
				}
			})
		}
	})

	t.Run("no value survives", func(t *testing.T) {
		// The point of the library: what was redacted is not in the output.
		// Fill leaves as many characters as the value had, so a scan that
		// located all but a byte of a value would pass everything above and
		// fail here.
		for _, redactor := range []mask.Redactor{mask.Fill('*'), mask.Fixed("[REDACTED]"), markRedactor} {
			got := maskerWith(patterns, redactor).Mask(c.in)
			for _, value := range values {
				if strings.Count(c.in, value) == 1 && strings.Contains(got, value) {
					t.Errorf("Mask(%q) = %q, which still holds %q", c.in, got, value)
				}
			}
		}
	})

	t.Run("text around a value", func(t *testing.T) {
		// Everything outside a redaction is the input's own bytes, in order.
		// Fixed("") leaves exactly those.
		got := maskerWith(patterns, mask.Fixed("")).Mask(c.in)
		if want := m.fixed(""); got != want {
			t.Errorf("Mask(%q) = %q, want %q", c.in, got, want)
		}
	})

	t.Run("order of patterns", func(t *testing.T) {
		// Which text is redacted may not depend on the order the patterns were
		// given in; only which pattern a redaction is attributed to may, and
		// the corpus states that with a pair of sets written in either order.
		forward := maskerWith(patterns, mask.Fill('*')).Mask(c.in)
		backward := maskerWith(reversed(patterns), mask.Fill('*')).Mask(c.in)
		if forward != backward {
			t.Errorf("Mask(%q) = %q with the patterns in order and %q reversed", c.in, forward, backward)
		}
	})

	t.Run("options in either order", func(t *testing.T) {
		want := m.fixed("X")
		byPatterns := mask.New(mask.WithPatterns(patterns...), mask.WithRedactor(mask.Fixed("X"))).Mask(c.in)
		byRedactor := mask.New(mask.WithRedactor(mask.Fixed("X")), mask.WithPatterns(patterns...)).Mask(c.in)
		if byPatterns != want || byRedactor != want {
			t.Errorf("Mask(%q) = %q and %q, want %q for both", c.in, byPatterns, byRedactor, want)
		}
	})

	t.Run("split across options", func(t *testing.T) {
		// A set given one pattern at a time through repeated options is the
		// same set.
		opts := make([]mask.Option, 0, len(patterns)+1)
		for _, p := range patterns {
			opts = append(opts, mask.WithPatterns(p))
		}
		opts = append(opts, mask.WithRedactor(mask.Fill('*')))
		if got, want := mask.New(opts...).Mask(c.in), m.fill(values, '*'); got != want {
			t.Errorf("Mask(%q) = %q, want %q", c.in, got, want)
		}
	})

	t.Run("no pattern redacts nothing", func(t *testing.T) {
		if got := mask.New().Mask(c.in); got != c.in {
			t.Errorf("a Masker with no pattern changed %q into %q", c.in, got)
		}
	})

	if !c.reads {
		return
	}

	t.Run("put back together", func(t *testing.T) {
		// The same claim the corpus makes, made again without reading the
		// corpus: mark the redactions with a separator the text does not hold,
		// put the values back, and the input must come out.
		//
		// It holds masking the output to reaching no further than the first
		// pass reached along the way, which is why it sits behind the guard
		// rather than beside the check above. A pattern reporting spans of its
		// own reports the same offsets into text that has changed under them,
		// so a case saying spans: reported is held back from every property
		// that rests on where a value sits.
		checkMasking(t, patterns, c.in)
	})

	t.Run("in a longer text", func(t *testing.T) {
		// A value does not arrive alone. It arrives in a log line, in a line of
		// JSON, in the middle of a paragraph, and what is redacted must be the
		// same wherever it sits. The text put around it is held to being text
		// these patterns find nothing in, so that a case cannot pass here by the
		// surroundings being masked too.
		//
		// A case whose patterns report spans of their own, rather than finding
		// them in the text, says spans: reported: nothing moves for it when the
		// text around it grows.
		affixes := []struct {
			name          string
			before, after string
		}{
			{name: "before", before: "time=2026-08-17T00:00:00Z level=info msg=\"calling api\" ", after: ""},
			{name: "after", before: "", after: " status=200 duration=13ms"},
			{name: "around", before: "log: ", after: " (end)"},
			{name: "on a line of its own", before: "first line\n", after: "\nlast line"},
			{name: "between multi-byte text", before: "日本語 ", after: " 日本語"},
			{name: "between tabs", before: "\t", after: "\t"},
		}

		for _, affix := range affixes {
			t.Run(affix.name, func(t *testing.T) {
				masker := maskerWith(patterns, mask.Fill('*'))
				if got := masker.Mask(affix.before + affix.after); got != affix.before+affix.after {
					t.Fatalf("the text put around the case is not left alone: %q", got)
				}
				src := affix.before + c.in + affix.after
				want := affix.before + m.fill(values, '*') + affix.after
				if got := masker.Mask(src); got != want {
					t.Errorf("Mask(%q) = %q, want %q", src, got, want)
				}
			})
		}
	})

	t.Run("twice over", func(t *testing.T) {
		// The same value twice in one text is redacted twice: a scan that stops
		// at the first, or one whose cursor does not carry past it, shows here.
		masker := maskerWith(patterns, mask.Fill('*'))
		src := c.in + "\n" + c.in
		want := m.fill(values, '*') + "\n" + m.fill(values, '*')
		if got := masker.Mask(src); got != want {
			t.Errorf("Mask(%q) = %q, want %q", src, got, want)
		}
	})
}

// maskerWith returns a Masker over patterns, with redactor where one is given
// and the default otherwise.
func maskerWith(patterns []mask.Pattern, redactor mask.Redactor) *mask.Masker {
	if redactor == nil {
		return mask.New(mask.WithPatterns(patterns...))
	}
	return mask.New(mask.WithPatterns(patterns...), mask.WithRedactor(redactor))
}

func TestConformance_concurrentUse(t *testing.T) {
	// A Masker, a Pattern and a Redactor are all documented safe for concurrent
	// use, and the built-in scans carry a cursor and a decoder as they go.
	// Driving the whole corpus from many goroutines at once puts what they
	// carry under the race detector and holds every answer to the one a single
	// goroutine gets.
	cases := corpusCases(t)
	maskers := make([]*mask.Masker, len(cases))
	for i, c := range cases {
		c.requireOut(t)
		maskers[i] = maskerWith(c.patterns(), markRedactor)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 4 {
				for i, c := range cases {
					if got := maskers[i].Mask(c.in); got != c.out {
						t.Errorf("%s: Mask(%q) = %q, want %q", c.id(), c.in, got, c.out)
						return
					}
				}
			}
		})
	}
	wg.Wait()
}

func TestConformance_oneMaskerForEveryCase(t *testing.T) {
	// A caller builds one Masker and hands it everything, so the corpus is run
	// again through a single Masker over the built-in patterns. Only the cases
	// masked with the built-in set say what must come out; the rest are here
	// because nothing may go wrong when they are handed to it.
	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...), mask.WithRedactor(markRedactor))

	for _, c := range corpusCases(t) {
		c.requireOut(t)
		got := m.Mask(c.in)
		if c.set == "default" && got != c.out {
			t.Errorf("%s: Mask(%q) = %q, want %q", c.id(), c.in, got, c.out)
		}
	}
}

func TestCorpus_coversEveryBuiltinPattern(t *testing.T) {
	// The corpus is the statement of what this library does, so a built-in
	// pattern absent from it is a pattern nothing here states anything about.
	// Adding one to AllBuiltinPatterns therefore fails until the corpus says what
	// it locates and what it leaves alone.
	const least = 3

	located := map[string]int{} // cases locating the pattern, however many times
	alone := map[string]int{}   // cases where the pattern by itself locates nothing
	for _, c := range corpusCases(t) {
		names := c.names(t)
		if len(names) > 0 {
			// Cases, not redactions: one line holding two tokens says one
			// thing about the pattern, not two, and counting it twice would
			// leave the bar below met by half the cases it asks for.
			for _, name := range slices.Compact(slices.Sorted(slices.Values(names))) {
				located[name]++
			}
			continue
		}
		// A case that locates nothing counts for a pattern only where that
		// pattern is the whole set it was masked with. The clean cases masked
		// with every built-in at once are inherited by each pattern added to
		// that set, and would meet the bar below without one case having been
		// written about the pattern being added.
		if set := c.patterns(); len(set) == 1 {
			alone[set[0].Name()]++
		}
	}

	for _, p := range mask.AllBuiltinPatterns() {
		t.Run(p.Name(), func(t *testing.T) {
			if located[p.Name()] < least {
				t.Errorf("the corpus has %d case(s) locating a %s, want at least %d", located[p.Name()], p.Name(), least)
			}
			if alone[p.Name()] < least {
				t.Errorf("the corpus has %d case(s) where %s alone locates nothing, want at least %d", alone[p.Name()], p.Name(), least)
			}
		})
	}
}

func TestCorpus_usesEveryPatternSet(t *testing.T) {
	// A set nothing names is a set nothing is stated with, and reading the
	// corpus would suggest otherwise.
	used := map[string]int{}
	for _, c := range corpusCases(t) {
		used[c.set]++
	}
	for _, name := range slices.Sorted(maps.Keys(patternSets)) {
		if used[name] == 0 {
			t.Errorf("no case is masked with the pattern set %q", name)
		}
	}
}

func TestCorpus_attributionIsExercised(t *testing.T) {
	// overlap_and_attribution.txt states how a redaction is attributed when two
	// patterns cover the same span, and states it with patterns of its own. What
	// it cannot say for itself is whether any built-in input reaches those rules:
	// two built-ins reporting one span is what drives the last of them,
	// registration order, and only the corpus in full can be counted for it.
	//
	// A comment there counts before writing "every", "only" or "no input at all",
	// and this is what a comment about this one rests on. No out line can say it.
	// An out line names the pattern the redaction went to, so it does pin which
	// of two that reach one span won it — but not that a second one reached it at
	// all. Let the losing pattern stop locating that value and the winner wins
	// still, the line stays exactly as it was, and the rule is reached by nothing
	// any more.
	//
	// Each case is read with the set it is masked with rather than with every
	// built-in, because reaching the rule is what is being counted and a case
	// masked with one pattern reaches nothing however its text reads. Moving the
	// case that reaches it under a set of one would otherwise leave this passing
	// on a collision the corpus no longer performs. Only built-ins count towards
	// it: the patterns of overlap_and_attribution.txt are written to cover one
	// span and would meet the bar on their own, which is the arrangement the
	// comment there is drawing a contrast with.
	type span struct{ start, end int }

	builtin := map[mask.Pattern]bool{}
	for _, p := range mask.AllBuiltinPatterns() {
		builtin[p] = true
	}

	var together []string
	for _, c := range corpusCases(t) {
		at := map[span][]string{}
		for _, p := range c.patterns() {
			if !builtin[p] {
				continue
			}
			for _, s := range p.Find(c.in) {
				// The names, not the spans: a scan reporting one span twice, or
				// a set naming one pattern twice, is one pattern still and
				// reaches no tie-break. Counting the report rather than the
				// pattern would leave this met with nothing contesting anything.
				k := span{s.Start, s.End}
				if !slices.Contains(at[k], p.Name()) {
					at[k] = append(at[k], p.Name())
				}
			}
		}
		for _, k := range slices.SortedFunc(maps.Keys(at), func(a, b span) int {
			if a.start != b.start {
				return cmp.Compare(a.start, b.start)
			}
			return cmp.Compare(a.end, b.end)
		}) {
			// The names are in the order the case's own set holds them, which
			// is the order the tie-break reads: Masker.locate sorts on the
			// index of the pattern in the list it was given. So of two tied
			// here the first is the one the redaction went to — though a third
			// pattern reporting a longer span from the same start would take it
			// from both, which is a different rule and not what this counts.
			if names := at[k]; len(names) > 1 {
				together = append(together, fmt.Sprintf("%s: [%d,%d) %s", c.id(), k.start, k.end, strings.Join(names, ", ")))
			}
		}
	}

	if len(together) == 0 {
		t.Error("no corpus case masks with two built-in patterns reporting one span, so nothing here reaches the tie-break " +
			"in overlap_and_attribution.txt; write a case that does, or say in that file that only its own patterns reach it")
		return
	}
	t.Log("built-in values sharing a span, first name first:\n\t" + strings.Join(together, "\n\t"))
}

func TestCorpus_summary(t *testing.T) {
	// What the corpus covers, in one place, for whoever is reading it rather
	// than running it.
	cases := corpusCases(t)
	byPattern := map[string]int{}
	clean := 0
	for _, c := range cases {
		names := c.names(t)
		if len(names) == 0 {
			clean++
		}
		for _, name := range names {
			byPattern[name]++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d cases, %d of which hold no value", len(cases), clean)
	for _, name := range slices.Sorted(maps.Keys(byPattern)) {
		fmt.Fprintf(&b, "\n\t%s: %d redaction(s)", name, byPattern[name])
	}
	t.Log(b.String())
}

func TestConformance_scale(t *testing.T) {
	// A log stream is not a line. The whole corpus is written into one document
	// of a few mebibytes and masked in one call, which a scan that costs time
	// quadratic in the length of its input does not finish, and which holds the
	// merge and the walk to what they do at size.
	const (
		size  = 2 << 20
		limit = 4 * time.Second
	)

	var b strings.Builder
	for _, c := range corpusCases(t) {
		b.WriteString(c.in)
		b.WriteString("\n")
	}
	unit := b.String()
	if unit == "" {
		t.Fatal("the corpus is empty")
	}
	src := strings.Repeat(unit, size/len(unit)+1)

	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...))
	start := time.Now()
	masked := m.Mask(src)
	if d := time.Since(start); d > limit {
		t.Errorf("masking %d bytes took %v, want under %v", len(src), d, limit)
	}
	if got, want := utf8.RuneCountInString(masked), utf8.RuneCountInString(src); got != want {
		t.Errorf("masking with Fill left %d runes, the input had %d", got, want)
	}

	// Masking again may redact more than masking once did, which the root
	// package states. What it may not do is redact less: Fill writes a rune for
	// a rune, so a run of asterisks may grow but no asterisk may turn back into
	// text.
	again := m.Mask(masked)
	if got, want := utf8.RuneCountInString(again), utf8.RuneCountInString(masked); got != want {
		t.Errorf("masking a masked document left %d runes, it had %d", got, want)
	}
	if got, want := strings.Count(again, "*"), strings.Count(masked, "*"); got < want {
		t.Errorf("masking a masked document left %d asterisk(s), it had %d", got, want)
	}
}
