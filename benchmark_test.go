package mask

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
)

// What the benchmarks of this package are driven by, and the bodies they share.
//
// What a pattern is timed on lives with the pattern, in the
// builtin_<name>_test.go beside it: what is worth timing in a scan is the run
// its cursor exists to walk once, the candidate crowded behind another and the
// byte test that turns most of a log line away — inputs crafted against what
// that one scan remembers, which say nothing about any other. A table here
// would hold them all and be read by nobody looking at the scan they were
// written for.
//
// What drives them is here, and is one benchmark over the registry rather than
// one function a pattern. A pattern keeps a fuzz target of its own because the
// corpus under testdata/fuzz is keyed on the name of the target; a benchmark
// has no such corpus, and a function a pattern would only be one more thing to
// forget — the entry names the cases, and BenchmarkBuiltins times whatever the
// entry names, so a built-in cannot arrive with a table nothing runs.
//
// The two measure different things and both are wanted. BenchmarkMasker_Mask is
// what a caller pays, the whole of it: every pattern over the same text, the
// spans sorted and merged, the output built. A regression in one scan is
// divided there by however many patterns the registry holds, and the more it
// holds the less of one is left to see, which is why a change to a scan is
// compared against that scan's own cases under BenchmarkBuiltins as well.

// maskerMaskBenchmarks is what a Masker holding every built-in is timed on.
// It is named rather than written inside the benchmark so that
// Test_maskerMaskBenchmarks below can hold every case to the count it states
// without -bench being run, as the entries in builtinPatterns hold the
// per-pattern ones.
func maskerMaskBenchmarks() []benchmarkCase {
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.github.com/user `

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "token=ghp_0123456789abcdefghijklmnopqrstuvwxyz",
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "token=ghp_0123456789abcdefghijklmnopqrstuvwxyz",
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"token=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n", 32),
			spans: 32,
		},
		{
			// The stateless installation token holds a JWT, so both built-in
			// patterns fire on it. The two spans overlap and are redacted
			// together as one, which is the single redaction counted here.
			name:  "overlapping values",
			src:   "token=ghs_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			spans: 1,
		},
		{
			// A record dense in colons written against digits, which the line
			// above has two of and an address table has one every few bytes.
			// Every pattern reading a separator rather than a literal prefix
			// stops at each of them, and no prefilter turns such a pattern
			// away, so this is where a scan that answered them expensively
			// would show — and the line above, which is what the other cases
			// are built from, cannot show it.
			name:  "a record dense in separators",
			src:   "fe80::1%en0 00:1b:44:11:3a:b7 2026-08-17T00:00:00Z 12:34:56.789 10.0.0.1:8443 ",
			spans: 0,
		},
	}
}

func BenchmarkMasker_Mask(b *testing.B) {
	benchmarkMask(b, New(WithPatterns(AllBuiltinPatterns()...)), maskerMaskBenchmarks())
}

// BenchmarkBuiltins times every built-in scan on its own, under the name the
// pattern reports: go test -bench Builtins/jwt runs one of them.
//
// It reads builtinPatterns, which is what holds a pattern to being timed at
// all. A benchmark written as a function a pattern could be left unwritten for
// a pattern and nothing would say so, since go test runs no benchmark and go
// vet sees a table named by the registry as used either way.
func BenchmarkBuiltins(b *testing.B) {
	for _, p := range builtinPatterns {
		b.Run(p.name, func(b *testing.B) {
			benchmarkFind(b, p.pattern().Find, p.benchmarks())
		})
	}
}

// BenchmarkWriter times a Writer over the cases BenchmarkMasker_Mask drives,
// written a line at a time into a writer that keeps none of it.
//
// A line and not a case: what a Writer costs over a case depends on where the
// line ends, since text ending in nothing any prefix opens with is released as
// it is written and text ending in a piece of one is held back. Both are what a
// caller sees, and the line break is what makes the first of them the case
// being timed here rather than an accident of what the case happens to close
// on.
//
// The Writer is made once and written to for every iteration, which is how a
// caller behind a log has one. What that leaves out is the cost of making one,
// which a caller pays once a stream and nothing here would say anything useful
// about.
func BenchmarkWriter(b *testing.B) {
	m := New(WithPatterns(AllBuiltinPatterns()...))
	for _, bm := range maskerMaskBenchmarks() {
		b.Run(bm.name, func(b *testing.B) {
			benchmarkWrite(b, m, bm)
		})
	}
}

// benchmarkWrite times a Writer over m on one case, holding the case to the
// redactions it says it holds first, as the bodies below do.
func benchmarkWrite(b *testing.B, m *Masker, bm benchmarkCase) {
	found := m.locate(bm.src, 0).found
	if got := len(found); got != bm.spans {
		b.Fatalf("the line holds %d value(s) in %d bytes, the case says %d", got, len(bm.src), bm.spans)
	}

	line := []byte(bm.src + "\n")
	w := NewWriter(io.Discard, m)
	defer func() {
		if err := w.Close(); err != nil {
			b.Fatalf("Close() = %v", err)
		}
	}()

	b.SetBytes(int64(len(line)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := w.Write(line); err != nil {
			b.Fatalf("Write() = %v", err)
		}
	}
}

// mustRegexpBenchmarks are what BenchmarkMustRegexp times: an expression over
// a line holding no match, one holding a match, and one whose matches stand
// against each other, which is where locating the ones that begin inside
// another costs anything at all.
func mustRegexpBenchmarks() []struct {
	name  string
	expr  string
	src   string
	spans int
} {
	line := "time=2026-08-17T00:00:00Z level=info msg=\"calling api\" "
	return []struct {
		name  string
		expr  string
		src   string
		spans int
	}{
		{name: "no match", expr: `INT-[0-9a-f]{32}`, src: line, spans: 0},
		{name: "one match", expr: `INT-[0-9a-f]{32}`, src: line + "token=INT-0123456789abcdef0123456789abcdef", spans: 1},
		{name: "a mask group", expr: `token=(?P<mask>[0-9a-f]{32})`, src: line + "token=0123456789abcdef0123456789abcdef", spans: 1},
		{name: "matches against one another", expr: `[0-9a-f]{32}`, src: line + strings.Repeat("0123456789abcdef", 16), spans: 1},
		{name: "a match reaching the end", expr: `[g-z]*x[0-9a-f]+`, src: line + "x" + strings.Repeat("0123456789abcdef", 16), spans: 1},
	}
}

// BenchmarkMustRegexp times a pattern built from an expression, which is what a
// caller pays for one of their own.
func BenchmarkMustRegexp(b *testing.B) {
	for _, bm := range mustRegexpBenchmarks() {
		b.Run(bm.name, func(b *testing.B) {
			m := New(WithPatterns(MustRegexp("p", bm.expr)))
			if got := len(m.locate(bm.src, 0).found); got != bm.spans {
				b.Fatalf("the line holds %d value(s) in %d bytes, the case says %d", got, len(bm.src), bm.spans)
			}
			b.SetBytes(int64(len(bm.src)))
			b.ReportAllocs()
			for b.Loop() {
				_ = m.Mask(bm.src)
			}
		})
	}
}

func Test_mustRegexpBenchmarks(t *testing.T) {
	// What holds the cases above honest, for the reason
	// Test_maskerMaskBenchmarks gives of the ones beside them.
	for _, bm := range mustRegexpBenchmarks() {
		t.Run(bm.name, func(t *testing.T) {
			m := New(WithPatterns(MustRegexp("p", bm.expr)))
			if got := len(m.locate(bm.src, 0).found); got != bm.spans {
				t.Errorf("the line holds %d value(s) in %d bytes, the case says %d", got, len(bm.src), bm.spans)
			}
		})
	}
}

func Test_maskerMaskBenchmarks(t *testing.T) {
	// What holds the cases above honest, for the reason
	// Test_builtins_benchmarkCasesHoldTheirValues gives of the per-pattern
	// ones: a case named "many values" whose text stopped holding one would
	// time a Masker redacting nothing and report that as a speedup.
	m := New(WithPatterns(AllBuiltinPatterns()...))
	for _, c := range maskerMaskBenchmarks() {
		t.Run(c.name, func(t *testing.T) {
			found := m.locate(c.src, 0).found
			if got := len(found); got != c.spans {
				t.Errorf("Mask redacted %d value(s) in %d bytes, the case says %d", got, len(c.src), c.spans)
			}
		})
	}
}

// benchmarkCase is one input a benchmark is timed on, together with how many
// spans it must yield there: what Find locates, or what Mask redacts once the
// overlaps between patterns have been merged.
//
// The count is what keeps the name of a case honest. A case called "many
// values" whose text stopped holding one — a count the vendor changed, a
// character class narrowed — measures a scan finding nothing and reports that
// as a speedup, which is the one failure a benchmark cannot report by itself.
// The bodies below check it before they start timing, and a test checks it
// again under a plain go test, where the cases of a benchmark nobody has run
// are reached at all: Test_maskerMaskBenchmarks for the table above,
// Test_builtins_benchmarkCasesHoldTheirValues for the per-pattern ones.
type benchmarkCase struct {
	name  string
	src   string
	spans int
}

// benchmarkFind times find over each case, holding each to the values it says
// it holds first.
//
// The scan is timed on its own rather than through a Masker driving it, because
// what a change to a scan is compared against is the scan: sorting the spans,
// merging what overlaps and building the output are the same work whichever
// pattern reported them, and BenchmarkMasker_Mask above measures that.
func benchmarkFind(b *testing.B, find func(string) ([]Span, int), cases []benchmarkCase) {
	for _, bm := range cases {
		b.Run(bm.name, func(b *testing.B) { timeFind(b, find, bm) })
	}
}

// timeFind is benchmarkFind over one case, without the name: a caller timing
// one case two ways has named it already, and naming it again leaves the arms
// under a name written twice.
func timeFind(b *testing.B, find func(string) ([]Span, int), bm benchmarkCase) {
	spans, _ := find(bm.src)
	if got := len(spans); got != bm.spans {
		b.Fatalf("Find located %d value(s) in %d bytes, the case says %d", got, len(bm.src), bm.spans)
	}
	b.SetBytes(int64(len(bm.src)))
	b.ReportAllocs()
	for b.Loop() {
		_, _ = find(bm.src)
	}
}

// benchmarkMask times m over each case, holding each to the redactions it says
// it holds first. What is counted is what Mask writes over, which is what
// locate leaves once the overlaps are merged, rather than what the patterns
// between them located.
func benchmarkMask(b *testing.B, m *Masker, cases []benchmarkCase) {
	for _, bm := range cases {
		b.Run(bm.name, func(b *testing.B) { timeMask(b, m, bm) })
	}
}

// timeLocate times m settling one case as a stream asks it to, holding the case
// to the redactions it says it holds first. It is what the prefilter is weighed
// on rather than timeMask, for the reason gramsWorthIt (mask.go) gives.
func timeLocate(b *testing.B, m *Masker, bm benchmarkCase) {
	found := m.locate(bm.src, 0).found
	if got := len(found); got != bm.spans {
		b.Fatalf("locate reported %d value(s) in %d bytes, the case says %d", got, len(bm.src), bm.spans)
	}
	b.SetBytes(int64(len(bm.src)))
	b.ReportAllocs()
	for b.Loop() {
		_ = m.locate(bm.src, 0)
	}
}

// timeMask is benchmarkMask over one case, without the name, for the reason
// timeFind gives.
func timeMask(b *testing.B, m *Masker, bm benchmarkCase) {
	found := m.locate(bm.src, 0).found
	if got := len(found); got != bm.spans {
		b.Fatalf("Mask redacted %d value(s) in %d bytes, the case says %d", got, len(bm.src), bm.spans)
	}
	b.SetBytes(int64(len(bm.src)))
	b.ReportAllocs()
	for b.Loop() {
		_ = m.Mask(bm.src)
	}
}

// What the prefilter is worth, measured with both arrangements of locate in one
// binary rather than by comparing two runs of it.
//
// A Masker holding none of the openings of its patterns hands every pattern the
// whole of the text, and each of them walks it looking for one byte of what its
// candidates open with; one holding them walks the text once itself and hands
// it to almost none of them. The benchmarks below alternate the two at every
// -count, so that the machine, the code layout and the inputs are the same for
// both and the ratio is the whole of what is read off them.

// maskerPrefiltered returns a Masker scanning with the patterns of m and
// redacting with its redactor, reading the openings of those patterns or
// holding them back whatever their number.
//
// It copies m rather than building a Masker of its own, so that a field added
// to a Masker later comes along and the two arrangements go on differing in the
// prefilter alone. Whatever their number, because gramsWorthIt is the number
// under measurement here: New settles it for a caller, and a benchmark asking
// what it should be settles nothing by asking New.
func maskerPrefiltered(m *Masker, on bool) *Masker {
	c := *m
	c.tails, c.opens, c.settlingWorthIt = nil, nil, false
	if on {
		c.filterOn(m.patterns)
		// On for both sides of the walk, which is not what New would settle
		// for every Masker here: the arms are what a filter costs and saves,
		// and gramsWorthIt is read off them, so a Masker New would build none
		// for is exactly the one that has to be timed with one.
		c.settlingWorthIt = true
	}
	return &c
}

// BenchmarkPrefilter_Mask times the cases BenchmarkMasker_Mask drives with the
// openings of the patterns read and with them held back.
func BenchmarkPrefilter_Mask(b *testing.B) {
	m := New(WithPatterns(AllBuiltinPatterns()...))
	for _, bm := range maskerMaskBenchmarks() {
		b.Run(bm.name, func(b *testing.B) {
			for _, arm := range prefilterArms(m) {
				b.Run(arm.name, func(b *testing.B) { timeMask(b, arm.masker, bm) })
			}
		})
	}
}

// BenchmarkPrefilter_Writer times the same cases through a Writer, a line at a
// time, with the openings read and with them held back.
func BenchmarkPrefilter_Writer(b *testing.B) {
	m := New(WithPatterns(AllBuiltinPatterns()...))
	for _, bm := range maskerMaskBenchmarks() {
		b.Run(bm.name, func(b *testing.B) {
			for _, arm := range prefilterArms(m) {
				b.Run(arm.name, func(b *testing.B) { benchmarkWrite(b, arm.masker, bm) })
			}
		})
	}
}

// BenchmarkPrefilter_Patterns times a Masker of each size over a line holding
// no value, with the literals read and with them held back. It is what
// gramsWorthIt (mask.go) is set from: the filter is one walk of the input
// whatever the Masker holds, so the size at which the arms cross is the size
// below which New must not build one.
//
// The size counted is the number of patterns the filter turns away, which is
// what New counts and what the filter is paid for by. Counting the registry
// instead would put the crossover at whatever proportion of it happens to
// declare literals, and would move under the constant every time a pattern was
// added that declares none.
//
// Both sides of the walk are timed, settling and masking, because gramsWorthIt
// governs both and is read off whichever the filter is worth least in. Which
// one that is has to be measured rather than assumed: a pattern declaring
// literals and no tail is turned away when masking and never when settling, so
// the two sides do not turn away the same patterns and the gap between them
// moves whenever such a pattern is added. Timed on one side alone, the reason
// the constant is read off the other could not be checked at all.
func BenchmarkPrefilter_Patterns(b *testing.B) {
	// Patterns the filter turns away on both sides, so that the count means
	// the same thing in each. One with literals and no tail is turned away
	// when masking and never when settling, so under the settling arm it would
	// stand in the count without standing in anything the arm saves — and the
	// crossing read off that arm would be the crossing for however many of
	// them the registry order happened to put under n. They are what New
	// counts for masking, and BenchmarkPrefilter_Mask times them there.
	var filterable []Pattern
	for _, p := range AllBuiltinPatterns() {
		if len(filterOpens(p)) > 0 && settlingTail(p) != nil {
			filterable = append(filterable, p)
		}
	}
	// Rungs close together where the arms are expected to cross, further apart
	// above that, and the whole of filterable last. A rung is kept only while
	// it stands below that whole: one above it would slice past the end of
	// filterable, and one standing on it would time the same Masker twice
	// under two names.
	rungs := []int{1, 2, 4, 6, 7, 8, 9, 10, 12, 16, 24, 32}
	counts := make([]int, 0, len(rungs)+1)
	for _, n := range rungs {
		if n < len(filterable) {
			counts = append(counts, n)
		}
	}
	counts = append(counts, len(filterable))

	// locate is what a stream asks and Mask is what a caller asks, and they are
	// the two the constant governs. Nothing else differs between them here.
	sides := []struct {
		name string
		time func(*testing.B, *Masker, benchmarkCase)
	}{
		{"settling", timeLocate},
		{"masking", timeMask},
	}
	for _, chars := range prefilterLineLengths {
		// The length carries its unit into the name so that it cannot be read,
		// or matched by -bench, as one of the pattern counts nested under it.
		bm := benchmarkCase{name: strconv.Itoa(chars) + "B", src: prefilterText(chars)}
		b.Run(bm.name, func(b *testing.B) {
			for _, n := range counts {
				m := New(WithPatterns(filterable[:n]...))
				b.Run(strconv.Itoa(n), func(b *testing.B) {
					for _, side := range sides {
						b.Run(side.name, func(b *testing.B) {
							for _, arm := range prefilterArms(m) {
								b.Run(arm.name, func(b *testing.B) { side.time(b, arm.masker, bm) })
							}
						})
					}
				})
			}
		})
	}
}

// prefilterLineLengths are the lengths BenchmarkPrefilter_Patterns drives, in
// bytes, from a few characters to a handful of records.
//
// More than one of them because the two arrangements do not scale together: the
// filter is emptied once a call whatever the text is, where the scans it saves
// cost in proportion to the text, so the number of patterns at which it starts
// winning moves with the length. gramsWorthIt (mask.go) is what reads that
// off.
var prefilterLineLengths = []int{8, 24, 48, 87, 348, 696}

// prefilterText returns chars bytes of log holding no value, written as records
// that differ from one another.
//
// Differing because the other half of what the width of a filter buys is what
// it lets through, and that grows with how much of the alphabet of three-byte
// pieces the text spells. One record repeated spells the same few dozen pieces
// however long it is, so a filter weighed on it is weighed where letting a
// pattern through costs nothing — and a pattern let through is a scan of the
// whole text. Nothing here opens any prefix a built-in reads, which the count
// on the case holds.
func prefilterText(chars int) string {
	levels := []string{"info", "warn", "debug", "error", "trace"}
	events := []string{"calling upstream", "retrying request", "closing idle conn", "flushing buffer", "opening stream"}
	hosts := []string{"api.github.com", "gitlab.example.net", "registry.npmjs.org", "storage.googleapis.com"}
	paths := []string{"user", "repos/list", "v2/tokens", "healthz", "objects/batch"}

	var b strings.Builder
	for i := 0; b.Len() < chars; i++ {
		fmt.Fprintf(&b, "time=2026-%02d-%02dT%02d:%02d:%02dZ level=%s msg=%q url=https://%s/%s took=%dms\n",
			1+i%12, 1+i%28, i%24, (i*7)%60, (i*13)%60,
			levels[i%len(levels)], events[i%len(events)], hosts[i%len(hosts)], paths[i%len(paths)], 3+i*11%900)
	}
	return b.String()[:chars]
}

// prefilterArms are the two arrangements of m the benchmarks above alternate,
// named for what separates them rather than for which came first, so that a
// filter changed again leaves the names meaning what they say.
func prefilterArms(m *Masker) []struct {
	name   string
	masker *Masker
} {
	return []struct {
		name   string
		masker *Masker
	}{
		{"unfiltered", maskerPrefiltered(m, false)},
		{"filtered", maskerPrefiltered(m, true)},
	}
}

// Test_maskerPrefiltered holds the two arrangements to masking the same text
// the same way and settling it at the same offset, so that what the benchmarks
// compare is one computation done two ways rather than two computations.
func Test_maskerPrefiltered(t *testing.T) {
	m := New(WithPatterns(AllBuiltinPatterns()...))
	filtered, unfiltered := maskerPrefiltered(m, true), maskerPrefiltered(m, false)

	var srcs []string
	for _, b := range builtinPatterns {
		srcs = append(srcs, append(builtinInputs(b.samples), b.anchors...)...)
	}
	for _, c := range maskerMaskBenchmarks() {
		srcs = append(srcs, c.src)
	}

	for _, src := range srcs {
		for cut := range len(src) + 1 {
			src := src[:cut]
			if got, want := filtered.locate(src, 0).retain, unfiltered.locate(src, 0).retain; got != want {
				t.Errorf("locate(%q) settled %d, where the same patterns unfiltered settle %d", src, got, want)
			}
			if got, want := filtered.Mask(src), unfiltered.Mask(src); got != want {
				t.Errorf("Mask(%q) = %q, where the same patterns unfiltered give %q", src, got, want)
			}
		}
	}
}
