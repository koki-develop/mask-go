package mask

import (
	"io"
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
		})
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
		b.Run(bm.name, func(b *testing.B) {
			spans, _ := find(bm.src)
			if got := len(spans); got != bm.spans {
				b.Fatalf("Find located %d value(s) in %d bytes, the case says %d", got, len(bm.src), bm.spans)
			}
			b.SetBytes(int64(len(bm.src)))
			b.ReportAllocs()
			for b.Loop() {
				_, _ = find(bm.src)
			}
		})
	}
}

// benchmarkMask times m over each case, holding each to the redactions it says
// it holds first. What is counted is what Mask writes over, which is what
// locate leaves once the overlaps are merged, rather than what the patterns
// between them located.
func benchmarkMask(b *testing.B, m *Masker, cases []benchmarkCase) {
	for _, bm := range cases {
		b.Run(bm.name, func(b *testing.B) {
			found := m.locate(bm.src, 0).found
			if got := len(found); got != bm.spans {
				b.Fatalf("Mask redacted %d value(s) in %d bytes, the case says %d", got, len(bm.src), bm.spans)
			}
			b.SetBytes(int64(len(bm.src)))
			b.ReportAllocs()
			for b.Loop() {
				_ = m.Mask(bm.src)
			}
		})
	}
}
