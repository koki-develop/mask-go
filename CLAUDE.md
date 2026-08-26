# mask-go

A Go library that redacts credentials (API keys, access tokens) from text.
Public surface: `Masker` (`mask.go`), `Pattern` (`pattern.go`), `Redactor`
(`redactor.go`), `Option` (`option.go`), `Reader` and `Writer` (`stream.go`),
built-in patterns (`builtins.go` and the `builtin_*.go` beside it) and the
vendor accessors (`vendors.go`).

What every built-in pattern is held to is in `.claude/rules/builtin-patterns.md`.
It loads on opening any of the files it governs — the `builtin_*.go`, the tables
and rules that reach across them, and `conformance/` — which its own `paths:`
lists. Read it before adding or changing a pattern, and put what you learn about
one pattern in that pattern's files rather than back into this one.

## Layout

One built-in pattern to a file: `builtin_<name>.go` with a
`builtin_<name>_test.go` beside it, holding the pattern, its scan, the helpers
only that scan reads, its behaviour tables, its reference, its fuzz target and
the cases it is benchmarked on. `builtins.go` is the registry alone,
`builtin_scan.go` holds what more than one scan reads (`segments`,
`isBase64URLByte`, `base64URLRunEnd`, `isBase62Byte`, `base62RunEnd`,
`prefixTail`), `builtins_test.go` holds what every built-in is held to,
`fuzz_test.go` holds the `Masker` targets and the body the per-pattern targets
share, `benchmark_test.go` holds every benchmark there is, and
`source_test.go` holds the rules about how this package is written rather than
about what it computes, read out of the syntax tree. `stream.go` and
`stream_test.go` are the masking of text arriving a piece at a time, which is a
`Reader` and a `Writer` over a `Masker` and belongs to none of the patterns.
Adding a pattern should touch the registry, the vendor accessor, the property
table, two new files and the conformance corpus — nothing else. Keep it that way
rather than letting a shared `builtin.go` grow back.

`vendors.go` is the vendor accessors alone, one `<Vendor>Patterns` apiece, with
`vendors_test.go` holding them and the registry to naming the same patterns.
Which pattern belongs to which accessor, and where the boundary between two
patterns of one vendor falls, is in `.claude/rules/builtin-patterns.md`.

One pattern may read another's declarations rather than spelling the borrowed
rule again and coming to disagree about it. Two things make a borrowing right:
the credentials nest, so one scan needs the other's anchor; or the two patterns
are halves of one vendor's format, which neither of them can change alone. Such
a borrowing belongs where it is defined, not in `builtin_scan.go`, and the file
doing the borrowing says so.

`conformance/` states the library end to end: a corpus of cases and one harness
holding each of them to every property masking must have, through the public API
alone. It has a `CLAUDE.md` of its own — read that before touching anything
there.

The built-ins are not in an `internal` package and should not be moved into one:
they need `Pattern`, `Span` and `NewPattern`, which the root package holds, so
an `internal` package importing them would close a cycle. Breaking it means
either aliasing `Span` to an internal type, which strips its documentation from
pkg.go.dev, or converting spans on every `Find`, which allocates.

## Commands

Tools are pinned in `mise.toml`. `mise bootstrap` installs the git hooks.

- `go test ./...` — tests. Run it without `-race` as well as with: the tests
  holding `Mask` to allocating nothing stand down under the race detector, so
  the two runs do not cover the same thing, and CI does both.
- `go test ./conformance -update` — regenerate the conformance corpus and check
  it in the same run (`conformance/CLAUDE.md`).
- `go test -fuzz FuzzJWT_matchesReference .` — fuzzing. The root package has
  `FuzzMasker_locate`, `FuzzMasker_Mask`, `FuzzBuiltins_retain`,
  `FuzzPatterns_lookBehind`, `FuzzWriter_matchesMask` and one target a built-in,
  named `Fuzz<Pattern>_matchesReference`; `conformance` has `FuzzMask`,
  `FuzzMask_customPatterns`, `FuzzStream` and `FuzzText`.
  `go test -list 'Fuzz.*' ./...` reports them all. CI gives each of them 30
  seconds.
- `go test -bench . -benchmem` — benchmarks. `BenchmarkMasker_Mask` drives every
  pattern at once through the public API, which is what a caller pays, and
  `BenchmarkWriter` drives the same cases a line at a time through a `Writer`;
  `BenchmarkBuiltins` drives each scan alone under the name its pattern reports,
  and that is what a change to a scan is compared against, since a regression in
  one is divided in the first by however many patterns the registry holds.
  `go test -bench Builtins/jwt -benchmem .` runs one of them.
- `golangci-lint run` — lint (no config file; defaults).
- `go fix ./...` — apply modern Go idioms. Go 1.26's `go fix` is the
  analyzer-driven fixer that supersedes the standalone `modernize`, so it
  ships with the pinned toolchain rather than needing a pin of its own.
  `go fix -diff ./...` reports without applying and exits non-zero when there
  is anything to apply, and that is what the pre-commit hook runs: a rewrite
  into `strings.Builder` or `slices.Contains` inside a scan is a change to a
  hot path, so it wants benchmarks either side of it rather than to be applied
  and staged behind your back.
- `betterleaks git` — secret scan.

## Tests

- Table-driven, one `name` per case, and each case writes out its own data
  literally rather than sharing fixtures or computing it.
- Behaviour that differs under the race detector is branched on `raceEnabled`
  (`race_test.go` / `norace_test.go`), not skipped.
- Count before writing "every", "only", "the one" or "all of them", in a
  comment or in a test name, and where the count is worth keeping have a test
  do the counting rather than the prose. A claim about the set is as easy to
  get wrong as a claim about the code, it is not what any assertion here
  reports, and it goes stale the next time the set grows —
  `TestMasker_Mask_withoutMatchDoesNotAllocate` reads its input out of
  `builtinPatterns` for that reason, and `TestCorpus_everyKindCaseHoldsEveryBuiltin`
  counts what a corpus case name claims.
- `LookBehind` — how far in front of a value a `Pattern` may read — is held by
  `Test_patterns_readNoFurtherBackThanLookBehind` and `FuzzPatterns_lookBehind`,
  over the built-ins and over what `MustRegexp` builds. A `Find` whose answer at
  one place depends on the whole of the text in front of it breaks it silently:
  the values move under the window as the window moves. Such a `Find` must
  settle nothing, which is what keeps a window from ever opening on it, and
  `Test_MustRegexp_settlesNothingWithoutABoundOrALiteral` holds the two
  together.
- What a scan settles — the second result of `Pattern.Find` — is held by
  `Test_builtins_retainSettles` and `FuzzBuiltins_retain`, and end to end by the
  cut properties in `conformance`. Those hold a scan to settling no more than it
  may; `Test_builtins_settleWhatIsNoValue` and
  `Test_builtins_holdNoFurtherBackThanTheCutCandidate` hold it to settling as
  much as it must. A scan pinned by text that will never become a value holds a
  stream open until the limit, and what a stream holds at the limit is redacted
  — so settling too little turns a log into asterisks. What a scan may hold on
  to is the candidate the end of the input cut short, and `builtin_scan.go`
  argues why it gives up on such a candidate rather than reading what is written
  of it. The two tests divide that between them: the first follows every prefix
  with prose, so its inputs end inside no candidate, and the second ends the
  input inside one.
- Adding a built-in pattern is `.claude/rules/builtin-patterns.md` and
  `conformance/CLAUDE.md`.

## Style

- Doc comments on every exported identifier. Comments explain *why* — the
  scanner rationale in each `builtin_<name>.go` is load-bearing, so update it
  rather than dropping it.
- A rule belongs where it is stated once; which declarations happen to fall on
  which side of it belongs beside those declarations. Do not keep a list of
  instances anywhere central, and above all do not number one: it has to be
  corrected by every declaration added, it conflicts between any two changes
  that add one, and it is read nowhere near what it describes, so it drifts
  without failing anything.
- The comment above a function of this package opens with the name of that
  function, and `Test_docComments_nameWhatTheyDocument` (`source_test.go`)
  holds it there. Of this package alone: the check reads the directory it
  stands in, so `conformance` is not held to it, where the one comment that
  would fail — the one on `decodeText` — opens on what the notation is and
  names itself in the paragraph that follows.

  staticcheck states the same rule and reaches only exported declarations
  outside `_test.go`, which leaves out every fuzz target, every reference and
  every helper the tests are built from — where the names are longest and a
  rename is most likely to leave a comment behind, and where being sent to
  rename the function to match the comment instead parts a target from the
  corpus in `testdata/fuzz` keyed on its name. The comment above a built-in's
  pattern variable is the rationale for the scan under it and opens on that
  rather than on the variable, which is why the rule is about functions alone.
- `Pattern` and `Redactor` implementations must be safe for concurrent use.
- Published library: any change to an exported name, signature or behaviour is
  breaking. Keep `README.md` in sync with the exported API.
