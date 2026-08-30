# conformance

The end-to-end statement of what this library does: a corpus of cases under
`testdata`, and one harness holding every case to every property masking must
have. It drives the public API only — the package imports `mask` as a caller
does — so nothing here may reach an unexported name.

Every file here is a `_test.go` file. Adding one that is not would publish
`github.com/koki-develop/mask-go/conformance` as part of the module.

## A case

```
case: a personal access token in an environment assignment
in:   GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz
out:  GITHUB_TOKEN=«github-token»
```

- `case` and `in` are written by hand. **`out` is generated: never write or edit
  it by hand.** Run `go test ./conformance -update`, which rewrites every `out`,
  lays the fields out to one column and checks the corpus in the same run. The
  diff it leaves is what a reviewer reads, so review it yourself before
  committing.
- `out` is what `Mask` returns with every redacted value written as
  `«pattern-name»`, always literally — including where nothing is redacted and
  the line repeats `in`. No keyword stands in for the output.
- `patterns` and `spans` are directives: between cases they apply to every case
  below, inside a case to that case alone. **A blank line ends a case**, which
  is what tells the two apart.
- `patterns` names an entry of `patternSets` (`patterns_test.go`). A case that
  names none is masked with **what the last `patterns` directive above it
  named** — `default` only where no directive stands above it, which is why a
  case appended to the bottom of a file is masked with that file's set and not
  with the built-ins. Every set must be named by some case.
- `spans: reported` marks a case whose patterns report spans of their own rather
  than finding them in the text. It holds back the properties that follow a
  value around — longer text, repetition, what a second pass may redact — which
  such a pattern cannot have. Use it for those cases only.
- `in` may not hold `«` or `»`. Escapes are `\n`, `\r`, `\t`, `\\` and `\xNN`; a
  field is read with the space around it trimmed, so whitespace at either end
  has to be escaped.
- Credentials are built from the ordered run `0123456789abcdef`, in the case
  the kind of credential is written in: `0123456789ABCDEF` where its alphabet
  is uppercase, as an AWS access key ID's is. The betterleaks allowlist covers
  `conformance/testdata/*.txt` on that condition alone, so a value written any
  other way fails the secret scan. Where the credential's own alphabet cannot
  carry the run — an age secret key is written in Bech32, which holds neither
  `1` nor `B` — the value is built from the run with the characters that
  alphabet leaves out taken away, and the file writes out which run that left.

## What a comment may say

The comments between cases are the one thing here that is neither generated nor
checked. An `out` that drifts from the library fails on the next run; a comment
that overstates drifts in silence, and reads as a guarantee for as long as
nobody measures it. Two rules keep one honest:

- **A comment states what the cases under it show, and stops there.** Where a
  rule narrows a problem rather than ending it, say what is left over **and
  write a case for it** — the case is what holds the sentence to the scan the
  next time the scan changes.
- **Count before writing `every`, `only`, `the one`, `no input at all`**, or
  write the sentence without them. A claim about the corpus is as easy to get
  wrong as a claim about the library, and it is the file's own cases that
  contradict it. Where a count is worth keeping, have a test do the counting and
  point the sentence at it: `TestCorpus_attributionIsExercised` counts the
  inputs on which two built-in patterns report one span, which is what the
  comment at the top of `overlap_and_attribution.txt` rests on and what no `out`
  line could report. An `out` line names the pattern the redaction went to, so it
  pins which of the two won — but not that a second one reached the span at all,
  and once the losing one stops locating that value the line reads exactly as it
  did with nothing left reaching the rule.

A case name carries the same weight as a comment and drifts the same way. Name a
case for the rule the scan reads, not for a property of the input that happens
to move with it: no `out` can contradict a name.

## Where a case goes

One file a built-in pattern, holding what that pattern locates and leaves alone
on its own, named `builtin_<name>.txt` where `<name>` is what the pattern reports
with the hyphens written as underscores: `aws-access-key-id` is
`builtin_aws_access_key_id.txt`. The corpus is loaded by a glob, so a file named
any other way is read and its cases run — nothing about the suite would fail.
`TestCorpus_everyBuiltinHasAFileOfItsOwn` is what asks for it by name. Then:

- `builtins_together.txt` — all of them at once, and the values two of them read
  differently.
- `custom_patterns.txt` — `MustRegexp`, `NewPattern`, and no pattern at all.
- `overlap_and_attribution.txt` — how overlapping values merge and which pattern
  the result is attributed to.
- `unusable_spans.txt` — the spans `Find` is documented to ignore.
- `text_shapes.txt` — log lines, JSON, command lines, and the credentials this
  library does not redact.
- `degenerate.txt` — empty text, control bytes, text that is not valid UTF-8.

## The harness

- A property belongs in `conformance_test.go`, written once, where every case is
  then held to it. Never write one per case.
- `properties_test.go` drives text derived from the corpus: every prefix and
  suffix, a byte pushed into every interesting position, cases run together and
  repeated. Nothing there compares against a second implementation —
  `checkMasking` marks redactions with a separator the text does not hold and
  puts the values back, which must give the input again. Use it for anything
  generated, where no expectation can be written down.
- `stream_test.go` drives the corpus through `NewWriter` and `NewReader`, cut at
  every offset and a byte at a time, and holds what comes out to what `Mask`
  returns for the case uncut. `Mask` is what the corpus states and what the
  properties beside it hold to everything masking must be, so holding a stream
  to `Mask` holds it to almost all of that at once.
- What is left over is `WithMaxRetained`. Giving up is the one output a stream
  writes that `Mask` does not, so it is what a stream property has to state on
  its own, and the second half of `stream_test.go` states it, driving the corpus
  at limits short enough to reach. `TestProperties_everyCutUnderALimit` counts
  the cases that parted from `Mask`: a limit none of them reached would leave
  every one of those properties driving nothing, and only the count would say
  so.
- Adding a built-in pattern means adding cases here:
  `TestCorpus_coversEveryBuiltinPattern` asks for at least three cases locating
  it, and three where it locates nothing **masked with a set holding that
  pattern alone** — a clean case masked with `default` counts for nothing, since
  every pattern added to that set would inherit it. The set holding it alone
  needs no writing: it is derived from `AllBuiltinPatterns` in `patterns_test.go`
  and named as the pattern names itself, as `builtinSets`
  (`properties_test.go`) already was.
- A case name that claims something about the whole registry is counted rather
  than trusted: `TestCorpus_everyKindCaseHoldsEveryBuiltin` holds the case named
  "every kind of credential this library knows" to naming every built-in, since
  a pattern left out of it leaves the line masked exactly as it was and no `out`
  can report the omission.
- Masking is not held to being idempotent here, because `Mask` is not, and the
  root package says so on `Mask` itself: a redaction does not read as the value
  it replaced, so it can open a prefix that value closed — an AWS access key ID
  written against a Slack prefix is redacted first and takes a Slack token with
  it second — and `Fixed("")` splices the text either side of a value into text
  that was never written. What is held here instead is where a second pass may
  redact. `checkSecondPass` (`properties_test.go`) asks that every value the
  second pass locates overlap a redaction of the first or stand against one; a
  value out of reach of all of them stands in text nothing had changed around,
  so the first pass read over it and declined to locate it, which is the scan
  defect the property is for. A value the first pass located only part of is
  not held there and cannot be — the rest of one begins where the redaction of
  its front ended, which is where a value a redaction opened begins as well —
  and is held instead by each case stating the spans it expects. The root
  package keeps a `checkSecondPass` of its own (`mask_test.go`) reading spans
  from `locate` rather than marking them. Adding an assertion that masking
  twice gives what masking once gave puts a promise back that the library does
  not make.
- The fuzz corpus under `testdata/fuzz` is keyed on the name of its target, so
  never rename one without moving the directory beside it.
