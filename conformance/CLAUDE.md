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
  value around — longer text, repetition, idempotence — which such a pattern
  cannot have. Use it for those cases only.
- `in` may not hold `«` or `»`. Escapes are `\n`, `\r`, `\t`, `\\` and `\xNN`; a
  field is read with the space around it trimmed, so whitespace at either end
  has to be escaped.
- Credentials are built from the ordered run `0123456789abcdef`. The betterleaks
  allowlist covers `conformance/testdata/*.txt` on that condition alone, so a
  value written any other way fails the secret scan.

## Where a case goes

`builtin_github_token.txt` and `builtin_jwt.txt` (one pattern each),
`builtins_together.txt` (all of them at once, and the values two of them read
differently), `custom_patterns.txt` (`MustRegexp`, `NewPattern`, and no pattern
at all), `overlap_and_attribution.txt`
(how overlapping values merge and which pattern the result is attributed to),
`unusable_spans.txt` (the spans `Find` is documented to ignore),
`text_shapes.txt` (log lines, JSON, command lines, and the credentials this
library does not redact), `degenerate.txt` (empty text, control bytes, text that
is not valid UTF-8).

## The harness

- A property belongs in `conformance_test.go`, written once, where every case is
  then held to it. Never write one per case.
- `properties_test.go` drives text derived from the corpus: every prefix and
  suffix, a byte pushed into every interesting position, cases run together and
  repeated. Nothing there compares against a second implementation —
  `checkMasking` marks redactions with a separator the text does not hold and
  puts the values back, which must give the input again. Use it for anything
  generated, where no expectation can be written down.
- Adding a built-in pattern means adding cases here:
  `TestCorpus_coversEveryBuiltinPattern` asks for at least three cases locating
  it, and three where it locates nothing **masked with a set holding that
  pattern alone** — a clean case masked with `default` counts for nothing, since
  every pattern added to that set would inherit it. So a new built-in also needs
  an entry of its own in `patternSets`, which `Test_patternSets_holdEveryBuiltinAlone`
  asks for. The property tests need no entry: `builtinSets`
  (`properties_test.go`) is derived from `DefaultPatterns`.
- Masking is held to being idempotent here, which `Mask` does not promise for
  every redactor: removing a value can splice the text either side of it into
  one that was not there, which `Fixed("")` makes easiest
  (`s3cr3t-s3cr3t-valuevalue` under a pattern for `s3cr3t-value`). No case does
  that today. One that did would be failing the harness rather than the library,
  so state that behaviour in the root package instead.
- The fuzz corpus under `testdata/fuzz` is keyed on the name of its target, so
  never rename `FuzzMask`, `FuzzMask_customPatterns` or `FuzzText` without
  moving the directory beside it.
