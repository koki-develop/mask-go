# mask-go

A Go library that redacts credentials (API keys, access tokens) from text.
Public surface: `Masker` (`mask.go`), `Pattern` (`pattern.go`), `Redactor`
(`redactor.go`), `Option` (`option.go`), built-in patterns (`builtin.go`).

## Commands

Tools are pinned in `mise.toml`. `mise run bootstrap` installs the git hooks.

- `go test ./...` — tests. Also `go test -race ./...` and
  `go test -fuzz FuzzJWT_matchesReference` (targets: `FuzzMasker_locate`,
  `FuzzMasker_Mask`, `FuzzJWT_matchesReference`,
  `FuzzGitHubToken_matchesReference`).
- `go test -bench . -benchmem` — benchmarks.
- `golangci-lint run` — lint (no config file; defaults).
- `modernize -fix ./...` — apply modern Go idioms.
- `betterleaks git` — secret scan.

## Tests

- Table-driven, one `name` per case, and each case writes out its own data
  literally rather than sharing fixtures or computing it.
- Adding a built-in pattern means two declarations: the pattern in `builtins`
  (`builtin.go`), which is what `DefaultPatterns` reports, and an entry in
  `builtinPatterns` (`builtins_test.go`), which is what holds it to the
  properties every built-in shares — its name and the convention `Pattern.Name`
  asks for, one value per accessor, usable spans, no false positive on prose,
  agreement with its reference, exhaustive and idempotent masking, concurrent
  use, and a linear-time scan. The two are held to naming the same patterns in
  the same order, so neither can be forgotten, and an entry is held to being
  whole: a field left out leaves most of the properties with nothing to hold
  rather than failing, so `Test_builtins_entriesAreFilledIn` reports the
  omission itself and runs first for that reason.
- The `samples` a `builtinPatterns` entry carries are the one place fixtures are
  shared. They say only "this is one of these", which is all the properties
  need; what exactly is located, and what is left alone, stays written out case
  by case in `builtin_test.go`. Inputs crafted against what one scan remembers
  stay with that scan too, as `Test_JWT_scanIsLinear` does.
- Both built-in scanners are checked against a reference in `fuzz_test.go`:
  `referenceJWTFind`, a plain implementation of the same rules, and
  `referenceGitHubToken`, the regular expression the GitHub token scan reads by
  hand. Change scanner and reference together, and keep the corpus in
  `testdata/fuzz/`. The targets share their body through
  `fuzzAgainstReference` but keep a name apiece, because the corpus is keyed on
  the name of the target.
- Behaviour that differs under the race detector is branched on `raceEnabled`
  (`race_test.go` / `norace_test.go`), not skipped.

## Style

- Doc comments on every exported identifier. Comments explain *why* — the
  scanner rationale in `builtin.go` is load-bearing, so update it rather than
  dropping it.
- `Pattern` and `Redactor` implementations must be safe for concurrent use.
- `Masker.locate` and both built-in scanners are deliberately linear-time and
  allocation-conscious; the cursors they keep over a run of base64url
  characters are what rule out quadratic inputs. Compare benchmarks before and
  after touching them.
- Published library: any change to an exported name, signature or behaviour is
  breaking. Keep `README.md` in sync with the exported API.
