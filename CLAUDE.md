# mask-go

A Go library that redacts credentials (API keys, access tokens) from text.
Public surface: `Masker` (`mask.go`), `Pattern` (`pattern.go`), `Redactor`
(`redactor.go`), `Option` (`option.go`), built-in patterns (`builtins.go` and
the `builtin_*.go` beside it).

## Layout

One built-in pattern to a file: `builtin_<name>.go` with a
`builtin_<name>_test.go` beside it, holding the pattern, its scan, the helpers
only that scan reads, its behaviour tables, its reference and its fuzz target.
`builtins.go` is the registry alone, `builtin_scan.go` holds what more than one
scan reads (`segments`, `isBase64URLByte`), `builtins_test.go` holds what every
built-in is held to, and `fuzz_test.go` holds the `Masker` targets and the body
the per-pattern targets share. Adding a pattern should touch the registry, the
property table, two new files and the conformance corpus — nothing else. Keep it
that way rather than letting a shared `builtin.go` grow back.

One pattern may read another's declarations where the credentials themselves
nest: `builtin_github_token.go` reads `opensJOSEHeaderAt`, `jwtHeaderPrefix` and
`signedSegments` from `builtin_jwt.go`, because a stateless installation token
carries a JWT and what that is stays the JWT pattern's to define. A scan
spelling the anchor again is a scan that can come to disagree about what opens a
header — drop the character behind the `ey` and a file name is drawn into a
token. Such a borrowing belongs where it is defined, not in `builtin_scan.go`,
and the file doing the borrowing says so — deleting the JWT pattern would break
the GitHub one.

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

Tools are pinned in `mise.toml`. `mise run bootstrap` installs the git hooks.

- `go test ./...` — tests. Run it without `-race` as well as with: the tests
  holding `Mask` to allocating nothing stand down under the race detector, so
  the two runs do not cover the same thing, and CI does both.
- `go test ./conformance -update` — regenerate the conformance corpus and check
  it in the same run (`conformance/CLAUDE.md`).
- `go test -fuzz FuzzJWT_matchesReference .` — fuzzing. Targets in the root
  package: `FuzzMasker_locate`, `FuzzMasker_Mask`, `FuzzJWT_matchesReference`,
  `FuzzGitHubToken_matchesReference`. In `conformance`: `FuzzMask`,
  `FuzzMask_customPatterns`, `FuzzText`. CI gives each of them 30 seconds.
- `go test -bench . -benchmem` — benchmarks.
- `golangci-lint run` — lint (no config file; defaults).
- `modernize -fix ./...` — apply modern Go idioms.
- `betterleaks git` — secret scan.

## Tests

- Table-driven, one `name` per case, and each case writes out its own data
  literally rather than sharing fixtures or computing it.
- Adding a built-in pattern means three declarations: the two below, and cases
  in the conformance corpus (`conformance/CLAUDE.md`).
- The first two are: the pattern in `builtins`
  (`builtins.go`), which is what `DefaultPatterns` reports, and an entry in
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
  by case in the pattern's own `builtin_<name>_test.go`. Inputs crafted against
  what one scan remembers stay with that scan too, as `Test_JWT_scanIsLinear`
  does.
- Both built-in scanners are checked against a reference kept beside them:
  `referenceJWTFind` (`builtin_jwt_test.go`) and `referenceGitHubTokenFind`
  (`builtin_github_token_test.go`), plain implementations of the same rules.
  The second tries `referenceGitHubToken`, the regular expression the GitHub
  token scan reads by hand, at every byte rather than handing it to
  `FindAllStringIndex`: a value either scan locates can hold the start of the
  next one, so a reference that resumed past a match would miss what the scan
  finds. Change scanner and reference together, and keep the corpus in
  `testdata/fuzz/`. The targets share their body through
  `fuzzAgainstReference` (`fuzz_test.go`) but keep a name apiece, because the
  corpus is keyed on the name of the target — so never rename a target without
  moving its corpus directory.
- Behaviour that differs under the race detector is branched on `raceEnabled`
  (`race_test.go` / `norace_test.go`), not skipped.

## Style

- Doc comments on every exported identifier. Comments explain *why* — the
  scanner rationale in each `builtin_<name>.go` is load-bearing, so update it
  rather than dropping it.
- `Pattern` and `Redactor` implementations must be safe for concurrent use.
- Both built-in scans resume one byte past the start of a candidate whether it
  became a value or not. A body and a signature are read as far as their
  alphabet runs, so either swallows the opening of a credential written
  straight after it, and consuming a match would step over that credential and
  leave it in the output whole. The cost is that a value nested in another —
  a JWT payload that is itself a header — is located too; the spans overlap and
  `Masker.locate` resolves them.
- `Masker.locate` and both built-in scanners are deliberately linear-time and
  allocation-conscious. Resuming one byte along means a run can hold a
  candidate for every character it has, and the cursors the scans keep over a
  run — of base64url characters, and of the alphabet a fine grained token body
  is written in — are what rule out quadratic inputs. Compare benchmarks before
  and after touching them.
- Published library: any change to an exported name, signature or behaviour is
  breaking. Keep `README.md` in sync with the exported API.
