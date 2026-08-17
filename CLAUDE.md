# mask-go

A Go library that redacts credentials (API keys, access tokens) from text.
Public surface: `Masker` (`mask.go`), `Pattern` (`pattern.go`), `Redactor`
(`redactor.go`), `Option` (`option.go`), built-in patterns (`builtin.go`).

## Commands

Tools are pinned in `mise.toml`. `mise run bootstrap` installs the git hooks.

- `go test ./...` — tests. Also `go test -race ./...` and
  `go test -fuzz FuzzJWT_matchesReference` (targets: `FuzzMasker_locate`,
  `FuzzMasker_Mask`, `FuzzJWT_matchesReference`).
- `go test -bench . -benchmem` — benchmarks.
- `golangci-lint run` — lint (no config file; defaults).
- `modernize -fix ./...` — apply modern Go idioms.
- `betterleaks git` — secret scan.

## Tests

- Table-driven, one `name` per case, and each case writes out its own data
  literally rather than sharing fixtures or computing it.
- The JWT scanner is checked against `referenceJWTFind` in `fuzz_test.go`, a
  plain implementation of the same rules. Change both together, and keep the
  corpus in `testdata/fuzz/`.
- Behaviour that differs under the race detector is branched on `raceEnabled`
  (`race_test.go` / `norace_test.go`), not skipped.

## Style

- Doc comments on every exported identifier. Comments explain *why* — the
  regex and scanner rationale in `builtin.go` is load-bearing, so update it
  rather than dropping it.
- `Pattern` and `Redactor` implementations must be safe for concurrent use.
- `Masker.locate` and the JWT scanner are deliberately linear-time and
  allocation-conscious. Compare benchmarks before and after touching them.
- Published library: any change to an exported name, signature or behaviour is
  breaking. Keep `README.md` in sync with the exported API.
