---
name: add-pattern
description: Workflow for adding a new built-in credential pattern to mask-go. Use when asked to add, implement, or register a built-in pattern for a new kind of token or credential.
---

The decision to add the pattern has already been made before this skill is
invoked. What to touch and how it must behave is stated in the root `CLAUDE.md`
and `conformance/CLAUDE.md` — this skill only fixes the order of work and the
steps easiest to lose.

## 1. Pin down the grammar

Verify the token's exact format against current official sources (`find-docs`,
then web search): prefix, alphabet, length, checksum, and every variant sharing
the prefix. Do not work from memory — formats change, and the scanner rationale
comment in `builtin_<name>.go` is written from what this step establishes.

## 2. Implement, with the pattern's own tests

The declarations to touch are named in the root `CLAUDE.md`. Points that don't
follow from the file layout alone:

- The exhaustive edge cases — what is located, what is left alone — belong in
  the behaviour tables of `builtin_<name>_test.go`, not in conformance. Writing
  the tables before the scan is fine; they are the spec.
- The reference (`reference<Name>Find`) is written with the scan, never after
  it.
- The fuzz target is `Fuzz<Name>_matchesReference`, one call to
  `fuzzAgainstReference`. No corpus directory to create — `testdata/fuzz/` is
  where fuzzing's own findings get checked in.

## 3. Conformance last

`out` lines are generated from the implementation, so this step cannot come
earlier. Read `conformance/CLAUDE.md` before writing cases. It asks for a solo
`patternSets` entry, a `builtin_<name>.txt`, at least three cases locating the
value and three clean ones under the solo set — plus `builtins_together.txt`
cases if the value interacts with another pattern. Then
`go test ./conformance -update` and review the diff it leaves as a reviewer
would.

## 4. Verify

- `go test ./...` and `go test -race ./...` — the two do not cover the same
  thing.
- `go test -fuzz Fuzz<Name>_matchesReference -fuzztime 30s .`
- `go test -bench . -benchmem` against `main` if `builtin_scan.go` or another
  scan's shared declarations moved.
- `golangci-lint run` and `betterleaks git`.
- The built-in table in `README.md` names the new pattern.
