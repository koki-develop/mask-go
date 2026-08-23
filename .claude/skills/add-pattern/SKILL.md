---
name: add-pattern
description: Workflow for adding a new built-in credential pattern to mask-go. Use when asked to add, implement, or register a built-in pattern for a new kind of token or credential.
---

The decision to add the pattern has already been made before this skill is
invoked. What to touch and how it must behave is stated in
`.claude/rules/builtin-patterns.md` — **read that first**, since it loads on
opening a `builtin_*.go` and this skill starts before there is one — together
with the root `CLAUDE.md` and `conformance/CLAUDE.md`. This skill only fixes the
order of work and the steps easiest to lose.

## 1. Pin down the grammar

Verify the token's exact format against current official sources: prefix,
alphabet, length, checksum, and every variant sharing the prefix. Do not work
from memory — formats change, and the scanner rationale comment in
`builtin_<name>.go` is written from what this step establishes.

## 2. Implement, with the pattern's own tests

The declarations to touch are named in the rules file. Points that don't follow
from the file layout alone:

- The exhaustive edge cases — what is located, what is left alone — belong in
  the behaviour tables of `builtin_<name>_test.go`, not in conformance. Writing
  the tables before the scan is fine; they are the spec.
- The reference (`reference<Name>Find`) is written with the scan, never after
  it.
- The fuzz target is `Fuzz<Name>_matchesReference`, one call to
  `fuzzAgainstReference`. No corpus directory to create — `testdata/fuzz/` is
  where fuzzing's own findings get checked in.
- Whatever is unusual about this pattern — why the reference went the way it
  did, how far the scan advances at a candidate, what rules out a quadratic
  input — is written in these two files and nowhere else. Do not add it to a
  list in `CLAUDE.md`; there is deliberately no such list to add to.

## 3. Conformance last

`out` lines are generated from the implementation, so this step cannot come
earlier. Read `conformance/CLAUDE.md` before writing cases. It asks for a
`builtin_<name>.txt` with at least three cases locating the value and three
clean ones under the pattern's own set — plus `builtins_together.txt` cases if
the value interacts with another pattern, and the entry in the case named "every
kind of credential this library knows", which a test holds to naming every
built-in. The solo `patternSets` entry is derived and needs no writing. Then
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
