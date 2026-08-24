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

The declarations to touch are named in the rules file. Decide the exported name
and the boundary before writing the scan — the rules file's "Where one pattern
ends and the next begins" is what settles whether this is one pattern or two,
and the name is held to a term the vendor itself uses for the whole of what the
pattern locates. Points that don't follow from the file layout alone:

- The vendor accessor in `vendors.go` is one of the declarations. A pattern for
  a vendor already there joins that vendor's slice; a pattern for a new vendor
  brings a `<Vendor>Patterns` of its own and an entry in `vendorAccessors`
  (`vendors_test.go`). A pattern naming a format rather than a vendor's
  credential goes in `patternsWithNoVendor` instead, which is a line a reviewer
  reads rather than an omission.

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
  input — is written in these two files and nowhere else.
- The rationale states this scan's own rule, not where the pattern sits among
  the others. A neighbouring file is the wrong thing to copy the shape of a
  sentence from here: the rules file's "Where a pattern states its own case"
  gives the question to ask of one that names another scan.

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
- `README.md` is in step with the change: its table is one row a vendor, so a
  pattern for a vendor already there may only widen that row's description,
  while a new vendor adds one. A vendor whose patterns a caller now has to
  choose between wants a sentence saying what the choice is.
