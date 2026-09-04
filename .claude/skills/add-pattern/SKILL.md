---
name: add-pattern
description: Workflow for adding a new built-in credential pattern to mask-go. Use when asked to add, implement, or register a built-in pattern for a new kind of token or credential.
---

The decision to implement the pattern has already been made before this skill
is invoked. Whether the format can be one is step 1's to settle, and one that
cannot stops there. What to touch and how it must behave is stated in
`.claude/rules/builtin-patterns.md` — **read that first**, since it loads on
opening a `builtin_*.go` and this skill starts before there is one — together
with the root `CLAUDE.md` and `conformance/CLAUDE.md`. This skill only fixes
the order of work and the steps easiest to lose.

## 1. Pin down the grammar

Verify the token's exact format against current official sources: prefix,
alphabet, length, checksum, and every variant sharing the prefix. Do not work
from memory — formats change, and the scanner rationale comment in
`builtin_<name>.go` is written from what this step establishes.

Which sources a grammar may be settled from, and what each of them is worth, is
the rules file's "What a grammar may rest on".

Then put what this step established through the rules file's "Weighing one
before adding it". The gate is asked of the grammar as established here, not of
what was assumed of it beforehand. Where it does not survive, stop and report
what was checked and what it turned out to be: nothing is written yet, which
makes this the cheapest place to stop. Three other answers end the work here
rather than starting it.

- No source of the vendor's states the prefix. Being wrong about a prefix is a
  pattern that never fires, which nothing downstream reports.
- A built-in already locates the value, which "Where one pattern ends and the
  next begins" answers with a name widened rather than with a second pattern.
- Deciding whether a value stands somewhere means reading further in front of it
  than `LookBehind` can bound.

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
  the tables before the scan is fine; they are the spec. The rules file's "What
  a pattern's tables answer" is what says which edges a table has to write out
  for itself.
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

Two counts here move with a pattern and report the number to set them to when
they fail: `TestCorpus_cleanCasesLocateNothingNewAcrossTheRegistry` and
`TestProperties_everyPairOfBuiltins`. Read what the failure lists before
changing either — this scan reaching past what its own file argues is a scan to
narrow, not a number to raise.

## 4. Verify

- `go test ./...` and `go test -race ./...` — the two do not cover the same
  thing.
- `go test -fuzz Fuzz<Name>_matchesReference -fuzztime 30s .`
- Where shared test machinery moved, every target `go test -list 'Fuzz.*' ./...`
  reports, at the same 30s. A plain `go test` runs a target over its checked-in
  corpus alone, so a property stated too broadly passes here and fails on
  generated input in CI.
- `go test -bench . -benchmem` against `main` if `builtin_scan.go` or another
  scan's shared declarations moved.
- `golangci-lint run` and `betterleaks git`.
- `README.md` is in step with the change: its table is one row an accessor — a
  row a vendor, and a row apiece for the patterns of `patternsWithNoVendor`,
  which name a format and sit under no vendor accessor. So a pattern for a
  vendor already there may only widen that row's list, while a new vendor or a
  new format-named pattern adds a row. A vendor whose patterns a caller now has
  to choose between wants a sentence saying what the choice is.
- A Locates column is names alone: one comma separated item a kind, and no
  prose about them. A kind is named as its vendor names it — a phrase shortened
  to fit that shape is how the table comes to name a credential nobody issues.
- The sentence above that table counts the built-in patterns, those kinds and
  the vendors: correct all three here. The vendor count moves only where the
  vendor is new. `Test_README_countsWhatItClaims` (`readme_test.go`) holds the
  first two against what the package declares, so a pattern or a vendor left
  uncounted fails under a plain `go test`. The count of kinds is held against
  the table's own rows and nothing else, since no declaration carries them, so a
  row widened without the sentence corrected is a reviewer's to catch.
