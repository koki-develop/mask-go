---
paths:
  - "builtin_*.go"
  - "builtins.go"
  - "builtins_test.go"
  - "vendors.go"
  - "vendors_test.go"
  - "benchmark_test.go"
  - "mask_test.go"
  - "fuzz_test.go"
  - "source_test.go"
  - "readme_test.go"
  - "conformance/**"
---

# Built-in patterns

What every built-in is held to. It loads when one of the files named in `paths:`
above is opened, which is where all of it applies and nowhere else.

## Where a pattern states its own case

A rule belongs here. Which side of it a pattern falls on belongs in that
pattern's own `builtin_<name>.go` and the `builtin_<name>_test.go` beside it,
never in a list kept somewhere central.

That is not a filing preference. A list of instances has to be corrected by
every pattern added, so it grows with the registry while the rule does not; two
patterns added at once each rewrite it, so it conflicts every time; and it is
read nowhere near the code it describes, so it drifts without anything failing.
Numbering the entries — "the third and the fifth are built on an expression" —
is worse again: an entry inserted renumbers every one after it, so adding one
rewrites the whole passage, and a passage rewritten under conflict that often
comes to disagree with itself.

A pattern's own file is no place for the list either, and what separates the two
is which patterns a sentence has to be right about. A file says what its scan
does and why: the count it reads and what makes that count readable, the thing
that bounds it, the tightening it declines and what declining costs. Naming the
other scans that reached the same answer states none of that and carries the
whole registry into a file that cannot see it. Ask of such a sentence whether a
built-in added tomorrow could make it false; where it could, it is the list
again under another name, and the rule it was reaching for is what to write
instead.

What survives that question is a reference to one other pattern this one is
coupled to: a declaration it borrows, the other half of a vendor's format, the
worked precedent for an alternative being weighed, a collision one format rules
out where this one pays for it. Those are about the pair rather than about the
registry, and no pattern added can falsify them.

So: state the rule and the test that holds it. Where a pattern is unusual, the
unusual thing is written in that pattern's own file, next to the declaration it
is about, where the next person to change that declaration is already reading.

## What a grammar may rest on

Two kinds of source settle a grammar, and the two do not carry the same weight.
The next person can open either again, which is what a count has to rest on: a
value read anywhere else settles nothing, however genuine it is.

The first is the vendor's own: its documentation, the SDKs and the CLI it
publishes, the fixtures those are tested against, and, where it is published,
the code that issues the credential. The vendor states the prefix and often
nothing else, while a grammar needs an alphabet and a length as well. Where the
vendor's own implementation is public, it states them, and that is the vendor
stating them. Where a vendor's docs mask an example, the width of the mask
corroborates a count stated elsewhere; on its own it establishes no length,
since a docs example may elide rather than mask byte for byte.

The second is the public secret-scanning rulesets. What those carry is
corroboration rather than authority: what someone else observed of the values,
not what the vendor undertakes to keep issuing. Read the rules themselves rather
than inferring them from what a ruleset does and does not fire on: a rule may be
written to an exact length rather than a floor, so a test value of one shape
misses a rule that exists for another.

Narrow the alphabet or raise the floor on evidence, never on its absence — a
value cut short is a credential with its tail left in the log. What the alphabet
and the length rest on goes in the rationale, named: the next person to widen
either needs to know whether they are reading the vendor's own format or an
assembly of what a ruleset happened to carry.

## Weighing one before adding it

`AllBuiltinPatterns` is the whole registry, so a pattern added to `builtins`
changes what every caller of it redacts with no signature moving to say so.
That is safe while a built-in over-matches only on values opaque to a reader —
being wrong about one of those costs the reader nothing. A grammar that admits a
git SHA, an MD5 or a word of prose does not qualify, however rarely it would
fire.

What that rules out is the loose grammar, not the unlucky one. The question to
ask of an over-match is whether the pattern could have been tighter: a bare
forty hex characters, or `SK` and thirty-two, casts a net over values that carry
meaning when a tighter net was available and was not taken. Where a value
carries nothing at all to be recognised by, the name it is assigned to is one of
the nets available, and the gate is asked of the grammar with that name in it
rather than of the value alone — how far in front of a value a pattern may read
is `LookBehind`'s to bound and is below. Where instead the grammar is already as
tight as the vendor's own format and text still lands inside it, that text is
indistinguishable from a credential — there is nothing left to read it by — and
redacting is right, because declining it would mean declining every real
credential of the same shape. A pattern relying on this
states the collision in its own file and pins it with cases, so that it is a
decision on the record rather than something the next reader discovers.

## Where one pattern ends and the next begins

A `Pattern` is what a caller switches on with `WithPatterns`, the name a
`Redactor` reads out of `Match.Pattern`, and an accessor they find in the
documentation. Those are three faces of one question, and it is the only
question the boundary between two built-ins turns on: is this one thing to the
caller, or two?

How the scanning is arranged has no say in it. `Find` may run two searches over
the input and return the spans of both, so a grammar shared or not shared, an
anchor standing in the value or in the text around it, a cursor kept or not
kept, argue for no boundary and against none. The exported surface is decided
first and the scan is written to it.

Three things put a boundary in, and one of them is enough.

- **The caller has reason to enable one and not the other.** Two credentials a
  vendor issues need not be worth the same to redact: one is published by design
  where the other authenticates, or one is the identifier a log is kept for and
  the other the secret standing beside it. A caller who can state that decision
  needs two switches to act on it.
- **The caller has reason to tell them apart in the output.** A redactor keying
  on `Match.Pattern.Name()` can write only the distinction the boundary hands
  it.
- **No term the vendor uses covers both**, which the next section is about.

What puts no boundary in is the count of prefixes. A vendor naming a dozen kinds
of token and giving each a prefix of its own is one pattern wherever the caller
redacts all of them together, labels none of them apart from the rest and has a
name for the whole of them — and there twelve switches are worse than one, since
a caller reaching for that vendor would have to know all twelve to redact what
it issues.

### The name

The exported accessor and the string `Pattern.Name` reports are held to a term
the vendor itself uses for the whole of what the pattern locates. That is
checkable against the same documentation the scan's rationale is already built
on, and it goes stale only when the pattern is widened, which is when it is
being read anyway.

A name covering less than the pattern locates is usually a name to change rather
than a pattern to split: where the vendor has a wider term, renaming to it
leaves the credentials under one scan, which is where they belong when nothing
above puts a boundary between them. The boundary is wrong only where no term of
the vendor's covers the whole, and then the pattern splits along the terms that
do.

## Vendor accessors

Every vendor has an accessor of its own, `<Vendor>Patterns() []Pattern`,
returning the built-ins that read what that vendor issues. It is written for
every vendor, including one with a single pattern, so that a caller reaching for
a vendor never has to know how many patterns it has, nor whether it is one of
the vendors that has an accessor.

A pattern naming a format rather than a vendor's credential has none.

The boundary between patterns is the caller's and is decided above. The boundary
between accessors is the vendor's, and it moves only when a vendor does.

## The declarations a pattern arrives with

Five, and no more: the pattern in `builtins` (`builtins.go`), its vendor's
accessor (`vendors.go`), an entry in `builtinPatterns` (`builtins_test.go`),
cases in the conformance corpus (`conformance/CLAUDE.md`), and a row in the
table of `README.md`. Everything else is derived from one of them.

The README row is a declaration rather than documentation kept in step: it
states what the pattern locates in the vendor's own words, and nothing in the
package carries that. `Test_README_countsWhatItClaims` and
`Test_README_namesEveryAccessor` (`readme_test.go`) hold the row and the counts
above the table against what the package declares.

Two variations. A pattern arriving with a vendor no accessor covers brings a
sixth, that accessor's entry in `vendorAccessors` (`vendors_test.go`); without
it the accessor is held to nothing —
`Test_vendorAccessors_nameEveryAccessorDeclared` reads the declarations out of
the syntax tree and fails for exactly that reason. A pattern naming a format
rather than a vendor's credential still brings five: it has no accessor to add,
so the second of them is an entry in `patternsWithNoVendor` (`vendors_test.go`)
instead, which is how it says the absence was meant.
`Test_vendorAccessors_coverEveryBuiltin` fails without it, and
`Test_README_namesEveryAccessor` holds that table to the accessors no vendor
returns.

`builtins` is what `AllBuiltinPatterns` reports, one name to a line.
`builtinPatterns` is what holds a pattern to the properties every built-in
shares: its name and the convention `Pattern.Name` asks for, one value per
accessor, usable spans, no false positive on prose, agreement with its
reference, masking that leaves nothing to find out of reach of what it redacted,
concurrent use, benchmark cases holding the values they state, what the scan
settles, and a linear-time scan. The two are held to naming the same patterns in
the same order by `Test_builtins_matchAllBuiltinPatterns`, so neither can be
forgotten.

An entry is held to being whole by `Test_builtins_entriesAreFilledIn`, which
runs first in its file for that reason: a field left out leaves most of the
properties with nothing to hold rather than failing, so the omission has to be
reported as itself.

- `samples` are the one place fixtures are shared. They say only "this is one of
  these", which is all the properties need; what exactly is located, and what is
  left alone, stays written out case by case in the pattern's own
  `builtin_<name>_test.go`. Inputs crafted against what one scan remembers stay
  with that scan too, as `Test_JWT_scanIsLinear` does.
- `anchors` say the opposite: what opens a candidate with a body too short to be
  a value. `TestMasker_Mask_withoutMatchDoesNotAllocate` (`mask_test.go`) builds
  its input from them, so a scan that allocated per candidate is measured. It
  reads the table rather than a string written out beside it so that the input
  reaches the whole registry rather than whatever the registry held when the
  string was last edited.

  Two things to get right, because only the first is held.
  `Test_builtins_anchorsAreNotValues` holds an anchor to locating nothing under
  any built-in, not merely under its own: the anchors are masked with the whole
  registry, so an anchor that is a value of some other pattern breaks that case
  exactly as one of its own would. That an anchor opens a candidate at all is
  not held and cannot be —
  a scan reports spans, not the positions it looked at, so a misspelled anchor
  and a real one report the same nothing — which is why the anchor is chosen
  where the scan is written and by whoever knows what the cheapest rejection
  there costs. And an anchor must stop short of work the scan means to pay for:
  the JWT scan allocates to decode the header of a candidate, bounded at four
  times to the dot, so an anchor reaching that decode would measure it and fail
  the test having found nothing wrong.
- `benchmarks` is named rather than carried, because what is worth timing in a
  scan — the run its cursor walks once, the candidate crowded behind another,
  the byte test that turns a log line away — is crafted against that scan and
  belongs in its file as `<pattern>FindBenchmarks`. `BenchmarkBuiltins`
  (`benchmark_test.go`) reads this table and nothing else, so a pattern cannot
  be left untimed: a benchmark written as a function could be left unwritten and
  nothing would report it, since `go test` runs no benchmark at all. Naming them
  here also puts every case under
  `Test_builtins_benchmarkCasesHoldTheirValues`, which holds it to the count it
  states — a case named "many values" whose text stopped holding one would
  otherwise time a scan finding nothing and report it as a speedup.
  `Test_maskerMaskBenchmarks` does the same for `maskerMaskBenchmarks`.

## References

Every built-in scanner is checked against a reference kept beside it in
`builtin_<name>_test.go`, a plain implementation of the same rules, driven
against the scan by a fuzz target. Four rules, each with a test:

- **A reference shares no declaration with the scan it checks.** It spells the
  prefixes, the counts and the character classes out again, so that the two can
  disagree and the target report it.
  `Test_references_shareNoDeclarationWithTheScans` (`source_test.go`) holds
  this, and it is the rule the whole arrangement rests on: a reference reading
  the scan's own declaration moves with whatever the scan is changed to, its
  target then compares a rule with itself, and nothing else reports it — the two
  agree on every input, the target passes and the corpus holds, because from
  then on they are wrong together or right together and never apart. The check
  type-checks the package and asks what each name resolves to rather than
  matching names, which is what makes it exact: a declaration of the scans is
  reached as a type, through a field of one, as the receiver of a method, as the
  key of a map literal or as the right-hand side of a binding that shadows it,
  and a walk of the syntax alone has a hole for each of those.
- **A reference lives beside the scan it checks**, which is where
  `Test_references_liveBesideTheScansTheyCheck` holds it: the rule above reads
  `builtin_*_test.go` alone, so one lifted elsewhere would leave it with nothing
  to hold rather than failing.
- **A reference is a named declaration**, not written inline at the call or
  bound to a local, since neither is one any rule reaches.
  `Test_references_areNamedRatherThanWritten` holds this.
- **A target keeps its own name.** The targets share their body through
  `fuzzAgainstReference` (`fuzz_test.go`) but are named
  `Fuzz<Pattern>_matchesReference` apiece, because the corpus under
  `testdata/fuzz/` is keyed on the name — so never rename a target without
  moving its corpus directory. There is one per built-in, which
  `Test_references_areNamedRatherThanWritten` counts: it holds the calls to the
  shared body to the size of the registry, so a pattern arriving without a
  target fails there rather than going quietly unfuzzed. CI reads the targets
  out of `go test -list` and gives each one a job, so nothing is listed by hand.

Change scanner and reference together.

### Whether to write a reference out or build it on an expression

Either is allowed. What decides it is what an expression costs the fuzz target,
and the pattern's own file states which way it went and why. The two things that
have made an expression too slow to fuzz with, both measured rather than
supposed:

- **A floor spelled as a counted repetition** costs an engine a machine as wide
  as the floor at every candidate. Where the input can crowd candidates
  together, that is quadratic, and it has left targets reporting no executions
  at all for most of their run. Exact counts do not cost this: the machine is
  read once and stops.
- **An opening written in the alphabet its own body is written in**, which makes
  a run of that alphabet a candidate at every byte, so a reference asking at
  every byte hands the engine the rest of the input each time.

A third consideration is the literal an engine searches the text for: one
literal in front of a grammar is what lets it skip, and an alternation of
literals sharing no first characters leaves it walking its machine at every
byte.

A reference asks at every byte rather than resuming past a match. Usually that
is because a value either scan locates can hold the start of the next one, so
resuming would miss what the scan finds. Where a pattern's values cannot nest,
asking at every byte is kept anyway — a reference is written to know nothing its
scan claims, and non-nesting is a thing the scan claims.

## What a scan does at a candidate

**Advance, never consume the match.** A scan steps forward whether the candidate
became a value or not. Consuming a match would step over a value written inside
the one just found and leave it in the output whole.

How far it advances, and what from, is the scan's own to decide and to justify
in its own file:

- A byte past the start of the candidate is the default, and needs no argument.
  A byte past the anchor is that same step reached from where the search stops
  rather than from where the candidate begins, which `builtin_scan.go` argues
  once: a scan taking it need say no more than that it resumes there, with
  whatever its own grammar makes worth saying about why consuming would not
  do.
- Anything else — the whole width of a prefix, or a resumption at a body — is an
  optimisation resting on a claim about the grammar, and the file makes the
  claim, names the test that drives it, and says why the default would not do. A
  pattern whose values provably cannot nest is held to that by a test of its own
  naming the claim, as `Test_RubyGemsAPIKey_noKeyBeginsInsideAnother` does.

The cost of advancing rather than consuming is that a value nested in another —
a JWT payload that is itself a header — is located too; the spans overlap and
`Masker.locate` resolves them.

## What a scan settles

`Pattern.Find` returns the offset from which the input is not settled, and every
scan answers it the same two ways: a piece of what a candidate opens with
standing at the end of the input, and a candidate the end of the input cut
short. `builtin_scan.go` states both and holds the first of them as `prefixTail`
for a scan whose openings are literals, where a scan opening on something else
asks the walk that already reads that opening rather than a second grammar free
to disagree with it. The other is the scan's own either way, and what it reports
there is the candidate's start.

- **Report the candidate, do not read what is written of it.** A scan that
  worked out that a truncated candidate could never have become a value would
  release a few more bytes at the end of a write, and it would cost a second
  grammar — the grammar of the halves — kept beside the first and free to
  disagree with it. Settling too little costs a stream the text it holds on to;
  settling too much releases a credential before it was found.

  The second grammar is what this rules out, and a scan may read a truncated
  candidate where the reading is the first grammar and nothing else: the same
  walk, over the same alphabet, against the same count, ruling the candidate out
  for every text carrying on from it rather than for the one in hand. A run
  already wider than a value is the shape that qualifies. Wanting the bytes back
  is not reason enough on its own — a scan reading a candidate here says in its
  own file what it would otherwise hold on to, and how much.
- **A helper that says no owes the reason where the reason is the input.** A
  walk that stopped because the text said so is settled; a walk that stopped
  because the input ran out is not, and only the walk can tell them apart. The
  helpers that report both — `opensJOSEHeaderAt`, `segmentsEnd`,
  `privateKeyBlockEnd`, `sentryAuthTokenOrgEnd` and the rest — return the
  question's answer and then whether the end of the input was what answered it.
- **Prefixes for a tail are derived, never listed again.** A pattern whose
  prefixes are built from parts — a kind, an opening, a separator — builds its
  `prefixTail` from those same parts, as `githubTokenPrefixes` and
  `sentryAuthTokenPrefixes` do. A table written out beside them is one that can
  come to disagree about which kinds there are, and what a stream does with the
  kind it was not told about is release the characters a token opens with.
- **The answer is not monotone, and nothing needs it to be.** An anchor arriving
  puts a candidate in text a scan had already walked past: `ANTHROPIC_AP` holds
  no candidate for an AWS access key ID and `ANTHROPIC_API` holds one two
  characters in front of its end. Both answers are true — what a scan settles it
  settles for every text carrying on from there — and `stream.go` keeps the
  further of the two.

`Test_builtins_retainSettles` holds every built-in to the whole of this on its
samples cut at every offset, `FuzzBuiltins_retain` on generated text, and the
cut properties in `conformance` end to end against `Mask`.

The other half is `LookBehind`, which `pattern.go` states: how far in front of a
value a `Pattern` may read. A built-in reads no further in front of one than
what decides whether a value stands there at all, and a prefix long enough to
stand on its own decides that without reading anything in front of a value.
What a scan reads there, and why reading nothing would not have done, is that
scan's decision and is argued in its own file.

A scan reading further than the character in front of a value owes a test of its
own besides, building the widest such reading out of the declarations the scan
reads it with and holding it to the limit. One character needs none: it cannot
grow, and the limit is not a number anything could carry it past. What the test
catches is a widening somewhere else: a count raised, a word added, a floor
lengthened, none of which is written near `LookBehind` and any of which can
carry the reading past it. Nothing else reports that: `Mask` is handed the whole
text and never notices, so what fails instead is a stream releasing a value the
same pattern locates when handed everything — and only where a case happens to
be written wide enough to reach the limit.
`Test_patterns_readNoFurtherBackThanLookBehind` and
`FuzzPatterns_lookBehind` hold every built-in to reading no further back than
`LookBehind` on the text they are driven with, which is the same rule over the
inputs that exist rather than over the ones a change makes possible.

## Linearity

`Masker.locate` and every built-in scanner are deliberately linear-time and
allocation-conscious. Advancing one byte along means a run can hold a candidate
for every character it has, so every scan needs something that rules out a
quadratic input. There are three ways one gets it, and a scan has whichever it
has for a reason its file gives:

- **A cursor over the run**, remembered between candidates. Every such cursor is
  load-bearing, and is held to never moving back by a test of its own — one
  named `Test_<X>_bodyNeverMovesBack`, as the prefix-table patterns have — or by
  a `Test_<Pattern>_scanIsLinear` driving the input that would find it wrong.
- **A fixed count**, which bounds what a candidate reads without any state to be
  wrong about.
- **A prefix closing with a character no body of that scan is written with**, so
  every body begins where a run begins and no two candidates can read the same
  run. This is what `isBase62Byte` (`builtin_scan.go`) leaving the underscore
  out is for, and it is why a scan resting on it can walk a payload of any
  length without remembering where the last one ended. A pattern resting on it
  is held to it by a test naming the character the guarantee rests on, as
  `Test_npmAccessTokenPrefix_runsDoNotOverlap` does.

A `Test_<Pattern>_scanIsLinear` is the input crafted against one scan and
nothing else, and it keeps its own name and its own sources. One handing over
finished text shares its body through `checkScanIsLinear` (`builtins_test.go`),
the way the targets above share `fuzzAgainstReference`; one whose inputs are
built rather than written out drives them itself, as
`Test_privateKey_scanIsLinear` does with a unit repeated to a length. Either
way, `scanIsLinearLimit` is how long a scan may take over such an input.

Compare benchmarks before and after touching any scan — that scan's cases under
`BenchmarkBuiltins` as well as `BenchmarkMasker_Mask`.
