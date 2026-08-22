# mask-go

A Go library that redacts credentials (API keys, access tokens) from text.
Public surface: `Masker` (`mask.go`), `Pattern` (`pattern.go`), `Redactor`
(`redactor.go`), `Option` (`option.go`), built-in patterns (`builtins.go` and
the `builtin_*.go` beside it).

## Layout

One built-in pattern to a file: `builtin_<name>.go` with a
`builtin_<name>_test.go` beside it, holding the pattern, its scan, the helpers
only that scan reads, its behaviour tables, its reference, its fuzz target and
the cases it is benchmarked on. `builtins.go` is the registry alone,
`builtin_scan.go` holds what more than one scan reads (`segments`,
`isBase64URLByte`, `base64URLRunEnd`, `isBase62Byte`, `base62RunEnd`),
`builtins_test.go` holds what every built-in is held to, `fuzz_test.go` holds
the `Masker` targets and the body the per-pattern targets share, and
`benchmark_test.go` holds every benchmark there is. Adding a pattern should
touch the registry, the property table, two new files and the conformance
corpus — nothing else. Keep it that way rather than letting a shared
`builtin.go` grow back.

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

Tools are pinned in `mise.toml`. `mise bootstrap` installs the git hooks.

- `go test ./...` — tests. Run it without `-race` as well as with: the tests
  holding `Mask` to allocating nothing stand down under the race detector, so
  the two runs do not cover the same thing, and CI does both.
- `go test ./conformance -update` — regenerate the conformance corpus and check
  it in the same run (`conformance/CLAUDE.md`).
- `go test -fuzz FuzzJWT_matchesReference .` — fuzzing. Targets in the root
  package: `FuzzMasker_locate`, `FuzzMasker_Mask`, `FuzzJWT_matchesReference`,
  `FuzzGitHubToken_matchesReference`, `FuzzAWSAccessKeyID_matchesReference`,
  `FuzzSlackToken_matchesReference`, `FuzzGitLabToken_matchesReference`,
  `FuzzGoogleAPIKey_matchesReference`, `FuzzOpenAIAPIKey_matchesReference`,
  `FuzzAnthropicAPIKey_matchesReference`, `FuzzStripeAPIKey_matchesReference`,
  `FuzzPyPIAPIToken_matchesReference`, `FuzzNPMToken_matchesReference`,
  `FuzzSendGridAPIKey_matchesReference` `FuzzSentryAuthToken_matchesReference`
  and `FuzzLinearAPIKey_matchesReference`. In `conformance`: `FuzzMask`,
  `FuzzMask_customPatterns`, `FuzzText`. CI gives each of them 30 seconds.
- `go test -bench . -benchmem` — benchmarks. `BenchmarkMasker_Mask` drives
  every pattern at once through the public API, which is what a caller pays;
  `BenchmarkBuiltins` drives each scan alone under the name its pattern
  reports, and that is what a change to a scan is compared against, since a
  regression in one is a fourteenth of what the first reports. `go test -bench
  Builtins/jwt -benchmem .` runs one of them.
- `golangci-lint run` — lint (no config file; defaults).
- `go fix ./...` — apply modern Go idioms. Go 1.26's `go fix` is the
  analyzer-driven fixer that supersedes the standalone `modernize`, so it
  ships with the pinned toolchain rather than needing a pin of its own.
  `go fix -diff ./...` reports without applying and exits non-zero when there
  is anything to apply, and that is what the pre-commit hook runs: a rewrite
  into `strings.Builder` or `slices.Contains` inside a scan is a change to a
  hot path, so it wants benchmarks either side of it rather than to be applied
  and staged behind your back.
- `betterleaks git` — secret scan.

## Tests

- Table-driven, one `name` per case, and each case writes out its own data
  literally rather than sharing fixtures or computing it.
- Weigh a built-in against the set before adding one, not on its own:
  `AllBuiltinPatterns` is the whole registry, so a pattern added to `builtins`
  changes what every caller of it redacts with no signature moving to say so.
  That is safe while a built-in over-matches only on values opaque to a reader
  — being wrong about one of those costs the reader nothing. A grammar that
  admits a git SHA, an MD5 or a word of prose does not qualify, however rarely
  it would fire.
- What that rules out is the loose grammar, not the unlucky one. The question
  to ask of an over-match is whether the pattern could have been tighter: a
  bare forty hex characters, or `SK` and thirty-two, casts a net over values
  that carry meaning when a tighter net was available and was not taken. Where
  instead the grammar is already as tight as the vendor's own format and text
  still lands inside it, that text is indistinguishable from a credential —
  there is nothing left to read it by — and redacting is right, because
  declining it would mean declining every real credential of the same shape. A
  pattern relying on this states the collision in its own file and pins it with
  cases, so that it is a decision on the record rather than something the next
  reader discovers.
- Adding a built-in pattern means three declarations: the two below, and cases
  in the conformance corpus (`conformance/CLAUDE.md`).
- The first two are: the pattern in `builtins`
  (`builtins.go`), which is what `AllBuiltinPatterns` reports, and an entry in
  `builtinPatterns` (`builtins_test.go`), which is what holds it to the
  properties every built-in shares — its name and the convention `Pattern.Name`
  asks for, one value per accessor, usable spans, no false positive on prose,
  agreement with its reference, masking that leaves nothing to find out of
  reach of what it redacted, concurrent use, benchmark cases holding the values
  they state, and a linear-time scan. The two are held to naming the same
  patterns in the same order, so neither can be forgotten, and an entry is held
  to being whole: a field left out leaves most of the properties with nothing to
  hold rather than failing, so `Test_builtins_entriesAreFilledIn` reports the
  omission itself and runs first for that reason.
- The `samples` a `builtinPatterns` entry carries are the one place fixtures are
  shared. They say only "this is one of these", which is all the properties
  need; what exactly is located, and what is left alone, stays written out case
  by case in the pattern's own `builtin_<name>_test.go`. Inputs crafted against
  what one scan remembers stay with that scan too, as `Test_JWT_scanIsLinear`
  does.
- `benchmarks` is the one field an entry names rather than carries, for that
  reason: what is worth timing in a scan — the run its cursor walks once, the
  candidate crowded behind another, the byte test that turns a log line away —
  is crafted against that scan, so the cases live in the pattern's own file as
  `<pattern>FindBenchmarks`. What times them is `BenchmarkBuiltins`
  (`benchmark_test.go`), which reads this table and nothing else, so a pattern
  cannot be left untimed: a benchmark written as a function a pattern could be
  left unwritten and nothing would report it, since `go test` runs no benchmark
  at all. Naming them here also puts every case under
  `Test_builtins_benchmarkCasesHoldTheirValues`, which holds it to the count it
  states — a case named "many values" whose text stopped holding one would
  otherwise time a scan finding nothing and report it as a speedup.
  `Test_maskerMaskBenchmarks` does the same for `maskerMaskBenchmarks`, the
  table `BenchmarkMasker_Mask` reads.
- Every built-in scanner is checked against a reference kept beside it:
  `referenceJWTFind` (`builtin_jwt_test.go`), `referenceGitHubTokenFind`
  (`builtin_github_token_test.go`), `referenceAWSAccessKeyIDFind`
  (`builtin_aws_access_key_id_test.go`), `referenceSlackTokenFind`
  (`builtin_slack_token_test.go`), `referenceGitLabTokenFind`
  (`builtin_gitlab_token_test.go`), `referenceGoogleAPIKeyFind`
  (`builtin_google_api_key_test.go`), `referenceOpenAIAPIKeyFind`
  (`builtin_openai_api_key_test.go`), `referenceAnthropicAPIKeyFind`
  (`builtin_anthropic_api_key_test.go`), `referenceStripeAPIKeyFind`
  (`builtin_stripe_api_key_test.go`), `referencePyPIAPITokenFind`
  (`builtin_pypi_api_token_test.go`), `referenceNPMTokenFind`
  (`builtin_npm_token_test.go`), `referenceSendGridAPIKeyFind`
  (`builtin_sendgrid_api_key_test.go`), `referenceSentryAuthTokenFind`
  (`builtin_sentry_auth_token_test.go`) and `referenceLinearAPIKeyFind`
  (`builtin_linear_api_key_test.go`), plain implementations of the same rules.
  The second tries `referenceGitHubToken`, the regular expression the GitHub
  token scan reads by hand, at every byte rather than handing it to
  `FindAllStringIndex`: a value either scan locates can hold the start of the
  next one, so a reference that resumed past a match would miss what the scan
  finds. The third, the fifth, the sixth, the seventh, the eleventh, the
  twelfth, the thirteenth and the fourteenth do the same for the same reason —
  an access key ID can begin three characters into the one before it, a GitLab
  body is written in an alphabet that holds every letter a GitLab prefix is, a
  Google API key's prefix and an OpenAI key's `sk-` are each written in the
  alphabet their own runs are, an npm body can close with the three letters an
  npm prefix opens with, a SendGrid key's `SG.` is two characters of a
  segment's own alphabet and the dot such a key already carries between its
  segments, and a Sentry organization payload is written in an alphabet holding
  every letter a Sentry prefix is, closed by the underscore that prefix ends
  on, and a Linear key's `lin_api_` opens with three characters a Linear body
  is written with. The first, the fourth, the eighth, the ninth and the tenth
  are written out rather than built on a regular expression, and all five start
  afresh at every position — all but the ninth for that same reason, and the
  ninth because a reference is written to know nothing its scan claims, and
  what the Stripe scan claims is that no key can begin inside another. What the
  first two read of a candidate — a decoded JOSE header, a run divided into
  segments — is not what an expression states compactly; the grammars of the
  eighth and the tenth are, and they are written out anyway, because a floor
  spelled as a counted repetition costs an engine a machine as wide as the
  floor at every candidate, which left the eighth's fuzz target wedged on one
  grown input instead of fuzzing. The Anthropic file measures both. The ninth's
  grammar cannot be spelled in Go's syntax at all: the byte it reads in front
  of a prefix admits the underscore where `\b` does not, and there is no
  lookbehind to write the demand with instead. The eleventh spells a floor as a
  counted repetition and is not wedged by it, for the reason its scan needs no
  cursor: no input crowds two npm candidates inside one run, so the walk an
  engine repeats at the eighth's candidates has nothing to repeat at its own.
  The twelfth spells no floor at all: both its counts are exact, twenty-two and
  forty-three, so the machine an engine builds for a candidate is read once and
  stops. The thirteenth spells none either, for the same reason — sixty-four
  and forty-three, both exact — and writes the one rule its scan reads as
  arithmetic, that a payload is a whole number of base64 groups, as base64
  itself writes it: groups of four, the last able to close with padding. That
  is the one place a reference and its scan state a rule differently on
  purpose, since a reference restating the modulus would agree by construction
  wherever the scan had the modulus wrong. The fourteenth spells a floor as a
  counted repetition and is not wedged by it either, and for the eleventh's
  reason: no input crowds two Linear candidates inside one run. A reference
  spells the prefixes, the counts and the character classes its scan reads out
  again rather than sharing the declarations, so that the two can disagree and
  the fuzz target report it. Change scanner and reference together, and keep
  the corpus in `testdata/fuzz/`. The targets share their body through
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
- Every built-in scan resumes a byte along from a candidate whether it became a
  value or not, and in all but one of them that is because a value can begin
  inside the one before it. A GitHub body and a JWT signature are read as far
  as their alphabet runs, so either swallows the opening of a credential
  written straight after it, as does an OpenAI key, whose run reaches to the
  end of the alphabet behind its marker; an AWS access key ID, a Google API key
  and a SendGrid key are read to a fixed count and swallow nothing, but each
  can still be written inside the one before it — the `A` closing `ASIA` opens
  the `AKIA` three characters along, `AIza` is four characters a key's own body
  may be written with, `sk-` is three of an OpenAI run's own, `sk-ant-` is
  seven of an Anthropic body's, `pypi-AgE` is eight of a PyPI token body's and
  `SG.` is two characters a SendGrid segment is written with followed by the
  dot such a key already carries between its segments, so a secret closing with
  `SG` opens a candidate two characters before its own key ends. An Anthropic
  key and a PyPI token are read to the end of their run as an OpenAI key is, so
  each swallows what is written straight after it too. An npm token is read to
  the end of its run as well, and only the three letters in front of its
  underscore belong to that run, so a token begins three characters before the
  one in front of it ends rather than anywhere inside it. A Sentry token is
  read to a fixed count too, and nests for the reason a SendGrid key does: the
  six characters in front of the underscore its prefix closes with are ones a
  Sentry organization payload is written with, and that underscore is the one
  such a token already carries between its payload and its secret, so a payload
  closing with `sntrys` or `sntryu` opens a candidate whose own body begins
  where the first token's secret does. A Linear API key is read to the end of
  its run as an npm token is, and nests as one does: `lin_api_` opens with
  three characters a body may be written with and closes with an underscore no
  body holds, so a key begins three characters before the one in front of it
  ends and nowhere else inside it. Consuming a match would step over such a
  value and leave it in the output whole. The cost is that a value nested in
  another — a JWT payload that is itself a header — is located too; the spans
  overlap and `Masker.locate` resolves them.
- The Stripe scan is the exception and states why in its own file: a key begins
  only where no letter and no digit stands in front of it, and everything a span
  covers is one or the other but for the underscores of its prefix, so no key
  can be written inside another and its spans never overlap one another. It
  resumes a byte past the two it searches for rather than a byte past the start
  of the candidate, because the candidate opens one byte in front of them and
  resuming there would find the same anchor again and never advance.
  `Test_StripeAPIKey_noKeyBeginsInsideAnother` is what holds the claim.
- `Masker.locate` and every built-in scanner are deliberately linear-time and
  allocation-conscious. Resuming one byte along means a run can hold a
  candidate for every character it has, and seven of the scans keep a cursor
  over that run to rule out quadratic inputs: the JWT scan over a run of
  base64url characters, the GitHub scan over that and over the alphabet a fine
  grained token body is written in, the GitLab scan over a body run, the Slack
  scan over a body run and the rightmost part of it able to be a secret, the
  OpenAI scan over a run and over where the marker inside it stands, the
  Anthropic scan over a body run, and the PyPI scan over one too. Each of those
  cursors is load-bearing; the ones the Slack, GitLab and Anthropic scans keep
  are held to never moving back by a `Test_..._bodyNeverMovesBack` of their
  own, and the two the OpenAI scan keeps by `Test_OpenAIAPIKey_scanIsLinear`,
  as the Anthropic one is by `Test_AnthropicAPIKey_scanIsLinear` and the PyPI
  one by `Test_PyPIAPIToken_scanIsLinear`. The PyPI scan needs no
  `bodyNeverMovesBack` beside those: its body stands a fixed distance past the
  start of its candidate, so it moves forward with the candidates and there is
  no separator to reason about. The AWS, Google and SendGrid scans keep no
  cursor and need none: a fixed count means a candidate reads a bounded number
  of bytes and stops, which is the same guarantee bought without state. The
  Stripe, npm, Sentry and Linear scans keep none either, and share a guarantee
  of their own: every prefix any of them reads closes with an underscore and no
  body of any of them is written with one, so every body begins where a run
  begins and no two candidates can read the same run. It is what the classic
  alternative of the GitHub scan has for that same reason, and it is what lets
  the Sentry scan walk an organization payload of any length without
  remembering where the last one ended. `Test_StripeAPIKey_scanIsLinear`,
  `Test_NPMToken_scanIsLinear`, `Test_SentryAuthToken_scanIsLinear` and
  `Test_LinearAPIKey_scanIsLinear` drive the inputs that would find it wrong,
  and `Test_npmTokenPrefix_runsDoNotOverlap`,
  `Test_sentryAuthTokenSeparator_runsDoNotOverlap` and
  `Test_linearAPIKeyPrefix_runsDoNotOverlap` hold those three prefixes to the
  character the guarantee rests on. Compare benchmarks before and after
  touching any of them — that scan's cases under `BenchmarkBuiltins` as well as
  `BenchmarkMasker_Mask`.
- Published library: any change to an exported name, signature or behaviour is
  breaking. Keep `README.md` in sync with the exported API.
