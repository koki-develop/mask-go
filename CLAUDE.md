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
the `Masker` targets and the body the per-pattern targets share,
`benchmark_test.go` holds every benchmark there is, and `source_test.go` holds
the rules about how this package is written rather than about what it computes,
read out of the syntax tree. Adding a pattern should touch the registry, the
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
  `FuzzPyPIAPIToken_matchesReference`, `FuzzNPMAccessToken_matchesReference`,
  `FuzzSendGridAPIKey_matchesReference`,
  `FuzzSentryAuthToken_matchesReference`, `FuzzLinearAPIKey_matchesReference`,
  `FuzzNotionAPIToken_matchesReference`,
  `FuzzHashiCorpVaultToken_matchesReference`,
  `FuzzGrafanaServiceAccountToken_matchesReference` and
  `FuzzSupabasePersonalAccessToken_matchesReference`. In `conformance`:
  `FuzzMask`, `FuzzMask_customPatterns`, `FuzzText`. CI gives each of them 30
  seconds.
- `go test -bench . -benchmem` — benchmarks. `BenchmarkMasker_Mask` drives
  every pattern at once through the public API, which is what a caller pays;
  `BenchmarkBuiltins` drives each scan alone under the name its pattern
  reports, and that is what a change to a scan is compared against, since a
  regression in one is an eighteenth of what the first reports. `go test -bench
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
  to being whole: a field left out leaves most of the properties with nothing
  to hold rather than failing, so `Test_builtins_entriesAreFilledIn` reports
  the omission itself and runs first for that reason.
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
  (`builtin_pypi_api_token_test.go`), `referenceNPMAccessTokenFind`
  (`builtin_npm_access_token_test.go`), `referenceSendGridAPIKeyFind`
  (`builtin_sendgrid_api_key_test.go`), `referenceSentryAuthTokenFind`
  (`builtin_sentry_auth_token_test.go`), `referenceLinearAPIKeyFind`
  (`builtin_linear_api_key_test.go`), `referenceNotionAPITokenFind`
  (`builtin_notion_api_token_test.go`), `referenceHashiCorpVaultTokenFind`
  (`builtin_hashicorp_vault_token_test.go`),
  `referenceGrafanaServiceAccountTokenFind`
  (`builtin_grafana_service_account_token_test.go`) and
  `referenceSupabasePersonalAccessTokenFind`
  (`builtin_supabase_personal_access_token_test.go`), plain implementations of
  the same rules. The third, the fifth, the sixth, the seventh, the eleventh,
  the twelfth, the fourteenth, the sixteenth, the seventeenth and the eighteenth
  are built on a regular expression, and each tries it at every byte rather than
  handing it to `FindAllStringIndex`. For all but the eighteenth that is because
  a value either scan locates can hold the start of the next one, so a reference
  that resumed past a match would miss what the scan finds — an access key ID
  can begin three characters into the one before it, a GitLab body is written in
  an alphabet that holds every letter a GitLab prefix is, a Google API key's
  prefix and an OpenAI key's `sk-` are each written in the alphabet their own
  runs are, an npm body can close with the three letters an npm prefix opens
  with, a SendGrid key's `SG.` is two characters of a segment's own alphabet and
  the dot such a key already carries between its segments, a Linear key's
  `lin_api_` opens with three characters a Linear body is written with, and a
  Vault token's `hv` and the letter naming its kind are three characters a Vault
  body is written with, in front of the separator such a token already carries,
  and a Grafana token's `glsa_` is four characters a secret is written with
  followed by the underscore such a token already carries between its secret and
  its checksum. The eighteenth is the exception and asks at every byte all the
  same: a Supabase token carries the letter its prefix opens with at its first
  character and nowhere else, since neither the `oauth_` of the longer form nor
  a body written in hexadecimal digits holds one, so no token begins inside
  another and `FindAllStringIndex` would report the same spans. What asking at
  every byte buys there is that the reference restates the scan's own resumption
  rather than a shorter rule that happens to agree with it. The first, the
  second, the fourth, the eighth, the ninth, the tenth, the thirteenth and the
  fifteenth are written out rather than built on a regular expression, and all
  eight start afresh at every position — all but the ninth for that same reason,
  the thirteenth because a Sentry organization payload is written in an alphabet
  holding every letter a Sentry prefix is, closed by the underscore that prefix
  ends on, the fifteenth because the `ntn` and `secret` in front of a Notion
  prefix's underscore are characters a Notion body is written with, and the
  ninth because a reference is written to know nothing its scan claims, and
  what the Stripe scan claims is that no key can begin inside another. What the
  first reads of a candidate — a decoded JOSE header, a run divided into
  segments — is not what an expression states compactly; the grammars of the
  second, the eighth and the tenth are, and they are written out anyway,
  because a floor spelled as a counted repetition costs an engine a machine as
  wide as the floor at every candidate, which left the fuzz targets of the
  second and the eighth wedged on a grown input instead of fuzzing. An
  expression at the second reaches forty-seven thousand executions in three
  seconds and reports none at all for the twenty-seven after them, where the
  walks written out there run seven million in forty seconds and do not stall.
  The Anthropic file measures both. The ninth's grammar cannot be spelled in
  Go's syntax at all: the byte it reads in front of a prefix admits the
  underscore where `\b` does not, and there is no lookbehind to write the
  demand with instead. The eleventh spells a floor as a counted repetition and
  is not wedged by it, for the reason its scan needs no cursor: no input crowds
  two npm candidates inside one run, so the walk an engine repeats at the
  eighth's candidates has nothing to repeat at its own. The twelfth spells no
  floor at all: both its counts are exact, twenty-two and forty-three, so the
  machine an engine builds for a candidate is read once and stops. The
  thirteenth is written out too, and neither its counts nor its repetition are
  why: sixty-four and forty-three are both exact and the group of four repeated
  without limit is a loop rather than a width, so the machine an engine builds
  for a candidate is bounded. What costs an expression there is that the
  alphabet a Sentry payload is written in holds every letter a Sentry opening
  is, so a run of them is a candidate at every byte and a reference asking at
  every byte hands the engine the whole of the rest of the input at each of
  them. Such an expression runs for three seconds of its target's thirty and
  reports no executions at all for the twenty-seven after them, where the walks
  written out there run seven million in forty-five seconds. It still writes
  the one rule its scan reads as arithmetic, that a payload is a whole number
  of base64 groups, as base64 itself writes it: groups of four walked one at a
  time, the last able to close with padding, rather than a length divided. That
  is the one place a reference and its scan state a rule differently on
  purpose, since a reference restating the modulus would agree by construction
  wherever the scan had the modulus wrong. The fourteenth spells a floor as a
  counted repetition and is not wedged by it either, and for the eleventh's
  reason: no input crowds two Linear candidates inside one run. The sixteenth
  spells a floor as a counted repetition and is not wedged by it for that same
  reason, and its alternation of three prefixes costs it nothing either: all
  three open with the same two characters, so an engine still has one literal
  to search the text for, where the fifteenth's two share none. The fifteenth
  is written out for a reason none of the others has: its grammar is an
  alternation of two literals, and an expression with one literal in front of
  it is scanned for by searching the text for that literal where two leave the
  engine walking its machine at every byte. A mebibyte of alphanumerics holding
  no token at all costs the alternation seventeen milliseconds and either half
  of it alone fourteen microseconds, and the mutator reaches inputs of that
  size — which had the target running at speed for fifteen seconds and at
  nothing at all for the rest of its run. What is written out there pays
  nothing for that: both counts are counts, so a position reads at most fifty
  bytes and stops, and the walk is linear where the eighth's is quadratic. It
  spells the two counts a body rather than the one total the scan subtracts a
  prefix from, so the subtraction is something the two can disagree about. The
  seventeenth spells no floor either: both its counts are exact, thirty-two and
  eight, so the machine an engine builds for a candidate is read once and
  stops, and the one literal in front of them is what the engine searches the
  text for. Nor does the eighteenth: its one count is exact, forty, and the
  optional group in front of that count leaves the engine the literal both forms
  of the token open with to search the text for, where the fifteenth's
  alternation of two literals leaves it none. A reference spells the prefixes,
  the counts and the character classes its scan reads out again rather than
  sharing the declarations, so that the two can disagree and the fuzz target
  report it. `Test_references_shareNoDeclarationWithTheScans` (`source_test.go`)
  is what holds this: a reference reading the scan's own declaration moves with
  whatever the scan is changed to, its target then compares a rule with itself,
  and nothing else reports it — the two agree on every input, the target passes
  and the corpus holds, because from then on they are wrong together or right
  together and never apart. It type-checks the package and asks what each name
  resolves to rather than matching names, which is what makes it exact: a
  declaration of the scans is reached as a type, through a field of one, as the
  receiver of a method, as the key of a map literal or as the right-hand side
  of a binding that shadows it, and a walk of the syntax alone has a hole for
  each of those. It reads `builtin_*_test.go` alone, which is where a reference
  belongs, and `Test_references_liveBesideTheScansTheyCheck` holds them there:
  one lifted elsewhere would leave the rule with nothing to hold rather than
  failing. `Test_references_areNamedRatherThanWritten` holds the reference a
  target is given to being one of those declarations, since a reference written
  inline at the call, or bound to a local, is one no declaration holds and no
  rule reaches. Change scanner and reference together, and keep the corpus in
  `testdata/fuzz/`. The targets share their body through `fuzzAgainstReference`
  (`fuzz_test.go`) but keep a name apiece, because the corpus is keyed on the
  name of the target — so never rename a target without moving its corpus
  directory.
- Behaviour that differs under the race detector is branched on `raceEnabled`
  (`race_test.go` / `norace_test.go`), not skipped.

## Style

- Doc comments on every exported identifier. Comments explain *why* — the
  scanner rationale in each `builtin_<name>.go` is load-bearing, so update it
  rather than dropping it.
- The comment above a function of this package opens with the name of that
  function, and `Test_docComments_nameWhatTheyDocument` (`source_test.go`)
  holds it there. Of this package alone: the check reads the directory it
  stands in, so `conformance` is not held to it, where the one comment that
  would fail — the one on `decodeText` — opens on what the notation is and
  names itself in the paragraph that follows.

  staticcheck states the same rule and reaches only exported declarations
  outside `_test.go`, which leaves out every fuzz target, every reference and
  every helper the tests are built from — where the names are longest and a
  rename is most likely to leave a comment behind, and where being sent to
  rename the function to match the comment instead parts a target from the
  corpus in `testdata/fuzz` keyed on its name. The comment above a built-in's
  pattern variable is the rationale for the scan under it and opens on that
  rather than on the variable, which is why the rule is about functions alone.
- `Pattern` and `Redactor` implementations must be safe for concurrent use.
- Every built-in scan advances a byte along whether the candidate became a value
  or not rather than consuming a match, and in all but two of them that is
  because a value can begin inside the one before it. What the byte is measured
  from is the start of the candidate in all but two: the Stripe scan and the
  Notion scan each measure from the anchor they searched for, and each says why
  in its own file. A GitHub body and a JWT signature are read as far as their
  alphabet runs, so either swallows the opening of a credential written straight
  after it, as does an OpenAI key, whose run reaches to the end of the alphabet
  behind its marker; an AWS access key ID, a Google API key and a SendGrid key
  are read to a fixed count and swallow nothing, but each can still be written
  inside the one before it — the `A` closing `ASIA` opens the `AKIA` three
  characters along, `AIza` is four characters a key's own body may be written
  with, `sk-` is three of an OpenAI run's own, `sk-ant-` is seven of an
  Anthropic body's, `pypi-AgE` is eight of a PyPI token body's and `SG.` is two
  characters a SendGrid segment is written with followed by the dot such a key
  already carries between its segments, so a secret closing with `SG` opens a
  candidate two characters before its own key ends. An Anthropic key and a PyPI
  token are read to the end of their run as an OpenAI key is, so each swallows
  what is written straight after it too. An npm access token is read to the end
  of its run as well, and only the three letters in front of its underscore
  belong to that run, so a token begins three characters before the one in front
  of it ends rather than anywhere inside it. A Sentry token is read to a fixed
  count too, and nests for the reason a SendGrid key does: the six characters in
  front of the underscore its prefix closes with are ones a Sentry organization
  payload is written with, and that underscore is the one such a token already
  carries between its payload and its secret, so a payload closing with `sntrys`
  or `sntryu` opens a candidate whose own body begins where the first token's
  secret does. A Linear API key is read to the end of its run as an npm access
  token is, and nests as one does: `lin_api_` opens with three characters a body
  may be written with and closes with an underscore no body holds, so a key
  begins three characters before the one in front of it ends and nowhere else
  inside it. A Notion token is read to a fixed count and swallows nothing too,
  and the `ntn` and `secret` in front of either of its prefixes' underscores are
  characters a body is written with, so a body closing with one of them hands
  the underscore written after the token to a candidate three or six characters
  before that token ends. A HashiCorp Vault token is read to the end of its run
  as a Linear key is, and nests as one does: the `hv` a prefix opens with and
  the letter naming its kind are three characters a body may be written with,
  and the dot the prefix closes with is none, so a token begins three characters
  before the one in front of it ends and nowhere else inside it. A Grafana
  service account token is read to a fixed count and swallows nothing either,
  and nests for the reason a Sentry token does: `glsa` is four characters a
  secret is written with and the underscore behind them is the one such a token
  already carries between its secret and its checksum, so a secret whose last
  four characters are `glsa` opens a candidate four characters before that
  secret ends and thirteen before the token does. Consuming a match would step
  over such a value and leave it in the output whole. The cost is that a value
  nested in another — a JWT payload that is itself a header — is located too;
  the spans overlap and `Masker.locate` resolves them.
- The two scans that advance a byte for another reason are the Stripe one and
  the Supabase one, and neither can have a value written inside another. The
  Supabase scan says so in its own file and rests it on one character: the
  letter `sbp_` opens with stands in a token exactly once, at its first
  character, since the `oauth_` of the longer form carries none and a body is
  written in lowercase hexadecimal digits, which carry none either. So its spans
  never overlap one another and the byte buys nothing for a candidate that
  became a token; what it is there for is the candidate that failed, since
  `sbp_sbp_` opens one whose own prefix stands four characters in.
  `Test_SupabasePersonalAccessToken_noTokenBeginsInsideAnother` holds the claim.
- The Stripe scan is the other, and states why in its own file: a key begins
  only where no letter and no digit stands in front of it, and everything a
  span covers is one or the other but for the underscores of its prefix, so no
  key can be written inside another and its spans never overlap one another. It
  resumes a byte past the two it searches for rather than a byte past the start
  of the candidate, because the candidate opens one byte in front of them and
  resuming there would find the same anchor again and never advance.
  `Test_StripeAPIKey_noKeyBeginsInsideAnother` is what holds the claim.
- The Notion scan measures from its anchor for a reason of its own, and states
  it in its own file: the two prefixes it reads share nothing but the
  underscore they close with, so that underscore is what it searches for and a
  candidate is read backwards from it. No body carries an underscore, so every
  candidate is found by one of its own and every underscore in the input is
  looked at in turn — advancing past one steps over nothing, and a token
  written inside another is found by the underscore standing past the token it
  begins inside. Reading a prefix backwards is also what makes the order the
  spans come out in an argument rather than an observation:
  `Test_notionAPITokenPrefixes` holds the table to what that argument rests on
  and `Test_NotionAPIToken_spansAreAscending` drives it.
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
  no separator to reason about. The AWS, Google, SendGrid, Notion, Grafana and
  Supabase scans keep no cursor and need none: a fixed count means a candidate
  reads a bounded number of bytes and stops, which is the same guarantee bought
  without state. The Stripe, npm, Sentry, Linear and Vault scans keep none
  either, and share a guarantee of their own: every prefix any of them reads
  closes with a character no body of that scan is written with — an underscore
  for the first four, the dot Vault writes between a prefix and a body for the
  fifth — so every body begins where a run begins and no two candidates can read
  the same run. It is what the classic alternative of the GitHub scan has for
  that same reason, and it is what lets the Sentry scan walk an organization
  payload of any length without remembering where the last one ended. The Notion
  scan reads that same underscore and reads it as the anchor itself rather than
  as what ends a body, which is what lets one search find two prefixes sharing
  no other character; what bounds it is still its count.
  `Test_StripeAPIKey_scanIsLinear`, `Test_NPMAccessToken_scanIsLinear`,
  `Test_SentryAuthToken_scanIsLinear`, `Test_LinearAPIKey_scanIsLinear` and
  `Test_HashiCorpVaultToken_scanIsLinear` drive the inputs that would find it
  wrong, and `Test_npmAccessTokenPrefix_runsDoNotOverlap`,
  `Test_sentryAuthTokenSeparator_runsDoNotOverlap`,
  `Test_linearAPIKeyPrefix_runsDoNotOverlap` and
  `Test_hashiCorpVaultTokenSeparator_runsDoNotOverlap` hold those four prefixes
  to the character the guarantee rests on, as `Test_notionAPITokenPrefixes`
  holds the two the Notion scan reads. Compare benchmarks before and after
  touching any of them — that scan's cases under `BenchmarkBuiltins` as well as
  `BenchmarkMasker_Mask`.
- Published library: any change to an exported name, signature or behaviour is
  breaking. Keep `README.md` in sync with the exported API.
