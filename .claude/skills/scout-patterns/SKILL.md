---
name: scout-patterns
description: Find credential formats that could become built-in patterns, verify them against the vendors' own documentation, and open an issue for the ones that survive. Use when asked to look for new patterns to add, refresh the candidate pool, or decide what to implement next.
---

Look for credential formats that could become built-in patterns, put each
through the gate, and open an issue for the ones that survive. This ends at an
issue; `add-pattern` starts from one.

Deciding whether a format can become a built-in means establishing its prefix,
alphabet and length — and the issue must carry none of that, because whoever
implements it is required to derive it from the vendor and will read anything
written here as settled instead. Research fully, decide, then write almost none
of it down.

Five to ten candidates in a run. Stop and report rather than growing the run.

## 1. What is already spoken for

`builtins.go` is the only truth about what is implemented; the issues labelled
`pattern`, open and closed, are the only truth about what is decided.

## 2. What could be one

The public secret-scanning rulesets — gitleaks, trufflehog and GitHub's secret
scanning partner list among them — are the widest net for formats carrying
their own anchor. Read them fresh each run: they disagree with each other, and
a vendor that introduced a prefix recently is in some and in none of the rest.

That a ruleset carries a format is evidence it exists, not evidence of what it
is. **Find the vendor stating the prefix, or open no issue** — ruleset
agreement does not substitute, and being wrong about a prefix means the pattern
never fires. Lengths and alphabets are usually absent from vendor docs; that is
normal and disqualifies nothing.

## 3. The gate

`.claude/rules/builtin-patterns.md`, "Weighing one before adding it" — whether
the grammar could have been tighter, not how often it would fire.

## 4. Report, then open issues on approval

Give the user what survived and what you dropped and why, and ask which to
open. Open nothing before they answer. Then, one issue per credential:

- **Title**: the vendor's own name for the secret, and nothing else. Rulesets
  name credentials in words their vendors don't use.
- **Body**: one sentence saying what the credential lets its holder do, with
  the vendor's name in it as a link. Not what it looks like, and not opening on
  a frame true of every secret ("the value that…").
- **Label**: `pattern`.

Read each back before filing. It must carry no prefix, length, alphabet or
count of kinds, no question of whether it is one pattern or several, no reason
it passed the gate, and no sentence noting that something was left out. All of
it was in front of you as you wrote, which is why this is a step and not a
memory.
