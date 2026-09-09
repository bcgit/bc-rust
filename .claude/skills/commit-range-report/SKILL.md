---
name: commit-range-report
description: Write a Markdown report summarising a range of commits on the current branch - branch name and commit list, public API changes and new functionality with code examples, then a per-commit summary. Use when asked to report on, summarise or document the commits since a given commit or between two commits.
---

# Commit range report

Produce a `.md` report for the commits from a start commit to an end commit (default: the branch
head), in this fixed structure:

1. **Title and preamble** — one sentence on what the range delivers as a whole.
2. **Branch and commits** — the branch name, then a table of every commit in the range with its
   full SHA and subject, oldest first. Note how they got there (squash merge of PR #N, cherry-pick,
   new work) when the subjects say so.
3. **Public API changes and new functionality** — grouped by crate, describing the API *as it is at
   the end of the range*, not each intermediate shape. For every new or changed public trait, type,
   alias or CLI subcommand: a short prose explanation of what it is for and any design rule behind
   it, then a code example. Traits are shown as their signatures (`pub trait ... { fn ...; }`);
   types are shown in use, end to end (construct a key, call the API, assert the result). Include
   the CLI with shell examples when subcommands were added.
4. **Summary of each commit** — one paragraph per commit, numbered to match the table: what changed,
   why, how it was verified, and the `files changed, insertions, deletions` line from `git show --stat`.
5. **Verification at the head** — formatting, tests, docs, and any vector suites that ran.

## Arguments

`$ARGUMENTS` is `<start-sha> [<end-ref>]`. The start commit is **included** in the range. If the end
is omitted use `HEAD`. If no argument is given, ask for the start commit.

## Procedure

Gather facts from the tree and git, never from memory of the session:

```sh
git rev-parse --abbrev-ref HEAD
git log --reverse --format='%H %s' <start>~1..<end>
for c in $(git log --reverse --format=%h <start>~1..<end>); do echo "$c: $(git show --stat --format= $c | tail -1)"; done
git diff --stat <start>~1 <end>                    # the whole range's footprint
```

For the API section, read the *current* source of every public item the range touched: trait
definitions (`awk '/^pub trait NAME/{p=1} p{print} p&&/^}/{exit}' file`), `pub use` / `pub struct` /
`pub type` lines, umbrella re-exports in `src/lib.rs`, and the CLI's `--help` output. Prefer taking
code examples from the crate's own doctests, since those are known to compile; adapt them minimally.
Quote spec citations exactly as the code does. Do not describe an API shape that a later commit in
the range replaced, except in the per-commit summary where it is history.

For the per-commit summaries, read each commit's message and stat; where a commit was a squash merge
or a cherry-pick with conflict resolution, say how the conflicts were resolved if the message or the
diff makes it clear.

## Output

Save the report as `local/<branch-slug>_<topic>_report.md` unless the user names a path (`local/` is
excluded from git on this checkout via `.git/info/exclude`; create it if absent), and leave it
uncommitted unless asked to commit it. Tell the user where it is. Keep the prose
in the house style: short sentences, one idea each, code only in fenced blocks, no em-dashes.
