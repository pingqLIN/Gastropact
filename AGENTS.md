# Gastropact Repository Instructions

## Authority model

- The active conversation-level Lead Agent owns scope, authorization interpretation,
  task authoring, dispatch, integration, evidence acceptance, and completion status.
- Execution Agents receive bounded file ownership and acceptance criteria. They may
  not expand scope, stage, commit, push, publish, deploy, access credentials, or
  mutate external runtimes unless a separate explicit authorization grants it.
- Review Agents are read-only unless the Lead explicitly authorizes a named fix.
- Agent output is evidence to recheck; an acknowledgement or claimed PASS is not
  proof of execution.

## Source and runtime boundary

- This repository is the canonical source-only project.
- Never copy live task bundles, user artifacts, backups, credentials, browser data,
  session data, or machine-specific evidence into tracked source.
- Local task state belongs under `.local/`; generated automation state belongs under
  `.automation/`; both are ignored by Git.
- `fixtures/` contains synthetic, reviewable test data only.

## Change workflow

1. Inspect branch, HEAD, special Git state, and `git status --short --branch` before
   writing.
2. Preserve unrelated and pre-existing work. A dirty-unknown worktree blocks edits.
3. Make one bounded checkpoint at a time and run the smallest relevant test first.
4. Run `pwsh -File automation/verify.ps1` before claiming repository acceptance.
5. Record `VERIFIED`, `INFERRED`, and `UNKNOWN` separately.

## Safety and publication

- YOLO mode changes interaction cadence, not authority.
- No destructive operation, history rewrite, commit, push, public release,
  deployment, dependency installation, or credential use without its applicable
  explicit gate.
- English non-suffixed documentation is authoritative. Important human-facing
  Markdown requires a `.zh-tw.md` companion.
- Internal plans, dispatch records, review notes, and raw evidence are not public
  release content.

## Completion gate

`COMPLETE` requires all enabled acceptance criteria to have observed, reviewable
evidence. Failed, skipped, missing, or unreviewed checks remain `PARTIAL`,
`INCOMPLETE`, or `BLOCKED` as appropriate.
