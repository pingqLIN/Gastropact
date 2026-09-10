# ADR-001: External per-task authority bundles

## Status

Accepted.

## Context

A new Codex session may not have the conversation that defined a task. Repository state, branches, and recent commands then provide tempting but incomplete signals. They cannot identify the user objective, acceptance criteria, forbidden actions, or the exact execution point of a stateful task. Treating them as task authority causes route drift.

## Decision

Use a small directory per task, external to the production repository by default:

- `TASK.json` is the immutable-in-practice authority record.
- `CONTRACT.sha256` seals its canonical bytes. The receiver rejects a changed or unsealed contract.
- `STATE.json` is the compact mutable snapshot.
- `events.jsonl` is append-only audit evidence for major checkpoints.

The receiver must validate, in order: contract schema/seal, project identity, contract authority, and execution state. A repository mismatch produces `STOP`, not task inference. The validator never chooses a branch, fast-forwards, runs a test, or reads task intent from repository state.

## Contract evolution

The author may create a new sealed task that references a predecessor in `authority.supersedes`. Mark the predecessor `SUPERSEDED`. Do not alter objective, acceptance, hard gates, allowed actions, or forbidden actions in place during execution.

## Consequences

This adds two small reads on resume and one small state write per major checkpoint. It does not guarantee that a task author supplied correct facts, validate live external evidence, or prevent a human/operator from deliberately bypassing the procedure. It does make missing authority and repository drift explicit and reviewable.

## Rejected alternatives

- **Put current task state in `AGENTS.md`:** conflates durable project governance with ephemeral task authority, increases every session's prompt load, and spreads stale task state across projects.
- **Infer from repository state:** repository state cannot encode full objective, acceptance, forbidden actions, or the correct stateful next step.
- **One global state file:** creates cross-project collision, large reads, and unclear ownership.
- **Copy full conversations:** high token cost, weak machine validation, and unnecessary retention of unrelated context.
