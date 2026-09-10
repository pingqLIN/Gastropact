#!/usr/bin/env python3
"""Run the source-only repository's deterministic local acceptance gate."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = (
    "AGENTS.md",
    "README.md",
    "README.zh-tw.md",
    "pyproject.toml",
    "schema/task-contract.schema.json",
    "schema/state.schema.json",
    "schema/executor-result.schema.json",
    "scripts/task_contract.py",
    "scripts/task_orchestrator.py",
)
FORBIDDEN_TRACKED_NAMES = {".env", "cookies", "login data", "web data"}


def fail(message: str) -> None:
    print(f"FAIL {message}")
    raise SystemExit(1)


def check_required_files() -> None:
    missing = [relative for relative in REQUIRED_FILES if not (ROOT / relative).is_file()]
    if missing:
        fail("missing required files: " + ", ".join(missing))


def check_json() -> None:
    roots = (ROOT / "schema", ROOT / "templates")
    checked = 0
    for directory in roots:
        for path in sorted(directory.rglob("*.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                fail(f"invalid JSON {path.relative_to(ROOT)}: {error}")
            if not isinstance(value, (dict, list)):
                fail(f"JSON root must be object or array: {path.relative_to(ROOT)}")
            checked += 1
    if checked == 0:
        fail("no JSON documents discovered")
    print(f"PASS json_documents={checked}")


def check_json_schemas() -> None:
    script = r"""
const fs = require("fs");
let Ajv2020;
try {
  Ajv2020 = require("ajv/dist/2020");
} catch (error) {
  console.error(`Ajv Draft 2020-12 validator unavailable: ${error.message}`);
  process.exit(2);
}
const ajvVersion = require("ajv/package.json").version;
if (!ajvVersion.startsWith("8.")) {
  console.error(`Ajv 8 is required, found ${ajvVersion}`);
  process.exit(2);
}
const ajv = new Ajv2020({allErrors: true, strict: true, strictRequired: false, allowUnionTypes: true});
ajv.addFormat("date-time", {
  type: "string",
  validate: (value) => /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$/.test(value) && Number.isFinite(Date.parse(value)),
});
const load = (path) => JSON.parse(fs.readFileSync(path, "utf8"));
const clone = (value) => JSON.parse(JSON.stringify(value));
const schemaPaths = [
  "schema/task-contract.schema.json",
  "schema/state.schema.json",
  "schema/executor-result.schema.json",
  "schema/handoff-task-contract-ref.schema.json",
];
const validators = new Map();
for (const path of schemaPaths) {
  validators.set(path, ajv.compile(load(path)));
}
const taskValidator = validators.get("schema/task-contract.schema.json");
const stateValidator = validators.get("schema/state.schema.json");
const resultValidator = validators.get("schema/executor-result.schema.json");
const handoffValidator = validators.get("schema/handoff-task-contract-ref.schema.json");
const task = load("templates/TASK.json");
const state = load("templates/STATE.json");
const digest = "0".repeat(64);
const result = {
  schema_version: "taskcontracts-executor-result.v2", result_id: "result-1",
  task_id: task.task_id, contract_hash: digest, workspace_baseline_digest: digest,
  lease_nonce: "lease-nonce", state_revision_seen: 0, action_id: "inspect-authority",
  executor: "schema-gate", outcome: "PASS", summary: "Schema gate fixture.", changed_paths: [],
  evidence: [{
    evidence_id: "evidence-1", evidence_class: "repository-authority", task_id: task.task_id,
    contract_hash: digest, state_revision_seen: 0, action_id: "inspect-authority",
    verified_action: "inspect-authority", verifier: "taskcontracts-local-sha256-v1",
    timestamp: "2026-09-03T00:00:00Z", verification_basis: "artifact",
    artifact_path: "evidence/schema-gate.json", artifact_digest: digest, artifact_size: 0,
  }],
  verification: {status: "PASS", checks: [{check_id: "schema", status: "PASS", summary: "Valid.", evidence_ids: ["evidence-1"]}]},
};
const handoff = {taskContractRef: {
  taskId: task.task_id, schemaVersion: "task-contract.v1.1", contractSha256: digest,
  stateRevision: 0, authorityRole: "external-task-definition", verificationRequired: true,
}};
const requireValid = (validator, value, label) => {
  if (!validator(value)) {
    console.error(`${label} unexpectedly invalid: ${ajv.errorsText(validator.errors)}`);
    process.exit(3);
  }
};
const requireInvalid = (validator, value, label) => {
  if (validator(value)) {
    console.error(`${label} unexpectedly passed schema validation`);
    process.exit(4);
  }
};
requireValid(taskValidator, task, "v1.2 TASK template");
requireValid(stateValidator, state, "v1.2 STATE template");
requireValid(resultValidator, result, "executor result v2 fixture");
requireValid(handoffValidator, handoff, "handoff adapter fixture");
const negativeCases = [
  [taskValidator, {...clone(task), authority_order: task.authority_order.slice(0, 7)}, "TASK authority_order minItems"],
  [taskValidator, {...clone(task), hard_gates: []}, "TASK hard_gates minItems"],
  [taskValidator, (() => { const value = clone(task); value.allowed_actions[0].allowed_workspace_paths = ["../outside"]; return value; })(), "TASK workspace traversal"],
  [stateValidator, {...clone(state), benchmark_progress: "invalid"}, "STATE benchmark_progress enum"],
  [taskValidator, {...clone(task), authority: {...task.authority, issued_at: "not-a-date"}}, "TASK authority date-time"],
  [taskValidator, (() => { const value = clone(task); value.project.git.authorized_commits[0].commit = "not-a-hash"; return value; })(), "TASK commit hash"],
  [taskValidator, {...clone(task), task_type: "invalid"}, "TASK task_type enum"],
  [stateValidator, {...clone(state), revision: "0"}, "STATE revision type"],
  [stateValidator, {...clone(state), status: "PASS", next_action_id: null, next_action: null}, "STATE terminal action null"],
  [stateValidator, {...clone(state), status: "PASS", resume_from: "inspect-authority"}, "STATE terminal resume null"],
  [resultValidator, {...clone(result), result_id: "../unsafe"}, "executor result opaque id"],
  [resultValidator, (() => { const value = clone(result); delete value.evidence[0].artifact_size; return value; })(), "executor artifact evidence binding"],
  [handoffValidator, {taskContractRef: {...handoff.taskContractRef, contractSha256: "invalid"}}, "handoff contract hash"],
];
for (const [validator, value, label] of negativeCases) {
  requireInvalid(validator, value, label);
}
console.log(`PASS ajv=${ajvVersion} schemas=${schemaPaths.length} positive=4 negative=${negativeCases.length}`);
"""
    try:
        completed = subprocess.run(
            ["node", "-e", script],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        fail(f"Node.js/Ajv Draft 2020-12 validator unavailable: {error}")
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        fail(f"JSON Schema Draft 2020-12 validation failed: {detail}")
    print(completed.stdout.strip())


def check_python_syntax() -> None:
    checked = 0
    for directory in (ROOT / "scripts", ROOT / "automation", ROOT / "tests"):
        for path in sorted(directory.rglob("*.py")):
            try:
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (OSError, UnicodeError, SyntaxError) as error:
                fail(f"invalid Python {path.relative_to(ROOT)}: {error}")
            checked += 1
    print(f"PASS python_syntax={checked}")


def check_publication_boundary() -> None:
    for path in ROOT.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        if path.name.casefold() in FORBIDDEN_TRACKED_NAMES:
            fail(f"forbidden sensitive filename: {path.relative_to(ROOT)}")
    for english in ROOT.rglob("*.md"):
        if english.name.endswith(".zh-tw.md") or "internal" not in english.parts:
            continue
        companion = english.with_name(f"{english.stem}.zh-tw.md")
        if english.name == "README.md":
            companion = english.with_name("README.zh-tw.md")
        if not companion.is_file():
            fail(f"missing zh-tw companion for {english.relative_to(ROOT)}")
    print("PASS source_runtime_boundary")


def run_tests() -> None:
    completed = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        fail(f"unit tests exited {completed.returncode}")
    print("PASS unit_tests")


def main() -> int:
    check_required_files()
    check_json()
    check_json_schemas()
    check_python_syntax()
    check_publication_boundary()
    run_tests()
    print("PASS repository_gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
