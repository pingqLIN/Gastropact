#!/usr/bin/env python3
"""Single-owner local automation for sealed TaskContracts v1.2 bundles.

The legacy ``task_contract.py`` CLI remains the compatibility authority for
sealing and read-only intake. This module adds an opt-in executor-result path:
only this process writes STATE.json/events.jsonl for an automated transition.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

import task_contract as contract_runtime


OUTCOMES = {"PASS", "BLOCKED", "FAILED", "RETRYABLE"}
RESULT_SCHEMA_VERSION = "taskcontracts-executor-result.v2"
RESULT_FIELDS = {
    "schema_version", "result_id", "task_id", "contract_hash", "state_revision_seen", "action_id",
    "executor", "outcome", "summary", "changed_paths", "evidence", "verification",
    "workspace_baseline_digest", "lease_nonce",
}
OPTIONAL_RESULT_FIELDS = {"blocker_code", "blocker_detail", "recommended_next_action"}
EVIDENCE_FIELDS = {
    "evidence_id", "evidence_class", "task_id", "contract_hash",
    "state_revision_seen", "action_id", "verified_action", "verifier", "timestamp",
    "verification_basis",
}
OPTIONAL_EVIDENCE_FIELDS = {"artifact_path", "artifact_digest", "artifact_size", "runtime_metadata"}
VERIFICATION_CHECK_FIELDS = {"check_id", "status", "summary", "evidence_ids"}
STATE_EVENT_NAMES = {"created", "gate_recorded", "checkpoint", "automation_transition"}
LIFECYCLE_EVENT_NAMES = {
    "automation_dispatched", "automation_lease_released",
    "automation_lease_recovered", "contract_resealed",
}
RUNTIME_DIR = ".automation"
JOURNAL_SCHEMA_VERSION = "taskcontracts-transition-journal.v1"
RECEIPT_SCHEMA_VERSION = "taskcontracts-result-receipt.v1"
WORKSPACE_BASELINE_SCHEMA_VERSION = "taskcontracts-workspace-baseline.v1"
RESULT_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
LOCAL_ARTIFACT_VERIFIER = "taskcontracts-local-sha256-v1"
LEASE_RECOVERY_AUTH_FIELDS = {
    "schema_version", "source", "task_id", "contract_hash", "state_revision",
    "old_lease_digest", "new_owner", "operator", "scope", "approved_at",
}
FAULT_AFTER_WAL = "AFTER_WAL_WRITE"
FAULT_AFTER_STATE = "AFTER_STATE_WRITE"
FAULT_AFTER_EVENT = "AFTER_EVENT_APPEND"
FAULT_AFTER_RECEIPT = "AFTER_RECEIPT_WRITE"
FAULT_AFTER_SUCCESSOR_BASELINE = "AFTER_SUCCESSOR_BASELINE_WRITE"
FAULT_AFTER_SUCCESSOR_ENVELOPE = "AFTER_SUCCESSOR_ENVELOPE_WRITE"
FAULT_AFTER_SUCCESSOR_EVENT = "AFTER_SUCCESSOR_EVENT_APPEND"


class AutomationError(ValueError):
    """A stable, fail-closed automation error."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_json(value: dict[str, Any]) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def json_file_sha256(value: dict[str, Any]) -> str:
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _fault_hook(name: str) -> None:
    """Named no-op fault boundary patched only by focused tests."""


def require_opaque_result_id(value: object) -> str:
    if not isinstance(value, str) or RESULT_ID_PATTERN.fullmatch(value) is None:
        raise AutomationError(
            "FAILED_RESULT_SCHEMA",
            "result_id must be an opaque 1-128 character ASCII identifier using only letters, digits, '_' or '-'",
        )
    return value


def runtime_dir(task: Path) -> Path:
    return task / RUNTIME_DIR


def runtime_paths(task: Path) -> dict[str, Path]:
    root = runtime_dir(task)
    return {
        "root": root,
        "lease": root / "lease.json",
        "lease_journal": root / "lease-recovery.json",
        "journal": root / "transition.json",
        "envelopes": root / "envelopes",
        "results": root / "results",
        "baselines": root / "baselines",
    }


def ensure_runtime_dirs(task: Path) -> dict[str, Path]:
    paths = runtime_paths(task)
    paths["root"].mkdir(exist_ok=True)
    paths["envelopes"].mkdir(exist_ok=True)
    paths["results"].mkdir(exist_ok=True)
    paths["baselines"].mkdir(exist_ok=True)
    return paths


def read_json(path: Path, error_code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AutomationError(error_code, f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise AutomationError(error_code, f"{path.name} must contain a JSON object")
    return value


def print_stop(error: AutomationError) -> int:
    print(f"STOP {error.code}")
    print(f"- {error.detail}")
    return 42


def load_authority(
    task: Path,
    project: Path,
    *,
    enforce_audit: bool = True,
    allow_dirty_worktree: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    contract, state, issues = contract_runtime.inspect(
        task,
        project,
        enforce_audit=enforce_audit,
        allow_dirty_worktree=allow_dirty_worktree,
    )
    if issues:
        raise AutomationError("BLOCKED_CONTRACT_INVALID", "; ".join(issue.message for issue in issues))
    if contract.get("schema_version") != contract_runtime.TASK_V12:
        raise AutomationError("BLOCKED_CONTRACT_INVALID", "automation requires an existing sealed TaskContracts v1.2 bundle")
    return contract, state


def action_for(contract: dict[str, Any], action_id: str) -> dict[str, Any]:
    action = contract_runtime.action_map(contract).get(action_id)
    if not action:
        raise AutomationError("BLOCKED_CONTRACT_INVALID", f"unknown action id: {action_id}")
    return action


def normalize_relative(path: str) -> str:
    value = path.replace("\\", "/")
    candidate = PurePosixPath(value)
    if not value or candidate.is_absolute() or ".." in candidate.parts:
        raise AutomationError("BLOCKED_SCOPE_CONFLICT", f"path is outside the allowed project scope: {path}")
    return candidate.as_posix().removeprefix("./")


def validate_changed_paths(action: dict[str, Any], changed_paths: list[Any]) -> list[str]:
    if not isinstance(changed_paths, list) or not all(isinstance(item, str) for item in changed_paths):
        raise AutomationError("FAILED_RESULT_SCHEMA", "changed_paths must be an array of relative paths")
    allowed = action["allowed_workspace_paths"]
    if not isinstance(allowed, list) or not all(isinstance(item, str) for item in allowed):
        raise AutomationError("BLOCKED_CONTRACT_INVALID", "automated action requires allowed_workspace_paths")
    roots = [normalize_relative(item).rstrip("/") for item in allowed]
    normalized = [normalize_relative(item) for item in changed_paths]
    for candidate in normalized:
        if not any(root in {"", "."} or candidate == root or candidate.startswith(root + "/") for root in roots):
            raise AutomationError("BLOCKED_SCOPE_CONFLICT", f"executor reported a changed path outside action scope: {candidate}")
    return normalized


def _git_value(project: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(project), *args], text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise AutomationError("BLOCKED_WORKSPACE_INVALID", f"Git command failed: {' '.join(args)}")
    return result.stdout.strip()


def workspace_file_manifest(project: Path, task: Path | None = None) -> dict[str, str]:
    project_root = project.resolve()
    excluded_root: Path | None = None
    if task is not None:
        resolved_task = task.resolve()
        if resolved_task == project_root:
            raise AutomationError("BLOCKED_WORKSPACE_INVALID", "task control root cannot equal the project root")
        if resolved_task.is_relative_to(project_root):
            excluded_root = resolved_task
    manifest: dict[str, str] = {}
    try:
        for current, directory_names, file_names in os.walk(project_root, followlinks=False):
            current_path = Path(current)
            retained_directories: list[str] = []
            for name in directory_names:
                candidate = current_path / name
                if name == ".git" or (excluded_root is not None and (candidate == excluded_root or candidate.is_relative_to(excluded_root))):
                    continue
                if candidate.is_symlink() or (hasattr(candidate, "is_junction") and candidate.is_junction()):
                    raise AutomationError("BLOCKED_WORKSPACE_INVALID", f"workspace contains an unverified linked directory: {candidate.relative_to(project_root).as_posix()}")
                retained_directories.append(name)
            directory_names[:] = retained_directories
            for name in file_names:
                path = current_path / name
                if excluded_root is not None and (path == excluded_root or path.is_relative_to(excluded_root)):
                    continue
                if path.is_symlink():
                    raise AutomationError("BLOCKED_WORKSPACE_INVALID", f"workspace contains an unverified linked file: {path.relative_to(project_root).as_posix()}")
                digest = hashlib.sha256()
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                manifest[path.relative_to(project_root).as_posix()] = digest.hexdigest()
    except AutomationError:
        raise
    except OSError as error:
        raise AutomationError("BLOCKED_WORKSPACE_INVALID", f"cannot hash workspace: {error}") from error
    return dict(sorted(manifest.items()))


def workspace_index_manifest(project: Path) -> dict[str, list[str]]:
    result = subprocess.run(
        ["git", "-C", str(project), "ls-files", "--stage", "-z"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise AutomationError("BLOCKED_WORKSPACE_INVALID", "cannot observe Git index")
    manifest: dict[str, list[str]] = {}
    try:
        records = result.stdout.decode("utf-8", errors="strict").split("\0")
    except UnicodeDecodeError as error:
        raise AutomationError("BLOCKED_WORKSPACE_INVALID", "Git index contains a non-UTF-8 path") from error
    for record in records:
        if not record:
            continue
        metadata, separator, raw_path = record.partition("\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise AutomationError("BLOCKED_WORKSPACE_INVALID", "unexpected Git index record")
        path = normalize_relative(raw_path)
        manifest.setdefault(path, []).append(" ".join(fields))
    return {path: sorted(entries) for path, entries in sorted(manifest.items())}


def observe_workspace(project: Path, task: Path | None = None) -> dict[str, Any]:
    status = subprocess.run(
        ["git", "-C", str(project), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        capture_output=True,
        check=False,
    )
    if status.returncode != 0:
        raise AutomationError("BLOCKED_WORKSPACE_INVALID", "cannot observe Git workspace delta")
    records = status.stdout.decode("utf-8", errors="strict").split("\0")
    changed: set[str] = set()
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if not record:
            continue
        if len(record) < 4 or record[2] != " ":
            raise AutomationError("BLOCKED_WORKSPACE_INVALID", "unexpected Git porcelain record")
        code = record[:2]
        changed.add(normalize_relative(record[3:]))
        if "R" in code or "C" in code:
            if index >= len(records) or not records[index]:
                raise AutomationError("BLOCKED_WORKSPACE_INVALID", "incomplete Git rename/copy record")
            changed.add(normalize_relative(records[index]))
            index += 1
    return {
        "project_root": os.path.normcase(os.path.abspath(str(project))),
        "head": _git_value(project, "rev-parse", "HEAD"),
        "branch": _git_value(project, "branch", "--show-current"),
        "actual_delta": sorted(changed),
        "file_manifest": workspace_file_manifest(project, task),
        "index_manifest": workspace_index_manifest(project),
    }


def _baseline_binding(baseline: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in baseline.items() if key != "workspace_baseline_digest"}


def capture_workspace_baseline(
    task: Path,
    project: Path,
    contract: dict[str, Any],
    state: dict[str, Any],
) -> dict[str, Any]:
    observation = observe_workspace(project, task)
    path = runtime_paths(task)["baselines"] / f"r{state['revision']}.json"
    if path.exists():
        existing = read_json(path, "FAILED_WORKSPACE_BASELINE")
        digest = sha256_json(_baseline_binding(existing))
        if (
            existing.get("workspace_baseline_digest") != digest
            or existing.get("task_id") != contract.get("task_id")
            or existing.get("contract_digest") != contract_runtime.canonical_sha256(task / "TASK.json")
            or existing.get("state_revision") != state.get("revision")
            or existing.get("action_id") != state.get("next_action_id")
            or any(existing.get(key) != value for key, value in observation.items())
        ):
            raise AutomationError("FAILED_WORKSPACE_BASELINE", "workspace baseline already exists with different content")
        return existing
    baseline = {
        "schema_version": WORKSPACE_BASELINE_SCHEMA_VERSION,
        "captured_at": now(),
        "task_id": contract["task_id"],
        "contract_digest": contract_runtime.canonical_sha256(task / "TASK.json"),
        "state_revision": state["revision"],
        "action_id": state["next_action_id"],
        **observation,
    }
    baseline["workspace_baseline_digest"] = sha256_json(baseline)
    contract_runtime.atomic_write_json(path, baseline)
    return baseline


def load_workspace_baseline(
    task: Path,
    contract: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    path = runtime_paths(task)["baselines"] / f"r{result['state_revision_seen']}.json"
    baseline = read_json(path, "FAILED_WORKSPACE_BASELINE")
    fields = {
        "schema_version", "captured_at", "task_id", "contract_digest",
        "state_revision", "action_id", "project_root", "head", "branch",
        "actual_delta", "file_manifest", "index_manifest", "workspace_baseline_digest",
    }
    if set(baseline) != fields or baseline.get("schema_version") != WORKSPACE_BASELINE_SCHEMA_VERSION:
        raise AutomationError("FAILED_WORKSPACE_BASELINE", "workspace baseline fields are invalid")
    digest = sha256_json(_baseline_binding(baseline))
    if baseline.get("workspace_baseline_digest") != digest or result.get("workspace_baseline_digest") != digest:
        raise AutomationError("FAILED_WORKSPACE_BASELINE", "workspace baseline digest is stale or mismatched")
    if (
        baseline.get("task_id") != contract.get("task_id")
        or baseline.get("contract_digest") != contract_runtime.canonical_sha256(task / "TASK.json")
        or baseline.get("state_revision") != result.get("state_revision_seen")
        or baseline.get("action_id") != result.get("action_id")
    ):
        raise AutomationError("FAILED_WORKSPACE_BASELINE", "workspace baseline authority binding is invalid")
    return baseline


def verify_workspace_result(
    task: Path,
    project: Path,
    contract: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    baseline = load_workspace_baseline(task, contract, result)
    actual = observe_workspace(project, task)
    if actual["project_root"] != baseline["project_root"] or actual["head"] != baseline["head"] or actual["branch"] != baseline["branch"]:
        raise AutomationError("BLOCKED_WORKSPACE_INVALID", "workspace root, HEAD, or branch changed after dispatch")
    before_manifest = baseline.get("file_manifest")
    after_manifest = actual.get("file_manifest")
    before_index = baseline.get("index_manifest")
    after_index = actual.get("index_manifest")
    if not all(isinstance(item, dict) for item in (before_manifest, after_manifest, before_index, after_index)):
        raise AutomationError("FAILED_WORKSPACE_BASELINE", "workspace baseline manifests are invalid")
    file_delta = {
        path
        for path in set(before_manifest) | set(after_manifest)
        if before_manifest.get(path) != after_manifest.get(path)
    }
    index_delta = {
        path
        for path in set(before_index) | set(after_index)
        if before_index.get(path) != after_index.get(path)
    }
    status_delta = set(baseline.get("actual_delta", [])) ^ set(actual.get("actual_delta", []))
    actual_relative_delta = sorted(file_delta | index_delta | status_delta)
    reported = validate_changed_paths(action_for(contract, result["action_id"]), result["changed_paths"])
    if sorted(set(reported)) != actual_relative_delta:
        raise AutomationError(
            "BLOCKED_SCOPE_CONFLICT",
            f"executor changed_paths do not exactly match observed workspace delta: reported={sorted(set(reported))}, actual={actual_relative_delta}",
        )
    actual["verified_relative_delta"] = actual_relative_delta
    return actual


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def is_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.utcoffset() is not None


def non_empty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def validate_evidence_item(
    item: Any,
    result: dict[str, Any],
    allowed_classes: set[str],
    action: dict[str, Any],
    project: Path,
) -> str:
    if not isinstance(item, dict):
        return "evidence items must be objects"
    missing = EVIDENCE_FIELDS - item.keys()
    unknown = set(item) - (EVIDENCE_FIELDS | OPTIONAL_EVIDENCE_FIELDS)
    if missing:
        return "evidence item missing " + ", ".join(sorted(missing))
    if unknown:
        return "evidence item has unknown fields: " + ", ".join(sorted(unknown))
    for field in ("evidence_id", "evidence_class", "task_id", "action_id", "verified_action", "verifier"):
        if not non_empty_string(item[field]):
            return f"evidence {field} must be a non-empty string"
    if not is_sha256(item["contract_hash"]):
        return "evidence contract_hash must be a lowercase SHA-256 digest"
    revision = item["state_revision_seen"]
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        return "evidence state_revision_seen must be a non-negative integer"
    if not is_timestamp(item["timestamp"]):
        return "evidence timestamp must be an offset-aware date-time"
    basis = item.get("verification_basis")
    if basis != "artifact":
        return "evidence verification_basis must be artifact; no trusted verifier is configured"
    if item.get("verifier") != LOCAL_ARTIFACT_VERIFIER:
        return f"artifact evidence verifier must be {LOCAL_ARTIFACT_VERIFIER}"
    artifact_fields = {"artifact_path", "artifact_digest", "artifact_size"}
    present_artifact_fields = artifact_fields.intersection(item)
    if basis == "artifact" and present_artifact_fields != artifact_fields:
        return "artifact evidence requires artifact_path, artifact_digest, and artifact_size"
    if basis == "artifact":
        if (
            not non_empty_string(item["artifact_path"])
            or not is_sha256(item["artifact_digest"])
            or not isinstance(item["artifact_size"], int)
            or isinstance(item["artifact_size"], bool)
            or item["artifact_size"] < 0
        ):
            return "evidence artifact binding is invalid"
        try:
            relative = normalize_relative(item["artifact_path"])
            validate_changed_paths(action, [relative])
        except AutomationError:
            return "evidence artifact_path must be project-relative and inside the action workspace scope"
        declared_changes = {normalize_relative(path) for path in result.get("changed_paths", []) if isinstance(path, str)}
        if relative not in declared_changes:
            return "evidence artifact_path must be declared as an action-produced changed path"
        project_root = project.resolve()
        try:
            artifact = (project_root / Path(relative)).resolve(strict=True)
            if not artifact.is_relative_to(project_root):
                return "evidence artifact resolves outside the project root"
            if not artifact.is_file():
                return "evidence artifact is unavailable or is not a regular file"
            if artifact.stat().st_size != item["artifact_size"]:
                return "evidence artifact size does not match"
            if contract_runtime.file_sha256(artifact) != item["artifact_digest"]:
                return "evidence artifact digest does not match"
        except OSError:
            return "evidence artifact cannot be verified"
    if "runtime_metadata" in item and not isinstance(item["runtime_metadata"], dict):
        return "evidence runtime_metadata must be an object"
    for field in ("task_id", "contract_hash", "state_revision_seen", "action_id"):
        if item[field] != result[field]:
            return f"evidence {field} does not match the sealed result binding"
    if item["verified_action"] != result["action_id"]:
        return "evidence verified_action does not match action_id"
    if item["evidence_class"] not in allowed_classes:
        return f"evidence class is not allowed for this action: {item['evidence_class']}"
    return ""


def validate_result(result: dict[str, Any], contract: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    missing = RESULT_FIELDS - result.keys()
    unknown = set(result) - (RESULT_FIELDS | OPTIONAL_RESULT_FIELDS)
    if missing or unknown:
        detail = []
        if missing:
            detail.append("missing " + ", ".join(sorted(missing)))
        if unknown:
            detail.append("unknown " + ", ".join(sorted(unknown)))
        raise AutomationError("FAILED_RESULT_SCHEMA", "; ".join(detail))
    if result["schema_version"] != RESULT_SCHEMA_VERSION:
        raise AutomationError("FAILED_RESULT_SCHEMA", f"schema_version must be {RESULT_SCHEMA_VERSION}")
    require_opaque_result_id(result["result_id"])
    if not non_empty_string(result["task_id"]) or result["task_id"] != contract["task_id"]:
        raise AutomationError("FAILED_VERIFICATION", "result task_id does not match the sealed task")
    if not is_sha256(result["workspace_baseline_digest"]):
        raise AutomationError("FAILED_RESULT_SCHEMA", "workspace_baseline_digest must be a lowercase SHA-256 digest")
    if not non_empty_string(result["lease_nonce"]):
        raise AutomationError("FAILED_RESULT_SCHEMA", "lease_nonce must be a non-empty string")
    if not is_sha256(result["contract_hash"]) or result["contract_hash"] != contract_runtime.canonical_sha256(Path(state["_task_path"]) / "TASK.json"):
        raise AutomationError("FAILED_VERIFICATION", "result contract_hash is stale or mismatched")
    if not isinstance(result["state_revision_seen"], int) or isinstance(result["state_revision_seen"], bool) or result["state_revision_seen"] < 0 or result["state_revision_seen"] != state["revision"]:
        raise AutomationError("FAILED_VERIFICATION", "result state_revision_seen is stale or mismatched")
    if not non_empty_string(result["action_id"]) or result["action_id"] != state["next_action_id"]:
        raise AutomationError("FAILED_VERIFICATION", "result action_id is stale or mismatched")
    if not non_empty_string(result["executor"]):
        raise AutomationError("FAILED_RESULT_SCHEMA", "executor must be a non-empty string")
    if not isinstance(result["outcome"], str) or result["outcome"] not in OUTCOMES or not non_empty_string(result["summary"]):
        raise AutomationError("FAILED_RESULT_SCHEMA", "outcome or summary is invalid")
    if not isinstance(result["evidence"], list) or not isinstance(result["verification"], dict):
        raise AutomationError("FAILED_RESULT_SCHEMA", "evidence and verification must be structured values")
    verification = result["verification"]
    checks = verification.get("checks")
    if set(verification) != {"status", "checks"} or verification.get("status") not in {"PASS", "FAILED", "NOT_RUN"} or not isinstance(checks, list):
        raise AutomationError("FAILED_RESULT_SCHEMA", "verification must contain status and checks")
    check_ids: set[str] = set()
    for check in checks:
        if not isinstance(check, dict) or set(check) != VERIFICATION_CHECK_FIELDS:
            raise AutomationError("FAILED_RESULT_SCHEMA", "verification checks must be strict structured records")
        if (
            not non_empty_string(check.get("check_id"))
            or check.get("status") not in {"PASS", "FAILED", "NOT_RUN"}
            or not non_empty_string(check.get("summary"))
            or not isinstance(check.get("evidence_ids"), list)
            or not check["evidence_ids"]
            or not all(non_empty_string(value) for value in check["evidence_ids"])
        ):
            raise AutomationError("FAILED_RESULT_SCHEMA", "verification check fields are invalid")
        if check["check_id"] in check_ids:
            raise AutomationError("FAILED_RESULT_SCHEMA", f"duplicate verification check_id: {check['check_id']}")
        check_ids.add(check["check_id"])
    action = action_for(contract, state["next_action_id"])
    allowed_classes = set(action["required_evidence_classes"])
    evidence_ids: set[str] = set()
    evidence_classes: set[str] = set()
    for item in result["evidence"]:
        error = validate_evidence_item(item, result, allowed_classes, action, Path(state["_project_path"]))
        if error:
            raise AutomationError("FAILED_RESULT_SCHEMA", error)
        if item["evidence_id"] in evidence_ids:
            raise AutomationError("FAILED_RESULT_SCHEMA", f"duplicate evidence_id: {item['evidence_id']}")
        evidence_ids.add(item["evidence_id"])
        evidence_classes.add(item["evidence_class"])
    referenced_evidence = {evidence_id for check in checks for evidence_id in check["evidence_ids"]}
    if referenced_evidence - evidence_ids:
        raise AutomationError("FAILED_VERIFICATION", "verification check references unknown evidence")
    if result["outcome"] == "PASS" and (
        verification["status"] != "PASS"
        or not checks
        or not result["evidence"]
        or any(check["status"] != "PASS" for check in checks)
        or referenced_evidence != evidence_ids
    ):
        raise AutomationError("FAILED_VERIFICATION", "PASS requires PASS verification, checks, and non-empty evidence")
    if result["outcome"] == "PASS" and not allowed_classes.issubset(evidence_classes):
        missing_classes = ", ".join(sorted(allowed_classes - evidence_classes))
        raise AutomationError("FAILED_VERIFICATION", f"PASS is missing required evidence classes: {missing_classes}")
    if result["outcome"] == "BLOCKED" and not non_empty_string(result.get("blocker_code")):
        raise AutomationError("FAILED_RESULT_SCHEMA", "BLOCKED requires blocker_code")
    for field in OPTIONAL_RESULT_FIELDS:
        if field in result and result[field] is not None and not non_empty_string(result[field]):
            raise AutomationError("FAILED_RESULT_SCHEMA", f"{field} must be a non-empty string or null")
    validated = dict(result)
    validated["changed_paths"] = validate_changed_paths(action, result["changed_paths"])
    return validated


def read_lease(paths: dict[str, Path]) -> dict[str, Any] | None:
    return read_json(paths["lease"], "BLOCKED_LEASE_CONFLICT") if paths["lease"].exists() else None


def lease_expired(lease: dict[str, Any]) -> bool:
    try:
        return datetime.fromisoformat(lease["expires_at"].replace("Z", "+00:00")) <= datetime.now(timezone.utc)
    except (KeyError, ValueError, TypeError):
        return False


def _validate_lease(
    lease: dict[str, Any],
    task_id: str,
    owner: str | None,
    nonce: str | None = None,
    *,
    require_unexpired: bool = True,
) -> None:
    fields = {"task_id", "owner", "acquired_at", "expires_at", "nonce"}
    if set(lease) != fields or lease.get("task_id") != task_id or (owner is not None and lease.get("owner") != owner):
        raise AutomationError("BLOCKED_LEASE_CONFLICT", "active lease identity does not match task and owner")
    if not non_empty_string(lease.get("owner")) or not non_empty_string(lease.get("nonce")) or not is_timestamp(lease.get("acquired_at")) or not is_timestamp(lease.get("expires_at")):
        raise AutomationError("BLOCKED_LEASE_CONFLICT", "active lease fields are invalid")
    if require_unexpired and lease_expired(lease):
        raise AutomationError("BLOCKED_LEASE_EXPIRED", "lease is expired and cannot be automatically recovered or replaced")
    if nonce is not None and lease.get("nonce") != nonce:
        raise AutomationError("BLOCKED_LEASE_CONFLICT", "result lease_nonce does not match the active lease")


def acquire_lease(paths: dict[str, Path], task_id: str, owner: str) -> dict[str, Any]:
    lease = read_lease(paths)
    if lease is None:
        lease = {
            "task_id": task_id,
            "owner": owner,
            "acquired_at": now(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=15)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "nonce": secrets.token_hex(16),
        }
        contract_runtime.atomic_write_json(paths["lease"], lease)
        return lease
    _validate_lease(lease, task_id, owner)
    return lease


def require_active_lease(paths: dict[str, Path], task_id: str, owner: str, nonce: str) -> dict[str, Any]:
    lease = read_lease(paths)
    if lease is None:
        raise AutomationError("BLOCKED_LEASE_CONFLICT", "result has no active dispatch lease")
    _validate_lease(lease, task_id, owner, nonce)
    return lease


def nonce_digest(nonce: str) -> str:
    return hashlib.sha256(nonce.encode("utf-8")).hexdigest()


def validate_lease_recovery_authorization(
    authorization: dict[str, Any],
    contract: dict[str, Any],
    state: dict[str, Any],
    expected_lease_digest: str,
    new_owner: str,
    operator: str,
    task: Path,
    validation_time: datetime | None = None,
) -> str:
    if set(authorization) != LEASE_RECOVERY_AUTH_FIELDS:
        raise AutomationError("BLOCKED_LEASE_RECOVERY", "lease recovery authorization fields are invalid")
    contract_hash = contract_runtime.canonical_sha256(task / "TASK.json")
    exact = {
        "schema_version": "taskcontracts-lease-recovery-authorization.v1",
        "source": "explicit-user",
        "task_id": contract["task_id"],
        "contract_hash": contract_hash,
        "state_revision": state["revision"],
        "old_lease_digest": expected_lease_digest,
        "new_owner": new_owner,
        "operator": operator,
        "scope": "recover-expired-lease",
    }
    for field, value in exact.items():
        if authorization.get(field) != value:
            raise AutomationError("BLOCKED_LEASE_RECOVERY", f"lease recovery authorization {field} binding is invalid")
    if not is_timestamp(authorization.get("approved_at")):
        raise AutomationError("BLOCKED_LEASE_RECOVERY", "lease recovery authorization approved_at is invalid")
    approved = datetime.fromisoformat(authorization["approved_at"].replace("Z", "+00:00"))
    state_updated = datetime.fromisoformat(state["updated_at"].replace("Z", "+00:00"))
    current = validation_time or datetime.now(timezone.utc)
    if approved < state_updated or approved > current + timedelta(minutes=1) or current - approved > timedelta(minutes=15):
        raise AutomationError("BLOCKED_LEASE_RECOVERY", "lease recovery authorization is stale or not bound after the current state")
    return sha256_json(authorization)


def recover_lease_journal(task: Path, contract: dict[str, Any]) -> None:
    paths = runtime_paths(task)
    journal_path = paths["lease_journal"]
    if not journal_path.exists():
        return
    journal = read_json(journal_path, "FAILED_LEASE_RECOVERY")
    fields = {"schema_version", "task_id", "from_lease", "from_digest", "target_lease", "target_digest", "authorization", "authorization_digest", "event", "event_digest", "journal_digest"}
    if set(journal) != fields or journal.get("schema_version") != "taskcontracts-lease-recovery.v1" or journal.get("task_id") != contract.get("task_id"):
        raise AutomationError("FAILED_LEASE_RECOVERY", "lease recovery journal identity is invalid")
    journal_base = {key: value for key, value in journal.items() if key != "journal_digest"}
    if sha256_json(journal_base) != journal.get("journal_digest"):
        raise AutomationError("FAILED_LEASE_RECOVERY", "lease recovery journal digest is invalid")
    source, target, event = journal.get("from_lease"), journal.get("target_lease"), journal.get("event")
    if not all(isinstance(item, dict) for item in (source, target, event)):
        raise AutomationError("FAILED_LEASE_RECOVERY", "lease recovery journal payload is invalid")
    if sha256_json(source) != journal.get("from_digest") or sha256_json(target) != journal.get("target_digest") or sha256_json(event) != journal.get("event_digest"):
        raise AutomationError("FAILED_LEASE_RECOVERY", "lease recovery journal digest binding is invalid")
    if not isinstance(journal.get("authorization"), dict) or sha256_json(journal["authorization"]) != journal.get("authorization_digest") or event.get("authorization_digest") != journal.get("authorization_digest"):
        raise AutomationError("FAILED_LEASE_RECOVERY", "lease recovery authorization journal binding is invalid")
    if not is_timestamp(event.get("at")) or not non_empty_string(event.get("operator")):
        raise AutomationError("FAILED_LEASE_RECOVERY", "lease recovery event authorization identity is invalid")
    state = read_json(task / "STATE.json", "FAILED_LEASE_RECOVERY")
    validated_authorization_digest = validate_lease_recovery_authorization(
        journal["authorization"], contract, state, nonce_digest(source["nonce"]),
        target["owner"], event.get("operator"), task,
        datetime.fromisoformat(event["at"].replace("Z", "+00:00")),
    )
    if validated_authorization_digest != journal["authorization_digest"]:
        raise AutomationError("FAILED_LEASE_RECOVERY", "lease recovery authorization cannot be revalidated")
    _validate_lease(source, contract["task_id"], None, require_unexpired=False)
    # Replay validates the journal-bound target identity, not its current age.
    # A long outage may outlive the replacement lease; the committed recovery
    # must converge before a later, separately authorized takeover can occur.
    _validate_lease(target, contract["task_id"], None, require_unexpired=False)
    current = read_lease(paths)
    if current == source:
        contract_runtime.atomic_write_json(paths["lease"], target)
    elif current != target:
        raise AutomationError("FAILED_LEASE_RECOVERY", "current lease is neither the journal source nor target")
    matches = [
        item for item in _read_events(task)
        if item.get("event") == "automation_lease_recovered"
        and item.get("new_nonce_digest") == event.get("new_nonce_digest")
    ]
    if len(matches) > 1 or (matches and matches[0] != event):
        raise AutomationError("FAILED_LEASE_RECOVERY", "lease recovery audit conflicts with the journal")
    if not matches:
        append_lifecycle_event(task, event)
    if read_lease(paths) != target:
        raise AutomationError("FAILED_LEASE_RECOVERY", "lease recovery target verification failed")
    journal_path.unlink(missing_ok=True)


def ensure_lease_released(
    task: Path,
    contract: dict[str, Any],
    state: dict[str, Any],
    owner: str,
    nonce: str,
) -> None:
    """Idempotently retire a task-session lease at a non-READY boundary."""
    if state.get("status") == "READY":
        return
    paths = runtime_paths(task)
    lease = read_lease(paths)
    if lease is None:
        raise AutomationError("FAILED_LEASE_RECOVERY", "completed transition has no lease to retire")
    _validate_lease(lease, contract["task_id"], owner, nonce, require_unexpired=False)
    released = dict(lease)
    released["expires_at"] = state["updated_at"]
    if lease != released:
        contract_runtime.atomic_write_json(paths["lease"], released)
    expected_event = {
        "at": state["updated_at"],
        "event": "automation_lease_released",
        "task_id": contract["task_id"],
        "revision": state["revision"],
        "action_id": state["last_completed_action_id"] or state["next_action_id"],
        "owner": owner,
        "nonce_digest": nonce_digest(nonce),
    }
    matches = [
        event for event in _read_events(task)
        if event.get("event") == "automation_lease_released"
        and event.get("revision") == state["revision"]
    ]
    if len(matches) > 1 or (matches and matches[0] != expected_event):
        raise AutomationError("FAILED_LEASE_RECOVERY", "lease release audit conflicts with the transition boundary")
    if not matches:
        append_lifecycle_event(task, expected_event)


def command_recover_lease(args: argparse.Namespace) -> int:
    task, project = Path(args.task), Path(args.project)
    try:
        if not all(non_empty_string(getattr(args, field, None)) for field in ("new_owner", "operator", "reason")):
            raise AutomationError("BLOCKED_LEASE_RECOVERY", "new owner, operator, and reason must be non-empty")
        if not is_sha256(getattr(args, "expected_lease_digest", None)):
            raise AutomationError("BLOCKED_LEASE_RECOVERY", "expected lease digest must be a lowercase SHA-256 digest")
        if args.confirm_no_active_owner != "I_CONFIRM_NO_ACTIVE_OWNER":
            raise AutomationError("BLOCKED_LEASE_RECOVERY", "explicit no-active-owner confirmation is required")
        with contract_runtime.checkpoint_lock(task):
            contract, state = load_authority(task, project, allow_dirty_worktree=True)
            paths = ensure_runtime_dirs(task)
            pending_recovery = paths["lease_journal"].exists()
            recover_lease_journal(task, contract)
            if pending_recovery:
                recovered = read_lease(paths)
                print(f"LEASE_RECOVERED task_id={contract['task_id']} revision={state['revision']} owner={recovered['owner']}")
                return 0
            if paths["journal"].exists():
                raise AutomationError("BLOCKED_LEASE_RECOVERY", "pending transition must be recovered before lease recovery")
            lease = read_lease(paths)
            if lease is None:
                raise AutomationError("BLOCKED_LEASE_RECOVERY", "no lease exists to recover")
            _validate_lease(lease, contract["task_id"], None, require_unexpired=False)
            if not lease_expired(lease):
                raise AutomationError("BLOCKED_LEASE_RECOVERY", "an unexpired lease cannot be replaced")
            if nonce_digest(lease["nonce"]) != args.expected_lease_digest:
                raise AutomationError("BLOCKED_LEASE_RECOVERY", "expected lease digest does not match the expired lease")
            authorization = read_json(Path(args.authorization), "BLOCKED_LEASE_RECOVERY")
            authorization_digest = validate_lease_recovery_authorization(
                authorization,
                contract,
                state,
                args.expected_lease_digest,
                args.new_owner,
                args.operator,
                task,
            )
            acquired_at = now()
            replacement = {
                "task_id": contract["task_id"],
                "owner": args.new_owner,
                "acquired_at": acquired_at,
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=15)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                "nonce": secrets.token_hex(16),
            }
            event = {
                "at": acquired_at,
                "event": "automation_lease_recovered",
                "task_id": contract["task_id"],
                "revision": state["revision"],
                "old_owner": lease["owner"],
                "new_owner": args.new_owner,
                "old_nonce_digest": nonce_digest(lease["nonce"]),
                "new_nonce_digest": nonce_digest(replacement["nonce"]),
                "operator": args.operator,
                "reason": args.reason,
                "authorization_digest": authorization_digest,
            }
            lease_journal_base = {
                "schema_version": "taskcontracts-lease-recovery.v1",
                "task_id": contract["task_id"],
                "from_lease": lease,
                "from_digest": sha256_json(lease),
                "target_lease": replacement,
                "target_digest": sha256_json(replacement),
                "authorization": authorization,
                "authorization_digest": authorization_digest,
                "event": event,
                "event_digest": sha256_json(event),
            }
            lease_journal = {**lease_journal_base, "journal_digest": sha256_json(lease_journal_base)}
            contract_runtime.atomic_write_json(paths["lease_journal"], lease_journal)
            recover_lease_journal(task, contract)
            print(f"LEASE_RECOVERED task_id={contract['task_id']} revision={state['revision']} owner={args.new_owner}")
            return 0
    except AutomationError as error:
        return print_stop(error)
    except contract_runtime.CheckpointLockError as error:
        return print_stop(AutomationError("BLOCKED_WRITER_CONFLICT", str(error)))
    except contract_runtime.AtomicDurabilityError as error:
        return print_stop(AutomationError("FAILED_DURABILITY_SYNC_AFTER_COMMIT", str(error)))
    except OSError as error:
        return print_stop(AutomationError("FAILED_RUNTIME_IO", str(error)))


def append_lifecycle_event(task: Path, event: dict[str, Any]) -> None:
    contract_runtime.append_event(task / "events.jsonl", event)


def envelope(
    task: Path,
    project: Path,
    contract: dict[str, Any],
    state: dict[str, Any],
    owner: str,
    lease: dict[str, Any],
    baseline: dict[str, Any],
) -> dict[str, Any]:
    action = action_for(contract, state["next_action_id"])
    result_schema = Path(__file__).resolve().parent.parent / "schema" / "executor-result.schema.json"
    return {
        "schema_version": "taskcontracts-execution-envelope.v1",
        "task_id": contract["task_id"],
        "contract_hash": contract_runtime.canonical_sha256(task / "TASK.json"),
        "state_revision": state["revision"],
        "action_id": action["id"],
        "action": action["action"],
        "project": str(project),
        "allowed_workspace_paths": action["allowed_workspace_paths"],
        "executor_routes": action["executor_routes"],
        "result_schema": "schema/executor-result.schema.json",
        "result_schema_version": RESULT_SCHEMA_VERSION,
        "result_schema_sha256": contract_runtime.file_sha256(result_schema),
        "result_delivery": "submit-result",
        "owner": owner,
        "lease_nonce": lease["nonce"],
        "workspace_baseline": str((runtime_paths(task)["baselines"] / f"r{state['revision']}.json").relative_to(task)),
        "workspace_baseline_digest": baseline["workspace_baseline_digest"],
        "created_at": baseline["captured_at"],
        "authority_notice": "This envelope is bounded evidence work. It cannot advance TaskContracts state.",
    }


def _read_events(task: Path) -> list[dict[str, Any]]:
    path = task / "events.jsonl"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        events = [json.loads(line) for line in lines if line.strip()]
    except (OSError, json.JSONDecodeError) as error:
        raise AutomationError("FAILED_TRANSITION_RECOVERY", f"events audit is unavailable or invalid: {error}") from error
    if not all(isinstance(event, dict) for event in events):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "events audit contains a non-object record")
    return events


def _exact_transition_event(task: Path, expected: dict[str, Any]) -> bool:
    matches = [
        event
        for event in _read_events(task)
        if event.get("transition_id") == expected["transition_id"]
    ]
    if len(matches) > 1:
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "transition event is duplicated")
    if not matches:
        return False
    if matches[0] != expected or sha256_json(matches[0]) != sha256_json(expected):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "transition event conflicts with the write-ahead journal")
    return True


def _validate_existing_audit_prefix(
    task: Path,
    task_id: str,
    expected_revisions: list[int],
    expected_last_digest: str,
) -> None:
    events = _read_events(task)
    allowed_names = STATE_EVENT_NAMES | LIFECYCLE_EVENT_NAMES
    for index, event in enumerate(events):
        if event.get("event") not in allowed_names or event.get("task_id") != task_id:
            raise AutomationError("FAILED_TRANSITION_RECOVERY", f"audit entry {index} has invalid task or event identity")
    state_events = [event for event in events if event.get("event") in STATE_EVENT_NAMES]
    revisions = [event.get("revision") for event in state_events]
    if revisions != expected_revisions:
        raise AutomationError(
            "FAILED_TRANSITION_RECOVERY",
            f"state-producing audit revisions are not continuous and unique: expected={expected_revisions}, actual={revisions}",
        )
    previous_target: str | None = None
    for revision, event in enumerate(state_events):
        target_digest = event.get("target_state_digest")
        if not is_sha256(target_digest):
            raise AutomationError("FAILED_TRANSITION_RECOVERY", f"state-producing audit revision {revision} has invalid target digest")
        if revision and event.get("previous_state_digest") != previous_target:
            raise AutomationError("FAILED_TRANSITION_RECOVERY", f"state-producing audit revision {revision} breaks the state digest chain")
        previous_target = target_digest
    if previous_target != expected_last_digest:
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "state-producing audit prefix does not bind the expected durable state")


def ensure_dispatch_artifacts(
    task: Path,
    project: Path,
    contract: dict[str, Any],
    state: dict[str, Any],
    owner: str,
    lease: dict[str, Any],
    *,
    successor_faults: bool = False,
) -> Path:
    paths = runtime_paths(task)
    baseline_path = paths["baselines"] / f"r{state['revision']}.json"
    baseline_existed = baseline_path.exists()
    baseline = capture_workspace_baseline(task, project, contract, state)
    if successor_faults and not baseline_existed:
        _fault_hook(FAULT_AFTER_SUCCESSOR_BASELINE)
    payload = envelope(task, project, contract, state, owner, lease, baseline)
    destination = paths["envelopes"] / f"r{state['revision']}-{state['next_action_id']}.json"
    envelope_existed = destination.exists()
    if envelope_existed:
        if read_json(destination, "FAILED_TRANSITION_RECOVERY") != payload:
            raise AutomationError("FAILED_TRANSITION_RECOVERY", "dispatch envelope conflicts with the sealed dispatch identity")
    else:
        contract_runtime.atomic_write_json(destination, payload)
    if successor_faults and not envelope_existed:
        _fault_hook(FAULT_AFTER_SUCCESSOR_ENVELOPE)
    expected_event = {
        "at": payload["created_at"],
        "event": "automation_dispatched",
        "task_id": contract["task_id"],
        "revision": state["revision"],
        "action_id": state["next_action_id"],
        "envelope": str(destination.relative_to(task)),
        "owner": owner,
    }
    matches = [
        event for event in _read_events(task)
        if event.get("event") == "automation_dispatched"
        and event.get("revision") == state["revision"]
        and event.get("action_id") == state["next_action_id"]
    ]
    if len(matches) > 1 or (matches and matches[0] != expected_event):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "dispatch audit event conflicts with the sealed dispatch identity")
    if not matches:
        append_lifecycle_event(task, expected_event)
        if successor_faults:
            _fault_hook(FAULT_AFTER_SUCCESSOR_EVENT)
    return destination


def continue_ready_dispatch(
    task: Path,
    project: Path,
    contract: dict[str, Any],
    state: dict[str, Any],
    owner: str,
    lease_nonce: str,
) -> Path | None:
    if state.get("status") != "READY":
        return None
    authority_errors = contract_runtime.validate_action_authorization(contract, state, state["next_action_id"])
    if authority_errors:
        return None
    paths = runtime_paths(task)
    lease = require_active_lease(paths, contract["task_id"], owner, lease_nonce)
    return ensure_dispatch_artifacts(
        task, project, contract, state, owner, lease, successor_faults=True,
    )


def _transaction_id(
    task_id: str,
    contract_digest: str,
    result_digest: str,
    from_revision: int,
    from_state_digest: str,
    target_revision: int,
    target_state_digest: str,
) -> str:
    return sha256_json({
        "task_id": task_id,
        "contract_digest": contract_digest,
        "result_digest": result_digest,
        "from_revision": from_revision,
        "from_state_digest": from_state_digest,
        "target_revision": target_revision,
        "target_state_digest": target_state_digest,
    })


def _receipt_binding(receipt: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in receipt.items() if key != "binding_digest"}


def _validate_receipt_shape(receipt: dict[str, Any]) -> None:
    fields = {
        "schema_version", "committed_at", "transaction_id", "task_id",
        "contract_digest", "result_id", "result_digest", "from_revision",
        "from_state_digest", "target_revision", "target_state_digest",
        "event_digest", "binding_digest",
    }
    if set(receipt) != fields or receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "committed receipt fields are invalid")
    if receipt.get("binding_digest") != sha256_json(_receipt_binding(receipt)):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "committed receipt binding digest is invalid")
    require_opaque_result_id(receipt.get("result_id"))
    for field in ("transaction_id", "contract_digest", "result_digest", "from_state_digest", "target_state_digest", "event_digest"):
        if not is_sha256(receipt.get(field)):
            raise AutomationError("FAILED_TRANSITION_RECOVERY", f"committed receipt {field} is invalid")
    if not is_timestamp(receipt.get("committed_at")):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "committed receipt timestamp is invalid")
    from_revision = receipt.get("from_revision")
    target_revision = receipt.get("target_revision")
    if (
        not isinstance(from_revision, int)
        or isinstance(from_revision, bool)
        or not isinstance(target_revision, int)
        or isinstance(target_revision, bool)
        or target_revision != from_revision + 1
    ):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "committed receipt revision boundary is invalid")


def _validate_journal(task: Path, contract: dict[str, Any], journal: dict[str, Any]) -> None:
    fields = {
        "schema_version", "transaction_id", "task_id", "contract_digest",
        "result", "result_digest", "from_revision", "from_state_digest",
        "target_revision", "target_state", "target_state_digest", "event",
        "event_digest", "receipt", "receipt_digest", "journal_digest",
    }
    if set(journal) != fields or journal.get("schema_version") != JOURNAL_SCHEMA_VERSION:
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "transition journal fields are invalid")
    unsigned = {key: value for key, value in journal.items() if key != "journal_digest"}
    if journal.get("journal_digest") != sha256_json(unsigned):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "transition journal digest is invalid")
    contract_digest = contract_runtime.canonical_sha256(task / "TASK.json")
    if journal.get("contract_digest") != contract_digest or journal.get("task_id") != contract.get("task_id"):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "transition journal contract binding is invalid")
    result = journal.get("result")
    target = journal.get("target_state")
    event = journal.get("event")
    receipt = journal.get("receipt")
    if not all(isinstance(value, dict) for value in (result, target, event, receipt)):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "transition journal payload is invalid")
    require_opaque_result_id(result.get("result_id"))
    if result.get("task_id") != contract.get("task_id") or result.get("contract_hash") != contract_digest:
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "journal result authority binding is invalid")
    if journal.get("result_digest") != sha256_json(result):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "journal result digest is invalid")
    from_revision = journal.get("from_revision")
    target_revision = journal.get("target_revision")
    if (
        not isinstance(from_revision, int)
        or isinstance(from_revision, bool)
        or not isinstance(target_revision, int)
        or isinstance(target_revision, bool)
        or target_revision != from_revision + 1
    ):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "journal revision boundary is invalid")
    if result.get("state_revision_seen") != from_revision:
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "journal result revision binding is invalid")
    if target.get("revision") != target_revision or target.get("task_id") != contract.get("task_id"):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "journal target state binding is invalid")
    if target.get("previous_state_digest") != journal.get("from_state_digest"):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "journal target previous-state digest is invalid")
    if journal.get("target_state_digest") != json_file_sha256(target):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "journal target state digest is invalid")
    expected_transaction_id = _transaction_id(
        journal["task_id"], contract_digest, journal["result_digest"], from_revision,
        journal["from_state_digest"], target_revision, journal["target_state_digest"],
    )
    if journal.get("transaction_id") != expected_transaction_id:
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "journal transaction identity is invalid")
    expected_event_fields = {
        "transition_id": expected_transaction_id,
        "task_id": contract["task_id"],
        "revision": target_revision,
        "previous_state_digest": journal["from_state_digest"],
        "target_state_digest": journal["target_state_digest"],
        "result_id": result["result_id"],
        "action_id": result.get("action_id"),
        "outcome": result.get("outcome"),
    }
    if any(event.get(key) != value for key, value in expected_event_fields.items()):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "journal transition event binding is invalid")
    if journal.get("event_digest") != sha256_json(event):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "journal transition event digest is invalid")
    _validate_receipt_shape(receipt)
    expected_receipt_fields = {
        "transaction_id": expected_transaction_id,
        "task_id": contract["task_id"],
        "contract_digest": contract_digest,
        "result_id": result["result_id"],
        "result_digest": journal["result_digest"],
        "from_revision": from_revision,
        "from_state_digest": journal["from_state_digest"],
        "target_revision": target_revision,
        "target_state_digest": journal["target_state_digest"],
        "event_digest": journal["event_digest"],
    }
    if any(receipt.get(key) != value for key, value in expected_receipt_fields.items()):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "journal committed receipt binding is invalid")
    if journal.get("receipt_digest") != sha256_json(receipt):
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "journal committed receipt digest is invalid")


def _validate_committed_duplicate(
    task: Path,
    contract: dict[str, Any],
    state: dict[str, Any],
    raw_result: dict[str, Any],
    receipt: dict[str, Any],
) -> None:
    _validate_receipt_shape(receipt)
    if receipt["result_id"] != raw_result.get("result_id") or receipt["result_digest"] != sha256_json(raw_result):
        raise AutomationError("FAILED_VERIFICATION", "duplicate result_id has different content")
    contract_digest = contract_runtime.canonical_sha256(task / "TASK.json")
    if receipt["task_id"] != contract.get("task_id") or receipt["contract_digest"] != contract_digest:
        raise AutomationError("FAILED_VERIFICATION", "duplicate receipt contract binding is invalid")
    expected_transaction_id = _transaction_id(
        receipt["task_id"], receipt["contract_digest"], receipt["result_digest"],
        receipt["from_revision"], receipt["from_state_digest"], receipt["target_revision"],
        receipt["target_state_digest"],
    )
    if receipt["transaction_id"] != expected_transaction_id:
        raise AutomationError("FAILED_VERIFICATION", "duplicate receipt transaction identity is invalid")
    if state.get("revision") != receipt["target_revision"] or contract_runtime.file_sha256(task / "STATE.json") != receipt["target_state_digest"]:
        raise AutomationError("FAILED_VERIFICATION", "duplicate receipt target state is not the current exact state")
    matches = [event for event in _read_events(task) if event.get("transition_id") == receipt["transaction_id"]]
    if len(matches) != 1 or sha256_json(matches[0]) != receipt["event_digest"]:
        raise AutomationError("FAILED_VERIFICATION", "duplicate receipt does not have one exact committed event")
    if matches[0].get("target_state_digest") != receipt["target_state_digest"]:
        raise AutomationError("FAILED_VERIFICATION", "duplicate event target state binding is invalid")


def recover_journal(task: Path, project: Path) -> None:
    paths = runtime_paths(task)
    if not paths["journal"].exists():
        return
    journal = read_json(paths["journal"], "FAILED_TRANSITION_RECOVERY")
    contract, state = load_authority(task, project, enforce_audit=False, allow_dirty_worktree=True)
    _validate_journal(task, contract, journal)
    lease = read_lease(paths)
    if lease is None:
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "pending transition has no matching lease")
    _validate_lease(
        lease,
        contract["task_id"],
        None,
        journal["result"].get("lease_nonce"),
        require_unexpired=False,
    )
    verify_workspace_result(task, project, contract, journal["result"])
    state_digest = contract_runtime.file_sha256(task / "STATE.json")
    at_from = state.get("revision") == journal["from_revision"] and state_digest == journal["from_state_digest"]
    at_target = state.get("revision") == journal["target_revision"] and state_digest == journal["target_state_digest"]
    if not at_from and not at_target:
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "current state is neither the exact journal source nor target")
    has_event = _exact_transition_event(task, journal["event"])
    if at_from:
        _validate_existing_audit_prefix(
            task,
            contract["task_id"],
            list(range(journal["from_revision"] + 1)),
            journal["from_state_digest"],
        )
        if has_event:
            raise AutomationError("FAILED_TRANSITION_RECOVERY", "transition event exists before its target state")
        contract_runtime.atomic_write_json(task / "STATE.json", journal["target_state"])
        _fault_hook(FAULT_AFTER_STATE)
        state = journal["target_state"]
        at_target = True
        has_event = False
    else:
        expected_revisions = list(range(journal["target_revision"] + (1 if has_event else 0)))
        expected_digest = journal["target_state_digest"] if has_event else journal["from_state_digest"]
        _validate_existing_audit_prefix(task, contract["task_id"], expected_revisions, expected_digest)
    if not has_event:
        append_lifecycle_event(task, journal["event"])
        _fault_hook(FAULT_AFTER_EVENT)
    receipt_path = paths["results"] / f"{journal['result']['result_id']}.json"
    if receipt_path.exists():
        existing = read_json(receipt_path, "FAILED_TRANSITION_RECOVERY")
        if existing != journal["receipt"] or sha256_json(existing) != journal["receipt_digest"]:
            raise AutomationError("FAILED_TRANSITION_RECOVERY", "committed receipt conflicts with the journal")
    else:
        contract_runtime.atomic_write_json(receipt_path, journal["receipt"])
        _fault_hook(FAULT_AFTER_RECEIPT)
    final_contract, final_state = load_authority(task, project, allow_dirty_worktree=True)
    if final_contract.get("task_id") != journal["task_id"] or contract_runtime.file_sha256(task / "STATE.json") != journal["target_state_digest"]:
        raise AutomationError("FAILED_TRANSITION_RECOVERY", "final state verification failed")
    _validate_committed_duplicate(task, final_contract, final_state, journal["result"], journal["receipt"])
    if final_state.get("status") != "READY":
        ensure_lease_released(
            task,
            final_contract,
            final_state,
            lease["owner"],
            journal["result"]["lease_nonce"],
        )
    paths["journal"].unlink(missing_ok=True)


def successor(contract: dict[str, Any], current: dict[str, Any]) -> str | None:
    successors = current.get("allowed_next_actions", [])
    if not isinstance(successors, list):
        raise AutomationError("BLOCKED_CONTRACT_INVALID", "allowed_next_actions must be an array")
    if not successors:
        return None
    if len(successors) != 1:
        raise AutomationError("BLOCKED_AUTHORITY_REQUIRED", "automatic continuation requires exactly one explicit successor")
    candidate = action_for(contract, successors[0])
    if candidate["authority_expansion"] is True:
        raise AutomationError("BLOCKED_AUTHORITY_REQUIRED", f"successor {candidate['id']} declares authority expansion")
    return candidate["id"]


def transition(
    task: Path,
    project: Path,
    contract: dict[str, Any],
    state: dict[str, Any],
    result: dict[str, Any],
    raw_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    current = action_for(contract, state["next_action_id"])
    outcome = result["outcome"]
    target = dict(state)
    event_status: str
    if outcome == "PASS":
        try:
            next_id = successor(contract, current)
        except AutomationError as error:
            target.update({"status": "BLOCKED", "current_state": error.detail, "blocker": error.code})
            event_status = "WAIT_AUTHORITY"
        else:
            target["completed_actions"] = list(dict.fromkeys([*state["completed_actions"], current["id"]]))
            target["last_completed_action_id"] = current["id"]
            if next_id is None:
                target.update({
                    "status": "PASS",
                    "current_state": result["summary"],
                    "next_action_id": current["id"],
                    "next_action": current["action"],
                    "blocker": None,
                    "resume_from": None,
                })
                event_status = "COMPLETE"
            else:
                next_action = action_for(contract, next_id)
                target.update({"status": "READY", "current_state": result["summary"], "next_action_id": next_id, "next_action": next_action["action"], "blocker": None, "resume_from": next_id})
                event_status = "ACTION_PASSED"
    elif outcome == "BLOCKED":
        target.update({"status": "BLOCKED", "current_state": result["summary"], "blocker": result["blocker_code"]})
        event_status = "BLOCKED"
    elif outcome == "FAILED":
        target.update({"status": "FAILED", "current_state": result["summary"], "blocker": result.get("blocker_code") or "FAILED_VERIFICATION"})
        event_status = "FAILED"
    else:
        target.update({"status": "BLOCKED", "current_state": result["summary"], "blocker": "RETRYABLE_EXECUTOR_FAILURE"})
        event_status = "RETRYABLE"
    timestamp = now()
    previous_digest = contract_runtime.file_sha256(task / "STATE.json")
    target.update({"revision": state["revision"] + 1, "previous_state_digest": previous_digest, "updated_at": timestamp, "last_verified": json.dumps(result["verification"], separators=(",", ":"))})
    contract_digest = contract_runtime.canonical_sha256(task / "TASK.json")
    submitted_result = raw_result if raw_result is not None else result
    result_digest = sha256_json(submitted_result)
    target_digest = json_file_sha256(target)
    transition_id = _transaction_id(
        contract["task_id"], contract_digest, result_digest, state["revision"],
        previous_digest, target["revision"], target_digest,
    )
    event = {
        "at": timestamp, "event": "automation_transition", "transition_id": transition_id,
        "task_id": contract["task_id"],
        "revision": target["revision"], "previous_state_digest": previous_digest, "target_state_digest": target_digest,
        "result_id": result["result_id"], "action_id": current["id"], "outcome": outcome,
        "lifecycle": ["RESULT_RECEIVED", "VERIFYING", event_status],
    }
    event_digest = sha256_json(event)
    receipt_base = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "committed_at": timestamp,
        "transaction_id": transition_id,
        "task_id": contract["task_id"],
        "contract_digest": contract_digest,
        "result_id": result["result_id"],
        "result_digest": result_digest,
        "from_revision": state["revision"],
        "from_state_digest": previous_digest,
        "target_revision": target["revision"],
        "target_state_digest": target_digest,
        "event_digest": event_digest,
    }
    receipt = {**receipt_base, "binding_digest": sha256_json(receipt_base)}
    journal = {
        "schema_version": JOURNAL_SCHEMA_VERSION,
        "transaction_id": transition_id,
        "task_id": contract["task_id"],
        "contract_digest": contract_digest,
        "result": submitted_result,
        "result_digest": result_digest,
        "from_revision": state["revision"],
        "from_state_digest": previous_digest,
        "target_revision": target["revision"],
        "target_state": target,
        "target_state_digest": target_digest,
        "event": event,
        "event_digest": event_digest,
        "receipt": receipt,
        "receipt_digest": sha256_json(receipt),
    }
    return {**journal, "journal_digest": sha256_json(journal)}


def command_dispatch(args: argparse.Namespace) -> int:
    task, project = Path(args.task), Path(args.project)
    try:
        with contract_runtime.checkpoint_lock(task):
            recover_journal(task, project)
            contract, state = load_authority(task, project)
            if state["status"] != "READY":
                raise AutomationError("BLOCKED_AUTHORITY_REQUIRED", f"task status {state['status']} is not dispatchable")
            authority_errors = contract_runtime.validate_action_authorization(contract, state, state["next_action_id"])
            if authority_errors:
                raise AutomationError("BLOCKED_AUTHORITY_REQUIRED", "; ".join(issue.message for issue in authority_errors))
            paths = ensure_runtime_dirs(task)
            lease = acquire_lease(paths, contract["task_id"], args.owner)
            destination = ensure_dispatch_artifacts(task, project, contract, state, args.owner, lease)
            print(f"DISPATCHED envelope={destination} action_id={state['next_action_id']} revision={state['revision']}")
            return 0
    except AutomationError as error:
        return print_stop(error)
    except contract_runtime.CheckpointLockError as error:
        return print_stop(AutomationError("BLOCKED_WRITER_CONFLICT", str(error)))
    except contract_runtime.AtomicDurabilityError as error:
        return print_stop(AutomationError("FAILED_DURABILITY_SYNC_AFTER_COMMIT", str(error)))
    except OSError as error:
        return print_stop(AutomationError("FAILED_RUNTIME_IO", str(error)))


def command_submit(args: argparse.Namespace) -> int:
    task, project = Path(args.task), Path(args.project)
    try:
        raw_result = read_json(Path(args.result), "FAILED_RESULT_SCHEMA")
        result_id = require_opaque_result_id(raw_result.get("result_id"))
        with contract_runtime.checkpoint_lock(task):
            recover_journal(task, project)
            contract, state = load_authority(task, project, allow_dirty_worktree=True)
            paths = ensure_runtime_dirs(task)
            receipt = paths["results"] / f"{result_id}.json"
            if receipt.exists():
                existing = read_json(receipt, "FAILED_VERIFICATION")
                _validate_committed_duplicate(task, contract, state, raw_result, existing)
                if state.get("status") == "READY":
                    require_active_lease(paths, contract["task_id"], args.owner, raw_result.get("lease_nonce"))
                    verify_workspace_result(task, project, contract, raw_result)
                    destination = continue_ready_dispatch(
                        task, project, contract, state, args.owner, raw_result.get("lease_nonce"),
                    )
                else:
                    ensure_lease_released(task, contract, state, args.owner, raw_result.get("lease_nonce"))
                    destination = None
                suffix = f" next_envelope={destination}" if destination is not None else (
                    " wait_authority=true" if state.get("status") == "READY" else ""
                )
                print(f"DUPLICATE_RESULT result_id={result_id} revision={state['revision']}{suffix}")
                return 0
            result = validate_result(raw_result, contract, {**state, "_task_path": str(task), "_project_path": str(project)})
            require_active_lease(paths, contract["task_id"], args.owner, result["lease_nonce"])
            verify_workspace_result(task, project, contract, result)
            journal = transition(task, project, contract, state, result, raw_result=raw_result)
            contract_runtime.atomic_write_json(paths["journal"], journal)
            _fault_hook(FAULT_AFTER_WAL)
            recover_journal(task, project)
            fresh_contract, fresh_state = load_authority(task, project, allow_dirty_worktree=True)
            if fresh_state["status"] == "READY":
                destination = continue_ready_dispatch(
                    task, project, fresh_contract, fresh_state, args.owner, result["lease_nonce"],
                )
                if destination is None:
                    print(f"RESULT_COMMITTED result_id={result['result_id']} status=READY wait_authority=true")
                else:
                    print(f"RESULT_COMMITTED result_id={result['result_id']} status=READY next_envelope={destination}")
            else:
                ensure_lease_released(task, fresh_contract, fresh_state, args.owner, result["lease_nonce"])
                print(f"RESULT_COMMITTED result_id={result['result_id']} status={fresh_state['status']}")
            return 0
    except AutomationError as error:
        return print_stop(error)
    except contract_runtime.CheckpointLockError as error:
        return print_stop(AutomationError("BLOCKED_WRITER_CONFLICT", str(error)))
    except contract_runtime.AtomicDurabilityError as error:
        return print_stop(AutomationError("FAILED_DURABILITY_SYNC_AFTER_COMMIT", str(error)))
    except OSError as error:
        return print_stop(AutomationError("FAILED_RUNTIME_IO", str(error)))


def command_status(args: argparse.Namespace) -> int:
    task, project = Path(args.task), Path(args.project)
    try:
        contract, state = load_authority(task, project)
        paths = runtime_paths(task)
        lease = read_lease(paths)
        print("AUTOMATION_STATUS")
        print(f"task_id={contract['task_id']}")
        print(f"revision={state['revision']}")
        print(f"status={state['status']}")
        print(f"current_action={state['next_action_id']}")
        print(f"blocker={state['blocker']}")
        print(f"pending_transition={paths['journal'].exists()}")
        print(f"lease_owner={lease.get('owner') if lease else None}")
        return 0
    except AutomationError as error:
        return print_stop(error)
    except contract_runtime.AtomicDurabilityError as error:
        return print_stop(AutomationError("FAILED_DURABILITY_SYNC_AFTER_COMMIT", str(error)))
    except OSError as error:
        return print_stop(AutomationError("FAILED_STATUS_IO", str(error)))


def command_recover(args: argparse.Namespace) -> int:
    task, project = Path(args.task), Path(args.project)
    try:
        with contract_runtime.checkpoint_lock(task):
            recover_journal(task, project)
            _, state = load_authority(task, project, allow_dirty_worktree=True)
            print(f"RECOVERED revision={state['revision']} status={state['status']}")
            return 0
    except AutomationError as error:
        return print_stop(error)
    except contract_runtime.CheckpointLockError as error:
        return print_stop(AutomationError("BLOCKED_WRITER_CONFLICT", str(error)))
    except contract_runtime.AtomicDurabilityError as error:
        return print_stop(AutomationError("FAILED_DURABILITY_SYNC_AFTER_COMMIT", str(error)))
    except OSError as error:
        return print_stop(AutomationError("FAILED_RUNTIME_IO", str(error)))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    for name, handler in (("dispatch", command_dispatch), ("submit-result", command_submit)):
        command = commands.add_parser(name)
        command.add_argument("--task", required=True)
        command.add_argument("--project", required=True)
        command.add_argument("--owner", required=True)
        if name == "submit-result":
            command.add_argument("--result", required=True)
        command.set_defaults(func=handler)
    for name, handler in (("status", command_status), ("recover", command_recover)):
        command = commands.add_parser(name)
        command.add_argument("--task", required=True)
        command.add_argument("--project", required=True)
        command.set_defaults(func=handler)
    command = commands.add_parser("recover-lease")
    command.add_argument("--task", required=True)
    command.add_argument("--project", required=True)
    command.add_argument("--expected-lease-digest", required=True)
    command.add_argument("--new-owner", required=True)
    command.add_argument("--operator", required=True)
    command.add_argument("--reason", required=True)
    command.add_argument("--authorization", required=True)
    command.add_argument("--confirm-no-active-owner", required=True)
    command.set_defaults(func=command_recover_lease)
    return root


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    return arguments.func(arguments)


if __name__ == "__main__":
    sys.exit(main())
