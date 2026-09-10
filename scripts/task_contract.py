#!/usr/bin/env python3
"""Standard-library validator for sealed Task Contract v1 through v1.2 bundles."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable, Iterator

STATUSES = {"READY", "RUNNING", "BLOCKED", "PASS", "FAILED", "SUPERSEDED"}
RISK_LEVELS = {"L0", "L1", "L2", "L3", "L4"}
TASK_V1 = "1.0"
TASK_V11 = "1.1"
TASK_V12 = "1.2"
MODERN_TASK_VERSIONS = {TASK_V11, TASK_V12}
STOP = 42

AUTHORITY_FIELDS = {
    "schema_version", "contract_version", "task_id", "project", "task_type",
    "objective", "authority", "authority_order", "baseline", "allowed_actions",
    "forbidden_actions", "hard_gates", "acceptance", "artifacts",
    "policy_boundaries", "resource_requirements", "threat_model",
}
STATE_V11_FIELDS = {
    "schema_version", "task_id", "revision", "previous_state_digest", "status",
    "current_state", "completed_actions", "last_completed_action_id",
    "next_action_id", "next_action", "blocker", "resume_from", "rounds_completed",
    "benchmark_progress", "gate_status", "approvals", "last_verified",
    "last_verified_commit", "artifact_path", "updated_at",
}
ACTION_V11_FIELDS = {
    "id", "action", "task_scope_authorized", "risk_level",
    "requires_fresh_approval", "prerequisites", "allowed_predecessors",
    "expected_commit_authority", "allowed_next_actions", "required_hard_gates",
    "required_evidence_classes", "route_class",
}
ACTION_V12_FIELDS = ACTION_V11_FIELDS | {
    "allowed_workspace_paths", "executor_routes", "authority_expansion",
}


@dataclass(frozen=True)
class Issue:
    reason: str
    message: str


class AuditAppendError(RuntimeError):
    pass


class CheckpointLockError(ValueError):
    pass


class AtomicDurabilityError(OSError):
    """The replacement is visible, but its directory entry was not synced."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read {path.name}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def canonical_bytes(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_sha256(path: Path) -> str:
    return hashlib.sha256(canonical_bytes(load_json(path))).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def is_git_commit(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def is_date_time(value: object) -> bool:
    if not isinstance(value, str) or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})",
        value,
    ) is None:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.utcoffset() is not None


def is_nullable_string(value: object) -> bool:
    return value is None or isinstance(value, str)


def required(value: dict, keys: set[str], name: str, reason: str = "authority_or_state_mismatch") -> list[Issue]:
    return [Issue(reason, f"{name}.{key} is required") for key in sorted(keys - value.keys())]


def action_map(contract: dict) -> dict[str, dict]:
    actions = contract.get("allowed_actions")
    if not isinstance(actions, list):
        return {}
    return {item["id"]: item for item in actions if isinstance(item, dict) and isinstance(item.get("id"), str)}


def validate_shape_v1(contract: dict, state: dict) -> list[Issue]:
    errors = required(contract, {"schema_version", "task_id", "project", "task_type", "objective", "authority", "baseline", "allowed_actions", "forbidden_actions", "hard_gates", "acceptance", "artifacts"}, "TASK")
    errors += required(state, {"schema_version", "task_id", "status", "current_state", "next_action_id", "next_action", "blocker", "resume_from", "last_verified", "last_verified_commit", "artifact_path", "updated_at"}, "STATE")
    if contract.get("schema_version") != TASK_V1:
        errors.append(Issue("authority_or_state_mismatch", "unsupported TASK schema_version"))
    if state.get("schema_version") != TASK_V1:
        errors.append(Issue("authority_or_state_mismatch", "unsupported STATE schema_version"))
    actions = action_map(contract)
    if not actions or any(not item.get("action") for item in actions.values()):
        errors.append(Issue("authority_or_state_mismatch", "TASK.allowed_actions must contain id and action"))
    elif state.get("next_action_id") not in actions:
        errors.append(Issue("authority_or_state_mismatch", "STATE.next_action_id is not an allowed task action"))
    elif state.get("next_action") != actions[state["next_action_id"]]["action"]:
        errors.append(Issue("authority_or_state_mismatch", "STATE.next_action does not match its allowed task action"))
    return errors


def validate_shape_modern(
    contract: dict,
    state: dict,
    action_fields: set[str],
    contract_version: int,
    state_version: str,
) -> list[Issue]:
    errors = required(contract, AUTHORITY_FIELDS, "TASK", "HANDOFF_AUTHORITY_MISSING")
    errors += required(state, STATE_V11_FIELDS, "STATE", "HANDOFF_AUTHORITY_MISSING")
    unknown_authority = set(contract) - AUTHORITY_FIELDS
    if unknown_authority:
        errors.append(Issue("authority_or_state_mismatch", "TASK has unknown fields: " + ", ".join(sorted(unknown_authority))))
    unknown_state = set(state) - STATE_V11_FIELDS
    if unknown_state:
        errors.append(Issue("authority_or_state_mismatch", "STATE has unknown fields: " + ", ".join(sorted(unknown_state))))
    if contract.get("contract_version") != contract_version:
        errors.append(Issue("authority_or_state_mismatch", f"TASK.contract_version must be {contract_version}"))
    if state.get("schema_version") != state_version:
        errors.append(Issue("authority_or_state_mismatch", f"STATE.schema_version must be {state_version}"))
    if not isinstance(contract.get("objective"), str) or not contract.get("objective", "").strip():
        errors.append(Issue("HANDOFF_AUTHORITY_MISSING", "TASK.objective must be explicit"))
    for key in ("forbidden_actions", "acceptance"):
        if not isinstance(contract.get(key), list) or not contract.get(key):
            errors.append(Issue("HANDOFF_AUTHORITY_MISSING", f"TASK.{key} must be non-empty"))
    if not isinstance(state.get("current_state"), str) or not state.get("current_state", "").strip():
        errors.append(Issue("HANDOFF_AUTHORITY_MISSING", "STATE.current_state is required"))
    actions = action_map(contract)
    if not actions:
        errors.append(Issue("HANDOFF_AUTHORITY_MISSING", "TASK.allowed_actions must be non-empty"))
    for action in actions.values():
        errors += required(action, action_fields, f"TASK.allowed_actions[{action.get('id', '?')}]", "HANDOFF_AUTHORITY_MISSING")
        unknown_action = set(action) - action_fields
        if unknown_action:
            errors.append(Issue("authority_or_state_mismatch", f"action {action.get('id')} has unknown fields: " + ", ".join(sorted(unknown_action))))
        if action.get("risk_level") not in RISK_LEVELS:
            errors.append(Issue("authority_or_state_mismatch", f"invalid risk level for {action.get('id')}"))
        if action.get("task_scope_authorized") is not True:
            errors.append(Issue("policy_boundary_mismatch", f"action {action.get('id')} is not task-scope authorized"))
    next_id = state.get("next_action_id")
    if next_id not in actions:
        errors.append(Issue("authority_or_state_mismatch", "STATE.next_action_id is not an allowed task action"))
    elif state.get("next_action") != actions[next_id].get("action"):
        errors.append(Issue("authority_or_state_mismatch", "STATE.next_action does not match its allowed task action"))
    if not isinstance(state.get("revision"), int) or isinstance(state.get("revision"), bool) or state.get("revision", -1) < 0:
        errors.append(Issue("authority_or_state_mismatch", "STATE.revision must be a non-negative integer"))
    if not isinstance(state.get("completed_actions"), list):
        errors.append(Issue("authority_or_state_mismatch", "STATE.completed_actions must be an array"))
    boundaries = contract.get("policy_boundaries")
    denied_values = boundaries.get("denied_action_ids", []) if isinstance(boundaries, dict) else []
    denied = set(denied_values) if isinstance(denied_values, list) and all(isinstance(item, str) for item in denied_values) else set()
    conflict = denied.intersection(actions)
    if conflict:
        errors.append(Issue("policy_boundary_mismatch", "TASK action conflicts with a declared higher-policy boundary: " + ", ".join(sorted(conflict))))
    return errors


def validate_shape_v11(contract: dict, state: dict) -> list[Issue]:
    return validate_shape_modern(contract, state, ACTION_V11_FIELDS, 1, TASK_V11)


def validate_shape_v12(contract: dict, state: dict) -> list[Issue]:
    errors = validate_shape_modern(contract, state, ACTION_V12_FIELDS, 2, TASK_V12)
    if not isinstance(contract.get("task_id"), str) or re.fullmatch(r"[a-z0-9][a-z0-9-]{2,79}", contract.get("task_id", "")) is None:
        errors.append(Issue("authority_or_state_mismatch", "TASK.task_id does not match the v1.2 identifier format"))
    if contract.get("task_type") not in {"benchmark", "development", "audit", "research", "operations"}:
        errors.append(Issue("authority_or_state_mismatch", "TASK.task_type is invalid"))
    authority_order = contract.get("authority_order")
    if not isinstance(authority_order, list) or len(authority_order) < 8 or any(not isinstance(item, str) for item in authority_order):
        errors.append(Issue("HANDOFF_AUTHORITY_MISSING", "TASK.authority_order must contain at least 8 string entries"))
    authority = contract.get("authority")
    authority_fields = {"kind", "source_ref", "issued_at", "supersedes"}
    if not isinstance(authority, dict) or set(authority) != authority_fields:
        errors.append(Issue("authority_or_state_mismatch", "TASK.authority fields do not match the v1.2 schema"))
    else:
        if authority.get("kind") not in {"user-direct", "handoff", "work-item"}:
            errors.append(Issue("authority_or_state_mismatch", "TASK.authority.kind is invalid"))
        if not isinstance(authority.get("source_ref"), str) or not authority["source_ref"]:
            errors.append(Issue("HANDOFF_AUTHORITY_MISSING", "TASK.authority.source_ref must be a non-empty string"))
        if not is_date_time(authority.get("issued_at")):
            errors.append(Issue("authority_or_state_mismatch", "TASK.authority.issued_at must be an offset-aware date-time"))
        if not is_nullable_string(authority.get("supersedes")):
            errors.append(Issue("authority_or_state_mismatch", "TASK.authority.supersedes must be a string or null"))
    project = contract.get("project")
    project_fields = {"project_id", "expected_root", "git"}
    git_fields = {"required", "remote", "authorized_commits", "require_clean_worktree", "forbid_detached_head", "forbid_special_operation"}
    if not isinstance(project, dict) or set(project) != project_fields:
        errors.append(Issue("authority_or_state_mismatch", "TASK.project fields do not match the v1.2 schema"))
    else:
        if any(not isinstance(project.get(key), str) or not project[key] for key in ("project_id", "expected_root")):
            errors.append(Issue("HANDOFF_AUTHORITY_MISSING", "TASK.project identity fields must be non-empty strings"))
        git = project.get("git")
        if not isinstance(git, dict) or set(git) != git_fields:
            errors.append(Issue("authority_or_state_mismatch", "TASK.project.git fields do not match the v1.2 schema"))
        else:
            if git.get("required") is not True or git.get("require_clean_worktree") is not True or git.get("forbid_detached_head") is not True or git.get("forbid_special_operation") is not True:
                errors.append(Issue("policy_boundary_mismatch", "TASK.project.git safety flags must all be true"))
            if not isinstance(git.get("remote"), str) or not git["remote"]:
                errors.append(Issue("authority_or_state_mismatch", "TASK.project.git.remote must be a non-empty string"))
            commits = git.get("authorized_commits")
            if not isinstance(commits, list) or not commits:
                errors.append(Issue("HANDOFF_AUTHORITY_MISSING", "TASK.project.git.authorized_commits must be non-empty"))
            else:
                for index, commit in enumerate(commits):
                    if not isinstance(commit, dict) or set(commit) != {"id", "ref", "commit"}:
                        errors.append(Issue("authority_or_state_mismatch", f"TASK.project.git.authorized_commits[{index}] fields are invalid"))
                    elif any(not isinstance(commit.get(key), str) or not commit[key] for key in ("id", "ref")) or not is_git_commit(commit.get("commit")):
                        errors.append(Issue("authority_or_state_mismatch", f"TASK.project.git.authorized_commits[{index}] contains an invalid binding"))
    baseline = contract.get("baseline")
    if not isinstance(baseline, dict) or set(baseline) != {"description", "required_inputs"} or not isinstance(baseline.get("description"), str) or not isinstance(baseline.get("required_inputs"), list) or any(not isinstance(item, str) for item in baseline.get("required_inputs", [])):
        errors.append(Issue("authority_or_state_mismatch", "TASK.baseline does not match the v1.2 schema"))
    forbidden = contract.get("forbidden_actions")
    if not isinstance(forbidden, list) or not forbidden or any(not isinstance(item, str) for item in forbidden):
        errors.append(Issue("HANDOFF_AUTHORITY_MISSING", "TASK.forbidden_actions must be a non-empty string array"))
    acceptance = contract.get("acceptance")
    if not isinstance(acceptance, list) or not acceptance:
        errors.append(Issue("HANDOFF_AUTHORITY_MISSING", "TASK.acceptance must be a non-empty array"))
    else:
        for index, criterion in enumerate(acceptance):
            if (
                not isinstance(criterion, dict)
                or set(criterion) != {"id", "criterion", "evidence_classes", "substitution_forbidden"}
                or any(not isinstance(criterion.get(key), str) or not criterion[key] for key in ("id", "criterion"))
                or not isinstance(criterion.get("evidence_classes"), list)
                or not criterion["evidence_classes"]
                or any(not isinstance(item, str) for item in criterion["evidence_classes"])
                or criterion.get("substitution_forbidden") is not True
            ):
                errors.append(Issue("authority_or_state_mismatch", f"TASK.acceptance[{index}] does not match the v1.2 schema"))
    artifacts = contract.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {"root", "expected"} or not isinstance(artifacts.get("root"), str) or not isinstance(artifacts.get("expected"), list) or any(not isinstance(item, str) for item in artifacts.get("expected", [])):
        errors.append(Issue("authority_or_state_mismatch", "TASK.artifacts does not match the v1.2 schema"))
    boundaries = contract.get("policy_boundaries")
    if (
        not isinstance(boundaries, dict)
        or set(boundaries) != {"task_scope_is_execution_approval", "denied_action_ids", "handoff_authority_role", "repository_state_authority_role"}
        or boundaries.get("task_scope_is_execution_approval") is not False
        or boundaries.get("handoff_authority_role") != "reference-envelope-only"
        or boundaries.get("repository_state_authority_role") != "supporting-evidence-only"
        or not isinstance(boundaries.get("denied_action_ids"), list)
        or any(not isinstance(item, str) for item in boundaries.get("denied_action_ids", []))
    ):
        errors.append(Issue("policy_boundary_mismatch", "TASK.policy_boundaries does not match the v1.2 schema"))
    resources = contract.get("resource_requirements")
    if not isinstance(resources, list):
        errors.append(Issue("authority_or_state_mismatch", "TASK.resource_requirements must be an array"))
    else:
        for index, resource in enumerate(resources):
            if not isinstance(resource, dict) or set(resource) != {"resource_class", "purpose", "authority_role"} or any(not isinstance(resource.get(key), str) for key in ("resource_class", "purpose")) or resource.get("authority_role") != "soft-hint-not-lock-or-evidence":
                errors.append(Issue("authority_or_state_mismatch", f"TASK.resource_requirements[{index}] does not match the v1.2 schema"))
    threat = contract.get("threat_model")
    if not isinstance(threat, dict) or set(threat) != {"seal_role", "external_authenticity_anchor"} or threat.get("seal_role") != "accidental-procedural-integrity" or threat.get("external_authenticity_anchor") is not False:
        errors.append(Issue("policy_boundary_mismatch", "TASK.threat_model does not match the v1.2 schema"))
    hard_gates = contract.get("hard_gates")
    if not isinstance(hard_gates, list) or not hard_gates:
        errors.append(Issue("HANDOFF_AUTHORITY_MISSING", "TASK.hard_gates must be a non-empty array"))
    else:
        required_gate_fields = {"id", "type", "required", "required_state", "required_evidence", "evidence_scope"}
        optional_gate_fields = {"minimum_evidence", "required_verified_actions"}
        for index, gate in enumerate(hard_gates):
            if not isinstance(gate, dict) or not required_gate_fields.issubset(gate) or set(gate) - required_gate_fields - optional_gate_fields:
                errors.append(Issue("authority_or_state_mismatch", f"TASK.hard_gates[{index}] fields are invalid"))
                continue
            if gate.get("type") not in {"repository-assertion", "policy-assertion", "runtime-assertion", "engine-assertion", "session-assertion", "artifact-assertion"} or gate.get("evidence_scope") not in {"task", "action"}:
                errors.append(Issue("authority_or_state_mismatch", f"TASK.hard_gates[{index}] enum value is invalid"))
            if any(not isinstance(gate.get(key), str) or not gate[key] for key in ("id", "required_state")) or not isinstance(gate.get("required"), bool):
                errors.append(Issue("authority_or_state_mismatch", f"TASK.hard_gates[{index}] identity or required flag is invalid"))
            evidence = gate.get("required_evidence")
            if not isinstance(evidence, list) or not evidence or any(not isinstance(item, str) for item in evidence):
                errors.append(Issue("authority_or_state_mismatch", f"TASK.hard_gates[{index}].required_evidence is invalid"))
            if "minimum_evidence" in gate and (not isinstance(gate["minimum_evidence"], int) or isinstance(gate["minimum_evidence"], bool) or gate["minimum_evidence"] < 1):
                errors.append(Issue("authority_or_state_mismatch", f"TASK.hard_gates[{index}].minimum_evidence is invalid"))
            verified_actions = gate.get("required_verified_actions", [])
            if not isinstance(verified_actions, list) or any(not isinstance(item, str) for item in verified_actions) or len(set(verified_actions)) != len(verified_actions):
                errors.append(Issue("authority_or_state_mismatch", f"TASK.hard_gates[{index}].required_verified_actions is invalid"))
    for action in action_map(contract).values():
        if any(not isinstance(action.get(key), str) or not action[key] for key in ("id", "action")):
            errors.append(Issue("authority_or_state_mismatch", f"action {action.get('id')} identity fields must be non-empty strings"))
        allowed = action.get("allowed_workspace_paths")
        if not isinstance(allowed, list) or any(not isinstance(item, str) or not item for item in allowed) or len(set(allowed or [])) != len(allowed or []):
            errors.append(Issue("authority_or_state_mismatch", f"action {action.get('id')} allowed_workspace_paths must contain unique non-empty strings"))
        else:
            for item in allowed:
                candidate = PurePosixPath(item)
                if "\\" in item or candidate.is_absolute() or ".." in candidate.parts or (candidate.parts and candidate.parts[0].endswith(":")):
                    errors.append(Issue("authority_or_state_mismatch", f"action {action.get('id')} has a non-relative allowed workspace path: {item}"))
        routes = action.get("executor_routes")
        if routes != ["KEEP_SINGLE"]:
            errors.append(Issue("authority_or_state_mismatch", f"action {action.get('id')} executor_routes must be ['KEEP_SINGLE']"))
        if not isinstance(action.get("authority_expansion"), bool):
            errors.append(Issue("authority_or_state_mismatch", f"action {action.get('id')} authority_expansion must be boolean"))
        evidence_classes = action.get("required_evidence_classes")
        if not isinstance(evidence_classes, list) or not evidence_classes or any(not isinstance(item, str) or not item for item in evidence_classes) or len(set(evidence_classes or [])) != len(evidence_classes or []):
            errors.append(Issue("authority_or_state_mismatch", f"action {action.get('id')} required_evidence_classes must contain unique non-empty strings"))
        if action.get("risk_level") in {"L3", "L4"} and action.get("requires_fresh_approval") is not True:
            errors.append(Issue("policy_boundary_mismatch", f"action {action.get('id')} requires fresh approval at risk level {action.get('risk_level')}"))
        if action.get("route_class") not in {"benchmark", "development", "audit", "research", "operations"}:
            errors.append(Issue("authority_or_state_mismatch", f"action {action.get('id')} route_class is invalid"))
        if not isinstance(action.get("requires_fresh_approval"), bool):
            errors.append(Issue("authority_or_state_mismatch", f"action {action.get('id')} requires_fresh_approval must be boolean"))
        for key in ("prerequisites", "allowed_predecessors", "allowed_next_actions", "required_hard_gates"):
            values = action.get(key)
            if not isinstance(values, list):
                errors.append(Issue("authority_or_state_mismatch", f"action {action.get('id')} {key} must be a unique array"))
            elif any(item is not None and not isinstance(item, str) for item in values) or (key != "allowed_predecessors" and any(not isinstance(item, str) for item in values)):
                errors.append(Issue("authority_or_state_mismatch", f"action {action.get('id')} {key} contains an invalid item type"))
            elif len(set(values)) != len(values):
                errors.append(Issue("authority_or_state_mismatch", f"action {action.get('id')} {key} must be a unique array"))
        if not is_nullable_string(action.get("expected_commit_authority")):
            errors.append(Issue("authority_or_state_mismatch", f"action {action.get('id')} expected_commit_authority must be a string or null"))
    approvals = state.get("approvals")
    required_approval_fields = {"action_id", "source", "approved_at", "scope", "contract_hash", "state_revision"}
    if not isinstance(approvals, list):
        errors.append(Issue("authority_or_state_mismatch", "STATE.approvals must be an array"))
    else:
        for index, approval in enumerate(approvals):
            if not isinstance(approval, dict):
                errors.append(Issue("authority_or_state_mismatch", f"STATE.approvals[{index}] must be an object"))
                continue
            missing = required_approval_fields - approval.keys()
            unknown = set(approval) - required_approval_fields
            if missing or unknown:
                errors.append(Issue("authority_or_state_mismatch", f"STATE.approvals[{index}] fields do not match v1.2 approval schema"))
                continue
            if approval.get("source") != "explicit-user":
                errors.append(Issue("authority_or_state_mismatch", f"STATE.approvals[{index}].source must be explicit-user"))
            if any(not isinstance(approval.get(key), str) or not approval[key].strip() for key in ("action_id", "approved_at", "scope", "contract_hash")):
                errors.append(Issue("authority_or_state_mismatch", f"STATE.approvals[{index}] contains an empty string binding"))
            if not is_date_time(approval.get("approved_at")):
                errors.append(Issue("authority_or_state_mismatch", f"STATE.approvals[{index}].approved_at must be an offset-aware date-time"))
            if not is_sha256(approval.get("contract_hash")):
                errors.append(Issue("authority_or_state_mismatch", f"STATE.approvals[{index}].contract_hash must be a lowercase SHA-256 digest"))
            if not isinstance(approval.get("state_revision"), int) or isinstance(approval.get("state_revision"), bool) or approval["state_revision"] < 0:
                errors.append(Issue("authority_or_state_mismatch", f"STATE.approvals[{index}].state_revision must be a non-negative integer"))
    previous_digest = state.get("previous_state_digest")
    if previous_digest is not None and not is_sha256(previous_digest):
        errors.append(Issue("authority_or_state_mismatch", "STATE.previous_state_digest must be null or a lowercase SHA-256 digest"))
    if state.get("benchmark_progress") not in {"none", "partial", "complete"}:
        errors.append(Issue("authority_or_state_mismatch", "STATE.benchmark_progress is invalid"))
    if not isinstance(state.get("rounds_completed"), int) or isinstance(state.get("rounds_completed"), bool) or state.get("rounds_completed", -1) < 0:
        errors.append(Issue("authority_or_state_mismatch", "STATE.rounds_completed must be a non-negative integer"))
    if not is_date_time(state.get("updated_at")):
        errors.append(Issue("authority_or_state_mismatch", "STATE.updated_at must be an offset-aware date-time"))
    for key in ("last_completed_action_id", "blocker", "resume_from", "last_verified", "last_verified_commit", "artifact_path"):
        if not is_nullable_string(state.get(key)):
            errors.append(Issue("authority_or_state_mismatch", f"STATE.{key} must be a string or null"))
    if not isinstance(state.get("next_action_id"), str) or not isinstance(state.get("next_action"), str):
        errors.append(Issue("authority_or_state_mismatch", "STATE terminal and non-terminal action bindings must remain strings, not null"))
    completed = state.get("completed_actions")
    if isinstance(completed, list) and (any(not isinstance(item, str) for item in completed) or len(set(completed)) != len(completed)):
        errors.append(Issue("authority_or_state_mismatch", "STATE.completed_actions must contain unique strings"))
    if state.get("status") == "PASS":
        if state.get("resume_from") is not None:
            errors.append(Issue("authority_or_state_mismatch", "PASS STATE.resume_from must be null"))
        if state.get("last_completed_action_id") != state.get("next_action_id"):
            errors.append(Issue("authority_or_state_mismatch", "PASS STATE must retain the last completed action identity"))
        if not isinstance(completed, list) or state.get("last_completed_action_id") not in completed:
            errors.append(Issue("authority_or_state_mismatch", "PASS STATE.completed_actions must include the terminal action"))
    gate_status = state.get("gate_status")
    if not isinstance(gate_status, list):
        errors.append(Issue("authority_or_state_mismatch", "STATE.gate_status must be an array"))
    else:
        evidence_fields = {"evidence_type", "evidence_ref", "evidence_digest", "verified_at", "verified_action"}
        for index, gate in enumerate(gate_status):
            if not isinstance(gate, dict) or set(gate) != {"id", "satisfied", "evidence"}:
                errors.append(Issue("authority_or_state_mismatch", f"STATE.gate_status[{index}] fields are invalid"))
                continue
            if not isinstance(gate.get("id"), str) or not isinstance(gate.get("satisfied"), bool) or not isinstance(gate.get("evidence"), list):
                errors.append(Issue("authority_or_state_mismatch", f"STATE.gate_status[{index}] types are invalid"))
                continue
            for evidence_index, evidence in enumerate(gate["evidence"]):
                if not isinstance(evidence, dict) or set(evidence) != evidence_fields:
                    errors.append(Issue("authority_or_state_mismatch", f"STATE.gate_status[{index}].evidence[{evidence_index}] fields are invalid"))
                elif not is_sha256(evidence.get("evidence_digest")) or not is_date_time(evidence.get("verified_at")) or any(not isinstance(evidence.get(key), str) for key in ("evidence_type", "evidence_ref", "verified_action")):
                    errors.append(Issue("authority_or_state_mismatch", f"STATE.gate_status[{index}].evidence[{evidence_index}] binding is invalid"))
    return errors


def validate_shape(contract: dict, state: dict) -> list[Issue]:
    version = contract.get("schema_version")
    if version == TASK_V1:
        errors = validate_shape_v1(contract, state)
    elif version == TASK_V11:
        errors = validate_shape_v11(contract, state)
    elif version == TASK_V12:
        errors = validate_shape_v12(contract, state)
    else:
        return [Issue("authority_or_state_mismatch", "unsupported TASK schema_version")]
    if contract.get("task_id") != state.get("task_id"):
        errors.append(Issue("authority_or_state_mismatch", "STATE task_id does not match TASK task_id"))
    if state.get("status") not in STATUSES:
        errors.append(Issue("authority_or_state_mismatch", "STATE.status is invalid"))
    if state.get("status") == "BLOCKED" and not state.get("blocker"):
        errors.append(Issue("authority_or_state_mismatch", "BLOCKED state requires a blocker"))
    project = contract.get("project")
    if not isinstance(project, dict) or not project.get("expected_root"):
        errors.append(Issue("HANDOFF_AUTHORITY_MISSING" if version in MODERN_TASK_VERSIONS else "authority_or_state_mismatch", "TASK.project.expected_root is required"))
    authority = contract.get("authority")
    if not isinstance(authority, dict) or not authority.get("source_ref"):
        errors.append(Issue("HANDOFF_AUTHORITY_MISSING" if version in MODERN_TASK_VERSIONS else "authority_or_state_mismatch", "TASK.authority.source_ref is required"))
    return errors


def git_result(project: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(project), *args], text=True, capture_output=True, check=False)


def git_value(project: Path, *args: str) -> str | None:
    result = git_result(project, *args)
    return result.stdout.strip() if result.returncode == 0 else None


def normalized_remote(value: str) -> str:
    return value.strip().replace("\\", "/").removesuffix(".git").lower()


def git_internal_path(project: Path, name: str) -> Path | None:
    value = git_value(project, "rev-parse", "--git-path", name)
    if value is None:
        return None
    path = Path(value)
    return path if path.is_absolute() else project / path


def validate_project(contract: dict, state: dict, project: Path, allow_dirty_worktree: bool = False) -> list[Issue]:
    errors: list[Issue] = []
    expected = os.path.normcase(os.path.abspath(contract["project"]["expected_root"]))
    actual = os.path.normcase(os.path.abspath(str(project)))
    if actual != expected:
        return [Issue("authority_or_state_mismatch", f"project root mismatch: expected {contract['project']['expected_root']}, got {project}")]
    git = contract["project"].get("git", {})
    if not git.get("required"):
        return errors
    top = git_value(project, "rev-parse", "--show-toplevel")
    if top is None:
        return [Issue("authority_or_state_mismatch", "required Git repository is unavailable")]
    if os.path.normcase(os.path.abspath(top)) != actual:
        errors.append(Issue("authority_or_state_mismatch", f"Git root mismatch: expected {project}, got {top}"))
    current = git_value(project, "rev-parse", "HEAD")
    if contract.get("schema_version") == TASK_V1:
        expected_commit = git.get("baseline_commit")
        if expected_commit and current != expected_commit:
            errors.append(Issue("authority_or_state_mismatch", f"baseline commit mismatch: expected {expected_commit}, got {current or 'unavailable'}"))
        return errors
    branch = git_value(project, "branch", "--show-current")
    if git.get("forbid_detached_head") and not branch:
        errors.append(Issue("authority_or_state_mismatch", "detached HEAD is not allowed"))
    if git.get("forbid_special_operation"):
        for marker in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply", "sequencer"):
            marker_path = git_internal_path(project, marker)
            if marker_path is None:
                errors.append(Issue("authority_or_state_mismatch", f"cannot resolve Git special-operation marker: {marker}"))
            elif marker_path.exists():
                errors.append(Issue("authority_or_state_mismatch", f"special Git operation in progress: {marker}"))
    status = git_result(project, "status", "--porcelain")
    if status.returncode != 0:
        errors.append(Issue("authority_or_state_mismatch", "cannot inspect production worktree status"))
    elif git.get("require_clean_worktree") and status.stdout.strip() and not allow_dirty_worktree:
        errors.append(Issue("authority_or_state_mismatch", "production worktree must be clean"))
    expected_remote = git.get("remote")
    actual_remote = git_value(project, "config", "--get", "remote.origin.url")
    if expected_remote and (not actual_remote or normalized_remote(actual_remote) != normalized_remote(expected_remote)):
        errors.append(Issue("authority_or_state_mismatch", "repository remote identity mismatch"))
    commits = {item.get("id"): item.get("commit") for item in git.get("authorized_commits", []) if isinstance(item, dict)}
    if current not in set(commits.values()):
        errors.append(Issue("authority_or_state_mismatch", f"HEAD is not an authorized task commit: {current or 'unavailable'}"))
    action = action_map(contract).get(state.get("next_action_id"), {})
    authority_id = action.get("expected_commit_authority")
    expected_phase_commit = commits.get(authority_id) if authority_id else None
    if expected_phase_commit and current != expected_phase_commit:
        errors.append(Issue("authority_or_state_mismatch", f"phase commit mismatch for {state.get('next_action_id')}: expected {authority_id} {expected_phase_commit}, got {current or 'unavailable'}"))
    return errors


def resolve_reference(task_dir: Path, reference: str) -> Path:
    path = Path(reference)
    return path if path.is_absolute() else task_dir / path


def validate_gate_evidence(task_dir: Path, contract: dict, state: dict, enforce_required: bool = True) -> list[Issue]:
    if contract.get("schema_version") not in MODERN_TASK_VERSIONS:
        return []
    errors: list[Issue] = []
    gates = {item.get("id"): item for item in contract.get("hard_gates", []) if isinstance(item, dict)}
    statuses = {item.get("id"): item for item in state.get("gate_status", []) if isinstance(item, dict)}
    for gate_id, status in statuses.items():
        if gate_id not in gates:
            errors.append(Issue("authority_or_state_mismatch", f"unknown STATE gate status: {gate_id}"))
            continue
        if not status.get("satisfied"):
            continue
        evidence = status.get("evidence", [])
        if not evidence:
            errors.append(Issue("authority_or_state_mismatch", f"satisfied gate {gate_id} has no evidence"))
            continue
        for item in evidence:
            missing = {"evidence_type", "evidence_ref", "evidence_digest", "verified_at", "verified_action"} - set(item) if isinstance(item, dict) else {"record"}
            if missing:
                errors.append(Issue("authority_or_state_mismatch", f"gate {gate_id} evidence is incomplete: {', '.join(sorted(missing))}"))
                continue
            path = resolve_reference(task_dir, item["evidence_ref"])
            try:
                if file_sha256(path) != item["evidence_digest"]:
                    errors.append(Issue("authority_or_state_mismatch", f"gate {gate_id} evidence digest mismatch"))
            except OSError:
                errors.append(Issue("authority_or_state_mismatch", f"gate {gate_id} evidence reference is unavailable"))
    action = action_map(contract).get(state.get("next_action_id"), {})
    satisfied: set[str] = set()
    for gate_id, value in statuses.items():
        if not value.get("satisfied"):
            continue
        gate = gates.get(gate_id, {})
        records = value.get("evidence", [])
        required_actions = set(gate.get("required_verified_actions", []))
        if required_actions and not required_actions.issubset({item.get("verified_action") for item in records}):
            continue
        if len(records) < gate.get("minimum_evidence", 1):
            continue
        if gate.get("evidence_scope") == "action" and not any(item.get("verified_action") == state.get("next_action_id") for item in records):
            continue
        satisfied.add(gate_id)
    missing_gates = set(action.get("required_hard_gates", [])) - satisfied
    if enforce_required and missing_gates:
        errors.append(Issue("unsatisfied_prerequisites", "required hard gates are unsatisfied: " + ", ".join(sorted(missing_gates))))
    completed = set(state.get("completed_actions", []))
    missing_actions = set(action.get("prerequisites", [])) - completed
    if missing_actions:
        errors.append(Issue("unsatisfied_prerequisites", "action prerequisites are unsatisfied: " + ", ".join(sorted(missing_actions))))
    predecessors = action.get("allowed_predecessors", [])
    last = state.get("last_completed_action_id")
    if predecessors and last not in predecessors:
        errors.append(Issue("unsatisfied_prerequisites", f"invalid predecessor for {state.get('next_action_id')}: {last}"))
    return errors


def validate_audit(task_dir: Path, contract: dict, state: dict) -> list[Issue]:
    if contract.get("schema_version") not in MODERN_TASK_VERSIONS:
        return []
    path = task_dir / "events.jsonl"
    try:
        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, json.JSONDecodeError) as error:
        return [Issue("audit_gap", f"events audit is unavailable or invalid: {error}")]
    if any(not isinstance(event, dict) for event in events):
        return [Issue("audit_gap", "events audit entries must be objects")]
    current_revision = state.get("revision")
    if not isinstance(current_revision, int) or isinstance(current_revision, bool) or current_revision < 0:
        return [Issue("audit_gap", "STATE revision is invalid for audit validation")]
    if contract.get("schema_version") == TASK_V12:
        task_id = contract.get("task_id")
        action_ids = set(action_map(contract))
        gate_ids = {gate.get("id") for gate in contract.get("hard_gates", []) if isinstance(gate, dict)}
        state_event_names = {"created", "gate_recorded", "checkpoint", "automation_transition"}
        lifecycle_event_names = {
            "automation_dispatched", "automation_lease_released",
            "automation_lease_recovered", "contract_resealed",
        }
        lifecycle_shapes = {
            "automation_dispatched": {"at", "event", "task_id", "revision", "action_id", "envelope", "owner"},
            "automation_lease_released": {"at", "event", "task_id", "revision", "action_id", "owner", "nonce_digest"},
            "automation_lease_recovered": {"at", "event", "task_id", "revision", "old_owner", "new_owner", "old_nonce_digest", "new_nonce_digest", "operator", "reason", "authorization_digest"},
            "contract_resealed": {"at", "event", "task_id", "previous_contract_sha256", "contract_sha256", "note"},
        }
        seen_lifecycle: set[tuple[object, ...]] = set()
        state_cursor = -1
        for index, event in enumerate(events):
            name = event.get("event")
            if name not in state_event_names | lifecycle_event_names:
                return [Issue("audit_gap", f"events audit entry {index} has an unknown event identity: {name}")]
            if event.get("task_id") != task_id:
                return [Issue("audit_gap", f"events audit entry {index} is not bound to task_id {task_id}")]
            if parse_approval_time(event.get("at")) is None:
                return [Issue("audit_gap", f"events audit entry {index} has an invalid timestamp")]
            if name in state_event_names:
                revision = event.get("revision")
                if revision != state_cursor + 1:
                    return [Issue("audit_gap", f"state event {index} is out of audit order")]
                state_cursor = revision
            else:
                if set(event) != lifecycle_shapes[name]:
                    return [Issue("audit_gap", f"lifecycle event {index} does not have the exact {name} shape")]
                if name != "contract_resealed" and event.get("revision") != state_cursor:
                    return [Issue("audit_gap", f"lifecycle event {index} is not ordered after its exact state revision")]
                identity = (
                    name,
                    event.get("revision"),
                    event.get("action_id"),
                    event.get("new_nonce_digest"),
                    event.get("contract_sha256"),
                )
                if identity in seen_lifecycle:
                    return [Issue("audit_gap", f"lifecycle event {index} duplicates an existing identity")]
                seen_lifecycle.add(identity)
            if name == "automation_dispatched":
                revision = event.get("revision")
                if not isinstance(revision, int) or isinstance(revision, bool) or not 0 <= revision <= current_revision:
                    return [Issue("audit_gap", f"automation_dispatched entry {index} has an invalid revision")]
                if event.get("action_id") not in action_ids:
                    return [Issue("audit_gap", f"automation_dispatched entry {index} names an unknown action")]
                envelope = event.get("envelope")
                normalized = PurePosixPath(envelope.replace("\\", "/")) if isinstance(envelope, str) else None
                if not envelope or normalized is None or normalized.is_absolute() or ".." in normalized.parts:
                    return [Issue("audit_gap", f"automation_dispatched entry {index} has an invalid envelope reference")]
                if not isinstance(event.get("owner"), str) or not event["owner"].strip():
                    return [Issue("audit_gap", f"automation_dispatched entry {index} has an invalid owner")]
            elif name == "contract_resealed":
                if not is_sha256(event.get("previous_contract_sha256")) or not is_sha256(event.get("contract_sha256")):
                    return [Issue("audit_gap", f"contract_resealed entry {index} has invalid contract digests")]
            elif name == "automation_lease_released":
                if (
                    not isinstance(event.get("revision"), int)
                    or isinstance(event.get("revision"), bool)
                    or not 0 <= event["revision"] <= current_revision
                    or event.get("action_id") not in action_ids
                    or not isinstance(event.get("owner"), str)
                    or not event["owner"].strip()
                    or not is_sha256(event.get("nonce_digest"))
                ):
                    return [Issue("audit_gap", f"automation_lease_released entry {index} has an invalid identity")]
            elif name == "automation_lease_recovered":
                if (
                    not isinstance(event.get("revision"), int)
                    or isinstance(event.get("revision"), bool)
                    or not 0 <= event["revision"] <= current_revision
                    or not all(isinstance(event.get(field), str) and event[field].strip() for field in ("old_owner", "new_owner", "operator", "reason"))
                    or not is_sha256(event.get("old_nonce_digest"))
                    or not is_sha256(event.get("new_nonce_digest"))
                    or not is_sha256(event.get("authorization_digest"))
                ):
                    return [Issue("audit_gap", f"automation_lease_recovered entry {index} has an invalid identity")]
    if contract.get("schema_version") == TASK_V12:
        revision_events = [event for event in events if event.get("event") in state_event_names]
    else:
        revision_events = [
            event
            for event in events
            if event.get("event") != "automation_dispatched"
            and isinstance(event.get("revision"), int)
            and not isinstance(event.get("revision"), bool)
        ]
    revisions = [event["revision"] for event in revision_events]
    expected_revisions = list(range(current_revision + 1))
    if revisions != expected_revisions:
        return [Issue("audit_gap", f"events audit revisions must be continuous and unique: expected {expected_revisions}, got {revisions}")]
    if contract.get("schema_version") == TASK_V12:
        previous_target: str | None = None
        for revision, event in enumerate(revision_events):
            name = event.get("event")
            if revision == 0 and name != "created":
                return [Issue("audit_gap", "revision 0 must be the created event")]
            if revision > 0 and name == "created":
                return [Issue("audit_gap", f"revision {revision} cannot repeat the created event")]
            if name == "gate_recorded":
                if event.get("gate_id") not in gate_ids or not is_sha256(event.get("evidence_digest")):
                    return [Issue("audit_gap", f"revision {revision} has an invalid gate_recorded identity")]
            elif name == "checkpoint":
                if contract.get("schema_version") == TASK_V12:
                    if event.get("completed_action_id") is not None or event.get("next_action_id") not in action_ids:
                        return [Issue("audit_gap", f"revision {revision} has an invalid v1.2 interruption checkpoint identity")]
                elif event.get("completed_action_id") not in action_ids or event.get("next_action_id") not in action_ids:
                    return [Issue("audit_gap", f"revision {revision} has an invalid checkpoint action identity")]
            elif name == "automation_transition":
                if (
                    not is_sha256(event.get("transition_id"))
                    or not isinstance(event.get("result_id"), str)
                    or not event["result_id"].strip()
                    or event.get("action_id") not in action_ids
                    or event.get("outcome") not in {"PASS", "BLOCKED", "FAILED", "RETRYABLE"}
                ):
                    return [Issue("audit_gap", f"revision {revision} has an invalid automation_transition identity")]
            target_digest = event.get("target_state_digest")
            if not is_sha256(target_digest):
                return [Issue("audit_gap", f"revision {revision} has an invalid target_state_digest")]
            if revision > 0:
                previous_digest = event.get("previous_state_digest")
                if not isinstance(previous_digest, str) or previous_digest != previous_target:
                    return [Issue("audit_gap", f"revision {revision} previous_state_digest does not continue the exact state chain")]
            previous_target = target_digest
        try:
            current_state_digest = file_sha256(task_dir / "STATE.json")
        except OSError as error:
            return [Issue("audit_gap", f"STATE digest is unavailable: {error}")]
        if previous_target != current_state_digest:
            return [Issue("audit_gap", "final audit target_state_digest does not match STATE.json")]
    return []


def inspect(
    task_dir: Path,
    project: Path,
    enforce_action_gates: bool = True,
    enforce_audit: bool = True,
    allow_dirty_worktree: bool = False,
) -> tuple[dict, dict, list[Issue]]:
    contract_path, state_path, seal_path = task_dir / "TASK.json", task_dir / "STATE.json", task_dir / "CONTRACT.sha256"
    try:
        contract, state = load_json(contract_path), load_json(state_path)
        expected_seal = seal_path.read_text(encoding="ascii").strip().lower()
        actual_seal = canonical_sha256(contract_path)
        errors = [] if expected_seal == actual_seal else [Issue("authority_or_state_mismatch", "TASK seal mismatch or missing CONTRACT.sha256")]
        errors += validate_shape(contract, state)
        if not errors:
            errors += validate_project(contract, state, project, allow_dirty_worktree=allow_dirty_worktree)
            errors += validate_gate_evidence(task_dir, contract, state, enforce_required=enforce_action_gates)
            if enforce_audit:
                errors += validate_audit(task_dir, contract, state)
        return contract, state, errors
    except (OSError, ValueError) as error:
        return {}, {}, [Issue("authority_or_state_mismatch", str(error))]


def print_stop(issues: list[Issue]) -> int:
    reason = issues[0].reason if issues else "authority_or_state_mismatch"
    print(f"STOP {reason}")
    for issue in issues:
        print(f"- [{issue.reason}] {issue.message}")
    return STOP


def atomic_write_json(path: Path, value: dict, before_replace: Callable[[Path], None] | None = None) -> None:
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if before_replace:
            before_replace(temp_path)
        os.replace(temp_path, path)
        try:
            fsync_parent_directory(path)
        except OSError as error:
            raise AtomicDurabilityError(
                f"atomic replacement completed but parent directory sync failed for {path}"
            ) from error
    finally:
        if temp_path.exists():
            temp_path.unlink()


def fsync_parent_directory(path: Path) -> None:
    """Persist a replaced directory entry where POSIX exposes directory fsync.

    Windows Python does not provide a portable directory handle with equivalent
    semantics, so Windows physical-power-loss durability remains unclaimed.
    """
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path.parent, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def append_event(path: Path, event: dict, before_append: Callable[[], None] | None = None) -> None:
    if before_append:
        before_append()
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


@contextmanager
def checkpoint_lock(task_dir: Path) -> Iterator[None]:
    lock_path = task_dir / ".STATE.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    acquired = False
    try:
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise CheckpointLockError("concurrent_state_change: checkpoint writer lock is already held") from error
        acquired = True
        metadata = {
            "schema_version": "taskcontracts-state-lock.v1",
            "pid": os.getpid(),
            "writer_nonce": secrets.token_hex(16),
            "acquired_at": utc_now(),
            "released_at": None,
            "platform": sys.platform,
        }
        encoded_metadata = json.dumps(metadata, separators=(",", ":")).encode("ascii") + b"\n"
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.write(descriptor, encoded_metadata)
        os.ftruncate(descriptor, len(encoded_metadata))
        os.fsync(descriptor)
        yield
    finally:
        try:
            if acquired:
                metadata["released_at"] = utc_now()
                encoded_metadata = json.dumps(metadata, separators=(",", ":")).encode("ascii") + b"\n"
                os.lseek(descriptor, 0, os.SEEK_SET)
                os.write(descriptor, encoded_metadata)
                os.ftruncate(descriptor, len(encoded_metadata))
                os.fsync(descriptor)
                os.lseek(descriptor, 0, os.SEEK_SET)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def command_seal(args: argparse.Namespace) -> int:
    task_dir = Path(args.task)
    path = task_dir / "CONTRACT.sha256"
    digest = canonical_sha256(task_dir / "TASK.json")
    previous = path.read_text(encoding="ascii").strip().lower() if path.exists() else None
    if previous and previous != digest and not args.reauthor:
        return print_stop([Issue("reauthor_required", "sealed TASK changed; use an explicit re-author/reseal workflow")])
    path.write_text(digest + "\n", encoding="ascii", newline="\n")
    if previous and previous != digest:
        contract = load_json(task_dir / "TASK.json")
        append_event(task_dir / "events.jsonl", {"at": utc_now(), "event": "contract_resealed", "task_id": contract.get("task_id"), "previous_contract_sha256": previous, "contract_sha256": digest, "note": args.note})
    print(f"SEALED task={task_dir.name} sha256={digest}")
    return 0


def print_resume(contract: dict, state: dict) -> None:
    print("RESUME_OK")
    print(f"task_id={contract['task_id']}")
    print(f"schema_version={contract['schema_version']}")
    print(f"task_type={contract['task_type']}")
    print(f"objective={contract['objective']}")
    if contract.get("schema_version") in MODERN_TASK_VERSIONS:
        commits = contract["project"]["git"].get("authorized_commits", [])
        print("repository_authority=" + " | ".join(f"{item['id']}:{item['commit']}" for item in commits))
        print(f"revision={state['revision']}")
        print(f"rounds_completed={state['rounds_completed']}")
        print(f"benchmark_progress={state['benchmark_progress']}")
    print(f"status={state['status']}")
    print(f"current_state={state['current_state']}")
    print(f"blocker={state['blocker']}")
    print(f"next_action={state['next_action_id']}: {state['next_action']}")
    if contract.get("schema_version") in MODERN_TASK_VERSIONS:
        action = action_map(contract)[state["next_action_id"]]
        print("resume_mode=READ_ONLY_INTAKE")
        print("do_not_execute_next_action=true")
        print("execution_requires_new_explicit_user_authorization=true")
        print("action_prerequisites=" + " | ".join(action["prerequisites"]))
        print(f"action_risk={action['risk_level']} fresh_approval_required={str(action['requires_fresh_approval']).lower()}")
        print("authority_notice=task-scope authorization is not system execution approval; higher runtime, AGENTS, MCP, Git, secret, and risk gates still apply")
        print("route_notice=repository state is supporting evidence and must not redefine the task objective")
    print("forbidden_actions=" + " | ".join(contract["forbidden_actions"]))


def command_resume(args: argparse.Namespace) -> int:
    contract, state, errors = inspect(Path(args.task), Path(args.project))
    if errors:
        return print_stop(errors)
    print_resume(contract, state)
    return 0


def parse_approval_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.utcoffset() is not None else None


def approval_valid(contract: dict, state: dict, action_id: str) -> bool:
    if contract.get("schema_version") != TASK_V12:
        return any(
            item.get("action_id") == action_id
            and item.get("source") == "explicit-user"
            and item.get("approved_at")
            for item in state.get("approvals", [])
            if isinstance(item, dict)
        )
    state_updated = parse_approval_time(state.get("updated_at"))
    if state_updated is None:
        return False
    contract_hash = hashlib.sha256(canonical_bytes(contract)).hexdigest()
    for item in state.get("approvals", []):
        if not isinstance(item, dict) or item.get("action_id") != action_id or item.get("source") != "explicit-user":
            continue
        approved_at = parse_approval_time(item.get("approved_at"))
        if (
            approved_at is not None
            and approved_at >= state_updated
            and item.get("contract_hash") == contract_hash
            and item.get("state_revision") == state.get("revision")
            and isinstance(item.get("scope"), str)
            and bool(item["scope"].strip())
        ):
            return True
    return False


def validate_action_authorization(contract: dict, state: dict, action_id: str) -> list[Issue]:
    actions = action_map(contract)
    if action_id != state.get("next_action_id") or action_id not in actions:
        return [Issue("approval_required", "dispatch action is not the current sealed action")]
    action = actions[action_id]
    approval_required = action.get("requires_fresh_approval") is True or action.get("risk_level") in {"L3", "L4"}
    if approval_required and not approval_valid(contract, state, action_id):
        return [Issue("approval_required", f"fresh explicit-user approval is required for {action_id}")]
    return []


def validate_transition(contract: dict, state: dict, completed_id: str, next_id: str) -> list[Issue]:
    actions = action_map(contract)
    if completed_id != state.get("next_action_id") or completed_id not in actions or next_id not in actions:
        return [Issue("unsatisfied_prerequisites", "checkpoint does not complete the currently selected action or selects an unknown next action")]
    current = actions[completed_id]
    if next_id not in current.get("allowed_next_actions", []):
        return [Issue("unsatisfied_prerequisites", f"illegal action transition: {completed_id} -> {next_id}")]
    return validate_action_authorization(contract, state, completed_id)


def validate_evidence_document(task_dir: Path, contract: dict, state: dict, gate_id: str, evidence_path: Path) -> tuple[dict | None, list[Issue]]:
    try:
        evidence = load_json(evidence_path)
    except ValueError as error:
        return None, [Issue("authority_or_state_mismatch", str(error))]
    fields = {"task_id", "action_id", "gate_id", "evidence_type", "artifact_path", "artifact_digest", "timestamp", "verified_action", "runtime_metadata"}
    missing = fields - evidence.keys()
    if missing:
        return None, [Issue("authority_or_state_mismatch", "gate evidence fields are missing: " + ", ".join(sorted(missing)))]
    if evidence["task_id"] != contract.get("task_id") or evidence["action_id"] != state.get("next_action_id") or evidence["gate_id"] != gate_id:
        return None, [Issue("authority_or_state_mismatch", "gate evidence task, action, or gate binding mismatch")]
    gates = {item.get("id"): item for item in contract.get("hard_gates", []) if isinstance(item, dict)}
    gate = gates.get(gate_id)
    if not gate or evidence["evidence_type"] not in gate.get("required_evidence", []):
        return None, [Issue("acceptance_substitution", "evidence class cannot satisfy the selected hard gate")]
    artifact = resolve_reference(task_dir, evidence["artifact_path"])
    try:
        if file_sha256(artifact) != evidence["artifact_digest"]:
            return None, [Issue("authority_or_state_mismatch", "referenced artifact digest mismatch")]
    except OSError:
        return None, [Issue("authority_or_state_mismatch", "referenced artifact is unavailable")]
    runtime = evidence.get("runtime_metadata", {})
    if gate.get("type") == "runtime-assertion" and gate_id == "browser-gate":
        expected = {"chrome_major": 154, "existing_intended_runtime": True, "extension_runtime_available": True, "chrome_runtime_id_non_null": True, "language_model_exists": True, "availability_most_predictable": "available"}
        if any(runtime.get(key) != value for key, value in expected.items()) or not runtime.get("manifest_version"):
            return None, [Issue("unsatisfied_prerequisites", "browser runtime evidence does not satisfy the complete Browser Gate")]
    if gate.get("type") == "engine-assertion":
        if runtime.get("engine", {}).get("type") != "lm":
            return None, [Issue("acceptance_substitution", "engine evidence must bind engine.type=lm")]
        for field in ("round_id", "branch", "commit"):
            if not evidence.get(field):
                return None, [Issue("authority_or_state_mismatch", f"engine evidence requires {field}")]
    record = {"evidence_type": evidence["evidence_type"], "evidence_ref": str(evidence_path), "evidence_digest": file_sha256(evidence_path), "verified_at": evidence["timestamp"], "verified_action": evidence["verified_action"]}
    return record, []


def command_record_gate(args: argparse.Namespace) -> int:
    task_dir, project = Path(args.task), Path(args.project)
    try:
        with checkpoint_lock(task_dir):
            contract, state, errors = inspect(task_dir, project, enforce_action_gates=False)
            if errors:
                return print_stop(errors)
            if contract.get("schema_version") not in MODERN_TASK_VERSIONS:
                return print_stop([Issue("invalid_contract", "record-gate requires a modern task contract")])
            if state["revision"] != args.expected_revision:
                return print_stop([Issue("concurrent_state_change", f"expected revision {args.expected_revision}, current revision is {state['revision']}")])
            record, errors = validate_evidence_document(task_dir, contract, state, args.gate_id, Path(args.evidence))
            if errors:
                return print_stop(errors)
            statuses = [dict(item) for item in state["gate_status"]]
            match = next((item for item in statuses if item.get("id") == args.gate_id), None)
            if match is None:
                return print_stop([Issue("authority_or_state_mismatch", "STATE has no status slot for the selected gate")])
            records = [item for item in match.get("evidence", []) if item.get("verified_action") != record["verified_action"]]
            records.append(record)
            match["evidence"] = records
            gate = next(item for item in contract["hard_gates"] if item.get("id") == args.gate_id)
            required_actions = set(gate.get("required_verified_actions", []))
            match["satisfied"] = len(records) >= gate.get("minimum_evidence", 1) and required_actions.issubset({item.get("verified_action") for item in records})
            now = utc_now()
            previous_digest = file_sha256(task_dir / "STATE.json")
            new_state = dict(state)
            new_state.update({"revision": state["revision"] + 1, "previous_state_digest": previous_digest, "gate_status": statuses, "updated_at": now})
            atomic_write_json(task_dir / "STATE.json", new_state)
            target_digest = file_sha256(task_dir / "STATE.json")
            try:
                event = {"at": now, "event": "gate_recorded", "task_id": contract["task_id"], "revision": new_state["revision"], "previous_state_digest": previous_digest, "gate_id": args.gate_id, "evidence_digest": record["evidence_digest"]}
                if contract.get("schema_version") == TASK_V12:
                    event["target_state_digest"] = target_digest
                append_event(task_dir / "events.jsonl", event)
            except OSError as error:
                raise AuditAppendError(str(error)) from error
            print(f"GATE_RECORDED task_id={contract['task_id']} gate_id={args.gate_id} revision={new_state['revision']}")
            return 0
    except AtomicDurabilityError as error:
        return print_stop([Issue("durability_sync_failed_after_state_commit", str(error))])
    except AuditAppendError as error:
        return print_stop([Issue("audit_append_failed_after_state_commit", str(error))])
    except ValueError as error:
        message = str(error)
        reason = "concurrent_state_change" if message.startswith("concurrent_state_change") else "invalid_contract"
        return print_stop([Issue(reason, message.removeprefix("concurrent_state_change: "))])


def command_checkpoint(args: argparse.Namespace) -> int:
    task_dir, project = Path(args.task), Path(args.project)
    try:
        with checkpoint_lock(task_dir):
            contract, state, errors = inspect(task_dir, project)
            if errors:
                return print_stop(errors)
            if contract.get("schema_version") in MODERN_TASK_VERSIONS:
                if args.expected_revision is None:
                    return print_stop([Issue("concurrent_state_change", "modern checkpoint requires --expected-revision")])
                if state["revision"] != args.expected_revision:
                    return print_stop([Issue("concurrent_state_change", f"expected revision {args.expected_revision}, current revision is {state['revision']}")])
                if contract.get("schema_version") == TASK_V12 and args.status == "PASS":
                    return print_stop([Issue(
                        "automation_result_required",
                        "v1.2 terminal PASS requires submit-result so bound evidence and verification are checked",
                    )])
                if contract.get("schema_version") == TASK_V12:
                    if args.completed_action_id is not None or args.next_action_id != state["next_action_id"]:
                        return print_stop([Issue(
                            "automation_result_required",
                            "v1.2 checkpoint is an interruption snapshot; action completion or advancement requires submit-result",
                        )])
                else:
                    errors = validate_transition(contract, state, args.completed_action_id, args.next_action_id)
                    if errors:
                        return print_stop(errors)
            actions = action_map(contract)
            if args.next_action_id not in actions:
                raise ValueError("next_action_id is not allowed by TASK")
            now = utc_now()
            previous_digest = file_sha256(task_dir / "STATE.json")
            new_state = dict(state)
            new_state.update({"status": args.status, "current_state": args.current_state, "next_action_id": args.next_action_id, "next_action": actions[args.next_action_id]["action"], "blocker": args.blocker, "resume_from": args.resume_from, "last_verified": args.last_verified, "last_verified_commit": args.last_verified_commit, "artifact_path": args.artifact_path, "updated_at": now})
            if contract.get("schema_version") in MODERN_TASK_VERSIONS:
                new_state["revision"] = state["revision"] + 1
                new_state["previous_state_digest"] = previous_digest
                if contract.get("schema_version") != TASK_V12:
                    new_state["completed_actions"] = list(dict.fromkeys([*state["completed_actions"], args.completed_action_id]))
                    new_state["last_completed_action_id"] = args.completed_action_id
            atomic_write_json(task_dir / "STATE.json", new_state)
            target_digest = file_sha256(task_dir / "STATE.json")
            event = {"at": now, "event": "checkpoint", "task_id": contract["task_id"], "status": args.status, "note": args.note, "last_verified": args.last_verified}
            if contract.get("schema_version") in MODERN_TASK_VERSIONS:
                event.update({"revision": new_state["revision"], "previous_state_digest": previous_digest, "completed_action_id": args.completed_action_id, "next_action_id": args.next_action_id})
            if contract.get("schema_version") == TASK_V12:
                event["target_state_digest"] = target_digest
            try:
                append_event(task_dir / "events.jsonl", event)
            except OSError as error:
                raise AuditAppendError(str(error)) from error
            print(f"CHECKPOINT_OK task_id={contract['task_id']} status={args.status} revision={new_state.get('revision', 'legacy')}")
            return 0
    except AtomicDurabilityError as error:
        return print_stop([Issue("durability_sync_failed_after_state_commit", str(error))])
    except AuditAppendError as error:
        return print_stop([Issue("audit_append_failed_after_state_commit", str(error))])
    except ValueError as error:
        message = str(error)
        reason = "concurrent_state_change" if message.startswith("concurrent_state_change") else "invalid_contract"
        return print_stop([Issue(reason, message.removeprefix("concurrent_state_change: "))])


def command_route_check(args: argparse.Namespace) -> int:
    contract, state, errors = inspect(Path(args.task), Path(args.project))
    if errors:
        return print_stop(errors)
    action = action_map(contract).get(args.action_id)
    if not action:
        return print_stop([Issue("authority_or_state_mismatch", "proposed action is outside the task action graph")])
    if args.route_class != contract.get("task_type") or action.get("route_class") != args.route_class:
        return print_stop([Issue("route_class_mismatch", "proposed route class does not match the sealed task class")])
    if args.evidence_class and args.evidence_class not in action.get("required_evidence_classes", []):
        return print_stop([Issue("acceptance_substitution", "proposed evidence class cannot satisfy this action")])
    if args.action_id != state.get("next_action_id"):
        return print_stop([Issue("unsatisfied_prerequisites", "proposed action is not the current next action")])
    print(f"ROUTE_OK action_id={args.action_id}")
    return 0


def command_resume_handoff(args: argparse.Namespace) -> int:
    try:
        handoff = load_json(Path(args.handoff))
        reference = handoff.get("taskContractRef")
        if not isinstance(reference, dict) or reference.get("verificationRequired") is not True:
            return print_stop([Issue("authority_missing", "handoff reference is missing or not independently verifiable")])
        task_dir = Path(args.task_root) / str(reference.get("taskId", ""))
        if not task_dir.is_dir():
            return print_stop([Issue("authority_missing", "referenced Task Contract bundle is unavailable")])
        seal = (task_dir / "CONTRACT.sha256").read_text(encoding="ascii").strip().lower()
        if seal != reference.get("contractSha256"):
            return print_stop([Issue("authority_missing", "handoff digest does not match the referenced bundle")])
        return command_resume(argparse.Namespace(task=str(task_dir), project=args.project))
    except (OSError, ValueError) as error:
        return print_stop([Issue("authority_missing", str(error))])


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    seal = commands.add_parser("seal")
    seal.add_argument("--task", required=True)
    seal.add_argument("--reauthor", action="store_true")
    seal.add_argument("--note")
    seal.set_defaults(func=command_seal)
    resume = commands.add_parser("resume")
    resume.add_argument("--task", required=True)
    resume.add_argument("--project", required=True)
    resume.set_defaults(func=command_resume)
    checkpoint = commands.add_parser("checkpoint")
    checkpoint.add_argument("--task", required=True)
    checkpoint.add_argument("--project", required=True)
    checkpoint.add_argument("--expected-revision", type=int)
    checkpoint.add_argument("--completed-action-id")
    checkpoint.add_argument("--status", required=True, choices=sorted(STATUSES))
    checkpoint.add_argument("--current-state", required=True)
    checkpoint.add_argument("--next-action-id", required=True)
    checkpoint.add_argument("--blocker", default=None)
    checkpoint.add_argument("--resume-from", default=None)
    checkpoint.add_argument("--last-verified", default=None)
    checkpoint.add_argument("--last-verified-commit", default=None)
    checkpoint.add_argument("--artifact-path", default=None)
    checkpoint.add_argument("--note", required=True)
    checkpoint.set_defaults(func=command_checkpoint)
    route = commands.add_parser("route-check")
    route.add_argument("--task", required=True)
    route.add_argument("--project", required=True)
    route.add_argument("--action-id", required=True)
    route.add_argument("--route-class", required=True)
    route.add_argument("--evidence-class")
    route.set_defaults(func=command_route_check)
    gate = commands.add_parser("record-gate")
    gate.add_argument("--task", required=True)
    gate.add_argument("--project", required=True)
    gate.add_argument("--expected-revision", required=True, type=int)
    gate.add_argument("--gate-id", required=True)
    gate.add_argument("--evidence", required=True)
    gate.set_defaults(func=command_record_gate)
    handoff = commands.add_parser("resume-handoff")
    handoff.add_argument("--handoff", required=True)
    handoff.add_argument("--task-root", required=True)
    handoff.add_argument("--project", required=True)
    handoff.set_defaults(func=command_resume_handoff)
    return root


if __name__ == "__main__":
    arguments = parser().parse_args()
    try:
        sys.exit(arguments.func(arguments))
    except ValueError as error:
        print(f"STOP invalid_contract: {error}")
        sys.exit(STOP)
