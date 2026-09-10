from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

import sys

sys.path.insert(0, str(SCRIPTS))

import task_contract as contract_runtime
import task_orchestrator as orchestrator


class InjectedCrash(RuntimeError):
    pass


class TransactionRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="TaskContracts-P0-B-")
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.task = self.root / "task"
        self.project.mkdir()
        self.task.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.project)], check=True)
        subprocess.run(["git", "-C", str(self.project), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.project), "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", str(self.project), "remote", "add", "origin", "https://example.invalid/taskcontracts/p0-b.git"], check=True)
        (self.project / "README.md").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.project), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(self.project), "commit", "-qm", "fixture"], check=True)
        self.commit = subprocess.run(
            ["git", "-C", str(self.project), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        self.contract = self._contract()
        self.state = self._state()
        self._write_bundle()
        paths = orchestrator.ensure_runtime_dirs(self.task)
        self.lease = orchestrator.acquire_lease(paths, self.contract["task_id"], "test-owner")
        self.baseline = orchestrator.capture_workspace_baseline(self.task, self.project, self.contract, self.state)
        artifact = self.project / "src" / "evidence.txt"
        artifact.parent.mkdir(exist_ok=True)
        artifact.write_text("verified recovery evidence\n", encoding="utf-8")
        self.result_path = self.root / "result.json"
        self.result = self._result()
        self._write_result(self.result)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _contract(self) -> dict:
        action = {
            "id": "p0-b-action",
            "action": "Exercise transaction recovery.",
            "task_scope_authorized": True,
            "risk_level": "L1",
            "requires_fresh_approval": False,
            "prerequisites": [],
            "allowed_predecessors": [],
            "expected_commit_authority": "BASE",
            "allowed_next_actions": [],
            "required_hard_gates": [],
            "required_evidence_classes": ["focused-test"],
            "route_class": "development",
            "allowed_workspace_paths": ["src"],
            "executor_routes": ["KEEP_SINGLE"],
            "authority_expansion": False,
        }
        return {
            "schema_version": "1.2",
            "contract_version": 2,
            "task_id": "fixture-p0-b",
            "project": {
                "project_id": "fixture",
                "expected_root": str(self.project),
                "git": {
                    "required": True,
                    "remote": "https://example.invalid/taskcontracts/p0-b.git",
                    "authorized_commits": [{"id": "BASE", "ref": "main", "commit": self.commit}],
                    "require_clean_worktree": True,
                    "forbid_detached_head": True,
                    "forbid_special_operation": True,
                },
            },
            "task_type": "development",
            "objective": "Verify exact, idempotent transition recovery.",
            "authority": {"kind": "user-direct", "source_ref": "test:p0-b", "issued_at": "2026-09-03T00:00:00Z", "supersedes": None},
            "authority_order": [
                "platform-runtime", "tool-mcp-enforcement", "current-user-authorization",
                "effective-agents-policy", "sealed-task", "validated-state",
                "repository-runtime-evidence", "handoff-events-artifacts",
            ],
            "baseline": {"description": "No transition committed.", "required_inputs": []},
            "allowed_actions": [action],
            "forbidden_actions": ["Do not expand beyond the fixture."],
            "hard_gates": [{
                "id": "fixture-gate", "type": "policy-assertion", "required": False,
                "required_state": "accepted", "required_evidence": ["focused-test"],
                "evidence_scope": "task",
            }],
            "acceptance": [{"id": "recovery", "criterion": "Recovery converges exactly once.", "evidence_classes": ["focused-test"], "substitution_forbidden": True}],
            "artifacts": {"root": str(self.root / "artifacts"), "expected": []},
            "policy_boundaries": {"task_scope_is_execution_approval": False, "denied_action_ids": [], "handoff_authority_role": "reference-envelope-only", "repository_state_authority_role": "supporting-evidence-only"},
            "resource_requirements": [],
            "threat_model": {"seal_role": "accidental-procedural-integrity", "external_authenticity_anchor": False},
        }

    def _state(self) -> dict:
        action = self.contract["allowed_actions"][0]
        return {
            "schema_version": "1.2",
            "task_id": self.contract["task_id"],
            "revision": 0,
            "previous_state_digest": None,
            "status": "READY",
            "current_state": "No transition committed.",
            "completed_actions": [],
            "last_completed_action_id": None,
            "next_action_id": action["id"],
            "next_action": action["action"],
            "blocker": None,
            "resume_from": action["id"],
            "rounds_completed": 0,
            "benchmark_progress": "none",
            "gate_status": [{"id": "fixture-gate", "satisfied": False, "evidence": []}],
            "approvals": [],
            "last_verified": None,
            "last_verified_commit": self.commit,
            "artifact_path": str(self.root / "artifacts"),
            "updated_at": "2026-09-03T00:00:00Z",
        }

    def _result(self) -> dict:
        contract_digest = contract_runtime.canonical_sha256(self.task / "TASK.json")
        return {
            "schema_version": orchestrator.RESULT_SCHEMA_VERSION,
            "result_id": "result-1",
            "task_id": self.contract["task_id"],
            "contract_hash": contract_digest,
            "workspace_baseline_digest": self.baseline["workspace_baseline_digest"],
            "lease_nonce": self.lease["nonce"],
            "state_revision_seen": 0,
            "action_id": "p0-b-action",
            "executor": "fixture-executor",
            "outcome": "PASS",
            "summary": "Transaction completed.",
            "changed_paths": ["src/evidence.txt"],
            "evidence": [{
                "evidence_id": "evidence-1",
                "evidence_class": "focused-test",
                "task_id": self.contract["task_id"],
                "contract_hash": contract_digest,
                "state_revision_seen": 0,
                "action_id": "p0-b-action",
                "verified_action": "p0-b-action",
                "verifier": orchestrator.LOCAL_ARTIFACT_VERIFIER,
                "timestamp": "2026-09-03T00:00:01Z",
                "verification_basis": "artifact",
                "artifact_path": "src/evidence.txt",
                "artifact_digest": contract_runtime.file_sha256(self.project / "src" / "evidence.txt"),
                "artifact_size": (self.project / "src" / "evidence.txt").stat().st_size,
            }],
            "verification": {"status": "PASS", "checks": [{
                "check_id": "focused-recovery",
                "status": "PASS",
                "summary": "Focused recovery fixture passed.",
                "evidence_ids": ["evidence-1"],
            }]},
        }

    def _write_bundle(self) -> None:
        (self.task / "TASK.json").write_text(json.dumps(self.contract, indent=2) + "\n", encoding="utf-8")
        (self.task / "STATE.json").write_text(json.dumps(self.state, indent=2) + "\n", encoding="utf-8")
        state_digest = contract_runtime.file_sha256(self.task / "STATE.json")
        (self.task / "events.jsonl").write_text(json.dumps({"at": "2026-09-03T00:00:00Z", "event": "created", "task_id": self.contract["task_id"], "revision": 0, "target_state_digest": state_digest}) + "\n", encoding="utf-8")
        (self.task / "CONTRACT.sha256").write_text(contract_runtime.canonical_sha256(self.task / "TASK.json") + "\n", encoding="ascii")

    def _write_result(self, result: dict) -> None:
        self.result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    def _submit_args(self) -> Namespace:
        return Namespace(task=str(self.task), project=str(self.project), owner="test-owner", result=str(self.result_path))

    def _recover_args(self) -> Namespace:
        return Namespace(task=str(self.task), project=str(self.project))

    def _transition_events(self) -> list[dict]:
        return [
            json.loads(line)
            for line in (self.task / "events.jsonl").read_text(encoding="utf-8").splitlines()
            if line and json.loads(line).get("event") == "automation_transition"
        ]

    def _exercise_fault(self, fault_name: str, expected_revision: int, expected_events: int, expected_receipt: bool) -> None:
        def crash(name: str) -> None:
            if name == fault_name:
                raise InjectedCrash(name)

        with mock.patch.object(orchestrator, "_fault_hook", side_effect=crash):
            with self.assertRaises(InjectedCrash):
                orchestrator.command_submit(self._submit_args())
        paths = orchestrator.runtime_paths(self.task)
        self.assertTrue(paths["journal"].exists())
        self.assertEqual(json.loads((self.task / "STATE.json").read_text(encoding="utf-8"))["revision"], expected_revision)
        self.assertEqual(len(self._transition_events()), expected_events)
        self.assertEqual((paths["results"] / "result-1.json").exists(), expected_receipt)
        self.assertEqual(orchestrator.command_recover(self._recover_args()), 0)
        self.assertFalse(paths["journal"].exists())
        self.assertEqual(json.loads((self.task / "STATE.json").read_text(encoding="utf-8"))["revision"], 1)
        self.assertEqual(len(self._transition_events()), 1)
        self.assertTrue((paths["results"] / "result-1.json").exists())
        self.assertEqual(orchestrator.command_recover(self._recover_args()), 0)
        self.assertEqual(orchestrator.command_submit(self._submit_args()), 0)
        self.assertEqual(len(self._transition_events()), 1)
        terminal = json.loads((self.task / "STATE.json").read_text(encoding="utf-8"))
        self.assertEqual(terminal["status"], "PASS")
        self.assertEqual(terminal["next_action_id"], "p0-b-action")
        self.assertEqual(terminal["next_action"], "Exercise transaction recovery.")
        self.assertIsNone(terminal["resume_from"])

    def test_fault_after_wal_recovers(self) -> None:
        self._exercise_fault(orchestrator.FAULT_AFTER_WAL, 0, 0, False)

    def test_fault_after_state_recovers_audit_gap(self) -> None:
        self._exercise_fault(orchestrator.FAULT_AFTER_STATE, 1, 0, False)

    def test_fault_after_event_recovers(self) -> None:
        self._exercise_fault(orchestrator.FAULT_AFTER_EVENT, 1, 1, False)

    def test_fault_after_receipt_recovers(self) -> None:
        self._exercise_fault(orchestrator.FAULT_AFTER_RECEIPT, 1, 1, True)

    def test_result_id_rejects_path_material_without_side_effects(self) -> None:
        for result_id in ("../STATE", "nested/result", r"nested\result", ".", "C:result", "result.json"):
            with self.subTest(result_id=result_id):
                invalid = {**self.result, "result_id": result_id}
                self._write_result(invalid)
                self.assertEqual(orchestrator.command_submit(self._submit_args()), 42)
                paths = orchestrator.runtime_paths(self.task)
                self.assertFalse(paths["journal"].exists())
                self.assertEqual(list(paths["results"].glob("*.json")), [])

    def test_duplicate_requires_exact_result_receipt_state_and_event(self) -> None:
        self.assertEqual(orchestrator.command_submit(self._submit_args()), 0)
        self.assertEqual(orchestrator.command_submit(self._submit_args()), 0)
        changed = {**self.result, "summary": "Different content."}
        self._write_result(changed)
        self.assertEqual(orchestrator.command_submit(self._submit_args()), 42)
        self._write_result(self.result)
        receipt_path = orchestrator.runtime_paths(self.task)["results"] / "result-1.json"
        original_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        corrupt_receipt = dict(original_receipt)
        corrupt_receipt["target_state_digest"] = "0" * 64
        corrupt_receipt["binding_digest"] = orchestrator.sha256_json(orchestrator._receipt_binding(corrupt_receipt))
        contract_runtime.atomic_write_json(receipt_path, corrupt_receipt)
        self.assertEqual(orchestrator.command_submit(self._submit_args()), 42)
        contract_runtime.atomic_write_json(receipt_path, original_receipt)
        events_path = self.task / "events.jsonl"
        events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line]
        events[-1]["outcome"] = "FAILED"
        events_path.write_text("".join(json.dumps(event, separators=(",", ":")) + "\n" for event in events), encoding="utf-8")
        self.assertEqual(orchestrator.command_submit(self._submit_args()), 42)

    def test_tampered_wal_and_unexplained_audit_gap_fail_closed(self) -> None:
        def crash_after_wal(name: str) -> None:
            if name == orchestrator.FAULT_AFTER_WAL:
                raise InjectedCrash(name)

        with mock.patch.object(orchestrator, "_fault_hook", side_effect=crash_after_wal):
            with self.assertRaises(InjectedCrash):
                orchestrator.command_submit(self._submit_args())
        journal_path = orchestrator.runtime_paths(self.task)["journal"]
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        journal["target_state_digest"] = "0" * 64
        contract_runtime.atomic_write_json(journal_path, journal)
        before = (self.task / "STATE.json").read_bytes()
        self.assertEqual(orchestrator.command_recover(self._recover_args()), 42)
        self.assertEqual((self.task / "STATE.json").read_bytes(), before)
        journal_path.unlink()
        state = json.loads((self.task / "STATE.json").read_text(encoding="utf-8"))
        state["revision"] = 1
        contract_runtime.atomic_write_json(self.task / "STATE.json", state)
        self.assertEqual(orchestrator.command_recover(self._recover_args()), 42)

    def test_dispatch_lifecycle_marker_cannot_mask_missing_state_event(self) -> None:
        def crash_after_wal(name: str) -> None:
            if name == orchestrator.FAULT_AFTER_WAL:
                raise InjectedCrash(name)

        with mock.patch.object(orchestrator, "_fault_hook", side_effect=crash_after_wal):
            with self.assertRaises(InjectedCrash):
                orchestrator.command_submit(self._submit_args())
        marker = {
            "at": "2026-09-03T00:00:01Z",
            "event": "automation_dispatched",
            "task_id": self.contract["task_id"],
            "revision": 0,
            "action_id": "p0-b-action",
            "envelope": ".automation/envelopes/r0-p0-b-action.json",
            "owner": "test-owner",
        }
        (self.task / "events.jsonl").write_text(json.dumps(marker) + "\n", encoding="utf-8")
        before = (self.task / "STATE.json").read_bytes()
        self.assertEqual(orchestrator.command_recover(self._recover_args()), 42)
        self.assertEqual((self.task / "STATE.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
