import copy
import json
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "task_orchestrator.py"
sys.path.insert(0, str(ROOT / "scripts"))

import task_contract as contract_runtime
import task_orchestrator as orchestrator


class TaskOrchestratorP0ATests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="TaskContracts-P0-A-")
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.task = self.root / "task-v12"
        self.project.mkdir()
        self.task.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.project)], check=True)
        subprocess.run(["git", "-C", str(self.project), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.project), "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", str(self.project), "remote", "add", "origin", "https://example.invalid/taskcontracts/p0-a.git"], check=True)
        (self.project / "README.md").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.project), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(self.project), "commit", "-qm", "fixture"], check=True)
        self.commit = subprocess.run(
            ["git", "-C", str(self.project), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        self.contract = self.make_contract()
        self.state = self.make_state()
        self.write_bundle()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_contract(self) -> dict:
        action = {
            "id": "implement-p0-a",
            "action": "Implement the bounded P0-A fixture.",
            "task_scope_authorized": True,
            "risk_level": "L3",
            "requires_fresh_approval": True,
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
            "task_id": "fixture-p0-a",
            "project": {
                "project_id": "fixture",
                "expected_root": str(self.project),
                "git": {
                    "required": True,
                    "remote": "https://example.invalid/taskcontracts/p0-a.git",
                    "authorized_commits": [{"id": "BASE", "ref": "main", "commit": self.commit}],
                    "require_clean_worktree": True,
                    "forbid_detached_head": True,
                    "forbid_special_operation": True,
                },
            },
            "task_type": "development",
            "objective": "Exercise the P0-A automation boundary.",
            "authority": {
                "kind": "user-direct",
                "source_ref": "test:p0-a",
                "issued_at": "2026-09-03T00:00:00Z",
                "supersedes": None,
            },
            "authority_order": [
                "platform-runtime",
                "tool-mcp-enforcement",
                "current-user-authorization",
                "effective-agents-policy",
                "sealed-task",
                "validated-state",
                "repository-runtime-evidence",
                "handoff-events-artifacts",
            ],
            "baseline": {"description": "No action started.", "required_inputs": []},
            "allowed_actions": [action],
            "forbidden_actions": ["Do not expand authority."],
            "hard_gates": [{
                "id": "fixture-gate",
                "type": "policy-assertion",
                "required": False,
                "required_state": "accepted",
                "required_evidence": ["focused-test"],
                "evidence_scope": "task",
            }],
            "acceptance": [{
                "id": "focused-tests",
                "criterion": "Focused tests pass.",
                "evidence_classes": ["focused-test"],
                "substitution_forbidden": True,
            }],
            "artifacts": {"root": str(self.root / "artifacts"), "expected": []},
            "policy_boundaries": {
                "task_scope_is_execution_approval": False,
                "denied_action_ids": [],
                "handoff_authority_role": "reference-envelope-only",
                "repository_state_authority_role": "supporting-evidence-only",
            },
            "resource_requirements": [],
            "threat_model": {
                "seal_role": "accidental-procedural-integrity",
                "external_authenticity_anchor": False,
            },
        }

    def make_state(self) -> dict:
        action = self.contract["allowed_actions"][0]
        return {
            "schema_version": "1.2",
            "task_id": self.contract["task_id"],
            "revision": 0,
            "previous_state_digest": None,
            "status": "READY",
            "current_state": "No action completed.",
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

    def write_bundle(self) -> None:
        (self.task / "TASK.json").write_text(json.dumps(self.contract, indent=2) + "\n", encoding="utf-8")
        (self.task / "STATE.json").write_text(json.dumps(self.state, indent=2) + "\n", encoding="utf-8")
        state_digest = contract_runtime.file_sha256(self.task / "STATE.json")
        (self.task / "events.jsonl").write_text(
            json.dumps({"at": "2026-09-03T00:00:00Z", "event": "created", "task_id": self.contract["task_id"], "revision": 0, "target_state_digest": state_digest}) + "\n",
            encoding="utf-8",
        )
        (self.task / "CONTRACT.sha256").write_text(
            contract_runtime.canonical_sha256(self.task / "TASK.json") + "\n",
            encoding="ascii",
        )

    def run_dispatch(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "dispatch",
                "--task",
                str(self.task),
                "--project",
                str(self.project),
                "--owner",
                "test-owner",
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def fresh_approval(self, approved_at: str = "2026-09-03T00:00:01Z") -> None:
        self.state["approvals"] = [{
            "action_id": "implement-p0-a",
            "source": "explicit-user",
            "approved_at": approved_at,
            "scope": "dispatch implement-p0-a at the current sealed revision",
            "contract_hash": contract_runtime.canonical_sha256(self.task / "TASK.json"),
            "state_revision": self.state["revision"],
        }]
        self.write_bundle()

    def valid_result(self) -> dict:
        contract_hash = contract_runtime.canonical_sha256(self.task / "TASK.json")
        paths = orchestrator.ensure_runtime_dirs(self.task)
        lease = orchestrator.acquire_lease(paths, self.contract["task_id"], "test-owner")
        baseline = orchestrator.capture_workspace_baseline(self.task, self.project, self.contract, self.state)
        artifact = self.project / "src" / "evidence.txt"
        artifact.parent.mkdir(exist_ok=True)
        artifact.write_text("verified fixture evidence\n", encoding="utf-8")
        return {
            "schema_version": orchestrator.RESULT_SCHEMA_VERSION,
            "result_id": "result-1",
            "task_id": self.contract["task_id"],
            "contract_hash": contract_hash,
            "workspace_baseline_digest": baseline["workspace_baseline_digest"],
            "lease_nonce": lease["nonce"],
            "state_revision_seen": self.state["revision"],
            "action_id": "implement-p0-a",
            "executor": "fixture-executor",
            "outcome": "PASS",
            "summary": "Focused checks passed.",
            "changed_paths": ["src/evidence.txt"],
            "evidence": [{
                "evidence_id": "evidence-1",
                "evidence_class": "focused-test",
                "task_id": self.contract["task_id"],
                "contract_hash": contract_hash,
                "state_revision_seen": self.state["revision"],
                "action_id": "implement-p0-a",
                "verified_action": "implement-p0-a",
                "verifier": orchestrator.LOCAL_ARTIFACT_VERIFIER,
                "timestamp": "2026-09-03T00:00:02Z",
                "verification_basis": "artifact",
                "artifact_path": "src/evidence.txt",
                "artifact_digest": contract_runtime.file_sha256(artifact),
                "artifact_size": artifact.stat().st_size,
            }],
            "verification": {"status": "PASS", "checks": [{
                "check_id": "focused-suite",
                "status": "PASS",
                "summary": "Focused suite passed.",
                "evidence_ids": ["evidence-1"],
            }]},
        }

    def assert_result_rejected(self, result: dict) -> None:
        state = {**self.state, "_task_path": str(self.task), "_project_path": str(self.project)}
        with self.assertRaises(orchestrator.AutomationError):
            orchestrator.validate_result(result, self.contract, state)

    def configure_successor(self, *, risk_level: str, requires_fresh_approval: bool) -> None:
        first = self.contract["allowed_actions"][0]
        first["allowed_next_actions"] = ["successor"]
        successor = copy.deepcopy(first)
        successor.update({
            "id": "successor",
            "action": "Execute the bounded successor.",
            "risk_level": risk_level,
            "requires_fresh_approval": requires_fresh_approval,
            "prerequisites": [first["id"]],
            "allowed_predecessors": [first["id"]],
            "allowed_next_actions": [],
        })
        self.contract["allowed_actions"].append(successor)
        self.write_bundle()

    def submit_successor_fixture(self, fault_name: str | None = None) -> tuple[int, dict]:
        self.fresh_approval()
        dispatched = self.run_dispatch()
        self.assertEqual(dispatched.returncode, 0, dispatched.stdout + dispatched.stderr)
        result = self.valid_result()
        result_path = self.root / "successor-result.json"
        result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        args = Namespace(task=str(self.task), project=str(self.project), owner="test-owner", result=str(result_path))
        if fault_name is None:
            return orchestrator.command_submit(args), result

        def crash(name: str) -> None:
            if name == fault_name:
                raise RuntimeError(name)

        with mock.patch.object(orchestrator, "_fault_hook", side_effect=crash):
            with self.assertRaises(RuntimeError):
                orchestrator.command_submit(args)
        return orchestrator.command_submit(args), result

    def test_task_schema_preserves_v11_and_adds_explicit_v12_automation_fields(self) -> None:
        schema = json.loads((ROOT / "schema" / "task-contract.schema.json").read_text(encoding="utf-8"))
        refs = {item["$ref"] for item in schema["oneOf"]}
        self.assertIn("#/$defs/v11", refs)
        self.assertIn("#/$defs/v12", refs)
        automation_fields = {"allowed_workspace_paths", "executor_routes", "authority_expansion"}
        self.assertTrue(automation_fields.isdisjoint(schema["$defs"]["actionV11"]["properties"]))
        self.assertTrue(automation_fields.issubset(schema["$defs"]["actionV12"]["properties"]))
        self.assertTrue(automation_fields.issubset(schema["$defs"]["actionV12"]["required"]))

    def test_v12_runtime_rejects_missing_automation_field(self) -> None:
        self.contract["allowed_actions"][0].pop("authority_expansion")
        errors = contract_runtime.validate_shape(self.contract, self.state)
        self.assertTrue(any("authority_expansion" in issue.message for issue in errors))

    def test_v12_runtime_rejects_v11_state(self) -> None:
        self.state["schema_version"] = "1.1"
        errors = contract_runtime.validate_shape(self.contract, self.state)
        self.assertTrue(any("STATE.schema_version must be 1.2" in issue.message for issue in errors))

    def test_executor_result_schema_is_v2_with_strict_evidence(self) -> None:
        schema = json.loads((ROOT / "schema" / "executor-result.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["schema_version"]["const"], orchestrator.RESULT_SCHEMA_VERSION)
        evidence_item = schema["properties"]["evidence"]["items"]
        self.assertFalse(evidence_item["additionalProperties"])
        self.assertIn("evidence_class", evidence_item["required"])
        self.assertIn("contract_hash", evidence_item["required"])
        self.assertIn("state_revision_seen", evidence_item["required"])
        self.assertIn("workspace_baseline_digest", schema["required"])
        self.assertIn("lease_nonce", schema["required"])
        self.assertEqual(schema["properties"]["verification"]["properties"]["checks"]["items"]["type"], "object")
        self.assertIn("verification_basis", evidence_item["required"])

    def test_v11_dispatch_is_rejected_without_automation_side_effects(self) -> None:
        self.contract["schema_version"] = "1.1"
        self.contract["contract_version"] = 1
        action = self.contract["allowed_actions"][0]
        for field in ("allowed_workspace_paths", "executor_routes", "authority_expansion"):
            action.pop(field)
        action["risk_level"] = "L1"
        action["requires_fresh_approval"] = False
        self.write_bundle()
        result = self.run_dispatch()
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        self.assertIn("BLOCKED_CONTRACT_INVALID", result.stdout)
        self.assertFalse((self.task / ".automation").exists())

    def test_l3_dispatch_without_approval_has_no_automation_side_effects(self) -> None:
        events_before = (self.task / "events.jsonl").read_bytes()
        state_before = (self.task / "STATE.json").read_bytes()
        result = self.run_dispatch()
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        self.assertIn("BLOCKED_AUTHORITY_REQUIRED", result.stdout)
        self.assertFalse((self.task / ".automation").exists())
        self.assertEqual(events_before, (self.task / "events.jsonl").read_bytes())
        self.assertEqual(state_before, (self.task / "STATE.json").read_bytes())

    def test_l3_dispatch_rejects_stale_approval_before_side_effects(self) -> None:
        self.fresh_approval("2026-09-02T23:59:59Z")
        result = self.run_dispatch()
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        self.assertIn("BLOCKED_AUTHORITY_REQUIRED", result.stdout)
        self.assertFalse((self.task / ".automation").exists())

    def test_l3_dispatch_rejects_wrong_contract_binding_before_side_effects(self) -> None:
        self.fresh_approval()
        self.state["approvals"][0]["contract_hash"] = "0" * 64
        self.write_bundle()
        result = self.run_dispatch()
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        self.assertIn("BLOCKED_AUTHORITY_REQUIRED", result.stdout)
        self.assertFalse((self.task / ".automation").exists())

    def test_l3_dispatch_rejects_wrong_revision_binding_before_side_effects(self) -> None:
        self.fresh_approval()
        self.state["approvals"][0]["state_revision"] = self.state["revision"] + 1
        self.write_bundle()
        result = self.run_dispatch()
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        self.assertIn("BLOCKED_AUTHORITY_REQUIRED", result.stdout)
        self.assertFalse((self.task / ".automation").exists())

    def test_l4_action_cannot_opt_out_of_fresh_approval(self) -> None:
        action = self.contract["allowed_actions"][0]
        action["risk_level"] = "L4"
        action["requires_fresh_approval"] = False
        self.write_bundle()
        result = self.run_dispatch()
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        self.assertIn("BLOCKED_CONTRACT_INVALID", result.stdout)
        self.assertFalse((self.task / ".automation").exists())

    def test_l3_dispatch_accepts_fresh_explicit_user_approval(self) -> None:
        self.fresh_approval()
        result = self.run_dispatch()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        envelopes = list((self.task / ".automation" / "envelopes").glob("*.json"))
        self.assertEqual(len(envelopes), 1)
        payload = json.loads(envelopes[0].read_text(encoding="utf-8"))
        self.assertEqual(payload["result_schema_version"], orchestrator.RESULT_SCHEMA_VERSION)
        self.assertEqual(len(payload["result_schema_sha256"]), 64)
        self.assertEqual(len(payload["workspace_baseline_digest"]), 64)
        self.assertEqual(len(payload["lease_nonce"]), 32)

    def test_result_v2_accepts_strict_bound_evidence(self) -> None:
        result = self.valid_result()
        state = {**self.state, "_task_path": str(self.task), "_project_path": str(self.project)}
        validated = orchestrator.validate_result(result, self.contract, state)
        self.assertEqual(validated["evidence"][0]["evidence_class"], "focused-test")

    def test_result_v2_rejects_empty_evidence_object(self) -> None:
        result = self.valid_result()
        result["evidence"] = [{}]
        self.assert_result_rejected(result)

    def test_result_v2_rejects_missing_evidence_class(self) -> None:
        result = self.valid_result()
        result["evidence"][0].pop("evidence_class")
        self.assert_result_rejected(result)

    def test_result_v2_rejects_missing_verification_checks(self) -> None:
        result = self.valid_result()
        result["verification"].pop("checks")
        self.assert_result_rejected(result)

    def test_result_v2_rejects_arbitrary_string_check(self) -> None:
        result = self.valid_result()
        result["verification"]["checks"] = ["claimed pass"]
        self.assert_result_rejected(result)

    def test_result_v2_rejects_untrusted_verifier_without_artifact(self) -> None:
        result = self.valid_result()
        result["evidence"][0]["verifier"] = "executor-self-assertion"
        result["evidence"][0]["verification_basis"] = "trusted-verifier"
        result["evidence"][0].pop("artifact_path")
        result["evidence"][0].pop("artifact_digest")
        result["evidence"][0].pop("artifact_size")
        self.assert_result_rejected(result)

    def test_result_v2_rejects_unregistered_verifier_and_out_of_scope_preexisting_artifact(self) -> None:
        result = self.valid_result()
        result["evidence"][0]["verifier"] = "self-asserted-executor"
        self.assert_result_rejected(result)

        result["evidence"][0]["verifier"] = orchestrator.LOCAL_ARTIFACT_VERIFIER
        evidence = result["evidence"][0]
        evidence.update({
            "artifact_path": "README.md",
            "artifact_digest": contract_runtime.file_sha256(self.project / "README.md"),
            "artifact_size": (self.project / "README.md").stat().st_size,
        })
        result["changed_paths"] = ["README.md"]
        self.assert_result_rejected(result)

    def test_result_v2_verifies_artifact_digest_and_size(self) -> None:
        result = self.valid_result()
        artifact = self.project / "src" / "evidence.txt"
        evidence = result["evidence"][0]
        evidence.update({
            "verification_basis": "artifact",
            "verifier": orchestrator.LOCAL_ARTIFACT_VERIFIER,
            "artifact_path": "src/evidence.txt",
            "artifact_digest": contract_runtime.file_sha256(artifact),
            "artifact_size": artifact.stat().st_size,
        })
        state = {**self.state, "_task_path": str(self.task), "_project_path": str(self.project)}
        orchestrator.validate_result(result, self.contract, state)
        evidence["artifact_digest"] = "0" * 64
        self.assert_result_rejected(result)

    def test_result_v2_rejects_mismatched_sealed_binding(self) -> None:
        result = self.valid_result()
        result["evidence"][0]["action_id"] = "different-action"
        self.assert_result_rejected(result)

    def test_l3_successor_without_revision_fresh_approval_has_no_dispatch_artifacts(self) -> None:
        self.configure_successor(risk_level="L3", requires_fresh_approval=True)
        code, _ = self.submit_successor_fixture()
        self.assertEqual(code, 0)
        state = json.loads((self.task / "STATE.json").read_text(encoding="utf-8"))
        self.assertEqual(state["status"], "READY")
        self.assertEqual(state["next_action_id"], "successor")
        self.assertFalse((self.task / ".automation" / "baselines" / "r1.json").exists())
        self.assertFalse((self.task / ".automation" / "envelopes" / "r1-successor.json").exists())
        events = [json.loads(line) for line in (self.task / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertFalse(any(event.get("event") == "automation_dispatched" and event.get("revision") == 1 for event in events))

    def test_successor_dispatch_repairs_crash_after_envelope_exactly_once(self) -> None:
        self.configure_successor(risk_level="L1", requires_fresh_approval=False)
        code, _ = self.submit_successor_fixture(orchestrator.FAULT_AFTER_SUCCESSOR_ENVELOPE)
        self.assertEqual(code, 0)
        self.assertTrue((self.task / ".automation" / "baselines" / "r1.json").exists())
        self.assertTrue((self.task / ".automation" / "envelopes" / "r1-successor.json").exists())
        events = [json.loads(line) for line in (self.task / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        successor_events = [event for event in events if event.get("event") == "automation_dispatched" and event.get("revision") == 1]
        self.assertEqual(len(successor_events), 1)

    def test_successor_dispatch_repairs_crash_after_baseline_exactly_once(self) -> None:
        self.configure_successor(risk_level="L1", requires_fresh_approval=False)
        code, _ = self.submit_successor_fixture(orchestrator.FAULT_AFTER_SUCCESSOR_BASELINE)
        self.assertEqual(code, 0)
        self.assertTrue((self.task / ".automation" / "baselines" / "r1.json").exists())
        self.assertTrue((self.task / ".automation" / "envelopes" / "r1-successor.json").exists())
        events = [json.loads(line) for line in (self.task / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        successor_events = [event for event in events if event.get("event") == "automation_dispatched" and event.get("revision") == 1]
        self.assertEqual(len(successor_events), 1)

    def test_successor_dispatch_retry_after_event_is_idempotent(self) -> None:
        self.configure_successor(risk_level="L1", requires_fresh_approval=False)
        code, _ = self.submit_successor_fixture(orchestrator.FAULT_AFTER_SUCCESSOR_EVENT)
        self.assertEqual(code, 0)
        events = [json.loads(line) for line in (self.task / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        successor_events = [event for event in events if event.get("event") == "automation_dispatched" and event.get("revision") == 1]
        self.assertEqual(len(successor_events), 1)


if __name__ == "__main__":
    unittest.main()
