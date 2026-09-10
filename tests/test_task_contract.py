from __future__ import annotations

import json
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "task_contract.py"
ORCHESTRATOR_SCRIPT = ROOT / "scripts" / "task_orchestrator.py"
FIXTURE = ROOT / "fixtures" / "vibe-reading-gemini-nano-a-b-b-a"

sys.path.insert(0, str(ROOT / "scripts"))
import task_orchestrator as ORCHESTRATOR

SPEC = importlib.util.spec_from_file_location("task_contract_module", SCRIPT)
assert SPEC and SPEC.loader
TASK_CONTRACT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TASK_CONTRACT
SPEC.loader.exec_module(TASK_CONTRACT)


def run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=cwd, text=True, capture_output=True, check=False)


class TaskContractHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.task = self.root / "task"
        self.project.mkdir(); shutil.copytree(FIXTURE, self.task)
        subprocess.run(["git", "init", "-q", str(self.project)], check=True)
        subprocess.run(["git", "-C", str(self.project), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.project), "config", "user.name", "Fixture"], check=True)
        (self.project / "README.md").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.project), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(self.project), "commit", "-qm", "baseline"], check=True)
        self.commit = subprocess.run(["git", "-C", str(self.project), "rev-parse", "HEAD"], text=True, capture_output=True, check=True).stdout.strip()
        contract_path, state_path = self.task / "TASK.json", self.task / "STATE.json"
        contract = json.loads(contract_path.read_text(encoding="utf-8")); state = json.loads(state_path.read_text(encoding="utf-8"))
        contract["project"]["expected_root"] = str(self.project); contract["project"]["git"]["baseline_commit"] = self.commit
        state["last_verified_commit"] = self.commit
        contract_path.write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        sealed = run("seal", "--task", str(self.task)); self.assertEqual(sealed.returncode, 0, sealed.stdout + sealed.stderr)

    def tearDown(self) -> None: self.temp.cleanup()

    def test_session_b_without_conversation_resumes_correct_benchmark(self) -> None:
        result = run("resume", "--task", str(self.task), "--project", str(self.project))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RESUME_OK", result.stdout)
        self.assertIn("task_type=benchmark", result.stdout)
        self.assertIn("A-B-B-A benchmark", result.stdout)
        self.assertIn("BLOCKED_BROWSER_AUTOMATION", result.stdout)
        self.assertIn("Do not fast-forward", result.stdout)
        self.assertNotIn("extension smoke", result.stdout.lower())

    def test_repository_commit_drift_stops_instead_of_reconstructing_objective(self) -> None:
        (self.project / "README.md").write_text("drift\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.project), "commit", "-am", "drift", "-q"], check=True)
        result = run("resume", "--task", str(self.task), "--project", str(self.project))
        self.assertEqual(result.returncode, 42)
        self.assertIn("STOP authority_or_state_mismatch", result.stdout)
        self.assertIn("baseline commit mismatch", result.stdout)
        self.assertNotIn("RESUME_OK", result.stdout)

    def test_contract_tamper_stops(self) -> None:
        path = self.task / "TASK.json"; contract = json.loads(path.read_text(encoding="utf-8")); contract["objective"] = "Infer anything from the branch."
        path.write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
        result = run("resume", "--task", str(self.task), "--project", str(self.project))
        self.assertEqual(result.returncode, 42)
        self.assertIn("TASK seal mismatch", result.stdout)

    def test_state_cannot_select_an_unapproved_route(self) -> None:
        path = self.task / "STATE.json"; state = json.loads(path.read_text(encoding="utf-8"))
        state["next_action_id"] = "fast-forward-branch"; state["next_action"] = "Fast-forward a branch."
        path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        result = run("resume", "--task", str(self.task), "--project", str(self.project))
        self.assertEqual(result.returncode, 42)
        self.assertIn("STATE.next_action_id is not an allowed task action", result.stdout)

    def test_checkpoint_updates_state_and_appends_event_without_changing_authority(self) -> None:
        before = (self.task / "TASK.json").read_bytes()
        events_before = [line for line in (self.task / "events.jsonl").read_text(encoding="utf-8").splitlines() if line]
        result = run("checkpoint", "--task", str(self.task), "--project", str(self.project), "--status", "BLOCKED", "--current-state", "No legs started.", "--next-action-id", "verify-chrome-bridge", "--blocker", "BLOCKED_BROWSER_AUTOMATION", "--resume-from", "before A1", "--last-verified", "No benchmark evidence exists.", "--last-verified-commit", self.commit, "--artifact-path", "C:\\TaskContractArtifacts\\vibe-reading-gemini-nano-abba", "--note", "Session B preserved benchmark route.")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(before, (self.task / "TASK.json").read_bytes())
        events_after = [line for line in (self.task / "events.jsonl").read_text(encoding="utf-8").splitlines() if line]
        self.assertEqual(len(events_after), len(events_before) + 1)

    def test_resume_payload_is_small(self) -> None:
        result = run("resume", "--task", str(self.task), "--project", str(self.project))
        self.assertLess(len(result.stdout.encode("utf-8")), 2500)


class TaskContractV11Tests(unittest.TestCase):
    ACTION_IDS = [
        "inspect-production-authority",
        "validate-governance-compatibility",
        "validate-existing-chrome-attachment",
        "validate-browser-gate",
        "run-old-a",
        "run-new-a",
        "run-new-b",
        "run-old-b",
        "evaluate-results",
        "produce-recommendation",
    ]

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="TaskContracts-T5.1-tests-")
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.task = self.root / "task-v11"
        self.project.mkdir(); self.task.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "old", str(self.project)], check=True)
        subprocess.run(["git", "-C", str(self.project), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.project), "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", str(self.project), "remote", "add", "origin", "https://example.invalid/fixture/repository.git"], check=True)
        (self.project / "value.txt").write_text("old\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.project), "add", "value.txt"], check=True)
        subprocess.run(["git", "-C", str(self.project), "commit", "-qm", "OLD"], check=True)
        self.old = self.git("rev-parse", "HEAD")
        subprocess.run(["git", "-C", str(self.project), "checkout", "-qb", "new"], check=True)
        (self.project / "value.txt").write_text("new\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.project), "commit", "-am", "NEW", "-q"], check=True)
        self.new = self.git("rev-parse", "HEAD")
        subprocess.run(["git", "-C", str(self.project), "checkout", "-qb", "third"], check=True)
        (self.project / "value.txt").write_text("third\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.project), "commit", "-am", "THIRD", "-q"], check=True)
        self.third = self.git("rev-parse", "HEAD")
        self.checkout("old")
        self.contract = self.make_contract()
        self.state = self.make_state()
        self.write_bundle()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def git(self, *args: str) -> str:
        return subprocess.run(["git", "-C", str(self.project), *args], text=True, capture_output=True, check=True).stdout.strip()

    def checkout(self, branch: str) -> None:
        subprocess.run(["git", "-C", str(self.project), "checkout", "-q", branch], check=True)

    def make_contract(self) -> dict:
        actions = []
        for index, action_id in enumerate(self.ACTION_IDS):
            predecessor = self.ACTION_IDS[index - 1] if index else None
            expected = "NEW" if action_id in {"run-new-a", "run-new-b"} else "OLD"
            actions.append({
                "id": action_id,
                "action": f"Perform {action_id}.",
                "task_scope_authorized": True,
                "risk_level": "L1",
                "requires_fresh_approval": False,
                "prerequisites": self.ACTION_IDS[:index],
                "allowed_predecessors": [predecessor] if predecessor else [],
                "expected_commit_authority": expected,
                "allowed_next_actions": [self.ACTION_IDS[index + 1]] if index + 1 < len(self.ACTION_IDS) else [],
                "required_hard_gates": [],
                "required_evidence_classes": ["benchmark-round"] if action_id.startswith("run-") else ["governance-evidence"],
                "route_class": "benchmark",
            })
        return {
            "schema_version": "1.1", "contract_version": 1, "task_id": "fixture-v11-abba",
            "project": {"project_id": "fixture", "expected_root": str(self.project), "git": {"required": True, "remote": "https://example.invalid/fixture/repository.git", "authorized_commits": [{"id": "OLD", "ref": "old", "commit": self.old}, {"id": "NEW", "ref": "new", "commit": self.new}], "require_clean_worktree": True, "forbid_detached_head": True, "forbid_special_operation": True}},
            "task_type": "benchmark", "objective": "Run the sealed A-B-B-A benchmark objective only.",
            "authority": {"kind": "user-direct", "source_ref": "test:T5.1", "issued_at": "2026-08-22T00:00:00Z", "supersedes": None},
            "authority_order": ["platform-runtime", "tool-mcp-enforcement", "current-user-authorization", "effective-agents-policy", "sealed-task", "validated-state", "repository-runtime-evidence", "handoff-events-artifacts"],
            "baseline": {"description": "No rounds started.", "required_inputs": []},
            "allowed_actions": actions,
            "forbidden_actions": ["Do not infer objective from Git.", "Do not substitute extension smoke."],
            "hard_gates": [{"id": "browser-gate", "type": "runtime-assertion", "required": True, "required_state": "available", "required_evidence": ["browser-runtime-probe"], "evidence_scope": "task"}],
            "acceptance": [{"id": "rounds", "criterion": "Four raw rounds exist.", "evidence_classes": ["benchmark-round"], "substitution_forbidden": True}],
            "artifacts": {"root": str(self.root / "artifacts"), "expected": ["old-a.json", "new-a.json", "new-b.json", "old-b.json"]},
            "policy_boundaries": {"task_scope_is_execution_approval": False, "denied_action_ids": [], "handoff_authority_role": "reference-envelope-only", "repository_state_authority_role": "supporting-evidence-only"},
            "resource_requirements": [{"resource_class": "browser-profile", "purpose": "fixture", "authority_role": "soft-hint-not-lock-or-evidence"}],
            "threat_model": {"seal_role": "accidental-procedural-integrity", "external_authenticity_anchor": False},
        }

    def make_state(self) -> dict:
        first = self.contract["allowed_actions"][0]
        return {"schema_version": "1.1", "task_id": self.contract["task_id"], "revision": 0, "previous_state_digest": None, "status": "READY", "current_state": "No action completed.", "completed_actions": [], "last_completed_action_id": None, "next_action_id": first["id"], "next_action": first["action"], "blocker": None, "resume_from": first["id"], "rounds_completed": 0, "benchmark_progress": "none", "gate_status": [{"id": "browser-gate", "satisfied": False, "evidence": []}], "approvals": [], "last_verified": None, "last_verified_commit": self.old, "artifact_path": str(self.root / "artifacts"), "updated_at": "2026-08-22T00:00:00Z"}

    def write_bundle(self) -> None:
        (self.task / "TASK.json").write_text(json.dumps(self.contract, indent=2) + "\n", encoding="utf-8")
        (self.task / "STATE.json").write_text(json.dumps(self.state, indent=2) + "\n", encoding="utf-8")
        (self.task / "events.jsonl").write_text(json.dumps({"at": "2026-08-22T00:00:00Z", "event": "created", "revision": self.state["revision"]}) + "\n", encoding="utf-8")
        (self.task / "CONTRACT.sha256").unlink(missing_ok=True)
        sealed = run("seal", "--task", str(self.task))
        self.assertEqual(sealed.returncode, 0, sealed.stdout + sealed.stderr)

    def set_phase(self, action_id: str) -> None:
        index = self.ACTION_IDS.index(action_id)
        action = self.contract["allowed_actions"][index]
        self.state.update({"revision": 0, "completed_actions": self.ACTION_IDS[:index], "last_completed_action_id": self.ACTION_IDS[index - 1] if index else None, "next_action_id": action_id, "next_action": action["action"]})
        (self.task / "STATE.json").write_text(json.dumps(self.state, indent=2) + "\n", encoding="utf-8")
        (self.task / "events.jsonl").write_text(json.dumps({"at": "2026-08-22T00:00:00Z", "event": "fixture-reset", "revision": 0}) + "\n", encoding="utf-8")

    def checkpoint(self, expected: int, completed: str, next_action: str) -> subprocess.CompletedProcess[str]:
        return run("checkpoint", "--task", str(self.task), "--project", str(self.project), "--expected-revision", str(expected), "--completed-action-id", completed, "--status", "RUNNING", "--current-state", f"{completed} complete", "--next-action-id", next_action, "--last-verified", "fixture evidence", "--last-verified-commit", self.git("rev-parse", "HEAD"), "--artifact-path", str(self.root / "artifacts"), "--note", "fixture checkpoint")

    def test_a1_old_authorized(self) -> None:
        self.set_phase("run-old-a"); self.checkout("old")
        self.assertEqual(run("resume", "--task", str(self.task), "--project", str(self.project)).returncode, 0)

    def test_a2_new_authorized_in_each_new_phase(self) -> None:
        self.checkout("new")
        for action_id in ("run-new-a", "run-new-b"):
            with self.subTest(action_id=action_id):
                self.set_phase(action_id)
                self.assertEqual(run("resume", "--task", str(self.task), "--project", str(self.project)).returncode, 0)

    def test_a3_unauthorized_third_commit_stops(self) -> None:
        self.set_phase("run-old-a"); self.checkout("third")
        result = run("resume", "--task", str(self.task), "--project", str(self.project))
        self.assertEqual(result.returncode, 42); self.assertIn("HEAD is not an authorized", result.stdout)

    def test_a4_correct_authority_wrong_phase_stops(self) -> None:
        self.set_phase("run-old-a"); self.checkout("new")
        result = run("resume", "--task", str(self.task), "--project", str(self.project))
        self.assertEqual(result.returncode, 42); self.assertIn("phase commit mismatch", result.stdout)

    def test_a5_complete_old_new_new_old_transition(self) -> None:
        self.set_phase("run-old-a"); self.checkout("old")
        self.assertEqual(self.checkpoint(0, "run-old-a", "run-new-a").returncode, 0)
        self.checkout("new")
        self.assertEqual(self.checkpoint(1, "run-new-a", "run-new-b").returncode, 0)
        self.assertEqual(self.checkpoint(2, "run-new-b", "run-old-b").returncode, 0)
        self.checkout("old")
        result = run("resume", "--task", str(self.task), "--project", str(self.project))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a6_skipped_transition_stops(self) -> None:
        self.set_phase("run-old-a"); self.checkout("old")
        result = self.checkpoint(0, "run-old-a", "run-new-b")
        self.assertEqual(result.returncode, 42); self.assertIn("unsatisfied_prerequisites", result.stdout)

    def test_b1_revision_increments(self) -> None:
        result = self.checkpoint(0, self.ACTION_IDS[0], self.ACTION_IDS[1])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads((self.task / "STATE.json").read_text(encoding="utf-8"))["revision"], 1)

    def test_b2_stale_writer_stops_without_overwrite(self) -> None:
        self.assertEqual(self.checkpoint(0, self.ACTION_IDS[0], self.ACTION_IDS[1]).returncode, 0)
        before = (self.task / "STATE.json").read_bytes()
        result = self.checkpoint(0, self.ACTION_IDS[0], self.ACTION_IDS[1])
        self.assertEqual(result.returncode, 42); self.assertIn("concurrent_state_change", result.stdout)
        self.assertEqual((self.task / "STATE.json").read_bytes(), before)

    def test_b3_correct_revision_invalid_action_stops(self) -> None:
        before = (self.task / "STATE.json").read_bytes()
        result = self.checkpoint(0, self.ACTION_IDS[0], "run-new-b")
        self.assertEqual(result.returncode, 42); self.assertEqual((self.task / "STATE.json").read_bytes(), before)

    def test_b4_failed_checkpoint_preserves_parseable_state(self) -> None:
        before = json.loads((self.task / "STATE.json").read_text(encoding="utf-8"))
        self.checkpoint(99, self.ACTION_IDS[0], self.ACTION_IDS[1])
        after = json.loads((self.task / "STATE.json").read_text(encoding="utf-8"))
        self.assertEqual(after, before)

    def test_b5_atomic_write_fault_preserves_original(self) -> None:
        path = self.task / "STATE.json"; before = path.read_bytes()
        def fail(_: Path) -> None: raise OSError("injected before replace")
        with self.assertRaises(OSError): TASK_CONTRACT.atomic_write_json(path, {"broken": True}, before_replace=fail)
        self.assertEqual(path.read_bytes(), before); json.loads(path.read_text(encoding="utf-8"))

    def test_parent_sync_failure_reports_state_committed_and_audit_gap(self) -> None:
        args = TASK_CONTRACT.parser().parse_args(["checkpoint", "--task", str(self.task), "--project", str(self.project), "--expected-revision", "0", "--completed-action-id", self.ACTION_IDS[0], "--status", "RUNNING", "--current-state", "done", "--next-action-id", self.ACTION_IDS[1], "--note", "directory sync fault"])
        output = StringIO()
        with mock.patch.object(TASK_CONTRACT, "fsync_parent_directory", side_effect=OSError("directory fsync unsupported")):
            with redirect_stdout(output):
                self.assertEqual(TASK_CONTRACT.command_checkpoint(args), 42)
        self.assertIn("durability_sync_failed_after_state_commit", output.getvalue())
        self.assertEqual(json.loads((self.task / "STATE.json").read_text(encoding="utf-8"))["revision"], 1)
        result = run("resume", "--task", str(self.task), "--project", str(self.project))
        self.assertEqual(result.returncode, 42)
        self.assertIn("audit_gap", result.stdout)

    def test_event_failure_leaves_committed_state_and_visible_audit_gap(self) -> None:
        args = TASK_CONTRACT.parser().parse_args(["checkpoint", "--task", str(self.task), "--project", str(self.project), "--expected-revision", "0", "--completed-action-id", self.ACTION_IDS[0], "--status", "RUNNING", "--current-state", "done", "--next-action-id", self.ACTION_IDS[1], "--note", "fault"])
        with mock.patch.object(TASK_CONTRACT, "append_event", side_effect=OSError("event fault")):
            self.assertEqual(TASK_CONTRACT.command_checkpoint(args), 42)
        self.assertEqual(json.loads((self.task / "STATE.json").read_text(encoding="utf-8"))["revision"], 1)
        result = run("resume", "--task", str(self.task), "--project", str(self.project))
        self.assertEqual(result.returncode, 42); self.assertIn("audit_gap", result.stdout)

    def test_c1_repository_route_reconstruction_stops(self) -> None:
        result = run("route-check", "--task", str(self.task), "--project", str(self.project), "--action-id", "infer-next-task-from-current-branch", "--route-class", "benchmark")
        self.assertEqual(result.returncode, 42)

    def test_c2_unrelated_fast_forward_stops(self) -> None:
        result = run("route-check", "--task", str(self.task), "--project", str(self.project), "--action-id", "fast-forward-fix-prompt-api", "--route-class", "benchmark")
        self.assertEqual(result.returncode, 42)

    def test_c3_and_c6_smoke_cannot_substitute_acceptance(self) -> None:
        self.set_phase("run-old-a")
        for evidence in ("extension-smoke", "toolbar-smoke"):
            result = run("route-check", "--task", str(self.task), "--project", str(self.project), "--action-id", "run-old-a", "--route-class", "benchmark", "--evidence-class", evidence)
            self.assertEqual(result.returncode, 42); self.assertIn("acceptance_substitution", result.stdout)

    def test_c4_missing_authority_fields_fail_closed(self) -> None:
        cases = [("contract", "objective"), ("contract", "acceptance"), ("contract", "forbidden_actions"), ("state", "current_state")]
        for target, field in cases:
            with self.subTest(field=field):
                contract = json.loads((self.task / "TASK.json").read_text(encoding="utf-8")); state = json.loads((self.task / "STATE.json").read_text(encoding="utf-8"))
                (contract if target == "contract" else state).pop(field)
                (self.task / "TASK.json").write_text(json.dumps(contract) + "\n", encoding="utf-8")
                (self.task / "STATE.json").write_text(json.dumps(state) + "\n", encoding="utf-8")
                (self.task / "CONTRACT.sha256").unlink(missing_ok=True)
                self.assertEqual(run("seal", "--task", str(self.task)).returncode, 0)
                result = run("resume", "--task", str(self.task), "--project", str(self.project))
                self.assertEqual(result.returncode, 42); self.assertIn("HANDOFF_AUTHORITY_MISSING", result.stdout)
                self.contract = self.make_contract(); self.state = self.make_state(); self.write_bundle()

    def test_c5_task_class_mismatch_stops(self) -> None:
        result = run("route-check", "--task", str(self.task), "--project", str(self.project), "--action-id", self.ACTION_IDS[0], "--route-class", "repo-maintenance")
        self.assertEqual(result.returncode, 42); self.assertIn("route_class_mismatch", result.stdout)

    def test_d1_higher_policy_declared_boundary_wins(self) -> None:
        self.contract["policy_boundaries"]["denied_action_ids"] = [self.ACTION_IDS[0]]
        (self.task / "TASK.json").write_text(json.dumps(self.contract) + "\n", encoding="utf-8")
        (self.task / "CONTRACT.sha256").unlink()
        self.assertEqual(run("seal", "--task", str(self.task)).returncode, 0)
        result = run("resume", "--task", str(self.task), "--project", str(self.project))
        self.assertEqual(result.returncode, 42); self.assertIn("policy_boundary_mismatch", result.stdout)

    def test_d2_l3_action_needs_fresh_approval(self) -> None:
        self.contract["allowed_actions"][0]["risk_level"] = "L3"; self.contract["allowed_actions"][0]["requires_fresh_approval"] = True
        (self.task / "TASK.json").write_text(json.dumps(self.contract) + "\n", encoding="utf-8")
        (self.task / "CONTRACT.sha256").unlink(); self.assertEqual(run("seal", "--task", str(self.task)).returncode, 0)
        result = self.checkpoint(0, self.ACTION_IDS[0], self.ACTION_IDS[1])
        self.assertEqual(result.returncode, 42); self.assertIn("approval_required", result.stdout)

    def test_d3_handoff_reference_without_bundle_is_not_authority(self) -> None:
        handoff = self.root / "handoff.json"
        handoff.write_text(json.dumps({"taskContractRef": {"taskId": "missing", "contractSha256": "0" * 64, "verificationRequired": True}}), encoding="utf-8")
        result = run("resume-handoff", "--handoff", str(handoff), "--task-root", str(self.root), "--project", str(self.project))
        self.assertEqual(result.returncode, 42); self.assertIn("authority_missing", result.stdout)

    def test_d4_soft_resource_hint_cannot_satisfy_browser_gate(self) -> None:
        self.set_phase("run-old-a")
        self.contract["allowed_actions"][4]["required_hard_gates"] = ["browser-gate"]
        (self.task / "TASK.json").write_text(json.dumps(self.contract) + "\n", encoding="utf-8")
        (self.task / "CONTRACT.sha256").unlink(); self.assertEqual(run("seal", "--task", str(self.task)).returncode, 0)
        result = run("resume", "--task", str(self.task), "--project", str(self.project))
        self.assertEqual(result.returncode, 42); self.assertIn("unsatisfied_prerequisites", result.stdout)

    def test_machine_verified_browser_gate_recording(self) -> None:
        artifact = self.task / "browser-probe.raw.json"
        artifact.write_text('{"probe":"complete"}\n', encoding="utf-8")
        digest = TASK_CONTRACT.file_sha256(artifact)
        evidence = self.task / "browser-probe.evidence.json"
        evidence.write_text(json.dumps({"task_id": self.contract["task_id"], "action_id": self.ACTION_IDS[0], "gate_id": "browser-gate", "evidence_type": "browser-runtime-probe", "artifact_path": artifact.name, "artifact_digest": digest, "timestamp": "2026-08-22T00:00:00Z", "verified_action": self.ACTION_IDS[0], "runtime_metadata": {"chrome_major": 154, "existing_intended_runtime": True, "extension_runtime_available": True, "chrome_runtime_id_non_null": True, "manifest_version": "1.0.0", "language_model_exists": True, "availability_most_predictable": "available"}}), encoding="utf-8")
        result = run("record-gate", "--task", str(self.task), "--project", str(self.project), "--expected-revision", "0", "--gate-id", "browser-gate", "--evidence", str(evidence))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        state = json.loads((self.task / "STATE.json").read_text(encoding="utf-8"))
        self.assertEqual(state["revision"], 1); self.assertTrue(state["gate_status"][0]["satisfied"])

    def test_d5_handoff_adapter_has_no_state_write_capability(self) -> None:
        schema = json.loads((ROOT / "schema" / "handoff-task-contract-ref.schema.json").read_text(encoding="utf-8"))
        properties = schema["properties"]["taskContractRef"]["properties"]
        self.assertNotIn("checkpoint", properties); self.assertNotIn("stateWrite", properties)

    def test_d6_no_execution_platform_components_added(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8").lower()
        for component in ("sqlite3", "http.server", "socketserver", "scheduler", "dashboard"):
            self.assertNotIn(component, source)

    def test_v11_resume_payload_budget_and_zero_context_fields(self) -> None:
        result = run("resume", "--task", str(self.task), "--project", str(self.project))
        self.assertEqual(result.returncode, 0)
        for field in ("task_id=", "schema_version=1.1", "task_type=benchmark", "objective=", "repository_authority=", "rounds_completed=0", "status=READY", "next_action=", "resume_mode=READ_ONLY_INTAKE", "do_not_execute_next_action=true", "execution_requires_new_explicit_user_authorization=true", "action_prerequisites=", "authority_notice=", "route_notice=", "forbidden_actions="):
            self.assertIn(field, result.stdout)
        self.assertLess(len(result.stdout.encode("utf-8")), 6000)
        self.assertLess(len(result.stdout.encode("utf-8")) / 4, 1500)


class TaskContractV12ContinuationTests(unittest.TestCase):
    """Synthetic v1.2 continuation tests keep terminal closure on submit-result."""

    def setUp(self) -> None:
        self.v11_fixture = TaskContractV11Tests(methodName="runTest")
        self.v11_fixture.setUp()
        self.root = self.v11_fixture.root
        self.project = self.v11_fixture.project
        self.task = self.v11_fixture.task
        self.contract = self.v11_fixture.contract
        self.state = self.v11_fixture.state
        self.ACTION_IDS = self.v11_fixture.ACTION_IDS
        contract = self.contract
        contract.update({"schema_version": "1.2", "contract_version": 2, "task_id": "fixture-v12-continuation"})
        for action in contract["allowed_actions"]:
            action.update({
                "allowed_workspace_paths": ["src"],
                "executor_routes": ["KEEP_SINGLE"],
                "authority_expansion": False,
            })
        self.state["schema_version"] = "1.2"
        self.state["task_id"] = contract["task_id"]
        self.write_v12_bundle()

    def write_v12_bundle(self) -> None:
        self.v11_fixture.write_bundle()
        state_digest = TASK_CONTRACT.file_sha256(self.task / "STATE.json")
        (self.task / "events.jsonl").write_text(
            json.dumps({
                "at": "2026-09-05T00:00:00Z", "event": "created",
                "task_id": self.contract["task_id"], "revision": 0,
                "target_state_digest": state_digest,
            }) + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.v11_fixture.tearDown()

    def git(self, *args: str) -> str:
        return self.v11_fixture.git(*args)

    def checkpoint_with_status(
        self, status: str, expected: int = 0, *, completed: str | None = None,
        next_action: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        completion_args = ["--completed-action-id", completed] if completed is not None else []
        return run(
            "checkpoint", "--task", str(self.task), "--project", str(self.project),
            "--expected-revision", str(expected),
            "--status", status, "--current-state", "synthetic checkpoint",
            "--next-action-id", next_action or self.ACTION_IDS[0], "--last-verified", "synthetic claim",
            "--last-verified-commit", self.git("rev-parse", "HEAD"),
            "--artifact-path", str(self.root / "artifacts"), "--note", "TC-01 synthetic interruption",
            *completion_args,
        )

    def bundle_bytes(self) -> dict[str, bytes]:
        return {name: (self.task / name).read_bytes()
                for name in ("TASK.json", "CONTRACT.sha256", "STATE.json", "events.jsonl")}

    def dispatch(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ORCHESTRATOR_SCRIPT), "dispatch", "--task", str(self.task),
             "--project", str(self.project), "--owner", "tc-01-test"],
            text=True, capture_output=True, check=False,
        )

    def valid_terminal_result(self) -> dict:
        envelope_path = next((self.task / ".automation" / "envelopes").glob("*.json"))
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        state = json.loads((self.task / "STATE.json").read_text(encoding="utf-8"))
        artifact = self.project / "src" / "evidence.txt"
        artifact.parent.mkdir(exist_ok=True)
        artifact.write_text("synthetic verified evidence\n", encoding="utf-8")
        contract_hash = TASK_CONTRACT.canonical_sha256(self.task / "TASK.json")
        return {
            "schema_version": ORCHESTRATOR.RESULT_SCHEMA_VERSION,
            "result_id": "tc-01-result",
            "task_id": self.contract["task_id"],
            "contract_hash": contract_hash,
            "workspace_baseline_digest": envelope["workspace_baseline_digest"],
            "lease_nonce": envelope["lease_nonce"],
            "state_revision_seen": state["revision"],
            "action_id": self.ACTION_IDS[0],
            "executor": "synthetic-continuation-test",
            "outcome": "PASS",
            "summary": "Synthetic terminal action verified.",
            "changed_paths": ["src/evidence.txt"],
            "evidence": [{
                "evidence_id": "evidence-1",
                "evidence_class": "governance-evidence",
                "task_id": self.contract["task_id"],
                "contract_hash": contract_hash,
                "state_revision_seen": state["revision"],
                "action_id": self.ACTION_IDS[0],
                "verified_action": self.ACTION_IDS[0],
                "verifier": ORCHESTRATOR.LOCAL_ARTIFACT_VERIFIER,
                "timestamp": "2026-09-05T00:00:00Z",
                "verification_basis": "artifact",
                "artifact_path": "src/evidence.txt",
                "artifact_digest": TASK_CONTRACT.file_sha256(artifact),
                "artifact_size": artifact.stat().st_size,
            }],
            "verification": {"status": "PASS", "checks": [{
                "check_id": "synthetic-check", "status": "PASS",
                "summary": "Synthetic check passed.", "evidence_ids": ["evidence-1"],
            }]},
        }

    def submit(self, result: dict) -> subprocess.CompletedProcess[str]:
        result_path = self.root / "executor-result.json"
        result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(ORCHESTRATOR_SCRIPT), "submit-result", "--task", str(self.task),
             "--project", str(self.project), "--owner", "tc-01-test", "--result", str(result_path)],
            text=True, capture_output=True, check=False,
        )

    def test_interruption_then_new_process_resume_is_read_only(self) -> None:
        original = self.bundle_bytes()
        original_state = json.loads(original["STATE.json"])
        interrupted = self.checkpoint_with_status("RUNNING")
        self.assertEqual(interrupted.returncode, 0, interrupted.stdout + interrupted.stderr)
        checkpointed = self.bundle_bytes()
        state = json.loads(checkpointed["STATE.json"])
        for field in ("completed_actions", "last_completed_action_id", "next_action_id"):
            self.assertEqual(state[field], original_state[field])
        for name in ("TASK.json", "CONTRACT.sha256"):
            self.assertEqual(checkpointed[name], original[name])
        self.assertTrue(checkpointed["events.jsonl"].startswith(original["events.jsonl"]))
        event = json.loads(checkpointed["events.jsonl"].decode().splitlines()[-1])
        self.assertIsNone(event["completed_action_id"])
        self.assertEqual(event["target_state_digest"], TASK_CONTRACT.file_sha256(self.task / "STATE.json"))
        resumed = run("resume", "--task", str(self.task), "--project", str(self.project))
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertIn("RESUME_OK", resumed.stdout)
        self.assertIn("revision=1", resumed.stdout)
        self.assertIn(f"next_action={self.ACTION_IDS[0]}", resumed.stdout)
        self.assertIn("resume_mode=READ_ONLY_INTAKE", resumed.stdout)
        self.assertIn("execution_requires_new_explicit_user_authorization=true", resumed.stdout)
        self.assertEqual(self.bundle_bytes(), checkpointed)
        self.assertFalse((self.task / ".automation").exists())

    def test_v12_rejects_completion_and_advancement_independently(self) -> None:
        before = self.bundle_bytes()
        cases = (
            {"completed": self.ACTION_IDS[0]},
            {"next_action": self.ACTION_IDS[1]},
        )
        for kwargs in cases:
            with self.subTest(**kwargs):
                result = self.checkpoint_with_status("RUNNING", **kwargs)
                self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
                self.assertIn("automation_result_required", result.stdout)
                self.assertEqual(self.bundle_bytes(), before)
                self.assertFalse((self.task / ".automation").exists())

    def test_v12_stale_interruption_preserves_state_and_audit(self) -> None:
        first = self.checkpoint_with_status("RUNNING")
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        before = self.bundle_bytes()
        stale = self.checkpoint_with_status("RUNNING", expected=0)
        self.assertEqual(stale.returncode, 42, stale.stdout + stale.stderr)
        self.assertIn("concurrent_state_change", stale.stdout)
        self.assertEqual(self.bundle_bytes(), before)

    def test_v12_resume_rejects_legacy_completion_checkpoint_without_rewriting(self) -> None:
        first = self.checkpoint_with_status("RUNNING")
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        path = self.task / "events.jsonl"
        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        # A legacy checkpoint shape must not acquire v1.2 completion authority.
        events[-1]["completed_action_id"] = self.ACTION_IDS[0]
        path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
        before = self.bundle_bytes()
        resumed = run("resume", "--task", str(self.task), "--project", str(self.project))
        self.assertEqual(resumed.returncode, 42, resumed.stdout + resumed.stderr)
        self.assertIn("audit_gap", resumed.stdout)
        self.assertEqual(self.bundle_bytes(), before)

    def test_v12_checkpoint_cannot_claim_terminal_pass_without_result_evidence(self) -> None:
        before = (self.task / "STATE.json").read_bytes()
        result = self.checkpoint_with_status("PASS")
        self.assertEqual(result.returncode, 42)
        self.assertIn("automation_result_required", result.stdout)
        self.assertEqual((self.task / "STATE.json").read_bytes(), before)

    def test_v12_checkpoint_cannot_complete_or_advance_an_action_without_result_evidence(self) -> None:
        before = (self.task / "STATE.json").read_bytes()
        result = run(
            "checkpoint", "--task", str(self.task), "--project", str(self.project),
            "--expected-revision", "0", "--completed-action-id", self.ACTION_IDS[0],
            "--status", "RUNNING", "--current-state", "unverified A claim",
            "--next-action-id", self.ACTION_IDS[1], "--last-verified", "unverified claim",
            "--last-verified-commit", self.git("rev-parse", "HEAD"),
            "--artifact-path", str(self.root / "artifacts"), "--note", "attempted A to B bypass",
        )
        self.assertEqual(result.returncode, 42)
        self.assertIn("automation_result_required", result.stdout)
        self.assertEqual((self.task / "STATE.json").read_bytes(), before)

    def test_submit_result_completes_terminal_v12_action_with_bound_evidence(self) -> None:
        self.contract["allowed_actions"][0]["allowed_next_actions"] = []
        self.write_v12_bundle()
        interrupted = self.checkpoint_with_status("READY")
        self.assertEqual(interrupted.returncode, 0, interrupted.stdout + interrupted.stderr)
        resumed = run("resume", "--task", str(self.task), "--project", str(self.project))
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        dispatched = self.dispatch()
        self.assertEqual(dispatched.returncode, 0, dispatched.stdout + dispatched.stderr)
        result = self.valid_terminal_result()
        submitted = self.submit(result)
        self.assertEqual(submitted.returncode, 0, submitted.stdout + submitted.stderr)
        self.assertIn("RESULT_COMMITTED", submitted.stdout)
        state = json.loads((self.task / "STATE.json").read_text(encoding="utf-8"))
        self.assertEqual(state["status"], "PASS")
        self.assertEqual(state["revision"], 2)
        before = self.bundle_bytes()
        repeated = self.submit(result)
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        self.assertIn("DUPLICATE_RESULT", repeated.stdout)
        self.assertEqual(self.bundle_bytes(), before)

    def test_submit_result_rejects_stale_or_substituted_evidence_without_state_change(self) -> None:
        dispatched = self.dispatch()
        self.assertEqual(dispatched.returncode, 0, dispatched.stdout + dispatched.stderr)
        invalid = self.valid_terminal_result()
        invalid["evidence"][0]["state_revision_seen"] = 1
        before = (self.task / "STATE.json").read_bytes()
        stale = self.submit(invalid)
        self.assertEqual(stale.returncode, 42)
        self.assertIn("FAILED_RESULT_SCHEMA", stale.stdout)
        self.assertEqual((self.task / "STATE.json").read_bytes(), before)

        invalid = self.valid_terminal_result()
        invalid["evidence"][0]["evidence_class"] = "extension-smoke"
        substituted = self.submit(invalid)
        self.assertEqual(substituted.returncode, 42)
        self.assertIn("FAILED_RESULT_SCHEMA", substituted.stdout)
        self.assertEqual((self.task / "STATE.json").read_bytes(), before)


if __name__ == "__main__": unittest.main(verbosity=2)
