from __future__ import annotations

import json
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import task_orchestrator as orchestrator
from tests import test_task_orchestrator as p0a_tests


class WorkspaceAndCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = p0a_tests.TaskOrchestratorP0ATests(
            methodName="test_l3_dispatch_accepts_fresh_explicit_user_approval"
        )
        self.fixture.setUp()

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def _dispatch_result(self) -> dict:
        self.fixture.fresh_approval()
        dispatched = self.fixture.run_dispatch()
        self.assertEqual(dispatched.returncode, 0, dispatched.stdout + dispatched.stderr)
        envelope_path = next((self.fixture.task / ".automation" / "envelopes").glob("*.json"))
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        result = self.fixture.valid_result()
        result["workspace_baseline_digest"] = envelope["workspace_baseline_digest"]
        result["lease_nonce"] = envelope["lease_nonce"]
        return result

    def _submit(self, result: dict) -> tuple[int, str]:
        result_path = self.fixture.root / "executor-result.json"
        result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        output = StringIO()
        with redirect_stdout(output):
            code = orchestrator.command_submit(Namespace(
                task=str(self.fixture.task),
                project=str(self.fixture.project),
                owner="test-owner",
                result=str(result_path),
            ))
        return code, output.getvalue()

    def _lease_authorization(self, lease: dict, *, new_owner: str = "recovery-owner", operator: str = "test-operator") -> str:
        state = json.loads((self.fixture.task / "STATE.json").read_text(encoding="utf-8"))
        authorization = {
            "schema_version": "taskcontracts-lease-recovery-authorization.v1",
            "source": "explicit-user",
            "task_id": self.fixture.contract["task_id"],
            "contract_hash": orchestrator.contract_runtime.canonical_sha256(self.fixture.task / "TASK.json"),
            "state_revision": state["revision"],
            "old_lease_digest": hashlib.sha256(lease["nonce"].encode("utf-8")).hexdigest(),
            "new_owner": new_owner,
            "operator": operator,
            "scope": "recover-expired-lease",
            "approved_at": orchestrator.now(),
        }
        path = self.fixture.root / "lease-recovery-authorization.json"
        path.write_text(json.dumps(authorization, indent=2) + "\n", encoding="utf-8")
        return str(path)

    def test_dispatch_binds_observed_git_baseline_and_lease(self) -> None:
        result = self._dispatch_result()
        baseline_path = self.fixture.task / ".automation" / "baselines" / "r0.json"
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        self.assertEqual(baseline["workspace_baseline_digest"], result["workspace_baseline_digest"])
        self.assertEqual(baseline["project_root"], os.path.normcase(os.path.abspath(str(self.fixture.project))))
        self.assertEqual(baseline["head"], self.fixture.commit)
        self.assertEqual(baseline["branch"], "main")
        self.assertEqual(baseline["actual_delta"], [])
        self.assertEqual(len(result["lease_nonce"]), 32)

    def test_submit_accepts_expected_dirty_worktree_with_exact_delta(self) -> None:
        result = self._dispatch_result()
        source = self.fixture.project / "src"
        source.mkdir(exist_ok=True)
        (source / "output.txt").write_text("executor output\n", encoding="utf-8")
        result["changed_paths"] = ["src/evidence.txt", "src/output.txt"]
        code, output = self._submit(result)
        self.assertEqual(code, 0, output)
        self.assertIn("RESULT_COMMITTED", output)

    def test_submit_uses_manifest_to_detect_git_ignored_changes(self) -> None:
        result = self._dispatch_result()
        source = self.fixture.project / "src"
        source.mkdir(exist_ok=True)
        (source / ".gitignore").write_text("ignored.bin\n", encoding="utf-8")
        (source / "ignored.bin").write_text("ignored by Git but not by authority\n", encoding="utf-8")
        result["changed_paths"] = ["src/evidence.txt", "src/.gitignore", "src/ignored.bin"]
        code, output = self._submit(result)
        self.assertEqual(code, 0, output)
        self.assertIn("RESULT_COMMITTED", output)

    def test_submit_rejects_underreported_and_overreported_delta(self) -> None:
        result = self._dispatch_result()
        source = self.fixture.project / "src"
        source.mkdir(exist_ok=True)
        (source / "output.txt").write_text("executor output\n", encoding="utf-8")
        result["changed_paths"] = ["src/evidence.txt"]
        code, output = self._submit(result)
        self.assertEqual(code, 42)
        self.assertIn("BLOCKED_SCOPE_CONFLICT", output)

        (source / "output.txt").unlink()
        result["changed_paths"] = ["src/evidence.txt", "src/output.txt"]
        code, output = self._submit(result)
        self.assertEqual(code, 42)
        self.assertIn("BLOCKED_SCOPE_CONFLICT", output)

    def test_submit_rejects_out_of_scope_delta_for_non_pass_outcome(self) -> None:
        result = self._dispatch_result()
        (self.fixture.project / "outside.txt").write_text("outside scope\n", encoding="utf-8")
        result.update({
            "outcome": "FAILED",
            "summary": "Executor reported failure.",
            "changed_paths": ["src/evidence.txt", "outside.txt"],
            "verification": {"status": "FAILED", "checks": [{
                "check_id": "executor-failure",
                "status": "FAILED",
                "summary": "Executor reported failure.",
                "evidence_ids": ["evidence-1"],
            }]},
        })
        code, output = self._submit(result)
        self.assertEqual(code, 42)
        self.assertIn("BLOCKED_SCOPE_CONFLICT", output)

    def test_submit_rejects_mm_index_only_delta_when_reported_paths_are_empty(self) -> None:
        source = self.fixture.project / "src"
        source.mkdir()
        tracked = source / "tracked.txt"
        tracked.write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.fixture.project), "add", "src/tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(self.fixture.project), "commit", "-qm", "tracked fixture"], check=True)
        self.fixture.commit = subprocess.run(
            ["git", "-C", str(self.fixture.project), "rev-parse", "HEAD"],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        git_contract = self.fixture.contract["project"]["git"]
        git_contract["authorized_commits"][0]["commit"] = self.fixture.commit
        self.fixture.state["last_verified_commit"] = self.fixture.commit
        self.fixture.write_bundle()
        result = self._dispatch_result()
        tracked.write_text("staged\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.fixture.project), "add", "src/tracked.txt"], check=True)
        tracked.write_text("baseline\n", encoding="utf-8")
        status = subprocess.run(
            ["git", "-C", str(self.fixture.project), "status", "--porcelain", "src/tracked.txt"],
            text=True, capture_output=True, check=True,
        ).stdout
        self.assertTrue(status.startswith("MM "), status)
        result["changed_paths"] = ["src/evidence.txt"]
        code, output = self._submit(result)
        self.assertEqual(code, 42)
        self.assertIn("BLOCKED_SCOPE_CONFLICT", output)

    def test_submit_accepts_exact_report_for_mm_index_only_delta(self) -> None:
        source = self.fixture.project / "src"
        source.mkdir()
        tracked = source / "tracked.txt"
        tracked.write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.fixture.project), "add", "src/tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(self.fixture.project), "commit", "-qm", "tracked fixture"], check=True)
        self.fixture.commit = subprocess.run(
            ["git", "-C", str(self.fixture.project), "rev-parse", "HEAD"],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        self.fixture.contract["project"]["git"]["authorized_commits"][0]["commit"] = self.fixture.commit
        self.fixture.state["last_verified_commit"] = self.fixture.commit
        self.fixture.write_bundle()
        result = self._dispatch_result()
        tracked.write_text("staged\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.fixture.project), "add", "src/tracked.txt"], check=True)
        tracked.write_text("baseline\n", encoding="utf-8")
        result["changed_paths"] = ["src/evidence.txt", "src/tracked.txt"]
        code, output = self._submit(result)
        self.assertEqual(code, 0, output)
        self.assertIn("RESULT_COMMITTED", output)

    def test_submit_rejects_head_change_after_dispatch(self) -> None:
        result = self._dispatch_result()
        (self.fixture.project / "README.md").write_text("new commit\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.fixture.project), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(self.fixture.project), "commit", "-qm", "unexpected head"], check=True)
        code, output = self._submit(result)
        self.assertEqual(code, 42)
        self.assertTrue("BLOCKED_CONTRACT_INVALID" in output or "BLOCKED_WORKSPACE_INVALID" in output, output)

    def test_expired_lease_cannot_be_taken_over_or_used_for_submit(self) -> None:
        result = self._dispatch_result()
        lease_path = self.fixture.task / ".automation" / "lease.json"
        lease = json.loads(lease_path.read_text(encoding="utf-8"))
        lease["expires_at"] = "2000-01-01T00:00:00Z"
        lease_path.write_text(json.dumps(lease, indent=2) + "\n", encoding="utf-8")
        with self.assertRaises(orchestrator.AutomationError) as acquired:
            orchestrator.acquire_lease(orchestrator.runtime_paths(self.fixture.task), self.fixture.contract["task_id"], "other-owner")
        self.assertEqual(acquired.exception.code, "BLOCKED_LEASE_CONFLICT")
        code, output = self._submit(result)
        self.assertEqual(code, 42)
        self.assertIn("BLOCKED_LEASE_EXPIRED", output)

    def test_operator_can_recover_exact_expired_lease_with_audit(self) -> None:
        self._dispatch_result()
        lease_path = self.fixture.task / ".automation" / "lease.json"
        lease = json.loads(lease_path.read_text(encoding="utf-8"))
        old_nonce = lease["nonce"]
        lease["expires_at"] = "2000-01-01T00:00:00Z"
        lease_path.write_text(json.dumps(lease, indent=2) + "\n", encoding="utf-8")
        output = StringIO()
        with redirect_stdout(output):
            code = orchestrator.command_recover_lease(Namespace(
                task=str(self.fixture.task),
                project=str(self.fixture.project),
                expected_lease_digest=hashlib.sha256(old_nonce.encode("utf-8")).hexdigest(),
                new_owner="recovery-owner",
                operator="test-operator",
                reason="expired owner was independently confirmed inactive",
                confirm_no_active_owner="I_CONFIRM_NO_ACTIVE_OWNER",
                authorization=self._lease_authorization(lease),
            ))
        self.assertEqual(code, 0, output.getvalue())
        replacement = json.loads(lease_path.read_text(encoding="utf-8"))
        self.assertEqual(replacement["owner"], "recovery-owner")
        self.assertNotEqual(replacement["nonce"], old_nonce)
        events = [json.loads(line) for line in (self.fixture.task / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        recovered = [event for event in events if event.get("event") == "automation_lease_recovered"]
        self.assertEqual(len(recovered), 1)
        self.assertNotIn(old_nonce, json.dumps(recovered[0]))
        orchestrator.load_authority(self.fixture.task, self.fixture.project, allow_dirty_worktree=True)

    def test_lease_recovery_rejects_unexpired_or_unconfirmed_replacement(self) -> None:
        self._dispatch_result()
        lease_path = self.fixture.task / ".automation" / "lease.json"
        lease = json.loads(lease_path.read_text(encoding="utf-8"))
        digest = hashlib.sha256(lease["nonce"].encode("utf-8")).hexdigest()
        base = dict(
            task=str(self.fixture.task), project=str(self.fixture.project),
            expected_lease_digest=digest, new_owner="recovery-owner",
            operator="test-operator", reason="fixture recovery",
            confirm_no_active_owner="I_CONFIRM_NO_ACTIVE_OWNER",
            authorization=self._lease_authorization(lease),
        )
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(orchestrator.command_recover_lease(Namespace(**base)), 42)
        self.assertIn("BLOCKED_LEASE_RECOVERY", output.getvalue())
        lease["expires_at"] = "2000-01-01T00:00:00Z"
        lease_path.write_text(json.dumps(lease, indent=2) + "\n", encoding="utf-8")
        base["confirm_no_active_owner"] = "not-confirmed"
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(orchestrator.command_recover_lease(Namespace(**base)), 42)
        self.assertIn("explicit no-active-owner confirmation", output.getvalue())

        base["confirm_no_active_owner"] = "I_CONFIRM_NO_ACTIVE_OWNER"
        base["operator"] = "   "
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(orchestrator.command_recover_lease(Namespace(**base)), 42)
        self.assertIn("must be non-empty", output.getvalue())

        base["operator"] = "test-operator"
        base["new_owner"] = "unauthorized-owner"
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(orchestrator.command_recover_lease(Namespace(**base)), 42)
        self.assertIn("authorization new_owner binding is invalid", output.getvalue())

    def test_lease_recovery_journal_converges_after_audit_append_failure(self) -> None:
        self._dispatch_result()
        lease_path = self.fixture.task / ".automation" / "lease.json"
        lease = json.loads(lease_path.read_text(encoding="utf-8"))
        lease["expires_at"] = "2000-01-01T00:00:00Z"
        lease_path.write_text(json.dumps(lease, indent=2) + "\n", encoding="utf-8")
        args = Namespace(
            task=str(self.fixture.task), project=str(self.fixture.project),
            expected_lease_digest=hashlib.sha256(lease["nonce"].encode("utf-8")).hexdigest(),
            new_owner="recovery-owner", operator="test-operator",
            reason="recover after simulated writer loss",
            confirm_no_active_owner="I_CONFIRM_NO_ACTIVE_OWNER",
            authorization=self._lease_authorization(lease),
        )
        output = StringIO()
        with mock.patch.object(orchestrator, "append_lifecycle_event", side_effect=OSError("fixture audit failure")):
            with redirect_stdout(output):
                self.assertEqual(orchestrator.command_recover_lease(args), 42)
        journal = self.fixture.task / ".automation" / "lease-recovery.json"
        self.assertTrue(journal.exists())
        output = StringIO()
        # WAL replay must still converge when downtime outlives the replacement
        # lease. Its age is handled only after this transaction is completed.
        with mock.patch.object(orchestrator, "lease_expired", return_value=True):
            with redirect_stdout(output):
                self.assertEqual(orchestrator.command_recover_lease(args), 0)
        self.assertFalse(journal.exists())
        events = [json.loads(line) for line in (self.fixture.task / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(sum(event.get("event") == "automation_lease_recovered" for event in events), 1)

    def test_terminal_result_retires_lease_and_duplicate_is_idempotent(self) -> None:
        result = self._dispatch_result()
        code, output = self._submit(result)
        self.assertEqual(code, 0, output)
        lease = json.loads((self.fixture.task / ".automation" / "lease.json").read_text(encoding="utf-8"))
        self.assertTrue(orchestrator.lease_expired(lease))
        code, output = self._submit(result)
        self.assertEqual(code, 0, output)
        self.assertIn("DUPLICATE_RESULT", output)
        events = [json.loads(line) for line in (self.fixture.task / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(sum(event.get("event") == "automation_lease_released" for event in events), 1)

    def test_dispatch_maps_atomic_write_oserror_to_stable_cli_code(self) -> None:
        self.fixture.fresh_approval()
        output = StringIO()
        with mock.patch.object(orchestrator.contract_runtime, "atomic_write_json", side_effect=OSError("fixture disk error")):
            with redirect_stdout(output):
                code = orchestrator.command_dispatch(Namespace(
                    task=str(self.fixture.task), project=str(self.fixture.project), owner="test-owner",
                ))
        self.assertEqual(code, 42)
        self.assertIn("FAILED_RUNTIME_IO", output.getvalue())

    def test_task_control_root_equal_to_project_root_fails_closed(self) -> None:
        with self.assertRaises(orchestrator.AutomationError) as raised:
            orchestrator.workspace_file_manifest(self.fixture.project, self.fixture.project)
        self.assertEqual(raised.exception.code, "BLOCKED_WORKSPACE_INVALID")

    def test_invalid_utf8_result_maps_to_result_schema_domain(self) -> None:
        invalid = self.fixture.root / "invalid-utf8.json"
        invalid.write_bytes(b"\xff\xfe")
        output = StringIO()
        with redirect_stdout(output):
            code = orchestrator.command_submit(Namespace(
                task=str(self.fixture.task), project=str(self.fixture.project),
                owner="test-owner", result=str(invalid),
            ))
        self.assertEqual(code, 42)
        self.assertIn("FAILED_RESULT_SCHEMA", output.getvalue())

    def test_main_parses_once_and_json_reader_preserves_caller_domain(self) -> None:
        parsed = Namespace(func=mock.Mock(return_value=7))
        fake_parser = mock.Mock()
        fake_parser.parse_args.return_value = parsed
        with mock.patch.object(orchestrator, "parser", return_value=fake_parser):
            self.assertEqual(orchestrator.main(["status"]), 7)
        fake_parser.parse_args.assert_called_once_with(["status"])
        parsed.func.assert_called_once_with(parsed)

        with tempfile.TemporaryDirectory(prefix="TaskContracts-invalid-json-") as temp:
            invalid = Path(temp) / "invalid.json"
            invalid.write_text("{", encoding="utf-8")
            with self.assertRaises(orchestrator.AutomationError) as raised:
                orchestrator.read_json(invalid, "FAILED_TRANSITION_RECOVERY")
        self.assertEqual(raised.exception.code, "FAILED_TRANSITION_RECOVERY")
        help_text = orchestrator.parser().format_help()
        self.assertNotIn("recover-stale-lease", help_text)
        self.assertIn("recover-lease", help_text)


if __name__ == "__main__":
    unittest.main()
