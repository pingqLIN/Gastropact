import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import task_contract


class OsBackedCheckpointLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="TaskContracts-core-lock-")
        self.task = Path(self.temp.name) / "task"
        self.task.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_existing_metadata_file_does_not_guess_that_writer_is_alive(self) -> None:
        lock_path = self.task / ".STATE.lock"
        lock_path.write_text(
            json.dumps({"pid": 999999, "acquired_at": "2000-01-01T00:00:00Z"}) + "\n",
            encoding="ascii",
        )
        with task_contract.checkpoint_lock(self.task):
            pass
        metadata = json.loads(lock_path.read_text(encoding="ascii"))
        self.assertEqual(metadata["pid"], task_contract.os.getpid())
        self.assertTrue(lock_path.exists())

    def test_active_writer_is_rejected_and_process_exit_releases_lock(self) -> None:
        child_code = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import task_contract
with task_contract.checkpoint_lock(Path(sys.argv[2])):
    print('LOCKED', flush=True)
    sys.stdin.read()
"""
        child = subprocess.Popen(
            [sys.executable, "-B", "-c", child_code, str(ROOT / "scripts"), str(self.task)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertEqual(child.stdout.readline().strip(), "LOCKED")
            with self.assertRaisesRegex(ValueError, "concurrent_state_change"):
                with task_contract.checkpoint_lock(self.task):
                    self.fail("active writer lock was not enforced")
            child.kill()
            child.wait(timeout=10)
            with task_contract.checkpoint_lock(self.task):
                pass
            metadata = json.loads((self.task / ".STATE.lock").read_text(encoding="ascii"))
            self.assertEqual(metadata["schema_version"], "taskcontracts-state-lock.v1")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()


class ExactAuditChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="TaskContracts-core-audit-")
        self.task = Path(self.temp.name) / "task"
        self.task.mkdir()
        self.contract = {
            "schema_version": "1.2",
            "task_id": "audit-fixture",
            "allowed_actions": [{"id": "a1"}],
            "hard_gates": [],
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_state(self, state: dict) -> str:
        (self.task / "STATE.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        return task_contract.file_sha256(self.task / "STATE.json")

    def write_events(self, events: list[dict]) -> None:
        (self.task / "events.jsonl").write_text(
            "".join(json.dumps(event, separators=(",", ":")) + "\n" for event in events),
            encoding="utf-8",
        )

    def v12_chain(self) -> tuple[dict, list[dict], str, str]:
        initial = {"schema_version": "1.2", "task_id": "audit-fixture", "revision": 0, "value": "initial"}
        initial_digest = self.write_state(initial)
        current = {
            "schema_version": "1.2",
            "task_id": "audit-fixture",
            "revision": 1,
            "previous_state_digest": initial_digest,
            "value": "current",
        }
        current_digest = self.write_state(current)
        events = [
            {"at": "2026-09-03T00:00:00Z", "event": "created", "task_id": "audit-fixture", "revision": 0, "target_state_digest": initial_digest},
            {
                "at": "2026-09-03T00:00:01Z",
                "event": "automation_transition",
                "task_id": "audit-fixture",
                "transition_id": "a" * 64,
                "revision": 1,
                "previous_state_digest": initial_digest,
                "target_state_digest": current_digest,
                "result_id": "result-1",
                "action_id": "a1",
                "outcome": "PASS",
            },
        ]
        return current, events, initial_digest, current_digest

    def test_v12_accepts_exact_automation_digest_chain_and_final_state(self) -> None:
        current, events, _, _ = self.v12_chain()
        events.insert(1, {"at": "2026-09-03T00:00:00Z", "event": "automation_dispatched", "task_id": "audit-fixture", "revision": 0, "action_id": "a1", "envelope": ".automation/envelopes/r0-a1.json", "owner": "test-owner"})
        self.write_events(events)
        self.assertEqual(task_contract.validate_audit(self.task, self.contract, current), [])

    def test_v12_rejects_invented_or_cross_task_event_identity(self) -> None:
        current, events, _, _ = self.v12_chain()
        mutations = (
            {"event": "invented-transition"},
            {"task_id": "another-task"},
            {"action_id": "invented-action"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                candidate = [dict(item) for item in events]
                candidate[1].update(mutation)
                self.write_events(candidate)
                issues = task_contract.validate_audit(self.task, self.contract, current)
                self.assertTrue(any(issue.reason == "audit_gap" for issue in issues))

    def test_v12_rejects_duplicate_lifecycle_identity(self) -> None:
        current, events, _, _ = self.v12_chain()
        dispatched = {"at": "2026-09-03T00:00:00Z", "event": "automation_dispatched", "task_id": "audit-fixture", "revision": 0, "action_id": "a1", "envelope": ".automation/envelopes/r0-a1.json", "owner": "test-owner"}
        events[1:1] = [dict(dispatched), dict(dispatched)]
        self.write_events(events)
        issues = task_contract.validate_audit(self.task, self.contract, current)
        self.assertTrue(any("duplicates" in issue.message for issue in issues), issues)

    def test_v12_rejects_broken_previous_digest_chain(self) -> None:
        current, events, _, _ = self.v12_chain()
        events[1]["previous_state_digest"] = "0" * 64
        self.write_events(events)
        issues = task_contract.validate_audit(self.task, self.contract, current)
        self.assertTrue(any("exact state chain" in issue.message for issue in issues))

    def test_v12_rejects_final_state_digest_mismatch(self) -> None:
        current, events, _, _ = self.v12_chain()
        self.write_events(events)
        current["value"] = "tampered"
        self.write_state(current)
        issues = task_contract.validate_audit(self.task, self.contract, current)
        self.assertTrue(any("does not match STATE.json" in issue.message for issue in issues))

    def test_v11_requires_revisions_to_be_ordered_continuous_and_unique(self) -> None:
        state = {"schema_version": "1.1", "revision": 2}
        self.write_state(state)
        cases = (
            [{"event": "created", "revision": 0}, {"event": "checkpoint", "revision": 2}],
            [{"event": "created", "revision": 0}, {"event": "checkpoint", "revision": 1}, {"event": "checkpoint", "revision": 1}, {"event": "checkpoint", "revision": 2}],
            [{"event": "checkpoint", "revision": 1}, {"event": "created", "revision": 0}, {"event": "checkpoint", "revision": 2}],
        )
        for events in cases:
            with self.subTest(events=events):
                self.write_events(events)
                issues = task_contract.validate_audit(self.task, {"schema_version": "1.1"}, state)
                self.assertTrue(any("continuous and unique" in issue.message for issue in issues))


class GitSpecialStateTests(unittest.TestCase):
    MARKERS = ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply", "sequencer")

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="TaskContracts-core-git-")
        self.project = Path(self.temp.name) / "project"
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.project)], check=True)
        subprocess.run(["git", "-C", str(self.project), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.project), "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", str(self.project), "remote", "add", "origin", "https://example.invalid/core-hardening.git"], check=True)
        (self.project / "README.md").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.project), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(self.project), "commit", "-qm", "fixture"], check=True)
        self.commit = subprocess.run(
            ["git", "-C", str(self.project), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        self.contract = {
            "schema_version": "1.2",
            "project": {
                "expected_root": str(self.project),
                "git": {
                    "required": True,
                    "remote": "https://example.invalid/core-hardening.git",
                    "authorized_commits": [{"id": "BASE", "commit": self.commit}],
                    "forbid_special_operation": True,
                },
            },
            "allowed_actions": [{"id": "action", "expected_commit_authority": "BASE"}],
        }
        self.state = {"next_action_id": "action"}

    def tearDown(self) -> None:
        self.temp.cleanup()

    def create_marker(self, marker: str) -> Path:
        path = task_contract.git_internal_path(self.project, marker)
        self.assertIsNotNone(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if marker.isupper():
            path.write_text(self.commit + "\n", encoding="ascii")
        else:
            path.mkdir(exist_ok=True)
        return path

    def remove_marker(self, path: Path) -> None:
        if path.is_dir():
            path.rmdir()
        else:
            path.unlink()

    def test_each_git_special_state_is_resolved_and_rejected(self) -> None:
        for marker in self.MARKERS:
            with self.subTest(marker=marker):
                path = self.create_marker(marker)
                try:
                    issues = task_contract.validate_project(self.contract, self.state, self.project)
                    self.assertTrue(any(f"in progress: {marker}" in issue.message for issue in issues))
                finally:
                    self.remove_marker(path)

    def test_special_state_check_obeys_contract_flag(self) -> None:
        path = self.create_marker("REVERT_HEAD")
        try:
            self.contract["project"]["git"]["forbid_special_operation"] = False
            issues = task_contract.validate_project(self.contract, self.state, self.project)
            self.assertFalse(any("special Git operation" in issue.message for issue in issues))
        finally:
            self.remove_marker(path)


if __name__ == "__main__":
    unittest.main()
