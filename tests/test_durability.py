from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "automation" / "durability_probe.py"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from automation import durability_probe
from tests import test_transaction_recovery as recovery_tests
import task_contract as contract_runtime
import task_orchestrator as orchestrator


HARD_EXIT_CODE = 91


def run_probe(*arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, "-B", str(PROBE), *arguments],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


class AtomicJsonAbruptExitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="TaskContracts-durability-atomic-")
        self.root = Path(self.temp.name)
        self.target = self.root / "STATE.json"
        self.old = {"revision": 0, "value": "old"}
        self.new = {"revision": 1, "value": "new"}
        self.target.write_text(json.dumps(self.old, indent=2) + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def invoke(self, fault: str) -> subprocess.CompletedProcess[str]:
        return run_probe(
            "atomic-write",
            "--path", str(self.target),
            "--payload-json", json.dumps(self.new, separators=(",", ":")),
            "--fault", fault,
            "--exit-code", str(HARD_EXIT_CODE),
        )

    def test_hard_exit_before_replace_preserves_old_parseable_json(self) -> None:
        completed = self.invoke("BEFORE_REPLACE")
        self.assertEqual(completed.returncode, HARD_EXIT_CODE, completed.stdout + completed.stderr)
        self.assertEqual(json.loads(self.target.read_text(encoding="utf-8")), self.old)

    def test_hard_exit_immediately_after_replace_exposes_whole_new_json(self) -> None:
        completed = self.invoke("AFTER_REPLACE")
        self.assertEqual(completed.returncode, HARD_EXIT_CODE, completed.stdout + completed.stderr)
        self.assertEqual(json.loads(self.target.read_text(encoding="utf-8")), self.new)

    def test_hard_exit_after_completed_atomic_write_exposes_whole_new_json(self) -> None:
        completed = self.invoke("AFTER_COMPLETE")
        self.assertEqual(completed.returncode, HARD_EXIT_CODE, completed.stdout + completed.stderr)
        self.assertEqual(json.loads(self.target.read_text(encoding="utf-8")), self.new)

    def test_atomic_write_invokes_parent_directory_sync_boundary(self) -> None:
        with mock.patch.object(contract_runtime, "fsync_parent_directory") as sync_parent:
            contract_runtime.atomic_write_json(self.target, self.new)
        sync_parent.assert_called_once_with(self.target)

    def test_claim_boundary_explicitly_excludes_physical_power_loss(self) -> None:
        self.assertTrue(durability_probe.PROCESS_ABRUPT_EXIT_SCOPE.startswith("VERIFIED:"))
        self.assertTrue(durability_probe.PHYSICAL_POWER_LOSS_SCOPE.startswith("UNKNOWN:"))
        self.assertIn("physical power loss", durability_probe.PHYSICAL_POWER_LOSS_SCOPE)


class TransactionAbruptExitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = recovery_tests.TransactionRecoveryTests(methodName="test_fault_after_wal_recovers")
        self.fixture.setUp()

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def submit_with_hard_exit(self, fault: str) -> subprocess.CompletedProcess[str]:
        return run_probe(
            "transaction-submit",
            "--task", str(self.fixture.task),
            "--project", str(self.fixture.project),
            "--result", str(self.fixture.result_path),
            "--owner", "test-owner",
            "--fault", fault,
            "--exit-code", str(HARD_EXIT_CODE),
        )

    def recover_in_new_process(self) -> subprocess.CompletedProcess[str]:
        return run_probe(
            "transaction-recover",
            "--task", str(self.fixture.task),
            "--project", str(self.fixture.project),
        )

    def transition_events(self) -> list[dict]:
        return [
            json.loads(line)
            for line in (self.fixture.task / "events.jsonl").read_text(encoding="utf-8").splitlines()
            if line and json.loads(line).get("event") == "automation_transition"
        ]

    def assert_hard_exit_recovers_exactly_once(
        self,
        fault: str,
        expected_revision: int,
        expected_events: int,
        expected_receipt: bool,
    ) -> None:
        crashed = self.submit_with_hard_exit(fault)
        self.assertEqual(crashed.returncode, HARD_EXIT_CODE, crashed.stdout + crashed.stderr)
        paths = orchestrator.runtime_paths(self.fixture.task)
        self.assertTrue(paths["journal"].is_file())
        state = json.loads((self.fixture.task / "STATE.json").read_text(encoding="utf-8"))
        self.assertEqual(state["revision"], expected_revision)
        self.assertEqual(len(self.transition_events()), expected_events)
        receipt = paths["results"] / "result-1.json"
        self.assertEqual(receipt.is_file(), expected_receipt)

        recovered = self.recover_in_new_process()
        self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)
        self.assertFalse(paths["journal"].exists())
        final_state = json.loads((self.fixture.task / "STATE.json").read_text(encoding="utf-8"))
        self.assertEqual(final_state["revision"], 1)
        self.assertEqual(final_state["status"], "PASS")
        self.assertEqual(len(self.transition_events()), 1)
        self.assertTrue(receipt.is_file())
        receipt_bytes = receipt.read_bytes()

        repeated = self.recover_in_new_process()
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        self.assertEqual(len(self.transition_events()), 1)
        self.assertEqual(receipt.read_bytes(), receipt_bytes)
        _, _, issues = contract_runtime.inspect(
            self.fixture.task,
            self.fixture.project,
            allow_dirty_worktree=True,
        )
        self.assertEqual(issues, [])

    def test_os_exit_after_wal_recovers(self) -> None:
        self.assert_hard_exit_recovers_exactly_once(orchestrator.FAULT_AFTER_WAL, 0, 0, False)

    def test_os_exit_after_state_recovers(self) -> None:
        self.assert_hard_exit_recovers_exactly_once(orchestrator.FAULT_AFTER_STATE, 1, 0, False)

    def test_os_exit_after_event_recovers(self) -> None:
        self.assert_hard_exit_recovers_exactly_once(orchestrator.FAULT_AFTER_EVENT, 1, 1, False)

    def test_os_exit_after_receipt_recovers(self) -> None:
        self.assert_hard_exit_recovers_exactly_once(orchestrator.FAULT_AFTER_RECEIPT, 1, 1, True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
