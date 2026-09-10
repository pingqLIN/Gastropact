from __future__ import annotations

import os
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import task_contract


@unittest.skipUnless(os.name == "posix", "POSIX fcntl lock semantics require a POSIX runner")
class PosixCheckpointLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="TaskContracts-posix-lock-")
        self.task = Path(self.temp.name) / "task"
        self.task.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_contender(self) -> subprocess.CompletedProcess[str]:
        child_code = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import task_contract
try:
    with task_contract.checkpoint_lock(Path(sys.argv[2])):
        print('ACQUIRED')
except task_contract.CheckpointLockError:
    print('CONTENDED')
    raise SystemExit(73)
"""
        return subprocess.run(
            [sys.executable, "-B", "-c", child_code, str(SCRIPTS), str(self.task)],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )

    def test_active_writer_rejects_second_process_then_releases(self) -> None:
        import fcntl  # noqa: F401 - proves this runner has the production POSIX primitive

        with task_contract.checkpoint_lock(self.task):
            contender = self.run_contender()
            self.assertEqual(contender.returncode, 73, contender.stdout + contender.stderr)
            self.assertEqual(contender.stdout.strip(), "CONTENDED")

        contender = self.run_contender()
        self.assertEqual(contender.returncode, 0, contender.stdout + contender.stderr)
        self.assertEqual(contender.stdout.strip(), "ACQUIRED")

    def test_sigkill_releases_kernel_lock_without_ttl_recovery(self) -> None:
        child_code = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import task_contract
with task_contract.checkpoint_lock(Path(sys.argv[2])):
    print('LOCKED', flush=True)
    sys.stdin.read()
"""
        holder = subprocess.Popen(
            [sys.executable, "-B", "-c", child_code, str(SCRIPTS), str(self.task)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertIsNotNone(holder.stdout)
            readable, _, _ = select.select([holder.stdout], [], [], 10)
            self.assertTrue(readable, "holder did not report lock acquisition within 10 seconds")
            self.assertEqual(holder.stdout.readline().strip(), "LOCKED")
            os.kill(holder.pid, signal.SIGKILL)
            holder.wait(timeout=10)
            self.assertLess(holder.returncode, 0)

            with task_contract.checkpoint_lock(self.task):
                pass
        finally:
            if holder.poll() is None:
                holder.kill()
                holder.wait(timeout=10)
            for stream in (holder.stdin, holder.stdout, holder.stderr):
                if stream is not None:
                    stream.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
