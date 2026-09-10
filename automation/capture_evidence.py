#!/usr/bin/env python3
"""Run the local gate and produce a digest-bound, Git-ignored evidence bundle."""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PARTS = {".git", ".local", ".automation", "__pycache__"}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def source_manifest() -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if not path.is_file() or EXCLUDED_PARTS.intersection(relative.parts):
            continue
        data = path.read_bytes()
        entries.append({
            "path": relative.as_posix(),
            "bytes": len(data),
            "sha256": sha256_bytes(data),
        })
    return entries


def main() -> int:
    captured_at = datetime.now(timezone.utc).replace(microsecond=0)
    evidence_id = captured_at.strftime("%Y%m%dT%H%M%SZ")
    destination = ROOT / ".local" / "evidence" / evidence_id
    destination.mkdir(parents=True, exist_ok=False)

    completed = subprocess.run(
        [sys.executable, "-B", "automation/verify_project.py"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    log = (
        "===== STDOUT =====\n"
        + completed.stdout
        + "\n===== STDERR =====\n"
        + completed.stderr
    )
    log_path = destination / "repository-gate.log"
    log_path.write_text(log, encoding="utf-8", newline="\n")

    files = source_manifest()
    canonical_manifest = json.dumps(files, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    report = {
        "schema_version": "taskcontracts-local-verification-evidence.v1",
        "evidence_id": evidence_id,
        "captured_at": captured_at.isoformat().replace("+00:00", "Z"),
        "result": "PASS" if completed.returncode == 0 else "FAIL",
        "exit_code": completed.returncode,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "command": "python -B automation/verify_project.py",
        "log": {
            "path": "repository-gate.log",
            "sha256": sha256_bytes(log_path.read_bytes()),
        },
        "source_manifest": {
            "file_count": len(files),
            "sha256": sha256_bytes(canonical_manifest),
            "files": files,
        },
        "publication_status": "LOCAL_GIT_IGNORED_NOT_FOR_PUBLICATION",
    }
    report_path = destination / "verification.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"EVIDENCE result={report['result']} path={destination}")
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
