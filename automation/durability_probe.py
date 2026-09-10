#!/usr/bin/env python3
"""Child-process probe for abrupt-exit durability tests.

This helper deliberately uses ``os._exit`` so Python cleanup handlers do not run.
It verifies process-abrupt-exit behavior only; it cannot simulate physical power
loss, storage-controller cache loss, or filesystem journal replay.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from argparse import Namespace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import task_contract as contract_runtime
import task_orchestrator as orchestrator


PROCESS_ABRUPT_EXIT_SCOPE = "VERIFIED: independent child process terminated through os._exit"
PHYSICAL_POWER_LOSS_SCOPE = "UNKNOWN: physical power loss and storage-cache persistence are not simulated"


def hard_exit(exit_code: int) -> None:
    if not 1 <= exit_code <= 255:
        raise ValueError("exit code must be between 1 and 255")
    os._exit(exit_code)


def command_atomic(args: argparse.Namespace) -> int:
    path = Path(args.path)
    payload = json.loads(args.payload_json)
    if not isinstance(payload, dict):
        raise ValueError("atomic payload must be a JSON object")
    if args.fault == "BEFORE_REPLACE":
        contract_runtime.atomic_write_json(
            path,
            payload,
            before_replace=lambda _temp: hard_exit(args.exit_code),
        )
    elif args.fault == "AFTER_REPLACE":
        original_replace = contract_runtime.os.replace

        def replace_then_exit(source: os.PathLike[str] | str, target: os.PathLike[str] | str) -> None:
            original_replace(source, target)
            hard_exit(args.exit_code)

        contract_runtime.os.replace = replace_then_exit
        contract_runtime.atomic_write_json(path, payload)
    else:
        contract_runtime.atomic_write_json(path, payload)
        hard_exit(args.exit_code)
    return 0


def command_submit(args: argparse.Namespace) -> int:
    def exit_at_fault(name: str) -> None:
        if name == args.fault:
            hard_exit(args.exit_code)

    orchestrator._fault_hook = exit_at_fault
    return orchestrator.command_submit(Namespace(
        task=args.task,
        project=args.project,
        owner=args.owner,
        result=args.result,
    ))


def command_recover(args: argparse.Namespace) -> int:
    return orchestrator.command_recover(Namespace(task=args.task, project=args.project))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    atomic = commands.add_parser("atomic-write")
    atomic.add_argument("--path", required=True)
    atomic.add_argument("--payload-json", required=True)
    atomic.add_argument("--fault", required=True, choices=("BEFORE_REPLACE", "AFTER_REPLACE", "AFTER_COMPLETE"))
    atomic.add_argument("--exit-code", required=True, type=int)
    atomic.set_defaults(func=command_atomic)
    submit = commands.add_parser("transaction-submit")
    submit.add_argument("--task", required=True)
    submit.add_argument("--project", required=True)
    submit.add_argument("--result", required=True)
    submit.add_argument("--owner", required=True)
    submit.add_argument("--fault", required=True, choices=(
        orchestrator.FAULT_AFTER_WAL,
        orchestrator.FAULT_AFTER_STATE,
        orchestrator.FAULT_AFTER_EVENT,
        orchestrator.FAULT_AFTER_RECEIPT,
    ))
    submit.add_argument("--exit-code", required=True, type=int)
    submit.set_defaults(func=command_submit)
    recover = commands.add_parser("transaction-recover")
    recover.add_argument("--task", required=True)
    recover.add_argument("--project", required=True)
    recover.set_defaults(func=command_recover)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
