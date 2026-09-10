from __future__ import annotations

import copy
import json
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from automation import verify_project
import task_contract


class V12SchemaParityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = json.loads((ROOT / "templates" / "TASK.json").read_text(encoding="utf-8"))
        self.state = json.loads((ROOT / "templates" / "STATE.json").read_text(encoding="utf-8"))

    def assert_runtime_rejects(self, contract: dict, state: dict, expected: str) -> None:
        messages = [issue.message for issue in task_contract.validate_shape(contract, state)]
        self.assertTrue(any(expected in message for message in messages), messages)

    def test_published_v12_templates_pass_runtime_validation(self) -> None:
        self.assertEqual(task_contract.validate_shape(self.contract, self.state), [])

    def test_runtime_rejects_reviewer_reproductions(self) -> None:
        cases = []
        short_order = copy.deepcopy(self.contract)
        short_order["authority_order"] = short_order["authority_order"][:7]
        cases.append((short_order, copy.deepcopy(self.state), "authority_order"))
        no_gates = copy.deepcopy(self.contract)
        no_gates["hard_gates"] = []
        cases.append((no_gates, copy.deepcopy(self.state), "hard_gates"))
        traversal = copy.deepcopy(self.contract)
        traversal["allowed_actions"][0]["allowed_workspace_paths"] = ["../outside"]
        cases.append((traversal, copy.deepcopy(self.state), "allowed workspace path"))
        windows_separator = copy.deepcopy(self.contract)
        windows_separator["allowed_actions"][0]["allowed_workspace_paths"] = ["src\\safe"]
        cases.append((windows_separator, copy.deepcopy(self.state), "allowed workspace path"))
        bad_progress = copy.deepcopy(self.state)
        bad_progress["benchmark_progress"] = "invalid"
        cases.append((copy.deepcopy(self.contract), bad_progress, "benchmark_progress"))
        for contract, state, expected in cases:
            with self.subTest(expected=expected):
                self.assert_runtime_rejects(contract, state, expected)

    def test_runtime_rejects_date_hash_enum_and_type_drift(self) -> None:
        cases = []
        bad_date = copy.deepcopy(self.contract)
        bad_date["authority"]["issued_at"] = "not-a-date"
        cases.append((bad_date, copy.deepcopy(self.state), "issued_at"))
        bad_hash = copy.deepcopy(self.state)
        bad_hash["previous_state_digest"] = "not-a-hash"
        cases.append((copy.deepcopy(self.contract), bad_hash, "previous_state_digest"))
        bad_enum = copy.deepcopy(self.contract)
        bad_enum["task_type"] = "invalid"
        cases.append((bad_enum, copy.deepcopy(self.state), "task_type"))
        bad_type = copy.deepcopy(self.state)
        bad_type["rounds_completed"] = "0"
        cases.append((copy.deepcopy(self.contract), bad_type, "rounds_completed"))
        bad_nested_type = copy.deepcopy(self.contract)
        bad_nested_type["policy_boundaries"] = []
        cases.append((bad_nested_type, copy.deepcopy(self.state), "policy_boundaries"))
        bad_action_item = copy.deepcopy(self.contract)
        bad_action_item["allowed_actions"][0]["prerequisites"] = [{}]
        cases.append((bad_action_item, copy.deepcopy(self.state), "prerequisites"))
        for contract, state, expected in cases:
            with self.subTest(expected=expected):
                self.assert_runtime_rejects(contract, state, expected)

    def test_nullable_fields_pass_but_terminal_action_null_is_rejected(self) -> None:
        self.assertEqual(task_contract.validate_shape(self.contract, self.state), [])
        terminal = copy.deepcopy(self.state)
        terminal.update({
            "status": "PASS",
            "completed_actions": ["inspect-authority"],
            "last_completed_action_id": "inspect-authority",
            "resume_from": None,
        })
        self.assertEqual(task_contract.validate_shape(self.contract, terminal), [])
        null_action = copy.deepcopy(terminal)
        null_action.update({"next_action_id": None, "next_action": None})
        self.assert_runtime_rejects(copy.deepcopy(self.contract), null_action, "action")
        resumable = copy.deepcopy(terminal)
        resumable["resume_from"] = "inspect-authority"
        self.assert_runtime_rejects(copy.deepcopy(self.contract), resumable, "resume_from")

    def test_approval_date_and_hash_are_runtime_validated(self) -> None:
        self.state["approvals"] = [{
            "action_id": "inspect-authority",
            "source": "explicit-user",
            "approved_at": "not-a-date",
            "scope": "bounded action",
            "contract_hash": "invalid",
            "state_revision": 0,
        }]
        messages = [issue.message for issue in task_contract.validate_shape(self.contract, self.state)]
        self.assertTrue(any("approved_at" in message for message in messages), messages)
        self.assertTrue(any("contract_hash" in message for message in messages), messages)

    def test_ajv_draft_2020_gate_compiles_and_validates_examples(self) -> None:
        verify_project.check_json_schemas()

    def test_ajv_gate_fails_closed_when_validator_is_unavailable(self) -> None:
        with mock.patch.object(verify_project.subprocess, "run", side_effect=FileNotFoundError("node unavailable")):
            with redirect_stdout(StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    verify_project.check_json_schemas()
        self.assertEqual(raised.exception.code, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
