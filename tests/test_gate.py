from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "asmevo" / "scripts"))

import gate


def evaluation() -> dict:
    return json.loads(
        (ROOT / "asmevo" / "assets" / "evaluation-template.json").read_text(
            encoding="utf-8"
        )
    )


class GateTests(unittest.TestCase):
    def test_accepts_correct_stable_improvement(self) -> None:
        decision = gate.evaluate(evaluation())

        self.assertTrue(decision["accepted"])
        self.assertEqual(decision["status"], "accepted")
        self.assertGreater(decision["metrics"]["candidate_speedup_over_parent"], 1.1)

    def test_build_failure_short_circuits_later_gates(self) -> None:
        document = evaluation()
        document["candidate_id"] = "broken"
        document["checks"] = {"build": {"passed": False}}
        document.pop("equivalence")
        document.pop("timing")

        decision = gate.evaluate(document)

        self.assertFalse(decision["accepted"])
        self.assertEqual(decision["status"], "build_invalid")
        self.assertNotIn("timing", decision["metrics"])

    def test_build_failure_does_not_require_a_candidate_artifact(self) -> None:
        document = evaluation()
        document["checks"]["build"]["passed"] = False
        document["artifacts"]["candidate_sha256"] = None

        decision = gate.evaluate(document)

        self.assertEqual(decision["status"], "build_invalid")

    def test_binary_mode_requires_static_consistency(self) -> None:
        document = evaluation()
        document["mode"] = "binary"
        document["contract"]["mode"] = "binary"
        document["checks"]["static_consistency"] = {"passed": False}

        decision = gate.evaluate(document)

        self.assertEqual(decision["status"], "static_invalid")

    def test_binary_mode_cannot_disable_static_consistency(self) -> None:
        document = evaluation()
        document["mode"] = "binary"
        document["contract"]["mode"] = "binary"
        document["checks"]["static_consistency"] = {
            "required": False,
            "passed": True,
        }

        decision = gate.evaluate(document)

        self.assertFalse(decision["accepted"])
        self.assertEqual(decision["status"], "static_invalid")

    def test_guard_corruption_has_distinct_failure(self) -> None:
        document = evaluation()
        document["equivalence"]["cases"][0]["guards_intact"] = False

        decision = gate.evaluate(document)

        self.assertEqual(decision["status"], "canary_corruption")

    def test_numeric_divergence_prevents_timing(self) -> None:
        document = evaluation()
        document["equivalence"]["cases"][0]["cosine_similarity"] = 0.5

        decision = gate.evaluate(document)

        self.assertEqual(decision["status"], "divergent")
        self.assertEqual(decision["metrics"], {})

    def test_float_metric_applicability_is_frozen_by_contract(self) -> None:
        document = evaluation()
        case_id = document["contract"]["case_ids"][0]
        document["equivalence"]["cases"][0]["float_metrics_applicable"] = False

        with self.assertRaisesRegex(gate.GateInputError, "exact_only_case_ids"):
            gate.evaluate(document)

        document["contract"]["equivalence_policy"]["exact_only_case_ids"] = [case_id]
        decision = gate.evaluate(document)
        self.assertTrue(decision["accepted"])

    def test_harness_can_invalidate_timing(self) -> None:
        document = evaluation()
        document["timing"] = {
            "valid": False,
            "invalid_reason": "clock throttling detected",
        }

        decision = gate.evaluate(document)

        self.assertEqual(decision["status"], "timing_invalid")
        self.assertIn("clock throttling", decision["reasons"][0])

    def test_unstable_samples_are_rejected(self) -> None:
        document = evaluation()
        document["timing"]["original_ms"] = [1.0, 1.4, 0.7, 1.3, 0.8]

        decision = gate.evaluate(document)

        self.assertEqual(decision["status"], "timing_unstable")

    def test_candidate_must_beat_verified_parent(self) -> None:
        document = evaluation()
        document["timing"]["parent_ms"] = [0.9] * 5
        document["timing"]["candidate_ms"] = [0.9] * 5

        decision = gate.evaluate(document)

        self.assertEqual(decision["status"], "insufficient_speedup")
        self.assertFalse(decision["accepted"])

    def test_input_is_not_mutated(self) -> None:
        document = evaluation()
        before = copy.deepcopy(document)

        gate.evaluate(document)

        self.assertEqual(document, before)

    def test_decision_is_deterministic_for_fixed_evidence(self) -> None:
        document = evaluation()

        first = gate.evaluate(document)
        second = gate.evaluate(document)

        self.assertEqual(first, second)

    def test_rejects_audit_mode_and_bad_samples(self) -> None:
        document = evaluation()
        document["mode"] = "audit"
        with self.assertRaises(gate.GateInputError):
            gate.evaluate(document)

        document = evaluation()
        document["unexpected"] = float("nan")
        with self.assertRaisesRegex(gate.GateInputError, "canonical JSON"):
            gate.evaluate(document)

    def test_case_set_must_match_frozen_contract(self) -> None:
        document = evaluation()
        document["equivalence"]["cases"][0]["case_id"] = "different-case"

        with self.assertRaisesRegex(
            gate.GateInputError, "must match contract.case_ids"
        ):
            gate.evaluate(document)

    def test_decision_carries_canonical_contract_identity(self) -> None:
        document = evaluation()

        decision = gate.evaluate(document)

        self.assertEqual(
            decision["contract_sha256"], gate.contract_digest(document["contract"])
        )

    def test_environment_identity_must_be_a_sha256(self) -> None:
        document = evaluation()
        document["contract"]["environment_sha256"] = (
            "replace-with-frozen-environment-fingerprint"
        )

        with self.assertRaisesRegex(gate.GateInputError, "64-character hexadecimal"):
            gate.evaluate(document)

    def test_cli_reports_malformed_samples_as_input_invalid(self) -> None:
        document = evaluation()
        document["timing"]["candidate_ms"][0] = 0
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "asmevo" / "scripts" / "gate.py"),
                    str(path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["status"], "input_invalid")

        document = evaluation()
        document["timing"]["candidate_ms"][0] = -1
        with self.assertRaises(gate.GateInputError):
            gate.evaluate(document)


if __name__ == "__main__":
    unittest.main()
