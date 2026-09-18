from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "asmevo" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import gate
import lineage
import preflight


def evaluation_template() -> dict:
    return json.loads(
        (ROOT / "asmevo" / "assets" / "evaluation-template.json").read_text(
            encoding="utf-8"
        )
    )


class LineageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.temporary.name)
        self.state = self.run_dir / "lineage.json"
        self.original = self.run_dir / "original.hsaco"
        self.original.write_bytes(b"immutable-original")
        self.contract = self.run_dir / "contract.json"
        self.contract.write_text(
            json.dumps(evaluation_template()["contract"]), encoding="utf-8"
        )
        self.environment = self.run_dir / "environment.json"
        self.environment.write_bytes(
            (ROOT / "asmevo" / "assets" / "example-environment.json").read_bytes()
        )
        self.adapter = self.run_dir / "adapter"
        self.adapter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.adapter.chmod(self.adapter.stat().st_mode | 0o111)
        self.preflight = self.run_dir / "preflight.json"
        capabilities = {
            name: str(self.adapter) for name in preflight.SOURCE_CAPABILITIES
        }
        report = preflight.inspect(
            mode="source",
            artifact=self.original,
            capabilities=capabilities,
            required_files=[],
            require_gpu=False,
            target_arch="gfx942",
            detected_arches=["gfx942"],
            optimization_surface="hip_source",
        )
        self.preflight.write_text(json.dumps(report), encoding="utf-8")
        lineage.initialize(
            self.state,
            "K0",
            self.original,
            1.0,
            self.contract,
            self.preflight,
            self.environment,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _evaluation(
        self,
        candidate_id: str,
        candidate: Path | None,
        *,
        parent_id: str = "K0",
    ) -> dict:
        document = evaluation_template()
        state = json.loads(self.state.read_text(encoding="utf-8"))
        document["candidate_id"] = candidate_id
        document["parent_id"] = parent_id
        document["contract"] = json.loads(self.contract.read_text(encoding="utf-8"))
        document["artifacts"]["original_sha256"] = state["nodes"]["K0"][
            "artifact_sha256"
        ]
        document["artifacts"]["parent_sha256"] = state["nodes"][parent_id][
            "artifact_sha256"
        ]
        if candidate is not None:
            candidate_hash = lineage._sha256(candidate)
            document["proposal_sha256"] = candidate_hash
            document["artifacts"]["candidate_sha256"] = candidate_hash
        return document

    def _write_evaluation(self, document: dict, name: str) -> Path:
        path = self.run_dir / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def _record_accepted(self, candidate_id: str = "c001") -> tuple[Path, Path]:
        candidate = self.run_dir / f"{candidate_id}.hsaco"
        candidate.write_bytes(f"artifact-{candidate_id}".encode())
        evidence = self._write_evaluation(
            self._evaluation(candidate_id, candidate), f"{candidate_id}.evaluation.json"
        )
        result = lineage.record(
            self.state,
            evidence,
            candidate,
            "hide VMEM latency",
            [".text+0x40:.text+0x78"],
        )
        self.assertTrue(result["accepted"])
        return candidate, evidence

    def test_accepted_candidate_becomes_verified_best(self) -> None:
        self._record_accepted()
        report = lineage.summary(self.state)

        self.assertEqual(report["best_id"], "c001")
        self.assertEqual(report["verified_nodes"], 2)
        self.assertGreater(report["best_speedup_over_original"], 1.0)
        state = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(
            state["attempts"][0]["evaluation"]["timing"]["candidate_ms"],
            [0.91, 0.9, 0.9, 0.89, 0.9],
        )

    def test_rejected_candidate_never_becomes_parent_node(self) -> None:
        candidate = self.run_dir / "slow.hsaco"
        candidate.write_bytes(b"slow-candidate")
        document = self._evaluation("slow", candidate)
        document["timing"]["candidate_ms"] = [1.0] * 5
        evidence = self._write_evaluation(document, "slow.evaluation.json")

        result = lineage.record(
            self.state,
            evidence,
            candidate,
            "attempt instruction substitution",
            [".text+0x80:.text+0x90"],
        )
        report = lineage.summary(self.state)

        self.assertFalse(result["accepted"])
        self.assertEqual(report["best_id"], "K0")
        self.assertEqual(report["verified_nodes"], 1)
        self.assertEqual(report["rejected_attempts"], 1)

    def test_failed_build_is_recorded_without_candidate_artifact(self) -> None:
        document = self._evaluation("build-failed", None)
        document["checks"]["build"]["passed"] = False
        document["artifacts"]["candidate_sha256"] = None
        evidence = self._write_evaluation(document, "build-failed.json")

        result = lineage.record(
            self.state,
            evidence,
            None,
            "try an encoding rejected by the assembler",
            ["window-build"],
        )

        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "build_invalid")
        self.assertEqual(lineage.summary(self.state)["attempts"], 1)

    def test_duplicate_artifact_is_not_promoted(self) -> None:
        document = self._evaluation("same-bytes", self.original)
        evidence = self._write_evaluation(document, "duplicate.evaluation.json")

        result = lineage.record(
            self.state,
            evidence,
            self.original,
            "no-op encoding change",
            [".text+0x10:.text+0x18"],
        )

        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "duplicate")
        self.assertEqual(lineage.summary(self.state)["verified_nodes"], 1)

    def test_rejected_proposal_hash_is_deduplicated(self) -> None:
        first = self._evaluation("slow-1", None)
        first["checks"]["build"]["passed"] = False
        first["artifacts"]["candidate_sha256"] = None
        first_path = self._write_evaluation(first, "slow-1.json")
        lineage.record(self.state, first_path, None, "slow proposal", ["window-a"])

        second = copy.deepcopy(first)
        second["candidate_id"] = "slow-2"
        second_path = self._write_evaluation(second, "slow-2.json")
        result = lineage.record(
            self.state, second_path, None, "repeat slow proposal", ["window-a"]
        )

        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "duplicate")

    def test_rejected_successful_build_artifact_is_deduplicated(self) -> None:
        candidate = self.run_dir / "same-final-bytes.hsaco"
        candidate.write_bytes(b"same-final-bytes")
        first = self._evaluation("slow-final-1", candidate)
        first["timing"]["candidate_ms"] = [1.0] * 5
        first_path = self._write_evaluation(first, "slow-final-1.json")
        lineage.record(
            self.state,
            first_path,
            candidate,
            "first measurement of final bytes",
            ["window-a"],
        )

        second = self._evaluation("slow-final-2", candidate)
        second["proposal_sha256"] = "f" * 64
        second_path = self._write_evaluation(second, "slow-final-2.json")
        result = lineage.record(
            self.state,
            second_path,
            candidate,
            "retry identical final bytes with a new proposal ID",
            ["window-b"],
        )

        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "duplicate")

    def test_successful_build_requires_candidate_artifact(self) -> None:
        candidate = self.run_dir / "omitted.hsaco"
        candidate.write_bytes(b"omitted-artifact")
        document = self._evaluation("omitted", candidate)
        document["timing"]["candidate_ms"] = [1.0] * 5
        evidence = self._write_evaluation(document, "omitted.json")

        with self.assertRaisesRegex(lineage.LineageError, "successful builds require"):
            lineage.record(
                self.state,
                evidence,
                None,
                "omit rejected artifact",
                ["window"],
            )

    def test_parent_must_be_a_verified_node(self) -> None:
        document = self._evaluation("orphan", None)
        document["parent_id"] = "unverified"
        evidence = self._write_evaluation(document, "orphan.evaluation.json")

        with self.assertRaises(lineage.LineageError):
            lineage.record(
                self.state,
                evidence,
                None,
                "invalid branch",
                [".text+0x20:.text+0x28"],
            )

    def test_gated_artifact_cannot_be_swapped_before_recording(self) -> None:
        candidate = self.run_dir / "swapped.hsaco"
        candidate.write_bytes(b"gated-candidate")
        evidence = self._write_evaluation(
            self._evaluation("swapped", candidate), "swapped.evaluation.json"
        )
        candidate.write_bytes(b"different-bytes-after-gate")

        with self.assertRaisesRegex(
            lineage.LineageError, "does not match gated candidate"
        ):
            lineage.record(
                self.state,
                evidence,
                candidate,
                "attempt artifact swap",
                [".text+0x30:.text+0x38"],
            )

    def test_fresh_parent_measurements_are_allowed(self) -> None:
        parent, _ = self._record_accepted("parent")
        child = self.run_dir / "child.hsaco"
        child.write_bytes(b"artifact-child")
        document = self._evaluation("child", child, parent_id="parent")
        document["timing"]["original_ms"] = [1.02] * 5
        document["timing"]["parent_ms"] = [0.91] * 5
        document["timing"]["candidate_ms"] = [0.8] * 5
        evidence = self._write_evaluation(document, "child.evaluation.json")

        result = lineage.record(
            self.state,
            evidence,
            child,
            "optimize child with fresh paired measurements",
            [".text+0x90:.text+0xa0"],
        )

        self.assertTrue(parent.is_file())
        self.assertTrue(result["accepted"])
        self.assertEqual(lineage.summary(self.state)["verified_nodes"], 3)

    def test_changed_contract_cannot_enter_existing_lineage(self) -> None:
        candidate = self.run_dir / "new-contract.hsaco"
        candidate.write_bytes(b"new-contract")
        document = self._evaluation("new-contract", candidate)
        document["contract"]["case_ids"] = ["different-case"]
        document["equivalence"]["cases"][0]["case_id"] = "different-case"
        evidence = self._write_evaluation(document, "new-contract.evaluation.json")

        with self.assertRaisesRegex(lineage.LineageError, "contract does not match"):
            lineage.record(
                self.state,
                evidence,
                candidate,
                "change contract after baseline",
                ["window"],
            )

    def test_gate_output_cannot_be_submitted_as_evaluation(self) -> None:
        candidate = self.run_dir / "forged.hsaco"
        candidate.write_bytes(b"forged")
        decision = gate.evaluate(self._evaluation("forged", candidate))
        decision["metrics"]["candidate_speedup_over_original"] = 10000.0
        forged = self._write_evaluation(decision, "forged-decision.json")

        with self.assertRaisesRegex(lineage.LineageError, "deterministic gate"):
            lineage.record(
                self.state,
                forged,
                candidate,
                "submit a hand-edited decision",
                ["window"],
            )

    def test_original_mutation_blocks_record_and_summary(self) -> None:
        candidate = self.run_dir / "after-mutation.hsaco"
        candidate.write_bytes(b"candidate-after-mutation")
        evidence = self._write_evaluation(
            self._evaluation("after-mutation", candidate), "after-mutation.json"
        )
        self.original.write_bytes(b"mutated-on-disk")

        with self.assertRaisesRegex(lineage.LineageError, "changed after verification"):
            lineage.record(
                self.state,
                evidence,
                candidate,
                "try to reuse a mutated baseline",
                ["window"],
            )
        with self.assertRaisesRegex(lineage.LineageError, "changed after verification"):
            lineage.summary(self.state)

    def test_summary_detects_mutated_best_artifact(self) -> None:
        candidate, _ = self._record_accepted()
        candidate.write_bytes(b"mutated-best")

        with self.assertRaisesRegex(lineage.LineageError, "changed after verification"):
            lineage.summary(self.state)

    def test_preflight_report_is_bound_to_lineage(self) -> None:
        report = json.loads(self.preflight.read_text(encoding="utf-8"))
        report["ready"] = False
        report["status"] = "blocked"
        self.preflight.write_text(json.dumps(report), encoding="utf-8")

        with self.assertRaisesRegex(
            lineage.LineageError, "preflight report is not ready"
        ):
            lineage.summary(self.state)

    def test_environment_manifest_is_bound_to_lineage(self) -> None:
        self.environment.write_text("changed", encoding="utf-8")

        with self.assertRaisesRegex(
            lineage.LineageError, "environment manifest changed"
        ):
            lineage.summary(self.state)

    def test_concurrent_records_are_serialized(self) -> None:
        commands: list[list[str]] = []
        for index, latency in ((1, 0.88), (2, 0.84)):
            candidate = self.run_dir / f"parallel-{index}.hsaco"
            candidate.write_bytes(f"parallel-{index}".encode())
            document = self._evaluation(f"parallel-{index}", candidate)
            document["timing"]["candidate_ms"] = [latency] * 5
            evidence = self._write_evaluation(document, f"parallel-{index}.json")
            commands.append(
                [
                    sys.executable,
                    str(SCRIPTS / "lineage.py"),
                    "record",
                    "--state",
                    str(self.state),
                    "--evaluation",
                    str(evidence),
                    "--artifact",
                    str(candidate),
                    "--edit-summary",
                    f"parallel edit {index}",
                    "--changed-window",
                    f"window-{index}",
                ]
            )

        processes = [
            subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            for command in commands
        ]
        results = [process.communicate(timeout=10) for process in processes]

        self.assertEqual([process.returncode for process in processes], [0, 0], results)
        report = lineage.summary(self.state)
        self.assertEqual(report["attempts"], 2)
        self.assertEqual(report["verified_nodes"], 3)


if __name__ == "__main__":
    unittest.main()
