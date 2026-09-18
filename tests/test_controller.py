from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "asmevo" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import controller
import lineage
import preflight

FAKE_ADAPTER = r"""#!/usr/bin/env python3
import hashlib
import json
import os
import sys
import time
from pathlib import Path


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


request_path = Path(sys.argv[sys.argv.index("--request") + 1])
request = json.loads(request_path.read_text(encoding="utf-8"))
control_path = Path(os.environ["ASMEVO_FAKE_CONTROL"])
control = json.loads(control_path.read_text(encoding="utf-8"))
log_path = Path(os.environ["ASMEVO_FAKE_LOG"])
with log_path.open("a", encoding="utf-8") as log:
    log.write(request["operation"] + "\n")

operation = request["operation"]
if control.get("sleep_operation") == operation:
    time.sleep(float(control.get("sleep_seconds", 2)))
if control.get("spam_operation") == operation:
    sys.stdout.write("x" * int(control.get("spam_bytes", 1048576)))
    sys.stdout.flush()

response = {
    "schema_version": request["schema_version"],
    "protocol": request["protocol"],
    "request_id": request["request_id"],
    "operation": operation,
    "binding": request["binding"],
    "ok": True,
}
if control.get("wrong_binding_operation") == operation:
    response["binding"] = dict(request["binding"])
    response["binding"]["contract_sha256"] = "f" * 64
if control.get("fail_operation") == operation:
    response["ok"] = False
    response["error"] = "injected adapter rejection"

outputs = request.get("outputs", {})
if response["ok"] and operation == "recover":
    path = Path(outputs["recovered"])
    path.write_text('{"recovered":true}\n', encoding="utf-8")
    response["output_sha256"] = digest(path)
elif response["ok"] and operation in {"build", "rebuild"}:
    path = Path(outputs["candidate_artifact"])
    payload = (
        b"fixed-candidate"
        if control.get("fixed_candidate_bytes") and request["purpose"] == "candidate"
        else (
            request["purpose"] + ":" + request["binding"]["proposal_sha256"]
        ).encode("utf-8")
    )
    path.write_bytes(payload)
    response["candidate_sha256"] = digest(path)
    if request["binding"].get("optimization_surface") == "amdgcn_assembly":
        response["compiled"] = True
        response["precompiled_variant"] = bool(control.get("precompiled_variant"))
        response["artifact_kind"] = "hsaco"
elif response["ok"] and operation == "disassemble":
    path = Path(outputs["disassembly_evidence"])
    path.write_text('{"disassembly":true}\n', encoding="utf-8")
    response["output_sha256"] = digest(path)
    response["artifact_kind"] = "hsaco"
    if request["purpose"] == "candidate":
        response["instruction_diff"] = {
            "nonempty": True,
            "within_declared_windows": True,
        }
elif response["ok"] and operation == "static_check":
    response["abi_consistent"] = True
    response["resource_consistent"] = True
elif response["ok"] and operation == "profile":
    path = Path(outputs["profile_evidence"])
    artifact = request["inputs"]["candidate_artifact"]
    profile = {
        "schema_version": 2,
        "kind": "asmevo.profile-evidence.v2",
        "status": "complete",
        "artifact_sha256": artifact["sha256"],
        "target_arch": request["binding"]["target_arch"],
        "contract_sha256": request["binding"]["contract_sha256"],
        "environment_sha256": request["binding"]["environment_sha256"],
        "kernel_symbol": "test_kernel",
        "dispatch_count": 5,
        "sampled_time_ms": 1.0,
        "hotspots": [{"start_pc": "0x40", "end_pc": "0x78", "weight": 1.0}],
        "counters": {"VMEM": 1},
        "unavailable_counters": [],
        "resources": {"vgpr_count": 8},
        "bottleneck_class": "long_latency_memory",
        "profiler": {"path": "fake-profiler", "sha256": "f" * 64},
        "raw_files": [
            {"relative_path": "fake.csv", "sha256": "e" * 64, "size_bytes": 1}
        ],
    }
    path.write_text(json.dumps(profile) + "\n", encoding="utf-8")
    response["output_sha256"] = digest(path)
elif response["ok"] and operation in {"oracle", "replay"}:
    if "observations" in outputs:
        path = Path(outputs["observations"])
        path.write_text('{"observations":true}\n', encoding="utf-8")
        response["output_sha256"] = digest(path)
    else:
        cosine = 0.5 if control.get("diverge_candidate") and request["purpose"] == "candidate" else 1.0
        response["equivalence"] = {
            "cases": [
                {
                    "case_id": case_id,
                    "runtime_ok": True,
                    "float_metrics_applicable": True,
                    "cosine_similarity": cosine,
                    "max_absolute_error": 0.0,
                    "integer_exact": True,
                    "guards_intact": True,
                }
                for case_id in request["binding"]["case_ids"]
            ]
        }
elif response["ok"] and operation == "compare":
    if control.get("mutate_observation_during_compare"):
        Path(request["inputs"]["candidate"]["path"]).write_text(
            '{"observations":"mutated"}\n', encoding="utf-8"
        )
    cosine = 0.5 if control.get("diverge_candidate") and request["purpose"] == "candidate" else 1.0
    response["equivalence"] = {
        "cases": [
            {
                "case_id": case_id,
                "runtime_ok": True,
                "float_metrics_applicable": True,
                "cosine_similarity": cosine,
                "max_absolute_error": 0.0,
                "integer_exact": True,
                "guards_intact": True,
            }
            for case_id in request["binding"]["case_ids"]
        ]
    }
elif response["ok"] and operation == "benchmark":
    if request["purpose"] == "baseline":
        response["samples_ms"] = [1.0, 1.0, 1.0, 1.0, 1.0]
    else:
        if control.get("mutate_candidate_during_benchmark"):
            candidate = request["inputs"]["measure_artifacts"]["candidate"]["path"]
            Path(candidate).write_bytes(b"mutated-during-benchmark")
        response["timing"] = {
            "valid": True,
            "original_ms": [1.0, 1.0, 1.0, 1.0, 1.0],
            "parent_ms": [1.0, 1.0, 1.0, 1.0, 1.0],
            "candidate_ms": control.get(
                "candidate_ms", [0.9, 0.9, 0.9, 0.9, 0.9]
            ),
        }

if control.get("close_streams_operation") == operation:
    os.write(1, (json.dumps(response, allow_nan=False) + "\n").encode("utf-8"))
    os.close(1)
    os.close(2)
    time.sleep(float(control.get("cleanup_seconds", 0.2)))
    os._exit(0)

print(json.dumps(response, allow_nan=False))
"""


class ControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.run_dir = self.directory / "run"
        self.state = self.directory / "lineage.json"
        self.original = self.directory / "original.hsaco"
        self.original.write_bytes(b"immutable-original")
        self.environment = self.directory / "environment.json"
        self.environment.write_text(
            json.dumps({"gpu": "gfx942", "driver": "test"}) + "\n",
            encoding="utf-8",
        )
        self.adapter = self.directory / "fake-adapter"
        self.adapter.write_text(
            textwrap.dedent(FAKE_ADAPTER), encoding="utf-8", newline="\n"
        )
        self.adapter.chmod(0o755)
        self.control = self.directory / "control.json"
        self.log = self.directory / "invocations.log"
        self._set_control({})
        self.log.write_text("", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _set_control(self, document: dict) -> None:
        self.control.write_text(json.dumps(document), encoding="utf-8")

    def _environment(self) -> mock._patch_dict:
        return mock.patch.dict(
            os.environ,
            {
                "ASMEVO_FAKE_CONTROL": str(self.control),
                "ASMEVO_FAKE_LOG": str(self.log),
            },
        )

    def _prepare(self, mode: str = "source", surface: str | None = None) -> None:
        environment_hash = hashlib.sha256(self.environment.read_bytes()).hexdigest()
        template = json.loads(
            (ROOT / "asmevo" / "assets" / "contract-template.json").read_text(
                encoding="utf-8"
            )
        )
        template["mode"] = mode
        if surface is not None:
            template["schema_version"] = 2
            template["optimization_surface"] = surface
        elif mode == "binary":
            template["schema_version"] = 1
            template.pop("optimization_surface", None)
        template["environment_sha256"] = environment_hash
        self.contract = self.directory / "contract.json"
        self.contract.write_text(json.dumps(template), encoding="utf-8")
        capabilities = preflight.backend_common.required_capabilities(mode, surface)
        report = preflight.inspect(
            mode=mode,
            artifact=self.original,
            capabilities={name: str(self.adapter) for name in capabilities},
            required_files=[],
            require_gpu=False,
            target_arch="gfx942",
            detected_arches=["gfx942"],
            optimization_surface=(
                surface
                if surface is not None
                else "hip_source"
                if mode == "source"
                else None
            ),
            tools=(
                {name: str(self.adapter) for name in preflight.ASM_TOOL_ROLES}
                if surface == "amdgcn_assembly"
                else {}
            ),
        )
        self.preflight = self.directory / "preflight.json"
        self.preflight.write_text(json.dumps(report), encoding="utf-8")
        with self._environment():
            result = controller.initialize_run(
                state=self.state,
                run_dir=self.run_dir,
                original_id="K0",
                contract_path=self.contract,
                preflight_path=self.preflight,
                environment_manifest_path=self.environment,
                timeout_seconds=1,
            )
        self.assertEqual(
            result["record_policy"],
            "controller-v2" if mode == "source" else "controller-v1",
        )
        self.initialized = result
        self.log.write_text("", encoding="utf-8")

    def _evaluate(
        self, candidate_id: str = "c001", max_output_bytes: int = 8 * 1024 * 1024
    ) -> dict:
        proposal = self.directory / f"{candidate_id}.proposal"
        proposal.write_text(f"proposal for {candidate_id}\n", encoding="utf-8")
        with self._environment():
            return controller.evaluate_candidate(
                state=self.state,
                run_dir=self.run_dir,
                candidate_id=candidate_id,
                proposal_path=proposal,
                edit_summary="hide VMEM latency",
                changed_windows=[".text+0x40:.text+0x78"],
                timeout_seconds=0.5,
                max_output_bytes=max_output_bytes,
            )

    def _operations(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines()

    def _evaluate_asm(self, candidate_id: str = "asm001") -> dict:
        source = self.directory / f"{candidate_id}.s"
        source.write_text("s_nop 0\n", encoding="utf-8")
        profile = self.run_dir / "attempts" / "baseline-K0" / "baseline-profile.json"
        state = json.loads(self.state.read_text(encoding="utf-8"))
        proposal = self.directory / f"{candidate_id}.json"
        proposal.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "optimization_surface": "amdgcn_assembly",
                    "parent_sha256": state["nodes"]["K0"]["artifact_sha256"],
                    "profile_evidence_sha256": hashlib.sha256(
                        profile.read_bytes()
                    ).hexdigest(),
                    "kernel_symbol": "test_kernel",
                    "bottleneck_class": "long_latency_memory",
                    "edited_windows": [{"start_pc": "0x40", "end_pc": "0x78"}],
                    "hypothesis": "move an independent load earlier",
                    "expected_observation": "lower dependency stalls",
                    "hazards": ["VGPR pressure", "waitcnt correctness"],
                    "source_path": source.name,
                }
            ),
            encoding="utf-8",
        )
        with self._environment():
            return controller.evaluate_candidate(
                state=self.state,
                run_dir=self.run_dir,
                candidate_id=candidate_id,
                proposal_path=proposal,
                profile_evidence_path=profile,
                edit_summary="move one load in the profiled window",
                changed_windows=[],
                timeout_seconds=1,
            )

    def test_amdgcn_assembly_runs_real_v2_phase_chain(self) -> None:
        self._prepare(surface="amdgcn_assembly")
        baseline = self.run_dir / "attempts" / "baseline-K0"
        self.assertEqual(
            self.initialized["baseline_profile"],
            str((baseline / "baseline-profile.json").resolve()),
        )
        self.assertEqual(
            [
                path.name.split("-", 1)[1]
                for path in sorted(baseline.iterdir())
                if path.is_dir() and path.name[:2].isdigit()
            ],
            [
                "disassemble",
                "static_check",
                "native_load",
                "oracle",
                "benchmark",
                "profile",
            ],
        )

        result = self._evaluate_asm()

        self.assertTrue(result["accepted"])
        self.assertEqual(
            result["candidate_profile"],
            str(
                (
                    self.run_dir / "attempts" / "asm001" / "candidate-profile.json"
                ).resolve()
            ),
        )
        self.assertEqual(
            self._operations(),
            [
                "build",
                "disassemble",
                "static_check",
                "native_load",
                "oracle",
                "benchmark",
                "profile",
            ],
        )
        summary = lineage.summary(self.state)
        self.assertEqual(summary["record_policy"], "controller-v2")
        self.assertEqual(summary["best_id"], "asm001")

    def test_amdgcn_assembly_rejects_precompiled_variant(self) -> None:
        self._prepare(surface="amdgcn_assembly")
        self.log.write_text("", encoding="utf-8")
        self._set_control({"precompiled_variant": True})

        with self.assertRaisesRegex(controller.ControllerError, "precompiled_variant"):
            self._evaluate_asm()

        self.assertEqual(self._operations(), ["build"])
        self.assertEqual(lineage.summary(self.state)["best_id"], "K0")

    def test_amdgcn_assembly_profiles_only_after_performance_qualifies(self) -> None:
        self._prepare(surface="amdgcn_assembly")
        self.log.write_text("", encoding="utf-8")
        self._set_control({"candidate_ms": [1.0] * 5})

        result = self._evaluate_asm()

        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "insufficient_speedup")
        self.assertEqual(
            self._operations(),
            [
                "build",
                "disassemble",
                "static_check",
                "native_load",
                "oracle",
                "benchmark",
            ],
        )

    def test_amdgcn_assembly_profile_failure_blocks_promotion(self) -> None:
        self._prepare(surface="amdgcn_assembly")
        self.log.write_text("", encoding="utf-8")
        self._set_control({"fail_operation": "profile"})

        result = self._evaluate_asm()

        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "asm_provenance_invalid")
        self.assertEqual(self._operations()[-2:], ["benchmark", "profile"])
        self.assertEqual(lineage.summary(self.state)["best_id"], "K0")

    def test_amdgcn_assembly_proposal_snapshot_tampering_breaks_lineage(self) -> None:
        self._prepare(surface="amdgcn_assembly")
        self.log.write_text("", encoding="utf-8")
        self._evaluate_asm()
        proposal = self.run_dir / "attempts" / "asm001" / "proposal.snapshot"
        proposal.chmod(0o600)
        proposal.write_text('{"forged":true}\n', encoding="utf-8")

        with self.assertRaisesRegex(lineage.LineageError, "proposal snapshot changed"):
            lineage.summary(self.state)

    def test_source_happy_path_mints_receipt_before_benchmark(self) -> None:
        self._prepare()

        result = self._evaluate()

        self.assertTrue(result["accepted"])
        self.assertEqual(self._operations(), ["build", "oracle", "benchmark"])
        attempt = self.run_dir / "attempts" / "c001"
        receipt = json.loads(
            (attempt / "correctness-receipt.json").read_text(encoding="utf-8")
        )
        benchmark_request = json.loads(
            (attempt / "03-benchmark" / "request.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            benchmark_request["binding"]["correctness_receipt_sha256"],
            lineage._document_digest(receipt),
        )
        summary = lineage.summary(self.state)
        self.assertEqual(summary["best_id"], "c001")
        self.assertEqual(summary["best_verification"], "controller-bound")

    def test_divergence_never_invokes_benchmark(self) -> None:
        self._prepare()
        self._set_control({"diverge_candidate": True})

        result = self._evaluate()

        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "divergent")
        self.assertEqual(self._operations(), ["build", "oracle"])
        self.assertFalse(
            (self.run_dir / "attempts" / "c001" / "correctness-receipt.json").exists()
        )

    def test_binary_static_failure_stops_before_oracle_and_benchmark(self) -> None:
        self._prepare(mode="binary")
        self._set_control({"fail_operation": "static_check"})

        result = self._evaluate()

        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "static_invalid")
        self.assertEqual(self._operations(), ["rebuild", "static_check"])

    def test_binary_rebuild_failure_is_recorded_without_traceback(self) -> None:
        self._prepare(mode="binary")
        self._set_control({"fail_operation": "rebuild"})

        result = self._evaluate()

        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "build_invalid")
        self.assertEqual(result["decision"]["status"], "build_invalid")
        self.assertEqual(self._operations(), ["rebuild"])

    def test_binary_oracle_always_receives_k0_and_replay_receives_candidate(
        self,
    ) -> None:
        self._prepare(mode="binary")
        baseline = self.run_dir / "attempts" / "baseline-K0"
        baseline_oracle = json.loads(
            (baseline / "05-oracle" / "request.json").read_text(encoding="utf-8")
        )
        baseline_replay = json.loads(
            (baseline / "06-replay" / "request.json").read_text(encoding="utf-8")
        )
        original_hash = hashlib.sha256(self.original.read_bytes()).hexdigest()
        self.assertEqual(
            baseline_oracle["inputs"]["oracle_artifact"]["sha256"], original_hash
        )
        self.assertNotEqual(
            baseline_replay["inputs"]["candidate_artifact"]["sha256"], original_hash
        )

        result = self._evaluate()

        self.assertTrue(result["accepted"])
        attempt = self.run_dir / "attempts" / "c001"
        oracle = json.loads(
            (attempt / "03-oracle" / "request.json").read_text(encoding="utf-8")
        )
        replay = json.loads(
            (attempt / "04-replay" / "request.json").read_text(encoding="utf-8")
        )
        self.assertEqual(oracle["inputs"]["oracle_artifact"]["sha256"], original_hash)
        self.assertEqual(
            replay["inputs"]["candidate_artifact"]["sha256"],
            replay["binding"]["candidate_sha256"],
        )
        self.assertNotEqual(
            replay["inputs"]["candidate_artifact"]["sha256"], original_hash
        )

    def test_stale_response_binding_fails_closed_before_benchmark(self) -> None:
        self._prepare()
        self._set_control({"wrong_binding_operation": "oracle"})

        with self.assertRaisesRegex(controller.ControllerError, "response binding"):
            self._evaluate()

        self.assertEqual(self._operations(), ["build", "oracle"])

    def test_timeout_kills_correctness_phase_and_blocks_benchmark(self) -> None:
        self._prepare()
        self._set_control({"sleep_operation": "oracle", "sleep_seconds": 1})

        result = self._evaluate()

        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "runtime_failure")
        self.assertEqual(self._operations(), ["build", "oracle"])

    def test_adapter_may_close_streams_before_clean_exit(self) -> None:
        self._prepare()
        self._set_control({"close_streams_operation": "oracle", "cleanup_seconds": 0.2})

        result = self._evaluate()

        self.assertTrue(result["accepted"])
        oracle = json.loads(
            (
                self.run_dir / "attempts" / "c001" / "02-oracle" / "stdout.json"
            ).read_text(encoding="utf-8")
        )
        self.assertTrue(oracle["ok"])

    def test_output_limit_kills_adapter_before_benchmark(self) -> None:
        self._prepare()
        self._set_control({"spam_operation": "oracle", "spam_bytes": 1024 * 1024})

        result = self._evaluate(max_output_bytes=1024)

        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "runtime_failure")
        self.assertEqual(self._operations(), ["build", "oracle"])
        stdout = self.run_dir / "attempts" / "c001" / "02-oracle" / "stdout.json"
        self.assertLessEqual(stdout.stat().st_size, 1024)

    def test_nonfinite_timeout_is_rejected_before_attempt_creation(self) -> None:
        self._prepare()
        proposal = self.directory / "nan.proposal"
        proposal.write_text("proposal", encoding="utf-8")

        with self.assertRaisesRegex(controller.ControllerError, "positive and finite"):
            controller.evaluate_candidate(
                state=self.state,
                run_dir=self.run_dir,
                candidate_id="nan-timeout",
                proposal_path=proposal,
                edit_summary="invalid timeout",
                changed_windows=[],
                timeout_seconds=float("nan"),
            )

        self.assertFalse((self.run_dir / "attempts" / "nan-timeout").exists())

    def test_candidate_mutation_during_benchmark_cannot_promote(self) -> None:
        self._prepare()
        self._set_control({"mutate_candidate_during_benchmark": True})

        with self.assertRaisesRegex(
            controller.ControllerError, "candidate artifact changed"
        ):
            self._evaluate()

        summary = lineage.summary(self.state)
        self.assertEqual(summary["best_id"], "K0")
        self.assertEqual(summary["attempts"], 0)

    def test_replaced_adapter_invalidates_frozen_preflight(self) -> None:
        self._prepare()
        self.adapter.write_text(FAKE_ADAPTER + "\n# changed\n", encoding="utf-8")

        with self.assertRaisesRegex(lineage.LineageError, "capability changed"):
            self._evaluate()

    def test_controller_lineage_rejects_direct_submitted_evidence(self) -> None:
        self._prepare()
        candidate = self.directory / "forged.hsaco"
        candidate.write_bytes(b"forged-candidate")
        candidate_hash = hashlib.sha256(candidate.read_bytes()).hexdigest()
        state = json.loads(self.state.read_text(encoding="utf-8"))
        document = json.loads(
            (ROOT / "asmevo" / "assets" / "evaluation-template.json").read_text(
                encoding="utf-8"
            )
        )
        document["contract"] = json.loads(self.contract.read_text(encoding="utf-8"))
        document["artifacts"]["original_sha256"] = state["nodes"]["K0"][
            "artifact_sha256"
        ]
        document["artifacts"]["parent_sha256"] = state["nodes"]["K0"]["artifact_sha256"]
        document["artifacts"]["candidate_sha256"] = candidate_hash
        document["proposal_sha256"] = candidate_hash
        forged = self.directory / "forged-evaluation.json"
        forged.write_text(json.dumps(document), encoding="utf-8")

        with self.assertRaisesRegex(lineage.LineageError, "controller-internal"):
            lineage.record(
                self.state,
                forged,
                candidate,
                "forge evidence",
                ["window"],
            )

    def test_public_lineage_init_cannot_claim_controller_baseline(self) -> None:
        self._prepare()
        receipt = self.run_dir / "attempts" / "baseline-K0" / "baseline-receipt.json"

        with self.assertRaisesRegex(lineage.LineageError, "controller-internal"):
            lineage.initialize(
                self.directory / "forged-lineage.json",
                "K0",
                self.original,
                1.0,
                self.contract,
                self.preflight,
                self.environment,
                receipt,
            )

    def test_raw_candidate_evidence_tampering_breaks_summary(self) -> None:
        self._prepare()
        self._evaluate()
        stdout = self.run_dir / "attempts" / "c001" / "03-benchmark" / "stdout.json"
        stdout.write_text('{"timing":"forged"}\n', encoding="utf-8")

        with self.assertRaisesRegex(lineage.LineageError, "stdout evidence changed"):
            lineage.summary(self.state)

    def test_evaluation_file_tampering_breaks_summary(self) -> None:
        self._prepare()
        self._evaluate()
        evaluation = self.run_dir / "attempts" / "c001" / "evaluation.json"
        evaluation.write_text('{"forged":true}\n', encoding="utf-8")

        with self.assertRaisesRegex(lineage.LineageError, "evaluation changed"):
            lineage.summary(self.state)

    def test_state_summary_and_node_corruption_is_detected(self) -> None:
        self._prepare()
        self._evaluate()
        original = json.loads(self.state.read_text(encoding="utf-8"))

        attempt_corruption = copy.deepcopy(original)
        attempt_corruption["attempts"][0]["accepted"] = False
        self.state.write_text(json.dumps(attempt_corruption), encoding="utf-8")
        with self.assertRaisesRegex(lineage.LineageError, "summary is inconsistent"):
            lineage.summary(self.state)

        node_corruption = copy.deepcopy(original)
        node_corruption["nodes"]["c001"]["speedup_over_original"] = 999.0
        self.state.write_text(json.dumps(node_corruption), encoding="utf-8")
        with self.assertRaisesRegex(lineage.LineageError, "node c001 is inconsistent"):
            lineage.summary(self.state)

    def test_attempt_history_cannot_place_child_before_parent(self) -> None:
        self._prepare()
        self._evaluate("c001")
        self._evaluate("c002")
        state = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(state["attempts"][1]["parent_id"], "c001")
        state["attempts"].reverse()
        self.state.write_text(json.dumps(state), encoding="utf-8")

        with self.assertRaisesRegex(
            lineage.LineageError, "parent was not yet verified"
        ):
            lineage.summary(self.state)

    def test_binary_observation_tampering_breaks_summary(self) -> None:
        self._prepare(mode="binary")
        self._evaluate()
        observations = (
            self.run_dir / "attempts" / "c001" / "candidate-observations.json"
        )
        observations.write_text('{"observations":"forged"}\n', encoding="utf-8")

        with self.assertRaisesRegex(lineage.LineageError, "output changed"):
            lineage.summary(self.state)

    def test_binary_compare_cannot_mutate_observations(self) -> None:
        self._prepare(mode="binary")
        self._set_control({"mutate_observation_during_compare": True})

        with self.assertRaisesRegex(controller.ControllerError, "changed after"):
            self._evaluate()

        self.assertNotIn("benchmark", self._operations())
        self.assertEqual(lineage.summary(self.state)["best_id"], "K0")

    def test_decision_file_failure_does_not_hide_committed_result(self) -> None:
        self._prepare()
        write_json = controller._atomic_write_json

        def fail_decision(path: Path, document: dict) -> None:
            if path.name == "decision.json":
                raise OSError("injected disk error")
            write_json(path, document)

        with mock.patch.object(
            controller, "_atomic_write_json", side_effect=fail_decision
        ):
            result = self._evaluate()

        self.assertTrue(result["accepted"])
        self.assertIsNone(result["decision_path"])
        self.assertIn("lineage commit succeeded", result["warning"])
        self.assertEqual(lineage.summary(self.state)["best_id"], "c001")

    def test_duplicate_artifact_has_one_consistent_final_decision(self) -> None:
        self._prepare()
        self._set_control({"fixed_candidate_bytes": True})
        first = self._evaluate("c001")
        second = self._evaluate("c002")

        self.assertTrue(first["accepted"])
        self.assertFalse(second["accepted"])
        self.assertEqual(second["status"], "duplicate")
        self.assertFalse(second["decision"]["accepted"])
        self.assertEqual(second["decision"]["status"], "duplicate")
        self.assertTrue(second["decision"]["gate_accepted"])
        self.assertEqual(second["decision"]["gate_status"], "accepted")
        decision_file = json.loads(
            (self.run_dir / "attempts" / "c002" / "decision.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(decision_file, second["decision"])
        state = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(state["attempts"][-1]["decision"], second["decision"])
        self.assertFalse(state["attempts"][-1]["accepted"])
        self.assertEqual(state["best_id"], "c001")
        self.assertEqual(lineage.summary(self.state)["best_id"], "c001")

    def test_unsafe_candidate_id_is_rejected_without_creating_attempt(self) -> None:
        self._prepare()
        proposal = self.directory / "proposal"
        proposal.write_text("proposal", encoding="utf-8")

        with self.assertRaises(controller.ControllerError), self._environment():
            controller.evaluate_candidate(
                state=self.state,
                run_dir=self.run_dir,
                candidate_id="../../escape",
                proposal_path=proposal,
                edit_summary="unsafe path",
                changed_windows=[],
            )

        self.assertFalse((self.directory / "escape").exists())

    def test_reserved_artifact_name_is_rejected_before_attempt_creation(self) -> None:
        self._prepare()
        proposal = self.directory / "reserved.proposal"
        proposal.write_text("proposal", encoding="utf-8")

        with self.assertRaisesRegex(controller.ControllerError, "reserved"):
            controller.evaluate_candidate(
                state=self.state,
                run_dir=self.run_dir,
                candidate_id="reserved-name",
                proposal_path=proposal,
                artifact_name="decision.json",
                edit_summary="must fail before evaluation",
                changed_windows=[],
            )

        self.assertFalse((self.run_dir / "attempts" / "reserved-name").exists())
        self.assertEqual(lineage.summary(self.state)["best_id"], "K0")

    def test_attempts_symlink_cannot_escape_run_directory(self) -> None:
        run_dir = self.directory / "symlink-run"
        outside = self.directory / "outside"
        run_dir.mkdir()
        outside.mkdir()
        (run_dir / "attempts").symlink_to(outside, target_is_directory=True)

        with self.assertRaisesRegex(controller.ControllerError, "real directory"):
            controller._new_attempt_directory(run_dir, "c001")

        self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
