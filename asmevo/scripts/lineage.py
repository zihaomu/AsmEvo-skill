#!/usr/bin/env python3
"""Maintain a locked, verified-candidate lineage for an AsmEvo run."""

from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import json
import math
import os
import stat
import statistics
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import gate
import preflight


class LineageError(ValueError):
    pass


_CONTROLLER_TOKEN = object()


def _reject_constant(value: str) -> None:
    raise LineageError(f"non-finite JSON number is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise LineageError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _document_digest(document: dict[str, Any]) -> str:
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _duplicate_decision(gate_decision: dict[str, Any], reason: str) -> dict[str, Any]:
    decision = copy.deepcopy(gate_decision)
    decision["gate_accepted"] = gate_decision.get("accepted")
    decision["gate_status"] = gate_decision.get("status")
    decision["gate_reasons"] = copy.deepcopy(gate_decision.get("reasons", []))
    decision["accepted"] = False
    decision["status"] = "duplicate"
    decision["reasons"] = [reason]
    return decision


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (OSError, json.JSONDecodeError, LineageError) as error:
        raise LineageError(f"cannot load {label}: {error}") from error
    if not isinstance(document, dict):
        raise LineageError(f"{label} root must be an object")
    return document


def _load(path: Path) -> dict[str, Any]:
    document = _load_json_object(path, "lineage")
    if document.get("schema_version") != 1:
        raise LineageError("unsupported lineage schema")
    if not isinstance(document.get("nodes"), dict) or not isinstance(
        document.get("attempts"), list
    ):
        raise LineageError("invalid lineage structure")
    if document.get("original_id") not in document["nodes"]:
        raise LineageError("lineage original node is missing")
    if document.get("best_id") not in document["nodes"]:
        raise LineageError("lineage best node is missing")
    return document


def _load_contract(path: Path) -> dict[str, Any]:
    contract = _load_json_object(path, "workload contract")
    try:
        gate.validate_contract(contract)
    except gate.GateInputError as error:
        raise LineageError(f"invalid workload contract: {error}") from error
    return contract


def _verify_contract(document: dict[str, Any]) -> dict[str, Any]:
    raw_path = document.get("contract_path")
    expected_hash = document.get("contract_sha256")
    if not isinstance(raw_path, str) or not isinstance(expected_hash, str):
        raise LineageError("lineage contract identity is incomplete")
    contract = _load_contract(Path(raw_path))
    if gate.contract_digest(contract) != expected_hash:
        raise LineageError("workload contract changed after lineage initialization")
    return contract


def _verify_environment(document: dict[str, Any], contract: dict[str, Any]) -> None:
    raw_path = document.get("environment_manifest_path")
    expected_hash = document.get("environment_sha256")
    contract_values = gate.validate_contract(contract)
    if not isinstance(raw_path, str) or not isinstance(expected_hash, str):
        raise LineageError("lineage environment identity is incomplete")
    if expected_hash != contract_values["environment_sha256"]:
        raise LineageError("lineage environment identity does not match contract")
    path = Path(raw_path)
    if not path.is_file():
        raise LineageError(f"environment manifest is missing: {path}")
    if _sha256(path) != expected_hash:
        raise LineageError("environment manifest changed after lineage initialization")


def _validate_preflight(
    report: dict[str, Any], contract: dict[str, Any], original_sha256: str
) -> None:
    contract_values = gate.validate_contract(contract)
    expected_capabilities = (
        preflight.SOURCE_CAPABILITIES
        if contract_values["mode"] == "source"
        else preflight.BINARY_CAPABILITIES
    )
    if report.get("schema_version") != 1:
        raise LineageError("unsupported preflight schema")
    if report.get("ready") is not True or report.get("status") != "ready":
        raise LineageError("preflight report is not ready")
    if report.get("failures") != []:
        raise LineageError("ready preflight report contains failures")
    if report.get("mode") != contract_values["mode"]:
        raise LineageError("preflight mode does not match workload contract")
    if report.get("target_arch") != contract_values["target_arch"]:
        raise LineageError(
            "preflight target architecture does not match workload contract"
        )
    artifact = report.get("artifact")
    if not isinstance(artifact, dict) or artifact.get("sha256") != original_sha256:
        raise LineageError("preflight artifact does not match original artifact")
    gpu = report.get("gpu")
    if not isinstance(gpu, dict) or gpu.get("target_arch_verified") is not True:
        raise LineageError("preflight did not verify the target GPU architecture")
    detected_architectures = gpu.get("detected_architectures")
    if (
        not isinstance(detected_architectures, list)
        or not all(isinstance(arch, str) for arch in detected_architectures)
        or contract_values["target_arch"] not in detected_architectures
    ):
        raise LineageError("preflight target architecture evidence is incomplete")
    required = report.get("required_capabilities")
    if (
        not isinstance(required, list)
        or not all(isinstance(name, str) for name in required)
        or set(required) != expected_capabilities
    ):
        raise LineageError("preflight required capability set is incomplete")
    capabilities = report.get("capabilities")
    if not isinstance(capabilities, dict) or any(
        not isinstance(capabilities.get(name), dict)
        or not capabilities[name].get("resolved")
        or not capabilities[name].get("sha256")
        for name in expected_capabilities
    ):
        raise LineageError("preflight has unresolved required capabilities")
    for name in expected_capabilities:
        capability = capabilities[name]
        executable = Path(str(capability["resolved"]))
        try:
            executable_metadata = executable.lstat()
        except OSError as error:
            raise LineageError(
                f"preflight capability is unavailable: {name}: {error}"
            ) from error
        if (
            stat.S_ISLNK(executable_metadata.st_mode)
            or not stat.S_ISREG(executable_metadata.st_mode)
            or not os.access(executable, os.X_OK)
        ):
            raise LineageError(f"preflight capability is no longer executable: {name}")
        if _sha256(executable) != capability["sha256"]:
            raise LineageError(f"preflight capability changed after inspection: {name}")


def _load_and_validate_preflight(
    path: Path, contract: dict[str, Any], original_sha256: str
) -> dict[str, Any]:
    report = _load_json_object(path, "preflight report")
    _validate_preflight(report, contract, original_sha256)
    return report


def _verify_preflight(document: dict[str, Any], contract: dict[str, Any]) -> None:
    raw_path = document.get("preflight_path")
    expected_hash = document.get("preflight_sha256")
    if not isinstance(raw_path, str) or not isinstance(expected_hash, str):
        raise LineageError("lineage preflight identity is incomplete")
    original_node = document["nodes"][document["original_id"]]
    report = _load_and_validate_preflight(
        Path(raw_path), contract, str(original_node.get("artifact_sha256"))
    )
    if _document_digest(report) != expected_hash:
        raise LineageError("preflight report changed after lineage initialization")


def _verify_node_artifact(node: dict[str, Any], label: str) -> None:
    raw_path = node.get("artifact_path")
    expected_hash = node.get("artifact_sha256")
    if not isinstance(raw_path, str) or not isinstance(expected_hash, str):
        raise LineageError(f"{label} artifact identity is incomplete")
    path = Path(raw_path)
    if not path.is_file():
        raise LineageError(f"{label} artifact is missing: {path}")
    if _sha256(path) != expected_hash:
        raise LineageError(f"{label} artifact changed after verification")


def _validate_phase_evidence(
    records: Any,
    *,
    preflight_report: dict[str, Any],
    expected_operations: list[str],
    require_all_success: bool,
) -> list[dict[str, Any]]:
    if not isinstance(records, list) or len(records) != len(expected_operations):
        raise LineageError(
            "controller phase evidence does not match the required chain"
        )
    capabilities = preflight_report.get("capabilities")
    if not isinstance(capabilities, dict):
        raise LineageError("controller preflight capability map is missing")
    parsed: list[dict[str, Any]] = []
    for index, (raw_record, operation) in enumerate(
        zip(records, expected_operations, strict=True)
    ):
        if not isinstance(raw_record, dict) or raw_record.get("operation") != operation:
            raise LineageError(f"controller phase {index} is not {operation}")
        capability = capabilities.get(operation)
        if not isinstance(capability, dict):
            raise LineageError(f"controller phase uses an unknown adapter: {operation}")
        adapter_path = raw_record.get("adapter_path")
        adapter_sha256 = raw_record.get("adapter_sha256")
        if (
            adapter_path != capability.get("resolved")
            or adapter_sha256 != capability.get("sha256")
            or not isinstance(adapter_path, str)
        ):
            raise LineageError(
                f"controller phase adapter binding is invalid: {operation}"
            )
        adapter = Path(adapter_path)
        if not adapter.is_file() or _sha256(adapter) != adapter_sha256:
            raise LineageError(f"controller phase adapter changed: {operation}")

        loaded_files: dict[str, Path] = {}
        for role in ("request", "stdout", "stderr"):
            raw_path = raw_record.get(f"{role}_path")
            expected_hash = raw_record.get(f"{role}_sha256")
            if not isinstance(raw_path, str) or not isinstance(expected_hash, str):
                raise LineageError(f"controller {operation} {role} evidence is missing")
            path = Path(raw_path)
            if not path.is_file() or _sha256(path) != expected_hash:
                raise LineageError(f"controller {operation} {role} evidence changed")
            loaded_files[role] = path

        request = _load_json_object(loaded_files["request"], f"{operation} request")
        request_id = raw_record.get("request_id")
        if (
            request.get("schema_version") != 1
            or request.get("protocol") != "asmevo.adapter.v1"
            or request.get("operation") != operation
            or request.get("request_id") != request_id
            or not isinstance(request.get("binding"), dict)
        ):
            raise LineageError(f"controller {operation} request binding is invalid")

        record_ok = raw_record.get("ok")
        if not isinstance(record_ok, bool):
            raise LineageError(f"controller {operation} evidence has no verdict")
        if require_all_success and not record_ok:
            raise LineageError(f"controller baseline phase failed: {operation}")
        if index < len(expected_operations) - 1 and not record_ok:
            raise LineageError(
                f"controller continued after a failed phase: {operation}"
            )

        response: dict[str, Any] | None = None
        try:
            response = _load_json_object(
                loaded_files["stdout"], f"{operation} response"
            )
        except LineageError:
            if record_ok:
                raise
        if response is not None:
            if (
                response.get("schema_version") != 1
                or response.get("protocol") != "asmevo.adapter.v1"
                or response.get("operation") != operation
                or response.get("request_id") != request_id
                or response.get("binding") != request.get("binding")
                or not isinstance(response.get("ok"), bool)
            ):
                raise LineageError(
                    f"controller {operation} response binding is invalid"
                )
            if record_ok != (response.get("ok") is True):
                raise LineageError(
                    f"controller {operation} response disagrees with phase evidence"
                )
        if record_ok and raw_record.get("return_code") != 0:
            raise LineageError(f"controller {operation} success has a non-zero exit")
        output_identity: dict[str, Any] | None = None
        if record_ok and isinstance(response, dict):
            output_name: str | None = None
            response_hash_name: str | None = None
            if operation in {"build", "rebuild"}:
                output_name = "candidate_artifact"
                response_hash_name = "candidate_sha256"
            elif operation == "recover":
                output_name = "recovered"
                response_hash_name = "output_sha256"
            elif (
                operation in {"oracle", "replay"}
                and isinstance(request.get("outputs"), dict)
                and "observations" in request["outputs"]
            ):
                output_name = "observations"
                response_hash_name = "output_sha256"
            if output_name is not None and response_hash_name is not None:
                outputs = request.get("outputs")
                raw_attempt = request.get("attempt_directory")
                raw_output = (
                    outputs.get(output_name) if isinstance(outputs, dict) else None
                )
                expected_output_hash = response.get(response_hash_name)
                if (
                    not isinstance(raw_attempt, str)
                    or not isinstance(raw_output, str)
                    or not isinstance(expected_output_hash, str)
                ):
                    raise LineageError(
                        f"controller {operation} output identity is incomplete"
                    )
                output_path = Path(raw_output)
                try:
                    output_metadata = output_path.lstat()
                except OSError as error:
                    raise LineageError(
                        f"controller {operation} output is unavailable: {error}"
                    ) from error
                if stat.S_ISLNK(output_metadata.st_mode) or not stat.S_ISREG(
                    output_metadata.st_mode
                ):
                    raise LineageError(
                        f"controller {operation} output is not a regular file"
                    )
                resolved_output = output_path.resolve()
                if not resolved_output.is_relative_to(Path(raw_attempt).resolve()):
                    raise LineageError(
                        f"controller {operation} output escaped its attempt directory"
                    )
                actual_output_hash = _sha256(resolved_output)
                if actual_output_hash != expected_output_hash:
                    raise LineageError(
                        f"controller {operation} output changed after validation"
                    )
                output_identity = {
                    "path": str(resolved_output),
                    "sha256": actual_output_hash,
                    "size_bytes": output_metadata.st_size,
                }
        parsed.append(
            {
                "record": raw_record,
                "request": request,
                "response": response,
                "output_identity": output_identity,
            }
        )
    return parsed


def _validate_common_bindings(
    parsed_phases: list[dict[str, Any]], expected: dict[str, Any]
) -> None:
    for phase in parsed_phases:
        binding = phase["request"]["binding"]
        for key, value in expected.items():
            if binding.get(key) != value:
                raise LineageError(
                    f"controller {phase['request']['operation']} request has stale {key}"
                )


def _validate_benchmark_authorization(
    phase: dict[str, Any],
    *,
    receipt: dict[str, Any],
    receipt_sha256: str,
    measure_artifacts: dict[str, Any],
) -> None:
    request = phase["request"]
    if request["binding"].get("correctness_receipt_sha256") != receipt_sha256:
        raise LineageError("controller benchmark was not authorized by the receipt")
    inputs = request.get("inputs")
    if (
        not isinstance(inputs, dict)
        or inputs.get("measure_artifacts") != measure_artifacts
    ):
        raise LineageError("controller benchmark received stale artifact identities")
    receipt_identity = inputs.get("correctness_receipt")
    if not isinstance(receipt_identity, dict) or set(receipt_identity) != {
        "path",
        "sha256",
    }:
        raise LineageError("controller benchmark receipt input is incomplete")
    raw_path = receipt_identity.get("path")
    if (
        not isinstance(raw_path, str)
        or receipt_identity.get("sha256") != receipt_sha256
    ):
        raise LineageError("controller benchmark receipt input has a stale identity")
    path = Path(raw_path)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise LineageError(
            f"controller benchmark receipt is unavailable: {error}"
        ) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise LineageError("controller benchmark receipt is not a regular file")
    attempt_directory = request.get("attempt_directory")
    if not isinstance(attempt_directory, str) or not path.resolve().is_relative_to(
        Path(attempt_directory).resolve()
    ):
        raise LineageError("controller benchmark receipt escaped its attempt directory")
    standalone = _load_json_object(path, "controller correctness receipt")
    if standalone != receipt or _document_digest(standalone) != receipt_sha256:
        raise LineageError("controller benchmark receipt file changed")


def _validate_baseline_receipt(
    receipt: dict[str, Any],
    *,
    original_id: str,
    original_sha256: str,
    contract: dict[str, Any],
    environment_sha256: str,
    preflight_sha256: str,
    baseline_median_ms: float,
    preflight_report: dict[str, Any],
) -> None:
    if (
        receipt.get("schema_version") != 1
        or receipt.get("kind") != "asmevo.baseline-receipt.v1"
        or receipt.get("status") != "verified"
    ):
        raise LineageError("invalid controller baseline receipt")
    bindings = receipt.get("bindings")
    if not isinstance(bindings, dict):
        raise LineageError("baseline receipt bindings are missing")
    contract_values = gate.validate_contract(contract)
    expected = {
        "original_id": original_id,
        "mode": contract_values["mode"],
        "target_arch": contract_values["target_arch"],
        "contract_sha256": gate.contract_digest(contract),
        "environment_sha256": environment_sha256,
        "preflight_sha256": preflight_sha256,
        "original_sha256": original_sha256,
        "case_ids": contract_values["case_ids"],
    }
    if bindings != expected:
        raise LineageError("baseline receipt does not match frozen run identities")
    correctness = receipt.get("correctness_receipt")
    correctness_hash = receipt.get("correctness_receipt_sha256")
    if not isinstance(correctness, dict) or not isinstance(correctness_hash, str):
        raise LineageError("baseline correctness receipt is missing")
    if _document_digest(correctness) != correctness_hash:
        raise LineageError("baseline correctness receipt hash does not match")
    if (
        correctness.get("schema_version") != 1
        or correctness.get("kind") != "asmevo.correctness-receipt.v1"
        or correctness.get("status") != "correctness_passed"
    ):
        raise LineageError("baseline correctness receipt did not pass")
    correctness_bindings = correctness.get("bindings")
    checks = correctness.get("checks")
    equivalence = correctness.get("equivalence")
    if (
        not isinstance(correctness_bindings, dict)
        or not isinstance(checks, dict)
        or not isinstance(equivalence, dict)
    ):
        raise LineageError("baseline correctness receipt is incomplete")
    expected_correctness = {
        "parent_id": original_id,
        "original_id": original_id,
        "mode": contract_values["mode"],
        "target_arch": contract_values["target_arch"],
        "contract_sha256": gate.contract_digest(contract),
        "environment_sha256": environment_sha256,
        "preflight_sha256": preflight_sha256,
        "proposal_sha256": original_sha256,
        "original_sha256": original_sha256,
        "parent_sha256": original_sha256,
        "case_ids": contract_values["case_ids"],
    }
    if any(
        correctness_bindings.get(key) != value
        for key, value in expected_correctness.items()
    ):
        raise LineageError("baseline correctness receipt has stale bindings")
    candidate_id = correctness_bindings.get("candidate_id")
    candidate_sha256 = correctness_bindings.get("candidate_sha256")
    if not isinstance(candidate_id, str) or not isinstance(candidate_sha256, str):
        raise LineageError("baseline correctness candidate identity is missing")
    expected_correctness.update(
        {"candidate_id": candidate_id, "candidate_sha256": candidate_sha256}
    )
    if correctness_bindings != expected_correctness:
        raise LineageError("baseline correctness receipt has unexpected bindings")
    probe = {
        "schema_version": 1,
        "candidate_id": candidate_id,
        "parent_id": original_id,
        "original_id": original_id,
        "mode": contract_values["mode"],
        "proposal_sha256": original_sha256,
        "contract": contract,
        "artifacts": {
            "original_sha256": original_sha256,
            "parent_sha256": original_sha256,
            "candidate_sha256": candidate_sha256,
        },
        "checks": checks,
        "equivalence": equivalence,
        "timing": {"valid": False, "invalid_reason": "baseline receipt probe"},
    }
    try:
        correctness_decision = gate.evaluate(probe)
    except gate.GateInputError as error:
        raise LineageError(f"invalid baseline correctness receipt: {error}") from error
    if correctness_decision.get("status") != "timing_invalid":
        raise LineageError("baseline correctness receipt does not pass the gate")

    expected_operations = (
        ["oracle", "benchmark"]
        if contract_values["mode"] == "source"
        else [
            "recover",
            "rebuild",
            "roundtrip",
            "static_check",
            "oracle",
            "replay",
            "compare",
            "benchmark",
        ]
    )
    phase_evidence = receipt.get("phase_evidence")
    parsed = _validate_phase_evidence(
        phase_evidence,
        preflight_report=preflight_report,
        expected_operations=expected_operations,
        require_all_success=True,
    )
    if correctness.get("phase_evidence") != phase_evidence[:-1]:
        raise LineageError("baseline correctness receipt has a spliced phase chain")
    common_binding = {
        "mode": contract_values["mode"],
        "target_arch": contract_values["target_arch"],
        "parent_id": original_id,
        "original_id": original_id,
        "contract_sha256": gate.contract_digest(contract),
        "environment_sha256": environment_sha256,
        "preflight_sha256": preflight_sha256,
        "original_sha256": original_sha256,
        "parent_sha256": original_sha256,
        "proposal_sha256": original_sha256,
        "case_ids": contract_values["case_ids"],
    }
    _validate_common_bindings(parsed, common_binding)
    if contract_values["mode"] == "source":
        oracle_candidate = (
            parsed[0]["request"].get("inputs", {}).get("candidate_artifact")
        )
        if (
            not isinstance(oracle_candidate, dict)
            or oracle_candidate.get("sha256") != original_sha256
        ):
            raise LineageError("source baseline oracle did not receive K0")
    else:
        if parsed[1]["request"].get("inputs", {}).get("recovered") != parsed[0].get(
            "output_identity"
        ):
            raise LineageError("binary rebuild did not consume recovered output")
        rebuilt_identity = parsed[1].get("output_identity")
        for phase_index in (2, 3):
            if (
                parsed[phase_index]["request"]
                .get("inputs", {})
                .get("candidate_artifact")
                != rebuilt_identity
            ):
                raise LineageError(
                    "binary round-trip check did not consume rebuilt bytes"
                )
        oracle_artifact = parsed[4]["request"].get("inputs", {}).get("oracle_artifact")
        replay_candidate = (
            parsed[5]["request"].get("inputs", {}).get("candidate_artifact")
        )
        if (
            not isinstance(oracle_artifact, dict)
            or oracle_artifact.get("sha256") != original_sha256
        ):
            raise LineageError("binary baseline oracle did not receive K0")
        if (
            not isinstance(replay_candidate, dict)
            or replay_candidate.get("sha256") != candidate_sha256
        ):
            raise LineageError("binary round-trip replay did not receive rebuilt bytes")
        compare_inputs = parsed[6]["request"].get("inputs", {})
        if compare_inputs.get("oracle") != parsed[4].get(
            "output_identity"
        ) or compare_inputs.get("candidate") != parsed[5].get("output_identity"):
            raise LineageError(
                "binary baseline compare did not consume frozen observations"
            )
    compare_index = 0 if contract_values["mode"] == "source" else 6
    compare_response = parsed[compare_index]["response"]
    if (
        not isinstance(compare_response, dict)
        or compare_response.get("equivalence") != equivalence
    ):
        raise LineageError("baseline adapter response does not bind equivalence")
    benchmark_response = parsed[-1]["response"]
    original_identity = preflight_report.get("artifact")
    if not isinstance(original_identity, dict):
        raise LineageError("baseline preflight artifact identity is missing")
    _validate_benchmark_authorization(
        parsed[-1],
        receipt=correctness,
        receipt_sha256=correctness_hash,
        measure_artifacts={"original": original_identity},
    )
    if not isinstance(benchmark_response, dict):
        raise LineageError("baseline benchmark response is missing")

    timing = receipt.get("timing")
    if not isinstance(timing, dict):
        raise LineageError("baseline timing evidence is missing")
    samples = timing.get("samples_ms")
    if (
        not isinstance(samples, list)
        or len(samples) < contract_values["minimum_samples"]
    ):
        raise LineageError("baseline receipt requires raw timing samples")
    normalized: list[float] = []
    for sample in samples:
        if isinstance(sample, bool) or not isinstance(sample, (int, float)):
            raise LineageError("baseline timing samples must be numeric")
        value = float(sample)
        if not math.isfinite(value) or value <= 0:
            raise LineageError("baseline timing samples must be positive and finite")
        normalized.append(value)
    if benchmark_response.get("samples_ms") != samples:
        raise LineageError("baseline receipt samples do not match benchmark stdout")
    recorded_median = timing.get("median_ms")
    actual_median = statistics.median(normalized)
    actual_cv = statistics.pstdev(normalized) / statistics.fmean(normalized)
    recorded_cv = timing.get("cv")
    if (
        isinstance(recorded_median, bool)
        or not isinstance(recorded_median, (int, float))
        or not math.isclose(float(recorded_median), actual_median)
        or not math.isclose(baseline_median_ms, actual_median)
        or isinstance(recorded_cv, bool)
        or not isinstance(recorded_cv, (int, float))
        or not math.isclose(float(recorded_cv), actual_cv)
    ):
        raise LineageError("baseline summary does not match raw receipt samples")
    if actual_cv > contract_values["maximum_cv"]:
        raise LineageError("baseline receipt exceeds the frozen maximum CV")


def _verify_controller_baseline(
    document: dict[str, Any], contract: dict[str, Any]
) -> None:
    if document.get("record_policy", "legacy-v1") != "controller-v1":
        return
    raw_path = document.get("baseline_receipt_path")
    expected_hash = document.get("baseline_receipt_sha256")
    embedded = document.get("baseline_receipt")
    if (
        not isinstance(raw_path, str)
        or not isinstance(expected_hash, str)
        or not isinstance(embedded, dict)
    ):
        raise LineageError("controller baseline receipt identity is incomplete")
    receipt = _load_json_object(Path(raw_path), "controller baseline receipt")
    if receipt != embedded or _document_digest(receipt) != expected_hash:
        raise LineageError("controller baseline receipt changed after initialization")
    original = document["nodes"][document["original_id"]]
    if (
        original.get("candidate_id") != document["original_id"]
        or original.get("parent_id") is not None
        or original.get("status") != "verified"
        or original.get("proposal_sha256") != original.get("artifact_sha256")
        or original.get("speedup_over_original") != 1.0
        or original.get("verification_level") != "controller-bound"
    ):
        raise LineageError("controller baseline node is inconsistent")
    _validate_baseline_receipt(
        receipt,
        original_id=document["original_id"],
        original_sha256=original["artifact_sha256"],
        contract=contract,
        environment_sha256=document["environment_sha256"],
        preflight_sha256=document["preflight_sha256"],
        baseline_median_ms=float(original["median_ms"]),
        preflight_report=document["preflight"],
    )


def _validate_controller_provenance(
    lineage_document: dict[str, Any],
    evaluation: dict[str, Any],
    decision: dict[str, Any],
) -> str:
    try:
        expected_gate_decision = gate.evaluate(evaluation)
    except gate.GateInputError as error:
        raise LineageError(
            f"controller evaluation no longer passes the deterministic gate: {error}"
        ) from error
    if decision.get("status") == "duplicate":
        reasons = decision.get("reasons")
        if (
            not isinstance(reasons, list)
            or not reasons
            or not all(isinstance(reason, str) and reason for reason in reasons)
        ):
            raise LineageError("duplicate controller decision has no reason")
        expected_decision = _duplicate_decision(expected_gate_decision, reasons[0])
        if len(reasons) != 1 or decision != expected_decision:
            raise LineageError("duplicate controller decision is inconsistent")
    elif decision != expected_gate_decision:
        raise LineageError("controller decision does not match deterministic gate")

    provenance = evaluation.get("provenance")
    if not isinstance(provenance, dict):
        raise LineageError("controller lineage requires controller provenance")
    if (
        provenance.get("schema_version") != 1
        or provenance.get("producer") != "asmevo-controller"
        or provenance.get("record_policy") != "controller-v1"
    ):
        raise LineageError("unsupported controller provenance")
    status = str(expected_gate_decision.get("status"))
    mode = expected_gate_decision.get("mode")
    phase_evidence = provenance.get("phase_evidence")
    if not isinstance(phase_evidence, list) or not phase_evidence:
        raise LineageError("controller provenance has no adapter evidence")
    observed_operations = [
        record.get("operation") if isinstance(record, dict) else None
        for record in phase_evidence
    ]
    full_chain = (
        ["build", "oracle", "benchmark"]
        if mode == "source"
        else ["rebuild", "static_check", "oracle", "replay", "compare", "benchmark"]
    )
    prefix_rejections = {
        "build_invalid",
        "static_invalid",
        "runtime_failure",
        "canary_corruption",
        "divergent",
    }
    if status in prefix_rejections:
        if provenance.get("stage") != "correctness_rejected":
            raise LineageError("controller rejection has an invalid stage marker")
        if status == "build_invalid":
            allowed_chains = [full_chain[:1]]
        elif (status == "static_invalid" and mode == "binary") or mode == "source":
            allowed_chains = [full_chain[:2]]
        elif status in {"divergent", "canary_corruption"}:
            allowed_chains = [full_chain[:5]]
        else:
            allowed_chains = [full_chain[:length] for length in (3, 4, 5)]
        if observed_operations not in allowed_chains:
            raise LineageError("controller rejection has an impossible phase chain")
    else:
        if (
            provenance.get("stage") != "benchmarked"
            or observed_operations != full_chain
        ):
            raise LineageError("controller timing evidence has an invalid phase chain")

    parsed = _validate_phase_evidence(
        phase_evidence,
        preflight_report=lineage_document["preflight"],
        expected_operations=observed_operations,
        require_all_success=False,
    )
    artifacts = decision.get("artifacts")
    if not isinstance(artifacts, dict):
        raise LineageError("controller decision artifact identities are missing")
    common_binding = {
        "mode": mode,
        "target_arch": gate.validate_contract(evaluation["contract"])["target_arch"],
        "candidate_id": expected_gate_decision.get("candidate_id"),
        "parent_id": expected_gate_decision.get("parent_id"),
        "original_id": expected_gate_decision.get("original_id"),
        "contract_sha256": expected_gate_decision.get("contract_sha256"),
        "environment_sha256": lineage_document.get("environment_sha256"),
        "preflight_sha256": lineage_document.get("preflight_sha256"),
        "original_sha256": artifacts.get("original_sha256"),
        "parent_sha256": artifacts.get("parent_sha256"),
        "proposal_sha256": expected_gate_decision.get("proposal_sha256"),
        "case_ids": gate.validate_contract(evaluation["contract"])["case_ids"],
    }
    _validate_common_bindings(parsed, common_binding)
    for index, phase in enumerate(parsed):
        expected_candidate = None if index == 0 else artifacts.get("candidate_sha256")
        if phase["request"]["binding"].get("candidate_sha256") != expected_candidate:
            raise LineageError("controller request has a stale candidate artifact")
    if mode == "source" and len(parsed) >= 2:
        oracle_candidate = (
            parsed[1]["request"].get("inputs", {}).get("candidate_artifact")
        )
        if (
            not isinstance(oracle_candidate, dict)
            or oracle_candidate != parsed[0].get("output_identity")
            or oracle_candidate.get("sha256") != artifacts.get("candidate_sha256")
        ):
            raise LineageError("source oracle did not receive the candidate artifact")
    if mode == "binary" and len(parsed) >= 3:
        oracle_artifact = parsed[2]["request"].get("inputs", {}).get("oracle_artifact")
        original_node = lineage_document["nodes"][lineage_document["original_id"]]
        if (
            not isinstance(oracle_artifact, dict)
            or oracle_artifact.get("path") != original_node.get("artifact_path")
            or oracle_artifact.get("sha256") != original_node.get("artifact_sha256")
        ):
            raise LineageError("binary oracle did not receive frozen K0")
    if mode == "binary" and len(parsed) >= 4:
        replay_candidate = (
            parsed[3]["request"].get("inputs", {}).get("candidate_artifact")
        )
        if (
            not isinstance(replay_candidate, dict)
            or replay_candidate != parsed[0].get("output_identity")
            or replay_candidate.get("sha256") != artifacts.get("candidate_sha256")
        ):
            raise LineageError("binary replay did not receive the candidate artifact")
    if mode == "binary" and len(parsed) >= 5:
        compare_inputs = parsed[4]["request"].get("inputs", {})
        if compare_inputs.get("oracle") != parsed[2].get(
            "output_identity"
        ) or compare_inputs.get("candidate") != parsed[3].get("output_identity"):
            raise LineageError("binary compare did not consume frozen observations")
    checks = evaluation.get("checks")
    if (
        not isinstance(checks, dict)
        or checks.get("build", {}).get("evidence") != phase_evidence[0]
    ):
        raise LineageError("controller build check is not bound to raw evidence")
    if (
        mode == "binary"
        and len(phase_evidence) >= 2
        and checks.get("static_consistency", {}).get("evidence") != phase_evidence[1]
    ):
        raise LineageError("controller static check is not bound to raw evidence")
    build_response = parsed[0]["response"]
    if parsed[0]["record"].get("ok") is True and (
        not isinstance(build_response, dict)
        or build_response.get("candidate_sha256") != artifacts.get("candidate_sha256")
    ):
        raise LineageError("controller build response does not bind candidate bytes")

    if status in prefix_rejections:
        correctness_index = 1 if mode == "source" else 4
        if len(parsed) > correctness_index:
            correctness_response = parsed[correctness_index]["response"]
            if (
                parsed[correctness_index]["record"].get("ok") is True
                and isinstance(correctness_response, dict)
                and correctness_response.get("equivalence")
                != evaluation.get("equivalence")
            ):
                raise LineageError(
                    "controller correctness response does not bind equivalence"
                )
        return "controller-rejected"

    receipt = provenance.get("correctness_receipt")
    receipt_hash = provenance.get("correctness_receipt_sha256")
    if not isinstance(receipt, dict) or not isinstance(receipt_hash, str):
        raise LineageError("benchmarking requires a controller correctness receipt")
    if _document_digest(receipt) != receipt_hash:
        raise LineageError("controller correctness receipt hash does not match")
    if (
        receipt.get("schema_version") != 1
        or receipt.get("kind") != "asmevo.correctness-receipt.v1"
        or receipt.get("status") != "correctness_passed"
    ):
        raise LineageError("controller correctness receipt did not pass")
    if receipt.get("checks") != evaluation.get("checks") or receipt.get(
        "equivalence"
    ) != evaluation.get("equivalence"):
        raise LineageError("controller receipt does not bind the evaluated correctness")
    if receipt.get("phase_evidence") != phase_evidence[:-1]:
        raise LineageError("controller correctness receipt has a spliced phase chain")
    bindings = receipt.get("bindings")
    if not isinstance(bindings, dict) or not isinstance(artifacts, dict):
        raise LineageError("controller receipt artifact bindings are missing")
    contract_values = gate.validate_contract(evaluation["contract"])
    expected = {
        "candidate_id": expected_gate_decision.get("candidate_id"),
        "parent_id": expected_gate_decision.get("parent_id"),
        "original_id": expected_gate_decision.get("original_id"),
        "mode": expected_gate_decision.get("mode"),
        "target_arch": contract_values["target_arch"],
        "contract_sha256": expected_gate_decision.get("contract_sha256"),
        "environment_sha256": lineage_document.get("environment_sha256"),
        "preflight_sha256": lineage_document.get("preflight_sha256"),
        "proposal_sha256": expected_gate_decision.get("proposal_sha256"),
        "original_sha256": artifacts.get("original_sha256"),
        "parent_sha256": artifacts.get("parent_sha256"),
        "candidate_sha256": artifacts.get("candidate_sha256"),
        "case_ids": contract_values["case_ids"],
    }
    if bindings != expected:
        raise LineageError("controller receipt does not match the gated identities")
    correctness_index = 1 if mode == "source" else 4
    correctness_response = parsed[correctness_index]["response"]
    if mode == "binary":
        correctness_response = parsed[4]["response"]
        compare_response = parsed[4]["response"]
        if not isinstance(compare_response, dict):
            raise LineageError("controller compare response is missing")
        correctness_response = compare_response
    if not isinstance(correctness_response, dict) or correctness_response.get(
        "equivalence"
    ) != evaluation.get("equivalence"):
        raise LineageError("controller adapter stdout does not bind equivalence")
    benchmark_response = parsed[-1]["response"]
    original_node = lineage_document["nodes"][lineage_document["original_id"]]
    parent_node = lineage_document["nodes"].get(expected_gate_decision.get("parent_id"))
    candidate_identity = parsed[0].get("output_identity")
    if not isinstance(parent_node, dict) or not isinstance(candidate_identity, dict):
        raise LineageError("controller benchmark artifact identity is incomplete")
    _validate_benchmark_authorization(
        parsed[-1],
        receipt=receipt,
        receipt_sha256=receipt_hash,
        measure_artifacts={
            "original": {
                "path": original_node.get("artifact_path"),
                "sha256": original_node.get("artifact_sha256"),
            },
            "parent": {
                "path": parent_node.get("artifact_path"),
                "sha256": parent_node.get("artifact_sha256"),
            },
            "candidate": candidate_identity,
        },
    )
    if parsed[-1]["record"].get("ok") is True:
        if not isinstance(benchmark_response, dict) or benchmark_response.get(
            "timing"
        ) != evaluation.get("timing"):
            raise LineageError("controller benchmark stdout does not bind timing")
    elif evaluation.get("timing", {}).get("valid") is not False:
        raise LineageError("failed controller benchmark cannot provide valid timing")
    return "controller-bound"


def _verify_controller_attempts(document: dict[str, Any]) -> None:
    if document.get("record_policy", "legacy-v1") != "controller-v1":
        return
    original_id = document["original_id"]
    expected_nodes = {original_id}
    expected_best_id = original_id
    expected_best_speedup = 1.0
    for index, attempt in enumerate(document.get("attempts", [])):
        if not isinstance(attempt, dict):
            raise LineageError(f"controller attempt {index} is malformed")
        evaluation = attempt.get("evaluation")
        decision = attempt.get("decision")
        if not isinstance(evaluation, dict) or not isinstance(decision, dict):
            raise LineageError(f"controller attempt {index} evidence is incomplete")
        raw_evaluation_path = attempt.get("evaluation_path")
        if not isinstance(raw_evaluation_path, str):
            raise LineageError(f"controller attempt {index} evaluation path is missing")
        evaluation_path = Path(raw_evaluation_path)
        standalone_evaluation = _load_json_object(
            evaluation_path, f"controller attempt {index} evaluation"
        )
        evaluation_hash = _document_digest(evaluation)
        if (
            standalone_evaluation != evaluation
            or attempt.get("evaluation_sha256") != evaluation_hash
            or decision.get("evidence_sha256") != evaluation_hash
            or attempt.get("evidence_sha256") != evaluation_hash
        ):
            raise LineageError(f"controller attempt {index} evaluation changed")
        decision_hash = _document_digest(decision)
        if attempt.get("decision_sha256") != decision_hash:
            raise LineageError(f"controller attempt {index} decision changed")
        decision_path = evaluation_path.with_name("decision.json")
        if decision_path.exists() or decision_path.is_symlink():
            decision_metadata = decision_path.lstat()
            if stat.S_ISLNK(decision_metadata.st_mode) or not stat.S_ISREG(
                decision_metadata.st_mode
            ):
                raise LineageError(
                    f"controller attempt {index} decision file is not regular"
                )
            standalone_decision = _load_json_object(
                decision_path, f"controller attempt {index} decision"
            )
            if standalone_decision != decision:
                raise LineageError(f"controller attempt {index} decision file changed")

        verification_level = _validate_controller_provenance(
            document, evaluation, decision
        )
        candidate_id = decision.get("candidate_id")
        parent_id = decision.get("parent_id")
        artifacts = decision.get("artifacts")
        if (
            not isinstance(candidate_id, str)
            or not isinstance(parent_id, str)
            or not isinstance(artifacts, dict)
        ):
            raise LineageError(f"controller attempt {index} identities are incomplete")
        if parent_id not in expected_nodes:
            raise LineageError(
                f"controller attempt {index} parent was not yet verified"
            )
        accepted = decision.get("accepted") is True
        status = decision.get("status")
        if (
            attempt.get("candidate_id") != candidate_id
            or attempt.get("parent_id") != parent_id
            or attempt.get("accepted") is not accepted
            or attempt.get("status") != status
            or attempt.get("reasons") != decision.get("reasons")
            or attempt.get("proposal_sha256") != decision.get("proposal_sha256")
            or attempt.get("artifact_sha256") != artifacts.get("candidate_sha256")
            or attempt.get("verification_level") != verification_level
        ):
            raise LineageError(f"controller attempt {index} summary is inconsistent")

        provenance = evaluation.get("provenance")
        phases = (
            provenance.get("phase_evidence") if isinstance(provenance, dict) else None
        )
        if not isinstance(phases, list) or not phases:
            raise LineageError(f"controller attempt {index} phase chain is missing")
        first_request_path = phases[0].get("request_path")
        if not isinstance(first_request_path, str):
            raise LineageError(f"controller attempt {index} build request is missing")
        first_request = _load_json_object(
            Path(first_request_path), f"controller attempt {index} build request"
        )
        attempt_directory = first_request.get("attempt_directory")
        if (
            not isinstance(attempt_directory, str)
            or evaluation_path.parent.resolve() != Path(attempt_directory).resolve()
        ):
            raise LineageError(f"controller attempt {index} escaped its directory")
        build = evaluation.get("checks", {}).get("build", {})
        build_passed = isinstance(build, dict) and build.get("passed") is True
        expected_artifact_path: str | None = None
        if build_passed:
            outputs = first_request.get("outputs")
            raw_artifact_path = (
                outputs.get("candidate_artifact") if isinstance(outputs, dict) else None
            )
            if not isinstance(raw_artifact_path, str):
                raise LineageError(
                    f"controller attempt {index} candidate output is missing"
                )
            expected_artifact_path = str(Path(raw_artifact_path).resolve())
        if attempt.get("artifact_path") != expected_artifact_path:
            raise LineageError(
                f"controller attempt {index} artifact path is inconsistent"
            )

        if accepted:
            if candidate_id in expected_nodes:
                raise LineageError("accepted controller candidate ID is duplicated")
            node = document["nodes"].get(candidate_id)
            metrics = decision.get("metrics")
            candidate_metrics = (
                metrics.get("candidate") if isinstance(metrics, dict) else None
            )
            speedup = (
                metrics.get("candidate_speedup_over_original")
                if isinstance(metrics, dict)
                else None
            )
            median = (
                candidate_metrics.get("median_ms")
                if isinstance(candidate_metrics, dict)
                else None
            )
            if (
                not isinstance(node, dict)
                or isinstance(speedup, bool)
                or not isinstance(speedup, (int, float))
                or isinstance(median, bool)
                or not isinstance(median, (int, float))
                or node.get("candidate_id") != candidate_id
                or node.get("parent_id") != parent_id
                or node.get("status") != "verified"
                or node.get("artifact_path") != attempt.get("artifact_path")
                or node.get("artifact_sha256") != attempt.get("artifact_sha256")
                or node.get("proposal_sha256") != attempt.get("proposal_sha256")
                or node.get("median_ms") != float(median)
                or node.get("speedup_over_original") != float(speedup)
                or node.get("edit_summary") != attempt.get("edit_summary")
                or node.get("changed_windows") != attempt.get("changed_windows")
                or node.get("verification_level") != verification_level
                or node.get("evaluation_sha256") != evaluation_hash
                or node.get("evidence_sha256") != evaluation_hash
                or node.get("decision_sha256") != decision_hash
            ):
                raise LineageError(
                    f"controller accepted node {candidate_id} is inconsistent"
                )
            expected_nodes.add(candidate_id)
            if float(speedup) > expected_best_speedup:
                expected_best_id = candidate_id
                expected_best_speedup = float(speedup)
        elif candidate_id in document["nodes"] and candidate_id != original_id:
            raise LineageError("rejected controller attempt became a verified node")

    if set(document["nodes"]) != expected_nodes:
        raise LineageError("controller lineage has nodes without accepted attempts")
    if document.get("best_id") != expected_best_id:
        raise LineageError("controller lineage best node is inconsistent")


@contextmanager
def _state_lock(path: Path, *, exclusive: bool) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f"{path.name}.lock")
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _atomic_write(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
            json.dump(document, destination, indent=2, sort_keys=True)
            destination.write("\n")
            destination.flush()
            os.fsync(destination.fileno())
        temporary.replace(path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def initialize(
    state: Path,
    original_id: str,
    artifact: Path,
    baseline_median_ms: float,
    contract_path: Path,
    preflight_path: Path,
    environment_manifest_path: Path,
    baseline_receipt_path: Path | None = None,
    *,
    _controller_token: object | None = None,
) -> dict[str, Any]:
    state = state.resolve()
    with _state_lock(state, exclusive=True):
        if state.exists():
            raise LineageError(f"lineage already exists: {state}")
        if not original_id.strip():
            raise LineageError("original ID must not be empty")
        if not artifact.is_file():
            raise LineageError(f"original artifact not found: {artifact}")
        if not math.isfinite(baseline_median_ms) or baseline_median_ms <= 0:
            raise LineageError("baseline median must be positive and finite")
        resolved_contract = contract_path.resolve()
        contract = _load_contract(resolved_contract)
        contract_values = gate.validate_contract(contract)
        resolved_environment = environment_manifest_path.resolve()
        if not resolved_environment.is_file():
            raise LineageError(
                f"environment manifest not found: {resolved_environment}"
            )
        environment_sha256 = _sha256(resolved_environment)
        if environment_sha256 != contract_values["environment_sha256"]:
            raise LineageError("environment manifest does not match workload contract")
        artifact_path = artifact.resolve()
        artifact_sha256 = _sha256(artifact_path)
        resolved_preflight = preflight_path.resolve()
        preflight_report = _load_and_validate_preflight(
            resolved_preflight, contract, artifact_sha256
        )
        preflight_sha256 = _document_digest(preflight_report)
        baseline_receipt: dict[str, Any] | None = None
        baseline_receipt_sha256: str | None = None
        record_policy = "legacy-v1"
        if baseline_receipt_path is not None:
            if _controller_token is not _CONTROLLER_TOKEN:
                raise LineageError(
                    "controller-v1 baseline requires the controller-internal call "
                    "token; the public lineage API is legacy"
                )
            resolved_receipt = baseline_receipt_path.resolve()
            baseline_receipt = _load_json_object(
                resolved_receipt, "controller baseline receipt"
            )
            _validate_baseline_receipt(
                baseline_receipt,
                original_id=original_id,
                original_sha256=artifact_sha256,
                contract=contract,
                environment_sha256=environment_sha256,
                preflight_sha256=preflight_sha256,
                baseline_median_ms=baseline_median_ms,
                preflight_report=preflight_report,
            )
            baseline_receipt_sha256 = _document_digest(baseline_receipt)
            record_policy = "controller-v1"
        document = {
            "schema_version": 1,
            "record_policy": record_policy,
            "original_id": original_id,
            "best_id": original_id,
            "contract_path": str(resolved_contract),
            "contract_sha256": gate.contract_digest(contract),
            "environment_manifest_path": str(resolved_environment),
            "environment_sha256": environment_sha256,
            "preflight_path": str(resolved_preflight),
            "preflight_sha256": preflight_sha256,
            "preflight": preflight_report,
            "baseline_receipt_path": (
                str(baseline_receipt_path.resolve())
                if baseline_receipt_path is not None
                else None
            ),
            "baseline_receipt_sha256": baseline_receipt_sha256,
            "baseline_receipt": baseline_receipt,
            "created_at": _now(),
            "nodes": {
                original_id: {
                    "candidate_id": original_id,
                    "parent_id": None,
                    "status": "verified",
                    "artifact_path": str(artifact_path),
                    "artifact_sha256": artifact_sha256,
                    "proposal_sha256": artifact_sha256,
                    "median_ms": baseline_median_ms,
                    "speedup_over_original": 1.0,
                    "edit_summary": "frozen original baseline",
                    "changed_windows": [],
                    "verification_level": (
                        "controller-bound" if baseline_receipt is not None else "legacy"
                    ),
                    "recorded_at": _now(),
                }
            },
            "attempts": [],
        }
        _atomic_write(state, document)
        return document


def _record_locked(
    state: Path,
    evaluation_path: Path,
    artifact: Path | None,
    edit_summary: str,
    changed_windows: list[str],
) -> dict[str, Any]:
    document = _load(state)
    contract = _verify_contract(document)
    _verify_environment(document, contract)
    _verify_preflight(document, contract)
    _verify_controller_baseline(document, contract)
    _verify_controller_attempts(document)
    evaluation = _load_json_object(evaluation_path, "evaluation")
    try:
        decision = gate.evaluate(evaluation)
    except gate.GateInputError as error:
        raise LineageError(f"evaluation failed deterministic gate: {error}") from error
    if decision.get("contract_sha256") != document.get("contract_sha256"):
        raise LineageError("evaluation contract does not match lineage")
    record_policy = document.get("record_policy", "legacy-v1")
    if record_policy == "controller-v1":
        verification_level = _validate_controller_provenance(
            document, evaluation, decision
        )
    elif record_policy == "legacy-v1":
        verification_level = "submitted-evidence"
    else:
        raise LineageError(f"unsupported lineage record policy: {record_policy}")

    candidate_id = decision.get("candidate_id")
    parent_id = decision.get("parent_id")
    if not isinstance(candidate_id, str) or not candidate_id:
        raise LineageError("decision candidate_id is missing")
    if not isinstance(parent_id, str) or parent_id not in document["nodes"]:
        raise LineageError("candidate parent is not a verified lineage node")
    if candidate_id in document["nodes"] or any(
        attempt.get("candidate_id") == candidate_id for attempt in document["attempts"]
    ):
        decision = _duplicate_decision(
            decision, "candidate ID already exists in the lineage"
        )
        return {
            "recorded": False,
            "accepted": False,
            "status": "duplicate",
            "best_id": document["best_id"],
            "decision": decision,
        }
    if decision.get("original_id") != document.get("original_id"):
        raise LineageError("decision original_id does not match lineage")
    if not edit_summary.strip():
        raise LineageError("edit summary must not be empty")
    if not all(
        isinstance(window, str) and window.strip() for window in changed_windows
    ):
        raise LineageError("changed windows must be non-empty strings")

    decision_artifacts = decision.get("artifacts")
    if not isinstance(decision_artifacts, dict):
        raise LineageError("decision artifact identities are missing")
    original_node = document["nodes"][document["original_id"]]
    parent_node = document["nodes"][parent_id]
    _verify_node_artifact(original_node, "original")
    if parent_id != document["original_id"]:
        _verify_node_artifact(parent_node, "parent")
    if decision_artifacts.get("original_sha256") != original_node.get(
        "artifact_sha256"
    ):
        raise LineageError("decision original artifact does not match lineage")
    if decision_artifacts.get("parent_sha256") != parent_node.get("artifact_sha256"):
        raise LineageError("decision parent artifact does not match lineage")

    artifact_path: str | None = None
    artifact_hash: str | None = None
    build = evaluation.get("checks", {}).get("build", {})
    build_passed = isinstance(build, dict) and build.get("passed") is True
    if build_passed and artifact is None:
        raise LineageError("successful builds require the candidate artifact")
    if artifact is not None:
        if not artifact.is_file():
            raise LineageError(f"candidate artifact not found: {artifact}")
        resolved = artifact.resolve()
        artifact_path = str(resolved)
        artifact_hash = _sha256(resolved)
        if decision_artifacts.get("candidate_sha256") != artifact_hash:
            raise LineageError("recorded artifact does not match gated candidate")
    if decision.get("accepted") is True and artifact_hash is None:
        raise LineageError("accepted candidates require an artifact")

    effective_status = str(decision.get("status", "input_invalid"))
    accepted = decision.get("accepted") is True
    if accepted != (effective_status == "accepted"):
        raise LineageError("gate returned inconsistent accepted flag and status")
    proposal_hash = decision.get("proposal_sha256")
    proposed_artifact_hash = decision_artifacts.get("candidate_sha256")
    proposal_seen = any(
        node.get("proposal_sha256") == proposal_hash
        for node in document["nodes"].values()
    ) or any(
        attempt.get("proposal_sha256") == proposal_hash
        for attempt in document["attempts"]
    )
    artifact_seen = proposed_artifact_hash is not None and (
        any(
            node.get("artifact_sha256") == proposed_artifact_hash
            for node in document["nodes"].values()
        )
        or any(
            attempt.get("artifact_sha256") == proposed_artifact_hash
            for attempt in document["attempts"]
        )
    )
    if proposal_seen or artifact_seen:
        effective_status = "duplicate"
        accepted = False
        if proposal_seen and artifact_seen:
            duplicate_reason = "proposal and candidate artifact were already evaluated"
        elif proposal_seen:
            duplicate_reason = "proposal was already evaluated"
        else:
            duplicate_reason = "candidate artifact was already evaluated"
        decision = _duplicate_decision(decision, duplicate_reason)

    metrics = decision.get("metrics")
    if accepted and (
        not isinstance(metrics, dict) or not isinstance(metrics.get("candidate"), dict)
    ):
        raise LineageError("accepted decision is missing timing metrics")

    evaluation_hash = _document_digest(evaluation)
    decision_hash = _document_digest(decision)
    attempt = {
        "candidate_id": candidate_id,
        "parent_id": parent_id,
        "accepted": accepted,
        "status": effective_status,
        "reasons": decision.get("reasons", []),
        "artifact_path": artifact_path,
        "artifact_sha256": artifact_hash,
        "proposal_sha256": proposal_hash,
        "evaluation_path": str(evaluation_path.resolve()),
        "evaluation_sha256": evaluation_hash,
        "evidence_sha256": decision.get("evidence_sha256"),
        "evaluation": evaluation,
        "decision_sha256": decision_hash,
        "decision": decision,
        "edit_summary": edit_summary,
        "changed_windows": changed_windows,
        "verification_level": verification_level,
        "recorded_at": _now(),
    }
    document["attempts"].append(attempt)

    if accepted:
        speedup = metrics.get("candidate_speedup_over_original")
        median = metrics["candidate"].get("median_ms")
        if (
            isinstance(speedup, bool)
            or not isinstance(speedup, (int, float))
            or not math.isfinite(float(speedup))
            or isinstance(median, bool)
            or not isinstance(median, (int, float))
            or not math.isfinite(float(median))
        ):
            raise LineageError("accepted decision has invalid timing metrics")
        document["nodes"][candidate_id] = {
            "candidate_id": candidate_id,
            "parent_id": parent_id,
            "status": "verified",
            "artifact_path": artifact_path,
            "artifact_sha256": artifact_hash,
            "proposal_sha256": proposal_hash,
            "median_ms": float(median),
            "speedup_over_original": float(speedup),
            "edit_summary": edit_summary,
            "changed_windows": changed_windows,
            "verification_level": verification_level,
            "evaluation_sha256": evaluation_hash,
            "evidence_sha256": decision.get("evidence_sha256"),
            "decision_sha256": decision_hash,
            "recorded_at": _now(),
        }
        best = document["nodes"][document["best_id"]]
        if float(speedup) > float(best["speedup_over_original"]):
            document["best_id"] = candidate_id

    _atomic_write(state, document)
    return {
        "recorded": True,
        "accepted": accepted,
        "status": effective_status,
        "best_id": document["best_id"],
        "decision": decision,
    }


def record(
    state: Path,
    evaluation_path: Path,
    artifact: Path | None,
    edit_summary: str,
    changed_windows: list[str],
    *,
    _controller_token: object | None = None,
) -> dict[str, Any]:
    state = state.resolve()
    with _state_lock(state, exclusive=True):
        document = _load(state)
        if (
            document.get("record_policy") == "controller-v1"
            and _controller_token is not _CONTROLLER_TOKEN
        ):
            raise LineageError(
                "controller-v1 lineage requires the controller-internal call token; "
                "the public lineage API is legacy"
            )
        return _record_locked(
            state, evaluation_path, artifact, edit_summary, changed_windows
        )


def summary(state: Path) -> dict[str, Any]:
    state = state.resolve()
    with _state_lock(state, exclusive=False):
        document = _load(state)
        contract = _verify_contract(document)
        _verify_environment(document, contract)
        _verify_preflight(document, contract)
        _verify_controller_baseline(document, contract)
        _verify_controller_attempts(document)
        for candidate_id, node in document["nodes"].items():
            _verify_node_artifact(node, f"verified node {candidate_id}")
        best = document["nodes"][document["best_id"]]
        return {
            "original_id": document["original_id"],
            "best_id": document["best_id"],
            "contract_sha256": document["contract_sha256"],
            "environment_sha256": document["environment_sha256"],
            "preflight_sha256": document["preflight_sha256"],
            "record_policy": document.get("record_policy", "legacy-v1"),
            "baseline_verification": best.get("verification_level")
            if document["best_id"] == document["original_id"]
            else document["nodes"][document["original_id"]].get(
                "verification_level", "legacy"
            ),
            "best_verification": best.get("verification_level", "legacy"),
            "best_speedup_over_original": best["speedup_over_original"],
            "verified_nodes": len(document["nodes"]),
            "attempts": len(document["attempts"]),
            "rejected_attempts": sum(
                1 for attempt in document["attempts"] if not attempt["accepted"]
            ),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--state", type=Path, required=True)
    init_parser.add_argument("--original-id", required=True)
    init_parser.add_argument("--original-artifact", type=Path, required=True)
    init_parser.add_argument("--baseline-median-ms", type=float, required=True)
    init_parser.add_argument("--contract", type=Path, required=True)
    init_parser.add_argument("--preflight", type=Path, required=True)
    init_parser.add_argument("--environment-manifest", type=Path, required=True)

    record_parser = subparsers.add_parser("record")
    record_parser.add_argument("--state", type=Path, required=True)
    record_parser.add_argument("--evaluation", type=Path, required=True)
    record_parser.add_argument("--artifact", type=Path)
    record_parser.add_argument("--edit-summary", required=True)
    record_parser.add_argument("--changed-window", action="append", default=[])

    summary_parser = subparsers.add_parser("summary")
    summary_parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()

    try:
        if args.command == "init":
            result = initialize(
                args.state,
                args.original_id,
                args.original_artifact,
                args.baseline_median_ms,
                args.contract,
                args.preflight,
                args.environment_manifest,
            )
            output = {
                "initialized": True,
                "best_id": result["best_id"],
                "contract_sha256": result["contract_sha256"],
                "environment_sha256": result["environment_sha256"],
                "preflight_sha256": result["preflight_sha256"],
                "state": str(args.state.resolve()),
            }
        elif args.command == "record":
            output = record(
                args.state,
                args.evaluation,
                args.artifact,
                args.edit_summary,
                args.changed_window,
            )
        else:
            output = summary(args.state)
    except (OSError, LineageError) as error:
        print(json.dumps({"status": "error", "error": str(error)}))
        return 2

    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
