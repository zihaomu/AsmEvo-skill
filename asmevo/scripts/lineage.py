#!/usr/bin/env python3
"""Maintain a locked, verified-candidate lineage for an AsmEvo run."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
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


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
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
        for name in expected_capabilities
    ):
        raise LineageError("preflight has unresolved required capabilities")


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
) -> dict[str, Any]:
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
        document = {
            "schema_version": 1,
            "original_id": original_id,
            "best_id": original_id,
            "contract_path": str(resolved_contract),
            "contract_sha256": gate.contract_digest(contract),
            "environment_manifest_path": str(resolved_environment),
            "environment_sha256": environment_sha256,
            "preflight_path": str(resolved_preflight),
            "preflight_sha256": _document_digest(preflight_report),
            "preflight": preflight_report,
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
                    "edit_summary": "immutable original baseline",
                    "changed_windows": [],
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
    evaluation = _load_json_object(evaluation_path, "evaluation")
    try:
        decision = gate.evaluate(evaluation)
    except gate.GateInputError as error:
        raise LineageError(f"evaluation failed deterministic gate: {error}") from error
    if decision.get("contract_sha256") != document.get("contract_sha256"):
        raise LineageError("evaluation contract does not match lineage")

    candidate_id = decision.get("candidate_id")
    parent_id = decision.get("parent_id")
    if not isinstance(candidate_id, str) or not candidate_id:
        raise LineageError("decision candidate_id is missing")
    if not isinstance(parent_id, str) or parent_id not in document["nodes"]:
        raise LineageError("candidate parent is not a verified lineage node")
    if candidate_id in document["nodes"] or any(
        attempt.get("candidate_id") == candidate_id for attempt in document["attempts"]
    ):
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

    metrics = decision.get("metrics")
    if accepted and (
        not isinstance(metrics, dict) or not isinstance(metrics.get("candidate"), dict)
    ):
        raise LineageError("accepted decision is missing timing metrics")

    evaluation_hash = _sha256(evaluation_path.resolve())
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
) -> dict[str, Any]:
    with _state_lock(state, exclusive=True):
        return _record_locked(
            state, evaluation_path, artifact, edit_summary, changed_windows
        )


def summary(state: Path) -> dict[str, Any]:
    with _state_lock(state, exclusive=False):
        document = _load(state)
        contract = _verify_contract(document)
        _verify_environment(document, contract)
        _verify_preflight(document, contract)
        for candidate_id, node in document["nodes"].items():
            _verify_node_artifact(node, f"verified node {candidate_id}")
        best = document["nodes"][document["best_id"]]
        return {
            "original_id": document["original_id"],
            "best_id": document["best_id"],
            "contract_sha256": document["contract_sha256"],
            "environment_sha256": document["environment_sha256"],
            "preflight_sha256": document["preflight_sha256"],
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
