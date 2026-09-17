#!/usr/bin/env python3
"""Deterministically decide whether an AsmEvo candidate may be promoted."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Any


class GateInputError(ValueError):
    """Raised when evaluation evidence is incomplete or malformed."""


def _reject_constant(value: str) -> None:
    raise GateInputError(f"non-finite JSON number is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise GateInputError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GateInputError(f"{name} must be an object")
    return value


def _nonempty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GateInputError(f"{name} must be a non-empty string")
    return value.strip()


def _sha256_string(value: Any, name: str) -> str:
    result = _nonempty_string(value, name).lower()
    if len(result) != 64 or any(
        character not in "0123456789abcdef" for character in result
    ):
        raise GateInputError(f"{name} must be a 64-character hexadecimal SHA-256")
    return result


def _number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GateInputError(f"{name} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise GateInputError(f"{name} must be finite")
    return result


def _positive_samples(value: Any, name: str, minimum: int) -> list[float]:
    if not isinstance(value, list):
        raise GateInputError(f"{name} must be an array")
    if len(value) < minimum:
        raise GateInputError(f"{name} requires at least {minimum} samples")
    samples = [_number(item, f"{name}[{index}]") for index, item in enumerate(value)]
    if any(item <= 0 for item in samples):
        raise GateInputError(f"{name} samples must be positive")
    return samples


def _summary(samples: list[float]) -> dict[str, float | int]:
    mean = statistics.fmean(samples)
    return {
        "median_ms": statistics.median(samples),
        "mean_ms": mean,
        "cv": statistics.pstdev(samples) / mean,
        "sample_count": len(samples),
    }


def _digest(document: dict[str, Any]) -> str:
    try:
        canonical = json.dumps(
            document, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError) as error:
        raise GateInputError(f"evaluation is not canonical JSON: {error}") from error
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def contract_digest(contract: dict[str, Any]) -> str:
    """Return the canonical identity used to freeze a workload contract."""

    return _digest(contract)


def validate_contract(contract: dict[str, Any]) -> dict[str, Any]:
    """Validate a workload contract and return normalized gate parameters."""

    if contract.get("schema_version") != 1:
        raise GateInputError("contract.schema_version must be 1")
    mode = _nonempty_string(contract.get("mode"), "contract.mode")
    if mode not in {"source", "binary"}:
        raise GateInputError("contract.mode must be source or binary")
    target_arch = _nonempty_string(contract.get("target_arch"), "contract.target_arch")
    environment_sha256 = _sha256_string(
        contract.get("environment_sha256"), "contract.environment_sha256"
    )

    raw_case_ids = contract.get("case_ids")
    if not isinstance(raw_case_ids, list) or not raw_case_ids:
        raise GateInputError("contract.case_ids must be a non-empty array")
    case_ids = [
        _nonempty_string(value, f"contract.case_ids[{index}]")
        for index, value in enumerate(raw_case_ids)
    ]
    if len(case_ids) != len(set(case_ids)):
        raise GateInputError("contract.case_ids must be unique")

    equivalence = _mapping(
        contract.get("equivalence_policy"), "contract.equivalence_policy"
    )
    min_cosine = _number(
        equivalence.get("min_cosine_similarity"),
        "contract.equivalence_policy.min_cosine_similarity",
    )
    max_error = _number(
        equivalence.get("max_absolute_error"),
        "contract.equivalence_policy.max_absolute_error",
    )
    if not -1.0 <= min_cosine <= 1.0:
        raise GateInputError("min_cosine_similarity must be between -1 and 1")
    if max_error < 0:
        raise GateInputError("max_absolute_error must be non-negative")
    require_integer = equivalence.get("require_integer_exact", True)
    require_guards = equivalence.get("require_guards_intact", True)
    if not isinstance(require_integer, bool) or not isinstance(require_guards, bool):
        raise GateInputError("equivalence policy boolean values must be boolean")
    raw_exact_only = equivalence.get("exact_only_case_ids", [])
    if not isinstance(raw_exact_only, list) or not all(
        isinstance(case_id, str) and case_id.strip() for case_id in raw_exact_only
    ):
        raise GateInputError("exact_only_case_ids must be an array of case IDs")
    exact_only_case_ids = [case_id.strip() for case_id in raw_exact_only]
    if len(exact_only_case_ids) != len(set(exact_only_case_ids)):
        raise GateInputError("exact_only_case_ids must be unique")
    unknown_exact_only = sorted(set(exact_only_case_ids) - set(case_ids))
    if unknown_exact_only:
        raise GateInputError(
            "exact_only_case_ids are absent from contract.case_ids: "
            + ", ".join(unknown_exact_only)
        )

    performance = _mapping(
        contract.get("performance_policy"), "contract.performance_policy"
    )
    minimum_samples = performance.get("minimum_samples", 5)
    if isinstance(minimum_samples, bool) or not isinstance(minimum_samples, int):
        raise GateInputError(
            "contract.performance_policy.minimum_samples must be an integer"
        )
    if minimum_samples < 2:
        raise GateInputError("minimum_samples must be at least 2")
    minimum_improvement = _number(
        performance.get("minimum_relative_improvement", 0.002),
        "contract.performance_policy.minimum_relative_improvement",
    )
    cv_multiplier = _number(
        performance.get("cv_multiplier", 0.85),
        "contract.performance_policy.cv_multiplier",
    )
    maximum_cv = _number(
        performance.get("maximum_cv", 0.03),
        "contract.performance_policy.maximum_cv",
    )
    speedup_floor = _number(
        performance.get("speedup_floor", 1.0),
        "contract.performance_policy.speedup_floor",
    )
    if (
        minimum_improvement < 0
        or cv_multiplier < 0
        or maximum_cv < 0
        or speedup_floor <= 0
    ):
        raise GateInputError(
            "performance thresholds must be non-negative and speedup_floor positive"
        )

    return {
        "mode": mode,
        "target_arch": target_arch,
        "environment_sha256": environment_sha256,
        "case_ids": case_ids,
        "min_cosine_similarity": min_cosine,
        "max_absolute_error": max_error,
        "require_integer_exact": require_integer,
        "require_guards_intact": require_guards,
        "exact_only_case_ids": exact_only_case_ids,
        "minimum_samples": minimum_samples,
        "minimum_relative_improvement": minimum_improvement,
        "cv_multiplier": cv_multiplier,
        "maximum_cv": maximum_cv,
        "speedup_floor": speedup_floor,
    }


def _base_decision(
    document: dict[str, Any], contract: dict[str, Any]
) -> dict[str, Any]:
    artifacts = _mapping(document.get("artifacts"), "artifacts")
    candidate_artifact = artifacts.get("candidate_sha256")
    return {
        "schema_version": 1,
        "candidate_id": _nonempty_string(document.get("candidate_id"), "candidate_id"),
        "parent_id": _nonempty_string(document.get("parent_id"), "parent_id"),
        "original_id": _nonempty_string(document.get("original_id"), "original_id"),
        "mode": _nonempty_string(document.get("mode"), "mode"),
        "contract_sha256": contract_digest(contract),
        "proposal_sha256": _sha256_string(
            document.get("proposal_sha256"), "proposal_sha256"
        ),
        "artifacts": {
            "original_sha256": _sha256_string(
                artifacts.get("original_sha256"), "artifacts.original_sha256"
            ),
            "parent_sha256": _sha256_string(
                artifacts.get("parent_sha256"), "artifacts.parent_sha256"
            ),
            "candidate_sha256": (
                None
                if candidate_artifact is None
                else _sha256_string(candidate_artifact, "artifacts.candidate_sha256")
            ),
        },
        "accepted": False,
        "status": "input_invalid",
        "reasons": [],
        "metrics": {},
        "evidence_sha256": _digest(document),
    }


def evaluate(document: dict[str, Any]) -> dict[str, Any]:
    if document.get("schema_version") != 1:
        raise GateInputError("schema_version must be 1")

    contract = _mapping(document.get("contract"), "contract")
    contract_values = validate_contract(contract)
    decision = _base_decision(document, contract)
    if decision["mode"] != contract_values["mode"]:
        raise GateInputError("mode must match contract.mode")

    checks = _mapping(document.get("checks"), "checks")
    build = _mapping(checks.get("build"), "checks.build")
    if build.get("passed") is not True:
        decision["status"] = "build_invalid"
        decision["reasons"] = ["build or assembly validity check failed"]
        return decision
    if decision["artifacts"]["candidate_sha256"] is None:
        raise GateInputError(
            "artifacts.candidate_sha256 is required after a successful build"
        )

    static = _mapping(checks.get("static_consistency"), "checks.static_consistency")
    declared_static_required = static.get("required", False)
    if not isinstance(declared_static_required, bool):
        raise GateInputError("checks.static_consistency.required must be boolean")
    if decision["mode"] == "binary" and declared_static_required is not True:
        decision["status"] = "static_invalid"
        decision["reasons"] = [
            "binary mode requires an executed static consistency gate"
        ]
        return decision
    static_required = decision["mode"] == "binary" or declared_static_required
    if static_required and static.get("passed") is not True:
        decision["status"] = "static_invalid"
        decision["reasons"] = [
            "ABI, metadata, descriptor, or resource consistency failed"
        ]
        return decision

    equivalence = _mapping(document.get("equivalence"), "equivalence")
    cases = equivalence.get("cases")
    if not isinstance(cases, list) or not cases:
        raise GateInputError("equivalence.cases must be a non-empty array")

    divergence: list[str] = []
    guard_failures: list[str] = []
    runtime_failures: list[str] = []
    observed_case_ids: list[str] = []
    for index, raw_case in enumerate(cases):
        case = _mapping(raw_case, f"equivalence.cases[{index}]")
        case_id = _nonempty_string(
            case.get("case_id"), f"equivalence.cases[{index}].case_id"
        )
        observed_case_ids.append(case_id)
        if case.get("runtime_ok") is not True:
            runtime_failures.append(case_id)
            continue
        float_applicable = case.get("float_metrics_applicable", True)
        if not isinstance(float_applicable, bool):
            raise GateInputError(f"{case_id}.float_metrics_applicable must be boolean")
        expected_float_applicable = (
            case_id not in contract_values["exact_only_case_ids"]
        )
        if float_applicable != expected_float_applicable:
            raise GateInputError(
                f"{case_id}.float_metrics_applicable does not match the frozen "
                "exact_only_case_ids policy"
            )
        if float_applicable:
            cosine = _number(
                case.get("cosine_similarity"), f"{case_id}.cosine_similarity"
            )
            absolute_error = _number(
                case.get("max_absolute_error"), f"{case_id}.max_absolute_error"
            )
            if not -1.0 <= cosine <= 1.0:
                raise GateInputError(f"{case_id}.cosine_similarity must be in [-1, 1]")
            if absolute_error < 0:
                raise GateInputError(
                    f"{case_id}.max_absolute_error must be non-negative"
                )
            if cosine < contract_values["min_cosine_similarity"]:
                divergence.append(
                    f"{case_id}: cosine similarity {cosine} < "
                    f"{contract_values['min_cosine_similarity']}"
                )
            if absolute_error > contract_values["max_absolute_error"]:
                divergence.append(
                    f"{case_id}: max absolute error {absolute_error} > "
                    f"{contract_values['max_absolute_error']}"
                )
        if (
            contract_values["require_integer_exact"]
            and case.get("integer_exact") is not True
        ):
            divergence.append(f"{case_id}: integer or opaque state is not exact")
        if (
            contract_values["require_guards_intact"]
            and case.get("guards_intact") is not True
        ):
            guard_failures.append(case_id)

    if observed_case_ids != contract_values["case_ids"]:
        raise GateInputError(
            "equivalence case IDs and order must match contract.case_ids"
        )
    if runtime_failures:
        decision["status"] = "runtime_failure"
        decision["reasons"] = [
            f"runtime failed for cases: {', '.join(runtime_failures)}"
        ]
        return decision
    if guard_failures:
        decision["status"] = "canary_corruption"
        decision["reasons"] = [
            f"guard corruption for cases: {', '.join(guard_failures)}"
        ]
        return decision
    if divergence:
        decision["status"] = "divergent"
        decision["reasons"] = divergence
        return decision

    timing = _mapping(document.get("timing"), "timing")
    timing_valid = timing.get("valid", True)
    if not isinstance(timing_valid, bool):
        raise GateInputError("timing.valid must be boolean")
    if not timing_valid:
        reason = timing.get(
            "invalid_reason", "measurement harness rejected the timing run"
        )
        if not isinstance(reason, str) or not reason.strip():
            raise GateInputError("timing.invalid_reason must be a non-empty string")
        decision["status"] = "timing_invalid"
        decision["reasons"] = [reason]
        return decision

    minimum_samples = contract_values["minimum_samples"]
    original = _positive_samples(
        timing.get("original_ms"), "timing.original_ms", minimum_samples
    )
    parent = _positive_samples(
        timing.get("parent_ms"), "timing.parent_ms", minimum_samples
    )
    candidate = _positive_samples(
        timing.get("candidate_ms"), "timing.candidate_ms", minimum_samples
    )
    original_summary = _summary(original)
    parent_summary = _summary(parent)
    candidate_summary = _summary(candidate)

    observed_cv = max(
        float(original_summary["cv"]),
        float(parent_summary["cv"]),
        float(candidate_summary["cv"]),
    )
    parent_speedup = float(original_summary["median_ms"]) / float(
        parent_summary["median_ms"]
    )
    candidate_speedup = float(original_summary["median_ms"]) / float(
        candidate_summary["median_ms"]
    )
    margin = max(
        contract_values["minimum_relative_improvement"],
        contract_values["cv_multiplier"] * observed_cv,
    )
    required_speedup = max(
        (1.0 + margin) * parent_speedup,
        contract_values["speedup_floor"],
    )
    relative_to_parent = float(parent_summary["median_ms"]) / float(
        candidate_summary["median_ms"]
    )

    decision["metrics"] = {
        "original": original_summary,
        "parent": parent_summary,
        "candidate": candidate_summary,
        "observed_cv": observed_cv,
        "parent_speedup_over_original": parent_speedup,
        "candidate_speedup_over_original": candidate_speedup,
        "candidate_speedup_over_parent": relative_to_parent,
        "required_speedup_over_original": required_speedup,
        "applied_relative_margin": margin,
    }

    if observed_cv > contract_values["maximum_cv"]:
        decision["status"] = "timing_unstable"
        decision["reasons"] = [
            f"observed CV {observed_cv:.6f} exceeds {contract_values['maximum_cv']:.6f}"
        ]
        return decision
    if candidate_speedup < required_speedup:
        decision["status"] = "insufficient_speedup"
        decision["reasons"] = [
            (
                f"candidate speedup {candidate_speedup:.6f} is below required "
                f"{required_speedup:.6f}"
            )
        ]
        return decision

    decision["accepted"] = True
    decision["status"] = "accepted"
    decision["reasons"] = []
    return decision


def _write_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evaluation", type=Path, help="candidate evaluation JSON")
    parser.add_argument("--output", type=Path, help="optional decision JSON path")
    args = parser.parse_args()

    try:
        document = json.loads(
            args.evaluation.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        if not isinstance(document, dict):
            raise GateInputError("evaluation root must be an object")
        decision = evaluate(document)
    except (OSError, json.JSONDecodeError, GateInputError) as error:
        print(
            json.dumps(
                {"accepted": False, "status": "input_invalid", "error": str(error)}
            )
        )
        return 2

    if args.output:
        _write_json(args.output, decision)
    print(json.dumps(decision, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
