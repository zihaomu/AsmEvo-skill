"""Validation helpers for profile-bound AMDGCN source-assembly proposals."""

from __future__ import annotations

import math
import re
from typing import Any

from .common import V2_ASSEMBLY_CAPABILITIES, BackendContractError

REQUIRED_CAPABILITIES = frozenset(V2_ASSEMBLY_CAPABILITIES)
CODE_OBJECT_KINDS = {"elf_object", "code_object", "hsaco"}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PC = re.compile(r"0x[0-9a-fA-F]+\Z")


def _string(document: dict[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        raise BackendContractError(f"ASM proposal.{key} must be a non-empty string")
    return value.strip()


def _sha256(document: dict[str, Any], key: str) -> str:
    value = _string(document, key)
    if not SHA256.fullmatch(value):
        raise BackendContractError(f"ASM proposal.{key} must be a SHA-256")
    return value


def validate_proposal(
    document: dict[str, Any],
    *,
    parent_sha256: str,
    profile_evidence_sha256: str,
) -> dict[str, Any]:
    """Validate the model-authored hypothesis without accepting conclusions."""

    if document.get("schema_version") != 2:
        raise BackendContractError("ASM proposal.schema_version must be 2")
    if document.get("optimization_surface") != "amdgcn_assembly":
        raise BackendContractError(
            "ASM proposal.optimization_surface must be amdgcn_assembly"
        )
    if _sha256(document, "parent_sha256") != parent_sha256:
        raise BackendContractError("ASM proposal is not bound to the verified parent")
    if _sha256(document, "profile_evidence_sha256") != profile_evidence_sha256:
        raise BackendContractError("ASM proposal is not bound to profile evidence")

    windows = document.get("edited_windows")
    if not isinstance(windows, list) or not windows:
        raise BackendContractError("ASM proposal.edited_windows must not be empty")
    normalized_windows: list[dict[str, str]] = []
    for index, window in enumerate(windows):
        if not isinstance(window, dict):
            raise BackendContractError(
                f"ASM proposal.edited_windows[{index}] must be an object"
            )
        start_pc = window.get("start_pc")
        end_pc = window.get("end_pc")
        if (
            not isinstance(start_pc, str)
            or not isinstance(end_pc, str)
            or not PC.fullmatch(start_pc)
            or not PC.fullmatch(end_pc)
            or int(start_pc, 16) > int(end_pc, 16)
        ):
            raise BackendContractError(
                f"ASM proposal.edited_windows[{index}] has an invalid PC range"
            )
        normalized_windows.append(
            {"start_pc": start_pc.lower(), "end_pc": end_pc.lower()}
        )

    hazards = document.get("hazards")
    if not isinstance(hazards, list) or not all(
        isinstance(value, str) and value.strip() for value in hazards
    ):
        raise BackendContractError("ASM proposal.hazards must be an array of strings")

    return {
        "schema_version": 2,
        "optimization_surface": "amdgcn_assembly",
        "parent_sha256": parent_sha256,
        "profile_evidence_sha256": profile_evidence_sha256,
        "kernel_symbol": _string(document, "kernel_symbol"),
        "bottleneck_class": _string(document, "bottleneck_class"),
        "edited_windows": normalized_windows,
        "hypothesis": _string(document, "hypothesis"),
        "expected_observation": _string(document, "expected_observation"),
        "hazards": [value.strip() for value in hazards],
        "source_path": _string(document, "source_path"),
    }


def validate_build_claim(response: dict[str, Any]) -> dict[str, Any]:
    """Reject parameter manifests and precompiled entry selection as ASM builds."""

    compiled = response.get("compiled")
    precompiled = response.get("precompiled_variant")
    artifact_kind = response.get("artifact_kind")
    if compiled is not True:
        raise BackendContractError("ASM build response must declare compiled=true")
    if precompiled is not False:
        raise BackendContractError(
            "ASM build response must declare precompiled_variant=false"
        )
    if artifact_kind not in CODE_OBJECT_KINDS:
        raise BackendContractError(
            "ASM build artifact_kind must be elf_object, code_object, or hsaco"
        )
    return {
        "compiled": True,
        "precompiled_variant": False,
        "artifact_kind": artifact_kind,
    }


def validate_profile_evidence(
    document: dict[str, Any],
    *,
    artifact_sha256: str,
    target_arch: str,
    contract_sha256: str,
    environment_sha256: str,
) -> None:
    if document.get("schema_version") != 2:
        raise BackendContractError("profile evidence.schema_version must be 2")
    if document.get("kind") != "asmevo.profile-evidence.v2":
        raise BackendContractError("profile evidence.kind is not v2")
    if document.get("status") != "complete":
        raise BackendContractError("profile evidence must have status=complete")
    expected = {
        "artifact_sha256": artifact_sha256,
        "target_arch": target_arch,
        "contract_sha256": contract_sha256,
        "environment_sha256": environment_sha256,
    }
    for key, value in expected.items():
        if document.get(key) != value:
            raise BackendContractError(
                f"profile evidence {key} does not match the frozen parent"
            )
    if (
        not isinstance(document.get("kernel_symbol"), str)
        or not document["kernel_symbol"].strip()
    ):
        raise BackendContractError("profile evidence.kernel_symbol is missing")
    hotspots = document.get("hotspots")
    if not isinstance(hotspots, list) or not hotspots:
        raise BackendContractError("profile evidence.hotspots must not be empty")
    for index, hotspot in enumerate(hotspots):
        start_pc = hotspot.get("start_pc") if isinstance(hotspot, dict) else None
        end_pc = hotspot.get("end_pc") if isinstance(hotspot, dict) else None
        weight = hotspot.get("weight") if isinstance(hotspot, dict) else None
        if (
            not isinstance(start_pc, str)
            or not isinstance(end_pc, str)
            or not PC.fullmatch(start_pc)
            or not PC.fullmatch(end_pc)
            or int(start_pc, 16) > int(end_pc, 16)
            or isinstance(weight, bool)
            or not isinstance(weight, (int, float))
            or not math.isfinite(float(weight))
            or float(weight) <= 0
        ):
            raise BackendContractError(
                f"profile evidence.hotspots[{index}] is malformed"
            )
    dispatch_count = document.get("dispatch_count")
    sampled_time_ms = document.get("sampled_time_ms")
    if (
        isinstance(dispatch_count, bool)
        or not isinstance(dispatch_count, int)
        or dispatch_count <= 0
    ):
        raise BackendContractError("profile evidence.dispatch_count must be positive")
    if (
        isinstance(sampled_time_ms, bool)
        or not isinstance(sampled_time_ms, (int, float))
        or not math.isfinite(float(sampled_time_ms))
        or float(sampled_time_ms) <= 0
    ):
        raise BackendContractError("profile evidence.sampled_time_ms must be positive")
    if not isinstance(document.get("resources"), dict):
        raise BackendContractError("profile evidence.resources must be an object")
    profiler = document.get("profiler")
    if (
        not isinstance(profiler, dict)
        or not isinstance(profiler.get("path"), str)
        or not profiler["path"]
        or not isinstance(profiler.get("sha256"), str)
        or not SHA256.fullmatch(profiler["sha256"])
    ):
        raise BackendContractError("profile evidence.profiler identity is missing")
    raw_files = document.get("raw_files")
    if not isinstance(raw_files, list) or not raw_files:
        raise BackendContractError("profile evidence.raw_files must not be empty")
    for index, raw_file in enumerate(raw_files):
        if (
            not isinstance(raw_file, dict)
            or not isinstance(raw_file.get("relative_path"), str)
            or not raw_file["relative_path"]
            or not isinstance(raw_file.get("sha256"), str)
            or not SHA256.fullmatch(raw_file["sha256"])
            or isinstance(raw_file.get("size_bytes"), bool)
            or not isinstance(raw_file.get("size_bytes"), int)
            or raw_file["size_bytes"] < 0
        ):
            raise BackendContractError(
                f"profile evidence.raw_files[{index}] is malformed"
            )
    if not isinstance(document.get("counters", {}), dict) or not isinstance(
        document.get("unavailable_counters", []), list
    ):
        raise BackendContractError("profile evidence counters are malformed")
    bottleneck = document.get("bottleneck_class")
    if not isinstance(bottleneck, str) or not bottleneck.strip():
        raise BackendContractError("profile evidence.bottleneck_class is missing")


def asm_gate_check(
    *,
    build_claim: dict[str, Any],
    profile_evidence_sha256: str,
    instruction_diff_nonempty: bool,
    diff_within_declared_windows: bool,
    native_load_passed: bool,
) -> dict[str, Any]:
    claim = validate_build_claim(build_claim)
    if not SHA256.fullmatch(profile_evidence_sha256):
        raise BackendContractError("profile evidence identity must be a SHA-256")
    return {
        **claim,
        "profile_evidence_sha256": profile_evidence_sha256,
        "instruction_diff_nonempty": instruction_diff_nonempty,
        "diff_within_declared_windows": diff_within_declared_windows,
        "native_load_passed": native_load_passed,
    }
