"""Shared optimization-surface rules.

This module intentionally contains no project workload, launcher, or GPU-host
configuration.  It is the small vocabulary shared by preflight, the gate, and
backend-specific validators.
"""

from __future__ import annotations

import re
from typing import Any


class BackendContractError(ValueError):
    """Raised when a v2 backend contract is internally inconsistent."""


OPTIMIZATION_SURFACES = {
    "launch_config",
    "hip_source",
    "triton_source",
    "amdgcn_assembly",
    "hsaco_binary",
    "audit_only",
}
ASM_SURFACES = {"amdgcn_assembly", "hsaco_binary"}
MEASURED_SURFACES = OPTIMIZATION_SURFACES - {"audit_only"}
TARGET_ARCH = re.compile(r"gfx[0-9a-z]+\Z")

SURFACE_MODES = {
    "launch_config": "source",
    "hip_source": "source",
    "triton_source": "source",
    "amdgcn_assembly": "source",
    "hsaco_binary": "binary",
    "audit_only": "audit",
}

V2_SOURCE_CAPABILITIES = {"build", "oracle", "benchmark"}
V2_ASSEMBLY_CAPABILITIES = {
    "build",
    "disassemble",
    "static_check",
    "native_load",
    "oracle",
    "profile",
    "benchmark",
}
V2_BINARY_CAPABILITIES = {
    "recover",
    "roundtrip",
    "rebuild",
    "disassemble",
    "static_check",
    "native_load",
    "oracle",
    "replay",
    "compare",
    "profile",
    "benchmark",
}


def contract_surface(contract: dict[str, Any]) -> tuple[str | None, bool]:
    """Return ``(surface, legacy)`` and validate mode compatibility.

    Schema-v1 contracts remain readable and deliberately have no inferred
    surface: a historical source run may have been launch selection, HIP source,
    or another source-level action.  Inferring ``amdgcn_assembly`` would turn an
    old result into a stronger claim than its evidence supports.
    """

    schema_version = contract.get("schema_version")
    mode = contract.get("mode")
    if schema_version == 1:
        if mode not in {"source", "binary"}:
            raise BackendContractError("legacy contract.mode must be source or binary")
        if "optimization_surface" in contract:
            raise BackendContractError(
                "schema-v1 contracts cannot declare optimization_surface"
            )
        return None, True
    if schema_version != 2:
        raise BackendContractError("contract.schema_version must be 1 or 2")

    surface = contract.get("optimization_surface")
    if not isinstance(surface, str) or surface not in OPTIMIZATION_SURFACES:
        raise BackendContractError(
            "contract.optimization_surface must be one of: "
            + ", ".join(sorted(OPTIMIZATION_SURFACES))
        )
    expected_mode = SURFACE_MODES[surface]
    if mode != expected_mode:
        raise BackendContractError(
            f"optimization_surface {surface} requires mode {expected_mode}, got {mode}"
        )
    return surface, False


def required_capabilities(mode: str, surface: str | None) -> set[str]:
    """Return the adapter operations required by a preflight report."""

    if surface == "amdgcn_assembly":
        return set(V2_ASSEMBLY_CAPABILITIES)
    if surface == "hsaco_binary":
        return set(V2_BINARY_CAPABILITIES)
    if surface == "audit_only" or mode == "audit":
        return set()
    if mode == "source":
        return set(V2_SOURCE_CAPABILITIES)
    if mode == "binary":
        # Legacy binary mode preserves the v1 adapter contract.  New binary
        # claims use hsaco_binary and the stricter v2 set above.
        return {
            "recover",
            "roundtrip",
            "rebuild",
            "static_check",
            "oracle",
            "replay",
            "compare",
            "benchmark",
        }
    raise BackendContractError("mode must be source, binary, or audit")
