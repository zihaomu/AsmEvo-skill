#!/usr/bin/env python3
"""Resolve exact AMDGPU targets and bind compact software-stack context."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

SKILL_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = SKILL_ROOT / "assets" / "architectures" / "targets.json"
COMPONENT_NAMES = {
    "rocm",
    "hip",
    "llvm",
    "rocr",
    "profiler",
    "kernel_driver",
    "firmware",
    "code_object",
}
TARGET_ARCH = re.compile(r"gfx[0-9a-z]+")


class TargetContextError(ValueError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_registry(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    resolved = path.expanduser().resolve()
    try:
        document = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TargetContextError(
            f"cannot load architecture registry: {error}"
        ) from error
    if not isinstance(document, dict):
        raise TargetContextError("architecture registry must be a JSON object")
    if document.get("schema_version") != 1 or document.get("kind") != (
        "asmevo.architecture-target-registry.v1"
    ):
        raise TargetContextError("unsupported architecture registry")
    if document.get("match_policy") != "exact_only":
        raise TargetContextError("architecture registry must use exact_only matching")
    targets = document.get("targets")
    if not isinstance(targets, dict):
        raise TargetContextError("architecture registry targets must be an object")
    for target, entry in targets.items():
        if not isinstance(target, str) or not TARGET_ARCH.fullmatch(target):
            raise TargetContextError(
                f"invalid target in architecture registry: {target}"
            )
        if not isinstance(entry, dict):
            raise TargetContextError(f"registry entry for {target} must be an object")
        required = (
            "architecture_family",
            "architecture_generation",
            "knowledge_reference",
        )
        if any(
            not isinstance(entry.get(name), str) or not entry[name] for name in required
        ):
            raise TargetContextError(f"registry entry for {target} is incomplete")
    identity = {
        "schema_version": 1,
        "kind": document["kind"],
        "path": str(resolved),
        "sha256": _sha256(resolved),
        "match_policy": "exact_only",
    }
    return document, identity


def resolve_architecture(
    target_arch: str, *, registry_path: Path | None = None
) -> dict[str, Any]:
    """Return exact-match context; unknown targets deliberately stay unclassified."""

    if not isinstance(target_arch, str):
        raise TargetContextError("target architecture must be an explicit gfx target")
    normalized = target_arch.strip()
    if not TARGET_ARCH.fullmatch(normalized):
        raise TargetContextError("target architecture must be an explicit gfx target")
    registry, identity = _load_registry(registry_path or DEFAULT_REGISTRY)
    entry = registry["targets"].get(normalized)
    if entry is None:
        return {
            "target_arch": normalized,
            "mapping_status": "unknown",
            "architecture_family": None,
            "architecture_generation": None,
            "representative_products": [],
            "knowledge_reference": None,
            "knowledge_sha256": None,
            "architecture_specific_guidance": False,
            "registry": identity,
            "proposal_policy": (
                "Use generic measured hypotheses only; do not infer an ISA family "
                "from a gfx prefix."
            ),
        }

    knowledge_relative = Path(entry["knowledge_reference"])
    knowledge_path = (SKILL_ROOT / knowledge_relative).resolve()
    try:
        knowledge_path.relative_to(SKILL_ROOT.resolve())
    except ValueError as error:
        raise TargetContextError(
            f"knowledge reference for {normalized} escapes the skill root"
        ) from error
    if not knowledge_path.is_file():
        raise TargetContextError(
            f"knowledge reference for {normalized} is missing: {knowledge_relative}"
        )
    products = entry.get("representative_products", [])
    if not isinstance(products, list) or not all(
        isinstance(product, str) and product for product in products
    ):
        raise TargetContextError(
            f"representative products for {normalized} must be strings"
        )
    return {
        "target_arch": normalized,
        "mapping_status": "known",
        "architecture_family": entry["architecture_family"],
        "architecture_generation": entry["architecture_generation"],
        "representative_products": products,
        "knowledge_reference": entry["knowledge_reference"],
        "knowledge_sha256": _sha256(knowledge_path),
        "architecture_specific_guidance": True,
        "registry": identity,
        "proposal_policy": (
            "Architecture guidance may shape candidate hypotheses only; live "
            "assembly, correctness, and benchmark gates remain authoritative."
        ),
    }


def software_stack(
    declared_components: dict[str, str] | None,
    tools: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Bind declared component versions separately from observed tool identities."""

    if declared_components is not None and not isinstance(declared_components, dict):
        raise TargetContextError("software components must be a mapping")
    if not isinstance(tools, dict):
        raise TargetContextError("observed tools must be a mapping")
    declared = declared_components or {}
    unknown = sorted(set(declared) - COMPONENT_NAMES)
    if unknown:
        raise TargetContextError("unknown software components: " + ", ".join(unknown))
    if any(
        not isinstance(value, str) or not value.strip() for value in declared.values()
    ):
        raise TargetContextError(
            "software component versions must be non-empty strings"
        )
    observed: dict[str, dict[str, Any]] = {}
    for role in sorted(tools):
        tool = tools[role]
        if not isinstance(tool, dict):
            continue
        observed[role] = {
            key: tool.get(key)
            for key in ("path", "resolved", "sha256", "version")
            if key in tool
        }
    return {
        "declared_components": {
            name: declared[name].strip() for name in sorted(declared)
        },
        "observed_tools": observed,
        "compatibility_policy": (
            "Treat umbrella ROCm and component versions as context, not proof of "
            "compatibility; exact target support, native load, correctness, and "
            "performance must be checked live."
        ),
    }
