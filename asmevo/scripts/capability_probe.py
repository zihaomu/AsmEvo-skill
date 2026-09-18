#!/usr/bin/env python3
"""Probe versioned AMDGPU backend tools without inferring unavailable features."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backends import common

TOOL_ROLES = {"compiler", "assembler", "linker", "objdump", "readobj", "profiler"}
SURFACE_REQUIRED_TOOLS = {
    "launch_config": set(),
    "hip_source": {"compiler", "profiler"},
    "triton_source": {"profiler"},
    "amdgcn_assembly": {"assembler", "linker", "objdump", "profiler"},
    "hsaco_binary": {"assembler", "linker", "objdump", "readobj", "profiler"},
    "audit_only": {"objdump"},
}


class ProbeError(ValueError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve(value: str) -> Path | None:
    if "/" in value:
        path = Path(value).expanduser().resolve()
        return path if path.is_file() and os.access(path, os.X_OK) else None
    found = shutil.which(value)
    return Path(found).resolve() if found else None


def _version(path: Path) -> str | None:
    try:
        result = subprocess.run(
            [str(path), "--version"],
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (result.stdout + "\n" + result.stderr).strip()
    return text[:4096] if text else None


def _parse_mapping(raw: str) -> tuple[str, str]:
    if "=" not in raw:
        raise ProbeError(f"expected NAME=VALUE: {raw}")
    name, value = (part.strip() for part in raw.split("=", 1))
    if not name or not value:
        raise ProbeError(f"expected NAME=VALUE: {raw}")
    return name, value


def probe(
    *,
    target_arch: str,
    detected_arches: list[str],
    optimization_surface: str,
    requested_tools: dict[str, str],
    native_load: bool,
    binary_roundtrip: bool,
) -> dict[str, Any]:
    if optimization_surface not in common.OPTIMIZATION_SURFACES:
        raise ProbeError(f"unknown optimization surface: {optimization_surface}")
    if not common.TARGET_ARCH.fullmatch(target_arch.strip()):
        raise ProbeError("target architecture must be an explicit gfx target")
    unknown_roles = sorted(set(requested_tools) - TOOL_ROLES)
    if unknown_roles:
        raise ProbeError("unknown tool roles: " + ", ".join(unknown_roles))

    tools: dict[str, dict[str, Any]] = {}
    for role in sorted(requested_tools):
        requested = requested_tools[role]
        resolved = _resolve(requested)
        tools[role] = {
            "requested": requested,
            "path": str(resolved) if resolved else None,
            "sha256": _sha256(resolved) if resolved else None,
            "size_bytes": resolved.stat().st_size if resolved else None,
            "version": _version(resolved) if resolved else None,
        }

    normalized_arches = sorted(
        {value.strip() for value in detected_arches if value.strip()}
    )
    required_tools = SURFACE_REQUIRED_TOOLS[optimization_surface]
    missing_tools = sorted(
        role for role in required_tools if not tools.get(role, {}).get("path")
    )
    features = {
        "assemble": bool(
            tools.get("assembler", {}).get("path")
            or tools.get("compiler", {}).get("path")
        ),
        "link": bool(
            tools.get("linker", {}).get("path") or tools.get("compiler", {}).get("path")
        ),
        "disassemble": bool(tools.get("objdump", {}).get("path")),
        "resource_scan": bool(
            tools.get("readobj", {}).get("path") or tools.get("objdump", {}).get("path")
        ),
        "profile": bool(tools.get("profiler", {}).get("path")),
        "native_load": native_load,
        "binary_roundtrip": binary_roundtrip,
    }
    required_features = {
        "amdgcn_assembly": {
            "assemble",
            "link",
            "disassemble",
            "resource_scan",
            "profile",
            "native_load",
        },
        "hsaco_binary": {
            "assemble",
            "link",
            "disassemble",
            "resource_scan",
            "profile",
            "native_load",
            "binary_roundtrip",
        },
    }.get(optimization_surface, set())
    missing_features = sorted(
        name for name in required_features if features.get(name) is not True
    )
    failures: list[str] = []
    if target_arch not in normalized_arches:
        failures.append(
            f"target architecture {target_arch} was not independently detected"
        )
    if missing_tools:
        failures.append("missing tools: " + ", ".join(missing_tools))
    if missing_features:
        failures.append("unverified features: " + ", ".join(missing_features))
    if optimization_surface == "hsaco_binary":
        failures.append(
            "hsaco_binary execution is not implemented by the generic v2 "
            "controller; use audit_only until a metadata-aware backend exists"
        )

    return {
        "schema_version": 2,
        "kind": "asmevo.capability-report.v2",
        "status": "ready" if not failures else "blocked",
        "ready": not failures,
        "failures": failures,
        "target_arch": target_arch,
        "detected_architectures": normalized_arches,
        "optimization_surfaces": [optimization_surface] if not failures else [],
        "requested_optimization_surface": optimization_surface,
        "tools": tools,
        "features": features,
        "required_tools": sorted(required_tools),
        "required_features": sorted(required_features),
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-arch", required=True)
    parser.add_argument("--detected-arch", action="append", default=[])
    parser.add_argument(
        "--optimization-surface",
        required=True,
        choices=tuple(sorted(common.OPTIMIZATION_SURFACES)),
    )
    parser.add_argument("--tool", action="append", default=[], metavar="ROLE=PATH")
    parser.add_argument("--native-load", action="store_true")
    parser.add_argument("--binary-roundtrip", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        tools = dict(_parse_mapping(value) for value in args.tool)
        if len(tools) != len(args.tool):
            raise ProbeError("tool roles must be unique")
        report = probe(
            target_arch=args.target_arch,
            detected_arches=args.detected_arch,
            optimization_surface=args.optimization_surface,
            requested_tools=tools,
            native_load=args.native_load,
            binary_roundtrip=args.binary_roundtrip,
        )
    except ProbeError as error:
        print(json.dumps({"status": "input_invalid", "error": str(error)}))
        return 2
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
