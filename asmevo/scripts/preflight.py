#!/usr/bin/env python3
"""Check whether an AsmEvo execution mode has its required local capabilities."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import target_context
from backends import common as backend_common

SOURCE_CAPABILITIES = set(backend_common.V2_SOURCE_CAPABILITIES)
BINARY_CAPABILITIES = backend_common.required_capabilities("binary", None)
ASM_CAPABILITIES = set(backend_common.V2_ASSEMBLY_CAPABILITIES)
ASM_TOOL_ROLES = {"assembler", "linker", "objdump", "profiler"}
BINARY_TOOL_ROLES = {"assembler", "linker", "objdump", "profiler", "readobj"}


class PreflightInputError(ValueError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_capability(raw: str) -> tuple[str, str]:
    if "=" not in raw:
        raise PreflightInputError(f"capability must be NAME=EXECUTABLE: {raw}")
    name, executable = raw.split("=", 1)
    name = name.strip()
    executable = executable.strip()
    if not name or not executable:
        raise PreflightInputError(f"capability must be NAME=EXECUTABLE: {raw}")
    return name, executable


def _resolve_executable(value: str) -> str | None:
    if "/" in value:
        path = Path(value).expanduser().resolve()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
        return None
    resolved = shutil.which(value)
    return str(Path(resolved).resolve()) if resolved else None


def _capability_identity(requested: str) -> dict[str, Any]:
    resolved = _resolve_executable(requested)
    if resolved is None:
        return {
            "requested": requested,
            "resolved": None,
            "sha256": None,
            "size_bytes": None,
        }
    path = Path(resolved)
    return {
        "requested": requested,
        "resolved": resolved,
        "sha256": _sha256(path),
        "size_bytes": path.stat().st_size,
    }


def inspect(
    *,
    mode: str,
    artifact: Path | None,
    capabilities: dict[str, str],
    required_files: list[Path],
    require_gpu: bool,
    target_arch: str | None,
    detected_arches: list[str],
    optimization_surface: str | None = None,
    tools: dict[str, str] | None = None,
    declared_features: dict[str, bool] | None = None,
    software_components: dict[str, str] | None = None,
) -> dict[str, Any]:
    if mode not in {"source", "binary", "audit"}:
        raise PreflightInputError("mode must be source, binary, or audit")
    if optimization_surface is not None:
        try:
            expected_mode = backend_common.SURFACE_MODES[optimization_surface]
        except KeyError as error:
            raise PreflightInputError(
                "unknown optimization surface: " + optimization_surface
            ) from error
        if expected_mode != mode:
            raise PreflightInputError(
                f"optimization surface {optimization_surface} requires mode "
                f"{expected_mode}, got {mode}"
            )
    try:
        required = backend_common.required_capabilities(mode, optimization_surface)
    except backend_common.BackendContractError as error:
        raise PreflightInputError(str(error)) from error
    if any(not isinstance(arch, str) or not arch.strip() for arch in detected_arches):
        raise PreflightInputError("detected architectures must be non-empty strings")
    normalized_arches = sorted({arch.strip() for arch in detected_arches})
    normalized_target_arch = (
        target_arch.strip() if isinstance(target_arch, str) else None
    )
    if (
        optimization_surface is not None
        and normalized_target_arch is not None
        and not backend_common.TARGET_ARCH.fullmatch(normalized_target_arch)
    ):
        raise PreflightInputError(
            "schema-v2 target architecture must be an explicit gfx target"
        )
    capability_identities = {
        name: _capability_identity(value) for name, value in capabilities.items()
    }
    tool_identities = {
        name: _capability_identity(value) for name, value in (tools or {}).items()
    }
    missing_capabilities = sorted(
        name
        for name in required
        if not capability_identities.get(name, {}).get("resolved")
    )

    artifact_info: dict[str, Any] | None = None
    failures: list[str] = []
    if artifact is not None:
        resolved_artifact = artifact.expanduser().resolve()
        if resolved_artifact.is_file():
            artifact_info = {
                "path": str(resolved_artifact),
                "size_bytes": resolved_artifact.stat().st_size,
                "sha256": _sha256(resolved_artifact),
            }
        else:
            failures.append(f"artifact not found: {resolved_artifact}")
    elif mode in {"source", "binary"}:
        failures.append(f"{mode} mode requires --artifact")
    if mode in {"source", "binary"} and not normalized_target_arch:
        failures.append(f"{mode} mode requires --target-arch")

    missing_files = [
        str(path.expanduser().resolve())
        for path in required_files
        if not path.expanduser().resolve().is_file()
    ]
    if missing_files:
        failures.append(f"required files missing: {', '.join(missing_files)}")
    if missing_capabilities:
        failures.append(f"missing capabilities: {', '.join(missing_capabilities)}")

    required_tool_roles: set[str] = set()
    if optimization_surface == "amdgcn_assembly":
        required_tool_roles = ASM_TOOL_ROLES
    elif optimization_surface == "hsaco_binary":
        required_tool_roles = BINARY_TOOL_ROLES
    missing_tools = sorted(
        name
        for name in required_tool_roles
        if not tool_identities.get(name, {}).get("resolved")
    )
    if missing_tools:
        failures.append(f"missing backend tools: {', '.join(missing_tools)}")

    computed_features = {
        "assemble": bool(
            capability_identities.get("build", {}).get("resolved")
            and tool_identities.get("assembler", {}).get("resolved")
        ),
        "link": bool(
            capability_identities.get("build", {}).get("resolved")
            and tool_identities.get("linker", {}).get("resolved")
        ),
        "disassemble": bool(
            capability_identities.get("disassemble", {}).get("resolved")
            and tool_identities.get("objdump", {}).get("resolved")
        ),
        "resource_scan": bool(
            capability_identities.get("static_check", {}).get("resolved")
            and tool_identities.get("objdump", {}).get("resolved")
        ),
        "profile": bool(
            capability_identities.get("profile", {}).get("resolved")
            and tool_identities.get("profiler", {}).get("resolved")
        ),
        "native_load": bool(
            capability_identities.get("native_load", {}).get("resolved")
        ),
        "binary_roundtrip": all(
            capability_identities.get(name, {}).get("resolved")
            for name in ("recover", "roundtrip", "rebuild", "replay")
        ),
    }
    for name, value in (declared_features or {}).items():
        if not isinstance(value, bool):
            raise PreflightInputError(f"feature {name} must be boolean")
        # A declaration may disable a computed feature, but cannot turn a
        # missing executable or adapter into a verified capability.
        computed_features[name] = bool(value and computed_features.get(name, False))
    required_features: set[str] = set()
    if optimization_surface == "amdgcn_assembly":
        required_features = {
            "assemble",
            "link",
            "disassemble",
            "resource_scan",
            "profile",
            "native_load",
        }
    elif optimization_surface == "hsaco_binary":
        required_features = {
            "assemble",
            "link",
            "disassemble",
            "resource_scan",
            "profile",
            "native_load",
            "binary_roundtrip",
        }
    missing_features = sorted(
        name for name in required_features if computed_features.get(name) is not True
    )
    if missing_features:
        failures.append("unverified backend features: " + ", ".join(missing_features))
    if optimization_surface == "hsaco_binary":
        failures.append(
            "hsaco_binary execution is not implemented by the generic v2 "
            "controller; use audit_only until a metadata-aware backend exists"
        )

    device_paths = [Path("/dev/kfd"), Path("/dev/dxg")]
    device_paths.extend(
        sorted(Path("/dev/dri").glob("renderD*")) if Path("/dev/dri").is_dir() else []
    )
    visible_devices = [str(path) for path in device_paths if path.exists()]
    device_nodes_visible = bool(visible_devices)
    target_arch_verified = bool(
        normalized_target_arch and normalized_target_arch in normalized_arches
    )
    if require_gpu and not device_nodes_visible:
        failures.append("no supported GPU device node is visible")
    if mode in {"source", "binary"} and not normalized_arches:
        failures.append("target GPU architecture was not independently detected")
    elif (
        mode in {"source", "binary"}
        and normalized_target_arch
        and not target_arch_verified
    ):
        failures.append(
            f"target architecture {normalized_target_arch} not found in detected architectures: "
            f"{', '.join(normalized_arches)}"
        )

    ready = not failures
    report = {
        "schema_version": 2 if optimization_surface is not None else 1,
        "mode": mode,
        "ready": ready,
        "status": "ready" if ready else "blocked",
        "failures": failures,
        "artifact": artifact_info,
        "target_arch": normalized_target_arch,
        "capabilities": {
            name: capability_identities[name] for name in sorted(capabilities)
        },
        "required_capabilities": sorted(required),
        "gpu": {
            "required": require_gpu,
            "device_nodes_visible": device_nodes_visible,
            "device_nodes": visible_devices,
            "detected_architectures": normalized_arches,
            "target_arch_verified": target_arch_verified,
        },
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "working_directory": str(Path.cwd()),
        },
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    if optimization_surface is not None:
        try:
            architecture = (
                target_context.resolve_architecture(normalized_target_arch)
                if normalized_target_arch
                else None
            )
            stack = target_context.software_stack(software_components, tool_identities)
        except target_context.TargetContextError as error:
            raise PreflightInputError(str(error)) from error
        report.update(
            {
                "kind": "asmevo.capability-report.v2",
                "optimization_surface": optimization_surface,
                "optimization_surfaces": [optimization_surface],
                "tools": {
                    name: tool_identities[name] for name in sorted(tool_identities)
                },
                "features": computed_features,
                "required_features": sorted(required_features),
                "architecture": architecture,
                "software_stack": stack,
            }
        )
    return report


def _parse_feature(raw: str) -> tuple[str, bool]:
    if "=" not in raw:
        raise PreflightInputError(f"feature must be NAME=true|false: {raw}")
    name, value = (part.strip() for part in raw.split("=", 1))
    if not name or value.lower() not in {"true", "false"}:
        raise PreflightInputError(f"feature must be NAME=true|false: {raw}")
    return name, value.lower() == "true"


def _parse_component(raw: str) -> tuple[str, str]:
    if "=" not in raw:
        raise PreflightInputError(f"component must be NAME=VERSION: {raw}")
    name, value = (part.strip() for part in raw.split("=", 1))
    if not name or not value:
        raise PreflightInputError(f"component must be NAME=VERSION: {raw}")
    return name, value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("source", "binary", "audit"), required=True)
    parser.add_argument(
        "--optimization-surface",
        choices=tuple(sorted(backend_common.OPTIMIZATION_SURFACES)),
    )
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--target-arch")
    parser.add_argument("--detected-arch", action="append", default=[])
    parser.add_argument(
        "--capability", action="append", default=[], metavar="NAME=EXECUTABLE"
    )
    parser.add_argument(
        "--tool", action="append", default=[], metavar="NAME=EXECUTABLE"
    )
    parser.add_argument("--feature", action="append", default=[], metavar="NAME=BOOL")
    parser.add_argument(
        "--component", action="append", default=[], metavar="NAME=VERSION"
    )
    parser.add_argument("--require-file", action="append", default=[], type=Path)
    parser.add_argument("--require-gpu", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    try:
        capabilities = dict(_parse_capability(raw) for raw in args.capability)
        if len(capabilities) != len(args.capability):
            raise PreflightInputError("capability names must be unique")
        tools = dict(_parse_capability(raw) for raw in args.tool)
        if len(tools) != len(args.tool):
            raise PreflightInputError("tool names must be unique")
        features = dict(_parse_feature(raw) for raw in args.feature)
        if len(features) != len(args.feature):
            raise PreflightInputError("feature names must be unique")
        components = dict(_parse_component(raw) for raw in args.component)
        if len(components) != len(args.component):
            raise PreflightInputError("software component names must be unique")
        report = inspect(
            mode=args.mode,
            artifact=args.artifact,
            capabilities=capabilities,
            required_files=args.require_file,
            require_gpu=args.require_gpu,
            target_arch=args.target_arch,
            detected_arches=args.detected_arch,
            optimization_surface=args.optimization_surface,
            tools=tools,
            declared_features=features,
            software_components=components,
        )
    except (OSError, PreflightInputError) as error:
        print(
            json.dumps({"ready": False, "status": "input_invalid", "error": str(error)})
        )
        return 2

    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
