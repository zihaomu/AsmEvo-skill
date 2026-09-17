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

SOURCE_CAPABILITIES = {"build", "oracle", "benchmark"}
BINARY_CAPABILITIES = {
    "recover",
    "roundtrip",
    "rebuild",
    "static_check",
    "oracle",
    "replay",
    "compare",
    "benchmark",
}


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
    return shutil.which(value)


def inspect(
    *,
    mode: str,
    artifact: Path | None,
    capabilities: dict[str, str],
    required_files: list[Path],
    require_gpu: bool,
    target_arch: str | None,
    detected_arches: list[str],
) -> dict[str, Any]:
    if mode not in {"source", "binary", "audit"}:
        raise PreflightInputError("mode must be source, binary, or audit")
    required = (
        SOURCE_CAPABILITIES
        if mode == "source"
        else BINARY_CAPABILITIES
        if mode == "binary"
        else set()
    )
    if any(not isinstance(arch, str) or not arch.strip() for arch in detected_arches):
        raise PreflightInputError("detected architectures must be non-empty strings")
    normalized_arches = sorted({arch.strip() for arch in detected_arches})
    normalized_target_arch = (
        target_arch.strip() if isinstance(target_arch, str) else None
    )
    resolved = {
        name: _resolve_executable(value) for name, value in capabilities.items()
    }
    missing_capabilities = sorted(name for name in required if not resolved.get(name))

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
    return {
        "schema_version": 1,
        "mode": mode,
        "ready": ready,
        "status": "ready" if ready else "blocked",
        "failures": failures,
        "artifact": artifact_info,
        "target_arch": normalized_target_arch,
        "capabilities": {
            name: {"requested": capabilities[name], "resolved": resolved[name]}
            for name in sorted(capabilities)
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("source", "binary", "audit"), required=True)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--target-arch")
    parser.add_argument("--detected-arch", action="append", default=[])
    parser.add_argument(
        "--capability", action="append", default=[], metavar="NAME=EXECUTABLE"
    )
    parser.add_argument("--require-file", action="append", default=[], type=Path)
    parser.add_argument("--require-gpu", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    try:
        capabilities = dict(_parse_capability(raw) for raw in args.capability)
        if len(capabilities) != len(args.capability):
            raise PreflightInputError("capability names must be unique")
        report = inspect(
            mode=args.mode,
            artifact=args.artifact,
            capabilities=capabilities,
            required_files=args.require_file,
            require_gpu=args.require_gpu,
            target_arch=args.target_arch,
            detected_arches=args.detected_arch,
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
