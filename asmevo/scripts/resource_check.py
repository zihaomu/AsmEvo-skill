#!/usr/bin/env python3
"""Scan final AMDGPU code-object metadata and apply frozen ABI/resource limits."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RESOURCE_PATTERNS = {
    "vgpr_count": [r"\.amdhsa_next_free_vgpr\s*:?\s*(\d+)", r"vgpr_count\s*:?\s*(\d+)"],
    "sgpr_count": [r"\.amdhsa_next_free_sgpr\s*:?\s*(\d+)", r"sgpr_count\s*:?\s*(\d+)"],
    "agpr_count": [r"\.amdhsa_accum_offset\s*:?\s*(\d+)", r"agpr_count\s*:?\s*(\d+)"],
    "lds_bytes": [
        r"\.amdhsa_group_segment_fixed_size\s*:?\s*(\d+)",
        r"group_segment_fixed_size\s*:?\s*(\d+)",
    ],
    "scratch_bytes": [
        r"\.amdhsa_private_segment_fixed_size\s*:?\s*(\d+)",
        r"private_segment_fixed_size\s*:?\s*(\d+)",
    ],
    "kernarg_size": [
        r"\.amdhsa_kernarg_size\s*:?\s*(\d+)",
        r"kernarg_segment_size\s*:?\s*(\d+)",
    ],
}
WAVE32_PATTERNS = [
    r"\.amdhsa_wavefront_size32\s*:?\s*([01])",
    r"wavefront_size\s*:?\s*(32|64)",
]


class ResourceError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _identity(path: Path) -> dict[str, Any]:
    path = path.expanduser().absolute()
    if path.is_symlink() or not path.is_file():
        raise ResourceError(f"expected regular non-symlink file: {path}")
    path = path.resolve()
    return {
        "path": str(path),
        "sha256": _sha256(path),
        "size_bytes": path.stat().st_size,
    }


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ResourceError(f"cannot read {label}: {error}") from error
    if not isinstance(document, dict):
        raise ResourceError(f"{label} must be a JSON object")
    return document


def parse_resources(text: str) -> dict[str, int | None]:
    resources: dict[str, int | None] = {}
    for key, patterns in RESOURCE_PATTERNS.items():
        value: int | None = None
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                value = int(match.group(1))
                break
        resources[key] = value
    wave_size: int | None = None
    for pattern in WAVE32_PATTERNS:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            raw = int(match.group(1))
            wave_size = 32 if raw == 1 else 64 if raw == 0 else raw
            break
    resources["wave_size"] = wave_size
    return resources


def scan(
    *,
    artifact: Path,
    readobj: str,
    target_arch: str,
    kernel_symbol: str,
    tool_args: list[str],
    policy: dict[str, Any],
) -> dict[str, Any]:
    artifact = artifact.expanduser().absolute()
    if artifact.is_symlink() or not artifact.is_file():
        raise ResourceError(f"artifact is not a regular file: {artifact}")
    artifact = artifact.resolve()
    found = shutil.which(readobj) if "/" not in readobj else readobj
    if not found:
        raise ResourceError(f"resource scanner was not found: {readobj}")
    tool = Path(found).expanduser().resolve()
    if not tool.is_file() or not os.access(tool, os.X_OK):
        raise ResourceError(f"resource scanner is not executable: {tool}")
    command = [
        str(tool),
        "--notes",
        "--symbols",
        "--sections",
        *tool_args,
        str(artifact),
    ]
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise ResourceError(
            "resource scanner failed: "
            + result.stderr.decode("utf-8", errors="replace")[-8192:]
        )
    text = result.stdout.decode("utf-8", errors="replace")
    resources = parse_resources(text)
    failures: list[str] = []
    if kernel_symbol not in text:
        failures.append(f"exported kernel symbol not found: {kernel_symbol}")
    required_fields = policy.get(
        "required_fields",
        [
            "vgpr_count",
            "sgpr_count",
            "lds_bytes",
            "scratch_bytes",
            "kernarg_size",
            "wave_size",
        ],
    )
    if not isinstance(required_fields, list) or not all(
        isinstance(value, str) for value in required_fields
    ):
        raise ResourceError("policy.required_fields must be an array of strings")
    for field in required_fields:
        if field not in resources or resources[field] is None:
            failures.append(f"resource field is unavailable: {field}")
    exact = policy.get("exact", {})
    maximum = policy.get("maximum", {})
    if not isinstance(exact, dict) or not isinstance(maximum, dict):
        raise ResourceError("policy exact and maximum values must be objects")
    for field, expected in exact.items():
        if resources.get(field) != expected:
            failures.append(
                f"{field} changed: observed {resources.get(field)}, expected {expected}"
            )
    for field, limit in maximum.items():
        observed = resources.get(field)
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit < 0
            or observed is None
            or observed > limit
        ):
            failures.append(
                f"{field} exceeds limit or is unavailable: observed {observed}, limit {limit}"
            )
    if policy.get("forbid_scratch") is True and resources.get("scratch_bytes") != 0:
        failures.append("candidate uses scratch while policy forbids it")
    return {
        "schema_version": 2,
        "kind": "asmevo.resource-check.v2",
        "status": "passed" if not failures else "failed",
        "passed": not failures,
        "failures": failures,
        "target_arch": target_arch,
        "kernel_symbol": kernel_symbol,
        "artifact": _identity(artifact),
        "scanner": _identity(tool),
        "command": command,
        "raw_stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "raw_stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "resources": resources,
        "policy": policy,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--readobj", required=True)
    parser.add_argument("--target-arch", required=True)
    parser.add_argument("--kernel-symbol", required=True)
    parser.add_argument("--tool-arg", action="append", default=[])
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = scan(
            artifact=args.artifact,
            readobj=args.readobj,
            target_arch=args.target_arch,
            kernel_symbol=args.kernel_symbol,
            tool_args=args.tool_arg,
            policy=_load_json(args.policy, "resource policy"),
        )
    except (ResourceError, OSError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"status": "input_invalid", "error": str(error)}))
        return 2
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
