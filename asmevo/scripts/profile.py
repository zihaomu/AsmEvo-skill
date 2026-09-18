#!/usr/bin/env python3
"""Capture profiler output and bind a deterministic hotspot summary to one artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PC = re.compile(r"0x[0-9a-fA-F]+\Z")


class ProfileError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(path: Path) -> dict[str, Any]:
    path = path.expanduser().absolute()
    if path.is_symlink() or not path.is_file():
        raise ProfileError(f"expected regular non-symlink file: {path}")
    path = path.resolve()
    return {
        "path": str(path),
        "sha256": _sha256(path),
        "size_bytes": path.stat().st_size,
    }


def _load_summary(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProfileError(f"cannot read profiler summary: {error}") from error
    if not isinstance(document, dict):
        raise ProfileError("profiler summary must be a JSON object")
    dispatch_count = document.get("dispatch_count")
    sampled_time_ms = document.get("sampled_time_ms")
    if (
        isinstance(dispatch_count, bool)
        or not isinstance(dispatch_count, int)
        or dispatch_count <= 0
    ):
        raise ProfileError("profiler summary.dispatch_count must be positive")
    if (
        isinstance(sampled_time_ms, bool)
        or not isinstance(sampled_time_ms, (int, float))
        or not math.isfinite(float(sampled_time_ms))
        or float(sampled_time_ms) <= 0
    ):
        raise ProfileError("profiler summary.sampled_time_ms must be positive")
    hotspots = document.get("hotspots")
    if not isinstance(hotspots, list) or not hotspots:
        raise ProfileError("profiler summary.hotspots must not be empty")
    for index, hotspot in enumerate(hotspots):
        start_pc = hotspot.get("start_pc") if isinstance(hotspot, dict) else None
        end_pc = hotspot.get("end_pc") if isinstance(hotspot, dict) else None
        weight = hotspot.get("weight") if isinstance(hotspot, dict) else None
        if (
            not isinstance(hotspot, dict)
            or not isinstance(start_pc, str)
            or not isinstance(end_pc, str)
            or not PC.fullmatch(start_pc)
            or not PC.fullmatch(end_pc)
            or int(start_pc, 16) > int(end_pc, 16)
            or isinstance(weight, bool)
            or not isinstance(weight, (int, float))
            or not math.isfinite(float(weight))
            or float(weight) <= 0
        ):
            raise ProfileError(f"profiler summary.hotspots[{index}] is malformed")
    if not isinstance(document.get("resources"), dict):
        raise ProfileError("profiler summary.resources must be an object")
    bottleneck = document.get("bottleneck_class")
    if not isinstance(bottleneck, str) or not bottleneck.strip():
        raise ProfileError("profiler summary.bottleneck_class is missing")
    counters = document.get("counters", {})
    unavailable = document.get("unavailable_counters", [])
    if (
        not isinstance(counters, dict)
        or not isinstance(unavailable, list)
        or not all(isinstance(value, str) and value for value in unavailable)
    ):
        raise ProfileError("profiler counter availability is malformed")
    return document


def _raw_manifest(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ProfileError(f"profiler output contains a symlink: {path}")
        if path.is_file():
            identity = _identity(path)
            identity["relative_path"] = str(path.relative_to(root))
            identity.pop("path")
            records.append(identity)
    if not records:
        raise ProfileError("profiler produced no raw evidence files")
    return records


def capture(
    *,
    artifact: Path,
    target_arch: str,
    kernel_symbol: str,
    contract_sha256: str,
    environment_sha256: str,
    profiler: str,
    profiler_args: list[str],
    workload_command: list[str],
    raw_directory: Path,
    summary_json: Path,
) -> dict[str, Any]:
    if not SHA256.fullmatch(contract_sha256) or not SHA256.fullmatch(
        environment_sha256
    ):
        raise ProfileError("contract and environment identities must be SHA-256")
    artifact = artifact.expanduser().absolute()
    if artifact.is_symlink() or not artifact.is_file():
        raise ProfileError(f"artifact is not a regular file: {artifact}")
    artifact = artifact.resolve()
    found = shutil.which(profiler) if "/" not in profiler else profiler
    if not found:
        raise ProfileError(f"profiler executable was not found: {profiler}")
    tool = Path(found).expanduser().resolve()
    if not tool.is_file() or not os.access(tool, os.X_OK):
        raise ProfileError(f"profiler is not executable: {tool}")
    if not workload_command:
        raise ProfileError("workload command must not be empty")
    raw_directory = raw_directory.expanduser().resolve()
    if raw_directory.exists():
        raise ProfileError(
            f"refusing to reuse profiler output directory: {raw_directory}"
        )
    raw_directory.mkdir(parents=True, mode=0o700)
    command = [str(tool), *profiler_args, "--", *workload_command]
    result = subprocess.run(
        command,
        cwd=raw_directory,
        check=False,
        capture_output=True,
        timeout=900,
    )
    (raw_directory / "profiler.stdout").write_bytes(result.stdout)
    (raw_directory / "profiler.stderr").write_bytes(result.stderr)
    if result.returncode != 0:
        raise ProfileError(
            "profiler failed with status "
            f"{result.returncode}: "
            + result.stderr.decode("utf-8", errors="replace")[-8192:]
        )
    summary_path = summary_json.expanduser().absolute()
    summary_identity = _identity(summary_path)
    summary = _load_summary(summary_path)
    if _sha256(summary_path) != summary_identity["sha256"]:
        raise ProfileError("profiler summary changed while it was being loaded")
    return {
        "schema_version": 2,
        "kind": "asmevo.profile-evidence.v2",
        "status": "complete",
        "artifact_sha256": _sha256(artifact),
        "artifact": _identity(artifact),
        "target_arch": target_arch,
        "contract_sha256": contract_sha256,
        "environment_sha256": environment_sha256,
        "kernel_symbol": kernel_symbol,
        "dispatch_count": summary["dispatch_count"],
        "sampled_time_ms": float(summary["sampled_time_ms"]),
        "hotspots": summary["hotspots"],
        "counters": summary.get("counters", {}),
        "unavailable_counters": summary.get("unavailable_counters", []),
        "resources": summary["resources"],
        "bottleneck_class": summary["bottleneck_class"],
        "classification_inputs": summary.get("classification_inputs", {}),
        "profiler": _identity(tool),
        "command": command,
        "raw_files": _raw_manifest(raw_directory),
        "summary_source": summary_identity,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--target-arch", required=True)
    parser.add_argument("--kernel-symbol", required=True)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--environment-sha256", required=True)
    parser.add_argument("--profiler", required=True)
    parser.add_argument("--profiler-arg", action="append", default=[])
    parser.add_argument("--raw-directory", type=Path, required=True)
    parser.add_argument("--summary-json", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("workload", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    workload = args.workload[1:] if args.workload[:1] == ["--"] else args.workload
    try:
        report = capture(
            artifact=args.artifact,
            target_arch=args.target_arch,
            kernel_symbol=args.kernel_symbol,
            contract_sha256=args.contract_sha256,
            environment_sha256=args.environment_sha256,
            profiler=args.profiler,
            profiler_args=args.profiler_arg,
            workload_command=workload,
            raw_directory=args.raw_directory,
            summary_json=args.summary_json,
        )
    except (ProfileError, OSError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"status": "failed", "error": str(error)}))
        return 1
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
