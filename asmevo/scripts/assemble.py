#!/usr/bin/env python3
"""Assemble and link one AMDGCN source into a fresh architecture-bound code object."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AssembleError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(path: Path) -> dict[str, Any]:
    requested = path.expanduser().absolute()
    if requested.is_symlink() or not requested.is_file():
        raise AssembleError(f"expected a regular non-symlink file: {requested}")
    resolved = requested.resolve()
    return {
        "path": str(resolved),
        "sha256": _sha256(resolved),
        "size_bytes": resolved.stat().st_size,
    }


def _executable(value: str, role: str) -> Path:
    found = shutil.which(value) if "/" not in value else value
    if not found:
        raise AssembleError(f"{role} executable was not found: {value}")
    path = Path(found).expanduser().resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise AssembleError(f"{role} is not executable: {path}")
    return path


def _run(command: list[str], cwd: Path, label: str) -> dict[str, Any]:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        timeout=300,
    )
    evidence = {
        "command": command,
        "return_code": result.returncode,
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "stdout": result.stdout.decode("utf-8", errors="replace")[-8192:],
        "stderr": result.stderr.decode("utf-8", errors="replace")[-8192:],
    }
    if result.returncode != 0:
        raise AssembleError(
            f"{label} failed with status {result.returncode}: {evidence['stderr']}"
        )
    return evidence


def build(
    *,
    source: Path,
    target_arch: str,
    assembler: str,
    linker: str,
    output: Path,
    assembler_args: list[str],
    linker_args: list[str],
) -> dict[str, Any]:
    source = source.expanduser().absolute()
    if source.is_symlink() or not source.is_file():
        raise AssembleError(f"assembly source is not a regular file: {source}")
    source = source.resolve()
    if not target_arch.startswith("gfx") or not target_arch[3:].isalnum():
        raise AssembleError("target architecture must be an explicit gfx target")
    assembler_path = _executable(assembler, "assembler")
    linker_path = _executable(linker, "linker")
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise AssembleError(f"refusing to overwrite code object: {output}")

    with tempfile.TemporaryDirectory(prefix="asmevo-assemble-") as temporary:
        work = Path(temporary)
        object_path = work / "candidate.o"
        assemble_command = [
            str(assembler_path),
            "-x",
            "assembler",
            "-target",
            "amdgcn-amd-amdhsa",
            f"-mcpu={target_arch}",
            *assembler_args,
            "-c",
            str(source),
            "-o",
            str(object_path),
        ]
        assemble_evidence = _run(assemble_command, work, "assembly")
        object_identity = _identity(object_path)
        temporary_output = work / output.name
        link_command = [
            str(linker_path),
            "-shared",
            *linker_args,
            str(object_path),
            "-o",
            str(temporary_output),
        ]
        link_evidence = _run(link_command, work, "link")
        code_object_identity = _identity(temporary_output)
        with (
            temporary_output.open("rb") as source_file,
            output.open("xb") as destination,
        ):
            shutil.copyfileobj(source_file, destination, 1024 * 1024)
            destination.flush()
            os.fsync(destination.fileno())
    final_identity = _identity(output)
    if final_identity["sha256"] != code_object_identity["sha256"]:
        raise AssembleError("code object changed while publishing the output")
    return {
        "schema_version": 2,
        "kind": "asmevo.assembly-build.v2",
        "status": "compiled",
        "compiled": True,
        "precompiled_variant": False,
        "artifact_kind": "hsaco",
        "target_arch": target_arch,
        "source": _identity(source),
        "assembler": _identity(assembler_path),
        "linker": _identity(linker_path),
        "object": {**object_identity, "path": None},
        "code_object": final_identity,
        "assemble": assemble_evidence,
        "link": link_evidence,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--target-arch", required=True)
    parser.add_argument("--assembler", required=True)
    parser.add_argument("--linker", required=True)
    parser.add_argument("--assembler-arg", action="append", default=[])
    parser.add_argument("--linker-arg", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    try:
        report = build(
            source=args.source,
            target_arch=args.target_arch,
            assembler=args.assembler,
            linker=args.linker,
            output=args.output,
            assembler_args=args.assembler_arg,
            linker_args=args.linker_arg,
        )
    except (AssembleError, OSError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"status": "failed", "error": str(error)}))
        return 1
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.evidence:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
