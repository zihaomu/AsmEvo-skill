#!/usr/bin/env python3
"""Produce hash-bound normalized AMDGCN disassembly evidence."""

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

SYMBOL = re.compile(r"^\s*([0-9a-fA-F]+)\s+<([^>]+)>:\s*$")
INSTRUCTION = re.compile(r"^\s*([0-9a-fA-F]+):\s*(.*?)\s*$")
LEADING_BYTES = re.compile(r"^(?:(?:[0-9a-fA-F]{2}|[0-9a-fA-F]{8})\s+)+")


class DisassemblyError(RuntimeError):
    pass


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(path: Path) -> dict[str, Any]:
    path = path.expanduser().absolute()
    if path.is_symlink() or not path.is_file():
        raise DisassemblyError(f"expected regular non-symlink file: {path}")
    path = path.resolve()
    return {
        "path": str(path),
        "sha256": _sha256(path),
        "size_bytes": path.stat().st_size,
    }


def normalize(text: str, kernel_symbol: str | None) -> tuple[str, list[dict[str, Any]]]:
    current_symbol: str | None = None
    selected_base: int | None = None
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        symbol_match = SYMBOL.match(line)
        if symbol_match:
            current_symbol = symbol_match.group(2)
            if kernel_symbol is None or current_symbol == kernel_symbol:
                selected_base = int(symbol_match.group(1), 16)
            continue
        instruction_match = INSTRUCTION.match(line)
        if not instruction_match:
            continue
        if kernel_symbol is not None and current_symbol != kernel_symbol:
            continue
        pc = int(instruction_match.group(1), 16)
        body = instruction_match.group(2).split("//", 1)[0].strip()
        body = LEADING_BYTES.sub("", body).strip()
        if not body:
            continue
        if selected_base is None:
            selected_base = pc
        records.append(
            {
                "pc": f"0x{pc:x}",
                "offset": f"0x{pc - selected_base:x}",
                "symbol": current_symbol,
                "instruction": " ".join(body.split()),
            }
        )
    if not records:
        requested = f" for symbol {kernel_symbol}" if kernel_symbol else ""
        raise DisassemblyError(f"objdump produced no parseable instructions{requested}")
    normalized = (
        "\n".join(f"{record['offset']}\t{record['instruction']}" for record in records)
        + "\n"
    )
    return normalized, records


def disassemble(
    *,
    artifact: Path,
    objdump: str,
    target_arch: str,
    kernel_symbol: str | None,
    objdump_args: list[str],
    normalized_output: Path,
    raw_output: Path,
) -> dict[str, Any]:
    artifact = artifact.expanduser().absolute()
    if artifact.is_symlink() or not artifact.is_file():
        raise DisassemblyError(f"artifact is not a regular file: {artifact}")
    artifact = artifact.resolve()
    found = shutil.which(objdump) if "/" not in objdump else objdump
    if not found:
        raise DisassemblyError(f"objdump executable was not found: {objdump}")
    tool = Path(found).expanduser().resolve()
    if not tool.is_file() or not os.access(tool, os.X_OK):
        raise DisassemblyError(f"objdump is not executable: {tool}")
    command = [str(tool), "--disassemble", *objdump_args, str(artifact)]
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        timeout=120,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")[-8192:]
        raise DisassemblyError(
            f"objdump failed with status {result.returncode}: {stderr}"
        )
    raw_output = raw_output.expanduser().resolve()
    normalized_output = normalized_output.expanduser().resolve()
    for path in (raw_output, normalized_output):
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            raise DisassemblyError(f"refusing to overwrite evidence: {path}")
    raw_output.write_bytes(result.stdout)
    normalized, instructions = normalize(
        result.stdout.decode("utf-8", errors="strict"), kernel_symbol
    )
    normalized_output.write_text(normalized, encoding="utf-8")
    return {
        "schema_version": 2,
        "kind": "asmevo.disassembly-evidence.v2",
        "status": "complete",
        "target_arch": target_arch,
        "kernel_symbol": kernel_symbol,
        "artifact": _identity(artifact),
        "objdump": _identity(tool),
        "command": command,
        "raw": _identity(raw_output),
        "raw_stderr_sha256": _sha256_bytes(result.stderr),
        "normalized": _identity(normalized_output),
        "instruction_count": len(instructions),
        "instructions": instructions,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--objdump", required=True)
    parser.add_argument("--target-arch", required=True)
    parser.add_argument("--kernel-symbol")
    parser.add_argument("--objdump-arg", action="append", default=[])
    parser.add_argument("--raw-output", type=Path, required=True)
    parser.add_argument("--normalized-output", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    try:
        report = disassemble(
            artifact=args.artifact,
            objdump=args.objdump,
            target_arch=args.target_arch,
            kernel_symbol=args.kernel_symbol,
            objdump_args=args.objdump_arg,
            normalized_output=args.normalized_output,
            raw_output=args.raw_output,
        )
    except (
        DisassemblyError,
        OSError,
        UnicodeDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
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
