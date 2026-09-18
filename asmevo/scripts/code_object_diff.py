#!/usr/bin/env python3
"""Compare two normalized AMDGCN disassemblies and enforce edited PC windows."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PC_RANGE = re.compile(r"(0x[0-9a-fA-F]+):(0x[0-9a-fA-F]+)\Z")


class DiffError(ValueError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DiffError(f"cannot read {label}: {error}") from error
    if not isinstance(document, dict):
        raise DiffError(f"{label} must be a JSON object")
    if (
        document.get("schema_version") != 2
        or document.get("kind") != "asmevo.disassembly-evidence.v2"
        or document.get("status") != "complete"
    ):
        raise DiffError(f"{label} is not complete v2 disassembly evidence")
    return document


def _instructions(document: dict[str, Any], label: str) -> list[dict[str, Any]]:
    records = document.get("instructions")
    if not isinstance(records, list) or not records:
        raise DiffError(f"{label} has no instructions")
    for index, record in enumerate(records):
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("pc"), str)
            or not isinstance(record.get("instruction"), str)
        ):
            raise DiffError(f"{label}.instructions[{index}] is malformed")
    return records


def _parse_windows(raw_windows: list[str]) -> list[tuple[int, int]]:
    windows: list[tuple[int, int]] = []
    for raw in raw_windows:
        match = PC_RANGE.fullmatch(raw)
        if not match:
            raise DiffError(f"invalid edited window: {raw}")
        start, end = (int(value, 16) for value in match.groups())
        if start > end:
            raise DiffError(f"edited window is reversed: {raw}")
        windows.append((start, end))
    if not windows:
        raise DiffError("at least one edited window is required")
    return windows


def compare(
    before: dict[str, Any],
    after: dict[str, Any],
    windows: list[tuple[int, int]],
) -> dict[str, Any]:
    if before.get("target_arch") != after.get("target_arch"):
        raise DiffError("disassemblies target different architectures")
    if before.get("kernel_symbol") != after.get("kernel_symbol"):
        raise DiffError("disassemblies target different kernel symbols")
    old = _instructions(before, "before")
    new = _instructions(after, "after")
    old_text = [record["instruction"] for record in old]
    new_text = [record["instruction"] for record in new]
    matcher = difflib.SequenceMatcher(a=old_text, b=new_text, autojunk=False)
    changes: list[dict[str, Any]] = []
    changed_pcs: list[int] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        before_slice = old[i1:i2]
        after_slice = new[j1:j2]
        changed_pcs.extend(int(record["pc"], 16) for record in before_slice)
        changed_pcs.extend(int(record["pc"], 16) for record in after_slice)
        changes.append(
            {
                "kind": tag,
                "before": before_slice,
                "after": after_slice,
            }
        )
    nonempty = bool(changes)
    within_windows = nonempty and all(
        any(start <= pc <= end for start, end in windows) for pc in changed_pcs
    )
    return {
        "schema_version": 2,
        "kind": "asmevo.instruction-diff.v2",
        "status": "complete",
        "target_arch": before["target_arch"],
        "kernel_symbol": before.get("kernel_symbol"),
        "before_artifact_sha256": before.get("artifact", {}).get("sha256"),
        "after_artifact_sha256": after.get("artifact", {}).get("sha256"),
        "before_normalized_sha256": before.get("normalized", {}).get("sha256"),
        "after_normalized_sha256": after.get("normalized", {}).get("sha256"),
        "edited_windows": [
            {"start_pc": f"0x{start:x}", "end_pc": f"0x{end:x}"}
            for start, end in windows
        ],
        "nonempty": nonempty,
        "within_declared_windows": within_windows,
        "changed_pc_count": len(set(changed_pcs)),
        "changes": changes,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--edited-window", action="append", default=[])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        before = _load(args.before, "before evidence")
        after = _load(args.after, "after evidence")
        report = compare(before, after, _parse_windows(args.edited_window))
        report["before_evidence_sha256"] = _sha256(args.before)
        report["after_evidence_sha256"] = _sha256(args.after)
    except DiffError as error:
        print(json.dumps({"status": "input_invalid", "error": str(error)}))
        return 2
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["nonempty"] and report["within_declared_windows"] else 1


if __name__ == "__main__":
    sys.exit(main())
