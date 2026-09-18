#!/usr/bin/env python3
"""Run the adapter-bound AsmEvo baseline and candidate gate in a fixed order."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import secrets
import selectors
import shutil
import signal
import stat
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import gate
import lineage
from backends import amdgcn_assembly
from backends import common as backend_common

PROTOCOLS = {1: "asmevo.adapter.v1", 2: "asmevo.adapter.v2"}
CONTROLLER_POLICIES = {1: "controller-v1", 2: "controller-v2"}
DEFAULT_TIMEOUT_SECONDS = 600.0
DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
RESERVED_ARTIFACT_NAMES = {
    "baseline-receipt.json",
    "candidate-observations.json",
    "correctness-receipt.json",
    "decision.json",
    "evaluation.json",
    "oracle-observations.json",
    "proposal.snapshot",
    "recovered.json",
    "roundtrip-observations.json",
    "roundtrip.artifact",
}


class ControllerError(ValueError):
    """Raised when a controller invariant cannot be established."""


def _validate_limits(timeout_seconds: float, max_output_bytes: int) -> None:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds <= 0
    ):
        raise ControllerError("adapter timeout must be positive and finite")
    if (
        isinstance(max_output_bytes, bool)
        or not isinstance(max_output_bytes, int)
        or max_output_bytes <= 0
    ):
        raise ControllerError("adapter output limit must be a positive integer")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _document_digest(document: dict[str, Any]) -> str:
    rendered = json.dumps(
        document, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _reject_constant(value: str) -> None:
    raise ControllerError(f"non-finite JSON number is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ControllerError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _strict_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ControllerError) as error:
        raise ControllerError(f"invalid {label}: {error}") from error
    if not isinstance(document, dict):
        raise ControllerError(f"{label} root must be an object")
    return document


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        return _strict_json_bytes(path.read_bytes(), label)
    except OSError as error:
        raise ControllerError(f"cannot read {label}: {error}") from error


def _atomic_write_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
            json.dump(document, destination, indent=2, sort_keys=True, allow_nan=False)
            destination.write("\n")
            destination.flush()
            os.fsync(destination.fileno())
        temporary.replace(path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def _safe_id(value: str, label: str) -> str:
    if not SAFE_ID.fullmatch(value) or value in {".", ".."}:
        raise ControllerError(
            f"{label} must match [A-Za-z0-9][A-Za-z0-9._-] and be at most 128 bytes"
        )
    return value


def _safe_artifact_name(value: str) -> str:
    path = Path(value)
    if (
        value in {"", ".", ".."}
        or path.name != value
        or path.is_absolute()
        or not SAFE_ID.fullmatch(value)
    ):
        raise ControllerError(
            "artifact name must be one safe basename of at most 128 characters"
        )
    if value in RESERVED_ARTIFACT_NAMES:
        raise ControllerError(f"artifact name is reserved by the controller: {value}")
    return value


def _regular_identity(
    path: Path,
    label: str,
    *,
    within: Path | None = None,
    protected: list[Path] | None = None,
) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ControllerError(f"{label} is unavailable: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ControllerError(f"{label} must be a regular non-symlink file")
    resolved = path.resolve()
    if within is not None and not resolved.is_relative_to(within.resolve()):
        raise ControllerError(f"{label} escaped the controller attempt directory")
    for protected_path in protected or []:
        protected_metadata = protected_path.stat()
        if (metadata.st_dev, metadata.st_ino) == (
            protected_metadata.st_dev,
            protected_metadata.st_ino,
        ):
            raise ControllerError(f"{label} aliases a protected artifact")
    return {
        "path": str(resolved),
        "sha256": _sha256(resolved),
        "size_bytes": metadata.st_size,
    }


def _snapshot_proposal(source: Path, destination: Path) -> dict[str, Any]:
    try:
        source_metadata = source.lstat()
    except OSError as error:
        raise ControllerError(f"proposal is unavailable: {error}") from error
    if stat.S_ISLNK(source_metadata.st_mode) or not stat.S_ISREG(
        source_metadata.st_mode
    ):
        raise ControllerError("proposal must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    source_fd = os.open(source, flags)
    try:
        opened_metadata = os.fstat(source_fd)
        if not stat.S_ISREG(opened_metadata.st_mode):
            raise ControllerError("proposal must remain a regular file")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o400,
        )
        try:
            with (
                os.fdopen(source_fd, "rb", closefd=False) as input_file,
                os.fdopen(destination_fd, "wb", closefd=False) as output_file,
            ):
                shutil.copyfileobj(input_file, output_file, 1024 * 1024)
                output_file.flush()
                os.fsync(output_file.fileno())
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)
    return _regular_identity(
        destination, "proposal snapshot", within=destination.parent
    )


def _new_attempt_directory(run_dir: Path, attempt_id: str) -> Path:
    requested_root = run_dir.expanduser().absolute()
    if requested_root.is_symlink():
        raise ControllerError("run directory must not be a symlink")
    requested_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = requested_root.resolve()
    attempts = root / "attempts"
    if attempts.exists() or attempts.is_symlink():
        metadata = attempts.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ControllerError("run attempts path must be a real directory")
    else:
        attempts.mkdir(mode=0o700)
    if not attempts.resolve().is_relative_to(root):
        raise ControllerError("run attempts path escaped the run directory")
    attempt = attempts / _safe_id(attempt_id, "attempt ID")
    try:
        attempt.mkdir(mode=0o700)
    except FileExistsError as error:
        raise ControllerError(f"attempt directory already exists: {attempt}") from error
    if not attempt.resolve().is_relative_to(root):
        raise ControllerError("attempt directory escaped the run directory")
    return attempt


def _load_initial_context(
    contract_path: Path,
    preflight_path: Path,
    environment_path: Path,
    original_id: str,
) -> dict[str, Any]:
    contract_path = contract_path.resolve()
    preflight_path = preflight_path.resolve()
    environment_path = environment_path.resolve()
    contract = _load_json(contract_path, "workload contract")
    try:
        contract_values = gate.validate_contract(contract)
    except gate.GateInputError as error:
        raise ControllerError(f"invalid workload contract: {error}") from error
    preflight = _load_json(preflight_path, "preflight report")
    artifact = preflight.get("artifact")
    if not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str):
        raise ControllerError("preflight report has no original artifact")
    original = Path(artifact["path"])
    original_identity = _regular_identity(original, "original artifact")
    try:
        lineage._validate_preflight(
            preflight, contract, str(original_identity["sha256"])
        )
    except lineage.LineageError as error:
        raise ControllerError(str(error)) from error
    environment_identity = _regular_identity(environment_path, "environment manifest")
    if environment_identity["sha256"] != contract_values["environment_sha256"]:
        raise ControllerError("environment manifest does not match workload contract")
    return {
        "schema_version": contract_values["schema_version"],
        "adapter_protocol": PROTOCOLS[contract_values["schema_version"]],
        "record_policy": CONTROLLER_POLICIES[contract_values["schema_version"]],
        "mode": contract_values["mode"],
        "optimization_surface": contract_values["optimization_surface"],
        "target_arch": contract_values["target_arch"],
        "case_ids": contract_values["case_ids"],
        "contract": contract,
        "contract_values": contract_values,
        "contract_path": contract_path,
        "contract_sha256": gate.contract_digest(contract),
        "environment_path": environment_path,
        "environment_sha256": environment_identity["sha256"],
        "preflight_path": preflight_path,
        "preflight": preflight,
        "preflight_sha256": lineage._document_digest(preflight),
        "original_id": original_id,
        "original": original_identity,
        "parent_id": original_id,
        "parent": original_identity,
    }


def _load_candidate_context(state: Path, parent_id: str | None) -> dict[str, Any]:
    state = state.resolve()
    with lineage._state_lock(state, exclusive=False):
        document = lineage._load(state)
        contract = lineage._verify_contract(document)
        lineage._verify_environment(document, contract)
        lineage._verify_preflight(document, contract)
        lineage._verify_controller_baseline(document, contract)
        lineage._verify_controller_attempts(document)
        contract_values = gate.validate_contract(contract)
        expected_policy = CONTROLLER_POLICIES[contract_values["schema_version"]]
        if document.get("record_policy") != expected_policy:
            raise ControllerError(
                f"candidate controller requires a {expected_policy} baseline; reinitialize "
                "the run with controller.py init"
            )
        selected_parent = parent_id or str(document["best_id"])
        if selected_parent not in document["nodes"]:
            raise ControllerError("parent is not a verified lineage node")
        original_node = document["nodes"][document["original_id"]]
        parent_node = document["nodes"][selected_parent]
        lineage._verify_node_artifact(original_node, "original")
        lineage._verify_node_artifact(parent_node, "parent")
        return {
            "schema_version": contract_values["schema_version"],
            "adapter_protocol": PROTOCOLS[contract_values["schema_version"]],
            "record_policy": expected_policy,
            "state": state,
            "lineage": copy.deepcopy(document),
            "mode": contract_values["mode"],
            "optimization_surface": contract_values["optimization_surface"],
            "target_arch": contract_values["target_arch"],
            "case_ids": contract_values["case_ids"],
            "contract": contract,
            "contract_values": contract_values,
            "contract_path": Path(str(document["contract_path"])),
            "contract_sha256": str(document["contract_sha256"]),
            "environment_path": Path(str(document["environment_manifest_path"])),
            "environment_sha256": str(document["environment_sha256"]),
            "preflight_path": Path(str(document["preflight_path"])),
            "preflight": copy.deepcopy(document["preflight"]),
            "preflight_sha256": str(document["preflight_sha256"]),
            "original_id": str(document["original_id"]),
            "original": {
                "path": str(original_node["artifact_path"]),
                "sha256": str(original_node["artifact_sha256"]),
            },
            "parent_id": selected_parent,
            "parent": {
                "path": str(parent_node["artifact_path"]),
                "sha256": str(parent_node["artifact_sha256"]),
            },
        }


def _verify_frozen_context(
    context: dict[str, Any],
    *,
    proposal: dict[str, Any] | None = None,
    candidate: dict[str, Any] | None = None,
) -> None:
    contract = _load_json(Path(context["contract_path"]), "workload contract")
    if gate.contract_digest(contract) != context["contract_sha256"]:
        raise ControllerError("workload contract changed during controller execution")
    if _sha256(Path(context["environment_path"])) != context["environment_sha256"]:
        raise ControllerError(
            "environment manifest changed during controller execution"
        )
    preflight = _load_json(Path(context["preflight_path"]), "preflight report")
    if lineage._document_digest(preflight) != context["preflight_sha256"]:
        raise ControllerError("preflight report changed during controller execution")
    for label in ("original", "parent"):
        artifact = context[label]
        if _sha256(Path(artifact["path"])) != artifact["sha256"]:
            raise ControllerError(
                f"{label} artifact changed during controller execution"
            )
    capabilities = context["preflight"].get("capabilities")
    if not isinstance(capabilities, dict):
        raise ControllerError("preflight capability map is missing")
    for name in context["preflight"].get("required_capabilities", []):
        entry = capabilities.get(name)
        if not isinstance(entry, dict):
            raise ControllerError(f"preflight capability is missing: {name}")
        executable = Path(str(entry.get("resolved")))
        try:
            executable_metadata = executable.lstat()
        except OSError as error:
            raise ControllerError(f"adapter is unavailable: {name}: {error}") from error
        if (
            stat.S_ISLNK(executable_metadata.st_mode)
            or not stat.S_ISREG(executable_metadata.st_mode)
            or not os.access(executable, os.X_OK)
        ):
            raise ControllerError(f"adapter is no longer executable: {name}")
        if _sha256(executable) != entry.get("sha256"):
            raise ControllerError(f"adapter changed after preflight: {name}")
    tools = context["preflight"].get("tools", {})
    if not isinstance(tools, dict):
        raise ControllerError("preflight tool identity map is malformed")
    for name, entry in tools.items():
        if not isinstance(entry, dict) or entry.get("resolved") is None:
            continue
        executable = Path(str(entry.get("resolved")))
        try:
            metadata = executable.lstat()
        except OSError as error:
            raise ControllerError(
                f"backend tool is unavailable: {name}: {error}"
            ) from error
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or not os.access(executable, os.X_OK)
        ):
            raise ControllerError(f"backend tool is no longer executable: {name}")
        if _sha256(executable) != entry.get("sha256"):
            raise ControllerError(f"backend tool changed after preflight: {name}")
    if proposal is not None and _sha256(Path(proposal["path"])) != proposal["sha256"]:
        raise ControllerError("proposal snapshot changed during controller execution")
    if (
        candidate is not None
        and _sha256(Path(candidate["path"])) != candidate["sha256"]
    ):
        raise ControllerError("candidate artifact changed during controller execution")


def _binding(
    context: dict[str, Any],
    *,
    candidate_id: str,
    proposal_sha256: str,
    candidate_sha256: str | None,
    correctness_receipt_sha256: str | None = None,
) -> dict[str, Any]:
    binding = {
        "mode": context["mode"],
        "target_arch": context["target_arch"],
        "candidate_id": candidate_id,
        "parent_id": context["parent_id"],
        "original_id": context["original_id"],
        "contract_sha256": context["contract_sha256"],
        "environment_sha256": context["environment_sha256"],
        "preflight_sha256": context["preflight_sha256"],
        "original_sha256": context["original"]["sha256"],
        "parent_sha256": context["parent"]["sha256"],
        "proposal_sha256": proposal_sha256,
        "candidate_sha256": candidate_sha256,
        "case_ids": context["case_ids"],
        "correctness_receipt_sha256": correctness_receipt_sha256,
    }
    if context["schema_version"] == 2:
        binding["optimization_surface"] = context["optimization_surface"]
    return binding


def _adapter_entry(context: dict[str, Any], operation: str) -> dict[str, Any]:
    capabilities = context["preflight"].get("capabilities")
    entry = capabilities.get(operation) if isinstance(capabilities, dict) else None
    if not isinstance(entry, dict) or not isinstance(entry.get("resolved"), str):
        raise ControllerError(f"required adapter is unavailable: {operation}")
    executable = Path(entry["resolved"])
    try:
        metadata = executable.lstat()
    except OSError as error:
        raise ControllerError(
            f"required adapter is unavailable: {operation}: {error}"
        ) from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or not os.access(executable, os.X_OK)
    ):
        raise ControllerError(
            f"required adapter is not a regular executable: {operation}"
        )
    if _sha256(executable) != entry.get("sha256"):
        raise ControllerError(f"adapter changed after preflight: {operation}")
    return entry


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _run_bounded_process(
    command: list[str],
    *,
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout_seconds: float,
    max_output_bytes: int,
    operation: str,
) -> tuple[int, bool, str | None]:
    """Run one adapter with a wall-clock timeout and a per-stream byte cap."""
    _validate_limits(timeout_seconds, max_output_bytes)

    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:  # pragma: no cover
        _kill_process_group(process)
        process.wait()
        raise ControllerError("failed to capture adapter output")

    selector = selectors.DefaultSelector()
    timed_out = False
    failure: str | None = None
    deadline = time.monotonic() + timeout_seconds
    streams = {
        process.stdout: (stdout_path, "stdout"),
        process.stderr: (stderr_path, "stderr"),
    }
    output_files: dict[Any, Any] = {}
    return_code: int | None = None
    try:
        for stream, (path, label) in streams.items():
            output_file = path.open("xb")
            output_files[stream] = output_file
            selector.register(stream, selectors.EVENT_READ, (output_file, label))

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                failure = f"{operation} adapter timed out after {timeout_seconds:g}s"
                _kill_process_group(process)
                break
            events = selector.select(min(remaining, 0.1))
            for key, _ in events:
                output_file, label = key.data
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                available = max_output_bytes - output_file.tell()
                if len(chunk) > available:
                    if available > 0:
                        output_file.write(chunk[:available])
                    failure = (
                        f"{operation} adapter {label} exceeded {max_output_bytes} bytes"
                    )
                    _kill_process_group(process)
                    break
                output_file.write(chunk)
            if failure is not None:
                break
        if failure is None:
            remaining = deadline - time.monotonic()
            try:
                return_code = process.wait(timeout=max(remaining, 0.0))
            except subprocess.TimeoutExpired:
                timed_out = True
                failure = f"{operation} adapter timed out after {timeout_seconds:g}s"
                _kill_process_group(process)
                return_code = process.wait()
        else:
            _kill_process_group(process)
            return_code = process.wait()
    finally:
        if process.poll() is None:
            _kill_process_group(process)
            process.wait()
        for stream, output_file in output_files.items():
            try:
                selector.unregister(stream)
            except (KeyError, ValueError):
                pass
            try:
                stream.close()
            except OSError:
                pass
            output_file.flush()
            os.fsync(output_file.fileno())
            output_file.close()
        selector.close()
    if return_code is None:  # pragma: no cover - guarded by the cleanup above
        return_code = process.returncode
    return return_code, timed_out, failure


def _invoke_adapter(
    context: dict[str, Any],
    *,
    attempt_directory: Path,
    operation: str,
    purpose: str,
    binding: dict[str, Any],
    inputs: dict[str, Any],
    outputs: dict[str, Any],
    evidence: list[dict[str, Any]],
    timeout_seconds: float,
    max_output_bytes: int,
) -> dict[str, Any]:
    entry = _adapter_entry(context, operation)
    executable = Path(entry["resolved"])
    phase_directory = attempt_directory / f"{len(evidence) + 1:02d}-{operation}"
    phase_directory.mkdir(mode=0o700)
    request_id = secrets.token_hex(16)
    request = {
        "schema_version": context["schema_version"],
        "protocol": context["adapter_protocol"],
        "request_id": request_id,
        "operation": operation,
        "purpose": purpose,
        "binding": binding,
        "contract": {
            "path": str(context["contract_path"]),
            "case_ids": context["case_ids"],
        },
        "artifacts": {
            "original": context["original"],
            "parent": context["parent"],
        },
        "inputs": inputs,
        "outputs": outputs,
        "attempt_directory": str(attempt_directory),
    }
    request_path = phase_directory / "request.json"
    stdout_path = phase_directory / "stdout.json"
    stderr_path = phase_directory / "stderr.log"
    _atomic_write_json(request_path, request)
    started_at = _now()
    return_code, timed_out, failure = _run_bounded_process(
        [str(executable), "--request", str(request_path)],
        cwd=attempt_directory,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        operation=operation,
    )
    ended_at = _now()
    if _sha256(executable) != entry.get("sha256"):
        failure = f"{operation} adapter changed while executing"
    response: dict[str, Any] | None = None
    if failure is None and return_code != 0:
        failure = f"{operation} adapter exited with status {return_code}"
    if failure is None:
        try:
            response = _strict_json_bytes(
                stdout_path.read_bytes(), f"{operation} adapter response"
            )
            if (
                response.get("schema_version") != context["schema_version"]
                or response.get("protocol") != context["adapter_protocol"]
                or response.get("request_id") != request_id
                or response.get("operation") != operation
                or response.get("binding") != binding
                or not isinstance(response.get("ok"), bool)
            ):
                raise ControllerError(
                    f"{operation} adapter response does not echo the frozen request"
                )
            if response["ok"] is not True:
                raw_error = response.get("error", "adapter rejected the phase")
                failure = str(raw_error)
        except (OSError, ControllerError) as error:
            failure = str(error)
    record = {
        "operation": operation,
        "purpose": purpose,
        "request_id": request_id,
        "adapter_path": str(executable),
        "adapter_sha256": entry["sha256"],
        "request_path": str(request_path),
        "request_sha256": _sha256(request_path),
        "stdout_path": str(stdout_path),
        "stdout_sha256": _sha256(stdout_path),
        "stderr_path": str(stderr_path),
        "stderr_sha256": _sha256(stderr_path),
        "return_code": return_code,
        "timed_out": timed_out,
        "started_at": started_at,
        "ended_at": ended_at,
        "ok": failure is None,
        "failure": failure,
    }
    evidence.append(record)
    return {"ok": failure is None, "failure": failure, "response": response}


def _require_adapter_output(
    response: dict[str, Any],
    path: Path,
    label: str,
    attempt_directory: Path,
    protected: list[Path],
) -> dict[str, Any]:
    identity = _regular_identity(
        path,
        label,
        within=attempt_directory,
        protected=protected,
    )
    if response.get("output_sha256") != identity["sha256"]:
        raise ControllerError(f"{label} hash does not match the adapter response")
    return identity


def _verify_identity(
    identity: dict[str, Any], label: str, attempt_directory: Path
) -> None:
    current = _regular_identity(
        Path(str(identity.get("path"))), label, within=attempt_directory
    )
    if current != identity:
        raise ControllerError(f"{label} changed after adapter output validation")


def _failure_cases(case_ids: list[str]) -> dict[str, Any]:
    return {
        "cases": [{"case_id": case_id, "runtime_ok": False} for case_id in case_ids]
    }


def _equivalence_from(result: dict[str, Any]) -> dict[str, Any]:
    response = result.get("response")
    equivalence = response.get("equivalence") if isinstance(response, dict) else None
    if not isinstance(equivalence, dict) or not isinstance(
        equivalence.get("cases"), list
    ):
        raise ControllerError("correctness adapter omitted equivalence cases")
    return equivalence


def _load_asm_profile_evidence(
    path: Path,
    *,
    context: dict[str, Any],
    artifact_sha256: str,
    within: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    identity = _regular_identity(path, "profile evidence", within=within)
    document = _load_json(Path(identity["path"]), "profile evidence")
    if _sha256(Path(identity["path"])) != identity["sha256"]:
        raise ControllerError("profile evidence changed while it was being loaded")
    try:
        amdgcn_assembly.validate_profile_evidence(
            document,
            artifact_sha256=artifact_sha256,
            target_arch=context["target_arch"],
            contract_sha256=context["contract_sha256"],
            environment_sha256=context["environment_sha256"],
        )
    except backend_common.BackendContractError as error:
        raise ControllerError(str(error)) from error
    return identity, document


def _asm_static_passed(result: dict[str, Any]) -> bool:
    response = result.get("response")
    return bool(
        result.get("ok")
        and isinstance(response, dict)
        and response.get("abi_consistent") is True
        and response.get("resource_consistent") is True
    )


def _asm_disassembly_claim(result: dict[str, Any]) -> tuple[str, bool, bool]:
    response = result.get("response")
    if not result.get("ok") or not isinstance(response, dict):
        raise ControllerError("ASM disassembly adapter failed")
    artifact_kind = response.get("artifact_kind")
    diff = response.get("instruction_diff")
    if artifact_kind not in amdgcn_assembly.CODE_OBJECT_KINDS:
        raise ControllerError("ASM disassembly did not identify a code object")
    if not isinstance(diff, dict):
        raise ControllerError("ASM disassembly omitted the normalized instruction diff")
    return (
        artifact_kind,
        diff.get("nonempty") is True,
        diff.get("within_declared_windows") is True,
    )


def _evaluation(
    context: dict[str, Any],
    *,
    candidate_id: str,
    proposal_sha256: str,
    candidate_sha256: str | None,
    checks: dict[str, Any],
    equivalence: dict[str, Any] | None,
    timing: dict[str, Any] | None,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": context["schema_version"],
        "candidate_id": candidate_id,
        "parent_id": context["parent_id"],
        "original_id": context["original_id"],
        "mode": context["mode"],
        "proposal_sha256": proposal_sha256,
        "contract": copy.deepcopy(context["contract"]),
        "artifacts": {
            "original_sha256": context["original"]["sha256"],
            "parent_sha256": context["parent"]["sha256"],
            "candidate_sha256": candidate_sha256,
        },
        "checks": checks,
    }
    if context["schema_version"] == 2:
        document["optimization_surface"] = context["optimization_surface"]
    if equivalence is not None:
        document["equivalence"] = equivalence
    if timing is not None:
        document["timing"] = timing
    if provenance is not None:
        document["provenance"] = provenance
    return document


def _correctness_receipt(
    context: dict[str, Any],
    evaluation: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    artifacts = evaluation["artifacts"]
    receipt = {
        "schema_version": context["schema_version"],
        "kind": f"asmevo.correctness-receipt.v{context['schema_version']}",
        "status": "correctness_passed",
        "bindings": {
            "candidate_id": evaluation["candidate_id"],
            "parent_id": evaluation["parent_id"],
            "original_id": evaluation["original_id"],
            "mode": evaluation["mode"],
            "target_arch": context["target_arch"],
            "contract_sha256": context["contract_sha256"],
            "environment_sha256": context["environment_sha256"],
            "preflight_sha256": context["preflight_sha256"],
            "proposal_sha256": evaluation["proposal_sha256"],
            "original_sha256": artifacts["original_sha256"],
            "parent_sha256": artifacts["parent_sha256"],
            "candidate_sha256": artifacts["candidate_sha256"],
            "case_ids": context["case_ids"],
        },
        "checks": copy.deepcopy(evaluation["checks"]),
        "equivalence": copy.deepcopy(evaluation["equivalence"]),
        "phase_evidence": copy.deepcopy(evidence),
        "issued_at": _now(),
    }
    if context["schema_version"] == 2:
        receipt["bindings"]["optimization_surface"] = context["optimization_surface"]
    return receipt


def _correctness_probe(evaluation: dict[str, Any]) -> None:
    try:
        decision = gate.evaluate(evaluation)
    except gate.GateInputError as error:
        raise ControllerError(f"invalid correctness evidence: {error}") from error
    if decision["status"] != "timing_invalid":
        raise ControllerError(
            f"correctness prefix did not pass: {decision['status']}: "
            + "; ".join(decision.get("reasons", []))
        )


def _validate_baseline_samples(
    samples: Any, contract_values: dict[str, Any]
) -> tuple[list[float], float, float]:
    if (
        not isinstance(samples, list)
        or len(samples) < contract_values["minimum_samples"]
    ):
        raise ControllerError("baseline benchmark returned too few raw samples")
    normalized: list[float] = []
    for sample in samples:
        if isinstance(sample, bool) or not isinstance(sample, (int, float)):
            raise ControllerError("baseline timing samples must be numeric")
        value = float(sample)
        if not math.isfinite(value) or value <= 0:
            raise ControllerError("baseline timing samples must be positive and finite")
        normalized.append(value)
    mean = statistics.fmean(normalized)
    cv = statistics.pstdev(normalized) / mean
    if cv > contract_values["maximum_cv"]:
        raise ControllerError(
            f"baseline CV {cv:.6f} exceeds {contract_values['maximum_cv']:.6f}"
        )
    return normalized, statistics.median(normalized), cv


def _record_candidate(
    context: dict[str, Any],
    *,
    attempt_directory: Path,
    evaluation: dict[str, Any],
    candidate: Path | None,
    edit_summary: str,
    changed_windows: list[str],
) -> dict[str, Any]:
    evaluation_path = attempt_directory / "evaluation.json"
    _atomic_write_json(evaluation_path, evaluation)
    try:
        result = lineage.record(
            context["state"],
            evaluation_path,
            candidate,
            edit_summary,
            changed_windows,
            _controller_token=lineage._CONTROLLER_TOKEN,
        )
    except lineage.LineageError as error:
        raise ControllerError(str(error)) from error
    decision_path = attempt_directory / "decision.json"
    result["evaluation_path"] = str(evaluation_path)
    try:
        _atomic_write_json(decision_path, result["decision"])
    except OSError as error:
        result["decision_path"] = None
        result["warning"] = (
            "lineage commit succeeded, but the derived decision file could not be "
            f"written: {error}"
        )
    else:
        result["decision_path"] = str(decision_path)
    return result


def initialize_run(
    *,
    state: Path,
    run_dir: Path,
    original_id: str,
    contract_path: Path,
    preflight_path: Path,
    environment_manifest_path: Path,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> dict[str, Any]:
    _validate_limits(timeout_seconds, max_output_bytes)
    original_id = _safe_id(original_id, "original ID")
    if state.resolve().exists():
        raise ControllerError(f"lineage already exists: {state.resolve()}")
    context = _load_initial_context(
        contract_path, preflight_path, environment_manifest_path, original_id
    )
    attempt = _new_attempt_directory(run_dir, f"baseline-{original_id}")
    evidence: list[dict[str, Any]] = []
    original_path = Path(context["original"]["path"])
    proposal_sha256 = context["original"]["sha256"]
    candidate_identity = context["original"]
    candidate_id = original_id
    protected = [original_path]

    if context["mode"] == "binary":
        recovered_path = attempt / "recovered.json"
        binding = _binding(
            context,
            candidate_id=candidate_id,
            proposal_sha256=proposal_sha256,
            candidate_sha256=context["original"]["sha256"],
        )
        recover = _invoke_adapter(
            context,
            attempt_directory=attempt,
            operation="recover",
            purpose="baseline",
            binding=binding,
            inputs={},
            outputs={"recovered": str(recovered_path)},
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if not recover["ok"]:
            raise ControllerError(f"binary recovery failed: {recover['failure']}")
        recovered = _require_adapter_output(
            recover["response"],
            recovered_path,
            "recovered representation",
            attempt,
            protected,
        )
        roundtrip_path = attempt / "roundtrip.artifact"
        rebuild = _invoke_adapter(
            context,
            attempt_directory=attempt,
            operation="rebuild",
            purpose="baseline-roundtrip",
            binding=binding,
            inputs={"recovered": recovered},
            outputs={"candidate_artifact": str(roundtrip_path)},
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if not rebuild["ok"]:
            raise ControllerError(
                f"binary round-trip rebuild failed: {rebuild['failure']}"
            )
        candidate_identity = _regular_identity(
            roundtrip_path,
            "round-trip artifact",
            within=attempt,
            protected=protected,
        )
        if rebuild["response"].get("candidate_sha256") != candidate_identity["sha256"]:
            raise ControllerError(
                "round-trip artifact hash does not match rebuild response"
            )
        candidate_id = f"{original_id}-roundtrip"
        binding = _binding(
            context,
            candidate_id=candidate_id,
            proposal_sha256=proposal_sha256,
            candidate_sha256=candidate_identity["sha256"],
        )
        for operation in ("roundtrip", "static_check"):
            result = _invoke_adapter(
                context,
                attempt_directory=attempt,
                operation=operation,
                purpose="baseline-roundtrip",
                binding=binding,
                inputs={"candidate_artifact": candidate_identity},
                outputs={},
                evidence=evidence,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
            )
            if not result["ok"]:
                raise ControllerError(f"{operation} failed: {result['failure']}")

        oracle_path = attempt / "oracle-observations.json"
        oracle = _invoke_adapter(
            context,
            attempt_directory=attempt,
            operation="oracle",
            purpose="baseline",
            binding=binding,
            inputs={"oracle_artifact": context["original"]},
            outputs={"observations": str(oracle_path)},
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if not oracle["ok"]:
            raise ControllerError(f"baseline oracle failed: {oracle['failure']}")
        oracle_identity = _require_adapter_output(
            oracle["response"], oracle_path, "oracle observations", attempt, protected
        )
        replay_path = attempt / "roundtrip-observations.json"
        replay = _invoke_adapter(
            context,
            attempt_directory=attempt,
            operation="replay",
            purpose="baseline-roundtrip",
            binding=binding,
            inputs={"candidate_artifact": candidate_identity},
            outputs={"observations": str(replay_path)},
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if not replay["ok"]:
            raise ControllerError(f"round-trip replay failed: {replay['failure']}")
        replay_identity = _require_adapter_output(
            replay["response"],
            replay_path,
            "round-trip observations",
            attempt,
            protected,
        )
        _verify_identity(oracle_identity, "oracle observations", attempt)
        _verify_identity(replay_identity, "round-trip observations", attempt)
        compare = _invoke_adapter(
            context,
            attempt_directory=attempt,
            operation="compare",
            purpose="baseline-roundtrip",
            binding=binding,
            inputs={"oracle": oracle_identity, "candidate": replay_identity},
            outputs={},
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if not compare["ok"]:
            raise ControllerError(f"round-trip comparison failed: {compare['failure']}")
        _verify_identity(oracle_identity, "oracle observations", attempt)
        _verify_identity(replay_identity, "round-trip observations", attempt)
        equivalence = _equivalence_from(compare)
        checks = {
            "build": {"passed": True, "evidence": evidence[1]},
            "static_consistency": {
                "required": True,
                "passed": True,
                "evidence": evidence[3],
            },
        }
    elif context["optimization_surface"] == "amdgcn_assembly":
        binding = _binding(
            context,
            candidate_id=candidate_id,
            proposal_sha256=proposal_sha256,
            candidate_sha256=candidate_identity["sha256"],
        )
        disassembly_path = attempt / "baseline-disassembly.json"
        disassembly = _invoke_adapter(
            context,
            attempt_directory=attempt,
            operation="disassemble",
            purpose="baseline",
            binding=binding,
            inputs={"candidate_artifact": candidate_identity},
            outputs={"disassembly_evidence": str(disassembly_path)},
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if not disassembly["ok"]:
            raise ControllerError(
                f"baseline disassembly failed: {disassembly['failure']}"
            )
        _require_adapter_output(
            disassembly["response"],
            disassembly_path,
            "baseline disassembly evidence",
            attempt,
            protected,
        )
        disassembly_response = disassembly["response"]
        artifact_kind = (
            disassembly_response.get("artifact_kind")
            if isinstance(disassembly_response, dict)
            else None
        )
        if artifact_kind not in amdgcn_assembly.CODE_OBJECT_KINDS:
            raise ControllerError("baseline artifact is not a code object")
        static_result = _invoke_adapter(
            context,
            attempt_directory=attempt,
            operation="static_check",
            purpose="baseline",
            binding=binding,
            inputs={"candidate_artifact": candidate_identity},
            outputs={},
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if not _asm_static_passed(static_result):
            raise ControllerError("baseline ASM ABI/resource check failed")
        native_load = _invoke_adapter(
            context,
            attempt_directory=attempt,
            operation="native_load",
            purpose="baseline",
            binding=binding,
            inputs={"candidate_artifact": candidate_identity},
            outputs={},
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if not native_load["ok"]:
            raise ControllerError(
                f"baseline native load failed: {native_load['failure']}"
            )
        oracle = _invoke_adapter(
            context,
            attempt_directory=attempt,
            operation="oracle",
            purpose="baseline",
            binding=binding,
            inputs={"candidate_artifact": candidate_identity},
            outputs={},
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if not oracle["ok"]:
            raise ControllerError(f"baseline oracle failed: {oracle['failure']}")
        equivalence = _equivalence_from(oracle)
        checks = {
            "build": {"passed": True, "evidence": "frozen original code object"},
            "static_consistency": {
                "required": True,
                "passed": True,
                "evidence": evidence[1],
            },
            "asm_provenance": {
                "artifact_kind": artifact_kind,
                "native_load_passed": True,
                "profile_capture_passed": False,
                "profile_evidence_sha256": "0" * 64,
            },
        }
        correctness_only = _evaluation(
            context,
            candidate_id=candidate_id,
            proposal_sha256=proposal_sha256,
            candidate_sha256=candidate_identity["sha256"],
            checks=checks,
            equivalence=equivalence,
            timing={"valid": False, "invalid_reason": "profile not authorized yet"},
            provenance=None,
        )
        _correctness_probe(correctness_only)
    else:
        binding = _binding(
            context,
            candidate_id=candidate_id,
            proposal_sha256=proposal_sha256,
            candidate_sha256=candidate_identity["sha256"],
        )
        oracle = _invoke_adapter(
            context,
            attempt_directory=attempt,
            operation="oracle",
            purpose="baseline",
            binding=binding,
            inputs={"candidate_artifact": candidate_identity},
            outputs={},
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if not oracle["ok"]:
            raise ControllerError(f"baseline oracle failed: {oracle['failure']}")
        equivalence = _equivalence_from(oracle)
        checks = {
            "build": {"passed": True, "evidence": "frozen original artifact"},
            "static_consistency": {
                "required": False,
                "passed": True,
                "evidence": "not required in source mode",
            },
        }

    probe = _evaluation(
        context,
        candidate_id=candidate_id,
        proposal_sha256=proposal_sha256,
        candidate_sha256=candidate_identity["sha256"],
        checks=checks,
        equivalence=equivalence,
        timing={"valid": False, "invalid_reason": "benchmark not authorized yet"},
        provenance=None,
    )
    _correctness_probe(probe)
    receipt = _correctness_receipt(context, probe, evidence)
    receipt_path = attempt / "correctness-receipt.json"
    _atomic_write_json(receipt_path, receipt)
    receipt_sha256 = _document_digest(receipt)
    _verify_frozen_context(context, candidate=candidate_identity)
    benchmark_binding = _binding(
        context,
        candidate_id=candidate_id,
        proposal_sha256=proposal_sha256,
        candidate_sha256=candidate_identity["sha256"],
        correctness_receipt_sha256=receipt_sha256,
    )
    benchmark = _invoke_adapter(
        context,
        attempt_directory=attempt,
        operation="benchmark",
        purpose="baseline",
        binding=benchmark_binding,
        inputs={
            "measure_artifacts": {"original": context["original"]},
            "correctness_receipt": {
                "path": str(receipt_path),
                "sha256": receipt_sha256,
            },
        },
        outputs={},
        evidence=evidence,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
    if not benchmark["ok"]:
        raise ControllerError(f"baseline benchmark failed: {benchmark['failure']}")
    response = benchmark["response"]
    samples, median, cv = _validate_baseline_samples(
        response.get("samples_ms") if isinstance(response, dict) else None,
        context["contract_values"],
    )
    _verify_frozen_context(context, candidate=candidate_identity)
    baseline_profile_identity: dict[str, Any] | None = None
    if context["optimization_surface"] == "amdgcn_assembly":
        profile_path = attempt / "baseline-profile.json"
        profile = _invoke_adapter(
            context,
            attempt_directory=attempt,
            operation="profile",
            purpose="baseline-after-benchmark",
            binding=binding,
            inputs={"candidate_artifact": candidate_identity},
            outputs={"profile_evidence": str(profile_path)},
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if not profile["ok"]:
            raise ControllerError(f"baseline profile failed: {profile['failure']}")
        baseline_profile_identity = _require_adapter_output(
            profile["response"],
            profile_path,
            "baseline profile evidence",
            attempt,
            protected,
        )
        _load_asm_profile_evidence(
            profile_path,
            context=context,
            artifact_sha256=candidate_identity["sha256"],
            within=attempt,
        )
        _verify_frozen_context(context, candidate=candidate_identity)
    baseline_receipt = {
        "schema_version": context["schema_version"],
        "kind": f"asmevo.baseline-receipt.v{context['schema_version']}",
        "status": "verified",
        "bindings": {
            "original_id": original_id,
            "mode": context["mode"],
            "target_arch": context["target_arch"],
            "contract_sha256": context["contract_sha256"],
            "environment_sha256": context["environment_sha256"],
            "preflight_sha256": context["preflight_sha256"],
            "original_sha256": context["original"]["sha256"],
            "case_ids": context["case_ids"],
        },
        "correctness_receipt_sha256": receipt_sha256,
        "correctness_receipt": receipt,
        "timing": {"samples_ms": samples, "median_ms": median, "cv": cv},
        "phase_evidence": evidence,
        "issued_at": _now(),
    }
    if baseline_profile_identity is not None:
        baseline_receipt["post_benchmark_profile"] = {
            "captured": True,
            "profile_evidence_sha256": baseline_profile_identity["sha256"],
        }
    if context["schema_version"] == 2:
        baseline_receipt["bindings"]["optimization_surface"] = context[
            "optimization_surface"
        ]
    baseline_receipt_path = attempt / "baseline-receipt.json"
    _atomic_write_json(baseline_receipt_path, baseline_receipt)
    try:
        initialized = lineage.initialize(
            state,
            original_id,
            original_path,
            median,
            Path(context["contract_path"]),
            Path(context["preflight_path"]),
            Path(context["environment_path"]),
            baseline_receipt_path,
            _controller_token=lineage._CONTROLLER_TOKEN,
        )
    except lineage.LineageError as error:
        raise ControllerError(str(error)) from error
    result = {
        "initialized": True,
        "status": "baseline_verified",
        "record_policy": initialized["record_policy"],
        "state": str(state.resolve()),
        "baseline_receipt": str(baseline_receipt_path),
        "baseline_receipt_sha256": _document_digest(baseline_receipt),
        "baseline_median_ms": median,
    }
    if baseline_profile_identity is not None:
        result["baseline_profile"] = baseline_profile_identity["path"]
        result["baseline_profile_sha256"] = baseline_profile_identity["sha256"]
    return result


def evaluate_candidate(
    *,
    state: Path,
    run_dir: Path,
    candidate_id: str,
    proposal_path: Path,
    edit_summary: str,
    changed_windows: list[str],
    parent_id: str | None = None,
    artifact_name: str = "candidate.artifact",
    profile_evidence_path: Path | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> dict[str, Any]:
    _validate_limits(timeout_seconds, max_output_bytes)
    candidate_id = _safe_id(candidate_id, "candidate ID")
    if not edit_summary.strip():
        raise ControllerError("edit summary must not be empty")
    context = _load_candidate_context(state, parent_id)
    asm_surface = context["optimization_surface"] == "amdgcn_assembly"
    if asm_surface and artifact_name == "candidate.artifact":
        artifact_name = "candidate.hsaco"
    artifact_name = _safe_artifact_name(artifact_name)
    asm_proposal: dict[str, Any] | None = None
    raw_asm_proposal: dict[str, Any] | None = None
    asm_source_path: Path | None = None
    asm_source_identity: dict[str, Any] | None = None
    parent_profile_identity: dict[str, Any] | None = None
    if asm_surface:
        if profile_evidence_path is None:
            raise ControllerError(
                "amdgcn_assembly candidates require --profile-evidence"
            )
        parent_profile_identity, _ = _load_asm_profile_evidence(
            profile_evidence_path,
            context=context,
            artifact_sha256=context["parent"]["sha256"],
        )
        raw_asm_proposal = _load_json(proposal_path.resolve(), "ASM proposal")
        try:
            asm_proposal = amdgcn_assembly.validate_proposal(
                raw_asm_proposal,
                parent_sha256=context["parent"]["sha256"],
                profile_evidence_sha256=parent_profile_identity["sha256"],
            )
        except backend_common.BackendContractError as error:
            raise ControllerError(str(error)) from error
        asm_source_path = Path(asm_proposal["source_path"])
        if not asm_source_path.is_absolute():
            asm_source_path = proposal_path.resolve().parent / asm_source_path
        asm_source_identity = _regular_identity(asm_source_path, "ASM candidate source")
        proposal_windows = [
            f"{window['start_pc']}:{window['end_pc']}"
            for window in asm_proposal["edited_windows"]
        ]
        if changed_windows and changed_windows != proposal_windows:
            raise ControllerError(
                "--changed-window values do not match the ASM proposal"
            )
        changed_windows = proposal_windows
    if candidate_id in context["lineage"]["nodes"] or any(
        attempt.get("candidate_id") == candidate_id
        for attempt in context["lineage"]["attempts"]
    ):
        raise ControllerError(f"candidate ID already exists: {candidate_id}")
    attempt = _new_attempt_directory(run_dir, candidate_id)
    proposal = _snapshot_proposal(proposal_path, attempt / "proposal.snapshot")
    asm_source: dict[str, Any] | None = None
    parent_profile: dict[str, Any] | None = None
    if asm_surface:
        assert asm_source_path is not None
        assert asm_source_identity is not None
        assert parent_profile_identity is not None
        assert raw_asm_proposal is not None
        if (
            _load_json(Path(proposal["path"]), "ASM proposal snapshot")
            != raw_asm_proposal
        ):
            raise ControllerError("ASM proposal changed while it was being snapshotted")
        asm_source = _snapshot_proposal(asm_source_path, attempt / "candidate.s")
        if asm_source["sha256"] != asm_source_identity["sha256"]:
            raise ControllerError(
                "ASM candidate source changed while it was being snapshotted"
            )
        parent_profile = _snapshot_proposal(
            Path(parent_profile_identity["path"]),
            attempt / "parent-profile.snapshot.json",
        )
        if parent_profile["sha256"] != parent_profile_identity["sha256"]:
            raise ControllerError(
                "parent profile evidence changed while it was being snapshotted"
            )
    if any(
        node.get("proposal_sha256") == proposal["sha256"]
        for node in context["lineage"]["nodes"].values()
    ) or any(
        prior.get("proposal_sha256") == proposal["sha256"]
        for prior in context["lineage"]["attempts"]
    ):
        raise ControllerError("proposal was already evaluated in this lineage")
    _verify_frozen_context(context, proposal=proposal)
    evidence: list[dict[str, Any]] = []
    artifact_directory = attempt / "artifacts"
    artifact_directory.mkdir(mode=0o700)
    candidate_path = artifact_directory / artifact_name
    build_operation = "build" if context["mode"] == "source" else "rebuild"
    initial_binding = _binding(
        context,
        candidate_id=candidate_id,
        proposal_sha256=proposal["sha256"],
        candidate_sha256=None,
    )
    build_inputs: dict[str, Any] = {"proposal": proposal}
    if asm_surface:
        build_inputs.update(
            {
                "candidate_source": asm_source,
                "parent_profile_evidence": parent_profile,
            }
        )
    build = _invoke_adapter(
        context,
        attempt_directory=attempt,
        operation=build_operation,
        purpose="candidate",
        binding=initial_binding,
        inputs=build_inputs,
        outputs={"candidate_artifact": str(candidate_path)},
        evidence=evidence,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
    if not build["ok"]:
        evaluation = _evaluation(
            context,
            candidate_id=candidate_id,
            proposal_sha256=proposal["sha256"],
            candidate_sha256=None,
            checks={
                "build": {"passed": False, "evidence": evidence[-1]},
            },
            equivalence=None,
            timing=None,
            provenance={
                "schema_version": context["schema_version"],
                "producer": "asmevo-controller",
                "record_policy": context["record_policy"],
                "stage": "correctness_rejected",
                "phase_evidence": evidence,
            },
        )
        return _record_candidate(
            context,
            attempt_directory=attempt,
            evaluation=evaluation,
            candidate=None,
            edit_summary=edit_summary,
            changed_windows=changed_windows,
        )
    protected = [Path(context["original"]["path"]), Path(context["parent"]["path"])]
    candidate = _regular_identity(
        candidate_path,
        "candidate artifact",
        within=attempt,
        protected=protected,
    )
    response = build["response"]
    if response.get("candidate_sha256") != candidate["sha256"]:
        raise ControllerError("candidate hash does not match build adapter response")
    asm_build_claim: dict[str, Any] | None = None
    if asm_surface:
        try:
            asm_build_claim = amdgcn_assembly.validate_build_claim(response)
        except backend_common.BackendContractError as error:
            raise ControllerError(str(error)) from error
    _verify_frozen_context(context, proposal=proposal, candidate=candidate)
    binding = _binding(
        context,
        candidate_id=candidate_id,
        proposal_sha256=proposal["sha256"],
        candidate_sha256=candidate["sha256"],
    )
    checks: dict[str, Any] = {
        "build": {"passed": True, "evidence": evidence[-1]},
        "static_consistency": {
            "required": context["mode"] == "binary",
            "passed": True,
            "evidence": "not required in source mode",
        },
    }
    if asm_surface:
        disassembly_path = attempt / "candidate-disassembly.json"
        disassembly = _invoke_adapter(
            context,
            attempt_directory=attempt,
            operation="disassemble",
            purpose="candidate",
            binding=binding,
            inputs={
                "candidate_artifact": candidate,
                "parent_artifact": context["parent"],
                "proposal": proposal,
            },
            outputs={"disassembly_evidence": str(disassembly_path)},
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if not disassembly["ok"]:
            raise ControllerError(
                f"candidate disassembly failed: {disassembly['failure']}"
            )
        _require_adapter_output(
            disassembly["response"],
            disassembly_path,
            "candidate disassembly evidence",
            attempt,
            protected,
        )
        artifact_kind, diff_nonempty, diff_in_windows = _asm_disassembly_claim(
            disassembly
        )
        if asm_build_claim is None or artifact_kind != asm_build_claim["artifact_kind"]:
            raise ControllerError("build and disassembly disagree on artifact kind")
        static_result = _invoke_adapter(
            context,
            attempt_directory=attempt,
            operation="static_check",
            purpose="candidate",
            binding=binding,
            inputs={
                "candidate_artifact": candidate,
                "parent_artifact": context["parent"],
                "disassembly_evidence": _regular_identity(
                    disassembly_path,
                    "candidate disassembly evidence",
                    within=attempt,
                ),
            },
            outputs={},
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        static_passed = _asm_static_passed(static_result)
        checks["static_consistency"] = {
            "required": True,
            "passed": static_passed,
            "evidence": evidence[-1],
        }
        checks["asm_provenance"] = {
            **asm_build_claim,
            "profile_evidence_sha256": parent_profile["sha256"],
            "instruction_diff_nonempty": diff_nonempty,
            "diff_within_declared_windows": diff_in_windows,
            "native_load_passed": False,
            "profile_capture_passed": False,
        }
        if not static_passed:
            evaluation = _evaluation(
                context,
                candidate_id=candidate_id,
                proposal_sha256=proposal["sha256"],
                candidate_sha256=candidate["sha256"],
                checks=checks,
                equivalence=None,
                timing=None,
                provenance={
                    "schema_version": context["schema_version"],
                    "producer": "asmevo-controller",
                    "record_policy": context["record_policy"],
                    "stage": "correctness_rejected",
                    "phase_evidence": evidence,
                },
            )
            return _record_candidate(
                context,
                attempt_directory=attempt,
                evaluation=evaluation,
                candidate=candidate_path,
                edit_summary=edit_summary,
                changed_windows=changed_windows,
            )
        native_load = _invoke_adapter(
            context,
            attempt_directory=attempt,
            operation="native_load",
            purpose="candidate",
            binding=binding,
            inputs={"candidate_artifact": candidate},
            outputs={},
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        checks["asm_provenance"]["native_load_passed"] = native_load["ok"]
        if not native_load["ok"]:
            evaluation = _evaluation(
                context,
                candidate_id=candidate_id,
                proposal_sha256=proposal["sha256"],
                candidate_sha256=candidate["sha256"],
                checks=checks,
                equivalence=None,
                timing=None,
                provenance={
                    "schema_version": context["schema_version"],
                    "producer": "asmevo-controller",
                    "record_policy": context["record_policy"],
                    "stage": "correctness_rejected",
                    "phase_evidence": evidence,
                },
            )
            return _record_candidate(
                context,
                attempt_directory=attempt,
                evaluation=evaluation,
                candidate=candidate_path,
                edit_summary=edit_summary,
                changed_windows=changed_windows,
            )
        _verify_frozen_context(context, proposal=proposal, candidate=candidate)
    elif context["mode"] == "binary":
        static_result = _invoke_adapter(
            context,
            attempt_directory=attempt,
            operation="static_check",
            purpose="candidate",
            binding=binding,
            inputs={"candidate_artifact": candidate},
            outputs={},
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        checks["static_consistency"] = {
            "required": True,
            "passed": static_result["ok"],
            "evidence": evidence[-1],
        }
        if not static_result["ok"]:
            evaluation = _evaluation(
                context,
                candidate_id=candidate_id,
                proposal_sha256=proposal["sha256"],
                candidate_sha256=candidate["sha256"],
                checks=checks,
                equivalence=None,
                timing=None,
                provenance={
                    "schema_version": context["schema_version"],
                    "producer": "asmevo-controller",
                    "record_policy": context["record_policy"],
                    "stage": "correctness_rejected",
                    "phase_evidence": evidence,
                },
            )
            return _record_candidate(
                context,
                attempt_directory=attempt,
                evaluation=evaluation,
                candidate=candidate_path,
                edit_summary=edit_summary,
                changed_windows=changed_windows,
            )
        _verify_frozen_context(context, proposal=proposal, candidate=candidate)

    if context["mode"] == "source":
        correctness_result = _invoke_adapter(
            context,
            attempt_directory=attempt,
            operation="oracle",
            purpose="candidate",
            binding=binding,
            inputs={"candidate_artifact": candidate},
            outputs={},
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        equivalence = (
            _equivalence_from(correctness_result)
            if correctness_result["ok"]
            else _failure_cases(context["case_ids"])
        )
    else:
        oracle_path = attempt / "oracle-observations.json"
        oracle = _invoke_adapter(
            context,
            attempt_directory=attempt,
            operation="oracle",
            purpose="candidate",
            binding=binding,
            inputs={"oracle_artifact": context["original"]},
            outputs={"observations": str(oracle_path)},
            evidence=evidence,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if not oracle["ok"]:
            correctness_result = oracle
            equivalence = _failure_cases(context["case_ids"])
        else:
            oracle_identity = _require_adapter_output(
                oracle["response"],
                oracle_path,
                "oracle observations",
                attempt,
                protected,
            )
            replay_path = attempt / "candidate-observations.json"
            replay = _invoke_adapter(
                context,
                attempt_directory=attempt,
                operation="replay",
                purpose="candidate",
                binding=binding,
                inputs={"candidate_artifact": candidate},
                outputs={"observations": str(replay_path)},
                evidence=evidence,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
            )
            if not replay["ok"]:
                correctness_result = replay
                equivalence = _failure_cases(context["case_ids"])
            else:
                replay_identity = _require_adapter_output(
                    replay["response"],
                    replay_path,
                    "candidate observations",
                    attempt,
                    protected,
                )
                _verify_identity(oracle_identity, "oracle observations", attempt)
                _verify_identity(replay_identity, "candidate observations", attempt)
                compare = _invoke_adapter(
                    context,
                    attempt_directory=attempt,
                    operation="compare",
                    purpose="candidate",
                    binding=binding,
                    inputs={"oracle": oracle_identity, "candidate": replay_identity},
                    outputs={},
                    evidence=evidence,
                    timeout_seconds=timeout_seconds,
                    max_output_bytes=max_output_bytes,
                )
                _verify_identity(oracle_identity, "oracle observations", attempt)
                _verify_identity(replay_identity, "candidate observations", attempt)
                correctness_result = compare
                equivalence = (
                    _equivalence_from(compare)
                    if compare["ok"]
                    else _failure_cases(context["case_ids"])
                )

    prefix = _evaluation(
        context,
        candidate_id=candidate_id,
        proposal_sha256=proposal["sha256"],
        candidate_sha256=candidate["sha256"],
        checks=checks,
        equivalence=equivalence,
        timing={"valid": False, "invalid_reason": "benchmark not authorized yet"},
        provenance=None,
    )
    try:
        prefix_decision = gate.evaluate(prefix)
    except gate.GateInputError as error:
        raise ControllerError(f"invalid correctness evidence: {error}") from error
    if prefix_decision["status"] != "timing_invalid":
        prefix["provenance"] = {
            "schema_version": context["schema_version"],
            "producer": "asmevo-controller",
            "record_policy": context["record_policy"],
            "stage": "correctness_rejected",
            "phase_evidence": evidence,
        }
        return _record_candidate(
            context,
            attempt_directory=attempt,
            evaluation=prefix,
            candidate=candidate_path,
            edit_summary=edit_summary,
            changed_windows=changed_windows,
        )

    receipt = _correctness_receipt(context, prefix, evidence)
    receipt_path = attempt / "correctness-receipt.json"
    _atomic_write_json(receipt_path, receipt)
    receipt_sha256 = _document_digest(receipt)
    _verify_frozen_context(context, proposal=proposal, candidate=candidate)
    if asm_surface:
        assert asm_source is not None
        assert parent_profile is not None
        _verify_identity(asm_source, "ASM candidate source", attempt)
        _verify_identity(parent_profile, "parent profile evidence", attempt)
    benchmark_binding = _binding(
        context,
        candidate_id=candidate_id,
        proposal_sha256=proposal["sha256"],
        candidate_sha256=candidate["sha256"],
        correctness_receipt_sha256=receipt_sha256,
    )
    benchmark = _invoke_adapter(
        context,
        attempt_directory=attempt,
        operation="benchmark",
        purpose="candidate",
        binding=benchmark_binding,
        inputs={
            "measure_artifacts": {
                "original": context["original"],
                "parent": context["parent"],
                "candidate": candidate,
            },
            "correctness_receipt": {
                "path": str(receipt_path),
                "sha256": receipt_sha256,
            },
        },
        outputs={},
        evidence=evidence,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
    _verify_frozen_context(context, proposal=proposal, candidate=candidate)
    if asm_surface:
        _verify_identity(asm_source, "ASM candidate source", attempt)
        _verify_identity(parent_profile, "parent profile evidence", attempt)
    if benchmark["ok"]:
        response = benchmark["response"]
        timing = response.get("timing") if isinstance(response, dict) else None
        if not isinstance(timing, dict):
            raise ControllerError("benchmark adapter omitted timing evidence")
    else:
        timing = {
            "valid": False,
            "invalid_reason": f"benchmark adapter failed: {benchmark['failure']}",
        }
    provenance = {
        "schema_version": context["schema_version"],
        "producer": "asmevo-controller",
        "record_policy": context["record_policy"],
        "stage": "benchmarked",
        "correctness_receipt_sha256": receipt_sha256,
        "correctness_receipt": receipt,
        "phase_evidence": evidence,
    }
    evaluation = _evaluation(
        context,
        candidate_id=candidate_id,
        proposal_sha256=proposal["sha256"],
        candidate_sha256=candidate["sha256"],
        checks=checks,
        equivalence=equivalence,
        timing=timing,
        provenance=provenance,
    )
    candidate_profile_path: Path | None = None
    if asm_surface:
        try:
            preliminary = gate.evaluate(evaluation)
        except gate.GateInputError as error:
            raise ControllerError(f"invalid benchmark evidence: {error}") from error
        if preliminary["status"] == "profile_required":
            candidate_profile_path = attempt / "candidate-profile.json"
            candidate_profile = _invoke_adapter(
                context,
                attempt_directory=attempt,
                operation="profile",
                purpose="accepted-candidate",
                binding=binding,
                inputs={"candidate_artifact": candidate},
                outputs={"profile_evidence": str(candidate_profile_path)},
                evidence=evidence,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
            )
            checks["asm_provenance"]["profile_capture_attempted"] = True
            if not candidate_profile["ok"]:
                checks["asm_provenance"]["profile_capture_passed"] = False
                checks["asm_provenance"]["profile_capture_failure"] = (
                    "candidate profile failed: " + str(candidate_profile["failure"])
                )
            else:
                candidate_profile_identity = _require_adapter_output(
                    candidate_profile["response"],
                    candidate_profile_path,
                    "candidate profile evidence",
                    attempt,
                    protected,
                )
                _load_asm_profile_evidence(
                    candidate_profile_path,
                    context=context,
                    artifact_sha256=candidate["sha256"],
                    within=attempt,
                )
                checks["asm_provenance"]["profile_capture_passed"] = True
                checks["asm_provenance"]["candidate_profile_evidence_sha256"] = (
                    candidate_profile_identity["sha256"]
                )
                _verify_identity(
                    candidate_profile_identity,
                    "candidate profile evidence",
                    attempt,
                )
            provenance["phase_evidence"] = evidence
            evaluation["checks"] = checks
            evaluation["provenance"] = provenance
    recorded = _record_candidate(
        context,
        attempt_directory=attempt,
        evaluation=evaluation,
        candidate=candidate_path,
        edit_summary=edit_summary,
        changed_windows=changed_windows,
    )
    if (
        asm_surface
        and recorded.get("accepted") is True
        and candidate_profile_path is not None
        and checks.get("asm_provenance", {}).get("profile_capture_passed") is True
    ):
        recorded["candidate_profile"] = str(candidate_profile_path.resolve())
        recorded["candidate_profile_sha256"] = checks["asm_provenance"][
            "candidate_profile_evidence_sha256"
        ]
    return recorded


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="verify K0 and freeze a baseline")
    init_parser.add_argument("--state", type=Path, required=True)
    init_parser.add_argument("--run-dir", type=Path, required=True)
    init_parser.add_argument("--original-id", default="K0")
    init_parser.add_argument("--contract", type=Path, required=True)
    init_parser.add_argument("--preflight", type=Path, required=True)
    init_parser.add_argument("--environment-manifest", type=Path, required=True)
    init_parser.add_argument(
        "--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS
    )
    init_parser.add_argument(
        "--max-output-bytes", type=int, default=DEFAULT_MAX_OUTPUT_BYTES
    )

    evaluate_parser = subparsers.add_parser(
        "evaluate", help="build, verify, benchmark, gate, and record one candidate"
    )
    evaluate_parser.add_argument("--state", type=Path, required=True)
    evaluate_parser.add_argument("--run-dir", type=Path, required=True)
    evaluate_parser.add_argument("--candidate-id", required=True)
    evaluate_parser.add_argument("--parent-id")
    evaluate_parser.add_argument("--proposal", type=Path, required=True)
    evaluate_parser.add_argument(
        "--profile-evidence",
        type=Path,
        help="verified parent profile evidence required by amdgcn_assembly",
    )
    evaluate_parser.add_argument("--artifact-name", default="candidate.artifact")
    evaluate_parser.add_argument("--edit-summary", required=True)
    evaluate_parser.add_argument("--changed-window", action="append", default=[])
    evaluate_parser.add_argument(
        "--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS
    )
    evaluate_parser.add_argument(
        "--max-output-bytes", type=int, default=DEFAULT_MAX_OUTPUT_BYTES
    )

    summary_parser = subparsers.add_parser("summary")
    summary_parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()

    if getattr(args, "timeout_seconds", DEFAULT_TIMEOUT_SECONDS) <= 0:
        print(
            json.dumps({"status": "input_invalid", "error": "timeout must be positive"})
        )
        return 2
    if getattr(args, "max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES) <= 0:
        print(
            json.dumps(
                {
                    "status": "input_invalid",
                    "error": "max output bytes must be positive",
                }
            )
        )
        return 2
    try:
        if args.command == "init":
            result = initialize_run(
                state=args.state,
                run_dir=args.run_dir,
                original_id=args.original_id,
                contract_path=args.contract,
                preflight_path=args.preflight,
                environment_manifest_path=args.environment_manifest,
                timeout_seconds=args.timeout_seconds,
                max_output_bytes=args.max_output_bytes,
            )
        elif args.command == "evaluate":
            result = evaluate_candidate(
                state=args.state,
                run_dir=args.run_dir,
                candidate_id=args.candidate_id,
                parent_id=args.parent_id,
                proposal_path=args.proposal,
                profile_evidence_path=args.profile_evidence,
                artifact_name=args.artifact_name,
                edit_summary=args.edit_summary,
                changed_windows=args.changed_window,
                timeout_seconds=args.timeout_seconds,
                max_output_bytes=args.max_output_bytes,
            )
        else:
            result = lineage.summary(args.state)
    except (OSError, ControllerError, lineage.LineageError) as error:
        print(json.dumps({"status": "controller_error", "error": str(error)}))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
