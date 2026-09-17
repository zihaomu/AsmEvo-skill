# Project adapter contract

The skill supplies the controller, not a universal compiler, replay harness, or
profiler. Project adapters form the trusted measurement boundary. Keep them small,
directly executable, deterministic where possible, and independently reviewed.

## Capability set

Source mode requires `build`, `oracle`, and `benchmark`.

Binary mode requires `recover`, `roundtrip`, `rebuild`, `static_check`, `oracle`,
`replay`, `compare`, and `benchmark`. Their semantic duties are described in
[binary-backend.md](binary-backend.md).

Register every adapter with `scripts/preflight.py` as `NAME=EXECUTABLE`. Preflight
resolves the absolute real path and records its executable SHA-256 and size. The
controller re-hashes every required adapter before each run and after each
invocation. Changing a wrapper requires a new preflight, baseline, and lineage.

## Invocation ABI

The controller invokes an adapter without a shell:

```text
/absolute/path/to/adapter --request /absolute/path/to/request.json
```

The adapter must write exactly one UTF-8 JSON object to stdout and diagnostics to
stderr. It must not add banners or log lines to stdout. Exit zero plus `"ok": true`
means the requested phase completed; every other outcome fails closed.

The common request envelope is:

```json
{
  "schema_version": 1,
  "protocol": "asmevo.adapter.v1",
  "request_id": "random-128-bit-hex",
  "operation": "build",
  "purpose": "candidate",
  "binding": {
    "mode": "source",
    "target_arch": "gfx942",
    "candidate_id": "c001",
    "parent_id": "K0",
    "original_id": "K0",
    "contract_sha256": "...",
    "environment_sha256": "...",
    "preflight_sha256": "...",
    "original_sha256": "...",
    "parent_sha256": "...",
    "proposal_sha256": "...",
    "candidate_sha256": null,
    "case_ids": ["m1024-n1024-k1024-fp16-seed0"],
    "correctness_receipt_sha256": null
  },
  "contract": {"path": "/private/run/contract.json", "case_ids": ["..."]},
  "artifacts": {"original": {"path": "...", "sha256": "..."}},
  "inputs": {},
  "outputs": {"candidate_artifact": "/private/run/attempts/c001/artifacts/candidate.hsaco"},
  "attempt_directory": "/private/run/attempts/c001"
}
```

The common response envelope is:

```json
{
  "schema_version": 1,
  "protocol": "asmevo.adapter.v1",
  "request_id": "random-128-bit-hex",
  "operation": "build",
  "binding": {},
  "ok": true,
  "candidate_sha256": "..."
}
```

`request_id`, `operation`, and the entire `binding` object must exactly echo the
request. The controller computes every output hash itself and compares it with the
adapter declaration. It never accepts an adapter-selected output path.

## Operation results

- `build` and `rebuild` write `outputs.candidate_artifact` and return its
  `candidate_sha256`.
- `recover` writes `outputs.recovered` and returns `output_sha256`.
- `roundtrip` and `static_check` return the common envelope; `ok` is the verdict.
- A binary `oracle` or `replay` writes `outputs.observations` and returns
  `output_sha256`.
- A source `oracle`, and binary `compare`, return `equivalence.cases` in the exact
  ordered form consumed by `gate.py`.
- A baseline `benchmark` returns `samples_ms`, including all post-warmup K0 samples.
- A candidate `benchmark` returns `timing` with fresh `original_ms`, `parent_ms`,
  and `candidate_ms` arrays. Its request has a non-null
  `correctness_receipt_sha256` and includes the matching receipt path and hash.

All correctness responses must cover the frozen case IDs in the same order. The
adapter computes numeric error, exact-state, and guard results. The contract's
`exact_only_case_ids` is the only way to declare a case without floating metrics;
the response cannot downgrade that requirement.

## Working directory and evidence

The controller runs the wrapper from the candidate attempt directory and passes
absolute paths. A wrapper must establish any project build directory, environment,
GPU lease, synchronization, warmup, and tool-specific timeout it needs.

The controller preserves the exact request, stdout, and stderr for each phase and
hashes all three. Large tool logs should be written beneath the attempt directory
and summarized on stderr; stdout and stderr are capped by the controller's
`--max-output-bytes` setting.

## Safety and scope

- Treat candidate code as untrusted.
- Do not pass secrets through arguments or stdout.
- Keep captured kernargs, memory, model weights, prompts, and user data in an
  authorized private run directory excluded from version control.
- Use a unique workspace and GPU lease per parallel worker.
- Version 1 is a local-file protocol. A remote worker needs content-addressed
  transfer and a separately authenticated receipt; returning local-looking paths
  from a remote service is not sufficient.
- A script hash does not bind its shebang interpreter, shared libraries, driver,
  or device firmware. Record those in the environment manifest.
