# Controller-bound evaluation contract

`scripts/controller.py` is the only recommended path for a measured AsmEvo run.
It accepts artifact proposals and descriptive metadata, invokes frozen adapters
itself, and assembles the evaluation document. It has no CLI option for caller-
supplied correctness results, timing samples, decisions, or receipts.

## State machine

Source baseline:

```text
K0 oracle -> correctness receipt -> K0 benchmark -> baseline receipt -> lineage
```

Binary baseline:

```text
recover K0 -> rebuild without edits -> round-trip check -> static check
  -> execute K0 oracle -> replay round-trip -> compare
  -> correctness receipt -> K0 benchmark -> baseline receipt -> lineage
```

Source candidate:

```text
proposal snapshot -> build -> independent oracle/compare
  -> correctness receipt -> benchmark -> verdict -> atomic lineage record
```

Binary candidate:

```text
proposal snapshot -> rebuild -> static check -> execute K0 oracle
  -> replay candidate -> compare -> correctness receipt
  -> benchmark -> verdict -> atomic lineage record
```

The controller stops at the first failure. In particular, it does not create or
spawn a benchmark request until the deterministic correctness prefix accepts every
frozen case. A failed or malformed adapter response cannot authorize the next
phase.

## Initialize a run

First create the contract, environment manifest, and ready preflight report. Then:

```bash
python3 "$ASMEVO_SKILL_ROOT/scripts/controller.py" init \
  --state run/lineage.json \
  --run-dir run \
  --original-id K0 \
  --contract run/contract.json \
  --preflight run/preflight.json \
  --environment-manifest run/environment.json
```

Initialization invokes the adapters and derives the baseline median from raw
samples. It does not accept a median on the command line. A successful state has
`record_policy: controller-v1`; older `legacy-v1` states must be reinitialized and
are never silently upgraded.

## Evaluate one proposal

The proposal is one regular file: edited source/assembly, a normalized diff, or a
deterministic manifest for a multi-file edit. The controller snapshots it before
any adapter sees it.

```bash
python3 "$ASMEVO_SKILL_ROOT/scripts/controller.py" evaluate \
  --state run/lineage.json \
  --run-dir run \
  --candidate-id c001 \
  --proposal work/c001.proposal \
  --artifact-name candidate.hsaco \
  --edit-summary "hide VMEM latency in the main loop" \
  --changed-window ".text+0x40:.text+0x78"
```

Omit `--parent-id` to use the current `best_id`; pass it explicitly to explore a
different verified branch. Gate acceptance makes a verified branch node. The
lineage changes `best_id` only when its recorded speedup is greater than the
current global best.

Each candidate gets a new `run/attempts/<candidate-id>/` directory. Candidate IDs
are restricted to letters, digits, dots, underscores, and hyphens. Existing
attempt directories are never reused. Candidate bytes are written only beneath
the dedicated `artifacts/` subdirectory; controller evidence names such as
`decision.json` are rejected as artifact names before the attempt is created.

## Correctness receipt

Before benchmarking, the controller atomically writes
`correctness-receipt.json`. The receipt binds:

- candidate, parent, and original IDs;
- mode, target architecture, and ordered case IDs;
- contract, preflight, environment, proposal, K0, parent, and candidate hashes;
- build/static results and complete equivalence cases;
- every pre-benchmark adapter path and executable hash;
- hashes of each request, raw stdout response, and stderr log.
- adapter-declared output paths and hashes, which lineage verification re-hashes;
  binary compare inputs must exactly match the oracle/replay output identities.

The benchmark request must echo the receipt SHA-256. The controller re-hashes all
frozen files and candidate bytes immediately before and after that invocation.
`lineage.py` rejects accepted or timing-stage evidence in a `controller-v1` state
when the embedded receipt is absent, mismatched, or does not bind the evaluated
checks and artifact identities.

## Failure and crash behavior

- Adapter execution never uses a shell and has a bounded timeout.
- Timeout or output overflow kills the adapter process group; partial output is
  retained for diagnosis but can never count as successful phase evidence.
- Stdout must be one strict UTF-8 JSON object. Duplicate keys, `NaN`, `Infinity`,
  extra text, wrong request bindings, and oversized output fail closed.
- Candidate and controller-owned evidence outputs must be regular non-symlink
  files inside the attempt directory and must not hard-link K0 or the parent.
- Requests, receipts, evaluations, decisions, and lineage state use fsync plus
  atomic rename. An orphaned attempt directory is evidence of an incomplete run,
  not a verified node.
- The atomically committed lineage is the source of truth. If the derived
  `decision.json` cannot be written after commit, the controller returns the
  committed result with a warning instead of reporting the candidate as failed.
- K0, parent, contract, environment, preflight, proposal snapshot, adapters, and
  candidate are re-hashed across the phase boundary. Drift prevents promotion.

## Guarantee boundary

For a cooperative caller using the public CLI, the controller keeps model-supplied
correctness values, timing samples, and decisions out of the normal measurement
and promotion path. It records a checkable chain attributed to frozen adapter
paths and hashes, in a fixed order, for frozen identities.

The module-private Python token is an accidental-misuse boundary, not an
authentication secret. A caller that can import the modules or write and execute
Python as the same OS user can reuse it and synthesize files. Therefore
`controller-bound` does not mean cryptographically authenticated or isolated from
the model.

It does not prove formal equivalence, that an adapter implements the promised
semantics, or that a same-user malicious process, compromised OS, remote worker,
driver, or GPU fabricated nothing. Stronger adversaries require OS isolation,
read-only or content-addressed storage, independently signed worker receipts, and
a separately administered measurement service.
