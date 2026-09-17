# Acceptance contract

The controller turns raw adapter responses into a deterministic verdict. The
model may propose bytes and explain a result, but it must not supply build flags,
correctness values, timing samples, receipts, or the promotion decision.

The complete invocation and receipt lifecycle is in
[controller-contract.md](controller-contract.md); the adapter wire format is in
[adapter-contract.md](adapter-contract.md).

## Gate order

For every candidate, the controller enforces:

1. build or assembly validity;
2. binary ABI, descriptor, metadata, and resource consistency;
3. runtime success and functional equivalence for every frozen case;
4. guard and exact-state integrity;
5. correctness-receipt creation;
6. fresh timing stability;
7. improvement over the selected verified parent;
8. atomic lineage record and possible global-best update.

The benchmark executable is not invoked before step 5. Binary mode cannot disable
step 2. A phase timeout, non-zero exit, malformed response, stale request binding,
or frozen-file drift stops the chain.

## Frozen workload contract

Copy `assets/contract-template.json` into a private run directory and replace all
placeholders before preflight. It freezes:

- source or binary mode and target architecture;
- the SHA-256 of the preserved environment manifest;
- ordered case IDs encoding shapes, dtypes, strides, seeds, and launch variants;
- floating, exact-state, guard, and exact-only case policy;
- sample count, maximum noise, and promotion thresholds.

Any semantic contract change creates a different canonical contract SHA-256 and
requires a new baseline. `preflight.py` similarly binds K0 and every adapter
executable. `controller.py init` then executes the baseline chain and stores raw
samples in a baseline receipt. A manually entered historical median is a legacy
low-level input, not controller-backed evidence.

## Controller-produced evaluation

The controller keeps the schema consumed by `gate.py`:

```json
{
  "schema_version": 1,
  "candidate_id": "c001",
  "parent_id": "K0",
  "original_id": "K0",
  "mode": "source",
  "proposal_sha256": "...",
  "contract": {},
  "artifacts": {
    "original_sha256": "...",
    "parent_sha256": "...",
    "candidate_sha256": "..."
  },
  "checks": {
    "build": {"passed": true, "evidence": {}},
    "static_consistency": {"required": false, "passed": true, "evidence": {}}
  },
  "equivalence": {"cases": []},
  "timing": {
    "valid": true,
    "original_ms": [1.01, 1.0, 0.99, 1.0, 1.0],
    "parent_ms": [1.01, 1.0, 0.99, 1.0, 1.0],
    "candidate_ms": [0.91, 0.9, 0.9, 0.89, 0.9]
  },
  "provenance": {
    "schema_version": 1,
    "producer": "asmevo-controller",
    "record_policy": "controller-v1",
    "stage": "benchmarked",
    "correctness_receipt_sha256": "...",
    "correctness_receipt": {},
    "phase_evidence": []
  }
}
```

The controller fills every field after directly running adapters. It embeds phase
evidence so deletion or editing of a standalone response file cannot erase the
record. A `controller-v1` lineage rejects accepted and timing-stage evaluations
without a matching correctness receipt. Pre-correctness failures may be recorded
without a receipt, but must carry controller phase evidence and the
`correctness_rejected` stage.

`assets/evaluation-template.json` is only a synthetic schema and arithmetic
fixture. Running it through `gate.py` proves neither that an adapter ran nor that a
GPU measurement occurred.

## Equivalence predicate

For every floating-output case $x$:

$$
\cos(K'(x), O(x)) \geq \theta
\quad\land\quad
\lVert K'(x)-O(x)\rVert_\infty \leq \tau
$$

The comparator must define NaN, Inf, signed-zero, subnormal,
nondeterministic-reduction, and random-state behavior. Integer or opaque state is
exact when required, and guards remain intact. A response may use
`float_metrics_applicable=false` only for a case listed in the frozen
`exact_only_case_ids`; it cannot downgrade comparison policy after observing a
candidate.

The gate rejects cosine values outside `[-1, 1]`, negative absolute errors,
missing cases, duplicates, and a different case order.

## Performance predicate

Let:

- $s_p=T(K_0)/T(K_{parent})$ be the selected parent's fresh speedup;
- $s_c=T(K_0)/T(K_{candidate})$ be the candidate's fresh speedup;
- $cv$ be the largest coefficient of variation across fresh K0, parent, and
  candidate samples;
- $\epsilon$ be `minimum_relative_improvement`;
- $k$ be `cv_multiplier`.

The gate computes:

$$
m=(1+\max(\epsilon,k\cdot cv))s_p
$$

and accepts performance only when:

$$
s_c \geq \max(m,s_{floor})
$$

It also rejects a run whose observed CV exceeds `maximum_cv`. Preserve every raw
sample and prefer alternating or randomized paired measurements. Never select a
single minimum latency.

Acceptance creates a verified node relative to the selected parent. The lineage
updates `best_id` only if this node beats the existing global best's recorded
speedup. These are distinct decisions in a multi-start search.

If lineage deduplication overrides a gate result, the final decision consistently
reports `accepted: false` and `status: duplicate` in the CLI result,
`decision.json`, and lineage attempt. Its `gate_accepted`, `gate_status`, and
`gate_reasons` fields preserve the deterministic pre-deduplication verdict.

## Low-level compatibility interfaces

`gate.py` still accepts a caller-supplied evaluation for schema tests, arithmetic
experiments, and audits. Its complete decision is deterministic for a fixed input;
wall-clock timestamps belong to controller receipts and lineage records rather
than the gate calculation.

`lineage.py init --baseline-median-ms` and `lineage.py record --evaluation` remain
available for legacy use. Such a state reports `record_policy: legacy-v1` and its
nodes report submitted evidence rather than controller verification. Do not use
that path to claim the closed-loop guarantee.

An evaluated rejection exits normally because rejection is a search result.
Malformed input or a controller invariant violation exits non-zero.
