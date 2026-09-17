# Acceptance contract

Use this contract to turn a candidate run into a deterministic decision. The
agent may prepare the evidence, but it must not edit measured values after seeing
the decision.

The command examples use `ASMEVO_SKILL_ROOT`, the absolute directory containing
this skill's `SKILL.md`:

```bash
ASMEVO_SKILL_ROOT="${CODEX_HOME:-${HOME}/.codex}/skills/asmevo"
```

For a source checkout, point it at the checkout's `asmevo/` directory. Run paths
remain relative to the target project.

## Gate order

The controller evaluates a candidate in this order:

1. build or assembly validity;
2. static ABI, descriptor, metadata, and resource consistency;
3. runtime success and functional equivalence for every configured case;
4. guard and exact-state integrity;
5. timing stability;
6. improvement over the verified parent.

Stop at the first failed correctness gate. Do not benchmark a candidate that
failed steps 1 through 4. Binary mode always requires step 2; setting
`checks.static_consistency.required=false` cannot disable it.

## Freeze the workload contract

First produce a `ready` preflight report as described in
[adapter-contract.md](adapter-contract.md) and preserve it in the private run
directory. A gate decision alone cannot enter verified lineage without this
bound report.

Copy `assets/contract-template.json` into the private run directory and replace
every placeholder before measuring the baseline. It freezes:

- source or binary mode;
- target GPU architecture;
- an environment fingerprint identifying compiler, ROCm, driver, clocks, and
  relevant launch settings, represented by the SHA-256 of a preserved manifest;
- the ordered case IDs, which should encode shapes, dtypes, strides, seeds, and
  launch variants;
- numeric, exact-state, and guard policy;
- sample-count, noise, and promotion thresholds.

Initialize the lineage with the frozen file:

```bash
python3 "$ASMEVO_SKILL_ROOT/scripts/lineage.py" init \
  --state run/lineage.json \
  --original-id K0 \
  --original-artifact run/original.hsaco \
  --baseline-median-ms 1.0 \
  --contract run/contract.json \
  --preflight run/preflight.json \
  --environment-manifest run/environment.json
```

`lineage.py` stores the canonical contract SHA-256 and re-hashes the file before
recording or summarizing. It also requires a ready preflight whose mode, target
architecture, original artifact, and complete capability set match the contract,
then binds that report by hash. The environment manifest must hash to the identity
inside the contract and remains immutable. Any contract, preflight, or environment
change requires a new lineage and baseline.

## Evaluation document

Start from `assets/evaluation-template.json`. Embed an exact JSON copy of the
frozen contract under `contract`; do not point to a mutable file. The evidence
has this shape:

The example environment hash below belongs only to
`assets/example-environment.json`, a schema smoke-test fixture. Never reuse it for
a real optimization run.

```json
{
  "schema_version": 1,
  "candidate_id": "c001",
  "parent_id": "K0",
  "original_id": "K0",
  "mode": "source",
  "proposal_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
  "contract": {
    "schema_version": 1,
    "mode": "source",
    "target_arch": "gfx942",
    "environment_sha256": "3936e10403f7c799226cd82ac4ba751fe41b94ddbba0efd18b0a8cf8a0310844",
    "case_ids": ["m1024-n1024-k1024-fp16-seed0"],
    "equivalence_policy": {
      "min_cosine_similarity": 0.9999,
      "max_absolute_error": 0.001,
      "require_integer_exact": true,
      "require_guards_intact": true
    },
    "performance_policy": {
      "minimum_samples": 5,
      "minimum_relative_improvement": 0.002,
      "cv_multiplier": 0.85,
      "maximum_cv": 0.03,
      "speedup_floor": 1.0
    }
  },
  "artifacts": {
    "original_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "parent_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "candidate_sha256": "1111111111111111111111111111111111111111111111111111111111111111"
  },
  "checks": {
    "build": {"passed": true, "evidence": "build.log"},
    "static_consistency": {
      "required": false,
      "passed": true,
      "evidence": "not required in source mode"
    }
  },
  "equivalence": {
    "cases": [
      {
        "case_id": "m1024-n1024-k1024-fp16-seed0",
        "runtime_ok": true,
        "float_metrics_applicable": true,
        "cosine_similarity": 1.0,
        "max_absolute_error": 0.0,
        "integer_exact": true,
        "guards_intact": true
      }
    ]
  },
  "timing": {
    "valid": true,
    "original_ms": [1.01, 1.00, 0.99, 1.00, 1.00],
    "parent_ms": [1.01, 1.00, 0.99, 1.00, 1.00],
    "candidate_ms": [0.91, 0.90, 0.90, 0.89, 0.90]
  }
}
```

`proposal_sha256` identifies a canonical edit payload, normalized diff, or edited
source/assembly before build, so failed builds can still be deduplicated. The
artifact hashes identify exact final bytes. For a multi-file artifact, use the
SHA-256 of a deterministic manifest containing component hashes. Hash the loadable
object, not merely the edited source. A build-failed evaluation may set
`artifacts.candidate_sha256` to `null`; every successful build must provide it.

Run the gate for a human-readable decision, then give the original evaluation—not
the decision—to the lineage helper:

```bash
python3 "$ASMEVO_SKILL_ROOT/scripts/gate.py" \
  run/c001.evaluation.json --output run/c001.decision.json
python3 "$ASMEVO_SKILL_ROOT/scripts/lineage.py" record \
  --state run/lineage.json \
  --evaluation run/c001.evaluation.json \
  --artifact run/c001.hsaco \
  --edit-summary "hide VMEM latency in the main loop" \
  --changed-window ".text+0x40:.text+0x78"
```

The lineage helper reruns the gate internally. A hand-edited decision file cannot
promote a candidate. It also binds original, parent, and candidate hashes; re-hashes
verified artifacts; deduplicates proposal and artifact hashes; and serializes concurrent
record operations with a file lock. Each attempt embeds the evaluation, including
raw samples, so later edits or deletion of the source JSON cannot erase the record.

These helpers validate structure, identity, gate ordering, and decision arithmetic;
they do not prove that raw numbers came from hardware. The authorized oracle and
benchmark adapters must produce the evidence in a private run directory. Treat
manually entered measurements as untrusted.

## Equivalence

For each evaluated case $x$, the float portion follows the paper's empirical
predicate:

$$
\cos(K'(x), O(x)) \geq \theta
\quad\land\quad
\lVert K'(x)-O(x)\rVert_\infty \leq \tau
$$

Integer or opaque state is checked exactly when the contract requires it. Guards
must remain intact when enabled. `float_metrics_applicable=false` is valid for an
exact-only case; it does not disable exact and guard checks.

The external comparator must define NaN, Inf, signed-zero, subnormal,
nondeterministic-reduction, and random-state behavior. Never infer those semantics
from a passing aggregate metric.

## Performance threshold

Let:

- $s_p=T(K_0)/T(K_{parent})$ be the verified parent's speedup;
- $s_c=T(K_0)/T(K_{candidate})$ be the candidate's speedup;
- $cv$ be the largest coefficient of variation across the fresh original, parent,
  and candidate timing samples;
- $\epsilon$ be `minimum_relative_improvement`;
- $k$ be `cv_multiplier`.

The helper computes:

$$
m=(1+\max(\epsilon,k\cdot cv))s_p
$$

and accepts performance only when:

$$
s_c \geq \max(m, s_{floor})
$$

Using the largest observed CV is a conservative implementation choice. The helper
also rejects a run whose CV exceeds `maximum_cv`.

Collect fresh samples after warmup. Prefer randomized or alternating paired
measurements of original, parent, and candidate when supported. The medians need
not equal historical node medians; the exact artifact hashes and frozen contract
establish identity while the fresh samples capture current conditions. Preserve
the raw sequence so a project can add paired-bootstrap or stronger promotion
rules. Never select a candidate from a single minimum latency.

Set `timing.valid=false` with a non-empty `timing.invalid_reason` when the harness
detects throttling, an interrupted run, mismatched launch conditions, or another
measurement fault. This produces `timing_invalid` without attempting promotion.
Malformed or incomplete JSON is instead an input error and exits nonzero.

## Decision output

The helper emits JSON with:

- `accepted` and a stable `status` from the failure taxonomy;
- all rejection reasons;
- canonical contract and evidence SHA-256 identities;
- medians, CVs, speedups, and the required speedup threshold;
- candidate, parent, and original artifact identities.

An evaluated rejection exits successfully because rejection is a normal search
outcome. Invalid input exits nonzero.
