# Failure taxonomy

Use one primary status per candidate and retain detailed sub-reasons.

| Status | Meaning | Default response |
|---|---|---|
| `build_invalid` | source, assembly, link, or code-object build failed | fix syntax/tool use or abandon the edit; do not time |
| `static_invalid` | ABI, descriptor, metadata, resource, symbol, or launch contract mismatch | reject; return to verified parent |
| `runtime_failure` | launch, device, timeout, or replay failed before a valid comparison | distinguish candidate failure from infrastructure failure |
| `canary_corruption` | an output guard or protected memory canary changed | reject immediately; inspect bounds and pointer arithmetic |
| `divergent` | numeric or exact-state comparison failed | reject the semantic edit; do not relax policy |
| `timing_invalid` | the harness explicitly reports throttling, interruption, or mismatched measurement conditions | repair the measurement environment and rerun from a clean state |
| `timing_unstable` | configured CV or environmental stability limit exceeded | stabilize clocks/load and rerun; never select an outlier |
| `insufficient_speedup` | correct candidate did not clear the variance-aware threshold | retain evidence, do not add a lineage node |
| `accepted` | all required gates passed and the promotion threshold was met for the supplied evidence | record a hash-bound node and re-profile; call it controller-bound only when matching controller receipts are present |
| `duplicate` | candidate ID, proposal hash, or artifact hash already exists | stop repeating this proposal and redirect |
| `controller_error` | the controller cannot complete a bound phase because an adapter timed out, violated the protocol, returned malformed evidence, or a frozen identity/receipt changed | fail closed; do not benchmark or promote, inspect the preserved phase evidence, and retry only after identifying an infrastructure cause |
| `infrastructure_error` | remote host, storage, profiler, or orchestration failed independently of candidate semantics | bounded retry is allowed |
| `input_invalid` | evaluation JSON is malformed, including missing, non-finite, non-positive, or insufficient timing samples | repair the evidence producer; CLI exits nonzero and no attempt is recorded |

## Classification rules

- Correctness failures are not infrastructure failures.
- `controller_error` means no normal gate decision could be produced safely. It is
  not evidence that the candidate is correct or incorrect, and it never authorizes
  the next phase.
- A timeout inside the candidate may be semantic; classify it as infrastructure
  only when the same harness failure reproduces on `K0` or another verified node.
- Changing the oracle, case set, comparison policy, target architecture, driver,
  or toolchain invalidates older decisions under that contract.
- Keep rejected attempts in run memory even though they never enter the verified
  lineage. `lineage.py` deduplicates both `proposal_sha256` and final artifact
  hashes, including when a failed build produces no artifact.
- Public `gate.py` and `lineage.py` CLI results are legacy evidence. Only the
  controller path can produce controller-bound receipts; its module-private Python token
  prevents ordinary CLI misuse, not hostile same-user processes or callers that
  can import the modules.
- After repeated identical failures, stop retrying and change the optimization
  hypothesis.
