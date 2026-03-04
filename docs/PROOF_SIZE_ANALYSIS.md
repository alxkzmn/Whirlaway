# Whirlaway Keccak Proof Size — Final Reconciled Analysis

This document is the canonical synthesis of:

- [`PROOF_SIZE_REFERENCE_2.md`](./PROOF_SIZE_REFERENCE_2.md)
- [`PROOF_SIZE_ANALYSIS_V2.md`](./PROOF_SIZE_ANALYSIS_V2.md)

It is optimized for planning and execution: measured facts first, exact formulas next, then confidence-tagged reduction levers and acceptance gates.

---

## 1) Scope, assumptions, and notation

Target:
- Whirlaway Keccak proof system (SuperSpartan-style PIOP + WHIR PCS)

Security/config profile (baseline used in both reports):
- `security_bits=100`
- `soundness=CapacityBound`
- `pow_bits=16`
- `folding_factor=ConstantFromSecondRound(7,4)`
- `whir_log_inv_rate=1`
- `whir_initial_domain_reduction_factor=5`
- `univariate_skips=0`
- `merkle_security_bits_override=Some(80)`

Conventions:
- **(M)** = measured from profiler/binary outputs
- **(E)** = model estimate / projection
- When M and E disagree, **M wins**

---

## 2) Canonical measured baselines (M)

This section now tracks both baseline architectures under the same security profile:
- `LegacyBitSponge` (old bit-sponge, width 5326)
- `ByteSpongeAlgebraic` (new byte-sponge, width 2911)

### 2.1 Input size = 128

| Mode | Air width | Air height | Native proof | Blob v3 | Calldata | Calldata gas |
|---|---:|---:|---:|---:|---:|---:|
| LegacyBitSponge | 5326 | 32 | 250,891 | 242,171 | 242,244 | 3,139,320 |
| ByteSpongeAlgebraic | 2911 | 32 | 163,825 | 157,700 | 157,796 | 2,274,884 |

### 2.2 Input size = 1024

| Mode | Air width | Air height | Native proof | Blob v3 | Calldata | Calldata gas |
|---|---:|---:|---:|---:|---:|---:|
| LegacyBitSponge | 5326 | 256 | 264,563 | 251,479 | 251,556 | 3,811,080 |
| ByteSpongeAlgebraic | 2911 | 256 | 184,147 | 172,275 | 172,356 | 2,547,600 |

### 2.3 Scaling (128 -> 1024)

LegacyBitSponge:
- Native: `+13,672`
- Blob v3: `+9,308`
- Calldata: `+9,312`

ByteSpongeAlgebraic:
- Native: `+20,322`
- Blob v3: `+14,575`
- Calldata: `+14,560`

---

## 3) Locked equations (planning-grade)

Whirlaway proof structure:

```rust
Proof {
  whir_proof: WhirProof<...>,
  proof_data: Vec<EF>,
}
```

With `EF` size = 16 bytes and witness width `W`:

### 3.1 Dominant floor

`proof_data_floor_bytes = 2 * W * 16`

At `W = 5326`:
- `proof_data_floor_bytes = 170,432`

At `W = 2911`:
- `proof_data_floor_bytes = 93,152`

### 3.2 Exact current-config formula (validated at both measured points)

Let `L = log_length` (so height = `2^L`) and `univariate_skips=0`:

- `zerocheck_poly_elems = 1 + 8L`
- `inner_sumcheck_elems = 3L`
- `sub_evals_elems = 1`
- `total_elems = 2W + 11L + 2`

Therefore:

`proof_data_bytes = 16 * (2W + 11L + 2) + 8`

Checks:
- `L=5` -> `171,352` ✅
- `L=8` -> `171,880` ✅

### 3.3 Per-column savings law

Removing one witness column saves exactly:

`2 * sizeof(EF) = 32 bytes`

This is the most reliable first-order optimization metric.

---

## 4) Bottleneck decomposition (reconciled)

From both reports, the picture is stable:

1. **Primary bottleneck: width-driven transcript cost** (`proof_data`, especially `inner_sums_up/down`).
2. **Secondary bottleneck: WHIR query/authentication batches** (Merkle paths + leaves), which dominate growth with input size.
3. Remaining components (sumchecks, OOD, commitments, overhead) are small.

Operationally:
- At fixed width, WHIR tuning helps but cannot cross major size thresholds alone.
- Width reduction is mandatory before WHIR tuning can deliver target-level outcomes.

---

## 5) Feasibility bound for <128KB native

Use:

`max_width ~= floor((target_native - whir_bytes - residual_bytes)/32)`

Using measured regimes from V2:
- 128B regime (`whir~78.6KB`, residual~0.9KB) -> max width ~`1,618`
- 1024B regime (`whir~93.8KB`, residual~1.4KB) -> max width ~`1,114`

Current width is `5,326`.

Conclusion:
- **<128KB is infeasible at current architecture/width**.
- **WHIR-only tuning is insufficient**.
- **Significant width reduction is a hard prerequisite**.

---

## 6) Lever ranking with confidence tags

## 6.1 High-confidence (do first)

1. **Reduce witness width**
   - Deterministic savings via 32B/column law.
   - Largest guaranteed impact.

2. **Retune WHIR only after width is reduced**
   - Effective for controlling large-input growth once transcript floor drops.

## 6.2 Medium-confidence (high value, higher engineering risk)

3. **Sponge representation redesign**
   - Candidate: reduce/replace `out_bits` representation.
   - Potentially large savings; requires careful degree/soundness validation.

4. **Pack `block_bits` representation**
   - Potentially strong width reduction.
   - Must preserve absorb/XOR semantics and low-risk constraints.

5. **Remove intermediate permutation helper columns (within degree budget)**
   - Additional moderate gains.
   - Requires AIR rewrite + proof-system-level validation.

## 6.3 Low-confidence / out-of-scope

6. **Protocol-family changes** (different hash family, field/protocol migration)
   - Not aligned with this benchmark track.

---

## 7) Pragmatic plan of record (PoR)

## Stage A (mandatory): Width-first

Goal:
- Drive width from `5326` toward low-thousands, ideally crossing power-of-two thresholds (`<=4096`, then `<=2048`).

Acceptance gates:
- Re-profile at `input_size=128` and `1024` with exact same security profile.
- Report: width, `proof_data`, `whir_proof`, native/blob/calldata, proving time, RAM.
- Confirm no regression in verifier correctness/security assumptions.

## Stage B: WHIR tuning post-width-cut

Goal:
- Reduce query/auth footprint and input-size growth after Stage A gains are realized.

Acceptance gates:
- Show measured deltas attributable to WHIR tuning alone on the reduced-width AIR.
- Keep security target unchanged unless explicitly approved.

## Stage C: Delivery envelope

Goal:
- Validate practical on-chain envelope (bytes + calldata gas).

Acceptance gates:
- Native/blob/calldata measured in the final config.
- Gas estimate reported and compared against deployment constraints.

---

## 8) Risk register (explicit)

1. **Algebraic rewrite risk**
   - `out_bits`/packing ideas can silently alter constraint semantics.

2. **Degree budget pressure**
   - Width-saving rewrites may increase degree or complexity unexpectedly.

3. **Estimate optimism risk**
   - Sub-128KB projections are useful hypotheses, not commitments.

4. **Config drift risk**
   - Small baseline differences across runs can confuse progress tracking; lock profiling config and reporting format.

---

## 9) Final decision statement

The two source analyses agree on the critical outcome:

- The dominant cost is the width-floor in `proof_data` (`2 * W * 16`).
- WHIR dominates incremental growth with larger inputs, but cannot by itself close the `<128KB` gap.
- Therefore, the only credible path is:
  1) **substantial width reduction first**,
  2) **then WHIR/query optimization**,
  3) **then final calldata/gas hardening**.

Use this document as the canonical reference for milestone planning and acceptance criteria.

---

## 10) Byte-sponge algebraic migration results (implemented)

Date:
- 2026-03-04 (local run)

Profile binary:
- `cargo run --release -p whirlaway-bench --bin keccak_profile`

Security/config:
- `security_bits=100`
- `soundness=CapacityBound`
- `pow_bits=16`
- `folding_factor=ConstantFromSecondRound(7,4)`
- `whir_log_inv_rate=1`
- `whir_initial_domain_reduction_factor=5`
- `univariate_skips=0`
- `merkle_security_bits_override=Some(80)`

Architecture comparison:
- Legacy mode: bit-sponge (`width=5326`)
- New mode: `ByteSpongeAlgebraic` (`width=2911`, single AIR, no lookup argument)

### 10.1 Measured before/after (M)

| Input | Mode | Air width | Native proof | Blob v3 | Calldata | Calldata gas | Prove ms |
|---|---|---:|---:|---:|---:|---:|---:|
| 128 | LegacyBitSponge | 5326 | 250,891 | 242,171 | 242,244 | 3,139,320 | 65 |
| 128 | ByteSpongeAlgebraic | 2911 | 163,825 | 157,700 | 157,796 | 2,274,884 | 100 |
| 1024 | LegacyBitSponge | 5326 | 264,563 | 251,479 | 251,556 | 3,811,080 | 228 |
| 1024 | ByteSpongeAlgebraic | 2911 | 184,147 | 172,275 | 172,356 | 2,547,600 | 213 |

### 10.2 Size deltas

128-byte input:
- Native: `-87,066` bytes (`-34.70%`)
- Blob v3: `-84,471` bytes (`-34.88%`)
- Calldata: `-84,448` bytes (`-34.86%`)

1024-byte input:
- Native: `-80,416` bytes (`-30.40%`)
- Blob v3: `-79,204` bytes (`-31.50%`)
- Calldata: `-79,200` bytes (`-31.48%`)

### 10.3 Interpretation

- The width cut (`5326 -> 2911`) produced a large first-order win exactly as expected.
- The migration is substantial, but still does **not** hit `<128KB` native:
  - 128-byte input: `163,825` bytes
  - 1024-byte input: `184,147` bytes
- Therefore, the width-floor conclusion in this document still stands: additional AIR/protocol work is required for sub-128KB.

### 10.4 Notes

- RAM script failed in these runs (`ram measurement failed`), so RAM deltas are not recorded here.
- All existing Whirlaway tests passed after migration; long-running 1024/2048 rewrite-mode tests are currently marked `ignored` in CI-facing test targets.
