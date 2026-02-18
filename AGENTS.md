# Copilot instructions (Whirlaway)

This repository is a Rust workspace implementing a hash-based SNARK. Most “interesting” correctness is in the IOP stack (sumcheck + AIR) and in PCS openings (via `whir-p3`). When writing or modifying tests here, there are several repo-specific gotchas that are easy to rediscover the hard way.

## How to run tests (known-good)

- **Run everything**: `cargo test --workspace`
- **Single crate**:
  - `cargo test -p sumcheck`
  - `cargo test -p air`
- **Single test target** (faster iteration):
  - `cargo test -p air --test prove`
  - `cargo test -p air --test verify`
  - `cargo test -p sumcheck --test integration`
- **Debug failures**: `RUST_BACKTRACE=1 cargo test ...`

## High-signal repo gotchas

### `whir-p3` parameter landmines (panics / UB)

- **Univariate skip is now resolved by mode**:
  - `AirSettings` supports `UnivariateSkipMode::Manual { skip }` and `UnivariateSkipMode::Auto { ... }`.
  - The resolved skip count is committed into transcript proof data and checked by the verifier.
  - For stable regression tests, prefer manual mode with an explicit `skip`.
- **`TooLarge(...)` panics**: some `AirSettings` / WHIR parameters are validated tightly and will panic if set too aggressively. In this repo’s tests we converged on settings that reliably work for `KoalaBear`:
  - Folding factor kept moderate (commonly `(4, 4)`).
  - `whir_initial_domain_reduction_factor` kept moderate (commonly `4`).
  - `security_bits` in tests commonly limited to **64 or 128**; larger values can exceed grinding capabilities and panic.

### AIR tests must use a _satisfying_ witness (don’t use “MockAir” for end-to-end)

- A recurring failure mode is `AirVerifError::Sumcheck(InvalidRound)` even when the code “looks right”.
- Root cause: a trivial/mock AIR + random witness does **not** satisfy the real algebraic constraints expected by the proof system.
- **Fix**: use `keccak_air::KeccakAir` to generate a valid trace/witness for end-to-end prove→verify tests.
  - There are helpers already written for this in:
    - `crates/air/tests/helpers.rs` (and similar helper patterns in `tests/air_prove_verify.rs`)
- Ensure the `air` crate has `keccak_air` as a **dev-dependency** (it was added for tests).

### Only real negative tests should “expect failure”

In this repository, “negative” tests should be _genuinely_ negative (invalid witness/proof/statement), not “panic-based smoke tests”.

- **Keep as real negative tests**:
  - `test_air_prove_witness_dimension_mismatch`
  - `test_pcs_invalid_opening` (verify should fail with a wrong statement/value)
- Everything else should usually be **prove→verify succeeds** on valid data.

### Field constants: `ONE`/`ZERO` require the right trait import

- For `KoalaBear`/`MontyField31`, `F::ONE` and `F::ZERO` require importing:
  - `use p3_field::PrimeCharacteristicRing;`
- If you forget, you’ll see errors like “no associated item named ONE/ZERO”.

### Matrix APIs: `DenseMatrix` uses a field, not a method

- `p3_matrix::dense::DenseMatrix` exposes `values` as a **public field** (`trace.values`), not a method (`trace.values()`).

### Packed vs extension-field types (`F` vs `EF`) bite often

Common mistakes and fixes:

- **Iterator product on references**: use `.iter().copied().product()` (not `.iter().product()`) when the product type is the owned field element.
- **`Statement` must match the prover/verifier type**:
  - PCS statements are typically `Statement<EF>`, not `Statement<F>`.
  - Use `Statement::<EF>::new(...)` and ensure values/weights passed in are `EF`.
- **Witness evaluation method**:
  - Evaluate via `packed_witness.polynomial.evaluate(...)` (not `packed_witness.evaluate(...)`).

### AIR sumcheck folding uses **suffix variables**

- When folding a multilinear over the outer sumcheck point, `EvaluationsList::fold` substitutes the **last** variables.
- The batched-witness check in verification folds the **suffix** of the point (i.e., `outer_sumcheck_challenge.point[1..]`).
- If you need sub-evaluations for that check, fold the **suffix** explicitly (see the `fold_suffix` helper in the AIR prover) rather than using `fold` with a full point in the wrong order.

### Zerocheck eq factor vs sumcheck challenges

- The zerocheck eq factor (`zerocheck_challenges`) is distinct from the outer sumcheck challenge point returned by the prover.
- Don’t overwrite or reuse the eq factor vector with sumcheck challenges, or the verifier’s checks will fail.

### Keccak trace input layout matters

- `keccak_air::generate_trace_rows` expects inputs in standard Keccak indexing `input[x + 5*y]` and **transposes** to `[x][y]` state.
- If you bypass the helper or construct traces manually, ensure the same transpose, or trace-vs-upstream comparisons will fail.

### Negative proof tests must still be well-formed

- `whir-p3`’s commitment reader assumes a populated proof structure.
- For “invalid proof” tests, use a real `WhirProof` and **truncate/corrupt proof data**, rather than constructing a default proof with empty commitments.

### Borrow/move gotchas in loops

- Hash/compress function handles (e.g. `merkle_hash`, `merkle_compress`) may be **moved** when passed into prove/verify routines inside loops; clone them per iteration if needed.

### `ConstraintFolder` / `PackedConstraintsFolder` **cannot** use `is_first_row` / `is_last_row` / `is_transition_window`

- These methods are implemented as `unreachable!()` in both `ConstraintFolder` and `ConstraintFolderPacked`. Calling `builder.when_first_row()`, `builder.when_last_row()`, or `builder.when_transition()` will **panic at runtime** during sumcheck evaluation.
- **Fix**: Use explicit selector columns (`first_row_sel`, `transition_sel`) already present in the trace and gate constraints with `builder.when(selector.clone())`.
- This applies to **any** AIR evaluated through the Whirlaway sumcheck path (i.e., all AIRs in this repo). It does _not_ apply when using upstream `p3_uni_stark` directly, which has its own `SymbolicAirBuilder` that supports these methods.

### Public values must flow through sumcheck

- When an AIR implements `AirBuilderWithPublicValues` and accesses `builder.public_values()`, the constraint evaluation during sumcheck needs those values.
- `ConstraintFolder` has a `public_values: &[NF]` field; `ConstraintFolderPacked` has `public_values: &[F::Packing]`.
- The sumcheck prover's `compute_over_hypercube` passes these through. In the first round, base-field `&[NF]` values are used; in later rounds, they are converted to extension field `&[EF]` values via `public_values_ef`.
- **Gotcha**: When adding public values to a circuit, you must update the `SumcheckComputation` and `SumcheckComputationPacked` trait impls (or the blanket impls via the constraint folders) _and_ thread the values through all call sites.

### Fiat-Shamir binding of public values

- Public values **must** be observed into the challenger **before** any challenges are derived (before proving/verification begins).
- Both prover and verifier must observe the same public values in the same order: `for value in &public_values { challenger.observe(*value); }`.
- Forgetting this on either side produces a transcript mismatch that manifests as `Fs(...)` or `Sumcheck(InvalidRound)` errors.

### Sponge AIR: zero-IV constraint is mandatory

- The Keccak sponge starts from an all-zero state. Without an explicit constraint enforcing this, a malicious prover could use an arbitrary IV.
- The zero-IV constraint recovers each input bit on the **first row** as `A[y,x,z] = a_prime XOR c XOR c_prime` and checks it against `block_bits[i]` (rate) or `0` (capacity).
- This constraint family has 1600 entries (one per state bit), each of degree ≤ 5.

### Constraint degree budget for sponge AIR

- The permutation-only `KeccakAir` uses `constraint_degree = 3`.
- The `KeccakSpongeAir` uses `constraint_degree = 6`. The XOR3 operation is degree 4, and when gated by a selector it reaches degree 5. Use 6 to accommodate all constraints comfortably.

### `constraint_degree` must match the actual algebraic degree of the AIR

- The `constraint_degree` parameter passed to `AirTable::new` controls how many evaluation points the sumcheck prover uses for polynomial interpolation. If it is too low, the interpolated polynomial is wrong and verification fails with `SumMismatch`.
- **Poseidon2 example**: `Poseidon2Air` with `SBOX_DEGREE = 5` and `SBOX_REGISTERS = 0` computes `x⁵` directly in one constraint, so the true constraint degree is **5**. Setting `constraint_degree = 3` silently produces wrong proofs — the prover "succeeds" but verification always fails.
- When `SBOX_REGISTERS > 0`, the AIR introduces intermediate witness columns that reduce the effective degree (e.g., `SBOX_REGISTERS = 1` with degree-7 would split into two degree-4 steps). So `constraint_degree` depends on _both_ `SBOX_DEGREE` and `SBOX_REGISTERS`.
- **Rule of thumb**: inspect the plonky3 AIR source or use `get_symbolic_constraints` to determine the max constraint degree, then set `constraint_degree` to at least that value.

### `p3_uni_stark::check_constraints` is `pub(crate)` — not usable externally

- At the pinned Plonky3 revision (`c38eb05`), `check_constraints` and `DebugConstraintBuilder` cannot be used from crates outside `p3_uni_stark`.
- **Workaround for negative tests**: Use the full prove→verify pipeline and assert failure, rather than trying to check constraints directly.

### `PackedValue::from_fn` for scalar broadcast

- `F::Packing::from_f(...)` does **not exist**. To broadcast a scalar `value: F` into a packed value, use:
  ```rust
  F::Packing::from_fn(|_| value)
  ```
  This requires `use p3_field::PackedValue;`.

### `from_u16` not `from_canonical_u16`

- For KoalaBear / MontyField31, use `F::from_u16(x)` from `PrimeCharacteristicRing`, not `from_canonical_u16` (which doesn't exist).

### `test-utils` feature for cross-crate test helpers

- Functions gated by `#[cfg(test)]` are only visible within the same crate.
- To expose test-only functions to integration tests in _other_ crates, use a feature flag: `#[cfg(any(test, feature = "test-utils"))]` in the library crate, and add `features = ["test-utils"]` to the consuming crate's `[dev-dependencies]`.
- Example: `keccak_air` exposes `generate_sponge_trace_with_iv` behind `test-utils` for the workspace-level negative test in `tests/sponge_zero_iv.rs`.

### Recovering Keccak preimage bits from AIR columns

- The input state bit `A[y,x,z]` can be recovered from the intermediate columns as:
  ```
  A[y,x,z] = a_prime[y][x][z] XOR c[x][z] XOR c_prime[x][z]
  ```
  where XOR over a prime field is `a + b - 2ab` (for bits).
- This identity is used in both the absorb-chaining and zero-IV constraints.

### KeccakSpongeAir column layout

- Extra sponge columns are appended **after** the `NUM_KECCAK_COLS` permutation columns:
  `[hash_end, seen_end, active, block_bits(1088), out_bits(1600)]`
- `hash_end` marks the final round of the last real permutation; `seen_end` is the running indicator; `active` drops to 0 after `hash_end`.
- `block_bits` are the rate-portion message bits, held constant across a permutation's 24 rounds.
- `out_bits` are the 1600-bit state decomposition, constrained only on final-step rows while active.

## What “good tests” look like here (avoid naïve assertions)

Prefer semantic invariants over smoke checks:

- **Sumcheck**:
  - Do full **prove→verify** roundtrips (`crates/sumcheck/tests/*.rs`).
  - Assert:
    - verifier’s claimed sum equals expected sum
    - returned challenge point matches transcript challenges
    - returned final evaluation matches evaluating the multilinear(s) at that point
- **AIR**:
  - Use a real AIR (`KeccakAir`) + valid witness.
  - Assert `table.verify(...)` succeeds for proofs produced by `table.prove(...)`.
- **PCS**:
  - Do full `commit → prove opening → verify opening`.
  - For negative tests, verify failure by changing the **statement/value**, not by expecting a panic.

## Where to look first (navigation)

- Sumcheck: `crates/sumcheck/src/*`, tests in `crates/sumcheck/tests/*`
- AIR: `crates/air/src/*`, tests in `crates/air/tests/*`, workspace integration in `tests/air_prove_verify.rs`
- PCS integration tests: `crates/air/tests/pcs_integration.rs`
- Concrete valid AIR for testing: `keccak_air/`
