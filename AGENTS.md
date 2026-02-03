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

- **Univariate skip > 1 is currently unsafe**: enabling `univariate_skips > 1` has been observed to trigger _undefined behavior_ in the underlying `whir-p3` sumcheck path. Keep tests using `univariate_skips = 1` unless/until upstream is fixed.
  - If you see tests constrained to `[1]` with a UB comment, it’s intentional.
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
