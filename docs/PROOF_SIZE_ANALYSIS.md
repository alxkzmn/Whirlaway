# Whirlaway Keccak Proof Size Analysis

Source of truth for Whirlaway proof size: anatomy, drivers, measurements, and optimization planning.

Conventions: **(M)** = measured from profiler. **(E)** = model estimate. Measured wins on conflict.

---

## 1. Proof anatomy

Whirlaway is a SuperSpartan-style PIOP + WHIR polynomial commitment scheme over a single AIR.

```rust
struct Proof {
    proof_data: Vec<EF>,                // ← ~58% of proof (PIOP transcript)
    whir_proof: WhirProof<F, EF, ...>,  // ← ~42% of proof (PCS opening)
}
```

The proof has exactly **two top-level components**. There are no separate commitments,
lookup arguments, or fractional-sum trees — everything is a single AIR evaluated
via sumcheck, then committed/opened by WHIR.

### 1.1 `proof_data` (PIOP transcript)

A flat `Vec<EF>` containing all prover messages from the sumcheck-based PIOP.
Its elements, in order:

| Sub-component         | Elements                      | What it is                                               |
| --------------------- | ----------------------------- | -------------------------------------------------------- |
| `inner_sums_up`       | `W`                           | Per-column evaluations at sumcheck challenge (local row) |
| `inner_sums_down`     | `W`                           | Per-column evaluations at sumcheck challenge (next row)  |
| Zerocheck round polys | `1 + (constraint_degree+1)×L` | Sumcheck round polynomials for constraint check          |
| Inner sumcheck polys  | `3L`                          | Sumcheck for combining column claims                     |
| Sub-evaluations       | `1`                           | Final composition evaluation                             |

Where `W` = AIR width (number of witness columns), `L` = `log₂(trace_height)`,
and `EF` = extension field element = **16 bytes** (`BinomialExtensionField<KoalaBear, D>`).

**Key formula:**

```
proof_data_bytes = sizeof(EF) × (2W + (constraint_degree+2)×L + 2) + 8
```

With the current config (`constraint_degree ≈ 11`, `univariate_skips=0`):

```
proof_data_bytes ≈ 16 × (2W + 13L + 2) + 8
```

The `2W` term dominates. Every column costs **32 bytes** of proof.

### 1.2 `whir_proof` (WHIR PCS)

The WHIR polynomial commitment opening proof. Its sub-components:

| Sub-component         | Typical bytes | What it is                                                     |
| --------------------- | ------------- | -------------------------------------------------------------- |
| `initial_commitment`  | 32            | Merkle root of the committed polynomial                        |
| `initial_ood_answers` | 40            | Out-of-domain evaluation answers                               |
| `initial_sumcheck`    | 240           | Initial sumcheck round polynomials                             |
| **`rounds`**          | **~57 KB**    | **FRI-like folding rounds: Merkle auth paths + query answers** |
| `final_poly`          | ~1 KB         | Final folded polynomial coefficients                           |
| `final_pow_witness`   | 4             | Proof-of-work grinding witness                                 |
| `final_query_batch`   | ~10 KB        | Final authentication batch (Merkle paths)                      |
| `final_sumcheck`      | ~200          | Final sumcheck round polynomials                               |

WHIR cost is driven by `rounds` (Merkle authentication paths), which scale with
the number of **queries** and `log₂(polynomial_size)`.

### 1.3 On-chain encoding

For EVM deployment, the native proof is re-encoded:

- **Proof blob v3**: Compact binary encoding with digest masking (80-bit Merkle security).
- **Calldata**: ABI-encoded blob for on-chain verification.
- **Calldata gas**: `16 × nonzero_bytes + 4 × zero_bytes`.

The blob/calldata are typically ~3–5% smaller than native (digest masking saves bytes).

---

## 2. Size drivers per component

### 2.1 `proof_data` drivers

| Driver                     | Effect                                         | Lever                                   |
| -------------------------- | ---------------------------------------------- | --------------------------------------- |
| **AIR width `W`**          | Linear: `+32 bytes` per column                 | Reduce columns (primary lever)          |
| Extension field degree `D` | Linear: `sizeof(EF) = 4D` bytes per element    | Choose Binomial4 vs Binomial8 (see §5)  |
| Trace height `2^L`         | Logarithmic: `+13×16 = 208 bytes` per doubling | Determined by circuit, not tunable      |
| Constraint degree          | Logarithmic: `+(degree+2)×16×L` total          | Higher degree can save columns (see §4) |

**The `2W` floor dominates.** At width 2911 and `EF` = 16 bytes:

```
proof_data_floor = 2 × 2911 × 16 = 93,152 bytes (~91 KB)
```

### 2.2 WHIR drivers

| Driver              | Effect                                                   | Lever                                              |
| ------------------- | -------------------------------------------------------- | -------------------------------------------------- |
| **Query count**     | Linear: more queries → more Merkle paths                 | Determined by security assumption + `log_inv_rate` |
| `log₂(poly_size)`   | Logarithmic: deeper Merkle trees                         | Affected by width via power-of-2 padding           |
| Folding factor      | Determines number of rounds                              | `ConstantFromSecondRound(7,4)` — tunable           |
| `log_inv_rate`      | Trade-off: higher = fewer queries but larger LDE         | Currently 1                                        |
| Digest masking bits | Per-digest: saves `(32 - masked_bytes)` per path element | `merkle_security_bits_override=80` → 20 bytes      |
| PoW bits            | Constant 4 bytes per grinding witness                    | Currently 16                                       |

**Power-of-2 width thresholds** (because columns are padded before commitment):

| Width range | Padded width | PCS `num_variables` (height=32) | WHIR cost  |
| ----------- | ------------ | ------------------------------- | ---------- |
| 2049–4096   | 4096         | 17                              | ~69 KB     |
| 1025–2048   | 2048         | 16                              | ~60 KB (E) |
| 513–1024    | 1024         | 15                              | ~52 KB (E) |

### 2.3 Security assumption impact on queries

The number of WHIR queries depends on the security assumption:

| Assumption    | δ (proximity) at lir=1 | Queries for 84-bit protocol security |
| ------------- | ---------------------- | ------------------------------------ |
| CapacityBound | 0.475                  | 91                                   |
| JohnsonBound  | 0.257                  | 196                                  |

JohnsonBound requires ~2× more queries, roughly doubling Merkle path costs in WHIR.

---

## 3. Measured baselines

Profile binary: `cargo run --release -p whirlaway-bench --bin keccak_profile`

Security config:

- `security_bits=100`, `soundness=CapacityBound`, `pow_bits=16`
- `folding_factor=ConstantFromSecondRound(7,4)`, `whir_log_inv_rate=1`
- `whir_initial_domain_reduction_factor=5`, `univariate_skips=0`
- `merkle_security_bits_override=Some(80)`, `EF=Binomial4` (124-bit, 16 bytes)

### 3.1 Summary table

| Input | Mode                | Width | Native proof | proof_data | whir_proof | Blob v3 | Calldata |
| ----- | ------------------- | ----: | -----------: | ---------: | ---------: | ------: | -------: |
| 128   | LegacyBitSponge     |  5326 |      250,891 |    ~171 KB |     ~79 KB | 242,171 |  242,244 |
| 128   | ByteSpongeAlgebraic |  2911 |      163,825 |     ~94 KB |     ~69 KB | 157,700 |  157,796 |
| 1024  | LegacyBitSponge     |  5326 |      264,563 |    ~172 KB |     ~94 KB | 251,479 |  251,556 |
| 1024  | ByteSpongeAlgebraic |  2911 |      184,147 |     ~95 KB |     ~89 KB | 172,275 |  172,356 |

### 3.2 WHIR sub-component breakdown (ByteSponge, 128B input, 69 KB total)

| Sub-component          |      Bytes | % of WHIR |
| ---------------------- | ---------: | --------: |
| `initial_commitment`   |         32 |      0.0% |
| `initial_ood_answers`  |         40 |      0.1% |
| `initial_sumcheck`     |        240 |      0.3% |
| **`rounds` (1 round)** | **57,225** | **82.6%** |
| `final_poly`           |      1,033 |      1.5% |
| `final_pow_witness`    |          4 |      0.0% |
| `final_query_batch`    |     10,498 |     15.2% |
| `final_sumcheck`       |        209 |      0.3% |

### 3.3 Byte-sponge migration deltas

| Input | Native Δ         | Blob Δ           | Calldata Δ       |
| ----- | ---------------- | ---------------- | ---------------- |
| 128   | -87,066 (-34.7%) | -84,471 (-34.9%) | -84,448 (-34.9%) |
| 1024  | -80,416 (-30.4%) | -79,204 (-31.5%) | -79,200 (-31.5%) |

### 3.4 Formula cross-check

For ByteSpongeAlgebraic, `W=2911`, `L=5`, `constraint_degree=11`:

```
proof_data = 16 × (2×2911 + 13×5 + 2) + 8 = 16 × 5889 + 8 = 94,232 bytes
```

Measured `proof_data ≈ 94,472` bytes. Residual ~240 bytes from bincode overhead. **~99.7% accurate.**

---

## 4. Keccak AIR column anatomy

### 4.1 KeccakF permutation columns (Plonky3 keccak-air): 2635 columns

| Group             | Shape        |     Cols |     % | Role                             |
| ----------------- | ------------ | -------: | ----: | -------------------------------- |
| `a_prime`         | `[5][5][64]` | **1600** | 60.7% | Post-θ state bits (core witness) |
| `c`               | `[5][64]`    |      320 | 12.1% | θ column parities                |
| `c_prime`         | `[5][64]`    |      320 | 12.1% | Rotated parities                 |
| `a`               | `[5][5][4]`  |      100 |  3.8% | Packed u16 state (θ output)      |
| `a_prime_prime`   | `[5][5][4]`  |      100 |  3.8% | Packed χ output                  |
| `a_pp_0_0_bits`   | `[64]`       |       64 |  2.4% | ι bit decomposition              |
| `a_ppp_0_0_limbs` | `[4]`        |        4 |  0.2% | ι output (lane 0,0)              |
| `step_flags`      | `[24]`       |       24 |  0.9% | One-hot round selector           |
| `preimage`        | `[5][5][4]`  |      100 |  3.8% | Permutation input                |
| `first_row_sel`   | scalar       |        1 |  0.0% | First-row selector               |
| `transition_sel`  | scalar       |        1 |  0.0% | Transition selector              |
| `export`          | scalar       |        1 |  0.0% | Sponge export flag               |

Note: Whirlaway's fork has 2635 columns (2 more than upstream Plonky3's 2633) due to
`first_row_sel` and `transition_sel` being witness columns rather than virtual.

### 4.2 ByteSponge wrapper: +276 columns

| Field                  | Cols | Purpose                                     |
| ---------------------- | ---: | ------------------------------------------- |
| `hash_end`             |    1 | Marks the final permutation row             |
| `seen_end`             |    1 | Running flag: 1 after hash_end              |
| `active`               |    1 | = 1 − seen_end                              |
| `is_new_start`         |    1 | = 1 on first permutation row of first block |
| `block_bytes[136]`     |  136 | Message/padding bytes per block             |
| `is_padding_byte[136]` |  136 | Padding flag per byte position              |

**Total current width: 2635 + 276 = 2911**

### 4.3 Column removal budget (if raising max constraint degree)

|  Max degree | Columns removed              | Width |  Proof Δ |
| ----------: | ---------------------------- | ----: | -------: |
| 3 (default) | none                         |  2911 | baseline |
|           4 | `a_ppp_0_0_limbs`            |  2907 |   -128 B |
|           5 | + `a`, `a_prime_prime`       |  2707 |  -6.5 KB |
|           6 | + `a_pp_0_0_bits`, `c_prime` |  2323 | -18.8 KB |

**Practical floor**: `a_prime` (1600) + `c` (320) + sponge (274 non-removable) = **~2194 columns**.
At 32 bytes/column: ~70 KB minimum for `proof_data`'s width-proportional term.

---

## 5. Security parameter tradeoffs: JohnsonBound vs CapacityBound

### 5.1 The problem

Switching from `CapacityBound` to `JohnsonBound` with a 31-bit base field (KoalaBear)
and 100-bit security causes a fatal assertion:

```
assertion failed: (1 << bits) <= F::ORDER_U64 as usize
```

at `SerializingChallenger32::grind()` / `sample_bits()`.

**Root cause**: JohnsonBound's weaker soundness produces larger `folding_pow_bits`
requirements. The WHIR protocol compensates for weaker proximity-gap error by
demanding more proof-of-work grinding, but `grind()` caps PoW at 30 bits for
KoalaBear (since `2^31 > p ≈ 2^{31}`).

### 5.2 The math

The critical formula is:

```
folding_pow_bits = max(0, security_level − min(prox_gaps_error, sumcheck_error))
```

The proximity-gaps error for JB scales as `field_bits − (2·num_vars + 3.5·lir + const)`,
vs CB's `field_bits − (num_vars + lir + const)`. The `2×num_vars` coefficient halves
the available soundness bits.

Computed for `num_vars=17`, `security=100`:

| Assumption |    EF bits |    lir=1 | lir=3 | lir=6 |
| ---------- | ---------: | -------: | ----: | ----: |
| **CB**     | 124 (Bin4) |  **0.3** |   6.3 |  15.3 |
| **JB**     | 124 (Bin4) | **36.8** |  43.8 |  54.3 |
| CB         | 248 (Bin8) |      0.0 |   0.0 |   0.0 |
| **JB**     | 248 (Bin8) |  **0.0** |   0.0 |   0.0 |

KoalaBear PoW ceiling = **30 bits**. JB + Binomial4 exceeds this at all `log_inv_rate` values.

### 5.3 The only parameter-level fix: Binomial8

Switching to `BinomialExtensionField<KoalaBear, 8>` (248-bit EF, 32 bytes per element)
makes `prox_gaps_error > 180` bits for all practical `num_vars`, so `folding_pow_bits = 0`.

**Proof size impact of Binomial8 + JohnsonBound:**

| Component          | Bin4+CB (current) | Bin8+JB (projected) | Reason                             |
| ------------------ | ----------------- | ------------------- | ---------------------------------- |
| `proof_data` floor | 93 KB             | **186 KB**          | `sizeof(EF)` doubles: 16→32 bytes  |
| WHIR rounds        | ~57 KB            | ~90–110 KB (E)      | ~2× queries (JB) + larger sumcheck |
| WHIR final batch   | ~10 KB            | ~15–20 KB (E)       | ~2× queries                        |
| **Native total**   | **164 KB**        | **~290–320 KB (E)** | ~2× overall                        |

Binomial8 roughly doubles proof size. This makes it unsuitable for proof-size
optimization, but it is the **only way** to use JohnsonBound (proven security
assumption) with a 31-bit base field at 100-bit security.

### 5.4 What does NOT fix JohnsonBound + Binomial4

| Knob                    | Why it fails                                                 |
| ----------------------- | ------------------------------------------------------------ |
| Increase `log_inv_rate` | JB folding_pow grows ~3.5 bits per lir step — makes it worse |
| Increase PoW ceiling    | Required bits already exceed 30; ceiling doesn't matter      |
| Reduce `num_variables`  | Need `nv ≤ 13` (width ≤ 256); impractical for keccak         |
| Larger folding factor   | Doesn't affect `prox_gaps_error` (the bottleneck)            |
| `univariate_skips`      | Changes sumcheck, not polynomial dimension                   |

### 5.5 Practical recommendation

Stay on **Binomial4 + CapacityBound** for proof-size benchmarks. CB relies on a
conjecture (RS capacity decodability + correlated agreement), but it is widely
used in production and gives 2× smaller proofs than Bin8+JB. Reserve JB for
contexts where provable security is required and proof size is secondary.

---

## 6. Optimization levers (ranked by ROI)

| #     | Lever                                                       |                  Savings | Difficulty   | Status                            |
| ----- | ----------------------------------------------------------- | -----------------------: | ------------ | --------------------------------- |
| **1** | **Reduce AIR width** (sponge redesign, column removal)      |              32 B/column | Medium–High  | ByteSponge done (5326→2911, -35%) |
| **2** | **Remove intermediate perm. columns** (raise degree to 5–6) |                  6–19 KB | High         | Requires forking keccak-air       |
| 3     | Tune WHIR parameters (lir, folding, queries)                |                  2–10 KB | Low          | Secondary, after width reduction  |
| —     | Switch to JohnsonBound                                      | Negative (doubles proof) | Low          | Only viable with Bin8 (see §5)    |
| —     | Smaller extension field                                     |           ~47 KB savings | Infeasible   | Violates 100-bit security         |
| —     | Different hash function                                     |                  ~60+ KB | Out of scope | Not aligned with Keccak goals     |

### Per-column savings law

Removing one witness column saves exactly **32 bytes** of native proof
(`2 × sizeof(EF)` from the local + next row evaluations in `proof_data`).

This is the single most reliable optimization metric.

---

## 7. Roadmap and acceptance gates

### Stage A: Width reduction ✅ DONE

- Byte-sponge migration: 5326 → 2911 columns, -35% proof size.
- Native proof at 128B input: 163,825 bytes.

### Stage B: Further width reduction (next)

- Remove intermediate columns (`a`, `a_prime_prime`, `c_prime`, `a_pp_0_0_bits`)
  by raising constraint degree to 5–6.
- Target: ~2323 columns, ~148 KB native (E).

### Stage C: WHIR tuning

- Optimize `log_inv_rate`, folding factor, query parameters on reduced-width AIR.
- Target: shave 2–10 KB from WHIR component.

### Acceptance gates

| #   | Gate                      | Threshold                                 |
| --- | ------------------------- | ----------------------------------------- |
| 1   | Correctness               | All keccak + blob codec tests pass        |
| 2   | `native_proof_size_bytes` | < 131,072 (128 KB) for ≤1 KB inputs       |
| 3   | Prove-time regression     | < 2× vs current byte-sponge mode          |
| 4   | Security config           | 100-bit security, locked profiling config |

---

## 8. Reference formulas

### 8.1 `proof_data` prediction

```
proof_data_bytes = sizeof(EF) × (2W + (D+2)×L + 2) + 8
```

Where `sizeof(EF)` = 16 (Bin4) or 32 (Bin8), `W` = width, `D` = constraint degree,
`L` = log₂(height). Validated to ~99.7% accuracy against profiler measurements.

### 8.2 Per-column cost (general)

```
cost_per_column = 2 × sizeof(EF) = { 32 bytes (Bin4), 64 bytes (Bin8) }
```

### 8.3 WHIR polynomial size

```
pcs_poly_size = width.next_power_of_two() × height
num_variables = log₂(pcs_poly_size)
```

A jump in `num_variables` (e.g., crossing a power-of-2 width threshold) causes
a step increase in WHIR proof size.
