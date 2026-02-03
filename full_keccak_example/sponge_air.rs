use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, BaseAirWithPublicValues};
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{KeccakAir, KeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS_MIN_1, U64_LIMBS};
use p3_matrix::horizontally_truncated::HorizontallyTruncated;
use p3_matrix::Matrix;

/// Keccak-f[1600] state bits.
pub(crate) const STATE_BITS: usize = 1600;
/// Keccak-256 rate bits.
pub(crate) const RATE_BITS: usize = 1088;
/// Keccak-256 digest bits (32 bytes).
const DIGEST_BITS: usize = 256;
/// Digest as 16-bit limbs.
pub(crate) const DIGEST_LIMBS: usize = DIGEST_BITS / 16;

// Extra columns layout (appended after `p3_keccak_air` columns):
// [hash_end, seen_end, active, block_bits(1088), out_bits(1600)]
pub(crate) const HASH_END_IDX: usize = NUM_KECCAK_COLS;
pub(crate) const SEEN_END_IDX: usize = HASH_END_IDX + 1;
pub(crate) const ACTIVE_IDX: usize = SEEN_END_IDX + 1;
pub(crate) const BLOCK_BITS_START: usize = ACTIVE_IDX + 1;
pub(crate) const OUT_BITS_START: usize = BLOCK_BITS_START + RATE_BITS;
const EXTRA_COLS: usize = 1 + 1 + 1 + RATE_BITS + STATE_BITS;

#[derive(Clone, Debug, Default)]
pub struct KeccakSpongeAir;

impl KeccakSpongeAir {
    pub fn new() -> Self {
        Self
    }
}

impl<F> BaseAir<F> for KeccakSpongeAir {
    fn width(&self) -> usize {
        NUM_KECCAK_COLS + EXTRA_COLS
    }
}

impl<F> BaseAirWithPublicValues<F> for KeccakSpongeAir {
    fn num_public_values(&self) -> usize {
        // 32-byte digest as 16 little-endian 16-bit limbs.
        DIGEST_LIMBS
    }
}

struct PrefixAirBuilder<'a, AB> {
    inner: &'a mut AB,
}

impl<AB: AirBuilder> AirBuilder for PrefixAirBuilder<'_, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type M = HorizontallyTruncated<AB::Var, AB::M>;

    fn main(&self) -> Self::M {
        HorizontallyTruncated::new(self.inner.main(), NUM_KECCAK_COLS)
            .expect("failed to truncate matrix")
    }

    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        self.inner.is_transition_window(size)
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.inner.assert_zero(x)
    }
}

fn assert_bool_like<AB: AirBuilder>(builder: &mut AB, x: AB::Expr) {
    // x * (x - 1) == 0
    builder.assert_zero(x.clone() * (x - AB::Expr::ONE));
}

fn xor2<Expr: Clone + core::ops::Add<Output = Expr> + core::ops::Sub<Output = Expr> + core::ops::Mul<Output = Expr>>(
    two: Expr,
    a: Expr,
    b: Expr,
) -> Expr {
    // For boolean a,b in a field (char != 2):
    // a XOR b = a + b - 2ab
    a.clone() + b.clone() - (two * a * b)
}

fn xor3<Expr: Clone + core::ops::Add<Output = Expr> + core::ops::Sub<Output = Expr> + core::ops::Mul<Output = Expr>>(
    two: Expr,
    a: Expr,
    b: Expr,
    c: Expr,
) -> Expr {
    xor2(two.clone(), xor2(two.clone(), a, b), c)
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for KeccakSpongeAir {
    fn eval(&self, builder: &mut AB) {
        // 1) Enforce the underlying Keccak-f AIR on the prefix columns.
        {
            let mut prefix = PrefixAirBuilder { inner: builder };
            KeccakAir {}.eval(&mut prefix);
        }

        // 2) Sponge-level constraints (hash_end bookkeeping + absorb chaining + digest check).
        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("empty trace"),
            main.row_slice(1).expect("trace has only 1 row"),
        );

        let local_keccak: &KeccakCols<AB::Var> = local_row[..NUM_KECCAK_COLS].borrow();
        let next_keccak: &KeccakCols<AB::Var> = next_row[..NUM_KECCAK_COLS].borrow();

        let local_hash_end = local_row[HASH_END_IDX].clone().into();
        let _next_hash_end = next_row[HASH_END_IDX].clone().into();
        let local_seen_end = local_row[SEEN_END_IDX].clone().into();
        let next_seen_end = next_row[SEEN_END_IDX].clone().into();
        let local_active = local_row[ACTIVE_IDX].clone().into();
        let next_active = next_row[ACTIVE_IDX].clone().into();

        let two = AB::Expr::TWO;

        // Booleanness of control flags.
        assert_bool_like(builder, local_hash_end.clone());
        assert_bool_like(builder, local_seen_end.clone());
        assert_bool_like(builder, local_active.clone());

        // First row: seen_end = 0, active = 1.
        builder.when_first_row().assert_zero(local_seen_end.clone());
        builder.when_first_row().assert_one(local_active.clone());

        // Transition:
        // seen_end_next = seen_end + hash_end  (ensures exactly one hash_end if last row has seen_end=1)
        // active_next = active - hash_end      (drops to 0 immediately after hash_end row)
        builder.when_transition().assert_zero(next_seen_end.clone() - (local_seen_end.clone() + local_hash_end.clone()));
        builder.when_transition().assert_zero(next_active.clone() - (local_active.clone() - local_hash_end.clone()));

        // hash_end may only happen while active.
        builder
            .when(local_hash_end.clone())
            .assert_zero((AB::Expr::ONE - local_active.clone()) * local_hash_end.clone());

        // hash_end must be on a final-step row.
        let local_final_step = local_keccak.step_flags[NUM_ROUNDS_MIN_1].clone().into();
        builder
            .when(local_hash_end.clone())
            .assert_zero(AB::Expr::ONE - local_final_step.clone());

        // Last row: seen_end must be 1.
        builder.when_last_row().assert_one(local_seen_end.clone());

        // Enforce out_bits decomposition only on final-step rows while active.
        // Also force out_bits to 0 on non-final-step rows to avoid unconstrained witness.
        {
            let local_out_bits = &local_row[OUT_BITS_START..OUT_BITS_START + STATE_BITS];
            let not_final = AB::Expr::ONE - local_final_step.clone();

            // When not final step: all out bits are zero.
            builder.when(not_final.clone()).assert_zeros::<STATE_BITS, _>(core::array::from_fn(|i| {
                local_out_bits[i].clone().into()
            }));

            // When final step AND active: out_bits are boolean and match the output limbs.
            let gate = local_final_step.clone() * local_active.clone();
            for lane in 0..25 {
                let x = lane % 5;
                let y = lane / 5;
                for limb in 0..U64_LIMBS {
                    // limb value (16-bit)
                    let limb_val: AB::Expr = local_keccak.a_prime_prime_prime(y, x, limb).clone().into();
                    let base_bit = (lane * 64) + (limb * 16);

                    // limb == sum bit_i * 2^i
                    let mut acc = AB::Expr::ZERO;
                    let mut pow2 = AB::Expr::ONE;
                    for i in 0..16 {
                        let b: AB::Expr = local_out_bits[base_bit + i].clone().into();
                        builder.when(gate.clone()).assert_zero(b.clone() * (b.clone() - AB::Expr::ONE));
                        acc = acc + b * pow2.clone();
                        pow2 = pow2.clone() + pow2;
                    }
                    builder.when(gate.clone()).assert_zero(acc - limb_val);
                }
            }
        }

        // Digest check on hash_end row: compare first 16 output limbs (256 bits) to public values.
        {
            // The first 256 bits are the first 4 u64 lanes (32 bytes) = first 16 16-bit limbs.
            for limb_idx in 0..DIGEST_LIMBS {
                let pv_limb: AB::Expr = builder.public_values()[limb_idx].into();
                let u64_index = limb_idx / U64_LIMBS;
                let limb_in_u64 = limb_idx % U64_LIMBS;
                let y = u64_index / 5;
                let x = u64_index % 5;
                let out_limb: AB::Expr = local_keccak.a_prime_prime_prime(y, x, limb_in_u64).clone().into();
                builder
                    .when(local_hash_end.clone())
                    .assert_zero(out_limb - pv_limb);
            }
        }

        // Absorb chaining at permutation boundaries (only while still active).
        //
        // Boundary is a transition where local is final round, next is first round.
        let next_first_step = next_keccak.step_flags[0].clone().into();
        let boundary_gate = local_final_step.clone() * next_first_step.clone() * next_active.clone();

        // For each bit, next input bit == local output bit XOR block bit (rate), or == local output bit (capacity).
        let local_out_bits = &local_row[OUT_BITS_START..OUT_BITS_START + STATE_BITS];
        let next_block_bits = &next_row[BLOCK_BITS_START..BLOCK_BITS_START + RATE_BITS];

        // Helper to compute next input bit A[x,y,z] from next row columns:
        // A = A' XOR C XOR C'
        let next_input_bit = |x: usize, y: usize, z: usize| -> AB::Expr {
            let a_prime = next_keccak.a_prime[y][x][z].clone().into();
            let c = next_keccak.c[x][z].clone().into();
            let c_prime = next_keccak.c_prime[x][z].clone().into();
            xor3(two.clone(), a_prime, c, c_prime)
        };

        for bit_idx in 0..STATE_BITS {
            let lane = bit_idx / 64;
            let z = bit_idx % 64;
            let x = lane % 5;
            let y = lane / 5;

            let rhs = if bit_idx < RATE_BITS {
                let a = local_out_bits[bit_idx].clone().into();
                let b = next_block_bits[bit_idx].clone().into();
                xor2(two.clone(), a, b)
            } else {
                local_out_bits[bit_idx].clone().into()
            };

            let lhs = next_input_bit(x, y, z);
            builder
                .when_transition()
                .when(boundary_gate.clone())
                .assert_zero(lhs - rhs);
        }

        // Enforce block bits are boolean at the start of each permutation (step_flags[0] == 1).
        {
            let gate = local_keccak.step_flags[0].clone().into();
            let local_block_bits = &local_row[BLOCK_BITS_START..BLOCK_BITS_START + RATE_BITS];
            for i in 0..RATE_BITS {
                let b: AB::Expr = local_block_bits[i].clone().into();
                builder.when(gate.clone()).assert_zero(b.clone() * (b - AB::Expr::ONE));
            }
        }

        // Enforce block bits are constant within a permutation (until final step).
        {
            let not_final_step = AB::Expr::ONE - local_final_step.clone();
            let local_block_bits = &local_row[BLOCK_BITS_START..BLOCK_BITS_START + RATE_BITS];
            let next_block_bits = &next_row[BLOCK_BITS_START..BLOCK_BITS_START + RATE_BITS];
            builder.when_transition().when(not_final_step).assert_zeros::<RATE_BITS, _>(core::array::from_fn(|i| {
                local_block_bits[i].clone().into() - next_block_bits[i].clone().into()
            }));
        }
    }
}

