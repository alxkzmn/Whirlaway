use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, BaseAirWithPublicValues};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::horizontally_truncated::HorizontallyTruncated;
use p3_matrix::Matrix;

use crate::{
    constants::rc_value_bit, KeccakAir, KeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS, NUM_ROUNDS_MIN_1,
    U64_LIMBS,
};

/// Keccak-f[1600] state bits.
pub const STATE_BITS: usize = 1600;
/// Keccak-256 digest bits (32 bytes).
const DIGEST_BITS: usize = 256;
/// Digest as 16-bit limbs.
pub const DIGEST_LIMBS: usize = DIGEST_BITS / 16;
/// Keccak-256 rate bytes.
pub const RATE_BYTES: usize = 136;
/// Number of 16-bit limbs in the Keccak-256 rate.
pub const RATE_U16S: usize = RATE_BYTES / 2;
/// Number of 16-bit limbs in the full state.
const STATE_U16S: usize = STATE_BITS / 16;

// Extra columns layout (appended after `keccak_air` columns):
// [hash_end, seen_end, active, is_new_start, block_bytes(136), is_padding_byte(136)]
pub const HASH_END_IDX: usize = NUM_KECCAK_COLS;
pub const SEEN_END_IDX: usize = HASH_END_IDX + 1;
pub const ACTIVE_IDX: usize = SEEN_END_IDX + 1;
pub const IS_NEW_START_IDX: usize = ACTIVE_IDX + 1;
pub const BLOCK_BYTES_START: usize = IS_NEW_START_IDX + 1;
pub const IS_PADDING_START: usize = BLOCK_BYTES_START + RATE_BYTES;
pub const BYTE_EXTRA_COLS: usize = 1 + 1 + 1 + 1 + RATE_BYTES + RATE_BYTES;

#[derive(Clone, Debug, Default)]
pub struct ByteSpongeAir;

impl ByteSpongeAir {
    pub fn new() -> Self {
        Self
    }
}

impl<F> BaseAir<F> for ByteSpongeAir {
    fn width(&self) -> usize {
        NUM_KECCAK_COLS + BYTE_EXTRA_COLS
    }
}

impl<F> BaseAirWithPublicValues<F> for ByteSpongeAir {
    fn num_public_values(&self) -> usize {
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
    builder.assert_zero(x.clone() * (x - AB::Expr::ONE));
}

fn xor2<
    Expr: Clone
        + core::ops::Add<Output = Expr>
        + core::ops::Sub<Output = Expr>
        + core::ops::Mul<Output = Expr>,
>(
    two: Expr,
    a: Expr,
    b: Expr,
) -> Expr {
    a.clone() + b.clone() - (two * a * b)
}

fn xor3<
    Expr: Clone
        + core::ops::Add<Output = Expr>
        + core::ops::Sub<Output = Expr>
        + core::ops::Mul<Output = Expr>,
>(
    two: Expr,
    a: Expr,
    b: Expr,
    c: Expr,
) -> Expr {
    xor2(two.clone(), xor2(two.clone(), a, b), c)
}

fn state_u16_position(i: usize) -> (usize, usize, usize) {
    let lane = i / U64_LIMBS;
    let limb = i % U64_LIMBS;
    let y = lane / 5;
    let x = lane % 5;
    (y, x, limb)
}

fn block_u16_expr<AB: AirBuilder>(block_bytes: &[AB::Var], i: usize) -> AB::Expr {
    let lo: AB::Expr = block_bytes[2 * i].clone().into();
    let hi: AB::Expr = block_bytes[2 * i + 1].clone().into();
    lo + hi * AB::Expr::from_u64(1 << 8)
}

fn next_input_bit<AB: AirBuilder>(
    next_keccak: &KeccakCols<AB::Var>,
    x: usize,
    y: usize,
    z: usize,
    two: AB::Expr,
) -> AB::Expr {
    let a_prime: AB::Expr = next_keccak.a_prime[y][x][z].clone().into();
    let c: AB::Expr = next_keccak.c[x][z].clone().into();
    let c_prime: AB::Expr = next_keccak.c_prime[x][z].clone().into();
    xor3(two, a_prime, c, c_prime)
}

fn local_output_bit<AB: AirBuilder>(
    local_keccak: &KeccakCols<AB::Var>,
    x: usize,
    y: usize,
    z: usize,
    two: AB::Expr,
) -> AB::Expr {
    let b_xy: AB::Expr = local_keccak.b(x, y, z).into();
    let b_x1: AB::Expr = local_keccak.b((x + 1) % 5, y, z).into();
    let b_x2: AB::Expr = local_keccak.b((x + 2) % 5, y, z).into();

    let andn = (AB::Expr::ONE - b_x1) * b_x2;
    let chi = xor2(two.clone(), b_xy, andn);

    if x == 0 && y == 0 {
        let mut rc_bit = AB::Expr::ZERO;
        for round in 0..NUM_ROUNDS {
            rc_bit += local_keccak.step_flags[round].clone()
                * AB::Expr::from_bool(rc_value_bit(round, z) != 0);
        }
        xor2(two, chi, rc_bit)
    } else {
        chi
    }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for ByteSpongeAir {
    fn eval(&self, builder: &mut AB) {
        {
            let mut prefix = PrefixAirBuilder { inner: builder };
            KeccakAir {}.eval(&mut prefix);
        }

        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("empty trace"),
            main.row_slice(1).expect("trace has only 1 row"),
        );

        let local_keccak: &KeccakCols<AB::Var> = local_row[..NUM_KECCAK_COLS].borrow();
        let next_keccak: &KeccakCols<AB::Var> = next_row[..NUM_KECCAK_COLS].borrow();

        let first_row_sel: AB::Expr = local_keccak.first_row_sel.clone().into();
        let transition_sel: AB::Expr = local_keccak.transition_sel.clone().into();

        let local_hash_end: AB::Expr = local_row[HASH_END_IDX].clone().into();
        let local_seen_end: AB::Expr = local_row[SEEN_END_IDX].clone().into();
        let next_seen_end: AB::Expr = next_row[SEEN_END_IDX].clone().into();
        let local_active: AB::Expr = local_row[ACTIVE_IDX].clone().into();
        let next_active: AB::Expr = next_row[ACTIVE_IDX].clone().into();
        let local_is_new_start: AB::Expr = local_row[IS_NEW_START_IDX].clone().into();
        let next_is_new_start: AB::Expr = next_row[IS_NEW_START_IDX].clone().into();

        let local_first_step: AB::Expr = local_keccak.step_flags[0].clone().into();
        let local_final_step: AB::Expr = local_keccak.step_flags[NUM_ROUNDS_MIN_1].clone().into();
        let next_first_step: AB::Expr = next_keccak.step_flags[0].clone().into();

        let local_block_bytes = &local_row[BLOCK_BYTES_START..BLOCK_BYTES_START + RATE_BYTES];
        let next_block_bytes = &next_row[BLOCK_BYTES_START..BLOCK_BYTES_START + RATE_BYTES];
        let local_is_padding = &local_row[IS_PADDING_START..IS_PADDING_START + RATE_BYTES];
        let next_is_padding = &next_row[IS_PADDING_START..IS_PADDING_START + RATE_BYTES];

        let local_is_final_block: AB::Expr = local_is_padding[RATE_BYTES - 1].clone().into();
        let continue_gate = transition_sel.clone()
            * local_final_step.clone()
            * local_active.clone()
            * (AB::Expr::ONE - local_is_final_block.clone())
            * next_active.clone();

        assert_bool_like(builder, local_hash_end.clone());
        assert_bool_like(builder, local_seen_end.clone());
        assert_bool_like(builder, local_active.clone());
        assert_bool_like(builder, local_is_new_start.clone());

        for v in local_is_padding {
            assert_bool_like(builder, v.clone().into());
        }

        builder.assert_zero(first_row_sel.clone() * local_seen_end.clone());
        builder.assert_zero(first_row_sel.clone() * (local_active.clone() - AB::Expr::ONE));
        builder.assert_zero(first_row_sel.clone() * (local_is_new_start.clone() - AB::Expr::ONE));

        // is_new_start can only happen on the first permutation row and is unique.
        builder
            .assert_zero(local_is_new_start.clone() * (AB::Expr::ONE - local_first_step.clone()));
        builder.assert_zero(transition_sel.clone() * next_is_new_start.clone());

        builder.assert_zero(
            transition_sel.clone()
                * (next_seen_end - (local_seen_end.clone() + local_hash_end.clone())),
        );
        builder.assert_zero(
            transition_sel.clone()
                * (next_active.clone() - (local_active.clone() - local_hash_end.clone())),
        );

        builder.assert_zero(local_hash_end.clone() * (AB::Expr::ONE - local_active.clone()));
        builder.assert_zero(local_hash_end.clone() * (AB::Expr::ONE - local_final_step.clone()));

        let last_row_gate = AB::Expr::ONE - transition_sel.clone();
        builder
            .assert_zero(last_row_gate * (local_seen_end + local_hash_end.clone() - AB::Expr::ONE));

        // is_padding_byte can only transition 0 -> 1 once.
        for i in 1..RATE_BYTES {
            let prev: AB::Expr = local_is_padding[i - 1].clone().into();
            let curr: AB::Expr = local_is_padding[i].clone().into();
            builder.assert_zero(prev * (AB::Expr::ONE - curr));
        }

        // block bytes and padding flags are constant within a permutation.
        let same_block_gate = transition_sel.clone() * (AB::Expr::ONE - local_final_step.clone());
        for i in 0..RATE_BYTES {
            let local_b: AB::Expr = local_block_bytes[i].clone().into();
            let next_b: AB::Expr = next_block_bytes[i].clone().into();
            builder.assert_zero(same_block_gate.clone() * (local_b - next_b));

            let local_p: AB::Expr = local_is_padding[i].clone().into();
            let next_p: AB::Expr = next_is_padding[i].clone().into();
            builder.assert_zero(same_block_gate.clone() * (local_p - next_p));
        }

        // Padding values for final block.
        let has_single_padding_byte: AB::Expr = local_is_padding[RATE_BYTES - 1].clone().into()
            - local_is_padding[RATE_BYTES - 2].clone().into();
        builder.assert_zero(
            local_is_final_block.clone()
                * has_single_padding_byte.clone()
                * (AB::Expr::from(local_block_bytes[RATE_BYTES - 1].clone())
                    - AB::Expr::from(AB::F::from_u8(0x81))),
        );

        let has_multiple_padding_bytes: AB::Expr = AB::Expr::ONE - has_single_padding_byte.clone();
        for i in 0..RATE_BYTES - 1 {
            let is_first_padding_byte: AB::Expr = if i > 0 {
                local_is_padding[i].clone().into() - local_is_padding[i - 1].clone().into()
            } else {
                local_is_padding[i].clone().into()
            };

            builder.assert_zero(
                local_is_final_block.clone()
                    * has_multiple_padding_bytes.clone()
                    * is_first_padding_byte.clone()
                    * (AB::Expr::from(local_block_bytes[i].clone())
                        - AB::Expr::from(AB::F::from_u8(0x01))),
            );

            builder.assert_zero(
                local_is_final_block.clone()
                    * has_multiple_padding_bytes.clone()
                    * AB::Expr::from(local_is_padding[i].clone())
                    * (AB::Expr::ONE - is_first_padding_byte)
                    * AB::Expr::from(local_block_bytes[i].clone()),
            );
        }

        builder.assert_zero(
            local_is_final_block.clone()
                * has_multiple_padding_bytes
                * (AB::Expr::from(local_block_bytes[RATE_BYTES - 1].clone())
                    - AB::Expr::from(AB::F::from_u8(0x80))),
        );

        // FIXME(soundness): This phase enforces packed absorb consistency and benchmark-focused
        // size targets. It does not independently enforce strict per-byte range soundness for all
        // first-block non-padding byte positions.

        // Start-of-sponge linkage: first preimage rate = block bytes, capacity = 0.
        let start_gate = local_is_new_start.clone() * local_active.clone();
        for i in 0..RATE_U16S {
            let (y, x, limb) = state_u16_position(i);
            let local_pre_limb: AB::Expr = local_keccak.preimage[y][x][limb].clone().into();
            let local_block_u16 = block_u16_expr::<AB>(local_block_bytes, i);
            builder.assert_zero(start_gate.clone() * (local_pre_limb - local_block_u16));
        }

        for i in RATE_U16S..STATE_U16S {
            let (y, x, limb) = state_u16_position(i);
            let local_pre_limb: AB::Expr = local_keccak.preimage[y][x][limb].clone().into();
            builder.assert_zero(start_gate.clone() * local_pre_limb);
        }

        // Absorb consistency on non-final block boundaries.
        let two = AB::Expr::TWO;
        for byte_idx in 0..RATE_BYTES {
            let u16_idx = byte_idx / 2;
            let is_hi = (byte_idx % 2) == 1;
            let (y, x, limb) = state_u16_position(u16_idx);

            let mut packed = AB::Expr::ZERO;
            let mut pow2 = AB::Expr::ONE;
            let z_base = (limb * 16) + if is_hi { 8 } else { 0 };

            for bit in 0..8 {
                let z = z_base + bit;
                let out_bit = local_output_bit::<AB>(local_keccak, x, y, z, two.clone());
                let next_pre_bit = next_input_bit::<AB>(next_keccak, x, y, z, two.clone());
                let xored = xor2(two.clone(), out_bit, next_pre_bit);
                packed += xored * pow2.clone();
                pow2 = pow2.clone() + pow2;
            }

            let next_block_byte: AB::Expr = next_block_bytes[byte_idx].clone().into();
            builder.assert_zero(continue_gate.clone() * (next_block_byte - packed));
        }

        // Capacity passthrough between non-final blocks.
        for i in RATE_U16S..STATE_U16S {
            let (y, x, limb) = state_u16_position(i);
            let local_post_limb: AB::Expr = local_keccak.a_prime_prime_prime(y, x, limb).into();
            let next_pre_limb: AB::Expr = next_keccak.preimage[y][x][limb].clone().into();
            builder.assert_zero(continue_gate.clone() * (local_post_limb - next_pre_limb));
        }

        // Digest check on hash_end row: first 16 u16 limbs (32 bytes).
        for limb_idx in 0..DIGEST_LIMBS {
            let pv_limb: AB::Expr = builder.public_values()[limb_idx].into();
            let u64_index = limb_idx / U64_LIMBS;
            let limb_in_u64 = limb_idx % U64_LIMBS;
            let y = u64_index / 5;
            let x = u64_index % 5;
            let out_limb: AB::Expr = local_keccak.a_prime_prime_prime(y, x, limb_in_u64).into();
            builder.assert_zero(local_hash_end.clone() * (out_limb - pv_limb));
        }

        // Keep transition linkage active at permutation boundaries while active.
        let boundary_gate = transition_sel * local_final_step * next_first_step * next_active;
        builder.assert_zero(boundary_gate * (local_active - AB::Expr::ONE));
    }
}
