use alloc::vec;
use alloc::vec::Vec;

use p3_field::PrimeField64;
use p3_keccak::KeccakF;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_symmetric::Permutation;

use crate::generation::generate_trace_rows;
use crate::sponge_air::{
    ACTIVE_IDX, BLOCK_BITS_START, DIGEST_LIMBS, HASH_END_IDX, OUT_BITS_START, RATE_BITS,
    RATE_BYTES, SEEN_END_IDX, STATE_BITS,
};
use crate::{NUM_KECCAK_COLS, NUM_ROUNDS};

fn keccak_pad10star1(mut msg: Vec<u8>) -> Vec<u8> {
    // Keccak-256 uses domain suffix 0x01, then pad10*1 (ends with 0x80 in last byte).
    msg.push(0x01);
    while (msg.len() % RATE_BYTES) != (RATE_BYTES - 1) {
        msg.push(0x00);
    }
    msg.push(0x80);
    msg
}

fn bytes_to_rate_block_bits(block: &[u8; RATE_BYTES]) -> [u8; RATE_BITS] {
    let mut bits = [0u8; RATE_BITS];
    for (i, byte) in block.iter().enumerate() {
        for b in 0..8 {
            // Little-endian bit order within each byte.
            bits[i * 8 + b] = (byte >> b) & 1;
        }
    }
    bits
}

fn state_to_bits_le(state: &[u64; 25]) -> [u8; STATE_BITS] {
    let mut bits = [0u8; STATE_BITS];
    for lane in 0..25 {
        let v = state[lane];
        for z in 0..64 {
            bits[lane * 64 + z] = ((v >> z) & 1) as u8;
        }
    }
    bits
}

fn digest_to_u16_limbs_le(digest: &[u8; 32]) -> [u16; DIGEST_LIMBS] {
    let mut out = [0u16; DIGEST_LIMBS];
    for i in 0..DIGEST_LIMBS {
        out[i] = u16::from_le_bytes([digest[2 * i], digest[2 * i + 1]]);
    }
    out
}

fn digest_from_state(state: &[u64; 25]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

/// Generate a trace for Keccak-256 over `message`.
///
/// Returns:
/// - full trace matrix (KeccakAir columns + sponge extra columns)
/// - public digest as 16 little-endian 16-bit limbs (32 bytes)
pub fn generate_sponge_trace_and_digest_limbs<F: PrimeField64>(
    message: &[u8],
) -> (RowMajorMatrix<F>, [u16; DIGEST_LIMBS]) {
    generate_sponge_trace_inner(message, [0u64; 25])
}

/// Same as [`generate_sponge_trace_and_digest_limbs`] but with a caller-chosen initial state.
/// Useful for testing that the zero-IV constraint rejects non-standard IVs.
#[cfg(any(test, feature = "test-utils"))]
pub fn generate_sponge_trace_with_iv<F: PrimeField64>(
    message: &[u8],
    initial_state: [u64; 25],
) -> (RowMajorMatrix<F>, [u16; DIGEST_LIMBS]) {
    generate_sponge_trace_inner(message, initial_state)
}

fn generate_sponge_trace_inner<F: PrimeField64>(
    message: &[u8],
    initial_state: [u64; 25],
) -> (RowMajorMatrix<F>, [u16; DIGEST_LIMBS]) {
    // Sponge simulation: absorb padded blocks, record permutation inputs, record outputs.
    let padded = keccak_pad10star1(message.to_vec());
    debug_assert_eq!(padded.len() % RATE_BYTES, 0);
    let num_blocks = padded.len() / RATE_BYTES;

    let mut perm_inputs: Vec<[u64; 25]> = Vec::with_capacity(num_blocks);
    let mut block_bits: Vec<[u8; RATE_BITS]> = Vec::with_capacity(num_blocks);
    let mut perm_outputs: Vec<[u64; 25]> = Vec::with_capacity(num_blocks);

    let mut state = initial_state;
    for b in 0..num_blocks {
        let block: &[u8; RATE_BYTES] = padded[b * RATE_BYTES..(b + 1) * RATE_BYTES]
            .try_into()
            .expect("slice length is RATE_BYTES");

        // Interpret block as 17 u64 lanes, little-endian per lane.
        for lane in 0..(RATE_BYTES / 8) {
            let chunk: [u8; 8] = block[lane * 8..(lane + 1) * 8]
                .try_into()
                .expect("u64 chunk length");
            let w = u64::from_le_bytes(chunk);
            state[lane] ^= w;
        }

        perm_inputs.push(state);
        block_bits.push(bytes_to_rate_block_bits(block));

        KeccakF.permute_mut(&mut state);
        perm_outputs.push(state);
    }

    let digest = digest_from_state(perm_outputs.last().expect("at least one block"));

    // Use KeccakAir trace generation for the permutation part.
    // It will pad to a power-of-two number of rows, possibly adding extra permutations/rounds.
    let keccak_trace = generate_trace_rows::<F>(perm_inputs.clone(), 0);
    let height = keccak_trace.height();
    let width = NUM_KECCAK_COLS + (1 + 1 + 1 + RATE_BITS + STATE_BITS);

    // Allocate full trace and copy permutation columns.
    let mut values = vec![F::ZERO; height * width];
    for r in 0..height {
        let src = keccak_trace.row_slice(r).expect("row_slice failed");
        let dst = &mut values[r * width..r * width + NUM_KECCAK_COLS];
        dst.copy_from_slice(&src);
    }

    // Helper to set a value in the full trace.
    let mut set = |r: usize, c: usize, v: F| {
        values[r * width + c] = v;
    };

    // Mark hash_end on the final round row of the last *real* permutation.
    let hash_end_row = (perm_outputs.len() * NUM_ROUNDS) - 1;
    debug_assert!(
        hash_end_row < height,
        "keccak trace too short for expected hash_end row"
    );

    // Fill extras.
    // active starts at 1 and drops to 0 right after hash_end row.
    for r in 0..height {
        let active = if r <= hash_end_row { F::ONE } else { F::ZERO };
        set(r, ACTIVE_IDX, active);
        // seen_end becomes 1 immediately after hash_end row.
        let seen_end = if r <= hash_end_row { F::ZERO } else { F::ONE };
        set(r, SEEN_END_IDX, seen_end);
        set(
            r,
            HASH_END_IDX,
            if r == hash_end_row { F::ONE } else { F::ZERO },
        );
    }

    // Block bits: constant across each full permutation; zero for padding beyond real blocks.
    for (perm_idx, bits) in block_bits.iter().enumerate() {
        let start_row = perm_idx * NUM_ROUNDS;
        let end_row = ((perm_idx + 1) * NUM_ROUNDS).min(height);
        for r in start_row..end_row {
            for (i, bit) in bits.iter().enumerate().take(RATE_BITS) {
                set(
                    r,
                    BLOCK_BITS_START + i,
                    if *bit == 1 { F::ONE } else { F::ZERO },
                );
            }
        }
    }

    // Output bits on final-step rows for real permutations (active region).
    for (perm_idx, out_state) in perm_outputs.iter().enumerate() {
        let final_row = (perm_idx + 1) * NUM_ROUNDS - 1;
        if final_row >= height {
            break;
        }
        let bits = state_to_bits_le(out_state);
        for (i, bit) in bits.iter().enumerate().take(STATE_BITS) {
            set(
                final_row,
                OUT_BITS_START + i,
                if *bit == 1 { F::ONE } else { F::ZERO },
            );
        }
    }

    // Public digest as limbs.
    let digest_limbs = digest_to_u16_limbs_le(&digest);

    (RowMajorMatrix::new(values, width), digest_limbs)
}

#[cfg(test)]
pub(crate) fn hash_end_row_for_message_len(msg_len: usize) -> usize {
    let padded_len = keccak_pad10star1(vec![0u8; msg_len]).len();
    let num_blocks = padded_len / RATE_BYTES;
    (num_blocks * NUM_ROUNDS) - 1
}

#[cfg(test)]
pub(crate) fn digest_from_trace_row<F: PrimeField64>(
    trace: &RowMajorMatrix<F>,
    row: usize,
) -> [u16; DIGEST_LIMBS] {
    use crate::columns::output_limb;

    let mut limbs = [0u16; DIGEST_LIMBS];
    for (i, limb) in limbs.iter_mut().enumerate().take(DIGEST_LIMBS) {
        let col = output_limb(i);
        let v = trace.values[row * trace.width() + col];
        *limb = v.as_canonical_u64() as u16;
    }
    limbs
}
