use alloc::vec;
use alloc::vec::Vec;

use p3_field::PrimeField64;
use p3_keccak::KeccakF;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_symmetric::Permutation;

use crate::byte_sponge_air::{
    ACTIVE_IDX, BLOCK_BYTES_START, BYTE_EXTRA_COLS, DIGEST_LIMBS, HASH_END_IDX, IS_NEW_START_IDX,
    IS_PADDING_START, RATE_BYTES, SEEN_END_IDX,
};
use crate::{generate_trace_rows, NUM_KECCAK_COLS, NUM_ROUNDS};

fn keccak_pad10star1(mut msg: Vec<u8>) -> Vec<u8> {
    msg.push(0x01);
    if msg.len().is_multiple_of(RATE_BYTES) {
        let last = msg.len() - 1;
        msg[last] ^= 0x80;
        return msg;
    }

    while (msg.len() % RATE_BYTES) != (RATE_BYTES - 1) {
        msg.push(0x00);
    }
    msg.push(0x80);
    msg
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

fn generate_byte_sponge_trace_inner<F: PrimeField64>(
    message: &[u8],
    initial_state: [u64; 25],
) -> (RowMajorMatrix<F>, [u16; DIGEST_LIMBS]) {
    let padded = keccak_pad10star1(message.to_vec());
    debug_assert_eq!(padded.len() % RATE_BYTES, 0);
    let num_blocks = padded.len() / RATE_BYTES;

    let mut perm_inputs: Vec<[u64; 25]> = Vec::with_capacity(num_blocks);
    let mut block_bytes: Vec<[u8; RATE_BYTES]> = Vec::with_capacity(num_blocks);
    let mut block_padding_flags: Vec<[u8; RATE_BYTES]> = Vec::with_capacity(num_blocks);
    let mut perm_outputs: Vec<[u64; 25]> = Vec::with_capacity(num_blocks);

    let mut state = initial_state;
    for block_idx in 0..num_blocks {
        let block: &[u8; RATE_BYTES] = padded[block_idx * RATE_BYTES..(block_idx + 1) * RATE_BYTES]
            .try_into()
            .expect("slice has RATE_BYTES bytes");

        for lane in 0..(RATE_BYTES / 8) {
            let chunk: [u8; 8] = block[lane * 8..(lane + 1) * 8]
                .try_into()
                .expect("lane chunk has 8 bytes");
            state[lane] ^= u64::from_le_bytes(chunk);
        }

        perm_inputs.push(state);
        block_bytes.push(*block);

        let mut padding_flags = [0u8; RATE_BYTES];
        for (i, bit) in padding_flags.iter_mut().enumerate().take(RATE_BYTES) {
            *bit = u8::from(block_idx * RATE_BYTES + i >= message.len());
        }
        block_padding_flags.push(padding_flags);

        KeccakF.permute_mut(&mut state);
        perm_outputs.push(state);
    }

    let digest = digest_from_state(perm_outputs.last().expect("at least one block"));

    let keccak_trace = generate_trace_rows::<F>(perm_inputs, 0);
    let height = keccak_trace.height();
    let width = NUM_KECCAK_COLS + BYTE_EXTRA_COLS;

    let mut values = vec![F::ZERO; height * width];
    for row in 0..height {
        let src = keccak_trace
            .row_slice(row)
            .expect("missing keccak trace row");
        values[row * width..row * width + NUM_KECCAK_COLS].copy_from_slice(&src);
    }

    let mut set = |row: usize, col: usize, v: F| {
        values[row * width + col] = v;
    };

    let hash_end_row = (num_blocks * NUM_ROUNDS) - 1;
    debug_assert!(hash_end_row < height);

    for row in 0..height {
        let active = if row <= hash_end_row { F::ONE } else { F::ZERO };
        let seen_end = if row <= hash_end_row { F::ZERO } else { F::ONE };
        set(row, ACTIVE_IDX, active);
        set(row, SEEN_END_IDX, seen_end);
        set(
            row,
            HASH_END_IDX,
            if row == hash_end_row { F::ONE } else { F::ZERO },
        );
    }

    for block_idx in 0..num_blocks {
        let block_start = block_idx * NUM_ROUNDS;
        let block_end = ((block_idx + 1) * NUM_ROUNDS).min(height);

        for row in block_start..block_end {
            for i in 0..RATE_BYTES {
                set(
                    row,
                    BLOCK_BYTES_START + i,
                    F::from_u8(block_bytes[block_idx][i]),
                );
                set(
                    row,
                    IS_PADDING_START + i,
                    F::from_u8(block_padding_flags[block_idx][i]),
                );
            }
        }

        if block_start < height {
            set(
                block_start,
                IS_NEW_START_IDX,
                if block_idx == 0 { F::ONE } else { F::ZERO },
            );
        }
    }

    let digest_limbs = digest_to_u16_limbs_le(&digest);
    (RowMajorMatrix::new(values, width), digest_limbs)
}

/// Generate a byte-sponge trace for Keccak-256 over `message`.
pub fn generate_byte_sponge_trace_and_digest_limbs<F: PrimeField64>(
    message: &[u8],
) -> (RowMajorMatrix<F>, [u16; DIGEST_LIMBS]) {
    generate_byte_sponge_trace_inner(message, [0u64; 25])
}

/// Same as [`generate_byte_sponge_trace_and_digest_limbs`] but with a caller-chosen initial state.
/// Useful for testing that zero-IV constraints reject non-standard IVs.
#[cfg(any(test, feature = "test-utils"))]
pub fn generate_byte_sponge_trace_with_iv<F: PrimeField64>(
    message: &[u8],
    initial_state: [u64; 25],
) -> (RowMajorMatrix<F>, [u16; DIGEST_LIMBS]) {
    generate_byte_sponge_trace_inner(message, initial_state)
}
