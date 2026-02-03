use anyhow::{Context, Result};
use p3_field::PrimeField64;
use p3_keccak::KeccakF;
use p3_keccak_air::{NUM_KECCAK_COLS, NUM_ROUNDS};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::Permutation;

use crate::keccak::sponge_air::{
    ACTIVE_IDX, BLOCK_BITS_START, DIGEST_LIMBS, HASH_END_IDX, OUT_BITS_START, RATE_BITS,
    SEEN_END_IDX, STATE_BITS,
};

const RATE_BYTES: usize = 136;

fn keccak_pad10star1(mut msg: Vec<u8>) -> Vec<u8> {
    // Ethereum Keccak256 uses domain suffix 0x01, then pad10*1 (ends with 0x80 in last byte).
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

/// Generate a trace for Keccak-256 over a single message of `input_size` bytes.
///
/// Returns:
/// - full trace matrix (KeccakAir columns + sponge extra columns)
/// - public digest as 16 little-endian 16-bit limbs (32 bytes)
pub fn generate_trace_and_public_digest_limbs<F: PrimeField64>(
    input_size: usize,
) -> Result<(RowMajorMatrix<F>, [u16; DIGEST_LIMBS])> {
    // Deterministic message+digest to keep benchmarks stable.
    let (msg, digest) = utils::generate_keccak_input(input_size);
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32-byte keccak digest"))?;

    // Sponge simulation: absorb padded blocks, record permutation inputs, record outputs.
    let padded = keccak_pad10star1(msg);
    if padded.len() % RATE_BYTES != 0 {
        anyhow::bail!("padding produced non-multiple of rate");
    }
    let num_blocks = padded.len() / RATE_BYTES;

    let mut perm_inputs: Vec<[u64; 25]> = Vec::with_capacity(num_blocks);
    let mut block_bits: Vec<[u8; RATE_BITS]> = Vec::with_capacity(num_blocks);
    let mut perm_outputs: Vec<[u64; 25]> = Vec::with_capacity(num_blocks);

    let mut state = [0u64; 25];
    for b in 0..num_blocks {
        let block: &[u8; RATE_BYTES] = padded[b * RATE_BYTES..(b + 1) * RATE_BYTES]
            .try_into()
            .expect("slice length is RATE_BYTES");

        // Interpret block as 17 u64 lanes, little-endian per lane.
        for lane in 0..(RATE_BYTES / 8) {
            let chunk: [u8; 8] = block[lane * 8..(lane + 1) * 8]
                .try_into()
                .unwrap();
            let w = u64::from_le_bytes(chunk);
            state[lane] ^= w;
        }

        perm_inputs.push(state);
        block_bits.push(bytes_to_rate_block_bits(block));

        KeccakF.permute_mut(&mut state);
        perm_outputs.push(state);
    }

    // Sanity: sponge output digest matches utils' digest.
    let mut computed_digest = [0u8; 32];
    for i in 0..4 {
        computed_digest[i * 8..(i + 1) * 8].copy_from_slice(&perm_outputs.last().unwrap()[i].to_le_bytes());
    }
    if computed_digest != digest {
        anyhow::bail!("keccak sponge simulation digest mismatch");
    }

    // Use upstream KeccakAir trace generation for the permutation part.
    // It will pad to a power-of-two number of rows, possibly adding extra (zero) permutations/rounds.
    let keccak_trace =
        p3_keccak_air::generate_trace_rows::<F>(perm_inputs.clone(), 0);
    let height = keccak_trace.height();
    let width = NUM_KECCAK_COLS + (1 + 1 + 1 + RATE_BITS + STATE_BITS);

    // Allocate full trace and copy permutation columns.
    let mut values = vec![F::ZERO; height * width];
    for r in 0..height {
        let src = keccak_trace
            .row_slice(r)
            .context("row_slice failed")?;
        let dst = &mut values[r * width..r * width + NUM_KECCAK_COLS];
        dst.copy_from_slice(&src);
    }

    // Helper to set a value in the full trace.
    let mut set = |r: usize, c: usize, v: F| {
        values[r * width + c] = v;
    };

    // Mark hash_end on the final round row of the last *real* permutation.
    let hash_end_row = (perm_outputs.len() * NUM_ROUNDS) - 1;
    if hash_end_row >= height {
        anyhow::bail!("keccak trace too short for expected hash_end row");
    }

    // Fill extras.
    // active starts at 1 and drops to 0 right after hash_end row.
    for r in 0..height {
        let active = if r <= hash_end_row { F::ONE } else { F::ZERO };
        set(r, ACTIVE_IDX, active);
        // seen_end is 0 until hash_end row inclusive? We want transition seen_end_next = seen_end + hash_end.
        // So seen_end becomes 1 immediately AFTER hash_end row. That means:
        // - rows <= hash_end_row: seen_end = 0
        // - rows >  hash_end_row: seen_end = 1
        let seen_end = if r <= hash_end_row { F::ZERO } else { F::ONE };
        set(r, SEEN_END_IDX, seen_end);
        set(r, HASH_END_IDX, if r == hash_end_row { F::ONE } else { F::ZERO });
    }

    // Block bits: constant across each full permutation; zero for padding beyond real blocks.
    for (perm_idx, bits) in block_bits.iter().enumerate() {
        let start_row = perm_idx * NUM_ROUNDS;
        let end_row = ((perm_idx + 1) * NUM_ROUNDS).min(height);
        for r in start_row..end_row {
            for i in 0..RATE_BITS {
                set(r, BLOCK_BITS_START + i, if bits[i] == 1 { F::ONE } else { F::ZERO });
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
        for i in 0..STATE_BITS {
            set(final_row, OUT_BITS_START + i, if bits[i] == 1 { F::ONE } else { F::ZERO });
        }
    }

    // Public digest as limbs.
    let digest_limbs = digest_to_u16_limbs_le(&digest);

    Ok((RowMajorMatrix::new(values, width), digest_limbs))
}

