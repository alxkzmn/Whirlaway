use alloc::vec::Vec;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::generate_trace_rows as local_generate;
use crate::sponge_air::DIGEST_LIMBS;
use crate::sponge_trace::{
    digest_from_trace_row, generate_sponge_trace_and_digest_limbs, hash_end_row_for_message_len,
};
use crate::{output_limb as local_output_limb, NUM_ROUNDS as LOCAL_NUM_ROUNDS};

// Upstream types
use p3_keccak_air as upstream;
use sha3::Digest;
use upstream::output_limb as upstream_output_limb;
use upstream::NUM_ROUNDS as UPSTREAM_NUM_ROUNDS;

#[test]
fn traces_match_for_random_inputs() {
    type F = p3_goldilocks::Goldilocks;

    let mut rng = SmallRng::seed_from_u64(1);

    // Generate a few permutations (multiple of 24 rows needed by upstream design)
    let num_perms = 8usize; // small for test speed

    let inputs: Vec<[u64; 25]> = (0..num_perms)
        .map(|_| {
            let mut a = [0u64; 25];
            for item in &mut a {
                *item = rng.random();
            }
            a
        })
        .collect();

    // Local trace using explicit inputs
    let local_trace: RowMajorMatrix<F> = local_generate::<F>(inputs.clone(), 0);

    // Upstream trace using the same explicit inputs
    let upstream_trace: RowMajorMatrix<F> = upstream::generate_trace_rows::<F>(inputs, 0);

    // Compare only Keccak-f outputs (rate limbs) at the last row per permutation
    assert_eq!(LOCAL_NUM_ROUNDS, UPSTREAM_NUM_ROUNDS);
    const RATE_LIMBS: usize = 1088 / 16;
    for p in 0..num_perms {
        let row = p * LOCAL_NUM_ROUNDS + (LOCAL_NUM_ROUNDS - 1);
        for i in 0..RATE_LIMBS {
            let col_local = local_output_limb(i);
            let col_up = upstream_output_limb(i);
            let a = local_trace.values[row * local_trace.width() + col_local];
            let b = upstream_trace.values[row * upstream_trace.width() + col_up];
            assert_eq!(a, b, "mismatch at perm {}, limb {}", p, i);
        }
    }
}

#[test]
fn keccak_sponge_end_to_end_matches_reference_digest() {
    type F = p3_goldilocks::Goldilocks;

    let msg = b"whirlaway-keccak";
    let (trace, digest_limbs) = generate_sponge_trace_and_digest_limbs::<F>(msg);

    // Reference digest from sha3::Keccak256.
    let mut hasher = sha3::Keccak256::new();
    hasher.update(msg);
    let digest = hasher.finalize();

    let mut expected_limbs = [0u16; DIGEST_LIMBS];
    for (i, limb) in expected_limbs.iter_mut().enumerate().take(DIGEST_LIMBS) {
        *limb = u16::from_le_bytes([digest[2 * i], digest[2 * i + 1]]);
    }
    assert_eq!(digest_limbs, expected_limbs);

    // Also check the output limbs at the hash_end row match the digest limbs.
    let hash_end_row = hash_end_row_for_message_len(msg.len());
    let trace_limbs = digest_from_trace_row(&trace, hash_end_row);
    assert_eq!(trace_limbs, expected_limbs);
}
