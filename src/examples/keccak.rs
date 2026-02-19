use air::AirSettings;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use std::fmt;
use std::time::{Duration, Instant};
use tracing::level_filters::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt, util::SubscriberInitExt};
use whir_p3::parameters::FoldingFactor;

use crate::circuits::keccak256::{Keccak256Circuit, Keccak256Input};
use crate::hashers::KECCAK_DIGEST_ELEMS;
use crate::proving_system::{Circuit, KeccakProvingSystemConfig, prepare, proof_size, prove, verify};
use sha3::Digest;

// BabyBear
// type F = BabyBear;
// type EF = BinomialExtensionField<F, 4>;
// type LinearLayers = GenericPoseidon2LinearLayersBabyBear;
// const SBOX_DEGREE: u64 = 7;
// const SBOX_REGISTERS: usize = 1;
// const HALF_FULL_ROUNDS: usize = 4;
// const PARTIAL_ROUNDS: usize = 13;

#[derive(Clone, Debug)]
pub struct KeccakBenchmark {
    pub log_n_rows: usize,
    pub message_len: usize,
    pub settings: AirSettings,
    pub prover_time: Duration,
    pub verifier_time: Duration,
    pub proof_size: f64, // in bytes
}

impl fmt::Display for KeccakBenchmark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Security level: {} bits ({:?}), starting rate: 1/{}, folding factor: {}",
            self.settings.security_bits,
            self.settings.whir_soudness_type,
            1 << self.settings.whir_log_inv_rate,
            match self.settings.whir_folding_factor {
                FoldingFactor::Constant(factor) => format!("{factor}"),
                FoldingFactor::ConstantFromSecondRound(first, then) =>
                    format!("1st: {first} then {then}"),
            }
        )?;
        let n_rows = 1 << self.log_n_rows;
        writeln!(
            f,
            "Proved Keccak-256 message ({} bytes, {} rows) in {:.3} s",
            self.message_len,
            n_rows,
            self.prover_time.as_millis() as f64 / 1000.0
        )?;
        writeln!(f, "Proof size: {:.1} KiB", self.proof_size / 1024.0)?;
        writeln!(f, "Verification: {} ms", self.verifier_time.as_millis())
    }
}

fn message_len_for_log_length(log_n_rows: usize) -> (usize, usize) {
    use keccak_air::{NUM_ROUNDS, RATE_BYTES};

    let target_rows = 1usize << log_n_rows;
    let mut num_blocks_max = target_rows / NUM_ROUNDS;
    if num_blocks_max == 0 {
        num_blocks_max = 1;
    }

    let min_rows = (target_rows / 2).saturating_add(1);
    let num_blocks_min = min_rows.div_ceil(NUM_ROUNDS);

    let num_blocks = if num_blocks_max * NUM_ROUNDS <= target_rows / 2 {
        num_blocks_min.max(1)
    } else {
        num_blocks_max
    };

    let rows = num_blocks * NUM_ROUNDS;
    let actual_log_n_rows = rows.next_power_of_two().ilog2() as usize;
    let message_len = num_blocks * RATE_BYTES - 2;

    (message_len, actual_log_n_rows)
}

pub fn prove_keccak(
    log_n_rows: usize,
    settings: AirSettings,
    n_preprocessed_columns: usize,
    display_logs: bool,
) -> KeccakBenchmark {
    let _ = n_preprocessed_columns;
    if display_logs {
        let env_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();

        Registry::default()
            .with(env_filter)
            .with(ForestLayer::default())
            .init();
    }

    let (message_len, actual_log_n_rows) = message_len_for_log_length(log_n_rows);

    let mut rng = StdRng::seed_from_u64(0);

    let message: Vec<u8> = (0..message_len).map(|_| rng.random()).collect();

    let proving_settings = KeccakProvingSystemConfig {
        air_settings: settings.clone(),
    };

    let t = Instant::now();

    let keccak_air_circuit = Keccak256Circuit {
        input_size: message_len,
    };

    let prepared =
        prepare::<Keccak256Circuit, _, KECCAK_DIGEST_ELEMS>(&proving_settings, keccak_air_circuit);
    let expected_digest: [u8; 32] = sha3::Keccak256::digest(&message).into();
    let input = Keccak256Input {
        message,
        expected_digest,
    };
    let public_values = Keccak256Circuit::public_values(&prepared.circuit, &input);
    let proof = prove(&prepared, &input);

    let prover_time = t.elapsed();
    let verify_enabled = std::env::var("VERIFY")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(true);
    let mut verifier_time = Duration::ZERO;
    if verify_enabled {
        let time = Instant::now();
        verify(&prepared, &proof, &public_values).unwrap();
        verifier_time = time.elapsed();
    }

    let proof_size = proof_size::<Keccak256Circuit, KECCAK_DIGEST_ELEMS>(&proof) as f64;

    // TODO(onchain): Serialize Keccak digests to bytes32 at the I/O boundary.

    KeccakBenchmark {
        log_n_rows: actual_log_n_rows,
        message_len,
        settings,
        prover_time,
        verifier_time,
        proof_size,
    }
}
