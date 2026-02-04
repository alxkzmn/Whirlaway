use air::AirSettings;
use p3_keccak::Keccak256Hash;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::fmt;
use std::time::{Duration, Instant};
use tracing::level_filters::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt, util::SubscriberInitExt};
use whir_p3::parameters::FoldingFactor;

use crate::circuits::keccak_air::{
    Challenger as MyChallenger, KeccakAirCircuit, MerkleCompress, MerkleHash,
};
use crate::hashers::KECCAK_DIGEST_ELEMS;
use crate::proving_system::{ProvingSystemConfig, prepare, proof_size, prove, verify};

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
            "Proved {} keccak hashes in {:.3} s ({} / s)",
            n_rows,
            self.prover_time.as_millis() as f64 / 1000.0,
            (n_rows as f64 / self.prover_time.as_secs_f64()).round() as usize
        )?;
        writeln!(f, "Proof size: {:.1} KiB", self.proof_size / 1024.0)?;
        writeln!(f, "Verification: {} ms", self.verifier_time.as_millis())
    }
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

    let n_rows = 1 << log_n_rows;

    let mut rng = StdRng::seed_from_u64(0);

    let inputs: Vec<[u64; 25]> = (0..n_rows)
        .map(|_| std::array::from_fn(|_| rng.random()))
        .collect();

    let merkle_hash = MerkleHash::default();
    let merkle_compress = MerkleCompress::default();
    let challenger = MyChallenger::from_hasher(Vec::new(), Keccak256Hash);
    let proving_settings =
        ProvingSystemConfig::new(settings.clone(), merkle_hash, merkle_compress, challenger);

    let t = Instant::now();

    let keccak_air_circuit = KeccakAirCircuit { n_inputs: n_rows };

    let prepared =
        prepare::<KeccakAirCircuit, _, KECCAK_DIGEST_ELEMS>(&proving_settings, keccak_air_circuit);
    let proof = prove(&prepared, &inputs);

    let prover_time = t.elapsed();
    let verify_enabled = std::env::var("VERIFY")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(true);
    let mut verifier_time = Duration::ZERO;
    if verify_enabled {
        let time = Instant::now();
        verify(&prepared, &proof).unwrap();
        verifier_time = time.elapsed();
    }

    let proof_size = proof_size::<KeccakAirCircuit, KECCAK_DIGEST_ELEMS>(&proof) as f64;

    // TODO(onchain): Serialize Keccak digests to bytes32 at the I/O boundary.

    KeccakBenchmark {
        log_n_rows,
        settings,
        prover_time,
        verifier_time,
        proof_size,
    }
}
