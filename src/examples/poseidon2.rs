use ::air::AirSettings;
use p3_poseidon2_air::RoundConstants;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::fmt;
use std::time::{Duration, Instant};
use tracing::level_filters::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt, util::SubscriberInitExt};
use whir_p3::parameters::FoldingFactor;

use crate::circuits::poseidon2::{
    Challenger as MyChallenger, F, HALF_FULL_ROUNDS, MerkleCompress, MerkleHash, PARTIAL_ROUNDS,
    Poseidon2Circuit, Poseidon16, Poseidon24, WIDTH,
};
use crate::proving_system::{ProvingSystemConfig, prepare, proof_size, prove, verify};

#[derive(Clone, Debug)]
pub struct Poseidon2Benchmark {
    pub log_n_rows: usize,
    pub settings: AirSettings,
    pub prover_time: Duration,
    pub verifier_time: Duration,
    pub proof_size: f64, // in bytes
}

impl fmt::Display for Poseidon2Benchmark {
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
            "Proved {} poseidon2 hashes in {:.3} s ({} / s)",
            n_rows,
            self.prover_time.as_millis() as f64 / 1000.0,
            (n_rows as f64 / self.prover_time.as_secs_f64()).round() as usize
        )?;
        writeln!(f, "Proof size: {:.1} KiB", self.proof_size / 1024.0)?;
        writeln!(f, "Verification: {} ms", self.verifier_time.as_millis())
    }
}

pub fn prove_poseidon2(
    log_n_rows: usize,
    settings: AirSettings,
    n_preprocessed_columns: usize,
    display_logs: bool,
) -> Poseidon2Benchmark {
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
    let constants =
        RoundConstants::<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>::from_rng(&mut rng);

    let inputs: Vec<[F; WIDTH]> = (0..n_rows)
        .map(|_| std::array::from_fn(|_| rng.random()))
        .collect();

    let poseidon16 = Poseidon16::new_from_rng_128(&mut rng);
    let poseidon24 = Poseidon24::new_from_rng_128(&mut rng);
    let merkle_hash = MerkleHash::new(poseidon24);
    let merkle_compress = MerkleCompress::new(poseidon16.clone());
    let challenger = MyChallenger::new(poseidon16);
    let proving_settings =
        ProvingSystemConfig::new(settings.clone(), merkle_hash, merkle_compress, challenger);

    let t = Instant::now();

    let poseidon_circuit = Poseidon2Circuit {
        log_length: log_n_rows,
        constants,
    };
    let prepared = prepare::<Poseidon2Circuit, _, 8>(&proving_settings, poseidon_circuit);
    let proof = prove(&prepared, &proving_settings, &inputs);

    let prover_time = t.elapsed();
    let verify_enabled = std::env::var("VERIFY")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(true);
    let mut verifier_time = Duration::ZERO;
    if verify_enabled {
        let time = Instant::now();
        verify(&prepared, &proving_settings, &proof).unwrap();
        verifier_time = time.elapsed();
    }

    let proof_size = proof_size::<Poseidon2Circuit, 8>(&proof) as f64;

    Poseidon2Benchmark {
        log_n_rows,
        settings,
        prover_time,
        verifier_time,
        proof_size,
    }
}
