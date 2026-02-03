use ::air::AirSettings;
use air::table::AirTable;
use keccak_air::{KeccakAir, generate_trace_rows};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_field::PrimeField64;
use p3_field::extension::BinomialExtensionField;
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::fmt;
use std::time::{Duration, Instant};
use tracing::level_filters::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt, util::SubscriberInitExt};
use utils::{ProverState, VerifierState};
use whir_p3::{
    fiat_shamir::domain_separator::DomainSeparator, parameters::FoldingFactor,
    whir::parameters::WhirConfig,
};

use crate::hashers::{KECCAK_DIGEST_ELEMS, KeccakNodeCompress, KeccakU32BeLeafHasher};

type MerkleHash = KeccakU32BeLeafHasher; // leaf hashing
type MerkleCompress = KeccakNodeCompress; // 2-to-1 compression
type MyChallenger = SerializingChallenger32<F, HashChallenger<u8, Keccak256Hash, 32>>;

// Koalabear
type F = KoalaBear;
type EF = BinomialExtensionField<F, 8>;

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

    let keccak_air = KeccakAir {};

    let inputs: Vec<[u64; 25]> = (0..n_rows)
        .map(|_| std::array::from_fn(|_| rng.random()))
        .collect();

    let witness_matrix = generate_trace_rows(inputs, 0).transpose();

    let width = witness_matrix.width;
    let height = witness_matrix.values.len() / width;
    let mut witness = (0..width)
        .map(|col| {
            let values = (0..height)
                .map(|row| witness_matrix.values[row * width + col])
                .collect::<Vec<_>>();
            whir_p3::poly::evals::EvaluationsList::new(values)
        })
        .collect::<Vec<_>>();

    let preprocessed_columns = witness.drain(..n_preprocessed_columns).collect::<Vec<_>>();

    let table = AirTable::<F, EF, _>::new(
        keccak_air,
        (width.ilog2()) as usize,
        settings.univariate_skips,
        preprocessed_columns,
        3,
    );

    let merkle_hash = MerkleHash::default();
    let merkle_compress = MerkleCompress::default();

    let t = Instant::now();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash, merkle_compress);
    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, { KECCAK_DIGEST_ELEMS }>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, { KECCAK_DIGEST_ELEMS }>(&whir_params);

    let challenger = MyChallenger::from_hasher(Vec::new(), Keccak256Hash);

    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    let whir_proof = table.prove(
        &settings,
        merkle_hash,
        merkle_compress,
        &mut prover_state,
        witness,
    );
    // let proof_size = prover_state.narg_string().len();

    let prover_time = t.elapsed();
    let verify_enabled = std::env::var("VERIFY")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(true);
    let mut verifier_time = Duration::ZERO;
    if verify_enabled {
        let time = Instant::now();
        let mut verifier_state =
            VerifierState::new(&domainsep, prover_state.proof_data().to_vec(), challenger);
        table
            .verify(
                &settings,
                merkle_hash,
                merkle_compress,
                &mut verifier_state,
                (width.ilog2()) as usize,
                &whir_proof,
            )
            .unwrap();
        verifier_time = time.elapsed();
    }

    let proof_size = prover_state.proof_data().len() as f64 * (F::ORDER_U64 as f64).log2() / 8.0;

    // TODO(onchain): Serialize Keccak digests to bytes32 at the I/O boundary.

    KeccakBenchmark {
        log_n_rows,
        settings,
        prover_time,
        verifier_time,
        proof_size,
    }
}
