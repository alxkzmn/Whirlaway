use air::AirSettings;
use air::table::AirTable;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use p3_challenger::DuplexChallenger;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear, Poseidon2KoalaBear};
use p3_matrix::Matrix;
use p3_poseidon2_air::{Poseidon2Air, RoundConstants, generate_trace_rows};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::{Rng, SeedableRng, rngs::StdRng};
use whir_p3::{
    fiat_shamir::domain_separator::DomainSeparator, parameters::FoldingFactor,
    parameters::errors::SecurityAssumption, whir::parameters::WhirConfig,
};

// Koalabear
type Poseidon16 = Poseidon2KoalaBear<16>;
type Poseidon24 = Poseidon2KoalaBear<24>;

type MerkleHash = PaddingFreeSponge<Poseidon24, 24, 16, 8>; // leaf hashing
type MerkleCompress = TruncatedPermutation<Poseidon16, 2, 8, 16>; // 2-to-1 compression
type MyChallenger = DuplexChallenger<F, Poseidon16, 16, 8>;

// Koalabear
type F = KoalaBear;
type EF = BinomialExtensionField<F, 8>;
type LinearLayers = GenericPoseidon2LinearLayersKoalaBear;
const SBOX_DEGREE: u64 = 5;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = 4;
const PARTIAL_ROUNDS: usize = 20;

const WIDTH: usize = 16;

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("whirlaway_poseidon2_proof");
    group.sample_size(10);

    let mut rng = StdRng::seed_from_u64(0);
    let constants =
        RoundConstants::<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>::from_rng(&mut rng);

    let poseidon_air = Poseidon2Air::<
        F,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >::new(constants.clone());

    // Default settings for benchmarking
    let settings = AirSettings {
        security_bits: 128,
        whir_soudness_type: SecurityAssumption::CapacityBound,
        whir_log_inv_rate: 3,
        whir_folding_factor: FoldingFactor::Constant(2),
        univariate_skips: 0,
        whir_initial_domain_reduction_factor: 1,
    };

    // Benchmark different trace sizes
    for log_n_rows in [6, 7, 8, 9] {
        group.bench_with_input(
            BenchmarkId::from_parameter(log_n_rows),
            &log_n_rows,
            |b, log_n_rows| {
                b.iter(|| {
                    // The witness generation is included because ProveKit doesn't separate witness generation and proving.

                    let n_rows = 1 << log_n_rows;
                    let inputs: Vec<[F; WIDTH]> = (0..n_rows)
                        .map(|_| std::array::from_fn(|_| rng.random()))
                        .collect();

                    let witness_matrix = generate_trace_rows::<
                        F,
                        LinearLayers,
                        WIDTH,
                        SBOX_DEGREE,
                        SBOX_REGISTERS,
                        HALF_FULL_ROUNDS,
                        PARTIAL_ROUNDS,
                    >(inputs, &constants, 0)
                    .transpose();

                    let mut witness = witness_matrix
                        .rows()
                        .map(|col| whir_p3::poly::evals::EvaluationsList::new(col.collect()))
                        .collect::<Vec<_>>();

                    let preprocessed_columns = witness.drain(..0).collect::<Vec<_>>(); // No preprocessed columns

                    let table = AirTable::<F, EF, _>::new(
                        Poseidon2Air::<
                            F,
                            LinearLayers,
                            WIDTH,
                            SBOX_DEGREE,
                            SBOX_REGISTERS,
                            HALF_FULL_ROUNDS,
                            PARTIAL_ROUNDS,
                        >::new(constants.clone()),
                        *log_n_rows,
                        settings.univariate_skips,
                        preprocessed_columns,
                        3,
                    );

                    let poseidon16 = Poseidon16::new_from_rng_128(&mut rng);
                    let poseidon24 = Poseidon24::new_from_rng_128(&mut rng);
                    let merkle_hash = MerkleHash::new(poseidon24);
                    let merkle_compress = MerkleCompress::new(poseidon16.clone());

                    let whir_params: WhirConfig<_, _, _, _, MyChallenger> = table
                        .build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());
                    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
                    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
                    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

                    let challenger = MyChallenger::new(poseidon16);

                    let mut prover_state = domainsep.to_prover_state(challenger.clone());
                    table.prove(
                        &settings,
                        merkle_hash,
                        merkle_compress,
                        &mut prover_state,
                        witness,
                    );
                    prover_state
                });
            },
        );
    }

    // Also benchmark verification
    let log_n_rows = 7; // Use smaller size for verification benchmark
    let n_rows = 1 << log_n_rows;
    let inputs: Vec<[F; WIDTH]> = (0..n_rows)
        .map(|_| std::array::from_fn(|_| rng.random()))
        .collect();

    let witness_matrix = generate_trace_rows::<
        F,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(inputs, &constants, 0)
    .transpose();

    let mut witness = witness_matrix
        .rows()
        .map(|col| whir_p3::poly::evals::EvaluationsList::new(col.collect()))
        .collect::<Vec<_>>();

    let preprocessed_columns = witness.drain(..0).collect::<Vec<_>>();

    let table = AirTable::<F, EF, _>::new(
        poseidon_air,
        log_n_rows,
        settings.univariate_skips.clone(),
        preprocessed_columns,
        3,
    );

    let poseidon16 = Poseidon16::new_from_rng_128(&mut rng);
    let poseidon24 = Poseidon24::new_from_rng_128(&mut rng);
    let merkle_hash = MerkleHash::new(poseidon24);
    let merkle_compress = MerkleCompress::new(poseidon16.clone());

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());
    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = MyChallenger::new(poseidon16);

    let mut prover_state = domainsep.to_prover_state(challenger.clone());
    table.prove(
        &settings,
        merkle_hash.clone(),
        merkle_compress.clone(),
        &mut prover_state,
        witness,
    );

    group.bench_function("verify", |b| {
        b.iter(|| {
            let mut verifier_state =
                domainsep.to_verifier_state(prover_state.proof_data().to_vec(), challenger.clone());
            let _ = table.verify(
                &settings,
                merkle_hash.clone(),
                merkle_compress.clone(),
                &mut verifier_state,
                log_n_rows,
            );
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
