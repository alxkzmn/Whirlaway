use air::AirSettings;
use air::table::AirTable;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use keccak_air::{KeccakAir, generate_trace_rows};
use p3_challenger::DuplexChallenger;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_matrix::Matrix;
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

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("whirlaway_keccak_proof");
    group.sample_size(10);

    let settings = AirSettings::new(
        128,
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(7, 4),
        1,
        4,
        5,
    );

    let mut rng = StdRng::seed_from_u64(0);
    let n_preprocessed_columns = 0;

    // Benchmark different trace sizes
    for log_n_rows in [5, 6, 7, 8] {
        group.bench_with_input(
            BenchmarkId::from_parameter(log_n_rows),
            &log_n_rows,
            |b, log_n_rows| {
                b.iter(|| {
                    // The witness generation is included because ProveKit doesn't separate witness generation and proving.

                    let keccak_air = KeccakAir {};

                    let n_rows = 1 << log_n_rows;

                    let inputs: Vec<[u64; 25]> = (0..n_rows)
                        .map(|_| std::array::from_fn(|_| rng.random()))
                        .collect();

                    let witness_matrix = generate_trace_rows(inputs, 0).transpose();

                    let mut witness = witness_matrix
                        .rows()
                        .map(|col| whir_p3::poly::evals::EvaluationsList::new(col.collect()))
                        .collect::<Vec<_>>();

                    let preprocessed_columns =
                        witness.drain(..n_preprocessed_columns).collect::<Vec<_>>();

                    let table = AirTable::<F, EF, _>::new(
                        keccak_air,
                        (witness_matrix.width().ilog2()) as usize,
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
                        merkle_hash.clone(),
                        merkle_compress.clone(),
                        &mut prover_state,
                        witness,
                    );

                    prover_state
                });
            },
        );
    }

    let log_length = 7;

    group.bench_function("verify", |b| {
        b.iter_batched(
            || {
                let keccak_air = KeccakAir {};

                let n_rows = 1 << log_length;

                let inputs: Vec<[u64; 25]> = (0..n_rows)
                    .map(|_| std::array::from_fn(|_| rng.random()))
                    .collect();

                let witness_matrix = generate_trace_rows(inputs, 0).transpose();

                let mut witness = witness_matrix
                    .rows()
                    .map(|col| whir_p3::poly::evals::EvaluationsList::new(col.collect()))
                    .collect::<Vec<_>>();

                let preprocessed_columns =
                    witness.drain(..n_preprocessed_columns).collect::<Vec<_>>();

                let log_length = (witness_matrix.width().ilog2()) as usize;
                let table = AirTable::<F, EF, _>::new(
                    keccak_air,
                    log_length,
                    settings.univariate_skips,
                    preprocessed_columns,
                    3,
                );

                let poseidon16 = Poseidon16::new_from_rng_128(&mut rng);
                let poseidon24 = Poseidon24::new_from_rng_128(&mut rng);
                let merkle_hash = MerkleHash::new(poseidon24);
                let merkle_compress = MerkleCompress::new(poseidon16.clone());

                let whir_params: WhirConfig<_, _, _, _, MyChallenger> = table.build_whir_params(
                    &settings,
                    merkle_hash.clone(),
                    merkle_compress.clone(),
                );
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

                (
                    domainsep,
                    prover_state,
                    challenger,
                    table,
                    merkle_hash,
                    merkle_compress,
                    log_length,
                )
            },
            |(
                domainsep,
                prover_state,
                challenger,
                table,
                merkle_hash,
                merkle_compress,
                log_length,
            )| {
                let mut verifier_state =
                    domainsep.to_verifier_state(prover_state.proof_data().to_vec(), challenger);
                table
                    .verify(
                        &settings,
                        merkle_hash,
                        merkle_compress,
                        &mut verifier_state,
                        log_length,
                    )
                    .unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
