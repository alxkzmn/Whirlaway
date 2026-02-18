use air::{AirSettings, UnivariateSkipMode};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use p3_poseidon2_air::RoundConstants;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use whir_p3::{parameters::FoldingFactor, parameters::errors::SecurityAssumption};

use whirlaway::circuits::poseidon2::{
    Challenger as MyChallenger, F, HALF_FULL_ROUNDS, MerkleCompress, MerkleHash, PARTIAL_ROUNDS,
    Poseidon2Circuit, Poseidon16, Poseidon24, WIDTH,
};
use whirlaway::proving_system::{ProvingSystemConfig, prepare, prove, verify};

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("whirlaway_poseidon2_proof");
    group.sample_size(10);

    let mut rng = StdRng::seed_from_u64(0);
    let constants =
        RoundConstants::<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>::from_rng(&mut rng);

    // Default settings for benchmarking
    let settings = AirSettings::new_with_skip_mode(
        128,
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(7, 4),
        1,
        UnivariateSkipMode::auto(6, 4096),
        5,
    );

    let poseidon16 = Poseidon16::new_from_rng_128(&mut rng);
    let poseidon24 = Poseidon24::new_from_rng_128(&mut rng);
    let merkle_hash = MerkleHash::new(poseidon24);
    let merkle_compress = MerkleCompress::new(poseidon16.clone());
    let challenger = MyChallenger::new(poseidon16);
    let proving_settings =
        ProvingSystemConfig::new(settings.clone(), merkle_hash, merkle_compress, challenger);

    // Benchmark different trace sizes
    for log_n_rows in [6, 7, 8, 9] {
        group.bench_with_input(
            BenchmarkId::from_parameter(log_n_rows),
            &log_n_rows,
            |b, log_n_rows| {
                let circuit = Poseidon2Circuit {
                    log_length: *log_n_rows,
                    constants: constants.clone(),
                };
                let prepared = prepare::<Poseidon2Circuit, _, 8>(&proving_settings, circuit);

                b.iter(|| {
                    // The witness generation is included because ProveKit doesn't separate witness generation and proving.

                    let n_rows = 1 << log_n_rows;
                    let inputs: Vec<[F; WIDTH]> = (0..n_rows)
                        .map(|_| std::array::from_fn(|_| rng.random()))
                        .collect();

                    let _proof = prove(&prepared, &inputs);
                });
            },
        );
    }

    // Also benchmark verification
    let log_n_rows = 7; // Use smaller size for verification benchmark
    let circuit = Poseidon2Circuit {
        log_length: log_n_rows,
        constants: constants.clone(),
    };
    let prepared = prepare::<Poseidon2Circuit, _, 8>(&proving_settings, circuit);
    let n_rows = 1 << log_n_rows;
    let inputs: Vec<[F; WIDTH]> = (0..n_rows)
        .map(|_| std::array::from_fn(|_| rng.random()))
        .collect();
    let proof = prove(&prepared, &inputs);

    group.bench_function("verify", |b| {
        b.iter(|| {
            let _ = verify(&prepared, &proof, &[]);
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
