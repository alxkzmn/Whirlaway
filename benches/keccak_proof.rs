use air::AirSettings;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::{Rng, SeedableRng, rngs::StdRng};
use whir_p3::{parameters::FoldingFactor, parameters::errors::SecurityAssumption};

use whirlaway::circuits::keccak_air::KeccakAirCircuit;
use whirlaway::hashers::KECCAK_DIGEST_ELEMS;
use whirlaway::proving_system::{KeccakProvingSystemConfig, prepare, prove, verify};

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
    let proving_settings = KeccakProvingSystemConfig {
        air_settings: settings.clone(),
    };

    // Benchmark different trace sizes
    for log_n_rows in [5, 6, 7, 8] {
        group.bench_with_input(
            BenchmarkId::from_parameter(log_n_rows),
            &log_n_rows,
            |b, log_n_rows| {
                let n_rows = 1 << log_n_rows;
                let keccak_air_circuit = KeccakAirCircuit { n_inputs: n_rows };
                let prepared = prepare(&proving_settings, keccak_air_circuit);

                b.iter(|| {
                    // The witness generation is included because ProveKit doesn't separate witness generation and proving.
                    let inputs: Vec<[u64; 25]> = (0..n_rows)
                        .map(|_| std::array::from_fn(|_| rng.random()))
                        .collect();

                    let _proof = prove(&prepared, &inputs);
                });
            },
        );
    }

    let log_length = 7;

    group.bench_function("verify", |b| {
        let n_rows = 1 << log_length;
        let keccak_air_circuit = KeccakAirCircuit { n_inputs: n_rows };
        let prepared = prepare::<KeccakAirCircuit, _, KECCAK_DIGEST_ELEMS>(
            &proving_settings,
            keccak_air_circuit,
        );

        b.iter_batched(
            || {
                let inputs: Vec<[u64; 25]> = (0..n_rows)
                    .map(|_| std::array::from_fn(|_| rng.random()))
                    .collect();
                prove(&prepared, &inputs)
            },
            |proof| {
                verify(&prepared, &proof).unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
