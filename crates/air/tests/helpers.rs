use air::AirSettings;
use keccak_air::KeccakAir;
use p3_air::{Air, BaseAir};
use p3_challenger::DuplexChallenger;
use p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_matrix::Matrix;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::{Rng, SeedableRng, rngs::StdRng};
use whir_p3::fiat_shamir::domain_separator::DomainSeparator;
use whir_p3::parameters::{FoldingFactor, errors::SecurityAssumption};
use whir_p3::{fiat_shamir::prover::ProverState, poly::evals::EvaluationsList};

pub type F = KoalaBear;
pub type EF = BinomialExtensionField<F, 8>;
type Poseidon16 = Poseidon2KoalaBear<16>;
type Poseidon24 = Poseidon2KoalaBear<24>;
pub type MerkleHash = PaddingFreeSponge<Poseidon24, 24, 16, 8>;
pub type MerkleCompress = TruncatedPermutation<Poseidon16, 2, 8, 16>;
pub type MyChallenger = DuplexChallenger<F, Poseidon16, 16, 8>;

// Simple mock AIR for testing
#[derive(Clone)]
pub struct MockAir {
    pub width: usize,
}

impl<AB: p3_air::AirBuilder<F = F>> Air<AB> for MockAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        // Constraint: sum of first row equals zero
        let mut sum = AB::Expr::ZERO;
        let row: Vec<_> = main
            .row(0)
            .expect("Matrix should have at least one row")
            .into_iter()
            .collect();
        for col in 0..self.width {
            sum = sum + row[col].clone();
        }
        builder.assert_zero(sum);
    }
}

impl BaseAir<F> for MockAir {
    fn width(&self) -> usize {
        self.width
    }
}

// Implement required traits for prove/verify
impl MockAir {
    pub fn new(width: usize) -> Self {
        Self { width }
    }
}

pub fn setup_challenger() -> MyChallenger {
    let mut rng = StdRng::seed_from_u64(42);
    let poseidon = Poseidon16::new_from_rng_128(&mut rng);
    DuplexChallenger::new(poseidon)
}

pub fn setup_prover_state() -> ProverState<F, EF, MyChallenger> {
    let domain_separator = DomainSeparator::new(vec![]);
    ProverState::new(&domain_separator, setup_challenger())
}

pub fn create_test_settings() -> AirSettings {
    AirSettings::new(
        128, // security_bits
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(4, 4),
        1, // whir_log_inv_rate
        1, // univariate_skips
        4, // whir_initial_domain_reduction_factor
    )
}

pub fn create_witness_columns(log_length: usize, n_columns: usize) -> Vec<EvaluationsList<F>> {
    let mut rng = StdRng::seed_from_u64(123);
    let n_rows = 1 << log_length;

    (0..n_columns)
        .map(|_| {
            let evals: Vec<F> = (0..n_rows)
                .map(|_| F::new(rng.random_range(0..100)))
                .collect();
            EvaluationsList::new(evals)
        })
        .collect()
}

pub fn create_preprocessed_columns(log_length: usize, n_columns: usize) -> Vec<EvaluationsList<F>> {
    create_witness_columns(log_length, n_columns)
}

/// Create columns that satisfy `MockAir`'s constraint for every row:
/// the sum of all columns in that row is zero.
pub fn create_satisfying_columns(log_length: usize, n_columns: usize) -> Vec<EvaluationsList<F>> {
    let mut cols = create_witness_columns(log_length, n_columns);
    if n_columns == 0 {
        return cols;
    }
    let n_rows = 1 << log_length;
    for row in 0..n_rows {
        let sum_other: F = cols
            .iter()
            .take(n_columns - 1)
            .map(|c| c.evals()[row])
            .sum();
        cols[n_columns - 1].evals_mut()[row] = -sum_other;
    }
    cols
}

pub fn create_keccak_witness_columns(
    num_hashes: usize,
    extra_capacity_bits: usize,
) -> (KeccakAir, usize, Vec<EvaluationsList<F>>) {
    let air = KeccakAir {};
    let trace = air.generate_trace_rows::<F>(num_hashes, extra_capacity_bits);
    let height = trace.height();
    let log_length = height.ilog2() as usize;
    assert_eq!(height, 1usize << log_length);

    let width = trace.width();
    let mut columns = Vec::with_capacity(width);
    for col in 0..width {
        let mut evals = Vec::with_capacity(height);
        for row in 0..height {
            evals.push(trace.values[row * width + col]);
        }
        columns.push(EvaluationsList::new(evals));
    }
    (air, log_length, columns)
}

pub fn setup_merkle_hash() -> MerkleHash {
    let mut rng = StdRng::seed_from_u64(789);
    let poseidon24 = Poseidon24::new_from_rng_128(&mut rng);
    MerkleHash::new(poseidon24)
}

pub fn setup_merkle_compress() -> MerkleCompress {
    let mut rng = StdRng::seed_from_u64(101);
    let poseidon16 = Poseidon16::new_from_rng_128(&mut rng);
    MerkleCompress::new(poseidon16)
}
