use p3_challenger::DuplexChallenger;
use p3_field::{
    ExtensionField, PrimeCharacteristicRing, TwoAdicField, extension::BinomialExtensionField,
};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use sumcheck::{SumcheckGrinding, prove, verify, verify_with_univariate_skip};
use utils::fiat_shamir::{ProverState, VerifierState};
use whir_p3::{fiat_shamir::domain_separator::DomainSeparator, poly::evals::EvaluationsList};

type F = KoalaBear;
type EF = BinomialExtensionField<F, 8>;
type Poseidon16 = Poseidon2KoalaBear<16>;
type MyChallenger = DuplexChallenger<F, Poseidon16, 16, 8>;

// Simple sumcheck computation: sum of all evaluations
struct SimpleSumComputation;

impl<F: p3_field::Field, NF: p3_field::ExtensionField<F>, EF: p3_field::ExtensionField<NF>>
    sumcheck::SumcheckComputation<F, NF, EF> for SimpleSumComputation
{
    fn eval(&self, point: &[NF], _: &[EF], _: &[NF]) -> EF {
        point.iter().map(|&x| EF::from(x)).sum()
    }
}

impl<F: p3_field::Field, EF: ExtensionField<F> + TwoAdicField>
    sumcheck::SumcheckComputationPacked<F, EF> for SimpleSumComputation
{
    fn eval_packed(
        &self,
        point: &[<F as p3_field::Field>::Packing],
        _: &[EF],
        _: &[Vec<F>],
        _: &[<F as p3_field::Field>::Packing],
    ) -> impl Iterator<Item = EF> + Send + Sync {
        use p3_field::PackedValue;
        point
            .iter()
            .map(|&x| {
                let mut acc = EF::ZERO;
                for i in 0..F::Packing::WIDTH {
                    acc += EF::from(x.as_slice()[i]);
                }
                acc
            })
            .collect::<Vec<_>>()
            .into_iter()
    }
}

fn setup_challenger() -> MyChallenger {
    let mut rng = StdRng::seed_from_u64(42);
    let poseidon = Poseidon16::new_from_rng_128(&mut rng);
    DuplexChallenger::new(poseidon)
}

fn create_simple_multilinear(n_vars: usize) -> EvaluationsList<F> {
    let mut rng = StdRng::seed_from_u64(123);
    let evals: Vec<F> = (0..1 << n_vars).map(|_| rng.random()).collect();
    EvaluationsList::new(evals)
}

#[test]
fn test_basic_verify() {
    let n_vars = 3;
    let multilinear = create_simple_multilinear(n_vars);

    let domain_separator = DomainSeparator::new(vec![]);
    let challenger = setup_challenger();
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    // Prove
    let (_challenges, _folded, _final_sum) = prove(
        1,
        &[&multilinear],
        &SimpleSumComputation,
        1,
        &[EF::from_i8(1)],
        None,
        false,
        &mut prover_state,
        expected_sum,
        None,
        SumcheckGrinding::None,
        None,
        &[],
        &[],
    );

    // Verify
    let mut verifier_state = VerifierState::new(
        &domain_separator,
        prover_state.proof_data().to_vec(),
        challenger,
    );
    let (sum, _eval) = verify::<F, EF, MyChallenger>(
        &mut verifier_state,
        n_vars,
        1, // degree
        SumcheckGrinding::None,
    )
    .unwrap();

    assert_eq!(sum, expected_sum);
}

#[test]
fn test_multi_round_verify() {
    let n_vars = 5;
    let multilinear = create_simple_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    let _ = prove(
        1,
        &[&multilinear],
        &SimpleSumComputation,
        1,
        &[EF::ONE],
        None,
        false,
        &mut prover_state,
        expected_sum,
        None,
        SumcheckGrinding::None,
        None,
        &[],
        &[],
    );

    let mut verifier_state = VerifierState::new(
        &domain_separator,
        prover_state.proof_data().to_vec(),
        challenger,
    );
    let (sum, _eval) =
        verify::<F, EF, MyChallenger>(&mut verifier_state, n_vars, 1, SumcheckGrinding::None)
            .unwrap();

    assert_eq!(sum, expected_sum);
}

#[test]
fn test_verify_with_univariate_skip() {
    let n_vars = 4;
    let skips = 2;
    let multilinear = create_simple_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    let _ = prove(
        skips,
        &[&multilinear],
        &SimpleSumComputation,
        1,
        &[EF::ONE],
        None,
        false,
        &mut prover_state,
        expected_sum,
        None,
        SumcheckGrinding::None,
        None,
        &[],
        &[],
    );

    let mut verifier_state = VerifierState::new(
        &domain_separator,
        prover_state.proof_data().to_vec(),
        challenger,
    );
    let (sum, _eval) = verify_with_univariate_skip::<F, EF, MyChallenger>(
        &mut verifier_state,
        1, // degree
        n_vars,
        skips,
        SumcheckGrinding::None,
    )
    .unwrap();

    assert_eq!(sum, expected_sum);
}

#[test]
fn test_verify_with_grinding() {
    let n_vars = 3;
    let multilinear = create_simple_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    let _ = prove(
        1,
        &[&multilinear],
        &SimpleSumComputation,
        1,
        &[EF::ONE],
        None,
        false,
        &mut prover_state,
        expected_sum,
        None,
        SumcheckGrinding::Auto { security_bits: 128 },
        None,
        &[],
        &[],
    );

    let mut verifier_state = VerifierState::new(
        &domain_separator,
        prover_state.proof_data().to_vec(),
        challenger,
    );
    let (sum, _eval) = verify::<F, EF, MyChallenger>(
        &mut verifier_state,
        n_vars,
        1,
        SumcheckGrinding::Auto { security_bits: 128 },
    )
    .unwrap();

    assert_eq!(sum, expected_sum);
}

#[test]
fn test_verify_invalid_proof() {
    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut verifier_state = VerifierState::new(&domain_separator, vec![], challenger);

    // Try to verify with empty proof data - should fail
    let result = verify::<F, EF, MyChallenger>(&mut verifier_state, 3, 1, SumcheckGrinding::None);

    assert!(result.is_err());
}

#[test]
fn test_verify_sum_mismatch() {
    let n_vars = 3;
    let multilinear = create_simple_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    let _ = prove(
        1,
        &[&multilinear],
        &SimpleSumComputation,
        1,
        &[EF::ONE],
        None,
        false,
        &mut prover_state,
        expected_sum,
        None,
        SumcheckGrinding::None,
        None,
        &[],
        &[],
    );

    // Corrupt the proof data
    let mut proof_data = prover_state.proof_data().to_vec();
    if !proof_data.is_empty() {
        proof_data[0] = EF::ZERO; // Corrupt first element
    }

    let mut verifier_state = VerifierState::new(&domain_separator, proof_data, challenger);
    let result =
        verify::<F, EF, MyChallenger>(&mut verifier_state, n_vars, 1, SumcheckGrinding::None);

    // Should fail due to invalid proof
    assert!(result.is_err());
}

#[test]
fn test_verify_higher_degree() {
    let n_vars = 3;
    let multilinear = create_simple_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    let _ = prove(
        1,
        &[&multilinear],
        &SimpleSumComputation,
        2, // degree
        &[EF::ONE],
        None,
        false,
        &mut prover_state,
        expected_sum,
        None,
        SumcheckGrinding::None,
        None,
        &[],
        &[],
    );

    let mut verifier_state = VerifierState::new(
        &domain_separator,
        prover_state.proof_data().to_vec(),
        challenger,
    );
    let (sum, _eval) = verify::<F, EF, MyChallenger>(
        &mut verifier_state,
        n_vars,
        2, // degree
        SumcheckGrinding::None,
    )
    .unwrap();

    assert_eq!(sum, expected_sum);
}

#[test]
fn test_verify_single_variable() {
    let n_vars = 4;
    let multilinear = create_simple_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    let _ = prove(
        1,
        &[&multilinear],
        &SimpleSumComputation,
        1,
        &[EF::ONE],
        None,
        false,
        &mut prover_state,
        expected_sum,
        None,
        SumcheckGrinding::None,
        None,
        &[],
        &[],
    );

    let mut verifier_state = VerifierState::new(
        &domain_separator,
        prover_state.proof_data().to_vec(),
        challenger,
    );
    let (sum, _eval) =
        verify::<F, EF, MyChallenger>(&mut verifier_state, n_vars, 1, SumcheckGrinding::None)
            .unwrap();

    assert_eq!(sum, expected_sum);
}
