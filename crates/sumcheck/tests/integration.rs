use p3_challenger::DuplexChallenger;
use p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use rand::{Rng, SeedableRng, rngs::StdRng};
use sumcheck::{SumcheckGrinding, prove, verify, verify_with_univariate_skip};
use utils::fiat_shamir::{ProverState, VerifierState};
use whir_p3::{
    fiat_shamir::domain_separator::DomainSeparator,
    poly::{evals::EvaluationsList, multilinear::MultilinearPoint},
};

type F = KoalaBear;
type EF = BinomialExtensionField<F, 8>;
type Poseidon16 = Poseidon2KoalaBear<16>;
type MyChallenger = DuplexChallenger<F, Poseidon16, 16, 8>;

// Simple sumcheck computation: sum of all evaluations
struct SimpleSumComputation;

impl<F: p3_field::Field, NF: p3_field::ExtensionField<F>, EF: p3_field::ExtensionField<NF>>
    sumcheck::SumcheckComputation<F, NF, EF> for SimpleSumComputation
{
    fn eval(&self, point: &[NF], _: &[EF]) -> EF {
        point.iter().map(|&x| EF::from(x)).sum()
    }
}

impl<F: p3_field::Field, EF: p3_field::ExtensionField<F>> sumcheck::SumcheckComputationPacked<F, EF>
    for SimpleSumComputation
{
    fn eval_packed(
        &self,
        point: &[<F as p3_field::Field>::Packing],
        _: &[EF],
        _: &[Vec<F>],
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

fn create_zero_multilinear(n_vars: usize) -> EvaluationsList<F> {
    EvaluationsList::new(vec![F::ZERO; 1 << n_vars])
}

#[test]
fn test_end_to_end_prove_verify() {
    let n_vars = 4;
    let multilinear = create_simple_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    // Prove
    let (_challenges, _folded, final_sum) = prove(
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
    );

    // Verify
    let mut verifier_state = VerifierState::new(
        &domain_separator,
        prover_state.proof_data().to_vec(),
        challenger,
    );
    let (verified_sum, eval) =
        verify::<F, EF, MyChallenger>(&mut verifier_state, n_vars, 1, SumcheckGrinding::None)
            .unwrap();

    assert_eq!(verified_sum, expected_sum);
    assert_eq!(eval.point.len(), n_vars);
    assert_eq!(eval.value, final_sum);

    let expected_value =
        multilinear.evaluate_hypercube_base::<EF>(&MultilinearPoint::new(eval.point.clone()));
    assert_eq!(eval.value, expected_value);
}

#[test]
fn test_end_to_end_various_degrees() {
    let n_vars = 3;
    let multilinear = create_simple_multilinear(n_vars);

    for degree in [1, 2, 3, 5] {
        let challenger = setup_challenger();
        let domain_separator = DomainSeparator::new(vec![]);
        let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

        let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

        let (_challenges, _folded, final_sum) = prove(
            1,
            &[&multilinear],
            &SimpleSumComputation,
            degree,
            &[EF::ONE],
            None,
            false,
            &mut prover_state,
            expected_sum,
            None,
            SumcheckGrinding::None,
            None,
        );

        let mut verifier_state = VerifierState::new(
            &domain_separator,
            prover_state.proof_data().to_vec(),
            challenger,
        );
        let (verified_sum, eval) = verify::<F, EF, MyChallenger>(
            &mut verifier_state,
            n_vars,
            degree,
            SumcheckGrinding::None,
        )
        .unwrap();
        assert_eq!(verified_sum, expected_sum);
        assert_eq!(eval.value, final_sum);
        let expected_value =
            multilinear.evaluate_hypercube_base::<EF>(&MultilinearPoint::new(eval.point.clone()));
        assert_eq!(eval.value, expected_value);
    }
}

#[test]
fn test_end_to_end_multiple_multilinears() {
    let n_vars = 3;
    let multilinear1 = create_simple_multilinear(n_vars);
    let multilinear2 = create_simple_multilinear(n_vars);
    let multilinear3 = create_simple_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    // Sum of all three multilinears
    let expected_sum: EF = multilinear1
        .as_slice()
        .iter()
        .zip(multilinear2.as_slice().iter())
        .zip(multilinear3.as_slice().iter())
        .map(|((&a, &b), &c)| EF::from(a) + EF::from(b) + EF::from(c))
        .sum();

    let (_challenges, _folded, final_sum) = prove(
        1,
        &[&multilinear1, &multilinear2, &multilinear3],
        &SimpleSumComputation,
        1,
        &[
            EF::from(F::new(0)),
            EF::from(F::new(1)),
            EF::from(F::new(2)),
        ],
        None,
        false,
        &mut prover_state,
        expected_sum,
        None,
        SumcheckGrinding::None,
        None,
    );

    let mut verifier_state = VerifierState::new(
        &domain_separator,
        prover_state.proof_data().to_vec(),
        challenger,
    );
    let (verified_sum, eval) =
        verify::<F, EF, MyChallenger>(&mut verifier_state, n_vars, 1, SumcheckGrinding::None)
            .unwrap();
    assert_eq!(verified_sum, expected_sum);
    assert_eq!(eval.value, final_sum);
    let point = MultilinearPoint::new(eval.point.clone());
    let expected_value = multilinear1.evaluate_hypercube_base::<EF>(&point)
        + multilinear2.evaluate_hypercube_base::<EF>(&point)
        + multilinear3.evaluate_hypercube_base::<EF>(&point);
    assert_eq!(eval.value, expected_value);
}

#[test]
#[ignore = "Univariate skip path triggers UB in current whir-p3"]
fn test_end_to_end_with_univariate_skip() {
    let n_vars = 5;
    let skips = 2;
    let multilinear = create_simple_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    let (_challenges, _folded, _final_sum) = prove(
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
    );

    let mut verifier_state = VerifierState::new(
        &domain_separator,
        prover_state.proof_data().to_vec(),
        challenger,
    );
    let (_verified_sum, _eval) = verify_with_univariate_skip::<F, EF, MyChallenger>(
        &mut verifier_state,
        1,
        n_vars,
        skips,
        SumcheckGrinding::None,
    )
    .unwrap();
}

#[test]
fn test_end_to_end_with_grinding() {
    let n_vars = 3;
    let multilinear = create_simple_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    let (_challenges, _folded, final_sum) = prove(
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
    );

    let mut verifier_state = VerifierState::new(
        &domain_separator,
        prover_state.proof_data().to_vec(),
        challenger,
    );
    let (verified_sum, eval) = verify::<F, EF, MyChallenger>(
        &mut verifier_state,
        n_vars,
        1,
        SumcheckGrinding::Auto { security_bits: 128 },
    )
    .unwrap();
    assert_eq!(verified_sum, expected_sum);
    assert_eq!(eval.value, final_sum);
    let expected_value =
        multilinear.evaluate_hypercube_base::<EF>(&MultilinearPoint::new(eval.point.clone()));
    assert_eq!(eval.value, expected_value);
}

#[test]
fn test_end_to_end_zerocheck() {
    let n_vars = 3;
    // Use the zero polynomial so the claimed sum is actually zero.
    let multilinear = create_zero_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    let expected_sum = EF::ZERO;

    let (_challenges, _folded, final_sum) = prove(
        1,
        &[&multilinear],
        &SimpleSumComputation,
        1,
        &[EF::ONE],
        None,
        true, // is_zerofier
        &mut prover_state,
        expected_sum,
        None,
        SumcheckGrinding::None,
        None,
    );

    let mut verifier_state = VerifierState::new(
        &domain_separator,
        prover_state.proof_data().to_vec(),
        challenger,
    );
    let (verified_sum, eval) =
        verify::<F, EF, MyChallenger>(&mut verifier_state, n_vars, 1, SumcheckGrinding::None)
            .unwrap();
    assert_eq!(verified_sum, expected_sum);
    assert_eq!(eval.value, final_sum);
    let expected_value =
        multilinear.evaluate_hypercube_base::<EF>(&MultilinearPoint::new(eval.point.clone()));
    assert_eq!(eval.value, expected_value);
}
