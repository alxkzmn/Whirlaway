use p3_challenger::DuplexChallenger;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use rand::{RngExt, SeedableRng, rngs::StdRng};
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

// Simple sumcheck computation
struct SimpleSumComputation;

impl<F: p3_field::Field, NF: p3_field::ExtensionField<F>, EF: p3_field::ExtensionField<NF>>
    sumcheck::SumcheckComputation<F, NF, EF> for SimpleSumComputation
{
    fn eval(&self, point: &[NF], _: &[EF], _: &[NF]) -> EF {
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
        _: &[<F as p3_field::Field>::Packing],
    ) -> impl Iterator<Item = EF> + Send + Sync {
        use p3_field::PackedValue;
        // Sum all packed elements
        point
            .iter()
            .map(|&x| {
                let mut result = EF::ZERO;
                for i in 0..F::Packing::WIDTH {
                    result += EF::from(x.as_slice()[i]);
                }
                result
            })
            .collect::<Vec<_>>()
            .into_iter()
    }
}

fn setup_challenger() -> MyChallenger {
    let mut rng = StdRng::seed_from_u64(42);
    let poseidon = Poseidon16::new_from_rng_128(&mut rng);
    DuplexChallenger::new(poseidon.clone())
}

fn create_multilinear(n_vars: usize) -> EvaluationsList<F> {
    let mut rng = StdRng::seed_from_u64(123);
    let evals: Vec<F> = (0..1 << n_vars).map(|_| rng.random()).collect();
    EvaluationsList::new(evals)
}

#[test]
fn test_sumcheck_with_pcs_commitment_flow() {
    let n_vars = 4;
    let multilinear = create_multilinear(n_vars);

    let challenger = setup_challenger();
    // Create a minimal domain separator for sumcheck tests
    let domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    // Prove sumcheck
    let (_challenges, _folded, final_sum) = prove(
        1,
        &[&multilinear],
        &SimpleSumComputation,
        1,
        &[EF::from(F::new(1))],
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

    // Verify sumcheck
    let challenger2 = setup_challenger();
    let mut verifier_state =
        VerifierState::new(&domainsep, prover_state.proof_data().to_vec(), challenger2);
    let (verified_sum, eval) =
        verify::<F, EF, MyChallenger>(&mut verifier_state, n_vars, 1, SumcheckGrinding::None)
            .unwrap();

    assert_eq!(verified_sum, expected_sum);
    assert_eq!(eval.value, final_sum);
    let expected_value =
        multilinear.evaluate_hypercube_base::<EF>(&MultilinearPoint::new(eval.point.clone()));
    assert_eq!(eval.value, expected_value);
}

#[test]
fn test_sumcheck_complex_multi_round() {
    let n_vars = 6;
    let multilinear = create_multilinear(n_vars);

    let challenger = setup_challenger();
    let domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    let (_challenges, _folded, final_sum) = prove(
        1,
        &[&multilinear],
        &SimpleSumComputation,
        1,
        &[EF::from(F::new(1))],
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

    let challenger2 = setup_challenger();
    let mut verifier_state =
        VerifierState::new(&domainsep, prover_state.proof_data().to_vec(), challenger2);
    let (verified_sum, eval) =
        verify::<F, EF, MyChallenger>(&mut verifier_state, n_vars, 1, SumcheckGrinding::None)
            .unwrap();
    assert_eq!(verified_sum, expected_sum);
    assert_eq!(eval.value, final_sum);
    let expected_value =
        multilinear.evaluate_hypercube_base::<EF>(&MultilinearPoint::new(eval.point.clone()));
    assert_eq!(eval.value, expected_value);
}

#[test]
fn test_sumcheck_with_univariate_skip() {
    let n_vars = 5;
    let skips = 2;
    let multilinear = create_multilinear(n_vars);

    let challenger = setup_challenger();
    let domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    let (_challenges, _folded, _final_sum) = prove(
        skips,
        &[&multilinear],
        &SimpleSumComputation,
        1,
        &[EF::from(F::new(1))],
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

    let challenger2 = setup_challenger();
    let mut verifier_state =
        VerifierState::new(&domainsep, prover_state.proof_data().to_vec(), challenger2);
    let (_verified_sum, _eval) = verify_with_univariate_skip(
        &mut verifier_state,
        1,
        n_vars,
        skips,
        SumcheckGrinding::None,
    )
    .unwrap();
}

#[test]
fn test_sumcheck_with_grinding() {
    let n_vars = 4;
    let multilinear = create_multilinear(n_vars);

    let challenger = setup_challenger();
    let domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    let (_challenges, _folded, final_sum) = prove(
        1,
        &[&multilinear],
        &SimpleSumComputation,
        1,
        &[EF::from(F::new(1))],
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

    let challenger2 = setup_challenger();
    let mut verifier_state =
        VerifierState::new(&domainsep, prover_state.proof_data().to_vec(), challenger2);
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
fn test_sumcheck_multiple_multilinears() {
    let n_vars = 3;
    let multilinear1 = create_multilinear(n_vars);
    let multilinear2 = create_multilinear(n_vars);
    let multilinear3 = create_multilinear(n_vars);

    let challenger = setup_challenger();
    let domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

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
            EF::from(F::new(1)),
            EF::from(F::new(1)),
            EF::from(F::new(1)),
        ],
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

    let challenger2 = setup_challenger();
    let mut verifier_state =
        VerifierState::new(&domainsep, prover_state.proof_data().to_vec(), challenger2);
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
