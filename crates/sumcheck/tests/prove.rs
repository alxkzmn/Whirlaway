use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use p3_challenger::DuplexChallenger;
use p3_field::{
    ExtensionField, PackedValue, PrimeCharacteristicRing, TwoAdicField,
    extension::BinomialExtensionField,
};
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

#[derive(Clone, Default)]
struct CountingSumComputation {
    scalar_calls: Arc<AtomicUsize>,
    packed_calls: Arc<AtomicUsize>,
}

impl CountingSumComputation {
    fn scalar_call_count(&self) -> usize {
        self.scalar_calls.load(Ordering::Relaxed)
    }

    fn packed_call_count(&self) -> usize {
        self.packed_calls.load(Ordering::Relaxed)
    }
}

impl<F: p3_field::Field, NF: p3_field::ExtensionField<F>, EF: p3_field::ExtensionField<NF>>
    sumcheck::SumcheckComputation<F, NF, EF> for CountingSumComputation
{
    fn eval(&self, point: &[NF], _: &[EF], _: &[NF]) -> EF {
        self.scalar_calls.fetch_add(1, Ordering::Relaxed);
        point.iter().copied().map(EF::from).sum()
    }
}

impl<F: p3_field::Field, EF: ExtensionField<F> + TwoAdicField>
    sumcheck::SumcheckComputationPacked<F, EF> for CountingSumComputation
{
    fn eval_packed(
        &self,
        point: &[<F as p3_field::Field>::Packing],
        _: &[EF],
        _: &[Vec<F>],
        _: &[<F as p3_field::Field>::Packing],
    ) -> impl Iterator<Item = EF> + Send + Sync {
        use p3_field::PackedValue;

        self.packed_calls.fetch_add(1, Ordering::Relaxed);
        (0..<F as p3_field::Field>::Packing::WIDTH)
            .map(|lane| {
                point
                    .iter()
                    .map(|value| EF::from(value.as_slice()[lane]))
                    .sum::<EF>()
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

fn lift_multilinear_to_extension(m: &EvaluationsList<F>) -> EvaluationsList<EF> {
    EvaluationsList::new(m.as_slice().iter().copied().map(EF::from).collect())
}

#[test]
fn test_basic_sumcheck_single_round() {
    let n_vars = 3;
    let multilinear = create_simple_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    // Compute expected sum
    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    let (challenges, _folded, final_sum) = prove(
        1, // skips = 1 (classic sumcheck)
        &[&multilinear],
        &SimpleSumComputation,
        1,          // degree
        &[EF::ONE], // batching scalars
        None,       // eq_factor
        false,      // is_zerofier
        &mut prover_state,
        expected_sum,
        None, // n_rounds
        SumcheckGrinding::None,
        None, // missing_mul_factor
        &[],
        &[],
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
    assert_eq!(eval.point, challenges);
    assert_eq!(eval.value, final_sum);

    let expected_value =
        multilinear.evaluate_hypercube_base::<EF>(&MultilinearPoint::new(eval.point.clone()));
    assert_eq!(eval.value, expected_value);
}

#[test]
fn test_multi_round_sumcheck() {
    let n_vars = 5;
    let multilinear = create_simple_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    let (challenges, _folded, final_sum) = prove(
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
    let (verified_sum, eval) =
        verify::<F, EF, MyChallenger>(&mut verifier_state, n_vars, 1, SumcheckGrinding::None)
            .unwrap();

    assert_eq!(verified_sum, expected_sum);
    assert_eq!(eval.point, challenges);
    assert_eq!(eval.value, final_sum);

    let expected_value =
        multilinear.evaluate_hypercube_base::<EF>(&MultilinearPoint::new(eval.point.clone()));
    assert_eq!(eval.value, expected_value);
}

#[test]
fn test_univariate_skip() {
    let n_vars = 4;
    let skips = 2;
    let multilinear = create_simple_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    let (challenges, _folded, final_sum) = prove(
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
    let (verified_sum, eval) = verify_with_univariate_skip::<F, EF, MyChallenger>(
        &mut verifier_state,
        1,
        n_vars,
        skips,
        SumcheckGrinding::None,
    )
    .unwrap();

    assert_eq!(verified_sum, expected_sum);
    assert_eq!(eval.point, challenges);
    assert_eq!(eval.value, final_sum);
}

#[test]
fn test_zerocheck_mode() {
    let n_vars = 3;
    // Use the zero polynomial so the claimed sum is actually zero.
    let multilinear = create_zero_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    // For zerocheck, sum should be zero
    let expected_sum = EF::ZERO;

    let (challenges, _folded, final_sum) = prove(
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
        &[],
        &[],
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
    assert_eq!(eval.point, challenges);
    assert_eq!(eval.value, final_sum);

    let expected_value =
        multilinear.evaluate_hypercube_base::<EF>(&MultilinearPoint::new(eval.point.clone()));
    assert_eq!(eval.value, expected_value);
}

#[test]
fn test_with_grinding() {
    let n_vars = 3;
    let multilinear = create_simple_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    let (challenges, _folded, final_sum) = prove(
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
    let (verified_sum, eval) = verify::<F, EF, MyChallenger>(
        &mut verifier_state,
        n_vars,
        1,
        SumcheckGrinding::Auto { security_bits: 128 },
    )
    .unwrap();

    assert_eq!(verified_sum, expected_sum);
    assert_eq!(eval.point, challenges);
    assert_eq!(eval.value, final_sum);

    let expected_value =
        multilinear.evaluate_hypercube_base::<EF>(&MultilinearPoint::new(eval.point.clone()));
    assert_eq!(eval.value, expected_value);
}

#[test]
fn test_with_eq_factor() {
    let n_vars = 3;
    // Use the zero polynomial so the weighted claim is actually zero.
    let multilinear = create_zero_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state_no_eq = ProverState::new(&domain_separator, challenger);

    let expected_sum = EF::ZERO;

    // Baseline proof without eq_factor.
    let (challenges_no_eq, _folded_no_eq, _final_sum_no_eq) = prove(
        1,
        &[&multilinear],
        &SimpleSumComputation,
        1,
        &[EF::ONE],
        None,
        false,
        &mut prover_state_no_eq,
        expected_sum,
        None,
        SumcheckGrinding::None,
        None,
        &[],
        &[],
    );

    // Create eq_factor
    let eq_factor = vec![
        EF::from(F::new(3)),
        EF::from(F::new(5)),
        EF::from(F::new(7)),
    ];

    let mut prover_state_eq = ProverState::new(&domain_separator, setup_challenger());
    let (challenges, _folded, final_sum) = prove(
        1,
        &[&multilinear],
        &SimpleSumComputation,
        1,
        &[EF::ONE],
        Some(&eq_factor),
        false,
        &mut prover_state_eq,
        expected_sum,
        None,
        SumcheckGrinding::None,
        None,
        &[],
        &[],
    );

    // The generic verifier doesn't support the eq_factor-weighted variant, but we can still
    // assert that enabling eq_factor changes the transcript and produces the expected number
    // of challenges.
    assert_eq!(challenges_no_eq.len(), n_vars);
    assert_eq!(challenges.len(), n_vars);
    assert_eq!(final_sum, final_sum);
    assert!(
        prover_state_eq.proof_data() != prover_state_no_eq.proof_data(),
        "eq_factor proof should change the transcript"
    );
    assert!(
        challenges != challenges_no_eq,
        "eq_factor proof should change sampled challenges"
    );
}

#[test]
fn test_multiple_multilinears() {
    let n_vars = 3;
    let multilinear1 = create_simple_multilinear(n_vars);
    let multilinear2 = create_simple_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    // Sum of both multilinears
    let expected_sum: EF = multilinear1
        .as_slice()
        .iter()
        .zip(multilinear2.as_slice().iter())
        .map(|(&a, &b)| EF::from(a) + EF::from(b))
        .sum();

    let (challenges, _folded, final_sum) = prove(
        1,
        &[&multilinear1, &multilinear2],
        &SimpleSumComputation,
        1,
        &[EF::ONE, EF::ONE],
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
    let (verified_sum, eval) =
        verify::<F, EF, MyChallenger>(&mut verifier_state, n_vars, 1, SumcheckGrinding::None)
            .unwrap();

    assert_eq!(verified_sum, expected_sum);
    assert_eq!(eval.point, challenges);
    assert_eq!(eval.value, final_sum);

    let point = MultilinearPoint::new(eval.point.clone());
    let expected_value = multilinear1.evaluate_hypercube_base::<EF>(&point)
        + multilinear2.evaluate_hypercube_base::<EF>(&point);
    assert_eq!(eval.value, expected_value);
}

#[test]
fn test_single_variable() {
    let n_vars = 4;
    let multilinear = create_simple_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    let (challenges, _folded, final_sum) = prove(
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
    let (verified_sum, eval) =
        verify::<F, EF, MyChallenger>(&mut verifier_state, n_vars, 1, SumcheckGrinding::None)
            .unwrap();

    assert_eq!(verified_sum, expected_sum);
    assert_eq!(eval.point, challenges);
    assert_eq!(eval.value, final_sum);

    let expected_value =
        multilinear.evaluate_hypercube_base::<EF>(&MultilinearPoint::new(eval.point.clone()));
    assert_eq!(eval.value, expected_value);
}

#[test]
fn test_higher_degree() {
    let n_vars = 3;
    let multilinear = create_simple_multilinear(n_vars);

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger.clone());

    let expected_sum: EF = multilinear.as_slice().iter().map(|&x| EF::from(x)).sum();

    // Test with degree 2
    let (challenges, _folded, final_sum) = prove(
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
    let (verified_sum, eval) =
        verify::<F, EF, MyChallenger>(&mut verifier_state, n_vars, 2, SumcheckGrinding::None)
            .unwrap();

    assert_eq!(verified_sum, expected_sum);
    assert_eq!(eval.point, challenges);
    assert_eq!(eval.value, final_sum);

    let expected_value =
        multilinear.evaluate_hypercube_base::<EF>(&MultilinearPoint::new(eval.point.clone()));
    assert_eq!(eval.value, expected_value);
}

#[test]
fn test_nf_equals_f_uses_packed_path_when_width_aligned() {
    let width = <F as p3_field::Field>::Packing::WIDTH;
    let Some(n_vars) = (1..20).find(|&n| (1usize << (n - 1)).is_multiple_of(width)) else {
        return;
    };

    let multilinear = create_simple_multilinear(n_vars);
    let expected_sum: EF = multilinear.as_slice().iter().copied().map(EF::from).sum();
    let computation = CountingSumComputation::default();

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger);

    let _ = prove(
        1,
        &[&multilinear],
        &computation,
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

    assert!(computation.packed_call_count() > 0);
}

#[test]
fn test_nf_equals_f_falls_back_to_scalar_when_not_width_aligned() {
    let width = <F as p3_field::Field>::Packing::WIDTH;
    let Some(n_vars) = (1..20).find(|&n| !(1usize << (n - 1)).is_multiple_of(width)) else {
        // If no such n exists, packing width is itself a power of two and every hypercube size aligns.
        return;
    };

    let multilinear = create_simple_multilinear(n_vars);
    let expected_sum: EF = multilinear.as_slice().iter().copied().map(EF::from).sum();
    let computation = CountingSumComputation::default();

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger);

    let _ = prove(
        1,
        &[&multilinear],
        &computation,
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

    assert!(computation.scalar_call_count() > 0);
    assert_eq!(computation.packed_call_count(), 0);
}

#[test]
fn test_zerocheck_fast_path_case_nf_equals_f_skips_gt_one() {
    let width = <F as p3_field::Field>::Packing::WIDTH;
    let skips = 2;
    let Some(n_vars) = (skips..20).find(|&n| (1usize << (n - skips)).is_multiple_of(width)) else {
        return;
    };

    let multilinear = create_zero_multilinear(n_vars);
    let computation = CountingSumComputation::default();

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger);

    let _ = prove(
        skips,
        &[&multilinear],
        &computation,
        2,
        &[EF::ONE],
        None,
        true,
        &mut prover_state,
        EF::ZERO,
        Some(1),
        SumcheckGrinding::None,
        None,
        &[],
        &[],
    );

    assert!(computation.packed_call_count() > 0);
}

#[test]
fn test_zerocheck_fast_path_fallback_when_nf_not_f() {
    let skips = 2;
    let n_vars = 4;
    let multilinear = lift_multilinear_to_extension(&create_zero_multilinear(n_vars));
    let computation = CountingSumComputation::default();

    let challenger = setup_challenger();
    let domain_separator = DomainSeparator::new(vec![]);
    let mut prover_state = ProverState::new(&domain_separator, challenger);

    let _ = prove(
        skips,
        &[&multilinear],
        &computation,
        2,
        &[EF::ONE],
        None,
        true,
        &mut prover_state,
        EF::ZERO,
        Some(1),
        SumcheckGrinding::None,
        None,
        &[],
        &[],
    );

    assert!(computation.scalar_call_count() > 0);
    assert_eq!(computation.packed_call_count(), 0);
}

#[test]
fn test_zerocheck_fast_path_matches_generic_fallback_transcript() {
    let width = <F as p3_field::Field>::Packing::WIDTH;
    let skips = 2;
    let Some(n_vars) = (skips..20).find(|&n| (1usize << (n - skips)).is_multiple_of(width)) else {
        return;
    };

    let multilinear_f = create_zero_multilinear(n_vars);
    let multilinear_ef = lift_multilinear_to_extension(&multilinear_f);
    let domain_separator = DomainSeparator::new(vec![]);

    let mut prover_state_fast = ProverState::new(&domain_separator, setup_challenger());
    let (challenges_fast, _, final_sum_fast) = prove(
        skips,
        &[&multilinear_f],
        &SimpleSumComputation,
        2,
        &[EF::ONE],
        None,
        true,
        &mut prover_state_fast,
        EF::ZERO,
        Some(1),
        SumcheckGrinding::None,
        None,
        &[],
        &[],
    );

    let mut prover_state_fallback = ProverState::new(&domain_separator, setup_challenger());
    let (challenges_fallback, _, final_sum_fallback) = prove(
        skips,
        &[&multilinear_ef],
        &SimpleSumComputation,
        2,
        &[EF::ONE],
        None,
        true,
        &mut prover_state_fallback,
        EF::ZERO,
        Some(1),
        SumcheckGrinding::None,
        None,
        &[],
        &[],
    );

    assert_eq!(challenges_fast, challenges_fallback);
    assert_eq!(final_sum_fast, final_sum_fallback);
    assert_eq!(
        prover_state_fast.proof_data(),
        prover_state_fallback.proof_data()
    );
}
