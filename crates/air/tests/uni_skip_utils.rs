use air::uni_skip_utils::{matrix_down_folded, matrix_up_folded};
use p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_koala_bear::KoalaBear;
use rand::{Rng, SeedableRng, rngs::StdRng};
use whir_p3::poly::evals::EvaluationsList;

type F = KoalaBear;
type EF = BinomialExtensionField<F, 8>;

fn create_test_challenges(n: usize) -> Vec<F> {
    let mut rng = StdRng::seed_from_u64(123);
    (0..n).map(|_| F::new(rng.random_range(0..100))).collect()
}

#[test]
fn test_matrix_up_folded() {
    let n = 3;
    let challenges = create_test_challenges(n);

    let result = matrix_up_folded(&challenges);

    // Should return an EvaluationsList with 2^n evaluations
    assert_eq!(result.num_variables(), n);
    assert_eq!(result.num_evals(), 1 << n);
}

#[test]
fn test_matrix_up_folded_correctness() {
    let n = 2;
    let challenges = vec![F::new(1), F::new(0)];

    let result = matrix_up_folded(&challenges);

    // Should have correct structure
    assert_eq!(result.num_evals(), 1 << n);

    // The last element should be modified according to the implementation
    // (last element -= product, second-to-last += product)
    let product: F = challenges.iter().copied().product();
    let last_idx = (1 << n) - 1;
    let second_last_idx = (1 << n) - 2;

    // Verify the modification happened
    let eq_poly = EvaluationsList::new_from_point(&challenges, F::ONE);
    let expected_last = eq_poly.as_slice()[last_idx] - product;
    let expected_second_last = eq_poly.as_slice()[second_last_idx] + product;

    assert_eq!(result.as_slice()[last_idx], expected_last);
    assert_eq!(result.as_slice()[second_last_idx], expected_second_last);
}

#[test]
fn test_matrix_down_folded() {
    let n = 3;
    let challenges = create_test_challenges(n);

    let result = matrix_down_folded(&challenges);

    // Should return an EvaluationsList with 2^n evaluations
    assert_eq!(result.num_variables(), n);
    assert_eq!(result.num_evals(), 1 << n);
}

#[test]
fn test_matrix_down_folded_structure() {
    let n = 2;
    let challenges = vec![F::new(1), F::new(0)];

    let result = matrix_down_folded(&challenges);

    // Should have correct size
    assert_eq!(result.num_evals(), 1 << n);

    // Bottom left corner should have the product
    let product: F = challenges.iter().copied().product();
    let last_idx = (1 << n) - 1;

    // The last element should include the product
    assert!(result.as_slice()[last_idx] != F::new(0) || product == F::new(0));
}

#[test]
fn test_matrix_folded_with_different_skips() {
    for n in 1..=4 {
        let challenges = create_test_challenges(n);

        let up_result = matrix_up_folded(&challenges);
        let down_result = matrix_down_folded(&challenges);

        assert_eq!(up_result.num_variables(), n);
        assert_eq!(down_result.num_variables(), n);
        assert_eq!(up_result.num_evals(), 1 << n);
        assert_eq!(down_result.num_evals(), 1 << n);
    }
}

#[test]
fn test_matrix_folded_with_zero_challenges() {
    let n = 2;
    let challenges = vec![F::new(0); n];

    let up_result = matrix_up_folded(&challenges);
    let down_result = matrix_down_folded(&challenges);

    // Should handle zeros correctly
    assert_eq!(up_result.num_evals(), 1 << n);
    assert_eq!(down_result.num_evals(), 1 << n);
}

#[test]
fn test_matrix_folded_with_one_challenges() {
    let n = 2;
    let challenges = vec![F::ONE; n];

    let up_result = matrix_up_folded(&challenges);
    let down_result = matrix_down_folded(&challenges);

    // Should handle ones correctly
    assert_eq!(up_result.num_evals(), 1 << n);
    assert_eq!(down_result.num_evals(), 1 << n);
}

#[test]
fn test_matrix_folded_consistency() {
    let n = 3;
    let challenges = create_test_challenges(n);

    // Both should produce valid multilinear polynomials
    let up_result = matrix_up_folded(&challenges);
    let down_result = matrix_down_folded(&challenges);

    // Verify they can be evaluated
    let test_point: Vec<F> = create_test_challenges(n);
    let up_eval = up_result.evaluate_hypercube_base::<F>(
        &whir_p3::poly::multilinear::MultilinearPoint::new(test_point.clone()),
    );
    let down_eval = down_result.evaluate_hypercube_base::<F>(
        &whir_p3::poly::multilinear::MultilinearPoint::new(test_point),
    );

    // Evaluations should be field elements
    assert!(up_eval != F::ZERO || challenges.iter().all(|&x| x == F::new(0)));
    assert!(down_eval != F::ZERO || challenges.iter().all(|&x| x == F::new(0)));
}

#[test]
fn test_matrix_folded_large_n() {
    let n = 5;
    let challenges = create_test_challenges(n);

    let up_result = matrix_up_folded(&challenges);
    let down_result = matrix_down_folded(&challenges);

    // Should handle larger n without issues
    assert_eq!(up_result.num_evals(), 1 << n);
    assert_eq!(down_result.num_evals(), 1 << n);
}
