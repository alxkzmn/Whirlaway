use p3_air::{Air, BaseAir};
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;
use sumcheck::SumcheckComputation;

type F = KoalaBear;
type EF = BinomialExtensionField<F, 8>;

// Simple AIR that computes sum of all columns
#[derive(Clone)]
struct SimpleAir;

impl<AB: p3_air::AirBuilder<F = F>> Air<AB> for SimpleAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let width = main.width();
        let mut sum = AB::Expr::ZERO;
        let row: Vec<_> = main
            .row(0)
            .expect("Matrix should have at least one row")
            .into_iter()
            .collect();
        for col in 0..width {
            sum = sum + row[col].clone();
        }
        builder.assert_zero(sum);
    }
}

impl BaseAir<F> for SimpleAir {
    fn width(&self) -> usize {
        2
    }
}

#[test]
fn test_sumcheck_computation_trait() {
    let air = SimpleAir;
    let _n_vars = 3;

    // Create a point with 2 * width elements (for up and down columns)
    let width = 2;
    let point: Vec<F> = (0..2 * width).map(|i| F::new(i as u32)).collect();

    let alpha_powers = vec![EF::ONE];

    let result = SumcheckComputation::eval(&air, &point, &alpha_powers);

    // SimpleAir: accumulator = alpha[0] * (row0col0 + row0col1)
    let expected = alpha_powers[0] * (point[0] + point[1]);
    assert_eq!(result, expected);
}

#[test]
fn test_sumcheck_computation_with_multiple_constraints() {
    // AIR with multiple constraints
    #[derive(Clone)]
    struct MultiConstraintAir;

    impl<AB: p3_air::AirBuilder<F = F>> Air<AB> for MultiConstraintAir {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let width = main.width();
            let row: Vec<_> = main
                .row(0)
                .expect("Matrix should have at least one row")
                .into_iter()
                .collect();

            // First constraint: sum of first column
            builder.assert_zero(row[0].clone());

            // Second constraint: sum of second column
            if width > 1 {
                builder.assert_zero(row[1].clone());
            }
        }
    }

    impl BaseAir<F> for MultiConstraintAir {
        fn width(&self) -> usize {
            2
        }
    }

    let air = MultiConstraintAir;
    let width = 2;
    let point: Vec<F> = (0..2 * width).map(|i| F::new(i as u32)).collect();

    let alpha_powers = vec![EF::ONE, EF::ONE];

    let result = SumcheckComputation::eval(&air, &point, &alpha_powers);

    // MultiConstraintAir: accumulator = alpha[0] * row0col0 + alpha[1] * row0col1
    let expected = alpha_powers[0] * point[0] + alpha_powers[1] * point[1];
    assert_eq!(result, expected);
}

#[test]
fn test_sumcheck_computation_with_alpha_powers() {
    let air = SimpleAir;
    let point: Vec<F> = vec![F::new(1), F::new(2), F::new(3), F::new(4)];

    // SimpleAir uses exactly one constraint, so only alpha_powers[0] is used.
    let alpha_powers = vec![EF::from(F::new(2))];

    let result = SumcheckComputation::eval(&air, &point, &alpha_powers);

    let expected = alpha_powers[0] * (point[0] + point[1]);
    assert_eq!(result, expected);
}

#[test]
fn test_sumcheck_computation_extension_field() {
    let air = SimpleAir;
    let _width = 2;

    // Use extension field elements in the point
    let point: Vec<EF> = vec![
        EF::from(F::new(1)),
        EF::from(F::new(2)),
        EF::from(F::new(3)),
        EF::from(F::new(4)),
    ];

    let alpha_powers = vec![EF::ONE];

    let result = SumcheckComputation::eval(&air, &point, &alpha_powers);

    let expected = alpha_powers[0] * (point[0] + point[1]);
    assert_eq!(result, expected);
}

#[test]
fn test_sumcheck_computation_zero_result() {
    let air = SimpleAir;
    let _width = 2;

    // Point where all elements sum to zero
    let point: Vec<F> = vec![F::new(1), -F::new(1), F::new(2), -F::new(2)];

    let alpha_powers = vec![EF::ONE];

    let result = SumcheckComputation::eval(&air, &point, &alpha_powers);

    // First row sums to zero, so the constraint evaluates to zero.
    assert_eq!(result, EF::ZERO);
}

#[test]
fn test_sumcheck_computation_packed() {
    use p3_field::PackedValue;
    use sumcheck::SumcheckComputationPacked;

    let air = SimpleAir;

    // Create packed points for a 2x2 matrix (2 * width elements).
    // Row 0 is [1, 2], row 1 is [3, 4] (row 1 is ignored by SimpleAir).
    let point: Vec<<F as Field>::Packing> = vec![
        <F as Field>::Packing::from(F::new(1)),
        <F as Field>::Packing::from(F::new(2)),
        <F as Field>::Packing::from(F::new(3)),
        <F as Field>::Packing::from(F::new(4)),
    ];

    let alpha_powers = vec![EF::ONE];
    let decomposed_alpha_powers: Vec<Vec<F>> = vec![vec![F::ONE]];

    let results: Vec<EF> = SumcheckComputationPacked::eval_packed(
        &air,
        &point,
        &alpha_powers,
        &decomposed_alpha_powers,
    )
    .collect();

    // Should return one result per SIMD lane.
    assert_eq!(results.len(), <F as Field>::Packing::WIDTH);
    for r in results {
        assert_eq!(r, EF::from(F::new(3)));
    }
}

#[test]
fn test_sumcheck_computation_with_constraint_folder() {
    let air = SimpleAir;

    // Create a matrix view
    let data: Vec<F> = vec![F::new(1), F::new(2), F::new(3), F::new(4)];
    let point: Vec<F> = data.clone();
    let alpha_powers = vec![EF::ONE];

    // This should work the same as the trait method
    let result = SumcheckComputation::eval(&air, &point, &alpha_powers);

    let expected = alpha_powers[0] * (point[0] + point[1]);
    assert_eq!(result, expected);
}
