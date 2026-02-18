use air::{AirSettings, UnivariateSkipMode, table::AirTable};
use air_test_utils::{
    EF, F, MockAir, MyChallenger, create_preprocessed_columns, setup_merkle_compress,
    setup_merkle_hash,
};
use whir_p3::parameters::{FoldingFactor, errors::SecurityAssumption};

#[test]
fn test_air_table_new() {
    let air = MockAir::new(4);
    let log_length = 3;
    let preprocessed = create_preprocessed_columns(log_length, 2);
    let constraint_degree = 1;

    let table = AirTable::<F, EF, _>::new(air, log_length, preprocessed, constraint_degree, 0);

    assert_eq!(table.log_length, log_length);
    assert_eq!(table.n_columns, 4);
    assert_eq!(table.n_preprocessed_columns(), 2);
    assert_eq!(table.n_witness_columns(), 2);
    assert_eq!(table.n_constraints, 1);
    assert_eq!(table.constraint_degree, constraint_degree);
}

#[test]
fn test_air_table_column_counting() {
    let air = MockAir::new(5);
    let log_length = 4;
    let preprocessed = create_preprocessed_columns(log_length, 2);

    let table = AirTable::<F, EF, _>::new(air, log_length, preprocessed, 1, 0);

    assert_eq!(table.n_columns, 5);
    assert_eq!(table.n_preprocessed_columns(), 2);
    assert_eq!(table.n_witness_columns(), 3);
    assert_eq!(table.log_n_witness_columns(), 2); // ceil(log2(3)) = 2
}

#[test]
fn test_air_table_no_preprocessed() {
    let air = MockAir::new(3);
    let log_length = 2;

    let table = AirTable::<F, EF, _>::new(
        air,
        log_length,
        vec![], // No preprocessed columns
        1,
        0,
    );

    assert_eq!(table.n_preprocessed_columns(), 0);
    assert_eq!(table.n_witness_columns(), 3);
    assert_eq!(table.n_columns, 3);
}

#[test]
fn test_air_table_build_whir_params() {
    let air = MockAir::new(4);
    let log_length = 3;
    let preprocessed = create_preprocessed_columns(log_length, 1);

    let table = AirTable::<F, EF, _>::new(air, log_length, preprocessed, 1, 0);

    let settings = AirSettings::new(
        128,
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(4, 4),
        1,
        1,
        4,
    );

    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params =
        table.build_whir_params::<_, _, MyChallenger>(&settings, merkle_hash, merkle_compress);

    // Should create valid WHIR parameters
    let expected_vars = log_length + table.log_n_witness_columns();
    assert_eq!(whir_params.num_variables, expected_vars);
}

#[test]
fn test_air_table_different_settings() {
    let air = MockAir::new(3);
    let log_length = 2;

    let table = AirTable::<F, EF, _>::new(air, log_length, vec![], 2, 0);
    let settings = AirSettings::new_with_skip_mode(
        128,
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(4, 4),
        1,
        UnivariateSkipMode::manual(1),
        4,
    );

    assert_eq!(table.constraint_degree, 2);
    assert_eq!(table.resolve_univariate_skips(&settings), 1);
}

#[test]
fn test_air_table_large_width() {
    let air = MockAir::new(16);
    let log_length = 5;

    let table = AirTable::<F, EF, _>::new(air, log_length, vec![], 1, 0);

    assert_eq!(table.n_columns, 16);
    assert_eq!(table.n_witness_columns(), 16);
    assert_eq!(table.log_n_witness_columns(), 4); // log2(16) = 4
}

#[test]
fn test_air_table_preprocessed_columns() {
    let air = MockAir::new(6);
    let log_length = 3;
    let n_preprocessed = 3;
    let preprocessed = create_preprocessed_columns(log_length, n_preprocessed);

    let table = AirTable::<F, EF, _>::new(air, log_length, preprocessed, 1, 0);

    assert_eq!(table.n_preprocessed_columns(), n_preprocessed);
    assert_eq!(table.n_witness_columns(), 6 - n_preprocessed);
    assert_eq!(table.preprocessed_columns.len(), n_preprocessed);
}

#[test]
fn test_air_table_univariate_selectors() {
    let air = MockAir::new(2);
    let log_length = 2;
    let table = AirTable::<F, EF, _>::new(air.clone(), log_length, vec![], 1, 0);

    for skips in [1, 2] {
        assert_eq!(table.selector_polynomials(skips).len(), 1 << skips);
    }
}

#[test]
fn test_air_table_resolve_univariate_skips_auto() {
    let air = MockAir::new(4);
    let table = AirTable::<F, EF, _>::new(air, 8, vec![], 3, 0);
    let settings = AirSettings::new_with_skip_mode(
        128,
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(4, 4),
        1,
        UnivariateSkipMode::auto(6, 200),
        4,
    );

    assert_eq!(table.resolve_univariate_skips(&settings), 5);
}

#[test]
fn test_air_table_validate_resolved_univariate_skips() {
    let air = MockAir::new(4);
    let table = AirTable::<F, EF, _>::new(air, 6, vec![], 2, 0);
    let settings = AirSettings::new_with_skip_mode(
        128,
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(4, 4),
        1,
        UnivariateSkipMode::manual(2),
        4,
    );

    assert!(table.validate_resolved_univariate_skips(&settings, 2));
    assert!(!table.validate_resolved_univariate_skips(&settings, 1));
}
