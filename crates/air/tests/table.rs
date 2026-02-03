use air::{AirSettings, table::AirTable};
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::KoalaBear;
use whir_p3::parameters::{FoldingFactor, errors::SecurityAssumption};
mod helpers;
use helpers::{
    MockAir, create_preprocessed_columns, setup_merkle_compress, setup_merkle_hash, MyChallenger,
};

type F = KoalaBear;
type EF = BinomialExtensionField<F, 8>;

#[test]
fn test_air_table_new() {
    let air = MockAir::new(4);
    let log_length = 3;
    let univariate_skips = 1;
    let preprocessed = create_preprocessed_columns(log_length, 2);
    let constraint_degree = 1;

    let table = AirTable::<F, EF, _>::new(
        air.clone(),
        log_length,
        univariate_skips,
        preprocessed.clone(),
        constraint_degree,
    );

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

    let table = AirTable::<F, EF, _>::new(air, log_length, 1, preprocessed, 1);

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
        1,
        vec![], // No preprocessed columns
        1,
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

    let table = AirTable::<F, EF, _>::new(air, log_length, 1, preprocessed, 1);

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

    let table = AirTable::<F, EF, _>::new(
        air,
        log_length,
        2, // univariate_skips = 2
        vec![],
        2, // constraint_degree = 2
    );

    assert_eq!(table.constraint_degree, 2);
    assert_eq!(table.univariate_selectors.len(), 1 << 2); // 2^2 = 4 selectors
}

#[test]
fn test_air_table_large_width() {
    let air = MockAir::new(16);
    let log_length = 5;

    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 1);

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

    let table = AirTable::<F, EF, _>::new(air, log_length, 1, preprocessed.clone(), 1);

    assert_eq!(table.n_preprocessed_columns(), n_preprocessed);
    assert_eq!(table.n_witness_columns(), 6 - n_preprocessed);
    assert_eq!(table.preprocessed_columns.len(), n_preprocessed);
}

#[test]
fn test_air_table_univariate_selectors() {
    let air = MockAir::new(2);
    let log_length = 2;

    for skips in [1, 2, 3] {
        let table = AirTable::<F, EF, _>::new(air.clone(), log_length, skips, vec![], 1);

        // Should have 2^skips selectors
        assert_eq!(table.univariate_selectors.len(), 1 << skips);
    }
}
