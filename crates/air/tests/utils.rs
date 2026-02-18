use air::utils::{column_down, column_up, columns_up_and_down, matrix_down_lde, matrix_up_lde};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use whir_p3::poly::evals::EvaluationsList;

type F = KoalaBear;

fn create_test_column(log_length: usize) -> EvaluationsList<F> {
    let mut rng = StdRng::seed_from_u64(123);
    let n_rows = 1 << log_length;
    let evals: Vec<F> = (0..n_rows)
        .map(|_| F::new(rng.random_range(0..100)))
        .collect();
    EvaluationsList::new(evals)
}

fn bits_be(n: usize, idx: usize) -> Vec<F> {
    (0..n)
        .map(|i| {
            let shift = n - 1 - i;
            let bit = (idx >> shift) & 1;
            if bit == 1 { F::ONE } else { F::ZERO }
        })
        .collect()
}

#[test]
fn test_matrix_up_lde_truth_table_n3() {
    // On boolean points, matrix_up_lde represents the matrix:
    // - Identity, except last row points to second-last row.
    let n = 3;
    let size = 1usize << n;
    let last = size - 1;
    let second_last = size - 2;

    for row in 0..size {
        for col in 0..size {
            let mut point = bits_be(n, row);
            point.extend(bits_be(n, col));

            let got = matrix_up_lde(&point);
            let expected_is_one = if row == last {
                col == second_last
            } else {
                col == row
            };
            let expected = if expected_is_one { F::ONE } else { F::ZERO };
            assert_eq!(got, expected, "row={row}, col={col}");
        }
    }
}

#[test]
fn test_matrix_down_lde_truth_table_n3() {
    // On boolean points, matrix_down_lde represents the matrix:
    // - Shift-down by one (col = row + 1), plus a 1 at the bottom-right corner.
    let n = 3;
    let size = 1usize << n;
    let last = size - 1;

    for row in 0..size {
        for col in 0..size {
            let mut point = bits_be(n, row);
            point.extend(bits_be(n, col));

            let got = matrix_down_lde(&point);
            let expected_is_one = if row == last {
                col == last
            } else {
                col == row + 1
            };
            let expected = if expected_is_one { F::ONE } else { F::ZERO };
            assert_eq!(got, expected, "row={row}, col={col}");
        }
    }
}

#[test]
fn test_column_up() {
    let log_length = 3;
    let column = create_test_column(log_length);
    let original_second_last = column.as_slice()[column.num_evals() - 2];

    let up = column_up(&column);

    // Last element should equal second-to-last
    assert_eq!(up.as_slice()[up.num_evals() - 1], original_second_last);
    // Other elements should be the same
    for i in 0..column.num_evals() - 1 {
        assert_eq!(up.as_slice()[i], column.as_slice()[i]);
    }
}

#[test]
fn test_column_down() {
    let log_length = 3;
    let column = create_test_column(log_length);
    let original_last = column.as_slice()[column.num_evals() - 1];

    let down = column_down(&column);

    // First element should be second element of original
    assert_eq!(down.as_slice()[0], column.as_slice()[1]);
    // Last element should be duplicated
    assert_eq!(down.as_slice()[down.num_evals() - 1], original_last);
    assert_eq!(down.as_slice()[down.num_evals() - 2], original_last);
    // Length should be the same
    assert_eq!(down.num_evals(), column.num_evals());
}

#[test]
fn test_columns_up_and_down() {
    let log_length = 3;
    let column1 = create_test_column(log_length);
    let column2 = create_test_column(log_length);
    let columns = vec![&column1, &column2];

    let result = columns_up_and_down(&columns);

    // Should return 2 * n_columns evaluations (up and down for each)
    assert_eq!(result.len(), 2 * columns.len());

    // First half should be "up" versions
    for i in 0..columns.len() {
        let up = column_up(columns[i]);
        assert_eq!(result[i].as_slice(), up.as_slice());
    }

    // Second half should be "down" versions
    for i in 0..columns.len() {
        let down = column_down(columns[i]);
        assert_eq!(result[columns.len() + i].as_slice(), down.as_slice());
    }
}

#[test]
fn test_column_up_two_rows() {
    let column = EvaluationsList::new(vec![F::new(7), F::new(9)]);
    let up = column_up(&column);

    // Last element should equal second-to-last.
    assert_eq!(up.as_slice(), &[F::new(7), F::new(7)]);
}

#[test]
fn test_column_down_two_rows() {
    let column = EvaluationsList::new(vec![F::new(7), F::new(9)]);
    let down = column_down(&column);

    // Shift left and duplicate last.
    assert_eq!(down.as_slice(), &[F::new(9), F::new(9)]);
}

// Note: next_mle is a private function used by matrix_down_lde.
// We test it indirectly through matrix_down_lde which uses it.
