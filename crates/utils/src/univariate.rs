use p3_field::Field;
use rayon::prelude::*;

use crate::DensePolynomial;

pub fn univariate_selectors<F: Field>(n: usize) -> Vec<DensePolynomial<F>> {
    (0..1 << n)
        .into_par_iter()
        .map(|i| {
            let values = (0..1 << n)
                .map(|j| (F::from_u64(j), if i == j { F::ONE } else { F::ZERO }))
                .collect::<Vec<_>>();
            DensePolynomial::lagrange_interpolation(&values).unwrap()
        })
        .collect()
}
