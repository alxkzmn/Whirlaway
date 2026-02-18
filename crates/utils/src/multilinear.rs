use std::borrow::Borrow;

use p3_field::{ExtensionField, Field, PackedValue, dot_product};
use rayon::prelude::*;
use tracing::instrument;
use whir_p3::poly::evals::EvaluationsList;

// Empirical crossover from release/native profiling: below ~64 output elements,
// Rayon scheduling overhead is typically higher than the fold itself.
const SMALL_FOLD_PAR_THRESHOLD: usize = 64;
// Batch fold parallelizes across polynomials; use total work (polys * output_len)
// and stay sequential below ~1k units to avoid over-threading tiny batches.
const SMALL_BATCH_FOLD_WORK_THRESHOLD: usize = 1024;

pub fn fold_multilinear_in_small_field<F: Field, EF: ExtensionField<F>>(
    m: &EvaluationsList<EF>,
    scalars: &[F],
) -> EvaluationsList<EF> {
    assert!(scalars.len().is_power_of_two() && scalars.len() <= m.num_evals());

    // Case skips == 1:
    if scalars.len() == 2 {
        let new_size = m.num_evals() / 2;
        let (first_half, second_half) = m.as_slice().split_at(new_size);

        if new_size <= SMALL_FOLD_PAR_THRESHOLD {
            EvaluationsList::new(
                first_half
                    .iter()
                    .zip(second_half.iter())
                    .map(|(&a, &b)| a * scalars[0] + b * scalars[1])
                    .collect(),
            )
        } else {
            EvaluationsList::new(
                first_half
                    .par_iter()
                    .zip(second_half.par_iter())
                    .map(|(&a, &b)| a * scalars[0] + b * scalars[1])
                    .collect(),
            )
        }
    } else {
        let new_size = m.num_evals() / scalars.len();

        if new_size <= SMALL_FOLD_PAR_THRESHOLD {
            EvaluationsList::new(
                (0..new_size)
                    .map(|i| {
                        scalars
                            .iter()
                            .enumerate()
                            .map(|(j, s)| m.as_slice()[i + j * new_size] * *s)
                            .sum()
                    })
                    .collect(),
            )
        } else {
            EvaluationsList::new(
                (0..new_size)
                    .into_par_iter()
                    .map(|i| {
                        scalars
                            .iter()
                            .enumerate()
                            .map(|(j, s)| m.as_slice()[i + j * new_size] * *s)
                            .sum()
                    })
                    .collect(),
            )
        }
    }
}

// TODO packing for all the cases
pub fn fold_multilinear_packed<F: Field>(
    m: &EvaluationsList<F>,
    scalars: &[F],
) -> EvaluationsList<F> {
    assert!(scalars.len().is_power_of_two() && scalars.len() <= m.num_evals());
    let new_size = m.num_evals() / scalars.len();
    let inners = (0..scalars.len())
        .map(|idx| &m.as_slice()[idx * new_size..(idx + 1) * new_size])
        .collect::<Vec<_>>();
    let inners_partitioned = inners
        .iter()
        .map(|inner| F::Packing::pack_slice_with_suffix(inner))
        .collect::<Vec<_>>();

    let mut dst = F::zero_vec(new_size);
    let (dst_packed, dst_suffix) = F::Packing::pack_slice_with_suffix_mut(&mut dst);

    if dst_packed.len() <= SMALL_FOLD_PAR_THRESHOLD {
        for (packed_idx, packed_out) in dst_packed.iter_mut().enumerate() {
            *packed_out = scalars
                .iter()
                .enumerate()
                .map(|(inner_idx, scalar)| inners_partitioned[inner_idx].0[packed_idx] * *scalar)
                .sum();
        }
    } else {
        dst_packed
            .par_iter_mut()
            .enumerate()
            .for_each(|(packed_idx, packed_out)| {
                *packed_out = scalars
                    .iter()
                    .enumerate()
                    .map(|(inner_idx, scalar)| {
                        inners_partitioned[inner_idx].0[packed_idx] * *scalar
                    })
                    .sum();
            });
    }

    if dst_suffix.len() <= SMALL_FOLD_PAR_THRESHOLD {
        for (suffix_idx, out) in dst_suffix.iter_mut().enumerate() {
            *out = scalars
                .iter()
                .enumerate()
                .map(|(inner_idx, scalar)| inners_partitioned[inner_idx].1[suffix_idx] * *scalar)
                .sum();
        }
    } else {
        dst_suffix
            .par_iter_mut()
            .enumerate()
            .for_each(|(suffix_idx, out)| {
                *out = scalars
                    .iter()
                    .enumerate()
                    .map(|(inner_idx, scalar)| {
                        inners_partitioned[inner_idx].1[suffix_idx] * *scalar
                    })
                    .sum();
            });
    }

    EvaluationsList::new(dst)
}

pub fn fold_multilinear_in_large_field<F: Field, EF: ExtensionField<F>>(
    m: &EvaluationsList<F>,
    scalars: &[EF],
) -> EvaluationsList<EF> {
    assert!(scalars.len().is_power_of_two() && scalars.len() <= m.num_evals());

    // Case skips == 1:
    if scalars.len() == 2 {
        let new_size = m.num_evals() / 2;
        let (first_half, second_half) = m.as_slice().split_at(new_size);

        if new_size <= SMALL_FOLD_PAR_THRESHOLD {
            EvaluationsList::new(
                first_half
                    .iter()
                    .zip(second_half.iter())
                    .map(|(&a, &b)| scalars[0] * a + scalars[1] * b)
                    .collect(),
            )
        } else {
            EvaluationsList::new(
                first_half
                    .par_iter()
                    .zip(second_half.par_iter())
                    .map(|(&a, &b)| scalars[0] * a + scalars[1] * b)
                    .collect(),
            )
        }
    } else {
        let new_size = m.num_evals() / scalars.len();
        if new_size <= SMALL_FOLD_PAR_THRESHOLD {
            EvaluationsList::new(
                (0..new_size)
                    .map(|i| {
                        scalars
                            .iter()
                            .enumerate()
                            .map(|(j, s)| *s * m.as_slice()[i + j * new_size])
                            .sum()
                    })
                    .collect(),
            )
        } else {
            EvaluationsList::new(
                (0..new_size)
                    .into_par_iter()
                    .map(|i| {
                        scalars
                            .iter()
                            .enumerate()
                            .map(|(j, s)| *s * m.as_slice()[i + j * new_size])
                            .sum()
                    })
                    .collect(),
            )
        }
    }
}

#[instrument(name = "multilinears_linear_combination", skip_all)]
pub fn multilinears_linear_combination<
    F: Field,
    EF: ExtensionField<F>,
    P: Borrow<EvaluationsList<F>> + Send + Sync,
>(
    pols: &[P],
    scalars: &[EF],
) -> EvaluationsList<EF> {
    assert_eq!(pols.len(), scalars.len());
    let n_vars = pols[0].borrow().num_variables();
    assert!(pols.iter().all(|p| p.borrow().num_variables() == n_vars));
    let evals = (0..1 << n_vars)
        .into_par_iter()
        .map(|i| {
            dot_product(
                scalars.iter().copied(),
                pols.iter().map(|p| p.borrow().as_slice()[i]),
            )
        })
        .collect::<Vec<_>>();
    EvaluationsList::new(evals)
}

pub fn batch_fold_multilinear_in_large_field<F: Field, EF: ExtensionField<F>>(
    polys: &[&EvaluationsList<F>],
    scalars: &[EF],
) -> Vec<EvaluationsList<EF>> {
    let new_size = polys
        .first()
        .map_or(0, |poly| poly.num_evals() / scalars.len().max(1));
    let total_work = polys.len().saturating_mul(new_size);
    if total_work <= SMALL_BATCH_FOLD_WORK_THRESHOLD {
        polys
            .iter()
            .map(|poly| fold_multilinear_in_large_field(poly, scalars))
            .collect()
    } else {
        polys
            .par_iter()
            .map(|poly| fold_multilinear_in_large_field(poly, scalars))
            .collect()
    }
}

pub fn batch_fold_multilinear_in_small_field<F: Field, EF: ExtensionField<F>>(
    polys: &[&EvaluationsList<EF>],
    scalars: &[F],
) -> Vec<EvaluationsList<EF>> {
    let new_size = polys
        .first()
        .map_or(0, |poly| poly.num_evals() / scalars.len().max(1));
    let total_work = polys.len().saturating_mul(new_size);
    if total_work <= SMALL_BATCH_FOLD_WORK_THRESHOLD {
        polys
            .iter()
            .map(|poly| fold_multilinear_in_small_field(poly, scalars))
            .collect()
    } else {
        polys
            .par_iter()
            .map(|poly| fold_multilinear_in_small_field(poly, scalars))
            .collect()
    }
}

pub fn packed_multilinear<F: Field>(pols: &[EvaluationsList<F>]) -> EvaluationsList<F> {
    let n_vars = pols[0].num_variables();
    assert!(pols.iter().all(|p| p.num_variables() == n_vars));
    let packed_len = (pols.len() << n_vars).next_power_of_two();
    let mut dst = F::zero_vec(packed_len);
    let mut offset = 0;
    // TODO parallelize
    for pol in pols {
        dst[offset..offset + pol.num_evals()].copy_from_slice(pol.as_slice());
        offset += pol.num_evals();
    }
    EvaluationsList::new(dst)
}

#[instrument(name = "add_multilinears", skip_all)]
pub fn add_multilinears<F: Field>(
    pol1: &EvaluationsList<F>,
    pol2: &EvaluationsList<F>,
) -> EvaluationsList<F> {
    assert_eq!(pol1.num_variables(), pol2.num_variables());
    let mut dst = pol1.as_slice().to_vec();
    dst.par_iter_mut()
        .zip(pol2.as_slice().par_iter())
        .for_each(|(a, b)| *a += *b);
    EvaluationsList::new(dst)
}

#[cfg(test)]
mod tests {
    use p3_field::{PackedValue, PrimeCharacteristicRing};
    use p3_koala_bear::KoalaBear;
    use whir_p3::poly::evals::EvaluationsList;

    use super::fold_multilinear_packed;

    type F = KoalaBear;

    fn fold_reference(evals: &[F], scalars: &[F]) -> Vec<F> {
        let new_size = evals.len() / scalars.len();
        (0..new_size)
            .map(|i| {
                scalars
                    .iter()
                    .enumerate()
                    .map(|(j, s)| evals[i + j * new_size] * *s)
                    .sum()
            })
            .collect()
    }

    #[test]
    fn fold_multilinear_packed_matches_reference_divisible() {
        let width = <F as p3_field::Field>::Packing::WIDTH;
        let Some(new_size) = (0..20)
            .map(|n| 1usize << n)
            .find(|size| size.is_multiple_of(width))
        else {
            return;
        };
        let scalars = vec![
            F::from_usize(2),
            F::from_usize(3),
            F::from_usize(5),
            F::from_usize(7),
        ];
        let evals = (0..new_size * scalars.len())
            .map(|i| F::from_usize(11 + 2 * i))
            .collect::<Vec<_>>();
        let m = EvaluationsList::new(evals.clone());

        let folded = fold_multilinear_packed(&m, &scalars);
        let expected = fold_reference(&evals, &scalars);

        assert_eq!(folded.as_slice(), expected.as_slice());
    }

    #[test]
    fn fold_multilinear_packed_matches_reference_with_suffix() {
        let width = <F as p3_field::Field>::Packing::WIDTH;
        let Some(new_size) = (0..20)
            .map(|n| 1usize << n)
            .find(|size| !size.is_multiple_of(width))
        else {
            return;
        };
        let scalars = vec![F::from_usize(3), F::from_usize(4)];
        let evals = (0..new_size * scalars.len())
            .map(|i| F::from_usize(17 + i))
            .collect::<Vec<_>>();
        let m = EvaluationsList::new(evals.clone());

        let folded = fold_multilinear_packed(&m, &scalars);
        let expected = fold_reference(&evals, &scalars);

        assert_eq!(folded.as_slice(), expected.as_slice());
    }
}
