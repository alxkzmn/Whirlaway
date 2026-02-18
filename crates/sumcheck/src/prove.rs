use std::{any::Any, borrow::Borrow};

use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PackedValue, TwoAdicField};
use rayon::prelude::*;
use tracing::instrument;
use utils::{
    DensePolynomial, ProverState, batch_fold_multilinear_in_large_field,
    batch_fold_multilinear_in_small_field, univariate_selectors,
};
use whir_p3::poly::evals::EvaluationsList;

use crate::{SumcheckComputation, SumcheckComputationPacked, SumcheckGrinding};

pub const MIN_VARS_FOR_GPU: usize = 0; // When there are a small number of variables, it's not worth using GPU
// Empirical crossover from release/native profiling: for <=64 hypercube points,
// per-task Rayon overhead tends to dominate scalar evaluation.
const SMALL_HYPERCUBE_PAR_THRESHOLD: usize = 64;
// Packed lane loops are very tight; parallelism only helps once there are more
// than a small number of packed chunks (~16) to amortize scheduling cost.
const SMALL_PACKED_PAR_THRESHOLD: usize = 16;
// Specialized first-round zerocheck parallelizes over z-values; keep tiny z-ranges
// (<=8 points) sequential to avoid thread-pool overhead in the hot first round.
const SMALL_FAST_Z_PAR_THRESHOLD: usize = 8;

#[allow(clippy::too_many_arguments)]
pub fn prove<F, NF, EF, M, SC, Challenger>(
    skips: usize, // skips == 1: classic sumcheck. skips >= 2: sumcheck with univariate skips (eprint 2024/108)
    multilinears: &[M],
    computation: &SC,
    constraints_degree: usize,
    batching_scalars: &[EF],
    eq_factor: Option<&[EF]>,
    is_zerofier: bool,
    fs_prover: &mut ProverState<F, EF, Challenger>,
    mut sum: EF,
    n_rounds: Option<usize>,
    grinding: SumcheckGrinding,
    mut missing_mul_factor: Option<EF>,
    public_values: &[NF],
    public_values_packed: &[F::Packing],
) -> (Vec<EF>, Vec<EvaluationsList<EF>>, EF)
where
    F: TwoAdicField,
    NF: ExtensionField<F>,
    EF: ExtensionField<NF> + ExtensionField<F> + TwoAdicField,
    M: Borrow<EvaluationsList<NF>>,
    SC: SumcheckComputation<F, NF, EF>
        + SumcheckComputation<F, EF, EF>
        + SumcheckComputationPacked<F, EF>,
    StandardUniform: Distribution<EF>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    let multilinears = multilinears.iter().map(|m| m.borrow()).collect::<Vec<_>>();
    let mut n_vars = multilinears[0].num_variables();
    assert!(multilinears.iter().all(|m| m.num_variables() == n_vars));

    let mut challenges = Vec::new();
    let n_rounds = n_rounds.unwrap_or(n_vars - skips + 1);
    if let Some(eq_factor) = &eq_factor {
        assert_eq!(eq_factor.len(), n_vars - skips + 1);
    }

    let public_values_ef = public_values
        .iter()
        .copied()
        .map(EF::from)
        .collect::<Vec<_>>();

    let mut folded_multilinears = sc_round(
        skips,
        &multilinears,
        &mut n_vars,
        computation,
        eq_factor,
        batching_scalars,
        is_zerofier,
        fs_prover,
        constraints_degree,
        &mut sum,
        grinding,
        &mut challenges,
        0,
        &mut missing_mul_factor,
        public_values,
        public_values_packed,
    );

    for i in 1..n_rounds {
        folded_multilinears = sc_round(
            1,
            &folded_multilinears.iter().collect::<Vec<_>>(),
            &mut n_vars,
            computation,
            eq_factor,
            batching_scalars,
            false,
            fs_prover,
            constraints_degree,
            &mut sum,
            grinding,
            &mut challenges,
            i,
            &mut missing_mul_factor,
            &public_values_ef,
            public_values_packed,
        );
    }

    (challenges, folded_multilinears, sum)
}

#[instrument(name = "sumcheck_round", skip_all, fields(round))]
#[allow(clippy::too_many_arguments)]
pub fn sc_round<F, NF, EF, SC, Challenger>(
    skips: usize, // the first round will fold 2^skips (instead of 2 in the basic sumcheck)
    multilinears: &[&EvaluationsList<NF>],
    n_vars: &mut usize,
    computation: &SC,
    eq_factor: Option<&[EF]>,
    batching_scalars: &[EF],
    is_zerofier: bool,
    fs_prover: &mut ProverState<F, EF, Challenger>,
    comp_degree: usize,
    sum: &mut EF,
    grinding: SumcheckGrinding,
    challenges: &mut Vec<EF>,
    round: usize,
    missing_mul_factor: &mut Option<EF>,
    public_values: &[NF],
    public_values_packed: &[F::Packing],
) -> Vec<EvaluationsList<EF>>
where
    F: TwoAdicField,
    NF: ExtensionField<F>,
    EF: ExtensionField<NF> + ExtensionField<F> + TwoAdicField,
    SC: SumcheckComputation<F, NF, EF> + SumcheckComputationPacked<F, EF>,
    StandardUniform: Distribution<EF>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    let eq_mle = eq_factor
        .map(|eq_factor| EvaluationsList::new_from_point(&eq_factor[1 + round..], EF::ONE));

    let selectors: Vec<DensePolynomial<F>> = if skips == 1 {
        // In the case skips == 1, we do not need to compute the selectors, as they are S_0(x) = 1 - x and S_1(x) = x.
        Vec::new()
    } else {
        univariate_selectors::<F>(skips)
    };

    let selectors_ef: Vec<DensePolynomial<EF>> = if skips == 1 {
        Vec::new()
    } else {
        selectors
            .iter()
            .map(|s| {
                DensePolynomial::from_coefficients_vec(
                    s.coeffs.iter().copied().map(EF::from).collect(),
                )
            })
            .collect()
    };

    let mut p_evals = Vec::<(F, EF)>::new();
    let start = if is_zerofier {
        p_evals.extend((0..1 << skips).map(|i| (F::from_usize(i), EF::ZERO)));
        1 << skips
    } else {
        0
    };

    if let Some(fast_sum_zs) = if is_zerocheck {
        maybe_fast_zerocheck_first_round_sums(
            skips,
            multilinears,
            &selectors,
            comp_degree,
            computation,
            batching_scalars,
            eq_mle.as_ref(),
            public_values,
            public_values_packed,
        )
    } else {
        None
    } {
        for (offset, mut sum_z) in fast_sum_zs.into_iter().enumerate() {
            if let Some(missing_mul_factor) = missing_mul_factor {
                sum_z *= *missing_mul_factor;
            }
            p_evals.push((F::from_usize(start + offset), sum_z));
        }
    } else {
        for z in start..=comp_degree * ((1 << skips) - 1) {
            let sum_z = if z == (1 << skips) - 1 {
                if let Some(eq_factor) = eq_factor {
                    if skips == 1 {
                        (*sum - p_evals[0].1 * (EF::ONE - eq_factor[round])) / eq_factor[round]
                    } else {
                        (*sum
                            - (0..(1 << skips) - 1)
                                .map(|i| p_evals[i].1 * selectors_ef[i].evaluate(eq_factor[round]))
                                .sum::<EF>())
                            / selectors_ef[(1 << skips) - 1].evaluate(eq_factor[round])
                    }
                } else {
                    *sum - p_evals.iter().map(|(_, s)| *s).sum::<EF>()
                }
            } else {
                let folded = if skips == 1 && z == 0 {
                    // In this case, we don't need to use the folding function, because we just have to take the first half of the evaluations.
                    multilinears
                        .par_iter()
                        .map(|poly| {
                            let evals = poly.as_slice();
                            let (first_half, _) = evals.split_at(evals.len() / 2);
                            EvaluationsList::new(first_half.to_vec())
                        })
                        .collect()
                } else {
                    let folding_scalars = if skips == 1 {
                        vec![F::ONE - F::from_usize(z), F::from_usize(z)]
                    } else {
                        selectors
                            .iter()
                            .map(|s| s.evaluate(F::from_usize(z)))
                            .collect::<Vec<_>>()
                    };

                    batch_fold_multilinear_in_small_field(multilinears, &folding_scalars)
                };

                let mut sum_z = compute_over_hypercube(
                    &folded,
                    computation,
                    batching_scalars,
                    eq_mle.as_ref(),
                    public_values,
                    public_values_packed,
                );

                if let Some(missing_mul_factor) = missing_mul_factor {
                    sum_z *= *missing_mul_factor;
                }

                sum_z
            };

            p_evals.push((F::from_usize(z), sum_z));
        }
    }

    let mut p = DensePolynomial::lagrange_interpolation(&p_evals).unwrap();

    if let Some(eq_factor) = &eq_factor {
        // https://eprint.iacr.org/2024/108.pdf Section 3.2
        // We do not take advantage of this trick to send less data, but we could do so in the future (TODO)
        if skips == 1 {
            // We multiply `p` by the polynomial q(X) = 1 - r_j + (2 * r_j - 1) * X.
            // This polynomial `q` interpolates the points (0, 1 - r_j) and (1, r_j).
            let a = EF::ONE - eq_factor[round];
            let b = EF::from_usize(2) * eq_factor[round] - EF::ONE;
            let selector_poly = DensePolynomial::from_coefficients_vec(vec![a, b]);
            p.mul_assign(&selector_poly);
        } else {
            let selector_poly = DensePolynomial::lagrange_interpolation(
                &(0..1 << skips)
                    .into_par_iter()
                    .map(|i| {
                        (
                            EF::from_usize(i),
                            selectors_ef[i].evaluate(eq_factor[round]),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            p.mul_assign(&selector_poly);
        }
    }

    fs_prover.add_extension_scalars(&p.coeffs);

    let challenge = fs_prover.sample();
    challenges.push(challenge);
    *sum = p.evaluate(challenge);
    *n_vars -= skips;

    let pow_bits = grinding
        .pow_bits::<EF>((comp_degree + usize::from(eq_factor.is_some())) * ((1 << skips) - 1));
    fs_prover.pow_grinding(pow_bits);

    let folding_scalars = selectors
        .iter()
        .map(|s| s.evaluate(challenge))
        .collect::<Vec<_>>();
    if let Some(eq_factor) = eq_factor {
        *missing_mul_factor = Some(
            // Recall taht if skips == 1, the selectors are S_0 and S_1 with
            // S_0(x) = 1 - x
            // S_1(x) = x
            if skips == 1 {
                ((EF::ONE - eq_factor[round]) * (EF::ONE - challenge)
                    + eq_factor[round] * challenge)
                    * missing_mul_factor.unwrap_or(EF::ONE)
            } else {
                selectors_ef
                    .iter()
                    .map(|s| s.evaluate(eq_factor[round]) * s.evaluate(challenge))
                    .sum::<EF>()
                    * missing_mul_factor.unwrap_or(EF::ONE)
            },
        );
    }

    let folding_scalars = if skips == 1 {
        vec![EF::ONE - challenge, challenge]
    } else {
        selectors_ef
            .iter()
            .map(|s| s.evaluate(challenge))
            .collect::<Vec<_>>()
    };

    batch_fold_multilinear_in_large_field(multilinears, &folding_scalars)
}

#[derive(Clone)]
struct FastZerocheckScratch<F: Field, NF: ExtensionField<F>> {
    point_packed: Vec<F::Packing>,
    point_scalar: Vec<NF>,
}

impl<F: Field, NF: ExtensionField<F>> FastZerocheckScratch<F, NF> {
    fn new(width: usize) -> Self {
        Self {
            point_packed: vec![F::Packing::from_fn(|_| F::ZERO); width],
            point_scalar: vec![NF::ZERO; width],
        }
    }
}

#[allow(clippy::too_many_arguments)]
/// Attempt the specialized zerocheck-first-round accumulator path.
///
/// Fast path eligibility:
/// - `skips > 1` and non-empty `selectors` (univariate-skip mode),
/// - every input multilinear can be downcast at runtime to `EvaluationsList<F>`
///   (i.e. this call is effectively the `NF = F` case),
/// - and `skips <= n_vars` for the provided multilinears.
///
/// When eligible, this computes the zerocheck round sums for all non-trivial
/// interpolation points `z` in ascending order over:
/// `z = 2^skips ..= comp_degree * (2^skips - 1)`.
/// Each entry already includes optional `eq_mle` weighting and is returned in
/// `EF`. The caller is responsible for any external round-level scaling
/// (e.g. `missing_mul_factor`) and for handling the skipped domain points.
///
/// Return value:
/// - `Some(values)`: fast path was used; `values[i]` corresponds to
///   `z = 2^skips + i`,
/// - `Some(vec![])`: fast path was used but the target `z` range is empty,
/// - `None`: fast path is not applicable and caller should use the generic path.
fn maybe_fast_zerocheck_first_round_sums<F, NF, EF, SC>(
    skips: usize,
    multilinears: &[&EvaluationsList<NF>],
    selectors: &[DensePolynomial<F>],
    comp_degree: usize,
    computation: &SC,
    batching_scalars: &[EF],
    eq_mle: Option<&EvaluationsList<EF>>,
    public_values: &[NF],
    public_values_packed: &[F::Packing],
) -> Option<Vec<EF>>
where
    F: Field,
    NF: ExtensionField<F>,
    EF: ExtensionField<NF> + ExtensionField<F>,
    SC: SumcheckComputation<F, NF, EF> + SumcheckComputationPacked<F, EF>,
{
    if skips <= 1 || selectors.is_empty() {
        return None;
    }

    let pols_f = multilinears
        .iter()
        .map(|pol| ((*pol) as &dyn Any).downcast_ref::<EvaluationsList<F>>())
        .collect::<Option<Vec<_>>>()?;
    let n_vars = pols_f.first()?.num_variables();
    if skips > n_vars {
        return None;
    }

    let chunk_count = 1usize << skips;
    debug_assert_eq!(selectors.len(), chunk_count);

    let reduced_size = 1usize << (n_vars - skips);
    let start = chunk_count;
    let end = comp_degree.saturating_mul(chunk_count.saturating_sub(1));
    if start > end {
        return Some(Vec::new());
    }

    let selector_values = (start..=end)
        .map(|z| {
            let zf = F::from_usize(z);
            selectors
                .iter()
                .map(|selector| selector.evaluate(zf))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let decomposed_batching_scalars = (0..<EF as BasedVectorSpace<F>>::DIMENSION)
        .map(|coeff_idx| {
            batching_scalars
                .iter()
                .map(|scalar| scalar.as_basis_coefficients_slice()[coeff_idx])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let eq_mle_values = eq_mle.map(EvaluationsList::as_slice);

    let chunked = pols_f
        .iter()
        .map(|pol| {
            let evals = pol.as_slice();
            (0..chunk_count)
                .map(|chunk_idx| {
                    let offset = chunk_idx * reduced_size;
                    &evals[offset..offset + reduced_size]
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let partitioned_chunks = chunked
        .iter()
        .map(|chunks| {
            chunks
                .iter()
                .map(|chunk| F::Packing::pack_slice_with_suffix(chunk))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let packed_width = F::Packing::WIDTH;
    let packed_len = reduced_size / packed_width;
    let suffix_offset = packed_len * packed_width;

    let eval_sum_for_selector =
        |scratch: &mut FastZerocheckScratch<F, NF>, selector_coeffs: &[F]| -> EF {
            let mut sum_z = EF::ZERO;

            if packed_len > 0 {
                for packed_idx in 0..packed_len {
                    for (pol_idx, chunks) in partitioned_chunks.iter().enumerate() {
                        let mut folded = F::Packing::from_fn(|_| F::ZERO);
                        for (chunk_idx, (packed_chunk, _)) in chunks.iter().enumerate() {
                            folded += packed_chunk[packed_idx] * selector_coeffs[chunk_idx];
                        }
                        scratch.point_packed[pol_idx] = folded;
                    }

                    let packed_eval = computation.eval_packed(
                        &scratch.point_packed,
                        batching_scalars,
                        &decomposed_batching_scalars,
                        public_values_packed,
                    );

                    if let Some(eq_mle_values) = eq_mle_values {
                        let lane_base = packed_idx * packed_width;
                        sum_z += packed_eval
                            .enumerate()
                            .map(|(lane, eval)| eval * eq_mle_values[lane_base + lane])
                            .sum::<EF>();
                    } else {
                        sum_z += packed_eval.sum::<EF>();
                    }
                }
                for suffix_idx in 0..(reduced_size - suffix_offset) {
                    for (pol_idx, chunks) in partitioned_chunks.iter().enumerate() {
                        let mut folded = F::ZERO;
                        for (chunk_idx, (_, suffix_chunk)) in chunks.iter().enumerate() {
                            folded += suffix_chunk[suffix_idx] * selector_coeffs[chunk_idx];
                        }
                        scratch.point_scalar[pol_idx] = NF::from(folded);
                    }

                    let mut eval =
                        computation.eval(&scratch.point_scalar, batching_scalars, public_values);
                    if let Some(eq_mle_values) = eq_mle_values {
                        eval *= eq_mle_values[suffix_offset + suffix_idx];
                    }
                    sum_z += eval;
                }
            } else {
                for x in 0..reduced_size {
                    for (pol_idx, chunks) in chunked.iter().enumerate() {
                        let mut folded = F::ZERO;
                        for (chunk_idx, chunk) in chunks.iter().enumerate() {
                            folded += chunk[x] * selector_coeffs[chunk_idx];
                        }
                        scratch.point_scalar[pol_idx] = NF::from(folded);
                    }

                    let mut eval =
                        computation.eval(&scratch.point_scalar, batching_scalars, public_values);
                    if let Some(eq_mle_values) = eq_mle_values {
                        eval *= eq_mle_values[x];
                    }
                    sum_z += eval;
                }
            }

            sum_z
        };

    if selector_values.len() <= SMALL_FAST_Z_PAR_THRESHOLD {
        let mut scratch = FastZerocheckScratch::<F, NF>::new(chunked.len());
        Some(
            selector_values
                .iter()
                .map(|selector_coeffs| eval_sum_for_selector(&mut scratch, selector_coeffs))
                .collect(),
        )
    } else {
        Some(
            selector_values
                .par_iter()
                .map_init(
                    || FastZerocheckScratch::<F, NF>::new(chunked.len()),
                    |scratch, selector_coeffs| eval_sum_for_selector(scratch, selector_coeffs),
                )
                .collect(),
        )
    }
}

fn compute_over_hypercube<F, NF, EF, SC>(
    pols: &[EvaluationsList<NF>],
    computation: &SC,
    batching_scalars: &[EF],
    eq_mle: Option<&EvaluationsList<EF>>,
    public_values: &[NF],
    public_values_packed: &[F::Packing],
) -> EF
where
    F: Field,
    NF: ExtensionField<F>,
    EF: ExtensionField<NF> + ExtensionField<F>,
    SC: SumcheckComputation<F, NF, EF> + SumcheckComputationPacked<F, EF>,
{
    assert!(
        pols.iter()
            .all(|p| p.num_variables() == pols[0].num_variables())
    );
    let n_vars = pols[0].num_variables();

    let pols_f = pols
        .iter()
        .map(|pol| (pol as &dyn Any).downcast_ref::<EvaluationsList<F>>())
        .collect::<Option<Vec<_>>>();
    let eval_len = 1usize << n_vars;

    if let Some(pols_f) = pols_f {
        if eval_len.is_multiple_of(F::Packing::WIDTH) {
            let packed_pols = pols_f
                .iter()
                .map(|pol| F::Packing::pack_slice(pol.as_slice()))
                .collect::<Vec<_>>();

            let decomposed_batching_scalars = (0..<EF as BasedVectorSpace<F>>::DIMENSION)
                .map(|coeff_idx| {
                    batching_scalars
                        .iter()
                        .map(|scalar| scalar.as_basis_coefficients_slice()[coeff_idx])
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let eq_mle_slice = eq_mle.map(EvaluationsList::as_slice);
            let packed_count = eval_len / F::Packing::WIDTH;

            if packed_count <= SMALL_PACKED_PAR_THRESHOLD {
                let mut point = vec![F::Packing::from_fn(|_| F::ZERO); packed_pols.len()];
                let mut sum = EF::ZERO;
                for packed_idx in 0..packed_count {
                    for (dst, pol) in point.iter_mut().zip(&packed_pols) {
                        *dst = pol[packed_idx];
                    }
                    let packed_eval = computation.eval_packed(
                        &point,
                        batching_scalars,
                        &decomposed_batching_scalars,
                        public_values_packed,
                    );

                    if let Some(eq_mle_slice) = eq_mle_slice {
                        let base = packed_idx * F::Packing::WIDTH;
                        sum += packed_eval
                            .enumerate()
                            .map(|(lane, eval)| eval * eq_mle_slice[base + lane])
                            .sum::<EF>();
                    } else {
                        sum += packed_eval.sum::<EF>();
                    }
                }
                return sum;
            }

            return (0..packed_count)
                .into_par_iter()
                .map_init(
                    || vec![F::Packing::from_fn(|_| F::ZERO); packed_pols.len()],
                    |point, packed_idx| {
                        for (dst, pol) in point.iter_mut().zip(&packed_pols) {
                            *dst = pol[packed_idx];
                        }
                        let packed_eval = computation.eval_packed(
                            point,
                            batching_scalars,
                            &decomposed_batching_scalars,
                            public_values_packed,
                        );

                        if let Some(eq_mle_slice) = eq_mle_slice {
                            let base = packed_idx * F::Packing::WIDTH;
                            packed_eval
                                .enumerate()
                                .map(|(lane, eval)| eval * eq_mle_slice[base + lane])
                                .sum::<EF>()
                        } else {
                            packed_eval.sum::<EF>()
                        }
                    },
                )
                .sum();
        }
    }

    if eval_len <= SMALL_HYPERCUBE_PAR_THRESHOLD {
        let mut point = vec![NF::ZERO; pols.len()];
        let mut sum = EF::ZERO;
        for x in 0..eval_len {
            for (dst, pol) in point.iter_mut().zip(pols) {
                *dst = pol.as_slice()[x];
            }
            let eq_mle_eval = eq_mle.map(|p| p.as_slice()[x]);
            sum += eval_sumcheck_computation(
                computation,
                batching_scalars,
                &point,
                eq_mle_eval,
                public_values,
            );
        }
        sum
    } else {
        (0..eval_len)
            .into_par_iter()
            .map(|x| {
                let point = pols.iter().map(|pol| pol.as_slice()[x]).collect::<Vec<_>>();
                let eq_mle_eval = eq_mle.map(|p| p.as_slice()[x]);
                eval_sumcheck_computation(
                    computation,
                    batching_scalars,
                    &point,
                    eq_mle_eval,
                    public_values,
                )
            })
            .sum()
    }
}

pub fn eval_sumcheck_computation<F, NF, EF, SC>(
    computation: &SC,
    batching_scalars: &[EF],
    point: &[NF],
    eq_mle_eval: Option<EF>,
    public_values: &[NF],
) -> EF
where
    F: Field,
    NF: ExtensionField<F>,
    EF: ExtensionField<NF>,
    SC: SumcheckComputation<F, NF, EF>,
{
    let res = computation.eval(point, batching_scalars, public_values);
    eq_mle_eval.map_or(res, |factor| res * factor)
}
