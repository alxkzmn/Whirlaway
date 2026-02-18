use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_dft::Radix2Bowers;
use p3_field::{
    BasedVectorSpace, ExtensionField, Field, Packable, PackedValue, TwoAdicField,
    cyclic_subgroup_known_order,
};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use serde::{Deserialize, Serialize};
use sumcheck::{SumcheckComputation, SumcheckComputationPacked, SumcheckGrinding};
use tracing::{Level, info_span, instrument, span};
use utils::fiat_shamir::ProverState;
use utils::{
    ConstraintFolder, ConstraintFolderPacked, add_multilinears, multilinears_linear_combination,
    packed_multilinear,
};
use whir_p3::parameters::ProtocolParameters;
use whir_p3::{
    poly::{evals::EvaluationsList, multilinear::MultilinearPoint},
    whir::{
        committer::writer::CommitmentWriter,
        constraints::statement::{EqStatement, initial::InitialStatement},
        parameters::SumcheckStrategy,
        proof::WhirProof,
        prover::Prover,
    },
};

use crate::{
    AirSettings,
    uni_skip_utils::{matrix_down_folded, matrix_up_folded},
    utils::{column_down, column_up, columns_up_and_down},
};

use super::table::AirTable;

/* Multi Column CCS (SuperSpartan)

cf https://eprint.iacr.org/2023/552.pdf and https://solvable.group/posts/super-air/#fnref:1

*/

fn scale_evals<F: Field>(evals: &EvaluationsList<F>, alpha: F) -> EvaluationsList<F> {
    EvaluationsList::new(evals.as_slice().iter().map(|&v| v * alpha).collect())
}

fn fold_suffix<F: Field, EF: ExtensionField<F>>(
    evals: &EvaluationsList<F>,
    suffix_point: &[EF],
) -> EvaluationsList<EF> {
    let eq = EvaluationsList::new_from_point(suffix_point, EF::ONE);
    let block_size = eq.num_evals();
    let num_blocks = evals.num_evals() / block_size;
    let mut folded = Vec::with_capacity(num_blocks);

    for block in 0..num_blocks {
        let start = block * block_size;
        let value = evals.as_slice()[start..start + block_size]
            .iter()
            .zip(eq.as_slice())
            .map(|(&a, &b)| b * EF::from(a))
            .sum();
        folded.push(value);
    }

    EvaluationsList::new(folded)
}

impl<F, EF, A> AirTable<F, EF, A>
where
    F: TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField,
    A: for<'a> Air<ConstraintFolder<'a, F, F, EF>>
        + for<'a> Air<ConstraintFolder<'a, F, EF, EF>>
        + for<'a> Air<ConstraintFolderPacked<'a, F, EF>>,
{
    #[instrument(name = "air: prove", skip_all)]
    pub fn prove<H, C, Challenger, W, const DIGEST_ELEMS: usize>(
        &self,
        settings: &AirSettings,
        merkle_hash: H,
        merkle_compress: C,
        prover_state: &mut ProverState<F, EF, Challenger>,
        public_values: &[F],
        witness: Vec<EvaluationsList<F>>,
    ) -> WhirProof<F, EF, W, DIGEST_ELEMS>
    where
        Challenger: FieldChallenger<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<p3_symmetric::Hash<F, W, DIGEST_ELEMS>>,
        H: CryptographicHasher<F, [W; DIGEST_ELEMS]> + Sync + Clone,
        C: PseudoCompressionFunction<[W; DIGEST_ELEMS], 2> + Sync + Clone,
        W: p3_field::PackedValue<Value = W> + Eq + Send + Sync + Default,
        [W; DIGEST_ELEMS]: Serialize + for<'de> Deserialize<'de>,
        F: Eq + Packable + Default,
        EF: Default,
        F::Packing: Eq + Send + Sync,
    {
        let log_length = self.log_length;
        let univariate_skips = self.resolve_univariate_skips(settings);
        assert!(witness.iter().all(|w| w.num_variables() == log_length));
        assert_eq!(public_values.len(), self.num_public_values);
        let public_values_packed = public_values
            .iter()
            .copied()
            .map(|value| F::Packing::from_fn(|_| value))
            .collect::<Vec<_>>();

        let whir_params = self.build_whir_params(settings, merkle_hash, merkle_compress);

        // 1) Commit to the witness columns

        // TODO avoid cloning (use a row major matrix for the witness)

        let packed_pol = packed_multilinear(&witness);

        let committer = CommitmentWriter::new(&whir_params);

        let _ext_dim = <EF as BasedVectorSpace<F>>::DIMENSION;
        let dft = Radix2Bowers;

        let proof_params = ProtocolParameters {
            security_level: settings.security_bits,
            pow_bits: crate::WHIR_POW_BITS,
            folding_factor: settings.whir_folding_factor,
            merkle_hash: whir_params.merkle_hash.clone(),
            merkle_compress: whir_params.merkle_compress.clone(),
            soundness_type: settings.whir_soudness_type,
            starting_log_inv_rate: settings.whir_log_inv_rate,
            rs_domain_initial_reduction_factor: settings.whir_initial_domain_reduction_factor,
        };
        let mut whir_proof = WhirProof::<F, EF, W, DIGEST_ELEMS>::from_protocol_parameters(
            &proof_params,
            whir_params.num_variables,
        );
        let mut statement =
            whir_params.initial_statement(packed_pol.clone(), SumcheckStrategy::Classic);
        let packed_witness = committer
            .commit::<_, F, W, W, DIGEST_ELEMS>(
                &dft,
                &mut whir_proof,
                prover_state.challenger_mut(),
                &mut statement,
            )
            .unwrap();

        self.constraints_batching_pow(prover_state, settings)
            .unwrap();

        let constraints_batching_scalar = prover_state.sample();

        let constraints_batching_scalars =
            cyclic_subgroup_known_order(constraints_batching_scalar, self.n_constraints)
                .collect::<Vec<_>>();

        self.zerocheck_pow(prover_state, settings).unwrap();
        // Commit resolved skip count into the transcript/proof data so verifier does not
        // need to infer it from local settings.
        prover_state.add_extension_scalars(&[EF::from_usize(univariate_skips)]);

        let mut zerocheck_challenges = vec![EF::ZERO; log_length + 1 - univariate_skips];
        for challenge in &mut zerocheck_challenges {
            *challenge = prover_state.sample();
        }

        let preprocessed_and_witness = self
            .preprocessed_columns
            .iter()
            .chain(&witness)
            .collect::<Vec<_>>();
        let (outer_sumcheck_challenges, all_inner_sums, _) =
            info_span!("zerocheck").in_scope(|| {
                sumcheck::prove(
                    univariate_skips,
                    &columns_up_and_down(&preprocessed_and_witness),
                    &self.air,
                    self.constraint_degree,
                    &constraints_batching_scalars,
                    Some(&zerocheck_challenges),
                    true,
                    prover_state,
                    EF::ZERO,
                    None,
                    SumcheckGrinding::Auto {
                        security_bits: settings.security_bits,
                    },
                    None,
                    public_values,
                    &public_values_packed,
                )
            });

        let _span = span!(Level::INFO, "inner sumchecks").entered();

        let inner_sums_up = all_inner_sums[self.n_preprocessed_columns()..self.n_columns]
            .iter()
            .map(|s| {
                s.as_constant().unwrap_or_else(|| {
                    s.evaluate_hypercube_ext::<F>(&MultilinearPoint::new(vec![]))
                })
            })
            .collect::<Vec<_>>();
        let inner_sums_down = all_inner_sums[self.n_columns + self.n_preprocessed_columns()..]
            .iter()
            .map(|s| {
                s.as_constant().unwrap_or_else(|| {
                    s.evaluate_hypercube_ext::<F>(&MultilinearPoint::new(vec![]))
                })
            })
            .collect::<Vec<_>>();

        prover_state.add_extension_scalars(&inner_sums_up);
        prover_state.add_extension_scalars(&inner_sums_down);

        info_span!("pow grinding").in_scope(|| {
            self.secondary_sumchecks_batching_pow(prover_state, settings)
                .unwrap();
        });

        let mut columns_batching_scalars = vec![EF::ZERO; self.log_n_witness_columns()];
        for challenge in &mut columns_batching_scalars {
            *challenge = prover_state.sample();
        }

        let batched_column = multilinears_linear_combination(
            &witness,
            &EvaluationsList::new_from_point(&columns_batching_scalars, EF::ONE).as_slice()
                [..witness.len()],
        );

        let alpha = prover_state.sample();

        let batched_column_mixed = add_multilinears(
            &column_up(&batched_column),
            &scale_evals(&column_down(&batched_column), alpha),
        );

        // TODO opti
        let sub_evals = fold_suffix(&batched_column_mixed, &outer_sumcheck_challenges[1..]);

        prover_state.add_extension_scalars(sub_evals.as_slice());

        let mut epsilons = vec![EF::ZERO; univariate_skips];
        for challenge in &mut epsilons {
            *challenge = prover_state.sample();
        }

        let point = [epsilons.clone(), outer_sumcheck_challenges[1..].to_vec()].concat();
        let mles_for_inner_sumcheck = vec![
            add_multilinears(
                &matrix_up_folded(&point),
                &scale_evals(&matrix_down_folded(&point), alpha),
            ),
            batched_column,
        ];

        // TODO do not recompute
        let inner_sum = info_span!("inner sum evaluation").in_scope(|| {
            batched_column_mixed.evaluate_hypercube_ext::<F>(&MultilinearPoint::new(point.clone()))
        });

        let (inner_challenges, inner_evals, _) = sumcheck::prove(
            1,
            &mles_for_inner_sumcheck,
            &InnerSumcheckCircuit,
            2,
            &[EF::ONE],
            None,
            false,
            prover_state,
            inner_sum,
            None,
            SumcheckGrinding::Auto {
                security_bits: settings.security_bits,
            },
            None,
            &[],
            &[],
        );

        let final_point = [columns_batching_scalars.clone(), inner_challenges].concat();

        let packed_value = inner_evals[1].as_constant().unwrap_or_else(|| {
            inner_evals[1].evaluate_hypercube_ext::<F>(&MultilinearPoint::new(vec![]))
        });

        std::mem::drop(_span);

        let prover = Prover(&whir_params);
        let final_point = MultilinearPoint::new(final_point);
        let mut final_statement = EqStatement::initialize(final_point.num_variables());
        final_statement.add_evaluated_constraint(final_point, packed_value);
        final_statement.concatenate(&statement.normalize());

        let statement = InitialStatement::from_eq_statement(packed_pol, final_statement);

        prover
            .prove::<_, F, W, W, DIGEST_ELEMS>(
                &dft,
                &mut whir_proof,
                prover_state.challenger_mut(),
                &statement,
                packed_witness,
            )
            .unwrap();

        whir_proof
    }
}

pub struct InnerSumcheckCircuit;

impl<F: Field, EF: ExtensionField<F>> SumcheckComputation<F, EF, EF> for InnerSumcheckCircuit {
    fn eval(&self, point: &[EF], _: &[EF], _: &[EF]) -> EF {
        point[0] * point[1]
    }
}

impl<F: Field, EF: ExtensionField<F>> SumcheckComputationPacked<F, EF> for InnerSumcheckCircuit {
    fn eval_packed(
        &self,
        _: &[<F as Field>::Packing],
        _: &[EF],
        _: &[Vec<F>],
        _: &[<F as Field>::Packing],
    ) -> impl Iterator<Item = EF> + Send + Sync {
        // Unreachable
        std::iter::once(EF::ZERO)
    }
}
