use p3_air::Air;
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_field::{ExtensionField, Field, PackedValue, TwoAdicField};

use p3_uni_stark::{SymbolicAirBuilder, get_symbolic_constraints};
use utils::{DensePolynomial, log2_up, univariate_selectors};
use whir_p3::{
    parameters::ProtocolParameters, poly::evals::EvaluationsList, whir::parameters::WhirConfig,
};

use crate::{AirSettings, UnivariateSkipMode, WHIR_POW_BITS};

pub struct AirTable<F: Field, EF, A> {
    pub log_length: usize,
    pub n_columns: usize,
    pub num_public_values: usize,
    pub air: A,
    pub preprocessed_columns: Vec<EvaluationsList<F>>, // TODO 'sparse' preprocessed columns (with non zero values at cylic shifts)
    pub n_constraints: usize,
    pub constraint_degree: usize,

    _phantom: std::marker::PhantomData<EF>,
}

impl<F, EF, A> AirTable<F, EF, A>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
{
    pub fn new(
        air: A,
        log_length: usize,
        preprocessed_columns: Vec<EvaluationsList<F>>,
        constraint_degree: usize,
        num_public_values: usize,
    ) -> Self
    where
        A: Air<SymbolicAirBuilder<F>>,
    {
        let symbolic_constraints = get_symbolic_constraints(&air, 0, num_public_values);
        let n_constraints = symbolic_constraints.len();

        Self {
            log_length,
            n_columns: air.width(),
            num_public_values,
            air,
            preprocessed_columns,
            n_constraints,
            constraint_degree,
            _phantom: std::marker::PhantomData,
        }
    }

    #[allow(clippy::missing_const_for_fn)]
    pub fn n_witness_columns(&self) -> usize {
        self.n_columns - self.preprocessed_columns.len()
    }

    /// rounded up
    pub fn log_n_witness_columns(&self) -> usize {
        log2_up(self.n_witness_columns())
    }

    #[allow(clippy::missing_const_for_fn)]
    pub fn n_preprocessed_columns(&self) -> usize {
        self.preprocessed_columns.len()
    }

    pub fn resolve_univariate_skips(&self, settings: &AirSettings) -> usize {
        let max_supported = self.max_supported_univariate_skips();
        match settings.univariate_skip_mode {
            UnivariateSkipMode::Manual { skip } => {
                assert!(
                    skip > 0 && skip <= max_supported,
                    "invalid manual univariate skip: skip={skip}, max_supported={max_supported}"
                );
                skip
            }
            UnivariateSkipMode::Auto {
                max_skip,
                max_first_round_coeffs,
            } => {
                if max_supported == 0 {
                    return 0;
                }
                let max_try = max_supported.min(max_skip.max(1));
                for skips in (1..=max_try).rev() {
                    if self.first_round_coeff_count(skips) <= max_first_round_coeffs {
                        return skips;
                    }
                }
                1
            }
        }
    }

    pub fn validate_resolved_univariate_skips(
        &self,
        settings: &AirSettings,
        resolved_skips: usize,
    ) -> bool {
        let max_supported = self.max_supported_univariate_skips();
        if resolved_skips == 0 || resolved_skips > max_supported {
            return false;
        }
        match settings.univariate_skip_mode {
            UnivariateSkipMode::Manual { skip } => resolved_skips == skip,
            UnivariateSkipMode::Auto {
                max_skip,
                max_first_round_coeffs,
            } => {
                resolved_skips <= max_skip.max(1)
                    && self.first_round_coeff_count(resolved_skips) <= max_first_round_coeffs
            }
        }
    }

    pub fn selector_polynomials(&self, univariate_skips: usize) -> Vec<DensePolynomial<F>> {
        univariate_selectors(univariate_skips)
    }

    fn max_supported_univariate_skips(&self) -> usize {
        if self.log_length == 0 {
            return 0;
        }
        // A skip value `k` collapses the first `k` Boolean variables into a size-`2^k`
        // univariate domain for the first sumcheck round. `k` must satisfy all of:
        // - table size: we cannot skip more variables than exist (`k <= log_length`);
        // - field structure: the protocol needs a 2^k-sized multiplicative subgroup in `F`,
        //   so `k` cannot exceed `F::TWO_ADICITY`;
        // - packed evaluation layout: we keep at least `log2(Packing::WIDTH)` suffix
        //   variables after skipping so packed chunks remain well-formed.
        // The effective limit is the most restrictive of these bounds.
        let max_by_log = self.log_length;
        let max_by_field = F::TWO_ADICITY;
        let pack_bits = log2_up(F::Packing::WIDTH);
        let max_by_pack = self.log_length.saturating_sub(pack_bits).max(1);
        max_by_log.min(max_by_field).min(max_by_pack)
    }

    fn first_round_coeff_count(&self, skips: usize) -> usize {
        let domain_size = 1usize.checked_shl(skips as u32).unwrap_or(usize::MAX);
        (self.constraint_degree + 1)
            .saturating_mul(domain_size.saturating_sub(1))
            .saturating_add(1)
    }

    pub fn build_whir_params<H, C, Challenger>(
        &self,
        settings: &AirSettings,
        merkle_hash: H,
        merkle_compress: C,
    ) -> WhirConfig<EF, F, H, C, Challenger>
    where
        Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let num_variables = self.log_length + self.log_n_witness_columns();
        let whir_params = ProtocolParameters {
            security_level: settings.security_bits,
            pow_bits: WHIR_POW_BITS,
            folding_factor: settings.whir_folding_factor,
            merkle_hash,
            merkle_compress,
            soundness_type: settings.whir_soudness_type,
            starting_log_inv_rate: settings.whir_log_inv_rate,
            rs_domain_initial_reduction_factor: settings.whir_initial_domain_reduction_factor,
        };

        WhirConfig::new(num_variables, whir_params)
    }
}
