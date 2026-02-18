#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod prove;
pub mod table;
pub mod uni_skip_utils;
pub mod utils;
pub mod verify;

// This crate is used in tests even though it appears unused
use p3_poseidon2 as _;

const WHIR_POW_BITS: usize = 16;

use serde::{Deserialize, Serialize};
use whir_p3::parameters::{FoldingFactor, errors::SecurityAssumption};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UnivariateSkipMode {
    /// Use a fixed skip count.
    Manual { skip: usize },
    /// Resolve skip count automatically within the provided caps.
    Auto {
        max_skip: usize,
        max_first_round_coeffs: usize,
    },
}

impl UnivariateSkipMode {
    pub const fn manual(skip: usize) -> Self {
        Self::Manual { skip }
    }

    pub const fn auto(max_skip: usize, max_first_round_coeffs: usize) -> Self {
        Self::Auto {
            max_skip,
            max_first_round_coeffs,
        }
    }
}

impl Default for UnivariateSkipMode {
    fn default() -> Self {
        // Conservative defaults: try to skip up to 6 rounds while keeping first-round
        // polynomial size bounded.
        Self::Auto {
            max_skip: 6,
            max_first_round_coeffs: 4096,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AirSettings {
    pub security_bits: usize,
    pub whir_soudness_type: SecurityAssumption,
    pub whir_folding_factor: FoldingFactor,
    pub whir_log_inv_rate: usize,
    pub univariate_skip_mode: UnivariateSkipMode,
    pub whir_initial_domain_reduction_factor: usize,
}

impl AirSettings {
    /// Backward-compatible constructor for a fixed skip setting.
    pub const fn new(
        security_bits: usize,
        whir_soudness_type: SecurityAssumption,
        whir_folding_factor: FoldingFactor,
        whir_log_inv_rate: usize,
        univariate_skips: usize,
        whir_initial_domain_reduction_factor: usize,
    ) -> Self {
        Self::new_with_skip_mode(
            security_bits,
            whir_soudness_type,
            whir_folding_factor,
            whir_log_inv_rate,
            UnivariateSkipMode::manual(univariate_skips),
            whir_initial_domain_reduction_factor,
        )
    }

    pub const fn new_with_skip_mode(
        security_bits: usize,
        whir_soudness_type: SecurityAssumption,
        whir_folding_factor: FoldingFactor,
        whir_log_inv_rate: usize,
        univariate_skip_mode: UnivariateSkipMode,
        whir_initial_domain_reduction_factor: usize,
    ) -> Self {
        Self {
            security_bits,
            whir_soudness_type,
            whir_folding_factor,
            whir_log_inv_rate,
            univariate_skip_mode,
            whir_initial_domain_reduction_factor,
        }
    }

    pub const fn with_manual_univariate_skips(mut self, univariate_skips: usize) -> Self {
        self.univariate_skip_mode = UnivariateSkipMode::manual(univariate_skips);
        self
    }
}

impl Default for AirSettings {
    fn default() -> Self {
        Self {
            security_bits: 128,
            whir_soudness_type: SecurityAssumption::CapacityBound,
            whir_folding_factor: FoldingFactor::ConstantFromSecondRound(7, 4),
            whir_log_inv_rate: 1,
            univariate_skip_mode: UnivariateSkipMode::default(),
            whir_initial_domain_reduction_factor: 5,
        }
    }
}
