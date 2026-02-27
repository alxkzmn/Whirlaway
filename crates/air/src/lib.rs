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
pub struct AirSettings {
    pub security_bits: usize,
    #[serde(default)]
    pub merkle_security_bits_override: Option<usize>,
    #[serde(default)]
    pub whir_pow_bits: Option<usize>,
    pub whir_soudness_type: SecurityAssumption,
    pub whir_folding_factor: FoldingFactor,
    pub whir_log_inv_rate: usize,
    pub univariate_skips: usize,
    pub whir_initial_domain_reduction_factor: usize,
}

impl AirSettings {
    pub const fn new(
        security_bits: usize,
        whir_soudness_type: SecurityAssumption,
        whir_folding_factor: FoldingFactor,
        whir_log_inv_rate: usize,
        univariate_skips: usize,
        whir_initial_domain_reduction_factor: usize,
    ) -> Self {
        Self {
            security_bits,
            merkle_security_bits_override: None,
            whir_pow_bits: None,
            whir_soudness_type,
            whir_folding_factor,
            whir_log_inv_rate,
            univariate_skips,
            whir_initial_domain_reduction_factor,
        }
    }

    pub const fn with_merkle_security_bits_override(
        mut self,
        override_bits: Option<usize>,
    ) -> Self {
        self.merkle_security_bits_override = override_bits;
        self
    }

    pub const fn with_whir_pow_bits(mut self, pow_bits: Option<usize>) -> Self {
        self.whir_pow_bits = pow_bits;
        self
    }

    pub fn effective_whir_pow_bits(&self) -> usize {
        self.whir_pow_bits.unwrap_or(WHIR_POW_BITS)
    }
}

impl Default for AirSettings {
    fn default() -> Self {
        Self {
            security_bits: 128,
            merkle_security_bits_override: None,
            whir_pow_bits: None,
            whir_soudness_type: SecurityAssumption::CapacityBound,
            whir_folding_factor: FoldingFactor::ConstantFromSecondRound(7, 4),
            whir_log_inv_rate: 1,
            univariate_skips: 4,
            whir_initial_domain_reduction_factor: 5,
        }
    }
}
