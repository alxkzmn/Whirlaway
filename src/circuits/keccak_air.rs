use air::AirSettings;
use air::table::AirTable;
use keccak_air::{KeccakAir, NUM_ROUNDS, generate_trace_rows};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_field::extension::BinomialExtensionField;
use p3_field::{ExtensionField, PrimeField64, TwoAdicField};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;
use serde::{Deserialize, Serialize};
use whir_p3::poly::evals::EvaluationsList;

use crate::hashers::{KECCAK_DIGEST_ELEMS, KeccakNodeCompress, KeccakU32BeLeafHasher};
use crate::proving_system::Circuit;

pub type F = KoalaBear;
pub type EF = BinomialExtensionField<F, 8>;

pub type MerkleHash = KeccakU32BeLeafHasher;
pub type MerkleCompress = KeccakNodeCompress;

pub type Challenger = SerializingChallenger32<F, HashChallenger<u8, Keccak256Hash, 32>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeccakAirPreprocessed {
    pub n_inputs: usize,
    pub log_length: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeccakAirCircuit;

impl Circuit<KECCAK_DIGEST_ELEMS> for KeccakAirCircuit {
    type F = F;
    type EF = EF;
    type Air = KeccakAir;

    type W = u64;

    type Params = usize; // number of inputs
    type Preprocessed = KeccakAirPreprocessed;
    type Input = Vec<[u64; 25]>;

    fn preprocess(params: &Self::Params, _settings: &AirSettings) -> Self::Preprocessed {
        let n_inputs = *params;
        let rows = n_inputs.saturating_mul(NUM_ROUNDS);
        let log_length = rows.next_power_of_two().ilog2() as usize;
        Self::Preprocessed { n_inputs, log_length }
    }

    fn make_table(
        preprocessed: &Self::Preprocessed,
        settings: &AirSettings,
    ) -> AirTable<Self::F, Self::EF, Self::Air> {
        AirTable::<F, EF, _>::new(
            KeccakAir {},
            preprocessed.log_length,
            settings.univariate_skips,
            Vec::new(),
            3,
        )
    }

    fn build_witness(
        preprocessed: &Self::Preprocessed,
        input: &Self::Input,
    ) -> Vec<EvaluationsList<Self::F>> {
        debug_assert_eq!(input.len(), preprocessed.n_inputs);

        let witness_matrix = generate_trace_rows::<F>(input.clone(), 0).transpose();
        witness_matrix
            .rows()
            .map(|col| EvaluationsList::new(col.collect()))
            .collect()
    }
}

// Extra trait bounds we rely on elsewhere.
const _: () = {
    fn _assert_bounds()
    where
        F: TwoAdicField + PrimeField64,
        EF: ExtensionField<F> + TwoAdicField,
    {
    }
};
