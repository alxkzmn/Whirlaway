use air::AirSettings;
use air::table::AirTable;
use keccak_air::{
    KeccakAir, NUM_KECCAK_COLS, NUM_ROUNDS, RATE_BYTES, generate_sponge_trace_and_digest_limbs,
};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_field::extension::BinomialExtensionField;
use p3_field::{ExtensionField, PrimeField64, TwoAdicField};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use serde::{Deserialize, Serialize};
use whir_p3::parameters::{FoldingFactor, errors::SecurityAssumption};
use whir_p3::poly::evals::EvaluationsList;

use crate::hashers::{KECCAK_DIGEST_ELEMS, KeccakNodeCompress, KeccakU32BeLeafHasher};
use crate::proving_system::Circuit;

pub type F = KoalaBear;
pub type EF = BinomialExtensionField<F, 8>;

pub type MerkleHash = KeccakU32BeLeafHasher;
pub type MerkleCompress = KeccakNodeCompress;

pub type Challenger = SerializingChallenger32<F, HashChallenger<u8, Keccak256Hash, 32>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keccak256Preprocessed {
    pub input_size: usize,
    pub log_length: usize,
}

fn padded_len(message_len: usize) -> usize {
    let mut len = message_len + 1; // domain suffix 0x01
    while (len % RATE_BYTES) != (RATE_BYTES - 1) {
        len += 1;
    }
    len + 1 // final 0x80
}

fn log_length_for_message_len(message_len: usize) -> usize {
    let padded = padded_len(message_len);
    let num_blocks = padded / RATE_BYTES;
    let rows = num_blocks * NUM_ROUNDS;
    rows.next_power_of_two().ilog2() as usize
}

fn trace_from_message(message: &[u8]) -> RowMajorMatrix<F> {
    let (full_trace, _digest_limbs) = generate_sponge_trace_and_digest_limbs::<F>(message);
    let height = full_trace.height();
    let mut values = Vec::with_capacity(height * NUM_KECCAK_COLS);
    for row in 0..height {
        let row_slice = full_trace.row_slice(row).expect("trace row missing");
        values.extend_from_slice(&row_slice[..NUM_KECCAK_COLS]);
    }
    RowMajorMatrix::new(values, NUM_KECCAK_COLS)
}

fn make_table(log_length: usize, settings: &AirSettings) -> AirTable<F, EF, KeccakAir> {
    AirTable::<F, EF, _>::new(
        KeccakAir {},
        log_length,
        settings.univariate_skips,
        Vec::new(),
        3,
    )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keccak256Circuit {
    pub input_size: usize,
}

impl Circuit<KECCAK_DIGEST_ELEMS> for Keccak256Circuit {
    type F = F;
    type EF = EF;
    type Air = KeccakAir;

    type W = u64;

    type Preprocessed = Keccak256Preprocessed;
    type Input = Vec<u8>; // message bytes

    fn preprocess(&self, _settings: &AirSettings) -> Self::Preprocessed {
        let log_length = log_length_for_message_len(self.input_size);
        Self::Preprocessed {
            input_size: self.input_size,
            log_length,
        }
    }

    fn make_table(
        preprocessed: &Self::Preprocessed,
        settings: &AirSettings,
    ) -> AirTable<Self::F, Self::EF, Self::Air> {
        make_table(preprocessed.log_length, settings)
    }

    fn build_witness(
        preprocessed: &Self::Preprocessed,
        input: &Self::Input,
    ) -> Vec<EvaluationsList<Self::F>> {
        debug_assert_eq!(input.len(), preprocessed.input_size);

        let trace = trace_from_message(input);
        debug_assert_eq!(trace.height(), 1 << preprocessed.log_length);

        let witness_matrix = trace.transpose();
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
