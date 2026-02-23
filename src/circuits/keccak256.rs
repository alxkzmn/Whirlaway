use air::AirSettings;
use air::table::AirTable;
use keccak_air::{
    DIGEST_LIMBS, KeccakSpongeAir, NUM_ROUNDS, RATE_BYTES, digest_to_u16_limbs_le,
    generate_sponge_trace_and_digest_limbs,
};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_field::{ExtensionField, PrimeCharacteristicRing, TwoAdicField};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use serde::{Deserialize, Serialize};
use whir_p3::poly::evals::EvaluationsList;

use crate::hashers::{KECCAK_DIGEST_ELEMS, KeccakNodeCompress, KeccakU32BeLeafHasher};
use crate::proving_system::Circuit;

pub type F = KoalaBear;
pub type Binomial4Challenge = BinomialExtensionField<F, 4>;
pub type Binomial8Challenge = BinomialExtensionField<F, 8>;
pub type QuinticChallenge = QuinticTrinomialExtensionField<F>;
pub type EF = Binomial8Challenge;

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
    full_trace
}

fn make_table<E: ExtensionField<F> + TwoAdicField>(
    log_length: usize,
    settings: &AirSettings,
) -> AirTable<F, E, KeccakSpongeAir> {
    AirTable::<F, E, _>::new(
        KeccakSpongeAir::new(),
        log_length,
        settings.univariate_skips,
        Vec::new(),
        6,
        DIGEST_LIMBS,
    )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keccak256Circuit<E: ExtensionField<F> + TwoAdicField = EF> {
    pub input_size: usize,
    pub _marker: std::marker::PhantomData<E>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keccak256Input {
    pub message: Vec<u8>,
    pub expected_digest: [u8; 32],
}

impl<E: ExtensionField<F> + TwoAdicField> Keccak256Circuit<E> {
    pub fn new(input_size: usize) -> Self {
        Self {
            input_size,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn public_values(preprocessed: &Keccak256Preprocessed, input: &Keccak256Input) -> Vec<F> {
        <Self as Circuit<F, E, KECCAK_DIGEST_ELEMS>>::public_values(preprocessed, input)
    }
}

impl<E: ExtensionField<F> + TwoAdicField> Circuit<F, E, KECCAK_DIGEST_ELEMS>
    for Keccak256Circuit<E>
{
    type Air = KeccakSpongeAir;

    type W = u64;

    type Preprocessed = Keccak256Preprocessed;
    type Input = Keccak256Input;

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
    ) -> AirTable<F, E, Self::Air> {
        make_table(preprocessed.log_length, settings)
    }

    fn build_witness(
        preprocessed: &Self::Preprocessed,
        input: &Self::Input,
    ) -> Vec<EvaluationsList<F>> {
        debug_assert_eq!(input.message.len(), preprocessed.input_size);

        let trace = trace_from_message(&input.message);
        debug_assert_eq!(trace.height(), 1 << preprocessed.log_length);

        let witness_matrix = trace.transpose();
        witness_matrix
            .rows()
            .map(|col| EvaluationsList::new(col.collect()))
            .collect()
    }

    fn public_values(_preprocessed: &Self::Preprocessed, input: &Self::Input) -> Vec<F> {
        digest_to_u16_limbs_le(&input.expected_digest)
            .iter()
            .map(|&limb| F::from_u16(limb))
            .collect()
    }
}
