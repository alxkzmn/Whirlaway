use air::AirSettings;
use air::table::AirTable;
use keccak_air::{
    ByteSpongeAir, DIGEST_LIMBS, KeccakSpongeAir, NUM_ROUNDS, RATE_BYTES, digest_to_u16_limbs_le,
    generate_byte_sponge_trace_and_digest_limbs, generate_sponge_trace_and_digest_limbs,
};
use p3_air::{Air, AirBuilderWithPublicValues, BaseAir, BaseAirWithPublicValues};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum KeccakMode {
    LegacyBitSponge,
    ByteSpongeAlgebraic,
}

impl Default for KeccakMode {
    fn default() -> Self {
        Self::LegacyBitSponge
    }
}

#[derive(Clone, Debug)]
pub enum KeccakAirVariant {
    LegacyBitSponge(KeccakSpongeAir),
    ByteSpongeAlgebraic(ByteSpongeAir),
}

impl<FF> BaseAir<FF> for KeccakAirVariant {
    fn width(&self) -> usize {
        match self {
            Self::LegacyBitSponge(inner) => BaseAir::<FF>::width(inner),
            Self::ByteSpongeAlgebraic(inner) => BaseAir::<FF>::width(inner),
        }
    }
}

impl<FF> BaseAirWithPublicValues<FF> for KeccakAirVariant {
    fn num_public_values(&self) -> usize {
        match self {
            Self::LegacyBitSponge(inner) => BaseAirWithPublicValues::<FF>::num_public_values(inner),
            Self::ByteSpongeAlgebraic(inner) => {
                BaseAirWithPublicValues::<FF>::num_public_values(inner)
            }
        }
    }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for KeccakAirVariant {
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::LegacyBitSponge(inner) => inner.eval(builder),
            Self::ByteSpongeAlgebraic(inner) => inner.eval(builder),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keccak256Preprocessed {
    pub input_size: usize,
    pub log_length: usize,
    pub mode: KeccakMode,
}

fn padded_len_legacy(message_len: usize) -> usize {
    let mut len = message_len + 1; // domain suffix 0x01
    while (len % RATE_BYTES) != (RATE_BYTES - 1) {
        len += 1;
    }
    len + 1 // final 0x80
}

fn padded_len_byte(message_len: usize) -> usize {
    let mut len = message_len + 1; // domain suffix 0x01
    if len.is_multiple_of(RATE_BYTES) {
        return len;
    }
    while (len % RATE_BYTES) != (RATE_BYTES - 1) {
        len += 1;
    }
    len + 1 // final 0x80
}

fn log_length_for_message_len(message_len: usize, mode: KeccakMode) -> usize {
    let padded = match mode {
        KeccakMode::LegacyBitSponge => padded_len_legacy(message_len),
        KeccakMode::ByteSpongeAlgebraic => padded_len_byte(message_len),
    };
    let num_blocks = padded / RATE_BYTES;
    let rows = num_blocks * NUM_ROUNDS;
    rows.next_power_of_two().ilog2() as usize
}

fn trace_from_message(message: &[u8], mode: KeccakMode) -> RowMajorMatrix<F> {
    match mode {
        KeccakMode::LegacyBitSponge => {
            let (full_trace, _digest_limbs) = generate_sponge_trace_and_digest_limbs::<F>(message);
            full_trace
        }
        KeccakMode::ByteSpongeAlgebraic => {
            let (full_trace, _digest_limbs) =
                generate_byte_sponge_trace_and_digest_limbs::<F>(message);
            full_trace
        }
    }
}

fn make_table<E: ExtensionField<F> + TwoAdicField>(
    log_length: usize,
    mode: KeccakMode,
    settings: &AirSettings,
) -> AirTable<F, E, KeccakAirVariant> {
    let (air, constraint_degree) = match mode {
        KeccakMode::LegacyBitSponge => {
            (KeccakAirVariant::LegacyBitSponge(KeccakSpongeAir::new()), 6)
        }
        KeccakMode::ByteSpongeAlgebraic => (
            KeccakAirVariant::ByteSpongeAlgebraic(ByteSpongeAir::new()),
            11,
        ),
    };

    AirTable::<F, E, _>::new(
        air,
        log_length,
        settings.univariate_skips,
        Vec::new(),
        constraint_degree,
        DIGEST_LIMBS,
    )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keccak256Circuit<E: ExtensionField<F> + TwoAdicField = EF> {
    pub input_size: usize,
    pub mode: KeccakMode,
    pub _marker: std::marker::PhantomData<E>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keccak256Input {
    pub message: Vec<u8>,
    pub expected_digest: [u8; 32],
}

impl<E: ExtensionField<F> + TwoAdicField> Keccak256Circuit<E> {
    pub fn new(input_size: usize) -> Self {
        Self::new_with_mode(input_size, KeccakMode::LegacyBitSponge)
    }

    pub fn new_with_mode(input_size: usize, mode: KeccakMode) -> Self {
        Self {
            input_size,
            mode,
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
    type Air = KeccakAirVariant;

    type W = u64;

    type Preprocessed = Keccak256Preprocessed;
    type Input = Keccak256Input;

    fn preprocess(&self, _settings: &AirSettings) -> Self::Preprocessed {
        let log_length = log_length_for_message_len(self.input_size, self.mode);
        Self::Preprocessed {
            input_size: self.input_size,
            log_length,
            mode: self.mode,
        }
    }

    fn make_table(
        preprocessed: &Self::Preprocessed,
        settings: &AirSettings,
    ) -> AirTable<F, E, Self::Air> {
        make_table(preprocessed.log_length, preprocessed.mode, settings)
    }

    fn build_witness(
        preprocessed: &Self::Preprocessed,
        input: &Self::Input,
    ) -> Vec<EvaluationsList<F>> {
        debug_assert_eq!(input.message.len(), preprocessed.input_size);

        let trace = trace_from_message(&input.message, preprocessed.mode);
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
