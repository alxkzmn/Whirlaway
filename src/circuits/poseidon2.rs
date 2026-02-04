use air::AirSettings;
use air::table::AirTable;
use p3_challenger::DuplexChallenger;
use p3_field::extension::BinomialExtensionField;
use p3_field::{ExtensionField, PrimeField64, TwoAdicField};
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear, Poseidon2KoalaBear};
use p3_matrix::Matrix;
use p3_poseidon2_air::{Poseidon2Air, RoundConstants, generate_trace_rows};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use whir_p3::poly::evals::EvaluationsList;

use crate::proving_system::Circuit;

// Koalabear
pub type Poseidon16 = Poseidon2KoalaBear<16>;
pub type Poseidon24 = Poseidon2KoalaBear<24>;

pub type MerkleHash = PaddingFreeSponge<Poseidon24, 24, 16, 8>; // leaf hashing
pub type MerkleCompress = TruncatedPermutation<Poseidon16, 2, 8, 16>; // 2-to-1 compression
pub type Challenger = DuplexChallenger<F, Poseidon16, 16, 8>;

// Koalabear
pub type F = KoalaBear;
pub type EF = BinomialExtensionField<F, 8>;
pub type LinearLayers = GenericPoseidon2LinearLayersKoalaBear;

pub const SBOX_DEGREE: u64 = 5;
pub const SBOX_REGISTERS: usize = 0;
pub const HALF_FULL_ROUNDS: usize = 4;
pub const PARTIAL_ROUNDS: usize = 20;

pub const WIDTH: usize = 16;

#[derive(Clone, Debug)]
pub struct Poseidon2Preprocessed {
    pub log_length: usize,
    pub constants: RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
}

#[derive(Clone, Debug)]
pub struct Poseidon2Params {
    pub log_length: usize,
    pub constants: RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
}

#[derive(Clone, Debug)]
pub struct Poseidon2Circuit;

impl Circuit<8> for Poseidon2Circuit {
    type F = F;
    type EF = EF;
    type Air = Poseidon2Air<
        F,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >;

    type W = F;

    type Params = Poseidon2Params;
    type Preprocessed = Poseidon2Preprocessed;
    type Input = Vec<[F; WIDTH]>;

    fn preprocess(params: &Self::Params, _settings: &AirSettings) -> Self::Preprocessed {
        Self::Preprocessed {
            log_length: params.log_length,
            constants: params.constants.clone(),
        }
    }

    fn make_table(
        preprocessed: &Self::Preprocessed,
        settings: &AirSettings,
    ) -> AirTable<Self::F, Self::EF, Self::Air> {
        AirTable::<F, EF, _>::new(
            Poseidon2Air::<
                F,
                LinearLayers,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >::new(preprocessed.constants.clone()),
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
        debug_assert_eq!(input.len(), 1 << preprocessed.log_length);

        let witness_matrix = generate_trace_rows::<
            F,
            LinearLayers,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >(input.clone(), &preprocessed.constants, 0)
        .transpose();

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
