use air::AirSettings;
use air::table::AirTable;
use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_field::{ExtensionField, Packable, PrimeField64, TwoAdicField};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use serde::{Deserialize, Serialize};
use utils::{ProverState, VerifierState};
use whir_p3::fiat_shamir::domain_separator::DomainSeparator;
use whir_p3::poly::evals::EvaluationsList;
use whir_p3::whir::proof::WhirProof;

pub trait Circuit<const DIGEST_ELEMS: usize> {
    type F: TwoAdicField + PrimeField64 + Ord + Eq + Packable + Default;
    type EF: ExtensionField<Self::F> + TwoAdicField + Default;

    type Air: for<'a> Air<utils::ConstraintFolder<'a, Self::F, Self::F, Self::EF>>
        + for<'a> Air<utils::ConstraintFolder<'a, Self::F, Self::EF, Self::EF>>
        + for<'a> Air<utils::ConstraintFolderPacked<'a, Self::F, Self::EF>>;

    type W: p3_field::PackedValue<Value = Self::W> + Eq + Send + Sync + Default;

    type MerkleHash: CryptographicHasher<Self::F, [Self::W; DIGEST_ELEMS]> + Sync + Clone + Default;
    type MerkleCompress: PseudoCompressionFunction<[Self::W; DIGEST_ELEMS], 2>
        + Sync
        + Clone
        + Default;

    type Challenger: FieldChallenger<Self::F>
        + GrindingChallenger<Witness = Self::F>
        + CanObserve<p3_symmetric::Hash<Self::F, Self::W, DIGEST_ELEMS>>
        + Clone;

    type Params: Clone + Serialize + for<'de> Deserialize<'de> + core::fmt::Debug;
    type Preprocessed: Clone + Serialize + for<'de> Deserialize<'de> + core::fmt::Debug;
    type Input;

    fn preprocess(params: &Self::Params, settings: &AirSettings) -> Self::Preprocessed;

    fn make_table(
        preprocessed: &Self::Preprocessed,
        settings: &AirSettings,
    ) -> AirTable<Self::F, Self::EF, Self::Air>;

    fn build_witness(
        preprocessed: &Self::Preprocessed,
        input: &Self::Input,
    ) -> Vec<EvaluationsList<Self::F>>;

    fn new_challenger() -> Self::Challenger;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Prepared<C, const DIGEST_ELEMS: usize>
where
    C: Circuit<DIGEST_ELEMS>,
{
    pub settings: AirSettings,
    pub circuit: C::Preprocessed,
    pub domain_separator: DomainSeparator<C::EF, C::F>,
}

#[derive(Clone, Debug)]
pub struct Proof<C, const DIGEST_ELEMS: usize>
where
    C: Circuit<DIGEST_ELEMS>,
{
    pub whir_proof: WhirProof<C::F, C::EF, C::W, DIGEST_ELEMS>,
    pub proof_data: Vec<C::EF>,
}

pub fn prepare<C, const DIGEST_ELEMS: usize>(
    params: C::Params,
    settings: AirSettings,
) -> Prepared<C, DIGEST_ELEMS>
where
    C: Circuit<DIGEST_ELEMS>,
    C::F: serde::Serialize + for<'de> serde::Deserialize<'de>,
    C::EF: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let circuit = C::preprocess(&params, &settings);
    let table = C::make_table(&circuit, &settings);

    let whir_params = table.build_whir_params::<C::MerkleHash, C::MerkleCompress, C::Challenger>(
        &settings,
        C::MerkleHash::default(),
        C::MerkleCompress::default(),
    );

    let mut domain_separator = DomainSeparator::<C::EF, C::F>::new(Vec::new());
    domain_separator
        .commit_statement::<C::MerkleHash, C::MerkleCompress, C::Challenger, DIGEST_ELEMS>(
            &whir_params,
        );
    domain_separator
        .add_whir_proof::<C::MerkleHash, C::MerkleCompress, C::Challenger, DIGEST_ELEMS>(
            &whir_params,
        );

    Prepared {
        settings,
        circuit,
        domain_separator,
    }
}

pub fn prove<C, const DIGEST_ELEMS: usize>(
    prepared: &Prepared<C, DIGEST_ELEMS>,
    input: &C::Input,
) -> Proof<C, DIGEST_ELEMS>
where
    C: Circuit<DIGEST_ELEMS>,
    C::F: Eq,
    C::EF: Default,
    C::W: p3_field::PackedValue<Value = C::W> + Eq + Send + Sync + Default,
    [C::W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    <C::F as p3_field::Field>::Packing: Eq + Send + Sync,
{
    let witness = C::build_witness(&prepared.circuit, input);
    let table = C::make_table(&prepared.circuit, &prepared.settings);

    let challenger = C::new_challenger();
    let mut prover_state = ProverState::new(&prepared.domain_separator, challenger.clone());

    let whir_proof = table
        .prove::<C::MerkleHash, C::MerkleCompress, C::Challenger, C::W, DIGEST_ELEMS>(
            &prepared.settings,
            C::MerkleHash::default(),
            C::MerkleCompress::default(),
            &mut prover_state,
            witness,
        );

    Proof {
        whir_proof,
        proof_data: prover_state.proof_data().to_vec(),
    }
}

pub fn verify<C, const DIGEST_ELEMS: usize>(
    prepared: &Prepared<C, DIGEST_ELEMS>,
    proof: &Proof<C, DIGEST_ELEMS>,
) -> Result<(), String>
where
    C: Circuit<DIGEST_ELEMS>,
    C::F: Eq,
    C::W: p3_field::PackedValue<Value = C::W> + Eq + Send + Sync + Copy,
    [C::W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    <C::F as p3_field::Field>::Packing: Eq + Send + Sync,
{
    let table = C::make_table(&prepared.circuit, &prepared.settings);

    let challenger = C::new_challenger();
    let mut verifier_state = VerifierState::new(
        &prepared.domain_separator,
        proof.proof_data.clone(),
        challenger,
    );

    table
        .verify::<C::MerkleHash, C::MerkleCompress, C::Challenger, C::W, DIGEST_ELEMS>(
            &prepared.settings,
            C::MerkleHash::default(),
            C::MerkleCompress::default(),
            &mut verifier_state,
            table.log_length,
            &proof.whir_proof,
        )
        .map_err(|e| format!("verify failed: {e:?}"))
}

pub fn preprocessing_size<C, const DIGEST_ELEMS: usize>(
    prepared: &Prepared<C, DIGEST_ELEMS>,
) -> usize
where
    C: Circuit<DIGEST_ELEMS>,
{
    bincode::serialize(prepared).map(|v| v.len()).unwrap_or(0)
}

pub fn proof_size<C, const DIGEST_ELEMS: usize>(proof: &Proof<C, DIGEST_ELEMS>) -> usize
where
    C: Circuit<DIGEST_ELEMS>,
    C::F: PrimeField64,
    C::F: serde::Serialize,
    C::EF: serde::Serialize,
    C::W: serde::Serialize,
    [C::W; DIGEST_ELEMS]: serde::Serialize,
{
    let proof_data_bytes =
        (proof.proof_data.len() as f64 * (C::F::ORDER_U64 as f64).log2() / 8.0).ceil() as usize;
    let whir_bytes = bincode::serialize(&proof.whir_proof)
        .map(|v| v.len())
        .unwrap_or(0);
    proof_data_bytes + whir_bytes
}

pub fn num_constraints<C, const DIGEST_ELEMS: usize>(prepared: &Prepared<C, DIGEST_ELEMS>) -> usize
where
    C: Circuit<DIGEST_ELEMS>,
{
    let table = C::make_table(&prepared.circuit, &prepared.settings);
    table.n_constraints
}
