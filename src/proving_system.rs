use air::AirSettings;
use air::table::AirTable;
use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_field::{ExtensionField, Packable, PrimeField64, TwoAdicField};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use utils::{ProverState, VerifierState};
use whir_p3::fiat_shamir::domain_separator::DomainSeparator;
use whir_p3::poly::evals::EvaluationsList;
use whir_p3::whir::proof::WhirProof;

pub trait ProvingSystemSettings<C, const DIGEST_ELEMS: usize>
where
    C: Circuit<DIGEST_ELEMS>,
{
    type MerkleHash: CryptographicHasher<C::F, [C::W; DIGEST_ELEMS]> + Sync + Clone;
    type MerkleCompress: PseudoCompressionFunction<[C::W; DIGEST_ELEMS], 2> + Sync + Clone;

    type Challenger: FieldChallenger<C::F>
        + GrindingChallenger<Witness = C::F>
        + CanObserve<p3_symmetric::Hash<C::F, C::W, DIGEST_ELEMS>>
        + Clone;

    fn air_settings(&self) -> &AirSettings;
    fn merkle_hash(&self) -> Self::MerkleHash;
    fn merkle_compress(&self) -> Self::MerkleCompress;
    fn new_challenger(&self) -> Self::Challenger;
}

#[derive(Clone, Debug)]
pub struct ProvingSystemConfig<MH, MC, CH> {
    pub air_settings: AirSettings,
    pub merkle_hash: MH,
    pub merkle_compress: MC,
    pub challenger: CH,
}

impl<MH, MC, CH> ProvingSystemConfig<MH, MC, CH> {
    pub fn new(
        air_settings: AirSettings,
        merkle_hash: MH,
        merkle_compress: MC,
        challenger: CH,
    ) -> Self {
        Self {
            air_settings,
            merkle_hash,
            merkle_compress,
            challenger,
        }
    }
}

impl<C, MH, MC, CH, const DIGEST_ELEMS: usize> ProvingSystemSettings<C, DIGEST_ELEMS>
    for ProvingSystemConfig<MH, MC, CH>
where
    C: Circuit<DIGEST_ELEMS>,
    MH: CryptographicHasher<C::F, [C::W; DIGEST_ELEMS]> + Sync + Clone,
    MC: PseudoCompressionFunction<[C::W; DIGEST_ELEMS], 2> + Sync + Clone,
    CH: FieldChallenger<C::F>
        + GrindingChallenger<Witness = C::F>
        + CanObserve<p3_symmetric::Hash<C::F, C::W, DIGEST_ELEMS>>
        + Clone,
{
    type MerkleHash = MH;
    type MerkleCompress = MC;
    type Challenger = CH;

    fn air_settings(&self) -> &AirSettings {
        &self.air_settings
    }

    fn merkle_hash(&self) -> Self::MerkleHash {
        self.merkle_hash.clone()
    }

    fn merkle_compress(&self) -> Self::MerkleCompress {
        self.merkle_compress.clone()
    }

    fn new_challenger(&self) -> Self::Challenger {
        self.challenger.clone()
    }
}

pub trait Circuit<const DIGEST_ELEMS: usize> {
    type F: TwoAdicField + PrimeField64 + Ord + Eq + Packable + Default;
    type EF: ExtensionField<Self::F> + TwoAdicField + Default;

    type Air: for<'a> Air<utils::ConstraintFolder<'a, Self::F, Self::F, Self::EF>>
        + for<'a> Air<utils::ConstraintFolder<'a, Self::F, Self::EF, Self::EF>>
        + for<'a> Air<utils::ConstraintFolderPacked<'a, Self::F, Self::EF>>;

    type W: p3_field::PackedValue<Value = Self::W> + Eq + Send + Sync + Default;

    type Preprocessed: Clone + core::fmt::Debug;
    type Input;

    fn preprocess(&self, settings: &AirSettings) -> Self::Preprocessed;

    fn make_table(
        preprocessed: &Self::Preprocessed,
        settings: &AirSettings,
    ) -> AirTable<Self::F, Self::EF, Self::Air>;

    fn build_witness(
        preprocessed: &Self::Preprocessed,
        input: &Self::Input,
    ) -> Vec<EvaluationsList<Self::F>>;
}

#[derive(Clone, Debug)]
pub struct Prepared<C, S, const DIGEST_ELEMS: usize>
where
    C: Circuit<DIGEST_ELEMS>,
    S: ProvingSystemSettings<C, DIGEST_ELEMS>,
{
    pub settings: S,
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

pub fn prepare<C, S, const DIGEST_ELEMS: usize>(
    settings: &S,
    circuit: C,
) -> Prepared<C, S, DIGEST_ELEMS>
where
    C: Circuit<DIGEST_ELEMS>,
    S: ProvingSystemSettings<C, DIGEST_ELEMS> + Clone,
    C::F: serde::Serialize + for<'de> serde::Deserialize<'de>,
    C::EF: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let preprocessed_circuit = circuit.preprocess(settings.air_settings());
    let table = C::make_table(&preprocessed_circuit, settings.air_settings());

    let whir_params = table.build_whir_params::<S::MerkleHash, S::MerkleCompress, S::Challenger>(
        settings.air_settings(),
        settings.merkle_hash(),
        settings.merkle_compress(),
    );

    let mut domain_separator = DomainSeparator::<C::EF, C::F>::new(Vec::new());
    domain_separator
        .commit_statement::<S::MerkleHash, S::MerkleCompress, S::Challenger, DIGEST_ELEMS>(
            &whir_params,
        );
    domain_separator
        .add_whir_proof::<S::MerkleHash, S::MerkleCompress, S::Challenger, DIGEST_ELEMS>(
            &whir_params,
        );

    Prepared {
        settings: settings.clone(),
        circuit: preprocessed_circuit,
        domain_separator,
    }
}

pub fn prove<C, S, const DIGEST_ELEMS: usize>(
    prepared: &Prepared<C, S, DIGEST_ELEMS>,
    input: &C::Input,
) -> Proof<C, DIGEST_ELEMS>
where
    C: Circuit<DIGEST_ELEMS>,
    S: ProvingSystemSettings<C, DIGEST_ELEMS>,
    C::F: Eq,
    C::EF: Default,
    C::W: p3_field::PackedValue<Value = C::W> + Eq + Send + Sync + Default,
    [C::W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    <C::F as p3_field::Field>::Packing: Eq + Send + Sync,
{
    let witness = C::build_witness(&prepared.circuit, input);
    let table = C::make_table(&prepared.circuit, prepared.settings.air_settings());

    let challenger = &prepared.settings.new_challenger();
    let mut prover_state = ProverState::new(&prepared.domain_separator, challenger.clone());

    let whir_proof = table
        .prove::<S::MerkleHash, S::MerkleCompress, S::Challenger, C::W, DIGEST_ELEMS>(
            prepared.settings.air_settings(),
            prepared.settings.merkle_hash(),
            prepared.settings.merkle_compress(),
            &mut prover_state,
            witness,
        );

    Proof {
        whir_proof,
        proof_data: prover_state.proof_data().to_vec(),
    }
}

pub fn verify<C, S, const DIGEST_ELEMS: usize>(
    prepared: &Prepared<C, S, DIGEST_ELEMS>,
    proof: &Proof<C, DIGEST_ELEMS>,
) -> Result<(), String>
where
    C: Circuit<DIGEST_ELEMS>,
    S: ProvingSystemSettings<C, DIGEST_ELEMS>,
    C::F: Eq,
    C::W: p3_field::PackedValue<Value = C::W> + Eq + Send + Sync + Copy,
    [C::W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    <C::F as p3_field::Field>::Packing: Eq + Send + Sync,
{
    let table = C::make_table(&prepared.circuit, prepared.settings.air_settings());

    let challenger = prepared.settings.new_challenger();
    let mut verifier_state = VerifierState::new(
        &prepared.domain_separator,
        proof.proof_data.clone(),
        challenger,
    );

    table
        .verify::<S::MerkleHash, S::MerkleCompress, S::Challenger, C::W, DIGEST_ELEMS>(
            prepared.settings.air_settings(),
            prepared.settings.merkle_hash(),
            prepared.settings.merkle_compress(),
            &mut verifier_state,
            table.log_length,
            &proof.whir_proof,
        )
        .map_err(|e| format!("verify failed: {e:?}"))
}

pub fn preprocessing_size<C, S, const DIGEST_ELEMS: usize>(
    prepared: &Prepared<C, S, DIGEST_ELEMS>,
) -> usize
where
    C: Circuit<DIGEST_ELEMS>,
    S: ProvingSystemSettings<C, DIGEST_ELEMS>,
    C::Preprocessed: serde::Serialize,
{
    bincode::serialize(&(prepared.settings.air_settings().clone(), &prepared.circuit))
        .map(|v| v.len())
        .unwrap_or(0)
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

pub fn num_constraints<C, S, const DIGEST_ELEMS: usize>(
    prepared: &Prepared<C, S, DIGEST_ELEMS>,
) -> usize
where
    C: Circuit<DIGEST_ELEMS>,
    S: ProvingSystemSettings<C, DIGEST_ELEMS>,
{
    let table = C::make_table(&prepared.circuit, prepared.settings.air_settings());
    table.n_constraints
}
