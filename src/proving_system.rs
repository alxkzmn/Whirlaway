use air::AirSettings;
use air::table::AirTable;
use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger, SerializingChallenger32};
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_keccak::Keccak256Hash;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use serde::{Deserialize, Serialize};
use utils::{ProverState, VerifierState};
use whir_p3::fiat_shamir::domain_separator::DomainSeparator;
use whir_p3::poly::evals::EvaluationsList;
use whir_p3::whir::proof::WhirProof;

use crate::hashers::{KECCAK_DIGEST_ELEMS, KeccakNodeCompress, KeccakU32BeLeafHasher};

pub trait ProvingSystemSettings<
    C,
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    const DIGEST_ELEMS: usize,
> where
    C: Circuit<F, EF, DIGEST_ELEMS>,
{
    type MerkleHash: CryptographicHasher<F, [C::W; DIGEST_ELEMS]> + Sync + Clone;
    type MerkleCompress: PseudoCompressionFunction<[C::W; DIGEST_ELEMS], 2> + Sync + Clone;

    type Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanObserve<p3_symmetric::Hash<F, C::W, DIGEST_ELEMS>>
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

impl<C, MH, MC, CH, F, EF, const DIGEST_ELEMS: usize> ProvingSystemSettings<C, F, EF, DIGEST_ELEMS>
    for ProvingSystemConfig<MH, MC, CH>
where
    F: TwoAdicField + Clone,
    EF: ExtensionField<F> + TwoAdicField,
    C: Circuit<F, EF, DIGEST_ELEMS>,
    MH: CryptographicHasher<F, [C::W; DIGEST_ELEMS]> + Sync + Clone,
    MC: PseudoCompressionFunction<[C::W; DIGEST_ELEMS], 2> + Sync + Clone,
    CH: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanObserve<p3_symmetric::Hash<F, C::W, DIGEST_ELEMS>>
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

#[derive(Clone, Debug)]
pub struct KeccakProvingSystemConfig<
    EF: ExtensionField<crate::circuits::keccak256::F> + TwoAdicField,
> {
    pub air_settings: AirSettings,
    _marker: std::marker::PhantomData<EF>,
}

impl<EF: ExtensionField<crate::circuits::keccak256::F> + TwoAdicField>
    KeccakProvingSystemConfig<EF>
{
    pub fn new(air_settings: AirSettings) -> Self {
        Self {
            air_settings,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<EF: ExtensionField<crate::circuits::keccak256::F> + TwoAdicField>
    ProvingSystemSettings<
        crate::circuits::keccak256::Keccak256Circuit<EF>,
        crate::circuits::keccak256::F,
        EF,
        KECCAK_DIGEST_ELEMS,
    > for KeccakProvingSystemConfig<EF>
{
    type MerkleHash = KeccakU32BeLeafHasher;
    type MerkleCompress = KeccakNodeCompress;
    type Challenger = crate::circuits::keccak256::Challenger;

    fn air_settings(&self) -> &AirSettings {
        &self.air_settings
    }

    fn merkle_hash(&self) -> Self::MerkleHash {
        KeccakU32BeLeafHasher::for_security_bits(self.air_settings.security_bits)
    }

    fn merkle_compress(&self) -> Self::MerkleCompress {
        KeccakNodeCompress::for_security_bits(self.air_settings.security_bits)
    }

    fn new_challenger(&self) -> Self::Challenger {
        SerializingChallenger32::from_hasher(Vec::new(), Keccak256Hash)
    }
}

pub trait Circuit<
    F: Field + TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    const DIGEST_ELEMS: usize,
>
{
    type Air: for<'a> Air<utils::ConstraintFolder<'a, F, F, EF>>
        + for<'a> Air<utils::ConstraintFolder<'a, F, EF, EF>>
        + for<'a> Air<utils::ConstraintFolderPacked<'a, F, EF>>;

    type W: p3_field::PackedValue<Value = Self::W> + Eq + Send + Sync + Default;

    type Preprocessed: Clone + core::fmt::Debug;
    type Input;

    fn preprocess(&self, settings: &AirSettings) -> Self::Preprocessed;

    fn make_table(
        preprocessed: &Self::Preprocessed,
        settings: &AirSettings,
    ) -> AirTable<F, EF, Self::Air>;

    fn build_witness(
        preprocessed: &Self::Preprocessed,
        input: &Self::Input,
    ) -> Vec<EvaluationsList<F>>;

    fn public_values(preprocessed: &Self::Preprocessed, input: &Self::Input) -> Vec<F> {
        let _ = preprocessed;
        let _ = input;
        Vec::new()
    }
}

#[derive(Clone, Debug)]
pub struct Prepared<
    C,
    S,
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    const DIGEST_ELEMS: usize,
> where
    C: Circuit<F, EF, DIGEST_ELEMS>,
    S: ProvingSystemSettings<C, F, EF, DIGEST_ELEMS>,
{
    pub settings: S,
    pub circuit: C::Preprocessed,
    pub domain_separator: DomainSeparator<EF, F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::W: Serialize, [C::W; DIGEST_ELEMS]: Serialize",
    deserialize = "C::W: Deserialize<'de>, [C::W; DIGEST_ELEMS]: Deserialize<'de>"
))]
pub struct Proof<
    C,
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    const DIGEST_ELEMS: usize,
> where
    C: Circuit<F, EF, DIGEST_ELEMS>,
{
    pub whir_proof: WhirProof<F, EF, C::W, DIGEST_ELEMS>,
    pub proof_data: Vec<EF>,
}

pub fn prepare<C, S, F, EF, const DIGEST_ELEMS: usize>(
    settings: &S,
    circuit: C,
) -> Prepared<C, S, F, EF, DIGEST_ELEMS>
where
    C: Circuit<F, EF, DIGEST_ELEMS>,
    S: ProvingSystemSettings<C, F, EF, DIGEST_ELEMS> + Clone,
    F: Field + TwoAdicField + serde::Serialize + for<'de> serde::Deserialize<'de>,
    EF: ExtensionField<F> + TwoAdicField + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let preprocessed_circuit = circuit.preprocess(settings.air_settings());
    let table = C::make_table(&preprocessed_circuit, settings.air_settings());

    let whir_params = table.build_whir_params::<S::MerkleHash, S::MerkleCompress, S::Challenger>(
        settings.air_settings(),
        settings.merkle_hash(),
        settings.merkle_compress(),
    );

    let mut domain_separator = DomainSeparator::<EF, F>::new(Vec::new());
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

pub fn prove<
    C,
    S,
    F: Field + TwoAdicField + Ord,
    EF: ExtensionField<F> + TwoAdicField + Default,
    const DIGEST_ELEMS: usize,
>(
    prepared: &Prepared<C, S, F, EF, DIGEST_ELEMS>,
    input: &C::Input,
) -> Proof<C, F, EF, DIGEST_ELEMS>
where
    C: Circuit<F, EF, DIGEST_ELEMS>,
    S: ProvingSystemSettings<C, F, EF, DIGEST_ELEMS>,
    C::W: p3_field::PackedValue<Value = C::W> + Eq + Send + Sync + Default,
    [C::W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    <F as p3_field::Field>::Packing: Eq + Send + Sync,
{
    let witness = C::build_witness(&prepared.circuit, input);
    let table = C::make_table(&prepared.circuit, prepared.settings.air_settings());
    let public_values = C::public_values(&prepared.circuit, input);

    let challenger = &prepared.settings.new_challenger();
    let mut prover_state = ProverState::new(&prepared.domain_separator, challenger.clone());
    for value in &public_values {
        prover_state.challenger_mut().observe(*value);
    }

    let whir_proof = table
        .prove::<S::MerkleHash, S::MerkleCompress, S::Challenger, C::W, DIGEST_ELEMS>(
            prepared.settings.air_settings(),
            prepared.settings.merkle_hash(),
            prepared.settings.merkle_compress(),
            &mut prover_state,
            &public_values,
            witness,
        );

    Proof {
        whir_proof,
        proof_data: prover_state.proof_data().to_vec(),
    }
}

pub fn verify<
    C,
    S,
    F: Field + TwoAdicField + Eq,
    EF: ExtensionField<F> + TwoAdicField,
    const DIGEST_ELEMS: usize,
>(
    prepared: &Prepared<C, S, F, EF, DIGEST_ELEMS>,
    proof: &Proof<C, F, EF, DIGEST_ELEMS>,
    public_values: &[F],
) -> Result<(), String>
where
    C: Circuit<F, EF, DIGEST_ELEMS>,
    S: ProvingSystemSettings<C, F, EF, DIGEST_ELEMS>,
    C::W: p3_field::PackedValue<Value = C::W> + Eq + Send + Sync + Copy,
    [C::W; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    <F as p3_field::Field>::Packing: Eq + Send + Sync,
{
    let table = C::make_table(&prepared.circuit, prepared.settings.air_settings());

    let challenger = prepared.settings.new_challenger();
    let mut verifier_state = VerifierState::new(
        &prepared.domain_separator,
        proof.proof_data.clone(),
        challenger,
    );
    for value in public_values {
        verifier_state.challenger_mut().observe(*value);
    }

    table
        .verify::<S::MerkleHash, S::MerkleCompress, S::Challenger, C::W, DIGEST_ELEMS>(
            prepared.settings.air_settings(),
            prepared.settings.merkle_hash(),
            prepared.settings.merkle_compress(),
            &mut verifier_state,
            public_values,
            table.log_length,
            &proof.whir_proof,
        )
        .map_err(|e| format!("verify failed: {e:?}"))?;

    if !verifier_state.is_fully_consumed() {
        return Err(format!(
            "verify failed: trailing proof_data elements ({})",
            verifier_state.remaining_proof_data_len()
        ));
    }

    Ok(())
}

pub fn preprocessing_size<
    C,
    S,
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    const DIGEST_ELEMS: usize,
>(
    prepared: &Prepared<C, S, F, EF, DIGEST_ELEMS>,
) -> usize
where
    C: Circuit<F, EF, DIGEST_ELEMS>,
    S: ProvingSystemSettings<C, F, EF, DIGEST_ELEMS>,
    C::Preprocessed: serde::Serialize,
{
    bincode::serialize(&(prepared.settings.air_settings().clone(), &prepared.circuit))
        .map(|v| v.len())
        .unwrap_or(0)
}

pub fn proof_size<C, F, EF, const DIGEST_ELEMS: usize>(
    proof: &Proof<C, F, EF, DIGEST_ELEMS>,
) -> usize
where
    C: Circuit<F, EF, DIGEST_ELEMS>,
    F: TwoAdicField + serde::Serialize,
    EF: ExtensionField<F> + TwoAdicField + serde::Serialize,
    C::W: serde::Serialize,
    [C::W; DIGEST_ELEMS]: serde::Serialize,
{
    bincode::serialize(proof).map(|v| v.len()).unwrap_or(0)
}

pub fn num_constraints<
    C,
    S,
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    const DIGEST_ELEMS: usize,
>(
    prepared: &Prepared<C, S, F, EF, DIGEST_ELEMS>,
) -> usize
where
    C: Circuit<F, EF, DIGEST_ELEMS>,
    S: ProvingSystemSettings<C, F, EF, DIGEST_ELEMS>,
{
    let table = C::make_table(&prepared.circuit, prepared.settings.air_settings());
    table.n_constraints
}
