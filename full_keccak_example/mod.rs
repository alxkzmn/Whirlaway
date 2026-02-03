mod sponge_air;
mod trace;

use anyhow::{Context, Result};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_hyperplonk::HyperPlonkConfig;
use p3_hyperplonk::{ProverInput, VerifierInput, keygen, prove as hyperprove, verify as hyperverify};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_whir::{
    FoldingFactor, InitialPhaseConfig, KeccakNodeCompress, KeccakU32BeLeafHasher,
    ProtocolParameters, SecurityAssumption, WhirPcs,
};

use crate::keccak::sponge_air::KeccakSpongeAir;

type Val = KoalaBear;
type Challenge = BinomialExtensionField<Val, 4>;
type FieldHash = KeccakU32BeLeafHasher;
type Compress = KeccakNodeCompress;
type Dft<Val> = Radix2DitParallel<Val>;
type Pcs<Val, Dft> = WhirPcs<Val, Dft, FieldHash, Compress, 4>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, Keccak256Hash, 32>>;

pub type HyperConfig = HyperPlonkConfig<Pcs<Val, Dft<Val>>, Challenge, Challenger>;

pub type KeccakProof = p3_hyperplonk::Proof<HyperConfig>;

pub struct PreparedKeccak {
    pub input_size: usize,
    pub config: HyperConfig,
    pub air: KeccakSpongeAir,
    pub pk: p3_hyperplonk::ProvingKey,
    pub vk: p3_hyperplonk::VerifyingKey,
    pub trace: RowMajorMatrix<Val>,
    pub public_values: Vec<Val>,
}

fn make_config() -> HyperConfig {
    let dft = Dft::<Val>::default();
    // Keep consistent with p3-playground example.
    let security_level = 100;
    let pow_bits = 20;
    let field_hash = FieldHash::default();
    let compress = Compress::default();
    let whir_params = ProtocolParameters {
        initial_phase_config: InitialPhaseConfig::WithStatementClassic,
        security_level,
        pow_bits,
        folding_factor: FoldingFactor::Constant(4),
        merkle_hash: field_hash,
        merkle_compress: compress,
        soundness_type: SecurityAssumption::CapacityBound,
        starting_log_inv_rate: 1,
        rs_domain_initial_reduction_factor: 3,
    };

    HyperPlonkConfig::<_, Challenge, _>::new(
        Pcs::new(dft, whir_params),
        Challenger::from_hasher(Vec::new(), Keccak256Hash),
    )
}

pub fn prepare(input_size: usize) -> Result<PreparedKeccak> {
    // Build AIR + trace + public digest.
    let (trace, digest_limbs) = trace::generate_trace_and_public_digest_limbs::<Val>(input_size)
        .context("failed to build keccak sponge trace")?;

    let air = KeccakSpongeAir::new();
    // Public values are 16 16-bit limbs (little-endian) of the Keccak256 digest.
    let public_values: Vec<Val> = digest_limbs
        .into_iter()
        .map(|x| Val::new(x as u32))
        .collect();

    let config = make_config();
    let (vk, pk) = keygen::<Val, _>([&air]);

    Ok(PreparedKeccak {
        input_size,
        config,
        air,
        pk,
        vk,
        trace,
        public_values,
    })
}

pub fn prove(prepared: &PreparedKeccak) -> KeccakProof {
    let prover_inputs = vec![ProverInput::new(
        prepared.air.clone(),
        prepared.public_values.clone(),
        prepared.trace.clone(),
    )];
    hyperprove(&prepared.config, &prepared.pk, prover_inputs)
}

pub fn verify(prepared: &PreparedKeccak, proof: &KeccakProof) -> Result<()> {
    let verifier_inputs =
        vec![VerifierInput::new(prepared.air.clone(), prepared.public_values.clone())];
    hyperverify(&prepared.config, &prepared.vk, verifier_inputs, proof)
        .map_err(|e| anyhow::anyhow!("hyperplonk verification failed: {e:?}"))
}

pub fn preprocessing_size(prepared: &PreparedKeccak) -> usize {
    // p3-playground's VK/PK don't currently implement serde, so we can't bincode them directly.
    // For now we use a conservative proxy: sum of per-AIR metadata (small) + trace-independent.
    prepared
        .vk
        .metas()
        .iter()
        .map(|m| {
            // 10 usize fields in AirMeta on 64-bit is ~80 bytes, but keep it simple.
            (m.width + m.public_value_count + m.constraint_count) * core::mem::size_of::<usize>()
        })
        .sum()
}

pub fn proof_size(proof: &KeccakProof) -> usize {
    bincode::serialize(proof).map(|v| v.len()).unwrap_or(0)
}

pub fn num_constraints(prepared: &PreparedKeccak) -> usize {
    prepared
        .vk
        .metas()
        .first()
        .map(|m| m.constraint_count)
        .unwrap_or(0)
}

