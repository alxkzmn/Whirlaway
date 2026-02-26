use core::fmt;

use p3_field::PrimeCharacteristicRing;
use p3_field::{BasedVectorSpace, ExtensionField, PrimeField32, TwoAdicField};
use p3_keccak::Keccak256Hash;
use p3_symmetric::CryptographicHasher;
use whir_p3::metrics::HashCountSnapshot;
use whir_p3::poly::evals::EvaluationsList;
use whir_p3::whir::merkle_multiproof::MerkleMultiProof;
use whir_p3::whir::proof::{QueryBatchOpening, SumcheckData, WhirProof, WhirRoundProof};

use crate::circuits::keccak256::{Binomial8Challenge, F, Keccak256Circuit};
use crate::hashers::digest_bytes32_to_u64;
use crate::hashers::{
    KECCAK_DIGEST_ELEMS, digest_u64_to_bytes32, effective_digest_bytes_for_security_bits,
};
use crate::proving_system::Proof as SystemProof;

pub const PROOF_BLOB_MAGIC: [u8; 4] = *b"WPK1";
pub const PROOF_BLOB_VERSION_V1: u8 = 1;
pub const PROOF_BLOB_VERSION_V2: u8 = 2;
pub const PROOF_BLOB_VERSION_V3: u8 = 3;
pub const PROOF_BLOB_VERSION: u8 = PROOF_BLOB_VERSION_V2;
pub const JSON_SCHEMA_V1: &str = "p3-whirlaway-evm-proof-v1";
pub const JSON_SCHEMA_V2: &str = "p3-whirlaway-evm-proof-v2";
pub const JSON_SCHEMA_V3: &str = "p3-whirlaway-evm-proof-v3";
pub const JSON_SCHEMA: &str = JSON_SCHEMA_V2;
pub const VERIFY_FUNCTION: &str = "verify(bytes)";
const EXTENSION_LIMBS: usize = 8;

pub type Val = F;
pub type Challenge = Binomial8Challenge;
pub type WhirPcsProof = WhirProof<Val, Challenge, u64, KECCAK_DIGEST_ELEMS>;
pub type KeccakProof = SystemProof<
    Keccak256Circuit<Binomial8Challenge>,
    F,
    Binomial8Challenge,
    { KECCAK_DIGEST_ELEMS },
>;

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct HashCountJson {
    pub leaf_hash_calls: u64,
    pub node_hash_calls: u64,
}

impl From<HashCountSnapshot> for HashCountJson {
    fn from(value: HashCountSnapshot) -> Self {
        Self {
            leaf_hash_calls: value.leaf_hash_calls,
            node_hash_calls: value.node_hash_calls,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct MerkleJsonMetrics {
    pub masked_digest_bytes: usize,
    pub masked_digest_bits: usize,
    pub total_merkle_digest_count: usize,
}

#[must_use]
pub const fn keccak_mode_label() -> &'static str {
    if cfg!(feature = "keccak_no_prefix") {
        "no_prefix"
    } else {
        "prefixed"
    }
}

#[must_use]
pub const fn clamp_effective_digest_bytes(effective_digest_bytes: usize) -> usize {
    if effective_digest_bytes == 0 {
        1
    } else if effective_digest_bytes > 32 {
        32
    } else {
        effective_digest_bytes
    }
}

#[must_use]
pub const fn effective_digest_bytes_for_v3_security_bits(security_bits: usize) -> usize {
    effective_digest_bytes_for_security_bits(security_bits)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum QueryKind {
    Base,
    Extension,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QueryBatchShape {
    pub kind: QueryKind,
    pub query_count: usize,
    pub row_width: usize,
    pub decommit_count: usize,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WhirProofV2Shape {
    pub round_shapes: Vec<QueryBatchShape>,
    pub final_shape: QueryBatchShape,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProofBlobV2DecodeContext {
    pub whir_shape: WhirProofV2Shape,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProofBlobV3DecodeContext {
    pub whir_shape: WhirProofV2Shape,
    pub effective_digest_bytes: usize,
}

#[derive(Debug, Clone, Default)]
pub struct ProofBlobOffsets {
    pub commitment_offset: Option<usize>,
    pub first_initial_ood_answer_offset: Option<usize>,
    pub first_sumcheck_coeff_offset: Option<usize>,
    pub first_merkle_sibling_offset: Option<usize>,
    pub first_final_poly_offset: Option<usize>,
    pub first_proof_data_offset: Option<usize>,
}

#[derive(Debug)]
pub struct DecodedProofBlob {
    pub public_values: Vec<Val>,
    pub proof: KeccakProof,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DecodeError {
    msg: String,
}

impl DecodeError {
    fn new(msg: impl Into<String>) -> Self {
        Self { msg: msg.into() }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for DecodeError {}

pub fn encode_proof_blob_v1(public_values: &[Val], proof: &KeccakProof) -> Vec<u8> {
    encode_proof_blob_v1_generic(public_values, proof)
}

pub fn encode_proof_blob_v1_with_offsets(
    public_values: &[Val],
    proof: &KeccakProof,
) -> (Vec<u8>, ProofBlobOffsets) {
    encode_proof_blob_v1_generic_with_offsets(public_values, proof)
}

pub fn encode_proof_blob_v1_generic<EF>(
    public_values: &[Val],
    proof: &SystemProof<Keccak256Circuit<EF>, F, EF, { KECCAK_DIGEST_ELEMS }>,
) -> Vec<u8>
where
    EF: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy,
{
    encode_proof_blob_v1_generic_with_offsets(public_values, proof).0
}

pub fn encode_proof_blob_v1_generic_with_offsets<EF>(
    public_values: &[Val],
    proof: &SystemProof<Keccak256Circuit<EF>, F, EF, { KECCAK_DIGEST_ELEMS }>,
) -> (Vec<u8>, ProofBlobOffsets)
where
    EF: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy,
{
    encode_proof_blob_generic_with_offsets(public_values, proof, PROOF_BLOB_VERSION_V1, false, 32)
}

pub fn encode_proof_blob_v2(public_values: &[Val], proof: &KeccakProof) -> Vec<u8> {
    encode_proof_blob_v2_generic(public_values, proof)
}

pub fn encode_proof_blob_v2_with_offsets(
    public_values: &[Val],
    proof: &KeccakProof,
) -> (Vec<u8>, ProofBlobOffsets) {
    encode_proof_blob_v2_generic_with_offsets(public_values, proof)
}

pub fn encode_proof_blob_v2_generic<EF>(
    public_values: &[Val],
    proof: &SystemProof<Keccak256Circuit<EF>, F, EF, { KECCAK_DIGEST_ELEMS }>,
) -> Vec<u8>
where
    EF: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy,
{
    encode_proof_blob_v2_generic_with_offsets(public_values, proof).0
}

pub fn encode_proof_blob_v2_generic_with_offsets<EF>(
    public_values: &[Val],
    proof: &SystemProof<Keccak256Circuit<EF>, F, EF, { KECCAK_DIGEST_ELEMS }>,
) -> (Vec<u8>, ProofBlobOffsets)
where
    EF: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy,
{
    encode_proof_blob_generic_with_offsets(public_values, proof, PROOF_BLOB_VERSION_V2, true, 32)
}

pub fn encode_proof_blob_v3(
    public_values: &[Val],
    proof: &KeccakProof,
    effective_digest_bytes: usize,
) -> Vec<u8> {
    encode_proof_blob_v3_generic(public_values, proof, effective_digest_bytes)
}

pub fn encode_proof_blob_v3_with_offsets(
    public_values: &[Val],
    proof: &KeccakProof,
    effective_digest_bytes: usize,
) -> (Vec<u8>, ProofBlobOffsets) {
    encode_proof_blob_v3_generic_with_offsets(public_values, proof, effective_digest_bytes)
}

pub fn encode_proof_blob_v3_generic<EF>(
    public_values: &[Val],
    proof: &SystemProof<Keccak256Circuit<EF>, F, EF, { KECCAK_DIGEST_ELEMS }>,
    effective_digest_bytes: usize,
) -> Vec<u8>
where
    EF: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy,
{
    encode_proof_blob_v3_generic_with_offsets(public_values, proof, effective_digest_bytes).0
}

pub fn encode_proof_blob_v3_generic_with_offsets<EF>(
    public_values: &[Val],
    proof: &SystemProof<Keccak256Circuit<EF>, F, EF, { KECCAK_DIGEST_ELEMS }>,
    effective_digest_bytes: usize,
) -> (Vec<u8>, ProofBlobOffsets)
where
    EF: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy,
{
    encode_proof_blob_generic_with_offsets(
        public_values,
        proof,
        PROOF_BLOB_VERSION_V3,
        true,
        clamp_effective_digest_bytes(effective_digest_bytes),
    )
}

fn encode_proof_blob_generic_with_offsets<EF>(
    public_values: &[Val],
    proof: &SystemProof<Keccak256Circuit<EF>, F, EF, { KECCAK_DIGEST_ELEMS }>,
    version: u8,
    compact_queries: bool,
    digest_bytes: usize,
) -> (Vec<u8>, ProofBlobOffsets)
where
    EF: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy,
{
    let mut writer = BlobWriter::new(clamp_effective_digest_bytes(digest_bytes));
    let mut offsets = ProofBlobOffsets::default();

    writer.write_bytes(&PROOF_BLOB_MAGIC);
    writer.write_u8(version);

    writer.write_len(public_values.len());
    for &value in public_values {
        writer.write_val(value);
    }

    writer.write_len(proof.proof_data.len());
    for &value in &proof.proof_data {
        writer.write_challenge_marked(value, &mut offsets.first_proof_data_offset);
    }

    encode_whir_proof(
        &mut writer,
        &proof.whir_proof,
        &mut offsets,
        compact_queries,
    );

    (writer.finish(), offsets)
}

fn encode_whir_proof<EF>(
    writer: &mut BlobWriter,
    proof: &WhirProof<Val, EF, u64, KECCAK_DIGEST_ELEMS>,
    offsets: &mut ProofBlobOffsets,
    compact_queries: bool,
) where
    EF: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy,
{
    offsets.commitment_offset = Some(writer.pos());
    writer.write_digest(&proof.initial_commitment);

    writer.write_len(proof.initial_ood_answers.len());
    for &answer in &proof.initial_ood_answers {
        writer.write_challenge_marked(answer, &mut offsets.first_initial_ood_answer_offset);
    }

    encode_whir_sumcheck(writer, &proof.initial_sumcheck, offsets);

    writer.write_len(proof.rounds.len());
    for round in &proof.rounds {
        encode_whir_round(writer, round, offsets, compact_queries);
    }

    writer.write_option(&proof.final_poly, |writer, final_poly| {
        if offsets.first_final_poly_offset.is_none() && !final_poly.as_slice().is_empty() {
            offsets.first_final_poly_offset = Some(writer.pos());
        }
        writer.write_len(final_poly.as_slice().len());
        for &value in final_poly.as_slice() {
            writer.write_challenge(value);
        }
    });

    writer.write_val(proof.final_pow_witness);

    let final_query_batch = proof
        .final_query_batch
        .as_ref()
        .expect("missing final query batch in WHIR proof");
    encode_query_batch(writer, final_query_batch, offsets, compact_queries);

    writer.write_option(&proof.final_sumcheck, |writer, sumcheck| {
        encode_whir_sumcheck(writer, sumcheck, offsets);
    });
}

fn encode_whir_round<EF>(
    writer: &mut BlobWriter,
    round: &WhirRoundProof<Val, EF, u64, KECCAK_DIGEST_ELEMS>,
    offsets: &mut ProofBlobOffsets,
    compact_queries: bool,
) where
    EF: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy,
{
    writer.write_digest(&round.commitment);

    writer.write_len(round.ood_answers.len());
    for &answer in &round.ood_answers {
        writer.write_challenge_marked(answer, &mut offsets.first_initial_ood_answer_offset);
    }

    writer.write_val(round.pow_witness);

    let query_batch = round
        .query_batch
        .as_ref()
        .expect("missing round query batch in WHIR proof");
    encode_query_batch(writer, query_batch, offsets, compact_queries);

    encode_whir_sumcheck(writer, &round.sumcheck, offsets);
}

fn encode_whir_sumcheck<EF>(
    writer: &mut BlobWriter,
    sumcheck: &SumcheckData<Val, EF>,
    offsets: &mut ProofBlobOffsets,
) where
    EF: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy,
{
    writer.write_len(sumcheck.polynomial_evaluations.len());
    for coeffs in &sumcheck.polynomial_evaluations {
        writer.write_challenge_marked(coeffs[0], &mut offsets.first_sumcheck_coeff_offset);
        writer.write_challenge_marked(coeffs[1], &mut offsets.first_sumcheck_coeff_offset);
    }

    writer.write_len(sumcheck.pow_witnesses.len());
    for &witness in &sumcheck.pow_witnesses {
        writer.write_val(witness);
    }
}

fn encode_query_batch<EF>(
    writer: &mut BlobWriter,
    query: &QueryBatchOpening<Val, EF, u64, KECCAK_DIGEST_ELEMS>,
    offsets: &mut ProofBlobOffsets,
    compact: bool,
) where
    EF: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy,
{
    match query {
        QueryBatchOpening::Base { values, proof } => {
            if !compact {
                writer.write_u8(0);
                writer.write_len(values.len());
            }
            let row_width = values.first().map_or(0, Vec::len);
            if !compact {
                writer.write_len(row_width);
            }
            for row in values {
                assert_eq!(row.len(), row_width, "inconsistent base query row width");
                for &value in row {
                    writer.write_val(value);
                }
            }
            if !compact {
                writer.write_len(proof.decommitments.len());
            }
            for sibling in &proof.decommitments {
                if offsets.first_merkle_sibling_offset.is_none() {
                    offsets.first_merkle_sibling_offset = Some(writer.pos());
                }
                writer.write_digest(sibling);
            }
        }
        QueryBatchOpening::Extension { values, proof } => {
            if !compact {
                writer.write_u8(1);
                writer.write_len(values.len());
            }
            let row_width = values.first().map_or(0, Vec::len);
            if !compact {
                writer.write_len(row_width);
            }
            for row in values {
                assert_eq!(
                    row.len(),
                    row_width,
                    "inconsistent extension query row width"
                );
                for &value in row {
                    writer.write_challenge(value);
                }
            }
            if !compact {
                writer.write_len(proof.decommitments.len());
            }
            for sibling in &proof.decommitments {
                if offsets.first_merkle_sibling_offset.is_none() {
                    offsets.first_merkle_sibling_offset = Some(writer.pos());
                }
                writer.write_digest(sibling);
            }
        }
    }
}

pub fn decode_proof_blob_v1(bytes: &[u8]) -> Result<DecodedProofBlob, DecodeError> {
    decode_proof_blob_with_contexts(bytes, None, None)
}

pub fn decode_proof_blob_v1_with_context(
    bytes: &[u8],
    v2_context: Option<&ProofBlobV2DecodeContext>,
) -> Result<DecodedProofBlob, DecodeError> {
    decode_proof_blob_with_contexts(bytes, v2_context, None)
}

pub fn decode_proof_blob_v2_with_context(
    bytes: &[u8],
    v2_context: &ProofBlobV2DecodeContext,
) -> Result<DecodedProofBlob, DecodeError> {
    decode_proof_blob_with_contexts(bytes, Some(v2_context), None)
}

pub fn decode_proof_blob_v3_with_context(
    bytes: &[u8],
    v3_context: &ProofBlobV3DecodeContext,
) -> Result<DecodedProofBlob, DecodeError> {
    decode_proof_blob_with_contexts(bytes, None, Some(v3_context))
}

pub fn decode_proof_blob_with_contexts(
    bytes: &[u8],
    v2_context: Option<&ProofBlobV2DecodeContext>,
    v3_context: Option<&ProofBlobV3DecodeContext>,
) -> Result<DecodedProofBlob, DecodeError> {
    let mut reader = BlobReader::new(bytes);

    let magic = reader.read_exact::<4>()?;
    if magic != PROOF_BLOB_MAGIC {
        return Err(DecodeError::new("invalid proof blob magic"));
    }

    let version = reader.read_u8()?;
    match version {
        PROOF_BLOB_VERSION_V1 => decode_proof_blob_v1_payload(&mut reader),
        PROOF_BLOB_VERSION_V2 => {
            let Some(ctx) = v2_context else {
                return Err(DecodeError::new(
                    "v2 compact proof decoding requires explicit shape context",
                ));
            };
            decode_proof_blob_v2_payload_compact(&mut reader, &ctx.whir_shape, 32)
        }
        PROOF_BLOB_VERSION_V3 => {
            let Some(ctx) = v3_context else {
                return Err(DecodeError::new(
                    "v3 compact proof decoding requires explicit v3 context",
                ));
            };
            decode_proof_blob_v2_payload_compact(
                &mut reader,
                &ctx.whir_shape,
                clamp_effective_digest_bytes(ctx.effective_digest_bytes),
            )
        }
        _ => Err(DecodeError::new("unsupported proof blob version")),
    }
}

pub fn derive_v2_decode_context(
    proof: &KeccakProof,
) -> Result<ProofBlobV2DecodeContext, DecodeError> {
    Ok(ProofBlobV2DecodeContext {
        whir_shape: derive_whir_v2_shape(&proof.whir_proof)?,
    })
}

pub fn derive_v3_decode_context(
    proof: &KeccakProof,
) -> Result<ProofBlobV3DecodeContext, DecodeError> {
    Ok(ProofBlobV3DecodeContext {
        whir_shape: derive_whir_v2_shape(&proof.whir_proof)?,
        effective_digest_bytes: 32,
    })
}

pub fn derive_v3_decode_context_with_digest_bytes(
    proof: &KeccakProof,
    effective_digest_bytes: usize,
) -> Result<ProofBlobV3DecodeContext, DecodeError> {
    Ok(ProofBlobV3DecodeContext {
        whir_shape: derive_whir_v2_shape(&proof.whir_proof)?,
        effective_digest_bytes: clamp_effective_digest_bytes(effective_digest_bytes),
    })
}

fn derive_whir_v2_shape(proof: &WhirPcsProof) -> Result<WhirProofV2Shape, DecodeError> {
    let mut round_shapes = Vec::with_capacity(proof.rounds.len());
    for round in &proof.rounds {
        let Some(query_batch) = round.query_batch.as_ref() else {
            return Err(DecodeError::new(
                "missing round query batch in shape derivation",
            ));
        };
        round_shapes.push(shape_from_query_batch(query_batch));
    }
    let Some(final_query_batch) = proof.final_query_batch.as_ref() else {
        return Err(DecodeError::new(
            "missing final query batch in shape derivation",
        ));
    };

    Ok(WhirProofV2Shape {
        round_shapes,
        final_shape: shape_from_query_batch(final_query_batch),
    })
}

fn shape_from_query_batch(
    query: &QueryBatchOpening<Val, Challenge, u64, KECCAK_DIGEST_ELEMS>,
) -> QueryBatchShape {
    match query {
        QueryBatchOpening::Base { values, proof } => QueryBatchShape {
            kind: QueryKind::Base,
            query_count: values.len(),
            row_width: values.first().map_or(0, Vec::len),
            decommit_count: proof.decommitments.len(),
        },
        QueryBatchOpening::Extension { values, proof } => QueryBatchShape {
            kind: QueryKind::Extension,
            query_count: values.len(),
            row_width: values.first().map_or(0, Vec::len),
            decommit_count: proof.decommitments.len(),
        },
    }
}

fn ensure_strictly_increasing_indices(indices: &[usize]) -> Result<(), DecodeError> {
    for pair in indices.windows(2) {
        if pair[0] >= pair[1] {
            return Err(DecodeError::new(
                "indices must be sorted and strictly increasing",
            ));
        }
    }
    Ok(())
}

pub fn derive_decommit_count_from_indices(
    indices: &[usize],
    depth: usize,
) -> Result<usize, DecodeError> {
    ensure_strictly_increasing_indices(indices)?;
    let mut frontier = indices.to_vec();
    let mut decommit_count = 0usize;

    for _ in 0..depth {
        let mut next_frontier = Vec::with_capacity(frontier.len().div_ceil(2));
        let mut cursor = 0usize;
        while cursor < frontier.len() {
            let node = frontier[cursor];
            if node & 1 == 0 && cursor + 1 < frontier.len() && frontier[cursor + 1] == node + 1 {
                cursor += 2;
            } else {
                decommit_count += 1;
                cursor += 1;
            }
            next_frontier.push(node >> 1);
        }
        next_frontier.dedup();
        frontier = next_frontier;
    }

    Ok(decommit_count)
}

pub fn derive_query_batch_shape_from_context(
    kind: QueryKind,
    row_width: usize,
    indices: &[usize],
    depth: usize,
) -> Result<QueryBatchShape, DecodeError> {
    Ok(QueryBatchShape {
        kind,
        query_count: indices.len(),
        row_width,
        decommit_count: derive_decommit_count_from_indices(indices, depth)?,
    })
}

fn decode_proof_blob_v1_payload(
    reader: &mut BlobReader<'_>,
) -> Result<DecodedProofBlob, DecodeError> {
    let n_public_values = reader.read_len()?;
    let mut public_values = Vec::with_capacity(n_public_values);
    for _ in 0..n_public_values {
        public_values.push(reader.read_val()?);
    }

    let n_proof_data = reader.read_len()?;
    let mut proof_data = Vec::with_capacity(n_proof_data);
    for _ in 0..n_proof_data {
        proof_data.push(reader.read_challenge()?);
    }

    let whir_proof = decode_whir_proof_v2(reader)?;
    if !reader.is_eof() {
        return Err(DecodeError::new("trailing bytes after proof payload"));
    }

    Ok(DecodedProofBlob {
        public_values,
        proof: KeccakProof {
            whir_proof,
            proof_data,
        },
    })
}

fn decode_proof_blob_v2_payload_compact(
    reader: &mut BlobReader<'_>,
    whir_shape: &WhirProofV2Shape,
    digest_bytes: usize,
) -> Result<DecodedProofBlob, DecodeError> {
    reader.set_digest_bytes(digest_bytes);

    let n_public_values = reader.read_len()?;
    let mut public_values = Vec::with_capacity(n_public_values);
    for _ in 0..n_public_values {
        public_values.push(reader.read_val()?);
    }

    let n_proof_data = reader.read_len()?;
    let mut proof_data = Vec::with_capacity(n_proof_data);
    for _ in 0..n_proof_data {
        proof_data.push(reader.read_challenge()?);
    }

    let whir_proof = decode_whir_proof_v2_compact(reader, whir_shape)?;
    if !reader.is_eof() {
        return Err(DecodeError::new("trailing bytes after proof payload"));
    }

    Ok(DecodedProofBlob {
        public_values,
        proof: KeccakProof {
            whir_proof,
            proof_data,
        },
    })
}

fn decode_whir_proof_v2(reader: &mut BlobReader<'_>) -> Result<WhirPcsProof, DecodeError> {
    let initial_commitment = reader.read_digest()?;

    let n_initial_ood_answers = reader.read_len()?;
    let mut initial_ood_answers = Vec::with_capacity(n_initial_ood_answers);
    for _ in 0..n_initial_ood_answers {
        initial_ood_answers.push(reader.read_challenge()?);
    }

    let initial_sumcheck = decode_whir_sumcheck(reader)?;

    let n_rounds = reader.read_len()?;
    let mut rounds = Vec::with_capacity(n_rounds);
    for _ in 0..n_rounds {
        rounds.push(decode_whir_round_v2(reader)?);
    }

    let final_poly = reader.read_option(|reader| {
        let n_evals = reader.read_len()?;
        if !n_evals.is_power_of_two() {
            return Err(DecodeError::new("final_poly length must be a power of two"));
        }
        let mut evals = Vec::with_capacity(n_evals);
        for _ in 0..n_evals {
            evals.push(reader.read_challenge()?);
        }
        Ok(EvaluationsList::new(evals))
    })?;

    let final_pow_witness = reader.read_val()?;

    let final_query_batch = decode_query_batch_v2(reader)?;

    let final_sumcheck = reader.read_option(decode_whir_sumcheck)?;

    Ok(WhirPcsProof {
        initial_commitment,
        initial_ood_answers,
        initial_sumcheck,
        rounds,
        final_poly,
        final_pow_witness,
        final_query_batch: Some(final_query_batch),
        final_sumcheck,
    })
}

fn decode_whir_round_v2(
    reader: &mut BlobReader<'_>,
) -> Result<WhirRoundProof<Val, Challenge, u64, KECCAK_DIGEST_ELEMS>, DecodeError> {
    let commitment = reader.read_digest()?;

    let n_ood_answers = reader.read_len()?;
    let mut ood_answers = Vec::with_capacity(n_ood_answers);
    for _ in 0..n_ood_answers {
        ood_answers.push(reader.read_challenge()?);
    }

    let pow_witness = reader.read_val()?;

    let query_batch = decode_query_batch_v2(reader)?;

    let sumcheck = decode_whir_sumcheck(reader)?;

    Ok(WhirRoundProof {
        commitment,
        ood_answers,
        pow_witness,
        query_batch: Some(query_batch),
        sumcheck,
    })
}

fn decode_whir_sumcheck(
    reader: &mut BlobReader<'_>,
) -> Result<SumcheckData<Val, Challenge>, DecodeError> {
    let n_poly_evals = reader.read_len()?;
    let mut polynomial_evaluations = Vec::with_capacity(n_poly_evals);
    for _ in 0..n_poly_evals {
        let c0 = reader.read_challenge()?;
        let c2 = reader.read_challenge()?;
        polynomial_evaluations.push([c0, c2]);
    }

    let n_pow_witnesses = reader.read_len()?;
    let mut pow_witnesses = Vec::with_capacity(n_pow_witnesses);
    for _ in 0..n_pow_witnesses {
        pow_witnesses.push(reader.read_val()?);
    }

    Ok(SumcheckData {
        polynomial_evaluations,
        pow_witnesses,
    })
}

fn decode_query_batch_v2(
    reader: &mut BlobReader<'_>,
) -> Result<QueryBatchOpening<Val, Challenge, u64, KECCAK_DIGEST_ELEMS>, DecodeError> {
    let tag = reader.read_u8()?;
    match tag {
        0 => {
            let query_count = reader.read_len()?;
            let row_width = reader.read_len()?;
            let mut values = Vec::with_capacity(query_count);
            for _ in 0..query_count {
                let mut row = Vec::with_capacity(row_width);
                for _ in 0..row_width {
                    row.push(reader.read_val()?);
                }
                values.push(row);
            }
            let n_decommitments = reader.read_len()?;
            let mut decommitments = Vec::with_capacity(n_decommitments);
            for _ in 0..n_decommitments {
                decommitments.push(reader.read_digest()?);
            }
            Ok(QueryBatchOpening::Base {
                values,
                proof: MerkleMultiProof { decommitments },
            })
        }
        1 => {
            let query_count = reader.read_len()?;
            let row_width = reader.read_len()?;
            let mut values = Vec::with_capacity(query_count);
            for _ in 0..query_count {
                let mut row = Vec::with_capacity(row_width);
                for _ in 0..row_width {
                    row.push(reader.read_challenge()?);
                }
                values.push(row);
            }
            let n_decommitments = reader.read_len()?;
            let mut decommitments = Vec::with_capacity(n_decommitments);
            for _ in 0..n_decommitments {
                decommitments.push(reader.read_digest()?);
            }
            Ok(QueryBatchOpening::Extension {
                values,
                proof: MerkleMultiProof { decommitments },
            })
        }
        _ => Err(DecodeError::new("unknown query batch tag")),
    }
}

fn decode_whir_proof_v2_compact(
    reader: &mut BlobReader<'_>,
    shape: &WhirProofV2Shape,
) -> Result<WhirPcsProof, DecodeError> {
    let initial_commitment = reader.read_digest()?;

    let n_initial_ood_answers = reader.read_len()?;
    let mut initial_ood_answers = Vec::with_capacity(n_initial_ood_answers);
    for _ in 0..n_initial_ood_answers {
        initial_ood_answers.push(reader.read_challenge()?);
    }

    let initial_sumcheck = decode_whir_sumcheck(reader)?;

    let n_rounds = reader.read_len()?;
    if n_rounds != shape.round_shapes.len() {
        return Err(DecodeError::new("v2 shape context round count mismatch"));
    }
    let mut rounds = Vec::with_capacity(n_rounds);
    for round_shape in &shape.round_shapes {
        rounds.push(decode_whir_round_v2_compact(reader, round_shape)?);
    }

    let final_poly = reader.read_option(|reader| {
        let n_evals = reader.read_len()?;
        if !n_evals.is_power_of_two() {
            return Err(DecodeError::new("final_poly length must be a power of two"));
        }
        let mut evals = Vec::with_capacity(n_evals);
        for _ in 0..n_evals {
            evals.push(reader.read_challenge()?);
        }
        Ok(EvaluationsList::new(evals))
    })?;

    let final_pow_witness = reader.read_val()?;
    let final_query_batch = decode_query_batch_v2_compact(reader, &shape.final_shape)?;
    let final_sumcheck = reader.read_option(decode_whir_sumcheck)?;

    Ok(WhirPcsProof {
        initial_commitment,
        initial_ood_answers,
        initial_sumcheck,
        rounds,
        final_poly,
        final_pow_witness,
        final_query_batch: Some(final_query_batch),
        final_sumcheck,
    })
}

fn decode_whir_round_v2_compact(
    reader: &mut BlobReader<'_>,
    shape: &QueryBatchShape,
) -> Result<WhirRoundProof<Val, Challenge, u64, KECCAK_DIGEST_ELEMS>, DecodeError> {
    let commitment = reader.read_digest()?;

    let n_ood_answers = reader.read_len()?;
    let mut ood_answers = Vec::with_capacity(n_ood_answers);
    for _ in 0..n_ood_answers {
        ood_answers.push(reader.read_challenge()?);
    }

    let pow_witness = reader.read_val()?;
    let query_batch = decode_query_batch_v2_compact(reader, shape)?;
    let sumcheck = decode_whir_sumcheck(reader)?;

    Ok(WhirRoundProof {
        commitment,
        ood_answers,
        pow_witness,
        query_batch: Some(query_batch),
        sumcheck,
    })
}

fn decode_query_batch_v2_compact(
    reader: &mut BlobReader<'_>,
    shape: &QueryBatchShape,
) -> Result<QueryBatchOpening<Val, Challenge, u64, KECCAK_DIGEST_ELEMS>, DecodeError> {
    match shape.kind {
        QueryKind::Base => {
            let mut values = Vec::with_capacity(shape.query_count);
            for _ in 0..shape.query_count {
                let mut row = Vec::with_capacity(shape.row_width);
                for _ in 0..shape.row_width {
                    row.push(reader.read_val()?);
                }
                values.push(row);
            }
            let mut decommitments = Vec::with_capacity(shape.decommit_count);
            for _ in 0..shape.decommit_count {
                decommitments.push(reader.read_digest()?);
            }
            Ok(QueryBatchOpening::Base {
                values,
                proof: MerkleMultiProof { decommitments },
            })
        }
        QueryKind::Extension => {
            let mut values = Vec::with_capacity(shape.query_count);
            for _ in 0..shape.query_count {
                let mut row = Vec::with_capacity(shape.row_width);
                for _ in 0..shape.row_width {
                    row.push(reader.read_challenge()?);
                }
                values.push(row);
            }
            let mut decommitments = Vec::with_capacity(shape.decommit_count);
            for _ in 0..shape.decommit_count {
                decommitments.push(reader.read_digest()?);
            }
            Ok(QueryBatchOpening::Extension {
                values,
                proof: MerkleMultiProof { decommitments },
            })
        }
    }
}

pub fn verify_bytes_selector() -> [u8; 4] {
    let hash: [u8; 32] = Keccak256Hash.hash_iter(VERIFY_FUNCTION.as_bytes().iter().copied());
    [hash[0], hash[1], hash[2], hash[3]]
}

pub fn encode_calldata_verify_bytes(proof_blob: &[u8]) -> Vec<u8> {
    let selector = verify_bytes_selector();
    let encoded_args = abi_encode_single_bytes(proof_blob);
    let mut out = Vec::with_capacity(4 + encoded_args.len());
    out.extend_from_slice(&selector);
    out.extend_from_slice(&encoded_args);
    out
}

pub fn decode_verify_bytes_calldata(calldata: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if calldata.len() < 4 + 64 {
        return Err(DecodeError::new("calldata too short"));
    }

    if calldata[..4] != verify_bytes_selector() {
        return Err(DecodeError::new("invalid verify(bytes) selector"));
    }

    let args = &calldata[4..];
    let offset = decode_abi_word_usize(&args[..32])?;
    if offset != 32 {
        return Err(DecodeError::new(
            "invalid ABI offset for single bytes argument",
        ));
    }

    let length = decode_abi_word_usize(&args[32..64])?;
    let data_start = 64usize;
    let data_end = data_start
        .checked_add(length)
        .ok_or_else(|| DecodeError::new("ABI length overflow"))?;
    if data_end > args.len() {
        return Err(DecodeError::new("ABI bytes length out of bounds"));
    }

    let padded_end = data_start
        .checked_add(pad32(length))
        .ok_or_else(|| DecodeError::new("ABI padded length overflow"))?;
    if padded_end != args.len() {
        return Err(DecodeError::new("unexpected trailing data in calldata"));
    }

    if args[data_end..].iter().any(|&byte| byte != 0) {
        return Err(DecodeError::new("non-zero ABI padding"));
    }

    Ok(args[data_start..data_end].to_vec())
}

#[must_use]
pub fn estimate_calldata_gas(calldata: &[u8]) -> u64 {
    let zero_bytes = calldata.iter().filter(|&&b| b == 0).count() as u64;
    let nonzero_bytes = calldata.len() as u64 - zero_bytes;
    zero_bytes.saturating_mul(4) + nonzero_bytes.saturating_mul(16)
}

#[must_use]
pub fn count_merkle_digests_in_proof<EF>(
    proof: &SystemProof<Keccak256Circuit<EF>, F, EF, { KECCAK_DIGEST_ELEMS }>,
) -> usize
where
    EF: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy,
{
    fn query_batch_decommit_count<EF>(
        query: &QueryBatchOpening<Val, EF, u64, KECCAK_DIGEST_ELEMS>,
    ) -> usize
    where
        EF: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy,
    {
        match query {
            QueryBatchOpening::Base { proof, .. } => proof.decommitments.len(),
            QueryBatchOpening::Extension { proof, .. } => proof.decommitments.len(),
        }
    }

    let whir_proof = &proof.whir_proof;
    // initial commitment
    let mut total = 1usize;
    total = total.saturating_add(whir_proof.rounds.len());
    for round in &whir_proof.rounds {
        if let Some(query_batch) = round.query_batch.as_ref() {
            total = total.saturating_add(query_batch_decommit_count(query_batch));
        }
    }
    if let Some(final_query_batch) = whir_proof.final_query_batch.as_ref() {
        total = total.saturating_add(query_batch_decommit_count(final_query_batch));
    }
    total
}

fn schema_for_version(version: u8) -> &'static str {
    match version {
        PROOF_BLOB_VERSION_V1 => JSON_SCHEMA_V1,
        PROOF_BLOB_VERSION_V2 => JSON_SCHEMA_V2,
        PROOF_BLOB_VERSION_V3 => JSON_SCHEMA_V3,
        _ => JSON_SCHEMA,
    }
}

fn proof_blob_version(proof_blob: &[u8]) -> u8 {
    if proof_blob.len() >= 5 && proof_blob[0..4] == PROOF_BLOB_MAGIC {
        proof_blob[4]
    } else {
        PROOF_BLOB_VERSION
    }
}

pub fn render_json_payload(proof_blob: &[u8], calldata: &[u8], pretty: bool) -> String {
    render_json_payload_with_metrics_and_merkle(
        proof_blob,
        calldata,
        HashCountJson::default(),
        HashCountJson::default(),
        MerkleJsonMetrics::default(),
        pretty,
    )
}

pub fn render_json_payload_with_metrics(
    proof_blob: &[u8],
    calldata: &[u8],
    hash_counts_prover: HashCountJson,
    hash_counts_verifier: HashCountJson,
    pretty: bool,
) -> String {
    render_json_payload_with_metrics_and_merkle(
        proof_blob,
        calldata,
        hash_counts_prover,
        hash_counts_verifier,
        MerkleJsonMetrics::default(),
        pretty,
    )
}

pub fn render_json_payload_with_metrics_and_merkle(
    proof_blob: &[u8],
    calldata: &[u8],
    hash_counts_prover: HashCountJson,
    hash_counts_verifier: HashCountJson,
    merkle_metrics: MerkleJsonMetrics,
    pretty: bool,
) -> String {
    let selector = verify_bytes_selector();
    let selector_hex = hex_prefixed(&selector);
    let proof_hex = hex_prefixed(proof_blob);
    let calldata_hex = hex_prefixed(calldata);
    let version = proof_blob_version(proof_blob);
    let schema = schema_for_version(version);
    let calldata_gas = estimate_calldata_gas(calldata);
    let hash_counts_total = HashCountJson {
        leaf_hash_calls: hash_counts_prover
            .leaf_hash_calls
            .saturating_add(hash_counts_verifier.leaf_hash_calls),
        node_hash_calls: hash_counts_prover
            .node_hash_calls
            .saturating_add(hash_counts_verifier.node_hash_calls),
    };

    if pretty {
        format!(
            "{{\n  \"schema\": \"{}\",\n  \"proof_blob_version\": {},\n  \"verify_function\": \"{}\",\n  \"selector\": \"{}\",\n  \"keccak_mode\": \"{}\",\n  \"masked_digest_bytes\": {},\n  \"masked_digest_bits\": {},\n  \"total_merkle_digest_count\": {},\n  \"proof_bytes\": \"{}\",\n  \"proof_bytes_len\": {},\n  \"calldata\": \"{}\",\n  \"calldata_len\": {},\n  \"calldata_gas_estimate\": {},\n  \"hash_counts_prover\": {{ \"leaf_hash_calls\": {}, \"node_hash_calls\": {} }},\n  \"hash_counts_verifier\": {{ \"leaf_hash_calls\": {}, \"node_hash_calls\": {} }},\n  \"hash_counts_total\": {{ \"leaf_hash_calls\": {}, \"node_hash_calls\": {} }}\n}}\n",
            schema,
            version,
            VERIFY_FUNCTION,
            selector_hex,
            keccak_mode_label(),
            merkle_metrics.masked_digest_bytes,
            merkle_metrics.masked_digest_bits,
            merkle_metrics.total_merkle_digest_count,
            proof_hex,
            proof_blob.len(),
            calldata_hex,
            calldata.len(),
            calldata_gas,
            hash_counts_prover.leaf_hash_calls,
            hash_counts_prover.node_hash_calls,
            hash_counts_verifier.leaf_hash_calls,
            hash_counts_verifier.node_hash_calls,
            hash_counts_total.leaf_hash_calls,
            hash_counts_total.node_hash_calls,
        )
    } else {
        format!(
            "{{\"schema\":\"{}\",\"proof_blob_version\":{},\"verify_function\":\"{}\",\"selector\":\"{}\",\"keccak_mode\":\"{}\",\"masked_digest_bytes\":{},\"masked_digest_bits\":{},\"total_merkle_digest_count\":{},\"proof_bytes\":\"{}\",\"proof_bytes_len\":{},\"calldata\":\"{}\",\"calldata_len\":{},\"calldata_gas_estimate\":{},\"hash_counts_prover\":{{\"leaf_hash_calls\":{},\"node_hash_calls\":{}}},\"hash_counts_verifier\":{{\"leaf_hash_calls\":{},\"node_hash_calls\":{}}},\"hash_counts_total\":{{\"leaf_hash_calls\":{},\"node_hash_calls\":{}}}}}",
            schema,
            version,
            VERIFY_FUNCTION,
            selector_hex,
            keccak_mode_label(),
            merkle_metrics.masked_digest_bytes,
            merkle_metrics.masked_digest_bits,
            merkle_metrics.total_merkle_digest_count,
            proof_hex,
            proof_blob.len(),
            calldata_hex,
            calldata.len(),
            calldata_gas,
            hash_counts_prover.leaf_hash_calls,
            hash_counts_prover.node_hash_calls,
            hash_counts_verifier.leaf_hash_calls,
            hash_counts_verifier.node_hash_calls,
            hash_counts_total.leaf_hash_calls,
            hash_counts_total.node_hash_calls,
        )
    }
}

pub fn hex_prefixed(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for &byte in bytes {
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0f) as usize] as char);
    }
    out
}

struct BlobWriter {
    bytes: Vec<u8>,
    digest_bytes: usize,
}

impl BlobWriter {
    fn new(digest_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            digest_bytes: clamp_effective_digest_bytes(digest_bytes),
        }
    }

    fn pos(&self) -> usize {
        self.bytes.len()
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn write_len(&mut self, value: usize) {
        encode_varuint(value, &mut self.bytes);
    }

    fn write_val(&mut self, value: Val) {
        self.bytes
            .extend_from_slice(&value.as_canonical_u32().to_be_bytes());
    }

    fn write_challenge<EF>(&mut self, value: EF)
    where
        EF: BasedVectorSpace<Val> + Copy,
    {
        for &limb in value.as_basis_coefficients_slice() {
            self.write_val(limb);
        }
    }

    fn write_challenge_marked<EF>(&mut self, value: EF, marker: &mut Option<usize>)
    where
        EF: BasedVectorSpace<Val> + Copy,
    {
        if marker.is_none() {
            *marker = Some(self.pos());
        }
        self.write_challenge(value);
    }

    fn write_digest(&mut self, digest: &[u64; KECCAK_DIGEST_ELEMS]) {
        let bytes32 = digest_u64_to_bytes32(digest);
        self.bytes
            .extend_from_slice(&bytes32[..self.digest_bytes]);
    }

    fn write_option<T, W>(&mut self, value: &Option<T>, mut write_some: W)
    where
        W: FnMut(&mut BlobWriter, &T),
    {
        match value {
            None => self.write_u8(0),
            Some(inner) => {
                self.write_u8(1);
                write_some(self, inner);
            }
        }
    }
}

struct BlobReader<'a> {
    bytes: &'a [u8],
    pos: usize,
    digest_bytes: usize,
}

impl<'a> BlobReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            digest_bytes: 32,
        }
    }

    fn set_digest_bytes(&mut self, digest_bytes: usize) {
        self.digest_bytes = clamp_effective_digest_bytes(digest_bytes);
    }

    fn is_eof(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn read_exact<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        if self.pos + N > self.bytes.len() {
            return Err(DecodeError::new("unexpected end of input"));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.bytes[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    fn read_u8(&mut self) -> Result<u8, DecodeError> {
        if self.pos >= self.bytes.len() {
            return Err(DecodeError::new("unexpected end of input"));
        }
        let out = self.bytes[self.pos];
        self.pos += 1;
        Ok(out)
    }

    fn read_len(&mut self) -> Result<usize, DecodeError> {
        let start = self.pos;

        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            if shift >= 64 {
                return Err(DecodeError::new("varuint overflow"));
            }

            let byte = self.read_u8()?;
            let payload = (byte & 0x7f) as u64;
            result |= payload << shift;

            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }

        if result > usize::MAX as u64 {
            return Err(DecodeError::new("length does not fit in usize"));
        }
        let value = result as usize;

        let mut canonical = Vec::new();
        encode_varuint(value, &mut canonical);
        if self.bytes[start..self.pos] != canonical {
            return Err(DecodeError::new("non-canonical varuint encoding"));
        }

        Ok(value)
    }

    fn read_val(&mut self) -> Result<Val, DecodeError> {
        let bytes = self.read_exact::<4>()?;
        Ok(Val::from_u32(u32::from_be_bytes(bytes)))
    }

    fn read_challenge(&mut self) -> Result<Challenge, DecodeError> {
        let mut limbs = [Val::ZERO; EXTENSION_LIMBS];
        for limb in &mut limbs {
            *limb = self.read_val()?;
        }
        Ok(Challenge::from_basis_coefficients_fn(|idx| limbs[idx]))
    }

    fn read_digest(&mut self) -> Result<[u64; KECCAK_DIGEST_ELEMS], DecodeError> {
        if self.pos + self.digest_bytes > self.bytes.len() {
            return Err(DecodeError::new("unexpected end of input"));
        }
        let mut bytes32 = [0u8; 32];
        bytes32[..self.digest_bytes]
            .copy_from_slice(&self.bytes[self.pos..self.pos + self.digest_bytes]);
        self.pos += self.digest_bytes;
        Ok(digest_bytes32_to_u64(&bytes32))
    }

    fn read_option<T, R>(&mut self, mut read_some: R) -> Result<Option<T>, DecodeError>
    where
        R: FnMut(&mut BlobReader<'_>) -> Result<T, DecodeError>,
    {
        match self.read_u8()? {
            0 => Ok(None),
            1 => read_some(self).map(Some),
            _ => Err(DecodeError::new("unknown option tag")),
        }
    }
}

fn encode_varuint(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

fn abi_encode_single_bytes(bytes: &[u8]) -> Vec<u8> {
    let padded_len = pad32(bytes.len());
    let mut out = Vec::with_capacity(64 + padded_len);
    out.extend_from_slice(&encode_abi_word_usize(32));
    out.extend_from_slice(&encode_abi_word_usize(bytes.len()));
    out.extend_from_slice(bytes);
    out.resize(64 + padded_len, 0);
    out
}

fn decode_abi_word_usize(word: &[u8]) -> Result<usize, DecodeError> {
    if word.len() != 32 {
        return Err(DecodeError::new("invalid ABI word length"));
    }
    if word[..24].iter().any(|&byte| byte != 0) {
        return Err(DecodeError::new("ABI word exceeds usize range"));
    }
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&word[24..]);
    let value_u64 = u64::from_be_bytes(tail);
    usize::try_from(value_u64).map_err(|_| DecodeError::new("ABI word does not fit in usize"))
}

fn encode_abi_word_usize(value: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&(value as u64).to_be_bytes());
    out
}

const fn pad32(len: usize) -> usize {
    let rem = len % 32;
    if rem == 0 { len } else { len + (32 - rem) }
}
