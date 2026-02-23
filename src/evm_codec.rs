use core::fmt;

use p3_field::PrimeCharacteristicRing;
use p3_field::{BasedVectorSpace, PrimeField32};
use p3_keccak::Keccak256Hash;
use p3_symmetric::CryptographicHasher;
use whir_p3::poly::evals::EvaluationsList;
use whir_p3::whir::proof::{QueryOpening, SumcheckData, WhirProof, WhirRoundProof};

use crate::circuits::keccak256::{Binomial8Challenge, F, Keccak256Circuit};
use crate::hashers::digest_bytes32_to_u64;
use crate::hashers::{KECCAK_DIGEST_ELEMS, digest_u64_to_bytes32};
use crate::proving_system::Proof as SystemProof;

pub const PROOF_BLOB_MAGIC: [u8; 4] = *b"WPK1";
pub const PROOF_BLOB_VERSION: u8 = 1;
pub const JSON_SCHEMA: &str = "p3-whirlaway-evm-proof-v1";
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
    encode_proof_blob_v1_with_offsets(public_values, proof).0
}

pub fn encode_proof_blob_v1_with_offsets(
    public_values: &[Val],
    proof: &KeccakProof,
) -> (Vec<u8>, ProofBlobOffsets) {
    let mut writer = BlobWriter::new();
    let mut offsets = ProofBlobOffsets::default();

    writer.write_bytes(&PROOF_BLOB_MAGIC);
    writer.write_u8(PROOF_BLOB_VERSION);

    writer.write_len(public_values.len());
    for &value in public_values {
        writer.write_val(value);
    }

    writer.write_len(proof.proof_data.len());
    for &value in &proof.proof_data {
        writer.write_challenge_marked(value, &mut offsets.first_proof_data_offset);
    }

    encode_whir_proof(&mut writer, &proof.whir_proof, &mut offsets);

    (writer.finish(), offsets)
}

fn encode_whir_proof(
    writer: &mut BlobWriter,
    proof: &WhirPcsProof,
    offsets: &mut ProofBlobOffsets,
) {
    offsets.commitment_offset = Some(writer.pos());
    writer.write_digest(&proof.initial_commitment);

    writer.write_len(proof.initial_ood_answers.len());
    for &answer in &proof.initial_ood_answers {
        writer.write_challenge_marked(answer, &mut offsets.first_initial_ood_answer_offset);
    }

    encode_whir_sumcheck(writer, &proof.initial_sumcheck, offsets);

    writer.write_len(proof.rounds.len());
    for round in &proof.rounds {
        encode_whir_round(writer, round, offsets);
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

    writer.write_len(proof.final_queries.len());
    for query in &proof.final_queries {
        encode_query_opening(writer, query, offsets);
    }

    writer.write_option(&proof.final_sumcheck, |writer, sumcheck| {
        encode_whir_sumcheck(writer, sumcheck, offsets);
    });
}

fn encode_whir_round(
    writer: &mut BlobWriter,
    round: &WhirRoundProof<Val, Challenge, u64, KECCAK_DIGEST_ELEMS>,
    offsets: &mut ProofBlobOffsets,
) {
    writer.write_digest(&round.commitment);

    writer.write_len(round.ood_answers.len());
    for &answer in &round.ood_answers {
        writer.write_challenge_marked(answer, &mut offsets.first_initial_ood_answer_offset);
    }

    writer.write_val(round.pow_witness);

    writer.write_len(round.queries.len());
    for query in &round.queries {
        encode_query_opening(writer, query, offsets);
    }

    encode_whir_sumcheck(writer, &round.sumcheck, offsets);
}

fn encode_whir_sumcheck(
    writer: &mut BlobWriter,
    sumcheck: &SumcheckData<Val, Challenge>,
    offsets: &mut ProofBlobOffsets,
) {
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

fn encode_query_opening(
    writer: &mut BlobWriter,
    query: &QueryOpening<Val, Challenge, u64, KECCAK_DIGEST_ELEMS>,
    offsets: &mut ProofBlobOffsets,
) {
    match query {
        QueryOpening::Base { values, proof } => {
            writer.write_u8(0);
            writer.write_len(values.len());
            for &value in values {
                writer.write_val(value);
            }
            writer.write_len(proof.len());
            for sibling in proof {
                if offsets.first_merkle_sibling_offset.is_none() {
                    offsets.first_merkle_sibling_offset = Some(writer.pos());
                }
                writer.write_digest(sibling);
            }
        }
        QueryOpening::Extension { values, proof } => {
            writer.write_u8(1);
            writer.write_len(values.len());
            for &value in values {
                writer.write_challenge(value);
            }
            writer.write_len(proof.len());
            for sibling in proof {
                if offsets.first_merkle_sibling_offset.is_none() {
                    offsets.first_merkle_sibling_offset = Some(writer.pos());
                }
                writer.write_digest(sibling);
            }
        }
    }
}

pub fn decode_proof_blob_v1(bytes: &[u8]) -> Result<DecodedProofBlob, DecodeError> {
    let mut reader = BlobReader::new(bytes);

    let magic = reader.read_exact::<4>()?;
    if magic != PROOF_BLOB_MAGIC {
        return Err(DecodeError::new("invalid proof blob magic"));
    }

    let version = reader.read_u8()?;
    if version != PROOF_BLOB_VERSION {
        return Err(DecodeError::new("unsupported proof blob version"));
    }

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

    let whir_proof = decode_whir_proof(&mut reader)?;
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

fn decode_whir_proof(reader: &mut BlobReader<'_>) -> Result<WhirPcsProof, DecodeError> {
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
        rounds.push(decode_whir_round(reader)?);
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

    let n_final_queries = reader.read_len()?;
    let mut final_queries = Vec::with_capacity(n_final_queries);
    for _ in 0..n_final_queries {
        final_queries.push(decode_query_opening(reader)?);
    }

    let final_sumcheck = reader.read_option(decode_whir_sumcheck)?;

    Ok(WhirPcsProof {
        initial_commitment,
        initial_ood_answers,
        initial_sumcheck,
        rounds,
        final_poly,
        final_pow_witness,
        final_queries,
        final_sumcheck,
    })
}

fn decode_whir_round(
    reader: &mut BlobReader<'_>,
) -> Result<WhirRoundProof<Val, Challenge, u64, KECCAK_DIGEST_ELEMS>, DecodeError> {
    let commitment = reader.read_digest()?;

    let n_ood_answers = reader.read_len()?;
    let mut ood_answers = Vec::with_capacity(n_ood_answers);
    for _ in 0..n_ood_answers {
        ood_answers.push(reader.read_challenge()?);
    }

    let pow_witness = reader.read_val()?;

    let n_queries = reader.read_len()?;
    let mut queries = Vec::with_capacity(n_queries);
    for _ in 0..n_queries {
        queries.push(decode_query_opening(reader)?);
    }

    let sumcheck = decode_whir_sumcheck(reader)?;

    Ok(WhirRoundProof {
        commitment,
        ood_answers,
        pow_witness,
        queries,
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

fn decode_query_opening(
    reader: &mut BlobReader<'_>,
) -> Result<QueryOpening<Val, Challenge, u64, KECCAK_DIGEST_ELEMS>, DecodeError> {
    let tag = reader.read_u8()?;
    match tag {
        0 => {
            let n_values = reader.read_len()?;
            let mut values = Vec::with_capacity(n_values);
            for _ in 0..n_values {
                values.push(reader.read_val()?);
            }
            let n_siblings = reader.read_len()?;
            let mut proof = Vec::with_capacity(n_siblings);
            for _ in 0..n_siblings {
                proof.push(reader.read_digest()?);
            }
            Ok(QueryOpening::Base { values, proof })
        }
        1 => {
            let n_values = reader.read_len()?;
            let mut values = Vec::with_capacity(n_values);
            for _ in 0..n_values {
                values.push(reader.read_challenge()?);
            }
            let n_siblings = reader.read_len()?;
            let mut proof = Vec::with_capacity(n_siblings);
            for _ in 0..n_siblings {
                proof.push(reader.read_digest()?);
            }
            Ok(QueryOpening::Extension { values, proof })
        }
        _ => Err(DecodeError::new("unknown query opening tag")),
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

pub fn render_json_payload(proof_blob: &[u8], calldata: &[u8], pretty: bool) -> String {
    let selector = verify_bytes_selector();
    let selector_hex = hex_prefixed(&selector);
    let proof_hex = hex_prefixed(proof_blob);
    let calldata_hex = hex_prefixed(calldata);

    if pretty {
        format!(
            "{{\n  \"schema\": \"{}\",\n  \"verify_function\": \"{}\",\n  \"selector\": \"{}\",\n  \"proof_bytes\": \"{}\",\n  \"proof_bytes_len\": {},\n  \"calldata\": \"{}\",\n  \"calldata_len\": {}\n}}\n",
            JSON_SCHEMA,
            VERIFY_FUNCTION,
            selector_hex,
            proof_hex,
            proof_blob.len(),
            calldata_hex,
            calldata.len(),
        )
    } else {
        format!(
            "{{\"schema\":\"{}\",\"verify_function\":\"{}\",\"selector\":\"{}\",\"proof_bytes\":\"{}\",\"proof_bytes_len\":{},\"calldata\":\"{}\",\"calldata_len\":{}}}",
            JSON_SCHEMA,
            VERIFY_FUNCTION,
            selector_hex,
            proof_hex,
            proof_blob.len(),
            calldata_hex,
            calldata.len(),
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
}

impl BlobWriter {
    fn new() -> Self {
        Self { bytes: Vec::new() }
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

    fn write_challenge(&mut self, value: Challenge) {
        for limb in Challenge::flatten_to_base(vec![value]) {
            self.write_val(limb);
        }
    }

    fn write_challenge_marked(&mut self, value: Challenge, marker: &mut Option<usize>) {
        if marker.is_none() {
            *marker = Some(self.pos());
        }
        self.write_challenge(value);
    }

    fn write_digest(&mut self, digest: &[u64; KECCAK_DIGEST_ELEMS]) {
        let bytes32 = digest_u64_to_bytes32(digest);
        self.bytes.extend_from_slice(&bytes32);
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
}

impl<'a> BlobReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
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
        let bytes32 = self.read_exact::<32>()?;
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
