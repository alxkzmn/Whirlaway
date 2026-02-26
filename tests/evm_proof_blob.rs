use air::AirSettings;
use p3_field::PrimeCharacteristicRing;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use sha3::Digest;
use whir_p3::parameters::{FoldingFactor, errors::SecurityAssumption};
use whir_p3::poly::evals::EvaluationsList;
use whir_p3::whir::proof::{QueryBatchOpening, SumcheckData};
use whirlaway::circuits::keccak256::{EF, F, Keccak256Circuit, Keccak256Input};
use whirlaway::evm_codec;
use whirlaway::hashers::{KECCAK_DIGEST_ELEMS, effective_digest_bytes_for_security_bits};
use whirlaway::proving_system::{self, KeccakProvingSystemConfig, Prepared};

use evm_codec::{
    count_merkle_digests_in_proof, decode_proof_blob_v1, decode_proof_blob_v1_with_context,
    decode_proof_blob_v3_with_context, decode_verify_bytes_calldata, derive_v2_decode_context,
    derive_v3_decode_context_with_digest_bytes, encode_calldata_verify_bytes, encode_proof_blob_v1,
    encode_proof_blob_v2, encode_proof_blob_v2_with_offsets, encode_proof_blob_v3,
    render_json_payload, verify_bytes_selector,
};

type PreparedKeccak =
    Prepared<Keccak256Circuit<EF>, KeccakProvingSystemConfig<EF>, F, EF, { KECCAK_DIGEST_ELEMS }>;
type KeccakProof = proving_system::Proof<Keccak256Circuit<EF>, F, EF, { KECCAK_DIGEST_ELEMS }>;

struct Fixture {
    prepared: PreparedKeccak,
    proof: KeccakProof,
    public_values: Vec<F>,
}

fn message_len_for_log_length(log_n_rows: usize) -> usize {
    use keccak_air::{NUM_ROUNDS, RATE_BYTES};

    let target_rows = 1usize << log_n_rows;
    let mut num_blocks_max = target_rows / NUM_ROUNDS;
    if num_blocks_max == 0 {
        num_blocks_max = 1;
    }

    let min_rows = (target_rows / 2).saturating_add(1);
    let num_blocks_min = min_rows.div_ceil(NUM_ROUNDS);

    let num_blocks = if num_blocks_max * NUM_ROUNDS <= target_rows / 2 {
        num_blocks_min.max(1)
    } else {
        num_blocks_max
    };

    num_blocks * RATE_BYTES - 2
}

fn settings(security_bits: usize) -> AirSettings {
    AirSettings::new(
        security_bits,
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(4, 4),
        1,
        1,
        4,
    )
}

fn build_fixture_with_security_bits(security_bits: usize) -> Fixture {
    let message_len = message_len_for_log_length(6);
    let mut rng = StdRng::seed_from_u64(0);
    let message: Vec<u8> = (0..message_len).map(|_| rng.random()).collect();
    let expected_digest: [u8; 32] = sha3::Keccak256::digest(&message).into();
    let input = Keccak256Input {
        message,
        expected_digest,
    };

    let config = KeccakProvingSystemConfig::<EF>::new(settings(security_bits));
    let prepared = proving_system::prepare(&config, Keccak256Circuit::new(message_len));
    let public_values = Keccak256Circuit::<EF>::public_values(&prepared.circuit, &input);
    let proof = proving_system::prove(&prepared, &input);
    proving_system::verify(&prepared, &proof, &public_values).unwrap();

    Fixture {
        prepared,
        proof,
        public_values,
    }
}

fn build_fixture() -> Fixture {
    build_fixture_with_security_bits(128)
}

fn decode_and_verify(
    fixture: &Fixture,
    blob: &[u8],
) -> Result<evm_codec::DecodedProofBlob, String> {
    let context = derive_v2_decode_context(&fixture.proof).map_err(|err| err.to_string())?;
    let decoded =
        decode_proof_blob_v1_with_context(blob, Some(&context)).map_err(|err| err.to_string())?;
    proving_system::verify(&fixture.prepared, &decoded.proof, &decoded.public_values)
        .map_err(|err| format!("verification failed: {err}"))?;
    Ok(decoded)
}

#[test]
fn proof_blob_roundtrip_and_strictness() {
    let fixture = build_fixture();

    let blob_a = encode_proof_blob_v2(&fixture.public_values, &fixture.proof);
    let blob_b = encode_proof_blob_v2(&fixture.public_values, &fixture.proof);
    assert_eq!(blob_a, blob_b, "encoding must be deterministic");

    let decoded = decode_and_verify(&fixture, &blob_a).expect("roundtrip decode+verify failed");
    assert_eq!(decoded.public_values, fixture.public_values);

    let mut trailing = blob_a.clone();
    trailing.push(0u8);
    let context =
        derive_v2_decode_context(&fixture.proof).expect("shape context derivation failed");
    assert!(
        decode_proof_blob_v1_with_context(&trailing, Some(&context)).is_err(),
        "decoder must reject trailing bytes"
    );

    // Replace canonical public_values_len = 16 (`0x10`) with non-canonical ULEB128 (`0x90 0x00`).
    let mut noncanonical = Vec::with_capacity(blob_a.len() + 1);
    noncanonical.extend_from_slice(&blob_a[..5]);
    noncanonical.extend_from_slice(&[0x90, 0x00]);
    noncanonical.extend_from_slice(&blob_a[6..]);
    assert!(
        decode_proof_blob_v1_with_context(&noncanonical, Some(&context)).is_err(),
        "decoder must reject non-canonical varuints"
    );
}

#[test]
fn calldata_and_json_mode_contract() {
    let fixture = build_fixture();

    let blob = encode_proof_blob_v2(&fixture.public_values, &fixture.proof);
    let calldata = encode_calldata_verify_bytes(&blob);

    assert_eq!(&calldata[..4], &verify_bytes_selector());

    let decoded_blob = decode_verify_bytes_calldata(&calldata).expect("invalid calldata encoding");
    assert_eq!(
        decoded_blob, blob,
        "calldata bytes arg must equal proof blob"
    );

    let json = render_json_payload(&blob, &calldata, false);
    assert!(json.contains("\"schema\":\"p3-whirlaway-evm-proof-v2\""));
    assert!(json.contains("\"verify_function\":\"verify(bytes)\""));
    assert!(json.contains(&format!(
        "\"keccak_mode\":\"{}\"",
        evm_codec::keccak_mode_label()
    )));
    assert!(json.contains("\"hash_counts_prover\":"));
    assert!(json.contains("\"hash_counts_verifier\":"));
    assert!(json.contains("\"hash_counts_total\":"));
    assert!(json.contains(&format!("\"proof_bytes_len\":{}", blob.len())));
    assert!(json.contains(&format!("\"calldata_len\":{}", calldata.len())));
}

#[test]
fn tampering_representative_fields_breaks_verification() {
    let fixture = build_fixture();
    let (blob, offsets) = encode_proof_blob_v2_with_offsets(&fixture.public_values, &fixture.proof);

    let targets = vec![
        ("commitment", offsets.commitment_offset),
        (
            "initial_ood_answer",
            offsets.first_initial_ood_answer_offset,
        ),
        ("sumcheck_coeff", offsets.first_sumcheck_coeff_offset),
        ("merkle_sibling", offsets.first_merkle_sibling_offset),
        ("final_poly", offsets.first_final_poly_offset),
        ("proof_data", offsets.first_proof_data_offset),
    ];

    for (name, maybe_offset) in targets {
        let offset = maybe_offset.unwrap_or_else(|| panic!("missing offset for {name}"));
        assert!(offset < blob.len(), "offset for {name} out of bounds");

        let mut tampered = blob.clone();
        tampered[offset] ^= 1;

        let context =
            derive_v2_decode_context(&fixture.proof).expect("shape context derivation failed");
        match decode_proof_blob_v1_with_context(&tampered, Some(&context)) {
            Ok(decoded) => {
                let ok = proving_system::verify(
                    &fixture.prepared,
                    &decoded.proof,
                    &decoded.public_values,
                )
                .is_ok();
                assert!(!ok, "tampering in {name} unexpectedly still verifies");
            }
            Err(_) => {
                // Strict decoder rejection is acceptable for tampered payloads.
            }
        }
    }
}

#[test]
fn option_roundtrip_stability_for_present_and_absent_sections() {
    let fixture = build_fixture();

    let mut with_options = fixture.proof.clone();
    if with_options.whir_proof.final_poly.is_none() {
        with_options.whir_proof.final_poly = Some(EvaluationsList::new(vec![EF::ZERO, EF::ONE]));
    }
    if with_options.whir_proof.final_sumcheck.is_none() {
        with_options.whir_proof.final_sumcheck = Some(SumcheckData {
            polynomial_evaluations: vec![[EF::ZERO, EF::ONE]],
            pow_witnesses: vec![F::ZERO],
        });
    }

    let with_options_blob = encode_proof_blob_v2(&fixture.public_values, &with_options);
    let with_options_context =
        derive_v2_decode_context(&with_options).expect("shape context derivation failed");
    let with_options_decoded =
        decode_proof_blob_v1_with_context(&with_options_blob, Some(&with_options_context))
            .expect("decode with options failed");
    assert!(with_options_decoded.proof.whir_proof.final_poly.is_some());
    assert!(
        with_options_decoded
            .proof
            .whir_proof
            .final_sumcheck
            .is_some()
    );
    let with_options_reencoded = encode_proof_blob_v2(
        &with_options_decoded.public_values,
        &with_options_decoded.proof,
    );
    assert_eq!(with_options_reencoded, with_options_blob);

    let mut without_options = fixture.proof.clone();
    without_options.whir_proof.final_poly = None;
    without_options.whir_proof.final_sumcheck = None;
    let without_options_blob = encode_proof_blob_v2(&fixture.public_values, &without_options);
    let without_options_context =
        derive_v2_decode_context(&without_options).expect("shape context derivation failed");
    let without_options_decoded =
        decode_proof_blob_v1_with_context(&without_options_blob, Some(&without_options_context))
            .expect("decode without options failed");
    assert!(
        without_options_decoded
            .proof
            .whir_proof
            .final_poly
            .is_none()
    );
    assert!(
        without_options_decoded
            .proof
            .whir_proof
            .final_sumcheck
            .is_none()
    );
    let without_options_reencoded = encode_proof_blob_v2(
        &without_options_decoded.public_values,
        &without_options_decoded.proof,
    );
    assert_eq!(without_options_reencoded, without_options_blob);
}

#[test]
fn verify_rejects_trailing_proof_data() {
    let fixture = build_fixture();
    let mut tampered = fixture.proof.clone();
    tampered.proof_data.push(EF::ZERO);

    let err = proving_system::verify(&fixture.prepared, &tampered, &fixture.public_values)
        .expect_err("verification should fail with trailing proof_data");
    assert!(err.contains("trailing proof_data"));
}

#[test]
fn v1_legacy_blob_decodes_and_verifies() {
    let fixture = build_fixture();
    let blob = encode_proof_blob_v1(&fixture.public_values, &fixture.proof);
    let decoded = decode_proof_blob_v1(&blob).expect("v1 blob should decode without context");
    proving_system::verify(&fixture.prepared, &decoded.proof, &decoded.public_values)
        .expect("v1 decoded proof should verify");
}

#[test]
fn v2_compact_blob_is_smaller_than_v1_for_fixture() {
    let fixture = build_fixture();
    let blob_v2 = encode_proof_blob_v2(&fixture.public_values, &fixture.proof);
    let blob_v1 = encode_proof_blob_v1(&fixture.public_values, &fixture.proof);
    assert!(
        blob_v2.len() < blob_v1.len(),
        "expected v2 blob ({}) to be smaller than v1 ({})",
        blob_v2.len(),
        blob_v1.len()
    );

    let calldata_v2 = encode_calldata_verify_bytes(&blob_v2);
    let calldata_v1 = encode_calldata_verify_bytes(&blob_v1);
    assert!(
        calldata_v2.len() <= calldata_v1.len(),
        "expected v2 calldata ({}) to be no larger than v1 ({})",
        calldata_v2.len(),
        calldata_v1.len()
    );
}

#[test]
fn v3_truncated_blob_roundtrip_and_size_delta_for_100() {
    let fixture = build_fixture_with_security_bits(100);
    let digest_bytes = effective_digest_bytes_for_security_bits(100);

    let blob_v2 = encode_proof_blob_v2(&fixture.public_values, &fixture.proof);
    let blob_v3 = encode_proof_blob_v3(&fixture.public_values, &fixture.proof, digest_bytes);
    assert!(
        blob_v3.len() < blob_v2.len(),
        "expected v3 blob ({}) to be smaller than v2 ({})",
        blob_v3.len(),
        blob_v2.len()
    );

    let calldata_v2 = encode_calldata_verify_bytes(&blob_v2);
    let calldata_v3 = encode_calldata_verify_bytes(&blob_v3);
    assert!(
        calldata_v3.len() < calldata_v2.len(),
        "expected v3 calldata ({}) to be smaller than v2 ({})",
        calldata_v3.len(),
        calldata_v2.len()
    );

    let ctx = derive_v3_decode_context_with_digest_bytes(&fixture.proof, digest_bytes)
        .expect("v3 context derivation failed");
    let decoded = decode_proof_blob_v3_with_context(&blob_v3, &ctx).expect("v3 decode failed");
    proving_system::verify(&fixture.prepared, &decoded.proof, &decoded.public_values)
        .expect("v3 decoded proof should verify");

    let bad_ctx = derive_v3_decode_context_with_digest_bytes(&fixture.proof, 32)
        .expect("v3 context derivation failed");
    assert!(
        decode_proof_blob_v3_with_context(&blob_v3, &bad_ctx).is_err(),
        "v3 decode with wrong digest width context should fail"
    );
}

#[test]
fn v3_matches_v2_for_128() {
    let fixture = build_fixture();
    let digest_bytes = effective_digest_bytes_for_security_bits(128);
    assert_eq!(digest_bytes, 32);

    let blob_v2 = encode_proof_blob_v2(&fixture.public_values, &fixture.proof);
    let blob_v3 = encode_proof_blob_v3(&fixture.public_values, &fixture.proof, digest_bytes);
    assert_eq!(blob_v3.len(), blob_v2.len());

    let calldata_v2 = encode_calldata_verify_bytes(&blob_v2);
    let calldata_v3 = encode_calldata_verify_bytes(&blob_v3);
    assert_eq!(calldata_v3.len(), calldata_v2.len());
}

#[test]
fn merkle_digest_count_includes_final_query_batch() {
    let fixture = build_fixture();
    let mut proof = fixture.proof.clone();
    let baseline = count_merkle_digests_in_proof(&proof);

    let final_query_batch = proof
        .whir_proof
        .final_query_batch
        .as_mut()
        .expect("missing final query batch");
    match final_query_batch {
        QueryBatchOpening::Base { proof, .. } | QueryBatchOpening::Extension { proof, .. } => {
            proof.decommitments.push([0u64; KECCAK_DIGEST_ELEMS]);
        }
    }

    let bumped = count_merkle_digests_in_proof(&proof);
    assert_eq!(bumped, baseline + 1);
}
