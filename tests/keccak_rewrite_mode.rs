use air::AirSettings;
use p3_field::PrimeCharacteristicRing;
use sha3::Digest;
use whir_p3::parameters::{FoldingFactor, errors::SecurityAssumption};
use whirlaway::circuits::keccak256::{EF, F, Keccak256Circuit, Keccak256Input, KeccakMode};
use whirlaway::hashers::KECCAK_DIGEST_ELEMS;
use whirlaway::proving_system::{Circuit, KeccakProvingSystemConfig, prepare, prove, verify};

fn test_settings() -> AirSettings {
    AirSettings::new(
        64,
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(4, 4),
        1,
        1,
        4,
    )
}

fn deterministic_message(input_size: usize) -> Vec<u8> {
    (0..input_size).map(|i| (i % 251) as u8).collect()
}

fn run_roundtrip(input_size: usize, mode: KeccakMode) {
    let message = deterministic_message(input_size);
    let expected_digest: [u8; 32] = sha3::Keccak256::digest(&message).into();

    let settings = test_settings();
    let config = KeccakProvingSystemConfig::<EF>::new(settings.clone());
    let prepared = prepare(&config, Keccak256Circuit::new_with_mode(input_size, mode));

    let input = Keccak256Input {
        message,
        expected_digest,
    };
    let public_values = Keccak256Circuit::<EF>::public_values(&prepared.circuit, &input);
    let proof = prove(&prepared, &input);

    verify(&prepared, &proof, &public_values).unwrap();
}

#[test]
fn byte_mode_roundtrip_128() {
    run_roundtrip(128, KeccakMode::ByteSpongeAlgebraic);
}

#[test]
fn byte_mode_roundtrip_135() {
    run_roundtrip(135, KeccakMode::ByteSpongeAlgebraic);
}

#[test]
fn byte_mode_roundtrip_136() {
    run_roundtrip(136, KeccakMode::ByteSpongeAlgebraic);
}

#[test]
#[ignore = "long-running"]
fn byte_mode_roundtrip_1024() {
    run_roundtrip(1024, KeccakMode::ByteSpongeAlgebraic);
}

#[test]
#[ignore = "long-running"]
fn byte_mode_roundtrip_2048() {
    run_roundtrip(2048, KeccakMode::ByteSpongeAlgebraic);
}

#[test]
fn mode_metadata_widths_and_degree() {
    let settings = test_settings();

    let legacy = Keccak256Circuit::<EF>::new_with_mode(128, KeccakMode::LegacyBitSponge);
    let legacy_pp = legacy.preprocess(&settings);
    let legacy_table =
        <Keccak256Circuit<EF> as Circuit<F, EF, { KECCAK_DIGEST_ELEMS }>>::make_table(
            &legacy_pp, &settings,
        );
    assert_eq!(legacy_table.n_columns, 5326);
    assert_eq!(legacy_table.constraint_degree, 6);

    let byte = Keccak256Circuit::<EF>::new_with_mode(128, KeccakMode::ByteSpongeAlgebraic);
    let byte_pp = byte.preprocess(&settings);
    let byte_table = <Keccak256Circuit<EF> as Circuit<F, EF, { KECCAK_DIGEST_ELEMS }>>::make_table(
        &byte_pp, &settings,
    );
    assert_eq!(byte_table.n_columns, 2911);
    assert_eq!(byte_table.constraint_degree, 11);
}

#[test]
fn byte_mode_public_values_binding() {
    let input_size = 128;
    let message = deterministic_message(input_size);
    let expected_digest: [u8; 32] = sha3::Keccak256::digest(&message).into();

    let settings = test_settings();
    let config = KeccakProvingSystemConfig::<EF>::new(settings);
    let prepared = prepare(
        &config,
        Keccak256Circuit::<EF>::new_with_mode(input_size, KeccakMode::ByteSpongeAlgebraic),
    );

    let input = Keccak256Input {
        message,
        expected_digest,
    };
    let public_values = Keccak256Circuit::<EF>::public_values(&prepared.circuit, &input);
    let proof = prove(&prepared, &input);

    verify(&prepared, &proof, &public_values).unwrap();

    let mut bad_public_values = public_values;
    bad_public_values[0] += F::ONE;
    assert!(verify(&prepared, &proof, &bad_public_values).is_err());
}
