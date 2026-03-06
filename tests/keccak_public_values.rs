use air::AirSettings;
use p3_field::PrimeCharacteristicRing;
use sha3::Digest;
use whir_p3::parameters::{FoldingFactor, errors::SecurityAssumption};
use whirlaway::circuits::keccak256::{EF, F, Keccak256Circuit, Keccak256Input};
use whirlaway::proving_system::{KeccakProvingSystemConfig, prepare, prove, verify};

#[test]
fn test_keccak_public_values_binding() {
    let message = b"keccak public input".to_vec();
    let circuit = Keccak256Circuit::new(message.len());
    let settings = AirSettings::new(
        64,
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(4, 4),
        1,
        1,
        4,
    );
    let config = KeccakProvingSystemConfig::<EF>::new(settings);

    let prepared = prepare(&config, circuit);
    let expected_digest: [u8; 32] = sha3::Keccak256::digest(&message).into();
    let input = Keccak256Input {
        message: message.clone(),
        expected_digest,
    };
    let public_values = Keccak256Circuit::<EF>::public_values(&prepared.circuit, &input);
    let proof = prove(&prepared, &input);

    verify(&prepared, &proof, &public_values).unwrap();

    let mut bad_public_values = public_values;
    bad_public_values[0] += F::ONE;
    assert!(verify(&prepared, &proof, &bad_public_values).is_err());
}
