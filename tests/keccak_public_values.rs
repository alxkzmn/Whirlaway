use air::AirSettings;
use p3_field::PrimeCharacteristicRing;
use whir_p3::parameters::{FoldingFactor, errors::SecurityAssumption};
use whirlaway::circuits::keccak256::{F, Keccak256Circuit, Keccak256Input};
use whirlaway::hashers::KECCAK_DIGEST_ELEMS;
use whirlaway::proving_system::{Circuit, KeccakProvingSystemConfig, prepare, prove, verify};

#[test]
fn test_keccak_public_values_binding() {
    let message = b"keccak public input".to_vec();
    let circuit = Keccak256Circuit {
        input_size: message.len(),
    };
    let settings = AirSettings::new(
        64,
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(4, 4),
        1,
        1,
        4,
    );
    let config = KeccakProvingSystemConfig {
        air_settings: settings,
    };

    let prepared = prepare::<Keccak256Circuit, _, KECCAK_DIGEST_ELEMS>(&config, circuit);
    let (_trace, digest_limbs) =
        keccak_air::generate_sponge_trace_and_digest_limbs::<F>(&message);
    let input = Keccak256Input {
        message: message.clone(),
        digest_limbs,
    };
    let public_values = Keccak256Circuit::public_values(&prepared.circuit, &input);
    let proof = prove(&prepared, &input);

    verify(&prepared, &proof, &public_values).unwrap();

    let mut bad_public_values = public_values;
    bad_public_values[0] += F::ONE;
    assert!(verify(&prepared, &proof, &bad_public_values).is_err());
}
