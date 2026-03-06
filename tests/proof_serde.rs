use p3_field::PrimeCharacteristicRing;
use whirlaway::circuits::keccak256::{EF, F, Keccak256Circuit};
use whirlaway::hashers::KECCAK_DIGEST_ELEMS;
use whirlaway::proving_system::{self, Proof};

type KeccakProof = Proof<Keccak256Circuit, F, EF, { KECCAK_DIGEST_ELEMS }>;

#[test]
fn proof_bincode_roundtrip_synthetic() {
    let proof = KeccakProof {
        whir_proof: Default::default(),
        proof_data: vec![EF::ZERO, EF::ONE],
    };

    let bytes = bincode::serialize(&proof).expect("synthetic proof serialization should succeed");
    let decoded: KeccakProof =
        bincode::deserialize(&bytes).expect("synthetic proof deserialization should succeed");

    assert_eq!(decoded.proof_data, proof.proof_data);
    assert_eq!(proving_system::proof_size(&proof), bytes.len());
}
