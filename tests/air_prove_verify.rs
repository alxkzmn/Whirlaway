use air::{AirSettings, table::AirTable};
use keccak_air::KeccakAir;
use p3_challenger::{DuplexChallenger, HashChallenger, SerializingChallenger32};
use p3_field::extension::BinomialExtensionField;
use p3_keccak::Keccak256Hash;
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_matrix::Matrix;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::{SeedableRng, rngs::StdRng};
use utils::fiat_shamir::{ProverState, VerifierState};
use whir_p3::parameters::{FoldingFactor, errors::SecurityAssumption};
use whir_p3::{fiat_shamir::domain_separator::DomainSeparator, whir::parameters::WhirConfig};
use whirlaway::hashers::{KECCAK_DIGEST_ELEMS, KeccakNodeCompress, KeccakU32BeLeafHasher};

type F = KoalaBear;
type EF = BinomialExtensionField<F, 8>;
type Poseidon16 = Poseidon2KoalaBear<16>;
type Poseidon24 = Poseidon2KoalaBear<24>;
type MerkleHash = PaddingFreeSponge<Poseidon24, 24, 16, 8>;
type MerkleCompress = TruncatedPermutation<Poseidon16, 2, 8, 16>;
type MyChallenger = DuplexChallenger<F, Poseidon16, 16, 8>;
type KeccakMerkleHash = KeccakU32BeLeafHasher;
type KeccakMerkleCompress = KeccakNodeCompress;
type KeccakChallenger = SerializingChallenger32<F, HashChallenger<u8, Keccak256Hash, 32>>;

fn create_keccak_witness_columns(
    num_hashes: usize,
) -> (
    KeccakAir,
    usize,
    Vec<whir_p3::poly::evals::EvaluationsList<F>>,
) {
    let air = KeccakAir {};
    let trace = air.generate_trace_rows::<F>(num_hashes, 0);
    let height = trace.height();
    let log_length = height.ilog2() as usize;
    assert_eq!(height, 1usize << log_length);

    let width = trace.width();
    let mut columns = Vec::with_capacity(width);
    for col in 0..width {
        let mut evals = Vec::with_capacity(height);
        for row in 0..height {
            evals.push(trace.values[row * width + col]);
        }
        columns.push(whir_p3::poly::evals::EvaluationsList::new(evals));
    }
    (air, log_length, columns)
}

fn setup_challenger() -> MyChallenger {
    let mut rng = StdRng::seed_from_u64(42);
    let poseidon = Poseidon16::new_from_rng_128(&mut rng);
    DuplexChallenger::new(poseidon)
}

fn setup_merkle_hash() -> MerkleHash {
    let mut rng = StdRng::seed_from_u64(789);
    let poseidon24 = Poseidon24::new_from_rng_128(&mut rng);
    MerkleHash::new(poseidon24)
}

fn setup_merkle_compress() -> MerkleCompress {
    let mut rng = StdRng::seed_from_u64(101);
    let poseidon16 = Poseidon16::new_from_rng_128(&mut rng);
    MerkleCompress::new(poseidon16)
}

fn setup_keccak_challenger() -> KeccakChallenger {
    KeccakChallenger::from_hasher(Vec::new(), Keccak256Hash)
}

fn setup_keccak_merkle_hash() -> KeccakMerkleHash {
    KeccakMerkleHash::default()
}

fn setup_keccak_merkle_compress() -> KeccakMerkleCompress {
    KeccakMerkleCompress::default()
}

#[test]
fn test_complete_air_prove_verify() {
    let (air, log_length, witness) = create_keccak_witness_columns(1);
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 4, 0);

    let settings = AirSettings::new(
        128,
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(4, 4),
        1,
        1,
        4,
    );

    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    // Prove
    let whir_proof = table.prove(
        &settings,
        merkle_hash.clone(),
        merkle_compress.clone(),
        &mut prover_state,
        &[],
        witness,
    );

    let proof_data = prover_state.proof_data().to_vec();
    assert!(!proof_data.is_empty());

    // Verify with a fresh domain separator/challenger
    let mut verify_domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    verify_domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    verify_domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);
    let mut verifier_state = VerifierState::new(&verify_domainsep, proof_data, setup_challenger());
    let result = table.verify(
        &settings,
        merkle_hash,
        merkle_compress,
        &mut verifier_state,
        &[],
        log_length,
        &whir_proof,
    );
    result.unwrap();
}

#[test]
fn test_complete_air_prove_verify_keccak_backend() {
    let (air, log_length, witness) = create_keccak_witness_columns(1);
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 4, 0);

    let settings = AirSettings::new(
        128,
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(4, 4),
        1,
        1,
        4,
    );

    let merkle_hash = setup_keccak_merkle_hash();
    let merkle_compress = setup_keccak_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, KeccakChallenger> =
        table.build_whir_params(&settings, merkle_hash, merkle_compress);

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, KECCAK_DIGEST_ELEMS>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, KECCAK_DIGEST_ELEMS>(&whir_params);

    let challenger = setup_keccak_challenger();
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    let whir_proof = table.prove(
        &settings,
        merkle_hash,
        merkle_compress,
        &mut prover_state,
        &[],
        witness,
    );

    let proof_data = prover_state.proof_data().to_vec();
    assert!(!proof_data.is_empty());

    let mut verify_domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    verify_domainsep.commit_statement::<_, _, _, KECCAK_DIGEST_ELEMS>(&whir_params);
    verify_domainsep.add_whir_proof::<_, _, _, KECCAK_DIGEST_ELEMS>(&whir_params);
    let mut verifier_state =
        VerifierState::new(&verify_domainsep, proof_data, setup_keccak_challenger());
    let result = table.verify(
        &settings,
        merkle_hash,
        merkle_compress,
        &mut verifier_state,
        &[],
        log_length,
        &whir_proof,
    );
    result.unwrap();
}

#[test]
fn test_air_prove_verify_with_preprocessed() {
    let (air, log_length, mut cols) = create_keccak_witness_columns(1);
    let preprocessed = cols.drain(..2).collect::<Vec<_>>();
    let witness = cols;
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, preprocessed, 4, 0);

    let settings = AirSettings::new(
        128,
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(4, 4),
        1,
        1,
        4,
    );

    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    let whir_proof = table.prove(
        &settings,
        merkle_hash.clone(),
        merkle_compress.clone(),
        &mut prover_state,
        &[],
        witness,
    );

    let proof_data = prover_state.proof_data().to_vec();
    let mut verify_domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    verify_domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    verify_domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);
    let mut verifier_state = VerifierState::new(&verify_domainsep, proof_data, setup_challenger());

    let result = table.verify(
        &settings,
        merkle_hash,
        merkle_compress,
        &mut verifier_state,
        &[],
        log_length,
        &whir_proof,
    );
    result.unwrap();
}

#[test]
fn test_air_prove_verify_different_settings() {
    let (air, log_length, witness) = create_keccak_witness_columns(1);
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 4, 0);

    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    for security_bits in [64, 128] {
        let settings = AirSettings::new(
            security_bits,
            SecurityAssumption::CapacityBound,
            FoldingFactor::ConstantFromSecondRound(4, 4),
            1,
            1,
            4,
        );

        let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
            table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

        let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
        domainsep.commit_statement::<_, _, _, 8>(&whir_params);
        domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

        let challenger = setup_challenger();
        let mut prover_state = ProverState::new(&domainsep, challenger.clone());

        let whir_proof = table.prove(
            &settings,
            merkle_hash.clone(),
            merkle_compress.clone(),
            &mut prover_state,
            &[],
            witness.clone(),
        );

        let proof_data = prover_state.proof_data().to_vec();
        let mut verify_domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
        verify_domainsep.commit_statement::<_, _, _, 8>(&whir_params);
        verify_domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);
        let mut verifier_state =
            VerifierState::new(&verify_domainsep, proof_data, setup_challenger());

        let result = table.verify(
            &settings,
            merkle_hash.clone(),
            merkle_compress.clone(),
            &mut verifier_state,
            &[],
            log_length,
            &whir_proof,
        );
        result.unwrap();
    }
}

#[test]
fn test_air_prove_verify_larger_table() {
    let (air, log_length, witness) = create_keccak_witness_columns(2);
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 4, 0);

    let settings = AirSettings::new(
        128,
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(4, 4),
        1,
        1,
        4,
    );

    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    let whir_proof = table.prove(
        &settings,
        merkle_hash.clone(),
        merkle_compress.clone(),
        &mut prover_state,
        &[],
        witness,
    );

    let proof_data = prover_state.proof_data().to_vec();
    assert!(!proof_data.is_empty());

    let mut verify_domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    verify_domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    verify_domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);
    let mut verifier_state = VerifierState::new(&verify_domainsep, proof_data, setup_challenger());
    let result = table.verify(
        &settings,
        merkle_hash,
        merkle_compress,
        &mut verifier_state,
        &[],
        log_length,
        &whir_proof,
    );
    result.unwrap();
}
