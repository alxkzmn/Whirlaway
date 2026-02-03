use air::{AirSettings, table::AirTable};
use air_test_utils::*;
use p3_dft::Radix2Bowers;
use p3_field::{Field, PrimeCharacteristicRing};
use utils::fiat_shamir::{ProverState, VerifierState};
use utils::packed_multilinear;
use whir_p3::parameters::{FoldingFactor, errors::SecurityAssumption};
use whir_p3::{
    fiat_shamir::domain_separator::DomainSeparator,
    poly::multilinear::MultilinearPoint,
    whir::{
        committer::reader::CommitmentReader, committer::writer::CommitmentWriter,
        constraints::statement::EqStatement, parameters::WhirConfig, proof::WhirProof,
        prover::Prover, verifier::Verifier,
    },
};

type PF = <F as Field>::Packing;

fn create_pcs_settings() -> AirSettings {
    AirSettings::new(
        128,
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(4, 4),
        1,
        1,
        4,
    )
}
#[test]
fn test_pcs_commitment_creation() {
    let log_length = 3;
    let n_columns = 4;
    let witness = create_witness_columns(log_length, n_columns);

    let air = MockAir::new(n_columns);
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 1);

    let settings = create_pcs_settings();
    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut prover_state = ProverState::new(&domainsep, challenger);

    let committer = CommitmentWriter::new(&whir_params);
    let packed_pol = packed_multilinear(&witness);

    let dft = Radix2Bowers;

    let mut whir_proof = WhirProof::<F, EF, F, 8>::default();
    let _commitment = committer
        .commit::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            packed_pol,
        )
        .unwrap();

    // Commitment should be created successfully
    assert!(
        whir_proof
            .initial_commitment
            .iter()
            .any(|&word| word != F::ZERO)
    );
}

#[test]
fn test_pcs_commitment_parsing() {
    let log_length = 3;
    let n_columns = 4;
    let witness = create_witness_columns(log_length, n_columns);

    let air = MockAir::new(n_columns);
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 1);

    let settings = create_pcs_settings();
    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    let committer = CommitmentWriter::new(&whir_params);
    let packed_pol = packed_multilinear(&witness);

    let dft = Radix2Bowers;

    let mut whir_proof = WhirProof::<F, EF, F, 8>::default();
    committer
        .commit::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            packed_pol,
        )
        .unwrap();

    // Parse commitment on verifier side
    let mut verifier_state =
        VerifierState::new(&domainsep, prover_state.proof_data().to_vec(), challenger);
    let commitment_reader = CommitmentReader::new(&whir_params);

    let parsed_commitment =
        commitment_reader.parse_commitment::<F, 8>(&whir_proof, verifier_state.challenger_mut());

    // Should parse successfully
    assert_eq!(
        parsed_commitment.ood_statement.num_variables(),
        whir_params.num_variables
    );
}

#[test]
fn test_pcs_opening_proof() {
    let log_length = 3;
    let n_columns = 4;
    let witness = create_witness_columns(log_length, n_columns);

    let air = MockAir::new(n_columns);
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 1);

    let settings = create_pcs_settings();
    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    let committer = CommitmentWriter::new(&whir_params);
    let packed_pol = packed_multilinear(&witness);

    let dft = Radix2Bowers;

    let mut whir_proof = WhirProof::<F, EF, F, 8>::default();
    let packed_witness = committer
        .commit::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            packed_pol,
        )
        .unwrap();

    // Create opening proof for an actual evaluation of the committed packed witness.
    let prover = Prover(&whir_params);
    let num_vars = table.log_n_witness_columns() + log_length;
    let point: Vec<EF> = (0..num_vars)
        .map(|i| if i % 2 == 0 { EF::ZERO } else { EF::ONE })
        .collect();
    let value = packed_witness
        .polynomial
        .evaluate_hypercube_base::<EF>(&MultilinearPoint::new(point.clone()));

    let mut statement = EqStatement::<EF>::initialize(num_vars);
    statement.add_evaluated_constraint(MultilinearPoint::new(point.clone()), value);

    prover
        .prove::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            statement.clone(),
            packed_witness,
        )
        .unwrap();

    // Verify opening proof
    let proof_data = prover_state.proof_data().to_vec();
    let mut verifier_state = VerifierState::new(&domainsep, proof_data, challenger);
    let commitment_reader = CommitmentReader::new(&whir_params);
    let parsed_commitment =
        commitment_reader.parse_commitment::<F, 8>(&whir_proof, verifier_state.challenger_mut());
    let verifier = Verifier::new(&whir_params);
    verifier
        .verify::<PF, F, PF, 8>(
            &whir_proof,
            verifier_state.challenger_mut(),
            &parsed_commitment,
            statement,
        )
        .unwrap();
}

#[test]
fn test_pcs_invalid_opening() {
    let log_length = 3;
    let n_columns = 4;
    let witness = create_witness_columns(log_length, n_columns);

    let air = MockAir::new(n_columns);
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 1);

    let settings = create_pcs_settings();
    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    let committer = CommitmentWriter::new(&whir_params);
    let packed_pol = packed_multilinear(&witness);

    let dft = Radix2Bowers;

    let mut whir_proof = WhirProof::<F, EF, F, 8>::default();
    let packed_witness = committer
        .commit::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            packed_pol,
        )
        .unwrap();

    // Prove a correct opening...
    let prover = Prover(&whir_params);
    let num_vars = table.log_n_witness_columns() + log_length;
    let point: Vec<EF> = (0..num_vars)
        .map(|i| if i % 2 == 0 { EF::ONE } else { EF::ZERO })
        .collect();
    let correct_value = packed_witness
        .polynomial
        .evaluate_hypercube_base::<EF>(&MultilinearPoint::new(point.clone()));

    let mut statement = EqStatement::<EF>::initialize(num_vars);
    statement.add_evaluated_constraint(MultilinearPoint::new(point.clone()), correct_value);

    prover
        .prove::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            statement,
            packed_witness,
        )
        .unwrap();

    // ...but verify against a *wrong* value.
    let wrong_value = correct_value + EF::ONE;
    let mut wrong_statement = EqStatement::<EF>::initialize(num_vars);
    wrong_statement.add_evaluated_constraint(MultilinearPoint::new(point.clone()), wrong_value);

    let proof_data = prover_state.proof_data().to_vec();
    let mut verifier_state = VerifierState::new(&domainsep, proof_data, challenger);
    let commitment_reader = CommitmentReader::new(&whir_params);
    let parsed_commitment =
        commitment_reader.parse_commitment::<F, 8>(&whir_proof, verifier_state.challenger_mut());
    let verifier = Verifier::new(&whir_params);
    assert!(
        verifier
            .verify::<PF, F, PF, 8>(
                &whir_proof,
                verifier_state.challenger_mut(),
                &parsed_commitment,
                wrong_statement,
            )
            .is_err()
    );
}

#[test]
fn test_pcs_multiple_evaluations() {
    let log_length = 3;
    let n_columns = 4;
    let witness = create_witness_columns(log_length, n_columns);

    let air = MockAir::new(n_columns);
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 1);

    let settings = create_pcs_settings();
    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    let committer = CommitmentWriter::new(&whir_params);
    let packed_pol = packed_multilinear(&witness);

    let dft = Radix2Bowers;

    let mut whir_proof = WhirProof::<F, EF, F, 8>::default();
    let packed_witness = committer
        .commit::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            packed_pol,
        )
        .unwrap();

    // Create statement with multiple constraints, using correct evaluations.
    let prover = Prover(&whir_params);
    let num_vars = table.log_n_witness_columns() + log_length;
    let point1: Vec<EF> = (0..num_vars)
        .map(|i| if i % 2 == 0 { EF::ZERO } else { EF::ONE })
        .collect();
    let point2: Vec<EF> = (0..num_vars)
        .map(|i| if i % 3 == 0 { EF::ONE } else { EF::ZERO })
        .collect();
    let value1 = packed_witness
        .polynomial
        .evaluate_hypercube_base::<EF>(&MultilinearPoint::new(point1.clone()));
    let value2 = packed_witness
        .polynomial
        .evaluate_hypercube_base::<EF>(&MultilinearPoint::new(point2.clone()));

    let mut statement = EqStatement::<EF>::initialize(num_vars);
    statement.add_evaluated_constraint(MultilinearPoint::new(point1.clone()), value1);
    statement.add_evaluated_constraint(MultilinearPoint::new(point2.clone()), value2);

    prover
        .prove::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            statement.clone(),
            packed_witness,
        )
        .unwrap();

    let proof_data = prover_state.proof_data().to_vec();
    let mut verifier_state = VerifierState::new(&domainsep, proof_data, challenger);
    let commitment_reader = CommitmentReader::new(&whir_params);
    let parsed_commitment =
        commitment_reader.parse_commitment::<F, 8>(&whir_proof, verifier_state.challenger_mut());
    let verifier = Verifier::new(&whir_params);
    verifier
        .verify::<PF, F, PF, 8>(
            &whir_proof,
            verifier_state.challenger_mut(),
            &parsed_commitment,
            statement,
        )
        .unwrap();
}

#[test]
fn test_pcs_different_polynomial_sizes() {
    for log_length in [2, 3, 4, 5] {
        let n_columns = 4;
        let witness = create_witness_columns(log_length, n_columns);

        let air = MockAir::new(n_columns);
        let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 1);

        let settings = create_pcs_settings();
        let merkle_hash = setup_merkle_hash();
        let merkle_compress = setup_merkle_compress();

        let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
            table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

        let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
        domainsep.commit_statement::<_, _, _, 8>(&whir_params);
        domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

        let challenger = setup_challenger();
        let mut prover_state = ProverState::new(&domainsep, challenger.clone());

        let committer = CommitmentWriter::new(&whir_params);
        let packed_pol = packed_multilinear(&witness);

        let dft = Radix2Bowers;

        let mut whir_proof = WhirProof::<F, EF, F, 8>::default();
        let commitment = committer.commit::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            packed_pol,
        );

        // Should work for different sizes
        assert!(commitment.is_ok());
    }
}
