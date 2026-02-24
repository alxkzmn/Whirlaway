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
        committer::reader::CommitmentReader,
        committer::writer::CommitmentWriter,
        constraints::statement::EqStatement,
        parameters::{SumcheckStrategy, WhirConfig},
        proof::WhirProof,
        prover::Prover,
        verifier::Verifier,
    },
};

type PF = <F as Field>::Packing;

const fn create_pcs_settings() -> AirSettings {
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
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 1, 0);

    let settings = create_pcs_settings();
    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash, merkle_compress);

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut prover_state = ProverState::new(&domainsep, challenger);

    let committer = CommitmentWriter::new(&whir_params);
    let packed_pol = packed_multilinear(&witness);
    let mut statement = whir_params.initial_statement(packed_pol, SumcheckStrategy::Classic);

    let dft = Radix2Bowers;

    let mut whir_proof = WhirProof::<F, EF, F, 8>::default();
    committer
        .commit::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            &mut statement,
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
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 1, 0);

    let settings = create_pcs_settings();
    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash, merkle_compress);

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    let committer = CommitmentWriter::new(&whir_params);
    let packed_pol = packed_multilinear(&witness);
    let mut statement = whir_params.initial_statement(packed_pol, SumcheckStrategy::Classic);

    let dft = Radix2Bowers;

    let mut whir_proof = WhirProof::<F, EF, F, 8>::default();
    committer
        .commit::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            &mut statement,
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
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 1, 0);

    let settings = create_pcs_settings();
    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash, merkle_compress);

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    let committer = CommitmentWriter::new(&whir_params);
    let packed_pol = packed_multilinear(&witness);

    let dft = Radix2Bowers;
    let num_vars = table.log_n_witness_columns() + log_length;
    let point: Vec<EF> = (0..num_vars)
        .map(|i| if i % 2 == 0 { EF::ZERO } else { EF::ONE })
        .collect();
    let point = MultilinearPoint::new(point);

    let mut initial_statement =
        whir_params.initial_statement(packed_pol, SumcheckStrategy::Classic);
    let _value = initial_statement.evaluate(&point);
    let verifier_statement = initial_statement.normalize();

    let mut whir_proof = WhirProof::<F, EF, F, 8>::default();
    let prover_data = committer
        .commit::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            &mut initial_statement,
        )
        .unwrap();

    // Create opening proof.
    let prover = Prover(&whir_params);
    prover
        .prove::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            &initial_statement,
            prover_data,
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
            verifier_statement,
        )
        .unwrap();
}

#[test]
fn test_pcs_invalid_opening() {
    let log_length = 3;
    let n_columns = 4;
    let witness = create_witness_columns(log_length, n_columns);

    let air = MockAir::new(n_columns);
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 1, 0);

    let settings = create_pcs_settings();
    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash, merkle_compress);

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    let committer = CommitmentWriter::new(&whir_params);
    let packed_pol = packed_multilinear(&witness);

    let dft = Radix2Bowers;
    let num_vars = table.log_n_witness_columns() + log_length;
    let point = MultilinearPoint::new(
        (0..num_vars)
            .map(|i| if i % 2 == 0 { EF::ONE } else { EF::ZERO })
            .collect(),
    );

    let mut initial_statement =
        whir_params.initial_statement(packed_pol, SumcheckStrategy::Classic);
    let correct_value = initial_statement.evaluate(&point);

    let mut whir_proof = WhirProof::<F, EF, F, 8>::default();
    let prover_data = committer
        .commit::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            &mut initial_statement,
        )
        .unwrap();

    // Prove a correct opening...
    let prover = Prover(&whir_params);
    prover
        .prove::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            &initial_statement,
            prover_data,
        )
        .unwrap();

    // ...but verify against a *wrong* value.
    let wrong_value = correct_value + EF::ONE;
    let mut wrong_statement = EqStatement::<EF>::initialize(num_vars);
    wrong_statement.add_evaluated_constraint(point, wrong_value);

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
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 1, 0);

    let settings = create_pcs_settings();
    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash, merkle_compress);

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    let committer = CommitmentWriter::new(&whir_params);
    let packed_pol = packed_multilinear(&witness);

    let dft = Radix2Bowers;
    let num_vars = table.log_n_witness_columns() + log_length;
    let point1 = MultilinearPoint::new(
        (0..num_vars)
            .map(|i| if i % 2 == 0 { EF::ZERO } else { EF::ONE })
            .collect(),
    );
    let point2 = MultilinearPoint::new(
        (0..num_vars)
            .map(|i| if i % 3 == 0 { EF::ONE } else { EF::ZERO })
            .collect(),
    );
    let mut initial_statement =
        whir_params.initial_statement(packed_pol, SumcheckStrategy::Classic);
    let _ = initial_statement.evaluate(&point1);
    let _ = initial_statement.evaluate(&point2);
    let verifier_statement = initial_statement.normalize();

    let mut whir_proof = WhirProof::<F, EF, F, 8>::default();
    let prover_data = committer
        .commit::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            &mut initial_statement,
        )
        .unwrap();

    // Prove multiple opening constraints.
    let prover = Prover(&whir_params);
    prover
        .prove::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            &initial_statement,
            prover_data,
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
            verifier_statement,
        )
        .unwrap();
}

#[test]
fn test_pcs_different_polynomial_sizes() {
    for log_length in [2, 3, 4, 5] {
        let n_columns = 4;
        let witness = create_witness_columns(log_length, n_columns);

        let air = MockAir::new(n_columns);
        let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 1, 0);

        let settings = create_pcs_settings();
        let merkle_hash = setup_merkle_hash();
        let merkle_compress = setup_merkle_compress();

        let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
            table.build_whir_params(&settings, merkle_hash, merkle_compress);

        let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
        domainsep.commit_statement::<_, _, _, 8>(&whir_params);
        domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

        let challenger = setup_challenger();
        let mut prover_state = ProverState::new(&domainsep, challenger.clone());

        let committer = CommitmentWriter::new(&whir_params);
        let packed_pol = packed_multilinear(&witness);
        let mut statement = whir_params.initial_statement(packed_pol, SumcheckStrategy::Classic);

        let dft = Radix2Bowers;

        let mut whir_proof = WhirProof::<F, EF, F, 8>::default();
        let commitment = committer.commit::<_, PF, F, PF, 8>(
            &dft,
            &mut whir_proof,
            prover_state.challenger_mut(),
            &mut statement,
        );

        // Should work for different sizes
        assert!(commitment.is_ok());
    }
}
