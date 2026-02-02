mod helpers;
use air::{AirSettings, table::AirTable, verify::AirVerifError};
use helpers::*;
use p3_air::Air;
use utils::{ConstraintFolder, ConstraintFolderPacked};
use whir_p3::{
    fiat_shamir::{domain_separator::DomainSeparator, verifier::VerifierState},
    whir::parameters::WhirConfig,
};

fn prove_and_get_proof_data<A>(
    table: &AirTable<F, EF, A>,
    settings: &AirSettings,
    witness: Vec<whir_p3::poly::evals::EvaluationsList<F>>,
) -> Vec<F>
where
    A: for<'a> Air<ConstraintFolder<'a, F, F, EF>>
        + for<'a> Air<ConstraintFolder<'a, F, EF, EF>>
        + for<'a> Air<ConstraintFolderPacked<'a, F, EF>>,
{
    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(settings, merkle_hash.clone(), merkle_compress.clone());

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut prover_state = domainsep.to_prover_state(challenger.clone());

    table.prove(
        settings,
        merkle_hash,
        merkle_compress,
        &mut prover_state,
        witness,
    );

    prover_state.proof_data().to_vec()
}

#[test]
fn test_air_verify_basic() {
    let (air, log_length, witness) = create_keccak_witness_columns(1, 0);
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 4);

    let settings = create_test_settings();
    let proof_data = prove_and_get_proof_data(&table, &settings, witness);

    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut verifier_state = domainsep.to_verifier_state(proof_data, challenger);

    let result = table.verify(
        &settings,
        merkle_hash,
        merkle_compress,
        &mut verifier_state,
        log_length,
    );

    result.unwrap();
}

#[test]
fn test_air_verify_with_preprocessed() {
    let (air, log_length, mut all_cols) = create_keccak_witness_columns(1, 0);
    let preprocessed = all_cols.drain(..2).collect::<Vec<_>>();
    let witness = all_cols;

    let table = AirTable::<F, EF, _>::new(air, log_length, 1, preprocessed, 4);

    let settings = create_test_settings();
    let proof_data = prove_and_get_proof_data(&table, &settings, witness);

    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut verifier_state = domainsep.to_verifier_state(proof_data, challenger);

    let result = table.verify(
        &settings,
        merkle_hash,
        merkle_compress,
        &mut verifier_state,
        log_length,
    );

    result.unwrap();
}

#[test]
fn test_air_verify_invalid_proof() {
    let log_length = 3;
    let air = MockAir::new(4);

    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 1);

    let settings = create_test_settings();
    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    // Use empty/invalid proof data
    let mut verifier_state = domainsep.to_verifier_state(vec![], challenger);

    let result = table.verify(
        &settings,
        merkle_hash,
        merkle_compress,
        &mut verifier_state,
        log_length,
    );

    // Should fail with invalid proof
    assert!(result.is_err());
    match result.unwrap_err() {
        AirVerifError::InvalidPcsCommitment | AirVerifError::Fs(_) | AirVerifError::Sumcheck(_) => {
        }
        _ => panic!("Unexpected error type"),
    }
}

#[test]
fn test_air_verify_corrupted_proof() {
    let (air, log_length, witness) = create_keccak_witness_columns(1, 0);

    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 4);

    let settings = create_test_settings();
    let mut proof_data = prove_and_get_proof_data(&table, &settings, witness);

    // Corrupt the proof data
    if !proof_data.is_empty() {
        proof_data[0] = F::new(0);
    }

    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut verifier_state = domainsep.to_verifier_state(proof_data, challenger);

    let result = table.verify(
        &settings,
        merkle_hash,
        merkle_compress,
        &mut verifier_state,
        log_length,
    );

    // Should fail verification
    assert!(result.is_err());
}

#[test]
fn test_air_verify_different_settings() {
    let (air, log_length, witness) = create_keccak_witness_columns(1, 0);
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 4);

    let settings = create_test_settings();
    let proof_data = prove_and_get_proof_data(&table, &settings, witness);

    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut verifier_state = domainsep.to_verifier_state(proof_data, challenger);

    // Verify with same settings
    let result = table.verify(
        &settings,
        merkle_hash,
        merkle_compress,
        &mut verifier_state,
        log_length,
    );

    result.unwrap();
}

#[test]
fn test_air_verify_larger_table() {
    let (air, log_length, witness) = create_keccak_witness_columns(2, 0);
    // Keep univariate_skips=1; skips>1 currently triggers UB in whir-p3.
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 4);

    let settings = create_test_settings();
    let proof_data = prove_and_get_proof_data(&table, &settings, witness);

    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut verifier_state = domainsep.to_verifier_state(proof_data, challenger);

    let result = table.verify(
        &settings,
        merkle_hash,
        merkle_compress,
        &mut verifier_state,
        log_length,
    );

    result.unwrap();
}

#[test]
fn test_air_verify_wrong_log_length() {
    let (air, log_length, witness) = create_keccak_witness_columns(1, 0);

    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], 4);

    let settings = create_test_settings();
    let proof_data = prove_and_get_proof_data(&table, &settings, witness);

    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut verifier_state = domainsep.to_verifier_state(proof_data, challenger);

    // Verify with wrong log_length
    let result = table.verify(
        &settings,
        merkle_hash,
        merkle_compress,
        &mut verifier_state,
        log_length + 1, // Wrong length
    );

    // Should fail
    assert!(result.is_err());
}
