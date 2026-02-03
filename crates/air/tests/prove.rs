mod helpers;
use air::{AirSettings, table::AirTable};
use helpers::*;
use p3_uni_stark::get_max_constraint_degree_extension;
use utils::fiat_shamir::{ProverState, VerifierState};
use whir_p3::{
    fiat_shamir::domain_separator::DomainSeparator,
    parameters::{FoldingFactor, errors::SecurityAssumption},
    whir::parameters::WhirConfig,
};

#[test]
fn test_air_prove_basic() {
    let (air, log_length, witness) = create_keccak_witness_columns(1, 0);
    let constraint_degree =
        get_max_constraint_degree_extension::<F, EF, _>(&air, 0, 0, 0, 0);
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], constraint_degree);

    let settings = create_test_settings();
    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    let whir_params: WhirConfig<_, _, _, _, MyChallenger> =
        table.build_whir_params(&settings, merkle_hash.clone(), merkle_compress.clone());

    let mut domainsep: DomainSeparator<EF, F> = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, _, 8>(&whir_params);
    domainsep.add_whir_proof::<_, _, _, 8>(&whir_params);

    let challenger = setup_challenger();
    let mut prover_state = ProverState::new(&domainsep, challenger.clone());

    // Should complete without panicking
    let whir_proof = table.prove(
        &settings,
        merkle_hash.clone(),
        merkle_compress.clone(),
        &mut prover_state,
        witness,
    );

    let mut verifier_state = VerifierState::new(
        &domainsep,
        prover_state.proof_data().to_vec(),
        challenger,
    );
    table
        .verify(
            &settings,
            merkle_hash,
            merkle_compress,
            &mut verifier_state,
            log_length,
            &whir_proof,
        )
        .unwrap();
}

#[test]
fn test_air_prove_with_preprocessed() {
    let (air, log_length, mut all_cols) = create_keccak_witness_columns(1, 0);
    let preprocessed = all_cols.drain(..2).collect::<Vec<_>>();
    let witness = all_cols;

    let constraint_degree =
        get_max_constraint_degree_extension::<F, EF, _>(&air, preprocessed.len(), 0, 0, 0);
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, preprocessed, constraint_degree);

    let settings = create_test_settings();
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
        witness,
    );

    let mut verifier_state = VerifierState::new(
        &domainsep,
        prover_state.proof_data().to_vec(),
        challenger,
    );
    table
        .verify(
            &settings,
            merkle_hash,
            merkle_compress,
            &mut verifier_state,
            log_length,
            &whir_proof,
        )
        .unwrap();
}

#[test]
fn test_air_prove_different_univariate_skips() {
    let (_air, log_length, witness) = create_keccak_witness_columns(1, 0);

    for skips in [1] {
        if skips >= log_length {
            continue; // Skip invalid cases
        }

        let constraint_degree = get_max_constraint_degree_extension::<F, EF, _>(
            &keccak_air::KeccakAir {},
            0,
            0,
            0,
            0,
        );
        let table = AirTable::<F, EF, _>::new(
            keccak_air::KeccakAir {},
            log_length,
            skips,
            vec![],
            constraint_degree,
        );

        let mut settings = create_test_settings();
        settings.univariate_skips = skips;

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
            witness.clone(),
        );

        let mut verifier_state = VerifierState::new(
            &domainsep,
            prover_state.proof_data().to_vec(),
            challenger,
        );
        table
            .verify(
                &settings,
                merkle_hash.clone(),
                merkle_compress.clone(),
                &mut verifier_state,
                log_length,
                &whir_proof,
            )
            .unwrap();
    }
}

#[test]
fn test_air_prove_different_settings() {
    let (air, log_length, witness) = create_keccak_witness_columns(1, 0);
    let constraint_degree =
        get_max_constraint_degree_extension::<F, EF, _>(&air, 0, 0, 0, 0);
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], constraint_degree);

    let merkle_hash = setup_merkle_hash();
    let merkle_compress = setup_merkle_compress();

    // Test with different security bits (must be compatible with KoalaBear grinding).
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
            witness.clone(),
        );

        let mut verifier_state = VerifierState::new(
            &domainsep,
            prover_state.proof_data().to_vec(),
            challenger,
        );
        table
            .verify(
                &settings,
                merkle_hash.clone(),
                merkle_compress.clone(),
                &mut verifier_state,
                log_length,
                &whir_proof,
            )
            .unwrap();
    }
}

#[test]
#[should_panic]
fn test_air_prove_witness_dimension_mismatch() {
    let log_length = 3;
    let air = MockAir::new(4);
    // Create witness with wrong log_length
    let witness = create_witness_columns(log_length + 1, 4);

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
    let mut prover_state = ProverState::new(&domainsep, challenger);

    // Should panic due to dimension mismatch
    let _ = table.prove(
        &settings,
        merkle_hash,
        merkle_compress,
        &mut prover_state,
        witness,
    );
}

#[test]
fn test_air_prove_larger_table() {
    let (air, log_length, witness) = create_keccak_witness_columns(2, 0);
    // Keep univariate_skips=1; skips>1 currently triggers UB in whir-p3.
    let constraint_degree =
        get_max_constraint_degree_extension::<F, EF, _>(&air, 0, 0, 0, 0);
    let table = AirTable::<F, EF, _>::new(air, log_length, 1, vec![], constraint_degree);

    let settings = create_test_settings();
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
        witness,
    );

    let mut verifier_state = VerifierState::new(
        &domainsep,
        prover_state.proof_data().to_vec(),
        challenger,
    );
    table
        .verify(
            &settings,
            merkle_hash,
            merkle_compress,
            &mut verifier_state,
            log_length,
            &whir_proof,
        )
        .unwrap();
}
