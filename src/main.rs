#![cfg_attr(not(test), allow(unused_crate_dependencies))]

mod examples;

use air::AirSettings;
use std::fmt::Display;
use whir_p3::parameters::{FoldingFactor, errors::SecurityAssumption};

use crate::examples::keccak::prove_keccak;
use crate::examples::poseidon2::prove_poseidon2;

fn main() {
    // Decide which benchmark to run (default: poseidon2)
    let bench_name = std::env::var("WHIR_BENCH").unwrap_or_else(|_| "poseidon2".to_string());
    // Retrieve LOG_B (used by Keccak) if set, else default to 7
    let log_b_env: usize = std::env::var("LOG_B")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7);

    // Use LOG_N_ROWS env var if provided, else default to 3 (8 rows × 16 field elements ≈ 1 KiB).
    let log_n_rows: usize = std::env::var("LOG_N_ROWS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);

    let settings = AirSettings::new(
        100, // security bits (kept in sync with HyperPlonk bench)
        SecurityAssumption::CapacityBound,
        FoldingFactor::Constant(4), // identical folding factor
        1,                          // starting log_inv_rate
        1,                          // univariate_skips (classic sumcheck, < log_n_rows)
        3,                          // domain reduction factor
    );

    let benchmark: Box<dyn Display> = match bench_name.as_str() {
        "poseidon2" => Box::new(prove_poseidon2(log_n_rows, settings.clone(), 0, true)),
        "keccak" => Box::new(prove_keccak(log_b_env, settings.clone(), 0, true)),
        other => {
            eprintln!(
                "Unknown WHIR_BENCH value `{}`. Expected `poseidon2` or `keccak`.",
                other
            );
            std::process::exit(1);
        }
    };
    println!("\n{}", benchmark);
}
