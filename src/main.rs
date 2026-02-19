#![cfg_attr(not(test), allow(unused_crate_dependencies))]

use air::AirSettings;
use std::fmt::Display;
use whir_p3::parameters::{FoldingFactor, errors::SecurityAssumption};

use whirlaway::examples::keccak::prove_keccak;
use whirlaway::examples::poseidon2::prove_poseidon2;

const SECURITY_BITS: usize = 128;

fn main() {
    // Decide which benchmark to run (default: poseidon2)
    let bench_name = std::env::var("WHIR_BENCH").unwrap_or_else(|_| "poseidon2".to_string());
    // Retrieve LOG_B (used by Keccak) if set, else default to 7
    let log_b_env: usize = std::env::var("LOG_B")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7);

    let settings = AirSettings::new(
        SECURITY_BITS,
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(7, 4),
        1,
        4,
        5,
    );

    let benchmark: Box<dyn Display> = match bench_name.as_str() {
        "poseidon2" => Box::new(prove_poseidon2(log_b_env, settings.clone(), 0, true)),
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
