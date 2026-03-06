use std::io::Write;
use std::path::PathBuf;

use air::AirSettings;
use keccak_air::{NUM_ROUNDS, RATE_BYTES};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use sha3::Digest;
use whir_p3::parameters::{FoldingFactor, errors::SecurityAssumption};
use whirlaway::circuits::keccak256::{Keccak256Circuit, Keccak256Input};
use whirlaway::evm_codec;
use whirlaway::evm_codec::{
    encode_calldata_verify_bytes, encode_proof_blob_v1, render_json_payload,
};
use whirlaway::hashers::KECCAK_DIGEST_ELEMS;
use whirlaway::proving_system::{Circuit, KeccakProvingSystemConfig, prepare, prove, verify};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputFormat {
    Json,
    Calldata,
}

struct CliArgs {
    format: OutputFormat,
    out: Option<PathBuf>,
    pretty: bool,
    log_b: usize,
}

impl CliArgs {
    fn parse() -> Result<Self, String> {
        let mut format = OutputFormat::Json;
        let mut out = None;
        let mut pretty = false;
        let mut log_b = 7usize;

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--format" => {
                    let Some(value) = args.next() else {
                        return Err(format!("missing value for --format\n{}", Self::usage()));
                    };
                    format = match value.as_str() {
                        "json" => OutputFormat::Json,
                        "calldata" => OutputFormat::Calldata,
                        _ => {
                            return Err(format!(
                                "unsupported format '{value}', expected 'json' or 'calldata'\n{}",
                                Self::usage()
                            ));
                        }
                    };
                }
                "--out" => {
                    let Some(value) = args.next() else {
                        return Err(format!("missing value for --out\n{}", Self::usage()));
                    };
                    out = Some(PathBuf::from(value));
                }
                "--pretty" => {
                    pretty = true;
                }
                "--log-b" => {
                    let Some(value) = args.next() else {
                        return Err(format!("missing value for --log-b\n{}", Self::usage()));
                    };
                    log_b = value
                        .parse::<usize>()
                        .map_err(|e| format!("invalid --log-b value '{value}': {e}"))?;
                    if log_b == 0 {
                        return Err("--log-b must be > 0".to_string());
                    }
                }
                "-h" | "--help" => {
                    return Err(Self::usage().to_string());
                }
                _ => {
                    return Err(format!("unknown argument '{arg}'\n{}", Self::usage()));
                }
            }
        }

        Ok(Self {
            format,
            out,
            pretty,
            log_b,
        })
    }

    const fn usage() -> &'static str {
        concat!(
            "Usage: cargo run --example evm_vectors -- [OPTIONS]\n\n",
            "Options:\n",
            "  --format <json|calldata>   Output format (default: json)\n",
            "  --out <path>               Write output to file (default: stdout)\n",
            "  --pretty                   Pretty-print JSON output\n",
            "  --log-b <usize>            Target log2(trace rows) (default: 7)\n",
            "  -h, --help                 Show this help\n",
        )
    }
}

fn message_len_for_log_length(log_n_rows: usize) -> (usize, usize) {
    let target_rows = 1usize << log_n_rows;
    let mut num_blocks_max = target_rows / NUM_ROUNDS;
    if num_blocks_max == 0 {
        num_blocks_max = 1;
    }

    let min_rows = (target_rows / 2).saturating_add(1);
    let num_blocks_min = min_rows.div_ceil(NUM_ROUNDS);

    let num_blocks = if num_blocks_max * NUM_ROUNDS <= target_rows / 2 {
        num_blocks_min.max(1)
    } else {
        num_blocks_max
    };

    let rows = num_blocks * NUM_ROUNDS;
    let actual_log_n_rows = rows.next_power_of_two().ilog2() as usize;
    let message_len = num_blocks * RATE_BYTES - 2;

    (message_len, actual_log_n_rows)
}

fn run() -> Result<(), String> {
    let cli = match CliArgs::parse() {
        Ok(cli) => cli,
        Err(err) => {
            if err == CliArgs::usage() {
                print!("{err}");
                return Ok(());
            }
            return Err(err);
        }
    };

    let settings = AirSettings::new(
        128,
        SecurityAssumption::CapacityBound,
        FoldingFactor::ConstantFromSecondRound(4, 4),
        1,
        1,
        4,
    );

    let (message_len, _actual_log_b) = message_len_for_log_length(cli.log_b);
    let proving_settings = KeccakProvingSystemConfig {
        air_settings: settings,
    };

    let mut rng = StdRng::seed_from_u64(0);
    let message: Vec<u8> = (0..message_len).map(|_| rng.random()).collect();
    let expected_digest: [u8; 32] = sha3::Keccak256::digest(&message).into();

    let circuit = Keccak256Circuit {
        input_size: message_len,
    };
    let prepared = prepare::<Keccak256Circuit, _, KECCAK_DIGEST_ELEMS>(&proving_settings, circuit);
    let input = Keccak256Input {
        message,
        expected_digest,
    };

    let public_values = Keccak256Circuit::public_values(&prepared.circuit, &input);
    let proof = prove(&prepared, &input);
    verify(&prepared, &proof, &public_values)
        .map_err(|err| format!("generated proof failed verification: {err}"))?;

    let proof_blob = encode_proof_blob_v1(&public_values, &proof);
    let calldata = encode_calldata_verify_bytes(&proof_blob);

    let output = match cli.format {
        OutputFormat::Json => render_json_payload(&proof_blob, &calldata, cli.pretty),
        OutputFormat::Calldata => evm_codec::hex_prefixed(&calldata),
    };

    match cli.out {
        Some(path) => {
            std::fs::write(&path, output.as_bytes())
                .map_err(|err| format!("failed to write output to '{}': {err}", path.display()))?;
        }
        None => {
            let mut stdout = std::io::stdout();
            stdout
                .write_all(output.as_bytes())
                .map_err(|err| format!("failed to write output to stdout: {err}"))?;
            if cli.format == OutputFormat::Calldata {
                stdout
                    .write_all(b"\n")
                    .map_err(|err| format!("failed to write newline: {err}"))?;
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
