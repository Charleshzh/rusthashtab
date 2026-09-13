//! Throughput measurement.
//!
//! Deliberately mirrors the shape of the C++ `Benchmark.cpp` this project replaces:
//! 4 MiB of data (fits in L2), N passes, drop the fastest and slowest 20%, report
//! MiB/s. Keeping the methodology identical is what makes a comparison meaningful.
//!
//! # What a number here does and does not mean
//!
//! It measures **our** code. It says nothing about correctness — that is
//! `cargo xtask verify`'s job. A fast wrong hash is still wrong.
//!
//! The number also depends heavily on `.cargo/config.toml`, which sets
//! `target-cpu=x86-64-v3`. Without it `sha2` loses SHA-NI, `xxhash-rust` loses
//! AVX2 and `blake3` loses AVX-512, all silently. If a result looks oddly low,
//! check that first.

use std::process::ExitCode;
use std::time::Instant;

use rusthashtab_hash::registry;

/// Data size, chosen to fit in L2 like the upstream benchmark.
const DEFAULT_SIZE: usize = 4 << 20;
/// Passes per algorithm.
const DEFAULT_PASSES: usize = 20;
/// Read block size, matching the scanner.
const BLOCK: usize = 2 << 20;

fn payload(n: usize) -> Vec<u8> {
    let mut state: u64 = 0x243F_6A88_85A3_08D3;
    let mut out = vec![0u8; n];
    for chunk in out.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let b = state.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
    out
}

/// Entry point: `cargo xtask bench [--passes N] [--size MiB] [--filter SUBSTR]`.
pub(crate) fn run(args: &[String]) -> ExitCode {
    let mut passes = DEFAULT_PASSES;
    let mut size = DEFAULT_SIZE;
    let mut filter: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--passes" => {
                let Some(v) = args.get(i + 1).and_then(|s| s.parse().ok()) else {
                    eprintln!("bench: --passes needs a number");
                    return ExitCode::from(2);
                };
                passes = v;
                i += 2;
            }
            "--size" => {
                let Some(mib) = args.get(i + 1).and_then(|s| s.parse::<usize>().ok()) else {
                    eprintln!("bench: --size needs a MiB count");
                    return ExitCode::from(2);
                };
                size = mib * 1024 * 1024;
                i += 2;
            }
            "--filter" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("bench: --filter needs a substring");
                    return ExitCode::from(2);
                };
                filter = Some(v.clone());
                i += 2;
            }
            other => {
                eprintln!("bench: unknown option `{other}`");
                return ExitCode::from(2);
            }
        }
    }

    if passes < 5 {
        eprintln!("bench: --passes must be at least 5 (need samples to trim)");
        return ExitCode::from(2);
    }
    let skip = passes / 5; // 20% trimmed from each end

    let names: Vec<&str> = registry::ALGORITHMS
        .iter()
        .filter(|a| a.is_implemented())
        .filter(|a| filter.as_ref().is_none_or(|f| a.name.contains(f.as_str())))
        .map(|a| a.name)
        .collect();

    if names.is_empty() {
        println!("No implemented algorithms match. Run `cargo xtask audit`.");
        return ExitCode::SUCCESS;
    }

    let data = payload(size);
    println!(
        "{} MiB payload, {passes} passes, {skip} trimmed each end, {BLOCK} B blocks\n",
        size / (1 << 20)
    );
    println!("{:<18} {:>12}  NOTES", "ALGORITHM", "MiB/s");
    println!("{}", "-".repeat(72));

    for name in names {
        let mut times: Vec<f64> = Vec::with_capacity(passes);
        for _ in 0..passes {
            let Some(mut h) = registry::make(name) else {
                break;
            };
            let t0 = Instant::now();
            for chunk in data.chunks(BLOCK) {
                h.update(chunk);
            }
            let d = Box::new(h).finalize();
            std::hint::black_box(&d);
            times.push(t0.elapsed().as_secs_f64());
        }
        if times.len() < passes {
            println!("{name:<18} {:>12}  not implemented", "-");
            continue;
        }
        times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let trimmed = &times[skip..passes - skip];
        let avg = trimmed.iter().sum::<f64>() / trimmed.len() as f64;
        let mibps = (size as f64 / (1 << 20) as f64) / avg;

        // Flag the known slow spots explicitly, so a regression in the Keccak
        // family is not mistaken for noise.
        let note = if mibps < 300.0 {
            "slow: check target-cpu in .cargo/config.toml"
        } else {
            ""
        };
        println!("{name:<18} {mibps:>12.1}  {note}");
    }

    ExitCode::SUCCESS
}
