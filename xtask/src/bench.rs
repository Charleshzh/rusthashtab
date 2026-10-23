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
use rusthashtab_scan::{FileJob, ScanConfig, ScanEvent, Scheduling, start};

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
    let mut combined = false;
    let mut scheduling: Option<String> = None;
    let mut files = 1usize;
    let mut all_algorithms = true;
    let mut single_algorithm: Option<String> = None;
    let mut groups: Option<usize> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--combined" => {
                combined = true;
                i += 1;
            }
            "--scheduling" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("bench: --scheduling needs auto, file or algorithm");
                    return ExitCode::from(2);
                };
                scheduling = Some(v.clone());
                i += 2;
            }
            "--files" => {
                let Some(v) = args.get(i + 1).and_then(|s| s.parse::<usize>().ok()) else {
                    eprintln!("bench: --files needs a count");
                    return ExitCode::from(2);
                };
                files = v.max(1);
                i += 2;
            }
            "--algorithms" => {
                match args.get(i + 1).map(String::as_str) {
                    Some("default") => {
                        all_algorithms = false;
                        single_algorithm = None;
                    }
                    Some("all") => {
                        all_algorithms = true;
                        single_algorithm = None;
                    }
                    Some(name)
                        if registry::ALGORITHMS
                            .iter()
                            .any(|algorithm| algorithm.name == name) =>
                    {
                        all_algorithms = false;
                        single_algorithm = Some(name.to_string());
                    }
                    _ => {
                        eprintln!("bench: --algorithms needs default, all, or an algorithm name");
                        return ExitCode::from(2);
                    }
                }
                i += 2;
            }
            "--groups" => {
                let Some(v) = args.get(i + 1).and_then(|s| s.parse::<usize>().ok()) else {
                    eprintln!("bench: --groups needs a count");
                    return ExitCode::from(2);
                };
                groups = Some(v.max(1));
                i += 2;
            }
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

    if let Some(mode) = scheduling {
        return report_scan(ScanOptions {
            size,
            passes,
            skip,
            files,
            mode: &mode,
            all_algorithms,
            single_algorithm: single_algorithm.as_deref(),
            forced_groups: groups,
        });
    }

    if combined {
        let data = payload(size);
        println!(
            "{} MiB payload, {passes} passes, {skip} trimmed each end, {BLOCK} B blocks\n",
            size / (1 << 20)
        );
        println!("{:<24} {:>12}  NOTES", "COMBINED SET", "MiB/s");
        println!("{}", "-".repeat(72));

        let defaults = ["MD5", "SHA-1", "SHA-256", "SHA-512"];
        report_combined("default 4", &defaults, &data, passes, skip);
        let all: Vec<&str> = registry::ALGORITHMS
            .iter()
            .filter(|algorithm| algorithm.is_implemented())
            .map(|algorithm| algorithm.name)
            .collect();
        report_combined("all implemented", &all, &data, passes, skip);
        return ExitCode::SUCCESS;
    }

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

/// The independent knobs of one real-scan measurement.
struct ScanOptions<'a> {
    size: usize,
    passes: usize,
    skip: usize,
    files: usize,
    mode: &'a str,
    all_algorithms: bool,
    single_algorithm: Option<&'a str>,
    forced_groups: Option<usize>,
}

/// Measure the real scan pipeline under one scheduling policy.
fn report_scan(options: ScanOptions<'_>) -> ExitCode {
    let ScanOptions {
        size,
        passes,
        skip,
        files,
        mode,
        all_algorithms,
        single_algorithm,
        forced_groups,
    } = options;
    let scheduling = match mode {
        "auto" => Scheduling::Auto,
        "file" => Scheduling::FileLevel,
        "algorithm" => {
            let cores = std::thread::available_parallelism()
                .map(|count| count.get())
                .unwrap_or(1);
            Scheduling::AlgorithmGroups {
                groups: forced_groups.unwrap_or_else(|| cores.saturating_sub(1).max(1)),
            }
        }
        other => {
            eprintln!("bench: unknown scheduling `{other}` (auto, file, algorithm)");
            return ExitCode::from(2);
        }
    };

    let dir = std::env::temp_dir().join(format!("rusthashtab-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    if let Err(error) = std::fs::create_dir_all(&dir) {
        eprintln!("bench: could not create {}: {error}", dir.display());
        return ExitCode::FAILURE;
    }

    let data = payload(size);
    let mut paths = Vec::with_capacity(files);
    for index in 0..files {
        let path = dir.join(format!("file-{index}.bin"));
        let start = size * index / files;
        let end = size * (index + 1) / files;
        if let Err(error) = std::fs::write(&path, &data[start..end]) {
            eprintln!("bench: could not write {}: {error}", path.display());
            let _ = std::fs::remove_dir_all(&dir);
            return ExitCode::FAILURE;
        }
        paths.push(path);
    }

    let jobs: Vec<FileJob> = paths
        .iter()
        .map(|path| FileJob {
            path: path.clone(),
            display_path: path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            expected: Vec::new(),
            size: std::fs::metadata(path)
                .map(|metadata| metadata.len())
                .unwrap_or(0),
        })
        .collect();

    let defaults = ["MD5", "SHA-1", "SHA-256", "SHA-512"];
    let enabled: Vec<bool> = registry::ALGORITHMS
        .iter()
        .map(|algorithm| match single_algorithm {
            Some(name) => algorithm.name == name,
            None => all_algorithms || defaults.contains(&algorithm.name),
        })
        .collect();

    let mut times = Vec::with_capacity(passes);
    for _ in 0..passes {
        let done = std::sync::Arc::new(std::sync::Mutex::new(false));
        let signal = std::sync::Arc::clone(&done);
        let started = Instant::now();
        let handle = start(
            ScanConfig {
                jobs: jobs.clone(),
                enabled: enabled.clone(),
                workers: 0,
                scheduling,
            },
            Box::new(move |event| {
                if let ScanEvent::Finished(_) = event {
                    *signal
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
                }
            }),
        );
        handle.wait();
        times.push(started.elapsed().as_secs_f64());
    }
    let _ = std::fs::remove_dir_all(&dir);

    times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let trimmed = &times[skip..passes - skip];
    let average = trimmed.iter().sum::<f64>() / trimmed.len() as f64;
    let mibps = (size as f64 / (1 << 20) as f64) / average;
    println!(
        "scheduling {mode}, {files} file(s), {} algorithms, {} MiB, {passes} passes: {mibps:.1} MiB/s",
        single_algorithm.unwrap_or(if all_algorithms { "all" } else { "default 4" }),
        size / (1 << 20)
    );
    ExitCode::SUCCESS
}

/// Measure one combined set: the same payload fed to every algorithm in turn.
fn report_combined(label: &str, names: &[&str], data: &[u8], passes: usize, skip: usize) {
    let mut times = Vec::with_capacity(passes);
    for _ in 0..passes {
        let mut hashers: Vec<Box<dyn rusthashtab_hash::Hasher>> = names
            .iter()
            .filter_map(|name| registry::make(name))
            .collect();
        if hashers.len() != names.len() {
            println!("{label:<24} {:>12}  not implemented", "-");
            return;
        }

        let started = Instant::now();
        for chunk in data.chunks(BLOCK) {
            for hasher in &mut hashers {
                hasher.update(chunk);
            }
        }
        for hasher in hashers {
            let digest = hasher.finalize();
            std::hint::black_box(&digest);
        }
        times.push(started.elapsed().as_secs_f64());
    }

    times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let trimmed = &times[skip..passes - skip];
    let average = trimmed.iter().sum::<f64>() / trimmed.len() as f64;
    let mibps = (data.len() as f64 / (1 << 20) as f64) / average;
    println!("{label:<24} {mibps:>12.1}");
}
