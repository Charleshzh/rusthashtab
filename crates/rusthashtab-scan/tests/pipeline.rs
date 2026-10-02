//! End-to-end tests for the scan pipeline.
//!
//! # What these tests are for
//!
//! The algorithms themselves are already proven correct against external
//! authorities (`cargo xtask verify`). What is new here is the pipeline: the
//! claim under test is not "this digest is right" but **"the pipeline does not
//! change the answer"**. Every digest a scan produces is therefore compared with
//! the same algorithm fed the whole file in one call, for every algorithm in the
//! table — including the sizes that sit exactly on a block boundary, where a
//! read-ahead ring that lost or duplicated a block would show up.
//!
//! The rest of the file covers the behaviour a UI depends on: every file
//! reported exactly once, progress that only moves forward, an unreadable file
//! that does not take the scan down with it, cancellation that actually stops the
//! work, and a handle that can be dropped without hanging the caller.

// Test code is allowed to fail loudly: a panic here is a test failure, not a
// process that takes the user's shell down with it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rusthashtab_hash::{ALGORITHMS, registry};
use rusthashtab_scan::{
    BLOCK_SIZE, FileJob, FileResult, MatchState, Progress, ScanConfig, ScanEvent, ScanHandle,
    ScanOutcome, start,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Nothing in this suite should take this long; a scan that does is hung, and a
/// hung test binary reports nothing at all.
const DEADLINE: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// A uniquely named temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::AtomicUsize;
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "rusthashtab-scan-pipeline-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the temporary directory must be creatable");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// Write a file of `len` deterministic bytes and return its path.
    fn file(&self, name: &str, len: usize) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, payload(len)).expect("the test file must be writable");
        path
    }

    /// Write a large file **without writing its bytes**, and return its path.
    ///
    /// `set_len` extends the file and leaves the new region as a hole, so the
    /// filesystem stores no data and the call is independent of `len`. NTFS reports
    /// the holes as zeroes, so the file hashes correctly and a scan of it takes
    /// long enough to be interrupted deliberately.
    ///
    /// The alternative -- `file(name, 64 MiB)` -- would write 64 MiB per file and
    /// make the cancellation tests slow enough that nobody would run them.
    fn large_file(&self, name: &str, len: u64) -> PathBuf {
        let path = self.0.join(name);
        let file = std::fs::File::create(&path).expect("the test file must be creatable");
        file.set_len(len).expect("the test file must be extendable");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Deterministic content: a failure must be reproducible, and a run of zeroes
/// would hide a block being duplicated or dropped anywhere but the tail.
///
/// The generator is written in `u64` on purpose, so the bytes are the same on
/// 32-bit and 64-bit targets and a digest difference between them would be a
/// real finding rather than a different test file.
fn payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| {
            (u64::try_from(index)
                .unwrap_or(0)
                .wrapping_mul(2_654_435_761)
                >> 11) as u8
        })
        .collect()
}

/// Every algorithm's digest of the whole file, computed in one call.
///
/// This is the independent side of the comparison: it uses no part of the scan
/// pipeline.
fn one_shot_digests(path: &Path) -> Vec<Vec<u8>> {
    let data = std::fs::read(path).expect("the test file must be readable");
    ALGORITHMS
        .iter()
        .map(|algorithm| {
            let mut hasher =
                registry::make(algorithm.name).expect("every table algorithm is implemented");
            hasher.update(&data);
            hasher.finalize()
        })
        .collect()
}

fn job_for(path: &Path) -> FileJob {
    FileJob {
        path: path.to_path_buf(),
        display_path: path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        expected: Vec::new(),
        size: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
    }
}

/// What a caller can ask the test harness to do to a scan while it runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CancelTrigger {
    /// Let the scan finish normally.
    Never,
    /// Cancel as soon as one file has been reported.
    AfterFirstFile,
    /// Cancel before any work can start.
    Immediately,
}

/// Everything a completed (or cancelled) scan produced.
struct ScanReport {
    outcome: ScanOutcome,
    /// Results in the order they were reported, with their job index.
    results: Vec<(usize, FileResult, MatchState)>,
    progress: Vec<Progress>,
}

impl ScanReport {
    fn result_for(&self, path: &Path) -> &(usize, FileResult, MatchState) {
        self.results
            .iter()
            .find(|(_, result, _)| result.path == path)
            .expect("the scan reported this file")
    }
}

/// Run a scan to completion, optionally cancelling it part way.
fn run_scan(config: ScanConfig, trigger: CancelTrigger) -> ScanReport {
    let events: Arc<Mutex<Vec<ScanEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let finished = Arc::new(AtomicBool::new(false));
    let first_file = Arc::new(AtomicBool::new(false));

    let sink_events = Arc::clone(&events);
    let sink_finished = Arc::clone(&finished);
    let sink_first = Arc::clone(&first_file);

    let handle = Arc::new(start(
        config,
        Box::new(move |event| {
            match &event {
                ScanEvent::FileFinished { .. } => sink_first.store(true, Ordering::SeqCst),
                ScanEvent::Finished(_) => sink_finished.store(true, Ordering::SeqCst),
                ScanEvent::Progress(_) => {}
            }
            sink_events
                .lock()
                .expect("the event list is not poisoned")
                .push(event);
        }),
    ));

    let canceller = match trigger {
        CancelTrigger::Never => None,
        CancelTrigger::Immediately => {
            handle.cancel();
            None
        }
        CancelTrigger::AfterFirstFile => {
            let watch_handle = Arc::clone(&handle);
            let watch_first = Arc::clone(&first_file);
            let watch_finished = Arc::clone(&finished);
            Some(thread::spawn(move || {
                while !watch_first.load(Ordering::SeqCst) {
                    if watch_finished.load(Ordering::SeqCst) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                watch_handle.cancel();
            }))
        }
    };

    let deadline = Instant::now() + DEADLINE;
    while !finished.load(Ordering::SeqCst) {
        assert!(
            Instant::now() < deadline,
            "the scan did not report Finished within {DEADLINE:?}"
        );
        thread::sleep(Duration::from_millis(2));
    }

    if let Some(canceller) = canceller {
        canceller
            .join()
            .expect("the canceller thread does not panic");
    }
    // Every other `Arc` has been dropped by now (`try_unwrap` would need
    // `ScanHandle: Debug`, which the public type deliberately is not).
    Arc::into_inner(handle)
        .expect("the scan handle is not shared any more")
        .wait();

    let collected = std::mem::take(&mut *events.lock().expect("the event list is not poisoned"));

    let mut outcome = None;
    let mut results = Vec::new();
    let mut progress = Vec::new();
    for event in collected {
        match event {
            ScanEvent::Progress(update) => progress.push(update),
            ScanEvent::FileFinished {
                job_index,
                result,
                match_state,
            } => results.push((job_index, result, match_state)),
            ScanEvent::Finished(ended) => {
                assert!(outcome.is_none(), "Finished must be emitted exactly once");
                outcome = Some(ended);
            }
        }
    }

    ScanReport {
        outcome: outcome.expect("Finished must be emitted"),
        results,
        progress,
    }
}

/// Whether `Finished` really was the last event: checked separately because the
/// report above flattens the stream.
fn run_scan_expecting_finished_last(config: ScanConfig) -> ScanReport {
    let events: Arc<Mutex<Vec<ScanEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let finished = Arc::new(AtomicBool::new(false));

    let sink_events = Arc::clone(&events);
    let sink_finished = Arc::clone(&finished);
    let handle = start(
        config,
        Box::new(move |event| {
            if matches!(event, ScanEvent::Finished(_)) {
                sink_finished.store(true, Ordering::SeqCst);
            }
            sink_events
                .lock()
                .expect("the event list is not poisoned")
                .push(event);
        }),
    );

    let deadline = Instant::now() + DEADLINE;
    while !finished.load(Ordering::SeqCst) {
        assert!(Instant::now() < deadline, "the scan did not finish in time");
        thread::sleep(Duration::from_millis(2));
    }
    handle.wait();

    let collected = std::mem::take(&mut *events.lock().expect("the event list is not poisoned"));
    let last = collected.last().cloned().expect("at least one event");
    assert!(
        matches!(last, ScanEvent::Finished(_)),
        "Finished must be the last event, got {last:?}"
    );

    let mut report = ScanReport {
        outcome: ScanOutcome::Complete,
        results: Vec::new(),
        progress: Vec::new(),
    };
    for event in collected {
        match event {
            ScanEvent::Progress(update) => report.progress.push(update),
            ScanEvent::FileFinished {
                job_index,
                result,
                match_state,
            } => report.results.push((job_index, result, match_state)),
            ScanEvent::Finished(ended) => report.outcome = ended,
        }
    }
    report
}

/// The sizes that make a block-boundary bug visible, plus ordinary ones.
fn boundary_sizes() -> Vec<usize> {
    vec![
        0,
        1,
        BLOCK_SIZE - 1,
        BLOCK_SIZE,
        BLOCK_SIZE + 1,
        3 * BLOCK_SIZE + 123,
    ]
}

// ---------------------------------------------------------------------------
// the phase gate: the pipeline must not change the answer
// ---------------------------------------------------------------------------

/// **The invariant this phase exists to establish.**
///
/// For every algorithm, and for every file size, the digest a scan produces must
/// equal the digest the same context produces from a single `update` of the
/// whole file. A ring that duplicated a block, dropped the tail, or fed blocks
/// out of order fails here rather than in a user's checksum comparison.
#[test]
fn the_pipeline_does_not_change_the_answer_for_any_algorithm() {
    let dir = TempDir::new("invariant");

    for size in boundary_sizes() {
        let path = dir.file(&format!("payload-{size}.bin"), size);
        let expected = one_shot_digests(&path);

        let report = run_scan(
            ScanConfig::all_algorithms(vec![job_for(&path)]),
            CancelTrigger::Never,
        );

        assert_eq!(report.outcome, ScanOutcome::Complete);
        assert_eq!(report.results.len(), 1, "one file, one result");

        let (_, result, _) = report.result_for(&path);
        assert_eq!(result.error, None, "size {size}: the file must be readable");
        assert_eq!(
            result.size, size as u64,
            "size {size}: the reported size must be the bytes hashed"
        );

        for (index, algorithm) in ALGORITHMS.iter().enumerate() {
            assert!(
                !expected[index].is_empty(),
                "{} must produce a digest",
                algorithm.name
            );
            assert_eq!(
                result.digests[index], expected[index],
                "{} differs for a {size}-byte file: pipeline vs whole-input",
                algorithm.name
            );
        }
    }
}

/// The same invariant, stated over a file read while several workers are busy:
/// sharing the buffer pool must not corrupt anyone's blocks.
#[test]
fn concurrent_files_each_match_their_own_whole_input_digest() {
    let dir = TempDir::new("concurrent");
    let mut jobs = Vec::new();
    let mut sizes = Vec::new();

    // Small files make the workers contend for the queue; large ones make them
    // contend for buffers.
    for index in 0..48 {
        let size = 4096 + index * 997;
        sizes.push(size);
        jobs.push(job_for(&dir.file(&format!("small-{index}.bin"), size)));
    }
    for index in 0..3 {
        let size = BLOCK_SIZE * 2 + index * 4096 + 17;
        sizes.push(size);
        jobs.push(job_for(&dir.file(&format!("large-{index}.bin"), size)));
    }

    let expected: Vec<Vec<Vec<u8>>> = jobs.iter().map(|job| one_shot_digests(&job.path)).collect();

    let mut config = ScanConfig::all_algorithms(jobs.clone());
    config.workers = 8;
    let report = run_scan(config, CancelTrigger::Never);

    assert_eq!(report.outcome, ScanOutcome::Complete);
    assert_eq!(
        report.results.len(),
        jobs.len(),
        "every file is reported once"
    );

    let mut seen = vec![false; jobs.len()];
    for (job_index, result, _) in &report.results {
        assert!(!seen[*job_index], "job {job_index} was reported twice");
        seen[*job_index] = true;
        assert_eq!(
            result.digests,
            expected[*job_index],
            "job {job_index} ({}) differs from its whole-input digest",
            result.path.display()
        );
    }
}

// ---------------------------------------------------------------------------
// results, matching and errors
// ---------------------------------------------------------------------------

#[test]
fn the_default_configuration_hashes_only_the_four_default_algorithms() {
    let dir = TempDir::new("defaults");
    let path = dir.file("default.bin", 1000);
    let expected = one_shot_digests(&path);

    let report = run_scan(ScanConfig::new(vec![job_for(&path)]), CancelTrigger::Never);
    let (_, result, _) = report.result_for(&path);

    assert_eq!(result.digests.len(), ALGORITHMS.len());
    for (index, algorithm) in ALGORITHMS.iter().enumerate() {
        if matches!(algorithm.name, "MD5" | "SHA-1" | "SHA-256" | "SHA-512") {
            assert_eq!(result.digests[index], expected[index], "{}", algorithm.name);
        } else {
            assert!(
                result.digests[index].is_empty(),
                "{} is disabled and must produce no digest",
                algorithm.name
            );
        }
    }
}

#[test]
fn an_expected_digest_is_matched_and_a_wrong_one_is_not() {
    let dir = TempDir::new("matching");
    let good = dir.file("good.bin", 20_000);
    let bad = dir.file("bad.bin", 20_000);

    let sha256 = ALGORITHMS
        .iter()
        .position(|algorithm| algorithm.name == "SHA-256")
        .expect("SHA-256 is in the table");
    let crc32 = ALGORITHMS
        .iter()
        .position(|algorithm| algorithm.name == "CRC32")
        .expect("CRC32 is in the table");

    let mut good_job = job_for(&good);
    good_job.expected = vec![one_shot_digests(&good)[sha256].clone()];
    let mut bad_job = job_for(&bad);
    bad_job.expected = vec![vec![0u8; 32]];

    let report = run_scan(
        ScanConfig::all_algorithms(vec![good_job, bad_job]),
        CancelTrigger::Never,
    );

    let (_, _, state) = report.result_for(&good);
    assert_eq!(
        *state,
        MatchState::Matched {
            algorithm: sha256,
            secure: true
        }
    );

    let (_, _, state) = report.result_for(&bad);
    assert_eq!(*state, MatchState::Mismatched);

    // A weak match is still a match, but it is not reported as a secure one.
    let mut weak_job = job_for(&good);
    weak_job.expected = vec![one_shot_digests(&good)[crc32].clone()];
    let report = run_scan(
        ScanConfig::all_algorithms(vec![weak_job]),
        CancelTrigger::Never,
    );
    let (_, _, state) = report.result_for(&good);
    assert_eq!(
        *state,
        MatchState::Matched {
            algorithm: crc32,
            secure: false
        }
    );
}

#[test]
fn an_unreadable_file_is_reported_without_losing_the_others() {
    let dir = TempDir::new("errors");
    let present = dir.file("present.bin", 5000);
    let missing = dir.path().join("not-there.bin");

    let report = run_scan(
        ScanConfig::all_algorithms(vec![job_for(&present), job_for(&missing)]),
        CancelTrigger::Never,
    );

    assert_eq!(
        report.outcome,
        ScanOutcome::Complete,
        "one unreadable file is not a failed scan"
    );
    assert_eq!(report.results.len(), 2);

    let (_, result, state) = report.result_for(&missing);
    assert_eq!(
        result.error,
        Some(2),
        "ERROR_FILE_NOT_FOUND must reach the caller"
    );
    assert_eq!(result.size, 0);
    assert!(
        result.digests.iter().all(Vec::is_empty),
        "an unreadable file has no digest"
    );
    assert_eq!(
        *state,
        MatchState::NotChecked,
        "an unreadable file is not a mismatch"
    );

    let (_, result, _) = report.result_for(&present);
    assert_eq!(result.error, None);
    assert_eq!(result.digests, one_shot_digests(&present));
}

// ---------------------------------------------------------------------------
// progress, ordering and shutdown
// ---------------------------------------------------------------------------

#[test]
fn progress_only_moves_forward_and_reaches_the_total() {
    let dir = TempDir::new("progress");
    let mut jobs = Vec::new();
    let mut total = 0u64;
    for index in 0..10 {
        let size = BLOCK_SIZE + index * 1000;
        total += size as u64;
        jobs.push(job_for(&dir.file(&format!("file-{index}.bin"), size)));
    }

    let report = run_scan(ScanConfig::all_algorithms(jobs), CancelTrigger::Never);

    assert!(!report.progress.is_empty(), "progress must be reported");

    let mut last = Progress {
        done: 0,
        total: 0,
        files_done: 0,
        files_total: 0,
    };
    for update in &report.progress {
        assert_eq!(update.total, total, "the total must not change mid-scan");
        assert_eq!(update.files_total, 10);
        assert!(
            update.done >= last.done,
            "progress went backwards: {} then {}",
            last.done,
            update.done
        );
        assert!(
            update.files_done >= last.files_done,
            "the file count went backwards"
        );
        assert!(update.done <= update.total, "progress passed the total");
        assert!(update.files_done <= update.files_total);
        last = *update;
    }

    assert_eq!(last.done, total, "progress must reach the total");
    assert_eq!(last.files_done, 10);
}

#[test]
fn finished_is_the_last_event() {
    let dir = TempDir::new("ordering");
    let jobs: Vec<FileJob> = (0..8)
        .map(|index| job_for(&dir.file(&format!("f-{index}.bin"), 3000 + index)))
        .collect();

    let report = run_scan_expecting_finished_last(ScanConfig::all_algorithms(jobs));
    assert_eq!(report.outcome, ScanOutcome::Complete);
    assert_eq!(report.results.len(), 8);
}

/// A handle that is dropped must take the scan with it: no worker may still be
/// reading a file after the caller has forgotten the scan.
#[test]
fn dropping_the_handle_stops_the_scan_promptly() {
    let dir = TempDir::new("drop");
    let jobs: Vec<FileJob> = (0..16)
        .map(|index| job_for(&dir.file(&format!("drop-{index}.bin"), BLOCK_SIZE + index)))
        .collect();

    let started = Instant::now();
    let handle: ScanHandle = start(ScanConfig::all_algorithms(jobs), Box::new(|_| {}));
    drop(handle);
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(60),
        "dropping the handle took {elapsed:?}; it must cancel and join"
    );
}

// ---------------------------------------------------------------------------
// cancellation
// ---------------------------------------------------------------------------

/// Cancelling after the first file must stop the rest.
///
/// # Why the files here are large and hollow
///
/// The canceller wakes within a millisecond of the first `FileFinished`, but the
/// other workers do not stop the instant the flag is set: they stop when they next
/// look at it, which for a worker already inside a file is at the next block. With
/// small files that window is long enough for every other worker to finish, and the
/// assertion below then fails with a message about cancellation having reported
/// every file -- measured on i686, where the whole-suite run made the machine far
/// busier than a single-test run did.
///
/// Large files turn that race into a certainty: a worker that has started a 64 MiB
/// file cannot finish it in the time the flag takes to set. One small file is kept
/// so a `FileFinished` arrives promptly to trigger the cancellation.
#[test]
fn cancelling_mid_scan_stops_the_work_and_reports_cancelled() {
    let dir = TempDir::new("cancel");
    let mut jobs: Vec<FileJob> = vec![job_for(&dir.file("cancel-small.bin", 4096))];
    jobs.extend(
        (0..63).map(|index| {
            job_for(&dir.large_file(&format!("cancel-{index}.bin"), 64 * 1024 * 1024))
        }),
    );

    let report = run_scan(
        ScanConfig::all_algorithms(jobs),
        CancelTrigger::AfterFirstFile,
    );

    assert_eq!(
        report.outcome,
        ScanOutcome::Cancelled,
        "a cancelled scan must say so rather than claiming completeness"
    );
    assert!(
        report.results.len() < 64,
        "cancellation reported every file anyway: {} results",
        report.results.len()
    );
}

#[test]
fn cancelling_before_anything_runs_finishes_immediately() {
    let dir = TempDir::new("cancel-now");
    let jobs: Vec<FileJob> = (0..32)
        .map(|index| job_for(&dir.file(&format!("now-{index}.bin"), 1024)))
        .collect();

    let started = Instant::now();
    let report = run_scan(ScanConfig::all_algorithms(jobs), CancelTrigger::Immediately);

    assert_eq!(report.outcome, ScanOutcome::Cancelled);
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "cancelling an idle scan must not wait for anything"
    );
}

/// Cancelling a scan whose files are being read right now must not deadlock on
/// the buffer pool, which is where a naive implementation waits forever.
#[test]
fn cancelling_a_scan_of_large_files_does_not_deadlock() {
    let dir = TempDir::new("cancel-large");
    let jobs: Vec<FileJob> = (0..4)
        .map(|index| job_for(&dir.file(&format!("big-{index}.bin"), 4 * BLOCK_SIZE)))
        .collect();

    let report = run_scan(
        ScanConfig::all_algorithms(jobs),
        CancelTrigger::AfterFirstFile,
    );

    assert_eq!(report.outcome, ScanOutcome::Cancelled);
}
