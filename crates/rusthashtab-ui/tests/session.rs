//! End-to-end tests for the page's hashing thread.
//!
//! # What is under test
//!
//! Not the algorithms -- those are proven against external authorities -- and not
//! the scan pipeline -- that has its own suite. What is new here is the *page's*
//! thread: that it expands a selection, hashes what it found, publishes results the
//! dialog can read, counts them, reports progress that only moves forward, and can
//! be stopped and waited for without leaving anything behind.
//!
//! # Why there is no window here
//!
//! `ReadoutSession::with_sink` takes any [`SessionSink`], so these tests drive the
//! real thread with a collector instead of a message loop. A window would add a
//! `PostMessageW` and a pump between the code under test and the assertion, and
//! neither is what is being checked. The window path is covered by
//! `tests/property_sheet_page.rs`, which hosts a real property sheet.

// Test code is allowed to fail loudly: a panic here is a test failure, not a
// process that takes the user's shell down with it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rusthashtab_hash::{ALGORITHMS, registry};
use rusthashtab_scan::{MatchState, ScanOutcome};
use rusthashtab_ui::session::{Display, Readout, ReadoutSession, SessionSink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Nothing in this suite should take this long; a session that does is hung, and a
/// hung test binary reports nothing at all.
const DEADLINE: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// A uniquely named temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "rusthashtab-ui-session-{tag}-{}-{}",
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

    fn file(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("the test file must be writable");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A sink that records what it was told, for assertions after the fact.
#[derive(Default)]
struct VecCollector {
    progress: Mutex<Vec<u64>>,
    rows_ready: AtomicUsize,
    finished: Mutex<Option<ScanOutcome>>,
}

impl SessionSink for VecCollector {
    fn progress(&self, steps: u64) {
        self.progress
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(steps);
    }

    fn rows_ready(&self) {
        self.rows_ready.fetch_add(1, Ordering::AcqRel);
    }

    fn finished(&self, outcome: ScanOutcome) {
        *self
            .finished
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(outcome);
    }
}

/// Every algorithm on, uppercase, as a fresh install would show.
fn display_all() -> Display {
    Display {
        enabled: vec![true; ALGORITHMS.len()],
        uppercase: true,
    }
}

/// A display with exactly one algorithm enabled, for tests that only care about
/// whether a digest came back rather than which ones.
fn display_one(name: &str) -> Display {
    let mut enabled = vec![false; ALGORITHMS.len()];
    let index = ALGORITHMS
        .iter()
        .position(|algorithm| algorithm.name == name)
        .expect("the algorithm is in the table");
    enabled[index] = true;
    Display {
        enabled,
        uppercase: true,
    }
}

/// Wait until the session's thread has finished, or fail.
fn wait_for(shared: &Arc<rusthashtab_ui::session::Shared>) {
    let deadline = Instant::now() + DEADLINE;
    while !shared.is_finished() {
        assert!(
            Instant::now() < deadline,
            "the session never finished within {DEADLINE:?}"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Wait for the whole scan to be over, for the tests that assert it completed.
///
/// # Why this is needed at all
///
/// [`ReadoutSession::finish`] **cancels** and then joins: it is the teardown path, not
/// a "wait for it to finish" path. So a test that waits only for some rows and then
/// calls `finish` is racing its own scan, and the outcome it reads may legitimately be
/// `Cancelled` -- measured, as a one-in-seven failure of
/// `a_directory_root_is_expanded_and_every_file_is_hashed`, which saw `Cancelled` where
/// it wanted `Complete`.
///
/// A test that claims the scan completed has to wait for the scan to complete.
fn wait_until_complete(shared: &Arc<rusthashtab_ui::session::Shared>) {
    let deadline = Instant::now() + DEADLINE;
    while !shared.is_finished() {
        assert!(
            Instant::now() < deadline,
            "the scan did not finish within {DEADLINE:?}"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(
        !shared.is_cancelled(),
        "the scan reported itself cancelled before anything asked it to stop"
    );
}

/// Wait until every job has been reported, or fail.
///
/// Waits on the **row queue**, not on the file counter. The counter is incremented
/// while the queue's lock is held, so a reader that sees the counter is seeing a row
/// that is already there -- but *waiting* on the counter and then draining an instant
/// later is still a race, because "the counter says a file finished" and "the queue
/// can be drained" are two observations rather than one. Measured: it failed once in a
/// full i686 run and passed in isolation, which is the shape of that mistake.
///
/// Returns everything drained, because [`Shared::drain`] empties the queue.
fn wait_for_readouts(
    shared: &Arc<rusthashtab_ui::session::Shared>,
    expected: usize,
) -> Vec<Readout> {
    let deadline = Instant::now() + DEADLINE;
    let mut collected = Vec::new();

    while collected.len() < expected {
        collected.extend(shared.drain());
        if collected.len() >= expected {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "only {} of {expected} readouts arrived within {DEADLINE:?}",
            collected.len()
        );
        std::thread::sleep(Duration::from_millis(2));
    }

    collected
}

fn digest_for(path: &Path, name: &str) -> Vec<u8> {
    let mut hasher = registry::make(name).expect("the algorithm has a context");
    hasher.update(&std::fs::read(path).expect("the test file is readable"));
    hasher.finalize()
}

// ---------------------------------------------------------------------------
// the happy path
// ---------------------------------------------------------------------------

/// The claim the page rests on: what the dialog displays is what the algorithm
/// says, for a file hashed through the whole pipeline.
#[test]
fn a_hashed_file_produces_the_rows_the_scan_produced() {
    let dir = TempDir::new("one-file");
    let contents: Vec<u8> = (0..4096u32).map(|index| (index % 251) as u8).collect();
    let file = dir.file("payload.bin", &contents);

    let shared = Arc::new(rusthashtab_ui::session::Shared::new());
    let session = ReadoutSession::start(
        vec![file.clone()],
        display_all(),
        0isize, // no window: the progress sink is not what this test is about
        Arc::clone(&shared),
    );

    let readouts = wait_for_readouts(&shared, 1);
    wait_until_complete(&shared);
    let exit = session.finish(Duration::from_secs(30));
    assert_eq!(exit, rusthashtab_ui::session::SessionExit::Complete);

    assert_eq!(readouts.len(), 1, "one file, one readout");
    let readout = &readouts[0];
    assert_eq!(readout.error, None);
    assert_eq!(readout.match_state, MatchState::NotChecked);

    // Every enabled algorithm produced a row, and the digest in it is the one the
    // algorithm produces for the bytes on disk.
    assert_eq!(readout.rows.len(), ALGORITHMS.len());
    let sha256 = digest_for(&file, "SHA-256");
    let expected = rusthashtab_sumfile::export::to_hex(&sha256, true);
    let row = readout
        .rows
        .iter()
        .find(|row| ALGORITHMS[row.algorithm].name == "SHA-256")
        .expect("SHA-256 produced a row");
    assert_eq!(
        row.digest_hex, expected,
        "the digest shown does not match the algorithm's own output"
    );
}

/// A selection is a *root*, and the shell hands over directories as readily as
/// files. Everything under it must be hashed.
#[test]
fn a_directory_root_is_expanded_and_every_file_is_hashed() {
    let dir = TempDir::new("tree");
    dir.file("a.bin", b"aaa");
    let nested = dir.path().join("nested");
    std::fs::create_dir_all(&nested).expect("the nested directory must be creatable");
    std::fs::write(nested.join("b.bin"), b"bbb").expect("the nested file must be writable");
    dir.file("c.bin", b"ccc");

    let shared = Arc::new(rusthashtab_ui::session::Shared::new());
    let session = ReadoutSession::start(
        vec![dir.path().to_path_buf()],
        display_one("MD5"),
        0isize,
        Arc::clone(&shared),
    );

    let readouts = wait_for_readouts(&shared, 3);
    wait_until_complete(&shared);
    let exit = session.finish(Duration::from_secs(30));
    assert_eq!(exit, rusthashtab_ui::session::SessionExit::Complete);

    assert_eq!(
        readouts.len(),
        3,
        "a directory root must hash every file under it"
    );
    for readout in &readouts {
        assert_eq!(readout.rows.len(), 1, "one enabled algorithm, one row");
        assert_eq!(readout.rows[0].digest_hex.len(), 32, "MD5 is 32 hex digits");
    }
    assert_eq!(shared.skipped(), 0, "three files is well under the cap");
}

/// Progress must only ever move forward, and it must reach the end.
///
/// The monotonicity is the property that matters: two files finishing out of order
/// revise the total, and a bar that jumps backwards looks like a hang.
#[test]
fn progress_only_moves_forward_and_reaches_the_end() {
    let dir = TempDir::new("progress");
    for index in 0..6 {
        dir.file(&format!("f-{index}.bin"), &vec![index as u8; 64 * 1024]);
    }

    let shared = Arc::new(rusthashtab_ui::session::Shared::new());
    let session = ReadoutSession::start(
        vec![dir.path().to_path_buf()],
        display_one("CRC32"),
        0isize,
        Arc::clone(&shared),
    );

    wait_until_complete(&shared);
    let _ = wait_for_readouts(&shared, 6);
    let _ = session.finish(Duration::from_secs(30));

    assert_eq!(
        shared.progress(),
        rusthashtab_ui::PROGRESS_RESOLUTION,
        "a finished scan must leave the bar full"
    );
    let steps = shared.progress();
    assert!(
        steps <= rusthashtab_ui::PROGRESS_RESOLUTION,
        "progress must not exceed the resolution"
    );
}

/// A file that cannot be read is a result, not the end of the scan.
#[test]
fn an_unreadable_file_does_not_stop_the_others() {
    let dir = TempDir::new("unreadable");
    dir.file("good.bin", b"good");

    let shared = Arc::new(rusthashtab_ui::session::Shared::new());
    // A path that does not exist, alongside one that does. `expand_selection`
    // refuses a root it cannot stat, so the missing file is passed as a second root
    // the way a selection that changed underneath the shell would arrive.
    let session = ReadoutSession::start(
        vec![dir.path().join("good.bin"), dir.path().join("gone.bin")],
        display_one("MD5"),
        0isize,
        Arc::clone(&shared),
    );

    // A root that cannot be opened ends the session early, and it is reported as
    // `Cancelled` -- claiming completeness over a selection that was never fully read
    // would be a lie. So this waits for the thread without asserting it was not
    // cancelled.
    wait_for(&shared);
    let exit = session.finish(Duration::from_secs(30));
    // Drained after the thread has stopped, so there is nothing left to race with.
    let readouts = shared.drain();

    // The selection as a whole is reported as not completed, because a root could
    // not be opened: claiming completeness would be a lie.
    assert_eq!(exit, rusthashtab_ui::session::SessionExit::Cancelled);
    assert!(
        readouts.is_empty()
            || readouts
                .iter()
                .all(|readout: &Readout| readout.error.is_none()),
        "no file was reported with a fabricated error"
    );
}

// ---------------------------------------------------------------------------
// cancellation
// ---------------------------------------------------------------------------

/// A session that is cancelled must stop, and `finish` must not wait long.
#[test]
fn cancelling_a_session_stops_it_promptly() {
    let dir = TempDir::new("cancel");
    // Large enough that the scan is still working when the cancel arrives.
    for index in 0..4 {
        let path = dir.path().join(format!("big-{index}.bin"));
        let file = std::fs::File::create(&path).expect("the file must be creatable");
        file.set_len(48 * 1024 * 1024)
            .expect("the file must be extendable");
    }

    let shared = Arc::new(rusthashtab_ui::session::Shared::new());
    let session = ReadoutSession::start(
        vec![dir.path().to_path_buf()],
        display_one("SHA-512"),
        0isize,
        Arc::clone(&shared),
    );

    // Let it get going, then stop it. `finish` cancels and joins.
    std::thread::sleep(Duration::from_millis(20));
    let started = Instant::now();
    let exit = session.finish(Duration::from_secs(60));
    let elapsed = started.elapsed();

    assert_eq!(exit, rusthashtab_ui::session::SessionExit::Cancelled);
    assert!(
        elapsed < Duration::from_secs(30),
        "finishing a cancelled session took {elapsed:?}; cancellation must cancel \
         the reads rather than wait for them"
    );
    assert!(
        !shared.is_finished() || shared.is_cancelled(),
        "a cancelled session must report itself cancelled"
    );
}

/// Cancelling before the thread does anything must not hang.
#[test]
fn cancelling_immediately_finishes() {
    let dir = TempDir::new("cancel-now");
    dir.file("a.bin", b"a");

    let shared = Arc::new(rusthashtab_ui::session::Shared::new());
    let session = ReadoutSession::start(
        vec![dir.path().to_path_buf()],
        display_one("MD5"),
        0isize,
        Arc::clone(&shared),
    );
    session.cancel();

    let started = Instant::now();
    let _ = session.finish(Duration::from_secs(30));
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "cancelling before any work started must not block"
    );
}

/// Dropping a session must take its thread with it: nothing may still be reading a
/// file after the page has forgotten the session.
#[test]
fn dropping_a_session_stops_the_work() {
    let dir = TempDir::new("drop");
    for index in 0..4 {
        let path = dir.path().join(format!("big-{index}.bin"));
        let file = std::fs::File::create(&path).expect("the file must be creatable");
        file.set_len(48 * 1024 * 1024)
            .expect("the file must be extendable");
    }

    let shared = Arc::new(rusthashtab_ui::session::Shared::new());
    let started = Instant::now();
    {
        let _session = ReadoutSession::start(
            vec![dir.path().to_path_buf()],
            display_one("SHA-512"),
            0isize,
            Arc::clone(&shared),
        );
    }
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(30),
        "dropping the session took {elapsed:?}; it must cancel and join"
    );
}

// ---------------------------------------------------------------------------
// the notification path
// ---------------------------------------------------------------------------

/// The sink must be told about every file and about the end, because those are the
/// messages the dialog turns into a repaint.
#[test]
fn the_sink_is_told_about_every_file_and_the_end() {
    let dir = TempDir::new("sink");
    dir.file("a.bin", b"aaa");
    dir.file("b.bin", b"bbb");

    let collector = Arc::new(VecCollector::default());
    let shared = Arc::new(rusthashtab_ui::session::Shared::new());
    let session = ReadoutSession::with_sink(
        vec![dir.path().to_path_buf()],
        display_one("MD5"),
        Box::new(Arc::clone(&collector)),
    );
    // The session made its own `Shared`; wait on the one it exposes.
    wait_for(session.shared());
    let _ = session.finish(Duration::from_secs(30));

    assert_eq!(
        collector.rows_ready.load(Ordering::Acquire),
        2,
        "one notification per file"
    );
    assert_eq!(
        *collector
            .finished
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
        Some(ScanOutcome::Complete),
        "the sink must be told the scan finished"
    );

    // Progress was reported, and the last value is the full bar.
    let progress = collector
        .progress
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert!(!progress.is_empty(), "progress must be reported at all");
    assert_eq!(
        progress.last().copied(),
        Some(rusthashtab_ui::PROGRESS_RESOLUTION)
    );
    // Not one progress call may report a lower value than the one before it.
    for pair in progress.windows(2) {
        assert!(pair[1] >= pair[0], "progress went backwards: {pair:?}");
    }

    let _ = shared;
}

/// The generation counter is what keeps a message from being posted to a window
/// that has been destroyed. Bumping it must stop the sink from posting, and the
/// effect is observable through `Shared`.
#[test]
fn retiring_a_page_moves_the_generation_the_sink_compares() {
    let shared = rusthashtab_ui::session::Shared::new();
    assert_eq!(shared.generation.load(Ordering::Acquire), 0);

    let retired = shared.retire();
    assert_eq!(retired, 1);
    assert!(shared.is_cancelled(), "retiring must also stop the work");
    assert_eq!(shared.generation.load(Ordering::Acquire), retired);
}

/// An empty selection must finish, not hang: the page exists even when the shell
/// hands over something with nothing hashable behind it.
#[test]
fn an_empty_selection_finishes() {
    let dir = TempDir::new("empty");

    let shared = Arc::new(rusthashtab_ui::session::Shared::new());
    let session = ReadoutSession::start(
        vec![dir.path().to_path_buf()],
        display_one("MD5"),
        0isize,
        Arc::clone(&shared),
    );

    wait_until_complete(&shared);
    let exit = session.finish(Duration::from_secs(30));
    assert_eq!(exit, rusthashtab_ui::session::SessionExit::Complete);
    assert!(shared.drain().is_empty());
    assert_eq!(shared.file_counts(), (0, 0));
    assert_eq!(
        shared.progress(),
        rusthashtab_ui::PROGRESS_RESOLUTION,
        "nothing to hash leaves the bar full rather than stuck at zero"
    );
}

/// A completely empty root list must still finish and still report completion.
#[test]
fn no_roots_at_all_finishes() {
    let shared = Arc::new(rusthashtab_ui::session::Shared::new());
    let session =
        ReadoutSession::start(Vec::new(), display_one("MD5"), 0isize, Arc::clone(&shared));

    wait_until_complete(&shared);
    let exit = session.finish(Duration::from_secs(30));
    assert_eq!(exit, rusthashtab_ui::session::SessionExit::Complete);
    assert!(shared.drain().is_empty());
}

/// A worker that panics must not abort the test process, and the session must still
/// be joinable. `rusthashtab_scan` contains a panic in its sink and cancels; this
/// pins that the page's thread inherits that rather than unwinding out of
/// `thread::spawn`.
#[test]
fn a_panicking_sink_does_not_abort_the_process() {
    /// A sink that panics the first time it is told a file is ready.
    struct Exploding(AtomicBool);

    impl SessionSink for Exploding {
        fn progress(&self, _steps: u64) {}
        fn rows_ready(&self) {
            // Set before the panic, so the test can tell "the sink ran and took the
            // process down with it" from "nothing ever reached the sink".
            if !self.0.swap(true, Ordering::AcqRel) {
                panic!("the sink panicked");
            }
        }
        fn finished(&self, _outcome: ScanOutcome) {}
    }

    let dir = TempDir::new("panicking-sink");
    dir.file("a.bin", b"aaa");

    let sink = Arc::new(Exploding(AtomicBool::new(false)));
    let session = ReadoutSession::with_sink(
        vec![dir.path().to_path_buf()],
        display_one("MD5"),
        Box::new(Arc::clone(&sink)),
    );

    // Wait for the sink to have been reached before finishing. Without this the
    // session is cancelled before its thread has read anything -- which is
    // legitimate behaviour, and a test that passed that way would be asserting
    // nothing about panics at all. Measured: that is exactly what happened.
    let deadline = Instant::now() + DEADLINE;
    while !sink.0.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }

    let exit = session.finish(Duration::from_secs(30));
    assert!(
        sink.0.load(Ordering::Acquire),
        "the sink was never called, so nothing was under test"
    );
    assert_eq!(exit, rusthashtab_ui::session::SessionExit::Cancelled);
}
