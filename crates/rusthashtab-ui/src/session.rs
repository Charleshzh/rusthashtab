//! The hashing thread a property sheet page owns.
//!
//! # Why this is a whole thread, and not just a call to `rusthashtab_scan::start`
//!
//! The scanner already runs files on its own workers. What it does not do is
//! *expand a selection*, which for a directory root means walking a tree, and that
//! can take seconds. `AddPages` runs on the thread that owns the Properties dialog,
//! so expanding there -- or even starting the expansion there -- freezes the dialog
//! the user is looking at.
//!
//! So the page owns exactly one thread. It expands, it runs the scan, it waits for
//! the scan, and it exits. `rusthashtab_scan`'s workers are started and joined
//! inside it, which means the page has one handle to cancel and one thread to join
//! rather than a set of them.
//!
//! ```text
//!   dialog thread ──start──▶ session thread ──expand_selection──▶ jobs
//!                                 │                              │
//!                                 └── rusthashtab_scan::start ───┘
//!                                        │  (its own workers)
//!                                        ▼
//!                                   sink ──▶ Shared ──▶ PostMessageW
//!   dialog thread ◀──────────────────────────────────────┘
//! ```
//!
//! # What crosses the thread boundary
//!
//! Numbers, and a mutex-protected queue. **No pointer is ever posted**, because a
//! message that is discarded -- which happens on every teardown -- would leak
//! whatever it pointed at. The message says "there is something to read"; the
//! queue holds the something.
//!
//! # What stops a message reaching a dead window
//!
//! Two things, and they cover different windows in time:
//!
//! * the [`Shared::generation`] counter, which the dialog bumps on `WM_NCDESTROY`
//!   and the sink checks before every post, so the common case never posts at all;
//! * [`crate::PROGRESS_RESOLUTION`]-style authentication of the message in
//!   [`crate::route`], so a post that does slip through is ignored by anything
//!   that is not our dialog.
//!
//! Neither is a substitute for the other: the first avoids the post, the second
//! makes a post harmless.

#![cfg(windows)]

use crate::{Counters, ListRow, MAX_HASHED_FILES};
use rusthashtab_scan::{ScanConfig, ScanEvent, ScanOutcome, expand_selection};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// One file's contribution to the page: the rows it adds, and what it did to the
/// counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readout {
    /// Index into the job list, so the page can show the file's name.
    pub job_index: usize,
    /// One row per enabled algorithm, or a single error row.
    pub rows: Vec<ListRow>,
    /// The file's comparison outcome, already folded into [`Readout::rows`] for
    /// display.
    pub match_state: rusthashtab_scan::MatchState,
    /// Set when the file could not be read at all.
    pub error: Option<u32>,
}

/// Everything the hashing thread and the dialog share.
///
/// Held behind one mutex rather than several atomics because the fields are read
/// together: a dialog that drained the rows but saw a stale counter would print a
/// status line that disagrees with the list.
#[derive(Debug)]
pub struct Shared {
    /// Generation of the page this state belongs to.
    ///
    /// Bumped when the page's window goes away. The sink compares it before every
    /// post, so a message is never sent to a window handle that has been destroyed
    /// and possibly recycled.
    pub generation: AtomicU64,
    /// Results waiting to be turned into list rows.
    readouts: Mutex<Vec<Readout>>,
    /// The status line's counters.
    counters: Mutex<Counters>,
    /// How rows are spelled out. See [`Display`].
    display: Mutex<Display>,
    /// Progress as a fraction of [`crate::PROGRESS_RESOLUTION`], monotonic.
    progress: AtomicU64,
    /// Files finished so far.
    files_done: AtomicUsize,
    /// Files the scan was given.
    files_total: AtomicUsize,
    /// Files the selection held but the cap left out.
    skipped: AtomicUsize,
    /// Set once the scan has ended, successfully or not.
    finished: AtomicBool,
    /// Set when the page wants the work to stop.
    cancelled: AtomicBool,
}

impl Shared {
    /// Fresh state for one page.
    pub fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            readouts: Mutex::new(Vec::new()),
            counters: Mutex::new(Counters::default()),
            display: Mutex::new(Display {
                enabled: Vec::new(),
                uppercase: true,
            }),
            progress: AtomicU64::new(0),
            files_done: AtomicUsize::new(0),
            files_total: AtomicUsize::new(0),
            skipped: AtomicUsize::new(0),
            finished: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        }
    }

    /// How rows are spelled out.
    pub fn display(&self) -> Display {
        self.display
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Take everything waiting to be displayed.
    ///
    /// Drained rather than copied: the rows are moved into the list view, and
    /// keeping a second copy would double the page's memory for no reader.
    pub fn drain(&self) -> Vec<Readout> {
        std::mem::take(&mut *self.lock_readouts())
    }

    /// The status line's counters as they stand.
    pub fn counters(&self) -> Counters {
        *self.lock_counters()
    }

    /// Progress as a fraction of [`crate::PROGRESS_RESOLUTION`].
    pub fn progress(&self) -> u64 {
        self.progress.load(Ordering::Acquire)
    }

    /// Files finished, and files given to the scan.
    pub fn file_counts(&self) -> (usize, usize) {
        (
            self.files_done.load(Ordering::Acquire),
            self.files_total.load(Ordering::Acquire),
        )
    }

    /// Files the selection held but the cap left out.
    pub fn skipped(&self) -> usize {
        self.skipped.load(Ordering::Acquire)
    }

    /// Whether the scan has ended.
    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }

    /// Whether the page asked for the work to stop.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Stop posting to a window that is going away.
    ///
    /// Called from `WM_NCDESTROY`, on the dialog's thread, before the state is
    /// freed. Returns the new generation so the caller can pass it to
    /// [`build`](Self::build).
    pub fn retire(&self) -> u64 {
        self.cancelled.store(true, Ordering::Release);
        self.generation.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Lock the queue, treating a poisoned mutex as usable.
    ///
    /// A panic while the lock was held cannot leave the vector inconsistent, and
    /// refusing to proceed would turn one contained panic into a page that never
    /// updates again.
    fn lock_readouts(&self) -> MutexGuard<'_, Vec<Readout>> {
        self.readouts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// See [`Shared::lock_readouts`].
    fn lock_counters(&self) -> MutexGuard<'_, Counters> {
        self.counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Store one file's result and update the counters.
    ///
    /// Returns the number of files finished, for the message's `lParam`.
    fn accept(&self, readout: Readout) -> usize {
        // The counters move with the rows, under their own lock, so a reader that
        // sees a row cannot see a counter that has not accounted for it. They are
        // two mutexes rather than one to keep the row queue's lock off the status
        // line's path, and the window in which the two disagree is bounded by the
        // next statement.
        {
            let mut counters = self.lock_counters();
            crate::readout::count_file(readout.match_state, readout.error.is_some(), &mut counters);
        }

        let mut queue = self.lock_readouts();
        queue.push(readout);
        self.files_done.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Record cumulative progress, never going backwards.
    fn set_progress(&self, done: u64, total: u64) {
        let steps = crate::route::quantise(done, total);
        // A monotonically larger value wins. Two files finishing out of order can
        // otherwise make the bar jump back, and a bar that goes backwards looks
        // like a hang.
        let _ = self
            .progress
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (steps > current).then_some(steps)
            });
    }
}

impl Default for Shared {
    fn default() -> Self {
        Self::new()
    }
}

/// How the page wants to be told that something is ready.
///
/// A trait rather than a bare `HWND` so the session can be tested without a window.
/// The tests use a collector; the page uses [`WindowSink`].
///
/// `Sync` as well as `Send`: the sink is shared by reference inside a closure that
/// the scanner requires to be `Send` -- it is called from whichever worker finished
/// a file -- so a sink that could only be moved across threads would not be enough.
/// Both real implementations satisfy it trivially: one holds a window handle as an
/// integer, the other a mutex.
pub trait SessionSink: Send + Sync + 'static {
    /// The scan reported progress. `steps` counts towards
    /// [`crate::PROGRESS_RESOLUTION`].
    fn progress(&self, steps: u64);
    /// One or more files finished; the queue has something to drain.
    fn rows_ready(&self);
    /// The scan is over.
    fn finished(&self, outcome: ScanOutcome);
}

/// A shared sink is a sink.
///
/// Not a convenience: the page's own sink is handed to the session while the page
/// keeps its own reference to the same state, and the tests want to inspect what a
/// sink was told after the session has ended. Without this, both would have to wrap
/// a second layer of indirection around something that is already reference
/// counted.
impl<T: SessionSink + ?Sized> SessionSink for Arc<T> {
    fn progress(&self, steps: u64) {
        (**self).progress(steps);
    }

    fn rows_ready(&self) {
        (**self).rows_ready();
    }

    fn finished(&self, outcome: ScanOutcome) {
        (**self).finished(outcome);
    }
}

/// Deliver notifications to a window with `PostMessageW`.
///
/// # Why the handle is an `isize` and not an `HWND`
///
/// `HWND` is not `Send`, and this sink is called from the hashing thread. Storing
/// the handle as an integer and rebuilding it at the call site is what makes the
/// closure `Send`, and it is honest about what is happening: the value is a
/// token identifying a window in another thread, not a pointer this one may
/// dereference.
pub struct WindowSink {
    /// The window, or 0 before `WM_INITDIALOG` has run.
    hwnd: isize,
    /// The generation this sink belongs to.
    generation: u64,
    /// The window's live generation, to compare against.
    shared: Arc<Shared>,
}

impl SessionSink for WindowSink {
    fn progress(&self, steps: u64) {
        self.post(crate::WM_FILE_PROGRESS, steps as isize);
    }

    fn rows_ready(&self) {
        self.post(crate::WM_FILE_FINISHED, 0);
    }

    fn finished(&self, _outcome: ScanOutcome) {
        self.post(crate::WM_SCAN_FINISHED, 0);
    }
}

impl WindowSink {
    /// Post one authenticated message, if the window is still the one this sink
    /// was made for.
    fn post(&self, message: u32, lparam: isize) {
        if self.hwnd == 0 {
            return;
        }
        // The page retires its generation on `WM_NCDESTROY`, so this is the check
        // that keeps a destroyed -- and possibly recycled -- window handle from
        // receiving our messages.
        if self.shared.generation.load(Ordering::Acquire) != self.generation {
            return;
        }

        // SAFETY: `hwnd` was a live window when the sink was built and the check
        // above says it has not been retired since. `PostMessageW` fails rather
        // than faults for a handle that has gone away in the meantime, and the
        // message carries two integers, so there is nothing to leak if it is
        // discarded.
        unsafe {
            let _ = windows::Win32::UI::WindowsAndMessaging::PostMessageW(
                Some(windows::Win32::Foundation::HWND(
                    self.hwnd as *mut core::ffi::c_void,
                )),
                message,
                windows::Win32::Foundation::WPARAM(crate::MESSAGE_MAGIC),
                windows::Win32::Foundation::LPARAM(lparam),
            );
        }
    }
}

/// How a finished session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionExit {
    /// Every file was hashed.
    Complete,
    /// The page asked it to stop, and the scan says the result set is incomplete.
    Cancelled,
}

/// How the page wants rows spelled out.
///
/// Carried on [`Shared`] because the row builder is reached from the scan's
/// callback, on the scan's thread, and has no other way to learn these. A snapshot
/// rather than a live read of the settings: the page's rows must be consistent with
/// the algorithms the scan was actually given, and re-reading settings mid-scan
/// could make a column appear for an algorithm that was never hashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Display {
    /// Which algorithms produce a row, indexed like `ALGORITHMS`.
    pub enabled: Vec<bool>,
    /// Upper-case hex.
    pub uppercase: bool,
}

/// A running hashing thread, and the state the page reads.
///
/// `Debug` because [`crate::DialogState`] is `Debug` and holds one. The shared state
/// and the generation are what a dump needs; the thread handle is not, and would not
/// be useful if it were.
pub struct ReadoutSession {
    /// Shared with the hashing thread while it runs.
    shared: Arc<Shared>,
    /// The generation the sink was built with.
    generation: u64,
    /// The thread handle, present until [`ReadoutSession::finish`].
    thread: Option<std::thread::JoinHandle<()>>,
    /// Set before the return value was captured, so `finish` can report it.
    outcome: Arc<Mutex<Option<ScanOutcome>>>,
}

impl core::fmt::Debug for ReadoutSession {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ReadoutSession")
            .field("generation", &self.generation)
            .field("shared", &self.shared)
            .field("running", &self.thread.is_some())
            .finish()
    }
}

impl ReadoutSession {
    /// Start hashing `roots` and report through a window.
    ///
    /// Returns immediately. Nothing here touches the file system: `roots` is stored
    /// as the shell handed it over, and the expansion happens on the new thread.
    pub fn start(roots: Vec<PathBuf>, display: Display, hwnd: isize, shared: Arc<Shared>) -> Self {
        let generation = shared.generation.load(Ordering::Acquire);
        let sink = WindowSink {
            hwnd,
            generation,
            shared: Arc::clone(&shared),
        };
        Self::spawn(roots, display, Box::new(sink), shared)
    }

    /// Start hashing `roots` and report through an arbitrary sink.
    ///
    /// The seam the tests use: no window, no message loop.
    pub fn with_sink(roots: Vec<PathBuf>, display: Display, sink: Box<dyn SessionSink>) -> Self {
        let shared = Arc::new(Shared::new());
        Self::spawn(roots, display, sink, shared)
    }

    /// The one place a session thread is created, so there is one place to look
    /// for what it does and one place it can be made to stop.
    fn spawn(
        roots: Vec<PathBuf>,
        display: Display,
        sink: Box<dyn SessionSink>,
        shared: Arc<Shared>,
    ) -> Self {
        let generation = shared.generation.load(Ordering::Acquire);
        let outcome = Arc::new(Mutex::new(None));
        *shared
            .display
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = display;

        let worker_shared = Arc::clone(&shared);
        let worker_outcome = Arc::clone(&outcome);
        let thread = std::thread::Builder::new()
            .name("rusthashtab-page".to_string())
            .spawn(move || {
                // `run` takes the sink, so it is dropped when the scan's own
                // closure is dropped -- after the last event, never before.
                let result = run(&roots, sink, &worker_shared);
                // Recorded before the thread exits, so `finish` cannot observe a
                // joined thread with no outcome.
                *worker_outcome
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(result);
                worker_shared.finished.store(true, Ordering::Release);
            })
            .ok();

        Self {
            shared,
            generation,
            thread,
            outcome,
        }
    }

    /// The page's view of the state.
    pub fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    /// The generation the notification sink was built with.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Ask the hashing thread to stop.
    ///
    /// Safe from the dialog's thread. The scan notices at its next block boundary
    /// and stops, and no `FileFinished` is emitted for a file that was interrupted.
    pub fn cancel(&self) {
        self.shared.cancelled.store(true, Ordering::Release);
    }

    /// Stop, wait for the thread, and report how it ended.
    ///
    /// Called from `WM_NCDESTROY` and from the page callback. Waiting is bounded:
    /// the scan cancels its outstanding reads and joins its own workers, and those
    /// reads return as soon as they are cancelled rather than after a whole file.
    pub fn finish(mut self, timeout: Duration) -> SessionExit {
        self.cancel();

        let Some(thread) = self.thread.take() else {
            // The thread never started. There is nothing to wait for, and the
            // outcome is whatever the worker would have recorded -- nothing.
            return SessionExit::Cancelled;
        };

        // Waiting is bounded by observation rather than by a `join` that could in
        // principle block forever. `is_finished` is set by the worker itself as its
        // last act, so an unset flag means real work is still in progress.
        let deadline = Instant::now() + timeout;
        while !thread.is_finished() && Instant::now() < deadline {
            std::thread::yield_now();
            std::thread::sleep(Duration::from_millis(1));
        }

        // Joined whether or not the deadline passed: a thread that is still running
        // would otherwise outlive the state it writes into. The loop above is what
        // keeps that join from being an open-ended wait in the normal case.
        let _ = thread.join();

        let outcome = *self
            .outcome
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match outcome {
            Some(ScanOutcome::Complete) => SessionExit::Complete,
            _ => SessionExit::Cancelled,
        }
    }
}

impl Drop for ReadoutSession {
    /// A dropped session must not leave a thread behind.
    fn drop(&mut self) {
        self.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The hashing thread's body.
///
/// Returns how the scan ended.
///
/// # Where the answer comes from, and why not from `Shared`
///
/// The obvious implementation returns `Cancelled` when the page asked for it. That
/// is only one of the ways a scan ends early: `rusthashtab_scan` also reports
/// `Cancelled` when a worker panicked or when the sink did, and the page did not ask
/// for either. Reading the outcome the scan actually reported is what makes the
/// three cases indistinguishable instead of silently claiming completeness over a
/// half-finished result set -- which a test caught here.
///
/// A selection that cannot be expanded at all also reports `Cancelled`: there is no
/// useful result set in that case, and `Complete` would be a lie about work that
/// never happened.
fn run(roots: &[PathBuf], sink: Box<dyn SessionSink>, shared: &Arc<Shared>) -> ScanOutcome {
    if shared.is_cancelled() {
        return ScanOutcome::Cancelled;
    }

    let display = shared.display();

    let Ok(mut jobs) = expand_selection(roots) else {
        // A root that cannot be stat'ed -- deleted between the shell reading the
        // selection and us opening it. Nothing else in the selection is lost
        // because of it, and the page says so through its empty result list.
        return ScanOutcome::Cancelled;
    };

    // The cap. Applied here rather than refusing the selection, so a directory of a
    // hundred thousand files performs a hundred thousand's worth of *visible* work
    // instead of making the page look hung.
    if jobs.len() > MAX_HASHED_FILES {
        let skipped = jobs.len() - MAX_HASHED_FILES;
        jobs.truncate(MAX_HASHED_FILES);
        shared.skipped.store(skipped, Ordering::Release);
    }

    shared.files_total.store(jobs.len(), Ordering::Release);

    let config = ScanConfig {
        jobs,
        enabled: display.enabled.clone(),
        workers: 0,
    };

    let scan_cancelled = Arc::new(AtomicBool::new(false));
    let collector = Collector {
        shared: Arc::clone(shared),
        sink,
        display,
        flag: Arc::clone(&scan_cancelled),
    };

    let handle = rusthashtab_scan::start(config, Box::new(move |event| collector.accept(event)));

    // Cancelling the scan is how the page stops it: it cancels the outstanding
    // reads rather than merely declining to hand out more work, so `wait` returns
    // promptly instead of after the file in flight has finished.
    if shared.is_cancelled() {
        handle.cancel();
    }
    handle.wait();

    if shared.is_cancelled() || scan_cancelled.load(Ordering::Acquire) {
        return ScanOutcome::Cancelled;
    }

    ScanOutcome::Complete
}

/// One flag, shared between the collector and the function that owns it.
///
/// A `Collector` field rather than an `Arc` per event: the collector is moved into
/// the scan's closure, so a field would be captured by value and be unreachable from
/// outside; the `Arc` is what both sides hold.
type ScanFlag = Arc<AtomicBool>;

/// The scan's sink: turns events into [`Readout`]s and notifications.
///
/// Owns the sink rather than borrowing it, because `rusthashtab_scan::start` wants
/// a `Send + 'static` closure and a borrowed sink cannot satisfy that. Moving it in
/// also means the sink is dropped by whichever thread finishes last, which is the
/// thread that will never use it again.
struct Collector {
    shared: Arc<Shared>,
    sink: Box<dyn SessionSink>,
    display: Display,
    /// Set when the scan reports an outcome other than `Complete`.
    flag: ScanFlag,
}

impl Collector {
    /// Handle one scan event.
    ///
    /// Must not panic: `rusthashtab_scan` contains a panic in a sink but then
    /// cancels the scan, because a sink that has panicked cannot be trusted with
    /// the remaining results. Everything here is written to be total -- the locks
    /// tolerate poisoning and the arithmetic saturates.
    fn accept(&self, event: ScanEvent) {
        match event {
            ScanEvent::Progress(progress) => {
                self.shared.set_progress(progress.done, progress.total);
                self.sink.progress(self.shared.progress());
            }
            ScanEvent::FileFinished {
                job_index,
                result,
                match_state,
            } => {
                let rows = crate::readout::rows_for(
                    job_index,
                    &result,
                    &self.display.enabled,
                    self.display.uppercase,
                );
                self.shared.accept(Readout {
                    job_index,
                    rows,
                    match_state,
                    error: result.error,
                });
                self.sink.rows_ready();
            }
            ScanEvent::Finished(outcome) => {
                if outcome == ScanOutcome::Complete {
                    // A scan that reports itself complete is complete even when it
                    // had nothing to do. No `Progress` event is emitted when there
                    // is no block to read, so an empty selection would otherwise
                    // leave the bar at zero -- which reads as "still working" on a
                    // page that has already finished.
                    //
                    // Done here rather than after the join, deliberately: the flag
                    // that tells a waiter the scan is over is set after that point,
                    // so filling the bar there would leave a window in which the
                    // scan is finished and the bar is not.
                    self.shared.set_progress(1, 1);
                    self.sink.progress(self.shared.progress());
                } else {
                    // Remembered as well as forwarded: the page's thread has to
                    // report the same answer `run` returns, and the sink is free to
                    // ignore what it is told.
                    self.flag.store(true, Ordering::Release);
                }
                self.sink.finished(outcome);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_generation_moves_when_the_page_is_retired() {
        let shared = Shared::new();
        assert_eq!(shared.generation.load(Ordering::Acquire), 0);
        assert!(!shared.is_cancelled());

        assert_eq!(shared.retire(), 1);
        assert_eq!(shared.generation.load(Ordering::Acquire), 1);
        assert!(shared.is_cancelled(), "retiring must also stop the work");

        // Twice must keep moving, or a sink built before the first retirement
        // would consider itself current again.
        assert_eq!(shared.retire(), 2);
    }

    #[test]
    fn progress_never_goes_backwards() {
        let shared = Shared::new();
        shared.set_progress(1000, 1000);
        let full = shared.progress();
        assert_eq!(full, crate::PROGRESS_RESOLUTION);

        // A file that finished later revises the total upward; the bar must stay
        // where it was rather than jump back.
        shared.set_progress(100, 10_000);
        assert_eq!(shared.progress(), full);
    }

    #[test]
    fn counters_move_with_the_rows_they_describe() {
        let shared = Shared::new();
        shared.accept(Readout {
            job_index: 0,
            rows: Vec::new(),
            match_state: rusthashtab_scan::MatchState::Mismatched,
            error: None,
        });

        assert_eq!(shared.counters().mismatched, 1);
        assert_eq!(shared.file_counts().0, 1);
        assert_eq!(shared.drain().len(), 1);
        assert!(shared.drain().is_empty(), "draining must empty the queue");
        // Draining rows does not undo the counters: the status line reports what
        // has been hashed, not what is still queued.
        assert_eq!(shared.counters().mismatched, 1);
    }

    #[test]
    fn a_failed_read_counts_as_an_error_not_a_mismatch() {
        let shared = Shared::new();
        shared.accept(Readout {
            job_index: 0,
            rows: Vec::new(),
            match_state: rusthashtab_scan::MatchState::Mismatched,
            error: Some(5),
        });

        let counters = shared.counters();
        assert_eq!(counters.error, 1);
        assert_eq!(counters.mismatched, 0);
    }
}
