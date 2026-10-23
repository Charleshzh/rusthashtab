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

use crate::{Counters, JobSpec, ListRow, MAX_HASHED_FILES};
use rusthashtab_hash::ALGORITHMS;
use rusthashtab_scan::{FileResult, ScanConfig, ScanEvent, ScanOutcome, expand_selection_with};
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
    /// Every job the scan was given, in job order.
    ///
    /// Indexed by the same `job_index` the scan reports, which is what lets a
    /// result be turned into rows with the job's display path without the sink
    /// having to remember it.
    jobs: Mutex<Vec<JobSpec>>,
    /// Each job's result, once it has finished; `None` while it is still running.
    ///
    /// Kept in addition to the [`Readout`] queue because the row list has to be
    /// rebuildable from the finished results alone: draining the queue must not
    /// mean forgetting the files that were already shown.
    results: Mutex<Vec<Option<FileResult>>>,
    /// Expected digests per job, from the verification source in effect.
    ///
    /// Mutable while the scan runs: a pasted digest or a checksum file can arrive
    /// after hashing has started, and the next result must be judged against it.
    expected: Mutex<Vec<Vec<Vec<u8>>>>,
    /// Which verification source produced [`Shared::expected`], if any.
    verification: Mutex<Option<VerificationInfo>>,
    /// Details of the checksum file this page interpreted as a manifest, if any.
    ///
    /// Kept separately from [`VerificationInfo`] because the status line only says
    /// that the source was a manifest; the page also needs to know whether the
    /// current scan is a manifest scan when it decides how a settings change
    /// applies.
    manifest: Mutex<Option<ManifestInfo>>,
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
            jobs: Mutex::new(Vec::new()),
            results: Mutex::new(Vec::new()),
            expected: Mutex::new(Vec::new()),
            verification: Mutex::new(None),
            manifest: Mutex::new(None),
            counters: Mutex::new(Counters::default()),
            display: Mutex::new(Display {
                enabled: Vec::new(),
                uppercase: true,
                look_for_sumfiles: false,
                hash_sumfile_too: false,
                sumfile_algorithm_only: true,
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

    /// Replace the scan's display snapshot.
    ///
    /// Written by the session thread once, after it has worked out the effective
    /// algorithm set (a checksum-file manifest can temporarily enable the
    /// algorithm its extension names). The page reads it back when the job list
    /// is published, so both sides build rows with the same `enabled` vector.
    pub(crate) fn set_display(&self, display: Display) {
        *self
            .display
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = display;
    }

    /// Change the digest case used for rows that finish from now on.
    ///
    /// The page applies a display-only settings change without restarting the
    /// scan; the collector reads this value for every result, so rows that arrive
    /// after the change cannot stick to the previous spelling.
    pub(crate) fn set_uppercase(&self, uppercase: bool) {
        self.display
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .uppercase = uppercase;
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

    /// Publish the job list, and reset the per-job result and expected slots.
    ///
    /// Called by the session thread after the selection has been expanded and the
    /// cap applied, before the scan starts. The other two vectors are rebuilt to
    /// the same length here rather than by the caller, because the three are
    /// indexed together: a result stored against a job index only means anything
    /// if the job list and the expected table have that index too.
    pub fn set_jobs(&self, jobs: Vec<JobSpec>) {
        let length = jobs.len();
        *self.lock_jobs() = jobs;
        *self.lock_results() = vec![None; length];
        *self.lock_expected() = vec![Vec::new(); length];
    }

    /// The job at `index`, or `None` when the list is shorter.
    pub fn job_at(&self, index: usize) -> Option<JobSpec> {
        self.lock_jobs().get(index).cloned()
    }

    /// Every job the scan was given, in job order.
    ///
    /// A snapshot, because a verification request matches a checksum file
    /// against the selection as it was after expansion; the scan's job list does
    /// not change after it is published.
    pub fn jobs(&self) -> Vec<JobSpec> {
        self.lock_jobs().clone()
    }

    /// Record one file's result, by job index.
    ///
    /// An index past the end is discarded rather than extending the vector: a
    /// result for a job the page does not have cannot be displayed, and growing
    /// the vector would take the job and result lists out of step.
    pub fn store_result(&self, index: usize, result: FileResult) {
        if let Some(slot) = self.lock_results().get_mut(index) {
            *slot = Some(result);
        }
    }

    /// Every result stored so far, in job order; `None` while a job is running.
    pub fn results(&self) -> Vec<Option<FileResult>> {
        self.lock_results().clone()
    }

    /// Replace the expected digests, one vector per job.
    ///
    /// A shorter vector is legal: a job past its end simply has nothing to compare
    /// against.
    pub fn set_expected(&self, expected: Vec<Vec<Vec<u8>>>) {
        *self.lock_expected() = expected;
    }

    /// The expected digests for one job, or nothing when the index is past the end.
    pub fn expected_at(&self, index: usize) -> Vec<Vec<u8>> {
        self.lock_expected().get(index).cloned().unwrap_or_default()
    }

    /// Every job's expected digests, in job order.
    ///
    /// Used when one job's expectation is replaced (a pasted digest) or the whole
    /// table is replaced (a checksum file): the caller edits a snapshot and
    /// publishes it back with [`Shared::set_expected`].
    pub fn expected_all(&self) -> Vec<Vec<Vec<u8>>> {
        self.lock_expected().clone()
    }

    /// Record the verification source in effect, or clear it with `None`.
    ///
    /// The source is published with the digests it produced, so the status line can
    /// always name where the verdicts came from.
    pub fn set_verification(&self, info: impl Into<Option<VerificationInfo>>) {
        *self.lock_verification() = info.into();
    }

    /// The verification source in effect, if any.
    pub fn verification(&self) -> Option<VerificationInfo> {
        self.lock_verification().clone()
    }

    /// Record the manifest this page was started from, or clear it with `None`.
    pub fn set_manifest(&self, info: Option<ManifestInfo>) {
        *self
            .manifest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = info;
    }

    /// The manifest this page was started from, if the selection was one.
    pub fn manifest(&self) -> Option<ManifestInfo> {
        self.manifest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Replace the status line's counters.
    ///
    /// Used when the whole result set is re-judged -- a new verification source
    /// changes every verdict -- so the new counts are published in one step and a
    /// reader never sees half of the old summary and half of the new one.
    pub fn replace_counters(&self, counters: Counters) {
        *self.lock_counters() = counters;
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

    /// See [`Shared::lock_readouts`].
    fn lock_jobs(&self) -> MutexGuard<'_, Vec<JobSpec>> {
        self.jobs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// See [`Shared::lock_readouts`].
    fn lock_results(&self) -> MutexGuard<'_, Vec<Option<FileResult>>> {
        self.results
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// See [`Shared::lock_readouts`].
    fn lock_expected(&self) -> MutexGuard<'_, Vec<Vec<Vec<u8>>>> {
        self.expected
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// See [`Shared::lock_readouts`].
    fn lock_verification(&self) -> MutexGuard<'_, Option<VerificationInfo>> {
        self.verification
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
    /// Discovery found this many files so far.
    ///
    /// Defaulted so the collectors that only care about hashing do not have to
    /// grow a method they would ignore.
    fn discovering(&self, _files: usize) {}
    /// The job list is published; `jobs` files will be hashed.
    fn jobs_ready(&self, _jobs: usize) {}
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

    fn discovering(&self, files: usize) {
        (**self).discovering(files);
    }

    fn jobs_ready(&self, jobs: usize) {
        (**self).jobs_ready(jobs);
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

    fn discovering(&self, files: usize) {
        self.post(crate::WM_DISCOVERY_PROGRESS, files as isize);
    }

    fn jobs_ready(&self, jobs: usize) {
        self.post(crate::WM_JOBS_READY, jobs as isize);
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

/// What the page knows about the verification source currently in effect.
///
/// One value rather than three independent fields: the status line prints the
/// source, the number of entries that matched no file, and whether any line was
/// malformed together, and a mix of one source's numbers with another source's
/// name would be a lie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationInfo {
    /// Where the expected digests came from, spelled the way the status line shows
    /// it (for example `checksum file: a.sha256`).
    pub source: String,
    /// Entries in the source that matched no file in the selection.
    pub unmatched: usize,
    /// Whether the source had lines that could not be parsed.
    pub had_error: bool,
    /// Checksum files found beside the hashed files that could not be read.
    ///
    /// Only sidecar lookups produce this: an explicitly chosen checksum file that
    /// cannot be read is reported with a message box instead.
    pub unreadable: usize,
}

/// What the page knows about a selection that was interpreted as a checksum-file
/// manifest.
///
/// The status line already names the source; this value exists so the page can
/// answer "is this scan a manifest scan" when a settings change has to decide
/// whether it affects the running work, and so tests can tell a manifest scan
/// from an ordinary one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestInfo {
    /// The checksum file that was interpreted.
    pub path: std::path::PathBuf,
    /// The algorithm inferred from its extension, if any.
    pub inferred: Option<usize>,
    /// Entries that named a file and became jobs.
    pub named_entries: usize,
    /// Whether the checksum file itself is also being hashed.
    pub sumfile_hashed: bool,
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
    /// Use a checksum file beside each hashed file as a verification source.
    ///
    /// Part of the session snapshot rather than read from the settings when the
    /// scan starts: the page can change settings while a scan runs, and the
    /// running scan must keep the behaviour it was given.
    pub look_for_sumfiles: bool,
    /// Also hash the checksum file itself when the selection is a manifest.
    pub hash_sumfile_too: bool,
    /// When the manifest's extension names an algorithm, use only that algorithm
    /// for this scan.
    ///
    /// A temporary choice: nothing here is written to the settings store.
    pub sumfile_algorithm_only: bool,
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
                // If anything in `run` panics, the page would otherwise wait
                // forever for a completion message that is never posted. The
                // wrapper's destructor reports cancellation on every path that
                // did not already report a finish.
                let sink: Box<dyn SessionSink> = Box::new(FinishOnDrop {
                    sink: Some(sink),
                    sent: AtomicBool::new(false),
                });
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
/// A selection that cannot be expanded at all is not `Cancelled`: expansion now
/// produces a job for every root it cannot stat, so the scanner reports those as
/// ordinary file errors and the page still gets its final "scan finished" message.
fn run(roots: &[PathBuf], sink: Box<dyn SessionSink>, shared: &Arc<Shared>) -> ScanOutcome {
    if shared.is_cancelled() {
        sink.finished(ScanOutcome::Cancelled);
        return ScanOutcome::Cancelled;
    }

    let mut display = shared.display();

    // A single selected checksum file is interpreted as a manifest: the files it
    // lists become the jobs, with their expected digests attached. Detection and
    // parsing happen here, on the session thread, because they are file-system
    // work. A selection that does not qualify falls through to ordinary
    // expansion, so the page never loses the ability to hash the file itself.
    let manifest = manifest_for(roots, &display);
    let is_manifest = manifest.is_some();
    let jobs = if let Some((path, plan)) = manifest {
        let inferred_name = plan.inferred.map(|index| ALGORITHMS[index].name);
        display.enabled = plan.enabled;
        shared.set_display(display.clone());
        shared.set_manifest(Some(ManifestInfo {
            path: path.clone(),
            inferred: plan.inferred,
            named_entries: plan.named_entries,
            sumfile_hashed: display.hash_sumfile_too,
        }));
        shared.set_verification(VerificationInfo {
            source: crate::resource::manifest_source(&path, inferred_name),
            unmatched: plan.unmatched,
            had_error: plan.had_error,
            unreadable: 0,
        });
        sink.discovering(plan.jobs.len());
        plan.jobs
    } else {
        sink.discovering(0);
        expand_selection_with(roots, &|| shared.is_cancelled(), &mut |discovery| {
            sink.discovering(discovery.files)
        })
    };

    if shared.is_cancelled() {
        sink.finished(ScanOutcome::Cancelled);
        return ScanOutcome::Cancelled;
    }

    let mut jobs = jobs;

    // The cap. Applied here rather than refusing the selection, so a directory of a
    // hundred thousand files performs a hundred thousand's worth of *visible* work
    // instead of making the page look hung.
    if jobs.len() > MAX_HASHED_FILES {
        let skipped = jobs.len() - MAX_HASHED_FILES;
        jobs.truncate(MAX_HASHED_FILES);
        shared.skipped.store(skipped, Ordering::Release);
    }

    // A checksum file beside each hashed file is an automatic verification
    // source when the setting asks for one. It is read here, on the session
    // thread, because it is file-system work and the dialog's thread must not
    // wait on it. A manifest scan already has its expectations from the manifest,
    // so sidecars are deliberately not consulted there.
    if display.look_for_sumfiles && !is_manifest {
        let attached = crate::verify::attach_sidecars(&mut jobs, &display.enabled);
        if attached.attached > 0
            || attached.unmatched > 0
            || attached.had_error
            || attached.unreadable > 0
        {
            shared.set_verification(VerificationInfo {
                source: String::from("checksum files beside the hashed files"),
                unmatched: attached.unmatched,
                had_error: attached.had_error,
                unreadable: attached.unreadable,
            });
        }
    }

    // Publish what is about to be scanned, before the scan starts: the sink needs
    // each job's display path to build the file column, and the result slots have
    // to exist before the first result arrives. The expected digests are the ones
    // the manifest or the sidecar scan attached (usually none); a source that
    // arrives during the scan replaces them through `set_expected`.
    shared.set_jobs(
        jobs.iter()
            .map(|job| JobSpec {
                path: job.path.clone(),
                display_path: job.display_path.clone(),
            })
            .collect(),
    );
    shared.set_expected(jobs.iter().map(|job| job.expected.clone()).collect());

    shared.files_total.store(jobs.len(), Ordering::Release);

    // Posted only after the job list and its expectation table are published: the
    // page's handler rebuilds from `Shared` when it receives this message, and a
    // message that arrived first would find an empty job list.
    sink.jobs_ready(jobs.len());

    let config = ScanConfig {
        jobs,
        enabled: display.enabled.clone(),
        workers: 0,
        scheduling: rusthashtab_scan::Scheduling::Auto,
    };

    let scan_cancelled = Arc::new(AtomicBool::new(false));
    let collector = Collector {
        shared: Arc::clone(shared),
        sink,
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

/// Interpret a single selected checksum file as a manifest.
///
/// Returns the normalized path and the plan. `None` means "not a manifest": more
/// than one root, a directory, an unregistered extension, an unreadable file, or
/// a file with no entry that names a file. Every `None` falls back to ordinary
/// hashing, so a failed interpretation never loses the selection.
fn manifest_for(
    roots: &[PathBuf],
    display: &Display,
) -> Option<(PathBuf, crate::manifest::ManifestPlan)> {
    let [root] = roots else {
        return None;
    };
    let path = rusthashtab_scan::normalize_path(root);
    let plan = crate::manifest::plan(
        &path,
        &display.enabled,
        display.hash_sumfile_too,
        display.sumfile_algorithm_only,
    )?;
    Some((path, plan))
}

/// One flag, shared between the collector and the function that owns it.
///
/// A `Collector` field rather than an `Arc` per event: the collector is moved into
/// the scan's closure, so a field would be captured by value and be unreachable from
/// outside; the `Arc` is what both sides hold.
type ScanFlag = Arc<AtomicBool>;

/// A sink that reports cancellation if it is dropped without a finish.
///
/// `run` has several early returns, all of which call `finished` explicitly. This
/// guard covers the path those cannot: a panic unwinding out of the session
/// thread. The page must never be left waiting for a completion message that no
/// one will post, and the destructor runs during unwinding.
struct FinishOnDrop {
    sink: Option<Box<dyn SessionSink>>,
    sent: AtomicBool,
}

impl SessionSink for FinishOnDrop {
    fn progress(&self, steps: u64) {
        if let Some(sink) = &self.sink {
            sink.progress(steps);
        }
    }

    fn rows_ready(&self) {
        if let Some(sink) = &self.sink {
            sink.rows_ready();
        }
    }

    fn finished(&self, outcome: ScanOutcome) {
        if self.sent.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(sink) = &self.sink {
            sink.finished(outcome);
        }
    }

    fn discovering(&self, files: usize) {
        if let Some(sink) = &self.sink {
            sink.discovering(files);
        }
    }

    fn jobs_ready(&self, jobs: usize) {
        if let Some(sink) = &self.sink {
            sink.jobs_ready(jobs);
        }
    }
}

impl Drop for FinishOnDrop {
    fn drop(&mut self) {
        if self.sent.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(sink) = self.sink.take() {
            sink.finished(ScanOutcome::Cancelled);
        }
    }
}

/// The scan's sink: turns events into [`Readout`]s and notifications.
///
/// Owns the sink rather than borrowing it, because `rusthashtab_scan::start` wants
/// a `Send + 'static` closure and a borrowed sink cannot satisfy that. Moving it in
/// also means the sink is dropped by whichever thread finishes last, which is the
/// thread that will never use it again.
struct Collector {
    shared: Arc<Shared>,
    sink: Box<dyn SessionSink>,
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
                job_index, result, ..
            } => {
                // The result is stored before the rows are built, so a reader that
                // sees the rows can also look the result up; draining the row queue
                // must not be the only place a finished file is remembered.
                self.shared.store_result(job_index, result.clone());

                // Read the display snapshot for every result rather than capturing
                // it when the collector was built: a display-only settings change
                // (upper-case hex) applies without restarting the scan, and rows
                // that arrive after it must not stick to the previous spelling.
                let display = self.shared.display();

                // The event's own verdict is deliberately ignored: it was computed
                // against the expected digests the scan was started with, and a
                // verification source can arrive *while* the scan runs. Recomputing
                // against the digests stored on `Shared` is what keeps a row's
                // colour consistent with the source the dialog currently shows.
                let expected = self.shared.expected_at(job_index);
                let verdict = rusthashtab_scan::match_state(&result, &expected, &display.enabled);

                // The job list was published before the scan started, so the job is
                // there. The empty fallback only matters if that contract is broken,
                // and an empty path is still displayed honestly.
                let display_path = self
                    .shared
                    .job_at(job_index)
                    .map(|job| job.display_path)
                    .unwrap_or_default();

                let rows = crate::readout::rows_for(
                    job_index,
                    &display_path,
                    &result,
                    &display.enabled,
                    display.uppercase,
                    verdict,
                    &expected,
                );
                self.shared.accept(Readout {
                    job_index,
                    rows,
                    match_state: verdict,
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

    fn job(display_path: &str) -> crate::JobSpec {
        crate::JobSpec {
            path: PathBuf::from(format!(r"C:\dir\{display_path}")),
            display_path: display_path.to_string(),
        }
    }

    fn result_for(path: &str, error: Option<u32>) -> FileResult {
        FileResult {
            path: PathBuf::from(path),
            digests: Vec::new(),
            size: 0,
            error,
        }
    }

    /// Publishing a job list sizes the result and expected tables with it: the
    /// three are indexed by the same job index, so a shorter table would silently
    /// route a result to the wrong slot.
    #[test]
    fn set_jobs_sizes_the_result_and_expected_tables() {
        let shared = Shared::new();
        shared.set_jobs(vec![job("a.bin"), job("b.bin")]);

        assert_eq!(
            shared.job_at(0),
            Some(job("a.bin")),
            "the job is readable back"
        );
        assert_eq!(shared.job_at(1), Some(job("b.bin")));
        assert_eq!(shared.job_at(2), None, "past the end is no job");
        assert_eq!(shared.results(), vec![None, None]);
        assert!(shared.expected_at(0).is_empty());
        assert!(shared.expected_at(1).is_empty());

        // Replacing the list with a shorter one must shrink the other tables too,
        // or a stale result would stay addressable past the end.
        shared.set_jobs(vec![job("c.bin")]);
        assert_eq!(shared.results().len(), 1);
        assert_eq!(shared.job_at(1), None);
    }

    /// A result is stored under the job index the scan reported, and an index the
    /// page does not have is discarded rather than growing the vector.
    #[test]
    fn results_are_stored_and_read_back_by_job_index() {
        let shared = Shared::new();
        shared.set_jobs(vec![job("a.bin"), job("b.bin")]);

        shared.store_result(1, result_for(r"C:\dir\b.bin", None));
        let results = shared.results();
        assert_eq!(results[0], None, "a running job has no result");
        assert_eq!(
            results[1],
            Some(result_for(r"C:\dir\b.bin", None)),
            "the result is stored under its job index"
        );

        shared.store_result(9, result_for(r"C:\dir\gone.bin", None));
        assert_eq!(
            shared.results().len(),
            2,
            "an out-of-range result must not extend the table"
        );
    }

    /// Expected digests are per job, and an index past the end has nothing to
    /// compare against rather than an error.
    #[test]
    fn expected_digests_are_per_job() {
        let shared = Shared::new();
        shared.set_jobs(vec![job("a.bin"), job("b.bin")]);
        shared.set_expected(vec![vec![vec![0xAA, 0xBB]], Vec::new()]);

        assert_eq!(shared.expected_at(0), vec![vec![0xAA, 0xBB]]);
        assert!(shared.expected_at(1).is_empty());
        assert!(
            shared.expected_at(9).is_empty(),
            "a job past the expected table has nothing to check"
        );
    }

    /// The verification source is published with its counts, and can be cleared
    /// when the source goes away.
    #[test]
    fn verification_info_round_trips_and_can_be_cleared() {
        let shared = Shared::new();
        assert_eq!(shared.verification(), None);

        let info = VerificationInfo {
            source: "checksum file: a.sha256".to_string(),
            unmatched: 2,
            had_error: true,
            unreadable: 1,
        };
        shared.set_verification(info.clone());
        assert_eq!(shared.verification(), Some(info));

        shared.set_verification(None);
        assert_eq!(shared.verification(), None);
    }

    /// Re-judging the result set publishes the whole counter summary at once.
    #[test]
    fn counters_can_be_replaced() {
        let shared = Shared::new();
        let counters = Counters {
            matched: 3,
            mismatched: 1,
            nothing_to_check: 2,
            error: 4,
        };
        shared.replace_counters(counters);
        assert_eq!(shared.counters(), counters);
    }
}
