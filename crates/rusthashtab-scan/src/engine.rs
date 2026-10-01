//! The scheduler: worker threads, the job queue, progress and events.
//!
//! # Threading contract
//!
//! The scan owns its threads and shuts them down deterministically. There is no
//! global pool here — spawning rayon, tokio or the `std` pool inside
//! `explorer.exe` is a defect, not a convenience — and no thread outlives the
//! [`ScanHandle`] that created it: dropping the handle cancels the scan and joins
//! every worker.
//!
//! One worker processes one file at a time, from open to finalize, so the
//! per-file algorithm contexts never need to be shared. Files are handed out
//! from a shared queue, which is what lets a scan of one huge file and a scan of
//! a thousand small ones use the same code path.
//!
//! # Why the last worker finishes the scan
//!
//! `Finished` must be the last event, and it must arrive after every
//! `FileFinished`. Rather than run a separate coordinator thread, each worker
//! decrements a count on the way out, and the one that reaches zero emits
//! `Finished`. The decrement is an acquire-release operation, so the last worker
//! is guaranteed to see every event its siblings emitted, and the handle only
//! has to join the workers it actually started.
//!
//! The count starts at the number of workers *intended*, not the number created,
//! so a worker cannot finish the scan while its siblings are still being
//! spawned; workers that could not be created are subtracted by the spawner
//! below.

use crate::cancel::CancelToken;
use crate::compare::match_state;
use crate::pool::BufferPool;
use crate::reader::{ReadOutcome, ReadScratch, read_file};
use crate::{FileJob, FileResult, MatchState, Progress};
use rusthashtab_hash::{ALGORITHMS, Hasher, registry};
use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};

/// What to scan, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanConfig {
    /// The files to hash, in the order they were expanded.
    pub jobs: Vec<FileJob>,
    /// Which algorithms to hash with, indexed by position in
    /// [`rusthashtab_hash::ALGORITHMS`].
    ///
    /// A short vector is legal: positions past its end count as disabled. Use
    /// [`ScanConfig::new`] for the four defaults, or [`ScanConfig::all_algorithms`]
    /// for every algorithm.
    pub enabled: Vec<bool>,
    /// Worker threads to use. Zero selects a default from the machine's
    /// parallelism, capped at [`crate::MAX_WORKERS`].
    pub workers: usize,
}

impl ScanConfig {
    /// A scan using the four algorithms enabled by default.
    ///
    /// Those are the ones people actually verify against; hashing every file
    /// with all 31 is measurably slower and almost never wanted.
    pub fn new(jobs: Vec<FileJob>) -> Self {
        Self {
            jobs,
            enabled: default_enabled(),
            workers: 0,
        }
    }

    /// A scan using every algorithm in the table.
    ///
    /// This is the configuration the pipeline's correctness invariant is stated
    /// over: the scan must produce the same digest as feeding the file whole, for
    /// all of them.
    pub fn all_algorithms(jobs: Vec<FileJob>) -> Self {
        Self {
            jobs,
            enabled: vec![true; ALGORITHMS.len()],
            workers: 0,
        }
    }
}

/// Something that happened during a scan, delivered to the sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanEvent {
    /// Cumulative progress. Emitted after each completed block and each finished
    /// file.
    Progress(Progress),
    /// One file finished, successfully or not.
    FileFinished {
        /// Index into [`ScanConfig::jobs`].
        job_index: usize,
        /// The digests, size, and any error.
        result: FileResult,
        /// How the digests compare to the file's expected ones.
        match_state: MatchState,
    },
    /// The scan is over. Always the last event a sink sees.
    Finished(ScanOutcome),
}

/// How a scan ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanOutcome {
    /// Every job was processed.
    Complete,
    /// Cancellation was requested, a worker panicked, or the sink itself
    /// panicked — the result set is incomplete.
    Cancelled,
}

/// A running scan.
///
/// Dropping the handle cancels the scan and waits for every worker to exit, so
/// nothing of the scan is still running once the caller has let go of it. Call
/// [`ScanHandle::wait`] to wait for a scan to finish *without* cancelling it.
pub struct ScanHandle {
    cancel: CancelToken,
    workers: Vec<JoinHandle<()>>,
}

impl ScanHandle {
    /// Ask the scan to stop.
    ///
    /// Safe to call from any thread, including the UI thread that started the
    /// scan. Files in flight are unwound, and no `FileFinished` is emitted for
    /// them.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Wait for the scan to finish, without cancelling it.
    pub fn wait(mut self) {
        self.join_all();
    }

    fn join_all(&mut self) {
        for worker in self.workers.drain(..) {
            // A worker that panicked has already been contained: the panic was
            // caught inside its loop, which then cancelled the scan. Its join
            // result carries nothing the caller could act on.
            let _ = worker.join();
        }
    }
}

impl Drop for ScanHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.join_all();
    }
}

/// The algorithms a fresh scan hashes with when the caller expresses no opinion.
fn default_enabled() -> Vec<bool> {
    let mut enabled = vec![false; ALGORITHMS.len()];
    for name in ["MD5", "SHA-1", "SHA-256", "SHA-512"] {
        if let Some(index) = ALGORITHMS
            .iter()
            .position(|algorithm| algorithm.name == name)
        {
            enabled[index] = true;
        }
    }
    enabled
}

/// The sink a scan reports through.
type Sink = Arc<Mutex<Box<dyn FnMut(ScanEvent) + Send>>>;

/// Start a scan and return a handle to it.
///
/// Returns immediately: the work happens on the scan's own worker threads, and
/// every result arrives through `sink`. Progress is reported at block
/// granularity ([`crate::BLOCK_SIZE`]); a UI that wants a coarser message — one
/// window message per 256th of the bar, say — should quantise at the sink rather
/// than asking the scanner to poll.
///
/// # Sink contract
///
/// The sink is called from worker threads and must not panic. A panic inside it
/// is contained (this crate runs inside `explorer.exe`, where an escaping panic
/// would take the user's desktop down), but the scan is then cancelled, because
/// a sink that has panicked cannot be relied on to receive the rest of the
/// results.
pub fn start(config: ScanConfig, sink: Box<dyn FnMut(ScanEvent) + Send>) -> ScanHandle {
    let ScanConfig {
        jobs,
        enabled,
        workers,
    } = config;

    let queue: VecDeque<(usize, FileJob)> = jobs.into_iter().enumerate().collect();
    let total_files = queue.len();
    let total_bytes = queue
        .iter()
        .map(|(_, job)| job.size)
        .fold(0u64, u64::saturating_add);
    let active: Vec<usize> = (0..ALGORITHMS.len())
        .filter(|index| enabled.get(*index).copied().unwrap_or(false))
        .collect();

    let worker_count = if workers == 0 {
        default_worker_count(total_files)
    } else {
        workers.clamp(1, crate::MAX_WORKERS)
    };

    let scheduler = Arc::new(Scheduler {
        queue: Mutex::new(queue),
        enabled,
        active,
        pool: BufferPool::for_scan(worker_count),
        cancel: CancelToken::new(),
        sink: Arc::new(Mutex::new(sink)),
        done: AtomicU64::new(0),
        files_done: AtomicUsize::new(0),
        // Deliberately the *intended* worker count: a worker that exits
        // immediately must not take this to zero and finish the scan while its
        // siblings are still being spawned. Anything not spawned is subtracted
        // below.
        active_workers: AtomicUsize::new(worker_count),
        finished: AtomicBool::new(false),
        total_bytes,
        total_files,
    });

    let mut handles = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let worker = Arc::clone(&scheduler);
        match thread::Builder::new()
            .name("rusthashtab-scan".to_string())
            .spawn(move || worker.run())
        {
            Ok(handle) => handles.push(handle),
            // Out of threads. Stop asking rather than pretending the intended
            // parallelism exists; the remaining jobs are still taken by the
            // workers that do exist.
            Err(_) => break,
        }
    }

    if handles.is_empty() {
        // Not a single worker thread could be created. Running the scan on the
        // caller's thread blocks, which is not what `start` promises, but it is
        // the only outcome that still produces results and a `Finished` event.
        scheduler.active_workers.store(1, Ordering::Release);
        scheduler.run();
        return ScanHandle {
            cancel: scheduler.cancel.clone(),
            workers: handles,
        };
    }

    let missing = worker_count - handles.len();
    if missing > 0
        && scheduler
            .active_workers
            .fetch_sub(missing, Ordering::AcqRel)
            == missing
    {
        // `old == missing` means this subtraction was the one that reached zero,
        // so no worker will report the scan as finished: do it here. (`old` can
        // never be *less* than `missing`: the spawned workers can only account
        // for `spawned` of the intended count.)
        scheduler.finish();
    }

    ScanHandle {
        cancel: scheduler.cancel.clone(),
        workers: handles,
    }
}

/// Worker threads to use when the caller did not say.
fn default_worker_count(jobs: usize) -> usize {
    let parallelism = thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    parallelism.clamp(1, crate::MAX_WORKERS).min(jobs.max(1))
}

/// The state every worker shares.
struct Scheduler {
    /// Jobs still to do, each with its index into the original job list.
    queue: Mutex<VecDeque<(usize, FileJob)>>,
    /// Which algorithms this scan hashes with, indexed like [`ALGORITHMS`].
    enabled: Vec<bool>,
    /// The same information as positions, which is how the contexts are built.
    active: Vec<usize>,
    pool: Arc<BufferPool>,
    cancel: CancelToken,
    sink: Sink,
    /// Bytes attributed as done, across all workers.
    done: AtomicU64,
    /// Files that produced a `FileFinished` event.
    files_done: AtomicUsize,
    /// Workers still running, including the caller when it ran the scan inline.
    active_workers: AtomicUsize,
    /// Whether `Finished` has been emitted, so it can only ever be emitted once.
    finished: AtomicBool,
    total_bytes: u64,
    total_files: usize,
}

impl Scheduler {
    /// Take the next job, or `None` when there is none left.
    fn next_job(&self) -> Option<(usize, FileJob)> {
        self.lock_queue().pop_front()
    }

    /// Lock the queue, treating a poisoned mutex as usable.
    ///
    /// Nothing here can leave the queue inconsistent, and refusing to proceed
    /// after a contained panic would turn one panic into a hung scan.
    fn lock_queue(&self) -> MutexGuard<'_, VecDeque<(usize, FileJob)>> {
        self.queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Hash files until the queue is empty or the scan is cancelled.
    fn run(self: &Arc<Self>) {
        let mut scratch = ReadScratch::new();

        loop {
            if self.cancel.is_cancelled() {
                break;
            }
            let Some((index, job)) = self.next_job() else {
                break;
            };

            // A panic in a hasher or in the read path must not unwind out of the
            // worker's thread start, and it must not leave the scan claiming a
            // completeness it does not have: contain it, then cancel so the
            // outcome is honest.
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                self.hash_one(index, &job, &mut scratch);
            }));
            if outcome.is_err() {
                self.cancel.cancel();
                break;
            }
        }

        if self.active_workers.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.finish();
        }
    }

    /// Hash one file and report it.
    fn hash_one(&self, job_index: usize, job: &FileJob, scratch: &mut ReadScratch) {
        let mut hashers: Vec<(usize, Box<dyn Hasher>)> = self
            .active
            .iter()
            .filter_map(|algorithm| {
                registry::make(ALGORITHMS[*algorithm].name).map(|hasher| (*algorithm, hasher))
            })
            .collect();

        let mut delivered: u64 = 0;
        let read = read_file(&job.path, &self.pool, &self.cancel, scratch, &mut |block| {
            for (_, hasher) in hashers.iter_mut() {
                hasher.update(block);
            }
            delivered += block.len() as u64;
            self.done.fetch_add(block.len() as u64, Ordering::Relaxed);
            self.emit_progress();
        });

        let error = match read {
            Ok(ReadOutcome::Done { .. }) => None,
            // A cancelled file has no result worth reporting: a half-hashed file
            // is not a hash, and the UI is about to be told the scan was
            // cancelled anyway.
            Ok(ReadOutcome::Cancelled) => return,
            Err(error) => Some(error.raw_os_error().unwrap_or(0) as u32),
        };

        // Converge on the total even when a file could not be read: the bytes it
        // was expected to contribute are accounted for, so a scan that hits one
        // unreadable file still reaches a full bar. Without this, a locked file
        // in the middle of a tree would leave the bar permanently short.
        self.done
            .fetch_add(job.size.saturating_sub(delivered), Ordering::Relaxed);

        let mut digests = vec![Vec::new(); ALGORITHMS.len()];
        if error.is_none() {
            for (algorithm, hasher) in hashers {
                digests[algorithm] = hasher.finalize();
            }
        }

        let result = FileResult {
            path: job.path.clone(),
            digests,
            size: delivered,
            error,
        };
        let state = match_state(&result, &job.expected, &self.enabled);

        self.files_done.fetch_add(1, Ordering::AcqRel);
        self.emit(ScanEvent::FileFinished {
            job_index,
            result,
            match_state: state,
        });
        self.emit_progress();
    }

    /// Report cumulative progress, clamped to the total.
    fn emit_progress(&self) {
        let total = self.total_bytes;
        let done = self.done.load(Ordering::Relaxed).min(total);
        self.emit(ScanEvent::Progress(Progress {
            done,
            total,
            files_done: self.files_done.load(Ordering::Relaxed),
            files_total: self.total_files,
        }));
    }

    /// Decide the outcome and report it.
    ///
    /// Called by whichever thread takes the worker count to zero, or by `start`
    /// when it subtracts the workers it could not create. The guard is belt and
    /// braces — exactly one decrement can observe the transition to zero — but a
    /// second `Finished` would be a UI-visible lie, and the cheap way to make it
    /// impossible rather than merely unreachable is to make it idempotent.
    fn finish(&self) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        let finished_everything = self.files_done.load(Ordering::Acquire) == self.total_files;
        let outcome = if self.cancel.is_cancelled() || !finished_everything {
            ScanOutcome::Cancelled
        } else {
            ScanOutcome::Complete
        };
        self.emit(ScanEvent::Finished(outcome));
    }

    /// Hand one event to the sink, containing a panic in it.
    fn emit(&self, event: ScanEvent) {
        let mut guard = self
            .sink
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let called = catch_unwind(AssertUnwindSafe(|| {
            let sink: &mut Box<dyn FnMut(ScanEvent) + Send> = &mut guard;
            sink(event);
        }));

        if called.is_err() {
            // The sink is caller code, often the UI. A panic in it is contained
            // here — an unwind escaping into the owning thread's start would
            // abort the process inside explorer — but the scan stops, because a
            // sink that panicked cannot be trusted with the rest.
            drop(guard);
            self.cancel.cancel();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_default_set_is_the_four_documented_algorithms() {
        let enabled = default_enabled();
        let names: Vec<&str> = ALGORITHMS
            .iter()
            .enumerate()
            .filter(|(index, _)| enabled[*index])
            .map(|(_, algorithm)| algorithm.name)
            .collect();
        assert_eq!(names, vec!["MD5", "SHA-1", "SHA-256", "SHA-512"]);
    }

    #[test]
    fn an_empty_job_list_still_runs() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink_events = Arc::clone(&events);
        let handle = start(
            ScanConfig::new(Vec::new()),
            Box::new(move |event| sink_events.lock().unwrap().push(event)),
        );
        handle.wait();

        let events = events.lock().unwrap();
        assert_eq!(
            events.last(),
            Some(&ScanEvent::Finished(ScanOutcome::Complete)),
            "an empty scan must still report that it finished"
        );
    }

    #[test]
    fn a_worker_count_is_clamped_and_never_zero() {
        assert_eq!(default_worker_count(0), 1);
        assert!(default_worker_count(1_000_000) <= crate::MAX_WORKERS);
        assert!(default_worker_count(1_000_000) >= 1);
    }
}
