//! Single-file algorithm fan-out.
//!
//! One file with many enabled algorithms is the one case where the ordinary
//! file-level scheduler leaves cores idle: a file is owned by one worker, and
//! that worker feeds every 2 MiB block to every hasher one after another. This
//! module splits the *algorithms* of one file across a small set of threads,
//! while the file itself is still read once.
//!
//! # Why blocks are copied once, not once per algorithm
//!
//! The reader hands each block to every algorithm. Copying the block per
//! algorithm would multiply memory traffic by the algorithm count. Instead the
//! block is copied once into an `Arc<[u8]>`, and every group receives a clone of
//! that `Arc`; the last group to finish with it frees it.
//!
//! # Thread ownership and shutdown
//!
//! The reader runs on the calling scan worker. Every group thread is created
//! here and is joined here before this function returns. [`Groups`] exists so
//! that an early return -- a read error, cancellation, a disconnected channel --
//! still drops the senders and joins the threads rather than detaching them.
//!
//! This is not a global pool: nothing is shared between files or scans, and no
//! thread outlives the `ScanHandle` that created it.

use crate::cancel::CancelToken;
use crate::pool::BufferPool;
use crate::reader::{ReadOutcome, read_file};
use rusthashtab_hash::{ALGORITHMS, Hasher, registry};
use std::io;
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// One group's digests, as `(algorithm index, digest)`.
type GroupDigests = Vec<(usize, Vec<u8>)>;
/// A spawned group thread's result.
type GroupHandle = JoinHandle<GroupDigests>;

/// How one file's fan-out ended.
pub(crate) enum FanoutOutcome {
    /// Every block was read and every group finalized.
    Done {
        /// Digests by algorithm-table index.
        digests: Vec<(usize, Vec<u8>)>,
        /// Bytes delivered by the reader.
        bytes: u64,
    },
    /// Cancellation was observed; no digest is usable.
    Cancelled,
}

/// Hash one file with `groups` algorithm groups.
///
/// `on_bytes` is called with the size of each block after it has been accepted by
/// every group's queue, so it measures work the hashers have actually been given
/// rather than bytes read ahead of them.
pub(crate) fn hash_file(
    path: &std::path::Path,
    pool: &Arc<BufferPool>,
    cancel: &CancelToken,
    active: &[usize],
    groups: usize,
    on_bytes: &mut dyn FnMut(u64),
) -> io::Result<FanoutOutcome> {
    let groups = groups.clamp(1, active.len().max(1));
    if groups == 1 {
        // The engine should have taken the inline path; supporting it here keeps
        // the function total and makes the fallback obvious.
        return hash_file_single(path, pool, cancel, active, on_bytes);
    }

    let buckets = assign_algorithms(active, groups);
    let mut handles: Vec<GroupHandle> = Vec::with_capacity(groups);
    let mut senders: Vec<SyncSender<Arc<[u8]>>> = Vec::with_capacity(groups);

    for (group_index, bucket) in buckets.into_iter().enumerate() {
        if bucket.is_empty() {
            continue;
        }
        let (sender, receiver) = sync_channel::<Arc<[u8]>>(crate::READ_AHEAD_BLOCKS);
        let builder = std::thread::Builder::new().name(format!("rusthashtab-hash-{group_index}"));
        let handle = builder.spawn(move || {
            let mut hashers: Vec<(usize, Box<dyn Hasher>)> = bucket
                .into_iter()
                .filter_map(|index| {
                    registry::make(ALGORITHMS[index].name).map(|hasher| (index, hasher))
                })
                .collect();

            while let Ok(block) = receiver.recv() {
                for (_, hasher) in &mut hashers {
                    hasher.update(&block);
                }
            }

            hashers
                .into_iter()
                .map(|(index, hasher)| (index, hasher.finalize()))
                .collect()
        })?;
        handles.push(handle);
        senders.push(sender);
    }

    let mut groups_guard = Groups {
        senders: Some(senders),
        handles: Some(handles),
    };

    let send_error: Arc<Mutex<Option<io::Error>>> = Arc::new(Mutex::new(None));
    let error_slot = Arc::clone(&send_error);
    let bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let byte_slot = Arc::clone(&bytes);
    let senders_ref = groups_guard.senders.as_ref().map_or(&[][..], Vec::as_slice);

    let read = read_file(
        path,
        pool,
        cancel,
        &mut crate::reader::ReadScratch::new(),
        &mut |block| {
            let block: Arc<[u8]> = Arc::from(block);
            for sender in senders_ref {
                match sender.try_send(Arc::clone(&block)) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        // A group is behind. Waiting here is bounded by the group's
                        // progress; cancellation still breaks out.
                        let mut spins = 0usize;
                        loop {
                            if cancel.is_cancelled() {
                                return;
                            }
                            match sender.try_send(Arc::clone(&block)) {
                                Ok(()) => break,
                                Err(TrySendError::Full(_)) => {
                                    spins += 1;
                                    if spins.is_multiple_of(64) {
                                        std::thread::sleep(std::time::Duration::from_millis(1));
                                    } else {
                                        std::thread::yield_now();
                                    }
                                }
                                Err(TrySendError::Disconnected(_)) => {
                                    *error_slot
                                        .lock()
                                        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                                        Some(io::Error::other("a hash group stopped unexpectedly"));
                                    cancel.cancel();
                                    return;
                                }
                            }
                        }
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        *error_slot
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                            Some(io::Error::other("a hash group stopped unexpectedly"));
                        cancel.cancel();
                        return;
                    }
                }
            }
            byte_slot.fetch_add(block.len() as u64, std::sync::atomic::Ordering::Relaxed);
            on_bytes(block.len() as u64);
        },
    );

    if let Some(error) = send_error
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
    {
        return Err(error);
    }

    match read {
        Err(error) => Err(error),
        Ok(ReadOutcome::Cancelled) => {
            let _ = groups_guard.finish();
            Ok(FanoutOutcome::Cancelled)
        }
        Ok(ReadOutcome::Done { bytes }) => {
            let digests = groups_guard.finish()?;
            Ok(FanoutOutcome::Done { digests, bytes })
        }
    }
}

/// The inline fallback: one thread, every algorithm in table order.
fn hash_file_single(
    path: &std::path::Path,
    pool: &Arc<BufferPool>,
    cancel: &CancelToken,
    active: &[usize],
    on_bytes: &mut dyn FnMut(u64),
) -> io::Result<FanoutOutcome> {
    let mut hashers: Vec<(usize, Box<dyn Hasher>)> = active
        .iter()
        .filter_map(|index| registry::make(ALGORITHMS[*index].name).map(|hasher| (*index, hasher)))
        .collect();
    let read = read_file(
        path,
        pool,
        cancel,
        &mut crate::reader::ReadScratch::new(),
        &mut |block| {
            for (_, hasher) in &mut hashers {
                hasher.update(block);
            }
            on_bytes(block.len() as u64);
        },
    )?;

    match read {
        ReadOutcome::Cancelled => Ok(FanoutOutcome::Cancelled),
        ReadOutcome::Done { bytes } => Ok(FanoutOutcome::Done {
            digests: hashers
                .into_iter()
                .map(|(index, hasher)| (index, hasher.finalize()))
                .collect(),
            bytes,
        }),
    }
}

/// Group threads and their senders, joined on every exit path.
struct Groups {
    senders: Option<Vec<SyncSender<Arc<[u8]>>>>,
    handles: Option<Vec<GroupHandle>>,
}

impl Groups {
    /// Drop the senders, join every group, and collect the digests.
    fn finish(&mut self) -> io::Result<Vec<(usize, Vec<u8>)>> {
        drop(self.senders.take());
        let Some(handles) = self.handles.take() else {
            return Ok(Vec::new());
        };
        let mut digests = Vec::new();
        for handle in handles {
            let group = handle
                .join()
                .map_err(|_| io::Error::other("a hash group panicked"))?;
            digests.extend(group);
        }
        Ok(digests)
    }
}

impl Drop for Groups {
    fn drop(&mut self) {
        // `finish` is the success path. This is the early-return path: release
        // the senders so the groups can see end-of-stream, then join them so no
        // thread outlives the scan worker.
        drop(self.senders.take());
        if let Some(handles) = self.handles.take() {
            for handle in handles {
                let _ = handle.join();
            }
        }
    }
}

/// Split the active algorithms into groups with roughly equal cost.
///
/// A greedy longest-processing-time assignment: the slowest algorithm goes first,
/// then each next one goes to the group with the smallest total. The weights are
/// derived from `cargo xtask bench` single-algorithm numbers; an algorithm that is
/// not listed uses the default, so adding one never drops it from the fan-out.
fn assign_algorithms(active: &[usize], groups: usize) -> Vec<Vec<usize>> {
    let mut sorted: Vec<usize> = active.to_vec();
    sorted.sort_by_key(|index| std::cmp::Reverse(cost(*index)));

    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); groups];
    let mut loads = vec![0u32; groups];
    for index in sorted {
        let target = loads
            .iter()
            .enumerate()
            .min_by_key(|(_, load)| **load)
            .map(|(index, _)| index)
            .unwrap_or(0);
        buckets[target].push(index);
        loads[target] = loads[target].saturating_add(cost(index));
    }
    buckets
}

/// A rough relative cost for one algorithm.
///
/// The absolute values do not matter, only the ratios. Keep this table in step
/// with the bench output when an algorithm changes materially; the default is
/// deliberately not zero, so an unlisted algorithm is still scheduled.
fn cost(index: usize) -> u32 {
    match ALGORITHMS.get(index).map(|algorithm| algorithm.name) {
        Some("GOST 2012 (512)") | Some("GOST 2012 (256)") => 120,
        Some("SHA3-512") | Some("SHA3-384") | Some("SHA3-256") | Some("SHA3-224") => 55,
        Some("K12-264") | Some("ParallelHash256-528") | Some("ParallelHash128-256") => 60,
        Some("BLAKE2sp") | Some("eD2k-ED2K") | Some("eD2k-EMule") => 35,
        Some("RipeMD160") | Some("MD4") => 20,
        _ => 10,
    }
}
