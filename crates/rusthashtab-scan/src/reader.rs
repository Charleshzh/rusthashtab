//! Overlapped (asynchronous) block reads.
//!
//! # Why overlapped reads at all
//!
//! A synchronous read blocks the worker for the whole disk latency of every
//! block, so hashing (which is CPU-bound) and reading (which is I/O-bound) take
//! turns instead of overlapping. Issuing the next few blocks *before* they are
//! needed keeps the device busy while the worker hashes the block it already
//! has. That is what the 2 MiB block size and the read-ahead depth are for.
//!
//! # Why a read-ahead ring rather than a completion port
//!
//! Blocks are consumed strictly in file order, so the pipeline never has to
//! match a completion to an arbitrary consumer. A ring of `depth` slots, each
//! with its own event, plus a wait on the *oldest* slot, gives the overlap
//! without a completion-port thread, without a callback that must not allocate,
//! and with a shutdown that is one `join` per worker. An IOCP would buy
//! scalability this design does not need at a cost in moving parts.
//!
//! # The one rule that keeps this sound
//!
//! **A buffer is released only after its read has been reaped.** The kernel
//! writes into that buffer after `ReadFile` returns; returning it to the pool
//! early is a use-after-free that corrupts a digest elsewhere in the scan. That
//! rule is enforced by [`ReadOp`]'s destructor rather than by discipline at each
//! exit: an outstanding read cancels and reaps itself before its slot — and
//! therefore its buffer — goes away. Every early return in [`read_file`] is then
//! safe by construction, including one taken because of an unrelated error.

use crate::cancel::{CancelToken, POLL_INTERVAL};
use crate::path::to_extension_path;
use crate::pool::{Buffer, BufferPool};
use std::collections::VecDeque;
use std::io;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;
use std::sync::Arc;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_HANDLE_EOF, ERROR_IO_PENDING, HANDLE, WAIT_FAILED, WAIT_OBJECT_0,
};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_OVERLAPPED, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, ReadFile,
};
use windows::Win32::System::IO::{
    CancelIoEx, GetOverlappedResult, OVERLAPPED, OVERLAPPED_0, OVERLAPPED_0_0,
};
use windows::Win32::System::Threading::{
    CreateEventW, INFINITE, ResetEvent, SetEvent, WaitForMultipleObjects, WaitForSingleObject,
};
use windows::core::PCWSTR;

/// How a file's read ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadOutcome {
    /// Every byte of the file as it was when opened has been handed to the
    /// callback.
    Done {
        /// Bytes actually delivered.
        bytes: u64,
    },
    /// Cancellation was observed; the digest is not usable.
    Cancelled,
}

/// An event handle that closes itself.
///
/// The reader owns one per read-ahead slot and reuses it for every file, so a
/// scan of 100,000 files creates a handful of events rather than 400,000.
#[derive(Debug)]
pub(crate) struct OwnedEvent(HANDLE);

// SAFETY: a Win32 event is a kernel object any thread may wait on or signal; the
// handle value carries no thread affinity and no pointer into this process's
// memory.
unsafe impl Send for OwnedEvent {}
// SAFETY: see above. Sharing the handle is what lets the canceller and every
// worker observe the same state.
unsafe impl Sync for OwnedEvent {}

impl OwnedEvent {
    /// Create an unnamed, manual-reset event in the non-signaled state.
    ///
    /// Manual-reset rather than auto-reset: the reader resets the event
    /// explicitly before issuing a read, which makes a reused slot
    /// deterministic. An auto-reset event is cleared by whichever wait happens
    /// to consume the signal, and a completion that arrived between two reads
    /// would leave the next wait returning immediately for a read that had not
    /// finished.
    pub(crate) fn new() -> io::Result<Self> {
        // SAFETY: CreateEventW accepts a null security descriptor, a null name
        // (which creates an unnamed event) and plain flags; no pointer passed
        // here outlives the call.
        let handle =
            unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.map_err(error_to_io)?;
        Ok(Self(handle))
    }

    /// The raw handle, for passing to a Win32 wait.
    pub(crate) fn raw(&self) -> HANDLE {
        self.0
    }

    /// Signal the event. A manual-reset event stays signaled until reset.
    pub(crate) fn set(&self) {
        // SAFETY: `self.0` is a live event handle for as long as `self` lives,
        // and SetEvent has no other precondition.
        let _ = unsafe { SetEvent(self.0) };
    }
}

impl Drop for OwnedEvent {
    fn drop(&mut self) {
        // SAFETY: the handle was created by CreateEventW and is closed exactly
        // once, here; nothing else in this crate closes it.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Per-worker kernel state reused across every file the worker processes.
///
/// Events are the only per-slot kernel resource; buffers and `OVERLAPPED`s come
/// and go with each file.
#[derive(Debug, Default)]
pub(crate) struct ReadScratch {
    events: Vec<OwnedEvent>,
}

impl ReadScratch {
    /// A scratch with no events yet; slots are created on first use.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn event(&mut self, slot: usize) -> io::Result<HANDLE> {
        while self.events.len() <= slot {
            self.events.push(OwnedEvent::new()?);
        }
        Ok(self.events[slot].raw())
    }
}

/// Read a file in blocks, handing each completed block to `on_block` in order.
///
/// Returns the number of bytes delivered. The file is read up to the size it had
/// when it was opened: a scan reports the file it saw, not a moving target.
///
/// # The read-ahead ring never waits for a buffer it is holding
///
/// A buffer becomes free when its read is reaped, so a worker that blocks on the
/// pool while its own slots hold buffers can be waiting for something only it
/// could release — with every worker in that state, the scan deadlocks. The ring
/// is therefore filled with [`BufferPool::try_acquire`], and a worker that cannot
/// get a buffer simply consumes what is already in flight, which frees one. The
/// only blocking acquisition happens when the ring is *empty*, where holding
/// nothing means there is no cycle to be part of.
pub(crate) fn read_file(
    path: &Path,
    pool: &Arc<BufferPool>,
    cancel: &CancelToken,
    scratch: &mut ReadScratch,
    on_block: &mut dyn FnMut(&[u8]),
) -> io::Result<ReadOutcome> {
    let file = open(path)?;
    let handle = HANDLE(file.as_raw_handle());
    let size = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);

    if cancel.is_cancelled() {
        return Ok(ReadOutcome::Cancelled);
    }
    if size == 0 {
        return Ok(ReadOutcome::Done { bytes: 0 });
    }

    let block = pool.block_size() as u64;
    // Only as many slots as this file can use: a 1 KiB file must not hold four
    // 2 MiB buffers out of the shared ceiling.
    let depth = size
        .div_ceil(block)
        .clamp(1, crate::READ_AHEAD_BLOCKS as u64)
        .min(pool.capacity().max(1) as u64) as usize;

    let mut ring: VecDeque<ReadOp> = VecDeque::with_capacity(depth);
    // Offset of the next read to issue, or `None` once the end of the file has
    // been reached.
    let mut next: Option<u64> = Some(0);
    let mut total: u64 = 0;
    // Event slots are handed out round-robin: at most `depth` reads are live at
    // once, so a slot number is never in use twice.
    let mut slots_used: usize = 0;

    loop {
        // Grow the ring as far as the pool allows without waiting.
        while ring.len() < depth {
            let Some(offset) = next else { break };
            let Some(buffer) = pool.try_acquire() else {
                break;
            };
            let want = request_len(size, offset, block);
            let mut op = ReadOp::new(handle, scratch.event(slots_used % depth)?, buffer);
            op.issue(offset, want)?;
            slots_used += 1;
            next = advance(size, offset, want);
            ring.push_back(op);
        }

        if ring.is_empty() {
            let Some(offset) = next else { break };

            // Nothing in flight and more to read, so a buffer must be waited for —
            // and this is the only place that is allowed. See the note above on
            // why holding nothing is what makes waiting safe.
            let Some(buffer) = pool.acquire(cancel) else {
                return Ok(ReadOutcome::Cancelled);
            };
            let want = request_len(size, offset, block);
            let mut op = ReadOp::new(handle, scratch.event(slots_used % depth)?, buffer);
            op.issue(offset, want)?;
            slots_used += 1;
            next = advance(size, offset, want);
            ring.push_back(op);
        }

        if cancel.is_cancelled() {
            return Ok(ReadOutcome::Cancelled);
        }

        let mut op = match ring.pop_front() {
            Some(op) => op,
            None => break,
        };
        let offset = op.offset;
        let requested = op.requested;

        let read = match op.wait(cancel)? {
            Wait::Cancelled => return Ok(ReadOutcome::Cancelled),
            Wait::Done(read) => read as usize,
        };

        if read > 0 {
            on_block(op.data(read));
            total += read as u64;
        }

        // The read is reaped, so this slot's buffer returns to the pool here
        // rather than at the end of the file.
        drop(op);

        if read == 0 {
            // End of file: nothing in flight can produce data either.
            ring.clear();
            next = None;
            continue;
        }

        if read < requested as usize {
            // A short read means the file no longer holds the bytes that were
            // asked for. Everything already in flight was issued against the old
            // size, so it is dropped and re-issued from here rather than
            // believed: trusting it could hash a gap.
            ring.clear();
            let after = offset + read as u64;
            next = if after < size { Some(after) } else { None };
        }
    }

    Ok(ReadOutcome::Done { bytes: total })
}

/// Bytes to ask for at `offset`, never reading past the size seen at open.
fn request_len(size: u64, offset: u64, block: u64) -> u32 {
    size.saturating_sub(offset)
        .min(block)
        .min(u64::from(u32::MAX)) as u32
}

/// The offset of the read after one of `want` bytes at `offset`, or `None` once
/// the end of the file has been reached.
///
/// Reading exactly the bytes that remain is what keeps the loop from issuing a
/// pointless read at the end of a file whose size is an exact multiple of the
/// block size.
fn advance(size: u64, offset: u64, want: u32) -> Option<u64> {
    let next = offset + u64::from(want);
    if next < size { Some(next) } else { None }
}

/// Open a file for overlapped reading, with sharing that lets the rest of the
/// system keep using it.
fn open(path: &Path) -> io::Result<std::fs::File> {
    // `to_extension_path` puts the `\\?\` prefix back: without it, a path longer
    // than MAX_PATH — or one whose name legitimately ends in a dot or a space —
    // fails to open even though the walk found it.
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
        .custom_flags(FILE_FLAG_OVERLAPPED.0)
        .open(to_extension_path(path))
}

/// Result of waiting for one read.
enum Wait {
    /// The read completed with this many bytes.
    Done(u32),
    /// Cancellation was observed before the read completed.
    Cancelled,
}

/// One slot of the read-ahead ring.
///
/// Owns everything whose lifetime must not end before the kernel is done with
/// it: the buffer being written into, the `OVERLAPPED` the kernel points at, and
/// the knowledge of whether a read is still outstanding.
struct ReadOp {
    /// The handle the read was issued on, kept so that the destructor can drain
    /// without being passed one.
    handle: HANDLE,
    /// Boxed because its address must not change while a read is outstanding:
    /// the kernel keeps this pointer until the operation is reaped.
    overlapped: Box<OVERLAPPED>,
    buffer: Buffer,
    /// Borrowed from the worker's [`ReadScratch`], which outlives every op.
    event: HANDLE,
    /// Offset the outstanding (or completed) read was issued at.
    offset: u64,
    /// Bytes that read was asked for, so a short completion can be recognised.
    requested: u32,
    /// True between issuing a read and reaping it.
    outstanding: bool,
    /// True when `ReadFile` completed the read inline, so no wait is needed.
    completed_inline: bool,
}

impl ReadOp {
    fn new(handle: HANDLE, event: HANDLE, buffer: Buffer) -> Self {
        Self {
            handle,
            overlapped: Box::new(OVERLAPPED::default()),
            buffer,
            event,
            offset: 0,
            requested: 0,
            outstanding: false,
            completed_inline: false,
        }
    }

    /// Start a read of `len` bytes at `offset`.
    ///
    /// Must not be called while this op is outstanding.
    fn issue(&mut self, offset: u64, len: u32) -> io::Result<()> {
        debug_assert!(
            !self.outstanding,
            "an outstanding read must be reaped before its slot is reused"
        );

        // Reset before issuing: this slot's event is reused for the next read,
        // and a signal left over from the previous one is indistinguishable from
        // this read finishing.
        // SAFETY: `self.event` is a live manual-reset event handle owned by the
        // caller's ReadScratch, and ResetEvent has no other precondition.
        let _ = unsafe { ResetEvent(self.event) };

        // The OVERLAPPED is overwritten in place, not replaced: the kernel holds
        // the address passed below.
        *self.overlapped = OVERLAPPED {
            Internal: 0,
            InternalHigh: 0,
            Anonymous: OVERLAPPED_0 {
                Anonymous: OVERLAPPED_0_0 {
                    Offset: offset as u32,
                    OffsetHigh: (offset >> 32) as u32,
                },
            },
            hEvent: self.event,
        };
        self.offset = offset;

        let data = self.buffer.as_mut_slice();
        let len = (len as usize).min(data.len());
        self.requested = len as u32;
        let target = &mut data[..len];
        let overlapped: *mut OVERLAPPED = self.overlapped.as_mut();

        // SAFETY: `self.handle` was opened with FILE_FLAG_OVERLAPPED; `target` is
        // writable for `len` bytes and owned by this op, so nothing else can
        // alias it until the read is reaped; `overlapped` is a stable Box
        // allocation that outlives the read. A null `lpNumberOfBytesRead` is
        // required for overlapped I/O, and the byte count is collected through
        // GetOverlappedResult instead.
        let result = unsafe { ReadFile(self.handle, Some(target), None, Some(overlapped)) };

        match result {
            Ok(()) => {
                self.outstanding = true;
                self.completed_inline = true;
                Ok(())
            }
            Err(error) if win32_code(&error) == ERROR_IO_PENDING.0 => {
                self.outstanding = true;
                self.completed_inline = false;
                Ok(())
            }
            Err(error) => Err(error_to_io(error)),
        }
    }

    /// Wait for this read, or for cancellation, whichever comes first.
    fn wait(&mut self, cancel: &CancelToken) -> io::Result<Wait> {
        if self.completed_inline {
            return self.reap(false).map(Wait::Done);
        }

        match cancel.wait_event() {
            Some(cancel_event) => {
                let handles = [self.event, cancel_event];
                // SAFETY: both handles are live for the duration of the call, and
                // `wait_all = false` makes the return value the index of the
                // first signaled handle. INFINITE is safe here precisely because
                // the cancel event is one of the two.
                let waited = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };
                if waited == WAIT_OBJECT_0 {
                    self.reap(false).map(Wait::Done)
                } else if waited.0 == WAIT_OBJECT_0.0 + 1 {
                    Ok(Wait::Cancelled)
                } else if waited == WAIT_FAILED {
                    Err(io::Error::other(
                        "WaitForMultipleObjects failed while waiting for a read",
                    ))
                } else {
                    // WAIT_TIMEOUT cannot happen with INFINITE and WAIT_ABANDONED
                    // is impossible for an event; treat anything unexpected as
                    // cancellation so the file is unwound through the drain path
                    // rather than read from an unsignalled slot.
                    Ok(Wait::Cancelled)
                }
            }
            None => {
                // The cancel event could not be created. Polling the flag is
                // slower to react but keeps cancellation working instead of
                // hanging forever.
                let poll_ms = POLL_INTERVAL.as_millis().min(u128::from(u32::MAX)) as u32;
                loop {
                    // SAFETY: `self.event` is live for as long as this op holds
                    // it, and a finite timeout cannot block indefinitely.
                    let waited = unsafe { WaitForSingleObject(self.event, poll_ms) };
                    if waited == WAIT_OBJECT_0 {
                        return self.reap(false).map(Wait::Done);
                    }
                    if cancel.is_cancelled() {
                        return Ok(Wait::Cancelled);
                    }
                }
            }
        }
    }

    /// Collect the result of a completed read.
    ///
    /// `wait` must be false when completion is already known (an inline
    /// completion, or a signaled event) and true only when the operation may
    /// still be in flight — after `CancelIoEx`, waiting on it is what keeps the
    /// `OVERLAPPED` and its buffer alive until the kernel is done.
    fn reap(&mut self, wait: bool) -> io::Result<u32> {
        let mut transferred: u32 = 0;
        let overlapped: *const OVERLAPPED = self.overlapped.as_ref();
        // SAFETY: `self.handle` is the handle the read was issued on and
        // `overlapped` is the same structure passed to ReadFile, still owned here
        // and not yet released.
        let result =
            unsafe { GetOverlappedResult(self.handle, overlapped, &mut transferred, wait) };
        self.outstanding = false;

        match result {
            Ok(()) => Ok(transferred),
            // Reading at or past the end of a file is not an error: it is how a
            // short final read reports that there is nothing left.
            Err(error) if win32_code(&error) == ERROR_HANDLE_EOF.0 => Ok(0),
            Err(error) => Err(error_to_io(error)),
        }
    }

    /// The first `len` bytes of this slot's buffer.
    fn data(&self, len: usize) -> &[u8] {
        self.buffer.filled(len)
    }
}

impl Drop for ReadOp {
    fn drop(&mut self) {
        if !self.outstanding {
            return;
        }

        // Cancel exactly this read, then wait for it: the buffer and the
        // OVERLAPPED are released by the fields below, and the kernel must no
        // longer own either of them when that happens.
        let overlapped: *const OVERLAPPED = self.overlapped.as_ref();
        // SAFETY: passing this operation's OVERLAPPED cancels only this read;
        // the handle is still open because the caller's `File` outlives the ring.
        let _ = unsafe { CancelIoEx(self.handle, Some(overlapped)) };
        // The result is deliberately discarded: this path is reached on
        // cancellation (where ERROR_OPERATION_ABORTED is expected) or while
        // unwinding another error, and neither has a use for the byte count.
        let _ = self.reap(true);
    }
}

/// The Win32 error code behind an error produced by a generated `Result` wrapper.
///
/// Those wrappers build their error with `Error::from_thread()`, whose code is
/// `HRESULT::from_win32(GetLastError())` — the low 16 bits hold the Win32 code.
fn win32_code(error: &windows::core::Error) -> u32 {
    (error.code().0 as u32) & 0x0000_ffff
}

/// Convert a generated-API failure into an [`io::Error`] carrying the Win32 code.
///
/// The scanner stores that code in `FileResult::error` and the UI shows it, so
/// the conversion must not lose it.
fn error_to_io(error: windows::core::Error) -> io::Error {
    io::Error::from_raw_os_error(win32_code(&error) as i32)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::{Seek as _, Write as _};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// A uniquely named temporary directory, removed on drop.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "rusthashtab-scan-reader-{tag}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn file(&self, name: &str, contents: &[u8]) -> std::path::PathBuf {
            let path = self.0.join(name);
            let mut file = std::fs::File::create(&path).unwrap();
            file.write_all(contents).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Deterministic contents, so a failure is reproducible.
    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(31) >> 3) as u8).collect()
    }

    /// Read a file through the ring, reassembling what the callback saw.
    fn collect(
        path: &Path,
        pool: &Arc<BufferPool>,
        cancel: &CancelToken,
    ) -> (ReadOutcome, Vec<u8>, Vec<usize>) {
        let mut scratch = ReadScratch::new();
        let mut assembled = Vec::new();
        let mut block_sizes = Vec::new();
        let outcome = read_file(path, pool, cancel, &mut scratch, &mut |block| {
            block_sizes.push(block.len());
            assembled.extend_from_slice(block);
        })
        .unwrap();
        (outcome, assembled, block_sizes)
    }

    #[test]
    fn a_file_smaller_than_one_block_arrives_whole() {
        let dir = TempDir::new("small");
        let data = payload(1000);
        let path = dir.file("small.bin", &data);
        let pool = BufferPool::new(4096, 8);
        let cancel = CancelToken::new();

        let (outcome, assembled, blocks) = collect(&path, &pool, &cancel);
        assert_eq!(outcome, ReadOutcome::Done { bytes: 1000 });
        assert_eq!(assembled, data);
        assert_eq!(blocks, vec![1000]);
    }

    #[test]
    fn an_empty_file_delivers_nothing_and_no_block() {
        let dir = TempDir::new("empty");
        let path = dir.file("empty.bin", &[]);
        let pool = BufferPool::new(4096, 8);
        let cancel = CancelToken::new();

        let (outcome, assembled, blocks) = collect(&path, &pool, &cancel);
        assert_eq!(outcome, ReadOutcome::Done { bytes: 0 });
        assert!(assembled.is_empty());
        assert!(blocks.is_empty(), "an empty file must not produce a block");
    }

    /// The whole point of the ring: many blocks, in order, with a short tail.
    /// The pool is deliberately smaller than the ring so slot reuse is exercised.
    #[test]
    fn a_multi_block_file_arrives_in_order_with_a_short_tail() {
        let dir = TempDir::new("blocks");
        let block = 4096usize;
        let data = payload(block * 5 + 17);
        let path = dir.file("blocks.bin", &data);
        let pool = BufferPool::new(block, 3);
        let cancel = CancelToken::new();

        let (outcome, assembled, blocks) = collect(&path, &pool, &cancel);
        assert_eq!(
            outcome,
            ReadOutcome::Done {
                bytes: data.len() as u64
            }
        );
        assert_eq!(assembled, data, "blocks must arrive in file order");
        assert_eq!(blocks, vec![block, block, block, block, block, 17]);
        assert!(
            pool.allocated() <= 3,
            "the pool ceiling must hold even with a deeper ring than capacity"
        );
    }

    #[test]
    fn a_file_that_is_an_exact_multiple_of_the_block_has_no_empty_tail() {
        let dir = TempDir::new("exact");
        let block = 1024usize;
        let data = payload(block * 3);
        let path = dir.file("exact.bin", &data);
        let pool = BufferPool::new(block, 4);
        let cancel = CancelToken::new();

        let (outcome, assembled, blocks) = collect(&path, &pool, &cancel);
        assert_eq!(
            outcome,
            ReadOutcome::Done {
                bytes: data.len() as u64
            }
        );
        assert_eq!(assembled, data);
        assert_eq!(blocks, vec![block, block, block]);
    }

    /// Cancelling while the worker is parked with no buffer at all must not
    /// deadlock, and must not leave the pool short of a buffer afterwards.
    #[test]
    fn cancelling_while_the_pool_is_drained_unwinds_the_file() {
        let dir = TempDir::new("pool-cancel");
        let block = 4096usize;
        let data = payload(block * 8);
        let path = dir.file("big.bin", &data);
        // One buffer, and the test thread holds it: the reader's first fill gets
        // nothing, so it waits — which is the blocking case that has to be
        // cancellable.
        let pool = BufferPool::new(block, 1);
        let held = pool.try_acquire().expect("the one buffer is free");
        let cancel = CancelToken::new();
        let canceller = cancel.clone();
        let delivered = Arc::new(AtomicBool::new(false));

        let worker_pool = Arc::clone(&pool);
        let flag = Arc::clone(&delivered);
        let worker = std::thread::spawn(move || {
            let mut scratch = ReadScratch::new();
            read_file(&path, &worker_pool, &canceller, &mut scratch, &mut |_| {
                flag.store(true, Ordering::SeqCst);
            })
        });

        std::thread::sleep(POLL_INTERVAL * 3);
        cancel.cancel();
        let outcome = worker.join().unwrap().unwrap();

        assert_eq!(outcome, ReadOutcome::Cancelled);
        assert!(
            !delivered.load(Ordering::SeqCst),
            "with no buffer available the reader cannot deliver a block"
        );
        drop(held);
    }

    /// Fewer buffers than the read-ahead depth must cost overlap, not
    /// correctness — and must not deadlock: this is the shape a busy machine
    /// produces when several workers share the pool.
    #[test]
    fn a_pool_smaller_than_the_ring_still_hashes_the_whole_file() {
        let dir = TempDir::new("small-pool");
        let block = 4096usize;
        let data = payload(block * 12 + 5);
        let path = dir.file("many-blocks.bin", &data);
        let pool = BufferPool::new(block, 2);
        let cancel = CancelToken::new();

        let (outcome, assembled, blocks) = collect(&path, &pool, &cancel);
        assert_eq!(
            outcome,
            ReadOutcome::Done {
                bytes: data.len() as u64
            }
        );
        assert_eq!(assembled, data);
        assert_eq!(blocks.len(), 13);
        assert!(
            pool.allocated() <= 2,
            "the pool ceiling is absolute, even when the ring wants more"
        );
    }

    #[test]
    fn cancelling_mid_file_stops_the_read() {
        let dir = TempDir::new("mid-cancel");
        let block = 4096usize;
        let data = payload(block * 64);
        let path = dir.file("large.bin", &data);
        let pool = BufferPool::new(block, 4);
        let cancel = CancelToken::new();

        let canceller = cancel.clone();
        let mut scratch = ReadScratch::new();
        let mut seen = 0u64;
        let outcome = read_file(&path, &pool, &cancel, &mut scratch, &mut |bytes| {
            seen += bytes.len() as u64;
            if seen >= (block as u64) * 3 {
                canceller.cancel();
            }
        })
        .unwrap();

        assert_eq!(outcome, ReadOutcome::Cancelled);
        assert!(
            seen < data.len() as u64,
            "cancellation must cut the read short"
        );
    }

    /// A missing file is an error carrying the Win32 code, not a panic and not a
    /// silently empty digest.
    #[test]
    fn a_missing_file_reports_the_os_error() {
        let dir = TempDir::new("missing");
        let pool = BufferPool::new(4096, 4);
        let cancel = CancelToken::new();
        let mut scratch = ReadScratch::new();

        let error = read_file(
            &dir.0.join("not-there.bin"),
            &pool,
            &cancel,
            &mut scratch,
            &mut |_| {},
        )
        .unwrap_err();

        assert_eq!(
            error.raw_os_error(),
            Some(2),
            "ERROR_FILE_NOT_FOUND must survive conversion"
        );
    }

    /// A short read must be re-issued from where the data actually ended, not
    /// from where the read was asked to end.
    ///
    /// A pool of one buffer forces the ring to hold a single read at a time,
    /// which removes the timing question: the truncation lands between the first
    /// delivered block and the read of the second, so that read necessarily comes
    /// back short.
    ///
    /// The file is then *restored* — the bytes from the short read's real end
    /// onwards are put back. That is what makes this test discriminating: an
    /// implementation that advanced its cursor by the requested length would skip
    /// exactly those bytes and report a digest for a file it never read, while
    /// the delivered byte count alone would look the same.
    #[test]
    fn a_short_read_is_reissued_from_where_the_data_ended() {
        let dir = TempDir::new("short-read");
        let block = 4096usize;
        let original = payload(block * 4);
        let path = dir.file("short.bin", &original);
        let pool = BufferPool::new(block, 1);
        let cancel = CancelToken::new();

        // Inside the second block, so the read at that offset comes back short
        // rather than empty.
        let truncated_to = block + 904;
        let mut scratch = ReadScratch::new();
        let mut assembled: Vec<u8> = Vec::new();

        let outcome = read_file(&path, &pool, &cancel, &mut scratch, &mut |bytes| {
            assembled.extend_from_slice(bytes);
            if assembled.len() == block {
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .expect("the test file is writable");
                file.set_len(truncated_to as u64).expect("the file shrinks");
            } else if assembled.len() == truncated_to {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .expect("the test file is writable");
                file.seek(std::io::SeekFrom::Start(truncated_to as u64))
                    .expect("the file is seekable");
                file.write_all(&original[truncated_to..])
                    .expect("the tail is restorable");
                file.set_len(original.len() as u64)
                    .expect("the file grows back");
            }
        })
        .expect("shrinking a file is not a read error");

        assert_eq!(
            outcome,
            ReadOutcome::Done {
                bytes: original.len() as u64
            },
            "the restored tail must be read in full"
        );
        assert_eq!(
            assembled, original,
            "a short read must not skip any byte of the file"
        );
    }

    /// A file that shrinks while a read-ahead ring is full must not corrupt the
    /// digest either: reads issued against the old size are still in flight, and
    /// whatever they return, the result must be a prefix of the file — never a
    /// gap, and never a block counted twice.
    #[test]
    fn a_file_truncated_while_reading_yields_a_prefix_not_a_gap() {
        let dir = TempDir::new("truncate");
        let block = 4096usize;
        let original = payload(block * 4);
        let path = dir.file("shrinking.bin", &original);
        let pool = BufferPool::new(block, 4);
        let cancel = CancelToken::new();

        let truncated_to = block + 904;
        let mut scratch = ReadScratch::new();
        let mut assembled: Vec<u8> = Vec::new();

        let outcome = read_file(&path, &pool, &cancel, &mut scratch, &mut |bytes| {
            assembled.extend_from_slice(bytes);
            if assembled.len() == block {
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .expect("the test file is writable");
                file.set_len(truncated_to as u64).expect("the file shrinks");
            }
        })
        .expect("shrinking a file is not a read error");

        let read = assembled.len();
        assert_eq!(outcome, ReadOutcome::Done { bytes: read as u64 });
        assert_eq!(
            assembled,
            original[..read],
            "the blocks delivered must be a prefix of the file, in order"
        );
        assert!(
            read >= truncated_to,
            "the reader delivered {read} bytes, less than the {truncated_to} still in the file"
        );
    }

    /// Events are per worker and reused across files: one per slot per file
    /// would create a kernel handle for every file in a tree.
    #[test]
    fn events_are_reused_across_files() {
        let dir = TempDir::new("reuse");
        let block = 4096usize;
        let pool = BufferPool::new(block, 4);
        let cancel = CancelToken::new();
        let mut scratch = ReadScratch::new();

        for index in 0..50 {
            let path = dir.file(&format!("file-{index}.bin"), &payload(block * 3));
            let mut blocks = 0;
            let outcome =
                read_file(&path, &pool, &cancel, &mut scratch, &mut |_| blocks += 1).unwrap();
            assert_eq!(
                outcome,
                ReadOutcome::Done {
                    bytes: (block * 3) as u64
                }
            );
            assert_eq!(blocks, 3);
        }
        // `depth` is capped at the read-ahead constant, which is 4; a 3-block
        // file therefore uses three slots.
        assert_eq!(
            scratch.events.len(),
            3,
            "one event per ring slot, reused for every file"
        );
    }
}
