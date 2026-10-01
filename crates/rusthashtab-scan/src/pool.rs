//! The bounded pool of read buffers.
//!
//! # What it is for
//!
//! A scan of a whole directory tree must not allocate memory in proportion to
//! the number of files or blocks in flight. The pool caps *total* bytes held by
//! the pipeline at `capacity × block_size` ([`crate::MAX_INFLIGHT_BLOCKS`]
//! blocks of [`crate::BLOCK_SIZE`], i.e. 1 GiB at the defaults) no matter how
//! many files are being read at once: a worker that cannot get a buffer waits
//! instead of allocating.
//!
//! # Why a free list rather than an allocator
//!
//! Buffers are recycled through the free list, so steady-state hashing performs
//! no allocation per block at all — the 2 MiB `Vec` is allocated once per slot
//! and reused for the rest of the scan. That matters inside `explorer.exe`,
//! where the process heap is shared with the shell.
//!
//! Waiting is cancellation-aware: a worker parked here while every buffer is
//! checked out must still react to a cancel request, otherwise cancelling a
//! scan of many large files would block until the slowest read finished.

use crate::MAX_INFLIGHT_BLOCKS;
use crate::cancel::{CancelToken, POLL_INTERVAL};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

#[derive(Debug, Default)]
struct Inner {
    /// Recycled buffers. The steady-state source of every acquisition.
    free: Vec<Box<[u8]>>,
    /// Buffers created so far, including those currently checked out. This is
    /// what the capacity limit applies to.
    allocated: usize,
}

/// What one non-blocking look at the pool found.
enum Attempt {
    /// A recycled buffer.
    Reused(Box<[u8]>),
    /// Room under the ceiling: the caller should allocate a buffer.
    Allocate,
    /// Nothing free and no room to make more.
    Exhausted,
}

/// A bounded pool of equal-sized read buffers.
///
/// Shared behind an [`Arc`] by every worker of one scan: the ceiling is a
/// property of the scan, not of a worker.
#[derive(Debug)]
pub(crate) struct BufferPool {
    inner: Mutex<Inner>,
    available: Condvar,
    block_size: usize,
    capacity: usize,
}

impl BufferPool {
    /// A pool of at most `capacity` buffers of `block_size` bytes each.
    ///
    /// No memory is reserved up front; the ceiling is enforced as buffers are
    /// first requested, so a scan of one small file never pays for 512 blocks.
    pub(crate) fn new(block_size: usize, capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner::default()),
            available: Condvar::new(),
            block_size,
            capacity,
        })
    }

    /// A pool sized for a scan: [`crate::BLOCK_SIZE`] blocks, at least
    /// [`crate::MAX_INFLIGHT_BLOCKS`] of them.
    ///
    /// # Why the worker count is an argument
    ///
    /// A worker holds up to [`crate::READ_AHEAD_BLOCKS`] buffers while it waits
    /// for the next one, so a pool smaller than `workers × READ_AHEAD_BLOCKS`
    /// could have every worker waiting on a buffer that only another waiter could
    /// release. The ceiling is therefore the larger of the documented memory cap
    /// and what the workers actually need, which today never exceeds the cap: 32
    /// workers × 4 blocks is 128 of the 512 available. Passing the worker count
    /// keeps that true if either constant is ever raised.
    pub(crate) fn for_scan(workers: usize) -> Arc<Self> {
        let needed = workers.saturating_mul(crate::READ_AHEAD_BLOCKS);
        Self::new(crate::BLOCK_SIZE, MAX_INFLIGHT_BLOCKS.max(needed))
    }

    /// Bytes per buffer.
    pub(crate) fn block_size(&self) -> usize {
        self.block_size
    }

    /// Maximum number of buffers that may exist at once.
    ///
    /// The reader consults this so that a ring can never be deeper than the pool
    /// it draws from — see [`crate::reader::read_file`] for why that matters.
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// Buffers created so far. Never exceeds the pool's capacity; the tests use
    /// it to prove recycling rather than assuming it.
    #[cfg(test)]
    pub(crate) fn allocated(&self) -> usize {
        self.lock().allocated
    }

    /// Check out a buffer, waiting for one to be returned if all are in use.
    ///
    /// Returns `None` when cancellation is requested while waiting: the caller
    /// then unwinds the file rather than blocking, which is what keeps
    /// cancellation prompt under memory pressure.
    ///
    /// # Waiting here is only safe while holding nothing
    ///
    /// A buffer is released when its read has been reaped, so a caller that waits
    /// here while holding buffers can end up waiting for a buffer that only its
    /// own held buffers could free. `reader::read_file` therefore waits here only
    /// when it holds none, and uses [`BufferPool::try_acquire`] everywhere else.
    pub(crate) fn acquire(self: &Arc<Self>, cancel: &CancelToken) -> Option<Buffer> {
        let mut inner = self.lock();
        loop {
            match self.attempt(&mut inner) {
                Attempt::Reused(data) => return Some(self.wrap(data)),
                Attempt::Allocate => {
                    // Allocate outside the lock: a 2 MiB `vec!` takes a page
                    // fault, and holding the pool lock through that would
                    // serialize every worker.
                    drop(inner);
                    return Some(self.allocate());
                }
                Attempt::Exhausted => {}
            }

            if cancel.is_cancelled() {
                return None;
            }

            // `wait_timeout` rather than `wait`: cancellation does not notify this
            // condvar (the canceller may be a UI thread that does not know the
            // pool exists), so the wait must time out and re-check.
            let (guard, _) = self
                .available
                .wait_timeout(inner, POLL_INTERVAL)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            inner = guard;
        }
    }

    /// Check out a buffer if one is available, without waiting.
    ///
    /// The reader uses this to grow its read-ahead ring only as far as the pool
    /// allows: a ring that stops growing reads more slowly, while a ring that
    /// waited for a buffer it could not get would stall that file entirely.
    pub(crate) fn try_acquire(self: &Arc<Self>) -> Option<Buffer> {
        let mut inner = self.lock();
        match self.attempt(&mut inner) {
            Attempt::Reused(data) => Some(self.wrap(data)),
            Attempt::Allocate => {
                drop(inner);
                Some(self.allocate())
            }
            Attempt::Exhausted => None,
        }
    }

    /// One non-blocking look at the pool's state.
    fn attempt(&self, inner: &mut Inner) -> Attempt {
        if let Some(data) = inner.free.pop() {
            return Attempt::Reused(data);
        }
        // The counter is bumped before the allocation happens; an allocation that
        // failed would have aborted the process rather than leaving it stale.
        if inner.allocated < self.capacity {
            inner.allocated += 1;
            return Attempt::Allocate;
        }
        Attempt::Exhausted
    }

    /// Wrap a recycled block as a checked-out buffer.
    fn wrap(self: &Arc<Self>, data: Box<[u8]>) -> Buffer {
        Buffer {
            pool: Arc::clone(self),
            data: Some(data),
        }
    }

    /// Allocate a fresh block.
    fn allocate(self: &Arc<Self>) -> Buffer {
        let data = vec![0u8; self.block_size].into_boxed_slice();
        Buffer {
            pool: Arc::clone(self),
            data: Some(data),
        }
    }

    /// Return a buffer to the free list.
    fn release(&self, data: Box<[u8]>) {
        let mut inner = self.lock();
        inner.free.push(data);
        self.available.notify_one();
    }

    /// Lock, treating a poisoned mutex as usable.
    ///
    /// The pool holds no invariant that a panicking holder could break, and a
    /// scan that panicked its way here is already being torn down; refusing to
    /// proceed would turn a contained panic into a deadlock.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A checked-out buffer, returned to its pool when dropped.
///
/// The reader holds one of these for the lifetime of an outstanding overlapped
/// read, so "buffer is back in the pool" and "the kernel is done writing to it"
/// are the same event.
#[derive(Debug)]
pub(crate) struct Buffer {
    pool: Arc<BufferPool>,
    data: Option<Box<[u8]>>,
}

impl Buffer {
    /// The writable block.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.data.as_deref_mut().unwrap_or_default()
    }

    /// The block as filled by a read of `len` bytes.
    pub(crate) fn filled(&self, len: usize) -> &[u8] {
        let data = self.data.as_deref().unwrap_or_default();
        &data[..len.min(data.len())]
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        if let Some(data) = self.data.take() {
            self.pool.release(data);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Small buffers keep the tests fast; the logic does not depend on the size.
    const BLOCK: usize = 64;

    #[test]
    fn buffers_are_recycled_not_reallocated() {
        let pool = BufferPool::new(BLOCK, 4);
        let cancel = CancelToken::new();

        for _ in 0..1000 {
            let mut buffer = pool.acquire(&cancel).unwrap();
            assert_eq!(buffer.as_mut_slice().len(), BLOCK);
            buffer.as_mut_slice()[0] = 0xAB;
        }

        assert_eq!(
            pool.allocated(),
            1,
            "a sequential user must reuse the one buffer it checks out"
        );
    }

    #[test]
    fn the_capacity_ceiling_is_never_breached() {
        let pool = BufferPool::new(BLOCK, 3);
        let cancel = CancelToken::new();

        let held: Vec<Buffer> = (0..3).map(|_| pool.acquire(&cancel).unwrap()).collect();
        assert_eq!(pool.allocated(), 3);

        // A fourth acquisition would have to allocate past the ceiling, so it
        // must block. The cancel token is the escape hatch that proves it.
        cancel.cancel();
        assert!(
            pool.acquire(&cancel).is_none(),
            "an exhausted pool must not allocate past its capacity"
        );
        assert_eq!(pool.allocated(), 3);

        drop(held);
    }

    /// The behaviour a cancelled scan depends on: a waiter parked because every
    /// buffer is checked out returns instead of hanging.
    #[test]
    fn a_waiter_wakes_up_when_cancelled() {
        let pool = BufferPool::new(BLOCK, 1);
        let cancel = CancelToken::new();
        let held = pool.acquire(&cancel).unwrap();

        let waiter_pool = Arc::clone(&pool);
        let waiter_cancel = cancel.clone();
        let woke = Arc::new(AtomicUsize::new(0));
        let woke_thread = Arc::clone(&woke);
        let waiter = std::thread::spawn(move || {
            let got = waiter_pool.acquire(&waiter_cancel);
            woke_thread.store(if got.is_none() { 1 } else { 2 }, Ordering::SeqCst);
        });

        // Let the waiter actually park, then cancel.
        std::thread::sleep(POLL_INTERVAL * 3);
        cancel.cancel();
        waiter.join().unwrap();

        assert_eq!(
            woke.load(Ordering::SeqCst),
            1,
            "the waiter must observe cancellation and give up"
        );
        drop(held);
    }

    #[test]
    fn a_returned_buffer_serves_the_next_waiter() {
        let pool = BufferPool::new(BLOCK, 1);
        let cancel = CancelToken::new();
        let held = pool.acquire(&cancel).unwrap();

        let other = Arc::clone(&pool);
        let other_cancel = cancel.clone();
        let handle = std::thread::spawn(move || other.acquire(&other_cancel).is_some());

        drop(held);
        assert!(handle.join().unwrap(), "the waiting acquire must succeed");
        assert_eq!(pool.allocated(), 1, "handing over must not allocate");
    }
}
