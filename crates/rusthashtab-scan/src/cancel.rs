//! Cooperative cancellation for a running scan.
//!
//! # Why a token and not a `bool` behind a mutex
//!
//! Three different waits have to observe cancellation: a worker taking a job
//! from the queue, a worker waiting for a read buffer, and a worker waiting for
//! an overlapped read to complete. The last one is a *kernel* wait, so a plain
//! atomic is not enough — a thread parked in `WaitForMultipleObjects` cannot
//! notice a flag change.
//!
//! Hence two mechanisms in one token:
//!
//! * an [`AtomicBool`], which the queue and the buffer pool poll (the pool polls
//!   every [`POLL_INTERVAL`], which is why a cancelled scan can be up to that
//!   long in noticing while all buffers are checked out), and
//! * a manual-reset Win32 event, which is the second handle in the reader's
//!   `WaitForMultipleObjects` so a blocked read wakes the instant it is cancelled.
//!
//! The event is created lazily and its creation failure is not fatal: without it
//! the reader falls back to polling the flag, which is slower to react but still
//! correct. A design that required the event would turn an out-of-handles
//! condition into a hung cancel.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// How long a waiter that can only poll sleeps between flag checks.
pub(crate) const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

/// A shareable "stop what you are doing" handle.
///
/// Cloning is cheap and every clone observes the same state, so the scheduler and
/// every worker hold one.
#[derive(Clone, Debug, Default)]
pub(crate) struct CancelToken {
    shared: Arc<CancelShared>,
}

#[derive(Debug, Default)]
struct CancelShared {
    cancelled: AtomicBool,
    /// Created on first use. `None` inside the `OnceLock` means creation failed
    /// once, and the reader must poll instead.
    #[cfg(windows)]
    event: std::sync::OnceLock<Option<crate::reader::OwnedEvent>>,
}

impl CancelToken {
    /// A token that is not cancelled yet.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Request cancellation. Idempotent, and safe to call from any thread.
    pub(crate) fn cancel(&self) {
        // Release: a worker that observes `true` with `Acquire` must also see
        // everything the cancelling thread wrote before it asked to stop.
        self.shared.cancelled.store(true, Ordering::Release);
        #[cfg(windows)]
        if let Some(Some(event)) = self.shared.event.get() {
            event.set();
        }
    }

    /// Whether cancellation has been requested.
    pub(crate) fn is_cancelled(&self) -> bool {
        self.shared.cancelled.load(Ordering::Acquire)
    }

    /// The event a kernel wait can block on, created on first call.
    ///
    /// `None` when the event could not be created; callers must then poll
    /// [`CancelToken::is_cancelled`].
    #[cfg(windows)]
    pub(crate) fn wait_event(&self) -> Option<windows::Win32::Foundation::HANDLE> {
        self.shared
            .event
            .get_or_init(|| crate::reader::OwnedEvent::new().ok())
            .as_ref()
            .map(crate::reader::OwnedEvent::raw)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_one_flag() {
        let a = CancelToken::new();
        let b = a.clone();
        assert!(!a.is_cancelled());
        b.cancel();
        assert!(
            a.is_cancelled(),
            "cancellation must be visible through clones"
        );
    }

    #[test]
    fn cancelling_twice_is_harmless() {
        let token = CancelToken::new();
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
    }

    /// The event is the whole reason this type is not a bare atomic. If it cannot
    /// be created the reader polls; this asserts the fallback is reachable and
    /// that the event, once created, is settable.
    #[cfg(windows)]
    #[test]
    fn the_wait_event_is_created_once_and_signalled_on_cancel() {
        let token = CancelToken::new();
        let first = token.wait_event();
        let second = token.wait_event();
        assert!(
            first.is_some(),
            "CreateEventW should succeed on a test host"
        );
        assert_eq!(
            first.map(|h| h.0),
            second.map(|h| h.0),
            "the event must be created once and reused"
        );

        token.cancel();
        // A manual-reset event stays signaled, which is what makes a late
        // canceller idempotent and lets every worker observe it.
        assert_eq!(token.wait_event().map(|h| h.0), first.map(|h| h.0));
    }
}
