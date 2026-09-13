//! Hash reputation lookup and update checking.
//!
//! # Privacy
//!
//! The reputation lookup sends a file's **path, creation time and digest** to a
//! third party. That is the whole point of the feature, but it means it must
//! never happen implicitly:
//!
//! * it is off until the user accepts the remote service's terms, and the
//!   acceptance is persisted;
//! * an administrator can disable it machine-wide
//!   ([`rusthashtab_settings::MACHINE_FORCE_DISABLE_LOOKUP`]);
//! * the request carries only the digest where the service allows it.
//!
//! # Not yet implemented
//!
//! This module is scaffolding. It fixes the request/response types so callers
//! can be written against them, and so the privacy-relevant shape is reviewable
//! before any code performs I/O.

#![warn(missing_docs)]

/// One entry in a reputation response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReputationResult {
    /// Index into the caller's file list.
    pub file_index: usize,
    /// Whether the service knows this digest.
    pub found: bool,
    /// Number of engines that flagged the sample. Zero when `found` is false.
    pub detections: u32,
    /// Total number of engines that scanned the sample. Zero when `found` is
    /// false.
    pub engines: u32,
    /// Link to the full report, when the service provides one.
    pub permalink: Option<String>,
}

/// Errors a lookup or update check can produce.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// The request could not be completed.
    #[error("network error: {0}")]
    Request(String),
    /// The service returned a non-success status.
    #[error("service returned HTTP {status}: {body}")]
    Http {
        /// HTTP status code.
        status: u16,
        /// Response body, truncated for display.
        body: String,
    },
    /// The response was not parseable.
    #[error("malformed response: {0}")]
    Malformed(String),
    /// The user has not accepted the remote service's terms.
    #[error("terms of service not accepted")]
    TermsNotAccepted,
}

/// A version triple as reported by an update check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// Major version. Breaking, user-visible changes.
    pub major: u16,
    /// Minor version. Backwards-compatible additions.
    pub minor: u16,
    /// Patch version. Fixes only.
    pub patch: u16,
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Query the reputation service for a batch of digests.
///
/// `digests` are hex strings; `algorithm` names the algorithm they came from so
/// the service can interpret them.
///
/// # Not yet implemented
pub fn lookup(_digests: &[String], _algorithm: &str) -> Result<Vec<ReputationResult>, NetError> {
    unimplemented!("scaffolding: the reputation lookup lands with the UI")
}

/// Check whether a newer release exists.
///
/// # Not yet implemented
pub fn check_for_update() -> Result<Option<Version>, NetError> {
    unimplemented!("scaffolding: the update check lands with the UI")
}
