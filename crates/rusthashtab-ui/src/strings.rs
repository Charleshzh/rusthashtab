//! User-facing strings, addressed by key rather than written inline.
//!
//! # Why this exists before localization
//!
//! Phase 5 adds a lot of text: sorting hints, copy results, cancellation,
//! export-format names, paste errors. Writing it as string literals at each call
//! site means every one of those sites has to be found again when Phase 8 turns
//! the page into a localized resource. A key catalog makes that seam explicit
//! now, while the text is still English and there is no runtime lookup cost
//! worth worrying about.
//!
//! This is deliberately a Rust table rather than a `STRINGTABLE` yet. A
//! `STRINGTABLE` would have to be compiled into both the test binaries and the
//! DLL, and the page would need to carry a module handle just to read a status
//! line; Phase 8 can replace [`text`] with a resource lookup without changing a
//! single caller. Until then the table is the single place a new string belongs.
//!
//! # What does not belong here
//!
//! Algorithm names, column headings derived from the algorithm table, paths, and
//! anything already formatted from data. Those are not user-interface prose and
//! must not be duplicated into a translation catalog.

/// A key for one piece of user-facing text.
///
/// The variants are grouped by where they appear, not alphabetically, so a new
/// control's strings are easy to find next to its neighbours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Key {
    /// Sorting was requested while the scan was still running.
    SortAfterHashing,
    /// The clipboard could not be filled.
    CopyFailed,
    /// A copy succeeded; `{}` is the number of rows.
    CopiedRows,
    /// The user asked to cancel and the scan has not stopped yet.
    Cancelling,
    /// The scan was cancelled.
    Cancelled,
    /// Appended to a cancelled result set.
    ResultsIncomplete,
    /// Discovery is still walking the selection; `{}` is the number found.
    Discovering,
    /// Hashing has started; `{}` is the job count.
    HashingJobs,
    /// Export is unavailable while hashing.
    ExportAfterHashing,
    /// Label for the export-format combo.
    ExportFormatLabel,
    /// Button that copies checksums in the selected format.
    CopyChecksums,
    /// Checkbox that restricts pasted verification to the current file.
    CurrentFileOnly,
    /// The pasted text is not a digest or a checksum line.
    PasteNotADigest,
    /// No enabled algorithm produces a digest of that length.
    PasteWrongLength,
    /// The pasted line names a file that is not in the selection.
    PasteFileNotSelected,
    /// The pasted line names more than one file.
    PasteMultipleEntries,
    /// The pasted line names a file ambiguously.
    PasteAmbiguousFile,
    /// No row is selected for a current-file check.
    PasteSelectRow,
    /// Settings were saved.
    SettingsSaved,
    /// A settings save failed.
    SettingsSaveFailed,
    /// Nothing was selected to hash.
    NothingToHash,
    /// Hashing finished with at least one unreadable file.
    NoFilesRead,
    /// Appended to a running status when a verification source is in effect.
    ResultsMayBePartial,
    /// The file column heading, for accessibility.
    FileColumnLabel,
    /// The results list's accessible name.
    ResultsListLabel,
    /// The status line's accessible name.
    StatusLineLabel,
    /// The expected-digest edit box's accessible name.
    ExpectedDigestLabel,
    /// The colour class: matched.
    ColourMatched,
    /// The colour class: weak match.
    ColourWeakMatch,
    /// The colour class: mismatch.
    ColourMismatch,
    /// The colour class: read error.
    ColourError,
    /// The colour class: not checked.
    ColourUnchecked,
    /// The "Text" colour button.
    ColourTextButton,
    /// The "Background" colour button.
    ColourBackgroundButton,
    /// The "Defaults" colour button.
    ColourDefaultsButton,
    /// The colour group's heading.
    ColourGroupLabel,
    /// The export-format mismatch error.
    ExportFormatMismatch,
    /// A copied checksum set; `{}` is the number of entries.
    CopiedHashes,
}

/// The English text for a key.
///
/// Every variant must have a non-empty value; [`tests::every_key_has_text`]
/// enforces it. Format placeholders are `{}` and are filled by the caller.
pub fn text(key: Key) -> &'static str {
    match key {
        Key::SortAfterHashing => "Sorting is available after hashing finishes",
        Key::CopyFailed => "Could not copy to the clipboard",
        Key::CopiedRows => "Copied {} rows",
        Key::Cancelling => "Cancelling\u{2026}",
        Key::Cancelled => "Cancelled",
        Key::ResultsIncomplete => "results incomplete",
        Key::Discovering => "Discovering files\u{2026} {} found",
        Key::HashingJobs => "Hashing {} files",
        Key::ExportAfterHashing => "Export is available after hashing finishes",
        Key::ExportFormatLabel => "Format",
        Key::CopyChecksums => "Copy checksums",
        Key::CurrentFileOnly => "Current file only",
        Key::PasteNotADigest => "Not a digest or checksum line",
        Key::PasteWrongLength => "No enabled algorithm produces that digest length",
        Key::PasteFileNotSelected => "The digest names a file that is not selected",
        Key::PasteMultipleEntries => "Paste one digest or one checksum line",
        Key::PasteAmbiguousFile => "The digest names more than one selected file",
        Key::PasteSelectRow => "Select a file row to check",
        Key::SettingsSaved => "Settings saved",
        Key::SettingsSaveFailed => "Could not save settings",
        Key::NothingToHash => "Nothing to hash",
        Key::NoFilesRead => "No files could be read",
        Key::ResultsMayBePartial => "results may be partial",
        Key::FileColumnLabel => "File",
        Key::ResultsListLabel => "Hash results",
        Key::StatusLineLabel => "Hash status",
        Key::ExpectedDigestLabel => "Expected digest",
        Key::ColourMatched => "Matched",
        Key::ColourWeakMatch => "Weak match",
        Key::ColourMismatch => "Mismatch",
        Key::ColourError => "Read error",
        Key::ColourUnchecked => "Not checked",
        Key::ColourTextButton => "Text\u{2026}",
        Key::ColourBackgroundButton => "Background\u{2026}",
        Key::ColourDefaultsButton => "Defaults",
        Key::ColourGroupLabel => "Colours",
        Key::ExportFormatMismatch => "The file name does not match the selected format",
        Key::CopiedHashes => "Copied {} hashes",
    }
}

/// Every key, in declaration order, for tests and future resource generation.
pub fn all() -> &'static [Key] {
    &[
        Key::SortAfterHashing,
        Key::CopyFailed,
        Key::CopiedRows,
        Key::Cancelling,
        Key::Cancelled,
        Key::ResultsIncomplete,
        Key::Discovering,
        Key::HashingJobs,
        Key::ExportAfterHashing,
        Key::ExportFormatLabel,
        Key::CopyChecksums,
        Key::CurrentFileOnly,
        Key::PasteNotADigest,
        Key::PasteWrongLength,
        Key::PasteFileNotSelected,
        Key::PasteMultipleEntries,
        Key::PasteAmbiguousFile,
        Key::PasteSelectRow,
        Key::SettingsSaved,
        Key::SettingsSaveFailed,
        Key::NothingToHash,
        Key::NoFilesRead,
        Key::ResultsMayBePartial,
        Key::FileColumnLabel,
        Key::ResultsListLabel,
        Key::StatusLineLabel,
        Key::ExpectedDigestLabel,
        Key::ColourMatched,
        Key::ColourWeakMatch,
        Key::ColourMismatch,
        Key::ColourError,
        Key::ColourUnchecked,
        Key::ColourTextButton,
        Key::ColourBackgroundButton,
        Key::ColourDefaultsButton,
        Key::ColourGroupLabel,
        Key::ExportFormatMismatch,
        Key::CopiedHashes,
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_key_has_text() {
        for key in all() {
            assert!(!text(*key).is_empty(), "{key:?} has no text");
        }
    }

    #[test]
    fn the_key_list_has_no_duplicates() {
        let mut seen = HashSet::new();
        for key in all() {
            assert!(seen.insert(*key), "{key:?} is listed twice");
        }
    }
}
