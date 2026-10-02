//! Names of the resources compiled from `src/ui.rc`, and the message text the
//! page displays.
//!
//! # Why the identifiers live here as well as in the `.rc`
//!
//! `rc.exe` resolves identifiers at compile time and embeds only the numbers.
//! Rust therefore has to know the same numbers, and nothing in the toolchain
//! links the two lists. [`tests::the_identifiers_match_the_dialog_template`]
//! parses `src/ui.rc` and compares, so a rename on one side fails the build's
//! test run instead of producing a page whose controls are silently missing.

/// The dialog template the property sheet page is created from.
pub const IDD_HASH_PROPPAGE: u16 = 101;

/// The results list (`SysListView32`, report mode).
pub const IDC_HASH_LIST: i32 = 1001;
/// The single line under the list that carries the per-file status.
pub const IDC_HASH_STATUS: i32 = 1002;
/// The scan progress bar.
pub const IDC_HASH_PROGRESS: i32 = 1003;
/// Copies the selected rows to the clipboard.
pub const IDC_HASH_COPY: i32 = 1004;

/// Identifiers the dialog template declares, in declaration order.
///
/// Used by the test above; also the single place to look when adding a control.
#[cfg(test)]
pub(crate) const TEMPLATE_IDENTIFIERS: &[(&str, u16)] = &[
    ("IDD_HASH_PROPPAGE", IDD_HASH_PROPPAGE),
    ("IDC_HASH_LIST", IDC_HASH_LIST as u16),
    ("IDC_HASH_STATUS", IDC_HASH_STATUS as u16),
    ("IDC_HASH_PROGRESS", IDC_HASH_PROGRESS as u16),
    ("IDC_HASH_COPY", IDC_HASH_COPY as u16),
];

/// Column headings of the results list, in display order.
pub const COLUMNS: [&str; 4] = ["Algorithm", "Digest", "Match", "File"];

/// The status line before the scan reports anything.
pub const STATUS_STARTING: &str = "Hashing\u{2026}";

/// The status line once every file has been hashed.
///
/// The order of the counters is the order [`crate::Counters`] declares its
/// fields in, which is why that struct's field order is documented as
/// load-bearing.
pub fn status_finished(counters: &crate::Counters) -> String {
    format!(
        "{} matched  \u{2022}  {} mismatched  \u{2022}  {} not checked  \u{2022}  {} error",
        counters.matched, counters.mismatched, counters.nothing_to_check, counters.error
    )
}

/// The status line while the scan runs.
///
/// The counters are shown as they stand rather than only at the end: a large tree
/// takes long enough that a bare "Hashing..." gives the user nothing to judge
/// progress by, and the per-file counts are known before the last file is done.
pub fn status_running(done: usize, total: usize, counters: &crate::Counters) -> String {
    format!(
        "Hashing {done}/{total} \u{2022}  {} matched  \u{2022}  {} mismatched  \u{2022}  {} error",
        counters.matched, counters.mismatched, counters.error
    )
}

/// The status line once every file has been hashed.
///
/// The order of the counters is the order [`crate::Counters`] declares its fields
/// in, which is why that struct's field order is documented as load-bearing.
///
/// `skipped` is how many files the selection held that
/// [`crate::MAX_HASHED_FILES`] left out. Reported rather than hidden: a page that
/// silently hashed a thousand of two thousand files would misrepresent what it
/// checked, and "nothing was found" is a very different claim from "nothing that was
/// looked at was found".
pub fn status_finished_with_skipped(counters: &crate::Counters, skipped: usize) -> String {
    let mut text = status_finished(counters);
    if skipped > 0 {
        text.push_str(&format!("  \u{2022}  {skipped} not hashed"));
    }
    text
}

/// The status line when the scan was cancelled before it finished.
pub const STATUS_CANCELLED: &str = "Cancelled";

/// The status line when the hashing thread failed to start.
pub const STATUS_FAILED: &str = "Could not start hashing";

/// The status line when the selection contained nothing hashable.
pub const STATUS_EMPTY: &str = "Nothing to hash";

/// Shown in the digest column for a file that could not be read.
///
/// The digest column already carries "this is the answer", so an unreadable file
/// says so there rather than leaving an empty cell that looks like a zero-length
/// digest.
pub fn read_error_text(code: u32) -> String {
    format!("Error {code}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The dialog template, read at compile time so it cannot go missing.
    const TEMPLATE: &str = include_str!("ui.rc");

    #[test]
    fn the_identifiers_match_the_dialog_template() {
        for (name, value) in TEMPLATE_IDENTIFIERS {
            let declaration = format!("#define {name} ");
            let line = TEMPLATE
                .lines()
                .find(|line| line.trim_start().starts_with(&declaration))
                .unwrap_or_else(|| panic!("src/ui.rc no longer declares `{name}`"));

            let text = line
                .trim_start()
                .trim_start_matches(&declaration)
                .split_whitespace()
                .next()
                .unwrap_or_else(|| panic!("`{name}` has no value in src/ui.rc"));

            assert_eq!(
                text.parse::<u16>().unwrap_or_else(|error| panic!(
                    "`{name}` in src/ui.rc is not a number rc.exe and Rust both accept: {error}"
                )),
                *value,
                "src/ui.rc and src/resource.rs disagree about `{name}`"
            );
        }
    }

    /// Every control identifier the template declares must be one this module
    /// names, so a control cannot be added to the dialog and then ignored.
    #[test]
    fn the_template_declares_no_unknown_controls() {
        for line in TEMPLATE.lines() {
            let line = line.trim_start();
            if !line.starts_with("#define IDC_") {
                continue;
            }
            let name = line
                .trim_start_matches("#define ")
                .split_whitespace()
                .next()
                .unwrap_or_default();
            assert!(
                TEMPLATE_IDENTIFIERS.iter().any(|(known, _)| *known == name),
                "src/ui.rc declares `{name}`, which src/resource.rs does not name"
            );
        }
    }

    #[test]
    fn the_finished_status_lists_the_counters_in_field_order() {
        let counters = crate::Counters {
            matched: 1,
            mismatched: 2,
            nothing_to_check: 3,
            error: 4,
        };
        let text = status_finished(&counters);
        assert_eq!(
            text,
            "1 matched  \u{2022}  2 mismatched  \u{2022}  3 not checked  \u{2022}  4 error"
        );
    }

    #[test]
    fn a_read_error_is_shown_where_the_digest_would_be() {
        assert_eq!(read_error_text(5), "Error 5");
    }
}
