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
/// Where the user pastes a digest to check against the selected file.
pub const IDC_HASH_EXPECTED: i32 = 1005;
/// Applies the pasted digest to the selected file.
pub const IDC_HASH_CHECK: i32 = 1006;
/// Opens a checksum file and verifies the hashed files against it.
pub const IDC_HASH_VERIFY: i32 = 1007;
/// Writes the hashes out as a checksum file.
pub const IDC_HASH_EXPORT: i32 = 1008;
/// Opens the settings dialog.
pub const IDC_HASH_SETTINGS: i32 = 1009;
/// Stops the running scan without closing the page.
pub const IDC_HASH_CANCEL: i32 = 1010;
/// Chooses which checksum format/algorithm to export.
pub const IDC_HASH_EXPORT_FORMAT: i32 = 1011;
/// Copies the selected format's checksums to the clipboard.
pub const IDC_HASH_EXPORT_CLIPBOARD: i32 = 1012;
/// Restricts a pasted digest to the selected file.
pub const IDC_HASH_CURRENT_ONLY: i32 = 1013;

/// The settings dialog template.
pub const IDD_SETTINGS: u16 = 102;

/// The checklist of all 31 algorithms (`SysListView32`, check boxes at runtime).
pub const IDC_SETTINGS_ALGORITHMS: i32 = 2101;
/// Upper-case hex in the results list.
pub const IDC_SETTINGS_UPPERCASE: i32 = 2102;
/// Monospace rendering in the results list.
pub const IDC_SETTINGS_MONOSPACE: i32 = 2103;
/// Look for a checksum file next to each hashed file.
pub const IDC_SETTINGS_LOOK_FOR_SUMFILES: i32 = 2104;
/// Upper-case hex in exported checksum files.
pub const IDC_SETTINGS_SUMFILE_UPPERCASE: i32 = 2105;
/// LF line endings in exported checksum files.
pub const IDC_SETTINGS_SUMFILE_LF: i32 = 2106;
/// Two spaces rather than space-asterisk in exported checksum files.
pub const IDC_SETTINGS_SUMFILE_DOUBLE_SPACE: i32 = 2107;
/// Forward slashes in exported checksum files.
pub const IDC_SETTINGS_SUMFILE_FORWARD_SLASH: i32 = 2108;
/// Emit corz `.hash` compatible lines.
pub const IDC_SETTINGS_SUMFILE_CORZ: i32 = 2109;
/// Emit a provenance banner.
pub const IDC_SETTINGS_SUMFILE_BANNER: i32 = 2110;
/// Include a timestamp in the banner.
pub const IDC_SETTINGS_SUMFILE_BANNER_DATE: i32 = 2111;
/// Restore the built-in defaults in the settings dialog.
pub const IDC_SETTINGS_DEFAULTS: i32 = 2112;
/// Require a pasted line's file name to resolve by full path.
pub const IDC_SETTINGS_VERIFY_STRICT: i32 = 2113;
/// Rewrite the paste box to canonical hex after a successful check.
pub const IDC_SETTINGS_VERIFY_AUTO_FORMAT: i32 = 2114;
/// Which colour class the colour controls edit.
pub const IDC_SETTINGS_COLOUR_CLASS: i32 = 2115;
/// A textual preview of the selected class's colours.
pub const IDC_SETTINGS_COLOUR_PREVIEW: i32 = 2116;
/// Pick the selected class's text colour.
pub const IDC_SETTINGS_COLOUR_TEXT: i32 = 2117;
/// Pick the selected class's background colour.
pub const IDC_SETTINGS_COLOUR_BG: i32 = 2118;
/// Restore the default colours.
pub const IDC_SETTINGS_COLOUR_DEFAULTS: i32 = 2119;
/// Whether the selected class paints its foreground colour.
pub const IDC_SETTINGS_COLOUR_TEXT_ENABLED: i32 = 2120;
/// Whether the selected class paints its background colour.
pub const IDC_SETTINGS_COLOUR_BG_ENABLED: i32 = 2121;
/// The hex/off label under the live colour sample.
pub const IDC_SETTINGS_COLOUR_PREVIEW_LABEL: i32 = 2122;
/// Also hash the checksum file itself when a selection is a manifest.
pub const IDC_SETTINGS_HASH_SUMFILE: i32 = 2123;
/// Restrict a manifest scan to the algorithm its extension names.
pub const IDC_SETTINGS_SUMFILE_ALGORITHM_ONLY: i32 = 2124;
/// Check a digest found on the clipboard after the scan finishes.
pub const IDC_SETTINGS_VERIFY_CLIPBOARD: i32 = 2125;

/// Identifiers the dialog templates declare, in declaration order.
///
/// Used by the test above; also the single place to look when adding a control.
#[cfg(test)]
pub(crate) const TEMPLATE_IDENTIFIERS: &[(&str, u16)] = &[
    ("IDD_HASH_PROPPAGE", IDD_HASH_PROPPAGE),
    ("IDC_HASH_LIST", IDC_HASH_LIST as u16),
    ("IDC_HASH_STATUS", IDC_HASH_STATUS as u16),
    ("IDC_HASH_PROGRESS", IDC_HASH_PROGRESS as u16),
    ("IDC_HASH_COPY", IDC_HASH_COPY as u16),
    ("IDC_HASH_EXPECTED", IDC_HASH_EXPECTED as u16),
    ("IDC_HASH_CHECK", IDC_HASH_CHECK as u16),
    ("IDC_HASH_VERIFY", IDC_HASH_VERIFY as u16),
    ("IDC_HASH_EXPORT", IDC_HASH_EXPORT as u16),
    ("IDC_HASH_SETTINGS", IDC_HASH_SETTINGS as u16),
    ("IDC_HASH_CANCEL", IDC_HASH_CANCEL as u16),
    ("IDC_HASH_EXPORT_FORMAT", IDC_HASH_EXPORT_FORMAT as u16),
    (
        "IDC_HASH_EXPORT_CLIPBOARD",
        IDC_HASH_EXPORT_CLIPBOARD as u16,
    ),
    ("IDC_HASH_CURRENT_ONLY", IDC_HASH_CURRENT_ONLY as u16),
    ("IDD_SETTINGS", IDD_SETTINGS),
    ("IDC_SETTINGS_ALGORITHMS", IDC_SETTINGS_ALGORITHMS as u16),
    ("IDC_SETTINGS_UPPERCASE", IDC_SETTINGS_UPPERCASE as u16),
    ("IDC_SETTINGS_MONOSPACE", IDC_SETTINGS_MONOSPACE as u16),
    (
        "IDC_SETTINGS_LOOK_FOR_SUMFILES",
        IDC_SETTINGS_LOOK_FOR_SUMFILES as u16,
    ),
    (
        "IDC_SETTINGS_SUMFILE_UPPERCASE",
        IDC_SETTINGS_SUMFILE_UPPERCASE as u16,
    ),
    ("IDC_SETTINGS_SUMFILE_LF", IDC_SETTINGS_SUMFILE_LF as u16),
    (
        "IDC_SETTINGS_SUMFILE_DOUBLE_SPACE",
        IDC_SETTINGS_SUMFILE_DOUBLE_SPACE as u16,
    ),
    (
        "IDC_SETTINGS_SUMFILE_FORWARD_SLASH",
        IDC_SETTINGS_SUMFILE_FORWARD_SLASH as u16,
    ),
    (
        "IDC_SETTINGS_SUMFILE_CORZ",
        IDC_SETTINGS_SUMFILE_CORZ as u16,
    ),
    (
        "IDC_SETTINGS_SUMFILE_BANNER",
        IDC_SETTINGS_SUMFILE_BANNER as u16,
    ),
    (
        "IDC_SETTINGS_SUMFILE_BANNER_DATE",
        IDC_SETTINGS_SUMFILE_BANNER_DATE as u16,
    ),
    ("IDC_SETTINGS_DEFAULTS", IDC_SETTINGS_DEFAULTS as u16),
    (
        "IDC_SETTINGS_VERIFY_STRICT",
        IDC_SETTINGS_VERIFY_STRICT as u16,
    ),
    (
        "IDC_SETTINGS_VERIFY_AUTO_FORMAT",
        IDC_SETTINGS_VERIFY_AUTO_FORMAT as u16,
    ),
    (
        "IDC_SETTINGS_COLOUR_CLASS",
        IDC_SETTINGS_COLOUR_CLASS as u16,
    ),
    (
        "IDC_SETTINGS_COLOUR_PREVIEW",
        IDC_SETTINGS_COLOUR_PREVIEW as u16,
    ),
    ("IDC_SETTINGS_COLOUR_TEXT", IDC_SETTINGS_COLOUR_TEXT as u16),
    ("IDC_SETTINGS_COLOUR_BG", IDC_SETTINGS_COLOUR_BG as u16),
    (
        "IDC_SETTINGS_COLOUR_DEFAULTS",
        IDC_SETTINGS_COLOUR_DEFAULTS as u16,
    ),
    (
        "IDC_SETTINGS_COLOUR_TEXT_ENABLED",
        IDC_SETTINGS_COLOUR_TEXT_ENABLED as u16,
    ),
    (
        "IDC_SETTINGS_COLOUR_BG_ENABLED",
        IDC_SETTINGS_COLOUR_BG_ENABLED as u16,
    ),
    (
        "IDC_SETTINGS_COLOUR_PREVIEW_LABEL",
        IDC_SETTINGS_COLOUR_PREVIEW_LABEL as u16,
    ),
    (
        "IDC_SETTINGS_HASH_SUMFILE",
        IDC_SETTINGS_HASH_SUMFILE as u16,
    ),
    (
        "IDC_SETTINGS_SUMFILE_ALGORITHM_ONLY",
        IDC_SETTINGS_SUMFILE_ALGORITHM_ONLY as u16,
    ),
    (
        "IDC_SETTINGS_VERIFY_CLIPBOARD",
        IDC_SETTINGS_VERIFY_CLIPBOARD as u16,
    ),
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

/// Shown while a checksum file is being read and matched against the results.
pub const STATUS_VERIFYING: &str = "Reading checksum file...";

/// Shown when the text in the expected-hash box is not a hex digest.
pub const STATUS_NOT_HEX: &str = "Not a hex digest";

/// Shown when the pasted digest is not the length of any enabled algorithm.
///
/// Applying it anyway would report a mismatch, which says the file is wrong when
/// the truth is that the digest was never comparable.
pub const STATUS_NO_MATCHING_LENGTH: &str = "No enabled algorithm produces that digest length";

/// Shown when the user asks to verify without a file selected.
pub const STATUS_SELECT_FILE: &str = "Select a file row to verify";

/// Shown when a checksum file cannot be read at all.
pub const STATUS_SUMFILE_UNREADABLE: &str = "Could not read the checksum file";

/// Shown when a checksum file parses but names none of the hashed files.
pub const STATUS_SUMFILE_NO_MATCH: &str = "The checksum file names no selected file";

/// Shown when there is nothing to export yet.
pub const STATUS_NOTHING_TO_EXPORT: &str = "Nothing has been hashed yet";

/// Shown when the export target cannot be written.
pub const STATUS_EXPORT_FAILED: &str = "Could not write the checksum file";

/// Shown while an export is being written.
pub const STATUS_EXPORTING: &str = "Exporting...";

/// The source label used after a digest was pasted.
pub const PASTED_SOURCE: &str = "pasted digest";

/// The source label for a checksum file, as it appears in the status line.
///
/// The file name alone rather than the full path: the status line is one line
/// wide, and the directory is already what the user was looking at.
pub fn sumfile_source(path: &std::path::Path) -> String {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());
    format!("checksum file: {name}")
}

/// The source label for a checksum file that was interpreted as a manifest.
///
/// The file name alone, like [`sumfile_source`], plus the inferred algorithm when
/// the extension named one. The wording is what tells the user the page did not
/// just hash the selected file.
pub fn manifest_source(path: &std::path::Path, inferred: Option<&str>) -> String {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());
    match inferred {
        Some(algorithm) => format!("checksum file: {name} (interpreted as sumfile: {algorithm})"),
        None => format!("checksum file: {name} (interpreted as sumfile)"),
    }
}

/// The status line once a verification source is in effect.
///
/// `base` is the ordinary counter summary -- the counts are still the important
/// part -- and the suffix says what they were counted against. Appending rather
/// than replacing keeps one status line instead of a second control.
pub fn with_verification(
    base: String,
    source: &str,
    unmatched: usize,
    had_error: bool,
    unreadable: usize,
) -> String {
    let mut text = format!("{base}  \u{2022}  {source}");
    if unmatched > 0 {
        text.push_str(&format!("  \u{2022}  {unmatched} entries matched no file"));
    }
    if had_error {
        text.push_str("  \u{2022}  malformed lines ignored");
    }
    if unreadable == 1 {
        text.push_str("  \u{2022}  1 checksum file could not be read");
    } else if unreadable > 1 {
        text.push_str(&format!(
            "  \u{2022}  {unreadable} checksum files could not be read"
        ));
    }
    text
}

/// Append the first matched `文件 × 算法` to the status line.
///
/// The counters say how many files matched; this says *which* one, which is the
/// difference between "3 matched" and "this file matched under SHA-256" when a
/// digest is checked against a whole selection.
pub fn with_match_detail(base: String, detail: &crate::readout::MatchDetail) -> String {
    let mut text = format!(
        "{base}  \u{2022}  matched: {} \u{00d7} {}",
        detail.display_path, detail.algorithm
    );
    if detail.more > 0 {
        text.push_str(&format!(" (+{} more)", detail.more));
    }
    text
}

/// The status line after a successful export.
pub fn status_exported(count: usize) -> String {
    format!("Exported {count} hashes")
}

/// The status line when the settings dialog is unavailable.
///
/// Reached only when the page was built without the module instance (a test
/// harness, not the shell): there is no template to load the dialog from.
pub const STATUS_SETTINGS_UNAVAILABLE: &str = "Settings are unavailable";

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The dialog template, read at compile time so it cannot go missing.
    ///
    /// Note what this is and is not. It is the **text** of `ui.rc`, which lets the
    /// test below check that the identifiers here and the declarations there agree.
    /// It says nothing about whether the file was compiled into anything -- that is
    /// a different question, and one that went unasked for a while: the template was
    /// compiled by this crate's build script, and a `.res` from a **library's**
    /// build script never reaches the `cdylib`, so the DLL had no template and the
    /// page could not be shown. `rusthashtab-shell/build.rs` compiles it into the
    /// DLL now, and `tests/page_in_sheet.rs` asserts it is reachable there.
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

    #[test]
    fn a_sumfile_source_names_the_file_not_the_directory() {
        assert_eq!(
            sumfile_source(std::path::Path::new(r"C:\some\dir\payload.sha256")),
            "checksum file: payload.sha256"
        );
        assert_eq!(
            sumfile_source(std::path::Path::new("payload.sha256")),
            "checksum file: payload.sha256"
        );
    }

    /// The counters stay first because they are the answer; the source is the
    /// qualifier, and both fit on one line for an ordinary checksum file.
    #[test]
    fn verification_suffix_appends_the_source_and_the_gaps() {
        let base = String::from("1 matched");
        assert_eq!(
            with_verification(base.clone(), "checksum file: a.sha256", 0, false, 0),
            "1 matched  \u{2022}  checksum file: a.sha256"
        );
        assert_eq!(
            with_verification(base.clone(), "checksum file: a.sha256", 2, false, 0),
            "1 matched  \u{2022}  checksum file: a.sha256  \u{2022}  2 entries matched no file"
        );
        assert_eq!(
            with_verification(base, "checksum file: a.sha256", 0, true, 0),
            "1 matched  \u{2022}  checksum file: a.sha256  \u{2022}  malformed lines ignored"
        );
    }

    /// A sidecar that could not be read is a gap the counters cannot express.
    #[test]
    fn verification_suffix_reports_unreadable_sidecars() {
        let base = String::from("1 matched");
        assert_eq!(
            with_verification(
                base.clone(),
                "checksum files beside the hashed files",
                0,
                false,
                1
            ),
            "1 matched  \u{2022}  checksum files beside the hashed files  \
             \u{2022}  1 checksum file could not be read"
        );
        assert!(
            with_verification(base, "sidecars", 0, false, 3)
                .contains("3 checksum files could not be read")
        );
    }

    /// A manifest source names the file and, when known, the inferred algorithm:
    /// "SHA-256" is what makes the temporary algorithm set explainable.
    #[test]
    fn a_manifest_source_names_the_file_and_the_inferred_algorithm() {
        assert_eq!(
            manifest_source(
                std::path::Path::new(r"C:\dir\payload.sha256"),
                Some("SHA-256")
            ),
            "checksum file: payload.sha256 (interpreted as sumfile: SHA-256)"
        );
        assert_eq!(
            manifest_source(std::path::Path::new("payload.sfv"), None),
            "checksum file: payload.sfv (interpreted as sumfile)"
        );
    }

    /// The status line names the first matched file and algorithm; a count keeps
    /// multi-file results bounded.
    #[test]
    fn a_match_detail_names_the_first_match() {
        let detail = crate::readout::MatchDetail {
            display_path: String::from("payload.bin"),
            algorithm: "SHA-256",
            more: 0,
        };
        assert_eq!(
            with_match_detail(String::from("1 matched"), &detail),
            "1 matched  \u{2022}  matched: payload.bin \u{00d7} SHA-256"
        );

        let detail = crate::readout::MatchDetail {
            display_path: String::from("payload.bin"),
            algorithm: "SHA-256",
            more: 2,
        };
        assert_eq!(
            with_match_detail(String::from("3 matched"), &detail),
            "3 matched  \u{2022}  matched: payload.bin \u{00d7} SHA-256 (+2 more)"
        );
    }

    #[test]
    fn an_export_status_names_the_count() {
        assert_eq!(status_exported(0), "Exported 0 hashes");
        assert_eq!(status_exported(3), "Exported 3 hashes");
    }
}
