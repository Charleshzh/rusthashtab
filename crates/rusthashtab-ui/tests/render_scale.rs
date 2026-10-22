//! Large-result rendering measurement.
//!
//! The page caps a selection at [`rusthashtab_ui::MAX_HASHED_FILES`] files, and
//! with every algorithm enabled that is 31,000 rows. This test builds a real
//! report-mode list view and times the first fill and a 10% verdict update, so
//! P5.16's threshold is measured rather than guessed.
//!
//! It is `#[ignore]`d because it is a measurement, not a pass/fail unit test:
//! the debug profile is not representative and the threshold belongs to a
//! release build on the reference machine. Run it with:
//!
//! ```text
//! cargo test -p rusthashtab-ui --release --test render_scale -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rusthashtab_hash::ALGORITHMS;
use rusthashtab_scan::MatchState;
use rusthashtab_ui::{ListRow, row_id};
use std::time::Instant;
use windows::Win32::UI::Controls::{
    ICC_LISTVIEW_CLASSES, INITCOMMONCONTROLSEX, INITCOMMONCONTROLSEX_ICC, InitCommonControlsEx,
    LVS_REPORT,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, WINDOW_EX_STYLE, WINDOW_STYLE,
};
use windows::core::w;

/// 1000 files × 31 algorithms.
const ROWS: usize = 31_000;
/// The release threshold from the Phase 5 plan.
const FILL_TARGET_MS: u128 = 500;
/// The verify-change target from the Phase 5 plan.
const UPDATE_TARGET_MS: u128 = 300;

#[test]
#[ignore = "measurement; run with --release -- --ignored --nocapture"]
fn thirty_one_thousand_rows_fill_and_update() {
    let classes = INITCOMMONCONTROLSEX {
        dwSize: core::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
        dwICC: INITCOMMONCONTROLSEX_ICC(ICC_LISTVIEW_CLASSES.0),
    };
    // SAFETY: `classes` declares its own size and lives for the call.
    let initialised = unsafe { InitCommonControlsEx(&classes) };
    assert!(initialised.as_bool(), "common controls must initialise");

    // SAFETY: a predefined system class, no parent, and every optional handle is
    // null; the window is never shown.
    let list = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("SysListView32"),
            w!(""),
            WINDOW_STYLE(LVS_REPORT),
            0,
            0,
            800,
            600,
            None,
            None,
            None,
            None,
        )
    }
    .expect("a list view can be created");
    assert!(!list.is_invalid());

    rusthashtab_ui::listview::add_columns(list);

    let mut rows = Vec::with_capacity(ROWS);
    for file in 0..1000usize {
        for (algorithm, entry) in ALGORITHMS.iter().enumerate() {
            rows.push(ListRow {
                id: row_id(file, algorithm),
                job_index: file,
                algorithm,
                digest_hex: "AB".repeat(entry.output_len),
                match_state: MatchState::NotChecked,
                error: None,
                display_path: format!("file-{file}.bin"),
            });
        }
    }

    let started = Instant::now();
    rusthashtab_ui::listview::set_rows(list, &rows);
    let fill = started.elapsed();
    println!("fill {ROWS} rows: {fill:?}");

    // A verification source changes some verdicts; the incremental path should
    // rewrite only those cells.
    for row in rows.iter_mut().take(ROWS / 10) {
        row.match_state = MatchState::Mismatched;
    }
    let started = Instant::now();
    rusthashtab_ui::listview::update_rows(list);
    let update = started.elapsed();
    println!("update {} rows: {update:?}", ROWS / 10);

    if cfg!(not(debug_assertions)) {
        assert!(
            fill.as_millis() <= FILL_TARGET_MS,
            "fill took {fill:?}, target <= {FILL_TARGET_MS} ms"
        );
        assert!(
            update.as_millis() <= UPDATE_TARGET_MS,
            "update took {update:?}, target <= {UPDATE_TARGET_MS} ms"
        );
    }

    // SAFETY: `list` was created by this test and is destroyed once.
    unsafe {
        let _ = DestroyWindow(list);
    }
}
