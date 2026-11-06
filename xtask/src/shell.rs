//! `cargo xtask shell-check` -- build the shell extension DLL and the standalone
//! launcher EXE, and optionally register the extension, so the page can be looked
//! at inside the real `explorer.exe` Properties dialog.
//!
//! # Two artifacts, one registration
//!
//! Phase 7 ships a pair: `rusthashtab_shell.dll` is the COM server and owns the
//! property page, the context menu and the standalone window; `rusthashtab.exe` is
//! a thin launcher that loads that DLL from its own directory and calls its
//! `StandaloneEntryW` export. Only the DLL is registered -- the EXE needs no
//! registry entry, because it is started directly -- so `--register` and
//! `--unregister` still run `regsvr32` against the DLL alone.
//!
//! # Why this is not part of `check`
//!
//! `check` must be safe to run on any developer machine at any time. Registering a
//! shell extension writes to the user's registry and changes what every Properties
//! dialog on the machine shows, which is not something a pre-commit gate may do on
//! its own initiative. So registering is a separate, explicit action, and this
//! command does nothing to the registry unless it is asked to.
//!
//! # Why the manual step exists at all
//!
//! `tests/property_sheet_page.rs` hosts the page in a real dialog and checks that
//! results appear, and `tests/session.rs` checks the hashing. What neither can reach
//! is the property sheet itself: `PropertySheetW` is modal, and the page only has to
//! receive messages. The context menu and the standalone window sit in the same
//! blind spot: they need a real shell, a real desktop and a human deciding whether
//! they look right. So the last step -- "does this appear where a user expects it,
//! and does closing it leave explorer alive" -- is a human looking at it, and this
//! command exists to make that step a single command rather than an afternoon of
//! `regsvr32` archaeology.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// The shipping target, the only one this command builds.
const TARGET: &str = "x86_64-pc-windows-msvc";

/// The registered shell extension.
const DLL_NAME: &str = "rusthashtab_shell.dll";

/// The standalone launcher. It loads the DLL from its own directory at run time,
/// so it must be copied to wherever the DLL ends up.
const EXE_NAME: &str = "rusthashtab.exe";

/// What to do to the registry, if anything.
enum Registry {
    /// Leave it alone. The default.
    Untouched,
    /// Register, then tell the user what to look at.
    Register,
    /// Remove the registration.
    Unregister,
}

/// `cargo xtask shell-check [--register|--unregister]`.
pub(crate) fn run(args: &[String]) -> ExitCode {
    let mut action = Registry::Untouched;
    for arg in args {
        match arg.as_str() {
            "--register" => action = Registry::Register,
            "--unregister" => action = Registry::Unregister,
            other => {
                eprintln!("shell-check: unknown option `{other}`");
                eprintln!("usage: cargo xtask shell-check [--register|--unregister]");
                return ExitCode::from(2);
            }
        }
    }

    let workspace = match workspace_root() {
        Some(root) => root,
        None => {
            eprintln!(
                "shell-check: could not find the workspace root from {}",
                std::env::current_dir()
                    .map_or_else(|_| String::from("?"), |p| p.display().to_string())
            );
            return ExitCode::FAILURE;
        }
    };

    // A release build, because the DLL is about to be loaded into explorer.exe and a
    // debug one links a different CRT and is far slower at hashing. The launcher is
    // built in the same profile so the pair that is printed is the pair that ships.
    println!(
        "=== building the shell extension and the standalone launcher ({TARGET}, release) ==="
    );
    let built = Command::new("cargo")
        .current_dir(&workspace)
        .args([
            "build",
            "--package",
            "rusthashtab-shell",
            "--package",
            "rusthashtab-standalone",
            "--release",
            "--target",
            TARGET,
        ])
        .status();
    match built {
        Ok(status) if status.success() => {}
        Ok(status) => {
            eprintln!("shell-check: the build failed with {status}");
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("shell-check: could not run cargo: {error}");
            return ExitCode::FAILURE;
        }
    }

    let release = workspace.join("target").join(TARGET).join("release");
    let dll = release.join(DLL_NAME);
    let exe = release.join(EXE_NAME);

    // Both artifacts are checked for the same reason: "the build succeeded" is a
    // statement about exit codes, not about files. A missing launcher means the
    // standalone mode does not exist; a missing DLL means the registered extension
    // does not either.
    println!("\n=== artifacts ===");
    let mut produced = true;
    for (kind, path) in [("DLL", &dll), ("EXE", &exe)] {
        if !path.is_file() {
            eprintln!(
                "shell-check: the build reported success but produced no {kind} at {}",
                path.display()
            );
            produced = false;
            continue;
        }
        println!("{}", path.display());
        match std::fs::metadata(path) {
            Ok(metadata) => println!("  {} bytes", metadata.len()),
            Err(error) => println!("  (could not stat it: {error})"),
        }
    }
    if !produced {
        return ExitCode::FAILURE;
    }

    // `regsvr32` is how a user would register it by hand, so using it here means the
    // path that gets tested is the documented one rather than a private call. It is
    // given the DLL only: the launcher needs no registration.
    match action {
        Registry::Untouched => {
            println!("\nnot touching the registry. To try the extension in explorer:");
            println!("  cargo xtask shell-check --register");
            println!("  ... right-click a file and choose Hashes (on Windows 11 that item");
            println!("      lives under \"Show more options\"); resize and close the window ...");
            println!("  ... launch the launcher directly with the files to hash:");
            println!("      \"{}\" <file> [<file> ...]", exe.display());
            println!("  ... then open a checksum file via \"Open with\" -> rustHashTab ...");
            println!("  cargo xtask shell-check --unregister");
        }
        Registry::Register => {
            println!("\n=== registering the extension (per user) ===");
            if !regsvr32(&dll, true) {
                return ExitCode::FAILURE;
            }
            println!("\n=== now look at it ===");
            println!(
                "The launcher needs no registration: it loads the DLL from its own directory."
            );
            println!("  1. In explorer, right-click any file and choose Hashes. On Windows 11");
            println!("     that entry is under \"Show more options\".");
            println!("  2. A window should open. Resize it, then close it. explorer must");
            println!("     still be running.");
            println!("  3. Launch the standalone launcher with the files to hash:");
            println!("       \"{}\" <file> [<file> ...]", exe.display());
            println!("     It should list a digest per enabled algorithm and fill the bar.");
            println!("  4. Open a file's Properties dialog and switch to the Hashes tab.");
            println!("  5. Open a checksum file via \"Open with\" -> rustHashTab and check");
            println!("     that its entries are listed and verified against the files.");
            println!("  6. Then run: cargo xtask shell-check --unregister");
            println!("\nIf the context-menu item or the tab does not appear, the shell has not");
            println!("noticed the new handler yet. Signing out and back in is the reliable fix;");
            println!("the registration itself is already written.");
        }
        Registry::Unregister => {
            println!("\n=== unregistering ===");
            if !regsvr32(&dll, false) {
                return ExitCode::FAILURE;
            }
            println!("\nUnregistered. If the tab is still shown, sign out and back in.");
        }
    }

    ExitCode::SUCCESS
}

/// Run `regsvr32` against the DLL, reporting what it said.
fn regsvr32(dll: &Path, register: bool) -> bool {
    // `/s` silences the message box, because the exit code says the same thing and a
    // modal box would hang a script. `regsvr32` still returns a non-zero status on
    // failure with `/s`.
    let mut command = Command::new("regsvr32");
    command.arg("/s");
    if !register {
        command.arg("/u");
    }
    command.arg(dll);

    match command.status() {
        Ok(status) if status.success() => {
            println!("regsvr32: ok");
            true
        }
        Ok(status) => {
            eprintln!("regsvr32 failed with {status}");
            eprintln!("The DLL registers itself under HKCU, so elevation should not be");
            eprintln!("needed. A failure here is usually the DLL refusing to load:");
            eprintln!("check it exports DllRegisterServer.");
            false
        }
        Err(error) => {
            eprintln!("could not run regsvr32: {error}");
            false
        }
    }
}

/// The workspace root, found by walking up from the current directory.
///
/// Found rather than assumed: this command is normally run from the workspace root
/// through `cargo xtask`, but a developer who has `cd`-ed into `xtask/` should not
/// get a confusing "the build produced no DLL".
fn workspace_root() -> Option<PathBuf> {
    let mut directory = std::env::current_dir().ok()?;
    loop {
        if directory.join("Cargo.toml").is_file() && directory.join("xtask").is_dir() {
            return Some(directory);
        }
        if !directory.pop() {
            return None;
        }
    }
}
