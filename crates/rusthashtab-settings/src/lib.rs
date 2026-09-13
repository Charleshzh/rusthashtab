//! Persisted user settings.
//!
//! Settings live in the registry under `HKCU\Software\rustHashTab` so that a
//! per-user install needs no elevation and the shell can read them without a
//! file handle. Every value is a `DWORD`, which keeps reads cheap and avoids
//! parsing on the property-sheet path.
//!
//! # Layout
//!
//! Each algorithm gets one boolean value named after it (`"SHA-256"`, `"K12-264"`,
//! …). Non-algorithm options use descriptive names (`"DisplayUppercase"`,
//! `"LookForSumfiles"`). Colours are stored as a `COLORREF` packed into a
//! `DWORD`.
//!
//! # Why not a config file
//!
//! The upstream implementation used the registry and users' existing settings
//! live there. Matching that layout means a migration is a no-op, and it keeps
//! the DLL from needing any writable file path at runtime.

#![warn(missing_docs)]

/// Registry subkey, relative to `HKCU` (or `HKLM` for machine-wide overrides).
pub const REG_KEY: &str = r"Software\rustHashTab";

/// A machine-wide override that disables the reputation lookup for every user.
///
/// Read from `HKLM\Software\rustHashTab`; any non-zero value disables the
/// feature. This exists so an administrator can turn the network call off
/// fleet-wide without touching per-user state.
pub const MACHINE_FORCE_DISABLE_LOOKUP: &str = "ForceDisableLookup";

/// A per-user language override, holding an LCID.
pub const LANG_ID_OVERRIDE: &str = "LangIdOverride";

/// The full set of user-configurable options.
///
/// Field names map 1:1 onto registry value names via [`Settings::value_name`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Upper-case hex digests in the list view.
    pub display_uppercase: bool,
    /// Render digests in a monospace font.
    pub display_monospace: bool,
    /// Look for a sumfile next to each file being hashed.
    pub look_for_sumfiles: bool,
    /// Uppercase hex when exporting sumfiles.
    pub sumfile_uppercase: bool,
    /// LF line endings in exported sumfiles.
    pub sumfile_unix_endings: bool,
    /// Two spaces instead of space-asterisk.
    pub sumfile_double_space: bool,
    /// Forward slashes in exported paths.
    pub sumfile_forward_slashes: bool,
    /// Also emit corz `.hash` compatible lines.
    pub sumfile_dot_hash_compatible: bool,
    /// Emit a provenance banner.
    pub sumfile_banner: bool,
    /// Include a timestamp in the banner.
    pub sumfile_banner_date: bool,
    /// Which algorithms are enabled, indexed by algorithm-table position.
    pub algorithms: Vec<bool>,
}

impl Default for Settings {
    /// The defaults a fresh install gets.
    ///
    /// Only the four algorithms people actually check against are on by
    /// default; enabling all 31 would make the first hash of a large file
    /// noticeably slower for no benefit.
    fn default() -> Self {
        Self {
            display_uppercase: true,
            display_monospace: true,
            look_for_sumfiles: false,
            sumfile_uppercase: true,
            sumfile_unix_endings: true,
            sumfile_double_space: false,
            sumfile_forward_slashes: true,
            sumfile_dot_hash_compatible: true,
            sumfile_banner: true,
            sumfile_banner_date: false,
            algorithms: Vec::new(),
        }
    }
}

impl Settings {
    /// Registry value name for a given field, for `RegGetValueW`/`RegSetKeyValueW`.
    ///
    /// Returns `None` for [`Settings::algorithms`], which has one value per
    /// entry named after the algorithm itself.
    pub fn value_name(field: &str) -> Option<&'static str> {
        Some(match field {
            "display_uppercase" => "DisplayUppercase",
            "display_monospace" => "DisplayMonospace",
            "look_for_sumfiles" => "LookForSumfiles",
            "sumfile_uppercase" => "SumfileUppercase",
            "sumfile_unix_endings" => "SumfileLF",
            "sumfile_double_space" => "SumfileDoubleSpace",
            "sumfile_forward_slashes" => "SumfileForwardSlash",
            "sumfile_dot_hash_compatible" => "SumfileDotHashCompat",
            "sumfile_banner" => "SumfileBanner",
            "sumfile_banner_date" => "SumfileBannerDate",
            _ => return None,
        })
    }
}
