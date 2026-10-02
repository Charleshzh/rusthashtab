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
//!
//! # Reading is total
//!
//! [`Settings::load`] never fails. A missing key, a value of the wrong type, a
//! truncated value, a registry that cannot be opened -- every one of them yields
//! the default for that field and nothing else. This runs while the shell is
//! building a property sheet, and the user's view of their files must not depend
//! on whether a registry read succeeded.

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
    ///
    /// Empty means "the user has never chosen", which [`Settings::is_enabled`]
    /// resolves to the default set rather than to "nothing enabled" — an empty
    /// list would silently hash nothing on a fresh install.
    pub algorithms: Vec<bool>,
    /// Registry key the values are read from, relative to `HKCU`.
    ///
    /// A field rather than a constant so tests can point at a scratch key
    /// instead of the user's real settings. It is not persisted.
    pub key: String,
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
            key: REG_KEY.to_string(),
        }
    }
}

/// The registry values of the four algorithms enabled by default.
///
/// Kept here rather than in the scan crate because it is a *setting*, and because
/// the two places that need it — a fresh scan and a page whose settings list is
/// empty — must agree.
pub const DEFAULT_ALGORITHMS: [&str; 4] = ["MD5", "SHA-1", "SHA-256", "SHA-512"];

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

    /// Read from a different registry key, for tests and for a future
    /// machine-wide override.
    #[must_use]
    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.key = key.into();
        self
    }

    /// Read every setting from the registry, falling back per field.
    ///
    /// Never fails: see the module documentation.
    #[must_use]
    pub fn load(self) -> Self {
        #[cfg(windows)]
        {
            registry::load(self)
        }
        #[cfg(not(windows))]
        {
            self
        }
    }

    /// Whether the algorithm at `index` is enabled.
    ///
    /// `names` is the algorithm table's names, in table order, so this crate does
    /// not have to depend on the hash crate to answer the question.
    ///
    /// An empty [`Settings::algorithms`] means "not chosen yet" and resolves to
    /// [`DEFAULT_ALGORITHMS`]. A position past the end of a non-empty list is
    /// disabled: a stored list shorter than the algorithm table is a settings
    /// file from an older build, and hashing a newly added algorithm without the
    /// user asking for it would be a surprise.
    #[must_use]
    pub fn is_enabled(&self, index: usize, names: &[&str]) -> bool {
        if self.algorithms.is_empty() {
            let Some(name) = names.get(index) else {
                return false;
            };
            return DEFAULT_ALGORITHMS.contains(name);
        }
        self.algorithms.get(index).copied().unwrap_or(false)
    }

    /// The enabled algorithms, as a list of table positions.
    #[must_use]
    pub fn enabled_indices(&self, names: &[&str]) -> Vec<usize> {
        (0..names.len())
            .filter(|index| self.is_enabled(*index, names))
            .collect()
    }
}

#[cfg(windows)]
mod registry {
    //! The Win32 half, kept in one module so the data model above stays testable
    //! and dependency-free.

    use super::{DEFAULT_ALGORITHMS, Settings};
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
    use windows::core::PCWSTR;

    /// Read one `DWORD`, or `None` when it is absent, of the wrong type, or the
    /// wrong size.
    ///
    /// `RRF_RT_REG_DWORD` makes the type check the API's job: a value stored as a
    /// string is refused rather than reinterpreted as a number.
    fn read_dword(key: &str, name: &str) -> Option<u32> {
        let key_wide = wide(key);
        let name_wide = wide(name);
        let mut value: u32 = 0;
        let mut size = core::mem::size_of::<u32>() as u32;

        // SAFETY: both wide strings are NUL-terminated and outlive the call;
        // `value` and `size` are live locals, and `size` declares exactly the
        // buffer `value` provides.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                PCWSTR(key_wide.as_ptr()),
                PCWSTR(name_wide.as_ptr()),
                RRF_RT_REG_DWORD,
                None,
                Some((&mut value as *mut u32).cast()),
                Some(&mut size),
            )
        };

        // A size other than four can only happen if the API disagreed with
        // `RRF_RT_REG_DWORD`, which would mean the value is not a `DWORD` after
        // all. Refuse it rather than use a half-written number.
        if status == ERROR_SUCCESS && size == core::mem::size_of::<u32>() as u32 {
            Some(value)
        } else {
            None
        }
    }

    /// A `DWORD` as a bool, the way the settings model stores them.
    ///
    /// `0` is false and anything else is true, which is what a checkbox and the
    /// registry's own conventions both mean.
    fn read_bool(key: &str, name: &str, fallback: bool) -> bool {
        read_dword(key, name).map_or(fallback, |value| value != 0)
    }

    /// Read every field, leaving `settings`' current value in place for any that
    /// could not be read.
    pub(super) fn load(mut settings: Settings) -> Settings {
        let key = settings.key.clone();

        settings.display_uppercase =
            read_bool(&key, "DisplayUppercase", settings.display_uppercase);
        settings.display_monospace =
            read_bool(&key, "DisplayMonospace", settings.display_monospace);
        settings.look_for_sumfiles = read_bool(&key, "LookForSumfiles", settings.look_for_sumfiles);
        settings.sumfile_uppercase =
            read_bool(&key, "SumfileUppercase", settings.sumfile_uppercase);
        settings.sumfile_unix_endings = read_bool(&key, "SumfileLF", settings.sumfile_unix_endings);
        settings.sumfile_double_space =
            read_bool(&key, "SumfileDoubleSpace", settings.sumfile_double_space);
        settings.sumfile_forward_slashes = read_bool(
            &key,
            "SumfileForwardSlash",
            settings.sumfile_forward_slashes,
        );
        settings.sumfile_dot_hash_compatible = read_bool(
            &key,
            "SumfileDotHashCompat",
            settings.sumfile_dot_hash_compatible,
        );
        settings.sumfile_banner = read_bool(&key, "SumfileBanner", settings.sumfile_banner);
        settings.sumfile_banner_date =
            read_bool(&key, "SumfileBannerDate", settings.sumfile_banner_date);

        // The algorithm flags are named after the algorithms themselves, so the
        // list can only be built by asking for each name in turn.
        settings.algorithms = DEFAULT_ALGORITHMS
            .iter()
            .map(|name| read_bool(&key, name, true))
            .collect();

        settings
    }

    /// NUL-terminate a Rust string for a `PCWSTR` parameter.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(core::iter::once(0)).collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A names list shaped like the algorithm table, for the tests that need one
    /// without depending on the hash crate.
    fn names() -> Vec<&'static str> {
        vec!["CRC32", "MD5", "SHA-1", "SHA-256", "SHA-512", "BLAKE3"]
    }

    #[test]
    fn a_fresh_settings_object_uses_the_default_set() {
        let settings = Settings::default();
        let enabled: Vec<&str> = settings
            .enabled_indices(&names())
            .into_iter()
            .map(|index| names()[index])
            .collect();
        assert_eq!(enabled, vec!["MD5", "SHA-1", "SHA-256", "SHA-512"]);
    }

    /// An explicitly empty list of flags means "nothing enabled", which is a
    /// different thing from "never chosen" -- the user may genuinely want to
    /// uncheck everything.
    #[test]
    fn an_explicit_all_false_list_enables_nothing() {
        let settings = Settings {
            algorithms: vec![false; names().len()],
            ..Settings::default()
        };
        assert!(settings.enabled_indices(&names()).is_empty());
    }

    /// A stored list shorter than the algorithm table is settings from an older
    /// build. Positions past its end are off, not on: hashing an algorithm the
    /// user never chose would be a surprise, and a slow one.
    #[test]
    fn positions_past_a_short_list_are_disabled() {
        let settings = Settings {
            algorithms: vec![true, false],
            ..Settings::default()
        };
        assert!(settings.is_enabled(0, &names()));
        assert!(!settings.is_enabled(1, &names()));
        assert!(!settings.is_enabled(2, &names()));
    }

    /// `names` is the authority on how long the table is; asking about a position
    /// beyond it must not panic.
    #[test]
    fn an_index_beyond_the_table_is_disabled() {
        let settings = Settings::default();
        assert!(!settings.is_enabled(99, &names()));
        assert!(!settings.is_enabled(0, &[]));
    }

    /// Every field has a value name, and every name is distinct. A duplicate
    /// would make two settings share storage.
    #[test]
    fn every_non_algorithm_field_has_a_distinct_value_name() {
        let fields = [
            "display_uppercase",
            "display_monospace",
            "look_for_sumfiles",
            "sumfile_uppercase",
            "sumfile_unix_endings",
            "sumfile_double_space",
            "sumfile_forward_slashes",
            "sumfile_dot_hash_compatible",
            "sumfile_banner",
            "sumfile_banner_date",
        ];

        let mut names: Vec<&str> = Vec::new();
        for field in fields {
            let name = Settings::value_name(field)
                .unwrap_or_else(|| panic!("`{field}` has no registry value name"));
            assert!(!names.contains(&name), "`{name}` is used by two fields");
            names.push(name);
        }
        assert_eq!(Settings::value_name("algorithms"), None);
    }

    /// The stored names have to be the ones the settings dialog will write, so
    /// they are pinned here rather than left to drift.
    #[test]
    fn the_value_names_are_the_documented_ones() {
        assert_eq!(
            Settings::value_name("display_uppercase"),
            Some("DisplayUppercase")
        );
        assert_eq!(
            Settings::value_name("sumfile_unix_endings"),
            Some("SumfileLF")
        );
        assert_eq!(
            Settings::value_name("sumfile_forward_slashes"),
            Some("SumfileForwardSlash")
        );
    }

    /// The default key is the documented one, and `with_key` only changes the
    /// key.
    #[test]
    fn the_default_key_is_the_documented_one() {
        assert_eq!(Settings::default().key, REG_KEY);
        let moved = Settings::default().with_key(r"Software\SomethingElse");
        assert_eq!(moved.key, r"Software\SomethingElse");
        assert_eq!(
            moved.display_uppercase,
            Settings::default().display_uppercase
        );
    }

    /// Loading a key that does not exist must return the defaults rather than
    /// zeroes or an error: this runs while the shell builds a property sheet.
    ///
    /// The algorithm vector is compared separately because a successful load
    /// spells the default set out explicitly -- `[true; 4]` rather than the empty
    /// "never chosen" vector -- and both are read the same way by
    /// [`Settings::is_enabled`]. That difference is deliberate: the loader records
    /// what it actually found, and the "never chosen" state only exists for a
    /// settings object that was never loaded.
    #[cfg(windows)]
    #[test]
    fn a_missing_key_yields_the_defaults() {
        let scratch = format!(r"Software\rustHashTab-test-missing-{}", std::process::id());
        let loaded = Settings::default().with_key(scratch).load();

        let expected = Settings {
            algorithms: vec![true; DEFAULT_ALGORITHMS.len()],
            key: loaded.key.clone(),
            ..Settings::default()
        };
        assert_eq!(loaded, expected);

        // And the enabled set is the default one either way.
        let names = ["MD5", "SHA-1", "SHA-256", "SHA-512", "BLAKE3"];
        assert_eq!(
            loaded.enabled_indices(&names),
            Settings::default().enabled_indices(&names)
        );
    }

    /// The real round trip: write values, read them back, and remove the scratch
    /// key afterwards. The scratch key keeps this off the user's settings.
    #[cfg(windows)]
    #[test]
    fn written_values_are_read_back_and_a_wrong_type_falls_back() {
        use windows::Win32::Foundation::ERROR_SUCCESS;
        use windows::Win32::System::Registry::{
            HKEY, HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
            RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW,
        };
        use windows::core::{PCWSTR, w};

        /// NUL-terminate a Rust string for a `PCWSTR` parameter.
        fn wide(text: &str) -> Vec<u16> {
            text.encode_utf16().chain(core::iter::once(0)).collect()
        }

        /// Write one value, panicking on failure: a test that cannot write what
        /// it intends to read is not testing the reader.
        fn write(
            key: HKEY,
            name: PCWSTR,
            kind: windows::Win32::System::Registry::REG_VALUE_TYPE,
            bytes: &[u8],
        ) {
            // SAFETY: `key` is open; `name` is a NUL-terminated wide string and
            // `bytes` is a live slice whose length is taken from it.
            let status = unsafe { RegSetValueExW(key, name, None, kind, Some(bytes)) };
            assert_eq!(status, ERROR_SUCCESS, "could not write a scratch value");
        }

        let scratch = format!(r"Software\rustHashTab-test-{}", std::process::id());
        let scratch_wide = wide(&scratch);

        let mut key = HKEY::default();
        // SAFETY: the key name is NUL-terminated and outlives the call, and both
        // out-parameters are live locals. `None` is allowed for the disposition,
        // which this test does not need.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(scratch_wide.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS,
                None,
                &mut key,
                None,
            )
        };
        assert_eq!(status, ERROR_SUCCESS, "could not create the scratch key");

        write(key, w!("DisplayUppercase"), REG_DWORD, &0u32.to_ne_bytes());
        write(key, w!("SHA-256"), REG_DWORD, &1u32.to_ne_bytes());
        // A string where a `DWORD` belongs: the loader has to refuse it rather
        // than reinterpret its first four bytes as a number.
        let wrong_type: Vec<u8> = wide("not a number")
            .iter()
            .flat_map(|unit| unit.to_ne_bytes())
            .collect();
        write(key, w!("DisplayMonospace"), REG_SZ, &wrong_type);

        let loaded = Settings::default().with_key(&scratch).load();

        // SAFETY: `key` was opened above and is closed exactly once.
        unsafe {
            let _ = RegCloseKey(key);
        }
        // SAFETY: the key name is NUL-terminated and outlives the call.
        let deleted = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(scratch_wide.as_ptr())) };
        assert_eq!(deleted, ERROR_SUCCESS, "left a scratch key behind");

        // The written values came back...
        assert!(
            !loaded.display_uppercase,
            "a written DWORD of 0 must read as false"
        );
        // ...the wrong-typed one fell back to the default, not to zero...
        assert!(
            loaded.display_monospace,
            "a REG_SZ where a DWORD belongs must fall back, not be reinterpreted"
        );
        // ...and so did every value that was never written.
        assert_eq!(
            loaded.sumfile_uppercase,
            Settings::default().sumfile_uppercase
        );

        // The algorithm flags are read from a known list of names, so a key with
        // no algorithm values at all leaves every one of them at its fallback.
        assert_eq!(loaded.algorithms, vec![true, true, true, true]);
    }
}
