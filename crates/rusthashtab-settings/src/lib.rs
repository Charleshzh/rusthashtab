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
//! `"LookForSumfiles"`). Each of the five row classes has two colours -- a text
//! and a background `COLORREF` -- plus one "paint this half" flag per colour, so
//! turning a half off keeps the value the user picked instead of destroying it.
//! The colour layout carries a version marker ([`COLOURS_VERSION`]) so a key
//! written before the flags existed can be reset once, deliberately.
//!
//! # Why not a config file
//!
//! The upstream implementation used the registry and users' existing settings
//! live there. Matching that layout means a migration is a no-op, and it keeps
//! the DLL from needing any writable file path at runtime.
//!
//! # Reading is total
//!
//! [`Settings::load_with`] never fails. A missing key, a value of the wrong type, a
//! truncated value, a registry that cannot be opened -- every one of them yields
//! the default for that field and nothing else. This runs while the shell is
//! building a property sheet, and the user's view of their files must not depend
//! on whether a registry read succeeded.
//!
//! # Writing reports failures
//!
//! [`Settings::save`] is the opposite of a read: it returns an error naming the
//! value and the Win32 code, because a user who changes an option and is told
//! nothing must not be left believing it stuck. Reading stays total because no
//! answer the user could give would make a failed read more useful than the
//! default.

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

/// Version of the colour layout in the registry.
///
/// Version 1 stored only ten colour values. Version 2 adds a separate enable flag
/// per half and changes the defaults from text-only colours to the reference
/// white-on-fill scheme. A key without this marker predates the flags, so its
/// colour values are ignored once and replaced with the new defaults; otherwise
/// an old dark-green text value would be paired with a new green fill.
pub const COLOURS_VERSION: u32 = 2;

/// The sentinel a colour uses to mean "whatever the system uses".
///
/// A `COLORREF` has only 24 meaningful bits; the reserved high byte is free, so a
/// value no real colour uses is a better sentinel than a separate Boolean per
/// field.
pub const SYSTEM_COLOUR: u32 = u32::MAX;

/// Foreground and background for one row class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowColour {
    /// Text colour, `0x00BBGGRR`. Ignored when [`RowColour::text_enabled`] is
    /// false; kept so toggling the checkbox off and on does not lose the colour.
    pub text: u32,
    /// Background colour, `0x00BBGGRR`. Ignored when
    /// [`RowColour::background_enabled`] is false.
    pub background: u32,
    /// Whether the foreground colour is painted.
    pub text_enabled: bool,
    /// Whether the background colour is painted.
    pub background_enabled: bool,
}

impl RowColour {
    /// Neither half painted; both colours keep the system sentinel.
    pub const fn system() -> Self {
        Self {
            text: SYSTEM_COLOUR,
            background: SYSTEM_COLOUR,
            text_enabled: false,
            background_enabled: false,
        }
    }

    /// Whether a foreground colour is enabled for this class.
    pub const fn has_text(&self) -> bool {
        self.text_enabled
    }

    /// Whether a background colour is enabled for this class.
    pub const fn has_background(&self) -> bool {
        self.background_enabled
    }
}

/// The five row classes the page can colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ColourClass {
    /// A digest matched under a secure algorithm.
    Matched,
    /// A digest matched under a weak algorithm.
    Weak,
    /// Expected digests existed and none matched.
    Mismatched,
    /// The file could not be read.
    Error,
    /// No expectation was compared.
    Neutral,
}

/// Which half of a [`RowColour`] is being named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColourPart {
    /// Foreground.
    Text,
    /// Background.
    Background,
}

/// Every configurable row colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowColours {
    /// Secure match.
    pub matched: RowColour,
    /// Weak match.
    pub weak: RowColour,
    /// Mismatch.
    pub mismatched: RowColour,
    /// Unreadable file.
    pub error: RowColour,
    /// Not checked.
    pub neutral: RowColour,
}

impl Default for RowColours {
    /// The colour scheme the page has always shown in this project's reference
    /// implementation: white text on a coloured Hash/Digest cell for a match,
    /// weak match and mismatch; red text with no fill for a read error; and no
    /// colour at all for an unchecked row.
    ///
    /// Only the Digest cell is painted. The Algorithm, Match and File cells stay
    /// on the sheet's normal background, which is what makes a row scannable
    /// instead of a solid block of colour.
    fn default() -> Self {
        Self {
            matched: RowColour {
                // White on RGB(45,170,23).
                text: 0x00FF_FFFF,
                background: 0x0017_AA2D,
                text_enabled: true,
                background_enabled: true,
            },
            weak: RowColour {
                // White on RGB(170,82,23).
                text: 0x00FF_FFFF,
                background: 0x0017_52AA,
                text_enabled: true,
                background_enabled: true,
            },
            mismatched: RowColour {
                // White on RGB(230,55,23).
                text: 0x00FF_FFFF,
                background: 0x0017_37E6,
                text_enabled: true,
                background_enabled: true,
            },
            error: RowColour {
                // Red text, no fill.
                text: 0x0017_37FF,
                background: SYSTEM_COLOUR,
                text_enabled: true,
                background_enabled: false,
            },
            neutral: RowColour::system(),
        }
    }
}

/// The registry value name for one colour half.
pub fn colour_value_name(class: ColourClass, part: ColourPart) -> &'static str {
    match (class, part) {
        (ColourClass::Matched, ColourPart::Text) => "ColourMatchedText",
        (ColourClass::Matched, ColourPart::Background) => "ColourMatchedBackground",
        (ColourClass::Weak, ColourPart::Text) => "ColourWeakText",
        (ColourClass::Weak, ColourPart::Background) => "ColourWeakBackground",
        (ColourClass::Mismatched, ColourPart::Text) => "ColourMismatchText",
        (ColourClass::Mismatched, ColourPart::Background) => "ColourMismatchBackground",
        (ColourClass::Error, ColourPart::Text) => "ColourErrorText",
        (ColourClass::Error, ColourPart::Background) => "ColourErrorBackground",
        (ColourClass::Neutral, ColourPart::Text) => "ColourNeutralText",
        (ColourClass::Neutral, ColourPart::Background) => "ColourNeutralBackground",
    }
}

/// The registry value name for one colour half's enable flag.
///
/// Kept separate from the colour value so turning a half off does not destroy the
/// colour the user picked: re-enabling restores it.
pub fn colour_enabled_value_name(class: ColourClass, part: ColourPart) -> &'static str {
    match (class, part) {
        (ColourClass::Matched, ColourPart::Text) => "ColourMatchedTextEnabled",
        (ColourClass::Matched, ColourPart::Background) => "ColourMatchedBackgroundEnabled",
        (ColourClass::Weak, ColourPart::Text) => "ColourWeakTextEnabled",
        (ColourClass::Weak, ColourPart::Background) => "ColourWeakBackgroundEnabled",
        (ColourClass::Mismatched, ColourPart::Text) => "ColourMismatchTextEnabled",
        (ColourClass::Mismatched, ColourPart::Background) => "ColourMismatchBackgroundEnabled",
        (ColourClass::Error, ColourPart::Text) => "ColourErrorTextEnabled",
        (ColourClass::Error, ColourPart::Background) => "ColourErrorBackgroundEnabled",
        (ColourClass::Neutral, ColourPart::Text) => "ColourNeutralTextEnabled",
        (ColourClass::Neutral, ColourPart::Background) => "ColourNeutralBackgroundEnabled",
    }
}

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
    /// Also hash the checksum file itself when one is read as a manifest.
    ///
    /// A checksum file is normally only a list of files to hash; its own digest
    /// is rarely interesting and would add a row the user did not ask for. When
    /// this is on, the manifest is hashed like any other selected file, which is
    /// what someone auditing the checksum file's own contents wants.
    pub hash_sumfile_too: bool,
    /// Restrict a manifest run to the algorithm its file extension names.
    ///
    /// A `.sha256` file is written by a SHA-256 exporter, so hashing the files it
    /// lists with every enabled algorithm wastes work and can present a match
    /// against an algorithm the file never recorded. With this on, a recognised
    /// extension narrows the run to that one algorithm; an unrecognised
    /// extension leaves the enabled set alone. The narrowing is for this run
    /// only -- it does not change the saved algorithm selection.
    pub sumfile_algorithm_only: bool,
    /// Require a pasted whole line's file name to resolve by full path.
    pub verify_strict: bool,
    /// Rewrite the paste box to canonical hex after a successful check.
    pub verify_auto_format: bool,
    /// Allow the clipboard to be used as the verification source.
    ///
    /// Off by default: reading the clipboard behind the user's back would turn
    /// whatever they last copied into an expected digest, and a "mismatch"
    /// against unrelated text is worse than not checking. When on, the page may
    /// take the expected digest from the clipboard without the user pasting it
    /// into the verify box.
    pub verify_from_clipboard: bool,
    /// Colours for the five result classes.
    pub colours: RowColours,
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
            hash_sumfile_too: false,
            sumfile_algorithm_only: true,
            verify_strict: false,
            verify_auto_format: false,
            verify_from_clipboard: false,
            colours: RowColours::default(),
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

/// Why [`Settings::save`] could not write the settings block.
///
/// Saving is the one operation in this crate that can fail visibly: a settings
/// dialog that silently loses a change is worse than one that says it could not
/// keep it.
#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveError {
    /// Registry value name that could not be written.
    ///
    /// Empty when the settings key itself could not be created, since in that
    /// case no particular value was reached.
    pub value: String,
    /// Win32 error code returned by the failing registry call.
    pub code: u32,
}

#[cfg(windows)]
impl core::fmt::Display for SaveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.value.is_empty() {
            write!(
                f,
                "could not create the settings registry key (Win32 error {})",
                self.code
            )
        } else {
            write!(
                f,
                "could not write the `{}` setting (Win32 error {})",
                self.value, self.code
            )
        }
    }
}

#[cfg(windows)]
impl core::error::Error for SaveError {}

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
            "hash_sumfile_too" => "HashSumfileToo",
            "sumfile_algorithm_only" => "SumfileAlgorithmOnly",
            "verify_strict" => "VerifyStrict",
            "verify_auto_format" => "VerifyAutoFormat",
            "verify_from_clipboard" => "VerifyFromClipboard",
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

    /// Read every setting from the registry, with one algorithm flag per name in
    /// `algorithm_names`.
    ///
    /// [`Settings::algorithms`] comes back with exactly one entry per name, in
    /// the same order, so the caller can index it with algorithm-table
    /// positions. A name with no stored value keeps its default: membership in
    /// [`DEFAULT_ALGORITHMS`], not `false`. That is the whole point of doing the
    /// fallback by name rather than by position -- an algorithm table that
    /// reorders or inserts entries must not silently switch an algorithm on or
    /// off for an existing install.
    ///
    /// Never fails: see the module documentation.
    #[must_use]
    pub fn load_with(self, algorithm_names: &[&str]) -> Self {
        #[cfg(windows)]
        {
            registry::load(self, algorithm_names)
        }
        #[cfg(not(windows))]
        {
            let _ = algorithm_names;
            self
        }
    }

    /// Write every setting to the registry.
    ///
    /// Creates the key when it does not exist. Every non-algorithm option is
    /// written first as a `DWORD`, then one `DWORD` per entry in
    /// `algorithm_names`, holding whether that position is enabled according to
    /// [`Settings::is_enabled`]. `is_enabled` is what the write goes through so
    /// that a settings object which was never loaded still persists the default
    /// set rather than an empty one.
    ///
    /// # Errors
    ///
    /// Returns [`SaveError`], naming the value that could not be written (empty
    /// when the key itself could not be created) and the Win32 error code.
    #[cfg(windows)]
    pub fn save(&self, algorithm_names: &[&str]) -> Result<(), SaveError> {
        registry::save(self, algorithm_names)
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

    use super::{DEFAULT_ALGORITHMS, SaveError, Settings};
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_DWORD, REG_OPTION_NON_VOLATILE,
        RRF_RT_REG_DWORD, RegCloseKey, RegCreateKeyExW, RegGetValueW, RegSetValueExW,
    };
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
    ///
    /// `algorithm_names` is repeated from the caller rather than being a
    /// constant because the algorithm table lives in `rusthashtab-hash`, which
    /// this crate deliberately does not depend on.
    pub(super) fn load(mut settings: Settings, algorithm_names: &[&str]) -> Settings {
        let key = settings.key.clone();

        settings.display_uppercase =
            read_bool(&key, "DisplayUppercase", settings.display_uppercase);
        settings.display_monospace =
            read_bool(&key, "DisplayMonospace", settings.display_monospace);
        settings.look_for_sumfiles = read_bool(&key, "LookForSumfiles", settings.look_for_sumfiles);
        settings.hash_sumfile_too = read_bool(&key, "HashSumfileToo", settings.hash_sumfile_too);
        settings.sumfile_algorithm_only = read_bool(
            &key,
            "SumfileAlgorithmOnly",
            settings.sumfile_algorithm_only,
        );
        settings.verify_strict = read_bool(&key, "VerifyStrict", settings.verify_strict);
        settings.verify_auto_format =
            read_bool(&key, "VerifyAutoFormat", settings.verify_auto_format);
        settings.verify_from_clipboard =
            read_bool(&key, "VerifyFromClipboard", settings.verify_from_clipboard);

        let defaults = settings.colours;
        let read_colour = |class, fallback: super::RowColour| super::RowColour {
            text: read_dword(
                &key,
                super::colour_value_name(class, super::ColourPart::Text),
            )
            .unwrap_or(fallback.text),
            background: read_dword(
                &key,
                super::colour_value_name(class, super::ColourPart::Background),
            )
            .unwrap_or(fallback.background),
            text_enabled: read_bool(
                &key,
                super::colour_enabled_value_name(class, super::ColourPart::Text),
                fallback.text_enabled,
            ),
            background_enabled: read_bool(
                &key,
                super::colour_enabled_value_name(class, super::ColourPart::Background),
                fallback.background_enabled,
            ),
        };
        // A key written before the enable flags existed has colour values but no
        // version marker. Pairing an old dark-green text with the new green fill
        // would be unreadable, so that one upgrade resets to the new defaults.
        if read_dword(&key, "ColoursVersion").unwrap_or(0) >= super::COLOURS_VERSION {
            settings.colours = super::RowColours {
                matched: read_colour(super::ColourClass::Matched, defaults.matched),
                weak: read_colour(super::ColourClass::Weak, defaults.weak),
                mismatched: read_colour(super::ColourClass::Mismatched, defaults.mismatched),
                error: read_colour(super::ColourClass::Error, defaults.error),
                neutral: read_colour(super::ColourClass::Neutral, defaults.neutral),
            };
        }
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
        // list can only be built by asking for each name in turn. The fallback
        // is "is this one of the defaults", looked up *by name*: matching by
        // position would flip a user's setting the day the table is reordered.
        settings.algorithms = algorithm_names
            .iter()
            .map(|name| read_bool(&key, name, DEFAULT_ALGORITHMS.contains(name)))
            .collect();

        settings
    }

    /// Write one `DWORD`, naming the value in the error if the write fails.
    fn write_dword(key: HKEY, name: &str, value: u32) -> Result<(), SaveError> {
        let name_wide = wide(name);
        let bytes = value.to_ne_bytes();

        // SAFETY: `key` was opened by the caller and is still open; `name_wide`
        // is NUL-terminated and outlives the call, and `bytes` is a live array
        // exactly four bytes long, so the API cannot read past it.
        let status = unsafe {
            RegSetValueExW(
                key,
                PCWSTR(name_wide.as_ptr()),
                None,
                REG_DWORD,
                Some(&bytes),
            )
        };

        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(SaveError {
                value: name.to_string(),
                code: status.0,
            })
        }
    }

    /// A bool as the `DWORD` the settings model stores it as.
    fn write_bool(key: HKEY, name: &str, enabled: bool) -> Result<(), SaveError> {
        write_dword(key, name, u32::from(enabled))
    }

    /// Write every setting, one value at a time, so the first failure can be
    /// attributed to the value that caused it.
    fn write_all(
        key: HKEY,
        settings: &Settings,
        algorithm_names: &[&str],
    ) -> Result<(), SaveError> {
        write_bool(key, "DisplayUppercase", settings.display_uppercase)?;
        write_bool(key, "DisplayMonospace", settings.display_monospace)?;
        write_bool(key, "LookForSumfiles", settings.look_for_sumfiles)?;
        write_bool(key, "HashSumfileToo", settings.hash_sumfile_too)?;
        write_bool(key, "SumfileAlgorithmOnly", settings.sumfile_algorithm_only)?;
        write_bool(key, "VerifyStrict", settings.verify_strict)?;
        write_bool(key, "VerifyAutoFormat", settings.verify_auto_format)?;
        write_bool(key, "VerifyFromClipboard", settings.verify_from_clipboard)?;
        write_dword(key, "ColoursVersion", super::COLOURS_VERSION)?;
        for (class, colour) in [
            (super::ColourClass::Matched, settings.colours.matched),
            (super::ColourClass::Weak, settings.colours.weak),
            (super::ColourClass::Mismatched, settings.colours.mismatched),
            (super::ColourClass::Error, settings.colours.error),
            (super::ColourClass::Neutral, settings.colours.neutral),
        ] {
            write_dword(
                key,
                super::colour_value_name(class, super::ColourPart::Text),
                colour.text,
            )?;
            write_dword(
                key,
                super::colour_value_name(class, super::ColourPart::Background),
                colour.background,
            )?;
            write_bool(
                key,
                super::colour_enabled_value_name(class, super::ColourPart::Text),
                colour.text_enabled,
            )?;
            write_bool(
                key,
                super::colour_enabled_value_name(class, super::ColourPart::Background),
                colour.background_enabled,
            )?;
        }
        write_bool(key, "SumfileUppercase", settings.sumfile_uppercase)?;
        write_bool(key, "SumfileLF", settings.sumfile_unix_endings)?;
        write_bool(key, "SumfileDoubleSpace", settings.sumfile_double_space)?;
        write_bool(key, "SumfileForwardSlash", settings.sumfile_forward_slashes)?;
        write_bool(
            key,
            "SumfileDotHashCompat",
            settings.sumfile_dot_hash_compatible,
        )?;
        write_bool(key, "SumfileBanner", settings.sumfile_banner)?;
        write_bool(key, "SumfileBannerDate", settings.sumfile_banner_date)?;

        // Going through `is_enabled` (rather than indexing the vector directly)
        // means a settings object that was never loaded persists the default set
        // instead of an empty one, which is what a fresh install must do.
        for (index, name) in algorithm_names.iter().enumerate() {
            write_bool(key, name, settings.is_enabled(index, algorithm_names))?;
        }

        Ok(())
    }

    /// Create the key if needed, write every value, and close the key on every
    /// path -- including the failing ones, so a failed save does not leak a
    /// handle into the property-sheet thread.
    pub(super) fn save(settings: &Settings, algorithm_names: &[&str]) -> Result<(), SaveError> {
        let key_wide = wide(&settings.key);
        let mut key = HKEY::default();

        // SAFETY: `key_wide` is NUL-terminated and outlives the call; `key` is a
        // live local written by the API only on success. `None` is allowed for
        // the class and the disposition, neither of which is used here.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(key_wide.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                None,
                &mut key,
                None,
            )
        };

        if status != ERROR_SUCCESS {
            return Err(SaveError {
                value: String::new(),
                code: status.0,
            });
        }

        let result = write_all(key, settings, algorithm_names);

        // SAFETY: `key` was opened by `RegCreateKeyExW` above and is closed
        // exactly once here; the handle is never used after this call.
        unsafe {
            let _ = RegCloseKey(key);
        }

        result
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

    #[cfg(windows)]
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    #[cfg(windows)]
    use windows::Win32::System::Registry::HKEY_CURRENT_USER;
    #[cfg(windows)]
    use windows::core::PCWSTR;

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

    /// The colour and enabled-flag registry names are all distinct, so one
    /// class's colour cannot overwrite another class's flag.
    #[test]
    fn every_colour_half_has_distinct_value_and_enabled_names() {
        use super::{ColourClass, ColourPart, colour_enabled_value_name, colour_value_name};
        let classes = [
            ColourClass::Matched,
            ColourClass::Weak,
            ColourClass::Mismatched,
            ColourClass::Error,
            ColourClass::Neutral,
        ];
        let parts = [ColourPart::Text, ColourPart::Background];
        let mut names = std::collections::HashSet::new();
        for class in classes {
            for part in parts {
                assert!(
                    names.insert(colour_value_name(class, part)),
                    "duplicate colour name for {class:?}/{part:?}"
                );
                assert!(
                    names.insert(colour_enabled_value_name(class, part)),
                    "duplicate enabled name for {class:?}/{part:?}"
                );
            }
        }
    }

    /// Every field has a value name, and every name is distinct. A duplicate
    /// would make two settings share storage.
    #[test]
    fn every_non_algorithm_field_has_a_distinct_value_name() {
        let fields = [
            "display_uppercase",
            "display_monospace",
            "look_for_sumfiles",
            "hash_sumfile_too",
            "sumfile_algorithm_only",
            "verify_strict",
            "verify_auto_format",
            "verify_from_clipboard",
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
        assert_eq!(
            Settings::value_name("hash_sumfile_too"),
            Some("HashSumfileToo")
        );
        assert_eq!(
            Settings::value_name("sumfile_algorithm_only"),
            Some("SumfileAlgorithmOnly")
        );
        assert_eq!(
            Settings::value_name("verify_from_clipboard"),
            Some("VerifyFromClipboard")
        );
    }

    /// The defaults for the workflow options are part of the documented
    /// behaviour, not an implementation detail: `SumfileAlgorithmOnly` defaults
    /// *on* while the other two default off, and a test that only checked "some
    /// value exists" would not notice the pair being swapped.
    #[test]
    fn the_workflow_options_default_to_the_documented_values() {
        let settings = Settings::default();
        assert!(
            !settings.hash_sumfile_too,
            "a manifest run must not hash the manifest itself unless asked"
        );
        assert!(
            settings.sumfile_algorithm_only,
            "a recognised sumfile extension must narrow the run to its algorithm"
        );
        assert!(
            !settings.verify_from_clipboard,
            "the clipboard is not a verification source unless the user opts in"
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
    /// spells the default set out explicitly -- one entry per name, with the four
    /// documented defaults on and everything else off -- rather than the empty
    /// "never chosen" vector. Both are read the same way by
    /// [`Settings::is_enabled`]; the difference is deliberate: the loader records
    /// what it actually found, and the "never chosen" state only exists for a
    /// settings object that was never loaded.
    #[cfg(windows)]
    #[test]
    fn a_missing_key_yields_the_defaults() {
        let names = ["CRC32", "MD5", "SHA-1", "SHA-256", "SHA-512", "BLAKE3"];
        let scratch = scratch_key("missing-key");
        let loaded = Settings::default().with_key(scratch).load_with(&names);

        let expected = Settings {
            algorithms: vec![false, true, true, true, true, false],
            key: loaded.key.clone(),
            ..Settings::default()
        };
        assert_eq!(loaded, expected);

        // And the enabled set is the default one either way.
        assert_eq!(
            loaded.enabled_indices(&names),
            Settings::default().enabled_indices(&names)
        );
    }

    /// The default set is matched by *name*. With the four defaults scattered
    /// through the table rather than leading it, the flags must still land on
    /// MD5/SHA-1/SHA-256/SHA-512 and nowhere else -- reading flags positionally
    /// would switch CRC32 on and SHA-512 off on an install that never chose.
    #[cfg(windows)]
    #[test]
    fn the_default_set_is_matched_by_name_not_position() {
        let names = ["CRC32", "BLAKE3-512", "MD5", "SHA-1", "SHA-256", "SHA-512"];
        let loaded = Settings::default()
            .with_key(scratch_key("defaults-by-name"))
            .load_with(&names);

        assert_eq!(
            loaded.algorithms,
            vec![false, false, true, true, true, true]
        );
        assert_eq!(loaded.enabled_indices(&names), vec![2, 3, 4, 5]);
    }

    /// 31 distinct names, shaped like an algorithm table. The real names live in
    /// `rusthashtab-hash` and this crate deliberately does not depend on it:
    /// settings storage only cares that names are unique and stable.
    #[cfg(windows)]
    fn algorithm_names(count: usize) -> Vec<String> {
        (0..count).map(|index| format!("Algo{index}")).collect()
    }

    /// Borrow a name table as the `&[&str]` the public API takes.
    #[cfg(windows)]
    fn name_refs(names: &[String]) -> Vec<&str> {
        names.iter().map(String::as_str).collect()
    }

    /// A scratch key unique to this process *and* test, so the registry tests
    /// can run in parallel without ever seeing each other's values.
    #[cfg(windows)]
    fn scratch_key(test: &str) -> String {
        format!(r"Software\rustHashTab-test-{}-{test}", std::process::id())
    }

    /// NUL-terminate a Rust string for a `PCWSTR` parameter.
    #[cfg(windows)]
    fn wide_nul(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(core::iter::once(0)).collect()
    }

    /// A scratch key that deletes itself when the test ends, including when it
    /// ends in a panic.
    #[cfg(windows)]
    struct ScratchKey {
        path: String,
    }

    #[cfg(windows)]
    impl ScratchKey {
        fn new(test: &str) -> Self {
            Self {
                path: scratch_key(test),
            }
        }
    }

    #[cfg(windows)]
    impl Drop for ScratchKey {
        fn drop(&mut self) {
            let wide = wide_nul(&self.path);
            // SAFETY: the key name is NUL-terminated and outlives the call.
            // Deleting a key that was never created reports
            // `ERROR_FILE_NOT_FOUND`, which is not a leak.
            let status = unsafe {
                windows::Win32::System::Registry::RegDeleteTreeW(
                    HKEY_CURRENT_USER,
                    PCWSTR(wide.as_ptr()),
                )
            };

            // Do not panic while already unwinding: that would abort the whole
            // test process instead of preserving the original failure.
            if !std::thread::panicking() {
                assert!(
                    status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND,
                    "left scratch key `{}` behind (Win32 error {})",
                    self.path,
                    status.0
                );
            }
        }
    }

    /// Read one `DWORD` straight out of a scratch key, so a test can check what
    /// `save` wrote rather than only what `load` can recover.
    #[cfg(windows)]
    fn scratch_dword(key: &str, name: &str) -> Option<u32> {
        use windows::Win32::System::Registry::{RRF_RT_REG_DWORD, RegGetValueW};

        let key_wide = wide_nul(key);
        let name_wide = wide_nul(name);
        let mut value: u32 = 0;
        let mut size = core::mem::size_of::<u32>() as u32;

        // SAFETY: both wide strings are NUL-terminated and outlive the call;
        // `value` and `size` are live locals and `size` describes the buffer
        // `value` provides.
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

        (status == ERROR_SUCCESS && size == core::mem::size_of::<u32>() as u32).then_some(value)
    }

    /// A full save/load round trip over every field, with 31 algorithms all
    /// switched off. That combination is the one a positional reader or an
    /// "empty means default" writer gets wrong, so it is the one pinned here.
    #[cfg(windows)]
    #[test]
    fn save_then_load_round_trips_every_field() {
        let names = algorithm_names(31);
        let name_refs = name_refs(&names);
        let scratch = ScratchKey::new("round-trip");

        // Every non-algorithm field is moved away from its default, so a writer
        // that skipped one cannot be hidden by the read fallback.
        let saved = Settings {
            display_uppercase: false,
            display_monospace: false,
            look_for_sumfiles: true,
            hash_sumfile_too: true,
            sumfile_algorithm_only: false,
            verify_strict: true,
            verify_auto_format: true,
            verify_from_clipboard: true,
            colours: RowColours {
                matched: RowColour {
                    text: 0x0012_3456,
                    background: 0x0065_4321,
                    text_enabled: false,
                    background_enabled: true,
                },
                ..RowColours::default()
            },
            sumfile_uppercase: false,
            sumfile_unix_endings: false,
            sumfile_double_space: true,
            sumfile_forward_slashes: false,
            sumfile_dot_hash_compatible: false,
            sumfile_banner: false,
            sumfile_banner_date: true,
            algorithms: vec![false; name_refs.len()],
            key: scratch.path.clone(),
        };

        saved.save(&name_refs).expect("save must succeed");

        let loaded = Settings::default()
            .with_key(scratch.path.clone())
            .load_with(&name_refs);

        assert_eq!(
            loaded.algorithms.len(),
            name_refs.len(),
            "one flag per name, in name-table order"
        );
        assert_eq!(
            loaded.algorithms,
            vec![false; name_refs.len()],
            "all 31 flags must stay off"
        );
        for index in 0..name_refs.len() {
            assert!(
                !loaded.is_enabled(index, &name_refs),
                "algorithm {index} came back enabled"
            );
        }

        assert_eq!(loaded, saved);
    }

    /// `save` must write a value for *every* name, including the ones that end
    /// up false: a missing value would silently re-enable a default algorithm on
    /// the next load, which is exactly what a read fallback hides.
    #[cfg(windows)]
    #[test]
    fn save_writes_one_dword_per_algorithm_name() {
        let names = algorithm_names(31);
        let name_refs = name_refs(&names);
        let scratch = ScratchKey::new("algorithm-values");

        let enabled: Vec<bool> = (0..names.len()).map(|index| index % 3 == 0).collect();
        let saved = Settings {
            algorithms: enabled,
            key: scratch.path.clone(),
            ..Settings::default()
        };

        saved.save(&name_refs).expect("save must succeed");

        for (index, name) in name_refs.iter().enumerate() {
            let expected = u32::from(saved.is_enabled(index, &name_refs));
            assert_eq!(
                scratch_dword(&scratch.path, name),
                Some(expected),
                "`{name}` was not written with the expected value"
            );
        }
    }

    /// The message has to name the setting: the settings dialog has nowhere
    /// else to learn which write failed.
    #[cfg(windows)]
    #[test]
    fn the_save_error_names_the_failing_setting() {
        let error = SaveError {
            value: "DisplayUppercase".to_string(),
            code: 5,
        };
        let message = error.to_string();
        assert!(message.contains("DisplayUppercase"), "{message}");
        assert!(message.contains('5'), "{message}");

        // A key-creation failure has no value name, so the message must not
        // look like a write of a value called "" failed.
        let key_error = SaveError {
            value: String::new(),
            code: 5,
        };
        assert!(key_error.to_string().contains("key"), "{key_error}");
    }

    /// The real round trip: write values, read them back, and remove the scratch
    /// key afterwards. The scratch key keeps this off the user's settings.
    #[cfg(windows)]
    #[test]
    fn written_values_are_read_back_and_a_wrong_type_falls_back() {
        use windows::Win32::System::Registry::{
            HKEY, KEY_ALL_ACCESS, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
            RegCreateKeyExW, RegSetValueExW,
        };
        use windows::core::w;

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

        let scratch = ScratchKey::new("wrong-type");
        let scratch_wide = wide_nul(&scratch.path);

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
        let wrong_type: Vec<u8> = wide_nul("not a number")
            .iter()
            .flat_map(|unit| unit.to_ne_bytes())
            .collect();
        write(key, w!("DisplayMonospace"), REG_SZ, &wrong_type);

        let names = ["CRC32", "MD5", "SHA-1", "SHA-256", "SHA-512", "BLAKE3"];
        let loaded = Settings::default()
            .with_key(&scratch.path)
            .load_with(&names);

        // SAFETY: `key` was opened above and is closed exactly once.
        unsafe {
            let _ = RegCloseKey(key);
        }

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
        // no algorithm values at all leaves every one of them at its fallback:
        // the four documented defaults on, and the rest off.
        assert_eq!(
            loaded.algorithms,
            vec![false, true, true, true, true, false]
        );
    }
}
