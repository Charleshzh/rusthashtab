//! Sumfile parsing.
//!
//! Three regexes drive everything; the first line that matches fixes the style
//! for the rest of the file.

use crate::{FileSum, MAX_DIGEST_LEN};
use std::sync::OnceLock;

/// Which hash encoding a sumfile turned out to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ParseStyle {
    /// Not yet determined.
    #[default]
    Unknown,
    /// `HASH␣␣FILE` / `HASH␣*FILE` with a hex digest.
    Hex,
    /// `FILE␣CRC32` — filename first, hex CRC32 second.
    Sfv,
    /// `HASH␣␣FILE` with a base64 digest.
    Base64,
}

/// Result of parsing one sumfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOutcome {
    /// Successfully parsed entries, in file order.
    pub entries: FileSumList,
    /// The style the parser settled on.
    pub style: ParseStyle,
    /// True when a line could not be interpreted.
    ///
    /// A malformed line is not fatal — the caller decides whether a partial
    /// parse is acceptable.
    pub had_error: bool,
}

/// Ordered list of parsed entries.
pub type FileSumList = Vec<FileSum>;

// The three patterns below are string literals, so a `Regex::new` failure would
// be a programming error caught by the unit tests rather than a runtime
// condition. `expect` is therefore appropriate here; the lint is allowed at this
// narrow scope rather than crate-wide so it still applies elsewhere.
#[allow(clippy::expect_used)]
mod patterns {
    use super::*;

    /// Hex digest followed by a space and ` ` or `*`, then the filename.
    ///
    /// The `{8,512}` bound accepts everything from a 32-bit CRC to a 512-bit
    /// digest, with room for non-standard lengths.
    pub(super) fn hex_re() -> &'static regex::Regex {
        static RE: OnceLock<regex::Regex> = OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r"^([0-9a-fA-F]{8,512}) [ \*](.++)").expect("literal"))
    }

    /// Base64 digest followed by a space and ` ` or `*`, then the filename.
    pub(super) fn b64_re() -> &'static regex::Regex {
        static RE: OnceLock<regex::Regex> = OnceLock::new();
        RE.get_or_init(|| {
            regex::Regex::new(r"^([0-9a-zA-Z=+/, \-_]{6,512}) [ \*](.++)").expect("literal")
        })
    }

    /// SFV: filename, whitespace, 8 hex digits.
    pub(super) fn sfv_re() -> &'static regex::Regex {
        static RE: OnceLock<regex::Regex> = OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r"^([^ ]++)\s++([0-9a-fA-F]{8})").expect("literal"))
    }
}

use patterns::{b64_re, hex_re, sfv_re};

/// Decode a hex string to bytes. Returns `None` on any invalid character.
pub fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

/// Parser state, carried across lines so the first match fixes the style.
#[derive(Debug, Default)]
pub struct SumFileParser {
    comment_hash: bool,
    comment_semicolon: bool,
    style: ParseStyle,
}

impl SumFileParser {
    /// A fresh parser with no style decided yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The style settled on so far.
    pub fn style(&self) -> ParseStyle {
        self.style
    }

    /// Interpret one line.
    ///
    /// Returns `Some(entry)` when the line described a file, `None` when it was
    /// blank, a comment, or unparseable. Use [`ParseOutcome::had_error`] via
    /// [`parse_all`] if you need to distinguish "ignored" from "malformed".
    pub fn process_line(&mut self, line: &str) -> Option<FileSum> {
        let trimmed = line.trim_matches(['\r', '\n', '\t', '\u{b}', '\u{c}', ' ']);
        if trimmed.is_empty() {
            return None;
        }

        // Comment styles are sticky once seen, so a `#` inside a later filename
        // does not get treated as a comment.
        if (self.comment_hash || self.style == ParseStyle::Unknown || !self.comment_semicolon)
            && trimmed.starts_with('#')
        {
            self.comment_hash = true;
            return None;
        }
        if (self.comment_semicolon || self.style == ParseStyle::Unknown || !self.comment_hash)
            && trimmed.starts_with(';')
        {
            self.comment_semicolon = true;
            return None;
        }

        if matches!(self.style, ParseStyle::Unknown | ParseStyle::Sfv)
            && let Some(c) = sfv_re().captures(trimmed)
        {
            let file = c[1].trim_end().to_string();
            if let Some(digest) = hex_to_bytes(&c[2]) {
                self.style = ParseStyle::Sfv;
                return Some(FileSum { path: file, digest });
            }
        }

        if matches!(self.style, ParseStyle::Unknown | ParseStyle::Hex)
            && let Some(c) = hex_re().captures(trimmed)
            && let Some(digest) = hex_to_bytes(&c[1])
        {
            self.style = ParseStyle::Hex;
            return Some(FileSum {
                path: c[2].to_string(),
                digest,
            });
        }

        if matches!(self.style, ParseStyle::Unknown | ParseStyle::Base64)
            && let Some(c) = b64_re().captures(trimmed)
            && let Some(digest) = base64_decode(&c[1])
        {
            self.style = ParseStyle::Base64;
            return Some(FileSum {
                path: c[2].to_string(),
                digest,
            });
        }

        None
    }
}

/// Decode a sumfile's base64 digest, tolerating the URL-safe alphabet and
/// missing padding, both of which appear in real files.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(cleaned.trim_end_matches('='))
        .ok()
        .filter(|v| !v.is_empty())
}

/// Parse a whole sumfile body.
///
/// A file consisting of a single bare digest — no filename — is a legal and
/// common case ("here is the SHA-256 of this file"), so it is recognised before
/// line-by-line parsing.
pub fn parse_all(text: &str) -> ParseOutcome {
    let body = text.strip_prefix('\u{feff}').unwrap_or(text);

    // Single-hash file: at most MAX_DIGEST_LEN*2 hex chars plus whitespace.
    if body.len() <= MAX_DIGEST_LEN * 2 * 2 {
        let trimmed = body.trim();
        if !trimmed.is_empty()
            && let Some(digest) = hex_to_bytes(trimmed)
        {
            return ParseOutcome {
                entries: vec![FileSum {
                    path: String::new(),
                    digest,
                }],
                style: ParseStyle::Hex,
                had_error: false,
            };
        }
    }

    let mut parser = SumFileParser::new();
    let mut entries = FileSumList::new();
    let mut had_error = false;

    for line in body.split(['\n', '\r']) {
        if line.trim().is_empty() {
            continue;
        }
        match parser.process_line(line) {
            Some(e) => entries.push(e),
            None => {
                // Blank/comment lines are fine; anything else is malformed.
                let t = line.trim_start();
                if !t.starts_with('#') && !t.starts_with(';') {
                    had_error = true;
                    break;
                }
            }
        }
    }

    ParseOutcome {
        entries,
        style: parser.style(),
        had_error,
    }
}

/// Parse from any [`std::io::Read`].
pub fn parse_reader<R: std::io::Read>(mut r: R) -> std::io::Result<ParseOutcome> {
    let mut s = String::new();
    r.read_to_string(&mut s)?;
    Ok(parse_all(&s))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_gnu_style_hex() {
        let out = parse_all(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  empty.txt\n",
        );
        assert_eq!(out.style, ParseStyle::Hex);
        assert!(!out.had_error);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].path, "empty.txt");
        assert_eq!(out.entries[0].digest.len(), 32);
    }

    #[test]
    fn parses_binary_marker_and_uppercase() {
        let out = parse_all("D41D8CD98F00B204E9800998ECF8427E *binary.bin\n");
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].path, "binary.bin");
        assert_eq!(out.entries[0].digest.len(), 16);
    }

    #[test]
    fn parses_sfv() {
        let out = parse_all("; SFV comment\nfile.txt 5B721D06\n");
        assert_eq!(out.style, ParseStyle::Sfv);
        assert_eq!(out.entries.len(), 1);
        // Filename comes first in SFV.
        assert_eq!(out.entries[0].path, "file.txt");
        assert_eq!(out.entries[0].digest, vec![0x5B, 0x72, 0x1D, 0x06]);
    }

    #[test]
    fn parses_single_bare_digest() {
        let out = parse_all("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n");
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].path, "", "bare digest has no filename");
        assert_eq!(out.entries[0].digest.len(), 32);
    }

    #[test]
    fn strips_utf8_bom() {
        let out = parse_all("\u{feff}d41d8cd98f00b204e9800998ecf8427e  a.txt\n");
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].path, "a.txt");
    }

    #[test]
    fn hash_comment_style_is_sticky() {
        // A '#' inside a later filename must not be treated as a comment.
        let out = parse_all(
            "# banner\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  a#b.txt\n",
        );
        assert!(!out.had_error);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].path, "a#b.txt");
    }

    #[test]
    fn malformed_line_is_reported() {
        let out = parse_all("this is not a sumfile line at all\n");
        assert!(out.had_error);
        assert!(out.entries.is_empty());
    }

    #[test]
    fn hex_decoder_rejects_odd_and_invalid() {
        assert!(hex_to_bytes("abc").is_none());
        assert!(hex_to_bytes("zz").is_none());
        assert_eq!(hex_to_bytes("00ff").unwrap(), vec![0x00, 0xFF]);
    }
}
