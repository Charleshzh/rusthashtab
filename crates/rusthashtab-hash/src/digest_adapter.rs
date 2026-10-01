//! Shared adapter from `digest::Digest` to [`Hasher`].
//!
//! Most of the registry is a RustCrypto crate behind this one macro: the only
//! things that differ between MD4, SHA-512, SHA3-256 or Streebog are the digest
//! length and the doc comment. Keeping the adapter in one place means the
//! streaming contract (`update` forwards, `finalize` consumes) is written once.
//!
//! `out_len` is passed explicitly rather than read from the type because the
//! scanner needs the size before a context exists.

/// Wrap any `digest::Digest` as a [`Hasher`].
macro_rules! digest_hasher {
    ($wrapper:ident, $inner:ty, $out_len:expr, $doc:expr) => {
        #[doc = $doc]
        pub struct $wrapper($inner);

        impl $wrapper {
            /// A fresh context.
            pub fn new() -> Self {
                Self(<$inner as Default>::default())
            }
        }

        impl Default for $wrapper {
            fn default() -> Self {
                Self::new()
            }
        }

        impl Hasher for $wrapper {
            fn update(&mut self, data: &[u8]) {
                Digest::update(&mut self.0, data);
            }

            fn finalize(self: Box<Self>) -> Vec<u8> {
                self.0.finalize().to_vec()
            }

            fn output_len(&self) -> usize {
                $out_len
            }
        }
    };
}

pub(crate) use digest_hasher;
