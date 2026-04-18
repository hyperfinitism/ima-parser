// SPDX-License-Identifier: Apache-2.0

//! Hash algorithms used by IMA.
//!
//! IMA templates store and reference several different hash algorithms; the
//! same algorithm identifiers appear in the `d-ng` / `d-ngv2` digest fields
//! of the event log, in the `hash_algo_name[]` table of the kernel, and in
//! `security.ima` extended attributes.
//!
//! This module provides:
//!
//! * [`HashAlgorithm`], an enum covering every algorithm currently known to
//!   the IMA kernel code, along with its byte-length digest size and
//!   canonical lower-case name.
//! * A small [`Hasher`] trait so template-hash computation can be plugged
//!   into any crypto stack. When the `hash` feature is enabled (the default),
//!   built-in implementations back [`HashAlgorithm::hasher`] with
//!   `sha1`/`sha2` from RustCrypto.

use core::fmt;

use crate::error::Error;

/// Hash algorithm identifiers used by IMA templates and digests.
///
/// The names match the strings emitted by the kernel (for example the
/// `sha256:` prefix of an ASCII log's `filedata-hash` column, or the
/// `<algo>\0` fragment inside a `d-ng` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// MD4 – 16 byte digest. Legacy.
    Md4,
    /// MD5 – 16 byte digest. Legacy.
    Md5,
    /// SHA-1 – 20 byte digest. IMA's historical default.
    Sha1,
    /// RIPEMD-160 – 20 byte digest.
    RmdRipeMd160,
    /// SHA-224 – 28 byte digest.
    Sha224,
    /// RIPEMD-128 – 16 byte digest.
    RmdRipeMd128,
    /// RIPEMD-256 – 32 byte digest.
    RmdRipeMd256,
    /// RIPEMD-320 – 40 byte digest.
    RmdRipeMd320,
    /// Whirlpool-256 – 32 byte digest.
    Wp256,
    /// Whirlpool-384 – 48 byte digest.
    Wp384,
    /// Whirlpool-512 – 64 byte digest.
    Wp512,
    /// SHA-256 – 32 byte digest. Current IMA default on most distros.
    Sha256,
    /// SHA-384 – 48 byte digest.
    Sha384,
    /// SHA-512 – 64 byte digest.
    Sha512,
    /// SM3-256 – 32 byte digest (Chinese national standard).
    Sm3_256,
    /// Streebog-256 – 32 byte digest (Russian national standard).
    Streebog256,
    /// Streebog-512 – 64 byte digest.
    Streebog512,
    /// SHA3-256 – 32 byte digest.
    Sha3_256,
    /// SHA3-384 – 48 byte digest.
    Sha3_384,
    /// SHA3-512 – 64 byte digest.
    Sha3_512,
}

impl HashAlgorithm {
    /// Returns the size, in bytes, of a raw digest produced by this
    /// algorithm.
    #[must_use]
    pub const fn digest_size(&self) -> usize {
        match self {
            Self::Md4 | Self::Md5 | Self::RmdRipeMd128 => 16,
            Self::Sha1 | Self::RmdRipeMd160 => 20,
            Self::Sha224 => 28,
            Self::Sha256
            | Self::RmdRipeMd256
            | Self::Wp256
            | Self::Sm3_256
            | Self::Streebog256
            | Self::Sha3_256 => 32,
            Self::RmdRipeMd320 => 40,
            Self::Sha384 | Self::Wp384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Wp512 | Self::Streebog512 | Self::Sha3_512 => 64,
        }
    }

    /// Canonical lower-case name as emitted by the kernel's `hash_algo_name`
    /// table – this is exactly the string that appears before `:` in a
    /// `d-ng` ASCII digest.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Md4 => "md4",
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::RmdRipeMd160 => "rmd160",
            Self::Sha224 => "sha224",
            Self::RmdRipeMd128 => "rmd128",
            Self::RmdRipeMd256 => "rmd256",
            Self::RmdRipeMd320 => "rmd320",
            Self::Wp256 => "wp256",
            Self::Wp384 => "wp384",
            Self::Wp512 => "wp512",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Sm3_256 => "sm3-256",
            Self::Streebog256 => "streebog256",
            Self::Streebog512 => "streebog512",
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_384 => "sha3-384",
            Self::Sha3_512 => "sha3-512",
        }
    }

    /// Parse an algorithm identifier from the case-insensitive kernel name.
    ///
    /// Accepts both the hyphenated form (`sm3-256`, `sha3-256`) and the
    /// underscore form (`sm3_256`, `sha3_256`).
    pub fn from_name(name: &str) -> Result<Self, Error> {
        let lower = name.trim().to_ascii_lowercase();
        let norm = lower.replace('_', "-");
        Ok(match norm.as_str() {
            "md4" => Self::Md4,
            "md5" => Self::Md5,
            "sha1" => Self::Sha1,
            "rmd160" | "ripemd-160" | "ripemd160" => Self::RmdRipeMd160,
            "sha224" => Self::Sha224,
            "rmd128" => Self::RmdRipeMd128,
            "rmd256" => Self::RmdRipeMd256,
            "rmd320" => Self::RmdRipeMd320,
            "wp256" => Self::Wp256,
            "wp384" => Self::Wp384,
            "wp512" => Self::Wp512,
            "sha256" => Self::Sha256,
            "sha384" => Self::Sha384,
            "sha512" => Self::Sha512,
            "sm3-256" | "sm3" => Self::Sm3_256,
            "streebog256" | "streebog-256" => Self::Streebog256,
            "streebog512" | "streebog-512" => Self::Streebog512,
            "sha3-256" => Self::Sha3_256,
            "sha3-384" => Self::Sha3_384,
            "sha3-512" => Self::Sha3_512,
            _ => return Err(Error::UnknownHashAlgorithm(name.to_owned())),
        })
    }

    /// Build a boxed streaming hasher for this algorithm.
    ///
    /// This is only available when the `hash` feature is enabled (it is by
    /// default). Algorithms not backed by RustCrypto's `sha1`/`sha2`
    /// (MD4, MD5, RIPEMD, Whirlpool, SM3, Streebog, SHA3, …) return `None`.
    #[cfg(feature = "hash")]
    #[must_use]
    pub fn hasher(&self) -> Option<Box<dyn Hasher>> {
        use crate::hash::backends::{
            Sha1Backend, Sha224Backend, Sha256Backend, Sha384Backend, Sha512Backend,
        };
        match self {
            Self::Sha1 => Some(Box::<Sha1Backend>::default()),
            Self::Sha224 => Some(Box::<Sha224Backend>::default()),
            Self::Sha256 => Some(Box::<Sha256Backend>::default()),
            Self::Sha384 => Some(Box::<Sha384Backend>::default()),
            Self::Sha512 => Some(Box::<Sha512Backend>::default()),
            _ => None,
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Minimal streaming hash interface used by the template-hash calculator.
///
/// Intentionally tiny: IMA only ever needs to feed a handful of chunks and
/// then read out a finalized digest. Implementing it against your own
/// crypto stack (OpenSSL, ring, etc.) requires only two methods.
pub trait Hasher {
    /// Feed more bytes into the digest.
    fn update(&mut self, data: &[u8]);

    /// Finalize and return the digest as an owned byte vector.
    ///
    /// Calling `finalize` consumes the hasher; callers that want a repeated
    /// computation must construct a fresh one.
    fn finalize(self: Box<Self>) -> Vec<u8>;
}

#[cfg(feature = "hash")]
pub(crate) mod backends {
    //! Internal RustCrypto-backed implementations of [`Hasher`].

    use super::Hasher;

    macro_rules! backend {
        ($name:ident, $algo:ty) => {
            #[derive(Default)]
            pub(crate) struct $name(pub(crate) $algo);

            impl Hasher for $name {
                fn update(&mut self, data: &[u8]) {
                    use ::sha2::Digest as _;
                    self.0.update(data);
                }
                fn finalize(self: Box<Self>) -> Vec<u8> {
                    use ::sha2::Digest as _;
                    self.0.finalize().to_vec()
                }
            }
        };
    }

    backend!(Sha1Backend, ::sha1::Sha1);
    backend!(Sha224Backend, ::sha2::Sha224);
    backend!(Sha256Backend, ::sha2::Sha256);
    backend!(Sha384Backend, ::sha2::Sha384);
    backend!(Sha512Backend, ::sha2::Sha512);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_sizes_are_consistent() {
        assert_eq!(HashAlgorithm::Sha1.digest_size(), 20);
        assert_eq!(HashAlgorithm::Sha256.digest_size(), 32);
        assert_eq!(HashAlgorithm::Sha512.digest_size(), 64);
    }

    #[test]
    fn roundtrip_names() {
        for algo in [
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
            HashAlgorithm::Md5,
            HashAlgorithm::Sm3_256,
        ] {
            let name = algo.name();
            assert_eq!(HashAlgorithm::from_name(name).unwrap(), algo);
        }
    }

    #[test]
    fn from_name_normalizes_underscores() {
        assert_eq!(
            HashAlgorithm::from_name("sha3_256").unwrap(),
            HashAlgorithm::Sha3_256
        );
        assert_eq!(
            HashAlgorithm::from_name("SHA256").unwrap(),
            HashAlgorithm::Sha256
        );
    }
}
