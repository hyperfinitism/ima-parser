// SPDX-License-Identifier: Apache-2.0

//! Decoded IMA template data.
//!
//! Each [`Event`](crate::log::Event) carries a [`TemplateData`] value that
//! captures the semantics of the `template_data` bytes for the well-known
//! built-in templates. For anything we don't recognise, the event falls back
//! to [`TemplateData::Unknown`], which preserves the raw field layout so
//! callers can still access the bytes without losing information.

use crate::hash::HashAlgorithm;

/// A decoded `d-ng` / `d-ngv2` style digest: a named hash algorithm plus the
/// raw digest bytes.
///
/// The length of `bytes` is always equal to `algorithm.digest_size()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest {
    /// Hash algorithm that produced the digest.
    pub algorithm: HashAlgorithm,
    /// Raw digest bytes. Length matches [`HashAlgorithm::digest_size`].
    pub bytes: Vec<u8>,
}

impl Digest {
    /// Convenience constructor.
    pub fn new(algorithm: HashAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }
}

impl core::fmt::Display for Digest {
    /// Formats as `<algo>:<hex>`, matching the kernel's ASCII output.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:", self.algorithm)?;
        for b in &self.bytes {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

/// Single `{length, bytes}` field inside an unknown template's
/// `template_data`.
///
/// Used by [`TemplateData::Unknown`] to preserve the raw wire layout when we
/// see a template we don't know how to interpret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateField {
    /// Raw field bytes (value, without the 4-byte length header).
    pub data: Vec<u8>,
}

/// Legacy `ima` template payload.
///
/// This template has a **fixed** layout on the wire: a 20-byte digest
/// (SHA-1/MD5, always 20 bytes including zero-padding of smaller hashes)
/// followed by a 256-byte NUL-terminated file name (the `n` field is always
/// zero-padded to `IMA_EVENT_NAME_LEN_MAX + 1` bytes).
///
/// Note that, unique to this template, the enclosing event has **no**
/// `template_data_length` header – parsers consume exactly 276 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImaEntry {
    /// 20-byte file-data digest (`d` field).
    pub digest: [u8; 20],
    /// File name (`n` field), NUL-terminated and padded to 256 bytes on the
    /// wire; only the leading string portion is retained here.
    pub filename: String,
}

/// `ima-ng` template payload: `d-ng | n-ng`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImaNgEntry {
    /// Hash of the file contents (`d-ng` field).
    pub digest: Digest,
    /// File name (`n-ng` field).
    pub filename: String,
}

/// `ima-sig` template payload: `d-ng | n-ng | sig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImaSigEntry {
    /// Hash of the file contents (`d-ng` field).
    pub digest: Digest,
    /// File name (`n-ng` field).
    pub filename: String,
    /// Raw contents of `security.ima` (may be empty when no signature was
    /// attached).
    pub signature: Vec<u8>,
}

/// `ima-buf` template payload: `d-ng | n-ng | buf`.
///
/// Used for `func=KEY_CHECK`, `func=CRITICAL_DATA`, `func=KEXEC_CMDLINE`…
/// rules, where the `buf` field is an arbitrary byte buffer (DER-encoded
/// X.509 certificate, kernel command line, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImaBufEntry {
    /// Hash of the buffer.
    pub digest: Digest,
    /// Logical name of the buffer (e.g. a keyring name).
    pub name: String,
    /// Raw buffer bytes.
    pub buf: Vec<u8>,
}

/// Decoded `template_data` for the built-in IMA templates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateData {
    /// Legacy `ima` template.
    Ima(ImaEntry),
    /// `ima-ng` (next-generation) template — the modern default.
    ImaNg(ImaNgEntry),
    /// `ima-sig` template.
    ImaSig(ImaSigEntry),
    /// `ima-buf` template.
    ImaBuf(ImaBufEntry),
    /// Any other template: we preserve the per-field raw bytes as they were
    /// framed by `u32 length | data` records on the wire.
    Unknown(Vec<TemplateField>),
}
