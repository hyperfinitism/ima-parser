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
/// `d-ngv2` digest prefix: differentiates regular IMA vs fs-verity digests.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DigestType {
    /// `ima` digest type.
    Ima,
    /// `verity` digest type.
    Verity,
    /// Future/unknown digest type.
    Other(String),
}

impl DigestType {
    /// Parse a digest-type string.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "ima" => Self::Ima,
            "verity" => Self::Verity,
            other => Self::Other(other.to_owned()),
        }
    }
    /// Return canonical digest-type name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ima => "ima",
            Self::Verity => "verity",
            Self::Other(s) => s,
        }
    }
}

/// Decoded `d-ngv2` value: `<digest_type>:<algorithm>:<digest>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestV2 {
    /// Digest namespace discriminator (`ima` vs `verity`).
    pub digest_type: DigestType,
    /// Algorithm-qualified digest payload.
    pub digest: Digest,
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
/// `ima-modsig` payload: `d-ng | n-ng | sig | d-modsig | modsig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImaModsigEntry {
    /// File-data digest (`d-ng`).
    pub digest: Digest,
    /// Measured file name (`n-ng`).
    pub filename: String,
    /// Raw `security.ima` signature (`sig`).
    pub signature: Vec<u8>,
    /// Module-signature digest field (`d-modsig`).
    pub modsig_digest: Option<Digest>,
    /// Raw appended module signature (`modsig`), PKCS#7 DER.
    pub modsig: Vec<u8>,
}

/// `ima-ngv2` payload: `d-ngv2 | n-ng`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImaNgV2Entry {
    /// Typed digest with namespace (`d-ngv2`).
    pub digest: DigestV2,
    /// Measured object name (`n-ng`).
    pub filename: String,
}

/// `ima-sigv2` payload: `d-ngv2 | n-ng | sig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImaSigV2Entry {
    /// Typed digest with namespace (`d-ngv2`).
    pub digest: DigestV2,
    /// Measured object name (`n-ng`).
    pub filename: String,
    /// Raw `security.ima` signature (`sig`).
    pub signature: Vec<u8>,
}

/// `evm-sig` payload as documented by the IMA template specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmSigEntry {
    /// Digest field (`d-ng`).
    pub digest: Digest,
    /// Object name (`n-ng`).
    pub filename: String,
    /// EVM signature bytes (`evmsig`).
    pub evmsig: Vec<u8>,
    /// Serialized xattr-name list (`xattrnames`).
    pub xattrnames: String,
    /// Encoded xattr lengths (`xattrlengths`).
    pub xattrlengths: Vec<u8>,
    /// Encoded xattr values (`xattrvalues`).
    pub xattrvalues: Vec<u8>,
    /// Inode owner uid (`iuid`).
    pub iuid: u32,
    /// Inode owner gid (`igid`).
    pub igid: u32,
    /// Inode mode bits (`imode`).
    pub imode: u16,
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
    /// `ima-modsig` template.
    ImaModsig(ImaModsigEntry),
    /// `ima-ngv2` template.
    ImaNgV2(ImaNgV2Entry),
    /// `ima-sigv2` template.
    ImaSigV2(ImaSigV2Entry),
    /// `evm-sig` template.
    EvmSig(EvmSigEntry),
    /// Any other template: we preserve the per-field raw bytes as they were
    /// framed by `u32 length | data` records on the wire.
    Unknown(Vec<TemplateField>),
}

/// IMA template identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Template {
    /// Legacy fixed-format template (`ima`).
    Ima,
    /// Next-generation digest+name template (`ima-ng`).
    ImaNg,
    /// Digest+name+signature template (`ima-sig`).
    ImaSig,
    /// Digest+name+buffer template (`ima-buf`).
    ImaBuf,
    /// Module-signature-aware template (`ima-modsig`).
    ImaModsig,
    /// V2 digest namespace template (`ima-ngv2`).
    ImaNgV2,
    /// Signature template using v2 digest field (`ima-sigv2`).
    ImaSigV2,
    /// EVM signature template (`evm-sig`).
    EvmSig,
    /// Any non built-in template name.
    Other(String),
}

impl Template {
    /// Parse a template name.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "ima" => Self::Ima,
            "ima-ng" => Self::ImaNg,
            "ima-sig" => Self::ImaSig,
            "ima-buf" => Self::ImaBuf,
            "ima-modsig" => Self::ImaModsig,
            "ima-ngv2" => Self::ImaNgV2,
            "ima-sigv2" => Self::ImaSigV2,
            "evm-sig" => Self::EvmSig,
            other => Self::Other(other.to_owned()),
        }
    }

    /// Render this template identifier using kernel spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ima => "ima",
            Self::ImaNg => "ima-ng",
            Self::ImaSig => "ima-sig",
            Self::ImaBuf => "ima-buf",
            Self::ImaModsig => "ima-modsig",
            Self::ImaNgV2 => "ima-ngv2",
            Self::ImaSigV2 => "ima-sigv2",
            Self::EvmSig => "evm-sig",
            Self::Other(s) => s,
        }
    }
}

/// Template data field identifiers from the IMA specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TemplateFieldId {
    /// `d`
    D,
    /// `d-ng`
    DNg,
    /// `d-modsig`
    DModsig,
    /// `d-ngv2`
    DNgV2,
    /// `n`
    N,
    /// `n-ng`
    NNg,
    /// `sig`
    Sig,
    /// `evmsig`
    EvmSig,
    /// `buf`
    Buf,
    /// `modsig`
    Modsig,
    /// `uuid`
    Uuid,
    /// `uid`
    Uid,
    /// `iuid`
    Iuid,
    /// `igid`
    Igid,
    /// `imode`
    Imode,
    /// `xattrnames`
    XattrNames,
    /// `xattrlengths`
    XattrLengths,
    /// `xattrvalues`
    XattrValues,
}

impl core::fmt::Display for Template {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
