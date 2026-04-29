// SPDX-License-Identifier: Apache-2.0

//! Binary IMA event-log parser.
//!
//! Wire format (one record):
//!
//! ```text
//! +----------------------------------------------------------+
//! | u32  PCR Index                                           |
//! | [N]byte Template Data Hash      (N = template_hash_size) |
//! | u32  Template Name Length                                |
//! | [L]byte Template Name           (not NUL-terminated)     |
//! | u32  Template Data Length       (ABSENT for "ima")       |
//! | [D]byte Template Data                                    |
//! +----------------------------------------------------------+
//! ```
//!
//! Integers are host-endian by default. When the kernel was booted with
//! `ima_canonical_fmt` they are little-endian; use
//! [`ParseOptions::with_endianness`] to match.

use std::io::Read;

use crate::error::{Error, Result};
use crate::hash::HashAlgorithm;

use super::IMA_EVENT_NAME_LEN_MAX;
use super::event::Event;
use super::template::{
    Digest, DigestType, DigestV2, EvmSigEntry, ImaBufEntry, ImaEntry, ImaModsigEntry, ImaNgEntry,
    ImaNgV2Entry, ImaSigEntry, ImaSigV2Entry, Template, TemplateData, TemplateField,
};

/// Byte order of the integer fields in the binary log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Endianness {
    /// Little-endian. What you get from `ima_canonical_fmt` and from every
    /// little-endian host (virtually everything today).
    #[default]
    Little,
    /// Big-endian. Host-native on big-endian machines that did not set the
    /// canonical flag.
    Big,
    /// Whatever byte order the host running the parser uses.
    Native,
}

impl Endianness {
    fn u32_from(self, bytes: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
            Self::Native => u32::from_ne_bytes(bytes),
        }
    }
}

/// Tunables for the binary parser.
#[derive(Debug, Clone)]
pub struct ParseOptions {
    endianness: Endianness,
    template_hash_algorithm: HashAlgorithm,
    max_field_len: usize,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            endianness: Endianness::Little,
            template_hash_algorithm: HashAlgorithm::Sha1,
            max_field_len: 16 * 1024 * 1024,
        }
    }
}

impl ParseOptions {
    /// Override the byte order used to decode 32-bit length/count fields.
    #[must_use]
    pub fn with_endianness(mut self, endianness: Endianness) -> Self {
        self.endianness = endianness;
        self
    }

    /// Override the hash algorithm used to size the fixed-width
    /// `template_hash` field. The kernel writes one binary log per
    /// configured PCR bank, so this will typically match the suffix of the
    /// securityfs file you're parsing.
    #[must_use]
    pub fn with_template_hash_algorithm(mut self, algo: HashAlgorithm) -> Self {
        self.template_hash_algorithm = algo;
        self
    }

    /// Cap on the size of any variable-length field the parser will try to
    /// allocate. Default is 16 MiB, which comfortably accommodates every
    /// real-world buffer but prevents a corrupted log from triggering a
    /// pathological allocation.
    #[must_use]
    pub fn with_max_field_len(mut self, max: usize) -> Self {
        self.max_field_len = max;
        self
    }

    /// Returns the configured endianness.
    #[must_use]
    pub fn endianness(&self) -> Endianness {
        self.endianness
    }

    /// Returns the configured template hash algorithm.
    #[must_use]
    pub fn template_hash_algorithm(&self) -> HashAlgorithm {
        self.template_hash_algorithm
    }
}

/// Streaming parser that yields one [`Event`] per `next()` call.
///
/// The parser reads lazily from a [`Read`]er, so it is safe to point at an
/// enormous measurement list without buffering all of it in memory.
pub struct EventLogParser<R: Read> {
    reader: R,
    opts: ParseOptions,
    eof: bool,
}

impl<R: Read> EventLogParser<R> {
    /// Construct a parser over `reader` with the given options.
    pub fn new(reader: R, opts: ParseOptions) -> Self {
        Self {
            reader,
            opts,
            eof: false,
        }
    }

    /// Access the options this parser was constructed with.
    #[must_use]
    pub fn options(&self) -> &ParseOptions {
        &self.opts
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<bool> {
        // Returns Ok(true) on success, Ok(false) on clean EOF at the first
        // byte, or an error when EOF happens mid-record.
        let mut filled = 0;
        while filled < buf.len() {
            match self.reader.read(&mut buf[filled..])? {
                0 => {
                    if filled == 0 {
                        return Ok(false);
                    }
                    return Err(Error::UnexpectedEof {
                        expected: buf.len() - filled,
                        context: "record body",
                    });
                }
                n => filled += n,
            }
        }
        Ok(true)
    }

    fn read_u32(&mut self, context: &'static str) -> Result<Option<u32>> {
        let mut buf = [0u8; 4];
        let mut filled = 0;
        while filled < 4 {
            match self.reader.read(&mut buf[filled..])? {
                0 => {
                    if filled == 0 {
                        return Ok(None);
                    }
                    return Err(Error::UnexpectedEof {
                        expected: 4 - filled,
                        context,
                    });
                }
                n => filled += n,
            }
        }
        Ok(Some(self.opts.endianness.u32_from(buf)))
    }

    fn read_vec(&mut self, len: usize, context: &'static str) -> Result<Vec<u8>> {
        if len > self.opts.max_field_len {
            return Err(Error::InvalidLength {
                value: len as u64,
                limit: self.opts.max_field_len as u64,
                context,
            });
        }
        let mut buf = vec![0u8; len];
        if !self.read_exact(&mut buf)? {
            return Err(Error::UnexpectedEof {
                expected: len,
                context,
            });
        }
        Ok(buf)
    }

    fn read_event(&mut self) -> Result<Option<Event>> {
        // 1) PCR index – also serves as our EOF probe.
        let pcr_index = match self.read_u32("PCR index")? {
            Some(v) => v,
            None => return Ok(None),
        };

        // 2) Template hash – fixed-width, no length prefix.
        let hash_size = self.opts.template_hash_algorithm.digest_size();
        let template_hash = self.read_vec(hash_size, "template hash")?;

        // 3) Template name.
        let name_len = self
            .read_u32("template name length")?
            .ok_or(Error::UnexpectedEof {
                expected: 4,
                context: "template name length",
            })? as usize;
        let name_bytes = self.read_vec(name_len, "template name")?;
        let template_name = String::from_utf8(name_bytes).map_err(|_| Error::InvalidUtf8 {
            context: "template name",
        })?;
        let template = Template::parse(&template_name);

        // 4) Template data length (suppressed for the legacy "ima" template).
        let (template_data_raw, template_data) = if template == Template::Ima {
            // Legacy `ima` template: 20-byte digest + 256-byte padded name.
            let raw = self.read_vec(20 + IMA_EVENT_NAME_LEN_MAX + 1, "ima template data")?;
            let entry = decode_legacy_ima(&raw)?;
            (raw, TemplateData::Ima(entry))
        } else {
            let data_len = self
                .read_u32("template data length")?
                .ok_or(Error::UnexpectedEof {
                    expected: 4,
                    context: "template data length",
                })? as usize;
            let raw = self.read_vec(data_len, "template data")?;
            let decoded = decode_generic(&template, &raw)?;
            (raw, decoded)
        };

        Ok(Some(Event {
            pcr_index,
            template_hash,
            template,
            template_data,
            template_data_raw,
        }))
    }
}

impl<R: Read> Iterator for EventLogParser<R> {
    type Item = Result<Event>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.eof {
            return None;
        }
        match self.read_event() {
            Ok(Some(ev)) => Some(Ok(ev)),
            Ok(None) => {
                self.eof = true;
                None
            }
            Err(e) => {
                self.eof = true;
                Some(Err(e))
            }
        }
    }
}

// ---------------------------------------------------------------------
// Template decoders
// ---------------------------------------------------------------------

fn decode_legacy_ima(raw: &[u8]) -> Result<ImaEntry> {
    if raw.len() != 20 + IMA_EVENT_NAME_LEN_MAX + 1 {
        return Err(Error::InvalidLength {
            value: raw.len() as u64,
            limit: (20 + IMA_EVENT_NAME_LEN_MAX + 1) as u64,
            context: "legacy ima template data",
        });
    }
    let mut digest = [0u8; 20];
    digest.copy_from_slice(&raw[..20]);

    let name_slice = &raw[20..];
    let end = name_slice
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(name_slice.len());
    let filename = std::str::from_utf8(&name_slice[..end])
        .map_err(|_| Error::InvalidUtf8 {
            context: "legacy ima filename",
        })?
        .to_owned();

    Ok(ImaEntry { digest, filename })
}

fn decode_generic(template: &Template, raw: &[u8]) -> Result<TemplateData> {
    let fields = split_fields(raw)?;
    let decoded = match template {
        Template::ImaNg => decode_ima_ng(&fields)?,
        Template::ImaSig => decode_ima_sig(&fields)?,
        Template::ImaBuf => decode_ima_buf(&fields)?,
        Template::ImaModsig => decode_ima_modsig(&fields)?,
        Template::ImaNgV2 => decode_ima_ngv2(&fields)?,
        Template::ImaSigV2 => decode_ima_sigv2(&fields)?,
        Template::EvmSig => decode_evm_sig(&fields)?,
        _ => TemplateData::Unknown(
            fields
                .into_iter()
                .map(|data| TemplateField { data })
                .collect(),
        ),
    };
    Ok(decoded)
}

fn decode_ima_ngv2(fields: &[Vec<u8>]) -> Result<TemplateData> {
    if fields.len() != 2 {
        return Err(Error::parse(format!(
            "ima-ngv2 expects 2 fields, got {}",
            fields.len()
        )));
    }
    Ok(TemplateData::ImaNgV2(ImaNgV2Entry {
        digest: decode_d_ngv2(&fields[0])?,
        filename: decode_n_ng(&fields[1])?,
    }))
}

fn decode_ima_sigv2(fields: &[Vec<u8>]) -> Result<TemplateData> {
    if fields.len() != 3 {
        return Err(Error::parse(format!(
            "ima-sigv2 expects 3 fields, got {}",
            fields.len()
        )));
    }
    Ok(TemplateData::ImaSigV2(ImaSigV2Entry {
        digest: decode_d_ngv2(&fields[0])?,
        filename: decode_n_ng(&fields[1])?,
        signature: fields[2].clone(),
    }))
}

fn decode_ima_modsig(fields: &[Vec<u8>]) -> Result<TemplateData> {
    if fields.len() != 5 {
        return Err(Error::parse(format!(
            "ima-modsig expects 5 fields, got {}",
            fields.len()
        )));
    }
    Ok(TemplateData::ImaModsig(ImaModsigEntry {
        digest: decode_d_ng(&fields[0])?,
        filename: decode_n_ng(&fields[1])?,
        signature: fields[2].clone(),
        modsig_digest: fields[3].clone(),
        modsig: fields[4].clone(),
    }))
}

fn decode_evm_sig(fields: &[Vec<u8>]) -> Result<TemplateData> {
    if fields.len() != 9 {
        return Err(Error::parse(format!(
            "evm-sig expects 9 fields, got {}",
            fields.len()
        )));
    }
    Ok(TemplateData::EvmSig(EvmSigEntry {
        digest: decode_d_ng(&fields[0])?,
        filename: decode_n_ng(&fields[1])?,
        evmsig: fields[2].clone(),
        xattrnames: decode_n_ng(&fields[3])?,
        xattrlengths: fields[4].clone(),
        xattrvalues: fields[5].clone(),
        iuid: parse_u32_le(&fields[6], "evm-sig iuid")?,
        igid: parse_u32_le(&fields[7], "evm-sig igid")?,
        imode: parse_u16_le(&fields[8], "evm-sig imode")?,
    }))
}

/// Decode the framed `template_data` into a plain list of field payloads.
///
/// Each field is `<u32 LE length> || <bytes>`. We always use little-endian
/// for these inner lengths – that's what the kernel writes, regardless of
/// `ima_canonical_fmt`, because the template-hash computation code uses
/// exactly those bytes.
fn split_fields(raw: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut fields = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        if i + 4 > raw.len() {
            return Err(Error::UnexpectedEof {
                expected: 4,
                context: "template field length",
            });
        }
        let len = u32::from_le_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]) as usize;
        i += 4;
        let end = i.checked_add(len).ok_or(Error::InvalidLength {
            value: len as u64,
            limit: raw.len() as u64,
            context: "template field",
        })?;
        if end > raw.len() {
            return Err(Error::UnexpectedEof {
                expected: end - raw.len(),
                context: "template field body",
            });
        }
        fields.push(raw[i..end].to_vec());
        i = end;
    }
    Ok(fields)
}

/// Decode an `ima-ng` field: `d-ng | n-ng`.
fn decode_ima_ng(fields: &[Vec<u8>]) -> Result<TemplateData> {
    if fields.len() != 2 {
        return Err(Error::parse(format!(
            "ima-ng expects 2 fields, got {}",
            fields.len()
        )));
    }
    let digest = decode_d_ng(&fields[0])?;
    let filename = decode_n_ng(&fields[1])?;
    Ok(TemplateData::ImaNg(ImaNgEntry { digest, filename }))
}

/// Decode an `ima-sig` field: `d-ng | n-ng | sig`.
fn decode_ima_sig(fields: &[Vec<u8>]) -> Result<TemplateData> {
    if fields.len() != 3 {
        return Err(Error::parse(format!(
            "ima-sig expects 3 fields, got {}",
            fields.len()
        )));
    }
    let digest = decode_d_ng(&fields[0])?;
    let filename = decode_n_ng(&fields[1])?;
    let signature = fields[2].clone();
    Ok(TemplateData::ImaSig(ImaSigEntry {
        digest,
        filename,
        signature,
    }))
}

/// Decode an `ima-buf` field: `d-ng | n-ng | buf`.
fn decode_ima_buf(fields: &[Vec<u8>]) -> Result<TemplateData> {
    if fields.len() != 3 {
        return Err(Error::parse(format!(
            "ima-buf expects 3 fields, got {}",
            fields.len()
        )));
    }
    let digest = decode_d_ng(&fields[0])?;
    let name = decode_n_ng(&fields[1])?;
    let buf = fields[2].clone();
    Ok(TemplateData::ImaBuf(ImaBufEntry { digest, name, buf }))
}

/// Decode a `d-ng` field: `<algo_name> ":" "\0" <digest_bytes>`.
pub(crate) fn decode_d_ng(raw: &[u8]) -> Result<Digest> {
    // Minimum length: "x:\0" + 1 byte of digest
    if raw.len() < 4 {
        return Err(Error::parse("d-ng field too short"));
    }
    let sep = raw
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| Error::parse("d-ng field missing NUL separator"))?;
    if sep < 2 || raw[sep - 1] != b':' {
        return Err(Error::parse("d-ng field missing ':\\0' separator"));
    }
    let algo_name = std::str::from_utf8(&raw[..sep - 1]).map_err(|_| Error::InvalidUtf8 {
        context: "d-ng algorithm name",
    })?;
    let algo = HashAlgorithm::from_name(algo_name)?;
    let digest_bytes = raw[sep + 1..].to_vec();
    if digest_bytes.len() != algo.digest_size() {
        return Err(Error::InvalidLength {
            value: digest_bytes.len() as u64,
            limit: algo.digest_size() as u64,
            context: "d-ng digest",
        });
    }
    Ok(Digest::new(algo, digest_bytes))
}

/// Decode a `d-ngv2` field: `<digest_type> ":" <algo_name> ":" "\0" <digest_bytes>`.
pub(crate) fn decode_d_ngv2(raw: &[u8]) -> Result<DigestV2> {
    let sep = raw
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| Error::parse("d-ngv2 field missing NUL separator"))?;
    if sep == 0 || raw[sep - 1] != b':' {
        return Err(Error::parse("d-ngv2 field missing ':\\0' separator"));
    }
    let header = std::str::from_utf8(&raw[..sep - 1]).map_err(|_| Error::InvalidUtf8 {
        context: "d-ngv2 header",
    })?;
    let mut parts = header.splitn(2, ':');
    let digest_type = DigestType::parse(
        parts
            .next()
            .ok_or_else(|| Error::parse("d-ngv2 missing digest type"))?,
    );
    let algo_name = parts
        .next()
        .ok_or_else(|| Error::parse("d-ngv2 missing hash algorithm"))?;
    let algo = HashAlgorithm::from_name(algo_name)?;
    let digest_bytes = raw[sep + 1..].to_vec();
    if digest_bytes.len() != algo.digest_size() {
        return Err(Error::InvalidLength {
            value: digest_bytes.len() as u64,
            limit: algo.digest_size() as u64,
            context: "d-ngv2 digest",
        });
    }
    Ok(DigestV2 {
        digest_type,
        digest: Digest::new(algo, digest_bytes),
    })
}

fn parse_u32_le(raw: &[u8], context: &'static str) -> Result<u32> {
    if raw.len() != 4 {
        return Err(Error::InvalidLength {
            value: raw.len() as u64,
            limit: 4,
            context,
        });
    }
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn parse_u16_le(raw: &[u8], context: &'static str) -> Result<u16> {
    if raw.len() != 2 {
        return Err(Error::InvalidLength {
            value: raw.len() as u64,
            limit: 2,
            context,
        });
    }
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

/// Decode an `n-ng` field: `<utf-8 bytes> \0`.
pub(crate) fn decode_n_ng(raw: &[u8]) -> Result<String> {
    // Drop the trailing nul if any.
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    let s = std::str::from_utf8(&raw[..end]).map_err(|_| Error::InvalidUtf8 {
        context: "n-ng filename",
    })?;
    Ok(s.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------- helpers ----------------

    fn d_ng_field(algo: HashAlgorithm, digest: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(algo.name().as_bytes());
        v.push(b':');
        v.push(0);
        v.extend_from_slice(digest);
        v
    }

    fn d_ngv2_field(dtype: &str, algo: HashAlgorithm, digest: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(dtype.as_bytes());
        v.push(b':');
        v.extend_from_slice(algo.name().as_bytes());
        v.push(b':');
        v.push(0);
        v.extend_from_slice(digest);
        v
    }

    fn n_ng_field(name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(name.as_bytes());
        v.push(0);
        v
    }

    fn frame_fields(fields: &[&[u8]]) -> Vec<u8> {
        let mut v = Vec::new();
        for f in fields {
            v.extend_from_slice(&(f.len() as u32).to_le_bytes());
            v.extend_from_slice(f);
        }
        v
    }

    fn build_event(pcr: u32, template_hash: &[u8], name: &str, td: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&pcr.to_le_bytes());
        v.extend_from_slice(template_hash);
        v.extend_from_slice(&(name.len() as u32).to_le_bytes());
        v.extend_from_slice(name.as_bytes());
        v.extend_from_slice(&(td.len() as u32).to_le_bytes());
        v.extend_from_slice(td);
        v
    }

    // ---------------- Endianness ----------------

    #[test]
    fn endianness_u32_from_little() {
        assert_eq!(
            Endianness::Little.u32_from([0x01, 0x02, 0x03, 0x04]),
            0x04030201
        );
    }

    #[test]
    fn endianness_u32_from_big() {
        assert_eq!(
            Endianness::Big.u32_from([0x01, 0x02, 0x03, 0x04]),
            0x01020304
        );
    }

    #[test]
    fn endianness_u32_from_native() {
        let bytes = 0xDEADBEEFu32.to_ne_bytes();
        assert_eq!(Endianness::Native.u32_from(bytes), 0xDEADBEEF);
    }

    #[test]
    fn endianness_default_is_little() {
        assert_eq!(Endianness::default(), Endianness::Little);
    }

    // ---------------- ParseOptions ----------------

    #[test]
    fn parse_options_default() {
        let opts = ParseOptions::default();
        assert_eq!(opts.endianness(), Endianness::Little);
        assert_eq!(opts.template_hash_algorithm(), HashAlgorithm::Sha1);
        assert_eq!(opts.max_field_len, 16 * 1024 * 1024);
    }

    #[test]
    fn parse_options_builders() {
        let opts = ParseOptions::default()
            .with_endianness(Endianness::Big)
            .with_template_hash_algorithm(HashAlgorithm::Sha256)
            .with_max_field_len(64);
        assert_eq!(opts.endianness(), Endianness::Big);
        assert_eq!(opts.template_hash_algorithm(), HashAlgorithm::Sha256);
        assert_eq!(opts.max_field_len, 64);
    }

    // ---------------- decode_d_ng ----------------

    #[test]
    fn decode_d_ng_sha1() {
        let raw = d_ng_field(HashAlgorithm::Sha1, &[0xAB; 20]);
        let d = decode_d_ng(&raw).unwrap();
        assert_eq!(d.algorithm, HashAlgorithm::Sha1);
        assert_eq!(d.bytes, vec![0xAB; 20]);
    }

    #[test]
    fn decode_d_ng_sha256() {
        let raw = d_ng_field(HashAlgorithm::Sha256, &[0x42; 32]);
        let d = decode_d_ng(&raw).unwrap();
        assert_eq!(d.algorithm, HashAlgorithm::Sha256);
        assert_eq!(d.bytes, vec![0x42; 32]);
    }

    #[test]
    fn decode_d_ng_too_short() {
        assert!(matches!(decode_d_ng(b"abc"), Err(Error::Parse(_))));
    }

    #[test]
    fn decode_d_ng_missing_nul() {
        let raw = b"sha1:abcdefghijklmnopqrst";
        assert!(matches!(decode_d_ng(raw), Err(Error::Parse(_))));
    }

    #[test]
    fn decode_d_ng_missing_colon_before_nul() {
        // "sha1\0<digest>" without the ':' before NUL.
        let mut raw = Vec::from(*b"sha1");
        raw.push(0);
        raw.extend_from_slice(&[0xAA; 20]);
        assert!(matches!(decode_d_ng(&raw), Err(Error::Parse(_))));
    }

    #[test]
    fn decode_d_ng_unknown_algo() {
        let mut raw = Vec::from(*b"bogus");
        raw.push(b':');
        raw.push(0);
        raw.extend_from_slice(&[0; 20]);
        assert!(matches!(
            decode_d_ng(&raw),
            Err(Error::UnknownHashAlgorithm(_))
        ));
    }

    #[test]
    fn decode_d_ng_wrong_digest_length() {
        // sha256 expects 32 bytes; supply 10.
        let raw = d_ng_field(HashAlgorithm::Sha256, &[0; 10]);
        assert!(matches!(
            decode_d_ng(&raw),
            Err(Error::InvalidLength { .. })
        ));
    }

    #[test]
    fn decode_d_ng_invalid_utf8_algo() {
        let mut raw = vec![0xFF, 0xFE];
        raw.push(b':');
        raw.push(0);
        raw.extend_from_slice(&[0; 20]);
        assert!(matches!(decode_d_ng(&raw), Err(Error::InvalidUtf8 { .. })));
    }

    // ---------------- decode_d_ngv2 ----------------

    #[test]
    fn decode_d_ngv2_ima_sha256() {
        let raw = d_ngv2_field("ima", HashAlgorithm::Sha256, &[0x11; 32]);
        let d = decode_d_ngv2(&raw).unwrap();
        assert_eq!(d.digest_type, DigestType::Ima);
        assert_eq!(d.digest.algorithm, HashAlgorithm::Sha256);
        assert_eq!(d.digest.bytes, vec![0x11; 32]);
    }

    #[test]
    fn decode_d_ngv2_verity_sha512() {
        let raw = d_ngv2_field("verity", HashAlgorithm::Sha512, &[0x22; 64]);
        let d = decode_d_ngv2(&raw).unwrap();
        assert_eq!(d.digest_type, DigestType::Verity);
        assert_eq!(d.digest.algorithm, HashAlgorithm::Sha512);
        assert_eq!(d.digest.bytes, vec![0x22; 64]);
    }

    #[test]
    fn decode_d_ngv2_other_digest_type() {
        let raw = d_ngv2_field("future", HashAlgorithm::Sha1, &[0x33; 20]);
        let d = decode_d_ngv2(&raw).unwrap();
        assert_eq!(d.digest_type, DigestType::Other("future".to_owned()));
    }

    #[test]
    fn decode_d_ngv2_roundtrip_with_encoder() {
        // Verify the decoder accepts what encode_d_ngv2 produces.
        let dv2 = DigestV2 {
            digest_type: DigestType::Ima,
            digest: Digest::new(HashAlgorithm::Sha256, vec![0x55; 32]),
        };
        let encoded = crate::log::template_hash::encode_d_ngv2(&dv2);
        assert_eq!(decode_d_ngv2(&encoded).unwrap(), dv2);
    }

    #[test]
    fn decode_d_ngv2_missing_nul() {
        // No NUL anywhere.
        let raw = b"ima:sha256:abcdef";
        assert!(matches!(decode_d_ngv2(raw), Err(Error::Parse(_))));
    }

    #[test]
    fn decode_d_ngv2_missing_colon_before_nul() {
        // "ima:sha256\0<digest>" — last colon is missing.
        let mut raw = Vec::from(*b"ima:sha256");
        raw.push(0);
        raw.extend_from_slice(&[0; 32]);
        assert!(matches!(decode_d_ngv2(&raw), Err(Error::Parse(_))));
    }

    #[test]
    fn decode_d_ngv2_nul_at_start() {
        let mut raw = Vec::new();
        raw.push(0);
        raw.extend_from_slice(&[0; 32]);
        assert!(matches!(decode_d_ngv2(&raw), Err(Error::Parse(_))));
    }

    #[test]
    fn decode_d_ngv2_no_inner_colon() {
        // "ima:\0<digest>" — only one colon, so no algo name.
        let mut raw = Vec::from(*b"ima:");
        raw.push(0);
        raw.extend_from_slice(&[0; 32]);
        assert!(matches!(decode_d_ngv2(&raw), Err(Error::Parse(_))));
    }

    #[test]
    fn decode_d_ngv2_unknown_algo() {
        let mut raw = b"ima:bogus:".to_vec();
        raw.push(0);
        raw.extend_from_slice(&[0; 20]);
        assert!(matches!(
            decode_d_ngv2(&raw),
            Err(Error::UnknownHashAlgorithm(_))
        ));
    }

    #[test]
    fn decode_d_ngv2_wrong_digest_length() {
        let raw = d_ngv2_field("ima", HashAlgorithm::Sha256, &[0; 8]);
        assert!(matches!(
            decode_d_ngv2(&raw),
            Err(Error::InvalidLength { .. })
        ));
    }

    #[test]
    fn decode_d_ngv2_invalid_utf8_header() {
        let mut raw = vec![0xFF, b':', b'x', b':'];
        raw.push(0);
        raw.extend_from_slice(&[0; 20]);
        assert!(matches!(
            decode_d_ngv2(&raw),
            Err(Error::InvalidUtf8 { .. })
        ));
    }

    // ---------------- decode_n_ng ----------------

    #[test]
    fn decode_n_ng_strips_nul() {
        assert_eq!(decode_n_ng(b"/usr/bin/ls\0").unwrap(), "/usr/bin/ls");
    }

    #[test]
    fn decode_n_ng_no_trailing_nul() {
        assert_eq!(decode_n_ng(b"/etc/hosts").unwrap(), "/etc/hosts");
    }

    #[test]
    fn decode_n_ng_empty() {
        assert_eq!(decode_n_ng(b"").unwrap(), "");
    }

    #[test]
    fn decode_n_ng_invalid_utf8() {
        assert!(matches!(
            decode_n_ng(&[0xFF, 0xFE, 0]),
            Err(Error::InvalidUtf8 { .. })
        ));
    }

    // ---------------- parse_u32_le / parse_u16_le ----------------

    #[test]
    fn parse_u32_le_ok() {
        assert_eq!(
            parse_u32_le(&[0x01, 0x02, 0x03, 0x04], "ctx").unwrap(),
            0x04030201
        );
    }

    #[test]
    fn parse_u32_le_wrong_length() {
        assert!(matches!(
            parse_u32_le(&[0x01, 0x02], "ctx"),
            Err(Error::InvalidLength { .. })
        ));
    }

    #[test]
    fn parse_u16_le_ok() {
        assert_eq!(parse_u16_le(&[0xCD, 0xAB], "ctx").unwrap(), 0xABCD);
    }

    #[test]
    fn parse_u16_le_wrong_length() {
        assert!(matches!(
            parse_u16_le(&[0x01], "ctx"),
            Err(Error::InvalidLength { .. })
        ));
    }

    // ---------------- split_fields ----------------

    #[test]
    fn split_fields_empty() {
        assert!(split_fields(&[]).unwrap().is_empty());
    }

    #[test]
    fn split_fields_single() {
        let raw = frame_fields(&[b"hello"]);
        let f = split_fields(&raw).unwrap();
        assert_eq!(f, vec![b"hello".to_vec()]);
    }

    #[test]
    fn split_fields_multiple() {
        let raw = frame_fields(&[b"abc", b"", b"defg"]);
        let f = split_fields(&raw).unwrap();
        assert_eq!(f, vec![b"abc".to_vec(), Vec::<u8>::new(), b"defg".to_vec()]);
    }

    #[test]
    fn split_fields_truncated_length_header() {
        // Only 2 bytes where 4 are needed.
        assert!(matches!(
            split_fields(&[0x01, 0x00]),
            Err(Error::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn split_fields_truncated_body() {
        // length says 10 but only 2 body bytes are present.
        let mut raw = 10u32.to_le_bytes().to_vec();
        raw.extend_from_slice(&[0xAA, 0xBB]);
        assert!(matches!(
            split_fields(&raw),
            Err(Error::UnexpectedEof { .. })
        ));
    }

    // ---------------- decode_legacy_ima ----------------

    #[test]
    fn decode_legacy_ima_ok() {
        let mut td = Vec::new();
        td.extend_from_slice(&[0xAA; 20]);
        let mut name = [0u8; IMA_EVENT_NAME_LEN_MAX + 1];
        name[..5].copy_from_slice(b"/init");
        td.extend_from_slice(&name);
        let entry = decode_legacy_ima(&td).unwrap();
        assert_eq!(entry.digest, [0xAA; 20]);
        assert_eq!(entry.filename, "/init");
    }

    #[test]
    fn decode_legacy_ima_wrong_length() {
        assert!(matches!(
            decode_legacy_ima(&[0; 10]),
            Err(Error::InvalidLength { .. })
        ));
    }

    #[test]
    fn decode_legacy_ima_invalid_utf8_name() {
        let mut td = vec![0u8; 20];
        let mut name = [0u8; IMA_EVENT_NAME_LEN_MAX + 1];
        name[0] = 0xFF;
        name[1] = 0xFE;
        td.extend_from_slice(&name);
        assert!(matches!(
            decode_legacy_ima(&td),
            Err(Error::InvalidUtf8 { .. })
        ));
    }

    // ---------------- per-template field-count errors ----------------

    #[test]
    fn decode_ima_ng_wrong_field_count() {
        let only_one = vec![b"a".to_vec()];
        assert!(matches!(decode_ima_ng(&only_one), Err(Error::Parse(_))));
    }

    #[test]
    fn decode_ima_sig_wrong_field_count() {
        let two = vec![b"a".to_vec(), b"b".to_vec()];
        assert!(matches!(decode_ima_sig(&two), Err(Error::Parse(_))));
    }

    #[test]
    fn decode_ima_buf_wrong_field_count() {
        let two = vec![b"a".to_vec(), b"b".to_vec()];
        assert!(matches!(decode_ima_buf(&two), Err(Error::Parse(_))));
    }

    #[test]
    fn decode_ima_modsig_wrong_field_count() {
        let four = vec![Vec::new(); 4];
        assert!(matches!(decode_ima_modsig(&four), Err(Error::Parse(_))));
    }

    #[test]
    fn decode_ima_ngv2_wrong_field_count() {
        let one = vec![Vec::<u8>::new()];
        assert!(matches!(decode_ima_ngv2(&one), Err(Error::Parse(_))));
    }

    #[test]
    fn decode_ima_sigv2_wrong_field_count() {
        let two = vec![Vec::<u8>::new(); 2];
        assert!(matches!(decode_ima_sigv2(&two), Err(Error::Parse(_))));
    }

    #[test]
    fn decode_evm_sig_wrong_field_count() {
        let three = vec![Vec::<u8>::new(); 3];
        assert!(matches!(decode_evm_sig(&three), Err(Error::Parse(_))));
    }

    // ---------------- end-to-end roundtrips ----------------

    #[test]
    fn parse_ima_ng_roundtrip() {
        let digest = [0xCDu8; 20];
        let td = frame_fields(&[
            &d_ng_field(HashAlgorithm::Sha1, &digest),
            &n_ng_field("/etc/hosts"),
        ]);
        let event = build_event(10, &[0xEE; 20], "ima-ng", &td);

        let events: Vec<_> = EventLogParser::new(event.as_slice(), ParseOptions::default())
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.pcr_index, 10);
        assert_eq!(ev.template, Template::ImaNg);
        match &ev.template_data {
            TemplateData::ImaNg(e) => {
                assert_eq!(e.filename, "/etc/hosts");
                assert_eq!(e.digest.algorithm, HashAlgorithm::Sha1);
                assert_eq!(e.digest.bytes, digest);
            }
            other => panic!("expected ImaNg, got {:?}", other),
        }
    }

    #[test]
    fn parse_legacy_ima() {
        let mut td = Vec::new();
        td.extend_from_slice(&[0x11; 20]);
        let mut name = [0u8; IMA_EVENT_NAME_LEN_MAX + 1];
        name[..5].copy_from_slice(b"/init");
        td.extend_from_slice(&name);

        // Legacy "ima" template has no template_data length prefix.
        let mut event = Vec::new();
        event.extend_from_slice(&10u32.to_le_bytes());
        event.extend_from_slice(&[0x22; 20]);
        event.extend_from_slice(&(b"ima".len() as u32).to_le_bytes());
        event.extend_from_slice(b"ima");
        event.extend_from_slice(&td);

        let events: Vec<_> = EventLogParser::new(event.as_slice(), ParseOptions::default())
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(events.len(), 1);
        match &events[0].template_data {
            TemplateData::Ima(e) => {
                assert_eq!(e.filename, "/init");
                assert_eq!(e.digest, [0x11; 20]);
            }
            other => panic!("expected Ima, got {:?}", other),
        }
    }

    #[test]
    fn parse_ima_sig_roundtrip() {
        let digest = [0xABu8; 32];
        let sig = b"signature-bytes";
        let td = frame_fields(&[
            &d_ng_field(HashAlgorithm::Sha256, &digest),
            &n_ng_field("/bin/sh"),
            sig,
        ]);
        let event = build_event(7, &[0; 20], "ima-sig", &td);
        let ev = EventLogParser::new(event.as_slice(), ParseOptions::default())
            .next()
            .unwrap()
            .unwrap();
        match ev.template_data {
            TemplateData::ImaSig(e) => {
                assert_eq!(e.filename, "/bin/sh");
                assert_eq!(e.digest.algorithm, HashAlgorithm::Sha256);
                assert_eq!(e.digest.bytes, digest);
                assert_eq!(e.signature, sig);
            }
            other => panic!("expected ImaSig, got {:?}", other),
        }
    }

    #[test]
    fn parse_ima_buf_roundtrip() {
        let digest = [0x44u8; 20];
        let buf = b"opaque-buffer-payload";
        let td = frame_fields(&[
            &d_ng_field(HashAlgorithm::Sha1, &digest),
            &n_ng_field(".builtin_trusted_keys"),
            buf,
        ]);
        let event = build_event(11, &[0; 20], "ima-buf", &td);
        let ev = EventLogParser::new(event.as_slice(), ParseOptions::default())
            .next()
            .unwrap()
            .unwrap();
        match ev.template_data {
            TemplateData::ImaBuf(e) => {
                assert_eq!(e.name, ".builtin_trusted_keys");
                assert_eq!(e.buf, buf);
                assert_eq!(e.digest.bytes, digest);
            }
            other => panic!("expected ImaBuf, got {:?}", other),
        }
    }

    #[test]
    fn parse_ima_modsig_roundtrip() {
        let digest = [0x55u8; 20];
        let sig = b"sig";
        let modsig_d = b"modsig-digest";
        let modsig = b"modsig-payload";
        let td = frame_fields(&[
            &d_ng_field(HashAlgorithm::Sha1, &digest),
            &n_ng_field("/lib/modules/x.ko"),
            sig,
            modsig_d,
            modsig,
        ]);
        let event = build_event(12, &[0; 20], "ima-modsig", &td);
        let ev = EventLogParser::new(event.as_slice(), ParseOptions::default())
            .next()
            .unwrap()
            .unwrap();
        match ev.template_data {
            TemplateData::ImaModsig(e) => {
                assert_eq!(e.filename, "/lib/modules/x.ko");
                assert_eq!(e.signature, sig);
                assert_eq!(e.modsig_digest, modsig_d);
                assert_eq!(e.modsig, modsig);
                assert_eq!(e.digest.bytes, digest);
            }
            other => panic!("expected ImaModsig, got {:?}", other),
        }
    }

    #[test]
    fn parse_ima_ngv2_roundtrip() {
        let digest = [0x66u8; 32];
        let td = frame_fields(&[
            &d_ngv2_field("ima", HashAlgorithm::Sha256, &digest),
            &n_ng_field("/usr/bin/ls"),
        ]);
        let event = build_event(10, &[0; 20], "ima-ngv2", &td);
        let ev = EventLogParser::new(event.as_slice(), ParseOptions::default())
            .next()
            .unwrap()
            .unwrap();
        match ev.template_data {
            TemplateData::ImaNgV2(e) => {
                assert_eq!(e.filename, "/usr/bin/ls");
                assert_eq!(e.digest.digest_type, DigestType::Ima);
                assert_eq!(e.digest.digest.algorithm, HashAlgorithm::Sha256);
                assert_eq!(e.digest.digest.bytes, digest);
            }
            other => panic!("expected ImaNgV2, got {:?}", other),
        }
    }

    #[test]
    fn parse_ima_sigv2_roundtrip() {
        let digest = [0x77u8; 32];
        let sig = b"sigv2";
        let td = frame_fields(&[
            &d_ngv2_field("verity", HashAlgorithm::Sha256, &digest),
            &n_ng_field("/etc/passwd"),
            sig,
        ]);
        let event = build_event(10, &[0; 20], "ima-sigv2", &td);
        let ev = EventLogParser::new(event.as_slice(), ParseOptions::default())
            .next()
            .unwrap()
            .unwrap();
        match ev.template_data {
            TemplateData::ImaSigV2(e) => {
                assert_eq!(e.filename, "/etc/passwd");
                assert_eq!(e.digest.digest_type, DigestType::Verity);
                assert_eq!(e.signature, sig);
            }
            other => panic!("expected ImaSigV2, got {:?}", other),
        }
    }

    #[test]
    fn parse_evm_sig_roundtrip() {
        let digest = [0x88u8; 20];
        let td = frame_fields(&[
            &d_ng_field(HashAlgorithm::Sha1, &digest),
            &n_ng_field("/var/log/messages"),
            b"evm-sig-bytes",
            &n_ng_field("user.foo\0user.bar"),
            b"\x01\x02\x03",
            b"\xAA\xBB",
            &1234u32.to_le_bytes(),
            &5678u32.to_le_bytes(),
            &0o644u16.to_le_bytes(),
        ]);
        let event = build_event(10, &[0; 20], "evm-sig", &td);
        let ev = EventLogParser::new(event.as_slice(), ParseOptions::default())
            .next()
            .unwrap()
            .unwrap();
        match ev.template_data {
            TemplateData::EvmSig(e) => {
                assert_eq!(e.filename, "/var/log/messages");
                assert_eq!(e.iuid, 1234);
                assert_eq!(e.igid, 5678);
                assert_eq!(e.imode, 0o644);
                assert_eq!(e.evmsig, b"evm-sig-bytes");
            }
            other => panic!("expected EvmSig, got {:?}", other),
        }
    }

    #[test]
    fn parse_unknown_template_preserves_raw_fields() {
        let td = frame_fields(&[b"alpha", b"beta", b"gamma"]);
        let event = build_event(10, &[0; 20], "exotic-template", &td);
        let ev = EventLogParser::new(event.as_slice(), ParseOptions::default())
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(ev.template, Template::Other("exotic-template".to_owned()));
        match ev.template_data {
            TemplateData::Unknown(fields) => {
                let datas: Vec<&[u8]> = fields.iter().map(|f| f.data.as_slice()).collect();
                assert_eq!(datas, vec![&b"alpha"[..], &b"beta"[..], &b"gamma"[..]]);
            }
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    // ---------------- iterator semantics ----------------

    #[test]
    fn empty_input_yields_no_events() {
        let events: Vec<_> = EventLogParser::new(&[][..], ParseOptions::default())
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn truncated_record_is_unexpected_eof() {
        // Just a 2-byte sliver where the PCR header (4 bytes) was expected.
        let mut p = EventLogParser::new(&[0x01, 0x02][..], ParseOptions::default());
        match p.next() {
            Some(Err(Error::UnexpectedEof { .. })) => {}
            other => panic!("expected UnexpectedEof, got {:?}", other),
        }
        // After an error the iterator must be fused.
        assert!(p.next().is_none());
    }

    #[test]
    fn truncated_template_hash_errors() {
        // Valid PCR but template_hash field cut short.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&10u32.to_le_bytes());
        bytes.extend_from_slice(&[0xAA; 5]); // sha1 needs 20
        let mut p = EventLogParser::new(bytes.as_slice(), ParseOptions::default());
        assert!(matches!(p.next(), Some(Err(Error::UnexpectedEof { .. }))));
    }

    #[test]
    fn multiple_events_parsed_in_order() {
        let d = d_ng_field(HashAlgorithm::Sha1, &[0xAA; 20]);
        let td = frame_fields(&[&d, &n_ng_field("/a")]);
        let mut log = build_event(10, &[0; 20], "ima-ng", &td);
        let td2 = frame_fields(&[&d, &n_ng_field("/b")]);
        log.extend_from_slice(&build_event(11, &[1; 20], "ima-ng", &td2));

        let events: Vec<_> = EventLogParser::new(log.as_slice(), ParseOptions::default())
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].pcr_index, 10);
        assert_eq!(events[1].pcr_index, 11);
    }

    #[test]
    fn big_endian_parses_lengths() {
        // Same record as parse_ima_ng_roundtrip but with the *outer* u32 fields
        // (PCR, name length, template_data length) encoded big-endian.
        let digest = [0xCDu8; 20];
        let td = frame_fields(&[
            &d_ng_field(HashAlgorithm::Sha1, &digest),
            &n_ng_field("/etc/hosts"),
        ]);
        let mut event = Vec::new();
        event.extend_from_slice(&10u32.to_be_bytes());
        event.extend_from_slice(&[0; 20]);
        event.extend_from_slice(&(b"ima-ng".len() as u32).to_be_bytes());
        event.extend_from_slice(b"ima-ng");
        event.extend_from_slice(&(td.len() as u32).to_be_bytes());
        event.extend_from_slice(&td);

        let opts = ParseOptions::default().with_endianness(Endianness::Big);
        let events: Vec<_> = EventLogParser::new(event.as_slice(), opts)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].pcr_index, 10);
    }

    #[test]
    fn max_field_len_caps_allocations() {
        // Announce a 1 MiB template hash but cap the parser at 32 bytes.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&10u32.to_le_bytes());
        // The next read is the template hash, which is sized by the algo
        // (sha512 = 64 bytes). Cap below that to trip the limit.
        let opts = ParseOptions::default()
            .with_template_hash_algorithm(HashAlgorithm::Sha512)
            .with_max_field_len(32);
        let mut p = EventLogParser::new(bytes.as_slice(), opts);
        assert!(matches!(p.next(), Some(Err(Error::InvalidLength { .. }))));
    }

    #[test]
    fn options_accessor_returns_configured_values() {
        let opts = ParseOptions::default()
            .with_endianness(Endianness::Big)
            .with_template_hash_algorithm(HashAlgorithm::Sha384);
        let parser = EventLogParser::new(&[][..], opts);
        assert_eq!(parser.options().endianness(), Endianness::Big);
        assert_eq!(
            parser.options().template_hash_algorithm(),
            HashAlgorithm::Sha384
        );
    }
}
